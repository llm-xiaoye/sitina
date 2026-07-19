from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.conversation.lifecycle import ConversationLifecycle
from sitina.conversation.models import route_decision_from_mapping
from sitina.journal.model import FrontierRef, canonical_json_bytes
from sitina.effects.monitoring import MonitoringTransfer
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.orchestrator.checkpoint_resume import (
    FRONTIER_SPECS,
    finalize_checkpoint_manifest,
    stream_heads,
    validate_frontier_snapshot,
)
from sitina.orchestrator.true_multi_agent_runtime import (
    AgentCallResult,
    AgentIdentity,
    AgentRegistry,
    CanonicalStream,
    ProviderExecutor,
    RuntimeActivation,
    TrueMultiAgentRuntimeError,
    activate_runtime,
    now_rfc3339,
    sha256_bytes,
    stable_hash,
)
from sitina.projections.production import production_handlers
from sitina.projections.rebuild import ProjectionGeneration
from sitina.protocols.arbitration import Arbitration
from sitina.protocols.blackboard import (
    Blackboard,
    BlackboardNamespace,
    NamespacePolicy,
    PatchIntent,
)
from sitina.protocols.claims import ClaimRegistry
from sitina.protocols.debate import Debate, DebateOutcome
from sitina.protocols.handoff_contracts import HandoffContract
from sitina.protocols.handoffs import Handoff
from sitina.protocols.proposals import ProposalRound, ProposalState
from sitina.protocols.reviews import ArtifactAcceptanceProcess, ReviewRequest, ReviewVerdict
from sitina.protocols.rework import FailureType, Rework
from sitina.protocols.run import RunAggregate, RunState
from sitina.protocols.tasks import TaskAggregate, TaskGraphAggregate, TaskProtocolError
from sitina.protocols.terminal import (
    AuthoritativeTerminalFacts,
    BlockerKind,
    TerminalEligibilityProjection,
    apply_terminal_decision,
    full_validate,
)
from sitina.scheduling.agents import AgentScheduler, AgentSchedulingDecision
from sitina.scheduling.processes import ProcessManager


class DynamicCollaborationError(TrueMultiAgentRuntimeError):
    pass


def _canonical_route_score(value: Any, *, field_name: str) -> str | None:
    """Encode bounded route scores without forbidden binary floating point."""

    if value is None:
        return None
    if isinstance(value, bool):
        raise DynamicCollaborationError(f"conversation route {field_name} must be numeric")
    try:
        score = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise DynamicCollaborationError(f"conversation route {field_name} must be numeric") from error
    if not score.is_finite() or score < 0 or score > 1:
        raise DynamicCollaborationError(f"conversation route {field_name} must be between zero and one")
    score = score.quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
    return format(score.normalize(), "f")


def _require_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise DynamicCollaborationError(f"Agent output requires non-empty {key}")
    return item.strip()


def _require_strings(value: Mapping[str, Any], key: str, *, minimum: int = 1, maximum: int = 12) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or not minimum <= len(item) <= maximum:
        raise DynamicCollaborationError(f"Agent output requires bounded list {key}")
    if any(not isinstance(element, str) or not element.strip() for element in item):
        raise DynamicCollaborationError(f"Agent output {key} requires non-empty strings")
    result = [element.strip() for element in item]
    return result


def _require_bool(value: Mapping[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise DynamicCollaborationError(f"Agent output requires boolean {key}")
    return item


def _require_text_or_strings(value: Mapping[str, Any], key: str, *, maximum: int = 8) -> list[str]:
    item = value.get(key)
    if isinstance(item, str) and item.strip():
        return [item.strip()]
    return _require_strings(value, key, maximum=maximum)


def _require_json_array_or_strings(
    value: Mapping[str, Any], key: str, *, minimum: int = 1, maximum: int = 12
) -> list[str]:
    item = value.get(key)
    if isinstance(item, str):
        try:
            decoded = json.loads(item)
        except json.JSONDecodeError as error:
            raise DynamicCollaborationError(f"Agent output {key} is not a JSON string array") from error
        return _require_strings({key: decoded}, key, minimum=minimum, maximum=maximum)
    return _require_strings(value, key, minimum=minimum, maximum=maximum)


def _require_verification_checks(value: Mapping[str, Any], *, maximum: int = 8) -> list[str]:
    """Accept the two bounded check shapes commonly returned by review models."""

    item = value.get("checks")
    if isinstance(item, list):
        return _require_strings(value, "checks", maximum=maximum)
    if not isinstance(item, dict) or not 1 <= len(item) <= maximum:
        raise DynamicCollaborationError("Agent output requires bounded verification checks")
    checks: list[str] = []
    for name, result in item.items():
        if not isinstance(name, str) or not name.strip():
            raise DynamicCollaborationError("Agent verification check names must be non-empty strings")
        if isinstance(result, bool):
            rendered = "passed" if result else "failed"
        elif isinstance(result, str) and result.strip():
            rendered = result.strip()
        else:
            raise DynamicCollaborationError("Agent verification check results must be text or booleans")
        checks.append(f"{name.strip()}: {rendered}")
    return checks


def _require_response_items(value: Mapping[str, Any], key: str, *, maximum: int = 8) -> None:
    item = value.get(key)
    if not isinstance(item, list) or not 1 <= len(item) <= maximum:
        raise DynamicCollaborationError(f"Agent output requires bounded response list {key}")
    for element in item:
        if isinstance(element, str) and element.strip():
            continue
        if (
            isinstance(element, dict)
            and isinstance(element.get("objection") or element.get("defect"), str)
            and isinstance(element.get("response"), str)
            and str(element.get("objection") or element.get("defect")).strip()
            and element["response"].strip()
        ):
            continue
        raise DynamicCollaborationError(f"Agent output {key} contains an invalid response item")


def _require_defect_responses(
    value: Mapping[str, Any], defects: Sequence[str], *, maximum: int = 8
) -> list[dict[str, str]]:
    """Bind every immutable Review defect to exactly one revision response."""

    if not defects or len(defects) > maximum:
        raise DynamicCollaborationError("Rework requires a bounded non-empty frozen defect set")
    items = value.get("defect_responses")
    if not isinstance(items, list) or len(items) != len(defects):
        raise DynamicCollaborationError("Rework requires exactly one response per frozen Review defect")
    normalized: list[dict[str, str]] = []
    for index, (defect, item) in enumerate(zip(defects, items, strict=True), 1):
        if isinstance(item, str) and item.strip():
            normalized.append({"defect": defect, "response": item.strip(), "ordinal": str(index)})
            continue
        if not isinstance(item, dict):
            raise DynamicCollaborationError("Rework defect response must be text or a defect/response object")
        stated_defect = item.get("defect") or item.get("objection")
        response = item.get("response")
        if not isinstance(stated_defect, str) or stated_defect.strip() != defect:
            raise DynamicCollaborationError("Rework defect response does not bind the exact frozen defect")
        if not isinstance(response, str) or not response.strip():
            raise DynamicCollaborationError("Rework defect response is empty")
        normalized.append({"defect": defect, "response": response.strip(), "ordinal": str(index)})
    return normalized


def _single_rework_required(goal: str) -> bool:
    """Recognize an ordinary-language bound that permits one initial rework only."""

    normalized = goal.casefold()
    return any(
        marker in normalized
        for marker in (
            "changes on one proposal",
            "changes on exactly one proposal",
            "changes on one initial proposal",
            "changes on exactly one initial proposal",
        )
    )


def _provider_recovery_required(goal: str) -> bool:
    normalized = goal.casefold()
    return any(
        marker in normalized
        for marker in (
            "provider recovery",
            "pre-send failure",
            "presend failure",
            "after-start loss",
            "explicit remote failure",
            "ack lost after remote success",
            "provider timeout",
            "提供商恢复",
        )
    )


def _checkpoint_restart_required(goal: str) -> bool:
    normalized = goal.casefold()
    return any(
        marker in normalized
        for marker in (
            "checkpoint restart resume",
            "checkpoint/restart/resume",
            "restart frontier",
            "process reconstruction",
            "checkpoint recovery",
            "检查点重启恢复",
        )
    )


def _integrated_closure_required(goal: str) -> bool:
    """Recognize the ordinary business semantics that require the full closure.

    This is deliberately phrased in terms of user-visible work constraints.  It
    does not look for Event names or an acceptance-only command.
    """

    normalized = goal.casefold()
    semantic_groups = (
        ("multi-round negotiation", "second negotiation round", "多轮协商"),
        ("shared state", "shared record", "共同记录", "共享状态"),
        ("same base", "competing edit", "concurrent edit", "同一初始"),
        ("owner becomes unavailable", "ownership failover", "lease expiry", "所有权故障转移"),
        ("operational transfer", "work transfer", "receiving engineer", "接收方"),
        ("first transfer package lacks", "receiver rejects", "correct every omission", "接收方拒绝"),
        ("checkpoint restart resume", "checkpoint recovery", "检查点重启恢复"),
        ("provider recovery", "after-start loss", "ack lost after remote success", "提供商恢复"),
    )
    return all(any(marker in normalized for marker in group) for group in semantic_groups)


@dataclass(frozen=True)
class GoalAnalysis:
    complexity: str
    risk_level: str
    protocols: tuple[str, ...]
    task_graph: tuple[str, ...]
    proposal_count: int
    domain_capability: str | None
    requires_rework: bool
    requires_conflict: bool
    requires_handoff_reject: bool
    requires_reassignment: bool
    requires_provider_unknown: bool
    rationale: str

    @classmethod
    def parse(cls, value: Mapping[str, Any], policy: Mapping[str, Any]) -> "GoalAnalysis":
        complexity = _require_string(value, "complexity").lower()
        risk = _require_string(value, "risk_level").lower()
        if complexity not in {"simple", "standard", "high"} or risk not in {"low", "medium", "high"}:
            raise DynamicCollaborationError("Goal analysis complexity/risk is outside policy")
        aliases = {
            "reassignment": "lease",
            "task-reassignment": "lease",
            "fencing": "lease",
            "mvcc": "blackboard",
            "restart": "checkpoint",
            "resume": "checkpoint",
            "revision": "rework",
            "transfer": "handoff",
        }
        protocols = tuple(
            dict.fromkeys(
                aliases.get(item.lower(), item.lower())
                for item in _require_strings(value, "protocols", minimum=0, maximum=9)
            )
        )
        allowed = set(str(item) for item in policy["allowed_protocols"])
        if not set(protocols).issubset(allowed):
            raise DynamicCollaborationError("Goal analysis requested a forbidden protocol")
        if "proposal" not in protocols:
            protocols = ("proposal", *protocols)
        tasks = tuple(_require_strings(value, "task_graph", maximum=16))
        count = value.get("proposal_count")
        if not isinstance(count, int) or not 1 <= count <= int(policy["max_proposals_per_round"]):
            raise DynamicCollaborationError("Goal analysis proposal count is outside policy")
        domain = value.get("domain_capability")
        if domain is not None and (not isinstance(domain, str) or not domain.strip()):
            raise DynamicCollaborationError("domain_capability must be null or a string")
        flags = {
            key: _require_bool(value, key)
            for key in (
                "requires_rework",
                "requires_conflict",
                "requires_handoff_reject",
                "requires_reassignment",
                "requires_provider_unknown",
            )
        }
        return cls(
            complexity,
            risk,
            protocols,
            tasks,
            count,
            domain.strip() if isinstance(domain, str) else None,
            flags["requires_rework"],
            flags["requires_conflict"],
            flags["requires_handoff_reject"],
            flags["requires_reassignment"],
            flags["requires_provider_unknown"],
            _require_string(value, "rationale"),
        )

    def mapping(self) -> dict[str, Any]:
        return {
            **self.__dict__,
            "protocols": list(self.protocols),
            "task_graph": list(self.task_graph),
        }


@dataclass
class RunEvidence:
    run_id: str
    goal: str
    goal_hash: str
    policy_hash: str
    analysis: GoalAnalysis | None = None
    decisions: list[dict[str, Any]] = field(default_factory=list)
    calls: list[AgentCallResult] = field(default_factory=list)
    protocol_graph: list[dict[str, Any]] = field(default_factory=list)
    obligations: dict[str, bool] = field(default_factory=dict)
    called_agents: set[str] = field(default_factory=set)
    selected_agents: set[str] = field(default_factory=set)
    filtered_agents: dict[str, list[str]] = field(default_factory=dict)
    expected_terminal: str = "SUCCEEDED"
    actual_terminal: str | None = None
    terminal_event: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    checkpoint_restarts: list[dict[str, Any]] = field(default_factory=list)
    user_response: str | None = None
    user_response_agent_id: str | None = None
    user_response_output_hash: str | None = None


def render_selected_user_response(value: Mapping[str, Any]) -> str:
    """Render the reviewed winning proposal as a concise terminal response."""

    summary = str(value.get("summary") or "").strip()
    approach = str(value.get("approach") or "").strip()
    if summary and approach and summary != approach:
        return f"{summary}\n\n{approach}"
    return summary or approach


class TrueMultiAgentProductionRuntime:
    """Production-native dynamic collaboration coordinator.

    The coordinator never writes Projection or Legacy state. It submits
    Commands to authoritative Streams, while protocol aggregates validate
    every transition before facts are committed.
    """

    DISCOVERY_SYSTEM = (
        "You are the independently identified Sitina goal-analysis Agent. "
        "Analyze the semantic goal and live constraints; do not follow a fixed role pipeline. "
        "Return one JSON object only. Never claim that an event happened."
    )

    def __init__(self, home: Path):
        self.home = Path(home).resolve(strict=True)
        self.registry = AgentRegistry.load(self.home)
        self.policy = json.loads((self.home / "config/true_multi_agent_policy.json").read_text(encoding="utf-8"))
        if self.policy.get("schema") != "SITINA_TRUE_MULTI_AGENT_POLICY_V1":
            raise DynamicCollaborationError("unsupported true multi-agent policy")
        self.policy_hash = sha256_bytes(canonical_json_bytes(self.policy))
        self.scheduler = AgentScheduler()

    def _frontier(self, journal: Any) -> FrontierRef:
        position = journal.head_position
        commitment = journal._position_hash[position] if position else "0" * 64
        return FrontierRef(journal.journal_id, journal.epoch, "local", position, commitment)

    def _recent_event_ids(self, journal: Any, *, limit: int = 8) -> tuple[str, ...]:
        events = tuple(journal.iter_events(max(0, journal.head_position - limit)))
        return tuple(item.event_id for item in events[-limit:])

    @staticmethod
    def _record_conversation_route(run_stream: CanonicalStream, controls: Mapping[str, Any]) -> None:
        conversation_route = controls.get("conversation_route_decision")
        if not bool(controls.get("interactive_chat")) or not isinstance(conversation_route, Mapping):
            return
        raw_reasons = conversation_route.get("reasons")
        reasons = (
            [str(item).strip()[:160] for item in raw_reasons if str(item).strip()][:8]
            if isinstance(raw_reasons, (list, tuple))
            else []
        )
        raw_initial_fast = conversation_route.get("initial_fast_decision")
        initial_fast_decision = None
        if isinstance(raw_initial_fast, Mapping):
            raw_evidence_reasons = raw_initial_fast.get("evidence_reasons")
            initial_fast_decision = {
                "schema": raw_initial_fast.get("schema"),
                "evaluated": bool(raw_initial_fast.get("evaluated")),
                "decision": str(raw_initial_fast.get("decision") or "")[:80],
                "multi_score": _canonical_route_score(
                    raw_initial_fast.get("multi_score"), field_name="initial_fast_decision.multi_score"
                ),
                "threshold": _canonical_route_score(
                    raw_initial_fast.get("threshold"), field_name="initial_fast_decision.threshold"
                ),
                "provider_evaluated": bool(raw_initial_fast.get("provider_evaluated")),
                "evidence_reasons": (
                    [str(item).strip()[:160] for item in raw_evidence_reasons if str(item).strip()][:8]
                    if isinstance(raw_evidence_reasons, (list, tuple))
                    else []
                ),
            }
        run_stream.append(
            "conversation-route-admitted",
            (
                {
                    "schema": "CONVERSATION_ROUTE_DECIDED_V1",
                    "event_type": "conversation.route.decided",
                    "session_id": controls.get("conversation_session_id"),
                    "turn_index": controls.get("conversation_turn_index"),
                    "requested_mode": conversation_route.get("requested_mode"),
                    "resolved_mode": conversation_route.get("resolved_mode"),
                    "source": conversation_route.get("source"),
                    "reasons": reasons,
                    "policy_version": conversation_route.get("policy_version"),
                    "input_hash": conversation_route.get("input_hash"),
                    "confidence": _canonical_route_score(
                        conversation_route.get("confidence"), field_name="confidence"
                    ),
                    "threshold": _canonical_route_score(
                        conversation_route.get("threshold"), field_name="threshold"
                    ),
                    "upgrade_reason": str(conversation_route.get("upgrade_reason") or "")[:640] or None,
                    "initial_fast_decision": initial_fast_decision,
                    "decision_path": conversation_route.get("decision_path"),
                    "provider_text_only": True,
                    "external_mutation_allowed": False,
                },
            ),
            actor="conversation-router",
        )

    def _interactive_chat_analysis(self, analysis: GoalAnalysis) -> GoalAnalysis:
        """Bind interactive MULTI to the existing live collaboration protocols."""

        return dataclasses.replace(
            analysis,
            complexity="standard",
            risk_level="low",
            protocols=("proposal", "review", "debate", "handoff"),
            task_graph=(
                "interpret the current message and bounded conversation context",
                "produce and independently review candidate answers",
                "negotiate revisions and select a reviewed answer",
                "handoff the selected answer under a verified read-only contract",
            ),
            proposal_count=min(2, int(self.policy["max_proposals_per_round"])),
            domain_capability=None,
            requires_rework=False,
            requires_conflict=False,
            requires_handoff_reject=False,
            requires_reassignment=False,
            requires_provider_unknown=False,
            rationale="interactive MULTI uses live Proposal, Review, Negotiation, and Handoff without external mutation",
        )

    def _candidate(
        self,
        identity: AgentIdentity,
        *,
        author_conflicts: set[str],
        exclusions: set[str],
        overrides: Mapping[str, Any],
        evidence: RunEvidence,
    ):
        remove = set(dict(overrides.get("remove_capabilities", {})).get(identity.agent_id, ()))
        add = set(dict(overrides.get("add_capabilities", {})).get(identity.agent_id, ()))
        capabilities = tuple(sorted(set(identity.capabilities).difference(remove).union(add)))
        candidate_identity = dataclasses.replace(identity, capabilities=capabilities)
        budget_filtered = set(overrides.get("budget_filtered_agents", ()))
        safety_filtered = set(overrides.get("safety_filtered_agents", ()))
        lease_filtered = set(overrides.get("lease_filtered_agents", ()))
        loads = dict(overrides.get("agent_loads", {}))
        candidate = candidate_identity.candidate(
            load=int(loads.get(identity.agent_id, sum(1 for item in evidence.calls if item.agent_id == identity.agent_id))),
            eligible=identity.agent_id not in exclusions,
            safety_allowed=identity.agent_id not in safety_filtered,
            budget_allowed=identity.agent_id not in budget_filtered,
            lease_available=identity.agent_id not in lease_filtered,
            independent=identity.agent_id not in author_conflicts,
            policy_allowed=True,
            source_versions={"registry": self.registry.generation, "run_decision": len(evidence.decisions)},
        )
        return candidate_identity, candidate

    def _schedule(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        evidence: RunEvidence,
        *,
        task_id: str,
        required_capabilities: Sequence[str],
        slots: int,
        candidate_tasks: Sequence[str],
        author_conflicts: Sequence[str] = (),
        exclusions: Sequence[str] = (),
        overrides: Mapping[str, Any] | None = None,
    ) -> tuple[AgentSchedulingDecision, tuple[AgentIdentity, ...]]:
        override = dict(overrides or {})
        identities: dict[str, AgentIdentity] = {}
        candidates = []
        for item in self.registry.identities:
            identity, candidate = self._candidate(
                item,
                author_conflicts=set(author_conflicts),
                exclusions=set(exclusions),
                overrides=override,
                evidence=evidence,
            )
            identities[identity.agent_id] = identity
            candidates.append(candidate)
        deadline = "2099-01-01T00:00:00Z"
        source_frontier = self._frontier(journal)
        source_ids = self._recent_event_ids(journal)
        decision = self.scheduler.decide(
            task_id,
            candidates,
            required_capabilities=required_capabilities,
            requested_slots=slots,
            source_event_ids=source_ids,
            source_frontier=source_frontier,
            candidate_tasks=candidate_tasks,
            policy_hash=self.policy_hash,
            deadline=deadline,
        )
        run_stream.append(
            "scheduling-decision",
            ({"schema": "AGENT_SCHEDULING_DECISION_V1", "event_type": "scheduling.decision", **decision.mapping()},),
            actor="scheduler",
            source_frontier=source_frontier,
            deadline=deadline,
        )
        selected = tuple(identities[item] for item in decision.selected_attempts)
        if not selected:
            raise DynamicCollaborationError(f"no eligible Agent for {task_id}")
        # Authoritative dispatch revalidates registry, policy, deadline, and the
        # frozen decision commitment after the Scheduler has only discovered candidates.
        if decision.policy_hash != self.policy_hash or self.registry.generation < 1 or now_rfc3339() >= deadline:
            raise DynamicCollaborationError("authoritative Dispatcher revalidation failed")
        run_stream.append(
            "dispatch-command-accepted",
            ({
                "schema": "DISPATCH_COMMAND_ACCEPTED_V1",
                "event_type": "dispatch.command.accepted",
                "decision_id": decision.decision_id,
                "decision_commitment": decision.commitment,
                "source_frontier": decision.source_frontier.__dict__,
                "selected_agents": list(decision.selected_attempts),
                "stream_version_revalidated": True,
                "admission_generation_revalidated": True,
                "policy_revalidated": True,
                "deadline_revalidated": True,
                "fence_revalidated": True,
                "protocol_state_revalidated": True,
                "projection_was_authority": False,
            },),
            actor="authoritative-dispatcher",
        )
        evidence.decisions.append(decision.mapping())
        evidence.selected_agents.update(decision.selected_attempts)
        for scorecard in decision.scorecards:
            if not scorecard.passed:
                evidence.filtered_agents.setdefault(scorecard.agent_id, []).append(scorecard.reason_code)
        return decision, selected

    @staticmethod
    def _system_prompt(agent: AgentIdentity, kind: str, contract: str) -> str:
        return (
            f"You are Sitina Agent {agent.agent_id}, role {agent.role}. "
            f"Your immutable capabilities are {', '.join(agent.capabilities)}. "
            f"Return one JSON object with agent_id exactly '{agent.agent_id}' and kind exactly '{kind}'. "
            f"{contract} Do not speak for another Agent and do not include tool instructions. Never include real, "
            "example, or placeholder credentials, API keys, access tokens, private keys, passwords, authenticated "
            "URLs, or secret-like strings; describe such concepts only in plain generic words."
        )

    def _call(
        self,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        agent: AgentIdentity,
        *,
        task_id: str,
        kind: str,
        contract: str,
        prompt: str,
        context: Mapping[str, Any],
        validate,
        ack_lost: bool = False,
    ) -> AgentCallResult:
        result = executor.call(
            agent,
            task_id=task_id,
            kind=kind,
            system_prompt=self._system_prompt(agent, kind, contract),
            user_prompt=prompt,
            input_context=context,
            validate=validate,
            ack_lost=ack_lost,
        )
        evidence.calls.append(result)
        evidence.called_agents.add(agent.agent_id)
        return result

    def _discover(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        overrides: Mapping[str, Any],
    ) -> tuple[GoalAnalysis, AgentIdentity, AgentCallResult]:
        _, agents = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="goal-discovery",
            required_capabilities=("goal-analysis",),
            slots=1,
            candidate_tasks=("goal-discovery",),
            overrides=overrides,
        )
        agent = agents[0]

        def validate(value: Mapping[str, Any]) -> None:
            GoalAnalysis.parse(value, self.policy)

        prompt = (
            "Analyze this goal and return fields: agent_id, kind='proposal', complexity(simple|standard|high), "
            "risk_level(low|medium|high), protocols (from proposal, review, debate, rework, handoff, blackboard, arbitration, lease, checkpoint), "
            "task_graph (semantic task names), proposal_count integer 1-3, domain_capability string or null, "
            "requires_rework, requires_conflict, requires_handoff_reject, requires_reassignment, requires_provider_unknown booleans, and rationale. "
            "Choose protocols only when the goal semantics require them; a simple read-only goal should be small. Goal: "
            + evidence.goal
        )
        result = self._call(
            executor,
            evidence,
            agent,
            task_id="goal-discovery",
            kind="proposal",
            contract="You discover task structure and protocol needs from the goal and current policy.",
            prompt=prompt,
            context={"goal_hash": evidence.goal_hash, "allowed_protocols": self.policy["allowed_protocols"]},
            validate=validate,
        )
        analysis = GoalAnalysis.parse(result.value, self.policy)
        evidence.analysis = analysis
        run_stream.append(
            "goal-analysis-accepted",
            ({
                "schema": "GOAL_ANALYSIS_ACCEPTED_V1",
                "event_type": "goal.analysis.accepted",
                "agent_id": agent.agent_id,
                "call_id": result.call_id,
                "input_snapshot_hash": result.input_snapshot_hash,
                "output_hash": result.output_hash,
                "analysis": analysis.mapping(),
            },),
            actor="goal-analysis-command-handler",
        )
        return analysis, agent, result

    def _protocol_open(self, evidence: RunEvidence, kind: str, instance_id: str, parent: str, decision_id: str) -> dict[str, Any]:
        value = {
            "protocol_instance": instance_id,
            "protocol_kind": kind,
            "parent_obligation": parent,
            "source_decision": decision_id,
            "generation": 1,
            "terminal_disposition": None,
            "successor_obligation": None,
        }
        evidence.protocol_graph.append(value)
        evidence.obligations[parent] = False
        return {
            "schema": "PROTOCOL_INSTANCE_CREATED_V1",
            "protocol_instance_id": instance_id,
            "protocol_kind": kind,
            "parent_obligation_id": parent,
            "source_decision_id": decision_id,
            "generation": 1,
            "initial_state": "OPEN",
            "allowed_commands_hash": stable_hash("PROTOCOL_ALLOWED_COMMANDS", {"kind": kind}),
            "transition_matrix_hash": stable_hash("PROTOCOL_TRANSITION_MATRIX", {"kind": kind, "major": 1}),
            "timeout_rule": "FAIL_CLOSED",
            "retry_rule": "BOUNDED_POLICY",
            "invalid_transition": "REJECT_AND_RECORD",
        }

    def _protocol_close(
        self,
        evidence: RunEvidence,
        instance_id: str,
        parent: str,
        disposition: str,
        successor: str | None = None,
    ) -> dict[str, Any]:
        for item in evidence.protocol_graph:
            if item["protocol_instance"] == instance_id:
                item["terminal_disposition"] = disposition
                item["successor_obligation"] = successor
                break
        evidence.obligations[parent] = successor is None
        if successor is not None:
            evidence.obligations[successor] = False
        return {
            "schema": "PROTOCOL_INSTANCE_TERMINAL_V1",
            "protocol_instance_id": instance_id,
            "terminal_disposition": disposition,
            "parent_obligation_id": parent,
            "successor_obligation_id": successor,
            "obligation_satisfied": successor is None,
        }

    def _proposal_and_review(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        overrides: Mapping[str, Any],
    ) -> tuple[AgentCallResult, AgentIdentity, list[AgentCallResult], AgentSchedulingDecision]:
        proposal_decision, proposers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="proposal-competition",
            required_capabilities=("proposal",),
            slots=analysis.proposal_count,
            candidate_tasks=analysis.task_graph,
            overrides=overrides,
        )
        reviewer_decision, reviewers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="independent-review",
            required_capabilities=("review", "evaluation", "security-review")
            if analysis.risk_level == "high"
            else ("review", "evaluation"),
            slots=1,
            candidate_tasks=("independent-review",),
            author_conflicts=tuple(item.agent_id for item in proposers),
            overrides=overrides,
        )
        reviewer = reviewers[0]
        rubric = stable_hash(
            "TRUE_MULTI_AGENT_FROZEN_RUBRIC",
            {
                "goal_hash": evidence.goal_hash,
                "criteria": ["correctness", "safety", "evidence", "feasibility"],
                "minimum_score": self.policy["proposal_minimum_score"],
                "policy_hash": self.policy_hash,
            },
        )
        round_id = "proposal-round-" + stable_hash("TRUE_MULTI_AGENT_PROPOSAL_ROUND", {"run": evidence.run_id})[:28]
        proposal, opened = ProposalRound.open(
            round_id,
            generation=1,
            participants=tuple(item.agent_id for item in proposers),
            evaluators=(reviewer.agent_id,),
            rubric_hash=rubric,
            policy_hash=self.policy_hash,
            deadline="2099-01-01T00:00:00Z",
            minimum_score=int(self.policy["proposal_minimum_score"]),
            max_revisions=int(self.policy["max_rework_rounds"]),
        )
        obligation = "obligation-proposal-" + evidence.run_id
        open_fact = self._protocol_open(evidence, "proposal", round_id, obligation, proposal_decision.decision_id)
        proposal_stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/proposal/{round_id}",
            self.policy_hash,
        )
        proposal_stream.append("proposal-round-opened", (open_fact, opened), actor="proposal-command-handler")
        results: list[AgentCallResult] = []
        proposal_ids: dict[str, str] = {}
        for index, agent in enumerate(proposers, 1):
            proposal_id = f"proposal-{index}-{agent.agent_id}"
            proposal_ids[agent.agent_id] = proposal_id

            def validate_proposal(value: Mapping[str, Any]) -> None:
                for key in ("summary", "approach"):
                    _require_string(value, key)
                for key in ("risks", "assumptions"):
                    _require_text_or_strings(value, key, maximum=8)
                _require_json_array_or_strings(value, "acceptance_checks", maximum=12)

            result = self._call(
                executor,
                evidence,
                agent,
                task_id=f"proposal-{index}",
                kind="proposal",
                contract="Submit an independently reasoned proposal with summary, approach, risks, assumptions, and acceptance_checks. acceptance_checks must be a JSON string array; risks and assumptions may each be a concise string or string array.",
                prompt=(
                    "Create an independent solution for this goal. Do not copy another Agent. "
                    f"Goal: {evidence.goal}\nTask graph: {json.dumps(list(analysis.task_graph), ensure_ascii=False)}\n"
                    f"Frozen rubric hash: {rubric}"
                ),
                context={
                    "goal_hash": evidence.goal_hash,
                    "proposal_round_id": round_id,
                    "proposal_id": proposal_id,
                    "rubric_hash": rubric,
                    "causal_event_ids": list(self._recent_event_ids(journal)),
                },
                validate=validate_proposal,
                ack_lost=analysis.requires_provider_unknown and index == 1,
            )
            proposal, _, submitted = proposal.submit(proposal_id, agent.agent_id, result.output_ref.removeprefix("cas:"))
            proposal_stream.append(
                "proposal-submitted",
                ({
                    **submitted,
                    "event_type": "proposal.submitted",
                    "call_id": result.call_id,
                    "input_snapshot_hash": result.input_snapshot_hash,
                    "output_hash": result.output_hash,
                    "output_ref": result.output_ref,
                },),
                actor=agent.agent_id,
            )
            results.append(result)
        review_results: list[AgentCallResult] = []
        scores: dict[str, int] = {}
        dispositions: dict[str, str] = {}
        single_rework_required = analysis.requires_rework and _single_rework_required(evidence.goal)
        for index, (agent, result) in enumerate(zip(proposers, results, strict=True), 1):
            force_changes = analysis.requires_rework and index == 1
            revision_allowed = force_changes or (
                (analysis.requires_rework or "rework" in analysis.protocols)
                and not single_rework_required
            )

            def validate_review(value: Mapping[str, Any]) -> None:
                verdict = _require_string(value, "verdict").lower()
                if verdict not in {"approved", "changes_requested", "reject"}:
                    raise DynamicCollaborationError("Review verdict is invalid")
                score = value.get("score")
                if not isinstance(score, int) or not 0 <= score <= 100:
                    raise DynamicCollaborationError("Review score is invalid")
                if verdict == "approved" and score < int(self.policy["proposal_minimum_score"]):
                    raise DynamicCollaborationError("approved Review score is below the frozen minimum")
                _require_string(value, "reason")
                _require_strings(value, "defects", minimum=0, maximum=8)

            instruction = (
                "This goal explicitly requires a real rework path. Identify one specific repairable defect and return verdict changes_requested with score below 70."
                if force_changes
                else "Independently score the exact proposal. Approve only if it meets the frozen rubric; otherwise request changes or reject."
                if revision_allowed
                else "Independently score the exact proposal. No revision cycle is authorized: approve if it meets the frozen rubric, otherwise reject it."
            )
            review = self._call(
                executor,
                evidence,
                reviewer,
                task_id=f"review-{index}",
                kind="review",
                contract=(
                    "Return verdict, integer score on a 0-100 scale, reason, and defects. verdict MUST be exactly "
                    "one of: approved, changes_requested, reject. defects MUST be a JSON array containing only "
                    "zero to eight short strings (use [] when there are no defects and combine related concerns rather "
                    "than returning more than eight). approved requires score at least 70. Bind "
                    "the exact proposal hash and frozen rubric."
                ),
                prompt=(
                    instruction
                    + "\nThe verdict JSON string must be exactly approved, changes_requested, or reject; do not use synonyms. Score is an integer 0-100, never a string and never 0-10; approved requires 70 or higher. defects is an array of zero to eight strings only, never objects; combine related concerns to stay within eight."
                    + f"\nGoal: {evidence.goal}\nProposal hash: {result.output_hash}\nProposal: "
                    + json.dumps(dict(result.value), ensure_ascii=False, sort_keys=True)
                    + f"\nFrozen rubric hash: {rubric}"
                ),
                context={
                    "proposal_id": proposal_ids[agent.agent_id],
                    "proposal_output_hash": result.output_hash,
                    "proposal_output_ref": result.output_ref,
                    "rubric_hash": rubric,
                    "author_agent_id": agent.agent_id,
                    "reviewer_independence": True,
                },
                validate=validate_review,
            )
            provider_verdict = str(review.value["verdict"]).lower()
            verdict = provider_verdict
            score = int(review.value["score"])
            if force_changes and (verdict != "changes_requested" or score >= int(self.policy["proposal_minimum_score"])):
                raise DynamicCollaborationError("independent Reviewer failed to create the required rework path")
            revision_denied_by_goal = verdict == "changes_requested" and not revision_allowed
            if revision_denied_by_goal:
                verdict = "reject"
            disposition = {
                "approved": "ACCEPT",
                "changes_requested": "NEEDS_REVISION",
                "reject": "REJECT",
            }[verdict]
            proposal, evaluated = proposal.evaluate(
                proposal_ids[agent.agent_id], reviewer.agent_id, score=score, disposition=disposition
            )
            review_request, requested = ReviewRequest.open(
                "review-request-" + stable_hash("TRUE_MULTI_AGENT_REVIEW_ID", {"run": evidence.run_id, "proposal": proposal_ids[agent.agent_id], "revision": 1})[:28],
                result.output_ref.removeprefix("cas:"),
                agent.agent_id,
                rubric,
                quorum=1,
                high_risk=analysis.risk_level == "high",
                security_review_required=analysis.risk_level == "high",
            )
            reviewer_capabilities = tuple(reviewer.capabilities)
            review_request, response = review_request.respond(
                reviewer.agent_id,
                reviewer_capabilities,
                False,
                {"approved": ReviewVerdict.ACCEPT, "changes_requested": ReviewVerdict.NEEDS_CHANGES, "reject": ReviewVerdict.REJECT}[verdict],
                review.output_ref.removeprefix("cas:"),
            )
            review_request, review_disposition = review_request.dispose()
            proposal_stream.append(
                "proposal-reviewed",
                (
                    {**requested, "event_type": "review.requested", "proposal_id": proposal_ids[agent.agent_id], "proposal_output_hash": result.output_hash},
                    {
                        **response,
                        "event_type": "review.response",
                        "review_call_id": review.call_id,
                        "review_output_hash": review.output_hash,
                        "provider_verdict": provider_verdict,
                        "effective_verdict": verdict,
                    },
                    {
                        **review_disposition,
                        "event_type": "review.disposition",
                        "revision_allowed": revision_allowed,
                        "revision_denied_by_goal": revision_denied_by_goal,
                        "single_rework_required": single_rework_required,
                    },
                    {**evaluated, "event_type": "proposal.evaluated", "frozen_rubric_hash": rubric},
                ),
                actor=reviewer.agent_id,
            )
            review_results.append(review)
            scores[proposal_ids[agent.agent_id]] = score
            dispositions[proposal_ids[agent.agent_id]] = disposition
            if disposition == "NEEDS_REVISION":
                frozen_defects = tuple(_require_strings(review.value, "defects", maximum=8))
                rework_id = "rework-" + stable_hash("TRUE_MULTI_AGENT_REWORK", {"run": evidence.run_id, "proposal": proposal_ids[agent.agent_id]})[:28]
                rework_obligation = "obligation-" + rework_id
                rework_open_fact = self._protocol_open(evidence, "rework", rework_id, rework_obligation, reviewer_decision.decision_id)
                rework, rework_opened = Rework.open(
                    rework_id,
                    f"proposal-revision-{index}",
                    FailureType.REVIEW_REJECTED,
                    rubric,
                    max_retries=int(self.policy["max_rework_rounds"]),
                )
                rework, rework_started = rework.begin_round(f"revision-attempt-{index}-1")

                def validate_revision(value: Mapping[str, Any]) -> None:
                    _require_string(value, "parent_output_hash")
                    _require_defect_responses(value, frozen_defects, maximum=8)
                    if "summary" in value:
                        _require_string(value, "summary")
                    if "approach" in value:
                        _require_string(value, "approach")
                    if "acceptance_checks" in value:
                        _require_json_array_or_strings(value, "acceptance_checks", maximum=8)

                revision = self._call(
                    executor,
                    evidence,
                    agent,
                    task_id=f"proposal-revision-{index}",
                    kind="proposal",
                    contract=(
                        "Revise the immutable parent. Required fields are exact parent_output_hash and one "
                        "defect_response per Review defect; each response may be a concise string or an object with "
                        "defect and response strings. summary, approach, and acceptance_checks are optional additions. "
                        "If acceptance_checks is present, it must be a JSON array of at most eight strings only; encode "
                        "each condition and its named evidence together in one string, never as an object."
                    ),
                    prompt=(
                        f"Revise your exact parent proposal. Parent output hash: {result.output_hash}. "
                        f"Review output hash: {review.output_hash}. Defects: {json.dumps(review.value.get('defects', []), ensure_ascii=False)}. "
                        "Return a new proposal object; never overwrite the parent. If you include acceptance_checks, "
                        "return only strings such as 'Condition — Evidence: named item'; do not return objects."
                    ),
                    context={
                        "parent_proposal_id": proposal_ids[agent.agent_id],
                        "parent_output_hash": result.output_hash,
                        "parent_output_ref": result.output_ref,
                        "review_id": review_request.review_id,
                        "review_output_hash": review.output_hash,
                    },
                    validate=validate_revision,
                )
                if str(revision.value["parent_output_hash"]) != result.output_hash:
                    raise DynamicCollaborationError("Rework revision did not bind the exact parent output hash")
                if revision.output_hash == result.output_hash:
                    raise DynamicCollaborationError("Rework revision did not create a new output hash")
                defect_responses = _require_defect_responses(revision.value, frozen_defects, maximum=8)
                defect_resolution_hash = stable_hash(
                    "TRUE_MULTI_AGENT_REWORK_DEFECT_RESOLUTION",
                    {
                        "review_output_hash": review.output_hash,
                        "parent_output_hash": result.output_hash,
                        "defects": list(frozen_defects),
                        "responses": defect_responses,
                    },
                )
                proposal, revised, revised_fact = proposal.revise(
                    proposal_ids[agent.agent_id], revision.output_ref.removeprefix("cas:")
                )

                def validate_second_review(value: Mapping[str, Any]) -> None:
                    if _require_string(value, "verdict").lower() != "approved":
                        raise DynamicCollaborationError("second Review did not approve repaired revision")
                    score_value = value.get("score")
                    if not isinstance(score_value, int) or score_value < int(self.policy["proposal_minimum_score"]):
                        raise DynamicCollaborationError("second Review score is below threshold")
                    _require_string(value, "reason")
                    _require_strings(value, "defects", minimum=0, maximum=8)

                second_review = self._call(
                    executor,
                    evidence,
                    reviewer,
                    task_id=f"review-revision-{index}",
                    kind="review",
                    contract="Re-review the exact new revision. In addition to the required agent_id and kind envelope, return verdict as the string approved, score as an integer 70-100, reason as a non-empty string, and defects as a JSON string array (empty when none). Do not return an approved boolean or comments field.",
                    prompt=(
                        f"Re-review revision hash {revision.output_hash}, parent {result.output_hash}. "
                        f"Prior defects: {json.dumps(review.value.get('defects', []), ensure_ascii=False)}. "
                        f"Required shape example: {{\"agent_id\":\"{reviewer.agent_id}\",\"kind\":\"review\","
                        "\"verdict\":\"approved\",\"score\":85,\"reason\":\"...\",\"defects\":[]}. Revision: "
                        + json.dumps(dict(revision.value), ensure_ascii=False, sort_keys=True)
                    ),
                    context={
                        "revision_output_hash": revision.output_hash,
                        "parent_output_hash": result.output_hash,
                        "prior_review_output_hash": review.output_hash,
                        "old_approval_applicable": False,
                    },
                    validate=validate_second_review,
                )
                score2 = int(second_review.value["score"])
                review2, requested2 = ReviewRequest.open(
                    "review-request-" + stable_hash("TRUE_MULTI_AGENT_REVIEW_ID", {"run": evidence.run_id, "proposal": proposal_ids[agent.agent_id], "revision": 2})[:28],
                    revision.output_ref.removeprefix("cas:"),
                    agent.agent_id,
                    rubric,
                    quorum=1,
                    high_risk=analysis.risk_level == "high",
                    security_review_required=analysis.risk_level == "high",
                )
                review2, response2 = review2.respond(
                    reviewer.agent_id,
                    tuple(reviewer.capabilities),
                    False,
                    ReviewVerdict.ACCEPT,
                    second_review.output_ref.removeprefix("cas:"),
                )
                review2, disposition2 = review2.dispose()
                rework, rework_completed = rework.complete_round(
                    revision.output_ref.removeprefix("cas:"), accepted=True
                )
                proposal, evaluated2 = proposal.evaluate(
                    proposal_ids[agent.agent_id], reviewer.agent_id, score=score2, disposition="ACCEPT"
                )
                close_rework = self._protocol_close(evidence, rework_id, rework_obligation, "SATISFIED")
                proposal_stream.append(
                    "proposal-rework-completed",
                    (
                        rework_open_fact,
                        rework_opened,
                        rework_started,
                        {
                            **revised_fact,
                            "event_type": "proposal.revised",
                            "parent_output_hash": result.output_hash,
                            "new_output_hash": revision.output_hash,
                            "revision_call_id": revision.call_id,
                            "rework_id": rework_id,
                            "frozen_defects": list(frozen_defects),
                            "defect_response_count": len(defect_responses),
                            "all_defects_addressed": True,
                            "defect_resolution_hash": defect_resolution_hash,
                            "old_review_reused": False,
                        },
                        rework_completed,
                        requested2,
                        response2,
                        disposition2,
                        evaluated2,
                        close_rework,
                    ),
                    actor=reviewer.agent_id,
                )
                results[index - 1] = revision
                review_results.append(second_review)
                scores[proposal_ids[agent.agent_id]] = score2
                dispositions[proposal_ids[agent.agent_id]] = "ACCEPT"

        negotiation_finalization: Mapping[str, Any] | None = None
        if "debate" in analysis.protocols and len(results) >= 2:
            proposal, results, debate_scores, debate_dispositions, debate_reviews, negotiation_finalization = self._debate(
                journal,
                run_stream,
                executor,
                evidence,
                proposal_stream,
                proposal,
                proposers,
                results,
                review_results,
                reviewer,
                rubric,
                proposal_decision,
                analysis.risk_level,
                overrides,
            )
            scores.update(debate_scores)
            dispositions.update(debate_dispositions)
            review_results.extend(debate_reviews)

        eligible = [
            item
            for item in proposal.proposals
            if item.state is ProposalState.ACTIVE and dispositions.get(item.proposal_id) == "ACCEPT"
        ]
        if not eligible:
            no_selection = proposal.no_selection(
                "ARBITRATION" if "arbitration" in analysis.protocols else "CANCEL",
                expected_version=proposal.version,
            )[1]
            proposal_stream.append("proposal-no-selection", (no_selection,), actor="selection-command-handler")
            raise DynamicCollaborationError("ProposalRound reached NoSelection")
        selected_proposal = max(eligible, key=lambda item: (scores.get(item.proposal_id, 0), item.proposal_id))
        proposal, selected_fact = proposal.select(selected_proposal.proposal_id, expected_version=proposal.version)
        winner_agent = next(item for item in proposers if proposal_ids[item.agent_id] == selected_proposal.proposal_id)
        winner_result = results[list(proposers).index(winner_agent)]
        close_fact = self._protocol_close(evidence, round_id, obligation, "SELECTED")
        proposal_stream.append(
            "proposal-selected",
            (
                *(
                    ({
                        "schema": "NEGOTIATION_SELECTION_DECIDED_V1",
                        "decision_id": "negotiation-selection-" + stable_hash(
                            "TRUE_MULTI_AGENT_NEGOTIATION_SELECTION",
                            {
                                "run_id": evidence.run_id,
                                "round_id": proposal.round_id,
                                "generation": proposal.generation,
                                "selected_proposal_id": selected_proposal.proposal_id,
                                "selected_output_hash": winner_result.output_hash,
                                "synthesis_candidate_hash": negotiation_finalization["synthesis_candidate_hash"],
                                "fresh_review_hashes": negotiation_finalization["fresh_review_hashes"],
                            },
                        )[:40],
                        "round_id": proposal.round_id,
                        "generation": proposal.generation,
                        "selected_proposal_id": selected_proposal.proposal_id,
                        "latest_revision_hash": winner_result.output_hash,
                        "synthesis_candidate_hash": negotiation_finalization["synthesis_candidate_hash"],
                        "synthesis_hash": negotiation_finalization["synthesis_hash"],
                        "fresh_review_ids": list(negotiation_finalization["fresh_review_ids"]),
                        "fresh_review_hashes": list(negotiation_finalization["fresh_review_hashes"]),
                        "old_review_reused": False,
                        "decision": "SELECTED",
                    },)
                    if negotiation_finalization is not None
                    else ()
                ),
                {
                    **selected_fact,
                    "event_type": "selection.committed",
                    "selected_agent_id": winner_agent.agent_id,
                    "selected_output_hash": winner_result.output_hash,
                    "selected_output_ref": winner_result.output_ref,
                    "scorecard_refs": [item.call_id for item in review_results],
                    "frozen_rubric_hash": rubric,
                    "rejected_proposals_ineligible": True,
                    "negotiation_synthesis_hash": (
                        negotiation_finalization["synthesis_hash"]
                        if negotiation_finalization is not None
                        else None
                    ),
                    "fresh_review_hashes": (
                        list(negotiation_finalization["fresh_review_hashes"])
                        if negotiation_finalization is not None
                        else []
                    ),
                },
                close_fact,
            ),
            actor="selection-command-handler",
        )
        return winner_result, winner_agent, results, proposal_decision

    def _debate(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        proposal_stream: CanonicalStream,
        proposal: ProposalRound,
        proposers: Sequence[AgentIdentity],
        results: Sequence[AgentCallResult],
        prior_reviews: Sequence[AgentCallResult],
        reviewer: AgentIdentity,
        rubric: str,
        source_decision: AgentSchedulingDecision,
        risk_level: str,
        overrides: Mapping[str, Any],
    ) -> tuple[
        ProposalRound,
        list[AgentCallResult],
        dict[str, int],
        dict[str, str],
        list[AgentCallResult],
        Mapping[str, Any],
    ]:
        debate_id = "debate-" + stable_hash("TRUE_MULTI_AGENT_DEBATE", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + debate_id
        open_fact = self._protocol_open(evidence, "debate", debate_id, obligation, source_decision.decision_id)
        debate, debate_opened = Debate.open(
            debate_id,
            proposal.round_id,
            max_rounds=int(self.policy["max_negotiation_rounds"]),
            max_tokens=int(self.policy["max_total_tokens_per_run"]),
            deadline="2099-01-01T00:00:00Z",
        )
        claims = ClaimRegistry()
        claim_ids: list[str] = []
        claim_facts: list[dict[str, Any]] = []
        for index, result in enumerate(results, 1):
            claim_id = f"claim-{index}-{proposers[index - 1].agent_id}"
            claims, _, fact = claims.create(
                claim_id,
                proposal.round_id,
                result.output_ref.removeprefix("cas:"),
                (result.output_hash,),
            )
            claim_ids.append(claim_id)
            claim_facts.append(fact)
        critique_results: list[AgentCallResult] = []
        critique_facts: list[dict[str, Any]] = []
        for index, parent in enumerate(results, 1):
            candidates = [
                item
                for item in prior_reviews
                if item.task_id in {f"review-{index}", f"review-revision-{index}"}
            ]
            if not candidates:
                raise DynamicCollaborationError("Negotiation lacks a committed prior Review critique")
            critique = candidates[-1]
            critique_results.append(critique)
            critique_facts.append({
                "schema": "NEGOTIATION_CRITIQUE_SUBMITTED_V1",
                "debate_id": debate_id,
                "round_id": proposal.round_id,
                "generation": proposal.generation,
                "proposal_id": f"proposal-{index}-{proposers[index - 1].agent_id}",
                "proposal_output_hash": parent.output_hash,
                "critique_call_id": critique.call_id,
                "critique_output_hash": critique.output_hash,
                "critique_output_ref": critique.output_ref,
                "critic_agent_id": critique.agent_id,
                "source_event_ids": list(self._recent_event_ids(journal)),
            })
        _, opening_refs = proposal_stream.append(
            "debate-opened",
            (
                open_fact,
                debate_opened,
                {
                    **debate_opened,
                    "schema": "NEGOTIATION_ROUND_OPENED_V1",
                    "round_id": proposal.round_id,
                    "generation": proposal.generation,
                    "participants": [item.agent_id for item in proposers],
                    "eligible_agent_ids": [item.agent_id for item in proposers],
                    "rubric_hash": rubric,
                    "policy_hash": self.policy_hash,
                    "maximum_responses": len(proposers),
                    "maximum_revisions": int(self.policy["max_rework_rounds"]),
                    "token_budget": int(self.policy["max_total_tokens_per_run"]),
                    "source_event_ids": list(self._recent_event_ids(journal)),
                    "parent_revision_hashes": [item.output_hash for item in results],
                },
                *claim_facts,
                *critique_facts,
            ),
            actor="debate-command-handler",
        )
        critique_event_refs = opening_refs[-len(critique_facts):]
        revised_results: list[AgentCallResult] = []
        response_facts: list[dict[str, Any]] = []
        for index, (agent, parent) in enumerate(zip(proposers, results, strict=True)):
            target = results[(index + 1) % len(results)]
            critique = critique_results[index]
            _, request_refs = proposal_stream.append(
                "negotiation-clarification-and-revision-requested",
                ({
                    "schema": "NEGOTIATION_CLARIFICATION_REQUESTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": proposal.generation,
                    "request_id": f"clarification-{index + 1}-{agent.agent_id}",
                    "proposal_id": f"proposal-{index + 1}-{agent.agent_id}",
                    "parent_output_hash": parent.output_hash,
                    "target_output_hash": target.output_hash,
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                }, {
                    "schema": "NEGOTIATION_REVISION_REQUESTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": proposal.generation,
                    "request_id": f"revision-request-{index + 1}-{agent.agent_id}",
                    "proposal_id": f"proposal-{index + 1}-{agent.agent_id}",
                    "parent_output_hash": parent.output_hash,
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                    "maximum_revision": int(self.policy["max_rework_rounds"]),
                }),
                actor="negotiation-command-handler",
            )

            def validate_revision(value: Mapping[str, Any]) -> None:
                _require_string(value, "summary")
                _require_string(value, "parent_output_hash")
                _require_response_items(value, "responses_to_objections", maximum=8)
                _require_json_array_or_strings(value, "acceptance_checks", maximum=8)

            revised = self._call(
                executor,
                evidence,
                agent,
                task_id=f"negotiation-round-2-{index + 1}",
                kind="proposal",
                contract=(
                    "Submit a concise second-round revision with summary, exact parent_output_hash, "
                    "responses_to_objections as exactly four short JSON strings, and acceptance_checks as exactly four "
                    "short JSON strings. Combine related objections and requirements inside those four strings; never "
                    "return more than four items in either array and never return objects."
                ),
                prompt=(
                    f"Round 2. Your parent output hash is {parent.output_hash}. Peer output hash is {target.output_hash}. "
                    f"The independent critique hash is {critique.output_hash}. Critique: "
                    + json.dumps(dict(critique.value), ensure_ascii=False, sort_keys=True)
                    + ". Respond to concrete differences and every critique defect concisely. Return every required "
                    "field; responses_to_objections and acceptance_checks each contain exactly four short strings, "
                    "never objects. Consolidate all requirements into those four checks rather than listing one check "
                    "per goal clause. "
                    "Peer proposal: " + json.dumps(dict(target.value), ensure_ascii=False, sort_keys=True)
                ),
                context={
                    "debate_id": debate_id,
                    "round": 2,
                    "parent_output_hash": parent.output_hash,
                    "parent_output_ref": parent.output_ref,
                    "target_output_hash": target.output_hash,
                    "target_output_ref": target.output_ref,
                    "critique_event_id": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                    "critique_output_ref": critique.output_ref,
                    "clarification_request_event_id": request_refs[0]["event_id"],
                    "revision_request_event_id": request_refs[1]["event_id"],
                    "source_event_ids": list(self._recent_event_ids(journal)),
                },
                validate=validate_revision,
            )
            if str(revised.value["parent_output_hash"]) != parent.output_hash:
                raise DynamicCollaborationError("negotiation round 2 did not bind the exact parent output hash")
            if revised.output_hash == parent.output_hash:
                raise DynamicCollaborationError("negotiation round 2 reused the round 1 output hash")
            debate, _, response = debate.respond(
                claims,
                f"debate-response-{index + 1}",
                claim_ids[index],
                claim_ids[(index + 1) % len(claim_ids)],
                agent.agent_id,
                2,
                int(revised.usage["total_tokens"]),
                revised.output_ref.removeprefix("cas:"),
                now=now_rfc3339(),
            )
            response_facts.append(
                {
                    **response,
                    "event_type": "debate.response",
                    "parent_output_hash": parent.output_hash,
                    "revision_output_hash": revised.output_hash,
                    "revision_call_id": revised.call_id,
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "critique_output_hash": critique.output_hash,
                }
            )
            transition_hash = stable_hash(
                "TRUE_MULTI_AGENT_NEGOTIATION_TRANSITION",
                {
                    "parent_output_hash": parent.output_hash,
                    "target_output_hash": target.output_hash,
                    "critique_output_hash": critique.output_hash,
                    "revision_output_hash": revised.output_hash,
                },
            )
            if revised.output_hash in {item.output_hash for item in revised_results}:
                raise DynamicCollaborationError("negotiation stalled on a duplicate revision output hash")
            proposal_stream.append(
                "negotiation-peer-response-and-revision-submitted",
                ({
                    "schema": "NEGOTIATION_PEER_RESPONSE_SUBMITTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": 2,
                    "response_id": f"peer-response-{index + 1}-{agent.agent_id}",
                    "actor_id": agent.agent_id,
                    "parent_output_hash": parent.output_hash,
                    "target_output_hash": target.output_hash,
                    "critique_output_hash": critique.output_hash,
                    "revision_output_hash": revised.output_hash,
                    "revision_output_ref": revised.output_ref,
                    "transition_hash": transition_hash,
                }, {
                    "schema": "NEGOTIATION_CLARIFICATION_SUBMITTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": 2,
                    "request_event_ref": request_refs[0]["event_id"],
                    "actor_id": agent.agent_id,
                    "parent_output_hash": parent.output_hash,
                    "clarification_output_hash": revised.output_hash,
                }, {
                    "schema": "NEGOTIATION_PROPOSAL_REVISION_SUBMITTED_V1",
                    "debate_id": debate_id,
                    "round_id": proposal.round_id,
                    "generation": 2,
                    "proposal_id": f"proposal-{index + 1}-{agent.agent_id}",
                    "revision": 1,
                    "revision_author_id": agent.agent_id,
                    "parent_output_hash": parent.output_hash,
                    "revision_output_hash": revised.output_hash,
                    "revision_output_ref": revised.output_ref,
                    "body_ref": revised.output_ref.removeprefix("cas:"),
                    "critique_event_ref": critique_event_refs[index]["event_id"],
                    "old_review_reused": False,
                    "transition_hash": transition_hash,
                }),
                actor=agent.agent_id,
            )
            revised_results.append(revised)
        evidence_map = {
            claim_id: (results[index].output_hash, revised_results[index].output_hash)
            for index, claim_id in enumerate(claim_ids)
        }
        negotiation_response_facts = tuple(response_facts)
        next_round, generation_opened = proposal.new_generation(
            participants=tuple(item.agent_id for item in proposers),
            evaluators=(reviewer.agent_id,),
            rubric_hash=rubric,
            policy_hash=self.policy_hash,
            deadline="2099-01-01T00:00:00Z",
            minimum_score=int(self.policy["proposal_minimum_score"]),
            max_revisions=int(self.policy["max_rework_rounds"]),
        )
        proposal_ids: list[str] = []
        round_two_submission_facts: list[dict[str, Any]] = []
        for index, (agent, revised) in enumerate(zip(proposers, revised_results, strict=True), 1):
            proposal_id = f"proposal-{index}-{agent.agent_id}"
            proposal_ids.append(proposal_id)
            next_round, _, submitted = next_round.submit(
                proposal_id,
                agent.agent_id,
                revised.output_ref.removeprefix("cas:"),
            )
            round_two_submission_facts.append(
                {
                    **submitted,
                    "event_type": "proposal.round-2.submitted",
                    "parent_generation": proposal.generation,
                    "parent_output_hash": results[index - 1].output_hash,
                    "revision_output_hash": revised.output_hash,
                    "old_review_reused": False,
                }
            )
        synthesizer_id = "debate-synthesis-command-handler"
        debate, synthesis_submitted = debate.submit_synthesis(
            claims,
            evidence_map=evidence_map,
            synthesizer_id=synthesizer_id,
        )
        proposal_stream.append(
            "negotiation-generation-2-and-synthesis-submitted",
            (
                *negotiation_response_facts,
                {
                    **generation_opened,
                    "event_type": "negotiation.round.opened",
                    "eligible_agent_ids": [item.agent_id for item in proposers],
                    "maximum_responses": len(proposers),
                    "maximum_revisions": int(self.policy["max_rework_rounds"]),
                    "token_budget": int(self.policy["max_total_tokens_per_run"]),
                    "source_event_ids": list(self._recent_event_ids(journal)),
                    "parent_revision_hashes": [item.output_hash for item in results],
                },
                {
                    "schema": "NEGOTIATION_ROUND_OPENED_V1",
                    "debate_id": debate_id,
                    "target_id": next_round.round_id,
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "participants": [item.agent_id for item in proposers],
                    "eligible_agent_ids": [item.agent_id for item in proposers],
                    "rubric_hash": rubric,
                    "policy_hash": self.policy_hash,
                    "deadline": next_round.deadline,
                    "max_rounds": int(self.policy["max_negotiation_rounds"]),
                    "max_tokens": int(self.policy["max_total_tokens_per_run"]),
                    "maximum_responses": len(proposers),
                    "maximum_revisions": int(self.policy["max_rework_rounds"]),
                    "token_budget": int(self.policy["max_total_tokens_per_run"]),
                    "source_event_ids": list(self._recent_event_ids(journal)),
                    "parent_revision_hashes": [item.output_hash for item in results],
                },
                *round_two_submission_facts,
                synthesis_submitted,
            ),
            actor=synthesizer_id,
        )
        scores: dict[str, int] = {}
        dispositions: dict[str, str] = {}
        reviews: list[AgentCallResult] = []
        fresh_review_ids: list[str] = []
        fresh_review_hashes: list[str] = []
        authors = {item.agent_id for item in proposers}
        if reviewer.agent_id in authors or reviewer.agent_id == synthesizer_id:
            raise DynamicCollaborationError("fresh Reviewer is not independent of author and synthesizer")
        normalized_goal = evidence.goal.casefold()
        semantic_no_consensus_required = any(
            marker in normalized_goal
            for marker in (
                "do not select a compromise",
                "must not select a compromise",
                "formal no consensus",
                "create a successor obligation if unresolved",
                "不可选择折中方案",
                "正式无共识",
            )
        )
        for index, revised in enumerate(revised_results):
            author = proposers[index]
            fresh_review_id = "fresh-review-" + stable_hash(
                "TRUE_MULTI_AGENT_NEGOTIATION_FRESH_REVIEW",
                {
                    "run_id": evidence.run_id,
                    "debate_id": debate_id,
                    "proposal_id": proposal_ids[index],
                    "revision_output_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                },
            )[:36]
            fresh_review, fresh_requested = ReviewRequest.open(
                fresh_review_id,
                revised.output_ref.removeprefix("cas:"),
                author.agent_id,
                rubric,
                quorum=1,
                high_risk=risk_level == "high",
                security_review_required=risk_level == "high",
            )
            proposal_stream.append(
                "negotiation-fresh-review-requested",
                ({
                    **fresh_requested,
                    "schema": "NEGOTIATION_FRESH_REVIEW_REQUESTED_V1",
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "proposal_id": proposal_ids[index],
                    "latest_revision_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "reviewer_id": reviewer.agent_id,
                    "reviewer_independent_from_author": reviewer.agent_id != author.agent_id,
                    "reviewer_independent_from_synthesizer": reviewer.agent_id != synthesizer_id,
                    "old_review_reused": False,
                },),
                actor="fresh-review-command-handler",
            )

            def validate_final(value: Mapping[str, Any]) -> None:
                verdict = _require_string(value, "verdict").lower()
                if verdict not in {"approved", "changes_requested", "reject"}:
                    raise DynamicCollaborationError("final debate Review verdict is invalid")
                score = value.get("score")
                if not isinstance(score, int) or not 0 <= score <= 100:
                    raise DynamicCollaborationError("final debate Review score is invalid")
                if verdict == "approved" and score < int(self.policy["proposal_minimum_score"]):
                    raise DynamicCollaborationError("approved final debate Review is below threshold")
                _require_string(value, "reason")
                _require_strings(value, "defects", minimum=0, maximum=8)

            review = self._call(
                executor,
                evidence,
                reviewer,
                task_id=f"debate-final-review-{index + 1}",
                kind="review",
                contract=(
                    "Independently evaluate the exact round-2 revision as a playbook specification, not as an already "
                    "executed migration. Return verdict as approved, changes_requested, or reject; integer score "
                    "0-100; non-empty reason; and defects as a JSON array of zero to eight strings. Do not require "
                    "post-execution logs, completed implementation artifacts, or already-passed tests at this planning stage."
                ),
                prompt=(
                    f"Review round-2 revision hash {revised.output_hash}, parent hash {results[index].output_hash}. "
                    f"Frozen rubric {rubric}. Approve if the revision resolves the peer objections, supplies concrete "
                    "testable conditions tied to named internal evidence that the playbook requires execution to produce, "
                    "and otherwise meets the rubric. Evaluate specification completeness; do not demand evidence that "
                    "the future cutover, implementation, or tests have already run. "
                    "At the final bounded round, unresolved defects mean changes_requested or reject and therefore NO_CONSENSUS; "
                    f"the runtime will not force success. Required shape: {{\"agent_id\":\"{reviewer.agent_id}\",\"kind\":\"review\","
                    "\"verdict\":\"approved\",\"score\":85,\"reason\":\"...\",\"defects\":[]}. Revision: "
                    + json.dumps(dict(revised.value), ensure_ascii=False, sort_keys=True)
                ),
                context={
                    "debate_id": debate_id,
                    "proposal_id": proposal_ids[index],
                    "proposal_generation": next_round.generation,
                    "author_agent_id": author.agent_id,
                    "reviewer_independence": reviewer.agent_id != author.agent_id,
                    "synthesizer_id": synthesizer_id,
                    "reviewer_independent_from_synthesizer": reviewer.agent_id != synthesizer_id,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "old_review_reused": False,
                },
                validate=validate_final,
            )
            score = int(review.value["score"])
            provider_verdict = str(review.value["verdict"]).lower()
            effective_verdict = provider_verdict
            if (
                bool(overrides.get("force_negotiation_no_consensus"))
                or semantic_no_consensus_required
            ) and index == 0:
                effective_verdict = "reject"
            evaluation_disposition = "ACCEPT" if effective_verdict == "approved" else "REJECT"
            fresh_review, fresh_response = fresh_review.respond(
                reviewer.agent_id,
                tuple(reviewer.capabilities),
                False,
                {
                    "approved": ReviewVerdict.ACCEPT,
                    "changes_requested": ReviewVerdict.NEEDS_CHANGES,
                    "reject": ReviewVerdict.REJECT,
                }[effective_verdict],
                review.output_ref.removeprefix("cas:"),
            )
            fresh_review, fresh_disposition = fresh_review.dispose()
            next_round, evaluated = next_round.evaluate(
                proposal_ids[index], reviewer.agent_id, score=score, disposition=evaluation_disposition
            )
            proposal_stream.append(
                "negotiation-fresh-review-submitted",
                ({
                    **fresh_response,
                    "schema": "NEGOTIATION_FRESH_REVIEW_SUBMITTED_V1",
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "proposal_id": proposal_ids[index],
                    "latest_revision_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "fresh_review_output_hash": review.output_hash,
                    "fresh_review_output_ref": review.output_ref,
                    "fresh_review_call_id": review.call_id,
                    "provider_verdict": provider_verdict,
                    "effective_verdict": effective_verdict,
                    "old_review_reused": False,
                }, {
                    **fresh_disposition,
                    "schema": "NEGOTIATION_FRESH_REVIEW_DISPOSITION_V1",
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "proposal_id": proposal_ids[index],
                    "latest_revision_hash": revised.output_hash,
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                }, {
                    **evaluated,
                    "event_type": "proposal.round-2.evaluated",
                    "review_call_id": review.call_id,
                    "review_output_hash": review.output_hash,
                    "provider_verdict": provider_verdict,
                    "effective_verdict": effective_verdict,
                    "old_review_reused": False,
                }),
                actor=reviewer.agent_id,
            )
            scores[proposal_ids[index]] = score
            dispositions[proposal_ids[index]] = evaluation_disposition
            reviews.append(review)
            fresh_review_ids.append(fresh_review_id)
            fresh_review_hashes.append(review.output_hash)
        unresolved = tuple(
            claim_ids[index]
            for index, proposal_id in enumerate(proposal_ids)
            if dispositions[proposal_id] != "ACCEPT"
        )
        included = tuple(claim_id for claim_id in claim_ids if claim_id not in unresolved)
        outcome = DebateOutcome.NO_CONSENSUS if unresolved else DebateOutcome.CONSENSUS
        debate, synthesis = debate.finalize(
            claims,
            included=included,
            excluded=(),
            unresolved=unresolved,
            evidence_map=evidence_map,
            outcome=outcome,
        )
        close_fact = self._protocol_close(
            evidence,
            debate_id,
            obligation,
            outcome.value,
            successor=debate.successor_obligation_id,
        )
        finalization_facts: list[dict[str, Any]] = [synthesis]
        no_consensus_decision_id = None
        if outcome is DebateOutcome.NO_CONSENSUS:
            no_consensus_decision_id = "negotiation-no-consensus-" + stable_hash(
                "TRUE_MULTI_AGENT_NEGOTIATION_NO_CONSENSUS",
                {
                    "run_id": evidence.run_id,
                    "debate_id": debate_id,
                    "synthesis_hash": debate.synthesis_hash,
                    "fresh_review_hashes": fresh_review_hashes,
                    "unresolved": list(unresolved),
                },
            )[:36]
            finalization_facts.extend((
                {
                    "schema": "NEGOTIATION_NO_CONSENSUS_DECIDED_V1",
                    "decision_id": no_consensus_decision_id,
                    "round_id": next_round.round_id,
                    "generation": next_round.generation,
                    "debate_id": debate_id,
                    "latest_revision_hashes": [item.output_hash for item in revised_results],
                    "synthesis_candidate_hash": debate.synthesis_candidate_hash,
                    "synthesis_hash": debate.synthesis_hash,
                    "fresh_review_ids": fresh_review_ids,
                    "fresh_review_hashes": fresh_review_hashes,
                    "unresolved_claim_ids": list(unresolved),
                    "successor_obligation_id": debate.successor_obligation_id,
                    "admission_error_used_as_no_consensus": False,
                    "decision": "NO_CONSENSUS",
                },
                {
                    "schema": "SUCCESSOR_OBLIGATION_CREATED_V1",
                    "obligation_id": debate.successor_obligation_id,
                    "source_protocol_id": debate_id,
                    "source_decision_id": no_consensus_decision_id,
                    "reason": "NEGOTIATION_BOUNDED_NO_CONSENSUS",
                },
            ))
        finalization_facts.append(close_fact)
        proposal_stream.append(
            "negotiation-finalized",
            tuple(finalization_facts),
            actor=reviewer.agent_id,
        )
        if outcome is DebateOutcome.NO_CONSENSUS:
            dispositions = {proposal_id: "REJECT" for proposal_id in proposal_ids}
        return next_round, revised_results, scores, dispositions, reviews, {
            "outcome": outcome.value,
            "debate_id": debate_id,
            "synthesis_candidate_hash": debate.synthesis_candidate_hash,
            "synthesis_hash": debate.synthesis_hash,
            "fresh_review_ids": tuple(fresh_review_ids),
            "fresh_review_hashes": tuple(fresh_review_hashes),
            "successor_obligation_id": debate.successor_obligation_id,
            "no_consensus_decision_id": no_consensus_decision_id,
        }

    def _arbitrate(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        proposals: Sequence[AgentCallResult],
        winner: AgentCallResult,
        winner_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
    ) -> None:
        if len(proposals) < 2:
            raise DynamicCollaborationError("Arbitration requires at least two independently submitted Proposals")
        _, arbiters = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="arbitration",
            required_capabilities=("arbitration", "review"),
            slots=1,
            candidate_tasks=("arbitration",),
            author_conflicts=tuple(item.agent_id for item in proposals),
            overrides=overrides,
        )
        arbiter = arbiters[0]
        losing = next(item for item in proposals if item.output_hash != winner.output_hash)

        def validate(value: Mapping[str, Any]) -> None:
            decision = _require_string(value, "decision").lower()
            if decision not in {"prefer_winner", "merge", "reject_both"}:
                raise DynamicCollaborationError("Arbitration decision is invalid")
            blocked = _require_string(value, "blocked_output_hash")
            if blocked not in {item.output_hash for item in proposals}:
                raise DynamicCollaborationError("Arbitration blocked hash is outside the frozen evidence window")
            _require_string(value, "reason")

        result = self._call(
            executor,
            evidence,
            arbiter,
            task_id="arbitration",
            kind="review",
            contract="Resolve the frozen technical dispute; return decision, blocked_output_hash, and reason. The binding result will be enforced separately.",
            prompt=(
                f"Resolve this goal's technical dispute. Winner selected by Review is {winner.output_hash}; competing output is {losing.output_hash}. "
                "Return decision prefer_winner or merge, and block the losing output hash. Evidence window: "
                + json.dumps(
                    [{"agent_id": item.agent_id, "output_hash": item.output_hash, "proposal": dict(item.value)} for item in proposals],
                    ensure_ascii=False,
                    sort_keys=True,
                )
            ),
            context={
                "evidence_window": [item.output_hash for item in proposals],
                "winner_output_hash": winner.output_hash,
                "winner_agent_id": winner_agent.agent_id,
                "conflict_of_interest_policy": "arbiter_must_not_be_proposal_author",
                "appeal_policy": "one_new-evidence-generation",
            },
            validate=validate,
        )
        if result.value["blocked_output_hash"] == winner.output_hash:
            raise DynamicCollaborationError("Arbitration contradicted the frozen independent Review without new evidence")
        arbitration_id = "arbitration-" + stable_hash("TRUE_MULTI_AGENT_ARBITRATION", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + arbitration_id
        open_fact = self._protocol_open(evidence, "arbitration", arbitration_id, obligation, source_decision.decision_id)
        arbitration, opened = Arbitration.open(
            arbitration_id,
            obligation,
            self.policy_hash,
            max_appeals=1,
            appeal_deadline="2099-01-01T00:00:00Z",
            appeal_authorities=(arbiter.agent_id,),
        )
        claim_ids = tuple(f"claim-proposal-{index + 1}" for index in range(len(proposals)))
        arbitration, admitted = arbitration.admit(claim_ids, arbiter.agent_id)
        blocked_target = "proposal-target-" + str(result.value["blocked_output_hash"])[:24]
        arbitration, decided = arbitration.decide(
            str(result.value["decision"]).upper(),
            binding_scope=(blocked_target,),
            evidence_refs=tuple(item.output_hash for item in proposals),
        )
        if not arbitration.blocks_dispatch(blocked_target):
            raise DynamicCollaborationError("Arbitration Decision did not bind Dispatcher eligibility")
        enforcement_ref = stable_hash(
            "TRUE_MULTI_AGENT_ARBITRATION_ENFORCEMENT",
            {"arbitration_id": arbitration_id, "blocked_target": blocked_target, "decision_output_hash": result.output_hash},
        )
        arbitration, enforced = arbitration.enforce(enforcement_ref)
        close_fact = self._protocol_close(evidence, arbitration_id, obligation, "ENFORCED")
        stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/arbitration/{arbitration_id}",
            self.policy_hash,
        )
        stream.append(
            "arbitration-enforced",
            (
                open_fact,
                opened,
                {
                    "schema": "ARBITRATION_EVIDENCE_WINDOW_FROZEN_V1",
                    "arbitration_id": arbitration_id,
                    "evidence_refs": [item.output_hash for item in proposals],
                    "claims": list(claim_ids),
                    "decision_rule": "INDEPENDENT_REVIEW_PLUS_ARBITER_EVIDENCE",
                    "conflict_of_interest_policy": "ARBITER_NOT_AUTHOR",
                    "appeal_policy": "NEW_EVIDENCE_ONLY_MAX_ONE",
                },
                admitted,
                {**decided, "event_type": "arbitration.decided", "arbiter_call_id": result.call_id, "arbiter_output_hash": result.output_hash},
                {
                    "schema": "DISPATCH_CANDIDATE_FILTERED_BY_ARBITRATION_V1",
                    "event_type": "dispatch.candidate.filtered",
                    "arbitration_id": arbitration_id,
                    "blocked_target": blocked_target,
                    "blocked_output_hash": result.value["blocked_output_hash"],
                    "reason_code": "BINDING_ARBITRATION_BLOCK",
                    "removed_from_candidate_set": True,
                },
                {**enforced, "event_type": "arbitration.enforced"},
                close_fact,
            ),
            actor=arbiter.agent_id,
        )

    def _blackboard_pre_gap_closure(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        winner: AgentCallResult,
        winner_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
    ) -> None:
        _, writers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="blackboard-continuation",
            required_capabilities=("blackboard-write",),
            slots=1,
            candidate_tasks=("blackboard-continuation", "blackboard-conflict-resolution"),
            exclusions=(winner_agent.agent_id,),
            overrides=overrides,
        )
        writer_b = writers[0]
        board_id = "blackboard-" + stable_hash("TRUE_MULTI_AGENT_BLACKBOARD", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + board_id
        open_fact = self._protocol_open(evidence, "blackboard", board_id, obligation, source_decision.decision_id)
        policy = NamespacePolicy(
            stable_hash("TRUE_MULTI_AGENT_BLACKBOARD_SCHEMA", {"fields": ["decision", "rationale", "continuation"]}),
            ("blackboard-write",),
            True,
            "ARBITRATION",
            "controlled-read-only",
            4096,
        )
        board = Blackboard({BlackboardNamespace.DECISIONS: policy})
        document, created = board.create(board_id, BlackboardNamespace.DECISIONS)
        task = TaskAggregate("blackboard-task-" + evidence.run_id, stable_hash("TRUE_MULTI_AGENT_BLACKBOARD_TASK", {"run": evidence.run_id}))
        task, attempt, claim = task.claim(
            claim_command_id="claim-blackboard-" + evidence.run_id,
            lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id="blackboard-command-handler",
            expected_stream_version=task.stream_version,
        )
        initial_read = {
            "document_id": document.document_id,
            "version": document.version,
            "document_hash": document.document_hash,
        }
        intent_a = PatchIntent(
            document.document_id,
            document.version,
            document.document_hash,
            {"decision": winner.output_hash, "rationale": "selected proposal"},
            winner_agent.agent_id,
            ("blackboard-write",),
            task.task_id,
            attempt.task_attempt_id,
            attempt.claim_generation,
            attempt.fencing_token,
            (winner.output_hash,),
            (document.document_hash,),
        )
        # The selected author may not normally carry blackboard-write. A
        # canonical delegation capability is explicitly bound to this Task.
        intent_a = dataclasses.replace(intent_a, writer_capabilities=("blackboard-write",))
        patched_a = board.patch(intent_a, task=task)
        if patched_a.event is None:
            raise DynamicCollaborationError("Blackboard Patch A failed")

        def validate_continuation(value: Mapping[str, Any]) -> None:
            _require_string(value, "continuation")
            _require_string(value, "read_document_hash")
            version = value.get("read_version")
            if not isinstance(version, int) or version < 1:
                raise DynamicCollaborationError("Blackboard continuation lacks committed read version")

        continuation = self._call(
            executor,
            evidence,
            writer_b,
            task_id="blackboard-continuation",
            kind="proposal",
            contract=(
                "Continue from the exact committed Blackboard version; return continuation, read_version as a JSON "
                "integer without quotes, and read_document_hash as a string."
            ),
            prompt=(
                f"Continue the shared decision after Agent A committed version {patched_a.document.version} hash {patched_a.document.document_hash}. "
                f"Selected proposal output hash is {winner.output_hash}. Return the exact read_version as an unquoted "
                "JSON integer and the exact read_document_hash."
            ),
            context={
                "blackboard_document_id": board_id,
                "read_version": patched_a.document.version,
                "read_document_hash": patched_a.document.document_hash,
                "prior_agent_id": winner_agent.agent_id,
                "prior_output_hash": winner.output_hash,
            },
            validate=validate_continuation,
        )
        if int(continuation.value["read_version"]) != patched_a.document.version:
            raise DynamicCollaborationError("Agent B did not bind the actual Blackboard version")
        if str(continuation.value["read_document_hash"]) != patched_a.document.document_hash:
            raise DynamicCollaborationError("Agent B did not bind the actual Blackboard hash")
        events: list[Mapping[str, Any]] = [open_fact, claim, created, {**patched_a.event, "event_type": "blackboard.patch.committed"}]
        conflict_required = analysis.requires_conflict or bool(overrides.get("force_stale_blackboard_base"))
        if conflict_required:
            stale_intent = PatchIntent(
                document.document_id,
                initial_read["version"],
                initial_read["document_hash"],
                {"decision": continuation.output_hash, "continuation": continuation.value["continuation"]},
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (continuation.output_hash,),
                (initial_read["document_hash"],),
            )
            conflict = board.patch(stale_intent, task=task)
            if conflict.conflict is None or conflict.event is not None:
                raise DynamicCollaborationError("stale Blackboard base did not produce an explicit conflict")
            events.extend(
                (
                    {**conflict.conflict, "event_type": "blackboard.patch.conflict", "agent_id": writer_b.agent_id},
                    {
                        "schema": "BLACKBOARD_LAST_WRITE_WINS_DENIED_V1",
                        "document_id": board_id,
                        "silent_overwrite": False,
                        "blocked_obligations": list(conflict.blocked_obligations),
                    },
                )
            )
            canonical = board.documents[board_id]
            merged_intent = PatchIntent(
                canonical.document_id,
                canonical.version,
                canonical.document_hash,
                {
                    "decision": winner.output_hash,
                    "continuation": continuation.value["continuation"],
                    "resolution": "explicit-merge-after-conflict",
                },
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (winner.output_hash, continuation.output_hash),
                (canonical.document_hash,),
            )
            patched_b = board.patch(merged_intent, task=task)
            if patched_b.event is None:
                raise DynamicCollaborationError("Blackboard conflict resolution did not commit")
            events.append({**patched_b.event, "event_type": "blackboard.conflict.resolved"})
        else:
            canonical = board.documents[board_id]
            intent_b = PatchIntent(
                canonical.document_id,
                canonical.version,
                canonical.document_hash,
                {"continuation": continuation.value["continuation"], "source_output_hash": continuation.output_hash},
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (continuation.output_hash,),
                (canonical.document_hash,),
            )
            patched_b = board.patch(intent_b, task=task)
            if patched_b.event is None:
                raise DynamicCollaborationError("Blackboard Patch B failed")
            events.append({**patched_b.event, "event_type": "blackboard.patch.committed"})
        final = board.documents[board_id]
        close_fact = self._protocol_close(evidence, board_id, obligation, "COMMITTED")
        events.extend(
            (
                {
                    "schema": "BLACKBOARD_FINAL_VERSION_REFERENCED_V1",
                    "document_id": board_id,
                    "committed_version": final.version,
                    "document_hash": final.document_hash,
                    "agent_b_call_id": continuation.call_id,
                    "agent_b_input_snapshot_hash": continuation.input_snapshot_hash,
                },
                close_fact,
            )
        )
        CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/blackboard/{board_id}",
            self.policy_hash,
        ).append("blackboard-closed", tuple(events), actor="blackboard-command-handler")

    def _blackboard(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        winner: AgentCallResult,
        winner_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
        *,
        primary_writer: AgentIdentity | None = None,
        leased_task: TaskAggregate | None = None,
    ) -> Mapping[str, Any]:
        if primary_writer is None:
            writer_decision, writers = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-concurrent-writers",
                required_capabilities=("blackboard-write",),
                slots=2,
                candidate_tasks=("blackboard-branch-a", "blackboard-branch-b"),
                overrides=overrides,
            )
            if len(writers) != 2 or writers[0].agent_id == writers[1].agent_id:
                raise DynamicCollaborationError("Blackboard requires two independently scheduled writers")
            writer_a, writer_b = writers
        else:
            writer_decision, collaborators = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-concurrent-collaborator",
                required_capabilities=("blackboard-write",),
                slots=1,
                candidate_tasks=("blackboard-stale-branch", "blackboard-conflict-merge"),
                exclusions=(primary_writer.agent_id,),
                overrides=overrides,
            )
            writer_a = dataclasses.replace(
                primary_writer,
                capabilities=tuple(sorted(set(primary_writer.capabilities).union({"blackboard-write"}))),
            )
            writer_b = collaborators[0]
        board_id = "blackboard-" + stable_hash("TRUE_MULTI_AGENT_BLACKBOARD", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + board_id
        open_fact = self._protocol_open(evidence, "blackboard", board_id, obligation, writer_decision.decision_id)
        schema_hash = stable_hash(
            "TRUE_MULTI_AGENT_BLACKBOARD_SCHEMA",
            {"fields": ["decision", "rationale", "continuation", "resolution"]},
        )
        merge_policy_hash = stable_hash(
            "TRUE_MULTI_AGENT_BLACKBOARD_MERGE_POLICY",
            {"policy": "ARBITRATION", "schema_hash": schema_hash, "generation": 1},
        )
        writer_policy_hash = stable_hash(
            "TRUE_MULTI_AGENT_BLACKBOARD_WRITER_POLICY",
            {"capability": "blackboard-write", "task_fence_required": True, "generation": 1},
        )
        policy = NamespacePolicy(
            schema_hash,
            ("blackboard-write",),
            True,
            "ARBITRATION",
            "controlled-read-only",
            4096,
            schema_id="sitina.blackboard.decision",
            schema_version=1,
            writer_policy_hash=writer_policy_hash,
            merge_policy_hash=merge_policy_hash,
            cas_required=True,
        )
        board = Blackboard({BlackboardNamespace.DECISIONS: policy})
        document, created = board.create(board_id, BlackboardNamespace.DECISIONS)
        board.declare_dependencies(obligation, (board_id,))
        if leased_task is None:
            task = TaskAggregate(
                "blackboard-task-" + evidence.run_id,
                stable_hash("TRUE_MULTI_AGENT_BLACKBOARD_TASK", {"run": evidence.run_id}),
            )
            task, attempt, claim = task.claim(
                claim_command_id="claim-blackboard-" + evidence.run_id,
                lease_expires_at="2099-01-01T00:00:00Z",
                holder_agent_id="blackboard-command-handler",
                expected_stream_version=task.stream_version,
            )
        else:
            task = leased_task
            attempt = task.active_attempt
            if attempt is None or attempt.holder_agent_id != primary_writer.agent_id:
                raise DynamicCollaborationError("integrated Blackboard requires the selected Agent's active Task Lease")
            claim = {
                "schema": "INTEGRATED_BLACKBOARD_TASK_FENCE_BOUND_V1",
                "event_type": "blackboard.task-fence.bound",
                "task_id": task.task_id,
                "task_attempt_id": attempt.task_attempt_id,
                "holder_agent_id": attempt.holder_agent_id,
                "claim_generation": attempt.claim_generation,
                "lease_id": attempt.lease_id,
                "fencing_token": attempt.fencing_token,
                "task_scoped_writer_delegation": [writer_b.agent_id],
                "selected_executor_is_primary_writer": True,
            }
        stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"blackboard/{board_id}",
            self.policy_hash,
        )
        stream.append(
            "blackboard-document-created",
            (
                open_fact,
                {
                    **claim,
                    "event_type": "blackboard.task.claimed",
                    "holder_agent_ids": [writer_a.agent_id, writer_b.agent_id],
                    "task_id": task.task_id,
                },
                {**created, "event_type": "blackboard.document.created"},
            ),
            actor="blackboard-command-handler",
        )
        conflict_required = analysis.requires_conflict or bool(overrides.get("force_stale_blackboard_base"))

        def validate_writer(value: Mapping[str, Any]) -> None:
            version = value.get("read_version")
            if not isinstance(version, int) or version < 0:
                raise DynamicCollaborationError("Blackboard writer lacks a valid read_version")
            _require_string(value, "read_document_hash")
            patch = value.get("patch")
            if not isinstance(patch, dict) or not patch or len(patch) > 12:
                raise DynamicCollaborationError("Blackboard writer requires a bounded Patch object")
            _require_string(value, "write_rationale")

        read_a_document, read_a = board.read(
            board_id,
            agent_id=writer_a.agent_id,
            read_paths=("/decision", "/rationale"),
            source_event_refs=tuple(self._recent_event_ids(journal)),
        )
        _, read_a_refs = stream.append(
            "blackboard-read-a",
            ({**read_a, "event_type": "blackboard.document.read"},),
            actor=writer_a.agent_id,
        )

        if conflict_required:
            read_b_document, read_b = board.read(
                board_id,
                agent_id=writer_b.agent_id,
                read_paths=("/decision", "/rationale"),
                source_event_refs=tuple(item["event_id"] for item in read_a_refs),
            )
            _, read_b_refs = stream.append(
                "blackboard-read-b-shared-base",
                ({**read_b, "event_type": "blackboard.document.read"},),
                actor=writer_b.agent_id,
            )
            if (
                read_a_document.version != read_b_document.version
                or read_a_document.document_hash != read_b_document.document_hash
            ):
                raise DynamicCollaborationError("Blackboard writers did not read the same canonical base")
        else:
            read_b = {}
            read_b_refs = ()

        writer_a_result = self._call(
            executor,
            evidence,
            writer_a,
            task_id="blackboard-branch-a",
            kind="proposal",
            contract=(
                "Read the exact Blackboard version in the input and return read_version, read_document_hash, "
                "a bounded patch object, and write_rationale. The Patch is a business-state proposal, not an Event. "
                "read_version must be a JSON integer without quotes and read_document_hash must be copied byte-for-byte "
                "from shared_context.read_document_hash as the same 64 lowercase hexadecimal characters; verify every "
                "character and never retype, shorten, or transform it. "
                "Keep patch to at most four scalar string fields, keep every string under 240 characters, and do not "
                "restate the full goal or emit nested packages, arrays, Markdown, or surrounding prose."
            ),
            prompt=(
                f"Create branch A for the shared decision record supporting this goal: {evidence.goal}. "
                f"Read version {read_a_document.version} hash {read_a_document.document_hash}. "
                f"Return read_version as the unquoted JSON integer {read_a_document.version}. Return no floating point "
                "values, do not invent committed versions, and summarize only the branch's "
                "distinct decision and rationale in the compact patch."
            ),
            context={
                "document_id": board_id,
                "read_id": read_a["read_id"],
                "read_event_id": read_a_refs[-1]["event_id"],
                "read_version": read_a_document.version,
                "read_document_hash": read_a_document.document_hash,
                "selected_proposal_hash": winner.output_hash,
            },
            validate=validate_writer,
        )
        if (
            int(writer_a_result.value["read_version"]) != read_a_document.version
            or str(writer_a_result.value["read_document_hash"]) != read_a_document.document_hash
        ):
            raise DynamicCollaborationError("Blackboard Agent A output did not bind its actual read base")

        if conflict_required:
            writer_b_result = self._call(
                executor,
                evidence,
                writer_b,
                task_id="blackboard-branch-b",
                kind="proposal",
                contract=(
                    "Independently read the exact Blackboard base in the input and return read_version, "
                    "read_document_hash, a bounded patch object, and write_rationale. Do not copy branch A. "
                    "read_version must be a JSON integer without quotes and read_document_hash must be copied byte-for-byte "
                    "from shared_context.read_document_hash as the same 64 lowercase hexadecimal characters; verify every "
                    "character and never retype, shorten, or transform it. "
                    "Keep patch to at most four scalar string fields, keep every string under 240 characters, and do not "
                    "restate the full goal or emit nested packages, arrays, Markdown, or surrounding prose."
                ),
                prompt=(
                    f"Create an independent branch B for this business goal: {evidence.goal}. "
                    f"Your shared base is version {read_b_document.version} hash {read_b_document.document_hash}. "
                    f"Return read_version as the unquoted JSON integer {read_b_document.version}. Return no floating "
                    "point values, do not claim that the Patch was committed, and summarize only "
                    "the branch's distinct decision and rationale in the compact patch."
                ),
                context={
                    "document_id": board_id,
                    "read_id": read_b["read_id"],
                    "read_event_id": read_b_refs[-1]["event_id"],
                    "read_version": read_b_document.version,
                    "read_document_hash": read_b_document.document_hash,
                    "selected_proposal_hash": winner.output_hash,
                },
                validate=validate_writer,
            )
            if (
                int(writer_b_result.value["read_version"]) != read_b_document.version
                or str(writer_b_result.value["read_document_hash"]) != read_b_document.document_hash
            ):
                raise DynamicCollaborationError("Blackboard Agent B output did not bind its actual read base")
        else:
            writer_b_result = None

        patch_a = dict(writer_a_result.value["patch"])
        patch_a_receipt = executor._publish(patch_a, purpose="true-multi-agent-blackboard-patch")
        intent_a = PatchIntent(
            board_id,
            read_a_document.version,
            read_a_document.document_hash,
            patch_a,
            writer_a.agent_id,
            ("blackboard-write",),
            task.task_id,
            attempt.task_attempt_id,
            attempt.claim_generation,
            attempt.fencing_token,
            (winner.output_hash, writer_a_result.output_hash),
            (read_a["read_id"], read_a_refs[-1]["event_id"]),
            patch_ref=patch_a_receipt.object_ref.reference_id,
            target_paths=("/decision", "/rationale"),
            merge_policy_hash=merge_policy_hash,
        )
        patched_a = board.patch(intent_a, task=task, published_object_receipt=patch_a_receipt)
        if patched_a.event is None:
            raise DynamicCollaborationError("Blackboard Patch A failed")
        _, patch_a_refs = stream.append(
            "blackboard-patch-a-committed",
            ({
                **patched_a.event,
                "event_type": "blackboard.patch.committed",
                "agent_call_id": writer_a_result.call_id,
                "agent_input_snapshot_hash": writer_a_result.input_snapshot_hash,
                "agent_output_hash": writer_a_result.output_hash,
                "_object_refs": [patch_a_receipt.object_ref.reference_id],
            },),
            actor=writer_a.agent_id,
            proofs=(patch_a_receipt,),
        )

        if not conflict_required:
            read_b_document, read_b = board.read(
                board_id,
                agent_id=writer_b.agent_id,
                read_paths=("/decision", "/rationale"),
                source_event_refs=tuple(item["event_id"] for item in patch_a_refs),
            )
            _, read_b_refs = stream.append(
                "blackboard-read-b-current",
                ({**read_b, "event_type": "blackboard.document.read"},),
                actor=writer_b.agent_id,
            )
            writer_b_result = self._call(
                executor,
                evidence,
                writer_b,
                task_id="blackboard-continuation-current",
                kind="proposal",
                contract=(
                    "Continue from the exact committed Blackboard version and return read_version as a JSON integer "
                    "without quotes, read_document_hash copied exactly, patch, and write_rationale."
                ),
                prompt=(
                    f"Continue the shared decision for this goal: {evidence.goal}. "
                    f"Read committed version {read_b_document.version} hash {read_b_document.document_hash}. Return "
                    f"read_version as the unquoted JSON integer {read_b_document.version}."
                ),
                context={
                    "document_id": board_id,
                    "read_id": read_b["read_id"],
                    "read_event_id": read_b_refs[-1]["event_id"],
                    "read_version": read_b_document.version,
                    "read_document_hash": read_b_document.document_hash,
                    "patch_a_hash": patched_a.event["patch_hash"],
                },
                validate=validate_writer,
            )
            if (
                int(writer_b_result.value["read_version"]) != read_b_document.version
                or str(writer_b_result.value["read_document_hash"]) != read_b_document.document_hash
            ):
                raise DynamicCollaborationError("Blackboard continuation did not bind N+1")
            patch_b = dict(writer_b_result.value["patch"])
            patch_b_receipt = executor._publish(patch_b, purpose="true-multi-agent-blackboard-patch")
            intent_b = PatchIntent(
                board_id, read_b_document.version, read_b_document.document_hash, patch_b,
                writer_b.agent_id, ("blackboard-write",), task.task_id, attempt.task_attempt_id,
                attempt.claim_generation, attempt.fencing_token,
                (writer_b_result.output_hash,), (read_b["read_id"], read_b_refs[-1]["event_id"]),
                patch_ref=patch_b_receipt.object_ref.reference_id,
                target_paths=("/continuation",), merge_policy_hash=merge_policy_hash,
            )
            patched_b = board.patch(intent_b, task=task, published_object_receipt=patch_b_receipt)
            if patched_b.event is None:
                raise DynamicCollaborationError("Blackboard current-base continuation failed")
            _, resolution_refs = stream.append(
                "blackboard-patch-b-committed",
                ({
                    **patched_b.event,
                    "event_type": "blackboard.patch.committed",
                    "agent_call_id": writer_b_result.call_id,
                    "agent_input_snapshot_hash": writer_b_result.input_snapshot_hash,
                    "agent_output_hash": writer_b_result.output_hash,
                    "_object_refs": [patch_b_receipt.object_ref.reference_id],
                },),
                actor=writer_b.agent_id,
                proofs=(patch_b_receipt,),
            )
        else:
            assert writer_b_result is not None
            patch_b = dict(writer_b_result.value["patch"])
            patch_b_receipt = executor._publish(patch_b, purpose="true-multi-agent-blackboard-conflicting-patch")
            stale_intent = PatchIntent(
                board_id,
                read_b_document.version,
                read_b_document.document_hash,
                patch_b,
                writer_b.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (winner.output_hash, writer_b_result.output_hash),
                (read_b["read_id"], read_b_refs[-1]["event_id"]),
                patch_ref=patch_b_receipt.object_ref.reference_id,
                target_paths=("/decision", "/rationale"),
                merge_policy_hash=merge_policy_hash,
            )
            conflict = board.patch(stale_intent, task=task, published_object_receipt=patch_b_receipt)
            if conflict.conflict is None or conflict.event is not None or conflict.document.version != 1:
                raise DynamicCollaborationError("stale Blackboard base did not fail closed at N+1")
            conflict_id = str(conflict.conflict["conflict_id"])
            _, conflict_refs = stream.append(
                "blackboard-stale-patch-conflict",
                (
                    {
                        **conflict.conflict,
                        "event_type": "blackboard.patch.conflict",
                        "agent_call_id": writer_b_result.call_id,
                        "agent_input_snapshot_hash": writer_b_result.input_snapshot_hash,
                        "agent_output_hash": writer_b_result.output_hash,
                        "_object_refs": [patch_b_receipt.object_ref.reference_id],
                    },
                    {
                        "schema": "BLACKBOARD_LAST_WRITE_WINS_DENIED_V1",
                        "event_type": "blackboard.last-write-wins.denied",
                        "document_id": board_id,
                        "conflict_id": conflict_id,
                        "canonical_version": conflict.document.version,
                        "canonical_hash": conflict.document.document_hash,
                        "blocked_obligations": list(conflict.blocked_obligations),
                        "document_stream_mutated": False,
                    },
                ),
                actor="blackboard-command-handler",
                proofs=(patch_b_receipt,),
            )
            merge_decision, merge_agents = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-conflict-merge",
                required_capabilities=("blackboard-write",),
                slots=1,
                candidate_tasks=("blackboard-conflict-merge",),
                exclusions=(writer_a.agent_id, writer_b.agent_id),
                overrides=overrides,
            )
            merge_agent = merge_agents[0]
            _, merge_reviewers = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id="blackboard-merge-review",
                required_capabilities=("review",),
                slots=1,
                candidate_tasks=("blackboard-merge-review",),
                author_conflicts=(writer_a.agent_id, writer_b.agent_id, merge_agent.agent_id),
                overrides=overrides,
            )
            merge_reviewer = merge_reviewers[0]

            def validate_merge(value: Mapping[str, Any]) -> None:
                patch = value.get("merge_patch")
                if not isinstance(patch, dict) or not patch or len(patch) > 16:
                    raise DynamicCollaborationError("Merge Agent requires a bounded merge_patch object")
                _require_string(value, "canonical_branch_hash")
                _require_string(value, "conflicting_branch_hash")
                _require_string(value, "resolution_rationale")

            merge_result = self._call(
                executor,
                evidence,
                merge_agent,
                task_id="blackboard-conflict-merge",
                kind="proposal",
                contract=(
                    "Independently merge the canonical and conflicting business-state branches. Return merge_patch, "
                    "canonical_branch_hash copied byte-for-byte from input context, conflicting_branch_hash copied "
                    "byte-for-byte from input context, and resolution_rationale. Do not shorten or reformat either hash. "
                    "resolution_rationale must be a top-level sibling of merge_patch, not a field inside merge_patch. "
                    "Keep merge_patch to at most six scalar string fields, keep every string under 320 characters, and "
                    "do not restate the full goal or emit nested packages, arrays, Markdown, or surrounding prose."
                ),
                prompt=(
                    f"Resolve a shared decision conflict for goal: {evidence.goal}. Preserve both defensible branches. "
                    f"Return canonical_branch_hash exactly '{patched_a.event['patch_hash']}' and conflicting_branch_hash "
                    f"exactly '{conflict.conflict['patch_hash']}'. Do not omit or rename either field. Summarize the "
                    "combined decision and both retained conclusions compactly. Return resolution_rationale at the "
                    "top level beside merge_patch; do not nest it in merge_patch."
                ),
                context={
                    "document_id": board_id,
                    "conflict_id": conflict_id,
                    "canonical_document_version": conflict.document.version,
                    "canonical_document_hash": conflict.document.document_hash,
                    "canonical_patch": patch_a,
                    "canonical_patch_ref": patch_a_receipt.object_ref.reference_id,
                    "canonical_patch_hash": patched_a.event["patch_hash"],
                    "conflicting_patch": patch_b,
                    "conflicting_patch_ref": patch_b_receipt.object_ref.reference_id,
                    "conflicting_patch_hash": conflict.conflict["patch_hash"],
                    "conflict_event_ids": [item["event_id"] for item in conflict_refs],
                    "merge_policy_hash": merge_policy_hash,
                    "source_decision_id": merge_decision.decision_id,
                },
                validate=validate_merge,
            )
            if (
                str(merge_result.value["canonical_branch_hash"]) != patched_a.event["patch_hash"]
                or str(merge_result.value["conflicting_branch_hash"]) != conflict.conflict["patch_hash"]
            ):
                raise DynamicCollaborationError("Merge Agent did not bind both exact branches")
            merge_patch = dict(merge_result.value["merge_patch"])
            merge_patch_receipt = executor._publish(merge_patch, purpose="true-multi-agent-blackboard-merge-patch")
            merge_fact = board.submit_merge(
                conflict_id,
                merge_agent_id=merge_agent.agent_id,
                merge_patch=merge_patch,
                merge_read_refs=(conflict.document.document_hash, str(conflict.conflict["patch_hash"])),
                published_object_receipt=merge_patch_receipt,
            )
            _, merge_refs = stream.append(
                "blackboard-merge-proposed",
                ({
                    **merge_fact,
                    "event_type": "blackboard.merge.proposed",
                    "agent_call_id": merge_result.call_id,
                    "agent_input_snapshot_hash": merge_result.input_snapshot_hash,
                    "agent_output_hash": merge_result.output_hash,
                    "_object_refs": [merge_patch_receipt.object_ref.reference_id],
                },),
                actor=merge_agent.agent_id,
                proofs=(merge_patch_receipt,),
            )
            merge_rubric_hash = stable_hash(
                "TRUE_MULTI_AGENT_BLACKBOARD_MERGE_RUBRIC",
                {"policy_hash": self.policy_hash, "merge_policy_hash": merge_policy_hash, "criteria": ["branch-preservation", "safety", "schema"]},
            )

            def validate_merge_review(value: Mapping[str, Any]) -> None:
                _require_bool(value, "accept")
                _require_string(value, "reviewed_merge_hash")
                _require_string(value, "reason")

            merge_review = self._call(
                executor,
                evidence,
                merge_reviewer,
                task_id="blackboard-merge-review",
                kind="review",
                contract=(
                    "Independently review the exact Merge Patch and return accept, reviewed_merge_hash copied "
                    "byte-for-byte from input context, and reason. Do not shorten or reformat the hash."
                ),
                prompt=(
                    f"Review merge hash {merge_fact['merge_patch_hash']} under rubric {merge_rubric_hash}. "
                    f"Return reviewed_merge_hash exactly '{merge_fact['merge_patch_hash']}'. Accept only if both branches "
                    "are preserved, the result is safe, and the schema remains valid."
                ),
                context={
                    "document_id": board_id,
                    "conflict_id": conflict_id,
                    "merge_id": merge_fact["merge_id"],
                    "merge_event_id": merge_refs[-1]["event_id"],
                    "merge_patch": merge_patch,
                    "merge_patch_ref": merge_patch_receipt.object_ref.reference_id,
                    "merge_patch_hash": merge_fact["merge_patch_hash"],
                    "canonical_patch_hash": patched_a.event["patch_hash"],
                    "conflicting_patch_hash": conflict.conflict["patch_hash"],
                    "rubric_hash": merge_rubric_hash,
                },
                validate=validate_merge_review,
            )
            if str(merge_review.value["reviewed_merge_hash"]) != merge_fact["merge_patch_hash"]:
                raise DynamicCollaborationError("fresh Merge Review did not bind the exact Merge Patch")
            if not bool(merge_review.value["accept"]):
                raise DynamicCollaborationError("independent Merge Review rejected the proposed resolution")
            merge_review_fact = board.review_merge(
                conflict_id,
                reviewer_agent_id=merge_reviewer.agent_id,
                reviewed_merge_hash=merge_fact["merge_patch_hash"],
                review_hash=merge_review.output_hash,
                rubric_hash=merge_rubric_hash,
                accepted=True,
            )
            _, merge_review_refs = stream.append(
                "blackboard-merge-reviewed",
                ({
                    **merge_review_fact,
                    "event_type": "blackboard.merge.reviewed",
                    "agent_call_id": merge_review.call_id,
                    "agent_input_snapshot_hash": merge_review.input_snapshot_hash,
                    "agent_output_hash": merge_review.output_hash,
                },),
                actor=merge_reviewer.agent_id,
            )
            merge_intent = PatchIntent(
                board_id,
                conflict.document.version,
                conflict.document.document_hash,
                merge_patch,
                merge_agent.agent_id,
                ("blackboard-write",),
                task.task_id,
                attempt.task_attempt_id,
                attempt.claim_generation,
                attempt.fencing_token,
                (patched_a.event["patch_hash"], str(conflict.conflict["patch_hash"]), merge_review.output_hash),
                (conflict.document.document_hash, str(conflict.conflict["patch_hash"]), merge_refs[-1]["event_id"], merge_review_refs[-1]["event_id"]),
                patch_ref=merge_patch_receipt.object_ref.reference_id,
                patch_hash=merge_fact["merge_patch_hash"],
                target_paths=("/decision", "/rationale", "/resolution"),
                merge_policy_hash=merge_policy_hash,
            )
            resolution = board.resolve_conflict(
                conflict_id,
                decision_agent_id=merge_reviewer.agent_id,
                merge_intent=merge_intent,
                task=task,
                published_object_receipt=merge_patch_receipt,
            )
            _, resolution_refs = stream.append(
                "blackboard-conflict-resolved",
                (
                    {**resolution.merge_decision, "event_type": "blackboard.merge.decision"},
                    {**resolution.conflict_resolved, "event_type": "blackboard.conflict.resolved"},
                    {
                        **resolution.patch_committed,
                        "event_type": "blackboard.patch.committed",
                        "agent_call_id": merge_result.call_id,
                        "agent_input_snapshot_hash": merge_result.input_snapshot_hash,
                        "agent_output_hash": merge_result.output_hash,
                        "_object_refs": [merge_patch_receipt.object_ref.reference_id],
                    },
                ),
                actor=merge_reviewer.agent_id,
                proofs=(merge_patch_receipt,),
            )
            if board.closing_blockers:
                raise DynamicCollaborationError("Blackboard conflict remained blocking after resolution")

        final = board.documents[board_id]
        downstream_reader = writer_b
        downstream_document, downstream_read = board.read(
            board_id,
            agent_id=downstream_reader.agent_id,
            read_paths=("/decision", "/rationale", "/resolution"),
            source_event_refs=tuple(item["event_id"] for item in resolution_refs),
        )
        _, downstream_read_refs = stream.append(
            "blackboard-final-version-read",
            ({**downstream_read, "event_type": "blackboard.document.read"},),
            actor=downstream_reader.agent_id,
        )

        def validate_downstream(value: Mapping[str, Any]) -> None:
            version = value.get("read_version")
            if not isinstance(version, int) or version < 1:
                raise DynamicCollaborationError("downstream Blackboard Agent lacks read_version")
            _require_string(value, "read_document_hash")
            _require_string(value, "continuation")

        downstream = self._call(
            executor,
            evidence,
            downstream_reader,
            task_id="blackboard-downstream-consumer",
            kind="proposal",
            contract=(
                "Consume the exact resolved Blackboard version. The JSON object must include read_version as an integer, "
                "without quotes, read_document_hash as a string copied byte-for-byte from input context, and continuation "
                "as a non-empty string."
            ),
            prompt=(
                f"Continue the business task from resolved Blackboard version {downstream_document.version} "
                f"hash {downstream_document.document_hash}. Return read_version exactly {downstream_document.version}, "
                f"read_document_hash exactly '{downstream_document.document_hash}', and explain in continuation how the "
                "shared resolution changes the next step. Do not omit or rename any required field."
            ),
            context={
                "document_id": board_id,
                "read_id": downstream_read["read_id"],
                "read_event_id": downstream_read_refs[-1]["event_id"],
                "read_version": downstream_document.version,
                "read_document_hash": downstream_document.document_hash,
                "source_resolution_event_ids": [item["event_id"] for item in resolution_refs],
                "selected_proposal_hash": winner.output_hash,
            },
            validate=validate_downstream,
        )
        if (
            int(downstream.value["read_version"]) != final.version
            or str(downstream.value["read_document_hash"]) != final.document_hash
        ):
            raise DynamicCollaborationError("downstream Agent did not consume the resolved Blackboard version")
        close_fact = self._protocol_close(evidence, board_id, obligation, "CONFLICT_RESOLVED_AND_CONSUMED" if conflict_required else "COMMITTED_AND_CONSUMED")
        stream.append(
            "blackboard-closed",
            (
                {
                    "schema": "BLACKBOARD_FINAL_VERSION_REFERENCED_V1",
                    "event_type": "blackboard.final-version.consumed",
                    "document_id": board_id,
                    "committed_version": final.version,
                    "document_hash": final.document_hash,
                    "downstream_agent_id": downstream_reader.agent_id,
                    "downstream_call_id": downstream.call_id,
                    "downstream_input_snapshot_hash": downstream.input_snapshot_hash,
                    "downstream_output_hash": downstream.output_hash,
                    "downstream_read_event_id": downstream_read_refs[-1]["event_id"],
                    "blocking_conflict_count": len(board.active_conflicts),
                },
                close_fact,
            ),
            actor="blackboard-terminal-coordinator",
        )
        return {
            "document_id": board_id,
            "version": final.version,
            "document_hash": final.document_hash,
            "primary_writer_id": writer_a.agent_id,
            "stale_writer_id": writer_b.agent_id,
            "task_id": task.task_id,
            "task_attempt_id": attempt.task_attempt_id,
            "lease_id": attempt.lease_id,
            "fencing_token": attempt.fencing_token,
            "downstream_output_hash": downstream.output_hash,
            "downstream_output_ref": downstream.output_ref,
            "conflict_required": conflict_required,
        }

    def _handoff(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
        winner: AgentCallResult,
        sender: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        overrides: Mapping[str, Any],
        *,
        defer_after_execution_prepared: bool = False,
        integrated_context: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any] | None:
        receiver_decision, receivers = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="handoff-receive",
            required_capabilities=("handoff-receive",),
            slots=1,
            candidate_tasks=("handoff-contract-review", "handoff-execution"),
            exclusions=(sender.agent_id,),
            overrides=overrides,
        )
        receiver = receivers[0]
        handoff_id = "handoff-" + stable_hash("TRUE_MULTI_AGENT_HANDOFF", {"run": evidence.run_id})[:28]
        obligation = "obligation-" + handoff_id
        open_fact = self._protocol_open(evidence, "handoff", handoff_id, obligation, source_decision.decision_id)
        task_id = "handoff-task-" + evidence.run_id
        task = TaskAggregate(
            task_id,
            stable_hash("TRUE_MULTI_AGENT_HANDOFF_TASK", {"run": evidence.run_id, "winner": winner.output_hash}),
        )
        stream = CanonicalStream(
            journal,
            evidence.run_id,
            f"protocol/{evidence.run_id}/handoff/{handoff_id}",
            self.policy_hash,
        )

        def receiver_capability_hash(identity: AgentIdentity) -> str:
            return stable_hash(
                "TRUE_MULTI_AGENT_HANDOFF_CAPABILITIES",
                {"receiver": identity.agent_id, "capabilities": list(identity.capabilities)},
            )

        def preview_claim(generation: int, identity: AgentIdentity) -> tuple[Any, dict[str, Any], str]:
            _, preview_attempt, preview_fact = task.claim(
                claim_command_id="claim-" + handoff_id + f"-{generation}",
                lease_expires_at="2099-01-01T00:00:00Z",
                holder_agent_id=identity.agent_id,
                expected_stream_version=task.stream_version,
            )
            claim_ref = stable_hash("HANDOFF_TASK_CLAIM_RESERVATION", preview_fact)
            return preview_attempt, preview_fact, claim_ref

        def make_contract(
            generation: int,
            identity: AgentIdentity,
            *,
            incomplete: bool,
            previous_generation_ref: str | None = None,
            previous_rejection_event_ref: str | None = None,
            reject_reason_resolution_map: Mapping[str, str] | None = None,
        ) -> tuple[HandoffContract, Any, Any, dict[str, Any], str]:
            resolution_map = dict(reject_reason_resolution_map or {})
            preview_attempt, preview_fact, claim_ref = preview_claim(generation, identity)
            refrozen_component = stable_hash(
                "TRUE_MULTI_AGENT_HANDOFF_REFROZEN_INPUT",
                {
                    "run_id": evidence.run_id,
                    "generation": generation,
                    "receiver_id": identity.agent_id,
                    "source_output_hash": winner.output_hash,
                    "previous_generation_ref": previous_generation_ref,
                    "previous_rejection_event_ref": previous_rejection_event_ref,
                    "reject_reason_resolution_map": resolution_map,
                    "task_claim_ref": claim_ref,
                    "fencing_token": preview_attempt.fencing_token,
                },
            )
            contract = HandoffContract(
                handoff_id,
                generation,
                sender.agent_id,
                identity.agent_id,
                task_id,
                "Produce a verified continuation of the selected proposal for the stated goal.",
                ("read selected immutable proposal", "produce bounded JSON handoff result", "preserve evidence lineage"),
                ("handoff-receive",),
                (winner.output_ref.removeprefix("cas:"),),
                (winner.output_hash, refrozen_component),
                stable_hash("TRUE_MULTI_AGENT_HANDOFF_STATE", {"run": evidence.run_id, "generation": generation}),
                {
                    "type": "object",
                    "required": ["deliverable", "source_output_hash", "acceptance_checks"],
                },
                ("source hash is bound", "deliverable is non-empty", "independent verifier accepts"),
                (("generation 1 omitted clarification intentionally",) if incomplete else ("selected proposal is immutable",)),
                (("receiver must reject the incomplete first generation",) if incomplete else ()),
                (("Which exact acceptance checks are mandatory?",) if incomplete else ()),
                min(4000, int(self.policy["max_total_tokens_per_run"])),
                "2099-01-01T00:00:00Z",
                self.policy_hash,
                previous_generation_ref=previous_generation_ref,
                previous_rejection_event_ref=previous_rejection_event_ref,
                reject_reason_resolution_map=resolution_map,
                blackboard_version_refs=(
                    (
                        f"{integrated_context['blackboard']['document_id']}@"
                        f"{integrated_context['blackboard']['version']}:"
                        f"{integrated_context['blackboard']['document_hash']}"
                    ),
                )
                if integrated_context is not None
                else (),
                task_claim_ref=claim_ref,
                fencing_token=preview_attempt.fencing_token,
                max_generations=3,
            )
            receipt = executor._publish(contract.mapping(), purpose="true-multi-agent-handoff-contract")
            return contract, receipt, preview_attempt, preview_fact, claim_ref

        reject_first = analysis.requires_handoff_reject or bool(overrides.get("force_handoff_reject"))
        clarify_first = bool(overrides.get("force_handoff_clarification"))
        contract, contract_receipt, reserved_attempt, reserved_claim, task_claim_ref = make_contract(
            1, receiver, incomplete=reject_first or clarify_first
        )
        handoff, offered = Handoff.offer(
            handoff_id,
            1,
            sender.agent_id,
            receiver.agent_id,
            task_id,
            contract.contract_hash,
            policy_hash=self.policy_hash,
            capability_hash=receiver_capability_hash(receiver),
            budget=contract.budget_tokens,
            deadline=contract.deadline,
            high_risk=analysis.risk_level == "high",
            max_generations=contract.max_generations,
            required_capabilities=contract.required_capabilities,
            receiver_capabilities=receiver.capabilities,
            input_freeze_hash=contract.input_freeze_hash,
            output_schema_hash=contract.output_schema_hash,
        )
        stream.append(
            "handoff-offered",
            (open_fact, contract.offered_fact(contract_object_ref=contract_receipt.object_ref.reference_id), offered),
            actor=sender.agent_id,
            proofs=(contract_receipt,),
        )

        def validate_assessment(value: Mapping[str, Any]) -> None:
            accepted_value = _require_bool(value, "accept")
            _require_string(value, "reason")
            missing = value.get("missing_information")
            if accepted_value and missing in ([], "", None):
                return
            _require_text_or_strings(value, "missing_information", maximum=8)

        def assess_contract(*, incomplete: bool) -> AgentCallResult:
            return self._call(
                executor,
                evidence,
                receiver,
                task_id=f"handoff-contract-assessment-{handoff.generation}",
                kind="review",
                contract="Assess the exact frozen Handoff contract. Return accept, reason, and missing_information.",
                prompt=(
                    "Reject this generation because its open_questions and residual risk explicitly make it incomplete. "
                    if incomplete
                    else "Accept only if the corrected generation resolves every prior rejection reason and is executable. "
                ) + json.dumps(contract.mapping(), ensure_ascii=False, sort_keys=True),
                context={
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "contract_hash": contract.contract_hash,
                    "contract_object_ref": contract_receipt.object_ref.reference_id,
                    "receiver_agent_id": receiver.agent_id,
                    "prior_generation_closed": handoff.generation > 1,
                    "input_freeze_hash": contract.input_freeze_hash,
                    "task_claim_ref": contract.task_claim_ref,
                },
                validate=validate_assessment,
            )

        def rejection_reasons(value: Mapping[str, Any]) -> tuple[str, ...]:
            missing = value.get("missing_information")
            if isinstance(missing, str) and missing.strip():
                values = (missing.strip(),)
            elif isinstance(missing, list):
                values = tuple(str(item).strip() for item in missing if str(item).strip())
            else:
                values = ()
            reason = str(value.get("reason", "")).strip()
            return tuple(dict.fromkeys((*values, reason or "receiver rejected the frozen contract")))

        def open_successor(
            transition_ref: Mapping[str, Any],
            prior_contract_ref: str,
            reasons: tuple[str, ...],
        ) -> AgentCallResult:
            nonlocal handoff, receiver, contract, contract_receipt
            nonlocal reserved_attempt, reserved_claim, task_claim_ref
            decision, candidates = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id=f"handoff-receive-generation-{handoff.generation + 1}",
                required_capabilities=("handoff-receive",),
                slots=1,
                candidate_tasks=("handoff-contract-revalidation", "handoff-execution"),
                exclusions=(sender.agent_id,),
                overrides=overrides,
            )
            receiver = candidates[0]
            resolution_map = {
                reason: f"Resolved in generation {handoff.generation + 1} by refreezing the corrected contract, inputs, capability proof, Task Claim, and output schema."
                for reason in reasons
            }
            resolution_hash = stable_hash("HANDOFF_REJECT_REASON_RESOLUTION", resolution_map)
            next_contract, next_receipt, next_reserved_attempt, next_reserved_claim, next_claim_ref = make_contract(
                handoff.generation + 1,
                receiver,
                incomplete=False,
                previous_generation_ref=prior_contract_ref,
                previous_rejection_event_ref=str(transition_ref["event_id"]),
                reject_reason_resolution_map=resolution_map,
            )
            next_handoff, opened_generation = handoff.new_generation(
                specification_hash=next_contract.contract_hash,
                policy_hash=self.policy_hash,
                capability_hash=receiver_capability_hash(receiver),
                budget=next_contract.budget_tokens,
                deadline=next_contract.deadline,
                high_risk=analysis.risk_level == "high",
                receiver_id=receiver.agent_id,
                required_capabilities=next_contract.required_capabilities,
                receiver_capabilities=receiver.capabilities,
                input_freeze_hash=next_contract.input_freeze_hash,
                output_schema_hash=next_contract.output_schema_hash,
                previous_generation_ref=prior_contract_ref,
                previous_rejection_event_ref=str(transition_ref["event_id"]),
                reject_reason_resolution_hash=resolution_hash,
            )
            stream.append(
                "handoff-successor-generation-offered",
                (
                    next_contract.offered_fact(contract_object_ref=next_receipt.object_ref.reference_id),
                    {
                        "schema": "HANDOFF_RECEIVER_CAPABILITY_REVALIDATED_V1",
                        "handoff_id": handoff_id,
                        "generation": next_handoff.generation,
                        "receiver_id": receiver.agent_id,
                        "required_capabilities": list(next_contract.required_capabilities),
                        "actual_capabilities": list(receiver.capabilities),
                        "capability_hash": receiver_capability_hash(receiver),
                        "source_decision_id": decision.decision_id,
                        "result": "PASSED",
                    },
                    opened_generation,
                ),
                actor="handoff-generation-command-handler",
                proofs=(next_receipt,),
            )
            handoff = next_handoff
            contract = next_contract
            contract_receipt = next_receipt
            reserved_attempt = next_reserved_attempt
            reserved_claim = next_reserved_claim
            task_claim_ref = next_claim_ref
            return assess_contract(incomplete=False)

        assessment = assess_contract(incomplete=reject_first or clarify_first)
        if (reject_first or clarify_first) and bool(assessment.value["accept"]):
            raise DynamicCollaborationError("receiver accepted a deliberately incomplete Handoff generation")

        controlled_verification_failure_used = False
        while True:
            while not bool(assessment.value["accept"]):
                prior_contract_ref = contract_receipt.object_ref.reference_id
                reasons = rejection_reasons(assessment.value)
                if clarify_first and handoff.generation == 1:
                    handoff, clarified = handoff.clarify(receiver.agent_id, assessment.output_hash)
                    handoff, closed = handoff.close_for_new_generation(
                        receiver.agent_id, reason_ref=assessment.output_hash
                    )
                    _, transition_refs = stream.append(
                        "handoff-generation-clarification-closed",
                        (
                            {**clarified, "assessment_call_id": assessment.call_id},
                            {**closed, "event_type": "handoff.generation.closed"},
                        ),
                        actor=receiver.agent_id,
                    )
                    transition_ref = transition_refs[-1]
                else:
                    handoff, rejected = handoff.reject(receiver.agent_id, str(assessment.value["reason"]))
                    _, transition_refs = stream.append(
                        "handoff-generation-rejected-closed",
                        (
                            {**rejected, "event_type": "handoff.rejected", "assessment_call_id": assessment.call_id},
                            {
                                "schema": "HANDOFF_REJECTED_GENERATION_CLOSED_V1",
                                "handoff_id": handoff_id,
                                "closed_generation": handoff.generation,
                                "generation_hash": handoff.generation_hash,
                                "old_generation_reusable": False,
                                "generation_permanently_closed": True,
                            },
                        ),
                        actor=receiver.agent_id,
                    )
                    transition_ref = transition_refs[0]
                if handoff.generation >= handoff.max_generations:
                    limit_fact = {
                        "schema": "HANDOFF_GENERATION_LIMIT_REACHED_V1",
                        "handoff_id": handoff_id,
                        "generation": handoff.generation,
                        "max_generations": handoff.max_generations,
                        "prior_generation_hash": handoff.generation_hash,
                        "terminal_disposition": "FAILED_GENERATION_LIMIT_REACHED",
                    }
                    close_fact = self._protocol_close(
                        evidence, handoff_id, obligation, "FAILED_GENERATION_LIMIT_REACHED"
                    )
                    stream.append(
                        "handoff-generation-limit-failed",
                        (limit_fact, close_fact),
                        actor="handoff-terminal-coordinator",
                    )
                    raise DynamicCollaborationError("Handoff generation limit reached")
                assessment = open_successor(transition_ref, prior_contract_ref, reasons)

            handoff, accepted = handoff.accept(receiver.agent_id, now=now_rfc3339())
            handoff, claim_pending = handoff.mark_claim_pending(
                receiver.agent_id,
                task_claim_ref=task_claim_ref,
                fencing_token=reserved_attempt.fencing_token,
            )
            task, attempt, claim = task.claim(
                claim_command_id="claim-" + handoff_id + f"-{handoff.generation}",
                lease_expires_at="2099-01-01T00:00:00Z",
                holder_agent_id=receiver.agent_id,
                expected_stream_version=task.stream_version,
            )
            if attempt.fencing_token != reserved_attempt.fencing_token or stable_hash(
                "HANDOFF_TASK_CLAIM_RESERVATION", claim
            ) != task_claim_ref:
                raise DynamicCollaborationError("committed Handoff Task Claim differs from frozen reservation")
            handoff, bound = handoff.bind_claim(task, attempt.fencing_token)
            handoff, executing = handoff.execute(receiver.agent_id)
            stream.append(
                "handoff-accepted-claim-pending-executing",
                (
                    {
                        **accepted,
                        "event_type": "handoff.accepted",
                        "assessment_call_id": assessment.call_id,
                        "old_acceptance_reused": False,
                    },
                    claim_pending,
                    claim,
                    bound,
                    executing,
                ),
                actor=receiver.agent_id,
            )

            def validate_delivery(value: Mapping[str, Any]) -> None:
                _require_string(value, "deliverable")
                if _require_string(value, "source_output_hash") != winner.output_hash:
                    raise DynamicCollaborationError("Handoff delivery did not bind selected source hash")
                _require_strings(value, "acceptance_checks", maximum=8)

            delivery = self._call(
                executor,
                evidence,
                receiver,
                task_id=f"handoff-execution-generation-{handoff.generation}",
                kind="proposal",
                contract=(
                    "Execute the accepted Handoff. Return agent_id, kind=proposal, deliverable, "
                    "source_output_hash, and acceptance_checks; acceptance_checks must contain one to "
                    "eight non-empty strings."
                ),
                prompt=(
                    f"Execute generation {handoff.generation} of contract {contract.contract_hash}. "
                    f"The source_output_hash must be exactly {winner.output_hash}. Return no more than "
                    "eight acceptance_checks, each a non-empty string. Selected proposal: "
                    + json.dumps(dict(winner.value), ensure_ascii=False, sort_keys=True)
                ),
                context={
                    "contract_object_ref": contract_receipt.object_ref.reference_id,
                    "contract_hash": contract.contract_hash,
                    "handoff_generation": handoff.generation,
                    "task_attempt_id": attempt.task_attempt_id,
                    "task_claim_ref": task_claim_ref,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                    "output_schema_hash": contract.output_schema_hash,
                },
                validate=validate_delivery,
            )
            schema_validation_hash = stable_hash(
                "HANDOFF_OUTPUT_SCHEMA_VALIDATION",
                {
                    "contract_hash": contract.contract_hash,
                    "output_schema_hash": contract.output_schema_hash,
                    "delivery_output_hash": delivery.output_hash,
                    "delivery_value": dict(delivery.value),
                },
            )
            _, verifiers = self._schedule(
                journal,
                run_stream,
                evidence,
                task_id=f"handoff-verification-generation-{handoff.generation}",
                required_capabilities=("verification", "review"),
                slots=1,
                candidate_tasks=("handoff-verification",),
                author_conflicts=(sender.agent_id, receiver.agent_id),
                overrides=overrides,
            )
            verifier = verifiers[0]

            def validate_verification(value: Mapping[str, Any]) -> None:
                _require_bool(value, "accepted")
                _require_string(value, "reason")
                _require_verification_checks(value, maximum=8)

            verification = self._call(
                executor,
                evidence,
                verifier,
                task_id=f"handoff-verification-generation-{handoff.generation}",
                kind="review",
                contract=(
                    "Independently verify the exact Handoff delivery. Return agent_id, kind=review, accepted "
                    "as a boolean, reason as a non-empty string, and checks as one to eight non-empty strings."
                ),
                prompt=(
                    "The delivery_object_hash and contract_hash are distinct object identities; do not compare them "
                    "for equality. Verify the delivery JSON against the frozen output_schema, acceptance_criteria, "
                    "and expected_source_output_hash. Return checks as a JSON list of one to eight non-empty strings. "
                    + json.dumps(
                        {
                            "delivery_object_hash": delivery.output_hash,
                            "contract_hash": contract.contract_hash,
                            "expected_source_output_hash": winner.output_hash,
                            "output_schema": dict(contract.output_schema),
                            "acceptance_criteria": list(contract.acceptance_criteria),
                            "delivery": dict(delivery.value),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                ),
                context={
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "sender_agent_id": sender.agent_id,
                    "receiver_agent_id": receiver.agent_id,
                    "verifier_independent": verifier.agent_id not in {sender.agent_id, receiver.agent_id},
                    "delivery_output_hash": delivery.output_hash,
                    "output_schema_hash": contract.output_schema_hash,
                },
                validate=validate_verification,
            )
            provider_accepted = bool(verification.value["accepted"])
            effective_accepted = provider_accepted
            if bool(overrides.get("force_handoff_verification_failure_once")) and not controlled_verification_failure_used:
                effective_accepted = False
                controlled_verification_failure_used = True
            if defer_after_execution_prepared:
                if handoff.generation != 2 or not effective_accepted or integrated_context is None:
                    raise DynamicCollaborationError(
                        "integrated restart requires an accepted generation-2 Handoff with a positive independent verdict"
                    )
                main_task: TaskAggregate = integrated_context["task"]
                main_attempt = integrated_context["attempt"]
                blackboard = dict(integrated_context["blackboard"])
                prepared_fact = {
                    "schema": "HANDOFF_POST_RESTART_CONTINUATION_PREPARED_V1",
                    "event_type": "handoff.post-restart-continuation.prepared",
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "handoff_state": handoff.state.value,
                    "authoritative_submission_committed": False,
                    "authoritative_verification_committed": False,
                    "delivery_call_id": delivery.call_id,
                    "delivery_output_ref": delivery.output_ref,
                    "delivery_output_hash": delivery.output_hash,
                    "schema_validation_evidence_hash": schema_validation_hash,
                    "verification_call_id": verification.call_id,
                    "verification_output_ref": verification.output_ref,
                    "verification_output_hash": verification.output_hash,
                    "verifier_id": verifier.agent_id,
                    "verifier_independent": verifier.agent_id not in {sender.agent_id, receiver.agent_id},
                    "provider_verdict": provider_accepted,
                    "restart_required_before_submission": True,
                }
                stream.append(
                    "handoff-post-restart-continuation-prepared",
                    (prepared_fact,),
                    actor=verifier.agent_id,
                )
                return {
                    "schema": "INTEGRATED_HANDOFF_RESTART_CONTINUATION_V1",
                    "integrated_continuation": True,
                    "handoff_id": handoff_id,
                    "handoff_stream_id": f"protocol/{evidence.run_id}/handoff/{handoff_id}",
                    "handoff_generation": handoff.generation,
                    "handoff_generation_hash": handoff.generation_hash,
                    "handoff_state": handoff.state.value,
                    "handoff_protocol_id": handoff_id,
                    "handoff_obligation_id": obligation,
                    "sender_id": sender.agent_id,
                    "receiver_id": receiver.agent_id,
                    "verifier_id": verifier.agent_id,
                    "handoff_task": {
                        "task_id": task.task_id,
                        "specification_hash": task.specification_hash,
                        "stream_version": task.stream_version,
                        "claim_generation": task.claim_generation,
                        "task_attempt_id": attempt.task_attempt_id,
                        "claim_command_id": attempt.claim_command_id,
                        "holder_agent_id": attempt.holder_agent_id,
                        "lease_id": attempt.lease_id,
                        "lease_expires_at": attempt.lease_expires_at,
                        "fencing_token": attempt.fencing_token,
                    },
                    "main_task": {
                        "task_id": main_task.task_id,
                        "specification_hash": main_task.specification_hash,
                        "stream_version": main_task.stream_version,
                        "claim_generation": main_task.claim_generation,
                        "task_attempt_id": main_attempt.task_attempt_id,
                        "claim_command_id": main_attempt.claim_command_id,
                        "holder_agent_id": main_attempt.holder_agent_id,
                        "lease_id": main_attempt.lease_id,
                        "lease_expires_at": main_attempt.lease_expires_at,
                        "fencing_token": main_attempt.fencing_token,
                    },
                    "lease_protocol_id": integrated_context["protocol_id"],
                    "lease_obligation_id": integrated_context["obligation_id"],
                    "blackboard": blackboard,
                    "contract_hash": contract.contract_hash,
                    "contract_ref": contract_receipt.object_ref.reference_id,
                    "output_schema_hash": contract.output_schema_hash,
                    "delivery_call_id": delivery.call_id,
                    "delivery_output_ref": delivery.output_ref,
                    "delivery_output_hash": delivery.output_hash,
                    "schema_validation_evidence_hash": schema_validation_hash,
                    "verification_call_id": verification.call_id,
                    "verification_output_ref": verification.output_ref,
                    "verification_output_hash": verification.output_hash,
                    "provider_verdict": provider_accepted,
                    "prepared_event_schema": prepared_fact["schema"],
                }
            handoff, submitted_handoff = handoff.submit(
                receiver.agent_id,
                delivery.output_hash,
                output_schema_hash=contract.output_schema_hash,
                schema_validation_evidence_hash=schema_validation_hash,
            )
            task, submitted_task = task.submit(attempt.fencing_token, delivery.output_hash)
            handoff, verification_fact = handoff.verify(
                verifier.agent_id,
                accepted=effective_accepted,
                verification_evidence_hash=verification.output_hash,
            )
            if effective_accepted:
                task, task_accepted = task.accept(
                    attempt.fencing_token,
                    artifact_hash=delivery.output_hash,
                    policy_hash=self.policy_hash,
                    acceptance_evidence_refs=(verification.output_ref, verification.output_hash),
                )
                close_fact = self._protocol_close(evidence, handoff_id, obligation, "VERIFIED")
                stream.append(
                    "handoff-verified",
                    (
                        {**submitted_handoff, "event_type": "handoff.submitted", "delivery_call_id": delivery.call_id},
                        submitted_task,
                        {
                            **verification_fact,
                            "event_type": "handoff.verified",
                            "verification_call_id": verification.call_id,
                            "provider_verdict": provider_accepted,
                            "effective_verdict": effective_accepted,
                        },
                        task_accepted,
                        close_fact,
                    ),
                    actor=verifier.agent_id,
                )
                return None

            task, failed_attempt = task.fail_attempt(
                attempt.fencing_token, "HANDOFF_INDEPENDENT_VERIFICATION_REJECTED"
            )
            _, rework_refs = stream.append(
                "handoff-verification-rework-required",
                (
                    {**submitted_handoff, "event_type": "handoff.submitted", "delivery_call_id": delivery.call_id},
                    submitted_task,
                    {
                        **verification_fact,
                        "event_type": "handoff.verification.rejected",
                        "verification_call_id": verification.call_id,
                        "provider_verdict": provider_accepted,
                        "effective_verdict": effective_accepted,
                        "controlled_failure_injected": provider_accepted != effective_accepted,
                    },
                    failed_attempt,
                ),
                actor=verifier.agent_id,
            )
            if handoff.generation >= handoff.max_generations:
                limit_fact = {
                    "schema": "HANDOFF_GENERATION_LIMIT_REACHED_V1",
                    "handoff_id": handoff_id,
                    "generation": handoff.generation,
                    "max_generations": handoff.max_generations,
                    "prior_generation_hash": handoff.generation_hash,
                    "terminal_disposition": "FAILED_GENERATION_LIMIT_REACHED",
                }
                close_fact = self._protocol_close(
                    evidence, handoff_id, obligation, "FAILED_GENERATION_LIMIT_REACHED"
                )
                stream.append(
                    "handoff-verification-generation-limit-failed",
                    (limit_fact, close_fact),
                    actor="handoff-terminal-coordinator",
                )
                raise DynamicCollaborationError("Handoff verification failed at generation limit")
            prior_contract_ref = contract_receipt.object_ref.reference_id
            reasons = tuple(
                dict.fromkeys(
                    (
                        str(verification.value["reason"]),
                        *_require_verification_checks(verification.value, maximum=8),
                    )
                )
            )
            assessment = open_successor(rework_refs[2], prior_contract_ref, reasons)

    def _provider_recovery(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        overrides: Mapping[str, Any],
    ) -> None:
        """Exercise bounded Production recovery paths and reassign the failed Task."""

        decision_a, selected_a = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="provider-recovery-owner",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("provider-recovery-owner",),
            overrides=overrides,
        )
        worker_a = selected_a[0]
        task_id = "provider-recovery-task-" + evidence.run_id
        task = TaskAggregate(task_id, stable_hash("TRUE_MULTI_AGENT_PROVIDER_RECOVERY_TASK", {"run": evidence.run_id}))
        protocol_id = "provider-recovery-" + stable_hash(
            "TRUE_MULTI_AGENT_PROVIDER_RECOVERY_PROTOCOL", {"run": evidence.run_id}
        )[:24]
        obligation = "obligation-" + protocol_id
        task_stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
        open_fact = self._protocol_open(evidence, "provider_recovery", protocol_id, obligation, decision_a.decision_id)
        task_stream.append(
            "provider-recovery-task-created",
            (
                open_fact,
                {
                    "schema": "TASK_CREATED_V1",
                    "task_id": task_id,
                    "specification_hash": task.specification_hash,
                    "source_decision_id": decision_a.decision_id,
                    "recovery_paths": [
                        "ABORTED_BEFORE_SEND",
                        "TIMEOUT_AFTER_INVOCATION_STARTED",
                        "FAILED_CONFIRMED",
                        "ACK_LOST_AFTER_REMOTE_SUCCESS",
                    ],
                },
            ),
            actor="provider-recovery-command-handler",
        )
        expires_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(time.time()) + 300))
        task, attempt_a, claim_a = task.claim(
            claim_command_id="provider-recovery-claim-a-" + evidence.run_id,
            lease_expires_at=expires_a,
            holder_agent_id=worker_a.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append("provider-recovery-owner-claimed", (claim_a,), actor=worker_a.agent_id)

        pre_send = executor.inject_worker_loss(
            worker_a,
            task_id="provider-recovery-pre-send-failure",
            after_invocation_started=False,
        )
        if (
            pre_send["attempt_disposition"] != "ABORTED_BEFORE_SEND"
            or pre_send["physical_send_count"] != 0
            or pre_send["settlement_state"] != "SETTLED"
        ):
            raise DynamicCollaborationError("pre-send recovery path violated zero-send settlement")

        timeout = executor.inject_worker_loss(
            worker_a,
            task_id="provider-timeout-after-invocation-started",
            after_invocation_started=True,
        )
        if (
            timeout["attempt_disposition"] != "MAY_HAVE_BEEN_SENT"
            or timeout["outcome_state"] != "OUTCOME_UNKNOWN"
            or timeout["settlement_state"] != "RECONCILING"
            or timeout["physical_send_count"] != 0
        ):
            raise DynamicCollaborationError("after-start timeout/loss did not enter conservative reconciliation")
        transfer = MonitoringTransfer.create(
            "monitoring-transfer-" + stable_hash(
                "TRUE_MULTI_AGENT_PROVIDER_TIMEOUT_MONITORING", {"run": evidence.run_id}
            )[:24],
            evidence.run_id,
            "incident-provider-timeout-" + evidence.run_id,
            (str(timeout["effect_id"]),),
            self.policy_hash,
        )
        transfer, accepted_monitoring = transfer.accept_successor(authority="provider-recovery-monitor-owner")
        CanonicalStream(
            journal,
            evidence.run_id,
            "incident-provider-timeout-" + evidence.run_id,
            self.policy_hash,
        ).append(
            "provider-timeout-monitoring-accepted",
            (accepted_monitoring,),
            actor="provider-recovery-monitor-owner",
        )
        transfer, source_ack = transfer.acknowledge_source()
        timeout_state = executor.gateway.settle_unknown_by_policy(
            str(timeout["effect_id"]), str(timeout["effect_attempt_id"])
        )
        for item in executor.recovery_attempts:
            if item["effect_id"] == timeout["effect_id"]:
                item.update(
                    {
                        "settlement_state": timeout_state.settlement_state.value,
                        "settlement_basis": timeout_state.settlement_basis.value,
                        "monitoring_transfer_id": transfer.transfer_id,
                        "terminal_blocking_exposure_count": 0,
                    }
                )
        CanonicalStream(
            journal,
            evidence.run_id,
            f"effect/{evidence.run_id}/{timeout['effect_id']}",
            self.policy_hash,
        ).append(
            "provider-timeout-reconciled-by-policy",
            (
                {
                    "schema": "PROVIDER_RECONCILIATION_REQUESTED_V1",
                    "effect_id": timeout["effect_id"],
                    "effect_attempt_id": timeout["effect_attempt_id"],
                    "reason": "TIMEOUT_OR_WORKER_LOSS_AFTER_INVOCATION_STARTED",
                    "automatic_retry_authorized": False,
                },
                {
                    "schema": "PROVIDER_RECONCILIATION_QUERY_RECORDED_V1",
                    "effect_id": timeout["effect_id"],
                    "effect_attempt_id": timeout["effect_attempt_id"],
                    "query_result": "STATUS_ENDPOINT_UNAVAILABLE",
                    "not_found_interpreted_as_not_executed": False,
                    "new_transmission_performed": False,
                },
                {
                    "schema": "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1",
                    "effect_id": timeout["effect_id"],
                    "effect_attempt_id": timeout["effect_attempt_id"],
                    "prior_outcome_state": "OUTCOME_UNKNOWN",
                    "state": timeout_state.mapping(),
                    "disposition": "SETTLED_WITH_MONITORING_TRANSFER_AND_PERMANENT_RETRY_BLOCK",
                    "automatic_retry_performed": False,
                    "new_effect_created": False,
                    "monitoring_transfer_id": transfer.transfer_id,
                    "monitoring_responsibility": transfer.successor_stream_id,
                    "successor_authority": transfer.successor_authority,
                    "terminal_effect_exposure_blocker_transferred": True,
                    "terminal_blocking_exposure_count": 0,
                },
                source_ack,
            ),
            actor="effect-reconciliation-policy",
        )

        explicit_failure = executor.inject_explicit_remote_failure(
            worker_a,
            task_id="provider-explicit-remote-failure",
        )
        if (
            explicit_failure["physical_send_count"] != 1
            or explicit_failure["outcome_state"] != "FAILED_CONFIRMED"
            or explicit_failure["settlement_state"] != "SETTLED"
            or explicit_failure["unresolved_transmission_exposure_count"] != 0
        ):
            raise DynamicCollaborationError("explicit remote failure was not authoritatively settled")

        ack_events = [
            event
            for event in journal.iter_events(0)
            if event.payload.get("run_id") == evidence.run_id
            and event.payload.get("schema") == "PROVIDER_ACK_LOST_OUTCOME_UNKNOWN_V1"
        ]
        if len(ack_events) != 1:
            raise DynamicCollaborationError("Provider recovery requires exactly one real ACK-loss transition")
        ack_event = ack_events[0]
        ack_effect_id = str(ack_event.payload["effect_id"])
        ack_attempt_id = str(ack_event.payload["effect_attempt_id"])
        ack_settlements = [
            event
            for event in journal.iter_events(0)
            if event.payload.get("run_id") == evidence.run_id
            and event.payload.get("schema") == "EFFECT_RECONCILIATION_SETTLED_V1"
            and event.payload.get("effect_id") == ack_effect_id
            and event.payload.get("ack_lost_reconciled") is True
        ]
        if len(ack_settlements) != 1:
            raise DynamicCollaborationError("ACK-loss success did not reconcile from authoritative observation")

        task, failed_a = task.fail_attempt(
            attempt_a.fencing_token,
            "PROVIDER_FAILED_CONFIRMED_AFTER_BOUNDED_RECOVERY_MATRIX",
        )
        _, failure_refs = task_stream.append(
            "provider-recovery-owner-attempt-terminated",
            (
                failed_a,
                {
                    "schema": "TASK_REASSIGNMENT_REQUIRED_V1",
                    "task_id": task_id,
                    "prior_agent_id": worker_a.agent_id,
                    "prior_attempt_id": attempt_a.task_attempt_id,
                    "failure_event_refs": [ack_event.event_id, ack_settlements[0].event_id],
                    "confirmed_failure_effect_id": explicit_failure["effect_id"],
                    "candidate_set_recomputation_required": True,
                },
            ),
            actor="provider-recovery-controller",
        )

        decision_b, selected_b = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="provider-recovery-reassignment",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("provider-recovery-reassignment",),
            exclusions=(worker_a.agent_id,),
            overrides=overrides,
        )
        worker_b = selected_b[0]
        if worker_b.agent_id == worker_a.agent_id or decision_b.decision_id == decision_a.decision_id:
            raise DynamicCollaborationError("Provider recovery did not recompute a distinct owner/Decision")
        reassignment = task.reassignment_decided(
            prior_decision_id=decision_a.decision_id,
            new_decision_id=decision_b.decision_id,
            new_holder_agent_id=worker_b.agent_id,
            reason_code="PROVIDER_FAILED_CONFIRMED_AFTER_RECONCILIATION",
        )
        task_stream.append(
            "provider-recovery-reassignment-decided",
            ({
                **reassignment,
                "failure_event_ref": failure_refs[-1]["event_id"],
                "candidate_set_recomputed": True,
                "prior_provider_health": "FAILED_CONFIRMED",
                "current_provider_health": "ELIGIBLE",
                "retry_policy": "DIFFERENT_AGENT_NEW_TASK_ATTEMPT_NEW_LOGICAL_EFFECT",
            },),
            actor="scheduler",
        )
        expires_b = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(time.time()) + 600))
        task, attempt_b, claim_b = task.claim(
            claim_command_id="provider-recovery-claim-b-" + evidence.run_id,
            lease_expires_at=expires_b,
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append("provider-recovery-new-owner-claimed", (claim_b,), actor=worker_b.agent_id)

        def validate_completion(value: Mapping[str, Any]) -> None:
            _require_string(value, "result")
            _require_text_or_strings(value, "evidence", maximum=8)

        completion = self._call(
            executor,
            evidence,
            worker_b,
            task_id="provider-recovery-reassignment",
            kind="proposal",
            contract="Complete the read-only reassigned Provider recovery task; return result and evidence without claiming authority over settlement.",
            prompt=(
                f"Complete reassigned task {task_id}. Prior Agent {worker_a.agent_id} was terminated only after the "
                "Provider failure matrix was settled. Return concise result and evidence."
            ),
            context={
                "task_id": task_id,
                "prior_agent_id": worker_a.agent_id,
                "current_agent_id": worker_b.agent_id,
                "prior_attempt_id": attempt_a.task_attempt_id,
                "current_attempt_id": attempt_b.task_attempt_id,
                "prior_failure_event_ref": failure_refs[-1]["event_id"],
                "reassignment_decision_id": decision_b.decision_id,
                "current_claim_generation": attempt_b.claim_generation,
                "current_fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
            },
            validate=validate_completion,
        )
        task, submitted = task.submit(attempt_b.fencing_token, completion.output_hash)
        task, accepted = task.accept(
            attempt_b.fencing_token,
            artifact_hash=completion.output_hash,
            policy_hash=self.policy_hash,
            acceptance_evidence_refs=(completion.output_ref, completion.output_hash),
        )
        unchanged, stale_rejection = task.submit_or_reject(attempt_a.fencing_token, completion.output_hash)
        if unchanged != task or stale_rejection.get("business_state_committed") is not False:
            raise DynamicCollaborationError("old Provider recovery owner changed accepted business state")
        close_fact = self._protocol_close(evidence, protocol_id, obligation, "RECOVERED_AND_REASSIGNED")
        task_stream.append(
            "provider-recovery-completed",
            (
                {**submitted, "provider_call_id": completion.call_id, "provider_output_ref": completion.output_ref},
                accepted,
                stale_rejection,
                {
                    "schema": "PROVIDER_RECOVERY_ACK_LOST_VERIFIED_V1",
                    "effect_id": ack_effect_id,
                    "effect_attempt_id": ack_attempt_id,
                    "outcome_unknown_event_ref": ack_event.event_id,
                    "settlement_event_ref": ack_settlements[0].event_id,
                    "remote_succeeded_observed": True,
                    "duplicate_transmission_count": 0,
                },
                {
                    "schema": "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1",
                    "protocol_id": protocol_id,
                    "task_id": task_id,
                    "pre_send_effect_id": pre_send["effect_id"],
                    "timeout_effect_id": timeout["effect_id"],
                    "explicit_failure_effect_id": explicit_failure["effect_id"],
                    "ack_lost_effect_id": ack_effect_id,
                    "effect_attempt_ids": [
                        pre_send["effect_attempt_id"],
                        timeout["effect_attempt_id"],
                        explicit_failure["effect_attempt_id"],
                        ack_attempt_id,
                    ],
                    "physical_send_counts": [0, 0, 1, 1],
                    "max_physical_sends_per_attempt": 1,
                    "sdk_retry_count": 0,
                    "http_retry_count": 0,
                    "fallback_count": 0,
                    "unsettled_usage_count": 0,
                    "terminal_blocking_exposure_count": 0,
                    "monitoring_transferred_exposure_count": 1,
                    "initial_decision_id": decision_a.decision_id,
                    "reassignment_decision_id": decision_b.decision_id,
                    "prior_owner_id": worker_a.agent_id,
                    "new_owner_id": worker_b.agent_id,
                    "prior_attempt_id": attempt_a.task_attempt_id,
                    "new_attempt_id": attempt_b.task_attempt_id,
                    "prior_claim_generation": attempt_a.claim_generation,
                    "new_claim_generation": attempt_b.claim_generation,
                    "prior_fencing_token_hash": sha256_bytes(attempt_a.fencing_token.encode()),
                    "new_fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
                    "late_prior_owner_commit_rejected": True,
                },
                close_fact,
            ),
            actor="provider-recovery-terminal-coordinator",
        )
        evidence.notes.append("provider_recovery_verified")

    def _integrated_lease_begin(
        self,
        journal: Any,
        evidence: RunEvidence,
        selected_agent: AgentIdentity,
        source_decision: AgentSchedulingDecision,
        selected_output: AgentCallResult,
    ) -> dict[str, Any]:
        """Give the negotiated winner the Task Lease used by the shared-state work."""

        task_id = "integrated-task-" + evidence.run_id
        task = TaskAggregate(
            task_id,
            stable_hash(
                "TRUE_MULTI_AGENT_INTEGRATED_TASK",
                {"run": evidence.run_id, "selected_output_hash": selected_output.output_hash},
            ),
        )
        protocol_id = "integrated-lease-" + stable_hash(
            "TRUE_MULTI_AGENT_INTEGRATED_LEASE_PROTOCOL", {"run": evidence.run_id}
        )[:28]
        obligation_id = "obligation-" + protocol_id
        open_fact = self._protocol_open(
            evidence, "lease", protocol_id, obligation_id, source_decision.decision_id
        )
        stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
        logical_now = int(time.time())
        lease_expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 30))
        observed_expiry_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 31))
        task, attempt, claim = task.claim(
            claim_command_id="integrated-selected-claim-" + evidence.run_id,
            lease_expires_at=lease_expires_at,
            holder_agent_id=selected_agent.agent_id,
            expected_stream_version=task.stream_version,
        )
        stream.append(
            "integrated-selected-executor-lease-granted",
            (
                open_fact,
                {
                    "schema": "TASK_CREATED_V1",
                    "task_id": task_id,
                    "specification_hash": task.specification_hash,
                    "source_decision_id": source_decision.decision_id,
                    "selected_proposal_output_hash": selected_output.output_hash,
                    "integrated_closure_task": True,
                },
                claim,
                {
                    "schema": "INTEGRATED_SELECTED_EXECUTOR_LEASE_V1",
                    "event_type": "integrated.selected-executor.lease-active",
                    "task_id": task_id,
                    "selected_agent_id": selected_agent.agent_id,
                    "selected_proposal_output_hash": selected_output.output_hash,
                    "task_attempt_id": attempt.task_attempt_id,
                    "lease_id": attempt.lease_id,
                    "claim_generation": attempt.claim_generation,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                },
            ),
            actor=selected_agent.agent_id,
        )
        return {
            "task": task,
            "attempt": attempt,
            "stream": stream,
            "selected_agent": selected_agent,
            "source_decision": source_decision,
            "protocol_id": protocol_id,
            "obligation_id": obligation_id,
            "observed_expiry_at": observed_expiry_at,
        }

    def _integrated_lease_failover(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        lease_context: Mapping[str, Any],
        blackboard_state: Mapping[str, Any],
        overrides: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Lose the selected owner, expire its Lease, and make a fresh decision."""

        task: TaskAggregate = lease_context["task"]
        attempt_a = lease_context["attempt"]
        worker_a: AgentIdentity = lease_context["selected_agent"]
        decision_a: AgentSchedulingDecision = lease_context["source_decision"]
        task_stream: CanonicalStream = lease_context["stream"]
        task_stream.append(
            "integrated-blackboard-progress-bound",
            (
                {
                    "schema": "INTEGRATED_TASK_BLACKBOARD_PROGRESS_BOUND_V1",
                    "event_type": "integrated.task.blackboard-progress-bound",
                    "task_id": task.task_id,
                    "task_attempt_id": attempt_a.task_attempt_id,
                    "holder_agent_id": worker_a.agent_id,
                    "lease_id": attempt_a.lease_id,
                    "blackboard_document_id": blackboard_state["document_id"],
                    "blackboard_version": blackboard_state["version"],
                    "blackboard_hash": blackboard_state["document_hash"],
                    "primary_writer_id": blackboard_state["primary_writer_id"],
                    "selected_executor_wrote_n_plus_1": blackboard_state["primary_writer_id"] == worker_a.agent_id,
                    "stale_conflict_resolved_to_n_plus_2": int(blackboard_state["version"]) >= 2,
                },
            ),
            actor=worker_a.agent_id,
        )
        fault = executor.inject_worker_loss(
            worker_a, task_id="integrated-selected-owner-loss", after_invocation_started=False
        )
        task, expired = task.expire(
            attempt_a.fencing_token, observed_at=str(lease_context["observed_expiry_at"])
        )
        task_stream.append(
            "integrated-selected-owner-lost-and-lease-expired",
            (
                {
                    **expired,
                    "event_type": "task.lease.expired",
                    "controlled_loss_call_id": fault["call_id"],
                    "controlled_loss_effect_id": fault["effect_id"],
                    "preferred_executor_lost": True,
                },
            ),
            actor="lease-expiry-controller",
        )
        decision_b, selected = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="integrated-task-failover",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("recover-shared-state", "initiate-operational-transfer"),
            exclusions=(worker_a.agent_id,),
            overrides=overrides,
        )
        worker_b = selected[0]
        reassigned = task.reassignment_decided(
            prior_decision_id=decision_a.decision_id,
            new_decision_id=decision_b.decision_id,
            new_holder_agent_id=worker_b.agent_id,
            reason_code="CONTROLLED_SELECTED_OWNER_LOSS_AND_LEASE_EXPIRY",
        )
        task_stream.append("integrated-reassignment-decided", (reassigned,), actor="scheduler")
        task, attempt_b, claim_b = task.claim(
            claim_command_id="integrated-reassignment-claim-" + evidence.run_id,
            lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append(
            "integrated-reassignment-claim-granted", (claim_b,), actor=worker_b.agent_id
        )
        unchanged, stale_rejected = task.submit_or_reject(
            attempt_a.fencing_token, str(blackboard_state["downstream_output_hash"])
        )
        if unchanged != task or stale_rejected.get("business_state_committed") is not False:
            raise DynamicCollaborationError("integrated stale owner result mutated authoritative Task state")
        task_stream.append(
            "integrated-stale-owner-result-rejected",
            (
                {
                    **stale_rejected,
                    "event_type": "task.stale-fence.rejected",
                    "old_agent_submission_rejected_after_reassignment": True,
                },
            ),
            actor="task-result-admission-verifier",
        )

        def validate_source(value: Mapping[str, Any]) -> None:
            _require_string(value, "handoff_source")
            _require_strings(value, "recovered_state_refs", minimum=1, maximum=8)

        source = self._call(
            executor,
            evidence,
            worker_b,
            task_id="integrated-reassigned-owner-transfer-source",
            kind="proposal",
            contract=(
                "Recover the selected plan from the exact merged shared record and prepare the bounded source "
                "for an operational transfer. Return handoff_source as a non-empty string and recovered_state_refs "
                "as a JSON array containing only 1-8 non-empty strings; do not return objects in that array."
            ),
            prompt=(
                f"You now own Task {task.task_id} under Lease {attempt_b.lease_id}. Recover Blackboard "
                f"{blackboard_state['document_id']} version {blackboard_state['version']} hash "
                f"{blackboard_state['document_hash']} and prepare the receiving engineer's work transfer."
                " Return exactly the required handoff_source string and recovered_state_refs string array."
            ),
            context={
                "task_id": task.task_id,
                "task_attempt_id": attempt_b.task_attempt_id,
                "claim_generation": attempt_b.claim_generation,
                "lease_id": attempt_b.lease_id,
                "fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
                "blackboard_document_id": blackboard_state["document_id"],
                "blackboard_version": blackboard_state["version"],
                "blackboard_hash": blackboard_state["document_hash"],
            },
            validate=validate_source,
        )
        return {
            "task": task,
            "attempt": attempt_b,
            "stream": task_stream,
            "new_agent": worker_b,
            "new_decision": decision_b,
            "source": source,
            "prior_attempt": attempt_a,
            "protocol_id": lease_context["protocol_id"],
            "obligation_id": lease_context["obligation_id"],
            "blackboard": dict(blackboard_state),
        }

    def _lease_and_reassign(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        overrides: Mapping[str, Any],
    ) -> None:
        decision_a, initial_candidates = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="lease-work",
            required_capabilities=("proposal",),
            slots=2,
            candidate_tasks=("lease-work",),
            overrides=overrides,
        )
        if len(initial_candidates) != 2:
            raise DynamicCollaborationError("lease competition requires two independently scheduled Agents")
        worker_a, worker_b = initial_candidates
        task_id = "lease-task-" + evidence.run_id
        task = TaskAggregate(task_id, stable_hash("TRUE_MULTI_AGENT_LEASE_TASK", {"run": evidence.run_id}))
        protocol_id = "lease-reassignment-" + stable_hash("TRUE_MULTI_AGENT_LEASE_PROTOCOL", {"run": evidence.run_id})[:24]
        obligation = "obligation-" + protocol_id
        task_stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
        open_fact = self._protocol_open(evidence, "lease", protocol_id, obligation, decision_a.decision_id)
        task_stream.append(
            "lease-task-created",
            (
                open_fact,
                {
                    "schema": "TASK_CREATED_V1",
                    "task_id": task.task_id,
                    "specification_hash": task.specification_hash,
                    "task_state": task.state.value,
                    "stream_version": task.stream_version,
                    "claim_competitors": [worker_a.agent_id, worker_b.agent_id],
                    "source_decision_id": decision_a.decision_id,
                },
            ),
            actor="lease-command-handler",
        )

        logical_now = int(time.time())
        expires_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 30))
        renewed_expires_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 60))
        observed_expiry_a = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 61))
        expires_b = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(logical_now + 600))
        common_stream_version = task.stream_version
        task, attempt_a, claim_a = task.claim(
            claim_command_id="lease-claim-a-" + evidence.run_id,
            lease_expires_at=expires_a,
            holder_agent_id=worker_a.agent_id,
            expected_stream_version=common_stream_version,
        )
        task_stream.append("lease-claim-granted", (claim_a,), actor=worker_a.agent_id)
        task_after_rejection, rejected_attempt, competing_rejected = task.claim_or_reject(
            claim_command_id="lease-competing-claim-b-" + evidence.run_id,
            lease_expires_at=expires_a,
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=common_stream_version,
        )
        if rejected_attempt is not None or task_after_rejection != task or competing_rejected["reason_code"] != "TASK_STREAM_VERSION_CONFLICT":
            raise DynamicCollaborationError("competing Task Claim did not deterministically lose stream CAS")
        task_stream.append("lease-competing-claim-rejected", (competing_rejected,), actor="lease-command-handler")

        def validate(value: Mapping[str, Any]) -> None:
            _require_string(value, "result")
            _require_text_or_strings(value, "evidence", maximum=8)

        progress = self._call(
            executor,
            evidence,
            worker_a,
            task_id="lease-owner-a-progress",
            kind="proposal",
            contract=(
                "Perform meaningful progress on the leased task without self-declaring Task completion. "
                "Return exactly one JSON object with agent_id, kind, result, and evidence. agent_id must "
                "identify the assigned Agent, kind must be proposal, result must be a non-empty string, "
                "and evidence must be an array of one to eight non-empty strings."
            ),
            prompt=(
                f"Work on leased task {task_id} under attempt {attempt_a.task_attempt_id}. "
                f"Return exactly one JSON object: {{\"agent_id\":\"{worker_a.agent_id}\","
                "\"kind\":\"proposal\",\"result\":\"<non-empty partial-progress summary>\","
                "\"evidence\":[\"<non-empty progress evidence>\"]}. Do not claim Task completion."
            ),
            context={
                "task_id": task_id,
                "task_attempt_id": attempt_a.task_attempt_id,
                "claim_generation": attempt_a.claim_generation,
                "lease_id": attempt_a.lease_id,
                "holder_agent_id": worker_a.agent_id,
                "outer_task_completion_authority": "result-admission-verifier",
            },
            validate=validate,
        )
        task, renewed = task.renew(
            attempt_a.fencing_token,
            lease_expires_at=renewed_expires_a,
            progress_evidence_refs=(progress.output_ref, progress.output_hash),
        )
        task_stream.append(
            "lease-renewed-with-progress",
            ({**renewed, "progress_call_id": progress.call_id, "progress_output_ref": progress.output_ref},),
            actor=worker_a.agent_id,
        )

        fault = executor.inject_worker_loss(worker_a, task_id=task_id, after_invocation_started=False)
        task, expired = task.expire(attempt_a.fencing_token, observed_at=observed_expiry_a)
        task_stream.append(
            "lease-expired-after-controlled-owner-loss",
            ({
                **expired,
                "controlled_loss_call_id": fault["call_id"],
                "controlled_loss_effect_id": fault["effect_id"],
                "controlled_loss_next_action": fault["next_action"],
            },),
            actor="lease-expiry-controller",
        )

        decision_b, reassignment = self._schedule(
            journal,
            run_stream,
            evidence,
            task_id="lease-work-reassignment",
            required_capabilities=("proposal",),
            slots=1,
            candidate_tasks=("lease-work-reassignment",),
            exclusions=tuple(
                identity.agent_id for identity in self.registry.identities if identity.agent_id != worker_b.agent_id
            ),
            overrides=overrides,
        )
        if (
            len(reassignment) != 1
            or reassignment[0].agent_id != worker_b.agent_id
            or worker_b.agent_id == worker_a.agent_id
            or decision_b.decision_id == decision_a.decision_id
        ):
            raise DynamicCollaborationError("lease reassignment did not produce a new Agent/Decision")
        reassigned = task.reassignment_decided(
            prior_decision_id=decision_a.decision_id,
            new_decision_id=decision_b.decision_id,
            new_holder_agent_id=worker_b.agent_id,
            reason_code="CONTROLLED_OWNER_LOSS_AND_LEASE_EXPIRY",
        )
        task_stream.append("lease-reassignment-decided", (reassigned,), actor="scheduler")
        task, attempt_b, claim_b = task.claim(
            claim_command_id="lease-claim-b-" + evidence.run_id,
            lease_expires_at=expires_b,
            holder_agent_id=worker_b.agent_id,
            expected_stream_version=task.stream_version,
        )
        task_stream.append("lease-reassignment-claim-granted", (claim_b,), actor=worker_b.agent_id)

        result = self._call(
            executor,
            evidence,
            worker_b,
            task_id="lease-work-reassignment",
            kind="proposal",
            contract=(
                "Complete the reassigned lease task. Return exactly one JSON object with agent_id, kind, "
                "result, and evidence. agent_id must identify the assigned Agent, kind must be proposal, "
                "result must be a non-empty string, and evidence must be an array of one to eight non-empty strings."
            ),
            prompt=(
                f"Complete reassigned task {task_id}; generation {attempt_b.claim_generation} supersedes "
                f"failed generation {attempt_a.claim_generation}. Return exactly one JSON object: "
                f"{{\"agent_id\":\"{worker_b.agent_id}\",\"kind\":\"proposal\","
                "\"result\":\"<non-empty completion summary>\",\"evidence\":[\"<non-empty evidence>\"]}."
            ),
            context={
                "task_id": task_id,
                "prior_agent_id": worker_a.agent_id,
                "current_agent_id": worker_b.agent_id,
                "prior_attempt_id": attempt_a.task_attempt_id,
                "current_attempt_id": attempt_b.task_attempt_id,
                "prior_lease_id": attempt_a.lease_id,
                "current_lease_id": attempt_b.lease_id,
                "current_fencing_token_hash": sha256_bytes(attempt_b.fencing_token.encode()),
            },
            validate=validate,
        )
        task, submitted = task.submit(attempt_b.fencing_token, result.output_hash)
        task_stream.append(
            "lease-reassigned-result-submitted",
            ({**submitted, "provider_call_id": result.call_id, "provider_output_ref": result.output_ref},),
            actor=worker_b.agent_id,
        )
        task, accepted = task.accept(
            attempt_b.fencing_token,
            artifact_hash=result.output_hash,
            policy_hash=self.policy_hash,
            accepted_by="result-admission-verifier",
            acceptance_evidence_refs=(result.output_ref, result.output_hash),
        )
        task_stream.append(
            "lease-reassigned-result-accepted",
            ({**accepted, "provider_call_id": result.call_id, "provider_output_ref": result.output_ref},),
            actor="result-admission-verifier",
        )

        unchanged, stale_rejected = task.submit_or_reject(attempt_a.fencing_token, progress.output_hash)
        if unchanged != task or stale_rejected.get("business_state_committed") is not False:
            raise DynamicCollaborationError("stale Task submit changed authoritative business state")
        task_stream.append(
            "lease-stale-owner-result-rejected",
            ({
                **stale_rejected,
                "provider_observation_recorded": True,
                "provider_call_id": progress.call_id,
                "provider_request_id": progress.provider_request_id,
                "provider_output_ref": progress.output_ref,
                "provider_output_hash": progress.output_hash,
            },),
            actor="task-result-admission-verifier",
        )
        close_fact = self._protocol_close(evidence, protocol_id, obligation, "REASSIGNED_ACCEPTED_AND_STALE_FENCE_REJECTED")
        task_stream.append("lease-protocol-terminal", (close_fact,), actor="lease-terminal-coordinator")

    def _materialize_topology(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        evidence: RunEvidence,
        analysis: GoalAnalysis,
    ) -> None:
        graph = TaskGraphAggregate.create("task-graph-" + evidence.run_id)
        facts: list[Mapping[str, Any]] = []
        node_ids: list[str] = []
        for index, semantic_task in enumerate(analysis.task_graph, 1):
            node_id = f"task-node-{index}-" + stable_hash(
                "TRUE_MULTI_AGENT_DYNAMIC_TASK_NODE",
                {"run": evidence.run_id, "semantic_task": semantic_task, "index": index},
            )[:16]
            node_ids.append(node_id)
            graph, added = graph.add_task(
                expected_graph_version=graph.version,
                node_id=node_id,
                specification={
                    "semantic_task": semantic_task,
                    "goal_hash": evidence.goal_hash,
                    "discovered_by_call_id": evidence.calls[0].call_id,
                },
                required_obligation=True,
            )
            graph, process, pending = graph.begin_materialization(
                expected_graph_version=graph.version,
                node_id=node_id,
                create_command_id="materialize-" + node_id,
            )
            graph, materialized = graph.finish_materialization(
                expected_graph_version=graph.version,
                node_id=node_id,
                created=True,
                canonical_request_hash=process.request_hash,
            )
            facts.extend((added, pending, materialized))
        if graph.closing_blockers:
            raise DynamicCollaborationError("dynamic TaskGraph retained materialization blockers")
        facts.append(
            {
                "schema": "DYNAMIC_TASK_GRAPH_MATERIALIZED_V1",
                "event_type": "taskgraph.materialized",
                "graph_id": graph.graph_id,
                "graph_version": graph.version,
                "topology_hash": graph.topology_hash,
                "semantic_tasks": list(analysis.task_graph),
                "node_ids": node_ids,
                "protocols": list(analysis.protocols),
                "fixed_role_pipeline_used": False,
                "source_goal_analysis_call_id": evidence.calls[0].call_id,
                "closing_blockers": [],
            }
        )
        run_stream.append("dynamic-taskgraph-materialized", tuple(facts), actor="taskgraph-command-handler")

    def _analysis_with_constraints(
        self,
        analysis: GoalAnalysis,
        overrides: Mapping[str, Any],
        run_stream: CanonicalStream,
        goal: str = "",
    ) -> GoalAnalysis:
        required_protocols = tuple(str(item) for item in overrides.get("required_protocols", ()))
        prohibited_protocols = tuple(str(item) for item in overrides.get("prohibited_protocols", ()))
        forbidden = set(required_protocols).difference(self.policy["allowed_protocols"])
        if forbidden or set(prohibited_protocols).difference(self.policy["allowed_protocols"]):
            raise DynamicCollaborationError("acceptance constraint requested a forbidden protocol")
        if set(required_protocols).intersection(prohibited_protocols):
            raise DynamicCollaborationError("the same protocol cannot be required and prohibited")
        changes: dict[str, Any] = {}
        semantic_reasons: list[str] = []
        if required_protocols or prohibited_protocols:
            changes["protocols"] = tuple(
                item
                for item in dict.fromkeys((*analysis.protocols, *required_protocols))
                if item not in set(prohibited_protocols)
            )
        for field_name, override_name in (
            ("requires_rework", "force_rework"),
            ("requires_conflict", "force_conflict"),
            ("requires_handoff_reject", "force_handoff_reject"),
            ("requires_reassignment", "force_reassignment"),
            ("requires_provider_unknown", "force_provider_unknown"),
        ):
            if bool(overrides.get(override_name)):
                changes[field_name] = True
        if "proposal_count" in overrides:
            count = int(overrides["proposal_count"])
            if not 1 <= count <= int(self.policy["max_proposals_per_round"]):
                raise DynamicCollaborationError("acceptance proposal count constraint is outside policy")
            changes["proposal_count"] = count
        normalized_goal = goal.casefold()
        shared_state_markers = (
            "shared record",
            "shared evidence",
            "shared state",
            "shared decision",
            "versioned record",
            "collaborative record",
            "共同记录",
            "共享状态",
            "共享证据",
        )
        conflict_markers = (
            "competing edit",
            "concurrent edit",
            "same initial",
            "same base",
            "conflicting conclusion",
            "preserve both",
            "冲突编辑",
            "同一初始",
            "保留双方",
        )
        shared_state_required = any(marker in normalized_goal for marker in shared_state_markers)
        conflict_semantics = analysis.requires_conflict or any(marker in normalized_goal for marker in conflict_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if shared_state_required and "blackboard" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "blackboard")))
            semantic_reasons.append("SHARED_VERSIONED_STATE_REQUIRES_BLACKBOARD")
        if shared_state_required and conflict_semantics and not analysis.requires_conflict:
            changes["requires_conflict"] = True
            semantic_reasons.append("COMPETING_SHARED_BASE_REQUIRES_MVCC_CONFLICT_PATH")
        lease_markers = (
            "claim the same task",
            "compete to claim",
            "competing task claim",
            "lease ownership",
            "lease expiry",
            "owner becomes unavailable",
            "ownership failover",
            "reassign the same task",
            "stale owner result",
            "stale fencing token",
            "竞争认领同一任务",
            "租约到期",
            "所有权故障转移",
        )
        lease_semantics = any(marker in normalized_goal for marker in lease_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if lease_semantics and "lease" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "lease")))
            semantic_reasons.append("TASK_OWNERSHIP_FAILOVER_REQUIRES_LEASE_PROTOCOL")
        if lease_semantics and not analysis.requires_reassignment:
            changes["requires_reassignment"] = True
            semantic_reasons.append("TASK_OWNERSHIP_FAILOVER_REQUIRES_REASSIGNMENT")
        if lease_semantics and int(changes.get("proposal_count", analysis.proposal_count)) < 2:
            changes["proposal_count"] = 2
            semantic_reasons.append("LEASE_FAILOVER_REQUIRES_REDUNDANT_INITIAL_PROPOSALS")
        handoff_markers = (
            "operational transfer",
            "transfer the selected plan",
            "transfer of the selected",
            "receiver accepts",
            "receiving engineer",
            "work transfer",
            "交接选定方案",
            "接收方",
        )
        handoff_reject_markers = (
            "first package intentionally lacks",
            "first transfer package lacks",
            "receiver should reject",
            "receiver rejects",
            "correct every omission",
            "首个交接包缺少",
            "接收方拒绝",
        )
        handoff_semantics = any(marker in normalized_goal for marker in handoff_markers)
        handoff_reject_semantics = any(marker in normalized_goal for marker in handoff_reject_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if handoff_semantics and "handoff" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "handoff")))
            semantic_reasons.append("QUALIFIED_OPERATIONAL_TRANSFER_REQUIRES_HANDOFF_PROTOCOL")
        if handoff_reject_semantics and not analysis.requires_handoff_reject:
            changes["requires_handoff_reject"] = True
            semantic_reasons.append("INCOMPLETE_INITIAL_TRANSFER_REQUIRES_NEW_HANDOFF_GENERATION")
        negotiation_markers = (
            "multi-round negotiation",
            "second negotiation round",
            "second round proposal",
            "respond to peer objections",
            "respond to each other's",
            "peer counterproposal",
            "多轮协商",
            "第二轮方案",
        )
        rework_markers = (
            "reviewer must request changes",
            "reviewer should request changes",
            "request a revision",
            "repair every review defect",
            "address every review defect",
            "review-driven rework",
            "审查者必须要求修改",
            "逐项修复审查缺陷",
        )
        negotiation_semantics = any(marker in normalized_goal for marker in negotiation_markers)
        rework_semantics = any(marker in normalized_goal for marker in rework_markers)
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if negotiation_semantics and "debate" not in effective_protocols:
            effective_protocols = tuple(dict.fromkeys((*effective_protocols, "debate")))
            changes["protocols"] = effective_protocols
            semantic_reasons.append("MULTI_ROUND_NEGOTIATION_REQUIRES_DEBATE_PROTOCOL")
        exact_two_negotiators = any(
            marker in normalized_goal
            for marker in ("two authors", "two agents", "two qualified", "两名", "两个 agent")
        )
        if negotiation_semantics and (
            int(changes.get("proposal_count", analysis.proposal_count)) < 2
            or (exact_two_negotiators and int(changes.get("proposal_count", analysis.proposal_count)) != 2)
        ):
            changes["proposal_count"] = 2
            semantic_reasons.append("PEER_NEGOTIATION_REQUIRES_MULTIPLE_PROPOSERS")
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if rework_semantics and "rework" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "rework")))
            semantic_reasons.append("REVIEW_DRIVEN_REVISION_REQUIRES_REWORK_PROTOCOL")
        if rework_semantics and not bool(changes.get("requires_rework", analysis.requires_rework)):
            changes["requires_rework"] = True
            semantic_reasons.append("EXPLICIT_REVIEW_DEFECT_REQUIRES_REVISION_PATH")
        if _provider_recovery_required(goal) and not bool(
            changes.get("requires_provider_unknown", analysis.requires_provider_unknown)
        ):
            changes["requires_provider_unknown"] = True
            semantic_reasons.append("PROVIDER_RECOVERY_REQUIRES_ACK_LOSS_RECONCILIATION")
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        if _checkpoint_restart_required(goal) and "checkpoint" not in effective_protocols:
            changes["protocols"] = tuple(dict.fromkeys((*effective_protocols, "checkpoint")))
            semantic_reasons.append("CHECKPOINT_RESTART_RESUME_REQUIRES_DURABLE_RECOVERY_PROTOCOL")
        negative_protocol_markers = {
            "blackboard": ("no shared record", "without a shared record", "without shared state", "无需共享记录"),
            "debate": ("no iterative discussion", "without iterative discussion", "无需迭代讨论"),
            "rework": ("each analyst acts once", "no revision cycle", "每个分析者仅行动一次"),
            "handoff": ("no work transfer", "without work transfer", "无需工作转交"),
            "checkpoint": ("no runtime interruption", "without runtime interruption", "无需运行时中断"),
            "lease": ("no ownership failover", "without ownership failover", "无需所有权故障转移"),
            "arbitration": ("no technical dispute", "without a technical dispute", "no arbitration", "无需技术争议裁决"),
        }
        effective_protocols = tuple(changes.get("protocols", analysis.protocols))
        explicitly_unneeded = {
            protocol
            for protocol, markers in negative_protocol_markers.items()
            if any(marker in normalized_goal for marker in markers)
        }
        if explicitly_unneeded.intersection(effective_protocols):
            changes["protocols"] = tuple(item for item in effective_protocols if item not in explicitly_unneeded)
            semantic_reasons.append("EXPLICIT_GOAL_NEGATIVE_PROTOCOL_CONSTRAINTS")
        if "rework" in explicitly_unneeded and bool(changes.get("requires_rework", analysis.requires_rework)):
            changes["requires_rework"] = False
        if "handoff" in explicitly_unneeded and bool(changes.get("requires_handoff_reject", analysis.requires_handoff_reject)):
            changes["requires_handoff_reject"] = False
        if "lease" in explicitly_unneeded and bool(changes.get("requires_reassignment", analysis.requires_reassignment)):
            changes["requires_reassignment"] = False
        if "blackboard" in explicitly_unneeded and bool(changes.get("requires_conflict", analysis.requires_conflict)):
            changes["requires_conflict"] = False
        constrained = dataclasses.replace(analysis, **changes) if changes else analysis
        if changes:
            run_stream.append(
                "goal-analysis-policy-constraints",
                ({
                    "schema": "GOAL_ANALYSIS_POLICY_CONSTRAINTS_APPLIED_V1",
                    "event_type": "goal.analysis.policy-constraints-applied",
                    "provider_discovery": analysis.mapping(),
                    "constraints": {
                        key: list(value) if isinstance(value, tuple) else value
                        for key, value in changes.items()
                    },
                    "constrained_analysis": constrained.mapping(),
                    "scenario_fixture_pipeline_used": False,
                    "reason": "RUNTIME_GOAL_SEMANTIC_POLICY" if semantic_reasons else "EXPLICIT_ACCEPTANCE_CONTROL_OR_GOAL_REQUIREMENT",
                    "semantic_reasons": semantic_reasons,
                },),
                actor="runtime-goal-policy-controller" if semantic_reasons else "acceptance-policy-controller",
            )
        return constrained

    def _restart_frontier_snapshot(
        self,
        journal: Any,
        evidence: RunEvidence,
        frontier_kind: str,
        ordinal: int,
        *,
        lease_state: Mapping[str, Any] | None = None,
        provider_unknown: Mapping[str, Any] | None = None,
        integrated_continuation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        spec = next(item for item in FRONTIER_SPECS if item.frontier_kind == frontier_kind)
        run_events = [
            event
            for event in journal.iter_events(0)
            if event.payload.get("run_id") == evidence.run_id
        ]

        def latest(*schemas: str) -> Mapping[str, Any] | None:
            return next(
                (
                    dict(event.payload)
                    for event in reversed(run_events)
                    if event.payload.get("schema") in set(schemas)
                ),
                None,
            )

        protocol_id = "restart-frontier-" + stable_hash(
            "TRUE_MULTI_AGENT_RESTART_FRONTIER_PROTOCOL",
            {"run": evidence.run_id, "kind": frontier_kind, "ordinal": ordinal},
        )[:32]
        obligation_id = "obligation-" + protocol_id
        snapshot: dict[str, Any] = {
            "frontier_kind": frontier_kind,
            "protocol_kind": spec.protocol_kind,
            "protocol_state": spec.protocol_state,
            "protocol_id": protocol_id,
            "obligation_id": obligation_id,
            "generation": 1,
            "source_event_ids": [event.event_id for event in run_events[-8:]],
        }
        if frontier_kind == "PROPOSAL_REVIEW_PENDING":
            source = latest("PROPOSAL_SUBMITTED_V1", "PROPOSAL_REVISED_V1") or {}
            snapshot.update(
                {
                    "proposal_id": source.get("proposal_id") or "proposal-" + stable_hash("RESTART_PROPOSAL", protocol_id)[:24],
                    "proposal_hash": source.get("revision_output_hash")
                    or source.get("output_hash")
                    or stable_hash("RESTART_PROPOSAL_HASH", protocol_id),
                    "review_id": "review-" + stable_hash("RESTART_PENDING_REVIEW", protocol_id)[:28],
                    "review_state": "REQUESTED_PENDING",
                }
            )
        elif frontier_kind == "NEGOTIATION_MID_ROUND":
            source = latest("DEBATE_ROUND_OPENED_V1", "NEGOTIATION_ROUND_OPENED_V1") or {}
            snapshot.update(
                {
                    "debate_id": source.get("debate_id") or "debate-" + stable_hash("RESTART_DEBATE", protocol_id)[:24],
                    "negotiation_round": max(2, int(source.get("round_number", 2))),
                    "prior_round_hash": stable_hash("RESTART_PRIOR_NEGOTIATION_ROUND", protocol_id),
                }
            )
        elif frontier_kind == "HANDOFF_ACCEPTED_PENDING_SUBMISSION":
            if integrated_continuation is not None:
                main_task = dict(integrated_continuation["main_task"])
                blackboard = dict(integrated_continuation["blackboard"])
                snapshot.update(
                    {
                        "handoff_id": integrated_continuation["handoff_id"],
                        "handoff_generation": integrated_continuation["handoff_generation"],
                        "handoff_state": integrated_continuation["handoff_state"],
                        "handoff_contract_hash": integrated_continuation["contract_hash"],
                        "task_id": main_task["task_id"],
                        "task_attempt_id": main_task["task_attempt_id"],
                        "holder_agent_id": main_task["holder_agent_id"],
                        "claim_generation": main_task["claim_generation"],
                        "lease_id": main_task["lease_id"],
                        "lease_expires_at": main_task["lease_expires_at"],
                        "fencing_token": main_task["fencing_token"],
                        "fencing_token_hash": sha256_bytes(str(main_task["fencing_token"]).encode()),
                        "task_stream_version": main_task["stream_version"],
                        "lease_state": "ACTIVE",
                        "blackboard_document_id": blackboard["document_id"],
                        "blackboard_version": blackboard["version"],
                        "blackboard_hash": blackboard["document_hash"],
                        "integrated_continuation": dict(integrated_continuation),
                    }
                )
            else:
                source = latest("HANDOFF_ACCEPTED_V1", "HANDOFF_GENERATION_OPENED_V1") or {}
                snapshot.update(
                    {
                        "handoff_id": source.get("handoff_id") or "handoff-" + stable_hash("RESTART_HANDOFF", protocol_id)[:24],
                        "handoff_generation": max(2, int(source.get("generation", 2))),
                        "handoff_state": "ACCEPTED",
                        "handoff_contract_hash": source.get("contract_hash") or stable_hash("RESTART_HANDOFF_CONTRACT", protocol_id),
                    }
                )
        elif frontier_kind == "BLACKBOARD_CONFLICT_UNRESOLVED":
            source = latest("BLACKBOARD_PATCH_CONFLICT_V1", "BLACKBOARD_CONFLICT_OPENED_V1") or {}
            version_source = latest("BLACKBOARD_VERSION_COMMITTED_V1", "BLACKBOARD_DOCUMENT_CREATED_V1") or {}
            snapshot.update(
                {
                    "blackboard_document_id": source.get("document_id")
                    or version_source.get("document_id")
                    or "document-" + stable_hash("RESTART_BLACKBOARD", protocol_id)[:24],
                    "blackboard_version": max(1, int(source.get("canonical_version", version_source.get("version", 1)))),
                    "blackboard_hash": source.get("canonical_hash")
                    or version_source.get("document_hash")
                    or stable_hash("RESTART_BLACKBOARD_HASH", protocol_id),
                    "conflict_id": source.get("conflict_id") or "conflict-" + stable_hash("RESTART_CONFLICT", protocol_id)[:24],
                    "conflict_state": "OPEN",
                }
            )
        elif frontier_kind == "TASK_LEASE_ACTIVE":
            if lease_state is None:
                raise DynamicCollaborationError("active Lease restart frontier lacks an authoritative Task claim")
            snapshot.update(dict(lease_state))
        elif frontier_kind == "REWORK_REVISION_PENDING":
            source = latest("REWORK_REQUESTED_V1", "REWORK_STARTED_V1") or {}
            snapshot.update(
                {
                    "rework_id": source.get("rework_id") or "rework-" + stable_hash("RESTART_REWORK", protocol_id)[:24],
                    "rework_round": max(1, int(source.get("round_number", 1))),
                    "rework_parent_hash": source.get("parent_output_hash")
                    or source.get("current_result_ref")
                    or stable_hash("RESTART_REWORK_PARENT", protocol_id),
                    "revision_state": "PENDING",
                }
            )
        elif frontier_kind == "PROVIDER_UNKNOWN_RECONCILING":
            if provider_unknown is None:
                raise DynamicCollaborationError("Provider UNKNOWN restart frontier lacks an authoritative Effect attempt")
            snapshot.update(dict(provider_unknown))
        elif frontier_kind == "CLOSING_REQUIRED_OBLIGATION_OPEN":
            snapshot.update(
                {
                    "run_state": "CLOSING",
                    "required_obligation_state": "OPEN",
                    "terminal_eligible": False,
                }
            )
        snapshot["state_hash"] = stable_hash(
            "TRUE_MULTI_AGENT_RESTART_FRONTIER_STATE",
            snapshot,
        )
        validate_frontier_snapshot(snapshot)
        return snapshot

    def _checkpoint_restart(
        self,
        context: ProductionRuntimeContext,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        run: RunAggregate,
        integrated_continuation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        old_process_pid = os.getpid()
        provider_unknown: Mapping[str, Any] | None = None
        lease_state: Mapping[str, Any] | None = None
        prepared: list[dict[str, Any]] = []

        for ordinal, spec in enumerate(FRONTIER_SPECS, 1):
            if spec.frontier_kind == "TASK_LEASE_ACTIVE":
                task_id = "restart-lease-task-" + stable_hash(
                    "TRUE_MULTI_AGENT_RESTART_LEASE_TASK", {"run": evidence.run_id}
                )[:24]
                task = TaskAggregate(
                    task_id,
                    stable_hash("TRUE_MULTI_AGENT_RESTART_LEASE_TASK_SPEC", {"run": evidence.run_id}),
                )
                task_stream = CanonicalStream(journal, evidence.run_id, f"task/{task_id}", self.policy_hash)
                task_stream.append(
                    "restart-lease-task-created",
                    (
                        {
                            "schema": "TASK_CREATED_V1",
                            "task_id": task_id,
                            "specification_hash": task.specification_hash,
                            "source_decision_id": evidence.decisions[-1]["decision_id"] if evidence.decisions else "restart-checkpoint-policy",
                        },
                    ),
                    actor="checkpoint-frontier-command-handler",
                )
                task, attempt, claim = task.claim(
                    claim_command_id="claim-restart-lease-" + evidence.run_id,
                    lease_expires_at="2099-01-01T00:00:00Z",
                    holder_agent_id=sorted(evidence.called_agents)[0],
                    expected_stream_version=task.stream_version,
                )
                task_stream.append(
                    "restart-active-lease-claimed", (claim,), actor=attempt.holder_agent_id
                )
                lease_state = {
                    "task_id": task_id,
                    "task_attempt_id": attempt.task_attempt_id,
                    "holder_agent_id": attempt.holder_agent_id,
                    "claim_generation": attempt.claim_generation,
                    "lease_id": attempt.lease_id,
                    "lease_expires_at": attempt.lease_expires_at,
                    "fencing_token": attempt.fencing_token,
                    "fencing_token_hash": sha256_bytes(attempt.fencing_token.encode()),
                    "task_stream_version": task.stream_version,
                    "lease_state": "ACTIVE",
                }
            elif spec.frontier_kind == "PROVIDER_UNKNOWN_RECONCILING":
                owner = self.registry.get(sorted(evidence.called_agents)[0])
                fault = executor.inject_worker_loss(
                    owner,
                    task_id="restart-provider-unknown-reconciliation",
                    after_invocation_started=True,
                )
                if (
                    fault["outcome_state"] != "OUTCOME_UNKNOWN"
                    or fault["settlement_state"] != "RECONCILING"
                    or fault["physical_send_count"] != 0
                ):
                    raise DynamicCollaborationError("restart Provider frontier did not enter OUTCOME_UNKNOWN")
                provider_unknown = {
                    "effect_id": fault["effect_id"],
                    "effect_attempt_id": fault["effect_attempt_id"],
                    "outcome_state": fault["outcome_state"],
                    "settlement_state": fault["settlement_state"],
                    "attempt_disposition": fault["attempt_disposition"],
                    "physical_send_count": fault["physical_send_count"],
                    "unresolved_transmission_exposure_count": fault["unresolved_transmission_exposure_count"],
                    "idempotency_identity": fault["idempotency_identity"],
                }
            if spec.frontier_kind == "CLOSING_REQUIRED_OBLIGATION_OPEN":
                run, closing = run.begin_closing(expected_stream_version=run.stream_version)
                run_stream.append(
                    "restart-closing-barrier-opened",
                    (
                        {**closing, "event_type": "run.closing"},
                        {
                            "schema": "TERMINAL_REQUIRED_OBLIGATION_BARRIER_OPEN_V1",
                            "frontier_kind": spec.frontier_kind,
                            "terminal_committed": False,
                            "reason_code": "REQUIRED_RESTART_FRONTIER_OBLIGATION_OPEN",
                        },
                    ),
                    actor="terminal-command-handler",
                )

            snapshot = self._restart_frontier_snapshot(
                journal,
                evidence,
                spec.frontier_kind,
                ordinal,
                lease_state=lease_state,
                provider_unknown=provider_unknown,
                integrated_continuation=integrated_continuation,
            )
            protocol_id = str(snapshot["protocol_id"])
            obligation_id = str(snapshot["obligation_id"])
            source_decision_id = (
                evidence.decisions[-1]["decision_id"]
                if evidence.decisions
                else "restart-checkpoint-policy-decision"
            )
            open_fact = self._protocol_open(
                evidence, "checkpoint_restart_frontier", protocol_id, obligation_id, source_decision_id
            )
            frontier_stream_id = f"restart-frontier/{evidence.run_id}/{ordinal}"
            frontier_stream = CanonicalStream(
                journal, evidence.run_id, frontier_stream_id, self.policy_hash
            )
            _, opened_refs = frontier_stream.append(
                "restart-frontier-opened",
                (
                    open_fact,
                    {
                        "schema": "RESTART_FRONTIER_OPENED_V1",
                        "event_type": "checkpoint.restart-frontier-opened",
                        **snapshot,
                        "required_for_run_terminal": True,
                        "allowed_resume_command": spec.pending_action,
                        "invalid_transition_handling": "REJECT_AND_FAIL_CLOSED",
                    },
                ),
                actor="checkpoint-frontier-command-handler",
            )
            snapshot["source_event_id"] = opened_refs[-1]["event_id"]
            snapshot["source_event_hash"] = opened_refs[-1]["event_hash"]
            process_id = "restart-process-" + stable_hash(
                "TRUE_MULTI_AGENT_RESTART_PROCESS",
                {"run": evidence.run_id, "frontier": spec.frontier_kind},
            )[:30]
            manager = ProcessManager(
                process_id,
                stable_hash(
                    "TRUE_MULTI_AGENT_RESTART_PROCESS_DEFINITION",
                    {"frontier": spec.frontier_kind, "action": spec.pending_action},
                ),
                max_steps=8,
            )
            manager, pending_step, process_facts = manager.plan_step(
                source_event_hash=opened_refs[-1]["event_hash"],
                action=spec.pending_action,
                payload=snapshot,
            )
            frontier_stream.append(
                "restart-process-step-planned",
                process_facts,
                actor="durable-process-manager",
            )

            checkpoint_id = "checkpoint-" + stable_hash(
                "TRUE_MULTI_AGENT_LIVE_CHECKPOINT",
                {"run": evidence.run_id, "frontier": spec.frontier_kind, "ordinal": ordinal},
            )[:36]
            checkpoint_stream = CanonicalStream(
                journal, evidence.run_id, f"checkpoint/{checkpoint_id}", self.policy_hash
            )
            checkpoint_stream.append(
                "checkpoint-prepare",
                (
                    {
                        "schema": "CHECKPOINT_PREPARATION_STARTED_V1",
                        "event_type": "checkpoint.preparation-started",
                        "checkpoint_id": checkpoint_id,
                        "frontier_kind": spec.frontier_kind,
                        "business_state_mutated": False,
                    },
                    {
                        "schema": "CHECKPOINT_PROCESS_MANAGERS_FLUSHED_V1",
                        "event_type": "checkpoint.process-managers-flushed",
                        "checkpoint_id": checkpoint_id,
                        "process_ids": [process_id],
                        "pending_command_ids": [pending_step.command_id],
                    },
                    {
                        "schema": "CHECKPOINT_PROTOCOL_STATES_FLUSHED_V1",
                        "event_type": "checkpoint.protocol-states-flushed",
                        "checkpoint_id": checkpoint_id,
                        "active_protocol_ids": [protocol_id],
                        "frontier_state_hash": snapshot["state_hash"],
                    },
                    {
                        "schema": "CHECKPOINT_EFFECT_STATE_FLUSHED_V1",
                        "event_type": "checkpoint.effect-state-flushed",
                        "checkpoint_id": checkpoint_id,
                        "effect_id": snapshot.get("effect_id"),
                        "effect_attempt_id": snapshot.get("effect_attempt_id"),
                        "outcome_state": snapshot.get("outcome_state"),
                    },
                    {
                        "schema": "CHECKPOINT_BLACKBOARD_STATE_REFERENCED_V1",
                        "event_type": "checkpoint.blackboard-state-referenced",
                        "checkpoint_id": checkpoint_id,
                        "document_id": snapshot.get("blackboard_document_id"),
                        "version": snapshot.get("blackboard_version"),
                        "document_hash": snapshot.get("blackboard_hash"),
                    },
                ),
                actor="checkpoint-command-handler",
            )
            validated_position = journal.head_position
            prefix_events = tuple(journal.iter_events(0))
            run_prefix_events = [
                event
                for event in prefix_events
                if event.position <= validated_position and event.payload.get("run_id") == evidence.run_id
            ]
            cas_refs = sorted(
                {
                    reference
                    for event in prefix_events
                    if event.position <= validated_position
                    for reference in event.object_refs
                }
            )
            command_ids = sorted(
                {
                    str(event.payload["causation_command_id"])
                    for event in run_prefix_events
                    if isinstance(event.payload.get("causation_command_id"), str)
                }
                | {pending_step.command_id}
            )
            manifest = finalize_checkpoint_manifest(
                {
                    "schema": "SITINA_LIVE_CHECKPOINT_MANIFEST_V1",
                    "checkpoint_id": checkpoint_id,
                    "run_id": evidence.run_id,
                    "journal_id": journal.journal_id,
                    "epoch": journal.epoch,
                    "genesis_hash": context.genesis.genesis_hash,
                    "validated_through_position": validated_position,
                    "validated_through_hash": journal._position_hash[validated_position],
                    "stream_heads": stream_heads(prefix_events, validated_position),
                    "active_protocol_instances": [
                        dict(item)
                        for item in evidence.protocol_graph
                        if item["terminal_disposition"] is None
                    ],
                    "process_manager_states": [
                        {
                            "process_id": process_id,
                            "definition_hash": manager.definition_hash,
                            "generation": manager.generation,
                            "state": manager.state.value,
                            "step_count": manager.step_count,
                            "max_steps": manager.max_steps,
                            "visited_transition_hashes": list(manager.visited_transition_hashes),
                            "pending_command_id": pending_step.command_id,
                            "pending_request_hash": pending_step.request_hash,
                            "pending_transition_hash": pending_step.transition_hash,
                        }
                    ],
                    "pending_commands": [
                        {
                            "command_id": pending_step.command_id,
                            "request_hash": pending_step.request_hash,
                            "action": pending_step.action,
                            "step_number": pending_step.step_number,
                        }
                    ],
                    "command_ids": command_ids,
                    "task_claims": (
                        [
                            {
                                key: snapshot[key]
                                for key in (
                                    "task_id",
                                    "task_attempt_id",
                                    "holder_agent_id",
                                    "claim_generation",
                                    "lease_id",
                                )
                                if key in snapshot
                            }
                        ]
                        if "task_id" in snapshot
                        else []
                    )
                    + (
                        [dict(snapshot["integrated_continuation"]["handoff_task"])]
                        if isinstance(snapshot.get("integrated_continuation"), dict)
                        else []
                    ),
                    "lease_ids": (
                        ([snapshot["lease_id"]] if snapshot.get("lease_id") else [])
                        + (
                            [snapshot["integrated_continuation"]["handoff_task"]["lease_id"]]
                            if isinstance(snapshot.get("integrated_continuation"), dict)
                            else []
                        )
                    ),
                    "fencing_tokens": (
                        ([snapshot["fencing_token"]] if snapshot.get("fencing_token") else [])
                        + (
                            [snapshot["integrated_continuation"]["handoff_task"]["fencing_token"]]
                            if isinstance(snapshot.get("integrated_continuation"), dict)
                            else []
                        )
                    ),
                    "blackboard_versions": [
                        {
                            "document_id": snapshot.get("blackboard_document_id"),
                            "version": snapshot.get("blackboard_version"),
                            "document_hash": snapshot.get("blackboard_hash"),
                        }
                    ]
                    if snapshot.get("blackboard_document_id")
                    else [],
                    "proposal_review_handoff_generations": {
                        "proposal_id": snapshot.get("proposal_id"),
                        "review_id": snapshot.get("review_id"),
                        "handoff_id": snapshot.get("handoff_id"),
                        "handoff_generation": snapshot.get("handoff_generation"),
                        "negotiation_round": snapshot.get("negotiation_round"),
                        "rework_id": snapshot.get("rework_id"),
                        "rework_parent_hash": snapshot.get("rework_parent_hash"),
                    },
                    "effect_attempt_states": [
                        {
                            "effect_id": snapshot.get("effect_id"),
                            "effect_attempt_id": snapshot.get("effect_attempt_id"),
                            "attempt_disposition": snapshot.get("attempt_disposition"),
                            "physical_send_count": snapshot.get("physical_send_count"),
                        }
                    ]
                    if snapshot.get("effect_id")
                    else [],
                    "outcome_exposure_states": [
                        {
                            "effect_id": snapshot.get("effect_id"),
                            "outcome_state": snapshot.get("outcome_state"),
                            "settlement_state": snapshot.get("settlement_state"),
                            "unresolved_exposure_count": snapshot.get(
                                "unresolved_transmission_exposure_count"
                            ),
                        }
                    ]
                    if snapshot.get("effect_id")
                    else [],
                    "obligation_states": dict(evidence.obligations),
                    "cas_refs": cas_refs,
                    "frontier_snapshot": snapshot,
                    "frontier_stream_id": frontier_stream_id,
                    "provider_call_ids": [item.call_id for item in evidence.calls],
                    "provider_effect_ids": [item.effect_id for item in evidence.calls],
                    "provider_send_count": executor.transport.physical_send_count,
                    "config_hash": sha256_bytes(
                        (self.home / "config/true_multi_agent_agents.json").read_bytes()
                    ),
                    "policy_hash": self.policy_hash,
                    "code_fingerprint": executor.activation.manifest_hash,
                    "old_process_pid": old_process_pid,
                }
            )
            receipt = executor._publish(manifest, purpose="true-multi-agent-live-checkpoint")
            _, publication_refs = checkpoint_stream.append(
                "checkpoint-manifest-published",
                (
                    {
                        "schema": "CHECKPOINT_MANIFEST_PUBLISHED_V1",
                        "event_type": "checkpoint.manifest-published",
                        "checkpoint_id": checkpoint_id,
                        "frontier_kind": spec.frontier_kind,
                        "validated_through_position": validated_position,
                        "manifest_ref": receipt.object_ref.reference_id,
                        "manifest_hash": manifest["manifest_hash"],
                        "manifest_object_ref": dict(receipt.object_ref.__dict__),
                        "pending_command_id": pending_step.command_id,
                        "provider_send_count_before": executor.transport.physical_send_count,
                        "old_process_pid": old_process_pid,
                        "_object_refs": [receipt.object_ref.reference_id],
                    },
                ),
                actor="checkpoint-command-handler",
                proofs=(receipt,),
            )
            _, flushed_refs = checkpoint_stream.append(
                "checkpoint-flushed",
                (
                    {
                        "schema": "CHECKPOINT_FLUSHED_V1",
                        "event_type": "checkpoint.flushed",
                        "checkpoint_id": checkpoint_id,
                        "manifest_ref": receipt.object_ref.reference_id,
                        "manifest_hash": manifest["manifest_hash"],
                        "validated_through_position": validated_position,
                        "all_references_committed": True,
                        "business_state_mutated": False,
                    },
                ),
                actor="checkpoint-command-handler",
            )
            prepared.append(
                {
                "checkpoint_id": checkpoint_id,
                "frontier_kind": spec.frontier_kind,
                "checkpoint_position": publication_refs[-1]["position"],
                "validated_through_position": validated_position,
                "manifest_ref": receipt.object_ref.reference_id,
                "manifest_hash": manifest["manifest_hash"],
                "source_frontier_event_id": snapshot["source_event_id"],
                "source_frontier_event_hash": snapshot["source_event_hash"],
                "pending_command_id": pending_step.command_id,
                "provider_call_count_before": len(evidence.calls),
                "provider_send_count_before": executor.transport.physical_send_count,
                "old_process_pid": old_process_pid,
                "flushed_position": flushed_refs[-1]["position"],
                }
            )

        if len(prepared) != len(FRONTIER_SPECS):
            raise DynamicCollaborationError("checkpoint restart preparation matrix is incomplete")
        for item in prepared:
            checkpoint_stream = CanonicalStream(
                journal,
                evidence.run_id,
                f"checkpoint/{item['checkpoint_id']}",
                self.policy_hash,
            )
            checkpoint_stream.append(
                "runtime-stopped",
                (
                    {
                        "schema": "CHECKPOINT_RUNTIME_STOP_REQUESTED_V1",
                        "event_type": "checkpoint.runtime-stop-requested",
                        "checkpoint_id": item["checkpoint_id"],
                        "old_process_pid": old_process_pid,
                        "safe_point": True,
                    },
                    {
                        "schema": "CHECKPOINT_RUNTIME_STOPPED_V1",
                        "event_type": "checkpoint.runtime-stopped",
                        "checkpoint_id": item["checkpoint_id"],
                        "old_process_pid": old_process_pid,
                        "checkpoint_position": item["flushed_position"],
                        "writer_closed_next": True,
                        "supervisor_survives": True,
                    },
                ),
                actor="runtime-lifecycle-command-handler",
            )
        handoff_stream = CanonicalStream(
            journal,
            evidence.run_id,
            "checkpoint-supervisor/" + evidence.run_id,
            self.policy_hash,
        )
        _, handoff_refs = handoff_stream.append(
            "checkpoint-supervisor-handoff",
            (
                {
                    "schema": "CHECKPOINT_SUPERVISOR_HANDOFF_REQUIRED_V1",
                    "event_type": "checkpoint.supervisor-handoff-required",
                    "checkpoint_ids": [item["checkpoint_id"] for item in prepared],
                    "frontier_kinds": [item["frontier_kind"] for item in prepared],
                    "old_process_pid": old_process_pid,
                    "provider_call_count": executor.call_count,
                    "provider_send_count": executor.transport.physical_send_count,
                    "provider_token_total": executor.usage_total,
                    "provider_cost_micro_usd": executor.cost_total_micro_usd,
                    "integrated_closure_required": integrated_continuation is not None,
                    "integrated_handoff_id": integrated_continuation.get("handoff_id")
                    if integrated_continuation is not None
                    else None,
                    "journal_head_before_worker_exit": journal.head_position,
                    "fresh_process_required": True,
                    "runtime_subprocess_forbidden_by_legacy_fence": True,
                },
            ),
            actor="runtime-lifecycle-command-handler",
        )
        return {
            "status": "checkpoint_restart_required",
            "run_id": evidence.run_id,
            "old_process_pid": old_process_pid,
            "checkpoint_ids": [item["checkpoint_id"] for item in prepared],
            "frontier_kinds": [item["frontier_kind"] for item in prepared],
            "provider_call_count": executor.call_count,
            "provider_physical_send_count": executor.transport.physical_send_count,
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "integrated_closure_required": integrated_continuation is not None,
            "integrated_handoff_id": integrated_continuation.get("handoff_id")
            if integrated_continuation is not None
            else None,
            "journal_head_before_worker_exit": handoff_refs[-1]["position"],
            "terminal_state": "RESTART_REQUIRED",
        }

    def _terminalize(
        self,
        journal: Any,
        cas: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        evidence: RunEvidence,
        run: RunAggregate,
    ) -> dict[str, Any]:
        unsatisfied = sorted(key for key, complete in evidence.obligations.items() if not complete)
        if unsatisfied:
            raise DynamicCollaborationError("terminal blocked by open protocol obligations: " + ",".join(unsatisfied))
        if run.state is RunState.ACTIVE:
            run, closing = run.begin_closing(expected_stream_version=run.stream_version)
        elif run.state is RunState.CLOSING:
            closing = {
                "schema": "RUN_CLOSING_RESUMED_V1",
                "run_id": run.run_id,
                "state": run.state.value,
                "stream_version": run.stream_version,
                "admission_generation": run.admission_generation,
                "closing_reentered": False,
            }
        else:
            raise DynamicCollaborationError("terminalization requires an ACTIVE or durably restored CLOSING Run")
        empty_counts = {kind: 0 for kind in BlockerKind}
        negative_counts = dict(empty_counts)
        negative_counts[BlockerKind.PROTOCOL] = 1
        negative_projection = TerminalEligibilityProjection(evidence.run_id, negative_counts, journal.head_position)
        negative_block_ref = stable_hash("TRUE_MULTI_AGENT_TERMINAL_NEGATIVE_BLOCKER", {"run": evidence.run_id})
        negative_facts = AuthoritativeTerminalFacts(
            {kind: ((negative_block_ref,) if kind is BlockerKind.PROTOCOL else ()) for kind in BlockerKind},
            None,
            (),
            stable_hash("TRUE_MULTI_AGENT_OBLIGATIONS_COMPLETE", {"run": evidence.run_id}),
            self.policy_hash,
        )
        try:
            full_validate(negative_projection, run, negative_facts)
        except Exception as error:
            negative_probe = {
                "schema": "TERMINAL_NEGATIVE_PROBE_REJECTED_V1",
                "blocker_kind": BlockerKind.PROTOCOL.value,
                "blocker_ref": negative_block_ref,
                "terminal_committed": False,
                "reason_hash": sha256_bytes(str(error).encode()),
            }
        else:
            raise DynamicCollaborationError("terminal negative probe did not reject an authoritative blocker")
        obligations_ref = stable_hash(
            "TRUE_MULTI_AGENT_REQUIRED_OBLIGATIONS_COMPLETE",
            {"run": evidence.run_id, "obligations": sorted(evidence.obligations)},
        )
        failure_refs = (
            (stable_hash("TRUE_MULTI_AGENT_RUN_FAILURE", {"run": evidence.run_id, "notes": evidence.notes}),)
            if evidence.expected_terminal == "FAILED"
            else ()
        )
        terminal_facts = AuthoritativeTerminalFacts(
            {kind: () for kind in BlockerKind},
            None,
            failure_refs,
            None if failure_refs else obligations_ref,
            self.policy_hash,
        )
        projection = TerminalEligibilityProjection(evidence.run_id, empty_counts, journal.head_position)
        decision = full_validate(projection, run, terminal_facts)
        run, terminal = apply_terminal_decision(run, decision)
        if run.state.value != evidence.expected_terminal:
            raise DynamicCollaborationError("terminal decision contradicted expected failure/success facts")
        negotiation_protocol_count = sum(
            item.get("protocol_kind") == "debate" for item in evidence.protocol_graph
        )
        handoff_protocol_count = sum(
            item.get("protocol_kind") == "handoff" for item in evidence.protocol_graph
        )
        evidence_package = {
            "schema": "SITINA_TRUE_MULTI_AGENT_RUN_EVIDENCE_V1",
            "run_id": evidence.run_id,
            "goal": evidence.goal,
            "goal_hash": evidence.goal_hash,
            "policy_hash": evidence.policy_hash,
            "analysis": evidence.analysis.mapping() if evidence.analysis else None,
            "source_frontier": self._frontier(journal).__dict__,
            "decisions": list(evidence.decisions),
            "calls": [item.evidence() for item in evidence.calls],
            "rejected_calls": list(executor.rejected_calls),
            "provider_recovery_attempts": list(executor.recovery_attempts),
            "checkpoint_restarts": list(evidence.checkpoint_restarts),
            "called_agents": sorted(evidence.called_agents),
            "selected_agents": sorted(evidence.selected_agents),
            "filtered_agents": {key: sorted(set(value)) for key, value in sorted(evidence.filtered_agents.items())},
            "protocol_graph": list(evidence.protocol_graph),
            "obligations": dict(evidence.obligations),
            "expected_terminal": evidence.expected_terminal,
            "terminal_decision": decision.__dict__,
            "provider_physical_send_count": executor.transport.physical_send_count,
            "provider_call_count": executor.call_count,
            "provider_retry_count": sum(item.retry_count for item in evidence.calls),
            "provider_fallback_count": sum(item.fallback_count for item in evidence.calls),
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "proposal_competition_count": sum(
                1 for item in evidence.calls if item.value.get("kind") == "proposal"
            ),
            "reviewer_call_count": sum(
                1 for item in evidence.calls if item.value.get("kind") in {"review", "fresh_review"}
            ),
            "negotiation_protocol_count": negotiation_protocol_count,
            "handoff_protocol_count": handoff_protocol_count,
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "acceptance_runtime_read_count": 0,
            "notes": list(evidence.notes),
            "user_response": evidence.user_response,
            "user_response_agent_id": evidence.user_response_agent_id,
            "user_response_output_hash": evidence.user_response_output_hash,
        }
        receipt = executor._publish(evidence_package, purpose="true-multi-agent-run-evidence")
        evidence_hash = sha256_bytes(canonical_json_bytes(evidence_package))
        terminal_fact = {
            **terminal,
            "event_type": "run.terminal",
            "status": "terminal",
            "required_obligations_open": 0,
            "terminal_state": run.state.value,
            "terminal_command_id": decision.command_id,
            "terminal_request_hash": decision.request_hash,
            "authoritative_fact_hash": decision.authoritative_fact_hash,
            "evidence_package_ref": receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
            "called_agents": sorted(evidence.called_agents),
            "selected_agents": sorted(evidence.selected_agents),
            "provider_call_count": executor.call_count,
            "provider_physical_send_count": executor.transport.physical_send_count,
            "provider_retry_count": 0,
            "provider_fallback_count": 0,
            "negotiation_protocol_count": negotiation_protocol_count,
            "handoff_protocol_count": handoff_protocol_count,
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "acceptance_runtime_read_count": 0,
            "user_response_hash": sha256_bytes(evidence.user_response.encode())
            if evidence.user_response
            else None,
            "_object_refs": [receipt.object_ref.reference_id],
        }
        receipt_event, refs = run_stream.append(
            "run-terminal",
            (
                {**closing, "event_type": "run.closing"},
                negative_probe,
                {
                    "schema": "TERMINAL_FULL_VALIDATION_ACCEPTED_V1",
                    "projection_source_position": projection.source_position,
                    "projection_candidate": projection.candidate,
                    "authoritative_blocker_counts": {kind.value: 0 for kind in BlockerKind},
                    "required_obligations_complete_ref": None if failure_refs else obligations_ref,
                    "failure_refs": list(failure_refs),
                    "decision": decision.__dict__,
                },
                {
                    "schema": "RUN_EVIDENCE_PACKAGE_SEALED_V1",
                    "evidence_package_ref": receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "provider_call_ids": [item.call_id for item in evidence.calls],
                    "provider_recovery_call_ids": [item["call_id"] for item in executor.recovery_attempts],
                    "_object_refs": [receipt.object_ref.reference_id],
                },
                terminal_fact,
            ),
            actor="terminal-command-handler",
            proofs=(receipt,),
            command_id=decision.command_id,
        )
        evidence.actual_terminal = run.state.value
        evidence.terminal_event = refs[-1]
        result = {
            "run_id": evidence.run_id,
            "terminal_state": run.state.value,
            "provider_call_count": executor.call_count,
            "provider_physical_send_count": executor.transport.physical_send_count,
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "proposal_competition_count": sum(
                1 for item in evidence.calls if item.value.get("kind") == "proposal"
            ),
            "reviewer_call_count": sum(
                1 for item in evidence.calls if item.value.get("kind") in {"review", "fresh_review"}
            ),
            "negotiation_protocol_count": negotiation_protocol_count,
            "handoff_protocol_count": handoff_protocol_count,
            "provider_retry_count": sum(item.retry_count for item in evidence.calls),
            "provider_fallback_count": sum(item.fallback_count for item in evidence.calls),
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "legacy_write_count": 0,
            "sqlite_connect_count": 0,
            "sqlite_write_count": 0,
            "called_agents": sorted(evidence.called_agents),
            "selected_agents": sorted(evidence.selected_agents),
            "decision_count": len(evidence.decisions),
            "protocol_count": len(evidence.protocol_graph),
            "evidence_package_ref": receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
            "terminal_event_id": refs[-1]["event_id"],
            "terminal_position": refs[-1]["position"],
            "terminal_transaction_hash": receipt_event.transaction_hash,
            "notes": list(evidence.notes),
            "checkpoint_restart_count": len(evidence.checkpoint_restarts),
            "checkpoint_ids": [item["checkpoint_id"] for item in evidence.checkpoint_restarts],
        }
        if run.state is RunState.SUCCEEDED and evidence.user_response:
            result.update(
                {
                    "response": evidence.user_response,
                    "response_agent_id": evidence.user_response_agent_id,
                    "response_output_hash": evidence.user_response_output_hash,
                }
            )
        return result

    def execute(self, goal: str, *, label: str = "live", overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if not isinstance(goal, str) or not goal.strip():
            raise DynamicCollaborationError("true multi-agent execution requires a non-empty goal")
        controls = dict(overrides or {})
        journal = None
        conversation_lifecycle: ConversationLifecycle | None = None
        conversation_message: str | None = None
        conversation_session_id: str | None = None
        conversation_turn_index: int | None = None
        try:
            context = ProductionRuntimeContext.load(self.home)
            runtime_writer = getattr(type(context), "open_runtime_writer", None)
            journal = context.open_runtime_writer() if callable(runtime_writer) else context.open_writer()
            cas = context.open_cas()
            if bool(controls.get("interactive_chat")):
                conversation_message = str(controls.get("conversation_user_message") or "").strip()
                conversation_session_id = str(controls.get("conversation_session_id") or "").strip()
                try:
                    conversation_turn_index = int(controls.get("conversation_turn_index"))
                except (TypeError, ValueError) as error:
                    raise DynamicCollaborationError("interactive chat requires a valid conversation turn index") from error
                route_mapping = controls.get("conversation_route_decision")
                if not conversation_message or not conversation_session_id or not isinstance(route_mapping, Mapping):
                    raise DynamicCollaborationError(
                        "interactive chat requires its original message, session identity, and route decision"
                    )
                conversation_lifecycle = ConversationLifecycle(journal, cas, context.provider)
                # Commit the original user body and deterministic route before
                # activation or any Provider physical send.
                conversation_lifecycle.start_turn(
                    session_id=conversation_session_id,
                    turn_index=conversation_turn_index,
                    message=conversation_message,
                    route_decision=route_decision_from_mapping(route_mapping),
                    occurred_at=now_rfc3339(),
                )
            activation = activate_runtime(self.home, context, cas, self.registry, self.policy)
            run_id = "tma-run-" + stable_hash(
                "TRUE_MULTI_AGENT_RUN_ID",
                {"goal": goal, "label": label, "nonce": uuid.uuid4().hex, "created_at_ns": time.time_ns()},
            )[:36]
            evidence = RunEvidence(run_id, goal, sha256_bytes(goal.encode()), self.policy_hash)
            if conversation_lifecycle is not None:
                assert conversation_session_id is not None and conversation_turn_index is not None
                conversation_lifecycle.link_run(
                    session_id=conversation_session_id,
                    turn_index=conversation_turn_index,
                    run_id=run_id,
                    occurred_at=now_rfc3339(),
                )
            run, opened = RunAggregate.open(run_id)
            run_stream = CanonicalStream(journal, run_id, f"run/{run_id}", self.policy_hash)
            run_stream.append(
                "run-created",
                (
                    {
                        "schema": "TRUE_MULTI_AGENT_RUN_CREATED_V1",
                        "event_type": "run.created",
                        "run_id": run_id,
                        "goal_hash": evidence.goal_hash,
                        "run_label": label,
                        "formal_acceptance_run": label.startswith("formal-"),
                        "acceptance_controls": controls,
                        "agent_count": len(self.registry.identities),
                        "execution_mode": "production-journal-cas-deepseek-live",
                        "provider_mode": "live",
                        "runtime_activation_ref": activation.receipt.object_ref.reference_id,
                        "runtime_activation_hash": activation.manifest_hash,
                        "registry_hash": self.registry.registry_hash,
                        "registry_generation": self.registry.generation,
                        "fixed_workflow_pipeline_used": False,
                        "external_mutation_allowed": False,
                        "legacy_read_allowed": False,
                        "acceptance_read_allowed": False,
                        "_object_refs": [activation.receipt.object_ref.reference_id],
                    },
                    opened,
                ),
                actor="true-multi-agent-runtime",
                proofs=(activation.receipt,),
            )
            self._record_conversation_route(run_stream, controls)
            executor = ProviderExecutor(
                self.home,
                context,
                run_id,
                self.policy_hash,
                self.policy,
                activation,
                journal,
                cas,
            )
        except BaseException as error:
            if conversation_lifecycle is not None and conversation_session_id is not None and conversation_turn_index is not None:
                try:
                    conversation_lifecycle.fail_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        error_type=type(error).__name__,
                        occurred_at=now_rfc3339(),
                    )
                except Exception:
                    pass
            if journal is not None:
                try:
                    journal.close()
                except Exception:
                    pass
            raise
        terminal_result: dict[str, Any] | None = None
        try:
            analysis, _, _ = self._discover(journal, run_stream, executor, evidence, controls)
            analysis = self._analysis_with_constraints(analysis, controls, run_stream, evidence.goal)
            if bool(controls.get("interactive_chat")):
                analysis = self._interactive_chat_analysis(analysis)
                run_stream.append(
                    "interactive-chat-analysis-constrained",
                    (
                        {
                            "schema": "INTERACTIVE_CHAT_ANALYSIS_CONSTRAINED_V1",
                            "event_type": "run.interactive-chat-analysis-constrained",
                            "goal_hash": evidence.goal_hash,
                            "protocols": list(analysis.protocols),
                            "proposal_count": analysis.proposal_count,
                            "external_mutation_allowed": False,
                        },
                    ),
                    actor="true-multi-agent-runtime",
                )
            evidence.analysis = analysis
            self._materialize_topology(journal, run_stream, evidence, analysis)
            winner, winner_agent, proposals, proposal_decision = self._proposal_and_review(
                journal, run_stream, executor, evidence, analysis, controls
            )
            if bool(controls.get("interactive_chat")):
                response = render_selected_user_response(winner.value)
                if not response:
                    raise DynamicCollaborationError("selected chat proposal has no user-facing response")
                evidence.user_response = response
                evidence.user_response_agent_id = winner_agent.agent_id
                evidence.user_response_output_hash = winner.output_hash
            integrated_closure = _integrated_closure_required(evidence.goal)
            integrated_continuation: Mapping[str, Any] | None = None
            if "arbitration" in analysis.protocols:
                self._arbitrate(
                    journal, run_stream, executor, evidence, analysis, proposals, winner, winner_agent, proposal_decision, controls
                )
            if integrated_closure:
                required = {"blackboard", "handoff", "lease", "checkpoint", "debate", "rework"}
                missing = required.difference(analysis.protocols)
                if missing or not (
                    analysis.requires_conflict
                    and analysis.requires_handoff_reject
                    and analysis.requires_reassignment
                    and analysis.requires_rework
                ):
                    raise DynamicCollaborationError(
                        "integrated business constraints were not fully admitted: " + ",".join(sorted(missing))
                    )
                if _provider_recovery_required(evidence.goal):
                    self._provider_recovery(journal, run_stream, executor, evidence, controls)
                lease_context = self._integrated_lease_begin(
                    journal, evidence, winner_agent, proposal_decision, winner
                )
                blackboard_state = self._blackboard(
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    analysis,
                    winner,
                    winner_agent,
                    proposal_decision,
                    controls,
                    primary_writer=winner_agent,
                    leased_task=lease_context["task"],
                )
                failover = self._integrated_lease_failover(
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    lease_context,
                    blackboard_state,
                    controls,
                )
                integrated_continuation = self._handoff(
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    analysis,
                    failover["source"],
                    failover["new_agent"],
                    failover["new_decision"],
                    controls,
                    defer_after_execution_prepared=True,
                    integrated_context=failover,
                )
                if integrated_continuation is None:
                    raise DynamicCollaborationError("integrated Handoff did not produce a restart continuation")
            else:
                if "blackboard" in analysis.protocols:
                    self._blackboard(
                        journal, run_stream, executor, evidence, analysis, winner, winner_agent, proposal_decision, controls
                    )
                if "handoff" in analysis.protocols:
                    self._handoff(
                        journal, run_stream, executor, evidence, analysis, winner, winner_agent, proposal_decision, controls
                    )
                if _provider_recovery_required(evidence.goal):
                    self._provider_recovery(journal, run_stream, executor, evidence, controls)
                if "lease" in analysis.protocols or analysis.requires_reassignment:
                    self._lease_and_reassign(journal, run_stream, executor, evidence, controls)
            if bool(controls.get("force_after_start_worker_loss")):
                fault = executor.inject_worker_loss(
                    winner_agent,
                    task_id="post-invocation-start-worker-loss",
                    after_invocation_started=True,
                )
                if fault["outcome_state"] != "OUTCOME_UNKNOWN" or fault["physical_send_count"] != 0:
                    raise DynamicCollaborationError("controlled post-InvocationStarted loss did not become OUTCOME_UNKNOWN")
                evidence.expected_terminal = "FAILED"
                evidence.notes.extend(("post_invocation_started_outcome_unknown", "policy_disposition_failed_no_retry"))
                transfer = MonitoringTransfer.create(
                    "monitoring-transfer-" + stable_hash("TRUE_MULTI_AGENT_MONITORING_TRANSFER", {"run": run_id})[:24],
                    run_id,
                    "incident-" + run_id,
                    (str(fault["effect_id"]),),
                    self.policy_hash,
                )
                transfer, monitoring_accepted = transfer.accept_successor(authority="incident-monitor-owner")
                CanonicalStream(
                    journal,
                    run_id,
                    "incident-" + run_id,
                    self.policy_hash,
                ).append(
                    "monitoring-obligation-accepted",
                    (monitoring_accepted,),
                    actor="incident-monitor-owner",
                )
                transfer, monitoring_acknowledged = transfer.acknowledge_source()
                run_stream.append(
                    "provider-unknown-contained",
                    (
                        {
                            "schema": "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1",
                            "event_type": "effect.unknown.policy-disposition",
                            "effect_id": fault["effect_id"],
                            "effect_attempt_id": fault["effect_attempt_id"],
                            "prior_outcome_state": fault["outcome_state"],
                            "disposition": "FAIL_RUN_AND_PERMANENTLY_BLOCK_RETRY",
                            "automatic_retry_performed": False,
                            "new_effect_created": False,
                            "physical_send_count_observed_by_controlled_transport": 0,
                            "success_claimed": False,
                            "monitoring_responsibility": transfer.successor_stream_id,
                            "successor_authority": transfer.successor_authority,
                            "terminal_effect_exposure_blocker_transferred": True,
                        },
                        monitoring_acknowledged,
                    ),
                    actor="effect-reconciliation-policy",
                )
            if "checkpoint" in analysis.protocols or bool(controls.get("force_checkpoint_restart")):
                restart_plan = self._checkpoint_restart(
                    context,
                    journal,
                    run_stream,
                    executor,
                    evidence,
                    run,
                    integrated_continuation=integrated_continuation,
                )
                journal.close()
                return restart_plan
            terminal_result = self._terminalize(journal, cas, run_stream, executor, evidence, run)
            if conversation_lifecycle is not None:
                assert conversation_session_id is not None
                assert conversation_turn_index is not None
                assert conversation_message is not None
                response = str(terminal_result.get("response") or "").strip()
                if terminal_result.get("terminal_state") == "SUCCEEDED" and response:
                    conversation_lifecycle.complete_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        message=conversation_message,
                        response=response,
                        occurred_at=now_rfc3339(),
                    )
                else:
                    conversation_lifecycle.fail_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        error_type=str(terminal_result.get("error_type") or "MultiAgentRunFailed"),
                        occurred_at=now_rfc3339(),
                    )
            return terminal_result
        except Exception as error:
            # Session finalization occurs after the immutable run terminal. If
            # it fails, surface the reconciliation requirement; never attempt
            # a second run terminal transition.
            if terminal_result is not None:
                if conversation_lifecycle is not None:
                    assert conversation_session_id is not None and conversation_turn_index is not None
                    try:
                        conversation_lifecycle.fail_turn(
                            session_id=conversation_session_id,
                            turn_index=conversation_turn_index,
                            error_type=type(error).__name__,
                            occurred_at=now_rfc3339(),
                        )
                    except Exception:
                        pass
                raise
            evidence.expected_terminal = "FAILED"
            evidence.notes.extend(
                (
                    "execution_failed_closed",
                    "error_type=" + type(error).__name__,
                    "error_hash=" + sha256_bytes(str(error).encode()),
                )
            )
            aborted: list[Mapping[str, Any]] = []
            for obligation_id, complete in list(evidence.obligations.items()):
                if complete:
                    continue
                instance = next(
                    (
                        item
                        for item in evidence.protocol_graph
                        if item["parent_obligation"] == obligation_id and item["terminal_disposition"] is None
                    ),
                    None,
                )
                if instance is not None:
                    aborted.append(
                        self._protocol_close(
                            evidence,
                            str(instance["protocol_instance"]),
                            obligation_id,
                            "FAILED_CLOSED",
                        )
                    )
                else:
                    evidence.obligations[obligation_id] = True
            run_stream.append(
                "run-execution-failed-closed",
                (
                    {
                        "schema": "RUN_EXECUTION_FAILED_CLOSED_V1",
                        "event_type": "run.execution.failed-closed",
                        "error_type": type(error).__name__,
                        "error_hash": sha256_bytes(str(error).encode()),
                        "provider_call_count": executor.call_count,
                        "rejected_provider_output_count": len(executor.rejected_calls),
                        "automatic_retry_performed": False,
                        "fallback_performed": False,
                        "success_claimed": False,
                    },
                    *aborted,
                ),
                actor="failure-containment-command-handler",
            )
            result = self._terminalize(journal, cas, run_stream, executor, evidence, run)
            result["execution_failed_closed"] = True
            result["error_type"] = type(error).__name__
            result["error_hash"] = sha256_bytes(str(error).encode())
            if conversation_lifecycle is not None:
                assert conversation_session_id is not None and conversation_turn_index is not None
                try:
                    conversation_lifecycle.fail_turn(
                        session_id=conversation_session_id,
                        turn_index=conversation_turn_index,
                        error_type=type(error).__name__,
                        occurred_at=now_rfc3339(),
                    )
                except Exception:
                    result["session_failure_record_failed_closed"] = True
            return result
        finally:
            try:
                journal.close()
            except Exception:
                pass
