from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from sitina.cas.crypto import encrypt_object
from sitina.conversation.context import ConversationContextSnapshot
from sitina.conversation.lifecycle import ConversationLifecycle
from sitina.conversation.models import ChatMode, RouteDecision, route_decision_from_mapping
from sitina.conversation.session_runtime import SessionRuntimeContext
from sitina.journal.model import (
    CODE_MODE_FAST_PRE_PROVIDER_PHASE,
    FrontierRef,
    canonical_json_bytes,
)
from sitina.orchestrator.true_multi_agent_runtime import (
    AgentCallResult,
    AgentIdentity,
    AgentRegistry,
    CanonicalStream,
    ProviderExecutor,
    TrueMultiAgentRuntimeError,
    activate_runtime,
    issue_root_pre_provider_authorization,
    now_rfc3339,
    sha256_bytes,
    stable_hash,
)
from sitina.protocols.run import RunAggregate, RunState
from sitina.protocols.terminal import (
    AuthoritativeTerminalFacts,
    BlockerKind,
    TerminalEligibilityProjection,
    apply_terminal_decision,
    full_validate,
)
from sitina.scheduling.agents import AgentScheduler


class FastConversationError(TrueMultiAgentRuntimeError):
    pass


class _RecoveredProviderExecutor:
    """Evidence publisher/accounting view for a previously committed call.

    It has no transport send method. Recovery can therefore terminalize a run
    from existing CAS/Journal facts without making a second Provider request.
    """

    def __init__(self, cas: Any, keys: Any, call: AgentCallResult):
        self.cas = cas
        self.keys = keys
        self.call_count = 1
        self.transport = SimpleNamespace(physical_send_count=1)
        self.usage_total = int(call.usage["total_tokens"])
        self.cost_total_micro_usd = int(call.cost_micro_usd)
        self.rejected_calls: list[dict[str, Any]] = []
        self.results = [call]

    def _publish(self, value: Mapping[str, Any], *, purpose: str):
        return self.cas.publish_verified(
            encrypt_object(canonical_json_bytes(dict(value)), self.keys, tenant_id="default", purpose=purpose)
        )


def validate_fast_answer(value: Mapping[str, Any]) -> dict[str, Any]:
    required_keys = {
        "agent_id",
        "kind",
        "answer",
        "confidence",
        "needs_multi",
        "escalation_reasons",
    }
    if set(value) != required_keys:
        raise FastConversationError("FAST output must match the exact conversation_answer schema")
    agent_id = value.get("agent_id")
    kind = value.get("kind")
    answer = value.get("answer")
    confidence = value.get("confidence")
    needs_multi = value.get("needs_multi")
    reasons = value.get("escalation_reasons")
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise FastConversationError("FAST output requires a non-empty agent_id")
    if kind != "conversation_answer":
        raise FastConversationError("FAST output kind must be conversation_answer")
    if not isinstance(answer, str) or not answer.strip():
        raise FastConversationError("FAST output requires a non-empty answer")
    if confidence not in {"high", "medium", "low"}:
        raise FastConversationError("FAST output confidence must be high, medium, or low")
    if not isinstance(needs_multi, bool):
        raise FastConversationError("FAST output needs_multi must be boolean")
    if not isinstance(reasons, list) or not 0 <= len(reasons) <= 8:
        raise FastConversationError("FAST output escalation_reasons must contain zero to eight entries")
    normalized_reasons: list[str] = []
    for reason in reasons:
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 160:
            raise FastConversationError("FAST escalation reasons must be bounded non-empty strings")
        normalized_reasons.append(reason.strip())
    if needs_multi and not normalized_reasons:
        raise FastConversationError("FAST needs_multi=true requires an escalation reason")
    return {
        "agent_id": agent_id.strip(),
        "kind": kind,
        "answer": answer.strip(),
        "confidence": str(confidence),
        "needs_multi": needs_multi,
        "escalation_reasons": normalized_reasons,
    }


class FastConversationRuntime:
    """One-Agent, one-send conversation path under Production Journal/CAS authority."""

    def __init__(
        self,
        home: Path,
        *,
        test_backend: Callable[..., Mapping[str, Any]] | None = None,
        runtime_context_factory: Any | None = None,
        session_runtime_provider: Any | None = None,
        provider_client: Any | None = None,
        provider_profile: Any | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        self._test_backend = test_backend
        self.runtime_context_factory = runtime_context_factory
        self.session_runtime_provider = session_runtime_provider
        self.provider_client = provider_client
        self.provider_profile = provider_profile
        self.registry: AgentRegistry | None = None
        self.policy: dict[str, Any] | None = None
        self.policy_hash: str | None = None
        self.scheduler = AgentScheduler()
        if test_backend is None:
            self.registry = AgentRegistry.load(self.home)
            base_policy = json.loads(
                (self.home / "config/true_multi_agent_policy.json").read_text(encoding="utf-8")
            )
            if base_policy.get("schema") != "SITINA_TRUE_MULTI_AGENT_POLICY_V1":
                raise FastConversationError("unsupported Provider policy for FAST conversation")
            # This is an execution ceiling, not an expected count: the transport
            # physically cannot send a second request in one FAST run.
            self.policy = {**base_policy, "max_provider_requests_per_run": 1}
            self.policy_hash = sha256_bytes(canonical_json_bytes(self.policy))

    @staticmethod
    def _frontier(journal: Any) -> FrontierRef:
        position = journal.head_position
        commitment = journal._position_hash[position] if position else "0" * 64
        return FrontierRef(journal.journal_id, journal.epoch, "local", position, commitment)

    @staticmethod
    def _recent_event_ids(journal: Any, *, limit: int = 8) -> tuple[str, ...]:
        events = tuple(journal.iter_events(max(0, journal.head_position - limit)))
        return tuple(item.event_id for item in events[-limit:])

    def _schedule(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        *,
        turn_index: int = 1,
        root_executor: ProviderExecutor | None = None,
    ) -> tuple[AgentIdentity, Mapping[str, Any]]:
        assert self.registry is not None and self.policy_hash is not None
        frontier = self._frontier(journal)
        candidates = tuple(
            identity.candidate(
                safety_allowed={"read-only", "provider-text-only"}.issubset(identity.safety_classes),
                source_versions={"registry": self.registry.generation, "conversation_turn": turn_index},
            )
            for identity in self.registry.identities
        )
        decision = self.scheduler.decide(
            "conversation-answer",
            candidates,
            required_capabilities=("proposal", "read-only", "synthesis"),
            requested_slots=1,
            source_event_ids=self._recent_event_ids(journal),
            source_frontier=frontier,
            candidate_tasks=("produce-one-read-only-conversation-answer",),
            policy_hash=self.policy_hash,
            deadline="2099-01-01T00:00:00Z",
        )
        if len(decision.selected_attempts) != 1:
            raise FastConversationError("no single registered synthesis Agent is eligible for FAST")
        selected = self.registry.get(decision.selected_attempts[0])
        mapping = decision.mapping()
        run_stream.append(
            "fast-agent-scheduling-decision",
            (
                {
                    "schema": "FAST_CONVERSATION_AGENT_SCHEDULING_DECISION_V1",
                    "event_type": "conversation.fast.scheduling.decision",
                    **mapping,
                },
                {
                    "schema": "FAST_CONVERSATION_DISPATCH_ACCEPTED_V1",
                    "event_type": "conversation.fast.dispatch.accepted",
                    "decision_id": decision.decision_id,
                    "decision_commitment": decision.commitment,
                    "selected_agents": [selected.agent_id],
                    "registry_generation_revalidated": True,
                    "capabilities_revalidated": True,
                    "read_only_safety_class_revalidated": True,
                },
            ),
            actor="conversation-scheduler",
            source_frontier=frontier,
            deadline=decision.deadline,
        )
        # Live FAST is still an authenticated root call.  Its one-call FSM
        # phase is distinct from discovery so the host cannot infer a
        # multi-agent planning sequence from a conversation answer.  Offline
        # callers retain the historical observation-only events above.
        authorization = (
            root_executor.pre_provider_authorization
            if isinstance(root_executor, ProviderExecutor)
            and isinstance(root_executor.pre_provider_authorization, Mapping)
            else None
        )
        if authorization is not None:
            decision_mapping = decision.mapping()
            root_common = {
                "run_id": root_executor.run_id,
                "session_instance_id": authorization.get("session_instance_id"),
                "conversation_session_id": authorization.get("conversation_session_id"),
                "turn_index": authorization.get("turn_index"),
                "generation": authorization.get("generation"),
                "run_attempt": authorization.get("run_attempt"),
                "decision_id": decision.decision_id,
                "decision_commitment": decision.commitment,
                "task_id": "conversation-answer",
                "phase": CODE_MODE_FAST_PRE_PROVIDER_PHASE,
                "selected_agents": list(decision.selected_attempts),
                "requested_slots": decision.requested_slots,
            }
            scheduling_fact = {
                "schema": "AGENT_SCHEDULING_DECISION_V1",
                "event_type": "scheduling.decision",
                "purpose": "code-mode-agent-scheduling",
                "purpose_class": "code-mode-agent-scheduling-decision",
                **root_common,
                "required_capabilities": list(decision.required_capabilities),
                "decision": decision_mapping,
            }
            dispatch_command_id = "dispatch-" + decision.decision_id
            dispatch_body = {
                **root_common,
                "dispatch_command_id": dispatch_command_id,
                "required_capabilities": list(decision.required_capabilities),
                "policy_hash": self.policy_hash,
                "deadline": decision.deadline,
            }
            dispatch_commitment = stable_hash(
                "CODE_MODE_DISPATCH_COMMAND_ACCEPTED",
                dispatch_body,
            )
            dispatch_fact = {
                "schema": "DISPATCH_COMMAND_ACCEPTED_V1",
                "event_type": "dispatch.command.accepted",
                "purpose": "code-mode-dispatch-command",
                "purpose_class": "code-mode-dispatch-command-accepted",
                **root_common,
                "dispatch_command_id": dispatch_command_id,
                "dispatch_commitment": dispatch_commitment,
                "required_capabilities": list(decision.required_capabilities),
                "state": "ACCEPTED",
            }
            root_executor._root_schedule_bindings = [{
                "scheduling_task_id": "conversation-answer",
                "phase": CODE_MODE_FAST_PRE_PROVIDER_PHASE,
                "scheduling_decision_id": decision.decision_id,
                "scheduling_decision_commitment": decision.commitment,
                "dispatch_command_id": dispatch_command_id,
                "dispatch_command_commitment": dispatch_commitment,
                "dispatch_commitment": dispatch_commitment,
                "selected_agents": list(decision.selected_attempts),
                "requested_slots": decision.requested_slots,
            }]
            run_stream.append_root_producer_fact(
                scheduling_fact,
                actor="scheduler",
                producer_role="root_scheduling",
                command_id="root-scheduling-" + decision.decision_id,
            )
            run_stream.append_root_producer_fact(
                dispatch_fact,
                actor="authoritative-dispatcher",
                producer_role="root_dispatch_acceptance",
                command_id=dispatch_command_id,
            )
        return selected, mapping

    @staticmethod
    def _system_prompt(agent: AgentIdentity) -> str:
        return (
            f"You are Sitina Agent {agent.agent_id}, role {agent.role}. Return exactly one JSON object with "
            f"agent_id exactly '{agent.agent_id}', kind exactly 'conversation_answer', a non-empty answer, "
            "confidence exactly high, medium, or low, boolean needs_multi, and escalation_reasons as an array of "
            "zero to eight short strings. needs_multi=true requires at least one reason. Answer directly in the "
            "user's language. You are provider-text-only and read-only: never execute tools, write files, modify "
            "Git, call MCP, publish, store memory, or cause external effects. If execution is requested, provide "
            "analysis or a plan and say that an explicit non-chat command is required. Never include credentials, "
            "tokens, private keys, passwords, authenticated URLs, or secret-like strings."
        )

    @staticmethod
    def _user_prompt(message: str, context: ConversationContextSnapshot) -> str:
        composed = any(
            item.get("component") == "current_user_message" and item.get("included")
            for item in context.component_manifest
        )
        prior = context.transcript or "(no prior successful conversation context)"
        if composed:
            return (
                f"Authoritative bounded conversation context:\n{prior}\n\n"
                "Give the best direct answer. Request independent multi-Agent review only when one answer is not "
                "reliable enough or the problem materially requires competing analysis."
            )
        return (
            f"Prior successful conversation context:\n{prior}\n\n"
            f"Current user message:\n{message.strip()}\n\n"
            "Give the best direct answer. Request independent multi-Agent review only when one answer is not "
            "reliable enough or the problem materially requires competing analysis."
        )

    def _append_answer_admitted(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        call: AgentCallResult,
        parsed: Mapping[str, Any],
        *,
        escalation_recommended: bool,
        escalation_allowed: bool,
        escalation_reasons: list[str],
        logical_provider_call_count: int,
        physical_send_count: int,
    ) -> None:
        """Commit the FAST answer by reusing its already-rooted CAS object proof."""

        output_root_proof = journal.lookup_existing_object_root_proof(
            call.output_object_ref,
            self._frontier(journal),
        )
        run_stream.append(
            "fast-conversation-answer-admitted",
            (
                {
                    "schema": "FAST_CONVERSATION_ANSWER_ADMITTED_V1",
                    "event_type": "conversation.fast.answer-admitted",
                    "call_id": call.call_id,
                    "agent_id": call.agent_id,
                    "output_ref": call.output_ref,
                    "output_hash": call.output_hash,
                    "response_hash": sha256_bytes(str(parsed["answer"]).encode()),
                    "confidence": parsed["confidence"],
                    "needs_multi": parsed["needs_multi"],
                    "escalation_reasons": escalation_reasons[:8],
                    "logical_provider_call_count": logical_provider_call_count,
                    "physical_send_count": physical_send_count,
                    "proposal_competition_count": 0,
                    "reviewer_call_count": 0,
                    "_object_refs": [call.output_ref],
                },
                {
                    "schema": (
                        "FAST_CONVERSATION_ESCALATION_REQUESTED_V1"
                        if escalation_recommended and escalation_allowed
                        else "FAST_CONVERSATION_ESCALATION_SUPPRESSED_V1"
                        if escalation_recommended
                        else "FAST_CONVERSATION_ESCALATION_NOT_REQUIRED_V1"
                    ),
                    "event_type": "conversation.fast.escalation-evaluated",
                    "fast_run_id": call.run_id,
                    "output_hash": call.output_hash,
                    "escalation_recommended": escalation_recommended,
                    "escalation_allowed": escalation_allowed,
                    "escalation_reasons": escalation_reasons[:8],
                    "prior_physical_send_count": physical_send_count,
                    "resolved_next_mode": "MULTI" if escalation_recommended and escalation_allowed else "FAST",
                },
            ),
            actor="fast-conversation-runtime",
            proofs=(output_root_proof,),
        )

    @staticmethod
    def incomplete_committed_runs(events: tuple[Any, ...]) -> tuple[str, ...]:
        """Find FAST runs with one admitted call but no terminal decision."""

        created = {
            str(event.payload["run_id"])
            for event in events
            if event.event_type == "run.created"
            and event.payload.get("schema") == "FAST_CONVERSATION_RUN_OPENED_V1"
            and isinstance(event.payload.get("run_id"), str)
        }
        terminal = {
            str(event.payload["run_id"])
            for event in events
            if event.event_type == "run.terminal" and isinstance(event.payload.get("run_id"), str)
        }
        recoverable = []
        for run_id in sorted(created - terminal):
            matching = tuple(event for event in events if event.payload.get("run_id") == run_id)
            outputs = [event for event in matching if event.payload.get("schema") == "AGENT_OUTPUT_COMMITTED_V1"]
            usages = [
                event
                for event in matching
                if event.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1"
                and event.payload.get("outcome") == "SUCCEEDED"
                and int(event.payload.get("physical_send_count", 0)) == 1
            ]
            if len(outputs) == 1 and len(usages) == 1 and outputs[0].payload.get("call_id") == usages[0].payload.get("call_id"):
                recoverable.append(run_id)
        return tuple(recoverable)

    def recover_committed_run(
        self,
        *,
        context_runtime: Any,
        journal: Any,
        cas: Any,
        historical_events: tuple[Any, ...],
        run_id: str,
    ) -> dict[str, Any]:
        """Finish an incomplete FAST run from its one committed Provider call."""

        if self._test_backend is not None:
            raise FastConversationError("test backend cannot recover a Production Provider call")
        assert self.policy_hash is not None
        matching = tuple(event for event in historical_events if event.payload.get("run_id") == run_id)
        if any(event.event_type == "run.terminal" for event in matching):
            raise FastConversationError("FAST recovery refused an already-terminal run")
        opened = [event for event in matching if event.payload.get("schema") == "FAST_CONVERSATION_RUN_OPENED_V1"]
        outputs = [event for event in matching if event.payload.get("schema") == "AGENT_OUTPUT_COMMITTED_V1"]
        usages = [
            event
            for event in matching
            if event.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1"
            and event.payload.get("outcome") == "SUCCEEDED"
            and int(event.payload.get("physical_send_count", 0)) == 1
        ]
        if len(opened) != 1 or len(outputs) != 1 or len(usages) != 1:
            raise FastConversationError("FAST recovery requires exactly one opened run, output, and successful send")
        opened_payload = opened[0].payload
        output = outputs[0].payload
        usage = usages[0].payload
        if output.get("call_id") != usage.get("call_id") or opened_payload.get("policy_hash") != self.policy_hash:
            raise FastConversationError("FAST recovery facts disagree on call or policy identity")
        output_ref = str(output["output_ref"])
        object_ref = cas.resolve_reference(output_ref)
        raw = cas.open_verified(object_ref)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise FastConversationError("recovered FAST output is not an object")
        parsed = validate_fast_answer(value)
        output_hash = sha256_bytes(canonical_json_bytes(value))
        if output_hash != output.get("output_hash"):
            raise FastConversationError("recovered FAST output hash differs from Journal")
        escalation_recommended = bool(parsed["needs_multi"] or parsed["confidence"] == "low")
        if escalation_recommended and str(opened_payload.get("requested_mode")) == ChatMode.AUTO.value:
            raise FastConversationError("incomplete AUTO escalation requires an explicit user retry")
        call = AgentCallResult(
            call_id=str(output["call_id"]),
            run_id=run_id,
            agent_id=str(output["agent_id"]),
            role=str(output["role"]),
            task_id=str(output["task_id"]),
            task_attempt_id=str(output["task_attempt_id"]),
            effect_id=str(output["effect_id"]),
            effect_attempt_id=str(output["effect_attempt_id"]),
            provider_request_id=str(usage["provider_request_id"]),
            input_snapshot_ref=str(output["input_snapshot_ref"]),
            input_snapshot_hash=str(output["input_snapshot_hash"]),
            output_ref=output_ref,
            output_object_ref=object_ref,
            output_hash=output_hash,
            value=value,
            usage={
                "input_tokens": int(usage["input_tokens"]),
                "output_tokens": int(usage["output_tokens"]),
                "total_tokens": int(usage["total_tokens"]),
            },
            cost_micro_usd=int(usage["cost_micro_usd"]),
            started_at=str(usage["started_at"]),
            completed_at=str(usage["completed_at"]),
            outcome=str(usage["outcome"]),
            settlement=str(usage["settlement"]),
            retry_count=int(usage.get("retry_count", 0)),
            fallback_count=int(usage.get("fallback_count", 0)),
        )
        route_decision = route_decision_from_mapping(dict(opened_payload["route_decision"]))
        snapshot = ConversationContextSnapshot(
            transcript="",
            turn_count=int(opened_payload["bounded_context_turn_count"]),
            char_count=int(opened_payload["bounded_context_char_count"]),
            context_hash=str(opened_payload["bounded_context_hash"]),
        )
        scheduling = next(
            (
                dict(event.payload)
                for event in matching
                if event.payload.get("schema") == "FAST_CONVERSATION_AGENT_SCHEDULING_DECISION_V1"
            ),
            {},
        )
        run_stream = CanonicalStream(
            journal,
            run_id,
            f"run/{run_id}",
            self.policy_hash,
            namespace="sitina-fast-conversation-v1",
        )
        run_stream.append(
            "fast-conversation-committed-call-recovered",
            (
                {
                    "schema": "FAST_CONVERSATION_COMMITTED_CALL_RECOVERED_V1",
                    "event_type": "conversation.fast.committed-call-recovered",
                    "call_id": call.call_id,
                    "output_ref": call.output_ref,
                    "output_hash": call.output_hash,
                    "physical_send_count": 1,
                    "automatic_provider_retry_performed": False,
                },
            ),
            actor="fast-conversation-reconciler",
        )
        reasons = list(parsed["escalation_reasons"])
        if parsed["confidence"] == "low" and "FAST Agent 置信度较低" not in reasons:
            reasons.append("FAST Agent 置信度较低")
        self._append_answer_admitted(
            journal,
            run_stream,
            call,
            parsed,
            escalation_recommended=escalation_recommended,
            escalation_allowed=False,
            escalation_reasons=reasons,
            logical_provider_call_count=1,
            physical_send_count=1,
        )
        executor = _RecoveredProviderExecutor(cas, context_runtime.provider, call)
        run, _opened_fact = RunAggregate.open(run_id)
        result = self._terminalize(
            journal,
            run_stream,
            executor,  # type: ignore[arg-type]
            run,
            run_id=run_id,
            session_id=str(opened_payload["session_id"]),
            turn_index=int(opened_payload["turn_index"]),
            message_hash=str(opened_payload["message_hash"]),
            context=snapshot,
            route_decision=route_decision,
            scheduling_decision=scheduling,
            call=call,
            expected_terminal="SUCCEEDED",
        )
        result["recovered_from_committed_provider_call"] = True
        result["automatic_provider_retry_performed"] = False
        return result

    def _terminalize(
        self,
        journal: Any,
        run_stream: CanonicalStream,
        executor: ProviderExecutor,
        run: RunAggregate,
        *,
        run_id: str,
        session_id: str,
        turn_index: int,
        message_hash: str,
        context: ConversationContextSnapshot,
        route_decision: RouteDecision,
        scheduling_decision: Mapping[str, Any] | None,
        call: AgentCallResult | None,
        expected_terminal: str,
        error: BaseException | None = None,
    ) -> dict[str, Any]:
        assert self.policy_hash is not None
        run, closing = run.begin_closing(expected_stream_version=run.stream_version)
        empty_counts = {kind: 0 for kind in BlockerKind}
        negative_counts = dict(empty_counts)
        negative_counts[BlockerKind.PROTOCOL] = 1
        negative_ref = stable_hash("FAST_CONVERSATION_TERMINAL_NEGATIVE_BLOCKER", {"run": run_id})
        negative_projection = TerminalEligibilityProjection(run_id, negative_counts, journal.head_position)
        negative_facts = AuthoritativeTerminalFacts(
            {kind: ((negative_ref,) if kind is BlockerKind.PROTOCOL else ()) for kind in BlockerKind},
            None,
            (),
            stable_hash("FAST_CONVERSATION_OBLIGATIONS_COMPLETE", {"run": run_id}),
            self.policy_hash,
        )
        try:
            full_validate(negative_projection, run, negative_facts)
        except Exception as negative_error:
            negative_probe = {
                "schema": "TERMINAL_NEGATIVE_PROBE_REJECTED_V1",
                "blocker_kind": BlockerKind.PROTOCOL.value,
                "blocker_ref": negative_ref,
                "terminal_committed": False,
                "reason_hash": sha256_bytes(str(negative_error).encode()),
            }
        else:
            raise FastConversationError("FAST terminal negative probe did not reject")
        obligations_ref = stable_hash("FAST_CONVERSATION_REQUIRED_OBLIGATIONS_COMPLETE", {"run": run_id})
        cancellation_ref = (
            stable_hash("FAST_CONVERSATION_RUN_CANCELLED", {"run": run_id})
            if expected_terminal == "CANCELLED"
            else None
        )
        failure_refs = (
            (stable_hash(
                "FAST_CONVERSATION_RUN_FAILURE",
                {"run": run_id, "error_type": type(error).__name__ if error else "unknown"},
            ),)
            if expected_terminal == "FAILED"
            else ()
        )
        facts = AuthoritativeTerminalFacts(
            {kind: () for kind in BlockerKind},
            cancellation_ref,
            failure_refs,
            None if failure_refs or cancellation_ref else obligations_ref,
            self.policy_hash,
        )
        projection = TerminalEligibilityProjection(run_id, empty_counts, journal.head_position)
        decision = full_validate(projection, run, facts)
        run, terminal = apply_terminal_decision(run, decision)
        if run.state.value != expected_terminal:
            raise FastConversationError("FAST terminal state contradicted authoritative facts")
        answer = str(call.value.get("answer") or "").strip() if call else ""
        evidence = {
            "schema": "SITINA_FAST_CONVERSATION_RUN_EVIDENCE_V1",
            "run_id": run_id,
            "session_id": session_id,
            "turn_index": turn_index,
            "message_hash": message_hash,
            "bounded_context_hash": context.context_hash,
            "bounded_context_turn_count": context.turn_count,
            "bounded_context_char_count": context.char_count,
            "route_decision": route_decision.canonical_mapping(),
            "scheduling_decision": dict(scheduling_decision or {}),
            "call": call.evidence() if call else None,
            "rejected_calls": list(executor.rejected_calls),
            "expected_terminal": expected_terminal,
            "terminal_decision": decision.__dict__,
            "provider_call_count": executor.call_count,
            "provider_physical_send_count": executor.transport.physical_send_count,
            "provider_retry_count": 0,
            "provider_fallback_count": 0,
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "proposal_competition_count": 0,
            "reviewer_call_count": 0,
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "legacy_write_count": 0,
            "sqlite_connect_count": 0,
            "sqlite_write_count": 0,
            "response_hash": sha256_bytes(answer.encode()) if answer else None,
            "error_type": type(error).__name__ if error else None,
            "error_hash": sha256_bytes(str(error).encode()) if error else None,
        }
        evidence_receipt = executor._publish(evidence, purpose="fast-conversation-run-evidence")
        evidence_hash = sha256_bytes(canonical_json_bytes(evidence))
        receipt, refs = run_stream.append(
            "fast-conversation-terminal",
            (
                {**closing, "event_type": "run.closing"},
                negative_probe,
                {
                    "schema": "TERMINAL_FULL_VALIDATION_ACCEPTED_V1",
                    "projection_source_position": projection.source_position,
                    "projection_candidate": projection.candidate,
                    "authoritative_blocker_counts": {kind.value: 0 for kind in BlockerKind},
                    "required_obligations_complete_ref": None if failure_refs or cancellation_ref else obligations_ref,
                    "cancellation_requested_ref": cancellation_ref,
                    "failure_refs": list(failure_refs),
                    "decision": decision.__dict__,
                },
                {
                    # This is the ordinary FAST terminal evidence package.
                    # RUN_EVIDENCE_PACKAGE_SEALED_V1 is reserved for the
                    # authenticated Code Mode terminal bundle; sharing that
                    # schema made the ordinary Journal path look like a Code
                    # Mode authority writer and tripped the reserved guard.
                    "schema": "FAST_CONVERSATION_EVIDENCE_PACKAGE_SEALED_V1",
                    "event_type": "conversation.fast.evidence.package.sealed",
                    "evidence_package_ref": evidence_receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "provider_call_ids": [call.call_id] if call else [],
                    "_object_refs": [evidence_receipt.object_ref.reference_id],
                },
                {
                    **terminal,
                    "event_type": "run.terminal",
                    "status": "terminal",
                    "terminal_state": run.state.value,
                    "required_obligations_open": 0,
                    "terminal_command_id": decision.command_id,
                    "terminal_request_hash": decision.request_hash,
                    "authoritative_fact_hash": decision.authoritative_fact_hash,
                    "evidence_package_ref": evidence_receipt.object_ref.reference_id,
                    "evidence_package_hash": evidence_hash,
                    "provider_call_count": executor.call_count,
                    "provider_physical_send_count": executor.transport.physical_send_count,
                    "provider_retry_count": 0,
                    "provider_fallback_count": 0,
                    "proposal_competition_count": 0,
                    "reviewer_call_count": 0,
                    "external_mutation_count": 0,
                    "legacy_read_count": 0,
                    "legacy_write_count": 0,
                    "sqlite_connect_count": 0,
                    "sqlite_write_count": 0,
                    "response_hash": sha256_bytes(answer.encode()) if answer else None,
                    "_object_refs": [evidence_receipt.object_ref.reference_id],
                },
            ),
            actor="terminal-command-handler",
            proofs=(evidence_receipt,),
            command_id=decision.command_id,
        )
        result: dict[str, Any] = {
            "run_id": run_id,
            "terminal_state": run.state.value,
            "provider_call_count": executor.call_count,
            "provider_physical_send_count": executor.transport.physical_send_count,
            "provider_token_total": executor.usage_total,
            "provider_cost_micro_usd": executor.cost_total_micro_usd,
            "provider_retry_count": 0,
            "provider_fallback_count": 0,
            "proposal_competition_count": 0,
            "reviewer_call_count": 0,
            "external_mutation_count": 0,
            "legacy_read_count": 0,
            "legacy_write_count": 0,
            "sqlite_connect_count": 0,
            "sqlite_write_count": 0,
            "evidence_package_ref": evidence_receipt.object_ref.reference_id,
            "evidence_package_hash": evidence_hash,
            "terminal_event_id": refs[-1]["event_id"],
            "terminal_position": refs[-1]["position"],
            "terminal_transaction_hash": receipt.transaction_hash,
        }
        if call and run.state is RunState.SUCCEEDED:
            parsed = validate_fast_answer(call.value)
            result.update(
                {
                    "response": parsed["answer"],
                    "response_agent_id": call.agent_id,
                    "response_output_hash": call.output_hash,
                    "confidence": parsed["confidence"],
                    "needs_multi": parsed["needs_multi"],
                    "escalation_reasons": parsed["escalation_reasons"],
                }
            )
        if error is not None:
            result.update(
                {
                    "execution_failed_closed": True,
                    "error_type": type(error).__name__,
                    "error_hash": sha256_bytes(str(error).encode()),
                }
            )
        return result

    def execute(
        self,
        message: str,
        *,
        context: ConversationContextSnapshot,
        route_decision: RouteDecision,
        session_id: str,
        turn_index: int,
        allow_escalation: bool,
        live_opt_in: bool = False,
    ) -> dict[str, Any]:
        if self._test_backend is not None:
            return dict(
                self._test_backend(
                    message=message,
                    context=context,
                    route_decision=route_decision,
                    session_id=session_id,
                    turn_index=turn_index,
                    allow_escalation=allow_escalation,
                )
            )
        if route_decision.resolved_mode is not ChatMode.FAST:
            raise FastConversationError("FAST runtime requires a FAST route decision")
        if not isinstance(message, str) or not message.strip():
            raise FastConversationError("FAST conversation requires a non-empty message")
        assert self.registry is not None and self.policy is not None and self.policy_hash is not None
        if callable(self.runtime_context_factory):
            context_runtime = self.runtime_context_factory(self.home)
        else:
            context_runtime = SessionRuntimeContext.open(
                self.home, provider=self.session_runtime_provider
            )
        runtime_writer = getattr(type(context_runtime), "open_runtime_writer", None)
        journal = context_runtime.open_runtime_writer() if callable(runtime_writer) else context_runtime.open_writer()
        run_id = "fast-chat-run-" + stable_hash(
            "FAST_CONVERSATION_RUN_ID",
            {
                "session_id": session_id,
                "turn_index": turn_index,
                "input_hash": route_decision.input_hash,
                "nonce": uuid.uuid4().hex,
                "created_at_ns": time.time_ns(),
            },
        )[:36]
        run, opened = RunAggregate.open(run_id)
        run_stream: CanonicalStream | None = None
        executor: ProviderExecutor | None = None
        lifecycle: ConversationLifecycle | None = None
        call: AgentCallResult | None = None
        scheduling_decision: Mapping[str, Any] | None = None
        terminal_result: dict[str, Any] | None = None
        try:
            cas = context_runtime.open_cas()
            lifecycle = ConversationLifecycle(journal, cas, context_runtime.provider)
            message_created_at = now_rfc3339()
            # This authoritative message commit is intentionally before runtime
            # activation and before ProviderExecutor can physically send.
            lifecycle.start_turn(
                session_id=session_id,
                turn_index=turn_index,
                message=message.strip(),
                route_decision=route_decision,
                occurred_at=message_created_at,
            )
            offline = self.provider_client is not None
            pre_provider_authorization = None
            if not offline and live_opt_in:
                pre_provider_authorization = issue_root_pre_provider_authorization(
                    context_runtime,
                    policy=self.policy,
                    session_id=session_id,
                    turn_index=turn_index,
                    run_id=run_id,
                    provider_profile=self.provider_profile,
                )
            activation = activate_runtime(
                self.home,
                context_runtime,
                cas,
                self.registry,
                self.policy,
                pre_provider_authorization=pre_provider_authorization,
                run_id=run_id,
                session_id=session_id,
                provider_profile=self.provider_profile,
                offline=offline,
                source_root=getattr(context_runtime, "source_root", self.home),
            )
            run_stream = CanonicalStream(
                journal,
                run_id,
                f"run/{run_id}",
                self.policy_hash,
                namespace="sitina-fast-conversation-v1",
            )
            executor = ProviderExecutor(
                self.home,
                context_runtime,
                run_id,
                self.policy_hash,
                self.policy,
                activation,
                journal,
                cas,
                client_override=self.provider_client,
                profile_override=self.provider_profile,
                pre_provider_authorization=pre_provider_authorization,
            )
            lifecycle.link_run(
                session_id=session_id,
                run_id=run_id,
                turn_index=turn_index,
                occurred_at=now_rfc3339(),
            )
            run_stream.append(
                "fast-conversation-run-opened",
                (
                    {
                        "schema": "FAST_CONVERSATION_RUN_OPENED_V1",
                        "event_type": "run.created",
                        "run_id": run_id,
                        "session_id": session_id,
                        "turn_index": turn_index,
                        "message_hash": sha256_bytes(message.strip().encode()),
                        "bounded_context_hash": context.context_hash,
                        "bounded_context_turn_count": context.turn_count,
                        "bounded_context_char_count": context.char_count,
                        "requested_mode": route_decision.requested_mode.value,
                        "resolved_mode": route_decision.resolved_mode.value,
                        "route_decision": route_decision.canonical_mapping(),
                        "runtime_activation_ref": activation.receipt.object_ref.reference_id,
                        "runtime_activation_hash": activation.manifest_hash,
                        "registry_hash": self.registry.registry_hash,
                        "registry_generation": self.registry.generation,
                        "provider_mode": "live",
                        "provider_text_only": True,
                        "external_mutation_allowed": False,
                        "legacy_read_allowed": False,
                        "sqlite_allowed": False,
                        "acceptance_controls": {
                            "session_instance_id": (
                                pre_provider_authorization.get("session_instance_id")
                                if isinstance(pre_provider_authorization, Mapping) else None
                            ),
                            "conversation_session_id": session_id,
                            "conversation_turn_index": turn_index,
                            "root_pre_provider_binding": {
                                field: pre_provider_authorization.get(field)
                                for field in (
                                    "session_instance_id", "conversation_session_id", "turn_index",
                                    "run_id", "run_attempt", "generation", "provider_profile",
                                    "provider_model",
                                )
                            } if isinstance(pre_provider_authorization, Mapping) else None,
                        },
                        "_object_refs": [activation.receipt.object_ref.reference_id],
                    },
                    opened,
                ),
                actor="fast-conversation-runtime",
                proofs=(activation.receipt,),
            )
            agent, scheduling_decision = self._schedule(
                journal,
                run_stream,
                turn_index=turn_index,
                root_executor=executor,
            )

            def validate(value: Mapping[str, Any]) -> None:
                validate_fast_answer(value)

            call = executor.call(
                agent,
                task_id="conversation-answer",
                kind="conversation_answer",
                root_phase=CODE_MODE_FAST_PRE_PROVIDER_PHASE,
                output_contract_id="sitina.conversation-answer.v1",
                task_type="conversation_answer",
                schema_id="SITINA_CONVERSATION_ANSWER_V1",
                system_prompt=self._system_prompt(agent),
                user_prompt=self._user_prompt(message, context),
                input_context={
                    "session_id": session_id,
                    "turn_index": turn_index,
                    "message_hash": sha256_bytes(message.strip().encode()),
                    "bounded_context_hash": context.context_hash,
                    "route_decision": route_decision.canonical_mapping(),
                    "provider_text_only": True,
                },
                validate=validate,
            )
            if executor.call_count != 1 or executor.transport.physical_send_count != 1:
                raise FastConversationError("FAST normal success requires exactly one logical call and one physical send")
            parsed = validate_fast_answer(call.value)
            escalation_recommended = bool(parsed["needs_multi"] or parsed["confidence"] == "low")
            reasons = list(parsed["escalation_reasons"])
            if parsed["confidence"] == "low" and "FAST Agent 置信度较低" not in reasons:
                reasons.append("FAST Agent 置信度较低")
            self._append_answer_admitted(
                journal,
                run_stream,
                call,
                parsed,
                escalation_recommended=escalation_recommended,
                escalation_allowed=allow_escalation,
                escalation_reasons=reasons,
                logical_provider_call_count=executor.call_count,
                physical_send_count=executor.transport.physical_send_count,
            )
            terminal_result = self._terminalize(
                journal,
                run_stream,
                executor,
                run,
                run_id=run_id,
                session_id=session_id,
                turn_index=turn_index,
                message_hash=sha256_bytes(message.strip().encode()),
                context=context,
                route_decision=route_decision,
                scheduling_decision=scheduling_decision,
                call=call,
                expected_terminal="SUCCEEDED",
            )
            # A session must never expose a successful assistant pair until
            # the linked run is durably terminal. AUTO escalation also must
            # never admit the unreviewed FAST candidate into session history;
            # the reviewed MULTI result owns the single assistant message.
            if not (allow_escalation and escalation_recommended):
                assistant_proof = cas.verify_existing(call.output_object_ref)
                lifecycle.complete_turn(
                    session_id=session_id,
                    turn_index=turn_index,
                    message=message.strip(),
                    response=str(parsed["answer"]),
                    occurred_at=now_rfc3339(),
                    published=assistant_proof,
                    body_selector="answer",
                )
            terminal_result["escalation_recommended"] = escalation_recommended
            terminal_result["escalation_allowed"] = allow_escalation
            terminal_result["escalation_reasons"] = reasons[:8]
            return terminal_result
        except KeyboardInterrupt as error:
            if lifecycle is not None:
                try:
                    lifecycle.fail_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        error_type="KeyboardInterrupt",
                        occurred_at=now_rfc3339(),
                    )
                except Exception:
                    pass
            if run_stream is not None and executor is not None:
                run_stream.append(
                    "fast-conversation-cancelled",
                    (
                        {
                            "schema": "FAST_CONVERSATION_CANCELLED_V1",
                            "event_type": "conversation.turn.cancelled",
                            "error_type": "KeyboardInterrupt",
                            "automatic_retry_performed": False,
                            "physical_send_count": executor.transport.physical_send_count,
                        },
                    ),
                    actor="fast-conversation-runtime",
                )
                self._terminalize(
                    journal,
                    run_stream,
                    executor,
                    run,
                    run_id=run_id,
                    session_id=session_id,
                    turn_index=turn_index,
                    message_hash=sha256_bytes(message.strip().encode()),
                    context=context,
                    route_decision=route_decision,
                    scheduling_decision=scheduling_decision,
                    call=call,
                    expected_terminal="CANCELLED",
                    error=error,
                )
            raise
        except Exception as error:
            if lifecycle is not None:
                try:
                    lifecycle.fail_turn(
                        session_id=session_id,
                        turn_index=turn_index,
                        error_type=type(error).__name__,
                        occurred_at=now_rfc3339(),
                    )
                except Exception:
                    pass
            # The run is already terminal and immutable. A later session
            # finalization failure must surface for reconciliation and must not
            # attempt a second terminal transition.
            if terminal_result is not None:
                raise
            if run_stream is None or executor is None:
                raise
            run_stream.append(
                "fast-conversation-failed-closed",
                (
                    {
                        "schema": "FAST_CONVERSATION_FAILED_CLOSED_V1",
                        "event_type": "conversation.turn.failed-closed",
                        "error_type": type(error).__name__,
                        "error_hash": sha256_bytes(str(error).encode()),
                        "automatic_retry_performed": False,
                        "fallback_performed": False,
                        "success_claimed": False,
                        "physical_send_count": executor.transport.physical_send_count,
                    },
                ),
                actor="fast-conversation-runtime",
            )
            return self._terminalize(
                journal,
                run_stream,
                executor,
                run,
                run_id=run_id,
                session_id=session_id,
                turn_index=turn_index,
                message_hash=sha256_bytes(message.strip().encode()),
                context=context,
                route_decision=route_decision,
                scheduling_decision=scheduling_decision,
                call=call,
                expected_terminal="FAILED",
                error=error,
            )
        finally:
            try:
                journal.close()
            except Exception:
                pass
