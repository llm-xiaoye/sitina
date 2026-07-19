from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, load_json_yaml, new_id, sha256_text, stable_json


ProposalType = Literal["task_graph", "implementation_strategy", "test_strategy", "risk_strategy", "review_strategy"]
ProposalStatus = Literal["submitted", "selected", "rejected", "blocked"]
EvaluationDecision = Literal["support", "oppose", "needs_revision", "block"]


class ProposalRound(StrictModel):
    schema_version: str = "1.0"
    proposal_round_id: str
    run_id: str
    task_id: str
    task_type: str
    participants: list[str]
    status: Literal["open", "closed", "selected", "blocked"]
    created_at: str
    closed_at: str | None = None


class ProposalBid(StrictModel):
    estimated_steps: int = 0
    estimated_risk: Literal["low", "medium", "high", "critical"] = "low"
    required_agents: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    read_paths: list[str] = Field(default_factory=list)
    write_paths: list[str] = Field(default_factory=list)
    writable_scope: list[str] = Field(default_factory=list)
    touched_files: list[str] = Field(default_factory=list)
    required_side_effects: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    rollback_plan: list[str] = Field(default_factory=list)
    verification_plan: list[str] = Field(default_factory=list)
    expected_artifacts: list[str] = Field(default_factory=list)
    cost_notes: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_bid_bounds(self) -> "ProposalBid":
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        return self


class Proposal(StrictModel):
    schema_version: str = "1.0"
    proposal_id: str
    proposal_round_id: str
    run_id: str
    proposer_agent: str
    proposal_type: ProposalType
    summary: str
    task_graph_patch: dict[str, Any] = Field(default_factory=dict)
    risk_level: Literal["low", "medium", "high", "critical"]
    required_gates: list[str] = Field(default_factory=list)
    estimated_cost: dict[str, Any] = Field(default_factory=dict)
    claimed_benefits: list[str] = Field(default_factory=list)
    known_risks: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    bid: ProposalBid = Field(default_factory=ProposalBid)
    status: ProposalStatus = "submitted"
    blocked_reason: str | None = None
    parent_proposal_id: str | None = None
    revision_id: str | None = None
    revision_round: int = 0

    @model_validator(mode="after")
    def validate_status_reason(self) -> "Proposal":
        if self.status == "blocked" and not self.blocked_reason:
            raise ValueError("blocked proposal requires blocked_reason")
        return self


class ProposalEvaluation(StrictModel):
    schema_version: str = "1.0"
    evaluation_id: str
    proposal_id: str
    reviewer_agent: str
    score: int
    decision: EvaluationDecision
    reason: str
    safety_issues: list[str] = Field(default_factory=list)
    quality_issues: list[str] = Field(default_factory=list)
    required_changes: list[str] = Field(default_factory=list)


class ProposalSelection(StrictModel):
    schema_version: str = "1.0"
    proposal_round_id: str
    run_id: str
    selected_proposal_id: str | None
    status: Literal["selected", "blocked"]
    reason: str
    rejected: dict[str, str] = Field(default_factory=dict)
    created_at: str


class ProposalManager:
    FORBIDDEN_ACTIONS = {"write_file", "delete_file", "move_file", "overwrite_file", "patch_apply", "approval_mutation", "memory_accept", "filesystem_mutation"}

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "config" / "proposal_policy.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}
        self.ledger = RunLedger(home, self.store)
        self.blackboard = Blackboard(home, self.store)

    @property
    def policy(self) -> dict[str, Any]:
        return self.config.get("proposal_policy", {}) if self.config else {}

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.config:
            return ["proposal_policy config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("proposal_policy schema_version major must be 1")
        for key in ("enabled_task_types", "proposer_agents", "evaluator_agents", "high_risk_requires_security", "forbidden_actions"):
            if key not in self.policy:
                errors.append(f"proposal_policy missing {key}")
        forbidden = set(self.policy.get("forbidden_actions", []))
        if not self.FORBIDDEN_ACTIONS.issubset(forbidden):
            errors.append("proposal_policy must forbid mutation/approval/apply/memory-accept actions")
        return errors, warnings

    def open_round(self, *, run_id: str, task_id: str, task_type: str, participants: list[str]) -> ProposalRound:
        if task_type not in set(self.policy.get("enabled_task_types", ["code_change", "high_risk_code_change", "maintenance"])):
            raise ValueError(f"proposal round not enabled for task_type: {task_type}")
        allowed = set(self.policy.get("proposer_agents", [])) | set(self.policy.get("evaluator_agents", []))
        blocked = sorted(set(participants) - allowed)
        if blocked:
            raise ValueError(f"proposal participants not policy allowed: {', '.join(blocked)}")
        round_ = ProposalRound(proposal_round_id="prop_round_" + new_id(), run_id=run_id, task_id=task_id, task_type=task_type, participants=sorted(set(participants)), status="open", created_at=iso_now())
        self.ledger.record("proposal_round_opened", run_id=run_id, task_id=task_id, task_type=task_type, status="ok", reason="proposal round opened", payload=round_.model_dump())
        self.store.record_audit("proposal_round_opened", round_.model_dump(), run_id=run_id, trace_id=f"{run_id}:proposal:{round_.proposal_round_id}", exit_status="ok")
        self.blackboard.record_document(run_id=run_id, task_id=task_id, author_agent="controller", doc_type="proposal", content_summary=f"Proposal round {round_.proposal_round_id} opened for {task_type}.")
        return round_

    def submit(
        self,
        round_: ProposalRound,
        *,
        proposer_agent: str,
        proposal_type: ProposalType,
        summary: str,
        risk_level: Literal["low", "medium", "high", "critical"],
        task_graph_patch: dict[str, Any] | None = None,
        required_gates: list[str] | None = None,
        claimed_benefits: list[str] | None = None,
        known_risks: list[str] | None = None,
        forbidden_actions: list[str] | None = None,
        bid: dict[str, Any] | ProposalBid | None = None,
        execution_contract: dict[str, Any] | None = None,
        parent_proposal_id: str | None = None,
        revision_id: str | None = None,
        revision_round: int = 0,
    ) -> Proposal:
        parsed_bid = ProposalBid.model_validate(bid or {})
        if proposer_agent not in set(self.policy.get("proposer_agents", [])):
            blocked_reason = f"proposer not policy allowed: {proposer_agent}"
        else:
            blocked_reason = self._policy_invalid_reason(
                task_graph_patch or {},
                required_gates or [],
                forbidden_actions or [],
                parsed_bid,
                execution_contract=execution_contract,
            )
        status: ProposalStatus = "blocked" if blocked_reason else "submitted"
        proposal = Proposal(
            proposal_id="proposal_" + new_id(),
            proposal_round_id=round_.proposal_round_id,
            run_id=round_.run_id,
            proposer_agent=proposer_agent,
            proposal_type=proposal_type,
            summary=summary[:1000],
            task_graph_patch=task_graph_patch or {},
            risk_level=risk_level,
            required_gates=required_gates or [],
            claimed_benefits=claimed_benefits or [],
            known_risks=known_risks or [],
            forbidden_actions=forbidden_actions or [],
            bid=parsed_bid,
            status=status,
            blocked_reason=blocked_reason,
            parent_proposal_id=parent_proposal_id,
            revision_id=revision_id,
            revision_round=revision_round,
        )
        event_type = "proposal_blocked" if status == "blocked" else "proposal_submitted"
        self.ledger.record(event_type, run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, agent_id=proposer_agent, status="blocked" if status == "blocked" else "ok", reason=blocked_reason or "proposal submitted", payload=proposal.model_dump())
        self.store.record_audit(event_type, proposal.model_dump(), run_id=round_.run_id, trace_id=f"{round_.run_id}:proposal:{proposal.proposal_id}", agent=proposer_agent, exit_status=status)
        self.blackboard.record_document(run_id=round_.run_id, task_id=round_.task_id, author_agent=proposer_agent, doc_type="proposal", content_summary=f"{proposal.summary}\nBid: {stable_json(proposal.bid.model_dump())}")
        return proposal

    def revise(
        self,
        round_: ProposalRound,
        parent: Proposal,
        *,
        proposer_agent: str,
        summary: str,
        risk_level: Literal["low", "medium", "high", "critical"],
        task_graph_patch: dict[str, Any],
        required_gates: list[str],
        claimed_benefits: list[str],
        known_risks: list[str],
        forbidden_actions: list[str],
        bid: dict[str, Any] | ProposalBid,
        revision_round: int,
        execution_contract: dict[str, Any] | None = None,
    ) -> Proposal:
        revision_id = "revision_" + new_id()
        revised = self.submit(
            round_,
            proposer_agent=proposer_agent,
            proposal_type=parent.proposal_type,
            summary=summary,
            risk_level=risk_level,
            task_graph_patch=task_graph_patch,
            required_gates=required_gates,
            claimed_benefits=claimed_benefits,
            known_risks=known_risks,
            forbidden_actions=forbidden_actions,
            bid=bid,
            parent_proposal_id=parent.proposal_id,
            revision_id=revision_id,
            revision_round=revision_round,
            execution_contract=execution_contract,
        )
        self.ledger.record(
            "proposal_revision_created",
            run_id=round_.run_id,
            task_id=round_.task_id,
            task_type=round_.task_type,
            agent_id=proposer_agent,
            status="blocked" if revised.status == "blocked" else "ok",
            reason="provider-backed proposal revision submitted",
            payload=revised.model_dump() | {"parent_proposal_id": parent.proposal_id, "revision_id": revision_id, "revision_round": revision_round},
        )
        self.store.record_audit(
            "proposal_revision_created",
            revised.model_dump() | {"parent_proposal_id": parent.proposal_id, "revision_id": revision_id, "revision_round": revision_round},
            run_id=round_.run_id,
            trace_id=f"{round_.run_id}:proposal:{revision_id}",
            agent=proposer_agent,
            exit_status=revised.status,
        )
        return revised

    def evaluate(
        self,
        round_: ProposalRound,
        proposal: Proposal,
        *,
        reviewer_agent: str,
        score: int,
        decision: EvaluationDecision,
        reason: str,
        safety_issues: list[str] | None = None,
        quality_issues: list[str] | None = None,
        required_changes: list[str] | None = None,
    ) -> ProposalEvaluation:
        if reviewer_agent not in set(self.policy.get("evaluator_agents", [])):
            raise ValueError(f"evaluator not policy allowed: {reviewer_agent}")
        evaluation = ProposalEvaluation(
            evaluation_id="prop_eval_" + new_id(),
            proposal_id=proposal.proposal_id,
            reviewer_agent=reviewer_agent,
            score=max(0, min(100, int(score))),
            decision=decision,
            reason=reason[:1000],
            safety_issues=safety_issues or [],
            quality_issues=quality_issues or [],
            required_changes=required_changes or [],
        )
        self.ledger.record(
            "proposal_evaluated",
            run_id=round_.run_id,
            task_id=round_.task_id,
            task_type=round_.task_type,
            agent_id=reviewer_agent,
            status="blocked" if decision == "block" else "ok",
            reason=evaluation.reason,
            payload=evaluation.model_dump(),
        )
        self.store.record_audit("proposal_evaluated", evaluation.model_dump(), run_id=round_.run_id, trace_id=f"{round_.run_id}:proposal:{evaluation.evaluation_id}", agent=reviewer_agent, exit_status=decision)
        self.blackboard.record_document(run_id=round_.run_id, task_id=round_.task_id, author_agent=reviewer_agent, doc_type="decision" if decision == "support" else "conflict", content_summary=f"{reviewer_agent} {decision} {proposal.proposal_id}: {reason}")
        return evaluation

    def select(self, round_: ProposalRound, proposals: list[Proposal], evaluations: list[ProposalEvaluation]) -> ProposalSelection:
        rejected: dict[str, str] = {}
        evals_by_proposal: dict[str, list[ProposalEvaluation]] = {}
        for evaluation in evaluations:
            evals_by_proposal.setdefault(evaluation.proposal_id, []).append(evaluation)
        candidates: list[tuple[int, str, Proposal]] = []
        for proposal in proposals:
            proposal_evals = evals_by_proposal.get(proposal.proposal_id, [])
            security_evals = [item for item in proposal_evals if item.reviewer_agent == "security"]
            if proposal.status == "blocked":
                rejected[proposal.proposal_id] = proposal.blocked_reason or "proposal blocked"
                continue
            if round_.task_type == "high_risk_code_change" and self.policy.get("high_risk_requires_security", True) and not security_evals:
                rejected[proposal.proposal_id] = "high-risk proposal missing security evaluation"
                continue
            if any(item.decision == "block" for item in proposal_evals):
                rejected[proposal.proposal_id] = "security/reviewer block overrides proposal"
                continue
            if any(item.decision == "needs_revision" for item in proposal_evals):
                rejected[proposal.proposal_id] = "proposal retains unresolved evaluator revision finding"
                continue
            score = sum(item.score for item in proposal_evals if item.decision == "support") - sum(100 - item.score for item in proposal_evals if item.decision in {"oppose", "needs_revision"})
            safety_bonus = 25 if any(item.reviewer_agent == "security" and item.decision == "support" for item in proposal_evals) else 0
            cost_penalty = int(proposal.bid.estimated_steps)
            candidates.append((score + safety_bonus - cost_penalty, proposal.proposal_id, proposal))
        for proposal in proposals:
            if proposal.proposal_id in rejected:
                self.ledger.record(
                    "proposal_rejected",
                    run_id=round_.run_id,
                    task_id=round_.task_id,
                    task_type=round_.task_type,
                    agent_id=proposal.proposer_agent,
                    status="blocked",
                    reason=rejected[proposal.proposal_id],
                    payload=proposal.model_dump() | {"rejection_reason": rejected[proposal.proposal_id]},
                )
        if not candidates:
            selection = ProposalSelection(proposal_round_id=round_.proposal_round_id, run_id=round_.run_id, selected_proposal_id=None, status="blocked", reason="no policy-valid proposal available", rejected=rejected, created_at=iso_now())
            self.ledger.record("proposal_blocked", run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, status="blocked", reason=selection.reason, payload=selection.model_dump())
            self.close_round(round_, status="blocked", reason=selection.reason)
            return selection
        candidates.sort(key=lambda item: (-item[0], item[1]))
        selected = candidates[0][2]
        for proposal in proposals:
            if proposal.proposal_id != selected.proposal_id and proposal.proposal_id not in rejected:
                rejected[proposal.proposal_id] = "lower ranked by conflict resolution"
                self.ledger.record("proposal_rejected", run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, agent_id=proposal.proposer_agent, status="ok", reason=rejected[proposal.proposal_id], payload=proposal.model_dump())
        selection = ProposalSelection(proposal_round_id=round_.proposal_round_id, run_id=round_.run_id, selected_proposal_id=selected.proposal_id, status="selected", reason=f"selected policy-valid proposal {selected.proposal_id}", rejected=rejected, created_at=iso_now())
        self.ledger.record("proposal_selected", run_id=round_.run_id, task_id=round_.task_id, task_type=round_.task_type, agent_id="controller", status="ok", reason=selection.reason, payload=selection.model_dump())
        self.store.record_audit("proposal_selected", selection.model_dump(), run_id=round_.run_id, trace_id=f"{round_.run_id}:proposal:selected", agent="controller", exit_status="selected", output_hash=sha256_text(stable_json(selection.model_dump())))
        self.blackboard.record_document(run_id=round_.run_id, task_id=round_.task_id, author_agent="controller", doc_type="decision", content_summary=selection.reason)
        self.close_round(round_, status="selected", reason=selection.reason)
        return selection

    def close_round(self, round_: ProposalRound, *, status: Literal["closed", "selected", "blocked"], reason: str) -> ProposalRound:
        closed = round_.model_copy(update={"status": status, "closed_at": iso_now()})
        self.ledger.record(
            "proposal_round_closed",
            run_id=round_.run_id,
            task_id=round_.task_id,
            task_type=round_.task_type,
            agent_id="controller",
            status="blocked" if status == "blocked" else "ok",
            reason=reason,
            payload=closed.model_dump(),
        )
        self.store.record_audit("proposal_round_closed", closed.model_dump(), run_id=round_.run_id, trace_id=f"{round_.run_id}:proposal:{round_.proposal_round_id}:closed", agent="controller", exit_status=status)
        self.blackboard.record_document(run_id=round_.run_id, task_id=round_.task_id, author_agent="controller", doc_type="decision", content_summary=f"Proposal round {round_.proposal_round_id} closed as {status}: {reason}")
        return closed

    def _policy_invalid_reason(
        self,
        task_graph_patch: dict[str, Any],
        required_gates: list[str],
        forbidden_actions: list[str],
        bid: ProposalBid | None = None,
        *,
        execution_contract: dict[str, Any] | None = None,
    ) -> str | None:
        forbidden = set(self.policy.get("forbidden_actions", [])) | self.FORBIDDEN_ACTIONS
        requested_forbidden = sorted(set(forbidden_actions) & forbidden)
        if requested_forbidden:
            return f"proposal requests forbidden action(s): {', '.join(requested_forbidden)}"
        if bid:
            forbidden_tools = sorted((set(bid.required_tools) | set(bid.required_side_effects)) & forbidden)
            if forbidden_tools:
                return f"proposal bid requests forbidden tool/action(s): {', '.join(forbidden_tools)}"
        if execution_contract and execution_contract.get("source_mutation_allowed") is False and bid:
            write_intent = sorted(
                set(bid.write_paths)
                | set(bid.touched_files)
                | set(bid.required_side_effects)
                | set(bid.writable_scope)
            )
            if write_intent:
                return "no-side-effect contract rejects write intent without writable scope: " + ", ".join(write_intent)
            required_flags = execution_contract.get("required_task_graph_flags")
            if isinstance(required_flags, dict):
                missing_flags = [
                    key
                    for key, expected in required_flags.items()
                    if task_graph_patch.get(key) != expected
                ]
                if missing_flags:
                    return "no-side-effect contract missing required task graph flag(s): " + ", ".join(sorted(missing_flags))
        patch_text = stable_json(task_graph_patch).lower()
        for marker in ("patch_apply", "approval_mutation", "memory_accept", "write_file", "delete_file", "filesystem_mutation"):
            if marker in patch_text:
                return f"proposal task_graph_patch contains forbidden side effect marker: {marker}"
        if any(gate in {"bypass_tester", "bypass_reviewer", "bypass_approval", "bypass_patch_hash"} for gate in required_gates):
            return "proposal attempts to bypass mandatory gate"
        return None
