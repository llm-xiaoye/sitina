from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash, validate_identifier


AGENT_FILTER_ORDER = (
    "eligibility",
    "capability",
    "safety",
    "budget",
    "lease",
    "independence",
    "policy",
)


@dataclass(frozen=True)
class AgentCandidate:
    agent_id: str
    role: str
    capabilities: tuple[str, ...]
    eligible: bool = True
    safety_allowed: bool = True
    budget_allowed: bool = True
    lease_available: bool = True
    independent: bool = True
    policy_allowed: bool = True
    load: int = 0
    cost_weight: int = 0
    source_versions: Mapping[str, int] | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.agent_id, field="agent_id")
        validate_identifier(self.role, field="agent_role")
        for capability in self.capabilities:
            validate_identifier(capability, field="agent_capability")
        if self.load < 0 or self.cost_weight < 0:
            raise ValueError("Agent load and cost weight must be non-negative")


@dataclass(frozen=True)
class AgentScorecard:
    agent_id: str
    role: str
    passed: bool
    first_failed_filter: str | None
    filter_results: tuple[tuple[str, bool], ...]
    capability_matches: tuple[str, ...]
    capability_missing: tuple[str, ...]
    capability_score: int
    load_penalty: int
    cost_penalty: int
    final_score: int | None
    reason_code: str
    source_versions: Mapping[str, int]

    def mapping(self) -> dict[str, Any]:
        return {
            **self.__dict__,
            "filter_results": [list(item) for item in self.filter_results],
            "capability_matches": list(self.capability_matches),
            "capability_missing": list(self.capability_missing),
            "source_versions": dict(self.source_versions),
        }


@dataclass(frozen=True)
class AgentSchedulingDecision:
    decision_id: str
    task_id: str
    source_event_ids: tuple[str, ...]
    source_frontier: FrontierRef
    candidate_tasks: tuple[str, ...]
    candidate_agents: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    scorecards: tuple[AgentScorecard, ...]
    ordered_attempts: tuple[str, ...]
    selected_attempts: tuple[str, ...]
    requested_slots: int
    reason_code: str
    policy_hash: str
    deadline: str
    filter_order: tuple[str, ...] = AGENT_FILTER_ORDER

    @property
    def commitment(self) -> str:
        return domain_hash("AGENT_SCHEDULING_DECISION", canonical_json_bytes(self.mapping(include_id=False)))

    def mapping(self, *, include_id: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "task_id": self.task_id,
            "source_event_ids": list(self.source_event_ids),
            "source_frontier": self.source_frontier.__dict__,
            "candidate_tasks": list(self.candidate_tasks),
            "candidate_agents": list(self.candidate_agents),
            "required_capabilities": list(self.required_capabilities),
            "eligibility_filters": list(self.filter_order),
            "capability_filters": list(self.required_capabilities),
            "safety_filters": ["safety_allowed"],
            "budget_filters": ["budget_allowed"],
            "lease_filters": ["lease_available"],
            "scorecards": [item.mapping() for item in self.scorecards],
            "ordered_attempts": list(self.ordered_attempts),
            "selected_attempts": list(self.selected_attempts),
            "selected_attempt": self.selected_attempts[0] if self.selected_attempts else None,
            "requested_slots": self.requested_slots,
            "reason_code": self.reason_code,
            "policy_hash": self.policy_hash,
            "deadline": self.deadline,
        }
        if include_id:
            value["decision_id"] = self.decision_id
            value["decision_commitment"] = self.commitment
        return value


class AgentScheduler:
    """Pure decision component. It discovers candidates but never claims work."""

    def decide(
        self,
        task_id: str,
        candidates: Sequence[AgentCandidate],
        *,
        required_capabilities: Sequence[str],
        requested_slots: int,
        source_event_ids: Sequence[str],
        source_frontier: FrontierRef,
        candidate_tasks: Sequence[str],
        policy_hash: str,
        deadline: str,
    ) -> AgentSchedulingDecision:
        validate_identifier(task_id, field="task_id")
        if len(policy_hash) != 64 or requested_slots < 1:
            raise ValueError("Agent scheduling requires a policy hash and positive requested slots")
        required = tuple(sorted(set(str(item) for item in required_capabilities)))
        for capability in required:
            validate_identifier(capability, field="required_capability")
        evaluations: list[AgentScorecard] = []
        for candidate in sorted(candidates, key=lambda item: item.agent_id):
            capabilities = set(candidate.capabilities)
            matches = tuple(sorted(capabilities.intersection(required)))
            missing = tuple(sorted(set(required).difference(capabilities)))
            filters = (
                ("eligibility", candidate.eligible),
                ("capability", not missing),
                ("safety", candidate.safety_allowed),
                ("budget", candidate.budget_allowed),
                ("lease", candidate.lease_available),
                ("independence", candidate.independent),
                ("policy", candidate.policy_allowed),
            )
            failed = next((name for name, passed in filters if not passed), None)
            capability_score = len(matches) * 100 + max(0, len(capabilities) - len(required))
            load_penalty = candidate.load * 10
            cost_penalty = candidate.cost_weight
            final = capability_score - load_penalty - cost_penalty if failed is None else None
            evaluations.append(
                AgentScorecard(
                    candidate.agent_id,
                    candidate.role,
                    failed is None,
                    failed,
                    filters,
                    matches,
                    missing,
                    capability_score,
                    load_penalty,
                    cost_penalty,
                    final,
                    "ELIGIBLE" if failed is None else f"FILTERED_{failed.upper()}",
                    dict(candidate.source_versions or {}),
                )
            )
        ordered = tuple(
            item.agent_id
            for item in sorted(
                (item for item in evaluations if item.passed),
                key=lambda item: (-int(item.final_score or 0), item.agent_id),
            )
        )
        selected = ordered[:requested_slots]
        reason = "SELECTED_CAPABILITY_SCORE" if selected else "NO_ELIGIBLE_AGENT"
        preimage = {
            "task_id": task_id,
            "source_event_ids": list(source_event_ids),
            "source_frontier": source_frontier.__dict__,
            "candidate_tasks": sorted(set(candidate_tasks)),
            "candidate_agents": [item.agent_id for item in evaluations],
            "required_capabilities": list(required),
            "scorecards": [item.mapping() for item in evaluations],
            "ordered_attempts": list(ordered),
            "selected_attempts": list(selected),
            "requested_slots": requested_slots,
            "reason_code": reason,
            "policy_hash": policy_hash,
            "deadline": deadline,
        }
        decision_id = "agent-decision-" + domain_hash(
            "AGENT_SCHEDULING_DECISION_ID", canonical_json_bytes(preimage)
        )
        return AgentSchedulingDecision(
            decision_id,
            task_id,
            tuple(source_event_ids),
            source_frontier,
            tuple(sorted(set(candidate_tasks))),
            tuple(item.agent_id for item in evaluations),
            required,
            tuple(evaluations),
            ordered,
            selected,
            requested_slots,
            reason,
            policy_hash,
            deadline,
        )
