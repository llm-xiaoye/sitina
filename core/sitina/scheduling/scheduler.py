from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash, validate_identifier

from .decisions import FILTER_ORDER, CandidateEvaluation, SchedulerDecision


@dataclass(frozen=True)
class TaskCandidate:
    task_id: str
    eligibility: bool
    safety: bool
    dependencies: bool
    capability: bool
    lease: bool
    budget: bool
    policy: bool
    base_score: int
    aging_score: int
    source_versions: Mapping[str, int]

    def __post_init__(self) -> None:
        validate_identifier(self.task_id, field="task_id")


class Scheduler:
    def decide(self, candidates: Sequence[TaskCandidate], *, source_frontier: FrontierRef, policy_hash: str) -> SchedulerDecision:
        if len(policy_hash) != 64: raise ValueError("invalid Scheduler policy hash")
        evaluations = []
        for candidate in sorted(candidates, key=lambda item: item.task_id):
            results = tuple((name, bool(getattr(candidate, name))) for name in FILTER_ORDER)
            failed = next((name for name, passed in results if not passed), None)
            passed = failed is None
            evaluations.append(
                CandidateEvaluation(
                    candidate.task_id, passed, failed, results, candidate.base_score, candidate.aging_score,
                    candidate.base_score + candidate.aging_score if passed else None, dict(candidate.source_versions),
                )
            )
        ordered = tuple(
            evaluation.task_id
            for evaluation in sorted(
                (item for item in evaluations if item.passed),
                key=lambda item: (-int(item.final_score), item.task_id),
            )
        )
        preimage = {
            "source_frontier": source_frontier.__dict__, "policy_hash": policy_hash,
            "candidate_ids": [item.task_id for item in evaluations],
            "candidate_versions": {item.task_id: dict(item.source_versions) for item in evaluations},
            "ordered_attempts": list(ordered), "filter_order": list(FILTER_ORDER),
        }
        decision_id = "scheduler-decision-" + domain_hash("SCHEDULER_DECISION_ID", canonical_json_bytes(preimage))
        return SchedulerDecision(decision_id, source_frontier, policy_hash, tuple(evaluations), ordered)

