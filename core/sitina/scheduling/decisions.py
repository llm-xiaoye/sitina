from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash


FILTER_ORDER = ("eligibility", "safety", "dependencies", "capability", "lease", "budget", "policy")


@dataclass(frozen=True)
class CandidateEvaluation:
    task_id: str
    passed: bool
    first_failed_filter: str | None
    filter_results: tuple[tuple[str, bool], ...]
    base_score: int
    aging_score: int
    final_score: int | None
    source_versions: Mapping[str, int]


@dataclass(frozen=True)
class SchedulerDecision:
    decision_id: str
    source_frontier: FrontierRef
    policy_hash: str
    candidates: tuple[CandidateEvaluation, ...]
    ordered_attempts: tuple[str, ...]
    filter_order: tuple[str, ...] = FILTER_ORDER

    @property
    def commitment(self) -> str:
        return domain_hash(
            "SCHEDULER_DECISION",
            canonical_json_bytes(
                {
                    "source_frontier": self.source_frontier.__dict__, "policy_hash": self.policy_hash,
                    "candidates": [
                        {
                            **candidate.__dict__, "source_versions": dict(candidate.source_versions),
                            "filter_results": list(candidate.filter_results),
                        }
                        for candidate in self.candidates
                    ],
                    "ordered_attempts": list(self.ordered_attempts), "filter_order": list(self.filter_order),
                }
            ),
        )

