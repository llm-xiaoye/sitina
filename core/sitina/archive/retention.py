from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ReplicaCopy:
    copy_id: str
    fault_domain: str
    region: str
    provider: str
    administrative_domain: str
    key_domain: str
    verified_at: int
    verified: bool
    canonical_residency: bool = True


@dataclass(frozen=True)
class ReplicaPolicy:
    min_count: int
    min_fault_domains: int
    min_regions: int
    min_providers: int
    min_admin_domains: int
    min_key_domains: int
    max_verification_age: int


@dataclass(frozen=True)
class ReplicaSetAssessment:
    compliant: bool
    eligible_copy_ids: tuple[str, ...]
    dimension_counts: Mapping[str, int]
    reasons: tuple[str, ...]


def evaluate_replica_set(copies: tuple[ReplicaCopy, ...], policy: ReplicaPolicy, *, now: int) -> ReplicaSetAssessment:
    eligible = tuple(
        copy for copy in copies
        if copy.canonical_residency and copy.verified and 0 <= now - copy.verified_at <= policy.max_verification_age
    )
    counts = {
        "count": len(eligible),
        "fault_domain": len({copy.fault_domain for copy in eligible}),
        "region": len({copy.region for copy in eligible}),
        "provider": len({copy.provider for copy in eligible}),
        "administrative_domain": len({copy.administrative_domain for copy in eligible}),
        "key_domain": len({copy.key_domain for copy in eligible}),
    }
    minimums = {
        "count": policy.min_count,
        "fault_domain": policy.min_fault_domains,
        "region": policy.min_regions,
        "provider": policy.min_providers,
        "administrative_domain": policy.min_admin_domains,
        "key_domain": policy.min_key_domains,
    }
    reasons = tuple(f"INSUFFICIENT_{name.upper()}" for name, minimum in minimums.items() if counts[name] < minimum)
    return ReplicaSetAssessment(not reasons, tuple(copy.copy_id for copy in eligible), counts, reasons)


@dataclass(frozen=True)
class RetentionBlockers:
    legal_holds: tuple[str, ...] = ()
    evidence_complete: bool = True
    active_jobs: tuple[str, ...] = ()
    cross_run_refs: tuple[str, ...] = ()

    @property
    def clear(self) -> bool:
        return not self.legal_holds and self.evidence_complete and not self.active_jobs and not self.cross_run_refs

    def mapping(self) -> dict[str, object]:
        return {
            "legal_holds": list(self.legal_holds),
            "evidence_complete": self.evidence_complete,
            "active_jobs": list(self.active_jobs),
            "cross_run_refs": list(self.cross_run_refs),
        }

