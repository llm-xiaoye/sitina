from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import IntEnum, Enum
from pathlib import Path

from sitina.journal.model import canonical_json_bytes


class CompletenessLevel(IntEnum):
    ASSERTED = 0
    STREAM_CHAIN_VERIFIED = 1
    JOURNAL_INDEX_PROVEN = 2
    CRYPTOGRAPHICALLY_COMPLETE = 3


class SelfContainment(str, Enum):
    SELF_CONTAINED = "SELF_CONTAINED"
    HYBRID = "HYBRID"
    REFERENTIAL = "REFERENTIAL"


@dataclass(frozen=True)
class CompletenessProofs:
    material_inventory: bool
    source_frontier: bool
    stream_chain: bool
    cas_closure: bool
    dependency_closure: bool
    journal_index: bool
    stream_enumeration: bool
    signed_frontier: bool
    inclusion_proof: bool
    omission_proof: bool
    trust_material: bool
    keys_available: bool


@dataclass(frozen=True)
class CompletenessAssessment:
    requested_level: CompletenessLevel
    actual_level: CompletenessLevel
    status: str
    reasons: tuple[str, ...]
    verify_self_containment: SelfContainment
    replay_self_containment: SelfContainment
    inspect_self_containment: SelfContainment

    def mapping(self) -> dict[str, object]:
        return {
            "requested_level": self.requested_level.name,
            "actual_level": self.actual_level.name,
            "status": self.status,
            "reasons": list(self.reasons),
            "verify_self_containment": self.verify_self_containment.value,
            "replay_self_containment": self.replay_self_containment.value,
            "inspect_self_containment": self.inspect_self_containment.value,
        }


_REQUIREMENTS = {
    CompletenessLevel.ASSERTED: ("material_inventory", "source_frontier"),
    CompletenessLevel.STREAM_CHAIN_VERIFIED: ("material_inventory", "source_frontier", "stream_chain", "cas_closure", "dependency_closure", "keys_available"),
    CompletenessLevel.JOURNAL_INDEX_PROVEN: ("material_inventory", "source_frontier", "stream_chain", "cas_closure", "dependency_closure", "journal_index", "stream_enumeration", "keys_available"),
    CompletenessLevel.CRYPTOGRAPHICALLY_COMPLETE: ("material_inventory", "source_frontier", "stream_chain", "cas_closure", "dependency_closure", "journal_index", "stream_enumeration", "signed_frontier", "inclusion_proof", "omission_proof", "trust_material", "keys_available"),
}


def assess_completeness(
    requested: CompletenessLevel,
    proofs: CompletenessProofs,
    *,
    verify: SelfContainment,
    replay: SelfContainment,
    inspect: SelfContainment,
) -> CompletenessAssessment:
    reasons: list[str] = []
    actual = CompletenessLevel.ASSERTED
    for level in CompletenessLevel:
        missing = [name for name in _REQUIREMENTS[level] if not getattr(proofs, name)]
        if missing:
            if level <= requested:
                reasons.extend(f"{name.upper()}_MISSING" for name in missing)
            break
        actual = level
        if level == requested:
            break
    if actual > requested:
        actual = requested
    # ASSERTED still requires its explicit inventory/frontier claims.
    asserted_missing = [name for name in _REQUIREMENTS[CompletenessLevel.ASSERTED] if not getattr(proofs, name)]
    if asserted_missing:
        actual = CompletenessLevel.ASSERTED
    reasons = list(dict.fromkeys(reasons))
    status = "PROVEN" if actual == requested and not reasons else "DOWNGRADED"
    if not proofs.keys_available or not proofs.trust_material and requested >= CompletenessLevel.CRYPTOGRAPHICALLY_COMPLETE:
        status = "UNVERIFIABLE"
    return CompletenessAssessment(requested, actual, status, tuple(reasons), verify, replay, inspect)


@dataclass(frozen=True)
class EvidencePolicy:
    profile_id: str
    minimum_completeness: CompletenessLevel
    cryptographic_completeness_requires_omission_proof: bool
    allow_asserted_to_seal: bool
    seal_eligible_assessment_statuses: frozenset[str]
    policy_hash: str
    trust_profile_hash: str
    container_profile_hash: str

    @classmethod
    def from_file(cls, path: Path) -> "EvidencePolicy":
        raw = json.loads(path.read_text(encoding="utf-8"))
        trust = raw["trust"]
        container = raw["container"]
        return cls(
            profile_id=raw["profile_id"],
            minimum_completeness=CompletenessLevel[raw["minimum_completeness"]],
            cryptographic_completeness_requires_omission_proof=bool(raw["cryptographic_completeness_requires_omission_proof"]),
            allow_asserted_to_seal=bool(raw["allow_asserted_to_seal"]),
            seal_eligible_assessment_statuses=frozenset(raw["seal_eligible_assessment_statuses"]),
            policy_hash=hashlib.sha256(canonical_json_bytes(raw)).hexdigest(),
            trust_profile_hash=hashlib.sha256(canonical_json_bytes(trust)).hexdigest(),
            container_profile_hash=hashlib.sha256(canonical_json_bytes(container)).hexdigest(),
        )

