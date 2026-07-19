from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .completeness import CompletenessAssessment
from .package import EvidencePackageCore


class AssessmentStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"
    UNVERIFIABLE = "UNVERIFIABLE"
    CONTRADICTED = "CONTRADICTED"


@dataclass(frozen=True)
class VerifierIdentity:
    verifier_id: str
    implementation: str
    version: str
    policy_hash: str
    canonical_profile: str

    def __post_init__(self) -> None:
        validate_identifier(self.verifier_id, field="verifier_id")

    def mapping(self) -> dict[str, str]:
        return {
            "verifier_id": self.verifier_id,
            "implementation": self.implementation,
            "version": self.version,
            "policy_hash": self.policy_hash,
            "canonical_profile": self.canonical_profile,
        }


@dataclass(frozen=True)
class EvidenceAssessment:
    core_hash: str
    verifier: VerifierIdentity
    completeness: CompletenessAssessment
    predicates: Mapping[str, bool]
    status: AssessmentStatus
    assessment_hash: str

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "EVIDENCE_ASSESSMENT_V1",
            "core_hash": self.core_hash,
            "verifier": self.verifier.mapping(),
            "completeness": self.completeness.mapping(),
            "predicates": dict(sorted(self.predicates.items())),
            "status": self.status.value,
        }


class ReadOnlyCoreView:
    def __init__(self, core: EvidencePackageCore):
        self._core = core

    @property
    def core(self) -> EvidencePackageCore:
        return self._core

    def read(self) -> dict[str, object]:
        return self._core.core_mapping()

    def write(self, _value: object) -> None:
        raise PermissionError("evidence verifier core view is read-only")


class EvidenceVerifier:
    def __init__(self, identity: VerifierIdentity):
        self.identity = identity
        self._issued: list[EvidenceAssessment] = []

    @property
    def issued_assessments(self) -> tuple[EvidenceAssessment, ...]:
        return tuple(self._issued)

    def verify(
        self,
        view: ReadOnlyCoreView,
        *,
        completeness: CompletenessAssessment,
        predicates: Mapping[str, bool],
        contradicted: bool = False,
        trust_unavailable: bool = False,
        fault: str | None = None,
    ) -> EvidenceAssessment:
        if fault == "CRASH_BEFORE_ASSESSMENT":
            raise RuntimeError("injected verifier crash before assessment issuance")
        if contradicted:
            status = AssessmentStatus.CONTRADICTED
        elif trust_unavailable or completeness.status == "UNVERIFIABLE":
            status = AssessmentStatus.UNVERIFIABLE
        elif completeness.status != "PROVEN":
            status = AssessmentStatus.INCOMPLETE
        elif not predicates or not all(predicates.values()):
            status = AssessmentStatus.FAILED
        else:
            status = AssessmentStatus.PASSED
        provisional = EvidenceAssessment(view.core.core_hash, self.identity, completeness, dict(predicates), status, "")
        assessment = EvidenceAssessment(
            provisional.core_hash,
            provisional.verifier,
            provisional.completeness,
            provisional.predicates,
            provisional.status,
            domain_hash("EVIDENCE_ASSESSMENT", canonical_json_bytes(provisional.mapping())),
        )
        self._issued.append(assessment)
        return assessment

