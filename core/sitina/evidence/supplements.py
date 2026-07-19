from __future__ import annotations

import dataclasses
from dataclasses import dataclass, replace
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier
from sitina.security.key_provider import EvidenceSealerCapability, InMemoryKeyProvider, KeyPurpose


class SupplementError(ValueError):
    pass


@dataclass(frozen=True)
class SupplementBody:
    base_seal_hash: str
    previous_record_hash: str | None
    coverage_frontier_hash: str
    late_facts: tuple[str, ...]
    dependency_refs: tuple[str, ...]
    proposed_audit_conclusion: str
    body_hash: str = ""

    def __post_init__(self) -> None:
        if self.body_hash:
            return
        object.__setattr__(self, "body_hash", domain_hash("EVIDENCE_SUPPLEMENT_BODY", canonical_json_bytes(self.mapping())))

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "EVIDENCE_SUPPLEMENT_BODY_V1",
            "base_seal_hash": self.base_seal_hash,
            "previous_record_hash": self.previous_record_hash,
            "coverage_frontier_hash": self.coverage_frontier_hash,
            "late_facts": list(self.late_facts),
            "dependency_refs": list(self.dependency_refs),
            "proposed_audit_conclusion": self.proposed_audit_conclusion,
        }


@dataclass(frozen=True)
class SupplementAssessment:
    body_hash: str
    status: str
    verifier_id: str
    policy_hash: str

    def mapping(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class SupplementRecord:
    body: SupplementBody
    assessment: SupplementAssessment
    key_id: str
    signature_hex: str
    record_hash: str

    def record_mapping(self) -> dict[str, object]:
        return {
            "schema": "EVIDENCE_SUPPLEMENT_RECORD_V1",
            "body": self.body.mapping(),
            "body_hash": self.body.body_hash,
            "assessment": self.assessment.mapping(),
            "key_id": self.key_id,
            "signature_hex": self.signature_hex,
        }

    @classmethod
    def sign(
        cls,
        body: SupplementBody,
        assessment: SupplementAssessment,
        provider: InMemoryKeyProvider,
        handle: EvidenceSealerCapability,
    ) -> "SupplementRecord":
        if assessment.body_hash != body.body_hash or assessment.status != "PASSED":
            raise SupplementError("supplement assessment is not seal eligible")
        unsigned = {
            "schema": "EVIDENCE_SUPPLEMENT_SIGNED_V1",
            "body_hash": body.body_hash,
            "assessment": assessment.mapping(),
        }
        key_id, signature = provider.sign_evidence_seal(
            b"SITINA-EVIDENCE-SUPPLEMENT-V1\0" + canonical_json_bytes(unsigned), handle
        )
        provisional = cls(body, assessment, key_id, signature.hex(), "")
        return replace(provisional, record_hash=domain_hash("EVIDENCE_SUPPLEMENT_RECORD", canonical_json_bytes(provisional.record_mapping())))

    def verify(self, provider: InMemoryKeyProvider) -> bool:
        unsigned = {
            "schema": "EVIDENCE_SUPPLEMENT_SIGNED_V1",
            "body_hash": self.body.body_hash,
            "assessment": self.assessment.mapping(),
        }
        return (
            self.assessment.body_hash == self.body.body_hash
            and provider.verify(
                self.key_id,
                KeyPurpose.EVIDENCE_SIGNING,
                b"SITINA-EVIDENCE-SUPPLEMENT-V1\0" + canonical_json_bytes(unsigned),
                bytes.fromhex(self.signature_hex),
            )
            and self.record_hash == domain_hash("EVIDENCE_SUPPLEMENT_RECORD", canonical_json_bytes(self.record_mapping()))
        )


@dataclass(frozen=True)
class SupplementStream:
    package_id: str
    base_seal_hash: str
    original_terminal_hash: str | None = None
    original_assessment_hash: str | None = None
    records: tuple[SupplementRecord, ...] = ()
    stream_version: int = 0

    def __post_init__(self) -> None:
        validate_identifier(self.package_id, field="package_id")

    @property
    def current_audit(self) -> str:
        return self.records[-1].body.proposed_audit_conclusion if self.records else "UNCHANGED"

    def accept(self, record: SupplementRecord, *, expected_version: int) -> tuple["SupplementStream", dict[str, object]]:
        if expected_version != self.stream_version:
            raise SupplementError("supplement stream CAS conflict")
        expected_previous = self.records[-1].record_hash if self.records else None
        if record.body.base_seal_hash != self.base_seal_hash or record.body.previous_record_hash != expected_previous:
            raise SupplementError("supplement does not extend the accepted chain head")
        if record.assessment.status != "PASSED":
            raise SupplementError("supplement assessment was not accepted")
        event = {
            "schema": "EVIDENCE_SUPPLEMENT_ACCEPTED_V1",
            "package_id": self.package_id,
            "version": self.stream_version + 1,
            "record_hash": record.record_hash,
        }
        return replace(self, records=(*self.records, record), stream_version=self.stream_version + 1), event

