from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

from sitina.journal.model import canonical_json_bytes, domain_hash
from sitina.security.key_provider import EvidenceSealerCapability, InMemoryKeyProvider, KeyPurpose

from .assessment import AssessmentStatus, EvidenceAssessment
from .package import EvidencePackageCore


class SealError(ValueError):
    pass


@dataclass(frozen=True)
class SealTrust:
    valid_at_seal_time: bool
    currently_trusted: bool
    revoked_or_compromised_after_seal: bool
    historical_validity_indeterminate: bool

    def mapping(self) -> dict[str, bool]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class EvidenceSeal:
    core_hash: str
    assessment_hash: str
    evidence_policy_hash: str
    trusted_time: str | None
    trust: SealTrust
    key_id: str
    signature_hex: str
    seal_hash: str

    def signed_mapping(self) -> dict[str, object]:
        return {
            "schema": "EVIDENCE_SEAL_V1",
            "core_hash": self.core_hash,
            "assessment_hash": self.assessment_hash,
            "evidence_policy_hash": self.evidence_policy_hash,
            "trusted_time": self.trusted_time,
            "trust": self.trust.mapping(),
        }

    def mapping(self) -> dict[str, object]:
        return {**self.signed_mapping(), "key_id": self.key_id, "signature_hex": self.signature_hex}

    def verify(self, provider: InMemoryKeyProvider) -> bool:
        if not re.fullmatch(r"[0-9a-f]{128}", self.signature_hex):
            return False
        signature_ok = provider.verify(
            self.key_id,
            KeyPurpose.EVIDENCE_SIGNING,
            b"SITINA-EVIDENCE-SEAL-V1\0" + canonical_json_bytes(self.signed_mapping()),
            bytes.fromhex(self.signature_hex),
        )
        return signature_ok and self.seal_hash == domain_hash("EVIDENCE_SEAL", canonical_json_bytes(self.mapping()))


class EvidenceSealer:
    def __init__(self, provider: InMemoryKeyProvider, capability: EvidenceSealerCapability, *, evidence_policy_hash: str):
        self.provider = provider
        self.capability = capability
        self.evidence_policy_hash = evidence_policy_hash

    def seal(self, core: EvidencePackageCore, assessment: EvidenceAssessment, *, trusted_time: str | None) -> EvidenceSeal:
        if assessment.status is not AssessmentStatus.PASSED:
            raise SealError("only PASSED assessments are seal eligible")
        if assessment.core_hash != core.core_hash:
            raise SealError("assessment does not bind the requested core")
        if assessment.verifier.policy_hash != self.evidence_policy_hash:
            raise SealError("verifier policy and evidence sealing policy differ")
        trust = SealTrust(
            valid_at_seal_time=True,
            currently_trusted=True,
            revoked_or_compromised_after_seal=False,
            historical_validity_indeterminate=trusted_time is None,
        )
        unsigned = EvidenceSeal(core.core_hash, assessment.assessment_hash, self.evidence_policy_hash, trusted_time, trust, "", "", "")
        key_id, signature = self.provider.sign_evidence_seal(
            b"SITINA-EVIDENCE-SEAL-V1\0" + canonical_json_bytes(unsigned.signed_mapping()),
            self.capability,
        )
        provisional = dataclasses.replace(unsigned, key_id=key_id, signature_hex=signature.hex())
        return dataclasses.replace(provisional, seal_hash=domain_hash("EVIDENCE_SEAL", canonical_json_bytes(provisional.mapping())))


def evaluate_seal_trust(
    seal: EvidenceSeal,
    *,
    currently_trusted: bool,
    compromised_after_seal: bool,
    trusted_time_material_available: bool,
) -> SealTrust:
    return SealTrust(
        valid_at_seal_time=seal.trust.valid_at_seal_time,
        currently_trusted=currently_trusted,
        revoked_or_compromised_after_seal=compromised_after_seal,
        historical_validity_indeterminate=not trusted_time_material_available,
    )

