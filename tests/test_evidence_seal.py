from __future__ import annotations

import dataclasses
import unittest

from sitina.evidence.assessment import AssessmentStatus, EvidenceVerifier, ReadOnlyCoreView, VerifierIdentity
from sitina.evidence.seal import EvidenceSealer, SealError, evaluate_seal_trust
from sitina.security.key_provider import InMemoryKeyProvider, KeyProviderError
from tests.test_evidence_assessment import completeness
from tests.test_evidence_package import core


def passed_assessment():
    return EvidenceVerifier(VerifierIdentity("verifier-1", "verifier", "1", "a" * 64, "SITINA_CANONICAL_JSON_V1")).verify(ReadOnlyCoreView(core()), completeness=completeness(), predicates={"integrity": True})


class EvidenceSealTests(unittest.TestCase):
    def test_only_sealer_role_can_receive_evidence_signing_handle(self) -> None:
        provider = InMemoryKeyProvider()
        for role in ("builder", "runtime-writer", "verifier"):
            with self.subTest(role=role), self.assertRaises(KeyProviderError): provider.issue_evidence_sealer_capability(role)
        handle = provider.issue_evidence_sealer_capability("evidence-sealer")
        self.assertEqual(handle.principal_role, "evidence-sealer")

    def test_sealer_rejects_nonpassed_wrong_core_and_wrong_policy(self) -> None:
        provider = InMemoryKeyProvider(); handle = provider.issue_evidence_sealer_capability("evidence-sealer")
        sealer = EvidenceSealer(provider, handle, evidence_policy_hash="a" * 64)
        assessment = passed_assessment()
        with self.assertRaises(SealError): sealer.seal(core(), dataclasses.replace(assessment, status=AssessmentStatus.INCOMPLETE), trusted_time=None)
        with self.assertRaises(SealError): sealer.seal(core(2, core().core_hash), assessment, trusted_time=None)
        with self.assertRaises(SealError): EvidenceSealer(provider, handle, evidence_policy_hash="b" * 64).seal(core(), assessment, trusted_time=None)

    def test_valid_seal_signature_and_trust_states(self) -> None:
        provider = InMemoryKeyProvider(); handle = provider.issue_evidence_sealer_capability("evidence-sealer")
        seal = EvidenceSealer(provider, handle, evidence_policy_hash="a" * 64).seal(core(), passed_assessment(), trusted_time="2026-07-14T00:00:00Z")
        self.assertTrue(seal.verify(provider))
        self.assertTrue(seal.trust.valid_at_seal_time)
        compromised = evaluate_seal_trust(seal, currently_trusted=False, compromised_after_seal=True, trusted_time_material_available=True)
        self.assertTrue(compromised.revoked_or_compromised_after_seal)
        self.assertFalse(compromised.currently_trusted)

    def test_key_compromise_does_not_replace_original_signature(self) -> None:
        provider = InMemoryKeyProvider(); handle = provider.issue_evidence_sealer_capability("evidence-sealer")
        seal = EvidenceSealer(provider, handle, evidence_policy_hash="a" * 64).seal(core(), passed_assessment(), trusted_time=None)
        original = seal.signature_hex
        current = evaluate_seal_trust(seal, currently_trusted=False, compromised_after_seal=True, trusted_time_material_available=False)
        self.assertEqual(seal.signature_hex, original)
        self.assertTrue(current.historical_validity_indeterminate)


if __name__ == "__main__": unittest.main()
