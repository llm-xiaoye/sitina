from __future__ import annotations

import json
import unittest
from pathlib import Path

from sitina.evidence.completeness import CompletenessLevel, EvidencePolicy


class EvidencePolicyProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = Path(__file__).parents[1] / "config" / "evidence_policy.bplus_v1.json"

    def test_frozen_policy_binds_trust_and_container_profiles(self) -> None:
        policy = EvidencePolicy.from_file(self.path)
        self.assertEqual(policy.profile_id, "SITINA_EVIDENCE_POLICY_BPLUS_V1")
        self.assertEqual(policy.minimum_completeness, CompletenessLevel.STREAM_CHAIN_VERIFIED)
        self.assertEqual(len(policy.policy_hash), 64)
        self.assertEqual(len(policy.trust_profile_hash), 64)
        self.assertEqual(len(policy.container_profile_hash), 64)

    def test_v1_cannot_claim_crypto_complete_without_omission_proof(self) -> None:
        policy = EvidencePolicy.from_file(self.path)
        self.assertTrue(policy.cryptographic_completeness_requires_omission_proof)
        self.assertFalse(policy.allow_asserted_to_seal)
        self.assertEqual(policy.seal_eligible_assessment_statuses, frozenset({"PASSED"}))

    def test_signature_and_trusted_time_rules_are_explicit(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(raw["trust"]["signature_profile"], "ED25519_RAW_64_BYTES_HEX_V1")
        self.assertEqual(raw["trust"]["missing_trusted_time_disposition"], "HISTORICAL_VALIDITY_INDETERMINATE")
        self.assertEqual(raw["container"]["fallback_when_zstandard_unavailable"], "LOGICAL_DIRECTORY_ONLY")
        self.assertFalse(raw["container"]["claim_tar_zst_when_dependency_unavailable"])


if __name__ == "__main__": unittest.main()
