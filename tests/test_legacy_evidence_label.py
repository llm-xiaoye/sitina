from __future__ import annotations

import unittest

from sitina.orchestrator.evidence_bundle import EvidenceBundleManager


class LegacyEvidenceLabelTests(unittest.TestCase):
    def test_legacy_bundle_has_exact_compatibility_label(self) -> None:
        claims=EvidenceBundleManager.legacy_compatibility_claims()
        self.assertEqual(claims["classification"],"artifact_integrity_verified_compatibility_export")
        self.assertFalse(claims["bplus_opt_compliant"]); self.assertFalse(claims["bplus_sealed"])

    def test_legacy_bundle_cannot_claim_bplus_completeness(self) -> None:
        claims=EvidenceBundleManager.legacy_compatibility_claims()
        self.assertEqual(claims["completeness_level"],"LEGACY_TERMINAL_MANIFEST")
        self.assertNotIn(claims["completeness_level"],{"STREAM_CHAIN_VERIFIED","JOURNAL_INDEX_PROVEN","CRYPTOGRAPHICALLY_COMPLETE"})

    def test_compatibility_export_remains_portable_hash_verified(self) -> None:
        claims=EvidenceBundleManager.legacy_compatibility_claims()
        self.assertTrue(claims["portable_relative_paths"]); self.assertTrue(claims["artifact_hashes_verified"])


if __name__ == "__main__": unittest.main()
