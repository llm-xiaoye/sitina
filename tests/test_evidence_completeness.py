from __future__ import annotations

import unittest

from sitina.evidence.completeness import (
    CompletenessLevel,
    CompletenessProofs,
    SelfContainment,
    assess_completeness,
)


def proofs(**changes: object) -> CompletenessProofs:
    values = {
        "material_inventory": True, "source_frontier": True, "stream_chain": True,
        "cas_closure": True, "dependency_closure": True, "journal_index": True,
        "stream_enumeration": True, "signed_frontier": True, "inclusion_proof": True,
        "omission_proof": True, "trust_material": True, "keys_available": True,
    }
    values.update(changes)
    return CompletenessProofs(**values)


class EvidenceCompletenessTests(unittest.TestCase):
    def test_each_level_requires_its_exact_proofs(self) -> None:
        for level in CompletenessLevel:
            result = assess_completeness(level, proofs(), verify=SelfContainment.SELF_CONTAINED, replay=SelfContainment.SELF_CONTAINED, inspect=SelfContainment.SELF_CONTAINED)
            self.assertEqual(result.actual_level, level)
            self.assertEqual(result.status, "PROVEN")

    def test_crypto_complete_without_omission_proof_is_forbidden_not_warned(self) -> None:
        result = assess_completeness(CompletenessLevel.CRYPTOGRAPHICALLY_COMPLETE, proofs(omission_proof=False), verify=SelfContainment.SELF_CONTAINED, replay=SelfContainment.SELF_CONTAINED, inspect=SelfContainment.SELF_CONTAINED)
        self.assertNotEqual(result.actual_level, CompletenessLevel.CRYPTOGRAPHICALLY_COMPLETE)
        self.assertIn("OMISSION_PROOF_MISSING", result.reasons)

    def test_self_containment_is_orthogonal_to_completeness(self) -> None:
        result = assess_completeness(CompletenessLevel.JOURNAL_INDEX_PROVEN, proofs(), verify=SelfContainment.SELF_CONTAINED, replay=SelfContainment.REFERENTIAL, inspect=SelfContainment.HYBRID)
        self.assertEqual(result.actual_level, CompletenessLevel.JOURNAL_INDEX_PROVEN)
        self.assertEqual(result.replay_self_containment, SelfContainment.REFERENTIAL)

    def test_missing_cas_key_dependency_or_index_downgrades_or_fails(self) -> None:
        for changes in ({"cas_closure": False}, {"keys_available": False}, {"dependency_closure": False}, {"journal_index": False}):
            with self.subTest(changes=changes):
                result = assess_completeness(CompletenessLevel.JOURNAL_INDEX_PROVEN, proofs(**changes), verify=SelfContainment.HYBRID, replay=SelfContainment.HYBRID, inspect=SelfContainment.HYBRID)
                self.assertIn(result.status, {"DOWNGRADED", "UNVERIFIABLE"})
                self.assertNotEqual(result.actual_level, CompletenessLevel.JOURNAL_INDEX_PROVEN)


if __name__ == "__main__": unittest.main()
