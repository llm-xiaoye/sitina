from __future__ import annotations

import os
import unittest
from pathlib import Path

from sitina.legacy.classify import (
    IncompleteReason,
    LegacyFactClassifier,
    LegacyFactDisposition,
    preserve_conflicting_records,
)
from sitina.legacy.model import LegacySourceKind, LegacySourceRecord


class LegacyClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        home = Path(os.environ["SITINA_HOME"])
        self.classifier = LegacyFactClassifier.from_file(home / "config/legacy_fact_classification.json")

    def record(self, kind: LegacySourceKind, ref: str, digest: str = "1") -> LegacySourceRecord:
        return LegacySourceRecord(kind=kind, source_ref=ref, content_hash="sha256:" + digest * 64, observed_at="2026-07-14T00:00:00Z")

    def test_versioned_matrix_never_claims_native_canonical_history(self) -> None:
        cases = [
            (LegacySourceKind.SQLITE_TABLE, "data/sitina.db#run_ledger:1", "coordination_fact_candidate"),
            (LegacySourceKind.EVENT_JSONL, "logs/events/x.jsonl:1", "supplementary_legacy_fact"),
            (LegacySourceKind.AUDIT_JSONL, "logs/audit/x.jsonl:1", "audit_representation"),
            (LegacySourceKind.MUTABLE_SNAPSHOT, "state/run_state.json", "state_assertion"),
            (LegacySourceKind.CHECKPOINT, "state/checkpoints/x.json", "legacy_evidence_artifact"),
            (LegacySourceKind.RUN_MANIFEST, "artifacts/runs/x/manifest.json", "legacy_evidence_artifact"),
            (LegacySourceKind.REPLAY_SNAPSHOT, "artifacts/replay/x.json", "legacy_evidence_artifact"),
            (LegacySourceKind.EVIDENCE_EXPORT, "artifacts/evidence/x.json", "legacy_evidence_artifact"),
        ]
        for kind, ref, fact_kind in cases:
            with self.subTest(kind=kind):
                value = self.classifier.classify(self.record(kind, ref))
                self.assertEqual(value.fact_kind, fact_kind)
                self.assertNotEqual(value.disposition, LegacyFactDisposition.NATIVE_CANONICAL_EVENT)
                self.assertTrue(value.migration_event_type.startswith("Imported") or value.migration_event_type.startswith("Migrated"))

    def test_incomplete_reasons_are_explicit(self) -> None:
        expected = {
            "MISSING_CAUSATION", "MISSING_TIMESTAMP", "MISSING_PAYLOAD", "MISSING_ACTOR",
            "MISSING_STREAM_HISTORY", "UNVERIFIABLE_HASH", "ORPHAN_RECORD", "CONFLICTING_RECORD",
        }
        self.assertEqual({item.value for item in IncompleteReason}, expected)

    def test_same_identity_different_hash_preserves_both(self) -> None:
        left = self.record(LegacySourceKind.EVENT_JSONL, "logs/events/x.jsonl:1", "1")
        right = self.record(LegacySourceKind.EVENT_JSONL, "logs/events/x.jsonl:1", "2")
        preserved = preserve_conflicting_records([left, right], installation_id="fixture-installation")
        self.assertEqual(len(preserved), 2)
        self.assertNotEqual(preserved[0].migration_id, preserved[1].migration_id)
        self.assertTrue(all(item.incomplete_reason is IncompleteReason.CONFLICTING_RECORD for item in preserved))
        self.assertEqual({item.source_ref for item in preserved}, {left.source_ref})


if __name__ == "__main__":
    unittest.main()
