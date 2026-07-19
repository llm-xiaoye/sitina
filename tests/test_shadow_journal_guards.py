from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.legacy.model import LegacySourceKind, LegacySourceRecord
from sitina.legacy.shadow import ShadowExecutionDenied, ShadowExecutionGuard, ShadowImporter


class ShadowJournalGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"]).resolve(strict=True)
        self.record = LegacySourceRecord(
            kind=LegacySourceKind.EVENT_JSONL,
            source_ref="logs/events/2026-01-01.jsonl:1",
            content_hash="sha256:" + "a" * 64,
            observed_at="2026-01-01T00:00:00Z",
        )

    def test_shadow_context_cannot_drive_any_authoritative_adapter(self) -> None:
        guard = ShadowExecutionGuard(authority=False)
        for operation in ("provider", "mcp", "tool", "approval", "timer", "terminal", "evidence_seal", "effect"):
            with self.subTest(operation=operation), self.assertRaises(ShadowExecutionDenied):
                guard.assert_operation_allowed(operation)

    def test_import_identity_is_deterministic_non_authoritative_and_physically_isolated(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.home / "temp") as temporary:
            root = Path(temporary)
            source_home = root / "source"
            shadow_root = root / "migration-workspace"
            source_home.mkdir()
            importer = ShadowImporter(
                source_home=source_home,
                shadow_root=shadow_root,
                installation_id="fixture-installation",
                snapshot_id="snapshot-1",
                snapshot_hash="sha256:" + "b" * 64,
                conversion_rule_hash="sha256:" + "c" * 64,
            )
            left = importer.import_record(self.record, payload={"legacy": True})
            right = importer.import_record(self.record, payload={"legacy": True})
            self.assertEqual(left.migration_fact_id, right.migration_fact_id)
            self.assertFalse(left.authority)
            self.assertEqual(left.namespace, "shadow/snapshot-1")
            self.assertEqual(left.event_type, "ImportedLegacyFact")
            self.assertEqual(left.historical_observed_at, self.record.observed_at)
            self.assertNotEqual(left.committed_at, left.historical_observed_at)
            self.assertTrue(str(importer.output_path.resolve()).startswith(str(shadow_root.resolve()) + os.sep))
            lines = importer.output_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1, "same deterministic record must be idempotent")
            self.assertFalse(json.loads(lines[0])["authority"])

    def test_shadow_root_cannot_overlap_source_or_production_home(self) -> None:
        with self.assertRaises(ValueError):
            ShadowImporter(
                source_home=self.home,
                shadow_root=self.home / "shadow",
                installation_id="x",
                snapshot_id="s",
                snapshot_hash="sha256:" + "0" * 64,
                conversion_rule_hash="sha256:" + "1" * 64,
            )


if __name__ == "__main__":
    unittest.main()
