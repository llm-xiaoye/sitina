from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sitina.legacy.fence import LegacyWriteGate
from sitina.legacy.inventory import InventoryError, build_frozen_snapshot, build_observational_inventory


def _seed(home: Path) -> None:
    for relative in ("data", "logs/events", "logs/audit", "state/checkpoints", "artifacts/evidence"):
        (home / relative).mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(home / "data/sitina.db") as connection:
        connection.execute("CREATE TABLE run_ledger(id INTEGER PRIMARY KEY, run_id TEXT, payload TEXT)")
        connection.execute("INSERT INTO run_ledger(run_id,payload) VALUES ('run_1','{}')")
    (home / "logs/events/2026-01-01.jsonl").write_text('{"event_id":"e1"}\n', encoding="utf-8")
    (home / "logs/audit/2026-01-01.jsonl").write_text('{"audit_id":"a1"}\n', encoding="utf-8")
    (home / "state/checkpoints/run_1.json").write_text('{"run_id":"run_1"}\n', encoding="utf-8")
    (home / "artifacts/evidence/run_1.json").write_text('{"run_id":"run_1"}\n', encoding="utf-8")


class LegacyInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.test_home = Path(os.environ["SITINA_HOME"]).resolve(strict=True)

    def test_observational_inventory_is_deterministic_and_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.test_home / "temp") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            _seed(source)
            before = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob("*") if p.is_file()}
            left = build_observational_inventory(source, root / "out-left")
            right = build_observational_inventory(source, root / "out-right")
            self.assertEqual(left.semantic_manifest_hash, right.semantic_manifest_hash)
            self.assertEqual(left.coherence, "LIVE_OBSERVATIONAL_INVENTORY")
            self.assertTrue((root / "out-left/sqlite-snapshot.db").is_file())
            self.assertTrue(left.capacity_check.passed)
            self.assertTrue(all(entry.observation_status == "STABLE" for entry in left.entries))
            after = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob("*") if p.is_file()}
            self.assertEqual(before, after)
            self.assertEqual(left.table_summaries["run_ledger"].row_count, 1)

    def test_output_inside_source_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.test_home / "temp") as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            _seed(source)
            with self.assertRaises(InventoryError):
                build_observational_inventory(source, source / "inventory-output")
            link = source / "state/escape"
            link.symlink_to(Path(temporary), target_is_directory=True)
            with self.assertRaises(InventoryError):
                build_observational_inventory(source, Path(temporary) / "outside")

    def test_frozen_snapshot_requires_verified_fixture_fence(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.test_home / "temp") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
            _seed(source)
            gate = LegacyWriteGate(source)
            with self.assertRaises(InventoryError):
                build_frozen_snapshot(source, root / "not-frozen", cutoff="2026-07-14T00:00:00Z")
            gate.freeze("snapshot_fixture", fixture_authorization=True)
            try:
                snapshot = build_frozen_snapshot(source, root / "frozen", cutoff="2026-07-14T00:00:00Z")
                self.assertEqual(snapshot.coherence, "FROZEN_COHERENT_SNAPSHOT")
                self.assertEqual(snapshot.fence_snapshot_id, "snapshot_fixture")
                self.assertFalse((root / "frozen/sqlite-snapshot.db-wal").exists())
                self.assertFalse((root / "frozen/sqlite-snapshot.db-shm").exists())
            finally:
                gate.unfreeze_fixture()


if __name__ == "__main__":
    unittest.main()
