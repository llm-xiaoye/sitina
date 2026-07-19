from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.archive.legacy_plan import LegacyArchivePlanError, LegacyArchivePlanner


class LegacyArchivePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        self.legacy = self.root / "legacy-source"
        self.legacy.mkdir()
        (self.legacy / "data").mkdir()
        (self.legacy / "data" / "sitina.db").write_bytes(b"legacy sqlite fixture")
        (self.legacy / "runs.jsonl").write_text('{"run_id":"old"}\n', encoding="utf-8")

    def test_plan_has_hashes_merkle_restore_signature_risk_and_no_mutation(self) -> None:
        before = {
            path.relative_to(self.legacy).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.legacy.rglob("*")
            if path.is_file()
        }
        target = self.root / "cold-target" / "legacy.tar.zst"
        plan = LegacyArchivePlanner().plan((self.legacy,), cold_archive_target=target)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["file_count"], 2)
        self.assertEqual(len(plan["tree_merkle_root"]), 64)
        self.assertEqual(len(plan["plan_commitment"]), 64)
        self.assertTrue(all(len(item["sha256"]) == 64 for item in plan["files"]))
        self.assertFalse(plan["archive_created"])
        self.assertFalse(plan["source_moved"])
        self.assertFalse(plan["source_deleted"])
        self.assertFalse(plan["native_trash_operated"])
        self.assertFalse(plan["restore_test"]["executed"])
        self.assertFalse(plan["signed_catalog"]["created"])
        self.assertIn("SECOND_USER_CONFIRMATION", plan["execution_sequence_if_separately_authorized"])
        self.assertFalse(target.exists())
        after = {
            path.relative_to(self.legacy).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.legacy.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)

    def test_hard_link_reclaim_estimate_does_not_double_count_inode(self) -> None:
        original = self.legacy / "runs.jsonl"
        linked = self.legacy / "runs-hardlink.jsonl"
        os.link(original, linked)
        plan = LegacyArchivePlanner().plan((self.legacy,), cold_archive_target=self.root / "cold")
        logical_allocated_sum = sum(item["allocated_bytes"] for item in plan["files"])
        self.assertLess(plan["estimated_reclaimable_allocated_bytes"], logical_allocated_sum)

    def test_symlink_and_overlapping_target_fail_closed(self) -> None:
        outside = self.root / "outside"
        outside.write_text("outside", encoding="utf-8")
        (self.legacy / "link").symlink_to(outside)
        with self.assertRaisesRegex(LegacyArchivePlanError, "symlink"):
            LegacyArchivePlanner().plan((self.legacy,), cold_archive_target=self.root / "cold")
        (self.legacy / "link").unlink()
        with self.assertRaisesRegex(LegacyArchivePlanError, "outside"):
            LegacyArchivePlanner().plan((self.legacy,), cold_archive_target=self.legacy / "cold")


if __name__ == "__main__":
    unittest.main()
