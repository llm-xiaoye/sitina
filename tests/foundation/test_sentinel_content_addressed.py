"""Regression guard for the content-addressed production sentinel (V2).

This locks in the property that unblocked `execution_activation_gate`:

  * a content-preserving rewrite that changes mtime_ns / inode / device does NOT
    change the sentinel hash (no more spurious drift), and
  * any real content / added-file / mode change DOES change it (tamper detection
    stays intact).

Before V2 the sentinel hashed mtime_ns/inode/device per file, so an atomic
rename or restore drifted the hash even with identical content -- which is why
the gate could never converge on a live, growing home.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

FOUNDATION = Path(__file__).resolve().parent
sys.path.insert(0, str(FOUNDATION))
sys.path.insert(0, str(FOUNDATION.parents[1] / "core"))  # home_factory imports sitina.*
from home_factory import (  # noqa: E402
    capture_production_sentinel,
    capture_production_mutable_sentinel,
)

GOAL = "goal-test-0000"


def _make_home(root: Path) -> Path:
    home = root / "SitinaHubTest"
    for sub in ("data", "logs/events", "logs/audit", "state", "artifacts",
                "outputs", "memory", "backups", "temp"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    (home / "data/sitina.db").write_bytes(b"SQLITE-CONTENT-1")
    (home / "logs/events/e1.jsonl").write_text('{"e":1}\n')
    (home / "logs/audit/a1.jsonl").write_text('{"a":1}\n')
    (home / "state/checkpoint-1.json").write_text('{"k":1}\n')
    (home / "artifacts/manifest-a.json").write_text('{"m":1}\n')
    (home / "outputs/out1.txt").write_text("hello\n")
    (home / "memory/mem.md").write_text("# mem\n")
    (home / "backups/b1.txt").write_text("backup\n")
    return home


def _churn_metadata(home: Path) -> None:
    """Rewrite every regular file so inode + mtime change, content identical."""
    for path in sorted(home.rglob("*")):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            tmp = path.with_name(path.name + ".churn")
            tmp.write_bytes(data)      # brand-new inode
            os.replace(tmp, path)      # atomic swap -> inode differs from before
            os.utime(path, ns=(0, 0))  # force a distinct mtime_ns


class ContentAddressedSentinelTest(unittest.TestCase):
    def test_schema_is_v2_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = _make_home(Path(tmp))
            base = capture_production_sentinel(home, GOAL)
            mut = capture_production_mutable_sentinel(home, GOAL)
            self.assertEqual(base["schema"], "PRODUCTION_SENTINEL_V2")
            self.assertEqual(mut["schema"], "PRODUCTION_MUTABLE_SENTINEL_V3")
            self.assertEqual(base["observation_mode"],
                             "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2")
            self.assertEqual(mut["observation_mode"],
                             "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2")
            self.assertEqual(mut["base_v1_report_sha256"], base["report_sha256"])
            # no volatile fields leaked into any record
            for report in (base, mut):
                for cat in report["categories"]:
                    for entry in cat["entries"]:
                        self.assertNotIn("mtime_ns", entry)
                        self.assertNotIn("inode", entry)
                        self.assertNotIn("device", entry)

    def test_metadata_churn_does_not_change_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = _make_home(Path(tmp))
            base_before = capture_production_sentinel(home, GOAL)["report_sha256"]
            mut_before = capture_production_mutable_sentinel(home, GOAL)["report_sha256"]
            _churn_metadata(home)
            base_after = capture_production_sentinel(home, GOAL)["report_sha256"]
            mut_after = capture_production_mutable_sentinel(home, GOAL)["report_sha256"]
            self.assertEqual(base_before, base_after,
                             "metadata churn must not change the base sentinel hash")
            self.assertEqual(mut_before, mut_after,
                             "metadata churn must not change the mutable sentinel hash")

    def test_content_change_changes_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = _make_home(Path(tmp))
            before = capture_production_sentinel(home, GOAL)["report_sha256"]
            (home / "state/checkpoint-1.json").write_text('{"k":2}\n')
            after = capture_production_sentinel(home, GOAL)["report_sha256"]
            self.assertNotEqual(before, after,
                                "a real content change must change the sentinel hash")

    def test_mutable_only_content_change_changes_v3_but_not_base_v2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = _make_home(Path(tmp))
            base_before = capture_production_sentinel(home, GOAL)["report_sha256"]
            mut_before = capture_production_mutable_sentinel(home, GOAL)["report_sha256"]
            (home / "memory/mem.md").write_text("# changed\n")
            base_after = capture_production_sentinel(home, GOAL)["report_sha256"]
            mut_after = capture_production_mutable_sentinel(home, GOAL)["report_sha256"]
            self.assertEqual(base_before, base_after)
            self.assertNotEqual(
                mut_before,
                mut_after,
                "a mutable-root-only content change must change the V3 sentinel hash",
            )

    def test_added_file_changes_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = _make_home(Path(tmp))
            before = capture_production_sentinel(home, GOAL)["report_sha256"]
            (home / "state/new.json").write_text("{}\n")
            after = capture_production_sentinel(home, GOAL)["report_sha256"]
            self.assertNotEqual(before, after,
                                "an added file must change the sentinel hash")

    def test_mode_change_changes_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = _make_home(Path(tmp))
            before = capture_production_sentinel(home, GOAL)["report_sha256"]
            target = home / "state/checkpoint-1.json"  # covered by base state_root
            current = stat.S_IMODE(os.stat(target).st_mode)
            os.chmod(target, current ^ 0o004)  # guaranteed-different permission bits
            after = capture_production_sentinel(home, GOAL)["report_sha256"]
            self.assertNotEqual(before, after,
                                "a permission-bit change must change the sentinel hash")


if __name__ == "__main__":
    unittest.main()
