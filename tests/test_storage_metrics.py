from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.cas.local import LocalCAS
from sitina.diagnostics.storage_metrics import StorageMetricsCollector
from sitina.security.key_provider import InMemoryKeyProvider


class StorageMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.cas = LocalCAS.open(self.home, InMemoryKeyProvider())
        self.cas.publish_plaintext(
            b"metrics plaintext" * 100,
            tenant_id="metrics",
            purpose_class="metrics",
            compression="none",
        )
        projection = self.home / "projections"
        (projection / "current").mkdir(parents=True)
        (projection / "previous").mkdir()
        (projection / "building").mkdir()
        (projection / "current" / "generation.sqlite").write_bytes(b"projection")
        (projection / "current-generation.json").write_text(
            json.dumps({"schema": "PROJECTION_GENERATION_POINTER_V2", "journal_frontier": 8}),
            encoding="utf-8",
        )
        sealed = self.home / "journal" / "sealed"
        sealed.mkdir(parents=True)
        (sealed / "segment-1.seg").write_bytes(b"sealed")

    def test_snapshot_contains_required_storage_and_memory_metrics_without_writes(self) -> None:
        before = {
            str(path.relative_to(self.home)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in self.home.rglob("*")
            if path.is_file()
        }
        report = {
            "checkpoint_used": True,
            "journal_bytes_scanned": 4096,
            "journal_events_verified": 4,
            "active_tail_event_count": 3,
        }
        memory_events = (
            {"event_type": "memory.candidate-created"},
            {"event_type": "memory.candidate-created"},
            {"event_type": "memory.accepted"},
            {"event_type": "memory.expired"},
            {"event_type": "memory.conflict"},
            {"event_type": "memory.retrieval", "payload": {"result_count": 2}},
            {"event_type": "memory.retrieval", "payload": {"result_count": 0}},
            {"event_type": "memory.episode-reused"},
        )
        snapshot = StorageMetricsCollector(self.home).collect(
            startup_duration_ms=12,
            journal_frontier=10,
            fast_start_report=report,
            memory_events=memory_events,
            gc_dry_run_plan={"candidates": [{"object_ref": "cas:" + "f" * 64}]},
        )
        required = {
            "startup_duration_ms",
            "journal_bytes_scanned",
            "journal_events_verified",
            "fast_start_checkpoint_used",
            "active_tail_event_count",
            "sealed_segment_count",
            "projection_frontier",
            "projection_lag",
            "projection_generation_count",
            "projection_disk_bytes",
            "cas_object_count",
            "cas_logical_bytes",
            "cas_allocated_bytes",
            "cas_dedup_ratio",
            "cas_staging_count",
            "cas_quarantine_count",
            "gc_candidate_count",
            "memory_candidate_count",
            "memory_acceptance_rate",
            "memory_expired_rate",
            "memory_conflict_rate",
            "memory_retrieval_hit_rate",
            "episode_reuse_rate",
        }
        self.assertTrue(required.issubset(snapshot))
        self.assertTrue(snapshot["read_only"])
        self.assertEqual(snapshot["journal_events_appended"], 0)
        self.assertEqual(snapshot["projection_lag"], 2)
        self.assertEqual(snapshot["memory_acceptance_rate"], 0.5)
        self.assertEqual(snapshot["memory_retrieval_hit_rate"], 0.5)
        self.assertEqual(snapshot["gc_candidate_count"], 1)
        after = {
            str(path.relative_to(self.home)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in self.home.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
