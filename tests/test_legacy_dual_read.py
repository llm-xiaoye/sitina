from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.legacy.compare import ComparisonDisposition, ComparisonProfile, compare_run, write_comparison_reports


class _Reader:
    def __init__(self, payload: dict):
        self.payload = payload

    def read_run(self, run_id: str, frontier: str) -> dict:
        return {"run_id": run_id, "frontier": frontier, **self.payload}


class LegacyDualReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"]).resolve(strict=True)
        self.profile = ComparisonProfile.v1()
        self.base = {
            "terminal_status": "done",
            "task_count": 3,
            "proposal_count": 2,
            "handoff_count": 1,
            "arbitration_count": 0,
            "lease_count": 1,
            "provider_call_count": 2,
            "checkpoint_hashes": ["sha256:" + "1" * 64],
            "evidence_hashes": ["sha256:" + "2" * 64],
            "secret_scan_status": "clean",
            "row_id": 99,
            "local_path": "/tmp/legacy/path",
        }

    def test_representation_fields_normalize_but_business_fields_do_not(self) -> None:
        shadow = dict(self.base, row_id=5, local_path="/different/root")
        result = compare_run("run_1", _Reader(self.base), _Reader(shadow), "frontier-1", self.profile)
        self.assertEqual(result.disposition, ComparisonDisposition.MATCH)
        self.assertEqual(result.ignored_fields, ["local_path", "row_id"])
        mismatch = compare_run("run_1", _Reader(self.base), _Reader(dict(shadow, terminal_status="failed")), "frontier-1", self.profile)
        self.assertEqual(mismatch.disposition, ComparisonDisposition.BLOCKING_MISMATCH)
        self.assertIn("terminal_status", mismatch.differences)

    def test_legacy_incomplete_requires_approved_reason_and_source_refs(self) -> None:
        shadow = dict(self.base)
        shadow.pop("provider_call_count")
        blocked = compare_run("run_1", _Reader(self.base), _Reader(shadow), "frontier-1", self.profile)
        self.assertEqual(blocked.disposition, ComparisonDisposition.BLOCKING_MISMATCH)
        approved = compare_run(
            "run_1",
            _Reader(self.base),
            _Reader(shadow),
            "frontier-1",
            self.profile,
            approved_incomplete={"provider_call_count": {"reason": "MISSING_PAYLOAD", "source_refs": ["data/sitina.db#run_1"]}},
        )
        self.assertEqual(approved.disposition, ComparisonDisposition.LEGACY_INCOMPLETE)
        self.assertEqual(approved.incomplete[0]["reason"], "MISSING_PAYLOAD")
        with self.assertRaises(ValueError):
            compare_run(
                "run_1", _Reader(self.base), _Reader(shadow), "frontier-1", self.profile,
                approved_incomplete={"provider_call_count": {"reason": "anything", "source_refs": []}},
            )

    def test_machine_and_markdown_reports_are_evidence_not_authority(self) -> None:
        result = compare_run("run_1", _Reader(self.base), _Reader(self.base), "frontier-1", self.profile)
        with tempfile.TemporaryDirectory(dir=self.home / "temp") as temporary:
            paths = write_comparison_reports(result, Path(temporary))
            machine = json.loads(paths["json"].read_text(encoding="utf-8"))
            self.assertFalse(machine["authority"])
            self.assertIn("Evidence only", paths["markdown"].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
