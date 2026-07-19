from __future__ import annotations

import os
import unittest
from pathlib import Path

from sitina.legacy.write_sink_inventory import AuditSinkRecorder, scan_tree
from sitina.orchestrator.engine import SitinaEngine


class LegacyWriteSinkInventoryTests(unittest.TestCase):
    def test_static_inventory_has_no_unknown_entrypoint(self) -> None:
        root = Path(__file__).resolve().parents[2]
        inventory = scan_tree(root)
        self.assertFalse(inventory["parse_errors"], inventory["parse_errors"])
        unknown = [
            entry for entry in inventory["entries"] if entry["classification"].startswith("UNKNOWN")
        ]
        self.assertFalse(unknown, unknown[:20])
        self.assertGreater(inventory["summary"]["legacy_mutation_count"], 0)

    def test_representative_legacy_flow_mutates_only_disposable_home(self) -> None:
        home = Path(os.environ["SITINA_HOME"]).resolve(strict=True)
        recorder = AuditSinkRecorder(home).install()
        result = SitinaEngine(home).run(
            "proposal-competition-fixture phase-minus1 dynamic sink inventory",
            provider_mode="mock",
        )
        self.assertIn(result["status"], {"done", "blocked", "awaiting_approval"})
        path_records = [record for record in recorder.records if "path" in record]
        self.assertTrue(path_records)
        outside = [record for record in path_records if not record["inside_allowed_home"]]
        self.assertFalse(outside, outside[:20])
        self.assertTrue(any(record["event"] == "sqlite3.connect" for record in recorder.records))


if __name__ == "__main__":
    unittest.main()
