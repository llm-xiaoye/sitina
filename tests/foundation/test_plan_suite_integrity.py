from __future__ import annotations

import hashlib
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "docs/superpowers/build_complete_plan.py"


class PlanSuiteIntegrityTests(unittest.TestCase):
    def test_generated_complete_plan_is_exact_and_current(self) -> None:
        module = runpy.run_path(str(GENERATOR))
        expected = module["render"]()
        output = module["OUTPUT"]
        self.assertEqual(output.read_text(encoding="utf-8"), expected)
        for source in module["SOURCES"]:
            body = (ROOT / source.relative_path).read_text(encoding="utf-8")
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            self.assertEqual(expected.count(body.rstrip()), 1, source.relative_path)
            self.assertIn(digest, expected)

    def test_check_detects_hand_edited_generated_output(self) -> None:
        module = runpy.run_path(str(GENERATOR))
        expected = module["render"]()
        self.assertNotEqual(expected + "hand edit\n", expected)

    def test_source_order_contains_every_phase_once(self) -> None:
        module = runpy.run_path(str(GENERATOR))
        paths = [source.relative_path for source in module["SOURCES"]]
        self.assertEqual(len(paths), len(set(paths)))
        for phase in ("phase-minus-1", "phase-0", "phase-1", "phase-2", "phase-3", "phase-4", "phase-5", "phase-6a", "phase-6b", "phase-7"):
            self.assertEqual(sum(phase in path for path in paths), 1, phase)


if __name__ == "__main__":
    unittest.main()
