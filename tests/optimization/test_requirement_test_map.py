from __future__ import annotations

import importlib
import json
import os
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RequirementTestMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = Path(os.environ["SITINA_HOME"])
        cls.ledger = json.loads((ROOT / "docs/optimization/optimization-ledger.json").read_text(encoding="utf-8"))
        cls.mapping = json.loads((ROOT / "tests/optimization/requirement-test-map.json").read_text(encoding="utf-8"))

    @staticmethod
    def _resolve(test_id: str):
        parts = test_id.split(".")
        if len(parts) < 4:
            raise AssertionError(f"test ID is not method-specific: {test_id}")
        module = importlib.import_module(".".join(parts[:-2]))
        case = getattr(module, parts[-2])
        return getattr(case, parts[-1])

    def test_requirement_map_has_exact_149_nonempty_method_specific_executable_mappings(self) -> None:
        requirements = self.mapping["requirements"]
        ledger_ids = {item["id"] for item in self.ledger["requirements"]}
        self.assertEqual(self.mapping["schema"], "SITINA_REQUIREMENT_TEST_MAP_V1")
        self.assertEqual((self.mapping["requirement_count"], len(requirements), set(requirements)), (149, 149, ledger_ids))
        for requirement_id, entry in requirements.items():
            with self.subTest(requirement_id=requirement_id):
                self.assertTrue(entry["test_ids"])
                self.assertTrue(entry["assertion"].strip())
                for test_id in entry["test_ids"]:
                    self.assertTrue(test_id.rsplit(".", 1)[-1].startswith("test_"))
                    self.assertTrue(callable(self._resolve(test_id)))

    def test_pass_new_never_uses_document_only_evidence_and_assertions_are_requirement_specific(self) -> None:
        by_id = {item["id"]: item for item in self.ledger["requirements"]}
        assertions = []
        for requirement_id, entry in self.mapping["requirements"].items():
            if by_id[requirement_id]["status"] == "PASS_NEW":
                self.assertIn(entry["evidence_kind"], {"behavior", "benchmark", "config_behavior"})
            self.assertIn(by_id[requirement_id]["summary"], entry["assertion"])
            assertions.append((requirement_id, entry["assertion"]))
        self.assertEqual(len(assertions), 149)


if __name__ == "__main__":
    unittest.main()
