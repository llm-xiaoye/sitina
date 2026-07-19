from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/optimization/optimization-ledger.json"
ALLOWED_STATUSES = {"PASS_NEW", "PASS_EXISTING", "FAIL", "BLOCKED"}


def expected_ids() -> list[str]:
    values: list[str] = []
    for prefix, count in (
        ("R", 15),
        ("O", 18),
        ("P", 22),
        ("PR", 16),
        ("H", 12),
        ("B", 10),
        ("M", 8),
        ("S", 10),
        ("F", 12),
        ("T", 10),
        ("PC", 8),
        ("E", 5),
    ):
        values.extend(f"{prefix}-{index:02d}" for index in range(1, count + 1))
    values.extend(("X-16", "X-17", "X-19"))
    return values


class OptimizationLedgerCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.value = json.loads(LEDGER.read_text(encoding="utf-8"))
        cls.requirements = cls.value["requirements"]

    def test_exact_requirement_inventory(self) -> None:
        actual = [item["id"] for item in self.requirements]
        self.assertEqual(len(actual), 149)
        self.assertEqual(len(set(actual)), 149)
        self.assertEqual(set(actual), set(expected_ids()))
        self.assertEqual(self.value["requirement_count"], 149)

    def test_every_requirement_has_auditable_fields(self) -> None:
        required = {
            "id",
            "status",
            "implementation_refs",
            "test_ids",
            "last_verified_commit",
            "evidence_refs",
            "notes",
        }
        for item in self.requirements:
            with self.subTest(requirement=item.get("id")):
                self.assertTrue(required.issubset(item))
                self.assertIn(item["status"], ALLOWED_STATUSES)
                self.assertIsInstance(item["implementation_refs"], list)
                self.assertIsInstance(item["test_ids"], list)
                self.assertIsInstance(item["evidence_refs"], list)
                self.assertIsInstance(item["notes"], list)
                self.assertTrue(item["last_verified_commit"])
                if item["status"] in {"PASS_NEW", "PASS_EXISTING"}:
                    self.assertTrue(item["implementation_refs"])
                    self.assertTrue(item["test_ids"])
                    self.assertTrue(item["evidence_refs"])

    def test_source_omissions_are_not_counted_as_requirements(self) -> None:
        self.assertEqual(
            self.value["source_not_provided"],
            ["E-06", "E-07", "E-08", "E-09", "E-10", "E-11", "第18项"],
        )

    def test_every_domain_declares_shared_contract_dependencies(self) -> None:
        dependencies = self.value["contract_dependency_by_domain"]
        self.assertEqual(set(dependencies), {item["domain"] for item in self.requirements})
        self.assertTrue(all(isinstance(items, list) and items for items in dependencies.values()))
        registry = self.value["shared_contract_registry"]
        self.assertEqual(registry["phase"], "01")
        self.assertEqual(registry["role"], "validation-and-interchange-only")
        self.assertFalse(registry["write_feature_flag_default"])

    def test_phase_lifecycle_is_a_contiguous_single_goal(self) -> None:
        phases = self.value["phases"]
        self.assertEqual([item["id"] for item in phases], [f"{index:02d}" for index in range(16)])
        statuses = [item["status"] for item in phases]
        self.assertTrue(set(statuses).issubset({"PENDING", "IN_PROGRESS", "COMPLETED"}))
        self.assertLessEqual(statuses.count("IN_PROGRESS"), 1)
        completed = statuses.count("COMPLETED")
        self.assertTrue(all(status == "COMPLETED" for status in statuses[:completed]))
        self.assertTrue(all(status != "COMPLETED" for status in statuses[completed:]))
        if "IN_PROGRESS" in statuses:
            current = statuses.index("IN_PROGRESS")
            self.assertEqual(self.value["current_phase"], f"{current:02d}")
            self.assertEqual(current, completed)


if __name__ == "__main__":
    unittest.main()
