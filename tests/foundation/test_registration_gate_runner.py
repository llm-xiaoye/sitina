from __future__ import annotations

import io
import json
import unittest
from pathlib import Path

from tests.foundation.registration_gate_runner import (
    LoadedRegistrationSuite,
    run_loaded_registration_suite,
    unique_registered_selectors,
)


ROOT = Path(__file__).resolve().parents[2]


class RegistrationGateRunnerTests(unittest.TestCase):
    def test_registry_derivation_is_unique_and_complete(self) -> None:
        registry = json.loads((ROOT / "tests/test_suites.json").read_text(encoding="utf-8"))
        selectors = unique_registered_selectors(registry)
        self.assertEqual(len(selectors), len(set(selectors)))
        self.assertIn("tests/foundation/test_dependency_lock_gate.py", selectors)
        self.assertIn("tests/foundation/test_sentinel_content_addressed.py", selectors)
        self.assertIn("tests/test_live_audit_acceptance_contract.py", selectors)

    def test_exact_skip_allowlist_is_accepted_and_reported(self) -> None:
        class Probe(unittest.TestCase):
            def test_pass(self):
                pass

            @unittest.skip("historical")
            def test_skip(self):
                pass

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Probe)
        ids = tuple(test.id() for test in suite)
        skip_id = next(test_id for test_id in ids if test_id.endswith(".test_skip"))
        loaded = LoadedRegistrationSuite(
            suite=suite,
            selectors=("probe",),
            selector_counts={"probe": len(ids)},
            collected_test_ids=ids,
            collection_errors=(),
            expected_skips=({"test_id": skip_id, "reason": "historical"},),
        )
        summary = run_loaded_registration_suite(loaded, stream=io.StringIO())
        self.assertTrue(summary["accepted"])
        self.assertTrue(summary["skip_allowlist_match"])
        self.assertEqual(
            summary["skip_details"],
            [{"test_id": skip_id, "reason": "historical"}],
        )

    def test_added_or_replaced_skip_is_rejected(self) -> None:
        class Probe(unittest.TestCase):
            @unittest.skip("unexpected")
            def test_skip(self):
                pass

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Probe)
        ids = tuple(test.id() for test in suite)
        loaded = LoadedRegistrationSuite(
            suite=suite,
            selectors=("probe",),
            selector_counts={"probe": len(ids)},
            collected_test_ids=ids,
            collection_errors=(),
            expected_skips=(
                {"test_id": ids[0], "reason": "historical"},
            ),
        )
        summary = run_loaded_registration_suite(loaded, stream=io.StringIO())
        self.assertFalse(summary["accepted"])
        self.assertFalse(summary["skip_allowlist_match"])


if __name__ == "__main__":
    unittest.main()
