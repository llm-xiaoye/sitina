from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path((_SITINA_ACCOUNT_HOME + '/Desktop/sitina/output'))
EXPECTED_MANIFEST_HASH = "7b9eafbd2b0a0cd10b5520774d72d6d46db8a6c471993fd9d3093224041f6f6a"
EXPECTED_PHASE_MINUS1_ACCEPTANCE = "c8176e5ae731fcaaf750428634bef884362a13fa1a8631bdd5ef6ad1359b03f8"
EXPECTED_PHASE_MINUS1_CONTENT = "13fd832932887fa11196f6736d1e3261a34552b5746322132d588a1ca48023e7"
EXPECTED_V1_SENTINEL = "0866e7f81ba5d886f794ebcdf63eb8b7e985c8a518f328b4e5c38c30265eeab0"
EXPECTED_MUTABLE_SENTINEL = "467786e69548a7731c272ff226f8ff1b5c2b19be6d5743a7d78e4c4853019795"


def _load(name: str) -> dict[str, Any]:
    value = json.loads((CONTROL / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"control report is not an object: {name}")
    return value


def _canonical_hash(value: dict[str, Any], *, excluded_field: str | None = None) -> str:
    body = dict(value)
    if excluded_field is not None:
        body.pop(excluded_field)
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class Phase0AcceptanceTests(unittest.TestCase):
    def test_manifest_is_goal_bound_and_non_cutover(self) -> None:
        manifest = _load("sitina-bplus-phase0-execution-manifest-v1.json")
        self.assertEqual(_canonical_hash(manifest), EXPECTED_MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "0")
        self.assertEqual(manifest["authorization"]["authorized_task_range"], "1..8")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "PHASE0_ACCEPTANCE")
        self.assertEqual(manifest["goal"]["thread_id"], "019f5c6b-3083-7860-b45b-c8b487c4e3ab")
        self.assertIn("AUTHORITY_CUTOVER", manifest["prohibited_operations"])
        self.assertIn("CREATE_PRODUCTION_BPLUS_JOURNAL_CAS_OR_PROJECTION", manifest["prohibited_operations"])

        previous = _load("sitina-bplus-phase-minus1-acceptance.json")
        self.assertEqual(previous["status"], "PASSED")
        self.assertEqual(previous["acceptance_sha256"], EXPECTED_PHASE_MINUS1_ACCEPTANCE)
        self.assertTrue(all(previous["predicates"].values()), previous["predicates"])

    def test_observational_inventory_is_honestly_scoped_and_covered(self) -> None:
        report = _load("sitina-bplus-phase0-observational-inventory.json")
        self.assertEqual(_canonical_hash(report, excluded_field="report_sha256"), report["report_sha256"])
        self.assertEqual(report["coherence"], "LIVE_OBSERVATIONAL_INVENTORY")
        self.assertEqual(report["scope"], "PHASE1_SENTINEL_DERIVED_CAPACITY_ONLY_NO_PRODUCTION_SNAPSHOT")
        self.assertFalse(report["observation_inputs"]["production_snapshot_created"])
        self.assertFalse(report["observation_inputs"]["sqlite_connection_opened"])
        self.assertEqual(report["observation_inputs"]["v1_sentinel_report_sha256"], EXPECTED_V1_SENTINEL)
        self.assertEqual(report["observation_inputs"]["full_mutable_sentinel_report_sha256"], EXPECTED_MUTABLE_SENTINEL)
        self.assertTrue(report["capacity_estimate"]["passed"])
        self.assertEqual(report["sink_inventory"]["summary"]["unknown_count"], 0)
        self.assertEqual(report["fence_coverage"]["summary"]["blocker_count"], 0)
        self.assertEqual(report["fence_coverage"]["summary"]["entry_count"], 290)
        self.assertEqual(report["authority"]["production_writer"], "legacy")
        self.assertFalse(report["authority"]["production_frozen"])
        self.assertFalse(report["authority"]["bplus_authority_created"])

    def test_source_manifest_chains_and_excludes_runtime(self) -> None:
        report = _load("sitina-bplus-content-manifest-phase0.json")
        self.assertEqual(_canonical_hash(report, excluded_field="manifest_sha256"), report["manifest_sha256"])
        self.assertEqual(report["previous_manifest_hash"], f"sha256:{EXPECTED_PHASE_MINUS1_CONTENT}")
        self.assertEqual(report["root"], (_SITINA_ACCOUNT_HOME + '/SitinaHub'))
        self.assertEqual(
            set(report["excluded_roots"]),
            {"artifacts", "backups", "data", "logs", "memory", "outputs", "state", "temp"},
        )
        paths = {entry["path"] for entry in report["entries"]}
        self.assertIn("tests/test_phase0_acceptance.py", paths)
        self.assertIn("core/sitina/legacy/fence.py", paths)
        for path in paths:
            self.assertNotIn(path.split("/", 1)[0], report["excluded_roots"], path)

    def test_all_phase0_regression_layers_pass_without_effect_attempts(self) -> None:
        expected_counts = {
            "phase0_fixture": (20, 0),
            "unit_fast": (27, 0),
            "integration_isolated": (154, 1),
            "crash_fault": (8, 0),
        }
        for suite, (test_count, skipped_count) in expected_counts.items():
            with self.subTest(suite=suite):
                result = _load(f"sitina-bplus-phase0-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{EXPECTED_MANIFEST_HASH}")
                self.assertEqual(result["return_code"], 0)
                self.assertFalse(result["timed_out"])
                self.assertEqual(result["test_count"], test_count)
                self.assertEqual(result["skipped_count"], skipped_count)
                self.assertEqual(result["warning_count"], 0)
                self.assertEqual(result["external_attempt_count"], 0)
                self.assertEqual(result["production_attempt_count"], 0)
                self.assertTrue(result["production_sentinel_unchanged"])
                self.assertEqual(result["production_sentinel_after"], EXPECTED_V1_SENTINEL)
                self.assertEqual(result["production_mutable_sentinel_after"], EXPECTED_MUTABLE_SENTINEL)

    def test_incident_is_exactly_recovered_and_post_sentinel_has_no_authority(self) -> None:
        incident = _load("sitina-bplus-phase0-production-lock-incident.json")
        self.assertEqual(incident["status"], "RECOVERED_REGRESSION_PASSED")
        self.assertFalse(incident["impact"]["legacy_sqlite_changed"])
        self.assertFalse(incident["impact"]["legacy_jsonl_changed"])
        self.assertFalse(incident["impact"]["existing_state_file_overwritten"])
        self.assertTrue(incident["recovery_evidence"]["sentinels_restored_exactly"])
        self.assertTrue(incident["regression_evidence"]["all_layers_passed"])

        post = _load("sitina-bplus-production-sentinel-phase0-post.json")
        self.assertEqual(_canonical_hash(post, excluded_field="report_sha256"), post["report_sha256"])
        self.assertEqual(post["v1_report_sha256"], EXPECTED_V1_SENTINEL)
        self.assertEqual(post["mutable_report_sha256"], EXPECTED_MUTABLE_SENTINEL)
        self.assertTrue(post["authority_material_absent"])
        self.assertTrue(all(item["absent"] for item in post["authority_path_checks"]))
        self.assertFalse(post["production_freeze_executed"])
        self.assertEqual(post["production_writer"], "legacy")

    def test_acceptance_process_is_disposable(self) -> None:
        home = Path(os.environ["SITINA_HOME"])
        self.assertNotEqual(home, Path((_SITINA_ACCOUNT_HOME + '/SitinaHub')))
        self.assertTrue((home / ".sitina-bplus-disposable-v1").is_file())


if __name__ == "__main__":
    unittest.main()
