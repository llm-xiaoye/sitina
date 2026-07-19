from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path("/Users/moss/Desktop/sitina/output")
MANIFEST_HASH = "8e96dd7a3e4d83190e968b99c8877c4467e6eb39bb2783a00fa9fc6ebf6c72df"
PHASE0_ACCEPTANCE = "c6b359afad4af52c3692ad51d35d03080046ec130e02fa16f8d41d977d93c008"
PHASE0_CONTENT = "b2a6add265318b7308626b971a1c0471bb4cee38cd9eada39524230b09ac46ed"
V1_SENTINEL = "0866e7f81ba5d886f794ebcdf63eb8b7e985c8a518f328b4e5c38c30265eeab0"
MUTABLE_SENTINEL = "467786e69548a7731c272ff226f8ff1b5c2b19be6d5743a7d78e4c4853019795"


def load(name: str) -> dict[str, Any]:
    value = json.loads((CONTROL / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"control report is not an object: {name}")
    return value


def canonical_hash(value: dict[str, Any], excluded: str | None = None) -> str:
    body = dict(value)
    if excluded:
        body.pop(excluded)
    return hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Phase1KernelAcceptanceTests(unittest.TestCase):
    def test_manifest_promotes_passed_phase0_without_authority_expansion(self) -> None:
        manifest = load("sitina-bplus-phase1-execution-manifest-v1.json")
        self.assertEqual(canonical_hash(manifest), MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "1")
        self.assertEqual(manifest["authorization"]["authorized_task_range"], "0..12")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "PHASE1_ACCEPTANCE")
        self.assertIn("CREATE_PRODUCTION_JOURNAL_CAS_PROJECTION_OR_AUTHORITY", manifest["prohibited_operations"])
        previous = load("sitina-bplus-phase0-acceptance.json")
        self.assertEqual(previous["status"], "PASSED")
        self.assertEqual(previous["acceptance_sha256"], PHASE0_ACCEPTANCE)
        self.assertTrue(all(previous["predicates"].values()))

    def test_profiles_were_frozen_before_persistent_fixture_bytes(self) -> None:
        freeze = load("sitina-bplus-phase1-profile-freeze.json")
        self.assertEqual(canonical_hash(freeze, "report_sha256"), freeze["report_sha256"])
        self.assertEqual(freeze["status"], "FROZEN_BEFORE_FIRST_PERSISTENT_BPLUS_BYTE")
        self.assertFalse(freeze["persistent_bplus_bytes_written_before_freeze"])
        self.assertFalse(freeze["amendment"]["persistent_bplus_bytes_written_before_amendment"])
        self.assertFalse(freeze["production_bplus_bytes_written"])
        self.assertFalse(freeze["key_bytes_serialized"])
        self.assertEqual(freeze["fullfsync_profile_status"], "NOT_YET_QUALIFIED")
        self.assertEqual(len(freeze["files"]), 7)

        content = load("sitina-bplus-content-manifest-phase1.json")
        entries = {entry["path"]: entry["sha256"] for entry in content["entries"]}
        for item in freeze["files"]:
            relative = Path(item["path"]).relative_to("/Users/moss/SitinaHub").as_posix()
            self.assertEqual(entries[relative], item["sha256"])

    def test_red_green_evidence_and_all_regression_layers_pass(self) -> None:
        red = load("sitina-bplus-phase1-red-tests.json")
        self.assertEqual(canonical_hash(red, "report_sha256"), red["report_sha256"])
        self.assertEqual(red["status"], "EXPECTED_RED_CONFIRMED")
        self.assertTrue(red["production_sentinels_unchanged"])
        expected = {
            "phase1_kernel": (74, 0), "unit_fast": (27, 0),
            "integration_isolated": (154, 1), "crash_fault": (8, 0),
        }
        for suite, (count, skips) in expected.items():
            with self.subTest(suite=suite):
                result = load(f"sitina-bplus-phase1-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{MANIFEST_HASH}")
                self.assertEqual((result["return_code"], result["test_count"], result["skipped_count"]), (0, count, skips))
                self.assertFalse(result["timed_out"])
                self.assertEqual(result["warning_count"], 0)
                self.assertEqual(result["external_attempt_count"], 0)
                self.assertEqual(result["production_attempt_count"], 0)
                self.assertTrue(result["production_sentinel_unchanged"])
                self.assertEqual(result["production_sentinel_after"], V1_SENTINEL)
                self.assertEqual(result["production_mutable_sentinel_after"], MUTABLE_SENTINEL)

    def test_benchmark_is_measured_but_explicitly_unqualified(self) -> None:
        report = load("sitina-bplus-phase1-benchmark.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "MEASURED_NOT_YET_QUALIFIED")
        self.assertEqual(report["qualification_status"], "NOT_YET_QUALIFIED")
        self.assertFalse(report["supported_capacity_claimed"])
        self.assertIn("NOT_YET_QUALIFIED", report["profiles"]["powerloss"])
        self.assertEqual([case["head_position"] for case in report["cases"]], [100, 100])

    def test_content_manifest_chains_phase0_and_excludes_runtime(self) -> None:
        content = load("sitina-bplus-content-manifest-phase1.json")
        self.assertEqual(canonical_hash(content, "manifest_sha256"), content["manifest_sha256"])
        self.assertEqual(content["previous_manifest_hash"], f"sha256:{PHASE0_CONTENT}")
        self.assertEqual(content["root"], "/Users/moss/SitinaHub")
        paths = {entry["path"] for entry in content["entries"]}
        for expected in ("core/sitina/journal/local.py", "core/sitina/cas/local.py", "core/sitina/projections/runner.py", "docs/journal-kernel-operations.md", "tests/test_phase1_kernel_acceptance.py"):
            self.assertIn(expected, paths)
        for path in paths:
            self.assertNotIn(path.split("/", 1)[0], content["excluded_roots"], path)

    def test_post_sentinel_proves_no_production_authority_or_legacy_change(self) -> None:
        post = load("sitina-bplus-production-sentinel-phase1-post.json")
        self.assertEqual(canonical_hash(post, "report_sha256"), post["report_sha256"])
        self.assertEqual(post["v1_report_sha256"], V1_SENTINEL)
        self.assertEqual(post["mutable_report_sha256"], MUTABLE_SENTINEL)
        self.assertTrue(post["authority_material_absent"])
        self.assertTrue(all(item["absent"] for item in post["authority_path_checks"]))
        self.assertFalse(post["production_freeze_executed"])
        self.assertFalse(post["production_legacy_import_executed"])
        self.assertFalse(post["bplus_authority_created"])
        self.assertEqual(post["production_writer"], "legacy")

    def test_acceptance_process_is_disposable(self) -> None:
        home = Path(os.environ["SITINA_HOME"])
        self.assertNotEqual(home, Path("/Users/moss/SitinaHub"))
        self.assertTrue((home / ".sitina-bplus-disposable-v1").is_file())


if __name__ == "__main__":
    unittest.main()
