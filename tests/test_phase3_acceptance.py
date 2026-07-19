from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path("/Users/moss/Desktop/sitina/output")
MANIFEST_HASH = "b4cfed0f4556a0e10f71a76f742236344cdc06acc31eb67a608dbd06f5d52563"
PHASE2_ACCEPTANCE = "1318f86b3ec8b6a835a0bf97b2d9688b0a454b8f48dfff73581cd8b3587bdced"
PHASE2_CONTENT = "3fdd93903918c36586e6b0620608a8bfb36a25a13e225a4a84f5b5607a4889fa"
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
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class Phase3AcceptanceTests(unittest.TestCase):
    def test_manifest_promotes_phase2_and_remains_non_cutover(self) -> None:
        manifest = load("sitina-bplus-phase3-execution-manifest-v1.json")
        self.assertEqual(canonical_hash(manifest), MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "3")
        self.assertEqual(manifest["authorization"]["authorized_task_range"], "1..12")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "PHASE3_ACCEPTANCE")
        self.assertIn("AUTHORITY_CUTOVER", manifest["prohibited_operations"])
        self.assertIn("WRITE_LEGACY_BLACKBOARD_HANDOFF_LEASE_OR_PROPOSAL_FILES_FROM_SHADOW", manifest["prohibited_operations"])
        previous = load("sitina-bplus-phase2-acceptance.json")
        self.assertEqual(previous["status"], "PASSED")
        self.assertEqual(previous["acceptance_sha256"], PHASE2_ACCEPTANCE)
        self.assertTrue(all(previous["predicates"].values()))

    def test_integrated_collaboration_crash_replay_and_rebuild_pass(self) -> None:
        red = load("sitina-bplus-phase3-red-tests.json")
        self.assertEqual(canonical_hash(red, "report_sha256"), red["report_sha256"])
        self.assertEqual(red["status"], "EXPECTED_RED_CONFIRMED")
        report = load("sitina-bplus-phase3-e2e-evidence.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["runtime_suite"]["test_count"], 42)
        self.assertTrue(all(report["lifecycle"].values()))
        self.assertTrue(all(report["recovery_boundaries"].values()))
        self.assertTrue(report["registry_rebuild"]["semantic_equal"])
        self.assertEqual(report["external_attempt_count"], 0)
        self.assertEqual(report["production_attempt_count"], 0)

    def test_legacy_protocol_views_are_classified_and_read_only(self) -> None:
        report = load("sitina-bplus-phase3-compatibility.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["blocking_difference_count"], 0)
        self.assertTrue(report["normalized_legacy_semantic_equal"])
        self.assertEqual(report["legacy_mutable_file_write_count"], 0)
        self.assertFalse(report["authority"])
        self.assertTrue(all(item["classification"] != "UNCLASSIFIED" for item in report["differences"]))

    def test_phase3_and_legacy_regression_layers_pass(self) -> None:
        expected = {
            "phase3_runtime": (42, 0),
            "unit_fast": (27, 0),
            "integration_isolated": (154, 1),
            "crash_fault": (8, 0),
        }
        for suite, (count, skips) in expected.items():
            with self.subTest(suite=suite):
                result = load(f"sitina-bplus-phase3-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{MANIFEST_HASH}")
                self.assertEqual((result["return_code"], result["test_count"], result["skipped_count"]), (0, count, skips))
                self.assertFalse(result["timed_out"])
                self.assertEqual(result["warning_count"], 0)
                self.assertEqual(result["external_attempt_count"], 0)
                self.assertEqual(result["production_attempt_count"], 0)
                self.assertTrue(result["production_sentinel_unchanged"])
                self.assertEqual(result["production_sentinel_after"], V1_SENTINEL)
                self.assertEqual(result["production_mutable_sentinel_after"], MUTABLE_SENTINEL)

    def test_content_manifest_chains_phase2_and_excludes_runtime_data(self) -> None:
        content = load("sitina-bplus-content-manifest-phase3.json")
        self.assertEqual(canonical_hash(content, "manifest_sha256"), content["manifest_sha256"])
        self.assertEqual(content["previous_manifest_hash"], f"sha256:{PHASE2_CONTENT}")
        paths = {entry["path"] for entry in content["entries"]}
        for expected in (
            "core/sitina/protocols/obligations.py",
            "core/sitina/protocols/proposals.py",
            "core/sitina/protocols/handoffs.py",
            "core/sitina/protocols/blackboard.py",
            "core/sitina/protocols/coordinator.py",
            "docs/bplus-collaboration-protocols.md",
            "tests/test_phase3_acceptance.py",
        ):
            self.assertIn(expected, paths)
        for path in paths:
            self.assertNotIn(path.split("/", 1)[0], content["excluded_roots"], path)

    def test_post_sentinel_proves_no_production_protocol_or_authority_material(self) -> None:
        post = load("sitina-bplus-production-sentinel-phase3-post.json")
        self.assertEqual(canonical_hash(post, "report_sha256"), post["report_sha256"])
        self.assertEqual(post["v1_report_sha256"], V1_SENTINEL)
        self.assertEqual(post["mutable_report_sha256"], MUTABLE_SENTINEL)
        self.assertTrue(post["authority_material_absent"])
        self.assertTrue(all(item["absent"] for item in post["authority_path_checks"]))
        self.assertEqual(post["legacy_mutable_file_write_count"], 0)
        self.assertFalse(post["bplus_authority_created"])
        self.assertEqual(post["production_writer"], "legacy")

    def test_acceptance_process_is_disposable(self) -> None:
        home = Path(os.environ["SITINA_HOME"])
        self.assertNotEqual(home, Path("/Users/moss/SitinaHub"))
        self.assertTrue((home / ".sitina-bplus-disposable-v1").is_file())


if __name__ == "__main__":
    unittest.main()
