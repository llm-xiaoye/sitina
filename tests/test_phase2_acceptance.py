from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path("/Users/moss/Desktop/sitina/output")
MANIFEST_HASH = "32616d4580f7566f13b91b2d3cfec8a99e34f3091abf98626db95de7365270dd"
PHASE1_ACCEPTANCE = "32d630a3023f3cd43adab0c16f2af4f459e08da6f3057d4ca08b54161989ae42"
PHASE1_CONTENT = "2a8ad1fbd4e43aadad94a30ff440c2ce7da631baccb96ecf94ba74953a834987"
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


class Phase2AcceptanceTests(unittest.TestCase):
    def test_manifest_promotes_phase1_without_cutover_authority(self) -> None:
        manifest = load("sitina-bplus-phase2-execution-manifest-v1.json")
        self.assertEqual(canonical_hash(manifest), MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "2")
        self.assertEqual(manifest["authorization"]["authorized_task_range"], "1..12")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "PHASE2_ACCEPTANCE")
        self.assertIn("AUTHORITY_CUTOVER", manifest["prohibited_operations"])
        self.assertIn(
            "DISPATCH_REAL_PROVIDER_TOOL_MCP_OR_WORKER",
            {operation.replace(" ", "_") for operation in manifest["prohibited_operations"]},
        )
        previous = load("sitina-bplus-phase1-acceptance.json")
        self.assertEqual(previous["status"], "PASSED")
        self.assertEqual(previous["acceptance_sha256"], PHASE1_ACCEPTANCE)
        self.assertTrue(all(previous["predicates"].values()))

    def test_integrated_lifecycle_and_recovery_evidence_pass(self) -> None:
        report = load("sitina-bplus-phase2-e2e-evidence.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["execution_manifest_hash"], f"sha256:{MANIFEST_HASH}")
        self.assertEqual(report["runtime_suite"]["test_count"], 56)
        self.assertEqual(report["lifecycle"]["terminal_state"], "SUCCEEDED")
        self.assertTrue(all(report["recovery_checkpoints"].values()))
        self.assertTrue(report["projection_rebuild"]["semantic_equal"])
        self.assertFalse(report["projection_rebuild"]["sqlite_authority"])
        self.assertEqual(report["external_attempt_count"], 0)
        self.assertEqual(report["production_attempt_count"], 0)

    def test_legacy_default_and_shadow_compatibility_are_non_authoritative(self) -> None:
        report = load("sitina-bplus-phase2-compatibility.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["baseline"]["semantic_hash"], "9e002427a2c9e917fec188458a6a948726c06e359a09e52ccb5909d779772f24")
        self.assertEqual(report["blocking_difference_count"], 0)
        self.assertTrue(report["default_off"]["legacy_output_shape_unchanged"])
        self.assertTrue(report["shadow_enabled_fixture"]["hash_only"])
        self.assertFalse(report["shadow_enabled_fixture"]["authority"])
        self.assertEqual(report["shadow_enabled_fixture"]["external_calls"], 0)
        self.assertTrue(report["production_home_rejected"])
        self.assertEqual(report["authority"]["production_writer"], "legacy")

    def test_all_phase2_and_phase_minus1_regression_layers_pass(self) -> None:
        expected = {
            "phase2_runtime": (56, 0),
            "unit_fast": (27, 0),
            "integration_isolated": (154, 1),
            "crash_fault": (8, 0),
        }
        for suite, (count, skips) in expected.items():
            with self.subTest(suite=suite):
                result = load(f"sitina-bplus-phase2-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{MANIFEST_HASH}")
                self.assertEqual(
                    (result["return_code"], result["test_count"], result["skipped_count"]),
                    (0, count, skips),
                )
                self.assertFalse(result["timed_out"])
                self.assertEqual(result["warning_count"], 0)
                self.assertEqual(result["external_attempt_count"], 0)
                self.assertEqual(result["production_attempt_count"], 0)
                self.assertTrue(result["production_sentinel_unchanged"])
                self.assertEqual(result["production_sentinel_after"], V1_SENTINEL)
                self.assertEqual(result["production_mutable_sentinel_after"], MUTABLE_SENTINEL)

    def test_content_manifest_chains_phase1_and_excludes_runtime_data(self) -> None:
        content = load("sitina-bplus-content-manifest-phase2.json")
        self.assertEqual(canonical_hash(content, "manifest_sha256"), content["manifest_sha256"])
        self.assertEqual(content["previous_manifest_hash"], f"sha256:{PHASE1_CONTENT}")
        self.assertEqual(content["root"], "/Users/moss/SitinaHub")
        paths = {entry["path"] for entry in content["entries"]}
        for expected in (
            "core/sitina/protocols/run.py",
            "core/sitina/protocols/tasks.py",
            "core/sitina/scheduling/dispatcher.py",
            "core/sitina/orchestrator/bplus_adapter.py",
            "docs/bplus-run-task-operations.md",
            "tests/test_phase2_acceptance.py",
        ):
            self.assertIn(expected, paths)
        for path in paths:
            self.assertNotIn(path.split("/", 1)[0], content["excluded_roots"], path)

    def test_post_sentinel_proves_legacy_is_still_sole_production_writer(self) -> None:
        incident = load("sitina-bplus-phase2-production-lock-incident.json")
        self.assertEqual(canonical_hash(incident, "report_sha256"), incident["report_sha256"])
        self.assertEqual(incident["status"], "EXACTLY_RECOVERED")
        self.assertEqual(incident["open_integrity_incident_count"], 0)
        self.assertFalse(incident["impact"]["existing_production_file_changed"])
        self.assertFalse(incident["impact"]["existing_production_file_deleted"])
        self.assertTrue(incident["recovery_evidence"]["sentinels_restored_exactly"])
        post = load("sitina-bplus-production-sentinel-phase2-post.json")
        self.assertEqual(canonical_hash(post, "report_sha256"), post["report_sha256"])
        self.assertEqual(post["v1_report_sha256"], V1_SENTINEL)
        self.assertEqual(post["mutable_report_sha256"], MUTABLE_SENTINEL)
        self.assertTrue(post["authority_material_absent"])
        self.assertTrue(all(item["absent"] for item in post["authority_path_checks"]))
        self.assertFalse(post["production_freeze_executed"])
        self.assertFalse(post["production_legacy_import_executed"])
        self.assertFalse(post["bplus_authority_created"])
        self.assertFalse(post["real_provider_tool_mcp_or_worker_dispatched"])
        self.assertEqual(post["production_writer"], "legacy")

    def test_acceptance_process_is_disposable(self) -> None:
        home = Path(os.environ["SITINA_HOME"])
        self.assertNotEqual(home, Path("/Users/moss/SitinaHub"))
        self.assertTrue((home / ".sitina-bplus-disposable-v1").is_file())


if __name__ == "__main__":
    unittest.main()
