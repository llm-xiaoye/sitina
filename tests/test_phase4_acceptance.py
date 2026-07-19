from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path("/Users/moss/Desktop/sitina/output")
MANIFEST_HASH = "bcb0849c9730b2dec990ff77c245a7abcc97b1f61645413952d47bc282cc8aa1"
PHASE3_ACCEPTANCE = "9db0721ad687d4c0aba2bcbd0f9e1ee994a02219d3825919bd45133c3a723912"
PHASE3_CONTENT = "b544cda1b3059218dcf95c71525548f00299df1688e6a9f731801e679ea3d5b1"
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


class Phase4AcceptanceTests(unittest.TestCase):
    def test_manifest_promotes_phase3_and_remains_mock_only(self) -> None:
        manifest = load("sitina-bplus-phase4-execution-manifest-v1.json")
        self.assertEqual(canonical_hash(manifest), MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "4")
        self.assertEqual(manifest["authorization"]["authorized_task_range"], "1..16")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "PHASE4_ACCEPTANCE_MOCK_ONLY")
        self.assertIn("DISPATCH_LIVE_PROVIDER_TOOL_MCP_MESSAGE_PUBLICATION_DELETE_PUSH_PAYMENT_OR_MUTATION", manifest["prohibited_operations"])
        previous = load("sitina-bplus-phase3-acceptance.json")
        self.assertEqual(previous["status"], "PASSED")
        self.assertEqual(previous["acceptance_sha256"], PHASE3_ACCEPTANCE)

    def test_red_baseline_precedes_implementation_and_touched_no_external_or_production_path(self) -> None:
        red = load("sitina-bplus-phase4-red-tests.json")
        self.assertEqual(canonical_hash(red, "report_sha256"), red["report_sha256"])
        self.assertEqual(red["status"], "EXPECTED_RED_CONFIRMED")
        self.assertEqual(red["failure_class"], "MISSING_PHASE4_EFFECT_PACKAGE")
        self.assertEqual(red["failed_selector_count"], 16)
        self.assertEqual((red["external_attempt_count"], red["production_attempt_count"]), (0, 0))

    def test_integrated_lost_ack_journal_restart_and_projection_rebuild_pass(self) -> None:
        report = load("sitina-bplus-phase4-e2e-evidence.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["runtime_suite"]["test_count"], 65)
        self.assertTrue(all(report["transmission_windows"].values()))
        self.assertTrue(all(report["recovery_levels"].values()))
        self.assertTrue(all(report["durability_and_rebuild"].values()))
        self.assertEqual(report["mock_remote"]["duplicate_remote_execution_count"], 0)
        self.assertEqual(report["mock_remote"]["live_external_effect_count"], 0)

    def test_legacy_default_semantics_are_exact_and_shadow_is_non_authoritative(self) -> None:
        report = load("sitina-bplus-phase4-compatibility.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["blocking_difference_count"], 0)
        self.assertTrue(report["normalized_legacy_semantic_equal"])
        self.assertEqual(report["legacy_mutable_file_write_count"], 0)
        self.assertFalse(report["shadow_authority"])
        self.assertTrue(all(item["classification"] != "UNCLASSIFIED" for item in report["differences"]))

    def test_phase4_and_cross_phase_regression_layers_pass(self) -> None:
        expected = {
            "phase4_runtime": (65, 0),
            "unit_fast": (27, 0),
            "integration_isolated": (154, 1),
            "crash_fault": (8, 0),
        }
        for suite, (count, skips) in expected.items():
            with self.subTest(suite=suite):
                result = load(f"sitina-bplus-phase4-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{MANIFEST_HASH}")
                self.assertEqual((result["return_code"], result["test_count"], result["skipped_count"]), (0, count, skips))
                self.assertFalse(result["timed_out"])
                self.assertEqual(result["warning_count"], 0)
                self.assertEqual((result["external_attempt_count"], result["production_attempt_count"]), (0, 0))
                self.assertTrue(result["production_sentinel_unchanged"])
                self.assertEqual(result["production_sentinel_after"], V1_SENTINEL)
                self.assertEqual(result["production_mutable_sentinel_after"], MUTABLE_SENTINEL)

    def test_activation_readiness_stops_at_mock_only(self) -> None:
        report = load("sitina-bplus-phase4-activation-readiness.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED_MOCK_ONLY")
        self.assertEqual(report["active_level"], "MOCK_ONLY")
        self.assertTrue(report["matrix"]["MOCK_ONLY"]["authorized"])
        for level in ("EXTERNAL_READ", "REVERSIBLE_MUTATION", "HIGH_RISK_OR_IRREVERSIBLE"):
            self.assertFalse(report["matrix"][level]["authorized"])
        self.assertEqual(report["live_external_effect_count"], 0)

    def test_content_manifest_chains_phase3_and_covers_effect_gateway(self) -> None:
        content = load("sitina-bplus-content-manifest-phase4.json")
        self.assertEqual(canonical_hash(content, "manifest_sha256"), content["manifest_sha256"])
        self.assertEqual(content["previous_manifest_hash"], f"sha256:{PHASE3_CONTENT}")
        paths = {entry["path"] for entry in content["entries"]}
        for expected in (
            "core/sitina/effects/model.py",
            "core/sitina/effects/gateway.py",
            "core/sitina/effects/observations.py",
            "core/sitina/effects/ingress_spool.py",
            "core/sitina/effects/results.py",
            "core/sitina/security/secret_provider.py",
            "config/effect_adapters.mock.json",
            "docs/bplus-effect-gateway-operations.md",
            "tests/test_phase4_acceptance.py",
        ):
            self.assertIn(expected, paths)
        for path in paths:
            self.assertNotIn(path.split("/", 1)[0], content["excluded_roots"], path)

    def test_post_sentinel_proves_no_production_effect_or_authority_material(self) -> None:
        post = load("sitina-bplus-production-sentinel-phase4-post.json")
        self.assertEqual(canonical_hash(post, "report_sha256"), post["report_sha256"])
        self.assertEqual(post["v1_report_sha256"], V1_SENTINEL)
        self.assertEqual(post["mutable_report_sha256"], MUTABLE_SENTINEL)
        self.assertTrue(post["authority_material_absent"])
        self.assertTrue(all(item["absent"] for item in post["authority_path_checks"]))
        self.assertEqual(post["legacy_mutable_file_write_count"], 0)
        self.assertEqual(post["live_external_effect_count"], 0)
        self.assertEqual(post["production_writer"], "legacy")
        self.assertNotEqual(Path(os.environ["SITINA_HOME"]), Path("/Users/moss/SitinaHub"))


if __name__ == "__main__":
    unittest.main()
