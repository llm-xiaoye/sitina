from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from typing import Any


CONTROL = Path("/Users/moss/Desktop/sitina/output")
MANIFEST_HASH = "151ac665bfc3f99d12d2b3f8e5a30c3e2ec443a74638f42173af8c86b1647d32"
PHASE4_ACCEPTANCE = "4c4091cbc99dfa9227040de6a55d89a96a289907431fb3bbfa736fb21899edd8"
PHASE4_CONTENT = "2b4e54a05dc0bf98913b56e9cffe3f42971a46cf7d9e0f13c7a6045a312d4367"
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


class Phase5AcceptanceTests(unittest.TestCase):
    def test_manifest_promotes_phase4_and_stops_at_shadow_controlled(self) -> None:
        manifest = load("sitina-bplus-phase5-execution-manifest-v1.json")
        self.assertEqual(canonical_hash(manifest), MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "5")
        self.assertEqual(manifest["authorization"]["authorized_task_range"], "0..16")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "PHASE5_ACCEPTANCE_SHADOW_CONTROLLED")
        self.assertIn("PRODUCTION_DELETE_HOT_EVICTION_CRYPTO_ERASURE_OR_RETENTION_EXECUTION", manifest["prohibited_operations"])
        previous = load("sitina-bplus-phase4-acceptance.json")
        self.assertEqual((previous["status"], previous["acceptance_sha256"]), ("PASSED", PHASE4_ACCEPTANCE))

    def test_red_baseline_precedes_phase5_packages(self) -> None:
        red = load("sitina-bplus-phase5-red-tests.json")
        self.assertEqual(canonical_hash(red, "report_sha256"), red["report_sha256"])
        self.assertEqual(red["status"], "EXPECTED_RED_CONFIRMED")
        self.assertEqual(red["failure_class"], "MISSING_PHASE5_EVIDENCE_ARCHIVE_PACKAGES")
        self.assertEqual((red["failed_selector_count"], red["external_attempt_count"], red["production_attempt_count"]), (16, 0, 0))

    def test_e2e_package_seal_archive_replay_backup_restore_and_gc_pass(self) -> None:
        report = load("sitina-bplus-phase5-e2e-evidence.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual((report["assessment_status"], report["archive_job_state"], report["archive_copy_assessment"]), ("PASSED", "COMPLETED", "VERIFIED"))
        self.assertTrue(report["seal_signature_verified"])
        self.assertTrue(report["fresh_staging_and_final_verifications"])
        self.assertEqual(report["replay_positions"], [1, 2, 3])
        self.assertFalse(report["replay_generated_assessment"])
        self.assertEqual((report["barrier_kinds_tested"], report["barrier_kinds_blocked"]), (18, 18))
        self.assertEqual((report["opt_v1_invalid_cardinalities_rejected"], report["opt_v1_component_count"]), (2, 1))
        self.assertEqual(report["retention_lost_ack_state"], "RECONCILING")
        self.assertFalse(report["retention_destructive_capability_present"])
        self.assertFalse(report["retention_physical_delete_executed"])
        self.assertTrue(report["backup_restore_verified"] and report["dr_restore_verified"])
        self.assertFalse(report["dr_writer_activated"] or report["gc_delete_authorized"] or report["gc_physical_delete_executed"])

    def test_replay_capability_is_honestly_application_guarded(self) -> None:
        report = load("sitina-bplus-phase5-replay-isolation-capability.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["active_capability"], "APPLICATION_GUARDED_ZERO_EFFECT")
        self.assertFalse(report["kernel_enforced"] or report["enforced_sandbox_claimed"] or report["sandbox_exec_currently_qualified"])
        self.assertTrue(all(item["denied"] for item in report["adversarial_results"].values()))

    def test_legacy_bundle_is_compatible_but_never_bplus_labeled(self) -> None:
        report = load("sitina-bplus-phase5-compatibility.json")
        self.assertEqual(canonical_hash(report, "report_sha256"), report["report_sha256"])
        self.assertEqual(report["status"], "PASSED")
        self.assertTrue(report["normalized_legacy_semantic_equal"])
        self.assertEqual(report["blocking_difference_count"], 0)
        claims = report["legacy_evidence_claims"]
        self.assertEqual(claims["classification"], "artifact_integrity_verified_compatibility_export")
        self.assertFalse(claims["bplus_opt_compliant"] or claims["bplus_sealed"])

    def test_phase5_and_cross_phase_regression_layers_pass(self) -> None:
        expected = {"phase5_runtime": (62, 0), "unit_fast": (27, 0), "integration_isolated": (154, 1), "crash_fault": (8, 0)}
        for suite, (count, skips) in expected.items():
            with self.subTest(suite=suite):
                result = load(f"sitina-bplus-phase5-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{MANIFEST_HASH}")
                self.assertEqual((result["return_code"], result["test_count"], result["skipped_count"]), (0, count, skips))
                self.assertFalse(result["timed_out"])
                self.assertEqual((result["warning_count"], result["external_attempt_count"], result["production_attempt_count"]), (0, 0, 0))
                self.assertTrue(result["production_sentinel_unchanged"])
                self.assertEqual((result["production_sentinel_after"], result["production_mutable_sentinel_after"]), (V1_SENTINEL, MUTABLE_SENTINEL))

    def test_content_manifest_chains_phase4_and_covers_phase5(self) -> None:
        content = load("sitina-bplus-content-manifest-phase5.json")
        self.assertEqual(canonical_hash(content, "manifest_sha256"), content["manifest_sha256"])
        self.assertEqual(content["previous_manifest_hash"], f"sha256:{PHASE4_CONTENT}")
        paths = {entry["path"] for entry in content["entries"]}
        for expected in (
            "config/evidence_policy.bplus_v1.json", "core/sitina/evidence/package.py",
            "core/sitina/evidence/seal.py", "core/sitina/archive/retention_operations.py",
            "core/sitina/archive/backup.py", "core/sitina/cas/gc.py",
            "docs/bplus-evidence-archive-operations.md", "tests/test_phase5_acceptance.py",
        ):
            self.assertIn(expected, paths)
        for path in paths:
            self.assertNotIn(path.split("/", 1)[0], content["excluded_roots"], path)

    def test_post_sentinel_proves_no_production_authority_or_destructive_action(self) -> None:
        post = load("sitina-bplus-production-sentinel-phase5-post.json")
        self.assertEqual(canonical_hash(post, "report_sha256"), post["report_sha256"])
        self.assertEqual((post["v1_report_sha256"], post["mutable_report_sha256"]), (V1_SENTINEL, MUTABLE_SENTINEL))
        self.assertTrue(post["authority_material_absent"])
        self.assertTrue(all(item["absent"] for item in post["authority_path_checks"]))
        self.assertEqual((post["production_evidence_seal_count"], post["production_archive_transfer_count"], post["destructive_retention_execution_count"]), (0, 0, 0))
        self.assertEqual(post["production_writer"], "legacy")
        self.assertNotEqual(Path(os.environ["SITINA_HOME"]), Path("/Users/moss/SitinaHub"))


if __name__ == "__main__":
    unittest.main()
