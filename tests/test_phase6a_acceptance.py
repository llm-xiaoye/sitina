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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


CONTROL = Path((_SITINA_ACCOUNT_HOME + '/Desktop/sitina/output'))
R1_EXECUTION_MANIFEST_HASH = "c97c027174b365d3c3e359763aacf4cc6488eefbcff109aa4169a732c60062b2"
R1A_EXECUTION_MANIFEST_HASH = "99c33e5f6cadfa21d5f1bed8c02e7e1b074166b89e17e297c201d2eb819d3b34"
EXECUTION_MANIFEST_HASH = "cb1f1c529e5cd9dfbf7c05c7bf8e023c6ee3191d06455952062ffed19603add1"
PREVIOUS_CONTENT = "a86e1c4d03f51d2a63762c45eeadfce216e14968b3555e44ba0d11132193de32"
SUPERSEDED_ACCEPTANCE = "22f977c5db492796334f9d2845432f70d84b523faa5f6e30d1571d3132f47acc"
SUPERSEDED_READINESS = "c21e8bf5bff524716507b630db2f7c866945bc030590714556bf499fe15"
BOUNDARY_INCIDENT = "1acecbd8a356ead2b20513b4ca017457c7cf0eb8a6681c6ed17976727acb761a"
V1_SENTINEL = "0866e7f81ba5d886f794ebcdf63eb8b7e985c8a518f328b4e5c38c30265eeab0"
MUTABLE_SENTINEL = "467786e69548a7731c272ff226f8ff1b5c2b19be6d5743a7d78e4c4853019795"


def load(name: str) -> dict[str, Any]:
    value = json.loads((CONTROL / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"control report is not an object: {name}")
    return value


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def canonical_hash(value: dict[str, Any], excluded: str | None = None) -> str:
    body = dict(value)
    if excluded:
        body.pop(excluded)
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


class Phase6AR1BAcceptanceTests(unittest.TestCase):
    def test_superseding_manifest_chain_is_exact_and_still_forbids_production_execution(self) -> None:
        r1 = load("sitina-bplus-phase6a-remediation-execution-manifest-v1.json")
        r1a = load("sitina-bplus-phase6a-runtime-bootstrap-addendum-execution-manifest-v1.json")
        manifest = load("sitina-bplus-phase6a-fixture-stability-addendum-execution-manifest-v1.json")
        self.assertEqual(canonical_hash(r1), R1_EXECUTION_MANIFEST_HASH)
        self.assertEqual(canonical_hash(r1a), R1A_EXECUTION_MANIFEST_HASH)
        self.assertEqual(canonical_hash(manifest), EXECUTION_MANIFEST_HASH)
        self.assertEqual(manifest["authorization"]["authorized_phase"], "6A-R1B")
        self.assertEqual(manifest["authorization"]["required_stop_point"], "CUTOVER_TOOLING_READY_R1B_FIXTURE_ONLY")
        self.assertIn("FREEZE_SNAPSHOT_IMPORT_OR_CUTOVER_PRODUCTION", manifest["prohibited_operations"])
        self.assertIn((_SITINA_ACCOUNT_HOME + '/SitinaHub/tests/test_sitina.py'), manifest["exact_authorized_files"])
        self.assertEqual(manifest["hashes"]["phase6a_r1a_addendum_hash"], f"sha256:{R1A_EXECUTION_MANIFEST_HASH}")
        self.assertEqual(manifest["hashes"]["phase6a_r1_acceptance_hash"], f"sha256:{SUPERSEDED_ACCEPTANCE}")

    def test_red_baseline_recorded_the_real_tooling_gap_without_attempts(self) -> None:
        red = load("sitina-bplus-phase6a-remediation-red-tests.json")
        self.assertEqual(canonical_hash(red, "report_sha256"), red["report_sha256"])
        self.assertEqual(red["status"], "EXPECTED_RED_CONFIRMED")
        self.assertEqual((red["external_attempt_count"], red["production_attempt_count"]), (0, 0))
        self.assertEqual(red["failure_class"], "MISSING_MANIFEST_BOUND_PRODUCTION_CUTOVER_TOOLING")
        self.assertGreater(red["expected_contract_test_count"], 0)

    def test_all_incidents_are_recovered_or_superseded_and_not_hidden(self) -> None:
        wal = load("sitina-bplus-phase6b-readonly-wal-sidecar-incident.json")
        lock = load("sitina-bplus-phase6a-r1-writer-lock-incident.json")
        boundary = load("sitina-bplus-phase6a-r1a-exact-file-boundary-incident.json")
        self.assertEqual(wal["status"], "RECOVERED_SENTINELS_RESTORED")
        self.assertEqual(lock["status"], "RECOVERED_SENTINELS_RESTORED")
        self.assertEqual(canonical_hash(lock, "report_sha256"), lock["report_sha256"])
        self.assertEqual(canonical_hash(boundary, "report_sha256"), BOUNDARY_INCIDENT)
        self.assertEqual(boundary["report_sha256"], BOUNDARY_INCIDENT)
        self.assertEqual(boundary["recovery_execution_manifest"]["sha256"], f"sha256:{EXECUTION_MANIFEST_HASH}")
        self.assertFalse(boundary["production_business_data_changed"] or boundary["production_authority_material_created"])
        self.assertTrue(lock["unaffected_business_data"])
        self.assertFalse(lock["database_opened"] or lock["authority_material_created"])
        self.assertEqual(lock["production_v1_sentinel_after_recovery"], V1_SENTINEL)
        self.assertEqual(lock["production_mutable_sentinel_after_recovery"], MUTABLE_SENTINEL)

    def test_production_tooling_e2e_and_compatibility_are_passed(self) -> None:
        e2e = load("sitina-bplus-phase6a-remediation-e2e-evidence.json")
        compatibility = load("sitina-bplus-phase6a-remediation-compatibility.json")
        self.assertEqual(canonical_hash(e2e, "report_sha256"), e2e["report_sha256"])
        self.assertEqual(canonical_hash(compatibility, "report_sha256"), compatibility["report_sha256"])
        self.assertEqual((e2e["status"], compatibility["status"]), ("PASSED", "PASSED"))
        self.assertTrue(all(e2e["predicates"].values()))
        self.assertEqual(e2e["operator_cli_cutover_verified_count"], 1)
        self.assertEqual(e2e["durable_post_window_authority_state"], "JOURNAL_WRITER_AUTHORIZED")
        self.assertEqual(compatibility["reader_generations"], ["bplus-journal-v1", "legacy-frozen-snapshot-v1"])
        self.assertEqual(compatibility["blocking_difference_count"], 0)
        self.assertFalse(compatibility["live_legacy_sqlite_opened"])

    def test_r1b_readiness_is_signed_evidence_and_not_authority(self) -> None:
        report = load("sitina-bplus-cutover-tooling-ready-r1b.json")
        self.assertEqual(canonical_hash(report, "readiness_sha256"), report["readiness_sha256"])
        signed = {
            key: value for key, value in report.items()
            if key not in {"public_key_hex", "signature_hex", "signed_body_sha256", "readiness_sha256"}
        }
        self.assertEqual(hashlib.sha256(canonical_bytes(signed)).hexdigest(), report["signed_body_sha256"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(report["public_key_hex"])).verify(
            bytes.fromhex(report["signature_hex"]), canonical_bytes(signed)
        )
        self.assertEqual(report["status"], "CUTOVER_TOOLING_READY")
        self.assertTrue(all(report["predicates"].values()))
        self.assertFalse(
            report["authority"] or report["maintenance_authorized"]
            or report["cutover_authorized"] or report["execute_capability_present"]
        )
        self.assertEqual(report["production_writer"], "legacy")
        self.assertEqual(report["supersedes_acceptance_sha256"], f"sha256:{SUPERSEDED_ACCEPTANCE}")
        self.assertEqual(report["supersedes_readiness_sha256"], f"sha256:{SUPERSEDED_READINESS}")

    def test_r1b_and_cross_phase_regression_layers_pass(self) -> None:
        expected = {
            "phase6a_production_tooling": (12, 0),
            "phase6a_runtime": (38, 0),
            "unit_fast": (27, 0),
            "integration_isolated": (154, 1),
            "crash_fault": (8, 0),
        }
        for suite, (count, skips) in expected.items():
            with self.subTest(suite=suite):
                result = load(f"sitina-bplus-phase6a-r1b-test-results/{suite}.json")
                self.assertEqual(result["execution_manifest_hash"], f"sha256:{EXECUTION_MANIFEST_HASH}")
                self.assertEqual((result["return_code"], result["test_count"], result["skipped_count"]), (0, count, skips))
                self.assertFalse(result["timed_out"])
                self.assertEqual((result["warning_count"], result["external_attempt_count"], result["production_attempt_count"]), (0, 0, 0))
                self.assertTrue(result["production_sentinel_unchanged"])

    def test_content_manifest_chains_r1_and_covers_runtime_and_fixture(self) -> None:
        content = load("sitina-bplus-content-manifest-phase6a-r1b.json")
        self.assertEqual(canonical_hash(content, "manifest_sha256"), content["manifest_sha256"])
        self.assertEqual(content["previous_manifest_hash"], f"sha256:{PREVIOUS_CONTENT}")
        paths = {entry["path"] for entry in content["entries"]}
        for expected in (
            "core/sitina/operations/phase6b.py",
            "core/sitina/security/macos_keychain.py",
            "core/sitina/legacy/coverage.py",
            "core/sitina/orchestrator/bplus_production.py",
            "core/sitina/storage/store.py",
            "bin/sitina",
            "core/sitina/__init__.py",
            "scripts/cutover-phase6b.py",
            "docs/phase6b-production-operations.md",
            "tests/test_sitina.py",
            "tests/test_phase6a_production_tooling.py",
            "tests/test_phase6a_acceptance.py",
        ):
            self.assertIn(expected, paths)

    def test_post_sentinel_proves_r1b_never_executed_against_production(self) -> None:
        post = load("sitina-bplus-production-sentinel-phase6a-r1b-post.json")
        self.assertEqual(canonical_hash(post, "report_sha256"), post["report_sha256"])
        self.assertEqual((post["v1_report_sha256"], post["mutable_report_sha256"]), (V1_SENTINEL, MUTABLE_SENTINEL))
        self.assertTrue(post["authority_material_absent"] and all(item["absent"] for item in post["authority_path_checks"]))
        self.assertEqual(
            (post["production_freeze_count"], post["production_import_count"], post["production_cutover_submission_count"], post["destructive_execution_count"]),
            (0, 0, 0, 0),
        )
        self.assertEqual(post["production_writer"], "legacy")
        self.assertNotEqual(Path(os.environ["SITINA_HOME"]), Path((_SITINA_ACCOUNT_HOME + '/SitinaHub')))


if __name__ == "__main__":
    unittest.main()
