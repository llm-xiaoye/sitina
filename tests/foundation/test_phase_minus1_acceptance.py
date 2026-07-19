from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path

from sitina.runtime.execution_contract import BootstrapFoundationRecord, ExecutionManifestV1


ROOT = Path(__file__).resolve().parents[2]
CONTROL = Path("/Users/moss/Desktop/sitina/output")
FOUNDATION = CONTROL / "sitina-bplus-bootstrap-foundation-record.json"
MANIFEST = CONTROL / "sitina-bplus-execution-manifest-v1-phase-minus1.json"
INITIAL_SENTINEL = CONTROL / "sitina-bplus-production-sentinel-initial.json"
MUTABLE_SENTINEL = CONTROL / "sitina-bplus-production-mutable-sentinel-phase-minus1-baseline.json"
CONTENT_MANIFEST = CONTROL / "sitina-bplus-content-manifest-phase-minus1-final.json"
INITIAL_BASELINE = CONTROL / "sitina-bplus-legacy-behavior-baseline.json"
FINAL_BASELINE = CONTROL / "sitina-bplus-legacy-behavior-baseline-phase-minus1-final.json"
FINAL_INVENTORY = CONTROL / "sitina-bplus-write-sink-inventory-phase-minus1-final.json"
INCIDENT = CONTROL / "sitina-bplus-phase-minus1-production-test-write-incident.json"
SUITE_RESULTS = CONTROL / "sitina-bplus-phase-minus1-test-results"
APPROVED_PYTHON = Path(
    "/Users/moss/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
)


def _load(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object: {path}")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha256_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@unittest.skipUnless(
    os.environ.get("SITINA_BPLUS_TEST_LAYER") == "legacy_readonly_observation",
    "historical Phase -1 acceptance is evaluated only by its manifest-bound suite",
)
class PhaseMinus1AcceptanceTests(unittest.TestCase):
    def test_manifest_promotion_and_pinned_profile(self) -> None:
        foundation = BootstrapFoundationRecord.from_mapping(_load(FOUNDATION))
        manifest = ExecutionManifestV1.from_mapping(_load(MANIFEST))
        manifest.assert_promotion_from(foundation)
        self.assertEqual(manifest.authorized_phase, "-1")
        self.assertEqual(manifest.authorized_task_range, "1..9")
        self.assertEqual(manifest.manifest_hash, "sha256:cc8329f17c5fceffc8dd00ff760508a3e4441fd78b710d60506e09161641f574")
        self.assertEqual(Path(sys.executable).resolve(strict=True), APPROVED_PYTHON.resolve(strict=True))
        self.assertEqual(
            "sha256:" + _sha256_file(ROOT / "requirements-bplus.lock"),
            foundation.dependency_lock_hash,
        )

    def test_source_only_manifest_is_current_and_excludes_runtime(self) -> None:
        manifest = _load(CONTENT_MANIFEST)
        self.assertEqual(manifest["schema"], "CONTENT_MANIFEST_V1")
        self.assertEqual(
            manifest["previous_manifest_hash"],
            "4e8f8fb8039e50a026fdf2af0c4dee71d3b41086ce61e4c8af0b385cf15709df",
        )
        core = dict(manifest)
        declared = core.pop("manifest_sha256")
        self.assertEqual(declared, hashlib.sha256(_canonical(core)).hexdigest())
        runtime_roots = {"data", "logs", "state", "artifacts", "outputs", "memory", "backups", "temp"}
        paths = {entry["path"] for entry in manifest["entries"]}
        self.assertIn("tests/foundation/test_phase_minus1_acceptance.py", paths)
        self.assertIn("docs/bplus-phase-minus1-acceptance.md", paths)
        for entry in manifest["entries"]:
            relative = Path(entry["path"])
            self.assertNotIn(relative.parts[0], runtime_roots)
            path = ROOT / relative
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode), entry)
            self.assertFalse(path.is_symlink(), entry)
            self.assertEqual(entry["size"], metadata.st_size, entry)
            self.assertEqual(entry["mode"], oct(metadata.st_mode & 0o7777), entry)
            self.assertEqual(entry["sha256"], _sha256_file(path), entry)

    def test_default_suites_pass_with_zero_external_or_production_access(self) -> None:
        expected_counts = {"unit_fast": 27, "integration_isolated": 154, "crash_fault": 8}
        initial = _load(INITIAL_SENTINEL)
        mutable = _load(MUTABLE_SENTINEL)
        self.assertEqual(mutable["base_v1_report_sha256"], initial["report_sha256"])
        for suite, minimum_count in expected_counts.items():
            result = _load(SUITE_RESULTS / f"{suite}.json")
            self.assertEqual(result["return_code"], 0, result)
            self.assertGreaterEqual(result["test_count"], minimum_count, result)
            self.assertEqual(result["external_attempt_count"], 0, result)
            self.assertEqual(result["production_attempt_count"], 0, result)
            self.assertEqual(result["warning_count"], 0, result)
            self.assertTrue(result["production_sentinel_unchanged"], result)
            self.assertEqual(result["production_sentinel_before"], initial["report_sha256"])
            self.assertEqual(result["production_mutable_sentinel_before"], mutable["report_sha256"])
            self.assertEqual(result["production_mutable_sentinel_after"], mutable["report_sha256"])
            self.assertEqual(result["production_guard_profile"], "APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1")
            child = Path(result["child_cwd"]).resolve(strict=False)
            self.assertNotEqual(child, Path("/Users/moss/SitinaHub"))
            self.assertTrue(str(child).startswith("/Users/moss/Desktop/sitina/bplus-test-homes/"))

    def test_legacy_baseline_reproducible_with_semantics_preserved(self) -> None:
        initial = _load(INITIAL_BASELINE)
        final = _load(FINAL_BASELINE)
        result = _load(SUITE_RESULTS / "legacy-behavior-baseline-record.json")
        self.assertEqual(result["return_code"], 0, result)
        self.assertEqual(result["mode"], "record_legacy_baseline")
        self.assertEqual(result["external_attempt_count"], 0)
        self.assertEqual(result["production_attempt_count"], 0)
        self.assertEqual(result["warning_count"], 0)
        self.assertTrue(result["production_sentinel_unchanged"])
        self.assertEqual(initial["semantic"], final["semantic"])
        self.assertEqual(initial["normalization_profile"], final["normalization_profile"])
        for name in ("fixture_hash", "config_policy_hash", "python_profile_hash"):
            self.assertEqual(initial["bindings"][name], final["bindings"][name], name)
        self.assertNotEqual(initial["bindings"]["source_manifest_hash"], final["bindings"]["source_manifest_hash"])
        final_core = dict(final)
        declared = final_core.pop("semantic_hash")
        self.assertEqual(declared, hashlib.sha256(_canonical(final_core)).hexdigest())

    def test_plan_inventory_and_incident_recovery_gates(self) -> None:
        checked = subprocess.run(
            [sys.executable, str(ROOT / "docs/superpowers/build_complete_plan.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        inventory = _load(FINAL_INVENTORY)
        self.assertEqual(inventory["summary"]["unknown_count"], 0, inventory["summary"])
        self.assertFalse(inventory["parse_errors"])
        incident = _load(INCIDENT)
        self.assertEqual(incident["status"], "RECOVERED_REGRESSION_PASSED")
        self.assertTrue(incident["recovery_evidence"]["production_incident_path_absent"])
        evidence = Path(incident["evidence_copy"]["path"])
        self.assertEqual(_sha256_file(evidence), incident["evidence_copy"]["expected_sha256"])
        self.assertEqual(incident["impact"]["legacy_data_changed"], False)
        self.assertEqual(incident["impact"]["existing_file_overwritten"], False)


if __name__ == "__main__":
    unittest.main()
