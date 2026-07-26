from __future__ import annotations

import json
import io
import runpy
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from scripts.bplus_dependency_gate import SUMMARY_MARKER, audit_dependency_lock


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "requirements-bplus.lock"
CONFIG = ROOT / "tests/test_suites.json"
LOCKED = {
    "annotated-types": "0.7.0",
    "cffi": "2.0.0",
    "cryptography": "49.0.0",
    "pycparser": "3.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.2",
    "zstandard": "0.25.0",
}


class DependencyLockGateTests(unittest.TestCase):
    def test_approved_runtime_exactly_matches_current_lock(self) -> None:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        approved_python = config["approved_python"]
        process = subprocess.run(
            [
                approved_python,
                str(ROOT / "scripts/bplus_dependency_gate.py"),
                "--lock",
                str(LOCK),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(process.returncode, 0, process.stdout)
        lines = [line for line in process.stdout.splitlines() if line.startswith(SUMMARY_MARKER)]
        self.assertEqual(len(lines), 1, process.stdout)
        report = json.loads(lines[0][len(SUMMARY_MARKER) :])
        self.assertTrue(report["accepted"])
        self.assertEqual(
            report["lock_sha256"],
            "dbc3f95b77ed7034b5a48954abf579f2af77d3d410061482a7062e08d7e8c4bc",
        )
        self.assertEqual(report["installed_locked_versions"]["cffi"], "2.0.0")
        self.assertEqual(report["installed_locked_versions"]["zstandard"], "0.25.0")

    def test_missing_locked_distribution_fails_closed(self) -> None:
        installed = dict(LOCKED)
        del installed["zstandard"]
        report = audit_dependency_lock(LOCK, installed_versions=installed)
        self.assertFalse(report["accepted"])
        self.assertEqual(report["missing"], ["zstandard"])
        self.assertEqual(report["version_mismatches"], [])

    def test_version_deviation_fails_closed(self) -> None:
        installed = {**LOCKED, "cffi": "2.1.0"}
        report = audit_dependency_lock(LOCK, installed_versions=installed)
        self.assertFalse(report["accepted"])
        self.assertEqual(
            report["version_mismatches"],
            [
                {
                    "name": "cffi",
                    "locked_version": "2.0.0",
                    "installed_version": "2.1.0",
                }
            ],
        )

    def test_historical_manifest_lock_binding_drift_is_reported_and_rejected(self) -> None:
        report = audit_dependency_lock(
            LOCK,
            installed_versions=LOCKED,
            expected_lock_sha256="sha256:"
            "a282878655ab317ce969201bb8ae6bd0c77692913e92472f13a3d03b87199feb",
        )
        self.assertTrue(report["dependencies_match"])
        self.assertFalse(report["manifest_binding_match"])
        self.assertFalse(report["accepted"])

    def test_runner_preflight_rejects_dependency_failure_before_starting_tests(self) -> None:
        namespace = runpy.run_path(
            str(ROOT / "scripts/test-bplus.py"),
            run_name="dependency_gate_runner_probe",
        )
        validate = namespace["_validate_dependency_environment"]
        validate.__globals__["audit_dependency_lock"] = lambda _path, **_kwargs: {
            "accepted": False,
            "lock_sha256": "d" * 64,
            "missing": ["zstandard"],
            "version_mismatches": [],
        }
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(
            SystemExit,
            "dependency lock/runtime consistency gate rejected execution",
        ):
            validate(
                SimpleNamespace(dependency_lock_hash="sha256:" + "a" * 64),
                {"dependency_lock_sha256": "d" * 64},
            )
        self.assertIn(SUMMARY_MARKER, output.getvalue())


if __name__ == "__main__":
    unittest.main()
