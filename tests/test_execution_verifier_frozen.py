"""Production verifier contracts under frozen-home (production) conditions.

Two distinct contracts (per review):

1. FAIL-CLOSED contract (passes now): when tests cannot execute (frozen fence
   denies subprocess), the verifier must return a STRUCTURED verdict
   (accepted=False, checked_tests=False, reasons) — never leak an exception.

2. SANDBOX-SUCCESS contract: when an authorized OS
   sandbox is available, a file with a passing doctest must yield
   accepted=True, checked_tests=True, test_count>0. This documents the real
   target contract through the Step-6 sandbox runner.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.fixtures.frozen_home import make_frozen_home, get_core_path, FrozenBootstrapUnavailable


def _run_verifier_in_frozen_home(
    frozen_home: Path,
    target_file: Path,
    evidence_root: Path,
    *,
    sandbox_executable: str = "/usr/bin/sandbox-exec",
) -> dict:
    """Run the production verifier in a subprocess bound to the frozen home.
    Returns the parsed verdict dict, or raises with stderr if it crashed."""
    core = get_core_path()
    result = subprocess.run(
        [
            sys.executable, "-c",
            f"import os, sys, json; "
            f"os.environ['SITINA_HOME']={str(frozen_home)!r}; "
            f"sys.path.insert(0, {core!r}); "
            f"from pathlib import Path; "
            f"from sitina.orchestrator.execution_verification import verify_execution_diff; "
            f"from sitina.orchestrator.execution_sandbox import FilesystemTestEvidencePublisher; "
            f"p = FilesystemTestEvidencePublisher(Path({str(evidence_root)!r})); "
            f"v = verify_execution_diff([{str(target_file)!r}], 'agent-delta', {{}}, "
            f"run_id='frozen-fixture-run', home=Path({str(frozen_home)!r}), "
            f"fixture_authorization=True, evidence_publisher=p, "
            f"sandbox_executable=Path({sandbox_executable!r})); "
            f"e = json.loads((Path({str(evidence_root)!r}) / "
            f"(v.test_evidence_hash + '.json')).read_text()) if v.test_evidence_hash else None; "
            f"print(json.dumps({{'accepted': v.accepted, 'checked_tests': v.checked_tests, "
            f"'reasons': list(v.reasons), 'test_evidence_ref': v.test_evidence_ref, "
            f"'test_evidence_hash': v.test_evidence_hash, 'evidence': e}}))"
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"verifier crashed (leaked exception) rc={result.returncode}\n"
            f"stderr: {result.stderr[-500:]}"
        )
    return json.loads(result.stdout.strip())


class ProductionVerifierFrozenHomeTests(unittest.TestCase):

    def test_fail_closed_when_tests_cannot_run(self):
        """Frozen fence denies subprocess -> verifier must fail-closed with a
        structured verdict, NOT leak LegacyWriteDenied."""
        try:
            frozen_home = make_frozen_home()
        except FrozenBootstrapUnavailable as exc:
            self.skipTest(str(exc))
        ws = Path(tempfile.mkdtemp(prefix="verifier-frozen-"))
        evidence_root = Path(tempfile.mkdtemp(prefix="verifier-evidence-"))
        try:
            f = ws / "add.py"
            f.write_text(
                'def add(a, b):\n'
                '    """Return a plus b.\n\n'
                '    >>> add(2, 3)\n'
                '    5\n'
                '    """\n'
                '    return a + b\n'
            )
            verdict = _run_verifier_in_frozen_home(
                frozen_home, f, evidence_root, sandbox_executable="/missing/sandbox-exec"
            )
            # Structured fail-closed (no leak): the whole point.
            self.assertFalse(verdict["accepted"], "must not accept when tests can't run")
            self.assertFalse(verdict["checked_tests"], "no test evidence when execution blocked")
            self.assertTrue(verdict["reasons"], "must give a structured reason")
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)
            shutil.rmtree(ws, ignore_errors=True)
            shutil.rmtree(evidence_root, ignore_errors=True)

    def test_sandbox_success_accepts_with_test_evidence(self):
        """TARGET (Step 6): with an authorized OS sandbox, a passing doctest
        must yield accepted=True, checked_tests=True, test_count>0.

        This is the contract Step-6 A must satisfy."""
        try:
            frozen_home = make_frozen_home()
        except FrozenBootstrapUnavailable as exc:
            self.skipTest(str(exc))
        ws = Path(tempfile.mkdtemp(prefix="verifier-frozen-success-"))
        evidence_root = Path(tempfile.mkdtemp(prefix="verifier-evidence-success-"))
        try:
            target = ws / "add.py"
            target.write_text(
                'def add(a, b):\n'
                '    """Return a plus b.\n\n'
                '    >>> add(2, 3)\n'
                '    5\n'
                '    """\n'
                '    return a + b\n'
            )
            verdict = _run_verifier_in_frozen_home(frozen_home, target, evidence_root)
            self.assertTrue(verdict["accepted"], verdict["reasons"])
            self.assertTrue(verdict["checked_tests"])
            self.assertTrue(verdict["test_evidence_ref"].startswith("test-evidence:"))
            self.assertEqual(len(verdict["test_evidence_hash"]), 64)
            evidence = verdict["evidence"]
            self.assertGreater(evidence["collected_test_count"], 0)
            self.assertEqual(evidence["executed_test_count"], evidence["collected_test_count"])
            self.assertEqual(evidence["passed_test_count"], evidence["executed_test_count"])
            self.assertEqual(evidence["failed_test_count"], 0)
            self.assertEqual(evidence["skipped_test_count"], 0)
            self.assertEqual(evidence["error_test_count"], 0)
            self.assertEqual(evidence["diff_hash_before"], evidence["diff_hash_after"])
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)
            shutil.rmtree(ws, ignore_errors=True)
            shutil.rmtree(evidence_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
