"""SL6: real-filesystem integration for the safe execution bridge. Exercises the
REAL stack — AutonomousRuntime loop + ToolExecutor SL1 pre-write gate + scoped
approval + real boundary redaction + real ast verifier + bounded rework + rollback
— driven by a scripted-mock Forge (no provider/live)."""
from __future__ import annotations

import ast
import itertools
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.extensions.runtime import AutonomousRuntime
from sitina.runners.provider import ProviderToolCall, ProviderToolTurn, ScriptedMockToolClient
from sitina.orchestrator.execution_bridge import ExecutionBinding, VerificationVerdict, run_safe_execution
from sitina.security.redaction import redact_boundary_value
from sitina.guards.path_lease import PathLease

EXEC_ID, VER_ID = "agent-forge", "agent-delta"


class _NoopAudit:
    def append(self, event, payload): pass
    def summary(self): return {}


def _write_turns(path, content):
    return [
        ProviderToolTurn("w", (ProviderToolCall("w", "sitina_write_file", {"path": path, "content": content}),), "tool_calls", {}),
        ProviderToolTurn("done", (), "stop", {}),
    ]


def _scoped_approval(ws: Path):
    root = str(ws.resolve(strict=False))
    def decide(req):
        if getattr(req, "permission", None) != "write":
            return False
        target = str(Path(str((getattr(req, "arguments", {}) or {}).get("path") or "")).expanduser().resolve(strict=False))
        return target == root or target.startswith(root + "/")
    return decide


class ExecutionBridgeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prev_home = os.environ.get("SITINA_HOME")
        self.home = Path(tempfile.mkdtemp())
        os.environ["SITINA_HOME"] = str(self.home)
        shutil.copytree("/Users/moss/SitinaHub/config", self.home / "config", dirs_exist_ok=True)
        self._ctr = itertools.count()

    def tearDown(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)
        if self._prev_home is not None:
            os.environ["SITINA_HOME"] = self._prev_home
        else:
            os.environ.pop("SITINA_HOME", None)

    def _run(self, scripts, max_attempts=2):
        base = self.home / "artifacts" / "executions" / f"run-{next(self._ctr)}"
        base.mkdir(parents=True, exist_ok=True)
        state = {"attempt": 1}
        def attempt_ws(a):
            w = base / f"attempt-{a}"; w.mkdir(parents=True, exist_ok=True); return w
        def forge_runner(attempt, _ws):
            state["attempt"] = attempt; ws = attempt_ws(attempt); fname, content = scripts(attempt)
            rt = AutonomousRuntime(self.home, client=ScriptedMockToolClient(_write_turns(str(ws / fname), content)),
                                   approval_callback=_scoped_approval(ws), workspace=ws, enforce_write_boundary=True)
            return rt.run_embedded("build", run_id=f"exec-{attempt}", journal_audit=_NoopAudit())
        def collect_diff():
            return sorted(str(p) for p in attempt_ws(state["attempt"]).rglob("*") if p.is_file())
        def boundary_check(diff):
            out = []
            for p in diff:
                try: text = Path(p).read_text(encoding="utf-8", errors="strict")
                except Exception: continue
                if redact_boundary_value(text, boundary="write").redacted_paths: out.append(p)
            return out
        # No mirror verifier: call the REAL production helper (eliminates drift).
        def verifier(diff, res):
            from sitina.orchestrator.execution_verification import verify_execution_diff
            return verify_execution_diff(diff, VER_ID, res)
        def rollback(a):
            w = base / f"attempt-{a}"
            if w.exists(): shutil.rmtree(w, ignore_errors=True)
        binding = ExecutionBinding("a"*64, (str(base),), "b"*64, f"run-{base.name}")
        res = run_safe_execution(binding=binding, executor_id=EXEC_ID, workspace=str(base),
            forge_runner=forge_runner, collect_diff=collect_diff, boundary_check=boundary_check,
            verifier=verifier, rollback=rollback, max_attempts=max_attempts)
        return res, base

    # code WITH a passing doctest -> real test evidence -> can be accepted
    _CODE_WITH_DOCTEST = (
        "def add(a, b):\n"
        "    \"\"\"Return a+b.\n\n    >>> add(2, 3)\n    5\n    \"\"\"\n"
        "    return a + b\n"
    )

    def test_clean_code_with_tests_accepted(self):
        res, _ = self._run(lambda a: ("add.py", self._CODE_WITH_DOCTEST))
        self.assertTrue(res.accepted)
        self.assertTrue(res.verification.checked_tests, "accept must have real test evidence")
        self.assertEqual(res.verification.verifier_id, VER_ID)
        self.assertNotEqual(res.verification.verifier_id, EXEC_ID)

    def test_clean_code_without_tests_not_accepted(self):
        # syntax-valid but NO executable tests -> fail-closed (the hollow-accept fix)
        res, _ = self._run(lambda a: ("add.py", "def add(a, b):\n    return a + b\n"))
        self.assertFalse(res.accepted)

    def test_secret_blocked_before_disk_and_not_accepted(self):
        res, base = self._run(lambda a: ("leak.py", "API_KEY = 'sk-deadbeef1234567890deadbeef'\n"))
        self.assertFalse(res.accepted)
        leaked = [p for p in base.rglob("*") if p.is_file() and "sk-deadbeef" in p.read_text(errors="ignore")]
        self.assertEqual(leaked, [], "secret must be blocked before it reaches disk (SL1)")

    def test_bad_syntax_bounded_rework_fail_closed(self):
        res, _ = self._run(lambda a: ("bad.py", "def broken(:\n  pass\n"))
        self.assertFalse(res.accepted)
        self.assertEqual(res.attempts, 2)
        self.assertIn("rework_exhausted_fail_closed", res.notes)

    def test_result_is_returned_not_discarded(self):
        res, _ = self._run(lambda a: ("add.py", self._CODE_WITH_DOCTEST))
        self.assertEqual(res.as_event()["schema"], "FORGE_EXECUTION_RESULT_V1")
        self.assertTrue(res.as_event()["accepted"])

    def test_concurrent_fencing_second_lease_blocked(self):
        p = self.home / "fence.txt"
        with PathLease(p, "run-A", self.home):
            with self.assertRaises(RuntimeError):
                with PathLease(p, "run-B", self.home):
                    pass


if __name__ == "__main__":
    unittest.main()
