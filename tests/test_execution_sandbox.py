from __future__ import annotations

import hashlib
import base64
import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sitina.legacy.fence import (
    LegacyWriteDenied,
    authorized_frozen_sandbox_execution,
    frozen_sandbox_profile,
    issue_frozen_sandbox_execution_capability,
)
from sitina.orchestrator.execution_sandbox import (
    ExecutionSandboxError,
    ExecutionSandboxRunner,
    FilesystemTestEvidencePublisher,
    SandboxResourceLimits,
    hash_diff,
)
from tests.fixtures.frozen_home import make_frozen_home


PASSING_DOCTEST = (
    "def add(a, b):\n"
    "    \"\"\"Return a plus b.\n\n"
    "    >>> add(2, 3)\n"
    "    5\n"
    "    \"\"\"\n"
    "    return a + b\n"
)


class ExecutionSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="sandbox-home-")).resolve()
        self.workspace = Path(tempfile.mkdtemp(prefix="sandbox-workspace-")).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_passing_doctest_produces_exact_complete_evidence(self) -> None:
        target = self.workspace / "add.py"
        target.write_text(PASSING_DOCTEST, encoding="utf-8")
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-passing-doctest"
        )
        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 1)
        self.assertEqual(evidence.passed_test_count, 1)
        self.assertEqual(evidence.failed_test_count, 0)
        self.assertEqual(evidence.skipped_test_count, 0)
        self.assertEqual(evidence.error_test_count, 0)
        self.assertEqual(evidence.diff_hash_before, evidence.diff_hash_after)
        self.assertEqual(evidence.sandbox_provider_id, "macos-seatbelt-sandbox-exec-v1")

    def test_skipped_unittest_is_real_nonpass_evidence(self) -> None:
        target = self.workspace / "test_skipped.py"
        target.write_text(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    @unittest.skip('not acceptable')\n"
            "    def test_value(self): pass\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-skipped-test"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 1)
        self.assertEqual(evidence.skipped_test_count, 1)

    def test_timeout_kills_process_group_and_rejects(self) -> None:
        target = self.workspace / "hang.py"
        target.write_text(
            "def probe():\n"
            "    \"\"\">>> probe()\n    None\n    \"\"\"\n"
            "    return None\n"
            "while True:\n"
            "    pass\n",
            encoding="utf-8",
        )
        limits = SandboxResourceLimits(cpu_seconds=1, wall_seconds=1)
        started = time.monotonic()
        evidence = ExecutionSandboxRunner(home=self.home, limits=limits).run_tests(
            [target], run_id="sandbox-timeout"
        )
        self.assertFalse(evidence.accepted)
        self.assertLess(time.monotonic() - started, 6)
        self.assertTrue(evidence.timed_out or evidence.runner_return_code != 0)

    def test_evidence_publisher_is_no_replace_and_symlink_safe(self) -> None:
        publisher = FilesystemTestEvidencePublisher(self.workspace / "evidence")
        raw = b'{"schema":"probe"}'
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(publisher.publish(raw, evidence_hash=digest), "test-evidence:" + digest)
        self.assertEqual(publisher.publish(raw, evidence_hash=digest), "test-evidence:" + digest)
        target = publisher.root / (hashlib.sha256(b"other").hexdigest() + ".json")
        target.symlink_to(publisher.root / (digest + ".json"))
        with self.assertRaises(ExecutionSandboxError):
            publisher.publish(b"other", evidence_hash=hashlib.sha256(b"other").hexdigest())

    def test_symlink_test_target_is_rejected(self) -> None:
        real = self.workspace / "real.py"
        real.write_text(PASSING_DOCTEST, encoding="utf-8")
        link = self.workspace / "linked.py"
        link.symlink_to(real)
        with self.assertRaises(ExecutionSandboxError):
            ExecutionSandboxRunner(home=self.home).run_tests([link], run_id="sandbox-symlink")

    def test_frozen_capability_is_exact_and_one_use(self) -> None:
        frozen_home = make_frozen_home()
        try:
            target = self.workspace / "capability.py"
            target.write_text(PASSING_DOCTEST, encoding="utf-8")
            diff_hash, _entries = hash_diff([target])
            runner = Path("/usr/bin/sandbox-exec").resolve(strict=True)
            python = Path(sys.executable).resolve(strict=True)
            worker = Path(__file__).resolve().parents[1] / "core/sitina/orchestrator/execution_sandbox_worker.py"
            limits = (("cpu_seconds", 1),)
            profile = frozen_sandbox_profile(
                python, worker, (self.workspace,), (self.home.parent,)
            )
            request = base64.urlsafe_b64encode(
                json.dumps({"resource_limits": dict(limits)}, sort_keys=True).encode("utf-8")
            ).decode("ascii")
            argv = (
                str(runner), "-p", profile, str(python), "-I", "-S", str(worker), "--request", request
            )
            capability = issue_frozen_sandbox_execution_capability(
                None,
                home=frozen_home,
                run_id="capability-contract",
                diff_hash=diff_hash,
                runner_executable=runner,
                python_executable=python,
                worker_path=worker,
                argv=argv,
                cwd=self.workspace,
                read_roots=(self.workspace,),
                write_roots=(self.home.parent,),
                sandbox_policy_hash=hashlib.sha256(profile.encode("utf-8")).hexdigest(),
                resource_limits=limits,
                expires_at=int(time.time()) + 30,
                fixture_authorization=True,
            )
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    capability, argv=argv + ("altered",), cwd=self.workspace, diff_hash=diff_hash
                ):
                    pass
            with authorized_frozen_sandbox_execution(
                capability, argv=argv, cwd=self.workspace, diff_hash=diff_hash
            ):
                pass
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    capability, argv=argv, cwd=self.workspace, diff_hash=diff_hash
                ):
                    pass
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
