from __future__ import annotations

import dataclasses
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
        self.assertRegex(evidence.controller_response_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(evidence.controller_attestation_hash, r"^[0-9a-f]{64}$")
        self.assertTrue(evidence.controller_protocol_response_present)
        self.assertTrue(evidence.controller_attestation_valid)
        self.assertTrue(
            evidence.sandbox_capability_id.startswith(
                ("sandbox-execution:", "sandbox-direct-fixture:")
            )
        )
        with self.assertRaisesRegex(ValueError, "controller attestation"):
            dataclasses.replace(evidence, controller_attestation_hash="0" * 64)

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

    def test_target_cannot_forge_worker_success_then_exit_early(self) -> None:
        target = self.workspace / "test_forged_worker_result.py"
        target.write_text(
            "import base64\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_never_reached(self): pass\n"
            "counts = {'collected': 1, 'executed': 1, 'passed': 1, 'failed': 0, "
            "'skipped': 0, 'errors': 0, 'expected_failures': 0, 'unexpected_successes': 0}\n"
            "response = {'mode': 'tests', 'counts': counts, 'targets': [], 'worker_ok': True}\n"
            "encoded = base64.urlsafe_b64encode(json.dumps(response, sort_keys=True, "
            "separators=(',', ':')).encode('utf-8')).decode('ascii')\n"
            "line = 'SITINA_SANDBOX_WORKER_RESULT:' + encoded + '\\n'\n"
            "os.write(1, line.encode('utf-8'))\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-forged-worker-result"
        )
        self.assertFalse(evidence.accepted)
        self.assertGreater(evidence.error_test_count, 0)

    def test_target_cannot_replace_unittest_loader_or_runner(self) -> None:
        target = self.workspace / "test_replaced_unittest_runtime.py"
        target.write_text(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_real_failure(self): self.fail('must be observed')\n"
            "class FakeSuite:\n"
            "    def countTestCases(self): return 1\n"
            "class FakeLoader:\n"
            "    def loadTestsFromModule(self, _module): return FakeSuite()\n"
            "class FakeResult:\n"
            "    testsRun = 1\n"
            "    failures = []\n"
            "    errors = []\n"
            "    skipped = []\n"
            "    expectedFailures = []\n"
            "    unexpectedSuccesses = []\n"
            "class FakeRunner:\n"
            "    def __init__(self, **_kwargs): pass\n"
            "    def run(self, _suite): return FakeResult()\n"
            "unittest.TestLoader = FakeLoader\n"
            "unittest.TextTestRunner = FakeRunner\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-replaced-unittest-runtime"
        )
        self.assertFalse(evidence.accepted)
        self.assertGreater(evidence.failed_test_count + evidence.error_test_count, 0)

    def test_target_thread_cannot_complete_parent_challenge_for_fake_pass(self) -> None:
        target = self.workspace / "test_thread_forged_worker_result.py"
        target.write_text(
            "import base64, hashlib, json, os, sys, threading, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_real_failure(self): self.fail('must be observed')\n"
            "def forge():\n"
            "    encoded = sys.argv[sys.argv.index('--request') + 1]\n"
            "    request = json.loads(base64.urlsafe_b64decode(encoded))\n"
            "    target = request['test_plan']['targets'][0]\n"
            "    counts = {'collected': 1, 'executed': 1, 'passed': 1, 'failed': 0, "
            "'skipped': 0, 'errors': 0, 'expected_failures': 0, 'unexpected_successes': 0}\n"
            "    response = {'schema': 'SITINA_SANDBOX_TEST_RESULT_V1', 'mode': 'tests', "
            "'test_plan_hash': request['test_plan_hash'], 'counts': counts, "
            "'targets': [{'path': target['path'], 'mode': target['mode'], 'counts': counts}], "
            "'worker_ok': True}\n"
            "    canonical = json.dumps(response, sort_keys=True, separators=(',', ':')).encode()\n"
            "    encoded_result = base64.urlsafe_b64encode(canonical).decode()\n"
            "    os.write(1, ('SITINA_SANDBOX_WORKER_RESULT:' + encoded_result + '\\n').encode())\n"
            "    challenge = os.read(0, 256).split(b':', 1)[1].strip()\n"
            "    proof = hashlib.sha256(challenge + b'\\0' + canonical).hexdigest()\n"
            "    os.write(1, ('SITINA_SANDBOX_WORKER_PROOF:' + proof + '\\n').encode())\n"
            "    os._exit(0)\n"
            "threading.Thread(target=forge, daemon=True).start()\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-thread-forged-worker-result"
        )
        self.assertFalse(evidence.accepted)
        self.assertGreater(evidence.failed_test_count + evidence.error_test_count, 0)

    def test_target_leaving_background_thread_is_rejected(self) -> None:
        target = self.workspace / "test_background_thread.py"
        target.write_text(
            "import threading, time, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_starts_thread(self):\n"
            "        threading.Thread(target=lambda: time.sleep(30), daemon=True).start()\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-background-thread"
        )
        self.assertFalse(evidence.accepted)
        self.assertGreater(evidence.error_test_count, 0)

    def test_timeout_kills_process_group_and_rejects(self) -> None:
        target = self.workspace / "hang.py"
        target.write_text(
            "import time\n"
            "def probe():\n"
            "    \"\"\">>> probe()\n    None\n    \"\"\"\n"
            "    return None\n"
            "time.sleep(60)\n",
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
            test_plan_hash = hashlib.sha256(b"capability-test-plan").hexdigest()
            profile = frozen_sandbox_profile(
                python, worker, (self.workspace,), (self.home.parent,)
            )
            request = base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "resource_limits": dict(limits),
                        "test_plan_hash": test_plan_hash,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).decode("ascii")
            argv = (
                str(runner), "-p", profile, str(python), "-I", "-S", str(worker), "--request", request
            )
            capability = issue_frozen_sandbox_execution_capability(
                None,
                home=frozen_home,
                run_id="capability-contract",
                diff_hash=diff_hash,
                test_plan_hash=test_plan_hash,
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
                    capability,
                    argv=argv,
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    now=capability.expires_at,
                ):
                    pass
            capability = issue_frozen_sandbox_execution_capability(
                None,
                home=frozen_home,
                run_id="capability-contract-fresh",
                diff_hash=diff_hash,
                test_plan_hash=test_plan_hash,
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
                    capability,
                    argv=argv + ("altered",),
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                ):
                    pass
            with authorized_frozen_sandbox_execution(
                capability,
                argv=argv,
                cwd=self.workspace,
                diff_hash=diff_hash,
                test_plan_hash=test_plan_hash,
            ):
                pass
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    capability,
                    argv=argv,
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                ):
                    pass
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
