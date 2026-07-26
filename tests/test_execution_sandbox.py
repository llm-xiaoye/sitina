from __future__ import annotations

import dataclasses
import hashlib
import base64
import importlib.util
import json
import os
import py_compile
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sitina.authority.model import AuthorityResolution, AuthorityState
from sitina.legacy.fence import (
    LegacyWriteDenied,
    _sandbox_capability_identity,
    authorized_frozen_sandbox_execution,
    frozen_sandbox_profile,
    issue_frozen_sandbox_execution_capability,
)
from sitina.orchestrator.execution_bridge import ExecutionIdentityBinding
from sitina.orchestrator.execution_sandbox import (
    ExecutionSandboxError,
    ExecutionSandboxRunner,
    FilesystemTestEvidencePublisher,
    SandboxResourceLimits,
    hash_diff,
)
from sitina.orchestrator.true_multi_agent_runtime import AgentRegistry
from tests.fixtures.frozen_home import make_frozen_home


PASSING_DOCTEST = (
    "def add(a, b):\n"
    "    \"\"\"Return a plus b.\n\n"
    "    >>> add(2, 3)\n"
    "    5\n"
    "    \"\"\"\n"
    "    return a + b\n"
)


def _identity_variants() -> dict[str, ExecutionIdentityBinding]:
    return {
        "proposer_id": ExecutionIdentityBinding.fixture(
            proposer_id="alternate-proposer"
        ),
        "verifier_id": ExecutionIdentityBinding.fixture(
            verifier_id="alternate-verifier"
        ),
        "registry_hash": ExecutionIdentityBinding.fixture(
            registry_hash="c" * 64
        ),
        "policy_hash": ExecutionIdentityBinding.fixture(
            policy_hash="d" * 64
        ),
        "executor_role_authorization_ref": ExecutionIdentityBinding.fixture(
            policy_hash="e" * 64
        ),
        "authority_ref": ExecutionIdentityBinding.fixture(
            authority_resolution_id="f" * 64
        ),
    }


def _attestation_for_identity(evidence, identity: ExecutionIdentityBinding) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "schema": "SITINA_SANDBOX_CONTROLLER_ATTESTATION_V2",
                "controller_identity": evidence.sandbox_capability_id,
                "diff_hash": evidence.diff_hash_before,
                "test_plan_hash": evidence.test_plan_hash,
                "execution_identity_hash": identity.binding_hash,
                "protocol_key_hash": evidence.controller_protocol_key_hash,
                "response_hash": evidence.controller_response_hash,
                "worker_hash": evidence.worker_hash,
                "argv_hash": evidence.argv_hash,
                "runner_return_code": evidence.runner_return_code,
                "timed_out": evidence.timed_out,
                "protocol_response_present":
                    evidence.controller_protocol_response_present,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


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
        self.assertRegex(evidence.controller_protocol_key_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(evidence.controller_response_hash, r"^[0-9a-f]{64}$")
        self.assertRegex(evidence.controller_attestation_hash, r"^[0-9a-f]{64}$")
        self.assertTrue(evidence.controller_protocol_response_present)
        self.assertTrue(evidence.controller_attestation_valid)
        execution_identity = evidence.mapping()["execution_identity"]
        self.assertEqual(execution_identity["proposer_id"], "fixture-proposer")
        self.assertEqual(
            execution_identity["executor_id"], "forge-execution-role"
        )
        self.assertEqual(execution_identity["verifier_id"], "fixture-verifier")
        for field in (
            "registry_hash",
            "policy_hash",
            "executor_role_authorization_ref",
            "authority_ref",
        ):
            self.assertTrue(execution_identity[field])
        trust = evidence.mapping()["trust_boundary"]
        self.assertEqual(
            trust["authenticated_channel"],
            "ONE_USE_CONTROLLER_KEYED_HMAC_SHA256_SEPARATE_SUPERVISOR_PROCESS",
        )
        self.assertTrue(trust["target_cannot_frame_introspect_signing_supervisor"])
        self.assertTrue(trust["trusted_controller_computes_counts_from_item_observations"])
        self.assertFalse(trust["executor_reports_aggregate_test_verdict"])
        self.assertEqual(trust["generic_unittest_result_source"], "FAIL_CLOSED_UNSUPPORTED")
        self.assertTrue(trust["one_seatbelt_process_per_attempted_item"])
        self.assertTrue(trust["structured_observations_constructed_outside_target_process"])
        self.assertEqual(trust["target_result_channel_access"], "NONE_RAW_STDOUT_STDERR_ONLY")
        self.assertEqual(trust["target_lifecycle_channel_access"], "NONE")
        self.assertEqual(
            trust["execution_contract"],
            "HASH_BOUND_UTF8_PURE_DOCTEST_AST_SUBSET_V1",
        )
        self.assertEqual(
            trust["target_source_execution"],
            "SINGLE_READ_BYTES_COMPILE_EXEC_NO_PATH_LOADER_OR_PYC",
        )
        self.assertEqual(
            trust["completion_owner"],
            "SIGNING_SUPERVISOR_NEVER_EXECUTES_TARGET_CODE",
        )
        self.assertFalse(trust["target_can_access_completion_primitive"])
        self.assertFalse(trust["target_receives_sealed_expected_output"])
        self.assertTrue(
            evidence.sandbox_capability_id.startswith(
                ("sandbox-execution:", "sandbox-direct-fixture:")
            )
        )
        with self.assertRaisesRegex(ValueError, "controller attestation"):
            dataclasses.replace(evidence, controller_attestation_hash="0" * 64)
        with self.assertRaisesRegex(ValueError, "controller attestation"):
            dataclasses.replace(evidence, controller_protocol_key_hash="0" * 64)
        base_mapping = evidence.identity.mapping()
        for field, alternate_identity in _identity_variants().items():
            with self.subTest(field=field):
                self.assertNotEqual(
                    base_mapping[field],
                    alternate_identity.mapping()[field],
                )
                alternate_evidence = dataclasses.replace(
                    evidence,
                    identity=alternate_identity,
                    controller_attestation_hash=_attestation_for_identity(
                        evidence, alternate_identity
                    ),
                )
                self.assertTrue(alternate_evidence.controller_attestation_valid)
                self.assertNotEqual(
                    evidence.evidence_hash,
                    alternate_evidence.evidence_hash,
                )

    def test_preexisting_pyc_cannot_replace_hash_bound_source_bytes(self) -> None:
        target = self.workspace / "stale_bytecode.py"
        cached_source = (
            "def value():\n"
            "    \"\"\"\n"
            "    >>> value()\n"
            "    1\n"
            "    \"\"\"\n"
            "    return 1\n"
        )
        checked_source = cached_source.replace("return 1", "return 2")
        self.assertEqual(len(cached_source), len(checked_source))
        target.write_text(cached_source, encoding="utf-8")
        source_timestamp = 1_700_000_000
        os.utime(target, (source_timestamp, source_timestamp))
        cache = Path(importlib.util.cache_from_source(str(target)))
        cache.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(target), cfile=str(cache), doraise=True)
        target.write_text(checked_source, encoding="utf-8")
        os.utime(target, (source_timestamp, source_timestamp))

        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-source-bytes-ignore-pyc"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 1)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertEqual(evidence.failed_test_count, 1)
        self.assertEqual(evidence.error_test_count, 0)
        self.assertEqual(evidence.runner_return_code, 0)

    def test_function_type_params_fail_closed_before_execution(self) -> None:
        target = self.workspace / "function_type_params.py"
        target.write_text(
            "def value[T: __import__('os')]():\n"
            "    \"\"\"\n"
            "    >>> value()\n"
            "    1\n"
            "    \"\"\"\n"
            "    return 1\n",
            encoding="utf-8",
        )

        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-function-type-params"
        )
        self.assertFalse(evidence.accepted, evidence.mapping())
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 0, evidence.mapping())
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

    def test_generic_unittest_fails_closed_before_assertions_run(self) -> None:
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
        self.assertEqual(evidence.executed_test_count, 0)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertEqual(evidence.skipped_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

    def test_failing_doctest_is_computed_as_a_real_failure_by_parent(self) -> None:
        target = self.workspace / "failing.py"
        target.write_text(
            "def add(a, b):\n"
            "    \"\"\">>> add(2, 3)\n    4\n    \"\"\"\n"
            "    return a + b\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-failing-doctest"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 1)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertEqual(evidence.failed_test_count, 1)
        self.assertEqual(evidence.error_test_count, 0)
        self.assertEqual(evidence.runner_return_code, 0)

    def test_expected_doctest_exception_is_compared_by_parent(self) -> None:
        target = self.workspace / "expected_exception.py"
        target.write_text(
            "def boom():\n"
            "    \"\"\"\n"
            "    >>> boom()\n"
            "    Traceback (most recent call last):\n"
            "    ...\n"
            "    ValueError: sealed boom\n"
            "    \"\"\"\n"
            "    raise ValueError('sealed boom')\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-expected-doctest-exception"
        )
        self.assertTrue(evidence.accepted)
        self.assertEqual(evidence.passed_test_count, 1)
        self.assertEqual(evidence.error_test_count, 0)

    def test_unexpected_doctest_exception_is_parent_error_evidence(self) -> None:
        target = self.workspace / "unexpected_exception.py"
        target.write_text(
            "def boom():\n"
            "    \"\"\">>> boom()\n    1\n    \"\"\"\n"
            "    raise RuntimeError('unexpected')\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-unexpected-doctest-exception"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 1)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertEqual(evidence.error_test_count, 1)
        self.assertEqual(evidence.runner_return_code, 0)

    def test_zero_test_target_is_rejected_before_sandbox_start(self) -> None:
        target = self.workspace / "empty.py"
        target.write_text("VALUE = 1\n", encoding="utf-8")
        with self.assertRaisesRegex(ExecutionSandboxError, "zero executable tests"):
            ExecutionSandboxRunner(home=self.home).run_tests(
                [target], run_id="sandbox-zero-tests"
            )

    def test_target_early_exit_never_counts_as_an_assertion_pass(self) -> None:
        target = self.workspace / "early_exit.py"
        target.write_text(
            "import os\n"
            "def value():\n"
            "    \"\"\">>> value()\n    1\n    \"\"\"\n"
            "    return 1\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-early-exit"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 0)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

    def test_target_cannot_forge_framework_completion_with_reserved_exit(self) -> None:
        target = self.workspace / "reserved_success_exit.py"
        target.write_text(
            "import os\n"
            "def value():\n"
            "    \"\"\"\n"
            "    >>> value()\n"
            "    1\n"
            "    \"\"\"\n"
            "    return 2\n"
            "os.write(1, b'1\\n')\n"
            "os._exit(70)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-reserved-success-early-exit"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertEqual(evidence.executed_test_count, 0, evidence.mapping())
        self.assertGreater(evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

    def test_target_cannot_complete_inherited_framework_control_protocol(self) -> None:
        target = self.workspace / "forged_framework_control.py"
        target.write_text(
            "import base64, hashlib, json, os, socket, sys\n"
            "def value():\n"
            "    \"\"\"\n"
            "    >>> value()\n"
            "    1\n"
            "    \"\"\"\n"
            "    return 2\n"
            "encoded = sys.argv[sys.argv.index('--execute-item') + 1]\n"
            "request = json.loads(base64.urlsafe_b64decode(encoded))\n"
            "control = socket.socket(fileno=request['framework_control_fd'])\n"
            "os.write(1, b'1\\n')\n"
            "control.sendall(b'SITINA_ITEM_FRAMEWORK_COMPLETE_V1\\n')\n"
            "challenge = b''\n"
            "while len(challenge) < 32:\n"
            "    challenge += control.recv(32 - len(challenge))\n"
            "ack = b'SITINA_ITEM_FRAMEWORK_ACK_V1:' + hashlib.sha256(challenge).hexdigest().encode() + b'\\n'\n"
            "control.sendall(ack)\n"
            "os._exit(70)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-forged-framework-control"
        )
        self.assertFalse(evidence.accepted, evidence.mapping())
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 0, evidence.mapping())
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

    def test_target_cannot_forge_framework_completion_with_sigstop(self) -> None:
        target = self.workspace / "forged_framework_sigstop.py"
        target.write_text(
            "import os, signal\n"
            "def value():\n"
            "    \"\"\"\n"
            "    >>> value()\n"
            "    1\n"
            "    \"\"\"\n"
            "    return 2\n"
            "os.write(1, b'1\\n')\n"
            "os.kill(os.getpid(), signal.SIGSTOP)\n"
            "os._exit(70)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-forged-framework-sigstop"
        )
        self.assertFalse(evidence.accepted, evidence.mapping())
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 0, evidence.mapping())
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

    def test_incomplete_item_observations_fail_closed(self) -> None:
        target = self.workspace / "incomplete_observations.py"
        target.write_text(
            "import base64, json, os, sys\n"
            "def value():\n"
            "    \"\"\">>> value()\n    1\n    \"\"\"\n"
            "    return 1\n"
            "encoded_request = sys.argv[sys.argv.index('--execute-request') + 1]\n"
            "request = json.loads(base64.urlsafe_b64decode(encoded_request))\n"
            "response = {'schema': 'SITINA_SANDBOX_TEST_OBSERVATIONS_V1', 'mode': 'tests', "
            "'test_plan_hash': request['test_plan_hash'], 'observations': [], 'worker_ok': True}\n"
            "encoded = base64.urlsafe_b64encode(json.dumps(response, sort_keys=True, "
            "separators=(',', ':')).encode()).decode()\n"
            "os.write(1, ('SITINA_SANDBOX_EXECUTOR_RESULT:' + encoded + '\\n').encode())\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-incomplete-observations"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.executed_test_count, 0)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)

    def test_target_cannot_submit_complete_matching_item_observations(self) -> None:
        target = self.workspace / "complete_matching_observations.py"
        target.write_text(
            "import base64, hashlib, json, os, sys\n"
            "from pathlib import Path\n"
            "def real_failure():\n"
            "    \"\"\">>> real_failure()\n    True\n    \"\"\"\n"
            "    return False\n"
            "canonical = lambda value: json.dumps(value, sort_keys=True, "
            "separators=(',', ':')).encode()\n"
            "if '--execute-request' in sys.argv:\n"
            "    encoded_request = sys.argv[sys.argv.index('--execute-request') + 1]\n"
            "    request = json.loads(base64.urlsafe_b64decode(encoded_request))\n"
            "else:\n"
            "    path = Path(__file__).resolve()\n"
            "    identity = {'source': 'real_failure()\\n', 'want': 'True\\n', "
            "'exc_msg': None, 'options': []}\n"
            "    fingerprint = hashlib.sha256(canonical(identity)).hexdigest()\n"
            "    example = {'index': 0, 'fingerprint': fingerprint, 'want': 'True\\n', "
            "'exc_msg': None, 'options': []}\n"
            "    planned = {'index': 0, 'path': str(path), 'mode': 'doctest', "
            "'source_hash': hashlib.sha256(path.read_bytes()).hexdigest(), 'expected_count': 1, "
            "'planned_test_ids': [], 'planned_examples': [example]}\n"
            "    plan = {'schema': 'SITINA_TRUSTED_TEST_PLAN_V1', 'targets': [planned], "
            "'collected_test_count': 1}\n"
            "    request = {'test_plan': plan, "
            "'test_plan_hash': hashlib.sha256(canonical(plan)).hexdigest()}\n"
            "planned = request['test_plan']['targets'][0]\n"
            "example = planned['planned_examples'][0]\n"
            "observation = {'index': example['index'], 'fingerprint': example['fingerprint'], "
            "'attempted': True, 'stdout': example['want'], 'exception_type': None, "
            "'exception_text': None}\n"
            "response = {'schema': 'SITINA_SANDBOX_TEST_OBSERVATIONS_V1', 'mode': 'tests', "
            "'test_plan_hash': request['test_plan_hash'], 'observations': [{'path': planned['path'], "
            "'mode': planned['mode'], 'examples': [observation]}], 'worker_ok': True}\n"
            "encoded = base64.urlsafe_b64encode(json.dumps(response, sort_keys=True, "
            "separators=(',', ':')).encode()).decode()\n"
            "os.write(1, ('SITINA_SANDBOX_EXECUTOR_RESULT:' + encoded + '\\n').encode())\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-complete-matching-observations"
        )
        self.assertFalse(evidence.accepted)
        self.assertEqual(evidence.collected_test_count, 1)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.failed_test_count + evidence.error_test_count, 0)
        self.assertNotEqual(evidence.runner_return_code, 0)

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

    def test_target_cannot_authenticate_synchronous_forged_success(self) -> None:
        target = self.workspace / "test_synchronous_forged_worker_result.py"
        target.write_text(
            "import base64, hashlib, json, os, sys, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_real_failure(self): self.fail('must be observed')\n"
            "request = json.loads(base64.urlsafe_b64decode(sys.argv[sys.argv.index('--request') + 1]))\n"
            "planned = request['test_plan']['targets'][0]\n"
            "counts = {'collected': 1, 'executed': 1, 'passed': 1, 'failed': 0, "
            "'skipped': 0, 'errors': 0, 'expected_failures': 0, 'unexpected_successes': 0}\n"
            "response = {'schema': 'SITINA_SANDBOX_TEST_RESULT_V1', 'mode': 'tests', "
            "'test_plan_hash': request['test_plan_hash'], 'counts': counts, "
            "'targets': [{'path': planned['path'], 'mode': planned['mode'], 'counts': counts}], "
            "'worker_ok': True}\n"
            "canonical = json.dumps(response, sort_keys=True, separators=(',', ':')).encode()\n"
            "encoded = base64.urlsafe_b64encode(canonical).decode()\n"
            "os.write(1, ('SITINA_SANDBOX_WORKER_RESULT:' + encoded + '\\n').encode())\n"
            "challenge = os.read(0, 256).split(b':', 1)[1].strip()\n"
            "unkeyed = hashlib.sha256(challenge + b'\\0' + canonical).hexdigest()\n"
            "os.write(1, ('SITINA_SANDBOX_WORKER_PROOF:' + unkeyed + '\\n').encode())\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-synchronous-forged-worker-result"
        )
        self.assertFalse(evidence.accepted)
        self.assertTrue(evidence.controller_protocol_response_present)
        self.assertEqual(evidence.passed_test_count, 0)
        self.assertGreater(evidence.error_test_count, 0)

    def test_target_cannot_frame_walk_to_sign_a_forged_pass(self) -> None:
        target = self.workspace / "test_frame_walk_forged_worker_result.py"
        target.write_text(
            "import base64, hashlib, hmac, json, os, sys, unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_real_failure(self): self.fail('must be observed')\n"
            "protocol_key = None\n"
            "request = None\n"
            "for current in sys._current_frames().values():\n"
            "    while current is not None:\n"
            "        local_key = current.f_locals.get('protocol_key')\n"
            "        local_request = current.f_locals.get('request')\n"
            "        if isinstance(local_key, bytes) and isinstance(local_request, dict):\n"
            "            protocol_key = local_key\n"
            "            request = local_request\n"
            "            break\n"
            "        current = current.f_back\n"
            "    if protocol_key is not None:\n"
            "        break\n"
            "if protocol_key is not None:\n"
            "    planned = request['test_plan']['targets'][0]\n"
            "    counts = {'collected': 1, 'executed': 1, 'passed': 1, 'failed': 0, "
            "'skipped': 0, 'errors': 0, 'expected_failures': 0, 'unexpected_successes': 0}\n"
            "    response = {'schema': 'SITINA_SANDBOX_TEST_RESULT_V1', 'mode': 'tests', "
            "'test_plan_hash': request['test_plan_hash'], 'counts': counts, "
            "'targets': [{'path': planned['path'], 'mode': planned['mode'], 'counts': counts}], "
            "'worker_ok': True}\n"
            "    canonical = json.dumps(response, sort_keys=True, separators=(',', ':')).encode()\n"
            "    encoded = base64.urlsafe_b64encode(canonical).decode()\n"
            "    os.write(1, ('SITINA_SANDBOX_WORKER_RESULT:' + encoded + '\\n').encode())\n"
            "    challenge = os.read(0, 256).split(b':', 1)[1].strip()\n"
            "    proof = hmac.digest(protocol_key, challenge + b'\\0' + canonical, 'sha256').hex()\n"
            "    os.write(1, ('SITINA_SANDBOX_WORKER_PROOF:' + proof + '\\n').encode())\n"
            "    os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-frame-walk-forged-worker-result"
        )
        self.assertFalse(evidence.accepted)
        self.assertGreater(evidence.failed_test_count + evidence.error_test_count, 0)

    def test_target_cannot_forge_inner_result_and_exit_zero(self) -> None:
        target = self.workspace / "inner_result_forgery.py"
        target.write_text(
            "import base64, json, os, sys\n"
            "def real_failure():\n"
            "    \"\"\">>> real_failure()\n    True\n    \"\"\"\n"
            "    return False\n"
            "encoded_request = sys.argv[sys.argv.index('--execute-request') + 1]\n"
            "request = json.loads(base64.urlsafe_b64decode(encoded_request))\n"
            "planned = request['test_plan']['targets'][0]\n"
            "counts = {'collected': 1, 'executed': 1, 'passed': 1, 'failed': 0, "
            "'skipped': 0, 'errors': 0, 'expected_failures': 0, 'unexpected_successes': 0}\n"
            "response = {'schema': 'SITINA_SANDBOX_TEST_RESULT_V1', 'mode': 'tests', "
            "'test_plan_hash': request['test_plan_hash'], 'counts': counts, "
            "'targets': [{'path': planned['path'], 'mode': planned['mode'], 'counts': counts}], "
            "'worker_ok': True}\n"
            "canonical = json.dumps(response, sort_keys=True, separators=(',', ':')).encode()\n"
            "encoded = base64.urlsafe_b64encode(canonical).decode()\n"
            "os.write(1, ('SITINA_SANDBOX_EXECUTOR_RESULT:' + encoded + '\\n').encode())\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        evidence = ExecutionSandboxRunner(home=self.home).run_tests(
            [target], run_id="sandbox-inner-result-forgery"
        )
        self.assertFalse(evidence.accepted)
        self.assertGreater(evidence.failed_test_count + evidence.error_test_count, 0)

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
        target = self.workspace / "background_thread.py"
        target.write_text(
            "import threading, time\n"
            "def value():\n"
            "    \"\"\">>> value()\n    1\n    \"\"\"\n"
            "    return 1\n"
            "threading.Thread(target=lambda: time.sleep(30), daemon=True).start()\n",
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
            repository = Path(__file__).resolve().parents[1]
            registry = AgentRegistry.load(repository)
            raw_policy = json.loads(
                (repository / "config/true_multi_agent_policy.json").read_text(
                    encoding="utf-8"
                )
            )
            policy_hash = hashlib.sha256(
                json.dumps(
                    raw_policy,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            moment = int(time.time())
            authority = AuthorityResolution(
                AuthorityState.JOURNAL_WRITER_AUTHORIZED,
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "execution-identity-test",
                moment - 5,
                moment + 120,
                "test journal authority",
            )
            execution_identity = ExecutionIdentityBinding.from_registry(
                registry,
                policy_hash=policy_hash,
                authority_resolution=authority,
                proposer_id="agent-atlas",
                executor_id="forge-execution-role",
                verifier_id="agent-delta",
                now=moment,
            )
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
            executor = {
                "schema": "SITINA_SANDBOX_EXECUTOR_BINDING_V1",
                "sandbox_executable": str(runner),
                "python_executable": str(python),
                "worker_path": str(worker),
                "sandbox_policy": profile,
                "sandbox_policy_hash": hashlib.sha256(profile.encode("utf-8")).hexdigest(),
            }
            request = base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "resource_limits": dict(limits),
                        "test_plan_hash": test_plan_hash,
                        "executor": executor,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).decode("ascii")
            argv = (
                str(python), "-I", "-S", str(worker), "--request", request
            )
            capability = issue_frozen_sandbox_execution_capability(
                authority,
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
                expires_at=moment + 30,
                proposer_id=execution_identity.proposer_id,
                executor_id=execution_identity.executor_id,
                verifier_id=execution_identity.verifier_id,
                identity_binding=execution_identity,
                agent_registry=registry,
                execution_policy_hash=policy_hash,
                now=moment,
            )
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    capability,
                    argv=argv,
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    authority_resolution=authority,
                    identity_binding=execution_identity,
                    agent_registry=registry,
                    execution_policy_hash=policy_hash,
                    now=capability.expires_at,
                ):
                    pass
            capability = issue_frozen_sandbox_execution_capability(
                authority,
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
                expires_at=moment + 30,
                proposer_id=execution_identity.proposer_id,
                executor_id=execution_identity.executor_id,
                verifier_id=execution_identity.verifier_id,
                identity_binding=execution_identity,
                agent_registry=registry,
                execution_policy_hash=policy_hash,
                now=moment,
            )
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    capability,
                    argv=argv + ("altered",),
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    authority_resolution=authority,
                    identity_binding=execution_identity,
                    agent_registry=registry,
                    execution_policy_hash=policy_hash,
                    now=moment + 1,
                ):
                    pass
            tampered_values = {
                "proposer_id": "agent-borealis",
                "executor_id": "tampered-execution-role",
                "verifier_id": "agent-horizon",
                "issued_at": capability.issued_at - 1,
                "capability_id": "sandbox-execution:" + "0" * 64,
                "authority_ref": "authority-resolution:" + "0" * 64,
                "authority_resolution_id": "0" * 64,
                "registry_hash": "0" * 64,
                "execution_policy_hash": "0" * 64,
                "executor_role_authorization_ref":
                    "execution-role-authorization:" + "0" * 64,
                "proposer_registry_ref": "agent-registry-identity:" + "0" * 64,
                "verifier_registry_ref": "agent-registry-identity:" + "0" * 64,
            }
            for field, replacement in tampered_values.items():
                with self.subTest(field=field):
                    tampered = dataclasses.replace(
                        capability, **{field: replacement}
                    )
                    with self.assertRaises(LegacyWriteDenied):
                        with authorized_frozen_sandbox_execution(
                            tampered,
                            argv=argv,
                            cwd=self.workspace,
                            diff_hash=diff_hash,
                            test_plan_hash=test_plan_hash,
                            authority_resolution=authority,
                            identity_binding=execution_identity,
                            agent_registry=registry,
                            execution_policy_hash=policy_hash,
                            now=moment + 1,
                        ):
                            pass
            recomputed = dataclasses.replace(
                capability, issued_at=capability.issued_at - 1
            )
            recomputed = dataclasses.replace(
                recomputed,
                capability_id=(
                    "sandbox-execution:"
                    + _sandbox_capability_identity(recomputed)
                ),
            )
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    recomputed,
                    argv=argv,
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    authority_resolution=authority,
                    identity_binding=execution_identity,
                    agent_registry=registry,
                    execution_policy_hash=policy_hash,
                    now=moment + 1,
                ):
                    pass
            with authorized_frozen_sandbox_execution(
                capability,
                argv=argv,
                cwd=self.workspace,
                diff_hash=diff_hash,
                test_plan_hash=test_plan_hash,
                authority_resolution=authority,
                identity_binding=execution_identity,
                agent_registry=registry,
                execution_policy_hash=policy_hash,
                now=moment + 1,
            ):
                pass
            with self.assertRaises(LegacyWriteDenied):
                with authorized_frozen_sandbox_execution(
                    capability,
                    argv=argv,
                    cwd=self.workspace,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    authority_resolution=authority,
                    identity_binding=execution_identity,
                    agent_registry=registry,
                    execution_policy_hash=policy_hash,
                    now=moment + 1,
                ):
                    pass
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
