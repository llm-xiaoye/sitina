from __future__ import annotations

import os
import hashlib
import json
import socket
import stat
import subprocess
import textwrap
import time
from unittest.mock import patch
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sitina.orchestrator.code_mode_controller import CodeModeControllerError, CodeModeControllerSession, _code_mode_sandbox_profile
from sitina.orchestrator.execution_bridge import ExecutionIdentityBinding
from sitina.orchestrator.execution_sandbox import FilesystemTestEvidencePublisher
from sitina.orchestrator.execution_verification import verify_execution_diff
from sitina.orchestrator.true_multi_agent import _tester_machine_command
from sitina.storage import SitinaStore


class CodeModeWorkerBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="code-mode-worker-"))
        # Runtime bookkeeping is deliberately outside the execution workspace;
        # user-created workspace/data files must remain visible to snapshots.
        self.runtime_root = Path(tempfile.mkdtemp(prefix="code-mode-worker-state-"))
        SitinaStore(self.runtime_root).init_db()
        self.context = SimpleNamespace(
            home=self.runtime_root,
            session_instance_id="session-instance-worker",
            _broker_client=None,
            validate_execution_child_authorization=lambda *args, **kwargs: True,
        )
        self.authorization = {
            "schema": "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1",
            "authorization_ref": "execution-authorization-child:test",
            "session_id": "session-worker",
            "session_instance_id": self.context.session_instance_id,
            "run_id": "worker-run",
            "run_attempt": 1,
            "intent_hash": "i" * 64,
            "workspace": str(self.root),
            "execution_root": str(self.root),
            "scope": [str(self.root)],
            "expires_at": int(__import__("time").time()) + 120,
        }
        self.controller = CodeModeControllerSession(
            context=self.context, run_id="worker-run", session_id="session-worker",
            authorization=self.authorization, workspace=self.root, offline=True,
        )
        self.executor = self.controller.worker_executor(
            attempt=1, authorization_binding=self.authorization, workspace=self.root,
        )
        self.capability = self.executor._mint_direct_capability(
            run_id="worker-run", authorization_ref=self.authorization["authorization_ref"],
            target_repo=str(self.root), allowed_roots=[str(self.root)], purpose="test",
        )

    def tearDown(self) -> None:
        self.controller.close()
        self.assertTrue(self.executor._revoked)
        with self.assertRaises(CodeModeControllerError):
            self.executor._binding(purpose="file-write")
        for path in sorted(self.root.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        self.root.rmdir()
        for path in sorted(self.runtime_root.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        self.runtime_root.rmdir()

    def test_real_worker_write_is_observed_by_controller(self) -> None:
        result = self.executor.write_direct(
            target=str(self.root / "created.txt"), content="controller observed",
            run_id="worker-run", capability=self.capability,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual((self.root / "created.txt").read_text(), "controller observed")
        self.assertEqual(result["before_hash"], None)
        self.assertTrue(str(result["after_hash"]).startswith("sha256:"))
        self.assertEqual(len(str(result["worker_binding_hash"])), 64)

    def test_worker_rejects_escape_and_symlink(self) -> None:
        outside = self.root.parent / "worker-outside.txt"
        try:
            result = self.executor.write_direct(
                target=str(outside), content="escape", run_id="worker-run", capability=self.capability,
            )
            self.assertEqual(result["status"], "blocked")
            link = self.root / "link"
            link.symlink_to(outside)
            linked_result = self.executor.write_direct(
                target=str(link), content="link", run_id="worker-run", capability=self.capability,
            )
            self.assertEqual(linked_result["status"], "blocked")
        finally:
            if outside.exists():
                outside.unlink()

    def test_shell_mutation_is_rejected_and_new_file_is_removed(self) -> None:
        script = self.root / "mutator.py"
        script.write_text(textwrap.dedent('''
            """A deliberately mutating doctest.

            >>> from pathlib import Path
            >>> Path("leftover.txt").write_text("dirty")
            5
            """
        '''), encoding="utf-8")
        command = f"{os.sys.executable} -m doctest {script}"
        result = self.executor.execute(
            operation="shell", run_id="worker-run", agent="tester",
            target=str(self.root), cwd=str(self.root), command=command,
            allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
        )
        self.assertEqual(result["status"], "blocked")
        self.assertIn("leftover.txt", result["unregistered_paths"])
        self.assertFalse((self.root / "leftover.txt").exists())

    def test_logical_python_unittest_uses_controller_interpreter_and_canonical_binding(self) -> None:
        script = self.root / "test_logical_python.py"
        script.write_text(
            "import unittest\n\n"
            "class LogicalPythonTest(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        captured: list[dict[str, object]] = []
        original_run_worker = self.executor._run_worker

        def capture(request: dict[str, object]) -> dict[str, object]:
            captured.append(dict(request))
            return original_run_worker(request)

        with patch.object(self.executor, "_run_worker", side_effect=capture):
            result = self.executor.execute(
                operation="shell", run_id="worker-run", agent="tester",
                target=str(self.root), cwd=str(self.root),
                command=f"python -m unittest {script.name}",
                allowed_commands=["python -m unittest"], capability=self.capability,
            )

        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(len(captured), 1)
        expected_executable = str(Path(os.sys.executable).expanduser().resolve(strict=True))
        expected_argv = [expected_executable, "-m", "unittest", script.name]
        expected_hash = "sha256:" + hashlib.sha256(
            json.dumps(expected_argv, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        request = captured[0]
        self.assertEqual(request["argv"], expected_argv)
        self.assertEqual(request["argv_hash"], expected_hash)
        self.assertEqual(request["binding"]["argv_hash"], expected_hash)
        self.assertEqual(request["allowed_argv"], [[expected_executable, "-m", "unittest"]])

    def test_logical_python_policy_rejects_interpreter_aliases_and_unsafe_modules(self) -> None:
        policy = ["python -m unittest"]
        self.assertIsNotNone(
            self.executor._canonical_shell_argv(["python", "-m", "unittest"], policy)
        )
        self.assertIsNotNone(
            self.executor._canonical_shell_argv(["python3", "-m", "unittest"], policy)
        )
        self.assertIsNone(
            self.executor._canonical_shell_argv(["python3.12", "-m", "unittest"], policy)
        )
        self.assertIsNone(
            self.executor._canonical_shell_argv(["pypy3", "-m", "unittest"], policy)
        )
        self.assertIsNone(
            self.executor._canonical_shell_argv([os.sys.executable, "-m", "unittest"], policy)
        )
        self.assertIsNone(
            self.executor._canonical_shell_argv(["python", "-m", "pytest"], policy)
        )
        self.assertIsNone(
            self.executor._canonical_shell_argv(["python", "-c", "pass"], policy)
        )
        self.assertIsNone(
            self.executor._canonical_shell_argv(["python", "-m", "unittest", "--failfast"], policy)
        )
        explicit_absolute_policy = [f"{os.sys.executable} -m unittest"]
        self.assertIsNotNone(
            self.executor._canonical_shell_argv(
                [os.sys.executable, "-m", "unittest"], explicit_absolute_policy
            )
        )

    def test_python3_logical_shell_and_argv_use_sealed_interpreter(self) -> None:
        script = self.root / "test_python3_logical.py"
        script.write_text(
            "import unittest\n\n"
            "class Python3LogicalTest(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        captured: list[dict[str, object]] = []
        original_run_worker = self.executor._run_worker

        def capture(request: dict[str, object]) -> dict[str, object]:
            captured.append(dict(request))
            return original_run_worker(request)

        with patch.object(self.executor, "_run_worker", side_effect=capture):
            result = self.executor.execute(
                operation="shell", run_id="worker-run", agent="tester",
                target=str(self.root), cwd=str(self.root),
                command=f"python3 -m unittest {script.name}",
                allowed_commands=["python -m unittest"], capability=self.capability,
            )

        self.assertEqual(result["status"], "ok", result)
        expected_executable = str(Path(os.sys.executable).expanduser().resolve(strict=True))
        expected_argv = [expected_executable, "-m", "unittest", script.name]
        self.assertEqual(captured[0]["argv"], expected_argv)
        self.assertEqual(
            self.executor._canonical_shell_argv(
                ["python3", "-m", "unittest", script.name], ["python -m unittest"]
            ),
            expected_argv,
        )

    def test_changed_unittest_file_produces_hash_bound_worker_evidence(self) -> None:
        source = self.root / "hello.py"
        target = self.root / "test_hello.py"
        source.write_text("def hello():\n    return 'hello'\n", encoding="utf-8")
        target.write_text(
            "import unittest\n"
            "from hello import hello\n\n"
            "class HelloTests(unittest.TestCase):\n"
            "    def test_hello(self):\n"
            "        self.assertEqual(hello(), 'hello')\n",
            encoding="utf-8",
        )
        identity = ExecutionIdentityBinding.fixture(verifier_id="agent-delta")
        verdict = verify_execution_diff(
            [str(source), str(target)],
            "agent-delta",
            {},
            run_id="worker-unittest-evidence",
            home=self.runtime_root,
            identity_binding=identity,
            fixture_authorization=True,
            evidence_publisher=FilesystemTestEvidencePublisher(self.runtime_root / "test-evidence"),
            worker_executor=self.executor,
        )
        self.assertTrue(verdict.accepted, verdict.reasons)
        self.assertTrue(verdict.checked_tests)
        self.assertTrue(verdict.test_evidence_ref)
        evidence_path = self.runtime_root / "test-evidence" / f"{verdict.test_evidence_hash}.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["runner_argv"][1:3], ["-m", "unittest"])
        self.assertEqual(evidence["runner_argv"][3:], ["test_hello.py"])
        self.assertEqual(evidence["collected_test_count"], 1)
        self.assertEqual(evidence["executed_test_count"], 1)
        self.assertEqual(evidence["passed_test_count"], 1)
        self.assertEqual(evidence["failed_test_count"], 0)
        self.assertEqual(evidence["skipped_test_count"], 0)
        self.assertEqual(evidence["error_test_count"], 0)
        self.assertFalse(evidence["timed_out"])
        self.assertEqual(evidence["diff_hash_before"], evidence["diff_hash_after"])
        self.assertEqual(
            evidence["trust_boundary"]["execution_contract"],
            "HASH_BOUND_UTF8_UNITTEST_TARGET_AST_PLAN_V1",
        )
        projected = _tester_machine_command(evidence, ["test_hello.py"])
        self.assertEqual(projected, evidence["runner_argv"])
        self.assertNotIn("python-doctest-supervisor", projected)

    def test_unchanged_baseline_unittest_is_executed_without_diff_membership(self) -> None:
        """Existing untracked tests remain executable evidence, never mutation."""
        source = self.root / "hello.py"
        target = self.root / "test_hello.py"
        source.write_text("def hello():\n    return 'hello'\n", encoding="utf-8")
        target.write_text(
            "import unittest\n"
            "from hello import hello\n\n"
            "class HelloTests(unittest.TestCase):\n"
            "    def test_hello(self):\n"
            "        self.assertEqual(hello(), 'hello')\n",
            encoding="utf-8",
        )
        target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        identity = ExecutionIdentityBinding.fixture(verifier_id="agent-delta")
        verdict = verify_execution_diff(
            [str(source)],
            "agent-delta",
            {},
            run_id="worker-baseline-unittest",
            home=self.runtime_root,
            identity_binding=identity,
            fixture_authorization=True,
            execution_root=self.root,
            baseline_test_inventory=(
                {"relative_path": "test_hello.py", "sha256": target_hash},
            ),
            evidence_publisher=FilesystemTestEvidencePublisher(self.runtime_root / "test-evidence-baseline"),
            worker_executor=self.executor,
        )
        self.assertTrue(verdict.accepted, verdict.reasons)
        evidence = json.loads(
            (self.runtime_root / "test-evidence-baseline" / f"{verdict.test_evidence_hash}.json").read_text()
        )
        self.assertEqual(evidence["runner_argv"][1:3], ["-m", "unittest"])
        self.assertEqual(evidence["runner_argv"][3:], ["test_hello.py"])
        self.assertEqual(evidence["target_hashes"], [[str(source.resolve()), hashlib.sha256(source.read_bytes()).hexdigest()]])
        self.assertEqual(evidence["collected_test_count"], 1)
        self.assertEqual(evidence["executed_test_count"], 1)
        self.assertEqual(evidence["passed_test_count"], 1)
        self.assertEqual(evidence["failed_test_count"], 0)

    def test_unittest_worker_failure_and_malformed_summary_fail_closed(self) -> None:
        source = self.root / "hello.py"
        target = self.root / "test_hello.py"
        source.write_text("def hello():\n    return 'wrong'\n", encoding="utf-8")
        target.write_text(
            "import unittest\n"
            "from hello import hello\n\n"
            "class HelloTests(unittest.TestCase):\n"
            "    def test_hello(self):\n"
            "        self.assertEqual(hello(), 'hello')\n",
            encoding="utf-8",
        )
        identity = ExecutionIdentityBinding.fixture(verifier_id="agent-delta")
        verdict = verify_execution_diff(
            [str(source), str(target)],
            "agent-delta",
            {},
            run_id="worker-unittest-failure",
            home=self.runtime_root,
            identity_binding=identity,
            fixture_authorization=True,
            evidence_publisher=FilesystemTestEvidencePublisher(self.runtime_root / "test-evidence-failure"),
            worker_executor=self.executor,
        )
        self.assertFalse(verdict.accepted)
        self.assertTrue(verdict.test_evidence_ref)

        original_shell = self.executor._shell
        try:
            self.executor._shell = lambda *args, **kwargs: {
                "status": "ok", "exit_code": 0, "timed_out": False,
                "output_hash": "sha256:output", "argv": [os.sys.executable, "-m", "unittest", "test_hello.py"],
                "unittest_result": None,
            }
            malformed = verify_execution_diff(
                [str(source), str(target)],
                "agent-delta",
                {},
                run_id="worker-unittest-malformed",
                home=self.runtime_root,
                identity_binding=identity,
                fixture_authorization=True,
                evidence_publisher=FilesystemTestEvidencePublisher(self.runtime_root / "test-evidence-malformed"),
                worker_executor=self.executor,
            )
            self.assertFalse(malformed.accepted)
            self.assertFalse(malformed.checked_tests)
            self.assertTrue(malformed.reasons)
        finally:
            self.executor._shell = original_shell

    def test_unittest_worker_error_is_counted_and_rejected(self) -> None:
        source = self.root / "hello.py"
        target = self.root / "test_hello.py"
        source.write_text("def hello():\n    return 'hello'\n", encoding="utf-8")
        target.write_text(
            "import unittest\n\n"
            "class ErrorTests(unittest.TestCase):\n"
            "    def test_error(self):\n"
            "        raise RuntimeError('boom')\n",
            encoding="utf-8",
        )
        identity = ExecutionIdentityBinding.fixture(verifier_id="agent-delta")
        verdict = verify_execution_diff(
            [str(source), str(target)],
            "agent-delta",
            {},
            run_id="worker-unittest-error",
            home=self.runtime_root,
            identity_binding=identity,
            fixture_authorization=True,
            evidence_publisher=FilesystemTestEvidencePublisher(self.runtime_root / "test-evidence-error"),
            worker_executor=self.executor,
        )
        self.assertFalse(verdict.accepted)
        self.assertTrue(verdict.test_evidence_ref)
        evidence = json.loads(
            (self.runtime_root / "test-evidence-error" / f"{verdict.test_evidence_hash}.json").read_text()
        )
        self.assertEqual(evidence["error_test_count"], 1)
        self.assertEqual(evidence["failed_test_count"], 0)

    def test_unittest_worker_timeout_fails_closed(self) -> None:
        source = self.root / "hello.py"
        target = self.root / "test_hello.py"
        source.write_text("def hello():\n    return 'hello'\n", encoding="utf-8")
        target.write_text("import unittest\nclass TimeoutTests(unittest.TestCase):\n    def test_timeout(self): pass\n", encoding="utf-8")
        original_shell = self.executor._shell
        try:
            self.executor._shell = lambda *args, **kwargs: {
                "status": "blocked", "exit_code": 124, "timed_out": True,
                "output_hash": "sha256:timeout", "argv": [os.sys.executable, "-m", "unittest", "test_hello.py"],
                "unittest_result": None,
            }
            verdict = verify_execution_diff(
                [str(source), str(target)],
                "agent-delta",
                {},
                run_id="worker-unittest-timeout",
                home=self.runtime_root,
                identity_binding=ExecutionIdentityBinding.fixture(verifier_id="agent-delta"),
                fixture_authorization=True,
                evidence_publisher=FilesystemTestEvidencePublisher(self.runtime_root / "test-evidence-timeout"),
                worker_executor=self.executor,
            )
            self.assertFalse(verdict.accepted)
            self.assertFalse(verdict.checked_tests)
            self.assertTrue(verdict.reasons)
        finally:
            self.executor._shell = original_shell

    def test_workspace_data_file_mutation_is_observed_not_ignored(self) -> None:
        data = self.root / "data"
        data.mkdir()
        target = data / "user.txt"
        target.write_text("before", encoding="utf-8")
        script = self.root / "data-mutator.py"
        script.write_text(textwrap.dedent('''
            """User data is part of the execution workspace.

            >>> from pathlib import Path
            >>> Path("data/user.txt").write_text("dirty")
            5
            """
        '''), encoding="utf-8")
        result = self.executor.execute(
            operation="shell", run_id="worker-run", agent="tester", target=str(self.root),
            cwd=str(self.root), command=f"{os.sys.executable} -m doctest {script}",
            allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
        )
        self.assertEqual(result["status"], "blocked", result)
        self.assertIn("data/user.txt", result["unregistered_paths"])
        self.assertEqual(target.read_text(encoding="utf-8"), "before")

    def test_shell_rejected_existing_file_is_restored_from_controller_memory(self) -> None:
        target = self.root / "existing.txt"
        target.write_text("original", encoding="utf-8")
        script = self.root / "existing-mutator.py"
        script.write_text(textwrap.dedent('''
            """A doctest that changes a pre-existing file.

            >>> from pathlib import Path
            >>> Path("existing.txt").write_text("dirty")
            5
            """
        '''), encoding="utf-8")
        command = f"{os.sys.executable} -m doctest {script}"
        result = self.executor.execute(
            operation="shell", run_id="worker-run", agent="tester", target=str(self.root),
            cwd=str(self.root), command=command,
            allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
        )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["rollback_status"], "complete")
        self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_allowed_doctest_with_failed_restore_is_reported_dirty(self) -> None:
        target = self.root / "dirty.txt"
        target.write_text("original", encoding="utf-8")
        script = self.root / "failed-restore.py"
        script.write_text(textwrap.dedent('''
            """A doctest used to exercise failed recovery.

            >>> from pathlib import Path
            >>> Path("dirty.txt").write_text("dirty")
            5
            """
        '''), encoding="utf-8")
        with patch.object(self.executor, "_restore_snapshot", side_effect=OSError("synthetic restore failure")):
            result = self.executor.execute(
                operation="shell", run_id="worker-run", agent="tester", target=str(self.root),
                cwd=str(self.root), command=f"{os.sys.executable} -m doctest {script}",
                allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
            )
        self.assertEqual(result["status"], "dirty")
        self.assertEqual(result["rollback_status"], "failed")
        self.assertEqual(target.read_text(encoding="utf-8"), "dirty")

    def test_allowed_doctest_network_is_denied_by_seatbelt(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        script = self.root / "network-probe.py"
        script.write_text(textwrap.dedent(f'''
            """Network access must be denied by the worker Seatbelt.

            >>> import socket
            >>> try:
            ...     socket.create_connection(({host!r}, {port}), timeout=1)
            ... except PermissionError:
            ...     print("seatbelt-network-denied")
            seatbelt-network-denied
            """
        '''), encoding="utf-8")
        try:
            result = self.executor.execute(
                operation="shell", run_id="worker-run", agent="tester", target=str(self.root),
                cwd=str(self.root), command=f"{os.sys.executable} -m doctest {script}",
                allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
            )
        finally:
            listener.settimeout(0.1)
            try:
                listener.accept()
                accepted = True
            except (socket.timeout, OSError):
                accepted = False
            listener.close()
        self.assertEqual(result["status"], "ok", result)
        self.assertFalse(accepted)

    def test_allowed_doctest_cannot_write_outside_controller_workspace(self) -> None:
        outside = self.root.parent / "production-sentinel-write.txt"
        # Prime the controller's own audit database before the shell snapshot;
        # that state is controller bookkeeping, not an unregistered tester
        # mutation to be rolled back.
        self.executor._record_direct_audit(
            "test_setup", {}, run_id="worker-run", risk_scan_id="setup", authorization_ref="setup",
            exit_status="ok",
        )
        script = self.root / "outside-write.py"
        script.write_text(textwrap.dedent(f'''
            """The worker Seatbelt must deny writes outside its declared root.

            >>> from pathlib import Path
            >>> try:
            ...     Path({str(outside)!r}).write_text("must-not-land")
            ... except PermissionError:
            ...     print("seatbelt-write-denied")
            seatbelt-write-denied
            """
        '''), encoding="utf-8")
        try:
            result = self.executor.execute(
                operation="shell", run_id="worker-run", agent="tester", target=str(self.root),
                cwd=str(self.root), command=f"{os.sys.executable} -m doctest {script}",
                allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
            )
            self.assertEqual(result["status"], "ok", result)
            self.assertFalse(outside.exists())
        finally:
            if outside.exists():
                outside.unlink()

    def test_allowed_doctest_timeout_reaps_tester_process_group(self) -> None:
        script = self.root / "timeout.py"
        script.write_text(textwrap.dedent('''
            """Bounded timeout fixture.

            >>> import time
            >>> time.sleep(20)
            """
        '''), encoding="utf-8")
        result = self.executor.execute(
            operation="shell", run_id="worker-run", agent="tester", target=str(self.root),
            cwd=str(self.root), command=f"{os.sys.executable} -m doctest {script}",
            allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
        )
        self.assertEqual(result["status"], "blocked", result)
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["process_group_reaped"])

    def test_allowed_doctest_fork_is_bounded_and_reaped(self) -> None:
        script = self.root / "fork.py"
        script.write_text(textwrap.dedent('''
            """A forked child must not outlive the tester boundary.

            >>> import os, time
            >>> child = os.fork()
            >>> if child == 0:
            ...     time.sleep(20)
            ... else:
            ...     print("forked")
            forked
            """
        '''), encoding="utf-8")
        result = self.executor.execute(
            operation="shell", run_id="worker-run", agent="tester",
            target=str(self.root), cwd=str(self.root), command=f"{os.sys.executable} -m doctest {script}",
            allowed_commands=[f"{os.sys.executable} -m doctest"], capability=self.capability,
        )
        self.assertIn(result["status"], {"blocked", "failed"}, result)
        self.assertTrue(result["process_group_reaped"], result)

    def test_worker_has_no_provider_or_authority_environment(self) -> None:
        os.environ["DEEPSEEK_API_KEY"] = "test-secret-that-must-not-cross"
        try:
            argv = [
                os.sys.executable, "-m", "unittest", "--help",
            ]
            argv_hash = "sha256:" + hashlib.sha256(json.dumps(argv, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            observation = self.executor._run_worker({
                "schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "shell",
                "argv": argv, "cwd": str(self.root),
                "allowed_argv": [[os.sys.executable, "-c"]],
                "binding": self.executor._binding(purpose="tester-command", argv_hash=argv_hash),
                "argv_hash": argv_hash,
            })
            self.assertEqual(observation["status"], "ok")
            self.assertNotIn("test-secret-that-must-not-cross", str(observation.get("output")))
            self.assertTrue(observation["secret_env_absent"])
            fd_values = {int(item["fd"]) for item in observation["fd_inventory"]}
            control_fd = int(observation["control_fd"])
            self.assertEqual(fd_values, {0, 1, 2, control_fd})
            self.assertNotIn(control_fd, {0, 1, 2})
            self.assertGreater(int(observation["worker_pid"]), 0)
        finally:
            os.environ.pop("DEEPSEEK_API_KEY", None)

    def test_worker_does_not_inherit_authority_provider_journal_or_bootstrap_fds(self) -> None:
        leaked = []
        try:
            for name in ("authority.sock", "provider.key", "journal.sqlite", "bootstrap.secret"):
                path = self.root / name
                path.write_text(name, encoding="utf-8")
                handle = path.open("rb")
                info = os.fstat(handle.fileno())
                identity = (
                    f"{stat.S_IFMT(info.st_mode)}:{stat.S_IMODE(info.st_mode)}:"
                    f"{info.st_dev}:{info.st_ino}:{info.st_rdev}"
                )
                leaked.append((handle, hashlib.sha256(identity.encode("ascii")).hexdigest()))
            argv = [os.sys.executable, "-m", "unittest", "--help"]
            argv_hash = "sha256:" + hashlib.sha256(
                json.dumps(argv, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest()
            observation = self.executor._run_worker({
                "schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "shell",
                "argv": argv, "cwd": str(self.root),
                "binding": self.executor._binding(purpose="tester-command", argv_hash=argv_hash),
                "argv_hash": argv_hash,
            })
            inherited_identities = {
                str(item.get("identity_hash")) for item in observation["fd_inventory"]
            }
            self.assertTrue(all("target_hash" not in item for item in observation["fd_inventory"]))
            self.assertTrue(observation["secret_env_absent"])
            self.assertTrue(
                all(identity not in inherited_identities for _handle, identity in leaked)
            )
        finally:
            for handle, _fd in leaked:
                handle.close()

    def _launch_worker_with_extra_fd(self, extra_fd: int) -> tuple[int, dict[str, object]]:
        """Use the real worker launcher and deliberately pass one extra FD."""
        worker = Path(__file__).parents[1] / "scripts" / "code_mode_worker.py"
        argv = [os.sys.executable, "-m", "unittest", "--help"]
        argv_hash = "sha256:" + hashlib.sha256(
            json.dumps(argv, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        parent, child = socket.socketpair()
        control_fd = child.fileno()
        binding = {
            "schema": "CODE_MODE_WORKER_BINDING_V1",
            "controller_pid": os.getpid(),
            "session_id": "launcher-session",
            "run_id": "launcher-run",
            "child_run_id": "launcher-run",
            "intent_hash": "i" * 64,
            "workspace": str(self.root),
            "workspace_dev": int(os.stat(self.root, follow_symlinks=False).st_dev),
            "workspace_inode": int(os.stat(self.root, follow_symlinks=False).st_ino),
            "expires_at": int(time.time()) + 120,
            "purpose": "tester-command",
            "read_roots": [str(self.root)],
            "write_roots": [str(self.root)],
            "runner_hash": hashlib.sha256(worker.read_bytes()).hexdigest(),
            "operation_id": "launcher-operation-1234",
            "nonce": "n" * 64,
            "argv_hash": argv_hash,
            "control_fd": control_fd,
        }
        request = {
            "schema": "CODE_MODE_WORKER_REQUEST_V1",
            "operation": "shell",
            "argv": argv,
            "argv_hash": argv_hash,
            "cwd": str(self.root),
            "control_fd": control_fd,
            "binding": binding,
        }
        profile = _code_mode_sandbox_profile(
            python_executable=Path(os.sys.executable), worker_script=worker,
            read_roots=(self.root,), write_roots=(self.root,), allow_fork=True,
        )
        command = [
            "/usr/bin/sandbox-exec", "-p", profile, "--", os.sys.executable,
            str(worker), "--control-fd", str(control_fd),
        ]
        process = subprocess.Popen(
            command, cwd=str(self.root), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, pass_fds=(control_fd, extra_fd),
            env={
                "PATH": "/usr/bin:/bin", "HOME": str(self.root),
                "TMPDIR": str(self.root / ".tmp"),
                "PYTHONDONTWRITEBYTECODE": "1", "SITINA_CODE_MODE_WORKER": "1",
            },
        )
        child.close()
        try:
            parent.sendall((json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode())
            parent.shutdown(socket.SHUT_WR)
            parent.settimeout(10)
            line = parent.makefile("rb").readline()
            response = json.loads(line.decode("utf-8")) if line else {}
            returncode = process.wait(timeout=10)
            return returncode, response
        finally:
            parent.close()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def test_worker_launcher_rejects_extra_pipe_fd(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            returncode, response = self._launch_worker_with_extra_fd(read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertEqual(returncode, 77, response)
        self.assertEqual(response.get("reason_code"), "FD_INVENTORY_NOT_EXACT")
        self.assertEqual(response.get("status"), "blocked")

    def test_worker_launcher_rejects_dup_dev_null_fd(self) -> None:
        extra_fd = os.open(os.devnull, os.O_RDONLY)
        try:
            returncode, response = self._launch_worker_with_extra_fd(extra_fd)
        finally:
            os.close(extra_fd)
        self.assertEqual(returncode, 77, response)
        self.assertEqual(response.get("reason_code"), "FD_INVENTORY_NOT_EXACT")
        self.assertEqual(response.get("status"), "blocked")

    def test_worker_binding_is_one_use_and_attempt_bound(self) -> None:
        target = self.root / "one-use.txt"
        binding = self.executor._binding(purpose="file-write")
        request = {
            "schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "write",
            "path": str(target), "content": "one", "expected_before_hash": None,
            "binding": binding,
        }
        self.assertEqual(self.executor._run_worker(request)["status"], "ok")
        with self.assertRaises(CodeModeControllerError):
            self.executor._run_worker(request)
        tampered = self.executor._binding(purpose="file-write")
        tampered["attempt"] = 2
        with self.assertRaises(CodeModeControllerError):
            self.executor._run_worker({**request, "binding": tampered})

    def test_code_mode_profile_is_deny_default_and_no_network(self) -> None:
        profile = _code_mode_sandbox_profile(
            python_executable=Path(os.sys.executable),
            worker_script=self.controller._worker_script,
            read_roots=(self.root,), write_roots=(self.root,), allow_fork=False,
        )
        self.assertIn("(deny default)", profile)
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny process-fork)", profile)
        self.assertNotIn("sitina.legacy", profile)

    def test_offline_controller_can_never_enter_authoritative_canary_gate(self) -> None:
        self.assertFalse(self.controller.authoritative)
        with self.assertRaises(CodeModeControllerError):
            self.controller.assert_canary_access(self.context, self.authorization)
