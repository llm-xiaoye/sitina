from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.extensions.tools import ToolCatalog, ToolRuntimeError
from sitina.orchestrator.managed_processes import ManagedProcessManager
from sitina.runners.provider import ProviderProfile, ProviderToolCall, ProviderToolTurn, ScriptedMockToolClient
from sitina.storage import SitinaStore


class ShellMutationGuardTests(unittest.TestCase):
    def test_async_managed_process_mutation_is_reconciled_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            home = Path(parent) / "home"
            workspace = Path(parent) / "workspace"
            home.mkdir()
            workspace.mkdir()
            (home / "config").mkdir()
            (home / "config" / "permissions.yaml").write_text(
                json.dumps({"tester_allowed_commands": [sys.executable], "risk_rules": []}),
                encoding="utf-8",
            )
            SitinaStore(home).init_db()
            command = [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; import signal, time; "
                    "signal.signal(signal.SIGUSR1, "
                    "lambda *_: (Path('async-leftover.txt').write_text('dirty'), "
                    "print('MUTATED', flush=True))); "
                    "print('READY', flush=True); time.sleep(5)"
                ),
            ]
            manager = ManagedProcessManager(home, workspace=workspace, run_id="async-process-guard")
            catalog = ToolCatalog(
                ExtensionManager(home),
                approval_callback=lambda request: request.permission == "shell",
                workspace=workspace,
                write_executor=None,
                managed_process_manager=manager,
            )
            catalog.bind_run("async-process-guard")
            started = catalog.execute("sitina_process_start", {"command": command})
            self.assertEqual(started.status, "ok")
            # Synchronize through the managed process's redacted log, not an
            # arbitrary sleep.  The child is deliberately held after READY;
            # SIGUSR1 is the explicit test-side authorization to perform the
            # unregistered mutation, and MUTATED is its acknowledgement.
            deadline = time.monotonic() + 2.0
            log_text = ""
            while time.monotonic() < deadline:
                try:
                    log_text = manager.log(started.value["process_id"]) ["text"]
                except (FileNotFoundError, OSError):
                    log_text = ""
                if "READY" in log_text:
                    break
                time.sleep(0.01)
            self.assertIn("READY", log_text)
            os.kill(int(started.value["pid"]), signal.SIGUSR1)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    log_text = manager.log(started.value["process_id"])["text"]
                except (FileNotFoundError, OSError):
                    log_text = ""
                if "MUTATED" in log_text:
                    break
                time.sleep(0.01)
            self.assertIn("MUTATED", log_text)
            with self.assertRaises(ToolRuntimeError):
                catalog.reconcile_managed_processes()
            self.assertFalse((workspace / "async-leftover.txt").exists())

        # The native path owns its command in Journal before dispatch. It
        # uses the same finite no-fork sandbox, not the legacy Popen manager.
        from types import SimpleNamespace
        from sitina.loop import LoopBackend, InputKind
        from sitina.loop.model import CompletionProposal, TaskStatus
        from sitina.loop.task_runtime import LoopOperationAdapter, LoopTaskRunner
        from sitina.loop.command_runner import observe_command_evidence
        from sitina.security.macos_keychain import MemoryKeychainBackend

        for ordinal, closure in enumerate(("explicit-stop", "input-invalidation", "backend-drain", "terminal-cancel"), 1):
            with tempfile.TemporaryDirectory(prefix="sitina-native-managed-") as parent:
                root = Path(parent)
                home = root / "home"
                workspace = root / "workspace"
                home.mkdir()
                workspace.mkdir()
                (home / "config").mkdir()
                (home / "config" / "permissions.yaml").write_text(
                    json.dumps({"tester_allowed_commands": ["python -m unittest"], "risk_rules": []}),
                    encoding="utf-8",
                )
                SitinaStore(home).init_db()
                artifact = workspace / "delivery.txt"
                artifact.write_text("ACCEPTED", encoding="utf-8")
                (workspace / "test_native_owned.py").write_text(
                    "import os,time,unittest\nfrom pathlib import Path\n"
                    "class Owned(unittest.TestCase):\n"
                    " def test_owned(self):\n"
                    "  out=Path(os.environ['SITINA_CHECK_OUTPUT'])\n"
                    "  try:\n"
                    "   Path(" + repr(str(artifact)) + ").write_text('EARLY-WRITE')\n"
                    "  except PermissionError:\n"
                    "   print('NATIVE_WRITE_DENIED',flush=True)\n"
                    "  else:\n"
                    "   raise AssertionError('business workspace was writable')\n"
                    "  print('NATIVE_READY',flush=True)\n"
                    "  while not (out/'release').exists(): time.sleep(0.02)\n"
                    "  (out/'late-attempted').write_text('attempted')\n"
                    "  Path(" + repr(str(artifact)) + ").write_text('LATE-WRITE')\n",
                    encoding="utf-8",
                )
                state = root / "native-state"
                keys = MemoryKeychainBackend()
                completed_owners = []
                with LoopBackend.open(state, keychain_backend=keys) as backend:
                    task_id = "native-managed-owner"
                    backend.create_task(
                        task_id=task_id, session_id="native-managed-session", task_kind="code_change",
                        goal="preserve the business artifact while controlling the owned command",
                        required_outcome_ids=("outcome-1",), artifact_ref="cas:unit-artifact",
                        environment_ref="unit-environment", capability_snapshot_id="unit-capabilities",
                    )
                    boundary = SimpleNamespace(
                        state_root=state, business_workspace=workspace,
                        interpreter=Path(sys.executable).resolve(strict=True),
                    )
                    runner = LoopTaskRunner(boundary, approve_writes=True)
                    catalog = ToolCatalog(
                        ExtensionManager(home), workspace=workspace,
                        approval_callback=lambda request: request.permission == "shell",
                        strict_workspace=True,
                    )
                    catalog.bind_loop_shell_description()
                    catalog.bind_run("native-managed-turn")

                    def new_adapter():
                        adapter = LoopOperationAdapter(backend, task_id, workspace)
                        adapter.bind_shell_runtime(
                            authorizer=catalog.authorize_for_loop, executor=runner._shell_tool_call,
                        )
                        return adapter

                    def invoke(adapter, call_id, name, arguments):
                        return adapter.tool_call(
                            "native-managed-turn", ProviderToolCall(call_id=call_id, name=name, arguments=arguments),
                            lambda: (_ for _ in ()).throw(AssertionError("legacy dispatch must not run")),
                            permission=catalog.get(name).permission,
                        )

                    adapter = new_adapter()
                    start = invoke(adapter, "start-" + str(ordinal), "sitina_process_start", {
                        "command": ["python", "-m", "unittest", "test_native_owned"],
                        "timeout_seconds": 30,
                    })
                    self.assertEqual(start.status, "ok")
                    self.assertEqual(start.value["state"], "running")
                    process_id = start.value["process_id"]
                    owner = backend.managed_process_evidence(task_id)[process_id]
                    self.assertTrue(owner["managed_process"])
                    self.assertEqual(owner["command_policy"], "COMMAND_FENCED_NO_FORK_V1")
                    self.assertIn("(deny process-fork)", json.loads(Path(owner["command_manifest_path"]).read_text())["profile"])
                    events = backend.store.task_events(task_id)
                    intent_index = next(i for i,e in enumerate(events) if e.event_type=="loop.operation-intent-recorded" and e.payload.get("operation_id")==process_id)
                    dispatch_index = next(i for i,e in enumerate(events) if e.event_type=="loop.operation-dispatch-started" and e.payload.get("operation_id")==process_id)
                    self.assertLess(intent_index, dispatch_index)
                    # A fresh adapter represents the next native tool turn;
                    # it must consume the same durable owner without respawn.
                    next_adapter = new_adapter()
                    status = invoke(next_adapter, "status-" + str(ordinal), "sitina_process_status", {"process_id": process_id})
                    self.assertEqual(status.value["state"], "running")
                    deadline = time.monotonic() + 5.0
                    log = ""
                    attempt = 0
                    while time.monotonic() < deadline and "NATIVE_READY" not in log:
                        attempt += 1
                        observed = invoke(next_adapter, "log-" + str(ordinal) + "-" + str(attempt), "sitina_process_log", {"process_id": process_id})
                        log = str(observed.value.get("stdout", "")) + str(observed.value.get("stderr", ""))
                        if "NATIVE_READY" not in log:
                            time.sleep(0.05)
                    self.assertIn("NATIVE_READY", log)
                    self.assertIn("NATIVE_WRITE_DENIED", log)
                    self.assertEqual(artifact.read_text(), "ACCEPTED")
                    if closure == "explicit-stop":
                        stopped = invoke(next_adapter, "stop-" + str(ordinal), "sitina_process_stop", {"process_id": process_id})
                        self.assertEqual(stopped.value["state"], "stopped")
                    elif closure == "input-invalidation":
                        backend.accept_input(task_id, input_id="native-owner-correction", kind=InputKind.CORRECTION, body="retain the artifact")
                        backend.handle_next_input(task_id, derive_effects_from_record=True)
                    elif closure == "terminal-cancel":
                        backend.accept_input(task_id, input_id="native-terminal-cancel", kind=InputKind.CANCEL, body="cancel this owned command")
                        backend.handle_next_input(task_id, derive_effects_from_record=True)
                        task = backend.get_task(task_id)
                        proposal = CompletionProposal(
                            proposal_id="native-managed-terminal-proposal", terminal_status=TaskStatus.CANCELLED,
                            expected_task_revision=task.task_revision, expected_run_instance_id=task.run_instance_id,
                            expected_execution_epoch=task.execution_epoch, expected_goal_version=task.goal_version,
                            expected_acceptance_version=task.acceptance_version,
                            expected_received_input_seq=task.received_input_seq,
                            expected_handled_input_seq=task.handled_input_seq, artifact_ref=task.artifact_ref,
                            final_result={"reason": "requested cancellation"},
                        )
                        terminal = backend.propose_terminal(task_id, proposal)
                        self.assertEqual(terminal.status, TaskStatus.CANCELLED)
                        terminal_events = [event for event in backend.store.task_events(task_id) if event.event_type == "loop.task-terminated"]
                        self.assertEqual(len(terminal_events), 1)
                        terminal_doc = backend.context_memory.read(terminal_events[0].payload["result_ref"])
                        refs = terminal_doc["managed_process_observations"]
                        self.assertEqual([item["operation_id"] for item in refs], [process_id])
                        saved = backend.context_memory.read(refs[0]["observation_ref"])["observation"]
                        actual = observe_command_evidence(owner, task_id=task_id, operation_id=process_id)
                        self.assertIsInstance(actual["manifest"]["timeout_seconds"], float)
                        self.assertIsInstance(actual["completion"]["completed_at"], float)
                        self.assertEqual(saved["manifest"]["timeout_seconds"], repr(actual["manifest"]["timeout_seconds"]))
                        self.assertEqual(saved["completion"]["completed_at"], repr(actual["completion"]["completed_at"]))
                        for field in ("manifest_raw_b64", "completion_raw_b64", "manifest_hash", "completion_hash"):
                            self.assertEqual(saved[field], actual[field])
                    completed_owners.append((task_id, process_id, dict(owner)))
                # Closing this backend settles the last owner before losing the
                # in-memory handle. Completion is proven from nonce-bound receipts.
                for owner_task_id, process_id, owner in completed_owners:
                    receipt = observe_command_evidence(owner, task_id=owner_task_id, operation_id=process_id)
                    self.assertEqual(receipt["decision"], "SUCCEEDED")
                    self.assertEqual(receipt["completion"]["status"], "CANCELLED")
                    output = Path(receipt["manifest"]["output_root"])
                    (output / "release").write_text("after-stop", encoding="utf-8")
                    self.assertFalse((output / "late-attempted").exists())
                self.assertEqual(artifact.read_text(), "ACCEPTED")

    def test_allowed_test_command_that_mutates_workspace_is_not_successful_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            home = Path(parent) / "home"
            workspace = Path(parent) / "workspace"
            home.mkdir()
            workspace.mkdir()
            (home / "config").mkdir()
            (home / "config" / "permissions.yaml").write_text(
                json.dumps({"tester_allowed_commands": [f"{sys.executable} -c"], "risk_rules": []}),
                encoding="utf-8",
            )
            SitinaStore(home).init_db()
            command = f"{sys.executable} -c \"from pathlib import Path; Path('unregistered.txt').write_text('dirty')\""
            client = ScriptedMockToolClient(
                [
                    ProviderToolTurn(
                        "run test",
                        (ProviderToolCall("shell-1", "sitina_shell", {"command": command}),),
                        "tool_calls",
                        {},
                    ),
                    ProviderToolTurn("done", (), "stop", {}),
                ]
            )
            runtime = AutonomousRuntime(
                home,
                client=client,
                profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
                approval_callback=lambda request: request.permission == "shell",
                workspace=workspace,
            )
            result = runtime.run_embedded("run the test", run_id="shell-guard")
            tool_result = result["tool_results"][0]
            self.assertEqual(tool_result["status"], "error")
            self.assertEqual(result["external_mutation_count"], 1)
            self.assertIn("unregistered.txt", json.dumps(tool_result, ensure_ascii=False))
            self.assertFalse((workspace / "unregistered.txt").exists())
            self.assertEqual(tool_result["result"]["rollback_status"], "complete")

    def test_shell_command_not_in_tester_allowlist_is_blocked_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            home = Path(parent) / "home"
            workspace = Path(parent) / "workspace"
            home.mkdir()
            workspace.mkdir()
            (home / "config").mkdir()
            (home / "config" / "permissions.yaml").write_text(
                json.dumps({"tester_allowed_commands": ["python -m unittest"], "risk_rules": []}),
                encoding="utf-8",
            )
            SitinaStore(home).init_db()
            marker = workspace / "should-not-exist.txt"
            command = f"python -c \"from pathlib import Path; Path('{marker.name}').write_text('no')\""
            client = ScriptedMockToolClient(
                [
                    ProviderToolTurn(
                        "run test",
                        (ProviderToolCall("shell-1", "sitina_shell", {"command": command}),),
                        "tool_calls",
                        {},
                    ),
                    ProviderToolTurn("done", (), "stop", {}),
                ]
            )
            runtime = AutonomousRuntime(
                home,
                client=client,
                profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
                approval_callback=lambda request: request.permission == "shell",
                workspace=workspace,
            )
            result = runtime.run_embedded("run the test", run_id="shell-allowlist")
            self.assertEqual(result["tool_results"][0]["status"], "error")
            self.assertFalse(marker.exists())

    def test_allowlisted_command_creating_symlink_is_detected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            home = Path(parent) / "home"
            workspace = Path(parent) / "workspace"
            home.mkdir()
            workspace.mkdir()
            (workspace / "target.txt").write_text("target", encoding="utf-8")
            (home / "config").mkdir()
            (home / "config" / "permissions.yaml").write_text(
                json.dumps({"tester_allowed_commands": [f"{sys.executable} -c"], "risk_rules": []}),
                encoding="utf-8",
            )
            SitinaStore(home).init_db()
            command = f"{sys.executable} -c \"from pathlib import Path; Path('link.txt').symlink_to('target.txt')\""
            client = ScriptedMockToolClient(
                [
                    ProviderToolTurn(
                        "run test",
                        (ProviderToolCall("shell-1", "sitina_shell", {"command": command}),),
                        "tool_calls",
                        {},
                    ),
                    ProviderToolTurn("done", (), "stop", {}),
                ]
            )
            runtime = AutonomousRuntime(
                home,
                client=client,
                profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
                approval_callback=lambda request: request.permission == "shell",
                workspace=workspace,
            )
            result = runtime.run_embedded("run the test", run_id="shell-symlink-guard")
            self.assertEqual(result["tool_results"][0]["status"], "error")
            self.assertEqual(result["external_mutation_count"], 1)
            self.assertIn("link.txt", json.dumps(result["tool_results"][0], ensure_ascii=False))
            self.assertFalse((workspace / "link.txt").exists())


if __name__ == "__main__":
    unittest.main()
