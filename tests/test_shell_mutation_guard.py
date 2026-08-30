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
