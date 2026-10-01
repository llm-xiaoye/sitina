from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sitina import cli
from sitina.loop.control import LoopAuthorityError


class RetiredChatCliTests(unittest.TestCase):
    def test_current_launcher_defaults_to_auto_loop_and_keeps_non_tty_help(self) -> None:
        launcher_path = Path(__file__).resolve().parents[1] / "bin" / "sitina"
        launcher = launcher_path.read_text(encoding="utf-8")
        marker_branch = 'if [[ -f "$SCRIPT_ROOT/.sitina-r4-development-root-v1.json" ]]; then'
        no_argument_branch = launcher.split("if [[ $# -eq 0 ]]; then", 1)[1].split("fi", 1)[0]

        self.assertIn(marker_branch, launcher)
        self.assertLess(launcher.index("if [[ $# -eq 0 ]]; then"), launcher.index(marker_branch))
        self.assertIn("[[ -t 0 && -t 1 ]]", no_argument_branch)
        self.assertIn("set -- loop", no_argument_branch)
        self.assertNotIn("set -- chat", no_argument_branch)
        self.assertIn("set -- --help", no_argument_branch)
        self.assertIn('SITINA_HOME="${SITINA_HOME:-$SCRIPT_ROOT}"', launcher)
        self.assertIn('export SITINA_SOURCE_ROOT="$SCRIPT_ROOT"', launcher)
        self.assertIn('export SITINA_PYTHON="$PYTHON_BIN"', launcher)

    def test_owned_loop_host_lifecycle_drains_without_force(self) -> None:
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 130

        failures = cli._drain_owned_loop_host_processes([process], timeout=0.25)

        self.assertEqual(failures, ())
        process.send_signal.assert_called_once_with(cli.signal.SIGINT)
        process.wait.assert_called_once_with(timeout=0.25)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

        clean_process = Mock()
        clean_process.poll.return_value = 0
        self.assertEqual(cli._drain_owned_loop_host_processes([clean_process]), ())
        clean_process.send_signal.assert_not_called()
        clean_process.wait.assert_not_called()
        self.assertEqual(
            cli._owned_loop_host_exit_failure(None),
            "owned Host exit could not be confirmed",
        )

        failed_process = Mock()
        failed_process.poll.return_value = 1
        self.assertEqual(
            cli._drain_owned_loop_host_processes([failed_process]),
            ("owned Host exited without a graceful drain (return code 1)",),
        )

        interrupted_process = Mock()
        interrupted_process.poll.return_value = None
        interrupted_process.wait.return_value = -2
        self.assertEqual(
            cli._drain_owned_loop_host_processes([interrupted_process]),
            ("owned Host exited without a graceful drain (return code -2)",),
        )

        vanished_process = Mock()
        vanished_process.poll.return_value = None
        vanished_process.send_signal.side_effect = ProcessLookupError()
        vanished_process.wait.return_value = 1
        self.assertEqual(
            cli._drain_owned_loop_host_processes([vanished_process]),
            ("owned Host exited without a graceful drain (return code 1)",),
        )
        vanished_process.wait.assert_called_once_with(timeout=30.0)

        slow_process = Mock()
        slow_process.poll.return_value = None
        slow_process.wait.side_effect = cli.subprocess.TimeoutExpired(
            "sitina-loop-host",
            0.01,
        )
        failures = cli._drain_owned_loop_host_processes([slow_process], timeout=0.01)
        self.assertEqual(
            failures,
            ("owned Host is still draining; no force termination was attempted",),
        )
        slow_process.terminate.assert_not_called()
        slow_process.kill.assert_not_called()

    def test_submission_records_spawned_host_before_retry(self) -> None:
        root = Path("/tmp/sitina-loop-ownership-test")
        boundary = SimpleNamespace(
            state_root=root / "state",
            source_root=root,
            business_workspace=root / "workspace",
            interpreter=Path(sys.executable).resolve(),
            interpreter_entry=Path(sys.executable),
        )
        process = Mock()
        owned: list[Mock] = []
        with patch(
            "sitina.loop.control.send_control_request",
            side_effect=[LoopAuthorityError("absent"), KeyboardInterrupt()],
        ), patch.object(cli.subprocess, "Popen", return_value=process) as popen:
            with self.assertRaises(KeyboardInterrupt):
                cli._submit_loop_task(
                    boundary,
                    {"command": "submit"},
                    provider_profile="deepseek",
                    approve_writes=False,
                    owned_host_processes=owned,
                )

        self.assertEqual(owned, [process])
        self.assertEqual(popen.call_args.args[0][0], str(boundary.interpreter_entry))
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertIs(popen.call_args.kwargs["stderr"], None)
        self.assertIs(popen.call_args.kwargs["stdout"], cli.subprocess.DEVNULL)

    def test_submission_surfaces_terminal_host_startup_failure_without_waiting(self) -> None:
        root = Path("/tmp/sitina-loop-startup-failure-test")
        boundary = SimpleNamespace(
            state_root=root / "state",
            source_root=root,
            business_workspace=root / "workspace",
            interpreter=Path(sys.executable).resolve(),
            interpreter_entry=Path(sys.executable),
        )
        process = Mock()
        process.poll.return_value = 17
        owned: list[Mock] = []
        with patch(
            "sitina.loop.control.send_control_request",
            side_effect=[LoopAuthorityError("absent"), LoopAuthorityError("still absent")],
        ), patch.object(cli.subprocess, "Popen", return_value=process) as popen, patch.object(
            cli.time,
            "sleep",
        ) as sleep:
            with self.assertRaisesRegex(
                LoopAuthorityError,
                "Loop Host exited during startup .*return code 17.*task submission was not confirmed",
            ):
                cli._submit_loop_task(
                    boundary,
                    {"command": "submit"},
                    provider_profile="deepseek",
                    approve_writes=False,
                    owned_host_processes=owned,
                )

        self.assertEqual(owned, [process])
        self.assertEqual(popen.call_args.args[0][0], str(boundary.interpreter_entry))
        process.poll.assert_called_once_with()
        sleep.assert_not_called()
        self.assertIs(popen.call_args.kwargs["stderr"], None)
        self.assertIs(popen.call_args.kwargs["stdout"], cli.subprocess.DEVNULL)

    def test_loop_exit_closes_no_preexisting_host_and_surfaces_drain_failure(self) -> None:
        args = SimpleNamespace()
        with patch.object(cli, "_run_loop_session", return_value=0) as session, patch.object(
            cli,
            "_drain_owned_loop_host_processes",
            return_value=(),
        ) as drain:
            self.assertEqual(cli.cmd_loop(args), 0)
        owned = session.call_args.args[1]
        self.assertEqual(owned, [])
        drain.assert_called_once_with(owned)

        error = io.StringIO()
        with patch.object(cli, "_run_loop_session", return_value=0), patch.object(
            cli,
            "_drain_owned_loop_host_processes",
            return_value=("owned Host is still draining; no force termination was attempted",),
        ), patch("sys.stderr", error):
            self.assertEqual(cli.cmd_loop(args), 3)
        self.assertIn("exit is incomplete", error.getvalue())

    def test_retired_chat_rejects_before_state_workspace_or_runtime_access(self) -> None:
        secret_profile = "secret-profile-name-must-not-be-echoed"
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            workspace = base / "must-not-be-created-workspace"
            state = base / "must-not-be-created-state"
            output = io.StringIO()
            with patch.object(
                cli.LegacyRuntimePolicy,
                "load",
                side_effect=AssertionError("retired chat must not read runtime policy or user state"),
            ) as policy_load, patch.object(
                cli,
                "_build_code_mode_runtime",
                side_effect=AssertionError("retired chat must not bootstrap CodeMode or a Provider"),
            ) as runtime_build, patch(
                "builtins.input",
                side_effect=AssertionError("retired chat must not request interactive input"),
            ), patch("sys.stdout", output):
                exit_code = cli.main(
                    [
                        "chat",
                        "--workspace",
                        str(workspace),
                        "--code-mode-state",
                        str(state),
                        "--offline-scripted",
                        "--access-mode",
                        "full",
                        "--profile",
                        secret_profile,
                        "--live",
                        "--allow-self-modify",
                    ]
                )

            self.assertEqual(exit_code, 3)
            policy_load.assert_not_called()
            runtime_build.assert_not_called()
            self.assertFalse(workspace.exists())
            self.assertFalse(state.exists())

        rendered = output.getvalue()
        self.assertNotIn(secret_profile, rendered)
        self.assertNotIn(str(workspace), rendered)
        self.assertNotIn(str(state), rendered)
        payload = json.loads(rendered)
        self.assertEqual(payload["schema"], "SITINA_RETIRED_CHAT_ENTRY_V1")
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["retired_modes"], ["FAST", "MULTI"])
        for field in (
            "automatic_reinterpretation",
            "replacement_dispatched",
            "task_created",
            "host_started",
            "workspace_inspected",
            "workspace_created",
            "journal_mutated",
            "cas_mutated",
            "user_state_read",
            "user_state_migrated",
        ):
            self.assertIs(payload[field], False)
        self.assertEqual(payload["provider_call_count"], 0)
        self.assertEqual(payload["physical_requests"], 0)

    def test_loop_and_suggest_parsers_are_auto_only(self) -> None:
        parser = cli.build_parser()
        loop_args = parser.parse_args(["loop"])
        self.assertIs(loop_args.func, cli.cmd_loop)
        self.assertIsNone(loop_args.state_root)
        self.assertIsNone(loop_args.workspace)
        self.assertFalse(hasattr(loop_args, "mode"))

        defaults = parser.parse_args(["suggest", "inspect routing"])
        self.assertEqual(defaults.sla_class, "standard")
        self.assertFalse(hasattr(defaults, "mode"))
        self.assertFalse(hasattr(defaults, "prior_mode"))

        explicit = parser.parse_args(
            [
                "suggest",
                "inspect routing",
                "--sla-class",
                "interactive",
            ]
        )
        self.assertEqual(explicit.sla_class, "interactive")
        for option, value in (("--mode", "MULTI"), ("--prior-mode", "FAST")):
            with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(["suggest", "inspect routing", option, value])


if __name__ == "__main__":
    unittest.main()
