from __future__ import annotations

import argparse
import io
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sitina import cli
from sitina.conversation.models import ChatMode, RouteDecision, RouteSource
from sitina.orchestrator.true_multi_agent import render_selected_user_response


def decision(mode: ChatMode, resolved: ChatMode | None = None) -> RouteDecision:
    actual = resolved or (ChatMode.FAST if mode is ChatMode.AUTO else mode)
    return RouteDecision(
        requested_mode=mode,
        resolved_mode=actual,
        source=RouteSource.LOCAL_ROUTER if mode is ChatMode.AUTO else RouteSource.USER_FORCED,
        reasons=("简单问题",) if actual is ChatMode.FAST else ("用户强制 MULTI",),
        policy_version="test-v1",
        input_hash="a" * 64,
    )


def successful_execute(session, message, *, status_callback=None):
    session.begin_turn(message)
    route = decision(session.mode)
    session.last_route_decision = route
    if status_callback:
        status_callback("route", route.mapping())
    result = {
        "run_id": "run-test",
        "terminal_state": "SUCCEEDED",
        "response": f"回答：{message}",
        "resolved_mode": route.resolved_mode.value,
    }
    session.record_success(message, result["response"])
    return result


class InteractiveChatCliTests(unittest.TestCase):
    def test_selected_proposal_is_rendered_for_terminal(self) -> None:
        self.assertEqual(
            render_selected_user_response({"summary": "结论", "approach": "具体说明"}),
            "结论\n\n具体说明",
        )

    def test_no_argument_non_tty_launcher_prints_help_without_blocking(self) -> None:
        launcher = Path("/Users/moss/SitinaHub/bin/sitina").read_text(encoding="utf-8")
        no_argument_branch = launcher.split("if [[ $# -eq 0 ]]; then", 1)[1].split("fi", 1)[0]
        self.assertIn("[[ -t 0 && -t 1 ]]", no_argument_branch)
        self.assertIn("set -- chat", no_argument_branch)
        self.assertIn("set -- --help", no_argument_branch)

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_chat_starts_in_auto_and_exits_zero(self, runtime_type: Mock, _installed: Mock, _production: Mock) -> None:
        runtime_type.return_value.execute_turn.side_effect = successful_execute
        runtime_type.return_value.resume_or_create_session.return_value = None
        output = io.StringIO()
        with patch("builtins.input", side_effect=["你好", "/exit"]) as user_input, patch("sys.stdout", output):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        self.assertEqual(user_input.call_args_list[0].args[0], "你 [auto] > ")
        self.assertIn("当前模式：AUTO", output.getvalue())
        self.assertIn("→ FAST · 单 Agent", output.getvalue())

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_chat_resumes_durable_session_before_prompt(
        self, runtime_type: Mock, _installed: Mock, _production: Mock
    ) -> None:
        from sitina.conversation.models import ChatSession, ConversationTurn

        recovered = ChatSession(
            session_id="chat-session-recovered",
            mode=ChatMode.MULTI,
            turn_index=3,
            history=[ConversationTurn("prior", "answer")],
        )
        runtime_type.return_value.resume_or_create_session.return_value = recovered
        output = io.StringIO()
        with patch("builtins.input", side_effect=["/exit"]) as user_input, patch("sys.stdout", output):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        self.assertEqual(user_input.call_args_list[0].args[0], "你 [multi] > ")
        self.assertIn("已恢复会话", output.getvalue())

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_mode_commands_override_auto_and_auto_restores_it(
        self, runtime_type: Mock, _installed: Mock, _production: Mock
    ) -> None:
        seen_modes = []

        def execute(session, message, *, status_callback=None):
            seen_modes.append(session.mode)
            return successful_execute(session, message, status_callback=status_callback)

        runtime_type.return_value.execute_turn.side_effect = execute
        output = io.StringIO()
        inputs = ["/multi", "你好", "/mode", "/new", "/fast", "复杂问题", "/auto", "你好", "/exit"]
        with patch("builtins.input", side_effect=inputs), patch("sys.stdout", output):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        self.assertEqual(seen_modes, [ChatMode.MULTI, ChatMode.FAST, ChatMode.AUTO])
        self.assertEqual(
            [call.args[1] for call in runtime_type.return_value.persist_mode.call_args_list],
            [ChatMode.MULTI, ChatMode.FAST, ChatMode.AUTO],
        )
        text = output.getvalue()
        self.assertIn("已切换到 MULTI", text)
        self.assertIn("上一轮实际路由：MULTI", text)
        self.assertIn("已开始新会话；当前模式仍为 MULTI", text)
        self.assertIn("已恢复 AUTO", text)

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_retry_only_reexecutes_last_failed_message(
        self, runtime_type: Mock, _installed: Mock, _production: Mock
    ) -> None:
        calls = []

        def execute(session, message, *, status_callback=None):
            calls.append(message)
            session.begin_turn(message)
            route = decision(session.mode)
            session.last_route_decision = route
            if status_callback:
                status_callback("route", route.mapping())
            if len(calls) == 1:
                session.record_failure(message, run_id="failed-run")
                return {"run_id": "failed-run", "terminal_state": "FAILED", "response": "", "error_type": "NetworkError"}
            session.record_success(message, "已恢复")
            return {"run_id": "success-run", "terminal_state": "SUCCEEDED", "response": "已恢复"}

        runtime_type.return_value.execute_turn.side_effect = execute
        output = io.StringIO()
        errors = io.StringIO()
        with patch("builtins.input", side_effect=["原消息", "/retry", "/retry", "/exit"]), patch(
            "sys.stdout", output
        ), patch("sys.stderr", errors):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        self.assertEqual(calls, ["原消息", "原消息"])
        self.assertIn("没有可重试", output.getvalue())
        self.assertIn("本轮未加入对话上下文", errors.getvalue())

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_ctrl_c_does_not_retry_and_preserves_failed_message(
        self, runtime_type: Mock, _installed: Mock, _production: Mock
    ) -> None:
        calls = []

        def execute(session, message, *, status_callback=None):
            calls.append(message)
            raise KeyboardInterrupt

        runtime_type.return_value.execute_turn.side_effect = execute
        output = io.StringIO()
        with patch("builtins.input", side_effect=["取消我", "/exit"]), patch("sys.stdout", output):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        self.assertEqual(calls, ["取消我"])
        self.assertIn("未自动重发", output.getvalue())

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_help_lists_every_command(self, runtime_type: Mock, _installed: Mock, _production: Mock) -> None:
        output = io.StringIO()
        with patch("builtins.input", side_effect=["/help", "/exit"]), patch("sys.stdout", output):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        text = output.getvalue()
        for command in ("/fast", "/multi", "/auto", "/mode", "/new", "/retry", "/help", "/exit", "/quit"):
            self.assertIn(command, text)
        runtime_type.return_value.execute_turn.assert_not_called()

    @patch("sitina.cli._is_production_home", return_value=True)
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ConversationRuntime")
    def test_auto_command_is_persisted_without_provider_execution(
        self, runtime_type: Mock, _installed: Mock, _production: Mock
    ) -> None:
        from sitina.conversation.models import ChatSession

        session = ChatSession(session_id="chat-session-mode-only", mode=ChatMode.FAST)
        runtime_type.return_value.resume_or_create_session.return_value = session
        with patch("builtins.input", side_effect=["/auto", "/exit"]), patch("sys.stdout", io.StringIO()):
            self.assertEqual(cli.cmd_chat(argparse.Namespace()), 0)
        runtime_type.return_value.persist_mode.assert_called_once_with(session, ChatMode.AUTO)
        runtime_type.return_value.execute_turn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
