from __future__ import annotations

import unittest
from pathlib import Path

from sitina.conversation.context import ConversationContext
from sitina.conversation.models import ChatMode, ChatSession, ConversationTurn, RouteSource
from sitina.conversation.router import ConversationRouter


HOME = Path(__file__).resolve().parents[1]


class ConversationRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.router = ConversationRouter.load(HOME)
        cls.context = ConversationContext(
            max_turns=cls.router.max_context_turns,
            max_chars=cls.router.max_context_chars,
        )

    def snapshot(self, history=()):
        return self.context.snapshot(history)

    def test_default_mode_is_auto(self) -> None:
        self.assertIs(ChatSession().mode, ChatMode.AUTO)

    def test_simple_greeting_routes_auto_to_fast(self) -> None:
        decision = self.router.decide(ChatMode.AUTO, "你好", self.snapshot())
        self.assertIs(decision.resolved_mode, ChatMode.FAST)
        self.assertIs(decision.source, RouteSource.LOCAL_ROUTER)

    def test_simple_definition_routes_auto_to_fast(self) -> None:
        decision = self.router.decide(ChatMode.AUTO, "什么是 MVCC？", self.snapshot())
        self.assertIs(decision.resolved_mode, ChatMode.FAST)

    def test_comparison_routes_auto_to_multi(self) -> None:
        decision = self.router.decide(
            ChatMode.AUTO,
            "比较三种事件存储方案并给出迁移建议",
            self.snapshot(),
        )
        self.assertIs(decision.resolved_mode, ChatMode.MULTI)
        self.assertIn("多方案比较与取舍", decision.reasons)

    def test_architecture_design_routes_auto_to_multi(self) -> None:
        decision = self.router.decide(ChatMode.AUTO, "为订单系统做完整架构设计", self.snapshot())
        self.assertIs(decision.resolved_mode, ChatMode.MULTI)

    def test_security_audit_routes_auto_to_multi(self) -> None:
        decision = self.router.decide(ChatMode.AUTO, "对这套认证方案做安全审计", self.snapshot())
        self.assertIs(decision.resolved_mode, ChatMode.MULTI)

    def test_execution_requests_route_auto_to_multi_by_direct_contract(self) -> None:
        cases = (
            "帮我改一下这段代码",
            "修复这个测试失败",
            "运行测试并告诉我结果",
            "run the tests for this module",
        )
        self.assertTrue(self.router.config.get("execution_markers"))
        for message in cases:
            with self.subTest(message=message):
                decision = self.router.decide(ChatMode.AUTO, message, self.snapshot())
                self.assertIs(decision.resolved_mode, ChatMode.MULTI)
                self.assertIn("需要执行:写代码/改文件/操作电脑", decision.reasons)
                self.assertIn(
                    "execution_markers",
                    tuple(dict(decision.observability or {}).get("evidence_codes") or ()),
                )

    def test_multiple_dependent_deliverables_route_auto_to_multi(self) -> None:
        decision = self.router.decide(
            ChatMode.AUTO,
            "实现代码，同时给出测试、文档和验收标准",
            self.snapshot(),
        )
        self.assertIs(decision.resolved_mode, ChatMode.MULTI)
        self.assertIn("包含多个相互依赖的交付物", decision.reasons)

    def test_user_forced_modes_override_local_router(self) -> None:
        forced_fast = self.router.decide(ChatMode.FAST, "比较三种复杂架构", self.snapshot())
        forced_multi = self.router.decide(ChatMode.MULTI, "你好", self.snapshot())
        self.assertIs(forced_fast.resolved_mode, ChatMode.FAST)
        self.assertIs(forced_multi.resolved_mode, ChatMode.MULTI)
        self.assertIs(forced_fast.source, RouteSource.USER_FORCED)
        self.assertIs(forced_multi.source, RouteSource.USER_FORCED)

    def test_same_input_and_policy_produce_stable_decision(self) -> None:
        snapshot = self.snapshot([ConversationTurn("前问", "前答")])
        first = self.router.decide(ChatMode.AUTO, "比较 A 和 B", snapshot)
        second = self.router.decide(ChatMode.AUTO, "比较 A 和 B", snapshot)
        self.assertEqual(first, second)
        self.assertEqual(first.mapping(), second.mapping())

    def test_context_is_limited_to_six_turns_and_12000_characters(self) -> None:
        history = [ConversationTurn(f"问题 {index}", "答" * 3000) for index in range(9)]
        snapshot = self.snapshot(history)
        self.assertEqual(snapshot.turn_count, 6)
        self.assertLessEqual(snapshot.char_count, 12_000)
        self.assertNotIn("问题 0", snapshot.transcript)

    def test_route_decision_contains_only_bounded_reasons(self) -> None:
        decision = self.router.decide(
            ChatMode.AUTO,
            "请多 Agent 比较架构并做安全审计、交叉验证、完整实施计划，同时满足冲突约束",
            self.snapshot(),
        )
        self.assertLessEqual(len(decision.reasons), 8)
        self.assertTrue(all(0 < len(item) <= 160 for item in decision.reasons))
        self.assertEqual(len(decision.input_hash), 64)

    def test_new_context_reset_preserves_mode_and_last_route(self) -> None:
        session = ChatSession(mode=ChatMode.MULTI)
        session.last_route_decision = self.router.decide(ChatMode.MULTI, "你好", self.snapshot())
        session.history.append(ConversationTurn("问题", "回答"))
        session.last_failed_message = "失败"
        session.reset_context()
        self.assertIs(session.mode, ChatMode.MULTI)
        self.assertEqual(session.history, [])
        self.assertIsNone(session.last_failed_message)
        self.assertIsNotNone(session.last_route_decision)


if __name__ == "__main__":
    unittest.main()
