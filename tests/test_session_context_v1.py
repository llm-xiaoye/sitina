from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.cas.local import LocalCAS
from sitina.conversation.context import ConversationContext, ContextPolicy, TokenAwareContextRenderer
from sitina.conversation.models import ChatMode, ConversationTurn
from sitina.conversation.persistence import JournalSessionRepository
from sitina.conversation.router import ConversationRouter, ConversationRouterError
from sitina.journal.local import LocalJournal
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class SessionAndContextV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.keys)

    def test_user_message_is_cas_published_and_journal_committed_before_effect(self) -> None:
        cas = LocalCAS.open(self.home, self.keys)
        journal = LocalJournal.open(self.home, self.auth)
        repository = JournalSessionRepository(journal, cas, self.keys)
        repository.ensure_created(
            session_id="session-1",
            title="Conversation",
            created_at="2026-07-18T00:00:00Z",
        )
        message = repository.append_message(
            session_id="session-1",
            message_id="message-1",
            role="user",
            body="persist me before Provider",
            turn_index=1,
            created_at="2026-07-18T00:00:01Z",
        )
        events = tuple(journal.iter_events(0))
        message_event = next(item for item in events if item.event_type == "session.message-appended")
        self.assertEqual(message_event.payload["body_ref"], message.body_ref)
        self.assertNotIn("body", message_event.payload)
        self.assertEqual(cas.open_verified(message.object_ref).decode(), "persist me before Provider")
        object_files = list((self.home / "cas/objects").rglob("*.obj"))
        self.assertEqual(len(object_files), 1)
        journal.close()

        recovered_journal = LocalJournal.open(self.home, self.auth)
        recovered_cas = LocalCAS.open(self.home, self.keys)
        recovered = JournalSessionRepository(recovered_journal, recovered_cas, self.keys).recover("session-1")
        self.assertEqual(recovered["messages"][0]["body"], "persist me before Provider")
        self.assertEqual(recovered["messages"][0]["role"], "user")
        recovered_journal.close()
        self.assertFalse((self.home / "state/active_conversation.json").exists())
        self.assertFalse((self.home / "logs/conversations").exists())

    def test_failed_turn_keeps_the_user_message(self) -> None:
        cas = LocalCAS.open(self.home, self.keys)
        journal = LocalJournal.open(self.home, self.auth)
        repository = JournalSessionRepository(journal, cas, self.keys)
        repository.ensure_created(session_id="session-failed", title="Failure", created_at="2026-07-18T00:00:00Z")
        repository.append_message(
            session_id="session-failed",
            message_id="message-failed",
            role="user",
            body="this must survive",
            turn_index=1,
            created_at="2026-07-18T00:00:01Z",
        )
        repository.record_turn_failed(
            session_id="session-failed",
            turn_index=1,
            error_type="ProviderReadTimeout",
            created_at="2026-07-18T00:00:02Z",
        )
        recovered = repository.recover("session-failed")
        self.assertEqual([item["body"] for item in recovered["messages"]], ["this must survive"])
        self.assertEqual(recovered["failed_turns"], [1])
        journal.close()

    def test_latest_session_recovery_includes_mode_route_runs_and_successful_turns(self) -> None:
        cas = LocalCAS.open(self.home, self.keys)
        journal = LocalJournal.open(self.home, self.auth)
        repository = JournalSessionRepository(journal, cas, self.keys)
        repository.ensure_created(
            session_id="session-restart",
            title="Conversation",
            created_at="2026-07-18T00:00:00Z",
        )
        repository.record_mode_changed(
            session_id="session-restart",
            mode="MULTI",
            created_at="2026-07-18T00:00:01Z",
        )
        route = {
            "requested_mode": "MULTI",
            "resolved_mode": "MULTI",
            "source": "user_forced",
            "reasons": ["用户强制 MULTI"],
            "policy_version": "fixture-v1",
            "input_hash": "a" * 64,
            "confidence": "1",
            "threshold": "0.65",
            "upgrade_reason": None,
            "initial_fast_decision": None,
            "decision_path": "USER_FORCED_MULTI",
        }
        repository.record_route_decision(
            session_id="session-restart",
            turn_index=1,
            decision=route,
            created_at="2026-07-18T00:00:02Z",
        )
        repository.append_message(
            session_id="session-restart",
            message_id="session-restart-user-1",
            role="user",
            body="persisted question",
            turn_index=1,
            created_at="2026-07-18T00:00:03Z",
        )
        repository.link_run(
            session_id="session-restart",
            run_id="multi-run-restart",
            turn_index=1,
            created_at="2026-07-18T00:00:04Z",
        )
        repository.append_message(
            session_id="session-restart",
            message_id="session-restart-assistant-1",
            role="assistant",
            body="persisted answer",
            turn_index=1,
            created_at="2026-07-18T00:00:05Z",
        )
        self.assertEqual(repository.latest_session_id(), "session-restart")
        journal.close()

        recovered_journal = LocalJournal.open(self.home, self.auth)
        recovered = JournalSessionRepository(
            recovered_journal,
            LocalCAS.open(self.home, self.keys),
            self.keys,
        ).recover("session-restart")
        self.assertEqual(recovered["mode"], "MULTI")
        self.assertEqual(recovered["turn_index"], 1)
        self.assertEqual(recovered["run_ids"], ["multi-run-restart"])
        self.assertEqual(recovered["route_decisions"][0]["decision"], route)
        self.assertEqual(
            recovered["successful_turns"],
            [{"turn_index": 1, "user": "persisted question", "assistant": "persisted answer"}],
        )
        recovered_journal.close()

    def test_context_composition_includes_durable_state_summary_and_accepted_memory(self) -> None:
        context = ConversationContext(
            policy=ContextPolicy(
                token_budget=500,
                history_token_budget=100,
                max_recent_turns=6,
                renderer_version="context-renderer-v2",
                long_context_token_threshold=400,
            )
        )
        snapshot = context.compose(
            [ConversationTurn("prior question", "prior answer")],
            current_user_message="current question",
            goal_constraints="goal: validate storage; constraint: preserve authority",
            working_state="next action: replay",
            memories=(("accepted durable memory", 900_000),),
            rolling_summary="confirmed: prior result",
        )
        self.assertIn("goal: validate storage", snapshot.transcript)
        self.assertIn("next action: replay", snapshot.transcript)
        self.assertIn("accepted durable memory", snapshot.transcript)
        self.assertIn("confirmed: prior result", snapshot.transcript)
        self.assertIn("prior question", snapshot.transcript)
        self.assertIn("current question", snapshot.transcript)
        included = {item["component"]: item["included"] for item in snapshot.component_manifest}
        self.assertTrue(all(included[name] for name in (
            "goal_constraints", "working_state", "memories", "rolling_summary", "recent_messages", "current_user_message"
        )))

    def test_token_renderer_drops_low_priority_components_not_required_content(self) -> None:
        policy = ContextPolicy(
            token_budget=80,
            history_token_budget=28,
            max_recent_turns=20,
            renderer_version="context-renderer-v2",
            long_context_token_threshold=60,
        )
        renderer = TokenAwareContextRenderer(policy)
        result = renderer.render(
            system_rules="SYSTEM RULES MUST REMAIN",
            goal_constraints="GOAL AND CONSTRAINTS MUST REMAIN",
            working_state="next action is verify",
            memories=[("low " * 80, 1), ("high value memory", 10)],
            rolling_summary="summary " * 20,
            recent_messages=["old raw " * 30, "new raw message"],
            current_user_message="CURRENT USER MESSAGE MUST REMAIN",
        )
        self.assertIn("SYSTEM RULES MUST REMAIN", result.rendered)
        self.assertIn("GOAL AND CONSTRAINTS MUST REMAIN", result.rendered)
        self.assertIn("CURRENT USER MESSAGE MUST REMAIN", result.rendered)
        self.assertNotIn("low low low", result.rendered)
        self.assertNotIn("old raw old raw", result.rendered)
        again = renderer.render(
            system_rules="SYSTEM RULES MUST REMAIN",
            goal_constraints="GOAL AND CONSTRAINTS MUST REMAIN",
            working_state="next action is verify",
            memories=[("low " * 80, 1), ("high value memory", 10)],
            rolling_summary="summary " * 20,
            recent_messages=["old raw " * 30, "new raw message"],
            current_user_message="CURRENT USER MESSAGE MUST REMAIN",
        )
        self.assertEqual(result.rendered_hash, again.rendered_hash)
        self.assertEqual(result.manifest, again.manifest)
        self.assertNotIn("rendered", result.manifest)

    def test_history_keeps_whole_turns_without_character_tail_slicing(self) -> None:
        policy = ContextPolicy(
            token_budget=100,
            history_token_budget=20,
            max_recent_turns=10,
            renderer_version="context-renderer-v2",
            long_context_token_threshold=60,
        )
        history = [
            ConversationTurn("old-user", "prefix-" + "x" * 400),
            ConversationTurn("new-user", "new-assistant"),
        ]
        snapshot = TokenAwareContextRenderer(policy).history_snapshot(history)
        self.assertNotIn("old-user", snapshot.transcript)
        self.assertNotIn("prefix-", snapshot.transcript)
        self.assertIn("User: new-user", snapshot.transcript)
        self.assertIn("Sitina: new-assistant", snapshot.transcript)

    def test_context_policy_is_single_source_and_legacy_router_conflict_fails_fast(self) -> None:
        (self.home / "config").mkdir()
        policy_path = Path(__file__).resolve().parents[1] / "config/context_policy.json"
        (self.home / "config/context_policy.json").write_text(policy_path.read_text(encoding="utf-8"), encoding="utf-8")
        router = {
            "schema": "SITINA_CONVERSATION_ROUTER_V1",
            "policy_version": "conflict",
            "max_context_turns": 10,
            "max_context_chars": 12000,
            "multi_markers": [],
            "high_risk_markers": [],
            "comparison_markers": [],
            "verification_markers": [],
            "planning_markers": [],
        }
        (self.home / "config/conversation_router.json").write_text(json.dumps(router), encoding="utf-8")
        with self.assertRaises(ConversationRouterError):
            ConversationRouter.load(self.home)

    def test_legacy_sitina_context_bound_conflicts_with_context_policy(self) -> None:
        (self.home / "config").mkdir()
        source = Path(__file__).resolve().parents[1] / "config/context_policy.json"
        (self.home / "config/context_policy.json").write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        (self.home / "config/sitina.yaml").write_text(
            json.dumps({"context": {"recent_turn_limit": 10}}), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "recent_turn_limit"):
            ContextPolicy.load(self.home)


if __name__ == "__main__":
    unittest.main()
