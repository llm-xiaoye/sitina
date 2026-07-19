from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.conversation.context import ConversationContext
from sitina.conversation.fast_runtime import FastConversationError, FastConversationRuntime, validate_fast_answer
from sitina.conversation.models import ChatMode, ChatSession, RouteDecision
from sitina.conversation.router import ConversationRouter
from sitina.conversation.runtime import ConversationRuntime
from sitina.journal.local import LocalJournal
from sitina.journal.model import FrontierRef, canonical_json_bytes
from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime
from sitina.orchestrator.true_multi_agent_runtime import AgentCallResult, CanonicalStream, sha256_bytes
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


HOME = Path("/Users/moss/SitinaHub")


def fast_success(*, needs_multi: bool = False, confidence: str = "high") -> dict:
    return {
        "run_id": "fast-run-1",
        "terminal_state": "SUCCEEDED",
        "response": "未经审阅的 FAST 候选",
        "response_agent_id": "agent-forge",
        "response_output_hash": "a" * 64,
        "provider_call_count": 1,
        "provider_physical_send_count": 1,
        "provider_token_total": 17,
        "provider_cost_micro_usd": 3,
        "provider_retry_count": 0,
        "provider_fallback_count": 0,
        "proposal_competition_count": 0,
        "reviewer_call_count": 0,
        "confidence": confidence,
        "needs_multi": needs_multi,
        "escalation_recommended": needs_multi or confidence == "low",
        "escalation_reasons": ["需要独立审阅"] if needs_multi else [],
        "external_mutation_count": 0,
        "legacy_read_count": 0,
        "legacy_write_count": 0,
        "sqlite_connect_count": 0,
        "sqlite_write_count": 0,
    }


def multi_success() -> dict:
    return {
        "run_id": "multi-run-1",
        "terminal_state": "SUCCEEDED",
        "response": "MULTI 最终获胜回答",
        "response_agent_id": "agent-borealis",
        "response_output_hash": "b" * 64,
        "provider_call_count": 5,
        "provider_physical_send_count": 5,
        "provider_token_total": 80,
        "provider_cost_micro_usd": 12,
        "proposal_competition_count": 2,
        "reviewer_call_count": 2,
        "external_mutation_count": 0,
        "legacy_read_count": 0,
        "legacy_write_count": 0,
        "sqlite_connect_count": 0,
        "sqlite_write_count": 0,
    }


class FastConversationRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = ConversationRouter.load(HOME)
        self.context = ConversationContext(
            max_turns=self.router.max_context_turns,
            max_chars=self.router.max_context_chars,
        )

    def test_fast_output_schema_accepts_required_shape(self) -> None:
        parsed = validate_fast_answer(
            {
                "agent_id": "agent-forge",
                "kind": "conversation_answer",
                "answer": "答案",
                "confidence": "medium",
                "needs_multi": False,
                "escalation_reasons": [],
            }
        )
        self.assertEqual(parsed["answer"], "答案")

    def test_fast_output_schema_rejects_invalid_or_unexplained_escalation(self) -> None:
        with self.assertRaises(FastConversationError):
            validate_fast_answer(
                {
                    "answer": "答案",
                    "confidence": "certain",
                    "needs_multi": False,
                    "escalation_reasons": [],
                }
            )
        with self.assertRaises(FastConversationError):
            validate_fast_answer(
                {
                    "answer": "答案",
                    "confidence": "low",
                    "needs_multi": True,
                    "escalation_reasons": [],
                }
            )

    def test_production_fast_policy_has_a_hard_one_send_ceiling(self) -> None:
        runtime = FastConversationRuntime(HOME)
        self.assertEqual(runtime.policy["max_provider_requests_per_run"], 1)
        forge = runtime.registry.get("agent-forge")
        self.assertTrue({"proposal", "synthesis", "read-only"}.issubset(forge.capabilities))

    def test_router_uses_frozen_defaults_for_older_v1_configs(self) -> None:
        legacy_config = dict(self.router.config)
        for key in ConversationRouter.DEFAULT_SCORES:
            legacy_config.pop(key)
        router = ConversationRouter(legacy_config)
        decision = router.decide(ChatMode.AUTO, "你好", self.context.snapshot([]))
        self.assertEqual(decision.resolved_mode, ChatMode.FAST)
        self.assertEqual(decision.confidence, 0.90)
        self.assertEqual(decision.threshold, 0.65)

    def test_route_decision_canonical_mapping_contains_no_floats(self) -> None:
        decision = self.router.decide(
            ChatMode.AUTO,
            "设计企业级多 Agent 架构，比较风险并验证方案",
            self.context.snapshot([]),
        )
        canonical = decision.canonical_mapping()
        canonical_json_bytes(canonical)
        self.assertEqual(canonical["confidence"], "0.8")
        self.assertEqual(canonical["threshold"], "0.65")
        self.assertEqual(canonical["initial_fast_decision"]["multi_score"], "0.8")
        self.assertEqual(canonical["initial_fast_decision"]["threshold"], "0.65")

    def test_auto_direct_multi_evidence_is_durable_in_canonical_journal(self) -> None:
        fixture = Path(tempfile.mkdtemp())
        (fixture / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        provider = InMemoryKeyProvider()
        auth = JournalAuthProvider(provider)
        journal = LocalJournal.open(fixture, auth)
        try:
            decision = self.router.decide(
                ChatMode.AUTO,
                "设计企业级多 Agent 架构，比较模块边界、风险并交叉验证实现方案",
                self.context.snapshot([]),
            )
            self.assertEqual(decision.resolved_mode, ChatMode.MULTI)
            stream = CanonicalStream(
                journal,
                "run-auto-route-evidence",
                "run/run-auto-route-evidence",
                "2" * 64,
            )
            TrueMultiAgentProductionRuntime._record_conversation_route(
                stream,
                {
                    "interactive_chat": True,
                    "conversation_session_id": "session-auto-route-evidence",
                    "conversation_turn_index": 1,
                    "conversation_route_decision": decision.mapping(),
                },
            )
            event = next(
                item for item in journal.iter_events(0)
                if item.event_type == "conversation.route.decided"
            )
            self.assertEqual(event.payload["decision_path"], "AUTO_DIRECT_MULTI")
            self.assertEqual(event.payload["confidence"], "0.9")
            self.assertEqual(event.payload["threshold"], "0.65")
            self.assertTrue(event.payload["upgrade_reason"])
            self.assertEqual(
                event.payload["initial_fast_decision"]["decision"],
                "REJECTED_FOR_DIRECT_MULTI",
            )
            self.assertFalse(event.payload["initial_fast_decision"]["provider_evaluated"])
            event_hash = event.event_hash
            journal.close()
            journal = LocalJournal.open(fixture, auth)
            replayed = next(
                item for item in journal.iter_events(0)
                if item.event_type == "conversation.route.decided"
            )
            self.assertEqual(replayed.event_hash, event_hash)
            self.assertEqual(replayed.payload, event.payload)
        finally:
            journal.close()
            shutil.rmtree(fixture)

    def test_auto_fast_runtime_escalation_evidence_is_canonical(self) -> None:
        fixture = Path(tempfile.mkdtemp())
        (fixture / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        provider = InMemoryKeyProvider()
        journal = LocalJournal.open(fixture, JournalAuthProvider(provider))
        try:
            initial = self.router.decide(ChatMode.AUTO, "解释什么是 RAG", self.context.snapshot([]))
            self.assertEqual(initial.resolved_mode, ChatMode.FAST)
            escalated = RouteDecision.escalation(
                initial,
                ("FAST Agent 请求独立审阅",),
                fast_confidence="low",
                needs_multi=True,
            )
            stream = CanonicalStream(
                journal,
                "run-auto-fast-escalation-evidence",
                "run/run-auto-fast-escalation-evidence",
                "3" * 64,
            )
            TrueMultiAgentProductionRuntime._record_conversation_route(
                stream,
                {
                    "interactive_chat": True,
                    "conversation_session_id": "session-auto-fast-escalation-evidence",
                    "conversation_turn_index": 1,
                    "conversation_route_decision": escalated.mapping(),
                },
            )
            event = next(
                item for item in journal.iter_events(0)
                if item.event_type == "conversation.route.decided"
            )
            self.assertEqual(event.payload["decision_path"], "AUTO_FAST_RUNTIME_ESCALATION")
            self.assertEqual(event.payload["confidence"], "0.95")
            self.assertEqual(event.payload["threshold"], "0.65")
            self.assertEqual(event.payload["initial_fast_decision"]["multi_score"], "0")
            self.assertTrue(event.payload["initial_fast_decision"]["provider_evaluated"])
            self.assertEqual(
                event.payload["initial_fast_decision"]["decision"],
                "REJECTED_AFTER_PROVIDER_EVALUATION",
            )
        finally:
            journal.close()
            shutil.rmtree(fixture)

    def test_registry_scheduler_selects_exactly_one_synthesis_agent(self) -> None:
        runtime = FastConversationRuntime(HOME)
        journal = Mock()
        journal.head_position = 0
        journal.journal_id = "journal-test"
        journal.epoch = 1
        journal.iter_events.return_value = ()
        run_stream = Mock()
        agent, scheduling = runtime._schedule(journal, run_stream)
        self.assertEqual(agent.agent_id, "agent-forge")
        self.assertEqual(scheduling["selected_attempts"], ["agent-forge"])
        self.assertEqual(scheduling["required_capabilities"], ["proposal", "read-only", "synthesis"])

    def test_real_answer_admitted_path_reuses_canonical_cas_root(self) -> None:
        fixture = Path(tempfile.mkdtemp())
        (fixture / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        provider = InMemoryKeyProvider()
        auth = JournalAuthProvider(provider)
        journal = LocalJournal.open(fixture, auth)
        try:
            runtime = FastConversationRuntime(HOME)
            run_id = "fast-answer-admitted-regression"
            value = {
                "agent_id": "agent-forge",
                "kind": "conversation_answer",
                "answer": "RAG combines retrieval with generation.",
                "confidence": "high",
                "needs_multi": False,
                "escalation_reasons": [],
            }
            payload = canonical_json_bytes(value)
            cas = LocalCAS.open(fixture, provider)
            published = cas.publish_verified(encrypt_object(payload, provider, tenant_id="default"))
            output_hash = sha256_bytes(payload)
            effect_stream = CanonicalStream(
                journal,
                run_id,
                f"effect/{run_id}/provider-result",
                runtime.policy_hash,
            )
            effect_stream.append(
                "provider-result-committed",
                ({
                    "schema": "AGENT_OUTPUT_COMMITTED_V1",
                    "output_ref": published.object_ref.reference_id,
                    "output_hash": output_hash,
                    "_object_refs": [published.object_ref.reference_id],
                },),
                actor="result-admission-verifier",
                proofs=(published,),
            )
            call = AgentCallResult(
                call_id="call-fast-answer-admitted",
                run_id=run_id,
                agent_id="agent-forge",
                role="synthesis-worker",
                task_id="conversation-answer",
                task_attempt_id="attempt-fast-answer-admitted",
                effect_id="effect-fast-answer-admitted",
                effect_attempt_id="effect-attempt-fast-answer-admitted",
                provider_request_id="provider-response-fast-answer-admitted",
                input_snapshot_ref="cas:" + "1" * 64,
                input_snapshot_hash="2" * 64,
                output_ref=published.object_ref.reference_id,
                output_object_ref=published.object_ref,
                output_hash=output_hash,
                value=value,
                usage={"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
                cost_micro_usd=1,
                started_at="2026-07-18T00:00:00Z",
                completed_at="2026-07-18T00:00:01Z",
                outcome="SUCCEEDED",
                settlement="CONFIRMED_REMOTE_OBSERVATION",
            )
            run_stream = CanonicalStream(
                journal,
                run_id,
                f"run/{run_id}",
                runtime.policy_hash,
                namespace="sitina-fast-conversation-v1",
            )
            runtime._append_answer_admitted(
                journal,
                run_stream,
                call,
                value,
                escalation_recommended=False,
                escalation_allowed=True,
                escalation_reasons=[],
                logical_provider_call_count=1,
                physical_send_count=1,
            )
            answer_event = next(
                event for event in journal.iter_events(0)
                if event.event_type == "conversation.fast.answer-admitted"
            )
            self.assertEqual(answer_event.object_refs, (published.object_ref.reference_id,))
            self.assertEqual(answer_event.payload["output_hash"], output_hash)
            self.assertEqual(cas.open_verified(published.object_ref), payload)
            frontier = FrontierRef(
                journal.journal_id,
                journal.epoch,
                "local",
                journal.head_position,
                journal._position_hash[journal.head_position],
            )
            rooted = journal.lookup_existing_object_root_proof(published.object_ref, frontier)
            self.assertLess(rooted.rooted_position, answer_event.position)
            journal.close()
            journal = LocalJournal.open(fixture, auth)
            replayed = [event for event in journal.iter_events(0) if event.payload.get("run_id") == run_id]
            self.assertEqual(len(replayed), 3)
            self.assertEqual(replayed[-2].event_type, "conversation.fast.answer-admitted")
            self.assertEqual(replayed[-2].object_refs, (published.object_ref.reference_id,))
        finally:
            journal.close()
            shutil.rmtree(fixture)

    def test_canonical_stream_uses_authenticated_fast_start_stream_head(self) -> None:
        journal = Mock()
        journal.iter_events.return_value = ()
        journal._stream_heads = {"run/sealed-run": 17}
        stream = CanonicalStream(journal, "sealed-run", "run/sealed-run", "4" * 64)
        self.assertEqual(stream.version, 17)
        self.assertEqual(stream.ordinal, 17)

    def test_test_backend_does_not_touch_sqlite_or_production_authority(self) -> None:
        backend = Mock(return_value=fast_success())
        runtime = FastConversationRuntime(HOME, test_backend=backend)
        snapshot = self.context.snapshot([])
        decision = self.router.decide(ChatMode.AUTO, "你好", snapshot)
        with patch("sqlite3.connect") as connect:
            result = runtime.execute(
                "你好",
                context=snapshot,
                route_decision=decision,
                session_id="session-test",
                turn_index=1,
                allow_escalation=True,
            )
        connect.assert_not_called()
        self.assertEqual(result["provider_call_count"], 1)
        self.assertEqual(result["provider_physical_send_count"], 1)
        self.assertEqual(result["proposal_competition_count"], 0)
        self.assertEqual(result["reviewer_call_count"], 0)
        self.assertEqual(result["legacy_read_count"], 0)
        self.assertEqual(result["legacy_write_count"], 0)
        self.assertEqual(result["sqlite_connect_count"], 0)
        self.assertEqual(result["sqlite_write_count"], 0)
        self.assertEqual(result["external_mutation_count"], 0)

    def test_fast_does_not_publish_session_success_before_run_terminal(self) -> None:
        runtime = FastConversationRuntime(HOME)
        snapshot = self.context.snapshot([])
        decision = self.router.decide(ChatMode.AUTO, "你好", snapshot)
        context_runtime = Mock()
        context_runtime.open_writer.return_value = Mock()
        cas = context_runtime.open_cas.return_value
        activation = Mock()
        activation.receipt.object_ref.reference_id = "cas:" + "1" * 64
        activation.manifest_hash = "2" * 64
        executor = Mock()
        executor.call_count = 1
        executor.transport.physical_send_count = 1
        executor.call.return_value.value = {
            "agent_id": "agent-forge",
            "kind": "conversation_answer",
            "answer": "durable answer",
            "confidence": "high",
            "needs_multi": False,
            "escalation_reasons": [],
        }
        executor.call.return_value.output_object_ref = Mock()
        lifecycle = Mock()
        with (
            patch("sitina.conversation.fast_runtime.ProductionRuntimeContext.load", return_value=context_runtime),
            patch("sitina.conversation.fast_runtime.activate_runtime", return_value=activation),
            patch("sitina.conversation.fast_runtime.ProviderExecutor", return_value=executor),
            patch("sitina.conversation.fast_runtime.ConversationLifecycle", return_value=lifecycle),
            patch("sitina.conversation.fast_runtime.CanonicalStream", return_value=Mock()),
            patch.object(runtime, "_schedule", return_value=(Mock(), {})),
            patch.object(runtime, "_append_answer_admitted"),
            patch.object(runtime, "_terminalize", side_effect=RuntimeError("terminal commit failed")),
        ):
            with self.assertRaisesRegex(RuntimeError, "terminal commit failed"):
                runtime.execute(
                    "你好",
                    context=snapshot,
                    route_decision=decision,
                    session_id="session-terminal-order",
                    turn_index=1,
                    allow_escalation=False,
                )
        lifecycle.complete_turn.assert_not_called()
        lifecycle.fail_turn.assert_called_once()
        cas.verify_existing.assert_not_called()

    def test_fast_session_finalization_failure_never_reterminalizes_run(self) -> None:
        runtime = FastConversationRuntime(HOME)
        snapshot = self.context.snapshot([])
        decision = self.router.decide(ChatMode.AUTO, "你好", snapshot)
        context_runtime = Mock()
        context_runtime.open_writer.return_value = Mock()
        cas = context_runtime.open_cas.return_value
        activation = Mock()
        activation.receipt.object_ref.reference_id = "cas:" + "3" * 64
        activation.manifest_hash = "4" * 64
        executor = Mock()
        executor.call_count = 1
        executor.transport.physical_send_count = 1
        executor.call.return_value.value = {
            "agent_id": "agent-forge",
            "kind": "conversation_answer",
            "answer": "durable answer",
            "confidence": "high",
            "needs_multi": False,
            "escalation_reasons": [],
        }
        executor.call.return_value.output_object_ref = Mock()
        lifecycle = Mock()
        lifecycle.complete_turn.side_effect = RuntimeError("session finalization failed")
        terminalize = Mock(return_value={"terminal_state": "SUCCEEDED", "response": "durable answer"})
        with (
            patch("sitina.conversation.fast_runtime.ProductionRuntimeContext.load", return_value=context_runtime),
            patch("sitina.conversation.fast_runtime.activate_runtime", return_value=activation),
            patch("sitina.conversation.fast_runtime.ProviderExecutor", return_value=executor),
            patch("sitina.conversation.fast_runtime.ConversationLifecycle", return_value=lifecycle),
            patch("sitina.conversation.fast_runtime.CanonicalStream", return_value=Mock()),
            patch.object(runtime, "_schedule", return_value=(Mock(), {})),
            patch.object(runtime, "_append_answer_admitted"),
            patch.object(runtime, "_terminalize", terminalize),
        ):
            with self.assertRaisesRegex(RuntimeError, "session finalization failed"):
                runtime.execute(
                    "你好",
                    context=snapshot,
                    route_decision=decision,
                    session_id="session-terminal-once",
                    turn_index=1,
                    allow_escalation=False,
                )
        terminalize.assert_called_once()
        lifecycle.fail_turn.assert_called_once()

    def runtime(self, fast_result: dict, multi_result: dict | None = None):
        fast = Mock()
        fast.execute.return_value = fast_result
        multi = Mock()
        multi.execute.return_value = multi_result or multi_success()
        # Conversation routing tests must not inherit the operator's global
        # extension registry or resolve a real Provider credential.
        with patch(
            "sitina.conversation.runtime.ExtensionManager.load_registry",
            return_value={"plugins": {}, "skills": {}},
        ):
            runtime = ConversationRuntime(
                HOME,
                router=self.router,
                fast_runtime=fast,
                multi_runtime=multi,
            )
        return runtime, fast, multi

    def test_auto_fast_normal_path_is_exactly_one_call_without_review(self) -> None:
        runtime, fast, multi = self.runtime(fast_success())
        session = ChatSession()
        result = runtime.execute_turn(session, "你好")
        self.assertEqual(result["resolved_mode"], "FAST")
        self.assertEqual(result["route_decision"]["decision_path"], "AUTO_FAST_ADMITTED")
        self.assertEqual(result["route_decision"]["confidence"], 0.90)
        self.assertEqual(result["route_decision"]["threshold"], 0.65)
        self.assertEqual(result["route_decision"]["initial_fast_decision"]["decision"], "ADMITTED")
        self.assertEqual(result["provider_call_count"], 1)
        self.assertEqual(result["provider_physical_send_count"], 1)
        self.assertEqual(result["proposal_competition_count"], 0)
        self.assertEqual(result["reviewer_call_count"], 0)
        fast.execute.assert_called_once()
        multi.execute.assert_not_called()

    def test_auto_needs_multi_escalates_and_never_exposes_fast_candidate(self) -> None:
        runtime, _fast, multi = self.runtime(fast_success(needs_multi=True))
        session = ChatSession()
        events = []
        result = runtime.execute_turn(session, "你好", status_callback=lambda event, value: events.append(event))
        self.assertEqual(events, ["route", "escalation"])
        self.assertTrue(result["escalated"])
        self.assertEqual(result["resolved_mode"], "MULTI")
        self.assertEqual(result["route_decision"]["decision_path"], "AUTO_FAST_RUNTIME_ESCALATION")
        self.assertTrue(result["route_decision"]["upgrade_reason"])
        self.assertEqual(
            result["route_decision"]["initial_fast_decision"]["decision"],
            "REJECTED_AFTER_PROVIDER_EVALUATION",
        )
        self.assertTrue(result["route_decision"]["initial_fast_decision"]["provider_evaluated"])
        self.assertEqual(result["response"], "MULTI 最终获胜回答")
        self.assertNotIn("未经审阅的 FAST 候选", result["response"])
        self.assertFalse(result["fast_candidate_displayed"])
        self.assertEqual(result["provider_call_count"], 6)
        goal = multi.execute.call_args.args[0]
        self.assertNotIn("未经审阅的 FAST 候选", goal)
        self.assertIn("must not be treated as a Proposal", goal)
        overrides = multi.execute.call_args.kwargs["overrides"]
        self.assertEqual(overrides["conversation_user_message"], "你好")
        canonical_json_bytes(overrides)
        self.assertEqual(overrides["conversation_route_decision"]["confidence"], "0.95")
        self.assertEqual(overrides["conversation_route_decision"]["threshold"], "0.65")

    def test_auto_low_confidence_also_escalates(self) -> None:
        runtime, _fast, multi = self.runtime(fast_success(confidence="low"))
        result = runtime.execute_turn(ChatSession(), "什么是这个？")
        self.assertTrue(result["escalated"])
        multi.execute.assert_called_once()

    def test_forced_fast_never_escalates_even_when_requested(self) -> None:
        runtime, fast, multi = self.runtime(fast_success(needs_multi=True))
        session = ChatSession(mode=ChatMode.FAST)
        result = runtime.execute_turn(session, "比较三种复杂架构")
        self.assertEqual(result["resolved_mode"], "FAST")
        self.assertFalse(result["escalated"])
        self.assertTrue(result["forced_fast_low_confidence"])
        self.assertFalse(fast.execute.call_args.kwargs["allow_escalation"])
        multi.execute.assert_not_called()

    def test_forced_multi_runs_reviewed_path_even_for_greeting(self) -> None:
        runtime, fast, multi = self.runtime(fast_success())
        session = ChatSession(mode=ChatMode.MULTI)
        result = runtime.execute_turn(session, "你好")
        self.assertEqual(result["resolved_mode"], "MULTI")
        self.assertGreaterEqual(result["proposal_competition_count"], 2)
        self.assertGreaterEqual(result["reviewer_call_count"], 1)
        fast.execute.assert_not_called()
        multi.execute.assert_called_once()
        overrides = multi.execute.call_args.kwargs["overrides"]
        canonical_json_bytes(overrides)
        self.assertEqual(overrides["conversation_route_decision"]["confidence"], "1")
        self.assertEqual(overrides["conversation_route_decision"]["threshold"], "0.65")

    def test_auto_router_direct_multi_is_marked_as_automatic_escalation(self) -> None:
        runtime, fast, multi = self.runtime(fast_success())
        result = runtime.execute_turn(ChatSession(), "比较三种事件存储方案并给出迁移建议")
        self.assertTrue(result["escalated"])
        self.assertEqual(result["resolved_mode"], "MULTI")
        evidence = result["route_decision"]
        self.assertEqual(evidence["decision_path"], "AUTO_DIRECT_MULTI")
        self.assertGreaterEqual(evidence["confidence"], evidence["threshold"])
        self.assertTrue(evidence["upgrade_reason"])
        self.assertEqual(evidence["initial_fast_decision"]["decision"], "REJECTED_FOR_DIRECT_MULTI")
        self.assertFalse(evidence["initial_fast_decision"]["provider_evaluated"])
        fast.execute.assert_not_called()
        multi.execute.assert_called_once()
        overrides = multi.execute.call_args.kwargs["overrides"]
        canonical_json_bytes(overrides)
        self.assertEqual(overrides["conversation_route_decision"]["confidence"], "0.8")
        self.assertEqual(overrides["conversation_route_decision"]["threshold"], "0.65")

    def test_failed_turn_is_not_added_to_history(self) -> None:
        failed = {**fast_success(), "terminal_state": "FAILED", "response": ""}
        runtime, _fast, _multi = self.runtime(failed)
        session = ChatSession()
        runtime.execute_turn(session, "失败消息")
        self.assertEqual(session.history, [])
        self.assertEqual(session.last_failed_message, "失败消息")

    def test_installed_extension_cannot_replace_forced_fast_agent_path(self) -> None:
        autonomous = Mock()
        fast = Mock()
        fast.execute.return_value = fast_success()
        runtime = ConversationRuntime(
            HOME,
            router=self.router,
            fast_runtime=fast,
            multi_runtime=Mock(),
            autonomous_runtime=autonomous,
        )
        session = ChatSession(session_id="chat-session-extension", mode=ChatMode.FAST)
        result = runtime.execute_turn(session, "use the active tool capability")
        self.assertEqual(result["terminal_state"], "SUCCEEDED")
        self.assertEqual(result["resolved_mode"], "FAST")
        fast.execute.assert_called_once()
        autonomous.run.assert_not_called()

    def test_secret_text_is_not_returned_by_cli_error_renderer(self) -> None:
        from sitina.cli import _chat_failure_text

        secret = "sk-example-secret-that-must-not-appear"
        rendered = _chat_failure_text("AuthenticationError", f"Authorization: Bearer {secret}")
        self.assertNotIn(secret, rendered)
        self.assertNotIn("Authorization", rendered)


if __name__ == "__main__":
    unittest.main()
