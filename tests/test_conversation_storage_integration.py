from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.conversation.context import ConversationContext
from sitina.conversation.fast_runtime import FastConversationRuntime
from sitina.conversation.lifecycle import ConversationLifecycle
from sitina.conversation.models import ChatMode, ChatSession
from sitina.conversation.persistence import JournalSessionRepository
from sitina.conversation.router import ConversationRouter
from sitina.conversation.runtime import ConversationRuntime
from sitina.effects.gateway import EffectGateway
from sitina.effects.results import ResultPipeline, ResultPolicy
from sitina.journal.local import LocalJournal
from sitina.orchestrator.bplus_production import VerifiedJournalReadView
from sitina.orchestrator.true_multi_agent_runtime import (
    AgentIdentity,
    ProviderExecutor,
    RuntimeActivation,
    TrueMultiAgentRuntimeError,
    normalize_usage,
)
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


SOURCE_ROOT = Path(__file__).resolve().parents[1]


class ControlledProviderTransport:
    """One-send deterministic transport behind the real EffectGateway."""

    def __init__(self, outputs: list[dict[str, object]] | None = None) -> None:
        self.profile = SimpleNamespace(name="deepseek", model="deepseek-v4-pro")
        self.prompts: dict[str, tuple[str, str]] = {}
        self.physical_send_count = 0
        self.outputs = list(outputs or [])

    def send_once(self, request, effect_attempt_id: str) -> dict[str, object]:
        self.physical_send_count += 1
        value = dict(self.outputs.pop(0)) if self.outputs else {
            "agent_id": str(request.request["agent_id"]),
            "kind": "conversation_answer",
            "answer": "The controlled storage path recovered this exact answer.",
            "confidence": "high",
            "needs_multi": False,
            "escalation_reasons": [],
        }
        value.setdefault("agent_id", str(request.request["agent_id"]))
        return {
            "raw_text": json.dumps(value, sort_keys=True),
            "metadata": {
                "provider_response_id": f"controlled-response-{self.physical_send_count}",
                "token_usage": {"input_tokens": 17, "output_tokens": 13, "total_tokens": 30},
            },
            "effect_attempt_id": effect_attempt_id,
            "physical_send_count": self.physical_send_count,
        }


class ConversationStorageIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        (self.home / "config").mkdir()
        for name in (
            "true_multi_agent_agents.json",
            "true_multi_agent_policy.json",
            "conversation_router.json",
            "context_policy.json",
        ):
            shutil.copy2(SOURCE_ROOT / "config" / name, self.home / "config" / name)
        (self.home / ".sitina-bplus-disposable-v1").write_text("controlled\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.keys)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_verified_read_view_has_a_noop_reader_lifecycle(self) -> None:
        view = VerifiedJournalReadView(())
        self.assertEqual(view.head_position, 0)
        view.close()
        with view as reopened:
            self.assertEqual(tuple(reopened.iter_events(0)), ())

    @staticmethod
    def _budget_only_executor(*, max_tokens: int = 100) -> ProviderExecutor:
        executor = object.__new__(ProviderExecutor)
        executor.policy = {
            "max_provider_requests_per_run": 4,
            "max_total_tokens_per_run": max_tokens,
            "max_total_cost_micro_usd_per_run": 1000,
            "pricing": {
                "input_micro_usd_per_million_tokens": 1_000_000,
                "output_micro_usd_per_million_tokens": 2_000_000,
            },
        }
        executor.run_id = "run-1"
        executor.call_count = 0
        executor.embedded_call_count = 0
        executor.embedded_physical_send_count = 0
        executor.usage_input_total = 0
        executor.usage_output_total = 0
        executor.usage_cache_read_total = 0
        executor.usage_cache_write_total = 0
        executor.usage_total = 0
        executor.cost_total_micro_usd = 0
        executor.unsettled_usage_count = 0
        executor.transport = SimpleNamespace(physical_send_count=0)
        executor.canary_authorization = None
        executor._transport_authorization_id = ""
        executor._transport_authorization_run_id = "run-1"
        executor._embedded_transport_receipt_seen = set()
        executor._embedded_transport_receipts_by_identity = {}
        return executor

    def test_unified_budget_records_embedded_cache_usage_and_cost(self) -> None:
        executor = self._budget_only_executor()
        executor.admit_embedded_provider_call(20)
        executor.settle_embedded_provider_call(
            {
                "physical_send_count": 1,
                "token_usage": {
                    "input_tokens": 12,
                    "output_tokens": 8,
                    "cache_read_tokens": 5,
                    "cache_write_tokens": 3,
                    "total_tokens": 20,
                },
            }
        )
        self.assertEqual(
            executor.usage_totals(),
            {
                "input_tokens": 12,
                "output_tokens": 8,
                "cache_read_tokens": 5,
                "cache_write_tokens": 3,
                "total_tokens": 20,
                "cost_micro_usd": 28,
                "unsettled_usage_count": 0,
                "retry_count": 0,
                "fallback_count": 0,
            },
        )
        self.assertEqual(executor.provider_call_total(), 1)
        # This fixture is a scripted/injected client.  Its self-reported
        # physical_send_count cannot mint a canary-grade send; it is still a
        # real logical embedded call for budget accounting.
        self.assertEqual(executor.embedded_call_count, 1)
        self.assertEqual(executor.physical_send_total(), 0)

    def test_authoritative_embedded_receipt_is_the_only_physical_send_source(self) -> None:
        executor = self._budget_only_executor()

        class IssuerBoundLedger:
            @staticmethod
            def contains(receipt):
                return receipt.get("receipt_id") == "issuer-receipt-1"

        executor.transport = SimpleNamespace(
            physical_send_count=0,
            authoritative_physical=True,
            transport_ledger=IssuerBoundLedger(),
        )
        executor._transport_authorization_id = "auth-current"
        executor._transport_authorization_run_id = "run-1"
        executor._embedded_transport_receipts = []
        executor._settled_embedded_transport_receipt_count = 0
        receipt = {
            "receipt_id": "issuer-receipt-1",
            "receipt_hash": "a" * 64,
            "authorization_id": "auth-current",
            "run_id": "run-1",
        }
        executor.record_embedded_transport_receipt(
            receipt
        )
        # Redelivery of the exact host receipt is idempotent and cannot
        # increase the physical-send cursor.
        executor.record_embedded_transport_receipt(dict(receipt))
        executor.settle_embedded_provider_call(
            {
                # Deliberately contradictory client metadata must be ignored.
                "physical_send_count": 99,
                "token_usage": {
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "total_tokens": 2,
                },
            }
        )
        self.assertEqual(executor.embedded_call_count, 1)
        self.assertEqual(executor.physical_send_total(), 1)

    def test_embedded_receipt_rejects_foreign_run_or_authorization(self) -> None:
        executor = self._budget_only_executor()

        class IssuerBoundLedger:
            @staticmethod
            def contains(receipt):
                return receipt.get("receipt_hash") in {"b" * 64, "c" * 64}

        executor.transport = SimpleNamespace(
            physical_send_count=0,
            authoritative_physical=True,
            transport_ledger=IssuerBoundLedger(),
        )
        executor._transport_authorization_id = "auth-current"
        executor._transport_authorization_run_id = "run-1"
        executor._embedded_transport_receipts = []
        executor._settled_embedded_transport_receipt_count = 0
        with self.assertRaises(PermissionError):
            executor.record_embedded_transport_receipt({
                "receipt_hash": "b" * 64,
                "authorization_id": "auth-other",
                "run_id": "run-1",
            })
        with self.assertRaises(PermissionError):
            executor.record_embedded_transport_receipt({
                "receipt_hash": "c" * 64,
                "authorization_id": "auth-current",
                "run_id": "run-other",
            })
        self.assertEqual(executor.physical_send_total(), 0)

    def test_authoritative_embedded_metadata_without_receipt_is_not_physical(self) -> None:
        executor = self._budget_only_executor()
        executor.transport = SimpleNamespace(
            physical_send_count=0,
            authoritative_physical=True,
            transport_ledger=object(),
        )
        executor._embedded_transport_receipts = []
        executor._settled_embedded_transport_receipt_count = 0
        executor.settle_embedded_provider_call(
            {
                "physical_send_count": 1,
                "token_usage": {
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "total_tokens": 2,
                },
            }
        )
        self.assertEqual(executor.embedded_call_count, 1)
        self.assertEqual(executor.physical_send_total(), 0)

    def test_non_authoritative_embedded_failure_metadata_cannot_mint_physical_send(self) -> None:
        executor = self._budget_only_executor()
        executor.settle_failed_embedded_provider_call(
            {"physical_send_count": 7, "retry_count": 3, "fallback_count": 1}
        )
        self.assertEqual(executor.embedded_call_count, 1)
        self.assertEqual(executor.physical_send_total(), 0)
        self.assertEqual(executor.unsettled_usage_count, 1)

    def test_post_response_budget_overrun_preserves_actual_usage(self) -> None:
        executor = self._budget_only_executor(max_tokens=20)
        executor.admit_embedded_provider_call(10)
        with self.assertRaises(TrueMultiAgentRuntimeError):
            executor.settle_embedded_provider_call(
                {
                    "token_usage": {
                        "input_tokens": 12,
                        "output_tokens": 9,
                        "total_tokens": 21,
                    }
                }
            )
        self.assertEqual(executor.usage_total, 21)
        self.assertEqual(executor.usage_input_total, 12)
        self.assertEqual(executor.usage_output_total, 9)
        self.assertEqual(executor.embedded_call_count, 1)

    def test_preflight_rejects_insufficient_remaining_budget_before_send(self) -> None:
        executor = self._budget_only_executor(max_tokens=20)
        executor.usage_total = 15
        with self.assertRaises(TrueMultiAgentRuntimeError):
            executor.admit_embedded_provider_call(10)
        self.assertEqual(executor.physical_send_total(), 0)
        self.assertEqual(executor.provider_call_total(), 0)

    def test_usage_normalization_rejects_inconsistent_total(self) -> None:
        with self.assertRaises(TrueMultiAgentRuntimeError):
            normalize_usage(
                {
                    "token_usage": {
                        "input_tokens": 4,
                        "output_tokens": 3,
                        "total_tokens": 99,
                    }
                }
            )

    def test_mode_only_command_survives_a_fresh_runtime_without_provider_execution(self) -> None:
        class ControlledContext:
            provider = self.keys

            def open_runtime_writer(inner_self):
                return LocalJournal.open(self.home, self.auth)

            def open_cas(inner_self):
                return LocalCAS.open(self.home, self.keys)

            def open_verified_journal_reader(inner_self):
                return LocalJournal.open(self.home, self.auth)

            def open_cas_reader(inner_self):
                return LocalCAS.open(self.home, self.keys)

        context = ControlledContext()
        process_one = ConversationRuntime.__new__(ConversationRuntime)
        process_one.home = self.home
        process_one.context = ConversationContext.load(self.home)
        original = ChatSession(session_id="session-durable-auto", mode=ChatMode.FAST)
        with patch(
            "sitina.conversation.runtime.SessionRuntimeContext.open",
            return_value=context,
        ):
            process_one.persist_mode(original, ChatMode.AUTO)

            process_two = ConversationRuntime.__new__(ConversationRuntime)
            process_two.home = self.home
            process_two.context = ConversationContext.load(self.home)
            recovered = process_two.resume_or_create_session()

        self.assertEqual(recovered.session_id, original.session_id)
        self.assertIs(recovered.mode, ChatMode.AUTO)
        self.assertEqual(recovered.turn_index, 0)
        journal = LocalJournal.open(self.home, self.auth)
        self.assertFalse(
            any("PROVIDER" in str(event.payload.get("schema", "")) for event in journal.iter_events(0))
        )
        journal.close()
        self.assertFalse((self.home / "data/sitina.db").exists())

    @staticmethod
    def _controlled_executor(*args, **_kwargs) -> ProviderExecutor:
        home, context, run_id, policy_hash, policy, activation, journal, cas = args
        executor = object.__new__(ProviderExecutor)
        executor.home = home
        executor.context = context
        executor.run_id = run_id
        executor.policy_hash = policy_hash
        executor.policy = policy
        executor.activation = activation
        executor.journal = journal
        executor.cas = cas
        executor.call_count = 0
        executor.usage_total = 0
        executor.cost_total_micro_usd = 0
        executor.results = []
        executor.rejected_calls = []
        executor.recovery_attempts = []
        executor.feature_activations = FeatureActivationRegistry.from_journal_events(context.events)
        executor.transport = ControlledProviderTransport()
        executor.gateway = EffectGateway(executor.transport)
        executor.pipeline = ResultPipeline(
            cas,
            context.provider,
            ResultPolicy(64 * 1024, frozenset({"agent_id", "kind"}), 64 * 1024),
        )
        return executor

    def test_parent_contract_rejection_precedes_task_accept_and_can_repair_once(self) -> None:
        """A wrong parent is recorded as a rejection, never as an accepted call."""

        from sitina.orchestrator.true_multi_agent import _require_exact_parent_output_hash

        cas = LocalCAS.open(self.home, self.keys)
        activation_receipt = cas.publish_verified(
            encrypt_object(b"controlled-parent-contract-activation", self.keys, tenant_id="default")
        )
        activation = RuntimeActivation(
            {"schema": "CONTROLLED_RUNTIME_ACTIVATION_V1", "provider": {"base_url_host": "api.deepseek.com"}},
            "a" * 64,
            activation_receipt,
        )

        class ControlledContext:
            provider = self.keys
            events: tuple[object, ...] = ()

        context = ControlledContext()
        journal = LocalJournal.open(self.home, self.auth)
        policy = {
            "provider_profile": "deepseek",
            "max_provider_requests_per_run": 4,
            "max_output_tokens_per_request": 32,
            "max_total_tokens_per_run": 1000,
            "max_total_cost_micro_usd_per_run": 1000,
            "pricing": {
                "input_micro_usd_per_million_tokens": 1,
                "output_micro_usd_per_million_tokens": 1,
            },
        }
        expected = "sha256:" + "c" * 64
        wrong = {
            "agent_id": "agent-atlas",
            "kind": "proposal",
            "summary": "wrong binding",
            "parent_output_hash": "sha256:" + "d" * 64,
        }
        exact = {
            "agent_id": "agent-atlas",
            "kind": "proposal",
            "summary": "exact binding",
            "parent_output_hash": expected,
        }
        executor = self._controlled_executor(
            self.home, context, "run-parent-contract", "b" * 64,
            policy, activation, journal, cas,
        )
        executor.transport = ControlledProviderTransport([wrong, exact])
        executor.gateway = EffectGateway(executor.transport)
        agent = AgentIdentity(
            "agent-atlas", "analyst", ("goal-analysis",), "deepseek", 1, ("low",)
        )
        def validate(value):
            _require_exact_parent_output_hash(value, expected)
            if not isinstance(value.get("summary"), str) or not value["summary"].strip():
                raise TrueMultiAgentRuntimeError("summary is required")
        try:
            with self.assertRaises(TrueMultiAgentRuntimeError):
                executor.call(
                    agent,
                    task_id="negotiation-round-2-1",
                    kind="proposal",
                    system_prompt="system",
                    user_prompt="wrong then exact",
                    input_context={"parent_output_hash": expected},
                    validate=validate,
                )
            self.assertEqual(len(executor.results), 0)
            self.assertEqual(len(executor.rejected_calls), 1)
            rejection = executor.rejected_calls[0]
            self.assertEqual(rejection["reason_code"], "PARENT_OUTPUT_HASH_MISMATCH")
            self.assertEqual(rejection["expected_binding_hash"], expected)
            self.assertEqual(rejection["result_admission"], "REJECTED")
            self.assertTrue(
                any(
                    event.payload.get("schema") == "AGENT_OUTPUT_CONTRACT_REJECTED_V1"
                    for event in journal.iter_events(0)
                )
            )
            accepted = executor.call(
                agent,
                task_id="negotiation-round-2-1",
                kind="proposal",
                system_prompt="system",
                user_prompt="exact repair",
                input_context={"parent_output_hash": expected},
                validate=validate,
            )
            self.assertEqual(accepted.value["parent_output_hash"], expected)
            self.assertEqual(len(executor.results), 1)
            self.assertEqual(len(executor.rejected_calls), 1)
            executor.results.clear()
            executor.rejected_calls.clear()
            executor.transport = ControlledProviderTransport([wrong, wrong])
            executor.gateway = EffectGateway(executor.transport)
            for _ in range(2):
                with self.assertRaises(TrueMultiAgentRuntimeError):
                    executor.call(
                        agent,
                        task_id="negotiation-round-2-continuous-mismatch",
                        kind="proposal",
                        system_prompt="system",
                        user_prompt="wrong again",
                        input_context={"parent_output_hash": expected},
                        validate=validate,
                    )
            self.assertEqual(len(executor.results), 0)
            self.assertEqual(len(executor.rejected_calls), 2)
            self.assertTrue(all(
                item["reason_code"] == "PARENT_OUTPUT_HASH_MISMATCH"
                for item in executor.rejected_calls
            ))
        finally:
            journal.close()

    def test_fast_turn_restarts_from_journal_cas_without_sqlite_or_body_leakage(self) -> None:
        cas = LocalCAS.open(self.home, self.keys)
        activation_receipt = cas.publish_verified(
            encrypt_object(b"controlled-runtime-activation", self.keys, tenant_id="default")
        )
        activation = RuntimeActivation(
            {"schema": "CONTROLLED_RUNTIME_ACTIVATION_V1"},
            "a" * 64,
            activation_receipt,
        )

        class ControlledContext:
            provider = self.keys
            events: tuple[object, ...] = ()

            def open_writer(inner_self):
                return LocalJournal.open(self.home, self.auth)

            def open_cas(inner_self):
                return LocalCAS.open(self.home, self.keys)

        context = ControlledContext()
        fast = FastConversationRuntime(self.home)
        renderer = ConversationContext.load(self.home)
        router = ConversationRouter.load(self.home)
        snapshot = renderer.compose(
            [],
            current_user_message="Prove restart storage closure.",
            goal_constraints="Use only Journal and CAS authority.",
            working_state="",
            memories=(),
            rolling_summary="",
        )
        decision = router.decide(ChatMode.FAST, "Prove restart storage closure.", snapshot)
        with (
            patch("sitina.conversation.fast_runtime.SessionRuntimeContext.open", return_value=context),
            patch("sitina.conversation.fast_runtime.activate_runtime", return_value=activation),
            patch("sitina.conversation.fast_runtime.ProviderExecutor", side_effect=self._controlled_executor),
        ):
            result = fast.execute(
                "Prove restart storage closure.",
                context=snapshot,
                route_decision=decision,
                session_id="session-controlled-storage",
                turn_index=1,
                allow_escalation=False,
            )
        self.assertEqual(result["terminal_state"], "SUCCEEDED")
        self.assertEqual(result["provider_call_count"], 1)
        self.assertEqual(result["provider_physical_send_count"], 1)

        reopened = LocalJournal.open(self.home, self.auth)
        reopened_cas = LocalCAS.open(self.home, self.keys)
        events = tuple(reopened.iter_events(0))
        user = next(
            item for item in events
            if item.event_type == "session.message-appended" and item.payload["role"] == "user"
        )
        invocation = next(item for item in events if item.payload.get("schema") == "EFFECT_INVOCATION_STARTED_V1")
        terminal = next(item for item in events if item.event_type == "run.terminal")
        assistant = next(
            item for item in events
            if item.event_type == "session.message-appended" and item.payload["role"] == "assistant"
        )
        self.assertLess(user.position, invocation.position)
        self.assertLess(terminal.position, assistant.position)
        serialized_payloads = json.dumps([item.payload for item in events], sort_keys=True)
        self.assertNotIn("Prove restart storage closure.", serialized_payloads)
        self.assertNotIn("The controlled storage path recovered this exact answer.", serialized_payloads)
        recovered = JournalSessionRepository(reopened, reopened_cas, self.keys).recover(
            "session-controlled-storage"
        )
        self.assertEqual(
            recovered["successful_turns"],
            [{
                "turn_index": 1,
                "user": "Prove restart storage closure.",
                "assistant": "The controlled storage path recovered this exact answer.",
            }],
        )
        reopened.close()

        reader = LocalJournal.open(self.home, self.auth)

        class ReaderContext:
            provider = self.keys

            @staticmethod
            def open_verified_journal_reader():
                return reader

            def open_cas_reader(inner_self):
                return LocalCAS.open(self.home, self.keys)

        runtime = ConversationRuntime.__new__(ConversationRuntime)
        runtime.home = self.home
        runtime.context = renderer
        with patch(
            "sitina.conversation.runtime.SessionRuntimeContext.open",
            return_value=ReaderContext(),
        ):
            session = runtime.resume_or_create_session()
        self.assertEqual(session.session_id, "session-controlled-storage")
        self.assertEqual(session.turn_index, 1)
        self.assertEqual(session.history[0].assistant, "The controlled storage path recovered this exact answer.")
        self.assertTrue(session.working_state)
        self.assertTrue(session.rolling_summary)
        # Opening another writer proves resume closed its verified reader.
        final_reopen = LocalJournal.open(self.home, self.auth)
        final_reopen.close()
        self.assertFalse(any(self.home.rglob("*.sqlite")))

    def test_restart_reconciles_terminal_before_assistant_without_second_provider_send(self) -> None:
        cas = LocalCAS.open(self.home, self.keys)
        activation_receipt = cas.publish_verified(
            encrypt_object(b"controlled-crash-window-activation", self.keys, tenant_id="default")
        )
        activation = RuntimeActivation(
            {"schema": "CONTROLLED_RUNTIME_ACTIVATION_V1"},
            "b" * 64,
            activation_receipt,
        )

        class ControlledContext:
            provider = self.keys
            events: tuple[object, ...] = ()

            def open_writer(inner_self):
                return LocalJournal.open(self.home, self.auth)

            def open_cas(inner_self):
                return LocalCAS.open(self.home, self.keys)

            def open_verified_journal_reader(inner_self):
                return LocalJournal.open(self.home, self.auth)

            def open_cas_reader(inner_self):
                return LocalCAS.open(self.home, self.keys)

        context = ControlledContext()
        fast = FastConversationRuntime(self.home)
        renderer = ConversationContext.load(self.home)
        router = ConversationRouter.load(self.home)
        message = "Recover the terminal-to-session crash window."
        snapshot = renderer.compose(
            [],
            current_user_message=message,
            goal_constraints="Never repeat an already committed provider effect.",
            working_state="",
            memories=(),
            rolling_summary="",
        )
        decision = router.decide(ChatMode.FAST, message, snapshot)
        with (
            patch("sitina.conversation.fast_runtime.SessionRuntimeContext.open", return_value=context),
            patch("sitina.conversation.fast_runtime.activate_runtime", return_value=activation),
            patch("sitina.conversation.fast_runtime.ProviderExecutor", side_effect=self._controlled_executor),
            patch.object(
                ConversationLifecycle,
                "complete_turn",
                side_effect=RuntimeError("simulated crash after run terminal before assistant"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                fast.execute(
                    message,
                    context=snapshot,
                    route_decision=decision,
                    session_id="session-terminal-crash",
                    turn_index=1,
                    allow_escalation=False,
                )

        before = LocalJournal.open(self.home, self.auth)
        before_events = tuple(before.iter_events(0))
        self.assertEqual(sum(item.event_type == "run.terminal" for item in before_events), 1)
        self.assertEqual(
            sum(
                item.event_type == "session.message-appended" and item.payload.get("role") == "assistant"
                for item in before_events
            ),
            0,
        )
        self.assertEqual(
            sum(item.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1" for item in before_events),
            1,
        )
        before.close()

        runtime = ConversationRuntime.__new__(ConversationRuntime)
        runtime.home = self.home
        runtime.context = renderer
        with patch(
            "sitina.conversation.runtime.SessionRuntimeContext.open",
            return_value=context,
        ):
            recovered = runtime.resume_or_create_session()
        self.assertEqual(recovered.history[0].user, message)
        self.assertEqual(
            recovered.history[0].assistant,
            "The controlled storage path recovered this exact answer.",
        )

        after = LocalJournal.open(self.home, self.auth)
        after_events = tuple(after.iter_events(0))
        self.assertEqual(
            sum(item.payload.get("schema") == "PROVIDER_USAGE_RECORDED_V1" for item in after_events),
            1,
        )
        reconciled = next(item for item in after_events if item.event_type == "session.turn-reconciled")
        self.assertFalse(reconciled.payload["automatic_provider_retry_performed"])
        self.assertGreater(reconciled.position, next(item.position for item in after_events if item.event_type == "run.terminal"))
        after.close()


if __name__ == "__main__":
    unittest.main()
