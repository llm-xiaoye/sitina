from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.effects.gateway import (
    AttemptDisposition,
    DispatchFence,
    EffectGateway,
    EffectGatewayError,
    MockTransport,
    TaskFence,
)
from sitina.effects.audit import SideEffectAudit, rebuild_effect_projection
from sitina.effects.breakers import CircuitBreaker
from sitina.effects.budgets import BudgetBundle, BudgetReservation
from sitina.effects.creation import EffectCreationSaga, EffectPermit
from sitina.effects.model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState, validate_effect_state
from sitina.effects.observations import EffectObservationApplier, ObservationIngress, make_signed_observation
from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from tests.test_effect_state_matrix import request


class EffectAttemptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = MockTransport()
        self.gateway = EffectGateway(self.transport, enforce_operational_gate=False)
        self.gateway.open_effect(request())

    def test_only_one_active_attempt_and_at_most_one_transport_send(self) -> None:
        self.gateway.claim_attempt("effect-1", "attempt-1", TaskFence("task-attempt-1", 1, "token-1", 100))
        with self.assertRaises(EffectGatewayError):
            self.gateway.claim_attempt("effect-1", "attempt-2", TaskFence("task-attempt-1", 1, "token-2", 100))
        self.gateway.prepare("effect-1", "attempt-1", approval_hash="a" * 64, credential_handle_id="cred-1", manifest_hash="b" * 64)
        self.gateway.start_invocation("effect-1", "attempt-1", DispatchFence("dispatch-1", 1, "dispatch-token", 100), now=10)
        self.gateway.transmit("effect-1", "attempt-1")
        with self.assertRaises(EffectGatewayError):
            self.gateway.transmit("effect-1", "attempt-1")
        self.assertEqual(self.transport.physical_send_count, 1)

    def test_task_and_dispatch_fences_are_both_checked_at_boundary(self) -> None:
        self.gateway.claim_attempt("effect-1", "attempt-1", TaskFence("task-attempt-1", 1, "token-1", 5))
        self.gateway.prepare("effect-1", "attempt-1", approval_hash="a" * 64, credential_handle_id="cred-1", manifest_hash="b" * 64)
        with self.assertRaises(EffectGatewayError):
            self.gateway.start_invocation("effect-1", "attempt-1", DispatchFence("dispatch-1", 1, "dispatch-token", 100), now=10)

    def test_crash_before_and_after_invocation_boundary_have_distinct_disposition(self) -> None:
        self.gateway.claim_attempt("effect-1", "attempt-1", TaskFence("task-attempt-1", 1, "token-1", 100))
        recovered = self.gateway.recover_after_crash("effect-1", "attempt-1")
        self.assertEqual(recovered.disposition, AttemptDisposition.ABORTED_BEFORE_SEND)
        self.assertEqual(self.gateway.effect("effect-1").state.outcome_state, OutcomeState.CANCELLED_BEFORE_SEND)
        self.assertEqual(self.gateway.effect("effect-1").state.settlement_state, SettlementState.SETTLED)
        self.gateway.claim_attempt("effect-1", "attempt-2", TaskFence("task-attempt-2", 2, "token-2", 100))
        self.gateway.prepare("effect-1", "attempt-2", approval_hash="a" * 64, credential_handle_id="cred-2", manifest_hash="b" * 64)
        self.gateway.start_invocation("effect-1", "attempt-2", DispatchFence("dispatch-2", 2, "dispatch-token-2", 100), now=10)
        recovered = self.gateway.recover_after_crash("effect-1", "attempt-2")
        self.assertEqual(recovered.disposition, AttemptDisposition.MAY_HAVE_BEEN_SENT)
        self.assertEqual(self.gateway.effect("effect-1").state.unresolved_transmission_exposure_count, 1)

    def test_late_observation_is_accepted_after_task_fence_expiry(self) -> None:
        self.gateway.claim_attempt("effect-1", "attempt-1", TaskFence("task-attempt-1", 1, "token-1", 11))
        self.gateway.prepare("effect-1", "attempt-1", approval_hash="a" * 64, credential_handle_id="cred-1", manifest_hash="b" * 64)
        self.gateway.start_invocation("effect-1", "attempt-1", DispatchFence("dispatch-1", 1, "dispatch-token", 11), now=10)
        self.gateway.recover_after_crash("effect-1", "attempt-1")
        event = self.gateway.link_late_observation("effect-1", "attempt-1", "observation-1", now=100)
        self.assertEqual(event["schema"], "ATTEMPT_OBSERVATION_LINKED_V1")

    def test_transport_exception_after_physical_send_is_recovered_as_unknown_and_policy_settled(self) -> None:
        class FailingTransport(MockTransport):
            def send_once(self, request, effect_attempt_id):
                self.physical_send_count += 1
                raise RuntimeError("remote timeout")

        transport = FailingTransport()
        gateway = EffectGateway(transport, enforce_operational_gate=False)
        gateway.open_effect(request())
        gateway.claim_attempt("effect-1", "attempt-1", TaskFence("task-attempt-1", 1, "token-1", 100))
        gateway.prepare("effect-1", "attempt-1", approval_hash="a" * 64, credential_handle_id="cred-1", manifest_hash="b" * 64)
        gateway.start_invocation("effect-1", "attempt-1", DispatchFence("dispatch-1", 1, "dispatch-token", 100), now=10)
        with self.assertRaises(RuntimeError):
            gateway.transmit("effect-1", "attempt-1")
        self.assertEqual(gateway.effect("effect-1").attempts[0].physical_send_count, 1)
        recovered = gateway.recover_after_crash("effect-1", "attempt-1")
        self.assertEqual(recovered.disposition, AttemptDisposition.MAY_HAVE_BEEN_SENT)
        state = gateway.settle_unknown_by_policy("effect-1", "attempt-1")
        self.assertEqual(state.outcome_state, OutcomeState.OUTCOME_UNKNOWN)
        self.assertEqual(state.settlement_state, SettlementState.SETTLED)
        self.assertEqual(state.settlement_basis, SettlementBasis.POLICY_DISPOSITION)

    def test_lost_ack_level_a_closes_from_observation_and_rebuilds_after_restart(self) -> None:
        home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        try:
            (home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
            effect_request = request()
            saga = EffectCreationSaga()
            process, _ = saga.begin(EffectPermit("permit-1", "run-1", effect_request.effect_id, effect_request.request_hash), process_id="effect-create-process", command_id="effect-create-command")
            process, requested = saga.apply_target(process, canonical_state="NO_STREAM")
            saga.reconcile(process, canonical_state="EFFECT_REQUESTED", canonical_request_hash=effect_request.request_hash)

            transport = MockTransport()
            gateway = EffectGateway(transport)
            gateway.open_effect(effect_request)
            gateway.claim_attempt("effect-1", "attempt-lost-ack", TaskFence("task-attempt-1", 1, "task-fence-1", 100))
            gateway.prepare("effect-1", "attempt-lost-ack", approval_hash="a" * 64, credential_handle_id="credential-1", manifest_hash="b" * 64)
            dispatch = DispatchFence("dispatch-1", 1, "dispatch-fence-1", 100)
            bundle = BudgetBundle.create("budget-1", "effect-1", "attempt-lost-ack", dispatch.token, (BudgetReservation("tokens", 100, 100),)).activate("tokens")
            breaker = CircuitBreaker("provider-x", half_open_probe_limit=1)
            breaker_token = breaker.precheck("attempt-lost-ack", dispatch.token)
            breaker, breaker_authorization = breaker.authorize_final(breaker_token, expected_version=breaker.version)
            invocation = gateway.start_invocation("effect-1", "attempt-lost-ack", dispatch, now=10, budget_bundle=bundle, breaker_authorization=breaker_authorization)
            gateway.transmit("effect-1", "attempt-lost-ack")
            recovered = gateway.recover_after_crash("effect-1", "attempt-lost-ack")
            self.assertEqual(recovered.disposition, AttemptDisposition.MAY_HAVE_BEEN_SENT)
            remote = transport.query(effect_request.idempotency_binding)
            self.assertIsNotNone(remote)
            self.assertEqual(transport.remote_execution_count, 1)

            source_key = b"level-a-source-key"
            binding = {"source_identity": "mock-source", "manifest_hash": "b" * 64, "effect_id": "effect-1", "effect_attempt_id": "attempt-lost-ack", "request_hash": effect_request.request_hash, "external_request_id": "external-1"}
            raw = make_signed_observation({**binding, "schema_major": 1, "observation_id": "observation-lost-ack", "nonce": "nonce-lost-ack", "received_at": 20, "remote_outcome": "SUCCEEDED", "remote_execution_id": remote["remote_execution_id"]}, source_key)
            observation = ObservationIngress({"mock-source": source_key}, now=lambda: 20).admit(raw, expected=binding, external_request_id_required=True).observation
            applied = EffectObservationApplier(gateway.effect("effect-1").state).apply(observation, expected_effect_version=0)
            final_state = EffectState(
                applied.state.outcome_state,
                applied.state.settlement_state,
                applied.state.settlement_basis,
                ExecutionCardinality.EXACTLY_ONE_CONFIRMED,
                0,
                exactly_once_proof_covers_all_attempts=True,
            )
            validate_effect_state(final_state)

            facts = [
                requested,
                {"schema": "EFFECT_ATTEMPT_CLAIMED_V1", "effect_id": "effect-1", "effect_attempt_id": "attempt-lost-ack", "task_fence": "task-fence-1", "dispatch_fence": "dispatch-fence-1"},
                {**invocation, "approval_id": "approval-1", "budget_bundle_id": "budget-1"},
                {"schema": "EFFECT_ATTEMPT_DISPOSITION_V1", "effect_id": "effect-1", "effect_attempt_id": "attempt-lost-ack", "disposition": "MAY_HAVE_BEEN_SENT"},
                {"schema": "OBSERVATION_ADMITTED_V1", "effect_id": "effect-1", "effect_attempt_id": "attempt-lost-ack", "observation_id": observation.observation_id, "outcome": "SUCCEEDED"},
                {"schema": "EFFECT_OUTCOME_ADVANCED_V1", "effect_id": "effect-1", "outcome": "SUCCEEDED", "settlement": "SETTLED", "basis": "AUTHORITATIVE_REMOTE_OBSERVATION", "cardinality": "EXACTLY_ONE_CONFIRMED"},
            ]
            provider = InMemoryKeyProvider()
            auth = JournalAuthProvider(provider)
            journal = LocalJournal.open(home, auth, journal_id="journal-phase4-e2e", namespace_kind="controlled_fixture")
            command = CommandEnvelope("phase4-e2e-command", "tenant-1", "effect-effect-1", "effect.lifecycle", "actor-gateway", "2026-07-14T00:00:00Z", {"effect_id": "effect-1", "fact_count": len(facts)})
            events = [EventEnvelope(f"phase4-e2e-event-{index}", "effect.fact", "tenant-1", "effect-effect-1", 0, 0, "2026-07-14T00:00:00Z", {"fact": fact}) for index, fact in enumerate(facts)]
            receipt = journal.append(command, 0, events)
            journal.close()
            recovered_journal = LocalJournal.open(home, auth, journal_id="journal-phase4-e2e", namespace_kind="controlled_fixture")
            recovered_facts = [event.payload["fact"] for event in recovered_journal.iter_events(0)]
            first_projection = rebuild_effect_projection(recovered_facts)
            first_checksum = first_projection["semantic_checksum"]
            del first_projection
            rebuilt = rebuild_effect_projection(recovered_facts)
            self.assertEqual(rebuilt["semantic_checksum"], first_checksum)
            self.assertEqual(rebuilt["effects"]["effect-1"]["outcome"], "SUCCEEDED")
            self.assertTrue(SideEffectAudit.build(recovered_facts).passed)
            self.assertEqual(receipt.last_position, len(facts))
            recovered_journal.close()
        finally:
            if os.environ.get("SITINA_AUDIT_RETAIN_STAGING") != "1":
                shutil.rmtree(home)


if __name__ == "__main__":
    unittest.main()
