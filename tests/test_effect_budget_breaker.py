from __future__ import annotations

import unittest

from sitina.effects.breakers import BreakerError, BreakerState, CircuitBreaker
from sitina.effects.budgets import BudgetBundle, BudgetError, BudgetReservation
from sitina.effects.gateway import DispatchFence, EffectGateway, EffectGatewayError, MockTransport, TaskFence
from tests.test_effect_state_matrix import request


class EffectBudgetBreakerTests(unittest.TestCase):
    def test_invocation_requires_all_reservations_activated_and_same_binding(self) -> None:
        bundle = BudgetBundle.create("bundle-1", "effect-1", "attempt-1", "fence-1", (
            BudgetReservation("tokens", 100, 20), BudgetReservation("cost-cents", 50, 20)
        ))
        bundle = bundle.activate("tokens")
        with self.assertRaises(BudgetError):
            bundle.assert_dispatch_authorized(now=10, effect_id="effect-1", effect_attempt_id="attempt-1", fence="fence-1")
        bundle = bundle.activate("cost-cents")
        bundle.assert_dispatch_authorized(now=10, effect_id="effect-1", effect_attempt_id="attempt-1", fence="fence-1")
        with self.assertRaises(BudgetError):
            bundle.assert_dispatch_authorized(now=10, effect_id="effect-1", effect_attempt_id="attempt-2", fence="fence-1")

    def test_partial_failure_is_compensated_and_leak_becomes_obligation(self) -> None:
        bundle = BudgetBundle.create("bundle-2", "effect-1", "attempt-1", "fence-1", (
            BudgetReservation("tokens", 100, 20), BudgetReservation("cost-cents", 50, 20)
        )).activate("tokens")
        compensated, event = bundle.fail_reservation("cost-cents", compensation_succeeds=False)
        self.assertEqual(event["schema"], "BUDGET_RESERVATION_LEAK_OBLIGATION_V1")
        self.assertTrue(compensated.leak_obligation_open)

    def test_actual_overrun_is_recorded_without_rejecting_receipt(self) -> None:
        bundle = BudgetBundle.create("bundle-3", "effect-1", "attempt-1", "fence-1", (BudgetReservation("tokens", 100, 20),)).activate("tokens")
        updated, event = bundle.record_actual("tokens", 120)
        self.assertEqual(event["schema"], "BUDGET_OVERRUN_DEBT_V1")
        self.assertTrue(updated.blocks_ordinary_dispatch)
        self.assertTrue(event["receipt_admitted"])

    def test_breaker_precheck_is_revalidated_by_final_cas_and_half_open_is_bounded(self) -> None:
        breaker = CircuitBreaker("provider-x", half_open_probe_limit=1)
        token = breaker.precheck("attempt-1", "fence-1")
        breaker = breaker.open(reason="failures")
        with self.assertRaises(BreakerError):
            breaker.authorize_final(token, expected_version=0)
        breaker = breaker.half_open()
        probe = breaker.precheck("attempt-2", "fence-2")
        breaker, auth = breaker.authorize_final(probe, expected_version=breaker.version)
        self.assertEqual(auth["schema"], "CIRCUIT_BREAKER_DISPATCH_AUTHORIZED_V1")
        with self.assertRaises(BreakerError):
            breaker.precheck("attempt-3", "fence-3")
        self.assertEqual(breaker.state, BreakerState.HALF_OPEN)

    def test_gateway_requires_exact_budget_and_breaker_authorization(self) -> None:
        gateway = EffectGateway(MockTransport())
        gateway.open_effect(request())
        gateway.claim_attempt("effect-1", "attempt-1", TaskFence("task-attempt-1", 1, "task-fence", 100))
        gateway.prepare("effect-1", "attempt-1", approval_hash="a" * 64, credential_handle_id="credential-1", manifest_hash="b" * 64)
        dispatch = DispatchFence("dispatch-1", 1, "dispatch-fence", 100)
        with self.assertRaises(EffectGatewayError):
            gateway.start_invocation("effect-1", "attempt-1", dispatch, now=10)
        bundle = BudgetBundle.create("bundle-1", "effect-1", "attempt-1", dispatch.token, (BudgetReservation("tokens", 10, 100),)).activate("tokens")
        breaker = CircuitBreaker("provider-x", half_open_probe_limit=1)
        token = breaker.precheck("attempt-1", dispatch.token)
        breaker, authorization = breaker.authorize_final(token, expected_version=breaker.version)
        event = gateway.start_invocation("effect-1", "attempt-1", dispatch, now=10, budget_bundle=bundle, breaker_authorization=authorization)
        self.assertEqual(event["budget_bundle_id"], "bundle-1")
        self.assertEqual(event["breaker_control_id"], "provider-x")


if __name__ == "__main__":
    unittest.main()
