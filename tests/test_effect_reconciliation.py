from __future__ import annotations

import unittest

from sitina.effects.adapters import RecoveryLevel, sign_manifest
from sitina.effects.model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState
from sitina.effects.reconcile import ReconciliationAction, ReconciliationEngine, ReconciliationError
from tests.test_adapter_manifests import payload


class EffectReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = ReconciliationEngine()

    def manifest(self, level: str, **changes: object):
        value = payload(level)
        value.update(changes)
        return sign_manifest(value, b"manifest-key")

    def test_level_a_reuses_key_but_level_b_queries_before_new_attempt(self) -> None:
        a = self.engine.plan(self.manifest("A"), elapsed_seconds=10)
        self.assertEqual(a.actions, (ReconciliationAction.QUERY_STATUS, ReconciliationAction.RETRY_SAME_IDEMPOTENCY_KEY))
        b = self.engine.plan(self.manifest("B"), elapsed_seconds=10)
        self.assertEqual(b.actions, (ReconciliationAction.QUERY_STATUS,))
        self.assertEqual(b.recovery_level, RecoveryLevel.B)

    def test_level_c_mutation_never_blindly_retries(self) -> None:
        plan = self.engine.plan(self.manifest("C"), elapsed_seconds=10)
        self.assertEqual(plan.actions, (ReconciliationAction.MANUAL_ACTION,))
        self.assertNotIn(ReconciliationAction.RETRY_SAME_IDEMPOTENCY_KEY, plan.actions)

    def test_success_with_other_exposure_remains_reconciling(self) -> None:
        state = EffectState(OutcomeState.OUTCOME_UNKNOWN, SettlementState.RECONCILING, SettlementBasis.NONE, ExecutionCardinality.UNKNOWN_CARDINALITY, 2)
        advanced = self.engine.confirm_success(state, resolved_exposures=1)
        self.assertEqual(advanced.outcome_state, OutcomeState.SUCCEEDED)
        self.assertEqual(advanced.settlement_state, SettlementState.RECONCILING)
        self.assertEqual(advanced.unresolved_transmission_exposure_count, 1)

    def test_not_found_only_proves_absence_when_manifest_contract_allows(self) -> None:
        with self.assertRaises(ReconciliationError):
            self.engine.apply_not_found(self.manifest("B"), authoritative=True)
        allowed = self.manifest("B", not_found_proves_absence=True)
        state = self.engine.apply_not_found(allowed, authoritative=True)
        self.assertEqual(state.outcome_state, OutcomeState.FAILED_CONFIRMED)


if __name__ == "__main__":
    unittest.main()
