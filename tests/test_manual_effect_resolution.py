from __future__ import annotations

import unittest

from sitina.effects.manual import ManualResolutionError, apply_late_confirmation, confirm_remote_fact, policy_settle_unknown
from sitina.effects.model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState


def unknown() -> EffectState:
    return EffectState(OutcomeState.OUTCOME_UNKNOWN, SettlementState.RECONCILING, SettlementBasis.NONE, ExecutionCardinality.UNKNOWN_CARDINALITY, 1, potential_duplicate_risk=True, potential_loss_risk=True)


class ManualEffectResolutionTests(unittest.TestCase):
    def test_human_statement_alone_cannot_confirm_remote_fact(self) -> None:
        with self.assertRaises(ManualResolutionError):
            confirm_remote_fact(unknown(), authority_kind="HUMAN_STATEMENT", claimed_outcome=OutcomeState.SUCCEEDED)

    def test_policy_settlement_preserves_uncertainty_risks_and_monitoring(self) -> None:
        resolution = policy_settle_unknown(unknown(), authority="owner", policy_hash="a" * 64, monitoring_owner="incident-1", obligation_disposition="TRANSFERRED")
        self.assertEqual(resolution.state.outcome_state, OutcomeState.OUTCOME_UNKNOWN)
        self.assertEqual(resolution.state.settlement_basis, SettlementBasis.POLICY_DISPOSITION)
        self.assertTrue(resolution.disclosure["physical_uncertainty_preserved"])
        self.assertTrue(resolution.disclosure["potential_duplicate_risk"])

    def test_late_confirmation_advances_knowledge_but_preserves_policy_basis(self) -> None:
        settled = policy_settle_unknown(unknown(), authority="owner", policy_hash="a" * 64, monitoring_owner="incident-1", obligation_disposition="TRANSFERRED")
        late = apply_late_confirmation(settled, OutcomeState.SUCCEEDED, remote_evidence_hash="b" * 64)
        self.assertEqual(late.state.outcome_state, OutcomeState.SUCCEEDED)
        self.assertEqual(late.state.settlement_basis, SettlementBasis.POLICY_DISPOSITION)
        self.assertTrue(late.state.confirmed_after_settlement)


if __name__ == "__main__":
    unittest.main()
