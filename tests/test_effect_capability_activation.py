from __future__ import annotations

import unittest

from sitina.effects.activation import ActivationController, ActivationError, CapabilityLevel, IntakeKind


class EffectCapabilityActivationTests(unittest.TestCase):
    def test_readiness_history_does_not_raise_active_ceiling(self) -> None:
        controller=ActivationController.phase6a()
        for level in (CapabilityLevel.EXTERNAL_READ,CapabilityLevel.REVERSIBLE_MUTATION,CapabilityLevel.HIGH_RISK_OR_IRREVERSIBLE):
            controller=controller.record_readiness(level,report_hash=(level.name[0].lower()*64))
        self.assertEqual(controller.active_ceiling,CapabilityLevel.MOCK_ONLY); self.assertEqual(len(controller.readiness_history),3)

    def test_phase6a_cannot_raise_above_mock_only_and_phase_flag_cannot_override(self) -> None:
        controller=ActivationController.phase6a()
        with self.assertRaises(ActivationError): controller.raise_ceiling(CapabilityLevel.EXTERNAL_READ,authorization_hash="a"*64,phase_flag="6B")

    def test_disable_new_transmission_preserves_receipt_observation_and_reconciliation(self) -> None:
        controller=ActivationController.phase6a().disable_new_transmission("incident")
        self.assertFalse(controller.accepts(IntakeKind.NEW_TRANSMISSION))
        for kind in (IntakeKind.RECEIPT,IntakeKind.OBSERVATION,IntakeKind.RECONCILIATION,IntakeKind.CONTAINMENT):
            self.assertTrue(controller.accepts(kind))

    def test_lowering_ceiling_never_erases_readiness_history_or_changes_authority(self) -> None:
        controller=ActivationController.fixture_for_test(CapabilityLevel.REVERSIBLE_MUTATION).record_readiness(CapabilityLevel.HIGH_RISK_OR_IRREVERSIBLE,"b"*64)
        lowered=controller.lower_ceiling(CapabilityLevel.MOCK_ONLY,"operator-stop")
        self.assertEqual(lowered.active_ceiling,CapabilityLevel.MOCK_ONLY); self.assertEqual(lowered.readiness_history,controller.readiness_history); self.assertFalse(lowered.journal_authority_changed)


if __name__ == "__main__": unittest.main()
