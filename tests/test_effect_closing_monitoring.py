from __future__ import annotations

import unittest

from sitina.effects.closing import ClosingEffectPurpose, ClosingPermit, ClosingPermitError
from sitina.effects.monitoring import MonitoringTransfer, MonitoringTransferError, TransferState


class EffectClosingMonitoringTests(unittest.TestCase):
    def test_closing_permit_rejects_ordinary_expansion(self) -> None:
        permit = ClosingPermit("closing-1", "run-1", frozenset({"effect-1"}), max_depth=2, purposes=frozenset({ClosingEffectPurpose.RECONCILIATION}))
        with self.assertRaises(ClosingPermitError):
            permit.authorize(effect_id="effect-2", linked_effect_id="effect-1", purpose="ORDINARY_MUTATION", depth=1)

    def test_reconciliation_compensation_and_disclosure_require_exact_link(self) -> None:
        permit = ClosingPermit("closing-2", "run-1", frozenset({"effect-1"}), max_depth=2, purposes=frozenset(ClosingEffectPurpose))
        for purpose in (ClosingEffectPurpose.RECONCILIATION, ClosingEffectPurpose.COMPENSATION, ClosingEffectPurpose.DISCLOSURE):
            event = permit.authorize(effect_id=f"new-{purpose.value.lower()}", linked_effect_id="effect-1", purpose=purpose, depth=1)
            self.assertEqual(event["schema"], "CLOSING_EFFECT_AUTHORIZED_V1")
        with self.assertRaises(ClosingPermitError):
            permit.authorize(effect_id="new-x", linked_effect_id="other", purpose=ClosingEffectPurpose.RECONCILIATION, depth=1)

    def test_successor_accepts_before_source_ack_releases_terminal_blocker(self) -> None:
        transfer = MonitoringTransfer.create("transfer-1", "run-1", "incident-1", ("effect-1",), "a" * 64)
        with self.assertRaises(MonitoringTransferError):
            transfer.acknowledge_source()
        transfer, accepted = transfer.accept_successor(authority="incident-owner")
        self.assertEqual(accepted["schema"], "MONITORING_OBLIGATION_ACCEPTED_V1")
        transfer, ack = transfer.acknowledge_source()
        self.assertEqual(transfer.state, TransferState.ACKNOWLEDGED)
        self.assertTrue(ack["terminal_blocker_released"])

    def test_late_actions_use_successor_authority_after_transfer(self) -> None:
        transfer = MonitoringTransfer.create("transfer-2", "run-1", "incident-1", ("effect-1",), "a" * 64)
        transfer, _ = transfer.accept_successor(authority="incident-owner")
        transfer, _ = transfer.acknowledge_source()
        event = transfer.authorize_late_action("effect-1", authority="incident-owner")
        self.assertEqual(event["authority_stream"], "incident-1")
        with self.assertRaises(MonitoringTransferError):
            transfer.authorize_late_action("effect-1", authority="run-1")


if __name__ == "__main__":
    unittest.main()
