from __future__ import annotations

import unittest

from sitina.protocols.arbitration import Arbitration, ArbitrationError, ArbitrationState


class ArbitrationProtocolTests(unittest.TestCase):
    def arbitration(self) -> Arbitration:
        return Arbitration.open("arbitration-1", "obligation-1", "11" * 32, max_appeals=2, appeal_deadline="2099-01-01T00:00:00Z", appeal_authorities=("appeals-board",))[0]

    def test_binding_effect_blocks_dispatch_until_enforced(self) -> None:
        arbitration, _ = self.arbitration().admit(("claim-1",), "arbiter-1")
        arbitration, event = arbitration.decide("decision-a", binding_scope=("task-1",), evidence_refs=("21" * 32,))
        self.assertEqual(arbitration.state, ArbitrationState.ENFORCEMENT_PENDING)
        self.assertTrue(arbitration.blocks_dispatch("task-1"))
        self.assertFalse(event["obligation_satisfied"])
        enforced, event = arbitration.enforce("31" * 32)
        self.assertEqual(enforced.state, ArbitrationState.ENFORCED)
        self.assertTrue(event["obligation_satisfied"])

    def test_decision_without_enforcement_never_satisfies_obligation(self) -> None:
        arbitration, _ = self.arbitration().admit(("claim-1",), "arbiter-1")
        arbitration, _ = arbitration.decide("decision-a", binding_scope=("task-1",), evidence_refs=("21" * 32,))
        self.assertFalse(arbitration.obligation_satisfied)

    def test_appeal_requires_new_evidence_deadline_authority_and_bound(self) -> None:
        arbitration, _ = self.arbitration().admit(("claim-1",), "arbiter-1")
        arbitration, _ = arbitration.decide("decision-a", binding_scope=("task-1",), evidence_refs=("21" * 32,))
        arbitration, _ = arbitration.enforce("31" * 32)
        with self.assertRaises(ArbitrationError):
            arbitration.appeal("agent-a", ("41" * 32,), now="2026-07-13T00:00:00Z")
        appealed, _ = arbitration.appeal("appeals-board", ("41" * 32,), now="2026-07-13T00:00:00Z")
        self.assertEqual(appealed.appeal_generation, 1)
        with self.assertRaises(ArbitrationError):
            appealed.appeal("appeals-board", ("41" * 32,), now="2026-07-13T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
