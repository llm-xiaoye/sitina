from __future__ import annotations

import unittest

from sitina.effects.compensation import CompensationError, CompensationRegistry, IrreversibleDisposition
from tests.test_effect_state_matrix import request


class CompensationEffectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = CompensationRegistry(max_chain_depth=3)

    def test_compensation_is_a_new_effect_and_does_not_rewrite_original(self) -> None:
        original = request()
        compensation = request("effect-comp-1", operation="mock.undo", idempotency_binding="undo-1")
        link, event = self.registry.create(original, compensation, original_reversibility="REVERSIBLE", approval_hash="a" * 64)
        self.assertEqual(link.compensates_effect_id, original.effect_id)
        self.assertEqual(event["schema"], "COMPENSATION_EFFECT_LINKED_V1")
        completed = self.registry.complete(link.compensation_effect_id, succeeded=True)
        self.assertEqual(completed["original_outcome_rewritten"], False)

    def test_duplicate_compensation_and_excessive_chain_are_rejected(self) -> None:
        original = request()
        self.registry.create(original, request("effect-comp-1", operation="mock.undo", idempotency_binding="undo-1"), original_reversibility="REVERSIBLE", approval_hash="a" * 64)
        with self.assertRaises(CompensationError):
            self.registry.create(original, request("effect-comp-2", operation="mock.undo", idempotency_binding="undo-2"), original_reversibility="REVERSIBLE", approval_hash="a" * 64)

    def test_irreversible_effect_requires_mitigation_or_risk_acceptance(self) -> None:
        with self.assertRaises(CompensationError):
            self.registry.create(request(), request("effect-comp", operation="mock.undo"), original_reversibility="IRREVERSIBLE", approval_hash="a" * 64)
        event = self.registry.disposition_irreversible(request(), IrreversibleDisposition.MITIGATION, authority="owner")
        self.assertEqual(event["schema"], "IRREVERSIBLE_EFFECT_DISPOSITION_V1")
        self.assertNotEqual(event["disposition"], "COMPENSATED")


if __name__ == "__main__":
    unittest.main()
