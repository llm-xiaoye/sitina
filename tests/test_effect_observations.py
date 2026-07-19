from __future__ import annotations

import unittest

from sitina.effects.model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState
from sitina.effects.observations import (
    ApplicationDisposition,
    EffectObservationApplier,
    ObservationIngress,
    ObservationIngressState,
    make_signed_observation,
)


class EffectObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"source-key"
        self.ingress = ObservationIngress({"mock-source": self.key}, now=lambda: 1000)
        self.binding = {
            "source_identity": "mock-source",
            "manifest_hash": "a" * 64,
            "effect_id": "effect-1",
            "effect_attempt_id": "attempt-1",
            "request_hash": "b" * 64,
            "external_request_id": "external-1",
        }

    def signed(self, **changes: object) -> dict:
        value = {**self.binding, "schema_major": 1, "observation_id": "observation-1", "nonce": "nonce-1", "received_at": 1000, "remote_outcome": "SUCCEEDED", "remote_execution_id": "execution-1"}
        value.update(changes)
        return make_signed_observation(value, self.key)

    def test_all_authentication_and_identity_dimensions_are_bound(self) -> None:
        admitted = self.ingress.admit(self.signed(), expected=self.binding, external_request_id_required=True)
        self.assertEqual(admitted.state, ObservationIngressState.ADMITTED)
        for field, value in (("manifest_hash", "c" * 64), ("effect_id", "effect-2"), ("request_hash", "d" * 64), ("schema_major", 2), ("received_at", 1)):
            candidate = self.signed(observation_id=f"bad-{field}", nonce=f"nonce-{field}", **{field: value})
            result = self.ingress.admit(candidate, expected=self.binding, external_request_id_required=True)
            self.assertEqual(result.state, ObservationIngressState.QUARANTINED, field)

    def test_nonce_replay_and_signature_failure_are_quarantined(self) -> None:
        raw = self.signed()
        self.assertEqual(self.ingress.admit(raw, expected=self.binding, external_request_id_required=True).state, ObservationIngressState.ADMITTED)
        self.assertEqual(self.ingress.admit(raw, expected=self.binding, external_request_id_required=True).reason, "NONCE_REPLAY")
        bad = self.signed(observation_id="observation-2", nonce="nonce-2")
        bad["signature"] = "0" * 64
        self.assertEqual(self.ingress.admit(bad, expected=self.binding, external_request_id_required=True).state, ObservationIngressState.QUARANTINED)

    def test_approved_fallback_identity_is_advisory_when_not_unique(self) -> None:
        raw = self.signed(external_request_id=None, provider_response_id="response-1")
        expected = dict(self.binding)
        expected["external_request_id"] = None
        result = self.ingress.admit(raw, expected=expected, external_request_id_required=False, fallback_identity_unique=False)
        self.assertEqual(result.state, ObservationIngressState.ADMITTED)
        self.assertEqual(result.observation.application_disposition, ApplicationDisposition.ADVISORY)

    def test_effect_stream_cas_serializes_application_and_preserves_contradiction(self) -> None:
        first = self.ingress.admit(self.signed(), expected=self.binding, external_request_id_required=True).observation
        second_raw = self.signed(observation_id="observation-2", nonce="nonce-2", remote_outcome="FAILED_CONFIRMED", remote_execution_id="execution-2")
        second = self.ingress.admit(second_raw, expected=self.binding, external_request_id_required=True).observation
        applier = EffectObservationApplier(
            EffectState(OutcomeState.OUTCOME_UNKNOWN, SettlementState.RECONCILING, SettlementBasis.NONE, ExecutionCardinality.UNKNOWN_CARDINALITY, 1)
        )
        applied = applier.apply(first, expected_effect_version=0)
        self.assertEqual(applied.state.outcome_state, OutcomeState.SUCCEEDED)
        with self.assertRaises(ValueError):
            applier.apply(second, expected_effect_version=0)
        contradicted = applier.apply(second, expected_effect_version=1)
        self.assertEqual(contradicted.state.outcome_state, OutcomeState.OUTCOME_CONTRADICTED)
        self.assertEqual(len(contradicted.contradiction_observation_ids), 2)


if __name__ == "__main__":
    unittest.main()
