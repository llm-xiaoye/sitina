from __future__ import annotations

import unittest

from sitina.effects.model import (
    EffectInvariantError,
    EffectRequest,
    EffectState,
    ExecutionCardinality,
    OutcomeState,
    SettlementBasis,
    SettlementState,
    require_new_effect_for_semantic_change,
    validate_effect_state,
)


def request(effect_id: str = "effect-1", **changes: object) -> EffectRequest:
    values = {
        "effect_id": effect_id,
        "operation": "mock.publish",
        "request": {"message": "hello"},
        "target": "mock://remote/item",
        "policy_hash": "1" * 64,
        "semantic_manifest_hash": "2" * 64,
        "risk_class": "REVERSIBLE_MUTATION",
        "credential_principal": "mock-principal",
        "credential_scope": "mock.publish",
        "idempotency_binding": "effect-1-key",
    }
    values.update(changes)
    return EffectRequest(**values)


class EffectStateMatrixTests(unittest.TestCase):
    def test_every_specified_outcome_settlement_basis_combination_is_legal(self) -> None:
        legal = {
            (OutcomeState.NOT_SENT, SettlementState.OPEN, SettlementBasis.NONE),
            (OutcomeState.IN_FLIGHT, SettlementState.OPEN, SettlementBasis.NONE),
            (OutcomeState.IN_FLIGHT, SettlementState.RECONCILING, SettlementBasis.NONE),
            (OutcomeState.OUTCOME_UNKNOWN, SettlementState.RECONCILING, SettlementBasis.NONE),
            (OutcomeState.OUTCOME_UNKNOWN, SettlementState.SETTLED, SettlementBasis.POLICY_DISPOSITION),
            (OutcomeState.SUCCEEDED, SettlementState.RECONCILING, SettlementBasis.NONE),
            (OutcomeState.SUCCEEDED, SettlementState.SETTLED, SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION),
            (OutcomeState.FAILED_CONFIRMED, SettlementState.SETTLED, SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION),
            (OutcomeState.SUCCEEDED, SettlementState.SETTLED, SettlementBasis.POLICY_DISPOSITION),
            (OutcomeState.FAILED_CONFIRMED, SettlementState.SETTLED, SettlementBasis.POLICY_DISPOSITION),
            (OutcomeState.DENIED_BEFORE_SEND, SettlementState.SETTLED, SettlementBasis.AUTHORITATIVE_LOCAL_PRE_SEND_FACT),
            (OutcomeState.CANCELLED_BEFORE_SEND, SettlementState.SETTLED, SettlementBasis.AUTHORITATIVE_LOCAL_PRE_SEND_FACT),
            (OutcomeState.EXPIRED_BEFORE_SEND, SettlementState.SETTLED, SettlementBasis.AUTHORITATIVE_LOCAL_PRE_SEND_FACT),
            (OutcomeState.OUTCOME_CONTRADICTED, SettlementState.RECONCILING, SettlementBasis.NONE),
            (OutcomeState.OUTCOME_CONTRADICTED, SettlementState.SETTLED, SettlementBasis.POLICY_DISPOSITION),
        }
        self.assertEqual(legal, set(EffectState.legal_triplets()))
        for outcome, settlement, basis in legal:
            exposure = 1 if settlement is SettlementState.RECONCILING or outcome is OutcomeState.OUTCOME_UNKNOWN else 0
            cardinality = ExecutionCardinality.UNKNOWN_CARDINALITY
            if outcome is OutcomeState.NOT_SENT or outcome.name.endswith("BEFORE_SEND"):
                cardinality = ExecutionCardinality.NONE_CONFIRMED
            elif outcome is OutcomeState.SUCCEEDED:
                cardinality = ExecutionCardinality.AT_LEAST_ONE_CONFIRMED
            state = EffectState(outcome, settlement, basis, cardinality, exposure)
            self.assertEqual(validate_effect_state(state)["schema"], "EFFECT_STATE_INVARIANT_ACCEPTED_V1")

    def test_unlisted_combinations_emit_stable_rejection_fact(self) -> None:
        invalid = EffectState(
            OutcomeState.OUTCOME_UNKNOWN,
            SettlementState.SETTLED,
            SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION,
            ExecutionCardinality.UNKNOWN_CARDINALITY,
            1,
        )
        with self.assertRaises(EffectInvariantError) as raised:
            validate_effect_state(invalid)
        self.assertEqual(raised.exception.fact["schema"], "EFFECT_STATE_INVARIANT_REJECTED_V1")
        self.assertEqual(raised.exception.fact["state_hash"], raised.exception.fact_hash)

    def test_exactly_one_requires_closed_exposure_and_covering_remote_proof(self) -> None:
        state = EffectState(
            OutcomeState.SUCCEEDED,
            SettlementState.SETTLED,
            SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION,
            ExecutionCardinality.EXACTLY_ONE_CONFIRMED,
            0,
            exactly_once_proof_covers_all_attempts=True,
        )
        validate_effect_state(state)
        with self.assertRaises(EffectInvariantError):
            validate_effect_state(state.with_updates(exactly_once_proof_covers_all_attempts=False))

    def test_semantic_change_requires_new_effect_and_retry_requires_new_attempt(self) -> None:
        original = request()
        changed_same_id = request(request={"message": "different"})
        with self.assertRaises(ValueError):
            require_new_effect_for_semantic_change(original, changed_same_id)
        superseding = request("effect-2", request={"message": "different"}, supersedes_effect_id="effect-1")
        require_new_effect_for_semantic_change(original, superseding)
        self.assertNotEqual(original.new_attempt("attempt-1").effect_attempt_id, original.new_attempt("attempt-2").effect_attempt_id)


if __name__ == "__main__":
    unittest.main()
