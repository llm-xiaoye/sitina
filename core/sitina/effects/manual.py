from __future__ import annotations

from dataclasses import dataclass

from .model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState, validate_effect_state


class ManualResolutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ManualResolution:
    state: EffectState
    authority: str
    policy_hash: str
    disclosure: dict[str, object]


def confirm_remote_fact(state: EffectState, *, authority_kind: str, claimed_outcome: OutcomeState) -> EffectState:
    if authority_kind != "AUTHORITATIVE_REMOTE_OBSERVATION":
        raise ManualResolutionError("a human statement cannot confirm a remote fact")
    if claimed_outcome not in {OutcomeState.SUCCEEDED, OutcomeState.FAILED_CONFIRMED}:
        raise ManualResolutionError("manual confirmation requires a confirmed remote outcome")
    cardinality = ExecutionCardinality.AT_LEAST_ONE_CONFIRMED if claimed_outcome is OutcomeState.SUCCEEDED else ExecutionCardinality.NONE_CONFIRMED
    updated = EffectState(claimed_outcome, SettlementState.SETTLED, SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION, cardinality, 0)
    validate_effect_state(updated)
    return updated


def policy_settle_unknown(
    state: EffectState,
    *,
    authority: str,
    policy_hash: str,
    monitoring_owner: str,
    obligation_disposition: str,
) -> ManualResolution:
    if state.outcome_state is not OutcomeState.OUTCOME_UNKNOWN or state.settlement_state is not SettlementState.RECONCILING:
        raise ManualResolutionError("only a reconciling unknown can be policy-settled")
    if len(policy_hash) != 64 or not authority or not monitoring_owner:
        raise ManualResolutionError("manual policy resolution bindings are incomplete")
    updated = state.with_updates(settlement_state=SettlementState.SETTLED, settlement_basis=SettlementBasis.POLICY_DISPOSITION)
    validate_effect_state(updated)
    disclosure = {
        "physical_uncertainty_preserved": True,
        "residual_risk": True,
        "potential_duplicate_risk": updated.potential_duplicate_risk,
        "potential_loss_risk": updated.potential_loss_risk,
        "monitoring_owner": monitoring_owner,
        "obligation_disposition": obligation_disposition,
    }
    return ManualResolution(updated, authority, policy_hash, disclosure)


def apply_late_confirmation(resolution: ManualResolution, outcome: OutcomeState, *, remote_evidence_hash: str) -> ManualResolution:
    if outcome not in {OutcomeState.SUCCEEDED, OutcomeState.FAILED_CONFIRMED} or len(remote_evidence_hash) != 64:
        raise ManualResolutionError("late confirmation is not authoritative")
    cardinality = ExecutionCardinality.AT_LEAST_ONE_CONFIRMED if outcome is OutcomeState.SUCCEEDED else ExecutionCardinality.NONE_CONFIRMED
    updated = EffectState(
        outcome,
        SettlementState.SETTLED,
        SettlementBasis.POLICY_DISPOSITION,
        cardinality,
        0,
        potential_duplicate_risk=False,
        potential_loss_risk=False,
        confirmed_after_settlement=True,
    )
    validate_effect_state(updated)
    return ManualResolution(updated, resolution.authority, resolution.policy_hash, {**resolution.disclosure, "confirmed_after_settlement": True, "remote_evidence_hash": remote_evidence_hash})
