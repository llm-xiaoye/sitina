from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .adapters import AdapterManifest, RecoveryLevel
from .model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState, validate_effect_state


class ReconciliationError(RuntimeError):
    pass


class ReconciliationAction(str, Enum):
    QUERY_STATUS = "QUERY_STATUS"
    RETRY_SAME_IDEMPOTENCY_KEY = "RETRY_SAME_IDEMPOTENCY_KEY"
    MANUAL_ACTION = "MANUAL_ACTION"
    SETTLE_AUTHORITATIVE_ABSENCE = "SETTLE_AUTHORITATIVE_ABSENCE"


@dataclass(frozen=True)
class ReconciliationPlan:
    recovery_level: RecoveryLevel
    actions: tuple[ReconciliationAction, ...]
    retention_expired: bool


class ReconciliationEngine:
    def plan(self, manifest: AdapterManifest, *, elapsed_seconds: int) -> ReconciliationPlan:
        if manifest.recovery_level is RecoveryLevel.A:
            expired = elapsed_seconds > manifest.idempotency_retention_seconds
            actions = (ReconciliationAction.QUERY_STATUS,) if expired else (ReconciliationAction.QUERY_STATUS, ReconciliationAction.RETRY_SAME_IDEMPOTENCY_KEY)
            return ReconciliationPlan(RecoveryLevel.A, actions, expired)
        if manifest.recovery_level is RecoveryLevel.B:
            return ReconciliationPlan(RecoveryLevel.B, (ReconciliationAction.QUERY_STATUS,), False)
        return ReconciliationPlan(RecoveryLevel.C, (ReconciliationAction.MANUAL_ACTION,), False)

    def confirm_success(self, state: EffectState, *, resolved_exposures: int) -> EffectState:
        if resolved_exposures < 1 or resolved_exposures > state.unresolved_transmission_exposure_count:
            raise ReconciliationError("invalid exposure resolution count")
        remaining = state.unresolved_transmission_exposure_count - resolved_exposures
        updated = EffectState(
            OutcomeState.SUCCEEDED,
            SettlementState.RECONCILING if remaining else SettlementState.SETTLED,
            SettlementBasis.NONE if remaining else SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION,
            ExecutionCardinality.AT_LEAST_ONE_CONFIRMED,
            remaining,
            potential_duplicate_risk=remaining > 0,
            potential_loss_risk=False,
        )
        validate_effect_state(updated)
        return updated

    def apply_not_found(self, manifest: AdapterManifest, *, authoritative: bool) -> EffectState:
        if not authoritative or not manifest.not_found_proves_absence:
            raise ReconciliationError("Not Found does not prove absence under this Adapter Manifest")
        state = EffectState(
            OutcomeState.FAILED_CONFIRMED,
            SettlementState.SETTLED,
            SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION,
            ExecutionCardinality.NONE_CONFIRMED,
            0,
        )
        validate_effect_state(state)
        return state
