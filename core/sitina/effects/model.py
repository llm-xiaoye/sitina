from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class OutcomeState(str, Enum):
    NOT_SENT = "NOT_SENT"
    IN_FLIGHT = "IN_FLIGHT"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    SUCCEEDED = "SUCCEEDED"
    FAILED_CONFIRMED = "FAILED_CONFIRMED"
    DENIED_BEFORE_SEND = "DENIED_BEFORE_SEND"
    CANCELLED_BEFORE_SEND = "CANCELLED_BEFORE_SEND"
    EXPIRED_BEFORE_SEND = "EXPIRED_BEFORE_SEND"
    OUTCOME_CONTRADICTED = "OUTCOME_CONTRADICTED"


class SettlementState(str, Enum):
    OPEN = "OPEN"
    RECONCILING = "RECONCILING"
    SETTLED = "SETTLED"


class SettlementBasis(str, Enum):
    NONE = "NONE"
    AUTHORITATIVE_REMOTE_OBSERVATION = "AUTHORITATIVE_REMOTE_OBSERVATION"
    AUTHORITATIVE_LOCAL_PRE_SEND_FACT = "AUTHORITATIVE_LOCAL_PRE_SEND_FACT"
    POLICY_DISPOSITION = "POLICY_DISPOSITION"


class ExecutionCardinality(str, Enum):
    NONE_CONFIRMED = "NONE_CONFIRMED"
    AT_LEAST_ONE_CONFIRMED = "AT_LEAST_ONE_CONFIRMED"
    EXACTLY_ONE_CONFIRMED = "EXACTLY_ONE_CONFIRMED"
    MULTIPLE_CONFIRMED = "MULTIPLE_CONFIRMED"
    UNKNOWN_CARDINALITY = "UNKNOWN_CARDINALITY"
    CONTRADICTED_CARDINALITY = "CONTRADICTED_CARDINALITY"


_LEGAL_TRIPLETS = (
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
)


@dataclass(frozen=True)
class EffectState:
    outcome_state: OutcomeState = OutcomeState.NOT_SENT
    settlement_state: SettlementState = SettlementState.OPEN
    settlement_basis: SettlementBasis = SettlementBasis.NONE
    execution_cardinality_state: ExecutionCardinality = ExecutionCardinality.NONE_CONFIRMED
    unresolved_transmission_exposure_count: int = 0
    potential_duplicate_risk: bool = False
    potential_loss_risk: bool = False
    exactly_once_proof_covers_all_attempts: bool = False
    confirmed_after_settlement: bool = False

    def __post_init__(self) -> None:
        if self.unresolved_transmission_exposure_count < 0:
            raise ValueError("unresolved exposure count cannot be negative")

    @staticmethod
    def legal_triplets() -> tuple[tuple[OutcomeState, SettlementState, SettlementBasis], ...]:
        return _LEGAL_TRIPLETS

    def mapping(self) -> dict[str, Any]:
        return {
            "outcome_state": self.outcome_state.value,
            "settlement_state": self.settlement_state.value,
            "settlement_basis": self.settlement_basis.value,
            "execution_cardinality_state": self.execution_cardinality_state.value,
            "unresolved_transmission_exposure_count": self.unresolved_transmission_exposure_count,
            "potential_duplicate_risk": self.potential_duplicate_risk,
            "potential_loss_risk": self.potential_loss_risk,
            "exactly_once_proof_covers_all_attempts": self.exactly_once_proof_covers_all_attempts,
            "confirmed_after_settlement": self.confirmed_after_settlement,
        }

    def with_updates(self, **changes: Any) -> "EffectState":
        return replace(self, **changes)


class EffectInvariantError(ValueError):
    def __init__(self, reason: str, fact: dict[str, Any]):
        super().__init__(reason)
        self.fact = fact
        self.fact_hash = fact["state_hash"]


def _rejection(state: EffectState, reason: str) -> EffectInvariantError:
    state_hash = domain_hash("EFFECT_STATE_INVARIANT_REJECTION", canonical_json_bytes(state.mapping()))
    fact = {
        "schema": "EFFECT_STATE_INVARIANT_REJECTED_V1",
        "state_hash": state_hash,
        "reason": reason,
        "state": state.mapping(),
    }
    return EffectInvariantError(reason, fact)


def validate_effect_state(state: EffectState) -> dict[str, Any]:
    triplet = (state.outcome_state, state.settlement_state, state.settlement_basis)
    if triplet not in _LEGAL_TRIPLETS:
        raise _rejection(state, "UNLISTED_OUTCOME_SETTLEMENT_BASIS_COMBINATION")
    if state.outcome_state in {
        OutcomeState.NOT_SENT,
        OutcomeState.DENIED_BEFORE_SEND,
        OutcomeState.CANCELLED_BEFORE_SEND,
        OutcomeState.EXPIRED_BEFORE_SEND,
    }:
        if state.unresolved_transmission_exposure_count != 0 or state.execution_cardinality_state is not ExecutionCardinality.NONE_CONFIRMED:
            raise _rejection(state, "PRE_SEND_STATE_CANNOT_HAVE_EXECUTION_OR_EXPOSURE")
    if state.outcome_state is OutcomeState.OUTCOME_UNKNOWN and state.unresolved_transmission_exposure_count < 1:
        raise _rejection(state, "UNKNOWN_REQUIRES_TRANSMISSION_EXPOSURE")
    if state.settlement_state is SettlementState.RECONCILING and state.unresolved_transmission_exposure_count < 1:
        raise _rejection(state, "RECONCILING_REQUIRES_OPEN_EXPOSURE")
    if state.outcome_state is OutcomeState.SUCCEEDED and state.execution_cardinality_state is ExecutionCardinality.NONE_CONFIRMED:
        raise _rejection(state, "SUCCESS_REQUIRES_AT_LEAST_ONE_EXECUTION")
    if state.execution_cardinality_state is ExecutionCardinality.EXACTLY_ONE_CONFIRMED:
        if state.unresolved_transmission_exposure_count or not state.exactly_once_proof_covers_all_attempts:
            raise _rejection(state, "EXACTLY_ONE_REQUIRES_CLOSED_EXPOSURE_AND_COVERING_REMOTE_PROOF")
    if state.execution_cardinality_state is ExecutionCardinality.MULTIPLE_CONFIRMED and state.outcome_state not in {OutcomeState.SUCCEEDED, OutcomeState.OUTCOME_CONTRADICTED}:
        raise _rejection(state, "MULTIPLE_EXECUTIONS_REQUIRE_SUCCESS_OR_CONTRADICTION")
    return {
        "schema": "EFFECT_STATE_INVARIANT_ACCEPTED_V1",
        "state_hash": domain_hash("EFFECT_STATE", canonical_json_bytes(state.mapping())),
    }


@dataclass(frozen=True)
class EffectAttemptIdentity:
    effect_id: str
    effect_attempt_id: str
    request_hash: str
    idempotency_binding: str

    def __post_init__(self) -> None:
        validate_identifier(self.effect_attempt_id, field="effect_attempt_id")


@dataclass(frozen=True)
class EffectRequest:
    effect_id: str
    operation: str
    request: Mapping[str, Any]
    target: str
    policy_hash: str
    semantic_manifest_hash: str
    risk_class: str
    credential_principal: str
    credential_scope: str
    idempotency_binding: str
    supersedes_effect_id: str | None = None
    compensates_effect_id: str | None = None

    def __post_init__(self) -> None:
        for value, field in (
            (self.effect_id, "effect_id"),
            (self.operation, "operation"),
            (self.risk_class, "risk_class"),
            (self.credential_principal, "credential_principal"),
            (self.credential_scope, "credential_scope"),
            (self.idempotency_binding, "idempotency_binding"),
        ):
            validate_identifier(value, field=field)
        for optional, field in ((self.supersedes_effect_id, "supersedes_effect_id"), (self.compensates_effect_id, "compensates_effect_id")):
            if optional is not None:
                validate_identifier(optional, field=field)
        if not self.target or self.target != self.target.strip():
            raise ValueError("effect target must be non-empty and trimmed")
        for value, field in ((self.policy_hash, "policy_hash"), (self.semantic_manifest_hash, "semantic_manifest_hash")):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"invalid {field}")
        canonical_json_bytes(dict(self.request))
        if self.supersedes_effect_id == self.effect_id or self.compensates_effect_id == self.effect_id:
            raise ValueError("effect cannot supersede or compensate itself")

    def semantic_mapping(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "request": dict(self.request),
            "target": self.target,
            "policy_hash": self.policy_hash,
            "semantic_manifest_hash": self.semantic_manifest_hash,
            "risk_class": self.risk_class,
            "credential_principal": self.credential_principal,
            "credential_scope": self.credential_scope,
            "idempotency_binding": self.idempotency_binding,
        }

    @property
    def request_hash(self) -> str:
        return domain_hash("EFFECT_REQUEST", canonical_json_bytes(self.semantic_mapping()))

    def new_attempt(self, effect_attempt_id: str) -> EffectAttemptIdentity:
        return EffectAttemptIdentity(self.effect_id, effect_attempt_id, self.request_hash, self.idempotency_binding)


def require_new_effect_for_semantic_change(previous: EffectRequest, candidate: EffectRequest) -> None:
    changed = previous.request_hash != candidate.request_hash
    if changed and candidate.effect_id == previous.effect_id:
        raise ValueError("semantic EffectRequest change requires a new effect_id")
    if changed and candidate.supersedes_effect_id != previous.effect_id:
        raise ValueError("semantic replacement must bind supersedes_effect_id")
    if not changed and candidate.effect_id != previous.effect_id and candidate.supersedes_effect_id is None and candidate.compensates_effect_id is None:
        raise ValueError("new logical Effect identity requires explicit lineage")
