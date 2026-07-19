from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash

from .model import (
    EffectState,
    ExecutionCardinality,
    OutcomeState,
    SettlementBasis,
    SettlementState,
    validate_effect_state,
)


class ObservationIngressState(str, Enum):
    ADMITTED = "ADMITTED"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


class ApplicationDisposition(str, Enum):
    UNAPPLIED = "UNAPPLIED"
    APPLIED = "APPLIED"
    ADVISORY = "ADVISORY"
    SUPERSEDED = "SUPERSEDED"


def _signed_body(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes({key: item for key, item in value.items() if key != "signature"})


def make_signed_observation(value: Mapping[str, Any], key: bytes) -> dict[str, Any]:
    body = dict(value)
    body["signature"] = hmac.new(key, b"SITINA-OBSERVATION-V1\0" + _signed_body(body), hashlib.sha256).hexdigest()
    return body


@dataclass(frozen=True)
class Observation:
    observation_id: str
    source_identity: str
    manifest_hash: str
    effect_id: str
    effect_attempt_id: str
    request_hash: str
    external_request_id: str | None
    remote_outcome: OutcomeState
    remote_execution_id: str | None
    raw_evidence_hash: str
    application_disposition: ApplicationDisposition = ApplicationDisposition.UNAPPLIED


@dataclass(frozen=True)
class ObservationAdmissionResult:
    state: ObservationIngressState
    reason: str | None
    observation: Observation | None
    quarantine_hash: str | None = None


class ObservationIngress:
    def __init__(self, source_keys: Mapping[str, bytes], *, now: Callable[[], int], max_clock_skew_seconds: int = 300):
        self.source_keys = dict(source_keys)
        self.now = now
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self._nonces: set[tuple[str, str]] = set()

    def _quarantine(self, raw: Mapping[str, Any], reason: str) -> ObservationAdmissionResult:
        return ObservationAdmissionResult(
            ObservationIngressState.QUARANTINED,
            reason,
            None,
            domain_hash("OBSERVATION_QUARANTINE", _signed_body(raw)),
        )

    def admit(
        self,
        raw: Mapping[str, Any],
        *,
        expected: Mapping[str, Any],
        external_request_id_required: bool,
        fallback_identity_unique: bool = True,
    ) -> ObservationAdmissionResult:
        required = {"schema_major", "observation_id", "source_identity", "manifest_hash", "effect_id", "effect_attempt_id", "request_hash", "nonce", "received_at", "remote_outcome", "signature"}
        if not required.issubset(raw):
            return self._quarantine(raw, "SCHEMA_INVALID")
        if raw.get("schema_major") != 1:
            return self._quarantine(raw, "SCHEMA_INVALID")
        source = raw.get("source_identity")
        key = self.source_keys.get(str(source))
        if key is None:
            return self._quarantine(raw, "SOURCE_UNTRUSTED")
        expected_signature = hmac.new(key, b"SITINA-OBSERVATION-V1\0" + _signed_body(raw), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(raw.get("signature")), expected_signature):
            return self._quarantine(raw, "SIGNATURE_INVALID")
        try:
            received_at = int(raw["received_at"])
        except (TypeError, ValueError):
            return self._quarantine(raw, "TIMESTAMP_INVALID")
        if abs(self.now() - received_at) > self.max_clock_skew_seconds:
            return self._quarantine(raw, "TIMESTAMP_OUT_OF_WINDOW")
        nonce_key = (str(source), str(raw["nonce"]))
        if nonce_key in self._nonces:
            return self._quarantine(raw, "NONCE_REPLAY")
        for field in ("source_identity", "manifest_hash", "effect_id", "effect_attempt_id", "request_hash"):
            if raw.get(field) != expected.get(field):
                return self._quarantine(raw, f"{field.upper()}_MISMATCH")
        external_request_id = raw.get("external_request_id")
        if external_request_id_required and external_request_id != expected.get("external_request_id"):
            return self._quarantine(raw, "EXTERNAL_REQUEST_ID_MISMATCH")
        if external_request_id is None and not any(raw.get(field) for field in ("provider_response_id", "provider_idempotency_identity", "signed_session_request_identity")):
            return self._quarantine(raw, "FALLBACK_IDENTITY_MISSING")
        try:
            remote_outcome = OutcomeState(str(raw["remote_outcome"]))
        except ValueError:
            return self._quarantine(raw, "REMOTE_OUTCOME_INVALID")
        if remote_outcome not in {OutcomeState.SUCCEEDED, OutcomeState.FAILED_CONFIRMED}:
            return self._quarantine(raw, "REMOTE_OUTCOME_NOT_AUTHORITATIVE")
        self._nonces.add(nonce_key)
        disposition = ApplicationDisposition.ADVISORY if external_request_id is None and not fallback_identity_unique else ApplicationDisposition.UNAPPLIED
        observation = Observation(
            str(raw["observation_id"]),
            str(source),
            str(raw["manifest_hash"]),
            str(raw["effect_id"]),
            str(raw["effect_attempt_id"]),
            str(raw["request_hash"]),
            str(external_request_id) if external_request_id is not None else None,
            remote_outcome,
            str(raw["remote_execution_id"]) if raw.get("remote_execution_id") is not None else None,
            hashlib.sha256(_signed_body(raw)).hexdigest(),
            disposition,
        )
        return ObservationAdmissionResult(ObservationIngressState.ADMITTED, None, observation)


@dataclass(frozen=True)
class ObservationApplicationResult:
    state: EffectState
    effect_version: int
    observation: Observation
    contradiction_observation_ids: tuple[str, ...] = ()


class EffectObservationApplier:
    def __init__(self, state: EffectState, *, effect_version: int = 0):
        self.state = state
        self.effect_version = effect_version
        self._applied: dict[str, Observation] = {}

    def apply(self, observation: Observation, *, expected_effect_version: int) -> ObservationApplicationResult:
        if expected_effect_version != self.effect_version:
            raise ValueError("Effect Stream expected version conflict")
        if observation.observation_id in self._applied:
            prior = self._applied[observation.observation_id]
            return ObservationApplicationResult(self.state, self.effect_version, prior)
        if observation.application_disposition is ApplicationDisposition.ADVISORY:
            admitted = replace(observation, application_disposition=ApplicationDisposition.ADVISORY)
            self._applied[observation.observation_id] = admitted
            self.effect_version += 1
            return ObservationApplicationResult(self.state, self.effect_version, admitted)
        authoritative_prior = [item for item in self._applied.values() if item.application_disposition is ApplicationDisposition.APPLIED]
        contradictory = [item for item in authoritative_prior if item.remote_outcome != observation.remote_outcome]
        admitted = replace(observation, application_disposition=ApplicationDisposition.APPLIED)
        if contradictory:
            new_state = EffectState(
                OutcomeState.OUTCOME_CONTRADICTED,
                SettlementState.RECONCILING,
                SettlementBasis.NONE,
                ExecutionCardinality.CONTRADICTED_CARDINALITY,
                max(1, self.state.unresolved_transmission_exposure_count),
                potential_duplicate_risk=True,
                potential_loss_risk=True,
            )
            contradiction_ids = tuple(sorted({observation.observation_id, *(item.observation_id for item in contradictory)}))
        elif observation.remote_outcome is OutcomeState.SUCCEEDED:
            remaining = max(0, self.state.unresolved_transmission_exposure_count - 1)
            new_state = EffectState(
                OutcomeState.SUCCEEDED,
                SettlementState.RECONCILING if remaining else SettlementState.SETTLED,
                SettlementBasis.NONE if remaining else SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION,
                ExecutionCardinality.AT_LEAST_ONE_CONFIRMED,
                remaining,
                potential_duplicate_risk=remaining > 0,
                potential_loss_risk=False,
            )
            contradiction_ids = ()
        else:
            remaining = max(0, self.state.unresolved_transmission_exposure_count - 1)
            if remaining:
                # A failure observation does not settle other unknown transmissions.
                new_state = EffectState(
                    OutcomeState.OUTCOME_UNKNOWN,
                    SettlementState.RECONCILING,
                    SettlementBasis.NONE,
                    ExecutionCardinality.UNKNOWN_CARDINALITY,
                    remaining,
                    potential_duplicate_risk=True,
                    potential_loss_risk=True,
                )
            else:
                new_state = EffectState(
                    OutcomeState.FAILED_CONFIRMED,
                    SettlementState.SETTLED,
                    SettlementBasis.AUTHORITATIVE_REMOTE_OBSERVATION,
                    ExecutionCardinality.NONE_CONFIRMED,
                    0,
                )
            contradiction_ids = ()
        validate_effect_state(new_state)
        self.state = new_state
        self.effect_version += 1
        self._applied[observation.observation_id] = admitted
        return ObservationApplicationResult(new_state, self.effect_version, admitted, contradiction_ids)
