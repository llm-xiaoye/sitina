from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import validate_identifier

from .model import (
    EffectRequest,
    EffectState,
    ExecutionCardinality,
    OutcomeState,
    SettlementBasis,
    SettlementState,
    validate_effect_state,
)


class EffectGatewayError(RuntimeError):
    pass


class AttemptDisposition(str, Enum):
    ABORTED_BEFORE_SEND = "ABORTED_BEFORE_SEND"
    REJECTED_BEFORE_SEND = "REJECTED_BEFORE_SEND"
    MAY_HAVE_BEEN_SENT = "MAY_HAVE_BEEN_SENT"
    TRANSMITTED_WITH_OBSERVATION_AT_CLOSE = "TRANSMITTED_WITH_OBSERVATION_AT_CLOSE"


@dataclass(frozen=True)
class TaskFence:
    task_attempt_id: str
    generation: int
    token: str
    expires_at: int

    def __post_init__(self) -> None:
        validate_identifier(self.task_attempt_id, field="task_attempt_id")
        validate_identifier(self.token, field="task_fencing_token")
        if self.generation < 1:
            raise ValueError("task fence generation must be positive")

    def assert_valid(self, now: int) -> None:
        if now > self.expires_at:
            raise EffectGatewayError("Task Fence expired before InvocationStarted")


@dataclass(frozen=True)
class DispatchFence:
    control_id: str
    generation: int
    token: str
    expires_at: int

    def __post_init__(self) -> None:
        validate_identifier(self.control_id, field="dispatch_control_id")
        validate_identifier(self.token, field="dispatch_fencing_token")
        if self.generation < 1:
            raise ValueError("dispatch fence generation must be positive")

    def assert_valid(self, now: int) -> None:
        if now > self.expires_at:
            raise EffectGatewayError("Dispatch Fence expired before InvocationStarted")


@dataclass(frozen=True)
class EffectAttempt:
    effect_attempt_id: str
    task_fence: TaskFence
    prepared: bool = False
    approval_hash: str | None = None
    credential_handle_id: str | None = None
    manifest_hash: str | None = None
    invocation_started: bool = False
    dispatch_fence: DispatchFence | None = None
    physical_send_count: int = 0
    disposition: AttemptDisposition | None = None
    linked_observation_ids: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        return self.disposition is None


@dataclass(frozen=True)
class EffectAggregate:
    request: EffectRequest
    state: EffectState
    version: int = 0
    attempts: tuple[EffectAttempt, ...] = ()

    @property
    def effect_id(self) -> str:
        return self.request.effect_id


class MockTransport:
    """Deterministic mock remote; a repeated idempotency key is not re-executed."""

    def __init__(self) -> None:
        self.physical_send_count = 0
        self.remote_execution_count = 0
        self._executions: dict[str, dict[str, Any]] = {}

    def send_once(self, request: EffectRequest, effect_attempt_id: str) -> dict[str, Any]:
        self.physical_send_count += 1
        if request.idempotency_binding not in self._executions:
            self.remote_execution_count += 1
            self._executions[request.idempotency_binding] = {
                "remote_execution_id": f"mock-execution-{self.remote_execution_count}",
                "outcome": "SUCCEEDED",
                "effect_attempt_id": effect_attempt_id,
            }
        return dict(self._executions[request.idempotency_binding])

    def query(self, idempotency_binding: str) -> dict[str, Any] | None:
        result = self._executions.get(idempotency_binding)
        return dict(result) if result is not None else None


class EffectGateway:
    def __init__(self, transport: MockTransport, *, enforce_operational_gate: bool = True):
        self.transport = transport
        self.enforce_operational_gate = enforce_operational_gate
        self._effects: dict[str, EffectAggregate] = {}

    def effect(self, effect_id: str) -> EffectAggregate:
        try:
            return self._effects[effect_id]
        except KeyError as error:
            raise EffectGatewayError("unknown effect") from error

    def open_effect(self, request: EffectRequest) -> EffectAggregate:
        prior = self._effects.get(request.effect_id)
        if prior is not None:
            if prior.request.request_hash != request.request_hash:
                raise EffectGatewayError("same Effect ID has a different request hash")
            return prior
        state = EffectState()
        validate_effect_state(state)
        aggregate = EffectAggregate(request, state)
        self._effects[request.effect_id] = aggregate
        return aggregate

    @staticmethod
    def _attempt(aggregate: EffectAggregate, effect_attempt_id: str) -> EffectAttempt:
        try:
            return next(item for item in aggregate.attempts if item.effect_attempt_id == effect_attempt_id)
        except StopIteration as error:
            raise EffectGatewayError("unknown effect attempt") from error

    @staticmethod
    def _replace_attempt(aggregate: EffectAggregate, attempt: EffectAttempt, *, state: EffectState | None = None) -> EffectAggregate:
        return replace(
            aggregate,
            version=aggregate.version + 1,
            state=state or aggregate.state,
            attempts=tuple(attempt if item.effect_attempt_id == attempt.effect_attempt_id else item for item in aggregate.attempts),
        )

    def claim_attempt(self, effect_id: str, effect_attempt_id: str, task_fence: TaskFence) -> EffectAttempt:
        validate_identifier(effect_attempt_id, field="effect_attempt_id")
        aggregate = self.effect(effect_id)
        existing = [item for item in aggregate.attempts if item.effect_attempt_id == effect_attempt_id]
        if existing:
            if existing[0].task_fence != task_fence:
                raise EffectGatewayError("same Attempt ID has a different Task Fence")
            return existing[0]
        if any(item.active for item in aggregate.attempts):
            raise EffectGatewayError("Effect already has an active Attempt")
        attempt = EffectAttempt(effect_attempt_id, task_fence)
        self._effects[effect_id] = replace(aggregate, version=aggregate.version + 1, attempts=aggregate.attempts + (attempt,))
        return attempt

    def prepare(self, effect_id: str, effect_attempt_id: str, *, approval_hash: str, credential_handle_id: str, manifest_hash: str) -> EffectAttempt:
        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        if attempt.disposition is not None or attempt.invocation_started:
            raise EffectGatewayError("Attempt can no longer be prepared")
        if len(approval_hash) != 64 or len(manifest_hash) != 64:
            raise EffectGatewayError("Prepared binding hash is invalid")
        updated = replace(attempt, prepared=True, approval_hash=approval_hash, credential_handle_id=credential_handle_id, manifest_hash=manifest_hash)
        self._effects[effect_id] = self._replace_attempt(aggregate, updated)
        return updated

    def start_invocation(
        self,
        effect_id: str,
        effect_attempt_id: str,
        dispatch_fence: DispatchFence,
        *,
        now: int,
        budget_bundle: Any | None = None,
        breaker_authorization: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        if not attempt.prepared or attempt.disposition is not None or attempt.invocation_started:
            raise EffectGatewayError("Attempt is not eligible for InvocationStarted")
        attempt.task_fence.assert_valid(now)
        dispatch_fence.assert_valid(now)
        if self.enforce_operational_gate:
            if budget_bundle is None or breaker_authorization is None:
                raise EffectGatewayError("Budget Bundle and final Circuit Breaker authorization are required")
            try:
                budget_bundle.assert_dispatch_authorized(
                    now=now,
                    effect_id=effect_id,
                    effect_attempt_id=effect_attempt_id,
                    fence=dispatch_fence.token,
                )
            except Exception as error:
                raise EffectGatewayError("Budget Bundle did not authorize InvocationStarted") from error
            if (
                breaker_authorization.get("schema") != "CIRCUIT_BREAKER_DISPATCH_AUTHORIZED_V1"
                or breaker_authorization.get("effect_attempt_id") != effect_attempt_id
                or breaker_authorization.get("fence") != dispatch_fence.token
            ):
                raise EffectGatewayError("Circuit Breaker final authorization binding mismatch")
        updated = replace(attempt, invocation_started=True, dispatch_fence=dispatch_fence)
        state = EffectState(
            OutcomeState.IN_FLIGHT,
            SettlementState.OPEN,
            SettlementBasis.NONE,
            ExecutionCardinality.UNKNOWN_CARDINALITY,
            aggregate.state.unresolved_transmission_exposure_count + 1,
            potential_duplicate_risk=aggregate.state.potential_duplicate_risk,
            potential_loss_risk=True,
        )
        validate_effect_state(state)
        self._effects[effect_id] = self._replace_attempt(aggregate, updated, state=state)
        return {
            "schema": "EFFECT_INVOCATION_STARTED_V1",
            "effect_id": effect_id,
            "effect_attempt_id": effect_attempt_id,
            "task_fence": attempt.task_fence.token,
            "dispatch_fence": dispatch_fence.token,
            "budget_bundle_id": getattr(budget_bundle, "bundle_id", None),
            "breaker_control_id": breaker_authorization.get("control_id") if breaker_authorization else None,
        }

    def transmit(self, effect_id: str, effect_attempt_id: str) -> dict[str, Any]:
        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        if not attempt.invocation_started or attempt.disposition is not None:
            raise EffectGatewayError("InvocationStarted is required before transmission")
        if attempt.physical_send_count != 0:
            raise EffectGatewayError("an Effect Attempt may authorize only one physical body send")
        prior_transport_sends = self.transport.physical_send_count
        try:
            remote = self.transport.send_once(aggregate.request, effect_attempt_id)
        except Exception:
            if self.transport.physical_send_count == prior_transport_sends + 1:
                updated = replace(attempt, physical_send_count=1)
                self._effects[effect_id] = self._replace_attempt(aggregate, updated)
            raise
        updated = replace(attempt, physical_send_count=1)
        self._effects[effect_id] = self._replace_attempt(aggregate, updated)
        return {"schema": "MOCK_TRANSPORT_SUBMITTED_V1", "effect_id": effect_id, "effect_attempt_id": effect_attempt_id, **remote}

    def recover_after_crash(self, effect_id: str, effect_attempt_id: str) -> EffectAttempt:
        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        if attempt.disposition is not None:
            return attempt
        if not attempt.invocation_started:
            updated = replace(attempt, disposition=AttemptDisposition.ABORTED_BEFORE_SEND)
            state = EffectState(
                OutcomeState.CANCELLED_BEFORE_SEND,
                SettlementState.SETTLED,
                SettlementBasis.AUTHORITATIVE_LOCAL_PRE_SEND_FACT,
                ExecutionCardinality.NONE_CONFIRMED,
                0,
            )
            validate_effect_state(state)
        else:
            updated = replace(attempt, disposition=AttemptDisposition.MAY_HAVE_BEEN_SENT)
            state = EffectState(
                OutcomeState.OUTCOME_UNKNOWN,
                SettlementState.RECONCILING,
                SettlementBasis.NONE,
                ExecutionCardinality.UNKNOWN_CARDINALITY,
                max(1, aggregate.state.unresolved_transmission_exposure_count),
                potential_duplicate_risk=True,
                potential_loss_risk=True,
            )
            validate_effect_state(state)
        self._effects[effect_id] = self._replace_attempt(aggregate, updated, state=state)
        return updated

    def settle_from_observation(
        self,
        effect_id: str,
        effect_attempt_id: str,
        observation_id: str,
        state: EffectState,
    ) -> EffectAttempt:
        """Advance Effect state from an authoritative observation without rewriting crash disposition."""

        validate_effect_state(state)
        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        validate_identifier(observation_id, field="observation_id")
        disposition = attempt.disposition or AttemptDisposition.TRANSMITTED_WITH_OBSERVATION_AT_CLOSE
        linked = attempt.linked_observation_ids
        if observation_id not in linked:
            linked = linked + (observation_id,)
        updated = replace(attempt, disposition=disposition, linked_observation_ids=linked)
        self._effects[effect_id] = self._replace_attempt(aggregate, updated, state=state)
        return updated

    def settle_unknown_by_policy(self, effect_id: str, effect_attempt_id: str) -> EffectState:
        """Settle an unknown exposure under explicit policy while preserving the unknown cardinality."""

        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        if attempt.disposition is not AttemptDisposition.MAY_HAVE_BEEN_SENT:
            raise EffectGatewayError("policy settlement requires a MAY_HAVE_BEEN_SENT Attempt")
        state = EffectState(
            OutcomeState.OUTCOME_UNKNOWN,
            SettlementState.SETTLED,
            SettlementBasis.POLICY_DISPOSITION,
            ExecutionCardinality.UNKNOWN_CARDINALITY,
            max(1, aggregate.state.unresolved_transmission_exposure_count),
            potential_duplicate_risk=True,
            potential_loss_risk=True,
        )
        validate_effect_state(state)
        self._effects[effect_id] = replace(aggregate, version=aggregate.version + 1, state=state)
        return state

    def link_late_observation(self, effect_id: str, effect_attempt_id: str, observation_id: str, *, now: int) -> dict[str, Any]:
        aggregate = self.effect(effect_id)
        attempt = self._attempt(aggregate, effect_attempt_id)
        validate_identifier(observation_id, field="observation_id")
        if observation_id not in attempt.linked_observation_ids:
            attempt = replace(attempt, linked_observation_ids=attempt.linked_observation_ids + (observation_id,))
            self._effects[effect_id] = self._replace_attempt(aggregate, attempt)
        return {
            "schema": "ATTEMPT_OBSERVATION_LINKED_V1",
            "effect_id": effect_id,
            "effect_attempt_id": effect_attempt_id,
            "observation_id": observation_id,
            "linked_at": now,
            "task_fence_revalidation_required": False,
        }
