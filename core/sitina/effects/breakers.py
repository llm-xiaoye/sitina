from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class BreakerError(RuntimeError):
    pass


class BreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass(frozen=True)
class BreakerPrecheck:
    control_id: str
    effect_attempt_id: str
    fence: str
    expected_version: int
    state: BreakerState
    token_hash: str


@dataclass(frozen=True)
class CircuitBreaker:
    control_id: str
    half_open_probe_limit: int
    state: BreakerState = BreakerState.CLOSED
    version: int = 0
    half_open_authorizations: int = 0
    reason: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.control_id, field="control_id")
        if self.half_open_probe_limit < 1:
            raise ValueError("HALF_OPEN probe limit must be positive")

    def open(self, *, reason: str) -> "CircuitBreaker":
        return replace(self, state=BreakerState.OPEN, version=self.version + 1, reason=reason, half_open_authorizations=0)

    def half_open(self) -> "CircuitBreaker":
        if self.state is not BreakerState.OPEN:
            raise BreakerError("only an OPEN breaker can enter HALF_OPEN")
        return replace(self, state=BreakerState.HALF_OPEN, version=self.version + 1, half_open_authorizations=0)

    def precheck(self, effect_attempt_id: str, fence: str) -> BreakerPrecheck:
        if self.state is BreakerState.OPEN:
            raise BreakerError("circuit breaker is OPEN")
        if self.state is BreakerState.HALF_OPEN and self.half_open_authorizations >= self.half_open_probe_limit:
            raise BreakerError("HALF_OPEN probe budget exhausted")
        body = {"control_id": self.control_id, "effect_attempt_id": effect_attempt_id, "fence": fence, "expected_version": self.version, "state": self.state.value}
        return BreakerPrecheck(self.control_id, effect_attempt_id, fence, self.version, self.state, domain_hash("BREAKER_PRECHECK", canonical_json_bytes(body)))

    def authorize_final(self, token: BreakerPrecheck, *, expected_version: int) -> tuple["CircuitBreaker", dict[str, Any]]:
        if expected_version != self.version or token.expected_version != self.version or token.control_id != self.control_id or token.state is not self.state:
            raise BreakerError("circuit breaker final CAS conflict")
        if self.state is BreakerState.OPEN:
            raise BreakerError("circuit breaker opened after precheck")
        if self.state is BreakerState.HALF_OPEN and self.half_open_authorizations >= self.half_open_probe_limit:
            raise BreakerError("HALF_OPEN probe budget exhausted")
        updated = replace(self, version=self.version + 1, half_open_authorizations=self.half_open_authorizations + (1 if self.state is BreakerState.HALF_OPEN else 0))
        return updated, {
            "schema": "CIRCUIT_BREAKER_DISPATCH_AUTHORIZED_V1",
            "control_id": self.control_id,
            "effect_attempt_id": token.effect_attempt_id,
            "fence": token.fence,
            "precheck_hash": token.token_hash,
            "authorized_version": self.version,
        }
