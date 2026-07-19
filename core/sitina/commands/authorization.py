from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Callable

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class AuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthorizationDecision:
    actor_id: str
    capability_id: str
    policy_hash: str
    target_id: str
    request_hash: str
    expires_at: str
    audit_reference: str
    allowed: bool
    reason_code: str

    def __post_init__(self) -> None:
        for value, field in ((self.actor_id, "actor_id"), (self.capability_id, "capability_id"), (self.target_id, "target_id"), (self.audit_reference, "audit_reference"), (self.reason_code, "reason_code")):
            validate_identifier(value, field=field)
        for digest in (self.policy_hash, self.request_hash):
            if len(digest) != 64:
                raise AuthorizationError("authorization decision hash is invalid")
        validate_timestamp(self.expires_at)

    @property
    def decision_hash(self) -> str:
        return domain_hash("AUTHORIZATION_DECISION", canonical_json_bytes(self.__dict__))

    def assert_current(self, now: dt.datetime | None = None) -> None:
        current = now or dt.datetime.now(dt.timezone.utc)
        expiry = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if current >= expiry:
            raise AuthorizationError("authorization decision expired")


class AuthorizationEngine:
    def __init__(self, record_decision: Callable[[dict], None]):
        self._record = record_decision

    def decide(self, decision: AuthorizationDecision) -> AuthorizationDecision:
        decision.assert_current()
        self._record({"schema": "AUTHORIZATION_DECISION_V1", **decision.__dict__, "decision_hash": decision.decision_hash})
        return decision

