from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class PermitError(RuntimeError):
    pass


class PermitPurpose(str, Enum):
    ENTITY_CREATE = "ENTITY_CREATE"
    CLOSING_ENTITY_CREATE = "CLOSING_ENTITY_CREATE"
    EFFECT = "EFFECT"
    APPROVAL = "APPROVAL"


@dataclass(frozen=True)
class AdmissionPermit:
    permit_id: str
    run_id: str
    admission_generation: int
    purpose: PermitPurpose
    scope: str
    remaining_count: int
    max_depth: int
    expires_at: str
    consumed_bindings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.permit_id, field="permit_id")
        validate_identifier(self.run_id, field="run_id")
        validate_identifier(self.scope, field="permit_scope")
        validate_timestamp(self.expires_at)
        if self.admission_generation < 1 or self.remaining_count < 0 or self.max_depth < 0:
            raise PermitError("invalid Permit bounds")

    @property
    def commitment(self) -> str:
        return domain_hash("ADMISSION_PERMIT", canonical_json_bytes({**self.__dict__, "purpose": self.purpose.value}))

    def consume(
        self,
        *,
        current_admission_generation: int,
        purpose: PermitPurpose,
        scope: str,
        depth: int,
        idempotency_binding: str,
        now: dt.datetime | None = None,
    ) -> tuple["AdmissionPermit", dict]:
        current = now or dt.datetime.now(dt.timezone.utc)
        expiry = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if current >= expiry:
            raise PermitError("Permit expired")
        if self.admission_generation != current_admission_generation:
            raise PermitError("Permit belongs to an old Admission Generation")
        if self.purpose is not purpose or self.scope != scope:
            raise PermitError("Permit purpose or scope mismatch")
        if depth > self.max_depth:
            raise PermitError("Permit depth exceeded")
        validate_identifier(idempotency_binding, field="idempotency_binding")
        if idempotency_binding in self.consumed_bindings:
            return self, {"schema": "PERMIT_CONSUME_DUPLICATE_V1", "permit_id": self.permit_id, "binding": idempotency_binding}
        if self.remaining_count < 1:
            raise PermitError("Permit count exhausted")
        updated = replace(self, remaining_count=self.remaining_count - 1, consumed_bindings=self.consumed_bindings + (idempotency_binding,))
        return updated, {
            "schema": "PERMIT_CONSUMED_V1", "permit_id": self.permit_id, "run_id": self.run_id,
            "admission_generation": self.admission_generation, "purpose": self.purpose.value,
            "scope": scope, "depth": depth, "idempotency_binding": idempotency_binding,
        }

