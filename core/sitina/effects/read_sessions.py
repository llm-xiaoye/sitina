from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ReadEffectSessionError(RuntimeError):
    pass


class QuerySlotState(str, Enum):
    RESERVED = "RESERVED"
    CONSUMED = "CONSUMED"
    TOMBSTONED_RELEASED = "TOMBSTONED_RELEASED"


@dataclass(frozen=True)
class QuerySlot:
    slot_id: str
    effect_id: str
    request_hash: str
    run_permit_id: str
    attempt_id: str
    receipt_id: str
    observation_id: str
    state: QuerySlotState = QuerySlotState.RESERVED


@dataclass(frozen=True)
class ReadEffectSession:
    session_id: str
    adapter_scope: str
    credential_principal: str
    query_limit: int
    expires_at: int
    slots: tuple[QuerySlot, ...] = ()

    @classmethod
    def create(cls, session_id: str, adapter_scope: str, credential_principal: str, *, query_limit: int, expires_at: int) -> "ReadEffectSession":
        for value, field in ((session_id, "session_id"), (adapter_scope, "adapter_scope"), (credential_principal, "credential_principal")):
            validate_identifier(value, field=field)
        if query_limit < 1:
            raise ReadEffectSessionError("query limit must be positive")
        return cls(session_id, adapter_scope, credential_principal, query_limit, expires_at)

    def reserve(self, effect_id: str, request_hash: str, *, run_permit_id: str, now: int) -> tuple["ReadEffectSession", QuerySlot]:
        if now > self.expires_at:
            raise ReadEffectSessionError("ReadEffectSession expired")
        if len(request_hash) != 64:
            raise ReadEffectSessionError("invalid Query Effect request hash")
        for value, field in ((effect_id, "effect_id"), (run_permit_id, "run_permit_id")):
            validate_identifier(value, field=field)
        if any(slot.effect_id == effect_id for slot in self.slots):
            raise ReadEffectSessionError("Query Effect identity is already present")
        occupied = sum(slot.state in {QuerySlotState.RESERVED, QuerySlotState.CONSUMED} for slot in self.slots)
        if occupied >= self.query_limit:
            raise ReadEffectSessionError("ReadEffectSession query limit exhausted")
        identity = domain_hash("READ_EFFECT_QUERY_SLOT", canonical_json_bytes({"session_id": self.session_id, "effect_id": effect_id, "request_hash": request_hash, "ordinal": len(self.slots)}))
        slot = QuerySlot(
            f"slot-{identity}",
            effect_id,
            request_hash,
            run_permit_id,
            f"query-attempt-{identity}",
            f"query-receipt-{identity}",
            f"query-observation-{identity}",
        )
        return replace(self, slots=self.slots + (slot,)), slot

    def _slot(self, slot_id: str) -> QuerySlot:
        try:
            return next(item for item in self.slots if item.slot_id == slot_id)
        except StopIteration as error:
            raise ReadEffectSessionError("unknown Query Slot") from error

    def _transition(self, slot: QuerySlot, state: QuerySlotState) -> "ReadEffectSession":
        updated = replace(slot, state=state)
        return replace(self, slots=tuple(updated if item.slot_id == slot.slot_id else item for item in self.slots))

    def consume(self, slot_id: str, *, effect_id: str, request_hash: str) -> tuple["ReadEffectSession", dict[str, object]]:
        slot = self._slot(slot_id)
        if (effect_id, request_hash) != (slot.effect_id, slot.request_hash) or slot.state is not QuerySlotState.RESERVED:
            raise ReadEffectSessionError("Query Slot and EffectRequested binding mismatch")
        return self._transition(slot, QuerySlotState.CONSUMED), {
            "schema": "READ_EFFECT_SESSION_SLOT_CONSUMED_V1",
            "slot_id": slot.slot_id,
            "effect_id": effect_id,
            "request_hash": request_hash,
        }

    def tombstone(self, slot_id: str, *, effect_id: str, request_hash: str) -> tuple["ReadEffectSession", dict[str, object]]:
        slot = self._slot(slot_id)
        if (effect_id, request_hash) != (slot.effect_id, slot.request_hash) or slot.state is not QuerySlotState.RESERVED:
            raise ReadEffectSessionError("Query Slot and Effect Tombstone binding mismatch")
        return self._transition(slot, QuerySlotState.TOMBSTONED_RELEASED), {
            "schema": "READ_EFFECT_SESSION_SLOT_RELEASED_V1",
            "slot_id": slot.slot_id,
            "effect_id": effect_id,
            "slot_released": True,
        }
