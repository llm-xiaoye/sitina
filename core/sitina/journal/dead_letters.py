from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .operational import OperationalAuthority, OperationalFactRef, OperationalFactType


@dataclass(frozen=True)
class DeadLetter:
    source_event_hash: str
    handler_id: str
    failure_class: str
    attempt_count: int
    blocking: bool
    payload_digest: str


def record_dead_letter(
    authority: OperationalAuthority,
    *,
    source_event_hash: str,
    handler_id: str,
    failure_class: str,
    attempt_count: int,
    blocking: bool,
    raw_payload: bytes,
    occurred_at: str,
) -> OperationalFactRef:
    fact = DeadLetter(source_event_hash, handler_id, failure_class, attempt_count, blocking, hashlib.sha256(raw_payload).hexdigest())
    return authority.record(OperationalFactType.DEAD_LETTER, fact.__dict__, occurred_at=occurred_at, blocking=blocking)

