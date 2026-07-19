from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from sitina.commands.model import CommandEnvelope

from .local import LocalJournal
from .model import AppendReceipt, EventEnvelope, canonical_json_bytes, domain_hash


class OperationalAuthorityError(RuntimeError):
    pass


class OperationalFactType(str, Enum):
    AUDIT = "audit"
    SECURITY_INTAKE = "security-intake"
    OPERATIONAL_CONTROL = "operational-control"
    DEAD_LETTER = "dead-letter"
    PROJECTION_FAILURE = "projection-failure"
    SCHEMA_REGISTRY = "schema-registry"
    AUTHORIZATION = "authorization"


@dataclass(frozen=True)
class OperationalFactRef:
    fact_type: OperationalFactType
    fact_hash: str
    transaction_hash: str
    position: int
    blocking: bool


class OperationalAuthority:
    def __init__(self, journal: LocalJournal, *, tenant_id: str = "system", actor_id: str = "system-kernel"):
        self.journal = journal
        self.tenant_id = tenant_id
        self.actor_id = actor_id

    def _stream(self, fact_type: OperationalFactType) -> str:
        return f"operational/{fact_type.value}"

    def record(self, fact_type: OperationalFactType, payload: Mapping[str, Any], *, occurred_at: str, blocking: bool = False) -> OperationalFactRef:
        stream = self._stream(fact_type)
        expected = sum(1 for event in self.journal.iter_events(0) if event.stream_id == stream)
        fact_hash = domain_hash("OPERATIONAL_FACT", canonical_json_bytes({"fact_type": fact_type.value, "payload": dict(payload), "blocking": blocking}))
        command_id = f"op-{uuid.uuid4().hex}"
        command = CommandEnvelope(command_id, self.tenant_id, stream, f"operational.record.{fact_type.value}", self.actor_id, occurred_at, {"fact_hash": fact_hash, "blocking": blocking})
        event = EventEnvelope(
            f"event-{uuid.uuid4().hex}", f"operational.{fact_type.value}.recorded", self.tenant_id, stream, 0, 0,
            occurred_at, {"fact_hash": fact_hash, "fact": dict(payload), "blocking": blocking},
        )
        receipt = self.journal.append(command, expected, [event])
        return OperationalFactRef(fact_type, fact_hash, receipt.transaction_hash, receipt.last_position, blocking)


def assert_journal_authoritative(reference: OperationalFactRef | None) -> OperationalFactRef:
    if not isinstance(reference, OperationalFactRef) or len(reference.transaction_hash) != 64 or reference.position < 1:
        raise OperationalAuthorityError("SQLite/log-only operational row is non-authoritative")
    return reference


@dataclass
class TerminalEligibility:
    blocking_dead_letters: int = 0
    required_projection_failures: int = 0

    def observe(self, reference: OperationalFactRef) -> None:
        assert_journal_authoritative(reference)
        if reference.blocking and reference.fact_type is OperationalFactType.DEAD_LETTER:
            self.blocking_dead_letters += 1
        if reference.blocking and reference.fact_type is OperationalFactType.PROJECTION_FAILURE:
            self.required_projection_failures += 1

    @property
    def eligible(self) -> bool:
        return self.blocking_dead_letters == 0 and self.required_projection_failures == 0

