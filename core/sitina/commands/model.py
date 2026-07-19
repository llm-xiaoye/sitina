from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from sitina.journal.model import (
    canonical_json_bytes,
    domain_hash,
    parse_canonical_json,
    validate_identifier,
    validate_timestamp,
)


class CommandStatus(str, Enum):
    COMMITTED = "COMMITTED"
    REJECTED = "REJECTED"
    CONFLICT = "CONFLICT"
    RETRYABLE_NOT_ACCEPTED = "RETRYABLE_NOT_ACCEPTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CommandEnvelope:
    command_id: str
    tenant_id: str
    stream_id: str
    command_type: str
    actor_id: str
    issued_at: str
    payload: Mapping[str, Any]
    major: int = 1
    received_at: str | None = None

    _REQUEST_FIELDS = frozenset(
        {"major", "command_id", "tenant_id", "stream_id", "command_type", "actor_id", "issued_at", "payload"}
    )
    _STORED_FIELDS = _REQUEST_FIELDS | {"received_at"}

    def __post_init__(self) -> None:
        if self.major != 1:
            raise ValueError("unknown command major version")
        for value, field in (
            (self.command_id, "command_id"),
            (self.tenant_id, "tenant_id"),
            (self.stream_id, "stream_id"),
            (self.command_type, "command_type"),
            (self.actor_id, "actor_id"),
        ):
            validate_identifier(value, field=field)
        validate_timestamp(self.issued_at)
        if self.received_at is not None:
            validate_timestamp(self.received_at)
        if not isinstance(self.payload, Mapping):
            raise TypeError("command payload must be an object")
        canonical_json_bytes(dict(self.payload))

    def request_mapping(self) -> dict[str, Any]:
        return {
            "major": self.major,
            "command_id": self.command_id,
            "tenant_id": self.tenant_id,
            "stream_id": self.stream_id,
            "command_type": self.command_type,
            "actor_id": self.actor_id,
            "issued_at": self.issued_at,
            "payload": dict(self.payload),
        }

    def canonical_request_bytes(self) -> bytes:
        return canonical_json_bytes(self.request_mapping())

    @property
    def command_request_hash(self) -> str:
        return domain_hash("COMMAND_REQUEST", self.canonical_request_bytes())

    def stored_bytes(self) -> bytes:
        value = self.request_mapping()
        if self.received_at is not None:
            value["received_at"] = self.received_at
        return canonical_json_bytes(value)

    @classmethod
    def from_stored_bytes(cls, raw: bytes) -> "CommandEnvelope":
        value = parse_canonical_json(raw, allowed_fields=cls._STORED_FIELDS)
        if not isinstance(value, dict):
            raise ValueError("command envelope must be an object")
        required = cls._REQUEST_FIELDS
        missing = required - value.keys()
        if missing:
            raise ValueError(f"missing command fields: {sorted(missing)}")
        return cls(**value)


@dataclass(frozen=True)
class CommandResult:
    status: CommandStatus
    command_id: str
    request_hash: str
    receipt: Any | None = None
    reason: str | None = None
    canonical_outcome_ref: str | None = None

