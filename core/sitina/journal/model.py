from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Protocol, Sequence


CANONICAL_PROFILE_ID = "SITINA_CANONICAL_JSON_V1"
IDENTIFIER_PROFILE_ID = "SITINA_IDENTIFIER_HASH_V1"
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]*$")
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")


class CanonicalizationError(ValueError):
    pass


class JournalModelError(ValueError):
    pass


class _Pairs(list[tuple[str, Any]]):
    pass


def _normalize_string(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if any(0xD800 <= ord(character) <= 0xDFFF for character in normalized):
        raise CanonicalizationError("surrogate code point is forbidden")
    return normalized


def _normalize(value: Any, *, set_like_fields: frozenset[str], field: str | None = None) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not INT64_MIN <= value <= INT64_MAX:
            raise CanonicalizationError("integer is outside signed 64-bit bounds")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating point values are forbidden")
    if isinstance(value, str):
        return _normalize_string(value)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            canonical_key = _normalize_string(key)
            if canonical_key in normalized:
                raise CanonicalizationError("duplicate key after NFC normalization")
            normalized[canonical_key] = _normalize(item, set_like_fields=set_like_fields, field=canonical_key)
        return normalized
    if isinstance(value, (list, tuple)):
        items = [_normalize(item, set_like_fields=set_like_fields) for item in value]
        if field in set_like_fields:
            encoded = [(canonical_json_bytes(item, set_like_fields=set_like_fields), item) for item in items]
            encoded.sort(key=lambda pair: pair[0])
            if any(encoded[index - 1][0] == encoded[index][0] for index in range(1, len(encoded))):
                raise CanonicalizationError(f"duplicate value in set-like field: {field}")
            return [item for _, item in encoded]
        return items
    raise CanonicalizationError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json_bytes(value: Any, *, set_like_fields: Iterable[str] = ()) -> bytes:
    normalized = _normalize(value, set_like_fields=frozenset(set_like_fields))
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError) as error:
        raise CanonicalizationError(str(error)) from error


def _pairs_to_value(value: Any) -> Any:
    if isinstance(value, _Pairs):
        result: dict[str, Any] = {}
        for key, item in value:
            normalized = _normalize_string(key)
            if normalized in result:
                raise CanonicalizationError(f"duplicate object member: {normalized}")
            result[normalized] = _pairs_to_value(item)
        return result
    if isinstance(value, list):
        return [_pairs_to_value(item) for item in value]
    return value


def parse_canonical_json(raw: bytes, *, allowed_fields: Iterable[str] | None = None) -> Any:
    if not isinstance(raw, bytes):
        raise TypeError("canonical input must be bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanonicalizationError("invalid UTF-8") from error

    def reject_float(_value: str) -> None:
        raise CanonicalizationError("floating point values are forbidden")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_Pairs,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except json.JSONDecodeError as error:
        raise CanonicalizationError(str(error)) from error
    value = _pairs_to_value(parsed)
    normalized = _normalize(value, set_like_fields=frozenset())
    if canonical_json_bytes(normalized) != raw:
        raise CanonicalizationError("persisted JSON bytes are not canonical")
    if allowed_fields is not None:
        if not isinstance(normalized, dict):
            raise CanonicalizationError("schema-bound value must be an object")
        unknown = normalized.keys() - set(allowed_fields)
        if unknown:
            raise CanonicalizationError(f"unknown fields: {sorted(unknown)}")
    return normalized


def domain_hash(domain: str, payload: bytes) -> str:
    if not re.fullmatch(r"[A-Z0-9_]+", domain):
        raise ValueError("hash domain must be uppercase ASCII")
    return hashlib.sha256(b"SITINA-BPLUS-V1\0" + domain.encode("ascii") + b"\0" + payload).hexdigest()


def validate_identifier(value: str, *, field: str = "identifier", max_bytes: int = 255) -> str:
    if not isinstance(value, str) or value != value.strip() or unicodedata.normalize("NFC", value) != value:
        raise JournalModelError(f"{field} must be a trimmed NFC string")
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= max_bytes or not _ID.fullmatch(value) or ".." in value or "\0" in value:
        raise JournalModelError(f"invalid {field}")
    return value


def validate_timestamp(value: str) -> str:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise JournalModelError("timestamp must be RFC3339 UTC")
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise JournalModelError("invalid calendar timestamp") from error
    return value


@dataclass(frozen=True)
class FrontierRef:
    journal_id: str
    epoch: int
    shard: str
    position: int
    commitment: str

    def __post_init__(self) -> None:
        validate_identifier(self.journal_id, field="journal_id")
        validate_identifier(self.shard, field="shard")
        if self.epoch < 1 or self.position < 0:
            raise JournalModelError("invalid frontier coordinate")
        if not re.fullmatch(r"[0-9a-f]{64}", self.commitment):
            raise JournalModelError("invalid frontier commitment")


class JournalAuthenticator(Protocol):
    def authenticate(self, journal_id: str, epoch: int, event_hash: str) -> tuple[str, str]: ...

    def verify(self, journal_id: str, epoch: int, key_id: str, event_hash: str, tag: str) -> bool: ...


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    event_type: str
    tenant_id: str
    stream_id: str
    stream_version: int
    position: int
    occurred_at: str
    payload: Mapping[str, Any]
    object_refs: tuple[str, ...] = ()
    schema_major: int = 1
    event_hash: str | None = None
    journal_auth_key_id: str | None = None
    journal_auth_tag: str | None = None

    _CORE_FIELDS = frozenset(
        {"schema_major", "event_id", "event_type", "tenant_id", "stream_id", "stream_version", "position", "occurred_at", "payload", "object_refs"}
    )
    _STORED_FIELDS = _CORE_FIELDS | {"event_hash", "journal_auth_key_id", "journal_auth_tag"}

    def __post_init__(self) -> None:
        if self.schema_major != 1:
            raise JournalModelError("unknown event major version")
        for value, field in (
            (self.event_id, "event_id"), (self.event_type, "event_type"), (self.tenant_id, "tenant_id"), (self.stream_id, "stream_id")
        ):
            validate_identifier(value, field=field)
        if self.stream_version < 0 or self.position < 0:
            raise JournalModelError("event coordinates cannot be negative")
        validate_timestamp(self.occurred_at)
        if not isinstance(self.payload, Mapping):
            raise JournalModelError("event payload must be an object")
        canonical_json_bytes(dict(self.payload))
        normalized_refs = tuple(sorted(self.object_refs))
        if normalized_refs != self.object_refs or len(set(self.object_refs)) != len(self.object_refs):
            raise JournalModelError("object references must be unique and sorted")
        for reference in self.object_refs:
            validate_identifier(reference, field="object_ref")
        present = (self.event_hash, self.journal_auth_key_id, self.journal_auth_tag)
        if any(item is not None for item in present) and not all(item is not None for item in present):
            raise JournalModelError("event hash and auth fields must be all present or all absent")
        if self.event_hash is not None and not re.fullmatch(r"[0-9a-f]{64}", self.event_hash):
            raise JournalModelError("invalid event hash")
        if self.journal_auth_tag is not None and not re.fullmatch(r"[0-9a-f]{64}", self.journal_auth_tag):
            raise JournalModelError("invalid Journal auth tag")

    def core_mapping(self) -> dict[str, Any]:
        return {
            "schema_major": self.schema_major,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "stream_id": self.stream_id,
            "stream_version": self.stream_version,
            "position": self.position,
            "occurred_at": self.occurred_at,
            "payload": dict(self.payload),
            "object_refs": list(self.object_refs),
        }

    def canonical_bytes_for_hash(self) -> bytes:
        return canonical_json_bytes(self.core_mapping(), set_like_fields={"object_refs"})

    @property
    def computed_event_hash(self) -> str:
        return domain_hash("EVENT_CORE", self.canonical_bytes_for_hash())

    def assign(self, *, stream_version: int, position: int) -> "EventEnvelope":
        if self.event_hash is not None:
            raise JournalModelError("cannot reassign a sealed event")
        return replace(self, stream_version=stream_version, position=position)

    def seal(self, *, journal_id: str, epoch: int, authenticator: JournalAuthenticator) -> "EventEnvelope":
        if self.event_hash is not None:
            raise JournalModelError("event is already sealed")
        event_hash = self.computed_event_hash
        key_id, tag = authenticator.authenticate(journal_id, epoch, event_hash)
        validate_identifier(key_id, field="journal_auth_key_id")
        return replace(self, event_hash=event_hash, journal_auth_key_id=key_id, journal_auth_tag=tag)

    def verify(self, *, journal_id: str, epoch: int, authenticator: JournalAuthenticator) -> bool:
        return bool(
            self.event_hash == self.computed_event_hash
            and self.journal_auth_key_id
            and self.journal_auth_tag
            and authenticator.verify(journal_id, epoch, self.journal_auth_key_id, self.event_hash, self.journal_auth_tag)
        )

    def stored_mapping(self) -> dict[str, Any]:
        if self.event_hash is None:
            raise JournalModelError("unsealed event cannot be stored")
        return {
            **self.core_mapping(),
            "event_hash": self.event_hash,
            "journal_auth_key_id": self.journal_auth_key_id,
            "journal_auth_tag": self.journal_auth_tag,
        }

    def canonical_stored_bytes(self) -> bytes:
        return canonical_json_bytes(self.stored_mapping(), set_like_fields={"object_refs"})

    @classmethod
    def from_stored_bytes(cls, raw: bytes) -> "EventEnvelope":
        value = parse_canonical_json(raw, allowed_fields=cls._STORED_FIELDS)
        if not isinstance(value, dict):
            raise JournalModelError("event must be an object")
        missing = cls._STORED_FIELDS - value.keys()
        if missing:
            raise JournalModelError(f"missing event fields: {sorted(missing)}")
        value["object_refs"] = tuple(value["object_refs"])
        return cls(**value)


def object_reference_manifest_hash(references: Sequence[str]) -> str:
    ordered = sorted(references)
    if len(set(ordered)) != len(ordered):
        raise JournalModelError("duplicate object reference")
    return domain_hash("OBJECT_REFERENCE_MANIFEST", canonical_json_bytes(ordered))


@dataclass(frozen=True)
class JournalTransaction:
    transaction_id: str
    command_id: str
    command_request_hash: str
    stream_id: str
    events: tuple[EventEnvelope, ...]
    object_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_identifier(self.transaction_id, field="transaction_id")
        validate_identifier(self.command_id, field="command_id")
        validate_identifier(self.stream_id, field="stream_id")
        if not re.fullmatch(r"[0-9a-f]{64}", self.command_request_hash):
            raise JournalModelError("invalid command request hash")
        if not self.events:
            raise JournalModelError("transaction requires at least one event")
        if any(event.stream_id != self.stream_id for event in self.events):
            raise JournalModelError("one transaction may modify only one stream")
        positions = [event.position for event in self.events]
        versions = [event.stream_version for event in self.events]
        if positions != list(range(positions[0], positions[0] + len(positions))):
            raise JournalModelError("local positions must be contiguous")
        if versions != list(range(versions[0], versions[0] + len(versions))):
            raise JournalModelError("stream versions must be contiguous")
        derived = tuple(sorted({ref for event in self.events for ref in event.object_refs}))
        if tuple(self.object_references) != derived:
            raise JournalModelError("transaction object references must exactly equal event references")

    @property
    def object_reference_manifest_hash(self) -> str:
        return object_reference_manifest_hash(self.object_references)

    @property
    def first_position(self) -> int:
        return self.events[0].position

    @property
    def last_position(self) -> int:
        return self.events[-1].position

    @property
    def first_stream_version(self) -> int:
        return self.events[0].stream_version

    @property
    def last_stream_version(self) -> int:
        return self.events[-1].stream_version


@dataclass(frozen=True)
class AppendReceipt:
    journal_id: str
    epoch: int
    transaction_id: str
    command_id: str
    command_request_hash: str
    stream_id: str
    first_position: int
    last_position: int
    first_stream_version: int
    last_stream_version: int
    transaction_hash: str
    object_reference_manifest_hash: str
    durability_profile: str = "MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1"

    @property
    def frontier(self) -> FrontierRef:
        return FrontierRef(self.journal_id, self.epoch, "local", self.last_position, self.transaction_hash)

