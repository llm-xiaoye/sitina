from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .model import canonical_json_bytes, domain_hash, validate_identifier


class SchemaRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class SchemaRegistration:
    event_type: str
    major: int
    schema_hash: str
    upcaster_chain_hash: str


class SchemaRegistry:
    def __init__(self, record_fact: Callable[[dict], None]):
        self._records: dict[tuple[str, int], SchemaRegistration] = {}
        self._record_fact = record_fact

    def register(self, event_type: str, major: int, schema_hash: str, upcaster_hashes: tuple[str, ...]) -> SchemaRegistration:
        validate_identifier(event_type, field="event_type")
        if major < 1 or len(schema_hash) != 64:
            raise SchemaRegistryError("invalid schema registration")
        chain_hash = domain_hash("UPCASTER_CHAIN", canonical_json_bytes(list(upcaster_hashes)))
        registration = SchemaRegistration(event_type, major, schema_hash, chain_hash)
        key = (event_type, major)
        if key in self._records and self._records[key] != registration:
            raise SchemaRegistryError("schema major registration is immutable")
        if key not in self._records:
            self._records[key] = registration
            self._record_fact({"schema": "SCHEMA_REGISTRATION_V1", **registration.__dict__})
        return registration

    def resolve(self, event_type: str, major: int) -> SchemaRegistration:
        try:
            return self._records[(event_type, major)]
        except KeyError as error:
            raise SchemaRegistryError("unknown event schema Major") from error

