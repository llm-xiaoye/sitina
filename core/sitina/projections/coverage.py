from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from sitina.journal.model import canonical_json_bytes


class ProjectionCoverageError(RuntimeError):
    pass


class MissingRequiredProjectionHandler(ProjectionCoverageError):
    pass


class ProjectionRequirement(str, Enum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True)
class ProjectionCoverageEntry:
    schema_id: str
    requirement: ProjectionRequirement
    handler_id: str | None

    @property
    def state(self) -> str:
        if self.handler_id is not None:
            return "HANDLED"
        return "MISSING_REQUIRED" if self.requirement is ProjectionRequirement.REQUIRED else "DIRECTORY_ONLY"

    def mapping(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "requirement": self.requirement.value,
            "handler_id": self.handler_id,
            "coverage_state": self.state,
        }


class ProjectionSchemaCoverage:
    """Deterministic schema -> importance -> handler coverage registry."""

    def __init__(self, entries: Iterable[ProjectionCoverageEntry] = ()):
        self._entries: dict[str, ProjectionCoverageEntry] = {}
        for entry in entries:
            self.register(entry)

    def register(self, entry: ProjectionCoverageEntry) -> None:
        current = self._entries.get(entry.schema_id)
        if current is not None and current != entry:
            raise ProjectionCoverageError("Projection schema coverage registration is immutable")
        self._entries[entry.schema_id] = entry

    @property
    def commitment(self) -> str:
        values = [self._entries[key].mapping() for key in sorted(self._entries)]
        return hashlib.sha256(canonical_json_bytes({"schema": "PROJECTION_SCHEMA_COVERAGE_V1", "entries": values})).hexdigest()

    def resolve(self, payload: Mapping[str, Any]) -> ProjectionCoverageEntry:
        schema_id = str(payload.get("schema", "UNSCHEMATIZED_EVENT_V1"))
        registered = self._entries.get(schema_id)
        if registered is not None:
            return registered
        raw_requirement = str(payload.get("projection_requirement", "OPTIONAL")).upper()
        if raw_requirement not in {item.value for item in ProjectionRequirement}:
            raise ProjectionCoverageError("invalid Projection schema importance")
        return ProjectionCoverageEntry(schema_id, ProjectionRequirement(raw_requirement), None)

    def assert_projectable(self, payload: Mapping[str, Any]) -> ProjectionCoverageEntry:
        entry = self.resolve(payload)
        if entry.state == "MISSING_REQUIRED":
            raise MissingRequiredProjectionHandler(f"Required schema has no Projection handler: {entry.schema_id}")
        return entry

    def entries(self) -> tuple[ProjectionCoverageEntry, ...]:
        return tuple(self._entries[key] for key in sorted(self._entries))


__all__ = [
    "MissingRequiredProjectionHandler",
    "ProjectionCoverageEntry",
    "ProjectionCoverageError",
    "ProjectionRequirement",
    "ProjectionSchemaCoverage",
]
