from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes


class CapabilityError(ValueError):
    pass


class UnknownRequiredSchema(CapabilityError):
    pass


_FORMAT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_UPCASTER = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


@dataclass(frozen=True)
class FormatCapability:
    format_name: str
    writer_version: int
    minimum_reader_version: int
    minimum_full_reader_version: int
    rollback_floor_version: int
    upcaster: str | None
    feature_flag: str
    rollback_safe_before_first_write: bool
    rollback_safe_after_first_write: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FormatCapability":
        expected = {
            "schema",
            "format_name",
            "writer_version",
            "minimum_reader_version",
            "minimum_full_reader_version",
            "rollback_floor_version",
            "upcaster",
            "feature_flag",
            "rollback_safe_before_first_write",
            "rollback_safe_after_first_write",
        }
        if set(value) != expected or value.get("schema") != "SITINA_FORMAT_CAPABILITY_V1":
            raise CapabilityError("format capability must match SITINA_FORMAT_CAPABILITY_V1 exactly")
        name = value.get("format_name")
        flag = value.get("feature_flag")
        upcaster = value.get("upcaster")
        if not isinstance(name, str) or not _FORMAT_NAME.fullmatch(name):
            raise CapabilityError("invalid format_name")
        if not isinstance(flag, str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,127}", flag):
            raise CapabilityError("invalid feature_flag")
        if upcaster is not None and (not isinstance(upcaster, str) or not _UPCASTER.fullmatch(upcaster)):
            raise CapabilityError("invalid upcaster")
        versions = []
        for field in (
            "writer_version",
            "minimum_reader_version",
            "minimum_full_reader_version",
            "rollback_floor_version",
        ):
            item = value.get(field)
            if not isinstance(item, int) or isinstance(item, bool) or item < 1:
                raise CapabilityError(f"{field} must be a positive integer")
            versions.append(item)
        writer, minimum, full, _rollback = versions
        if minimum > full or full > writer:
            raise CapabilityError("format version ordering is inconsistent")
        before = value.get("rollback_safe_before_first_write")
        after = value.get("rollback_safe_after_first_write")
        if not isinstance(before, bool) or not isinstance(after, bool):
            raise CapabilityError("rollback safety fields must be boolean")
        if after and not before:
            raise CapabilityError("rollback cannot become safer after the first write")
        return cls(name, writer, minimum, full, _rollback, upcaster, flag, before, after)

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_FORMAT_CAPABILITY_V1",
            "format_name": self.format_name,
            "writer_version": self.writer_version,
            "minimum_reader_version": self.minimum_reader_version,
            "minimum_full_reader_version": self.minimum_full_reader_version,
            "rollback_floor_version": self.rollback_floor_version,
            "upcaster": self.upcaster,
            "feature_flag": self.feature_flag,
            "rollback_safe_before_first_write": self.rollback_safe_before_first_write,
            "rollback_safe_after_first_write": self.rollback_safe_after_first_write,
        }


@dataclass(frozen=True)
class SchemaDecision:
    schema: str
    required: bool
    known_format: str | None
    semantic_support: bool
    event_directory_only: bool


class FormatCapabilityRegistry:
    def __init__(self, formats: tuple[FormatCapability, ...]):
        if not formats:
            raise CapabilityError("format capability registry cannot be empty")
        names = [item.format_name for item in formats]
        if len(names) != len(set(names)):
            raise CapabilityError("duplicate format capability")
        flags = [item.feature_flag for item in formats]
        if len(flags) != len(set(flags)):
            raise CapabilityError("feature_flag must identify exactly one format")
        self._formats = {item.format_name: item for item in formats}
        document = {
            "schema": "SITINA_FORMAT_CAPABILITY_REGISTRY_V1",
            "formats": [self._formats[name].mapping() for name in sorted(self._formats)],
        }
        self.registry_hash = hashlib.sha256(canonical_json_bytes(document)).hexdigest()

    @classmethod
    def load(cls, path: str | Path) -> "FormatCapabilityRegistry":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CapabilityError("format capability registry is unreadable") from error
        if not isinstance(value, dict) or set(value) != {"schema", "formats"}:
            raise CapabilityError("format capability registry has unknown or missing fields")
        if value.get("schema") != "SITINA_FORMAT_CAPABILITY_REGISTRY_V1":
            raise CapabilityError("unsupported format capability registry")
        formats = value.get("formats")
        if not isinstance(formats, list):
            raise CapabilityError("formats must be an array")
        if any(not isinstance(item, dict) for item in formats):
            raise CapabilityError("every formats entry must be an object")
        return cls(tuple(FormatCapability.from_mapping(item) for item in formats))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._formats))

    def get(self, format_name: str) -> FormatCapability:
        try:
            return self._formats[format_name]
        except KeyError as error:
            raise CapabilityError(f"unknown format: {format_name}") from error

    def classify_event(self, schema: str, *, required: bool) -> SchemaDecision:
        if not isinstance(schema, str) or not _FORMAT_NAME.fullmatch(schema):
            raise CapabilityError("event schema name is invalid")
        known = next(
            (name for name in self._formats if schema == name or schema.startswith(name + "_V")),
            None,
        )
        if known is None and required:
            raise UnknownRequiredSchema(f"unknown Required Major Schema: {schema}")
        return SchemaDecision(
            schema=schema,
            required=required,
            known_format=known,
            semantic_support=known is not None,
            event_directory_only=known is None and not required,
        )
