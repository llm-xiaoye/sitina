from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class BlackboardStateError(ValueError):
    pass


@dataclass(frozen=True)
class BlackboardLimits:
    max_total_bytes: int = 16 * 1024 * 1024
    max_document_bytes: int = 1024 * 1024
    max_field_bytes: int = 256 * 1024
    warning_ratio_millis: int = 800

    def __post_init__(self) -> None:
        if (
            self.max_total_bytes < 1
            or self.max_document_bytes < 1
            or self.max_field_bytes < 1
            or self.max_document_bytes > self.max_total_bytes
            or self.max_field_bytes > self.max_document_bytes
            or not 1 <= self.warning_ratio_millis <= 1_000
        ):
            raise BlackboardStateError("invalid Blackboard capacity limits")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BlackboardLimits":
        expected = {
            "schema",
            "max_total_bytes",
            "max_document_bytes",
            "max_field_bytes",
            "warning_ratio_millis",
        }
        if set(value) != expected or value.get("schema") != "SITINA_BLACKBOARD_LIMITS_V1":
            raise BlackboardStateError("Blackboard limits contain unknown fields or schema")
        for field in expected - {"schema"}:
            item = value.get(field)
            if not isinstance(item, int) or isinstance(item, bool):
                raise BlackboardStateError(f"Blackboard limit {field} must be an integer")
        try:
            return cls(
                max_total_bytes=value["max_total_bytes"],
                max_document_bytes=value["max_document_bytes"],
                max_field_bytes=value["max_field_bytes"],
                warning_ratio_millis=value["warning_ratio_millis"],
            )
        except (KeyError, TypeError) as error:
            raise BlackboardStateError("Blackboard limits are malformed") from error

    @classmethod
    def load(cls, path: str | Path) -> "BlackboardLimits":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise BlackboardStateError("Blackboard limits config is unreadable") from error
        if not isinstance(value, Mapping):
            raise BlackboardStateError("Blackboard limits config must be an object")
        return cls.from_mapping(value)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class BlackboardBodyV1(_StrictModel):
    schema_id: Literal["SITINA_BLACKBOARD_BODY_V1"] = Field(alias="schema")
    schema_version: Literal[1]
    notes: str = Field(default="", max_length=16_000)
    data: dict[str, Any] = Field(default_factory=dict)
    tags: tuple[str, ...] = Field(default=(), max_length=128)


@dataclass(frozen=True)
class BlackboardBodyRead:
    body: BlackboardBodyV1
    upcast_audit: Mapping[str, Any] | None = None


def read_blackboard_body(value: Mapping[str, Any]) -> BlackboardBodyRead:
    schema = value.get("schema") if isinstance(value, Mapping) else None
    if schema == "SITINA_BLACKBOARD_BODY_V1":
        try:
            return BlackboardBodyRead(BlackboardBodyV1.model_validate(dict(value)))
        except ValidationError as error:
            raise BlackboardStateError(str(error)) from error
    if schema == "SITINA_BLACKBOARD_BODY_V0":
        if set(value) != {"schema", "text"} or not isinstance(value.get("text"), str):
            raise BlackboardStateError("legacy Blackboard body is malformed or contains unknown fields")
        canonical = {
            "schema": "SITINA_BLACKBOARD_BODY_V1",
            "schema_version": 1,
            "notes": value["text"],
            "data": {},
            "tags": [],
        }
        body = BlackboardBodyV1.model_validate(canonical)
        return BlackboardBodyRead(
            body,
            {
                "schema": "SITINA_BLACKBOARD_BODY_UPCAST_AUDIT_V1",
                "source_schema": schema,
                "target_schema": body.schema_id,
                "upcaster": "blackboard-body-v0-to-v1",
                "input_hash": hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest(),
                "output_hash": hashlib.sha256(
                    canonical_json_bytes(body.model_dump(mode="json", by_alias=True))
                ).hexdigest(),
                "deterministic": True,
            },
        )
    if isinstance(schema, str) and schema.startswith("SITINA_BLACKBOARD_BODY_V"):
        raise BlackboardStateError(f"unsupported Blackboard body version: {schema}")
    raise BlackboardStateError("Blackboard body schema is required")


_PROTECTED_NORMALIZED = frozenset(
    {
        "allowedscope",
        "approvalrequired",
        "denylist",
        "permissions",
        "risklevel",
        "verificationstatus",
    }
)
_SENSITIVE_NORMALIZED = frozenset(
    {
        "accesstoken",
        "apikey",
        "authtoken",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "password",
        "privatekey",
        "refreshtoken",
        "secret",
    }
)


def _normalized_field(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def protected_paths(value: Any, *, path: str = "$") -> tuple[str, ...]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}"
            if _normalized_field(str(key)) in _PROTECTED_NORMALIZED:
                found.append(child)
            found.extend(protected_paths(item, path=child))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(protected_paths(item, path=f"{path}[{index}]"))
    return tuple(found)


def _is_sensitive_path(path: str) -> bool:
    return any(_normalized_field(piece) in _SENSITIVE_NORMALIZED for piece in path.split("."))


def field_level_changes(before: Mapping[str, Any] | None, after: Mapping[str, Any] | None) -> tuple[dict[str, Any], ...]:
    missing = object()
    changes: list[dict[str, Any]] = []

    def walk(left: Any, right: Any, path: str) -> None:
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            for key in sorted(set(left) | set(right)):
                walk(left.get(key, missing), right.get(key, missing), f"{path}.{key}" if path else str(key))
            return
        if left is missing and isinstance(right, Mapping):
            for key in sorted(right):
                walk(missing, right[key], f"{path}.{key}" if path else str(key))
            return
        if right is missing and isinstance(left, Mapping):
            for key in sorted(left):
                walk(left[key], missing, f"{path}.{key}" if path else str(key))
            return
        if left == right:
            return
        sensitive = _is_sensitive_path(path)

        def commitment(item: Any) -> str | None:
            if item is missing:
                return None
            if sensitive:
                return "REDACTED"
            return domain_hash("BLACKBOARD_FIELD_VALUE", canonical_json_bytes(item))

        changes.append(
            {
                "path": path,
                "operation": "ADD" if left is missing else "REMOVE" if right is missing else "REPLACE",
                "before_commitment": commitment(left),
                "after_commitment": commitment(right),
                "sensitive_value_redacted": sensitive,
            }
        )

    walk(dict(before or {}), dict(after or {}), "")
    return tuple(changes)


def largest_field_size(value: Any) -> int:
    sizes: list[int] = []

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                sizes.append(len(canonical_json_bytes(str(key))))
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)
        else:
            sizes.append(len(canonical_json_bytes(item)))

    visit(value)
    return max(sizes, default=0)


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class BlackboardSnapshot:
    snapshot_id: str
    tenant_id: str
    run_id: str
    position: int
    documents: tuple[Mapping[str, Any], ...]
    snapshot_hash: str
    read_only: bool = True

    @classmethod
    def build(
        cls,
        *,
        tenant_id: str,
        run_id: str,
        position: int,
        documents: tuple[Mapping[str, Any], ...],
    ) -> "BlackboardSnapshot":
        validate_identifier(tenant_id, field="blackboard_tenant_id")
        validate_identifier(run_id, field="blackboard_run_id")
        if position < 0:
            raise BlackboardStateError("snapshot position cannot be negative")
        frozen_documents = tuple(_deep_freeze(item) for item in documents)
        payload = {
            "tenant_id": tenant_id,
            "run_id": run_id,
            "position": position,
            "documents": frozen_documents,
            "read_only": True,
        }
        digest = domain_hash("BLACKBOARD_SNAPSHOT", canonical_json_bytes(payload))
        return cls("blackboard-snapshot-" + digest[:32], tenant_id, run_id, position, frozen_documents, digest)

    def verify(self) -> None:
        expected = self.build(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            position=self.position,
            documents=self.documents,
        )
        if not self.read_only or self.snapshot_id != expected.snapshot_id or self.snapshot_hash != expected.snapshot_hash:
            raise BlackboardStateError("Blackboard snapshot is damaged or mutable")


@dataclass(frozen=True)
class BlackboardQueryPage:
    documents: tuple[Any, ...]
    next_cursor: str | None
    snapshot_position: int


@dataclass(frozen=True)
class BlackboardQueryIndex:
    namespace: Mapping[str, frozenset[str]]
    keys: Mapping[str, frozenset[str]]
    tags: Mapping[str, frozenset[str]]
    runs: Mapping[str, frozenset[str]]
    versions: Mapping[int, frozenset[str]]
    all_document_ids: frozenset[str]

    @classmethod
    def build(cls, documents: tuple[Any, ...]) -> "BlackboardQueryIndex":
        namespaces: dict[str, set[str]] = {}
        keys: dict[str, set[str]] = {}
        tags: dict[str, set[str]] = {}
        runs: dict[str, set[str]] = {}
        versions: dict[int, set[str]] = {}

        def collect_keys(value: Any) -> set[str]:
            found: set[str] = set()
            if isinstance(value, Mapping):
                for key, item in value.items():
                    found.add(str(key))
                    found.update(collect_keys(item))
            elif isinstance(value, (list, tuple)):
                for item in value:
                    found.update(collect_keys(item))
            return found

        for document in documents:
            document_id = str(document.document_id)
            namespaces.setdefault(str(document.namespace.value), set()).add(document_id)
            for key in collect_keys(document.inline_body):
                keys.setdefault(key, set()).add(document_id)
            for tag in document.tags:
                tags.setdefault(str(tag), set()).add(document_id)
            if document.run_id is not None:
                runs.setdefault(str(document.run_id), set()).add(document_id)
            versions.setdefault(int(document.version), set()).add(document_id)
        freeze = lambda mapping: MappingProxyType({key: frozenset(items) for key, items in mapping.items()})
        return cls(
            freeze(namespaces),
            freeze(keys),
            freeze(tags),
            freeze(runs),
            freeze(versions),
            frozenset(str(document.document_id) for document in documents),
        )

    def match(
        self,
        *,
        namespace: str | None,
        key: str | None,
        tag: str | None,
        run_id: str | None,
        version: int | None,
    ) -> frozenset[str]:
        candidates = set(self.all_document_ids)
        filters = (
            self.namespace.get(namespace, frozenset()) if namespace is not None else None,
            self.keys.get(key, frozenset()) if key is not None else None,
            self.tags.get(tag, frozenset()) if tag is not None else None,
            self.runs.get(run_id, frozenset()) if run_id is not None else None,
            self.versions.get(version, frozenset()) if version is not None else None,
        )
        for selected in filters:
            if selected is not None:
                candidates.intersection_update(selected)
        return frozenset(candidates)


@dataclass(frozen=True)
class BlackboardNotification:
    notification_id: str
    subscription_id: str
    event_id: str
    position: int
    document_id: str
    namespace: str
    committed_version: int
    committed_hash: str


@dataclass(frozen=True)
class BlackboardNotificationPage:
    notifications: tuple[BlackboardNotification, ...]
    lagging: bool
    highest_position: int


@dataclass(frozen=True)
class BlackboardSubscription:
    subscription_id: str
    namespaces: tuple[str, ...]
    last_acked_position: int
    max_pending: int

    def __post_init__(self) -> None:
        validate_identifier(self.subscription_id, field="blackboard_subscription_id")
        if self.last_acked_position < 0 or self.max_pending < 1 or not self.namespaces:
            raise BlackboardStateError("invalid Blackboard subscription")
