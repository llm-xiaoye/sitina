from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import ValidationError

from sitina.journal.model import canonical_json_bytes, parse_canonical_json

from .models import CONTRACT_MODELS, VersionedRecord


class ContractReadError(ValueError):
    pass


class UnsupportedContractVersion(ContractReadError):
    pass


@dataclass(frozen=True)
class ContractReadResult:
    contract: VersionedRecord
    audit_record: dict[str, Any] | None


_PRIMARY_IDS = {
    "SITINA_BLACKBOARD_DOCUMENT_V1": "document_id",
    "SITINA_EVALUATION_RESULT_V1": "evaluation_id",
    "SITINA_FAILURE_V1": "failure_id",
    "SITINA_HANDOFF_V1": "handoff_id",
    "SITINA_MEMORY_RECORD_V1": "memory_id",
    "SITINA_SPAN_EVENT_V1": "event_id",
    "SITINA_SPAN_V1": "span_id",
    "SITINA_TASK_DEPENDENCY_V1": "dependency_id",
    "SITINA_TASK_GRAPH_V1": "graph_id",
    "SITINA_TASK_V1": "task_id",
    "SITINA_TOKEN_BUDGET_V1": "budget_id",
    "SITINA_TOKEN_USAGE_V1": "usage_id",
    "SITINA_TRACE_V1": "trace_id",
}
_UPCAST_ADDED_FIELDS = {
    "schema_version",
    "correlation_id",
    "causation_id",
    "source",
    "trust",
    "extensions",
}


def read_contract(value: Mapping[str, Any]) -> ContractReadResult:
    if not isinstance(value, Mapping):
        raise ContractReadError("contract must be an object")
    schema = value.get("schema")
    if not isinstance(schema, str):
        raise ContractReadError("contract schema is required")
    if schema in CONTRACT_MODELS:
        try:
            return ContractReadResult(CONTRACT_MODELS[schema].model_validate(dict(value)), None)
        except ValidationError as error:
            raise ContractReadError(str(error)) from error
    if schema.endswith("_V0"):
        return _upcast_v0(value)
    family = schema.rsplit("_V", 1)[0] if "_V" in schema else schema
    if any(known.rsplit("_V", 1)[0] == family for known in CONTRACT_MODELS):
        raise UnsupportedContractVersion(f"unsupported contract version: {schema}")
    raise ContractReadError(f"unknown contract schema: {schema}")


def read_contract_json(raw: bytes) -> ContractReadResult:
    try:
        value = parse_canonical_json(raw)
    except Exception as error:  # canonical parser intentionally owns exact JSON failures
        raise ContractReadError("contract JSON is malformed or non-canonical") from error
    if not isinstance(value, Mapping):
        raise ContractReadError("contract JSON root must be an object")
    return read_contract(value)


def _upcast_v0(value: Mapping[str, Any]) -> ContractReadResult:
    source_schema = str(value.get("schema"))
    target_schema = source_schema[:-3] + "_V1"
    model = CONTRACT_MODELS.get(target_schema)
    if model is None:
        raise UnsupportedContractVersion(f"no deterministic upcaster for: {source_schema}")
    allowed = {
        field.alias or name
        for name, field in model.model_fields.items()
        if name not in _UPCAST_ADDED_FIELDS
    }
    unknown = set(value) - allowed
    if unknown:
        raise ContractReadError(f"legacy contract contains unknown fields: {sorted(unknown)}")
    primary_field = _PRIMARY_IDS[target_schema]
    primary_id = value.get(primary_field)
    if not isinstance(primary_id, str) or not primary_id:
        raise ContractReadError(f"legacy contract requires {primary_field}")
    canonical = dict(value)
    canonical.update(
        {
            "schema": target_schema,
            "schema_version": "1.0",
            "correlation_id": primary_id,
            "causation_id": None,
            "source": {
                "component": "legacy-contract-upcaster",
                "actor_id": "system",
                "source_ref": primary_id,
            },
            "trust": "untrusted",
            "extensions": {},
        }
    )
    try:
        parsed = model.model_validate(canonical)
    except ValidationError as error:
        raise ContractReadError(str(error)) from error
    input_bytes = canonical_json_bytes(dict(value))
    output_mapping = parsed.model_dump(mode="json", by_alias=True)
    output_bytes = canonical_json_bytes(output_mapping)
    audit = {
        "schema": "SITINA_SHARED_CONTRACT_UPCAST_AUDIT_V1",
        "upcaster": f"{source_schema.lower()}-to-v1",
        "upcaster_version": 1,
        "source_schema": source_schema,
        "target_schema": target_schema,
        "input_hash": hashlib.sha256(input_bytes).hexdigest(),
        "output_hash": hashlib.sha256(output_bytes).hexdigest(),
        "deterministic": True,
    }
    return ContractReadResult(parsed, audit)
