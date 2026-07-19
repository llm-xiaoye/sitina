from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sitina.journal.model import canonical_json_bytes


class UpcasterError(ValueError):
    pass


UpcastFunction = Callable[[Mapping[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class UpcastResult:
    canonical_document: dict[str, Any]
    audit_record: dict[str, Any]


@dataclass(frozen=True)
class DeterministicUpcaster:
    name: str
    version: int
    source_schema: str
    target_schema: str
    implementation_descriptor: str
    transform: UpcastFunction

    @property
    def implementation_hash(self) -> str:
        return hashlib.sha256(self.implementation_descriptor.encode("utf-8")).hexdigest()

    def apply(self, value: Mapping[str, Any]) -> UpcastResult:
        if value.get("schema") != self.source_schema:
            raise UpcasterError(f"{self.name} cannot read {value.get('schema')!r}")
        input_bytes = canonical_json_bytes(dict(value))
        output = self.transform(dict(value))
        if output.get("schema") != self.target_schema:
            raise UpcasterError("upcaster produced an unexpected target schema")
        output_bytes = canonical_json_bytes(output)
        return UpcastResult(
            output,
            {
                "schema": "SITINA_UPCAST_AUDIT_V1",
                "stored_schema": self.source_schema,
                "canonical_schema": self.target_schema,
                "upcaster": self.name,
                "upcaster_version": self.version,
                "upcaster_hash": self.implementation_hash,
                "input_hash": hashlib.sha256(input_bytes).hexdigest(),
                "output_hash": hashlib.sha256(output_bytes).hexdigest(),
            },
        )


def _checkpoint_v1_to_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema",
        "checkpoint_id",
        "run_id",
        "journal_from_position",
        "journal_to_position",
        "cas_refs",
        "frontier_commitment",
        "base_checkpoint_ref",
        "blackboard_delta_ref",
        "worktree_state_ref",
        "checkpoint_kind",
    }
    unknown = set(value) - allowed
    if unknown:
        raise UpcasterError(f"checkpoint V1 contains unknown fields: {sorted(unknown)}")
    start = value.get("journal_from_position")
    end = value.get("journal_to_position")
    refs = value.get("cas_refs", [])
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
        raise UpcasterError("checkpoint V1 journal range is invalid")
    if not isinstance(refs, list) or any(not isinstance(item, str) or not item.startswith("cas:") for item in refs):
        raise UpcasterError("checkpoint V1 CAS references are invalid")
    return {
        "schema": "SITINA_RUN_CHECKPOINT_V2",
        "checkpoint_id": value.get("checkpoint_id"),
        "run_id": value.get("run_id"),
        "checkpoint_kind": value.get("checkpoint_kind", "incremental"),
        "base_checkpoint_ref": value.get("base_checkpoint_ref"),
        "journal_range": {"from_position": start, "to_position": end},
        "new_cas_refs": sorted(set(refs)),
        "blackboard_delta_ref": value.get("blackboard_delta_ref"),
        "worktree_state_ref": value.get("worktree_state_ref"),
        "frontier_commitment": value.get("frontier_commitment"),
    }


def _evidence_v1_to_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema", "evidence_id", "run_id", "journal_from_position", "journal_to_position",
        "terminal_event_id", "terminal_event_hash", "checkpoint_ref", "input_refs", "output_refs",
        "tool_record_refs", "provider_call_ids", "evidence_policy_hash",
    }
    unknown = set(value) - allowed
    if unknown:
        raise UpcasterError(f"Evidence V1 contains unknown fields: {sorted(unknown)}")
    start = value.get("journal_from_position")
    end = value.get("journal_to_position")
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
        raise UpcasterError("Evidence V1 Journal range is invalid")
    collection_fields = ("input_refs", "output_refs", "tool_record_refs", "provider_call_ids")
    for field in collection_fields:
        if not isinstance(value.get(field, []), list) or any(not isinstance(item, str) for item in value.get(field, [])):
            raise UpcasterError(f"Evidence V1 {field} is invalid")
    return {
        "schema": "SITINA_RUN_EVIDENCE_V2",
        "evidence_id": value.get("evidence_id"),
        "run_id": value.get("run_id"),
        "journal_range": {"from_position": start, "to_position": end},
        "terminal_event_id": value.get("terminal_event_id"),
        "terminal_event_hash": value.get("terminal_event_hash"),
        "checkpoint_ref": value.get("checkpoint_ref"),
        "input_refs": sorted(set(value.get("input_refs", []))),
        "output_refs": sorted(set(value.get("output_refs", []))),
        "tool_record_refs": sorted(set(value.get("tool_record_refs", []))),
        "provider_call_ids": sorted(set(value.get("provider_call_ids", []))),
        "evidence_policy_hash": value.get("evidence_policy_hash"),
    }


def _agent_context_v1_to_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema", "run_id", "call_id", "agent_id", "prompt_template_ref", "base_project_context_ref",
        "conversation_state_ref", "retrieved_memory_refs", "blackboard_base_ref", "delta_refs",
        "rendered_input_hash",
    }
    unknown = set(value) - allowed
    if unknown:
        raise UpcasterError(f"Agent Context V1 contains unknown fields: {sorted(unknown)}")
    for field in ("retrieved_memory_refs", "delta_refs"):
        items = value.get(field, [])
        if not isinstance(items, list) or any(not isinstance(item, str) for item in items) or len(items) != len(set(items)):
            raise UpcasterError(f"Agent Context V1 {field} is invalid")
    return {
        "schema": "SITINA_AGENT_CONTEXT_MANIFEST_V2",
        "run_id": value.get("run_id"),
        "call_id": value.get("call_id"),
        "agent_id": value.get("agent_id"),
        "prompt_template_ref": value.get("prompt_template_ref"),
        "base_project_context_ref": value.get("base_project_context_ref"),
        "conversation_state_ref": value.get("conversation_state_ref"),
        "rolling_summary_ref": None,
        "retrieved_memory_refs": list(value.get("retrieved_memory_refs", [])),
        "blackboard_base_ref": value.get("blackboard_base_ref"),
        "delta_refs": list(value.get("delta_refs", [])),
        "renderer_version": "context-renderer-v2",
        "rendered_input_hash": value.get("rendered_input_hash"),
    }


def _journal_event_v1_to_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema", "event_id", "event_type", "tenant_id", "stream_id", "stream_version", "position",
        "occurred_at", "payload", "object_refs", "projection_requirement",
    }
    unknown = set(value) - allowed
    if unknown:
        raise UpcasterError(f"Journal Event V1 contains unknown fields: {sorted(unknown)}")
    if not isinstance(value.get("payload"), Mapping) or not isinstance(value.get("object_refs", []), list):
        raise UpcasterError("Journal Event V1 payload or references are invalid")
    return {
        "schema": "SITINA_JOURNAL_EVENT_V2",
        "event_id": value.get("event_id"),
        "event_type": value.get("event_type"),
        "tenant_id": value.get("tenant_id"),
        "stream_id": value.get("stream_id"),
        "stream_version": value.get("stream_version"),
        "position": value.get("position"),
        "occurred_at": value.get("occurred_at"),
        "payload": dict(value["payload"]),
        "object_refs": sorted(set(value.get("object_refs", []))),
        "projection_requirement": str(value.get("projection_requirement", "OPTIONAL")).upper(),
    }


class UpcasterRegistry:
    def __init__(self, upcasters: tuple[DeterministicUpcaster, ...]):
        self._by_source = {item.source_schema: item for item in upcasters}
        if len(self._by_source) != len(upcasters):
            raise UpcasterError("duplicate source schema upcaster")

    @classmethod
    def default(cls) -> "UpcasterRegistry":
        return cls(
            (
                DeterministicUpcaster(
                    name="journal-event-v1-to-v2",
                    version=1,
                    source_schema="SITINA_JOURNAL_EVENT_V1",
                    target_schema="SITINA_JOURNAL_EVENT_V2",
                    implementation_descriptor=(
                        "journal-event-v1-to-v2@1:preserve-envelope;canonicalize-object-refs;"
                        "default-projection-requirement-optional;no-clock-no-io-no-provider"
                    ),
                    transform=_journal_event_v1_to_v2,
                ),
                DeterministicUpcaster(
                    name="checkpoint-v1-to-v2",
                    version=1,
                    source_schema="SITINA_RUN_CHECKPOINT_V1",
                    target_schema="SITINA_RUN_CHECKPOINT_V2",
                    implementation_descriptor=(
                        "checkpoint-v1-to-v2@1:preserve-identity;range-object;cas-refs-to-new-cas-refs;"
                        "nullable-base-blackboard-worktree;no-clock-no-io-no-provider"
                    ),
                    transform=_checkpoint_v1_to_v2,
                ),
                DeterministicUpcaster(
                    name="evidence-v1-to-v2",
                    version=1,
                    source_schema="SITINA_RUN_EVIDENCE_V1",
                    target_schema="SITINA_RUN_EVIDENCE_V2",
                    implementation_descriptor=(
                        "evidence-v1-to-v2@1:range-object;refs-only;canonicalize-set-fields;"
                        "no-body-copy-no-clock-no-io-no-provider"
                    ),
                    transform=_evidence_v1_to_v2,
                ),
                DeterministicUpcaster(
                    name="agent-context-v1-to-v2",
                    version=1,
                    source_schema="SITINA_AGENT_CONTEXT_MANIFEST_V1",
                    target_schema="SITINA_AGENT_CONTEXT_MANIFEST_V2",
                    implementation_descriptor=(
                        "agent-context-v1-to-v2@1:add-null-rolling-summary;renderer-v2;"
                        "preserve-ref-order;no-clock-no-io-no-provider"
                    ),
                    transform=_agent_context_v1_to_v2,
                ),
            )
        )

    def upcast(self, value: Mapping[str, Any]) -> UpcastResult:
        schema = value.get("schema")
        if not isinstance(schema, str) or schema not in self._by_source:
            raise UpcasterError(f"no deterministic upcaster for {schema!r}")
        return self._by_source[schema].apply(value)

    @property
    def manifest(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                "name": item.name,
                "version": item.version,
                "source_schema": item.source_schema,
                "target_schema": item.target_schema,
                "upcaster_hash": item.implementation_hash,
            }
            for item in sorted(self._by_source.values(), key=lambda item: item.name)
        )
