from __future__ import annotations

from contextlib import nullcontext

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit

from sitina.journal.model import canonical_json_bytes
from sitina.utils import redact_text
from sitina.security.tool_security import PromptIsolationPolicy
from sitina.runners.provider import (
    ANTHROPIC_MESSAGES,
    OPENAI_CHAT_COMPLETIONS,
    SUPPORTED_WIRE_PROTOCOLS,
    provider_messages_for_wire,
    provider_tools_for_wire,
)

from .model import ControlIntent, InputKind, SPEC_VERSION, TaskStatus
from .storage import LoopEventStore
from .text_measurements import TextMeasurementScopeError, measure_text
from .review_evidence import (REVIEW_EVIDENCE_PLAN_BLOCKERS, REVIEW_VIEW, compact_review_materials, current_review_summary,
                              review_recipient_attempt_chain, source_read_bytes)


HISTORY_MIN_PAGE_BYTES = 768
GOAL_COMPLETION_EVIDENCE_FEEDBACK_MAX_BYTES = 4096


def completion_next_step(progress: Mapping[str, Any], measurement: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Publish bounded executable navigation, without granting reading or verdict credit."""
    missing = list(progress.get("missing_source_refs", ()))
    if missing:
        actions = progress.get("next_reads", {})
        return {
            "stage": "READ_REQUIRED_EVIDENCE",
            "pending_source_count": len(missing),
            "tool_calls": [
                {"name": "sitina_history_query", "arguments": dict(actions[ref])}
                for ref in missing[:3] if isinstance(actions.get(ref), Mapping)
            ],
            "instruction": "Execute these exact read arguments before proposing a decision. The next request refreshes remaining reads. source_ref (history:) is not continuation_ref (hc1:). Reading is not approval.",
        }
    pending = measurement.get("pending_measurements", ()) if isinstance(measurement, Mapping) else ()
    if pending:
        return {
            "stage": "MEASURE_REQUIRED_DELIVERABLES",
            "tool_calls": [{"name": "sitina_history_query", "arguments": dict(item["arguments"])}
                           for item in pending[:3]],
            "instruction": "Complete current required measurements before assessing the business conditions.",
        }
    return {"stage": "ASSESS_CONDITIONS", "tool_calls": [],
            "instruction": "Read coverage is complete. Judge every current condition from actual evidence; return OPEN findings for remaining business work."}


class ContextCoreError(RuntimeError):
    pass


class ContextPolicyError(ContextCoreError):
    pass


class HistoryQueryError(ContextCoreError):
    pass


class StaleContextProjection(ContextCoreError):
    pass


class ContextCoverageBlocked(ContextCoreError):
    def __init__(
        self,
        reason: str,
        required_source_refs: Sequence[str],
        *,
        context_binding: Mapping[str, Any] | None = None,
    ):
        super().__init__(reason)
        self.reason = reason
        self.required_source_refs = tuple(sorted(set(str(item) for item in required_source_refs)))
        self.context_binding = dict(context_binding) if context_binding is not None else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_LOOP_CONTEXT_COVERAGE_BLOCKED_V1",
            "status": TaskStatus.CONTEXT_BLOCKED.value,
            "reason": self.reason,
            "required_source_refs": list(self.required_source_refs),
            "semantic_requirement_compaction_available": False,
            "task_failure": False,
            "no_progress_incremented": False,
        }


class HistoryBatchCapacityBlocked(ContextCoverageBlocked):
    """The entire tool group was rejected before any tool dispatch."""

    def __init__(self, calls: Sequence[Mapping[str, Any]], *, context_binding: Mapping[str, Any],
                 minimum_response_bytes: int, minimum_protocol_group_bytes: int, response_limit_bytes: int):
        super().__init__(
            ("history page minimum cannot fit the current request; no smaller batch is possible"
             if len(calls) == 1 else
             "history batch minimum and paired feedback cannot fit; a smaller atomic group is required"),
            tuple(str(call["arguments"].get("source_ref") or "") for call in calls
                  if isinstance(call.get("arguments"), Mapping)),
            context_binding=context_binding,
        )
        self.calls = tuple(dict(call) for call in calls)
        self.safe_to_replan = len(calls) > 1 and all(
            call.get("name") == "sitina_history_query"
            and isinstance(call.get("arguments"), Mapping)
            and call["arguments"].get("operation") == "read" for call in calls)
        self.capacity = {"minimum_response_bytes": minimum_response_bytes,
                         "minimum_protocol_group_bytes": minimum_protocol_group_bytes,
                         "response_limit_bytes": response_limit_bytes}

    def as_dict(self) -> dict[str, Any]:
        return {**super().as_dict(), **self.capacity,
                "calls": [{"call_id": call.get("id"), "tool": call.get("name"),
                           "arguments": dict(call["arguments"]) if isinstance(call.get("arguments"), Mapping) else None,
                           "state": "NOT_DISPATCHED"}
                          for call in self.calls]}


class ContextAdmissionBlocked(ContextCoverageBlocked):
    def __init__(
        self,
        admission: "RequestAdmission",
        required_source_refs: Sequence[str],
        *,
        context_binding: Mapping[str, Any] | None = None,
    ):
        super().__init__(admission.reason, required_source_refs, context_binding=context_binding)
        self.admission = admission


def _wire_json_bytes(value: Any) -> bytes:
    """Match the Provider transport's exact JSON serialization contract."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def normalize_provider_endpoint(value: str) -> str:
    """Normalize an API base while retaining path identity.

    A host-only identity is insufficient: two adapters at `/v1` and `/gateway/v1`
    can expose different models or chat templates. Credentials, query strings,
    and fragments are never valid parts of the capacity identity.
    """

    parsed = urlsplit(str(value).strip())
    if (
        parsed.scheme.lower() not in {"https", "http", "mock"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ContextPolicyError("provider capacity endpoint identity is invalid")
    host = parsed.hostname.casefold()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        parsed_port = parsed.port
    except ValueError as error:
        raise ContextPolicyError("provider capacity endpoint port is invalid") from error
    default_port = (parsed.scheme.lower() == "https" and parsed_port == 443) or (
        parsed.scheme.lower() == "http" and parsed_port == 80
    )
    port = f":{parsed_port}" if parsed_port is not None and not default_port else ""
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), host + port, path, "", ""))


@dataclass(frozen=True)
class ProviderContextIdentity:
    profile: str
    endpoint: str
    model: str
    wire_protocol: str

    def __post_init__(self) -> None:
        if not self.profile.strip() or not self.model.strip():
            raise ContextPolicyError("provider profile and model are required")
        if self.wire_protocol not in SUPPORTED_WIRE_PROTOCOLS:
            raise ContextPolicyError("provider wire protocol is unsupported")
        object.__setattr__(self, "endpoint", normalize_provider_endpoint(self.endpoint))

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.profile, self.endpoint, self.model, self.wire_protocol

    def as_dict(self) -> dict[str, str]:
        return {
            "profile": self.profile,
            "endpoint": self.endpoint,
            "model": self.model,
            "wire_protocol": self.wire_protocol,
        }


@dataclass(frozen=True)
class ModelCapacityPolicy:
    identity: ProviderContextIdentity
    context_capacity_tokens: int
    next_tool_turn_receipt_reserve_tokens: int
    history_query_max_bytes: int
    counter_mode: str
    counter_name: str
    counter_applicability: str
    protocol_margin_tokens: int
    thinking_mode: str = "provider_default"
    max_output_tokens: int = 4096
    reasoning_effort: str = "high"

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (
                self.context_capacity_tokens,
                self.next_tool_turn_receipt_reserve_tokens,
                self.history_query_max_bytes,
                self.protocol_margin_tokens,
            )
        ):
            raise ContextPolicyError("capacity policy numeric values must be integers")
        if self.context_capacity_tokens < 1 or self.next_tool_turn_receipt_reserve_tokens < 1:
            raise ContextPolicyError("context capacity and next-tool reserve must be positive")
        if self.history_query_max_bytes < HISTORY_MIN_PAGE_BYTES:
            raise ContextPolicyError("history query maximum is below the minimum bounded envelope")
        if self.counter_mode not in {"qualified_tokenizer", "conservative_utf8"}:
            raise ContextPolicyError("unsupported context counter mode")
        if not self.counter_name.strip() or not self.counter_applicability.strip():
            raise ContextPolicyError("counter identity and applicability are required")
        if self.protocol_margin_tokens < 0:
            raise ContextPolicyError("protocol margin cannot be negative")
        if self.counter_mode == "conservative_utf8" and self.protocol_margin_tokens < 1:
            raise ContextPolicyError("conservative UTF-8 counting requires an explicit protocol margin")
        if self.thinking_mode not in {"provider_default", "enabled", "disabled"}:
            raise ContextPolicyError(
                "bounded Loop supports provider-default or an explicit thinking toggle"
            )
        if type(self.max_output_tokens) is not int or self.max_output_tokens < 1:
            raise ContextPolicyError("capacity execution output reserve must be a positive integer")
        if self.reasoning_effort not in {"low", "high", "max"}:
            raise ContextPolicyError("capacity execution reasoning effort must be low, high, or max")


class ModelCapacityRegistry:
    SCHEMA = "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1"

    def __init__(self, entries: Sequence[ModelCapacityPolicy]):
        keyed = {item.identity.key: item for item in entries}
        if len(keyed) != len(entries):
            raise ContextPolicyError("capacity policy contains duplicate exact identities")
        self._entries = keyed

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ModelCapacityRegistry":
        if set(value) != {"schema", "entries"} or value.get("schema") != cls.SCHEMA:
            raise ContextPolicyError("capacity policy schema is invalid")
        raw_entries = value.get("entries")
        if not isinstance(raw_entries, list):
            raise ContextPolicyError("capacity policy entries must be an array")
        entries: list[ModelCapacityPolicy] = []
        for raw in raw_entries:
            required_fields = {
                "profile",
                "endpoint",
                "model",
                "wire_protocol",
                "context_capacity_tokens",
                "next_tool_turn_receipt_reserve_tokens",
                "history_query_max_bytes",
                "counter",
            }
            if (
                not isinstance(raw, Mapping)
                or not required_fields.issubset(raw)
                or set(raw) - required_fields != ({"execution"} if "execution" in raw else set())
            ):
                raise ContextPolicyError("capacity policy entry fields are invalid")
            counter = raw.get("counter")
            if not isinstance(counter, Mapping) or set(counter) != {
                "mode", "name", "applicability", "protocol_margin_tokens"
            }:
                raise ContextPolicyError("capacity counter fields are invalid")
            string_fields = ("profile", "endpoint", "model", "wire_protocol")
            integer_fields = (
                "context_capacity_tokens",
                "next_tool_turn_receipt_reserve_tokens",
                "history_query_max_bytes",
            )
            if any(type(raw[field]) is not str or not str(raw[field]).strip() for field in string_fields):
                raise ContextPolicyError("capacity identity fields must be non-empty strings")
            if any(type(raw[field]) is not int for field in integer_fields):
                raise ContextPolicyError("capacity numeric fields must be integers")
            if any(
                type(counter[field]) is not str or not str(counter[field]).strip()
                for field in ("mode", "name", "applicability")
            ) or type(counter["protocol_margin_tokens"]) is not int:
                raise ContextPolicyError("capacity counter value types are invalid")
            execution = raw.get(
                "execution",
                {"thinking_mode": "provider_default", "max_output_tokens": 4096},
            )
            if (
                not isinstance(execution, Mapping)
                or not {"thinking_mode", "max_output_tokens"}.issubset(execution)
                or set(execution) - {"thinking_mode", "max_output_tokens", "reasoning_effort"}
                or type(execution["thinking_mode"]) is not str
                or type(execution["max_output_tokens"]) is not int
                or type(execution.get("reasoning_effort", "high")) is not str
            ):
                raise ContextPolicyError("capacity execution fields are invalid")
            entries.append(
                ModelCapacityPolicy(
                    ProviderContextIdentity(
                        str(raw["profile"]),
                        str(raw["endpoint"]),
                        str(raw["model"]),
                        str(raw["wire_protocol"]),
                    ),
                    int(raw["context_capacity_tokens"]),
                    int(raw["next_tool_turn_receipt_reserve_tokens"]),
                    int(raw["history_query_max_bytes"]),
                    str(counter["mode"]),
                    str(counter["name"]),
                    str(counter["applicability"]),
                    int(counter["protocol_margin_tokens"]),
                    thinking_mode=str(execution["thinking_mode"]),
                    max_output_tokens=int(execution["max_output_tokens"]),
                    reasoning_effort=str(execution.get("reasoning_effort", "high")),
                )
            )
        return cls(entries)

    def resolve(self, identity: ProviderContextIdentity) -> ModelCapacityPolicy | None:
        return self._entries.get(identity.key)


class QualifiedWireRequestCounter(Protocol):
    name: str
    applicability: str

    def count_wire_request(self, body: bytes) -> int: ...


@dataclass(frozen=True)
class RenderedProviderRequest:
    identity: ProviderContextIdentity
    canonical_body: bytes
    body_hash: str
    component_bytes: Mapping[str, int]
    max_tokens: int

    @property
    def body(self) -> Mapping[str, Any]:
        """Return a detached diagnostic copy, never the admitted send object."""

        value = json.loads(self.canonical_body)
        if not isinstance(value, dict):  # pragma: no cover - renderer always emits an object.
            raise ContextPolicyError("rendered Provider request is not an object")
        return value

    def body_for_send(self, expected_identity: ProviderContextIdentity) -> dict[str, Any]:
        """Rebuild the only sendable body from the protected admitted bytes."""

        if expected_identity != self.identity:
            raise ContextPolicyError("rendered request identity changed before send")
        if hashlib.sha256(self.canonical_body).hexdigest() != self.body_hash:
            raise ContextPolicyError("rendered request body hash changed before send")
        value = self.body
        if value.get("model") != self.identity.model or value.get("max_tokens") != self.max_tokens:
            raise ContextPolicyError("rendered request model or output reserve changed before send")
        if _wire_json_bytes(value) != self.canonical_body:
            raise ContextPolicyError("rendered request bytes changed during send reconstruction")
        return dict(value)


def render_provider_tool_request(
    identity: ProviderContextIdentity,
    *,
    system_prompt: str,
    messages: Sequence[Mapping[str, Any]],
    tools: Sequence[Mapping[str, Any]],
    max_tokens: int,
    thinking_mode: str = "provider_default",
    reasoning_effort: str = "high",
    expect_json: bool = False,
) -> RenderedProviderRequest:
    if max_tokens < 1:
        raise ContextPolicyError("Provider output reserve must be positive")
    if thinking_mode not in {"provider_default", "enabled", "disabled"}:
        raise ContextPolicyError("Provider thinking mode is unsupported")
    if reasoning_effort not in {"low", "high", "max"}:
        raise ContextPolicyError("Provider reasoning effort is unsupported")
    converted_messages = provider_messages_for_wire(messages, identity.wire_protocol)
    converted_tools = provider_tools_for_wire(tools, identity.wire_protocol)
    if identity.wire_protocol == OPENAI_CHAT_COMPLETIONS:
        body: dict[str, Any] = {
            "model": identity.model,
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": system_prompt},
                *converted_messages,
            ],
            "tools": converted_tools,
        }
        if expect_json:
            body["response_format"] = {"type": "json_object"}
        if thinking_mode == "enabled":
            body["thinking"] = {"type": "enabled"}
            body["reasoning_effort"] = reasoning_effort
        elif thinking_mode == "disabled":
            body["thinking"] = {"type": "disabled"}
    elif identity.wire_protocol == ANTHROPIC_MESSAGES:
        body = {
            "model": identity.model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": converted_messages,
            "tools": converted_tools,
        }
        if thinking_mode == "enabled":
            body["reasoning"] = {"effort": reasoning_effort}
        elif thinking_mode == "disabled":
            body["reasoning"] = {"effort": "none"}
    else:  # pragma: no cover - ProviderContextIdentity already validates this.
        raise ContextPolicyError("Provider wire protocol is unsupported")
    canonical = _wire_json_bytes(body)
    component_bytes = {
        "system": len(system_prompt.encode("utf-8")),
        "tool_schemas": len(_wire_json_bytes(converted_tools)),
        "messages": len(_wire_json_bytes(converted_messages)),
        "protocol_body": len(canonical),
    }
    return RenderedProviderRequest(
        identity,
        canonical,
        hashlib.sha256(canonical).hexdigest(),
        component_bytes,
        max_tokens,
    )


@dataclass(frozen=True)
class RequestAdmission:
    status: str
    reason: str
    identity: ProviderContextIdentity
    body_hash: str
    body_bytes: int
    counting_mode: str
    counter_name: str
    counter_applicability: str
    protocol_margin_tokens: int
    input_bound_tokens: int
    output_reserve_tokens: int
    next_tool_turn_receipt_reserve_tokens: int
    total_reserved_tokens: int
    context_capacity_tokens: int | None
    component_bytes: Mapping[str, int]

    @property
    def admitted(self) -> bool:
        return self.status == "ADMITTED"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_LOOP_REQUEST_ADMISSION_V1",
            "status": self.status,
            "reason": self.reason,
            "capacity_identity": self.identity.as_dict(),
            "body_hash": self.body_hash,
            "body_bytes": self.body_bytes,
            "counting_mode": self.counting_mode,
            "counter_name": self.counter_name,
            "counter_applicability": self.counter_applicability,
            "protocol_margin_tokens": self.protocol_margin_tokens,
            "input_bound_tokens": self.input_bound_tokens,
            "output_reserve_tokens": self.output_reserve_tokens,
            "next_tool_turn_receipt_reserve_tokens": self.next_tool_turn_receipt_reserve_tokens,
            "total_reserved_tokens": self.total_reserved_tokens,
            "context_capacity_tokens": self.context_capacity_tokens,
            "component_bytes": dict(self.component_bytes),
            "provider_reported_actual_usage": False,
            "cumulative_task_budget_applied": False,
        }


class ProviderRequestPlanner:
    def __init__(
        self,
        registry: ModelCapacityRegistry,
        *,
        qualified_counter: QualifiedWireRequestCounter | None = None,
    ) -> None:
        self.registry = registry
        self.qualified_counter = qualified_counter

    def plan(self, rendered: RenderedProviderRequest) -> RequestAdmission:
        policy = self.registry.resolve(rendered.identity)
        if policy is None:
            return RequestAdmission(
                "CONTEXT_BLOCKED",
                "no exact profile/endpoint/model/wire capacity policy is configured",
                rendered.identity,
                rendered.body_hash,
                len(rendered.canonical_body),
                "unavailable",
                "unavailable",
                "no applicable counter contract",
                0,
                0,
                rendered.max_tokens,
                0,
                rendered.max_tokens,
                None,
                rendered.component_bytes,
            )

        if policy.counter_mode == "qualified_tokenizer":
            counter = self.qualified_counter
            if (
                counter is None
                or counter.name != policy.counter_name
                or counter.applicability != policy.counter_applicability
            ):
                return self._blocked(rendered, policy, "qualified wire-request tokenizer is unavailable or mismatched")
            counted = counter.count_wire_request(rendered.canonical_body)
            if not isinstance(counted, int) or isinstance(counted, bool) or counted < 0:
                return self._blocked(rendered, policy, "qualified tokenizer returned an invalid count")
            input_bound = counted + policy.protocol_margin_tokens
        else:
            # One token per UTF-8 byte is intentionally conservative only for
            # the applicability asserted by this exact policy entry. The
            # explicit margin covers provider-side chat-template material not
            # present in the JSON body. It is never reported as actual usage.
            input_bound = len(rendered.canonical_body) + policy.protocol_margin_tokens

        output_reserve = rendered.max_tokens
        total = input_bound + output_reserve + policy.next_tool_turn_receipt_reserve_tokens
        admitted = total <= policy.context_capacity_tokens
        return RequestAdmission(
            "ADMITTED" if admitted else "CONTEXT_BLOCKED",
            "request fits the exact policy" if admitted else "request plus reserves exceeds declared model capacity",
            rendered.identity,
            rendered.body_hash,
            len(rendered.canonical_body),
            policy.counter_mode,
            policy.counter_name,
            policy.counter_applicability,
            policy.protocol_margin_tokens,
            input_bound,
            output_reserve,
            policy.next_tool_turn_receipt_reserve_tokens,
            total,
            policy.context_capacity_tokens,
            rendered.component_bytes,
        )

    @staticmethod
    def _blocked(
        rendered: RenderedProviderRequest,
        policy: ModelCapacityPolicy,
        reason: str,
    ) -> RequestAdmission:
        output_reserve = rendered.max_tokens
        return RequestAdmission(
            "CONTEXT_BLOCKED",
            reason,
            rendered.identity,
            rendered.body_hash,
            len(rendered.canonical_body),
            policy.counter_mode,
            policy.counter_name,
            policy.counter_applicability,
            policy.protocol_margin_tokens,
            0,
            output_reserve,
            policy.next_tool_turn_receipt_reserve_tokens,
            output_reserve + policy.next_tool_turn_receipt_reserve_tokens,
            policy.context_capacity_tokens,
            rendered.component_bytes,
        )


@dataclass(frozen=True)
class ProtocolMessageGroup:
    assistant: Mapping[str, Any]
    tool_results: tuple[Mapping[str, Any], ...]
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.assistant.get("role") != "assistant" or not self.source_refs:
            raise ContextCoreError("protocol group requires an assistant turn and committed source refs")
        calls = self.assistant.get("tool_calls")
        if not isinstance(calls, list) or not calls:
            raise ContextCoreError("protocol group assistant must contain tool calls")
        call_ids = [str(item.get("id") or "") for item in calls if isinstance(item, Mapping)]
        result_ids = [str(item.get("tool_call_id") or "") for item in self.tool_results]
        if (
            len(call_ids) != len(calls)
            or not all(call_ids)
            or len(set(call_ids)) != len(call_ids)
            or len(set(result_ids)) != len(result_ids)
            or sorted(call_ids) != sorted(result_ids)
            or any(item.get("role") != "tool" for item in self.tool_results)
        ):
            raise ContextCoreError("protocol group tool-call/result pairing is incomplete or ambiguous")
        if tuple(sorted(set(self.source_refs))) != self.source_refs:
            raise ContextCoreError("protocol group source refs must be sorted and unique")

    def messages(self) -> tuple[Mapping[str, Any], ...]:
        return self.assistant, *self.tool_results

    @classmethod
    def from_committed_history(
        cls,
        index: "LoopContextIndex",
        assistant: Mapping[str, Any],
        tool_results: Sequence[Mapping[str, Any]],
        source_refs: Sequence[str],
    ) -> "ProtocolMessageGroup":
        index.refresh()
        visible = {item.source_ref for item in index.entries}
        refs = tuple(sorted(set(str(item) for item in source_refs)))
        if not refs or any(item not in visible for item in refs):
            raise ContextCoreError("protocol group source refs are not committed in this task history")
        return cls(assistant, tuple(tool_results), refs)


@dataclass(frozen=True)
class ProtocolGroupSelection:
    groups: tuple[ProtocolMessageGroup, ...]
    omitted_source_refs: tuple[str, ...]
    serialized_bytes: int


class ProtocolGroupSelector:
    @staticmethod
    def select(
        groups: Sequence[ProtocolMessageGroup],
        *,
        max_serialized_bytes: int,
        require_latest: bool = True,
    ) -> ProtocolGroupSelection:
        if max_serialized_bytes < 2:
            raise ContextCoreError("protocol-group byte budget is invalid")
        selected_reversed: list[tuple[int, ProtocolMessageGroup]] = []
        for index in reversed(range(len(groups))):
            group = groups[index]
            candidate = tuple(item[1] for item in reversed([*selected_reversed, (index, group)]))
            raw = _wire_json_bytes([message for item in candidate for message in item.messages()])
            if len(raw) <= max_serialized_bytes:
                selected_reversed.append((index, group))
            elif not selected_reversed and require_latest:
                raise ContextCoverageBlocked(
                    "latest complete assistant/tool protocol group cannot fit",
                    group.source_refs,
                )
            else:
                break
        selected_pairs = tuple(reversed(selected_reversed))
        selected = tuple(item[1] for item in selected_pairs)
        selected_indices = {item[0] for item in selected_pairs}
        omitted = tuple(sorted({ref for index, item in enumerate(groups) if index not in selected_indices for ref in item.source_refs}))
        serialized = len(_wire_json_bytes([message for item in selected for message in item.messages()]))
        return ProtocolGroupSelection(selected, omitted, serialized)


@dataclass(frozen=True)
class HistoryIndexEntry:
    ordinal: int
    event_position: int
    stream_version: int
    kind: str
    subject_id: str
    source_ref: str
    content_hash: str
    internal_cas_ref: str
    input_sequence: int | None = None
    input_kind: str | None = None

    def list_row(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "event_position": self.event_position,
            "stream_version": self.stream_version,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "source_ref": self.source_ref,
            "content_hash": self.content_hash,
        }


def _task_history_navigation_row(
    entry: HistoryIndexEntry, operation_tool_names: Mapping[str, str],
) -> dict[str, Any] | None:
    """Project task navigation without promoting retrieval receipts to work.

    The full index and explicit history reads remain unchanged for diagnosis.
    Only automatic navigation is filtered; no evidence or read credit is added.
    """
    tool = operation_tool_names.get(entry.subject_id)
    if entry.kind in {"operation_intent", "operation_result"} and tool == "sitina_history_query":
        return None
    row = entry.list_row()
    if entry.kind in {"operation_intent", "operation_result"} and tool:
        row["source_tool"] = tool
    return row


_HISTORY_FIELDS: Mapping[str, tuple[str, str, str, str]] = {
    "loop.task-created": ("goal", "goal_ref", "goal_hash", "task_id"),
    "loop.input-received": ("input", "body_ref", "body_hash", "input_id"),
    "loop.operation-intent-recorded": ("operation_intent", "intent_ref", "intent_hash", "operation_id"),
    "loop.operation-result-recorded": ("operation_result", "result_ref", "result_hash", "operation_id"),
    "loop.task-memory-view-revalidated": (
        "memory_view_revalidation",
        "revalidation_ref",
        "revalidation_hash",
        "task_id",
    ),
    "loop.acceptance-result-recorded": ("acceptance", "acceptance_ref", "acceptance_hash", "acceptance_id"),
    "loop.attempt-planned": ("attempt_plan", "plan_ref", "plan_hash", "attempt_id"),
    "loop.attempt-checkpointed": ("attempt_checkpoint", "checkpoint_ref", "checkpoint_hash", "checkpoint_id"),
    "loop.main-result-checkpointed": ("main_result_checkpoint", "checkpoint_ref", "checkpoint_hash", "checkpoint_id"),
    "loop.attempt-settled": ("attempt", "settlement_ref", "settlement_hash", "attempt_id"),
    "loop.review-findings-recorded": ("review", "review_ref", "review_hash", "task_id"),
    "loop.review-repair-recorded": ("review_repair", "repair_ref", "repair_hash", "task_id"),
    "loop.task-waiting": ("waiting", "waiting_ref", "waiting_hash", "task_id"),
    "loop.native-execution-wait-updated": ("waiting", "waiting_ref", "waiting_hash", "task_id"),
    "loop.task-context-blocked": ("context_blocker", "waiting_ref", "waiting_hash", "task_id"),
    "loop.resource-handoff-recorded": ("resource_handoff", "handoff_ref", "handoff_hash", "handoff_id"),
    "loop.task-terminated": ("terminal", "result_ref", "result_hash", "terminal_event_id"),
    "loop.child-delegation-admitted": ("child_contract", "contract_ref", "contract_hash", "delegation_id"),
    "loop.child-delegation-checkpointed": ("child_checkpoint", "checkpoint_ref", "checkpoint_hash", "delegation_id"),
    "loop.child-delegation-result-recorded": ("child_result", "result_ref", "result_hash", "delegation_id"),
    "loop.child-delegation-settled": ("child_settlement", "settlement_ref", "settlement_hash", "delegation_id"),
    "loop.child-delegation-applicability-updated": ("child_applicability", "applicability_ref", "applicability_hash", "delegation_id"),
    "loop.child-delegation-recovery-blocked": ("child_recovery", "recovery_ref", "recovery_hash", "delegation_id"),
    "loop.work-plan-updated": ("work_plan", "plan_ref", "plan_hash", "task_id"),
}

_KNOWN_LOOP_EVENT_TYPES = frozenset({
    "loop.work-plan-updated",
    "loop.task-created",
    "loop.input-received",
    "loop.input-handled",
    "loop.task-memory-view-revalidated",
    "loop.operation-intent-recorded",
    "loop.operation-dispatch-started",
    "loop.operation-precondition-changed",
    "loop.operation-result-recorded",
    "loop.operation-recovery-decided",
    "loop.artifact-updated",
    "loop.attempt-planned",
    "loop.attempt-checkpointed",
    "loop.main-result-checkpointed",
    "loop.attempt-settled",
    "loop.review-findings-recorded",
    "loop.review-repair-recorded",
    "loop.acceptance-result-recorded",
    "loop.task-waiting",
    "loop.native-execution-wait-updated",
    "loop.task-context-blocked",
    "loop.task-paused",
    "loop.task-recovery-docked",
    "loop.task-recovery-discovered",
    "loop.task-recovery-claimed",
    "loop.task-recovery-ready",
    "loop.task-recovery-blocked",
    "loop.task-resume-requested",
    "loop.task-terminated",
    "loop.resource-handoff-recorded",
    "loop.child-delegation-admitted",
    "loop.child-delegation-checkpointed",
    "loop.child-delegation-dispatch-started",
    "loop.child-delegation-result-recorded",
    "loop.child-delegation-cancel-requested",
    "loop.child-delegation-settled",
    "loop.child-delegation-applicability-updated",
    "loop.child-delegation-recovery-blocked",
})


class LoopContextIndex:
    """Process-local incremental index over committed task event metadata.

    Refresh scans the verified Journal stream but processes only new stream
    versions and never decrypts historical CAS bodies. Content verification is
    deferred to a requested read or the small set of current requirement refs.
    This is the reusable boundary for replacing `get_task()` full-CAS replay in
    the G2 request/control hot path; it is not cross-process recovery.
    """

    def __init__(self, store: LoopEventStore, task_id: str):
        self.store = store
        self.task_id = task_id
        self.entries: list[HistoryIndexEntry] = []
        self.state: dict[str, Any] = {}
        self._last_stream_version = 0
        self._last_position = 0
        self._active_operations: set[str] = set()
        self._unknown_operations: set[str] = set()
        self._handled_input_positions: dict[int, int] = {}
        self._operation_input_bindings: dict[str, int] = {}
        self._settled_operation_statuses: dict[str, str] = {}
        self._operation_tool_names: dict[str, str] = {}
        self._preparation_operation_ids: set[str] = set()

    @property
    def binding_hash(self) -> str:
        if not self.state:
            self.refresh()
        return hashlib.sha256(
            canonical_json_bytes({
                "spec_version": SPEC_VERSION,
                "task_id": self.task_id,
                "session_id": self.state["session_id"],
            })
        ).hexdigest()

    @property
    def frontier(self) -> int:
        return self._last_position

    def unresolved_operation_facts(self) -> tuple[Mapping[str, Any], ...]:
        self.refresh()
        return tuple(
            {
                "operation_id": operation_id,
                "effect_state": (
                    "UNKNOWN" if operation_id in self._unknown_operations else "IN_FLIGHT"
                ),
                "next_step": (
                    "Observe and reconcile the existing effect before deciding whether a retry is safe."
                    if operation_id in self._unknown_operations
                    else "Wait for or cancel and settle the running operation before repeating its effect."
                ),
                "unverified_replay_allowed": False,
            }
            for operation_id in sorted(self._active_operations | self._unknown_operations)
        )

    def current_binding(self) -> dict[str, Any]:
        self.refresh()
        return {
            "task_revision": self._last_stream_version,
            "run_instance_id": self.state["run_instance_id"],
            "execution_epoch": self.state["execution_epoch"],
            "goal_version": self.state["goal_version"],
            "acceptance_version": self.state["acceptance_version"],
            "criteria_lineage_version": self.state["criteria_lineage_version"],
            "received_input_seq": self.state["received_input_seq"],
            "handled_input_seq": self.state["handled_input_seq"],
            "control_intent": self.state["control_intent"],
            "status": self.state["status"],
            "artifact_ref": self.state["artifact_ref"],
            "frontier": self._last_position,
        }

    def reviewer_file_sources(
        self, relevant_source_refs: Sequence[str], *, capability_snapshot_id: str, environment_ref: str,
    ) -> list[dict[str, Any]]:
        """Resolve reviewer file receipts under the original immutable file authority.

        A permitted file read can create a new history handle. The handle does
        not grant new paths or versions, and repeated reads share one canonical
        source so they do not create another required full read.
        """
        from pathlib import PurePath
        from sitina.extensions.tools import file_read_content_bound

        current = self.current_binding()
        key = (self._last_stream_version, tuple(relevant_source_refs), capability_snapshot_id, environment_ref)
        cached = getattr(self, "_review_file_source_cache", None)
        if cached is not None and cached[0] == key:
            return [dict(item) for item in cached[1]]
        by_ref = {item.source_ref: item for item in self.entries}
        by_subject = {(item.kind, item.subject_id): item for item in self.entries}
        documents: dict[str, Mapping[str, Any]] = {}

        def read(entry: HistoryIndexEntry) -> Mapping[str, Any]:
            if entry.source_ref not in documents:
                documents[entry.source_ref] = self.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            return documents[entry.source_ref]

        allowed: set[tuple[str, str]] = set()
        canonical: dict[tuple[str, str], str] = {}
        artifact_sources: set[str] = set()
        for reference in relevant_source_refs:
            entry = by_ref.get(reference)
            if entry is None:
                continue
            document = read(entry)
            if entry.kind == "artifact" and entry.internal_cas_ref == current["artifact_ref"]:
                if document.get("schema") != "SITINA_LOOP_ARTIFACT_V1" or document.get("task_id") != self.task_id:
                    continue
                root = document.get("workspace_path")
                snapshot = document.get("workspace_snapshot")
                if not isinstance(root, str) or not PurePath(root).is_absolute() or not isinstance(snapshot, Mapping):
                    continue
                artifact_sources.add(reference)
                for relative in document.get("changed_paths", ()):
                    digest = snapshot.get(relative)
                    if (not isinstance(relative, str) or PurePath(relative).is_absolute()
                            or ".." in PurePath(relative).parts or not isinstance(digest, str)
                            or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
                        continue
                    allowed.add((str(PurePath(root) / relative), "sha256:" + digest))
            result = document.get("result", {})
            value = result.get("value") if isinstance(result, Mapping) else None
            if (document.get("effect_status") == "SUCCEEDED" and isinstance(result, Mapping)
                    and result.get("tool") == "sitina_read_file" and result.get("status") == "ok"
                    and isinstance(value, Mapping) and value.get("exists") is True
                    and isinstance(value.get("path"), str) and file_read_content_bound(value)):
                pair = (value["path"], value["version"])
                allowed.add(pair)
                canonical.setdefault(pair, reference)
        resolved: list[dict[str, Any]] = []
        if artifact_sources:
            for entry in self.entries:
                if entry.kind != "operation_result" or self._operation_tool_names.get(entry.subject_id) != "sitina_read_file":
                    continue
                intent_entry = by_subject.get(("operation_intent", entry.subject_id))
                if intent_entry is None:
                    continue
                intent = read(intent_entry)
                plan_entry = by_subject.get(("attempt_plan", intent.get("business_attempt_id")))
                if plan_entry is None:
                    continue
                plan = read(plan_entry)
                if (intent.get("agent_role") != "reviewer" or intent.get("mode") != "READ"
                        or intent.get("execution_owner") is not None or intent.get("task_id") != self.task_id
                        or plan.get("schema") != "SITINA_LOOP_ATTEMPT_PLAN_V1"
                        or plan.get("task_id") != self.task_id or plan.get("session_id") != self.state["session_id"]
                        or plan.get("acceptance_item_id") != "outcome-1"
                        or plan.get("blocker_id") not in REVIEW_EVIDENCE_PLAN_BLOCKERS
                        or plan.get("lineage_id") != f"lineage:{plan.get('goal_version')}:{plan.get('blocker_id')}"
                        or "history-read" not in plan.get("scope", {}).get("allowed_action_kinds", ())
                        or not artifact_sources.intersection(plan.get("relevant_source_refs", ()))
                        or plan.get("capability_snapshot_id") != capability_snapshot_id
                        or plan.get("environment_ref") != environment_ref
                        or intent.get("capability_snapshot_id") != capability_snapshot_id
                        or any(plan.get(field) != current[field] for field in
                               ("goal_version", "acceptance_version", "handled_input_seq"))
                        or any(intent.get("expected_" + field) != plan.get(field) for field in
                               ("run_instance_id", "execution_epoch", "goal_version", "acceptance_version", "handled_input_seq"))):
                    continue
                document = read(entry)
                result = document.get("result", {})
                value = result.get("value") if isinstance(result, Mapping) else None
                if (document.get("schema") != "SITINA_LOOP_OPERATION_RESULT_V1"
                        or document.get("task_id") != self.task_id or document.get("operation_id") != entry.subject_id
                        or document.get("effect_status") != "SUCCEEDED"
                        or any(document.get(key) != plan.get(field) for key, field in
                               (("bound_goal_version", "goal_version"), ("bound_acceptance_version", "acceptance_version"),
                                ("bound_input_seq", "handled_input_seq")))
                        or not isinstance(result, Mapping) or result.get("tool") != "sitina_read_file"
                        or result.get("status") != "ok" or not isinstance(value, Mapping)
                        or value.get("exists") is not True or not file_read_content_bound(value)
                        or (value.get("path"), value.get("version")) not in allowed):
                    continue
                pair = (value["path"], value["version"])
                canonical.setdefault(pair, entry.source_ref)
                resolved.append({"source_ref": entry.source_ref, "canonical_source_ref": canonical[pair],
                                 "path": pair[0], "content_version": pair[1], "source_role": "review_file_read"})
        self._review_file_source_cache = (key, tuple(resolved))
        return [dict(item) for item in resolved]

    def reviewer_request_evidence(
        self, attempt_id: str, operation_ids: Sequence[str],
    ) -> Mapping[str, Any] | None:
        """Return only the admitted, sent native request of this exact recipient.

        reviewer_read_progress must refresh authentication first. A prepared or
        historical sibling request is never a substitute for a missing receipt.
        """
        cache = getattr(self, "_review_read_cache", {})
        requests = cache.get("review_requests", {})
        for operation_id in reversed(tuple(operation_ids)):
            if not operation_id.startswith("provider-"):
                continue
            request = requests.get(operation_id)
            if request is None or request["attempt_id"] != attempt_id:
                return None
            return dict(request)
        return None

    def reviewer_read_progress(
        self, required_source_refs: Sequence[str], *, capability_snapshot_id: str, environment_ref: str,
        include_prepared: bool = False, available_source_refs: Sequence[str] = (),
        recipient_attempt_id: str | None = None,
    ) -> Mapping[str, Any]:
        """Authenticate reads and distinguish preparation from actual delivery.

        Model reads keep their native provenance. Product-prepared pages receive
        credit only after their exact text occurs in an admitted, sent request.
        Both paths retain immutable source/range facts across artifact changes.
        """
        current = self.current_binding()
        cache = getattr(self, "_review_read_cache", None)
        if cache is None:
            cache = {"seen": 0, "entries": {}, "sources": {}, "documents": {},
                     "projections": {}, "reads": [], "prepared": {}, "delivered": {},
                     "deliveries": {}, "requirements": [], "review_requests": {}}
            self._review_read_cache = cache

        def document(entry: HistoryIndexEntry) -> Mapping[str, Any]:
            if entry.source_ref not in cache["documents"]:
                cache["documents"][entry.source_ref] = self.store.read_json(
                    entry.internal_cas_ref, expected_hash=entry.content_hash,
                )
            return cache["documents"][entry.source_ref]

        binding_fields = ("run_instance_id", "execution_epoch", "goal_version",
                          "criteria_lineage_version", "handled_input_seq")
        for entry in self.entries[cache["seen"]:]:
            cache["entries"][(entry.kind, entry.subject_id)] = entry
            cache["sources"][entry.source_ref] = entry
            if entry.kind != "operation_result" or not entry.subject_id.startswith(("tool-", "provider-")):
                continue
            intent_entry = cache["entries"].get(("operation_intent", entry.subject_id))
            if intent_entry is None:
                continue
            intent = document(intent_entry)
            if (intent.get("agent_role") != "reviewer" or intent.get("mode") != "READ"
                    or intent.get("execution_owner") is not None or intent.get("task_id") != self.task_id):
                continue
            plan_entry = cache["entries"].get(("attempt_plan", intent.get("business_attempt_id")))
            if plan_entry is None:
                continue
            plan = document(plan_entry)
            if (plan.get("schema") != "SITINA_LOOP_ATTEMPT_PLAN_V1"
                    or plan.get("task_id") != self.task_id or plan.get("session_id") != self.state["session_id"]
                    or plan.get("acceptance_item_id") != "outcome-1"
                    or plan.get("blocker_id") not in REVIEW_EVIDENCE_PLAN_BLOCKERS
                    or plan.get("lineage_id") != f"lineage:{plan.get('goal_version')}:{plan.get('blocker_id')}"
                    or "history-read" not in plan.get("scope", {}).get("allowed_action_kinds", ())
                    or intent.get("capability_snapshot_id") != plan.get("capability_snapshot_id")
                    or any(intent.get("expected_" + key) != plan.get(key) for key in
                           ("run_instance_id", "execution_epoch", "goal_version", "acceptance_version", "handled_input_seq"))):
                continue
            result_document = document(entry)
            result = result_document.get("result", {})
            if (result_document.get("schema") != "SITINA_LOOP_OPERATION_RESULT_V1"
                    or result_document.get("task_id") != self.task_id
                    or result_document.get("operation_id") != entry.subject_id
                    or result_document.get("effect_status") != "SUCCEEDED"
                    or any(result_document.get(key) != plan.get(field) for key, field in
                           (("bound_goal_version", "goal_version"), ("bound_acceptance_version", "acceptance_version"),
                            ("bound_input_seq", "handled_input_seq")))
                    or not isinstance(result, Mapping)):
                continue

            if entry.subject_id.startswith("provider-"):
                wire = result.get("private_review_evidence_request")
                metadata = result.get("metadata")
                if not isinstance(wire, str) or not isinstance(metadata, Mapping):
                    continue
                admission = metadata.get("sitina_request_admission")
                digest = hashlib.sha256(wire.encode("utf-8")).hexdigest()
                if (not isinstance(admission, Mapping) or admission.get("status") != "ADMITTED"
                        or admission.get("body_hash") != digest
                        or metadata.get("request_body_hash") != digest
                        or metadata.get("sitina_admitted_body_hash") != digest
                        or type(metadata.get("physical_send_count")) is not int
                        or metadata["physical_send_count"] < 1):
                    continue
                try:
                    body = json.loads(wire)
                except (ValueError, TypeError):
                    continue
                messages = body.get("messages") if isinstance(body, Mapping) else None
                if not isinstance(messages, list):
                    continue
                contexts = []
                for message in messages:
                    if not isinstance(message, Mapping) or message.get("role") != "user":
                        continue
                    content = message.get("content")
                    texts = ([content] if isinstance(content, str) else
                             [block.get("text") for block in content
                              if isinstance(block, Mapping) and block.get("type") == "text"]
                             if isinstance(content, list) else [])
                    for text in texts:
                        try:
                            value = json.loads(text)
                        except (ValueError, TypeError):
                            continue
                        if isinstance(value, Mapping) and value.get("schema") == "SITINA_LOOP_MODEL_CONTEXT_V1":
                            contexts.append(value)
                if len(contexts) != 1:
                    continue
                context = contexts[0]
                execution = context.get("execution_context", {})
                task_context = context.get("task_context")
                if (context.get("role") != "reviewer"
                        or not isinstance(task_context, Mapping) or task_context.get("task_id") != self.task_id
                        or not isinstance(execution, Mapping)
                        or execution.get("phase") != "independent_read_only_review"
                        or execution.get("review_read_authority") != {
                            "capability_snapshot_id": plan["capability_snapshot_id"],
                            "environment_ref": plan["environment_ref"],
                        }):
                    continue
                # A complete file tool reply is also evidence when its exact
                # value reaches this reviewer in an admitted physical request.
                # Register only verified member text, never receipt wrappers.
                from .review_evidence import review_file_delivery_ranges
                role_rows = execution.get("review_source_roles", ())
                visible_refs = {row["source_ref"] for row in role_rows
                                if isinstance(row, Mapping) and isinstance(row.get("source_ref"), str)}
                plan_refs = set(plan.get("relevant_source_refs", ()))
                file_aliases = {row["source_ref"]: row["canonical_source_ref"]
                                for row in self.reviewer_file_sources(
                                    tuple(plan_refs), capability_snapshot_id=plan["capability_snapshot_id"],
                                    environment_ref=plan["environment_ref"])}
                allowed_refs = (plan_refs | set(file_aliases.values())) & visible_refs
                for message in messages:
                    if (not isinstance(message, Mapping) or message.get("role") != "tool"
                            or not isinstance(message.get("content"), str)):
                        continue
                    try:
                        envelope = json.loads(message["content"])
                    except (ValueError, TypeError):
                        continue
                    payload = envelope.get("result") if isinstance(envelope, Mapping) else None
                    ref = payload.get("source_ref") if isinstance(payload, Mapping) else None
                    if not isinstance(ref, str):
                        continue
                    canonical_ref = file_aliases.get(ref, ref)
                    source = cache["sources"].get(ref)
                    canonical = cache["sources"].get(canonical_ref)
                    if (canonical_ref not in allowed_refs or source is None or canonical is None
                            or source.kind != "operation_result" or canonical.kind != "operation_result"):
                        continue
                    if review_file_delivery_ranges(document(source), envelope) is None:
                        continue
                    delivered_file = review_file_delivery_ranges(document(canonical), envelope)
                    if delivered_file is None:
                        continue
                    raw, projection, ranges = delivered_file
                    cache["delivered"][entry.source_ref] = entry.source_ref
                    for interval in ranges:
                        cache["reads"].append({
                            "source_ref": canonical_ref, "source_content_hash": canonical.content_hash,
                            "content_hash": hashlib.sha256(raw).hexdigest(), "content_projection": projection,
                            "total_bytes": len(raw), "range": interval, "receipt_source_ref": entry.source_ref,
                            "file_read_receipt_source_ref": source.source_ref,
                            "binding": {key: plan[key] for key in binding_fields},
                            "acceptance_version": plan["acceptance_version"],
                            "capability_snapshot_id": plan["capability_snapshot_id"],
                            "environment_ref": plan["environment_ref"], "origin": "model_file_delivery",
                            "attempt_id": intent["business_attempt_id"], "view": "review",
                        })
                pages = execution.get("product_prepared_evidence", ())
                progress = execution.get("history_read_progress")
                if (isinstance(progress, Mapping)
                        and isinstance(progress.get("citable_source_refs"), list)
                        and all(isinstance(ref, str) for ref in progress["citable_source_refs"])):
                    cache["review_requests"][entry.subject_id] = {
                        "attempt_id": intent["business_attempt_id"],
                        "operation_id": entry.subject_id,
                        "result_ref": entry.internal_cas_ref,
                        "result_hash": entry.content_hash,
                        "request_body_hash": digest,
                        "citable_source_refs": list(progress["citable_source_refs"]),
                    }
                requirements = task_context.get("current_requirements")
                if isinstance(requirements, list):
                    for row in requirements:
                        if not isinstance(row, Mapping) or not isinstance(row.get("source_ref"), str):
                            continue
                        original = cache["sources"].get(row["source_ref"])
                        if original is None or original.kind not in {"goal", "input"}:
                            continue
                        text = document(original).get("goal" if original.kind == "goal" else "body")
                        if not isinstance(text, str) or row.get("text") != text:
                            continue
                        cache["requirements"].append({
                            "source_ref": original.source_ref, "source_content_hash": original.content_hash,
                            "text_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                            "delivery_receipt_source_ref": entry.source_ref,
                            "attempt_id": intent["business_attempt_id"],
                            "binding": {key: plan[key] for key in binding_fields},
                            "capability_snapshot_id": plan["capability_snapshot_id"],
                            "environment_ref": plan["environment_ref"],
                        })
                if not isinstance(pages, list) or not isinstance(progress, Mapping):
                    continue
                roles = execution.get("review_source_roles")
                registered_optional_refs = {
                    row["source_ref"] for row in roles
                    if isinstance(row, Mapping) and isinstance(row.get("source_ref"), str)
                } if isinstance(roles, list) else set()
                registered_optional_refs.intersection_update(plan.get("relevant_source_refs", ()))
                for page in pages:
                    if not isinstance(page, Mapping) or not isinstance(page.get("read_receipt_source_ref"), str):
                        continue
                    read = cache["prepared"].get(page.get("read_receipt_source_ref"))
                    if (read is not None and dict(page) == read["prepared_page"]
                            and all(read["binding"][key] == plan[key] for key in binding_fields)
                            and 0 < read["acceptance_version"] <= plan["acceptance_version"]
                            and read["capability_snapshot_id"] == plan["capability_snapshot_id"]
                            and read["environment_ref"] == plan["environment_ref"]
                            and (read["source_ref"] in progress.get("required_source_refs", ())
                                 or read["source_ref"] in registered_optional_refs)):
                        cache["delivered"][read["receipt_source_ref"]] = entry.source_ref
                        cache["deliveries"].setdefault(read["receipt_source_ref"], {})[entry.subject_id] = {
                            "attempt_id": intent["business_attempt_id"],
                            "delivery_receipt_source_ref": entry.source_ref,
                        }
                continue

            if result.get("tool") != "sitina_history_query" or result.get("status") != "ok":
                continue
            arguments, page = result.get("arguments"), result.get("value")
            if not isinstance(arguments, Mapping) or not isinstance(page, Mapping):
                continue
            arguments = LoopHistoryQuery._canonical_read_arguments(arguments)
            if arguments.get("continuation_ref") is not None:
                resolver = cache.get("continuations")
                if resolver is None:
                    resolver = LoopHistoryQuery(self, max_page_bytes=LoopHistoryQuery.BODY_MAX_BYTES)
                    cache["continuations"] = resolver
                arguments, error = resolver._resolve_committed_continuation(
                    arguments, refresh_index=False, before_ordinal=entry.ordinal,
                )
                if error is not None:
                    continue
            source_ref = arguments.get("source_ref")
            source = cache["sources"].get(source_ref) if isinstance(source_ref, str) else None
            query = page.get("query")
            authorized_sources = set(plan.get("relevant_source_refs", ()))
            if source_ref not in authorized_sources:
                authorized_sources.update(item["canonical_source_ref"] for item in self.reviewer_file_sources(
                    tuple(authorized_sources), capability_snapshot_id=plan["capability_snapshot_id"],
                    environment_ref=plan["environment_ref"],
                ))
            if (arguments.get("operation") != "read" or source is None
                    or source_ref not in authorized_sources
                    or page.get("schema") != "SITINA_LOOP_HISTORY_READ_V1" or page.get("status") != "OK"
                    or page.get("source_ref") != source_ref or page.get("task_session_binding") != self.binding_hash
                    or not isinstance(query, Mapping) or query.get("operation") != "read"
                    or query.get("source_ref") != source_ref):
                continue
            view = arguments.get("view", "raw")
            if view not in {"raw", "review"}:
                continue
            projection_key = (source_ref, view)
            if projection_key not in cache["projections"]:
                value = self.store.read_json(source.internal_cas_ref, expected_hash=source.content_hash)
                value, projection = LoopHistoryQuery._history_safe_document(source, value)
                raw, projection = source_read_bytes(value, projection, view)
                cache["projections"][projection_key] = (raw, projection, hashlib.sha256(raw).hexdigest())
            raw, projection, projected_hash = cache["projections"][projection_key]
            offset, returned, total = page.get("offset"), page.get("returned_bytes"), page.get("total_bytes")
            if (any(type(value) is not int for value in (offset, returned, total, arguments.get("offset", 0)))
                    or offset != arguments.get("offset", 0) or not 0 <= offset < offset + returned <= total
                    or total != len(raw) or type(page.get("has_more")) is not bool
                    or page["has_more"] != (offset + returned < total)
                    or page.get("next_offset") != (offset + returned if page["has_more"] else None)
                    or page.get("content_hash") != (projected_hash if projection else source.content_hash)
                    or page.get("content_projection") != projection
                    or (projection and (page.get("source_content_hash") != source.content_hash
                                        or page.get("content_hash_scope") != "projected-readable-content"))):
                continue
            try:
                observed = base64.b64decode(page.get("data_base64", ""), validate=True)
                readable = observed.decode("utf-8")
            except (ValueError, TypeError, UnicodeError):
                continue
            if observed != raw[offset:offset + returned] or page.get("readable_text") != readable:
                continue
            origin = result.get("invocation_origin", "model")
            if origin not in {"model", "product_review_preparation"}:
                continue
            read = {
                "source_ref": source_ref, "source_content_hash": source.content_hash,
                "content_hash": page["content_hash"], "content_projection": projection, "total_bytes": total,
                "range": [offset, offset + returned], "receipt_source_ref": entry.source_ref,
                "binding": {key: plan[key] for key in binding_fields},
                "acceptance_version": plan["acceptance_version"],
                "capability_snapshot_id": plan["capability_snapshot_id"], "environment_ref": plan["environment_ref"],
                "origin": origin,
                "attempt_id": intent["business_attempt_id"],
                "view": view,
            }
            if origin == "product_review_preparation":
                if intent.get("description") != "prepare required review evidence with sitina_history_query":
                    continue
                read["prepared_page"] = {
                    "origin": origin, "source_ref": source_ref,
                    "read_receipt_source_ref": entry.source_ref,
                    "source_content_hash": source.content_hash,
                    "content_hash": page["content_hash"], "content_projection": projection,
                    "offset": offset, "returned_bytes": returned, "total_bytes": total,
                    "has_more": page["has_more"], "next_offset": page["next_offset"],
                    "readable_text": readable,
                    "view": view, "next_read": page.get("next_read"),
                }
                cache["prepared"][entry.source_ref] = read
            cache["reads"].append(read)
        cache["seen"] = len(self.entries)
        from .model import current_reviewer_continuation

        continuation = current_reviewer_continuation(
            self.state.get("provider_response_dispositions", {}), task_id=self.task_id, binding=current,
        )
        prior_binding = continuation["original_binding"] if continuation is not None else None
        recipient_chain: tuple[str, ...] = ()
        recipient_scope = None
        if recipient_attempt_id is not None:
            plans = {subject_id: document(entry) for (kind, subject_id), entry in cache["entries"].items()
                     if kind == "attempt_plan"}
            recipient_chain = review_recipient_attempt_chain(
                plans, recipient_attempt_id, task_id=self.task_id, session_id=self.state["session_id"],
            )
            recipient_scope = frozenset(recipient_chain)
        required = list(dict.fromkeys(required_source_refs))
        available = list(dict.fromkeys((*required, *available_source_refs)))
        versions: dict[tuple[str, str, str | None], Any] = {}
        pending: dict[str, Any] = {}
        retained: dict[tuple[Any, ...], Mapping[str, Any]] = {}
        for read in cache["reads"]:
            ref = read["source_ref"]
            same_binding = all(read["binding"][key] == current[key] for key in binding_fields)
            continued_binding = (prior_binding is not None
                                 and all(read["binding"][key] == prior_binding[key] for key in binding_fields))
            own_deliveries = [
                row for row in cache["deliveries"].get(read["receipt_source_ref"], {}).values()
                if recipient_scope is not None and row["attempt_id"] in recipient_scope
            ]
            same_reader = bool(
                recipient_scope
                and (own_deliveries if read["origin"] == "product_review_preparation"
                     else read["attempt_id"] in recipient_scope)
                and all(read["binding"][key] == current[key]
                        for key in ("goal_version", "criteria_lineage_version"))
                and read["acceptance_version"] == current["acceptance_version"]
            )
            if (ref not in available or not (same_binding or continued_binding or same_reader)
                    or read["capability_snapshot_id"] != capability_snapshot_id or read["environment_ref"] != environment_ref
                    or not 0 < read["acceptance_version"] <= current["acceptance_version"]):
                continue
            delivery = cache["delivered"].get(read["receipt_source_ref"])
            if recipient_scope is not None:
                if read["origin"] == "product_review_preparation":
                    delivery = own_deliveries[-1]["delivery_receipt_source_ref"] if own_deliveries else None
                elif read["attempt_id"] not in recipient_scope:
                    continue
            if read["origin"] == "product_review_preparation" and delivery is None:
                # Offer an authenticated current page without granting delivery credit.
                # Other readers' sends never make it read by this recipient.
                if ((recipient_scope is None or recipient_scope) and same_binding
                        and read["acceptance_version"] == current["acceptance_version"]):
                    pending[ref] = dict(read["prepared_page"])
                continue
            if read["origin"] == "product_review_preparation":
                page = read["prepared_page"]
                retained[(ref, read["content_hash"], read["content_projection"],
                          page["offset"], page["returned_bytes"])] = dict(page)
            version_key = (ref, read["content_hash"], read["content_projection"])
            row = versions.setdefault(version_key, {key: read[key] for key in
                ("source_ref", "source_content_hash", "content_hash", "content_projection", "total_bytes", "view")})
            row.setdefault("read_ranges", []).append(read["range"])
            row["receipt_source_ref"] = read["receipt_source_ref"]
            if delivery is not None:
                row["delivery_receipt_source_ref"] = delivery
        for row in versions.values():
            merged: list[list[int]] = []
            for start, end in sorted(row["read_ranges"]):
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            row["read_ranges"] = merged
            row["complete_source_read"] = merged == [[0, row["total_bytes"]]]
            cursor = merged[0][1] if merged[0][0] == 0 else 0
            row["next_unread_offset"] = None if cursor == row["total_bytes"] else cursor
        # A complete older representation remains valid for that immutable source.
        # Partial ranges from different projections never share coordinates.
        rows: dict[str, Any] = {}
        for row in versions.values():
            previous = rows.get(row["source_ref"])
            if (previous is None or (row["complete_source_read"] and not previous["complete_source_read"])
                    or (row["complete_source_read"] == previous["complete_source_read"]
                        and row["view"] == "review")):
                rows[row["source_ref"]] = row
        delivered_requirements = {}
        for row in cache["requirements"]:
            if recipient_scope is not None and row["attempt_id"] not in recipient_scope:
                continue
            if (row["capability_snapshot_id"] == capability_snapshot_id and row["environment_ref"] == environment_ref
                    and (all(row["binding"][key] == current[key] for key in binding_fields)
                         or (prior_binding is not None and all(row["binding"][key] == prior_binding[key]
                                                              for key in binding_fields)))):
                delivered_requirements[row["source_ref"]] = {key: row[key] for key in
                    ("source_ref", "source_content_hash", "text_hash", "delivery_receipt_source_ref")}
        return {"coverage_scope": "RECIPIENT" if recipient_scope is not None else "HISTORICAL_AGGREGATE",
                "recipient_attempt_id": recipient_attempt_id,
                "recipient_attempt_ids": list(recipient_chain),
                "recipient_root_attempt_id": recipient_chain[-1] if recipient_chain else None,
                "required_source_refs": required,
                "delivered_requirement_sources": list(delivered_requirements.values()),
                "completed_source_refs": [ref for ref in required if ref in rows and rows[ref]["complete_source_read"]],
                "partially_read_source_refs": [ref for ref in required if ref in rows and not rows[ref]["complete_source_read"]],
                "observed_source_refs": [ref for ref in required if ref in rows],
                "citable_source_refs": [ref for ref in available if ref in rows] if recipient_scope is not None else [],
                "unread_source_refs": [ref for ref in required if ref not in rows],
                "missing_source_refs": [ref for ref in required if ref not in rows or not rows[ref]["complete_source_read"]],
                "next_read_offsets": {ref: rows[ref]["next_unread_offset"] if ref in rows else 0 for ref in required},
                "read_sources": [rows[ref] for ref in available if ref in rows],
                **({"prepared_source_pages": [pending[ref] for ref in available if ref in pending
                                              and pending[ref]["offset"] == (
                                                  rows[ref]["next_unread_offset"] if ref in rows else 0)
                                              and (ref not in rows or pending[ref]["content_hash"] == rows[ref]["content_hash"])],
                    "retained_prepared_source_pages": list(retained.values())}
                   if include_prepared else {})}
    def working_summary(
        self, execution_context: Mapping[str, Any], *, include_recent_actions: bool = True,
    ) -> Mapping[str, Any]:
        """Incremental, source-linked progress beside the persisted goal interpretation.

        User requirements remain verbatim. No model call, historical CAS scan,
        or guessed completion is needed to retain the results of evicted turns.
        """
        binding = self.current_binding()
        work_plan = None
        if self.state.get("work_plan_goal_version") == binding["goal_version"]:
            from .model import validate_work_plan
            work_plan = self.store.read_json(self.state["work_plan_ref"], expected_hash=self.state["work_plan_hash"])
            validate_work_plan(work_plan, task_id=self.task_id, goal_version=binding["goal_version"],
                               previous_revision=self.state["work_plan_revision"] - 1)
        results = {item.subject_id: item for item in self.entries if item.kind == "operation_result"}
        settled_actions = [(operation_id, status) for operation_id, status in self._settled_operation_statuses.items()
                           if not operation_id.startswith("provider-")
                           and self._operation_tool_names.get(operation_id) != "sitina_history_query"
                           and operation_id not in self._preparation_operation_ids]
        recent = [{"operation_id": operation_id, "effect_status": status,
                   "source_ref": results[operation_id].source_ref,
                   "content_hash": results[operation_id].content_hash,
                   "observed_under_input_sequence": self._operation_input_bindings.get(operation_id)}
                  for operation_id, status in (settled_actions[-12:] if include_recent_actions else ())
                  if operation_id in results]
        corrections = [item for item in self.requirement_entries() if item.kind == "input"]
        interpretation = execution_context.get("interpreted_goal_input")
        provenance = execution_context.get("goal_input_provenance")
        interpretation_current = (isinstance(interpretation, Mapping) and isinstance(provenance, Mapping)
                                  and provenance.get("goal_version") == binding["goal_version"]
                                  and provenance.get("criteria_lineage_version") == binding["criteria_lineage_version"])
        return {
            "schema": "SITINA_STRUCTURED_TASK_NOTES_V1",
            "kind": "current_goal_and_durable_progress",
            "task_id": self.task_id,
            "session_id": self.state["session_id"],
            "revision": binding["task_revision"],
            "persistence": "Rebuilt from authenticated Journal events and immutable CAS sources; not a separate editable truth store.",
            "goal_and_constraints_path": "task_context.current_requirements",
            "pending_work_path": "task_context.open_obligations",
            "confirmation_policy": {
                "recent_action_results": "RECORDED_OPERATION_OUTCOME: confirms the receipt, not the business conclusion or current file contents.",
                "work_plan": "VERSIONED_PLAN: step status is not independent acceptance.",
                "assistant_notes": "UNCONFIRMED: model statements remain hypotheses until supported by applicable evidence.",
                "user_requirements": "AUTHORITATIVE_INSTRUCTIONS: preserved verbatim, separate from inferred facts.",
            },
            "binding": {key: binding[key] for key in ("goal_version", "acceptance_version", "handled_input_seq", "frontier")},
            "goal_summary_path": ("execution_context.interpreted_goal_input" if interpretation_current else None),
            "goal_summary_state": "CURRENT" if interpretation_current else "NEEDS_CURRENT_INTERPRETATION",
            "work_plan": work_plan,
            "work_plan_revision": work_plan["revision"] if work_plan else 0,
            "work_plan_source": ({"cas_ref": self.state["work_plan_ref"],
                                  "content_hash": self.state["work_plan_hash"],
                                  "goal_version": binding["goal_version"]} if work_plan else None),
            "plan_rule": "The current work plan replaces the initial execution steps, not the user's goal or acceptance conditions.",
            "goal_summary_source_refs": list(execution_context.get("goal_input_source_refs") or ()) if interpretation_current else [],
            "authority": "derived_summary; current user requirements and action records take precedence",
            "handled_changes": [{"kind": item.input_kind, "sequence": item.input_sequence, "source_ref": item.source_ref}
                                for item in corrections],
            "settled_action_count": len(settled_actions),
            "successful_action_count": sum(status == "SUCCEEDED" for _, status in settled_actions),
            "action_count_scope": "Committed non-Provider operations excluding history-query receipts; counts do not prove business completion.",
            "history_query_receipt_count": sum(name == "sitina_history_query" for name in self._operation_tool_names.values()),
            "business_action_rule": "Follow the current goal with the available business tools. History restores necessary prior evidence; Provider replies and history-query receipts are not new external facts or task completion. Do not recursively read history-query receipts.",
            **({
                "action_count_scope": "Committed non-Provider operations excluding history-query and review preparation receipts; counts do not prove business completion.",
                "review_preparation_receipt_count": len(self._preparation_operation_ids),
                "review_preparation_trace": "execution_context.product_prepared_evidence and authenticated task history; these receipts are not business sources.",
            } if self._preparation_operation_ids else {}),
            "recent_action_results": recent,
            "older_action_count": max(0, len(settled_actions) - len(recent)),
            "older_actions": {"tool": "sitina_history_query", "operation": "list"},
            "unresolved_actions_path": "task_context.unresolved_operations",
            "memory_view_ref": self.state.get("memory_view_ref"),
            "memory_revalidation_ref": self.state.get("memory_view_revalidation_ref"),
            "excluded_memory_ids": list(self.state.get("memory_view_excluded_ids", ())),
            "continuation_rule": "Preserve completed actions; reconcile unknown effects; revise only work affected by current changes.",
        }

    def refresh(self) -> None:
        events = self.store.task_events(self.task_id, after_position=self._last_position)
        if not events and not self.state:
            raise KeyError(self.task_id)
        new_events = [event for event in events if event.stream_version > self._last_stream_version]
        expected = self._last_stream_version + 1
        for event in new_events:
            if event.stream_version != expected:
                raise ContextCoreError("task history stream version is discontinuous")
            if event.payload.get("spec_version") != SPEC_VERSION:
                raise ContextCoreError("task history mixes specification versions")
            if event.event_type not in _KNOWN_LOOP_EVENT_TYPES:
                raise ContextCoreError("task history contains an unknown event type")
            if not self.state and event.event_type != "loop.task-created":
                raise ContextCoreError("task history does not begin with task creation")
            self._apply_state(event.event_type, event.payload, object_refs=event.object_refs)
            if event.event_type == "loop.input-handled":
                self._handled_input_positions[int(event.payload["handled_input_seq"])] = event.position
            elif event.event_type == "loop.operation-intent-recorded":
                self._operation_input_bindings[str(event.payload["operation_id"])] = int(
                    event.payload["bound_input_seq"]
                )
            fields = _HISTORY_FIELDS.get(event.event_type)
            history_fields = [fields] if fields is not None else []
            if event.event_type in {"loop.task-created", "loop.artifact-updated"} and event.payload.get(
                "artifact_hash"
            ):
                history_fields.append(("artifact", "artifact_ref", "artifact_hash", "task_id"))
            if event.event_type == "loop.task-created" and event.payload.get("memory_view_hash"):
                # The immutable selected view is native task evidence, not a
                # new requirement or an instruction. Keep the same committed
                # object-reference and task/session visibility checks below.
                history_fields.append(("memory_view", "memory_view_ref", "memory_view_hash", "task_id"))
            if event.payload.get("stop_report_ref") and event.payload.get("stop_report_hash"):
                history_fields.append(("stop_report", "stop_report_ref", "stop_report_hash", "task_id"))
            for kind, ref_key, hash_key, subject_key in history_fields:
                reference = str(event.payload.get(ref_key) or "")
                content_hash = str(event.payload.get(hash_key) or "")
                # Visibility requires both a committed event field and the
                # Journal's verified object-reference proof. Artifact refs
                # without such a proof are intentionally not indexed here.
                if reference and content_hash and reference in event.object_refs:
                    ordinal = len(self.entries) + 1
                    handle_digest = hashlib.sha256(
                        canonical_json_bytes({
                            "binding": self.binding_hash,
                            "ordinal": ordinal,
                            "reference": reference,
                            "content_hash": content_hash,
                        })
                    ).hexdigest()
                    handle = f"history:{self.binding_hash}:{ordinal}:{handle_digest}"
                    entry = HistoryIndexEntry(
                        ordinal,
                        event.position,
                        event.stream_version,
                        kind,
                        str(event.payload.get(subject_key) or self.task_id),
                        handle,
                        content_hash,
                        reference,
                        int(event.payload["input_seq"])
                        if kind == "input" and event.event_type == "loop.input-received"
                        else None,
                        str(event.payload["kind"])
                        if kind == "input" and event.event_type == "loop.input-received"
                        else None,
                    )
                    self.entries.append(entry)
                    if kind == "operation_result" and not entry.subject_id.startswith("provider-"):
                        result = self.store.read_json(reference, expected_hash=content_hash).get("result")
                        if isinstance(result, Mapping) and isinstance(result.get("tool"), str):
                            self._operation_tool_names[entry.subject_id] = result["tool"]
                        if isinstance(result, Mapping) and result.get("invocation_origin") == "product_review_preparation":
                            self._preparation_operation_ids.add(entry.subject_id)
                    if kind in {"waiting", "context_blocker"}:
                        self.state["waiting_source_ref"] = handle
            self._last_stream_version = event.stream_version
            self._last_position = event.position
            expected += 1

    def _apply_state(
        self,
        event_type: str,
        value: Mapping[str, Any],
        *,
        object_refs: Sequence[str] = (),
    ) -> None:
        if event_type == "loop.work-plan-updated":
            previous_revision = (self.state.get("work_plan_revision", 0)
                                 if self.state.get("work_plan_goal_version") == self.state.get("goal_version") else 0)
            if (value.get("schema") != "SITINA_LOOP_WORK_PLAN_UPDATED_V1"
                    or type(value.get("goal_version")) is not int or value["goal_version"] != self.state.get("goal_version")
                    or type(value.get("revision")) is not int or value["revision"] != previous_revision + 1
                    or not value.get("plan_hash") or value.get("plan_ref") not in object_refs):
                raise ContextCoreError("work plan event lacks its current version and content proof")
            self.state.update({"work_plan_goal_version": value["goal_version"], "work_plan_revision": value["revision"],
                               "work_plan_ref": value["plan_ref"], "work_plan_hash": value["plan_hash"]})
        elif event_type == "loop.task-created":
            self.state = {
                "session_id": str(value["session_id"]),
                "task_kind": str(value["task_kind"]),
                "run_instance_id": str(value["run_instance_id"]),
                "execution_epoch": int(value["execution_epoch"]),
                "goal_version": int(value["goal_version"]),
                "acceptance_version": int(value["acceptance_version"]),
                "criteria_lineage_version": int(value.get("criteria_lineage_version", 1)),
                "artifact_version": int(value.get("artifact_version", 1)),
                "artifact_ref": str(value["artifact_ref"]),
                "received_input_seq": int(value["received_input_seq"]),
                "handled_input_seq": int(value["handled_input_seq"]),
                "control_intent": str(value["control_intent"]),
                "status": str(value["status"]),
                "resume_request_id": None,
                "required_outcome_ids": tuple(str(item) for item in value["required_outcome_ids"]),
                "waiting_ref": None,
                "waiting_source_ref": None,
                "memory_view_ref": str(value["memory_view_ref"]) if value.get("memory_view_ref") else None,
                "memory_view_hash": str(value["memory_view_hash"]) if value.get("memory_view_hash") else None,
                "memory_view_revalidation_ref": None,
                "memory_view_revalidation_hash": None,
                "memory_view_revalidation_input_seq": None,
                "memory_view_excluded_ids": (),
                "child_delegations": {},
            }
            return
        if event_type == "loop.input-received":
            self.state["received_input_seq"] = int(value["input_seq"])
            self.state["control_intent"] = str(value["control_intent"])
            self.state["status"] = str(value["status"])
        elif event_type == "loop.input-handled":
            self.state["handled_input_seq"] = int(value["handled_input_seq"])
            self.state["goal_version"] = int(value["goal_version"])
            self.state["acceptance_version"] = int(value["acceptance_version"])
            self.state["criteria_lineage_version"] = int(
                value.get("criteria_lineage_version", self.state["criteria_lineage_version"])
            )
            self.state["control_intent"] = str(value["control_intent"])
            self.state["status"] = str(value["status"])
            self.state["waiting_ref"] = None
            self.state["waiting_source_ref"] = None
        elif event_type == "loop.task-memory-view-revalidated":
            reference = str(value.get("revalidation_ref") or "")
            content_hash = str(value.get("revalidation_hash") or "")
            if not reference or not content_hash or reference not in set(object_refs):
                raise ContextCoreError("memory view revalidation event lacks a committed CAS proof")
            if value.get("schema") != "SITINA_LOOP_MEMORY_VIEW_REVALIDATED_V1":
                raise ContextCoreError("memory view revalidation event schema is invalid")
            if str(value.get("task_id") or "") != self.task_id:
                raise ContextCoreError("memory view revalidation event task binding is invalid")
            original_ref = str(value.get("original_memory_view_ref") or "")
            original_hash = str(value.get("original_memory_view_hash") or "")
            if (
                not original_ref
                or not original_hash
                or original_ref != self.state.get("memory_view_ref")
                or original_hash != self.state.get("memory_view_hash")
            ):
                raise ContextCoreError("memory view revalidation original binding is invalid")
            try:
                original = self.store.read_json(original_ref, expected_hash=original_hash)
                document = self.store.read_json(reference, expected_hash=content_hash)
            except Exception as error:
                raise ContextCoreError("memory view revalidation CAS is unavailable or unverifiable") from error
            if (
                original.get("schema") != "SITINA_LOOP_MEMORY_VIEW_V1"
                or str(original.get("task_id") or "") != self.task_id
                or document.get("schema") != "SITINA_LOOP_MEMORY_VIEW_REVALIDATION_V1"
                or str(document.get("task_id") or "") != self.task_id
                or document.get("original_memory_view_ref") != original_ref
                or document.get("original_memory_view_hash") != original_hash
                or int(document.get("bound_task_revision", -1)) != self._last_stream_version
                or str(document.get("run_instance_id") or "") != str(self.state.get("run_instance_id") or "")
                or int(document.get("execution_epoch", -1)) != int(self.state.get("execution_epoch", -2))
                or int(document.get("goal_version", -1)) != int(self.state.get("goal_version", -2))
                or int(document.get("acceptance_version", -1)) != int(self.state.get("acceptance_version", -2))
                or int(document.get("handled_input_seq", -1)) != int(self.state.get("handled_input_seq", -2))
            ):
                raise ContextCoreError("memory view revalidation binding is stale")
            try:
                correction_seq = int(document.get("correction_input_seq", -1))
            except (TypeError, ValueError) as error:
                raise ContextCoreError("memory view revalidation correction binding is invalid") from error
            if correction_seq < 1 or correction_seq > int(self.state["handled_input_seq"]):
                raise ContextCoreError("memory view revalidation correction is outside handled history")
            if not any(
                item.kind == "input"
                and item.input_sequence == correction_seq
                and item.input_kind == InputKind.CORRECTION.value
                for item in self.entries
            ):
                raise ContextCoreError("memory view revalidation correction is not in task history")
            selected_ids = tuple(str(item) for item in original.get("selected_memory_ids", ()))
            selected_versions = original.get("selected_memory_versions")
            active_entries = document.get("active_entries")
            excluded_entries = document.get("excluded_entries")
            excluded_ids = document.get("excluded_memory_ids")
            if (
                not isinstance(selected_versions, Mapping)
                or not isinstance(active_entries, list)
                or not isinstance(excluded_entries, list)
                or not isinstance(excluded_ids, list)
            ):
                raise ContextCoreError("memory view revalidation evidence is malformed")
            active_by_id: dict[str, Mapping[str, Any]] = {}
            excluded_by_id: dict[str, Mapping[str, Any]] = {}
            for entry, target in ((active_entries, active_by_id), (excluded_entries, excluded_by_id)):
                for item in entry:
                    if not isinstance(item, Mapping):
                        raise ContextCoreError("memory view revalidation entry is malformed")
                    memory_id = str(item.get("memory_id") or "")
                    try:
                        expected_version = int(item.get("expected_version", -1))
                    except (TypeError, ValueError) as error:
                        raise ContextCoreError("memory view revalidation version is malformed") from error
                    if not memory_id or expected_version < 1 or memory_id in target:
                        raise ContextCoreError("memory view revalidation entry identity is invalid")
                    target[memory_id] = item
                    if int(selected_versions.get(memory_id, -1)) != expected_version:
                        raise ContextCoreError("memory view revalidation version binding is invalid")
            if (
                set(active_by_id) | set(excluded_by_id) != set(selected_ids)
                or set(active_by_id) & set(excluded_by_id)
                or set(str(item) for item in excluded_ids) != set(excluded_by_id)
                or set(str(key) for key in selected_versions) != set(selected_ids)
            ):
                raise ContextCoreError("memory view revalidation selection coverage is invalid")
            self.state["memory_view_revalidation_ref"] = reference
            self.state["memory_view_revalidation_hash"] = content_hash
            self.state["memory_view_revalidation_input_seq"] = correction_seq
            self.state["memory_view_excluded_ids"] = tuple(sorted(excluded_by_id))
        elif event_type == "loop.operation-intent-recorded":
            self._active_operations.add(str(value["operation_id"]))
            if self.state["control_intent"] == ControlIntent.RUN.value:
                self.state["status"] = TaskStatus.WAITING_OPERATION.value
        elif event_type == "loop.operation-result-recorded":
            operation_id = str(value["operation_id"])
            self._settled_operation_statuses[operation_id] = str(value["effect_status"])
            self._active_operations.discard(operation_id)
            if bool(value.get("unknown_effect")):
                self._unknown_operations.add(operation_id)
            else:
                self._unknown_operations.discard(operation_id)
            if not self._active_operations:
                if self._unknown_operations:
                    self.state["status"] = TaskStatus.WAITING_OPERATION.value
                elif self.state["control_intent"] == ControlIntent.PAUSE.value:
                    self.state["status"] = TaskStatus.PAUSED.value
                elif self.state["control_intent"] == ControlIntent.CANCEL.value:
                    self.state["status"] = TaskStatus.CANCELLING.value
                else:
                    self.state["status"] = TaskStatus.RUNNABLE.value
        elif event_type == "loop.artifact-updated":
            self.state["artifact_version"] = int(value["artifact_version"])
            self.state["artifact_ref"] = str(value["artifact_ref"])
            self.state["acceptance_version"] = int(value["acceptance_version"])
        elif event_type == "loop.native-execution-wait-updated":
            reference, content_hash = value.get("waiting_ref"), value.get("waiting_hash")
            if not reference or not content_hash or str(reference) not in object_refs:
                raise ContextCoreError("native wait lacks its proof-bound document")
            document = self.store.read_json(str(reference), expected_hash=str(content_hash))
            status_by_state = {"WAITING": "WAITING_OPERATION", "BLOCKED": "RECOVERY_BLOCKED", "RESOLVED": "RUNNABLE"}
            wait_state = document.get("state")
            if (document.get("schema") != "SITINA_NATIVE_EXECUTION_WAIT_V1"
                    or document.get("task_id") != self.task_id
                    or document.get("blocker_id") != "native-execution" or not document.get("wait_id")
                    or wait_state not in status_by_state
                    or document.get("status") != status_by_state[wait_state]
                    or value.get("status") != status_by_state[wait_state]
                    or document.get("goal_version") != self.state["goal_version"]
                    or document.get("acceptance_version") != self.state["acceptance_version"]
                    or document.get("handled_input_seq") != self.state["handled_input_seq"]
                    or self.state["received_input_seq"] != self.state["handled_input_seq"]):
                raise ContextCoreError("native wait identity or task binding is invalid")
            if wait_state != "WAITING" and (self.state.get("native_execution_wait") or {}).get("wait_id") != document["wait_id"]:
                raise ContextCoreError("native result has no matching original wait")
            self.state["native_execution_wait"] = document
            self.state["waiting_ref"] = str(reference)
            self.state["status"] = status_by_state[wait_state]
        elif event_type in {"loop.task-waiting", "loop.task-context-blocked"}:
            self.state.pop("native_execution_wait", None)
            self.state["status"] = str(value["status"])
            self.state["waiting_ref"] = str(value["waiting_ref"])
            self.state["stop_report_ref"] = value.get("stop_report_ref")
        elif event_type in {"loop.task-paused", "loop.task-recovery-blocked"}:
            self.state["status"] = str(value["status"])
            self.state["stop_report_ref"] = str(value["stop_report_ref"])
        elif event_type == "loop.task-recovery-docked":
            self.state["run_instance_id"] = str(value["run_instance_id"])
            self.state["execution_epoch"] = int(value["execution_epoch"])
            self.state["status"] = str(value["status"])
        elif event_type in {
            "loop.task-recovery-discovered",
            "loop.task-recovery-claimed",
            "loop.task-recovery-ready",
            "loop.task-recovery-blocked",
        }:
            if value.get("run_instance_id") is not None:
                self.state["run_instance_id"] = str(value["run_instance_id"])
            if value.get("execution_epoch") is not None:
                self.state["execution_epoch"] = int(value["execution_epoch"])
            if value.get("status") is not None:
                self.state["status"] = str(value["status"])
            if value.get("control_intent") is not None:
                self.state["control_intent"] = str(value["control_intent"])
            if event_type == "loop.task-recovery-ready":
                from .model import bind_reviewer_continuation

                bind_reviewer_continuation(
                    self.state.get("provider_response_dispositions", {}),
                    self.state.get("resume_request_id"), self.state,
                )
                self.state["resume_request_id"] = None
                native_wait = self.state.get("native_execution_wait") or {}
                if (native_wait.get("goal_version") == self.state["goal_version"]
                        and native_wait.get("acceptance_version") == self.state["acceptance_version"]
                        and native_wait.get("handled_input_seq") == self.state["handled_input_seq"]
                        and self.state["received_input_seq"] == self.state["handled_input_seq"]):
                    self.state["status"] = native_wait["status"]
        elif event_type == "loop.task-resume-requested":
            self.state["resume_request_id"] = str(value["resume_request_id"])
            disposition = value.get("provider_response_disposition")
            if isinstance(disposition, Mapping) and isinstance(disposition.get("review_continuation"), Mapping):
                # The native reducer validated this receipt before it was committed.
                # Retain UNKNOWN in history; only its explicitly abandoned response
                # ceases to be an unresolved dispatch dependency.
                operation_id = disposition["request"]["operation_id"]
                self.state.setdefault("provider_response_dispositions", {})[operation_id] = dict(disposition)
                self._unknown_operations.discard(operation_id)
        elif event_type == "loop.task-terminated":
            self.state["status"] = str(value["terminal_status"])
        elif event_type == "loop.child-delegation-admitted":
            self.state.setdefault("child_delegations", {})[str(value.get("delegation_id"))] = {
                "status": "ADMITTED",
                "required": bool(value.get("required", True)),
                "unknown_effect": False,
                "parent_attempt_id": value.get("parent_attempt_id"),
                "physical_send_state": str(value.get("physical_send_state") or "NOT_STARTED"),
                "applicability": "CURRENT_PARENT_INPUT",
                "parent_binding": dict(value.get("parent_binding") or {}),
            }
        elif event_type == "loop.child-delegation-dispatch-started":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            ).update({"status": "RUNNING", "physical_send_state": value.get("physical_send_state")})
        elif event_type == "loop.child-delegation-checkpointed":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            )["checkpoint_ref"] = value.get("checkpoint_ref")
        elif event_type == "loop.child-delegation-result-recorded":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            ).update({
                "status": "RESULT_PERSISTED",
                "physical_send_state": value.get("physical_send_state"),
                "applicability": str(value.get("applicability") or "CURRENT_PARENT_INPUT"),
                "evidence_fingerprint": value.get("evidence_fingerprint"),
                "parent_binding": dict(value.get("parent_binding") or {}),
            })
        elif event_type == "loop.child-delegation-cancel-requested":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            )["status"] = "CANCEL_REQUESTED"
        elif event_type == "loop.child-delegation-settled":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            )["status"] = str(value.get("status") or "SETTLED")
        elif event_type == "loop.child-delegation-applicability-updated":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            ).update({
                "applicability": str(value.get("applicability") or "LATE_EVIDENCE_ONLY"),
                "applicability_ref": value.get("applicability_ref"),
            })
        elif event_type == "loop.child-delegation-recovery-blocked":
            self.state.setdefault("child_delegations", {}).setdefault(
                str(value.get("delegation_id")), {}
            ).update({
                "status": "RECOVERY_BLOCKED",
                "unknown_effect": bool(value.get("unknown_effect", True)),
                "recovery_ref": value.get("recovery_ref"),
                "blocker_id": value.get("blocker_id"),
            })

    def requirement_entries(self) -> tuple[HistoryIndexEntry, ...]:
        self.refresh()
        handled = int(self.state["handled_input_seq"])
        return tuple(
            item
            for item in self.entries
            if item.kind == "goal"
            or (
                item.kind == "input"
                and item.input_sequence is not None
                and item.input_sequence <= handled
                and item.input_kind in {InputKind.MESSAGE.value, InputKind.CORRECTION.value, InputKind.CLARIFICATION.value}
            )
        )


def _encode_cursor(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    checksum = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    raw = canonical_json_bytes({**payload, "checksum": checksum})
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(value: str, *, read: bool = False) -> Mapping[str, Any]:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode((value + padding).encode("ascii"))
        document = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise HistoryQueryError("history cursor encoding is invalid") from error
    if not isinstance(document, dict) or "checksum" not in document:
        raise HistoryQueryError("history cursor document is invalid")
    checksum = str(document.pop("checksum"))
    fields = ({"schema", "binding", "source_ref", "source_content_hash", "content_hash",
               "content_projection", "range_start", "range_end", "next_offset"} if read else
              {"schema", "binding", "frontier", "after_ordinal", "kind"})
    if set(document) != fields:
        raise HistoryQueryError("history cursor fields are invalid")
    expected_schema = "SITINA_LOOP_HISTORY_READ_CURSOR_V1" if read else "SITINA_LOOP_HISTORY_CURSOR_V1"
    if document.get("schema") != expected_schema:
        raise HistoryQueryError("history cursor schema is invalid")
    if checksum != hashlib.sha256(canonical_json_bytes(document)).hexdigest():
        raise HistoryQueryError("history cursor checksum is invalid")
    return document


class LoopHistoryQuery:
    MIN_PAGE_BYTES = HISTORY_MIN_PAGE_BYTES
    BODY_TARGET_BYTES = 2048
    BODY_MAX_BYTES = 4096
    TURN_RESPONSE_MAX_BYTES = 32768

    def __init__(self, index: LoopContextIndex, *, max_page_bytes: int):
        if max_page_bytes < self.MIN_PAGE_BYTES:
            raise HistoryQueryError(f"configured max_page_bytes must be at least {self.MIN_PAGE_BYTES}")
        self.index = index
        self.max_page_bytes = max_page_bytes
        # A disposable lookup over native receipts, never a second progress ledger.
        self._continuation_receipts: dict[str, HistoryIndexEntry] = {}
        self._continuation_frontier = 0

    @staticmethod
    def _continuation_ref(page: Mapping[str, Any], binding: Mapping[str, Any]) -> str:
        payload = {
            "binding": {key: binding[key] for key in
                        ("goal_version", "acceptance_version", "handled_input_seq")},
            "task_session_binding": page["task_session_binding"],
            "source_ref": page["source_ref"], "content_hash": page["content_hash"],
            "source_content_hash": page.get("source_content_hash", page["content_hash"]),
            "content_projection": page.get("content_projection"),
            "requested_range": page["requested_range"],
            "next_offset": page["read_range"]["end"],
            "scope": page["continuation_scope"],
        }
        return "hc1:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    @staticmethod
    def _continuation_arguments(page: Mapping[str, Any], max_bytes: int | None = None) -> dict[str, Any]:
        resolved = {
            "operation": "read", "source_ref": page["source_ref"],
            "offset": page["read_range"]["end"], "end_offset": page["requested_range"]["end"],
            **dict(page["continuation_scope"]),
            "read_cursor": _encode_cursor({
                "schema": "SITINA_LOOP_HISTORY_READ_CURSOR_V1",
                "binding": page["task_session_binding"], "source_ref": page["source_ref"],
                "source_content_hash": page.get("source_content_hash", page["content_hash"]),
                "content_hash": page["content_hash"], "content_projection": page.get("content_projection"),
                "range_start": page["requested_range"]["start"],
                "range_end": page["requested_range"]["end"], "next_offset": page["read_range"]["end"],
            }),
        }
        if max_bytes is not None:
            resolved["max_bytes"] = max_bytes
        return resolved

    @staticmethod
    def _canonical_read_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Normalize the unambiguous native continuation token before authorization.

        This only repairs the argument name. The committed receipt, current
        task/input binding, explicit constraints and source scope still have to
        validate before any bytes or read credit are returned.
        """
        normalized = dict(arguments)
        cursor = normalized.get("read_cursor")
        if (normalized.get("continuation_ref") is None
                and isinstance(cursor, str) and cursor.startswith("hc1:")):
            normalized["continuation_ref"] = normalized.pop("read_cursor")
        return normalized

    def resolve_read_arguments(
        self, arguments: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Mapping[str, Any] | None]:
        """Resolve only a committed successful page in the current task/input binding."""
        arguments = self._canonical_read_arguments(arguments)
        reference = arguments.get("continuation_ref")
        if reference is None:
            return dict(arguments), None
        max_bytes = arguments["max_bytes"]
        self._validate_max_bytes(max_bytes)

        resolved, error = self._resolve_committed_continuation(arguments)
        if error is not None:
            recovery: Any = "Use an exact next_read from current authenticated read progress; do not guess a reference."
            # A source locator copied into the cursor field is a common model
            # error. Explain it using only the current authenticated inventory;
            # never silently interpret it as a successful continuation/read.
            if isinstance(reference, str) and reference.startswith("history:"):
                self.index.refresh()
                if any(entry.source_ref == reference for entry in self.index.entries):
                    recovery = {
                        "reason": "A history: locator belongs in source_ref. continuation_ref must be the hc1: token copied from next_read.",
                        "read_credit": False,
                        "next_read": {"operation": "read", "source_ref": reference,
                                      "offset": 0, "view": "review", "max_bytes": max_bytes},
                        "instruction": "Prefer current history_read_progress.next_reads for an existing chain. This explicit source seek starts at zero and grants no credit until actually read.",
                    }
            try:
                page = self._status(error["status"], max_bytes, reason=error["reason"],
                                    read_credit=False, recovery=recovery)
            except HistoryQueryError:
                if not isinstance(recovery, Mapping):
                    raise
                # A long locator may not fit a minimum-size error page. Keep
                # the refusal bounded; current progress still has exact reads.
                page = self._status(error["status"], max_bytes, reason=error["reason"], read_credit=False,
                    recovery="history: belongs in source_ref; hc1: belongs in continuation_ref. Copy current history_read_progress.next_reads or the last page's next_read.")
            return dict(arguments), page
        resolved["max_bytes"] = max_bytes
        return resolved, None

    def _resolve_committed_continuation(
        self, arguments: Mapping[str, Any], *, refresh_index: bool = True,
        before_ordinal: int | None = None,
    ) -> tuple[dict[str, Any], Mapping[str, Any] | None]:
        """Resolve cursor identity without inventing or revalidating a read budget.

        Replay uses its stable index and only receipts committed before the read
        being examined. Resolution alone never grants source coverage.
        """
        arguments = self._canonical_read_arguments(arguments)
        reference = arguments.get("continuation_ref")
        if reference is None:
            return dict(arguments), None

        def reject(reason: str, status: str = "INVALID_CONTINUATION") -> tuple[dict[str, Any], Mapping[str, Any]]:
            return dict(arguments), {"status": status, "reason": reason}

        if (not isinstance(reference, str) or len(reference) != 68 or not reference.startswith("hc1:")
                or any(char not in "0123456789abcdef" for char in reference[4:])):
            return reject("continuation_ref is malformed")
        if refresh_index:
            self.index.refresh()
        for entry in self.index.entries:
            if before_ordinal is not None and entry.ordinal >= before_ordinal:
                break
            if entry.ordinal <= self._continuation_frontier:
                continue
            self._continuation_frontier = entry.ordinal
            if (entry.kind != "operation_result"
                    or self.index._operation_tool_names.get(entry.subject_id) != "sitina_history_query"):
                continue
            document = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            result = document.get("result")
            if (document.get("effect_status") != "SUCCEEDED" or not isinstance(result, Mapping)
                    or result.get("tool") != "sitina_history_query" or result.get("status") != "ok"):
                continue
            page = result.get("value")
            if (not isinstance(page, Mapping) or page.get("schema") != "SITINA_LOOP_HISTORY_READ_V1"
                    or page.get("status") != "OK" or page.get("range_complete") is not False
                    or not isinstance(page.get("next_read"), Mapping)
                    or not isinstance(page.get("continuation_scope"), Mapping)):
                continue
            bound = {"goal_version": document.get("bound_goal_version"),
                     "acceptance_version": document.get("bound_acceptance_version"),
                     "handled_input_seq": document.get("bound_input_seq")}
            token = self._continuation_ref(page, bound)
            if page["next_read"].get("continuation_ref") == token:
                self._continuation_receipts[token] = entry
        entry = self._continuation_receipts.get(reference)
        if entry is None or (before_ordinal is not None and entry.ordinal >= before_ordinal):
            return reject("continuation_ref has no committed successful receipt before this read in this task")
        document = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
        current = self.index.current_binding() if refresh_index else self.index.state
        if any(document.get(field) != current[key] for field, key in
               (("bound_goal_version", "goal_version"), ("bound_acceptance_version", "acceptance_version"),
                ("bound_input_seq", "handled_input_seq"))):
            return reject("continuation_ref belongs to a prior input or acceptance version", "STALE_CONTINUATION")
        page = document["result"]["value"]
        if page["task_session_binding"] != self.index.binding_hash or self._continuation_ref(page, current) != reference:
            return reject("continuation receipt binding changed", "STALE_CONTINUATION")
        resolved = self._continuation_arguments(page)
        for key in ("source_ref", "offset", "end_offset", "view", "read_cursor",
                    "review_question", "review_claim_source_ref", "review_claim_quote"):
            if key in arguments and arguments[key] != resolved.get(key):
                return reject("continuation_ref conflicts with explicit " + key)
        resolved["continuation_ref"] = reference
        return resolved, None

    def _validate_max_bytes(self, max_bytes: int) -> None:
        if max_bytes < self.MIN_PAGE_BYTES:
            raise HistoryQueryError(f"max_bytes must be at least {self.MIN_PAGE_BYTES}")
        if max_bytes > self.max_page_bytes:
            raise HistoryQueryError("max_bytes exceeds the configured history-query maximum")

    @staticmethod
    def _body_target(target_payload_bytes: int | None, *, read_budget: int | None = None) -> int:
        if read_budget is not None:
            target = read_budget if target_payload_bytes is None else target_payload_bytes
            if type(target) is not int or target < 1:
                raise HistoryQueryError("history payload target must be a positive integer")
            return min(target, read_budget)
        target = LoopHistoryQuery.BODY_TARGET_BYTES if target_payload_bytes is None else target_payload_bytes
        if type(target) is not int or target < 1:
            raise HistoryQueryError("history payload target must be a positive integer")
        return min(target, LoopHistoryQuery.BODY_MAX_BYTES)

    @staticmethod
    def _fixed_page(page: Mapping[str, Any]) -> Any:
        return lambda _target: dict(page)

    def list(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        kind: str | None = None,
        max_bytes: int = 4096,
        target_payload_bytes: int | None = None,
    ) -> Mapping[str, Any]:
        target = self._body_target(target_payload_bytes)
        return self._prepare_list(cursor=cursor, limit=limit, kind=kind, max_bytes=max_bytes)(target)

    def _prepare_list(
        self, *, cursor: str | None = None, limit: int = 50,
        kind: str | None = None, max_bytes: int = 4096,
    ) -> Any:
        self._validate_max_bytes(max_bytes)
        if not 1 <= limit <= 1_000:
            return self._fixed_page(self._status("INVALID_LIMIT", max_bytes, reason="limit must be between 1 and 1000"))
        self.index.refresh()
        if cursor:
            try:
                decoded = _decode_cursor(cursor)
            except HistoryQueryError as error:
                return self._fixed_page(self._status("INVALID_CURSOR", max_bytes, reason=str(error)))
            if decoded.get("binding") != self.index.binding_hash:
                return self._fixed_page(self._status("NOT_VISIBLE", max_bytes, reason="cursor belongs to another task/session"))
            if decoded.get("kind") != kind:
                return self._fixed_page(self._status("INVALID_CURSOR", max_bytes, reason="cursor filter changed"))
            try:
                frontier = int(decoded["frontier"])
                after = int(decoded["after_ordinal"])
            except (KeyError, TypeError, ValueError):
                return self._fixed_page(self._status("INVALID_CURSOR", max_bytes, reason="cursor fields are invalid"))
            if frontier < 1 or after < 0 or frontier > self.index.frontier:
                return self._fixed_page(self._status("INVALID_CURSOR", max_bytes, reason="cursor frontier is invalid"))
        else:
            frontier = self.index.frontier
            after = 0
        eligible = [
            item for item in self.index.entries
            if item.ordinal > after and item.event_position <= frontier and (kind is None or item.kind == kind)
        ]
        return lambda target: self._list_page(eligible, limit, frontier, after, kind, max_bytes, target)

    def _list_page(
        self, eligible: Sequence[HistoryIndexEntry], limit: int, frontier: int,
        after: int, kind: str | None, max_bytes: int, target_payload_bytes: int,
    ) -> Mapping[str, Any]:
        target = self._body_target(target_payload_bytes)
        first = [eligible[0].list_row()] if eligible else []
        first_body_bytes = len(canonical_json_bytes(first))
        # A complete index row is the minimum list body, not receipt_max_bytes.
        # The soft target may grow for that row, but never above the body cap.
        body_limit = min(self.BODY_MAX_BYTES, max(target, first_body_bytes))
        selected: list[Mapping[str, Any]] = []
        for item in eligible[:limit]:
            candidate = [*selected, item.list_row()]
            more = len(eligible) > len(candidate)
            document = self._list_document(candidate, frontier, item.ordinal if more else None, kind)
            if (len(canonical_json_bytes(candidate)) > body_limit
                    or len(canonical_json_bytes(document)) > max_bytes):
                break
            selected = candidate
        if eligible and not selected:
            minimum = len(canonical_json_bytes(self._list_document(first, frontier, eligible[0].ordinal, kind)))
            return self._status("PAGE_TOO_SMALL", max_bytes, reason="one history index row cannot fit", minimum_bytes=minimum)
        last = int(selected[-1]["ordinal"]) if selected else after
        more = len(eligible) > len(selected)
        document = self._list_document(selected, frontier, last if more else None, kind)
        if len(canonical_json_bytes(document)) > max_bytes:
            raise HistoryQueryError("history list envelope exceeds max_bytes")
        return document

    def _list_document(
        self,
        entries: Sequence[Mapping[str, Any]],
        frontier: int,
        next_ordinal: int | None,
        kind: str | None,
    ) -> dict[str, Any]:
        next_cursor = (
            _encode_cursor({
                "schema": "SITINA_LOOP_HISTORY_CURSOR_V1",
                "binding": self.index.binding_hash,
                "frontier": frontier,
                "after_ordinal": next_ordinal,
                "kind": kind,
            })
            if next_ordinal is not None
            else None
        )
        return self._with_response_bytes({
            "schema": "SITINA_LOOP_HISTORY_LIST_V1",
            "status": "OK",
            "task_session_binding": self.index.binding_hash,
            "frontier": frontier,
            "entries": list(entries),
            "returned_count": len(entries),
            "next_cursor": next_cursor,
            "has_more": next_cursor is not None,
            "auto_injected": False,
        })

    def read(
        self, *, source_ref: str | None = None, offset: int | None = None, max_bytes: int = 4096,
        end_offset: int | None = None, read_cursor: str | None = None,
        target_payload_bytes: int | None = None, view: str | None = None,
        continuation_ref: str | None = None,
    ) -> Mapping[str, Any]:
        target = self._body_target(target_payload_bytes, read_budget=max_bytes)
        arguments, error = self.resolve_read_arguments({"operation": "read", "max_bytes": max_bytes,
            **{key: value for key, value in {"source_ref": source_ref, "offset": offset,
                "end_offset": end_offset, "read_cursor": read_cursor, "view": view,
                "continuation_ref": continuation_ref}.items() if value is not None}})
        if error is not None:
            return error
        return self._prepare_read(
            source_ref=arguments.get("source_ref", ""), offset=arguments.get("offset", 0), max_bytes=max_bytes,
            end_offset=arguments.get("end_offset"), read_cursor=arguments.get("read_cursor"),
            view=arguments.get("view", "raw"), continued_from=arguments.get("continuation_ref"),
            native_navigation=arguments.get("continuation_ref") is not None,
        )(target)

    def _prepare_read(
        self, *, source_ref: str, offset: int = 0, max_bytes: int = 4096,
        end_offset: int | None = None, read_cursor: str | None = None,
        continuation_arguments: Mapping[str, Any] | None = None,
        include_navigation: bool = True,
        view: str = "raw",
        native_navigation: bool = False,
        continued_from: str | None = None,
    ) -> Any:
        self._validate_max_bytes(max_bytes)
        if view not in {"raw", "review"}:
            raise HistoryQueryError("history read view must be raw or review")
        self.index.refresh()
        parts = str(source_ref).split(":")
        if len(parts) != 4 or parts[0] != "history":
            return self._fixed_page(self._status("NOT_VISIBLE", max_bytes, reason="source ref is not task-scoped"))
        if parts[1] != self.index.binding_hash:
            return self._fixed_page(self._status("NOT_VISIBLE", max_bytes, reason="source ref belongs to another task/session"))
        try:
            ordinal = int(parts[2])
        except ValueError:
            return self._fixed_page(self._status(
                "MISSING", max_bytes, reason="source ref ordinal is invalid",
                reference_error="NOT_IN_COMMITTED_INDEX",
            ))
        entry = next((item for item in self.index.entries if item.ordinal == ordinal), None)
        if entry is None or entry.source_ref != source_ref:
            # This is a failed lookup in the freshly authenticated index, not
            # unavailable content for an indexed source. Keep that distinction
            # in the native receipt so completion can offer bounded correction.
            return self._fixed_page(self._status(
                "MISSING", max_bytes, reason="source ref is not in the committed task index",
                reference_error="NOT_IN_COMMITTED_INDEX",
            ))
        try:
            document = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            document, content_projection = self._history_safe_document(entry, document)
            capability_metadata = self._capability_public_metadata(document, content_projection)
            raw, content_projection = source_read_bytes(document, content_projection, view)
            projected_content_hash = hashlib.sha256(raw).hexdigest()
        except Exception as error:
            return self._fixed_page(self._status(
                "STALE_SOURCE", max_bytes,
                reason=f"{type(error).__name__}: indexed CAS content is unavailable or unverifiable",
                source_ref=source_ref, content_hash=entry.content_hash,
            ))
        content_hash = projected_content_hash if content_projection else entry.content_hash
        identity = {
            "source_ref": source_ref, "source_content_hash": entry.content_hash,
            "content_hash": content_hash, "content_projection": content_projection,
            "total_bytes": len(raw),
        }
        if continued_from is not None:
            # Version changes must not be misreported as a bad UTF-8 position
            # after a once-valid cursor is applied to a different projection.
            cursor_identity = _decode_cursor(read_cursor, read=True)
            if any(cursor_identity[key] != identity[key] for key in
                   ("source_ref", "source_content_hash", "content_hash", "content_projection")):
                return self._fixed_page(self._status(
                    "STALE_CONTINUATION", max_bytes,
                    reason="continuation source or readable projection version changed",
                    read_credit=False, **identity,
                ))

        def invalid_boundary(value: Any) -> Mapping[str, int]:
            bounded = min(len(raw), max(0, value)) if type(value) is int else 0
            lower, upper = bounded, bounded
            while lower > 0 and lower < len(raw) and raw[lower] & 0xC0 == 0x80:
                lower -= 1
            while upper < len(raw) and raw[upper] & 0xC0 == 0x80:
                upper += 1
            return {"at_or_before": lower, "at_or_after": upper}

        def boundary_ok(value: Any) -> bool:
            return (type(value) is int and 0 <= value <= len(raw)
                    and (value == len(raw) or raw[value] & 0xC0 != 0x80))

        if not boundary_ok(offset):
            return self._fixed_page(self._status(
                "INVALID_OFFSET", max_bytes, reason="offset is outside content or splits a UTF-8 code point",
                **identity, legal_offset_boundaries=invalid_boundary(offset),
            ))
        range_end = len(raw) if end_offset is None else end_offset
        if not boundary_ok(range_end) or range_end < offset:
            return self._fixed_page(self._status(
                "INVALID_RANGE", max_bytes, reason="end_offset must be a UTF-8 boundary at or after offset",
                **identity, legal_end_offset_boundaries=invalid_boundary(range_end),
            ))
        range_start = offset
        if read_cursor is not None:
            try:
                if not isinstance(read_cursor, str) or not read_cursor:
                    raise HistoryQueryError("read_cursor must be a nonempty string")
                cursor = _decode_cursor(read_cursor, read=True)
                expected = {
                    "binding": self.index.binding_hash, "source_ref": source_ref,
                    "source_content_hash": entry.content_hash, "content_hash": content_hash,
                    "content_projection": content_projection, "range_end": range_end,
                    "next_offset": offset,
                }
                if any(cursor[key] != value for key, value in expected.items()):
                    raise HistoryQueryError("read cursor source, version, range or next offset changed")
                range_start = cursor["range_start"]
                if (not boundary_ok(range_start) or range_start > offset
                        or type(cursor["range_end"]) is not int
                        or type(cursor["next_offset"]) is not int or offset >= range_end):
                    raise HistoryQueryError("read cursor range is invalid or already complete")
            except HistoryQueryError as error:
                return self._fixed_page(self._status(
                    "INVALID_READ_CURSOR", max_bytes, reason=str(error), **identity,
                ))
        # This closure is rendered again after the actual turn budget is
        # allocated. Its next_read must describe that final page, not a forecast.
        return lambda target: self._read_page(
            entry, raw, offset, max_bytes, content_projection=content_projection,
            projected_content_hash=projected_content_hash,
            capability_metadata=capability_metadata, target_payload_bytes=target,
            end_offset=range_end, range_start=range_start,
            read_mode="continue" if read_cursor is not None else "seek",
            continuation_arguments={**(continuation_arguments or {}), **({"view": view} if view != "raw" else {})},
            include_navigation=include_navigation,
            native_navigation=native_navigation, continued_from=continued_from,
        )

    @staticmethod
    def _history_safe_document(
        entry: HistoryIndexEntry,
        document: Any,
    ) -> tuple[Any, str | None]:
        """Project persisted Provider results onto an explicit public field set.

        Raw thinking remains in encrypted task state so it can be replayed in
        the next protocol request, but the model-accessible history tool must
        never turn that private field into readable/base64 tool output.
        """

        if entry.kind != "operation_result" or not isinstance(document, Mapping):
            return document, None
        result = document.get("result")
        if not isinstance(result, Mapping):
            return document, None

        # Extension consumer results are persisted with a private execution
        # binding and (for Plugin commands) the exact expected output.  Only
        # expose the verified business value and its stable method identity;
        # the original envelope/proof remains in the private CAS object above.
        effect_status = str(document.get("effect_status") or "")
        execution_binding = result.get("execution_binding")
        contract = execution_binding.get("method_contract") if isinstance(execution_binding, Mapping) else None
        capability_kind = str(contract.get("kind") or "") if isinstance(contract, Mapping) else ""
        capability_value = result.get("value")
        capability_ok = (
            effect_status == "SUCCEEDED"
            and str(result.get("status") or "") == "ok"
            and isinstance(execution_binding, Mapping)
            and str(execution_binding.get("method_schema") or "") == "SITINA_EXTENSION_TRIAL_METHOD_V1"
            and capability_kind in {"skill-resource-read", "plugin-command"}
        )
        if capability_ok and capability_kind == "plugin-command":
            expected_output = contract.get("expected_output") if isinstance(contract, Mapping) else None
            capability_ok = (
                expected_output is not None
                and capability_value == expected_output
                and str(result.get("program_status") or "") == "PASS"
            )
        if capability_ok and capability_kind == "skill-resource-read":
            expected = execution_binding.get("expected") if isinstance(execution_binding, Mapping) else None
            capability_ok = (
                isinstance(expected, Mapping)
                and isinstance(capability_value, Mapping)
                and capability_value.get("status") == "ok"
                and capability_value.get("path") == expected.get("relative_path")
                and capability_value.get("resource_sha256") == expected.get("sha256")
            )
        if capability_ok:
            value_hash = hashlib.sha256(canonical_json_bytes(capability_value)).hexdigest()
            binding = {
                key: execution_binding.get(key)
                for key in (
                    "candidate_id",
                    "snapshot_id",
                    "snapshot_hash",
                    "method_schema",
                    "method_version",
                    "method_id",
                    "handler",
                    "tool_name",
                )
                if execution_binding.get(key) is not None
            }
            source_key = hashlib.sha256(
                canonical_json_bytes({
                    "candidate_id": binding.get("candidate_id"),
                    "snapshot_id": binding.get("snapshot_id"),
                    "snapshot_hash": binding.get("snapshot_hash"),
                    "method_id": binding.get("method_id"),
                    "tool_name": binding.get("tool_name"),
                    "business_value_hash": value_hash,
                })
            ).hexdigest()
            projected = {
                "schema": "SITINA_LOOP_CAPABILITY_RESULT_PUBLIC_V1",
                "task_id": document.get("task_id"),
                # The model needs the committed operation identity to pass a
                # verified trial receipt forward.  It is deliberately not
                # part of capability_source_key or business progress.
                "operation_id": document.get("operation_id"),
                "effect_status": effect_status,
                "bound_goal_version": document.get("bound_goal_version"),
                "bound_acceptance_version": document.get("bound_acceptance_version"),
                "bound_input_seq": document.get("bound_input_seq"),
                "result": {
                    "tool": result.get("tool") or document.get("tool") or binding.get("tool_name"),
                    "status": "ok",
                    "value": capability_value,
                    "program_status": result.get("program_status"),
                    "capability_binding": binding,
                    "business_value_hash": value_hash,
                    "business_value_bytes": len(canonical_json_bytes(capability_value)),
                    "capability_source_key": source_key,
                },
            }
            return projected, "capability-result-public-fields-v1"

        private_failure_fields = ("private_provider_failure", "private_rejected_tool_response",
                                  "private_provider_request", "private_completion_evidence_request",
                                  "private_request_delivery")
        has_private_failure = any(key in result for key in private_failure_fields)
        if has_private_failure:
            result = {key: value for key, value in result.items() if key not in private_failure_fields}
            document = {**document, "result": result}
        if "reasoning_content" not in result:
            # Native tool envelopes may echo the same business value at the
            # root and under result. Keep the immutable receipt in CAS, but do
            # not make a reader consume that exact value twice. The page binds
            # both the original receipt hash and this public projection hash.
            if (
                not has_private_failure
                and document.get("schema") == "SITINA_LOOP_OPERATION_RESULT_V1"
                and effect_status == "SUCCEEDED"
                and document.get("status") == result.get("status") == "ok"
                and isinstance(document.get("tool"), str)
                and document.get("tool") == result.get("tool")
                and "value" in document and "value" in result
                and canonical_json_bytes(document["value"]) == canonical_json_bytes(result["value"])
            ):
                projected = {key: value for key, value in document.items() if key != "value"}
                projected["schema"] = "SITINA_LOOP_TOOL_RESULT_PUBLIC_V1"
                projected["source_schema"] = document["schema"]
                projected["value_alias"] = "/result/value"
                if len(canonical_json_bytes(projected)) < len(canonical_json_bytes(document)):
                    return projected, "tool-result-single-value-v1"
            return document, "provider-result-public-fields-v1" if has_private_failure else None

        public_document_fields = (
            "schema",
            "task_id",
            "operation_id",
            "effect_status",
            "bound_goal_version",
            "bound_acceptance_version",
            "bound_input_seq",
        )
        public_result_fields = ("turn", "stop_reason", "text", "tool_calls")
        public_metadata_fields = (
            "protocol",
            "protocol_fallback_used",
            "structured_feature_fallback",
            "physical_send_count",
            "physical_send_count_status",
            "uncertain_physical_send_attempt_count",
            "retry_count",
            "fallback_count",
            "sitina_provider_profile",
            "sitina_provider_model",
            "provider_request_id",
            "provider_response_id",
            "request_body_hash",
            "output_hash",
            "reasoning_content_present",
            "reasoning_content_bytes",
            "reasoning_content_hash",
            "truncated_tool_call_count",
            "truncated_tool_calls_hash",
            "tool_protocol_error",
            "token_usage",
            "tool_call_count",
            "sitina_request_admission",
            "sitina_admitted_body_hash",
            "effect_shadow",
        )
        projected = {
            key: document[key]
            for key in public_document_fields
            if key in document
        }
        projected_result = {
            key: result[key]
            for key in public_result_fields
            if key in result
        }
        metadata = result.get("metadata")
        if isinstance(metadata, Mapping):
            projected_result["metadata"] = {
                key: metadata[key]
                for key in public_metadata_fields
                if key in metadata
            }
        projected["result"] = projected_result
        return projected, "provider-result-public-fields-v1"

    @staticmethod
    def _capability_public_metadata(
        document: Mapping[str, Any], content_projection: str | None,
    ) -> Mapping[str, Any] | None:
        if content_projection != "capability-result-public-fields-v1":
            return None
        result = document.get("result")
        if not isinstance(result, Mapping):
            return None
        binding = result.get("capability_binding")
        if not isinstance(binding, Mapping):
            return None
        required = ("business_value_hash", "business_value_bytes", "capability_source_key")
        if any(key not in result for key in required):
            return None
        try:
            value_raw = canonical_json_bytes(result.get("value"))
            projected_raw = canonical_json_bytes(document)
            marker = b'"value":' + value_raw
            marker_offset = projected_raw.find(marker)
            if marker_offset < 0:
                return None
            business_start = marker_offset + len(b'"value":')
            business_end = business_start + len(value_raw)
        except Exception:
            return None
        return {
            "capability_source_key": str(result["capability_source_key"]),
            "capability_value_hash": str(result["business_value_hash"]),
            "capability_value_bytes": int(result["business_value_bytes"]),
            "capability_method_id": str(binding.get("method_id") or ""),
            # Internal response-construction hint; removed before emission.
            "_capability_business_range": [business_start, business_end],
        }

    def receipt_for_operation_result(
        self,
        operation_id: str,
        *,
        max_bytes: int = 4096,
    ) -> Mapping[str, Any]:
        self.index.refresh()
        entry = next(
            (
                item for item in reversed(self.index.entries)
                if item.kind == "operation_result" and item.subject_id == operation_id
            ),
            None,
        )
        if entry is None:
            return self._status("MISSING", max_bytes, reason="operation has no committed result reference")
        # This operation is committed, but its model projection is not a
        # committed history-query page. Offer an exact initial seek rather
        # than a short reference with no native page behind it.
        page = dict(self._prepare_read(
            source_ref=entry.source_ref, offset=0, max_bytes=max_bytes,
        )(self.BODY_TARGET_BYTES))
        if isinstance(page.get("next_read"), Mapping):
            page["next_read"] = {key: value for key, value in page["next_read"].items() if key != "read_cursor"}
            page = self._with_response_bytes(page)
        return page

    def _read_page(
        self,
        entry: HistoryIndexEntry,
        raw: bytes,
        offset: int,
        max_bytes: int,
        *,
        content_projection: str | None = None,
        projected_content_hash: str | None = None,
        capability_metadata: Mapping[str, Any] | None = None,
        target_payload_bytes: int | None = None,
        end_offset: int | None = None,
        range_start: int | None = None,
        read_mode: str = "seek",
        continuation_arguments: Mapping[str, Any] | None = None,
        include_navigation: bool = True,
        native_navigation: bool = False,
        continued_from: str | None = None,
    ) -> Mapping[str, Any]:
        range_end = len(raw) if end_offset is None else end_offset
        range_start = offset if range_start is None else range_start
        navigation_binding = self.index.current_binding() if native_navigation else None

        def utf8_prefix(limit: int) -> bytes:
            candidate = raw[offset:offset + limit]
            while candidate:
                try:
                    candidate.decode("utf-8")
                    return candidate
                except UnicodeDecodeError as error:
                    if error.reason != "unexpected end of data":
                        raise HistoryQueryError("canonical history content is not valid UTF-8") from error
                    candidate = candidate[:error.start]
            return b""

        def document_for(chunk: bytes, *, receipt_budget: int | None = None) -> dict[str, Any]:
            next_offset = offset + len(chunk)
            has_more = next_offset < len(raw)
            range_complete = next_offset == range_end
            next_read = None
            if include_navigation and not range_complete and not native_navigation:
                cursor = _encode_cursor({
                    "schema": "SITINA_LOOP_HISTORY_READ_CURSOR_V1",
                    "binding": self.index.binding_hash, "source_ref": entry.source_ref,
                    "source_content_hash": entry.content_hash,
                    "content_hash": projected_content_hash if content_projection else entry.content_hash,
                    "content_projection": content_projection, "range_start": range_start,
                    "range_end": range_end, "next_offset": next_offset,
                })
                next_read = {
                    "operation": "read", "source_ref": entry.source_ref,
                    "offset": next_offset, "end_offset": range_end,
                    "max_bytes": max_bytes if receipt_budget is None else receipt_budget, "read_cursor": cursor,
                    **dict(continuation_arguments or {}),
                }
            response_capability_metadata: dict[str, Any] = {}
            if capability_metadata is not None:
                response_capability_metadata = {
                    str(key): value
                    for key, value in capability_metadata.items()
                    if key != "_capability_business_range"
                }
                business_range = capability_metadata.get("_capability_business_range")
                if (
                    isinstance(business_range, (list, tuple))
                    and len(business_range) == 2
                    and type(business_range[0]) is int
                    and type(business_range[1]) is int
                    and 0 <= business_range[0] <= business_range[1] <= len(raw)
                ):
                    business_start, business_end = business_range
                    overlap_start = max(offset, business_start)
                    overlap_end = min(next_offset, business_end)
                    response_capability_metadata.update({
                        "capability_business_offset": max(0, overlap_start - business_start),
                        "capability_business_returned_bytes": max(0, overlap_end - overlap_start),
                        "capability_business_total_bytes": business_end - business_start,
                    })
            document = {
                "schema": "SITINA_LOOP_HISTORY_READ_V1",
                "status": "OK",
                "task_session_binding": self.index.binding_hash,
                "frontier": self.index.frontier,
                "source_ref": entry.source_ref,
                "kind": entry.kind,
                "content_hash": (
                    projected_content_hash
                    if content_projection is not None
                    else entry.content_hash
                ),
                **(
                    {
                        "content_projection": content_projection,
                        "content_hash_scope": "projected-readable-content",
                        "source_content_hash": entry.content_hash,
                    }
                    if content_projection is not None
                    else {}
                ),
                "content_encoding": "canonical-json-utf8+base64",
                "readable_encoding": "canonical-json-utf8",
                "total_bytes": len(raw),
                "offset": offset,
                **({
                    "read_mode": read_mode,
                    "read_range": {"start": offset, "end": next_offset, "coordinate": "utf-8-bytes"},
                    "requested_range": {"start": range_start, "end": range_end, "coordinate": "utf-8-bytes"},
                    "range_complete": range_complete, "next_read": next_read,
                } if include_navigation else {}),
                "returned_bytes": len(chunk),
                "data_base64": base64.b64encode(chunk).decode("ascii"),
                "readable_text": chunk.decode("utf-8"),
                "next_offset": next_offset if has_more else None,
                "has_more": has_more,
                "query": {"operation": "read", "source_ref": entry.source_ref,
                          **({"continuation_ref": continued_from, "offset": offset}
                             if continued_from is not None else {})},
                **(
                    {
                        **response_capability_metadata,
                        "capability_operation_id": entry.subject_id,
                    }
                    if capability_metadata is not None
                    else {}
                ),
            }
            if native_navigation and include_navigation:
                document["continuation_scope"] = {"view": "raw", **dict(continuation_arguments or {})}
                if not range_complete:
                    document["next_read"] = {
                        "operation": "read", "continuation_ref": self._continuation_ref(document, navigation_binding),
                        "max_bytes": max_bytes if receipt_budget is None else receipt_budget,
                    }
            return self._with_response_bytes(document)

        def minimum_budget(chunk: bytes) -> int:
            # next_read carries its own budget; changing its digit count must
            # not make the advertised minimum one byte too small.
            budget = len(canonical_json_bytes(document_for(chunk)))
            for _attempt in range(8):
                needed = len(canonical_json_bytes(document_for(chunk, receipt_budget=budget)))
                if needed == budget:
                    return needed
                budget = needed
            raise HistoryQueryError("history minimum byte size did not converge")

        remaining = range_end - offset
        empty_size = minimum_budget(b"")
        if remaining == 0 and empty_size > max_bytes:
            return self._status("PAGE_TOO_SMALL", max_bytes, reason="empty range receipt cannot fit", minimum_bytes=empty_size)
        first_width = 1
        while first_width <= min(4, remaining) and not utf8_prefix(first_width):
            first_width += 1
        body_limit = max(self._body_target(target_payload_bytes, read_budget=max_bytes), min(first_width, remaining))
        low, high = 0, min(remaining, body_limit)
        selected = b""
        while low < high:
            middle = (low + high + 1) // 2
            candidate = utf8_prefix(middle)
            if len(canonical_json_bytes(document_for(candidate))) <= max_bytes:
                low = middle
                if len(candidate) > len(selected):
                    selected = candidate
            else:
                high = middle - 1
        candidate = utf8_prefix(low)
        if len(candidate) > len(selected) and len(canonical_json_bytes(document_for(candidate))) <= max_bytes:
            selected = candidate
        if remaining and not selected:
            first_width = 1
            while first_width <= min(4, remaining) and not utf8_prefix(first_width):
                first_width += 1
            first = utf8_prefix(first_width)
            minimum = minimum_budget(first)
            return self._status("PAGE_TOO_SMALL", max_bytes, reason="one UTF-8 code point cannot fit", minimum_bytes=minimum)
        result = document_for(selected)
        if len(canonical_json_bytes(result)) > max_bytes:
            raise HistoryQueryError("history read envelope exceeds max_bytes")
        if offset + len(selected) < range_end and not selected:
            raise HistoryQueryError("history content cursor did not advance")
        return result

    def _status(self, status: str, max_bytes: int, **details: Any) -> Mapping[str, Any]:
        self._validate_max_bytes(max_bytes)
        document = self._with_response_bytes({
            "schema": "SITINA_LOOP_HISTORY_STATUS_V1",
            "status": status,
            "task_session_binding": self.index.binding_hash,
            **details,
        })
        if len(canonical_json_bytes(document)) > max_bytes:
            raise HistoryQueryError("history status envelope exceeds max_bytes")
        return document

    @staticmethod
    def _with_response_bytes(value: Mapping[str, Any]) -> dict[str, Any]:
        document = {**dict(value), "response_bytes": 0}
        for _attempt in range(8):
            size = len(canonical_json_bytes(document))
            if document["response_bytes"] == size:
                return document
            document["response_bytes"] = size
        raise HistoryQueryError("history response byte size did not converge")


@dataclass(frozen=True)
class RequirementCoverageEntry:
    source_ref: str
    content_hash: str
    text_hash: str
    label: str
    text: str

    def manifest_row(self) -> dict[str, str]:
        return {
            "source_ref": self.source_ref,
            "content_hash": self.content_hash,
            "text_hash": self.text_hash,
            "label": self.label,
            "coverage": "verbatim",
        }


@dataclass(frozen=True)
class TaskContextProjection:
    binding: Mapping[str, Any]
    task_id: str
    session_id: str
    task_kind: str
    status: str
    control_intent: str
    required_outcome_ids: tuple[str, ...]
    requirements: tuple[RequirementCoverageEntry, ...]
    current_blocker: Mapping[str, Any] | None
    open_obligations: tuple[Mapping[str, Any], ...]
    recent_attempts: tuple[Mapping[str, Any], ...]
    eliminated_method_index: Mapping[str, Any]
    ready_for_request: bool
    coverage_issues: tuple[str, ...]
    history_directory: tuple[Mapping[str, Any], ...]
    history_query_wiring_status: str
    coverage_manifest_hash: str
    serialized: bytes
    unresolved_operations: tuple[Mapping[str, Any], ...] = ()

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "schema": "SITINA_LOOP_TASK_CONTEXT_PROJECTION_V1",
            "binding": dict(self.binding),
            "task_id": self.task_id,
            "session_id": self.session_id,
            "task_kind": self.task_kind,
            "status": self.status,
            "control_intent": self.control_intent,
            "required_outcome_ids": list(self.required_outcome_ids),
            "requirement_coverage": {
                "mode": "verbatim-current-user-input-v1",
                "semantic_requirement_compaction_available": False,
                "manifest_hash": self.coverage_manifest_hash,
                "entries": [item.manifest_row() for item in self.requirements],
            },
            "current_requirements": [
                {"label": item.label, "source_ref": item.source_ref, "text": item.text}
                for item in self.requirements
            ],
            "current_blocker": dict(self.current_blocker) if self.current_blocker is not None else None,
            "open_obligations": [dict(item) for item in self.open_obligations],
            "unresolved_operations": [dict(item) for item in self.unresolved_operations],
            "recent_attempts": [dict(item) for item in self.recent_attempts],
            "eliminated_method_index": dict(self.eliminated_method_index),
            "ready_for_request": self.ready_for_request,
            "coverage_issues": list(self.coverage_issues),
            "history_directory": [dict(item) for item in self.history_directory],
            "history_query_available": True,
            "history_query_wiring_status": self.history_query_wiring_status,
        }


@dataclass(frozen=True)
class CoverageVerification:
    verified: bool
    reasons: tuple[str, ...]


class TaskContextProjector:
    def __init__(self, index: LoopContextIndex, *, history_query_connected: bool = False):
        self.index = index
        self.history_query_wiring_status = (
            "CONNECTED_READ_ONLY_TOOL" if history_query_connected else "CORE_ONLY_NOT_IN_TOOL_CATALOG"
        )

    def build(
        self,
        *,
        max_bytes: int,
        max_history_rows: int = 50,
        max_recent_attempts: int = 4,
    ) -> TaskContextProjection:
        if max_bytes < 1 or max_history_rows < 0 or max_recent_attempts < 0:
            raise ContextCoreError("task context projection limits are invalid")
        self.index.refresh()
        before = self.index.current_binding()
        required_index = self.index.requirement_entries()
        internal_to_handle = {item.internal_cas_ref: item.source_ref for item in self.index.entries}
        unresolved_operations = self.index.unresolved_operation_facts()
        blocker: Mapping[str, Any] | None = None
        coverage_issues: list[str] = []
        blocker_source_ref = self.index.state.get("waiting_source_ref")
        blocker_internal_ref = self.index.state.get("waiting_ref")
        blocker_is_current = self.index.state.get("status") in {
            TaskStatus.CONTEXT_BLOCKED.value,
            TaskStatus.STALLED.value,
            TaskStatus.WAITING_INPUT.value,
        }
        if blocker_is_current and isinstance(blocker_source_ref, str) and isinstance(blocker_internal_ref, str):
            blocker_entry = next(
                (item for item in self.index.entries if item.source_ref == blocker_source_ref),
                None,
            )
            if blocker_entry is None:
                raise ContextCoverageBlocked("current blocker has no committed history entry", (blocker_source_ref,))
            try:
                blocker_document = self.index.store.read_json(
                    blocker_internal_ref, expected_hash=blocker_entry.content_hash
                )
            except Exception as error:
                raise ContextCoverageBlocked(
                    f"current blocker is unavailable or unverifiable: {type(error).__name__}",
                    (blocker_source_ref,),
                ) from error
            raw_evidence = tuple(str(item) for item in blocker_document.get("evidence_refs", ()))
            evidence_sources: list[dict[str, Any]] = []
            for evidence_ref in raw_evidence:
                handle = internal_to_handle.get(evidence_ref)
                if handle is None:
                    evidence_sources.append({
                        "source_ref": None,
                        "verification_status": "MISSING_REFERENCE",
                    })
                    coverage_issues.append("current blocker evidence is not resolved in committed task history")
                    continue
                evidence_entry = next(item for item in self.index.entries if item.source_ref == handle)
                try:
                    self.index.store.read_json(
                        evidence_entry.internal_cas_ref,
                        expected_hash=evidence_entry.content_hash,
                    )
                except Exception:
                    verification_status = "STALE"
                    coverage_issues.append("current blocker evidence is stale or unverifiable")
                else:
                    verification_status = "VERIFIED"
                evidence_sources.append({
                    "source_ref": handle,
                    "content_hash": evidence_entry.content_hash,
                    "verification_status": verification_status,
                })
            statuses = {str(item["verification_status"]) for item in evidence_sources}
            if not evidence_sources:
                aggregate_status = "NOT_REQUIRED"
            elif statuses == {"VERIFIED"}:
                aggregate_status = "VERIFIED"
            elif "STALE" in statuses:
                aggregate_status = "STALE"
            else:
                aggregate_status = "MISSING_REFERENCE"
            blocker = {
                "blocker_id": str(blocker_document.get("blocker_id") or "context-blocked"),
                "reason": str(blocker_document.get("reason") or ""),
                "source_ref": blocker_source_ref,
                "evidence_sources": evidence_sources,
                "evidence_ref_count": len(raw_evidence),
                "reference_resolution_complete": all(
                    item["verification_status"] != "MISSING_REFERENCE" for item in evidence_sources
                ),
                "evidence_verification_status": aggregate_status,
            }
        open_obligations = tuple(
            {
                "outcome_id": outcome_id,
                "status": "OPEN_OR_UNVERIFIED",
                "current_acceptance_reduction_connected": False,
            }
            for outcome_id in self.index.state["required_outcome_ids"]
        )
        all_attempt_entries = [item for item in self.index.entries if item.kind == "attempt"]
        recent_attempt_entries = all_attempt_entries[-max_recent_attempts:] if max_recent_attempts else []
        recent_attempts = tuple(item.list_row() for item in recent_attempt_entries)
        eliminated_method_index = {
            "classification_status": "NOT_CLASSIFIED",
            "methods": [],
            "recent_attempt_source_refs": [item.source_ref for item in recent_attempt_entries],
            "general_semantic_progress_classification_connected": False,
        }
        pinned_only = TaskContextProjection(
            before,
            self.index.task_id,
            str(self.index.state["session_id"]),
            str(self.index.state["task_kind"]),
            str(self.index.state["status"]),
            str(self.index.state["control_intent"]),
            tuple(self.index.state["required_outcome_ids"]),
            (),
            blocker,
            open_obligations,
            recent_attempts,
            eliminated_method_index,
            not coverage_issues,
            tuple(coverage_issues),
            (),
            self.history_query_wiring_status,
            "0" * 64,
            b"",
            unresolved_operations=unresolved_operations,
        )
        if len(canonical_json_bytes(pinned_only.as_dict())) > max_bytes:
            affected = (str(blocker_source_ref),) if blocker is not None else tuple(
                item.source_ref for item in required_index
            )
            raise ContextCoverageBlocked("pinned current task facts cannot fit the projection", affected)
        requirements: list[RequirementCoverageEntry] = []
        for item in required_index:
            try:
                document = self.index.store.read_json(item.internal_cas_ref, expected_hash=item.content_hash)
            except Exception as error:
                raise ContextCoverageBlocked(
                    f"required source is unavailable or unverifiable: {type(error).__name__}",
                    (item.source_ref,),
                ) from error
            key = "goal" if item.kind == "goal" else "body"
            text = document.get(key)
            if not isinstance(text, str):
                raise ContextCoverageBlocked("required user source does not contain canonical text", (item.source_ref,))
            label = "original-goal" if item.kind == "goal" else f"{item.input_kind.lower()}-{item.input_sequence}"
            requirements.append(
                RequirementCoverageEntry(
                    item.source_ref,
                    item.content_hash,
                    hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    label,
                    text,
                )
            )
            partial = TaskContextProjection(
                before,
                self.index.task_id,
                str(self.index.state["session_id"]),
                str(self.index.state["task_kind"]),
                str(self.index.state["status"]),
                str(self.index.state["control_intent"]),
                tuple(self.index.state["required_outcome_ids"]),
                tuple(requirements),
                blocker,
                open_obligations,
                recent_attempts,
                eliminated_method_index,
                not coverage_issues,
                tuple(coverage_issues),
                (),
                self.history_query_wiring_status,
                "0" * 64,
                b"",
                unresolved_operations=unresolved_operations,
            )
            if len(canonical_json_bytes(partial.as_dict())) > max_bytes:
                raise ContextCoverageBlocked(
                    "current user requirements do not fit verbatim; semantic requirement compaction is not implemented",
                    tuple(value.source_ref for value in required_index),
                )
        self.index.refresh()
        after = self.index.current_binding()
        if before != after:
            raise StaleContextProjection("task binding changed while current requirements were read")
        manifest_document = {
            "schema": "SITINA_LOOP_REQUIREMENT_COVERAGE_MANIFEST_V1",
            "binding": before,
            "mode": "verbatim-current-user-input-v1",
            "entries": [item.manifest_row() for item in requirements],
        }
        manifest_hash = hashlib.sha256(canonical_json_bytes(manifest_document)).hexdigest()

        def make(rows: Sequence[Mapping[str, Any]]) -> TaskContextProjection:
            provisional = TaskContextProjection(
                before,
                self.index.task_id,
                str(self.index.state["session_id"]),
                str(self.index.state["task_kind"]),
                str(self.index.state["status"]),
                str(self.index.state["control_intent"]),
                tuple(self.index.state["required_outcome_ids"]),
                tuple(requirements),
                blocker,
                open_obligations,
                recent_attempts,
                eliminated_method_index,
                not coverage_issues,
                tuple(coverage_issues),
                tuple(rows),
                self.history_query_wiring_status,
                manifest_hash,
                b"",
                unresolved_operations=unresolved_operations,
            )
            raw = canonical_json_bytes(provisional.as_dict())
            return TaskContextProjection(
                provisional.binding,
                provisional.task_id,
                provisional.session_id,
                provisional.task_kind,
                provisional.status,
                provisional.control_intent,
                provisional.required_outcome_ids,
                provisional.requirements,
                provisional.current_blocker,
                provisional.open_obligations,
                provisional.recent_attempts,
                provisional.eliminated_method_index,
                provisional.ready_for_request,
                provisional.coverage_issues,
                provisional.history_directory,
                provisional.history_query_wiring_status,
                provisional.coverage_manifest_hash,
                raw,
                unresolved_operations=unresolved_operations,
            )

        base = make(())
        if len(base.serialized) > max_bytes:
            raise ContextCoverageBlocked(
                "current user requirements do not fit verbatim; semantic requirement compaction is not implemented",
                tuple(item.source_ref for item in requirements),
            )
        required_refs = {item.source_ref for item in requirements}
        rows: list[Mapping[str, Any]] = []
        for item in reversed(self.index.entries):
            if item.source_ref in required_refs or len(rows) >= max_history_rows:
                continue
            row = _task_history_navigation_row(item, self.index._operation_tool_names)
            if row is None:
                continue
            candidate_rows = [row, *rows]
            candidate = make(candidate_rows)
            if len(candidate.serialized) <= max_bytes:
                rows = candidate_rows
        return make(rows)


class RequirementCoverageVerifier:
    @staticmethod
    def verify(index: LoopContextIndex, projection: TaskContextProjection) -> CoverageVerification:
        reasons: list[str] = []
        index.refresh()
        if projection.unresolved_operations != index.unresolved_operation_facts():
            reasons.append("unresolved operation responsibility is missing or stale in the projection")
        if projection.binding != index.current_binding():
            reasons.append("task binding changed after projection")
        required = index.requirement_entries()
        expected_refs = tuple(item.source_ref for item in required)
        actual_refs = tuple(item.source_ref for item in projection.requirements)
        if actual_refs != expected_refs:
            reasons.append("coverage manifest does not exactly enumerate current user sources")
        for coverage, entry in zip(projection.requirements, required):
            try:
                document = index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            except Exception as error:
                reasons.append(f"required source cannot be verified: {type(error).__name__}")
                continue
            key = "goal" if entry.kind == "goal" else "body"
            text = document.get(key)
            if not isinstance(text, str):
                reasons.append("required source text is missing")
                continue
            if coverage.content_hash != entry.content_hash:
                reasons.append("required source content hash changed")
            if coverage.text != text or coverage.text_hash != hashlib.sha256(text.encode("utf-8")).hexdigest():
                reasons.append("required source is not represented verbatim")
        manifest_document = {
            "schema": "SITINA_LOOP_REQUIREMENT_COVERAGE_MANIFEST_V1",
            "binding": dict(projection.binding),
            "mode": "verbatim-current-user-input-v1",
            "entries": [item.manifest_row() for item in projection.requirements],
        }
        if projection.coverage_manifest_hash != hashlib.sha256(canonical_json_bytes(manifest_document)).hexdigest():
            reasons.append("coverage manifest hash is invalid")
        if projection.serialized != canonical_json_bytes(projection.as_dict()):
            reasons.append("serialized projection differs from its document")
        if projection.current_blocker is not None:
            blocker_ref = projection.current_blocker.get("source_ref")
            blocker_entry = next(
                (item for item in index.entries if item.source_ref == blocker_ref),
                None,
            )
            if blocker_entry is None:
                reasons.append("current blocker source is not in committed task history")
            else:
                try:
                    blocker_document = index.store.read_json(
                        blocker_entry.internal_cas_ref,
                        expected_hash=blocker_entry.content_hash,
                    )
                except Exception:
                    reasons.append("current blocker source is stale or unverifiable")
                else:
                    if (
                        str(blocker_document.get("blocker_id") or "context-blocked")
                        != projection.current_blocker.get("blocker_id")
                        or str(blocker_document.get("reason") or "")
                        != projection.current_blocker.get("reason")
                    ):
                        reasons.append("current blocker projection differs from its committed source")
            for evidence in projection.current_blocker.get("evidence_sources", ()):
                if not isinstance(evidence, Mapping) or evidence.get("verification_status") != "VERIFIED":
                    continue
                evidence_ref = evidence.get("source_ref")
                evidence_entry = next(
                    (item for item in index.entries if item.source_ref == evidence_ref),
                    None,
                )
                if evidence_entry is None:
                    reasons.append("current blocker evidence is no longer in committed task history")
                    continue
                try:
                    index.store.read_json(
                        evidence_entry.internal_cas_ref,
                        expected_hash=evidence_entry.content_hash,
                    )
                except Exception:
                    reasons.append("current blocker evidence became stale after projection")
        reasons.extend(
            issue for issue in projection.coverage_issues
            if issue not in reasons
        )
        if projection.ready_for_request != (not projection.coverage_issues):
            reasons.append("projection request-readiness contradicts its coverage issues")
        index.refresh()
        if projection.binding != index.current_binding() and "task binding changed after projection" not in reasons:
            reasons.append("task binding changed after projection")
        return CoverageVerification(not reasons, tuple(reasons))


@dataclass(frozen=True)
class PreparedProviderCall:
    system_prompt: str
    messages: tuple[Mapping[str, Any], ...]
    tools: tuple[Mapping[str, Any], ...]
    projection: TaskContextProjection
    protocol_groups: ProtocolGroupSelection
    rendered_request: RenderedProviderRequest
    admission: RequestAdmission
    product_prepared_evidence: tuple[Mapping[str, Any], ...] = ()
    material_profile: Mapping[str, Any] | None = None


class LoopRequestAssembler:
    """One task-bound request path shared by main and reviewer runtimes."""

    def __init__(
        self,
        index: LoopContextIndex,
        registry: ModelCapacityRegistry,
        *,
        identity: ProviderContextIdentity,
        role: str,
        execution_context: Mapping[str, Any] | None = None,
        projection_max_bytes: int = 128 * 1024,
        protocol_groups_max_bytes: int = 64 * 1024,
        receipt_max_bytes: int = 4096,
        qualified_counter: QualifiedWireRequestCounter | None = None,
        scope_attempt_id: str | None = None,
        scope_attempt_ids: Sequence[str] | None = None,
        scope_execution_owner: str | None = None,
        snapshot_lock: Any | None = None,
        activity_callback: Any | None = None,
    ) -> None:
        if not role.strip():
            raise ContextCoreError("Loop request role is required")
        if min(projection_max_bytes, protocol_groups_max_bytes, receipt_max_bytes) < 1:
            raise ContextCoreError("Loop request limits must be positive")
        self.index = index
        self.snapshot_lock = snapshot_lock
        self.activity_callback = activity_callback
        self._compaction_active = False
        self.scope_execution_owner = scope_execution_owner
        self.role = role
        self.execution_context = dict(execution_context or {})
        self.projection_max_bytes = projection_max_bytes
        self.protocol_groups_max_bytes = protocol_groups_max_bytes
        self.identity = identity
        self.planner = ProviderRequestPlanner(registry, qualified_counter=qualified_counter)
        self.policy = registry.resolve(identity)
        query_limit = (
            self.policy.history_query_max_bytes
            if self.policy is not None
            else HISTORY_MIN_PAGE_BYTES
        )
        self.receipt_max_bytes = min(receipt_max_bytes, query_limit)
        if self.receipt_max_bytes < HISTORY_MIN_PAGE_BYTES:
            raise ContextPolicyError("receipt maximum is below the bounded history envelope minimum")
        self.history_query = LoopHistoryQuery(index, max_page_bytes=query_limit)
        self._history_turn_pages: dict[bytes, Mapping[str, Any]] = {}
        self._text_measurements: dict[str, Mapping[str, Any]] = {}
        self.scope_attempt_ids = frozenset(
            str(item) for item in (scope_attempt_ids or (() if scope_attempt_id is None else (scope_attempt_id,)))
        )
        self._groups: list[ProtocolMessageGroup] = []
        self._file_read_sources: dict[str, dict[str, Any]] = {}
        self._history_read_sources: dict[str, dict[str, Any]] = {}
        self._assistant_notes: dict[str, dict[str, Any]] = {}
        self.compaction_count = 0
        self.compaction_receipts: list[Mapping[str, Any]] = []
        self._last_compaction_signature: str | None = None
        self.admission_receipts: list[Mapping[str, Any]] = []
        self.last_prepared: PreparedProviderCall | None = None
        self._runtime_feedback: Mapping[str, Any] | None = None
        self.review_recipient_attempt_id: str | None = None
        self._review_scope_enforced = (role == "reviewer" and
                                      self.execution_context.get("phase") == "independent_read_only_review")
        if self._review_scope_enforced:
            recipient = scope_attempt_id
            if recipient is None:
                self.index.refresh()
                candidates = [entry.subject_id for entry in self.index.entries
                              if entry.kind == "attempt_plan" and entry.subject_id in self.scope_attempt_ids]
                recipient = candidates[-1] if candidates else ""
            self.bind_review_recipient(recipient)

    def bind_review_recipient(self, attempt_id: str) -> None:
        """Use the same native reader for protocol, offered material and read credit."""
        if not self._review_scope_enforced:
            return
        self.index.refresh()
        self.review_recipient_attempt_id = attempt_id
        progress = self.reviewer_read_progress((), **self.execution_context["review_read_authority"])
        self.scope_attempt_ids = frozenset(progress["recipient_attempt_ids"])

    def reviewer_read_progress(self, required_source_refs: Sequence[str], **kwargs: Any) -> Mapping[str, Any]:
        return self.index.reviewer_read_progress(
            required_source_refs, recipient_attempt_id=self.review_recipient_attempt_id or "", **kwargs,
        )

    @property
    def history_query_max_bytes(self) -> int:
        return self.history_query.max_page_bytes

    def begin_tool_turn(
        self, *, history_call_count: int, assistant_message: Mapping[str, Any] | None = None,
    ) -> None:
        """Size the real atomic group before its concurrent history workers run.

        Native responses and the complete model-facing group are measured
        separately. Sources are loaded once; allocation renders real UTF-8
        pages from those verified snapshots, never guessed receipt minima.
        """
        if type(history_call_count) is not int or history_call_count < 0:
            raise ContextCoreError("history call count must be a nonnegative integer")
        self._history_turn_pages = {}
        if not history_call_count or assistant_message is None:
            return
        allocation_binding = dict(self.index.current_binding())
        assistant = dict(assistant_message)
        calls = assistant.get("tool_calls")
        if not isinstance(calls, list) or any(not isinstance(call, Mapping) for call in calls):
            raise ContextCoreError("history allocation requires the actual assistant tool calls")
        history_calls = [call for call in calls if call.get("name") == "sitina_history_query"]
        if len(history_calls) != history_call_count:
            raise ContextCoreError("history allocation call count does not match the actual group")
        if self.policy is not None and self.policy.thinking_mode == "enabled":
            assistant["reasoning_content"] = assistant.get("reasoning_content")
        else:
            assistant.pop("reasoning_content", None)
        response_pool = min(LoopHistoryQuery.TURN_RESPONSE_MAX_BYTES, self.protocol_groups_max_bytes)
        renderers: dict[bytes, Any] = {}
        for call in history_calls:
            arguments = call.get("arguments")
            if not isinstance(arguments, Mapping):
                raise HistoryQueryError("history arguments must be an object")
            key = canonical_json_bytes(arguments)
            if key not in renderers:
                try:
                    renderers[key] = self._history_query_renderer(arguments)
                except HistoryQueryError as error:
                    # Missing/invalid operation names and missing read locators
                    # are request rejections that the caller can correct.
                    # Storage and capacity failures stay fail-closed.
                    operation = arguments.get("operation")
                    source_ref = arguments.get("source_ref")
                    invalid_operation = operation not in ("list", "read", "measure_text")
                    missing_source = operation == "read" and not (type(source_ref) is str and source_ref)
                    if not (invalid_operation or missing_source):
                        raise
                    max_bytes = arguments.get("max_bytes")
                    if type(max_bytes) is not int:
                        raise
                    self.history_query._validate_max_bytes(max_bytes)
                    error_page = {
                        "status": "INVALID_REQUEST",
                        "error_type": "HistoryQueryError",
                        "reason": redact_text(str(error)),
                    }
                    renderers[key] = lambda _target, page=error_page: page

        def pages_for(target: int) -> dict[bytes, Mapping[str, Any]]:
            return {key: render(target) for key, render in renderers.items()}

        def sizes(pages: Mapping[bytes, Mapping[str, Any]]) -> tuple[int, int, list[Mapping[str, Any]]]:
            response_bytes = 0
            group: list[Mapping[str, Any]] = [assistant]
            for call in calls:
                history = call.get("name") == "sitina_history_query"
                value: Mapping[str, Any] = {}
                if history:
                    page = pages[canonical_json_bytes(call["arguments"])]
                    response_bytes += len(canonical_json_bytes(page))
                    value = self.model_history_page(page)
                group.append({
                    "role": "tool", "tool_call_id": call["id"], "name": call["name"],
                    "content": PromptIsolationPolicy().wrap_tool_result(
                        tool_name=str(call["name"]), status="ok", value=value,
                    ),
                    "is_error": False,
                })
            return response_bytes, len(_wire_json_bytes(group)), group

        def fits(pages: Mapping[bytes, Mapping[str, Any]]) -> bool:
            response_bytes, group_bytes, group = sizes(pages)
            # Required thinking messages stay intact in the full forecast below;
            # the response pool bounds actual tool messages, not that assistant.
            pool_message_bytes = (
                len(_wire_json_bytes(group[1:]))
                if self.policy is not None and self.policy.thinking_mode == "enabled"
                else group_bytes
            )
            if response_bytes > response_pool or pool_message_bytes > response_pool:
                return False
            if self.last_prepared is None or self.policy is None:
                return True
            # The next context also gains source cursors and possibly original
            # file facts. Measure those on detached dictionaries; this forecast
            # is never published as a completed read or an accepted result.
            planning = object.__new__(type(self))
            planning.__dict__.update(self.__dict__)
            planning._file_read_sources = json.loads(canonical_json_bytes(self._file_read_sources))
            planning._history_read_sources = json.loads(canonical_json_bytes(self._history_read_sources))
            binding = allocation_binding
            for page in pages.values():
                planning._project_history_source(page, binding=binding)
            projection = TaskContextProjector(
                self.index, history_query_connected=True,
            ).build(
                max_bytes=max(self.projection_max_bytes, self.policy.context_capacity_tokens
                              * (16 if self.policy.counter_mode == "qualified_tokenizer" else 1)),
                max_history_rows=0,
            )
            coverage = RequirementCoverageVerifier.verify(self.index, projection)
            if not coverage.verified or not projection.ready_for_request:
                raise ContextCoverageBlocked(
                    "; ".join(coverage.reasons or projection.coverage_issues),
                    tuple(item.source_ref for item in self.index.requirement_entries()),
                    context_binding=binding,
                )
            thinking = self.policy.thinking_mode == "enabled"
            prepared_selection = (self.last_prepared.protocol_groups if thinking else
                                  ProtocolGroupSelection((), tuple(sorted({
                                      ref for item in self._groups for ref in item.source_refs
                                  })), len(_wire_json_bytes([]))))
            retained_messages = tuple(
                message for message in self.last_prepared.messages
                if not (message.get("role") == "user"
                        and json.loads(str(message["content"])).get("schema")
                        == "SITINA_LOOP_RUNTIME_FEEDBACK_CONTEXT_V1")
            )
            original_protocol = tuple(
                message for item in prepared_selection.groups for message in item.messages()
            )
            if thinking:
                if tuple(message for message in retained_messages
                         if message.get("role") != "user") != original_protocol:
                    raise ContextCoreError("prepared protocol differs from its retained messages")
                # Every selected group was delivered in last_prepared. Pending
                # results stay separate and untouched until their real commit.
                trials = planning._thinking_protocol_trials(
                    groups=prepared_selection.groups, protect_latest=False,
                )
            else:
                trials = iter((((), []),))
            runtime_feedback = planning._current_runtime_feedback(binding)
            last_forecast_body: bytes | None = None
            for selected_groups, _replacements in trials:
                candidate_protocol = tuple(
                    message for item in selected_groups for message in item.messages()
                )
                if len(candidate_protocol) != len(original_protocol):
                    raise ContextCoreError("history forecast changed protocol message count")
                selection = ProtocolGroupSelection(
                    selected_groups, prepared_selection.omitted_source_refs,
                    len(_wire_json_bytes(candidate_protocol)),
                )
                # Prefer retaining bounded file excerpts. The detached forecast
                # must never publish predicted reads, credit or compaction receipts.
                for include_file_views in (True, False):
                    context = dict(planning._context_document(
                        projection, selection, include_progress=False, include_file_views=include_file_views,
                        runtime_feedback=None,
                    ))
                    # Guarded reads commit intent, dispatch-start and result, then
                    # the tool step commits one checkpoint before the next request.
                    # Size the post-commit counters on detached dictionaries; never
                    # publish these forecast values as observed state/read credit.
                    native_growth = 3 * len(calls) + 1
                    task_context = dict(context["task_context"])
                    task_binding = dict(task_context["binding"])
                    for key in ("frontier", "task_revision"):
                        task_binding[key] += native_growth
                    task_context["binding"] = task_binding
                    context["task_context"] = task_context
                    summary = dict(context["working_summary"])
                    summary_binding = dict(summary["binding"])
                    summary_binding["frontier"] += native_growth
                    summary["binding"] = summary_binding
                    summary["history_query_receipt_count"] += len(history_calls)
                    context["working_summary"] = summary
                    prior_messages = [message for item in selection.groups for message in item.messages()]
                    context["protocol_history"]["selected_complete_group_count"] += 1
                    context["protocol_history"]["selected_serialized_bytes"] = len(
                        _wire_json_bytes([*prior_messages, *group]))
                    context_message = {
                        "role": "user", "content": canonical_json_bytes(context).decode("utf-8"),
                    }
                    protocol_messages = iter(candidate_protocol)
                    messages = (tuple(
                        context_message if message.get("role") == "user" else next(protocol_messages)
                        for message in retained_messages
                    ) if thinking else (context_message,))
                    feedback_messages = ((planning._runtime_feedback_message(
                        runtime_feedback, task_id=str(context["task_context"]["task_id"]),
                    ),) if runtime_feedback is not None else ())
                    previous = self.last_prepared.rendered_request
                    forecast = render_provider_tool_request(
                        self.identity, system_prompt=self.last_prepared.system_prompt,
                        messages=(*messages, *group, *feedback_messages), tools=self.last_prepared.tools,
                        max_tokens=previous.max_tokens, thinking_mode=self.policy.thinking_mode,
                        reasoning_effort=self.policy.reasoning_effort,
                        expect_json=previous.body.get("response_format") == {"type": "json_object"},
                    )
                    if forecast.canonical_body == last_forecast_body:
                        continue
                    last_forecast_body = forecast.canonical_body
                    # The final request still undergoes its own exact admission after
                    # all real tool results and Journal events have been committed.
                    if self.planner.plan(forecast).admitted:
                        return True
            return False

        minimum_pages = pages_for(1)
        if not fits(minimum_pages):
            minimum_response_bytes, minimum_group_bytes, _ = sizes(minimum_pages)
            feedback = self.history_query._with_response_bytes({
                "schema": "SITINA_LOOP_HISTORY_STATUS_V1",
                "status": "BATCH_CAPACITY_BLOCKED",
                "task_session_binding": self.index.binding_hash,
                "reason": "request fewer history pages in one atomic turn; no source body was returned",
                "response_limit_bytes": response_pool,
                "minimum_response_bytes": minimum_response_bytes,
                "minimum_protocol_group_bytes": minimum_group_bytes,
            })
            blocked_pages = {key: feedback for key in renderers}
            if len(calls) == 1 or not fits(blocked_pages):
                raise HistoryBatchCapacityBlocked(
                    calls,
                    context_binding=allocation_binding,
                    minimum_response_bytes=minimum_response_bytes,
                    minimum_protocol_group_bytes=minimum_group_bytes,
                    response_limit_bytes=response_pool,
                )
            self._history_turn_pages = blocked_pages
            return
        # Read page length follows the caller's existing full-receipt budget.
        # Renderers and fits() still enforce per-page, atomic-turn and exact
        # next-request capacity; no fixed 2 KiB ceiling wastes that capacity.
        target = max((min(call["arguments"]["max_bytes"], response_pool)
                      for call in history_calls if call["arguments"].get("operation") == "read"),
                     default=LoopHistoryQuery.BODY_TARGET_BYTES)
        selected = pages_for(target)
        if not fits(selected):
            low, high = 1, target
            selected = minimum_pages
            while low < high:
                middle = (low + high + 1) // 2
                candidate = pages_for(middle)
                if fits(candidate):
                    low, selected = middle, candidate
                else:
                    high = middle - 1
        # The original max_bytes was validated by each renderer and still
        # bounds its full response. Every requested pair remains in the group.
        if not fits(selected):
            raise ContextCoreError("history allocation exceeded its measured response bound")
        self._history_turn_pages = selected

    def _refresh_completion_measurement_progress(self, binding: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """Publish the same current receipt requirements consumed by completion."""
        from .text_measurements import apply_completion_text_measurements, completion_text_measurement_progress
        self.execution_context.pop("text_measurements", None)
        self.execution_context.pop("completion_measurement_progress", None)
        contract = self.execution_context.get("response_contract", {})
        requirements = {str(ordinal): dict(item)
                        for ordinal, item in enumerate(contract.get("condition_requirements", ()))}
        if not any(isinstance(item.get("text_length_requirement"), Mapping)
                   for item in requirements.values()):
            return None
        for item in requirements.values():
            if item.get("kind") == "SEMANTIC_CONDITION":
                item["allowed_evidence_refs"] = list(contract["semantic_condition_allowed_evidence_refs"])
        receipts = self.completion_text_measurement_attempts()
        candidate_response = str(self.execution_context.get("candidate_response") or "")
        apply_completion_text_measurements(
            requirements, receipts, artifact_ref=contract["artifact_ref"],
            goal_version=binding["goal_version"], acceptance_version=binding["acceptance_version"],
            input_seq=binding["handled_input_seq"], candidate_response=candidate_response,
        )
        # A tool receipt can become committed within this same runtime. Expose
        # its condition-specific citation obligation before the next send;
        # updating only the progress display would leave the reply contract stale.
        self.execution_context["response_contract"] = {
            **contract,
            "condition_requirements": [
                {key: value for key, value in item.items()
                 if key != "allowed_evidence_refs" or item.get("kind") != "SEMANTIC_CONDITION"}
                for item in requirements.values()
            ],
            "semantic_condition_allowed_evidence_refs": next((
                item["allowed_evidence_refs"] for item in requirements.values()
                if item.get("kind") == "SEMANTIC_CONDITION"
            ), []),
        }
        progress = completion_text_measurement_progress(
            list(requirements.values()), receipts, artifact_ref=contract["artifact_ref"],
            goal_version=binding["goal_version"], acceptance_version=binding["acceptance_version"],
            input_seq=binding["handled_input_seq"], candidate_response=candidate_response,
            history_query_max_bytes=self.history_query_max_bytes,
            unread_source_refs=self.execution_context.get("history_read_progress", {}).get("missing_source_refs", ()),
        )
        if progress is not None:
            self.execution_context["completion_measurement_progress"] = progress
            accepted = {item["measurement_source_ref"] for item in progress["measurements"]}
            self.execution_context["text_measurements"] = [item for item in receipts
                                                            if item["measurement_source_ref"] in accepted]
        return progress

    def _measure_text(self, arguments: Mapping[str, Any], *, max_bytes: int) -> Mapping[str, Any]:
        """Measure only a complete required target in the current authenticated artifact."""
        self.history_query._validate_max_bytes(max_bytes)
        context = self.execution_context
        evidence = context.get("business_evidence")
        if context.get("phase") != "goal_completion" or not isinstance(evidence, Mapping):
            return self.history_query._status("INVALID_MEASUREMENT", max_bytes, reason="text measurement is bound to current completion only")
        condition_id = arguments.get("condition_id")
        condition = next((item for item in evidence.get("condition_observations", ())
                          if item.get("condition_id") == condition_id), None)
        requirement = condition.get("text_length_requirement") if condition is not None else None
        if condition is not None and (not isinstance(requirement, Mapping) or requirement.get("status") != "BOUND"):
            return self.history_query._status("INVALID_MEASUREMENT", max_bytes, reason="the current condition has no unambiguous complete text scope")
        target = arguments.get("target")
        targets = requirement.get("required_targets", ()) if condition is not None else ()
        if target == "candidate_response":
            selected = next((item for item in targets if item["target"] == target), None)
            source_ref = context.get("artifact_source_ref")
        elif target == "source":
            source_ref = arguments.get("source_ref")
            selected = next((item for item in targets if item["target"] == target
                             and source_ref in item["source_refs"]), None)
        else:
            selected, source_ref = None, None
        if selected is None:
            progress = self._refresh_completion_measurement_progress(self.index.current_binding())
            value = self.history_query._with_response_bytes({
                "schema": "SITINA_LOOP_HISTORY_STATUS_V1", "status": "INVALID_MEASUREMENT",
                "task_session_binding": self.index.binding_hash,
                "reason": ("condition_id does not identify a current completion condition; no text was measured"
                           if condition is None else
                           "target/source_ref is not one of this condition's required current deliverables"),
                **({"binding": progress["binding"], "pending_measurements": progress["pending_measurements"]}
                   if progress is not None else {}),
            })
            if len(canonical_json_bytes(value)) > max_bytes:
                return self.history_query._status("PAGE_TOO_SMALL", max_bytes,
                    reason="increase max_bytes for the current measurement binding",
                    minimum_bytes=len(canonical_json_bytes(value)))
            return value
        self.index.refresh()
        entry = next((item for item in self.index.entries if item.source_ref == source_ref), None)
        if entry is None:
            return self.history_query._status("STALE_SOURCE", max_bytes, reason="the required source is not committed in this task")
        try:
            document = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            if target == "candidate_response":
                main = document.get("main_result")
                text = main.get("response") if isinstance(main, Mapping) else None
                if (entry.kind != "artifact"
                        or not isinstance(text, str) or text != context.get("candidate_response")):
                    raise ValueError("candidate text does not match the authenticated current artifact")
            else:
                result = document.get("result", {})
                value = result.get("value", {})
                text = value.get("content") if isinstance(value, Mapping) else None
                if (document.get("schema") != "SITINA_LOOP_OPERATION_RESULT_V1"
                        or document.get("task_id") != evidence["binding"]["task_id"]
                        or document.get("effect_status") != "SUCCEEDED" or result.get("status") != "ok"
                        or result.get("tool") != "sitina_read_file" or not isinstance(text, str)
                        or hashlib.sha256(text.encode("utf-8")).hexdigest() != selected["text_content_hash"]):
                    raise ValueError("file content does not match the current required delivery hash")
            goal = context.get("interpreted_goal_input", {})
            metadata_context = "\n".join(str(value) for value in
                [context.get("measurement_source_request", goal.get("goal", "")),
                 *goal.get("constraints", ()), *goal.get("acceptance_conditions", ())])
            titles = [path.rsplit("/", 1)[-1] for path in requirement["target_paths"]]
            titles += [title.rsplit(".", 1)[0] for title in titles]
            statistics = measure_text(
                text, requirement=requirement, scope=arguments.get("scope"),
                metadata_context=metadata_context, target_titles=titles,
                section_heading=arguments.get("section_heading"), label_separator=arguments.get("label_separator"),
            )
        except (ValueError, KeyError, TypeError) as error:
            # Keep an actual rejected scope bound to the same current target.
            # It is a failure observation, never a successful count receipt.
            value = self.history_query._with_response_bytes({
                "schema": "SITINA_LOOP_TEXT_MEASUREMENT_V1", "status": "INVALID_MEASUREMENT",
                "reason": str(error), "task_session_binding": self.index.binding_hash,
                "binding": {key: self.index.current_binding()[key] for key in
                            ("goal_version", "acceptance_version", "handled_input_seq")},
                "artifact_ref": context["response_contract"]["artifact_ref"],
                "condition_id": condition_id, "target": target, "target_key": selected["target_key"],
                "source_ref": source_ref, "source_content_hash": entry.content_hash,
                "scope_contract_hash": requirement["scope_contract_hash"],
                "required_text_content_hash": (hashlib.sha256(context["candidate_response"].encode("utf-8")).hexdigest()
                                      if target == "candidate_response" else selected["text_content_hash"]),
                "scope": arguments.get("scope"), "section_heading": arguments.get("section_heading"),
                "label_separator": arguments.get("label_separator"),
                **({"format_feedback": error.feedback} if isinstance(error, TextMeasurementScopeError) else {}),
            })
            if len(canonical_json_bytes(value)) > max_bytes:
                return self.history_query._status("PAGE_TOO_SMALL", max_bytes, reason="increase max_bytes for the bound measurement error",
                                                 minimum_bytes=len(canonical_json_bytes(value)))
            return value
        value = self.history_query._with_response_bytes({
            "schema": "SITINA_LOOP_TEXT_MEASUREMENT_V1", "status": "MEASURED",
            "task_session_binding": self.index.binding_hash,
            "binding": {key: self.index.current_binding()[key] for key in
                        ("goal_version", "acceptance_version", "handled_input_seq")},
            "artifact_ref": context["response_contract"]["artifact_ref"],
            "condition_id": condition_id, "target": target, "target_key": selected["target_key"],
            "source_ref": source_ref, "source_content_hash": entry.content_hash,
            "scope_contract_hash": requirement["scope_contract_hash"],
            "text_content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(), **statistics,
        })
        if len(canonical_json_bytes(value)) > max_bytes:
            return self.history_query._status("PAGE_TOO_SMALL", max_bytes, reason="increase max_bytes for the complete measurement",
                                             minimum_bytes=len(canonical_json_bytes(value)))
        return value

    def completion_text_measurements(self) -> list[Mapping[str, Any]]:
        """Only actual successful counts are measurement receipts."""
        return [item for item in self.completion_text_measurement_attempts() if item["status"] == "MEASURED"]

    def completion_text_measurement_attempts(self) -> list[Mapping[str, Any]]:
        """Recover authenticated current successes or bound failures, never the display cache."""
        context = self.execution_context
        evidence = context.get("business_evidence", {})
        return self.current_completion_text_measurement_attempts(
            self.index, task_id=evidence.get("binding", {}).get("task_id"),
            artifact_ref=context.get("response_contract", {}).get("artifact_ref"),
        )

    @staticmethod
    def current_completion_text_measurement_attempts(
        index: LoopContextIndex, *, task_id: str | None, artifact_ref: str | None,
    ) -> list[Mapping[str, Any]]:
        """Use the same native receipt binding during live completion and cold rework."""
        binding = {key: index.current_binding()[key] for key in
                   ("goal_version", "acceptance_version", "handled_input_seq")}
        index.refresh()
        receipts: list[Mapping[str, Any]] = []
        for entry in index.entries:
            if entry.kind != "operation_result":
                continue
            document = index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            result = document.get("result")
            if not isinstance(result, Mapping):
                continue
            arguments, value = result.get("arguments"), result.get("value")
            if (document.get("schema") != "SITINA_LOOP_OPERATION_RESULT_V1"
                    or document.get("task_id") != task_id or document.get("effect_status") != "SUCCEEDED"
                    or document.get("bound_goal_version") != binding["goal_version"]
                    or document.get("bound_acceptance_version") != binding["acceptance_version"]
                    or document.get("bound_input_seq") != binding["handled_input_seq"]
                    or result.get("tool") != "sitina_history_query" or result.get("status") != "ok"
                    or not isinstance(arguments, Mapping) or arguments.get("operation") != "measure_text"
                    or not isinstance(value, Mapping) or value.get("schema") != "SITINA_LOOP_TEXT_MEASUREMENT_V1"
                    or value.get("status") not in {"MEASURED", "INVALID_MEASUREMENT"} or value.get("binding") != binding
                    or value.get("task_session_binding") != index.binding_hash
                    or value.get("artifact_ref") != artifact_ref
                    or any(arguments.get(key) != value.get(key) for key in
                           ("condition_id", "target", "scope", "section_heading", "label_separator"))
                    or (arguments.get("target") == "source" and arguments.get("source_ref") != value.get("source_ref"))):
                continue
            receipts.append({**dict(value), "measurement_source_ref": entry.source_ref,
                             "measurement_content_hash": entry.content_hash})
        return receipts

    def history_tool(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        max_bytes = arguments.get("max_bytes")
        if type(max_bytes) is not int:
            raise HistoryQueryError("history max_bytes must be an integer")
        self.history_query._validate_max_bytes(max_bytes)
        allocated = self._history_turn_pages.get(canonical_json_bytes(arguments))
        if allocated is not None:
            # Detached native page; concurrent callers cannot mutate another
            # result or an already committed cold-replay page.
            return json.loads(_wire_json_bytes(allocated))
        target = max_bytes if arguments.get("operation") == "read" else LoopHistoryQuery.BODY_TARGET_BYTES
        return self._history_query_renderer(arguments)(target)

    def _history_query_renderer(self, arguments: Mapping[str, Any]) -> Any:
        operation = arguments.get("operation")
        max_bytes = arguments.get("max_bytes")
        if type(max_bytes) is not int:
            raise HistoryQueryError("history max_bytes must be an integer")
        # Validate the original hard bound before any soft payload allocation.
        self.history_query._validate_max_bytes(max_bytes)
        if operation == "measure_text":
            return self.history_query._fixed_page(self._measure_text(arguments, max_bytes=max_bytes))
        if operation == "list":
            limit = arguments.get("limit", 50)
            if type(limit) is not int:
                raise HistoryQueryError("history list limit must be an integer")
            cursor = arguments.get("cursor")
            kind = arguments.get("kind")
            if cursor is not None and type(cursor) is not str:
                raise HistoryQueryError("history list cursor must be a string")
            if kind is not None and type(kind) is not str:
                raise HistoryQueryError("history list kind must be a string")
            return self.history_query._prepare_list(
                cursor=cursor,
                limit=limit,
                kind=kind,
                max_bytes=max_bytes,
            )
        if operation == "read":
            arguments, navigation_error = self.history_query.resolve_read_arguments(arguments)
            if navigation_error is not None:
                return self.history_query._fixed_page(navigation_error)
            source_ref = arguments.get("source_ref")
            offset = arguments.get("offset", 0)
            if type(source_ref) is not str or not source_ref:
                raise HistoryQueryError("history read requires a source_ref")
            if type(offset) is not int:
                raise HistoryQueryError("history read offset must be an integer")
            end_offset = arguments.get("end_offset")
            read_cursor = arguments.get("read_cursor")
            if end_offset is not None and type(end_offset) is not int:
                raise HistoryQueryError("history read end_offset must be an integer")
            if read_cursor is not None and type(read_cursor) is not str:
                raise HistoryQueryError("history read read_cursor must be a string")
            view = arguments.get("view", "raw")
            if type(view) is not str or view not in {"raw", "review"}:
                raise HistoryQueryError("history read view must be raw or review")
            render = self.history_query._prepare_read(
                source_ref=source_ref, offset=offset, max_bytes=max_bytes,
                end_offset=end_offset, read_cursor=read_cursor, view=view,
                continuation_arguments={key: arguments[key] for key in
                    ("review_question", "review_claim_source_ref", "review_claim_quote") if key in arguments},
                native_navigation=True, continued_from=arguments.get("continuation_ref"),
            )
            base_render = render

            def render_with_navigation(target: int) -> Mapping[str, Any]:
                page = base_render(target)
                if page.get("status") not in {"INVALID_OFFSET", "INVALID_RANGE", "INVALID_READ_CURSOR"}:
                    return page
                row = next((item for item in self.history_read_sources()
                            if item["source_ref"] == source_ref and item["applicability"] == "CURRENT_BINDING"), None)
                if (row is None or row["read_content_hash"] != page.get("content_hash")
                        or row["source_content_hash"] != page.get("source_content_hash")
                        or any(row["last_history_page"].get(key) != page.get(key) for key in
                               ("content_projection", "total_bytes"))):
                    return page
                action = row.get("next_read") or row.get("next_unread_read")
                if not isinstance(action, Mapping):
                    return page
                recovered = self.history_query._with_response_bytes({
                    **page, "recovery": {"next_read": dict(action), "read_credit": False,
                        "basis": "committed_current_binding_receipt",
                        "instruction": "For this existing read chain use next_read directly. A new deliberate range must use legal UTF-8 boundaries."},
                })
                return recovered if recovered["response_bytes"] <= max_bytes else page

            render = render_with_navigation
            if self.role != "reviewer" or self.execution_context.get("phase") != "independent_read_only_review":
                return render
            authority = self.execution_context["review_read_authority"]
            required = self.execution_context["history_read_progress"]["required_source_refs"]
            progress = self.reviewer_read_progress(required, **authority)

            def render_with_recovery(target: int) -> Mapping[str, Any]:
                page = render(target)
                if page.get("status") != "INVALID_OFFSET" or source_ref not in required:
                    return page
                row = next((item for item in progress["read_sources"] if item["source_ref"] == source_ref), None)
                if row is not None and any(row[key] != page[key] for key in
                        ("source_content_hash", "content_hash", "content_projection", "total_bytes")):
                    return page
                recovery = {**page.get("recovery", {}),
                            "next_unread_offset": progress["next_read_offsets"][source_ref],
                            "complete_source_read": source_ref in progress["completed_source_refs"],
                            "basis": "authenticated_current_review_read_ranges", "read_credit": False}
                return self.history_query._status(
                    "INVALID_OFFSET", max_bytes,
                    **{key: value for key, value in page.items()
                       if key not in {"schema", "status", "task_session_binding", "response_bytes", "recovery"}},
                    recovery=recovery,
                )

            return render_with_recovery
        raise HistoryQueryError("history operation must be list, read or measure_text")

    def set_runtime_feedback(self, *, kind: str, instruction: str) -> None:
        """Bind one small protocol repair instruction to the current task version."""

        if not kind.strip() or not instruction.strip():
            raise ContextCoreError("bounded runtime feedback requires kind and instruction")
        max_bytes = (
            GOAL_COMPLETION_EVIDENCE_FEEDBACK_MAX_BYTES
            if kind == "goal_completion_evidence_repair"
            else 1024
        )
        if len(instruction.encode("utf-8")) > max_bytes:
            raise ContextCoreError(f"bounded runtime feedback exceeds {max_bytes} UTF-8 bytes")
        self._runtime_feedback = {
            "schema": "SITINA_LOOP_BOUNDED_RUNTIME_FEEDBACK_V1",
            "kind": kind,
            "instruction": instruction,
            "binding": self.index.current_binding(),
            "role": self.role,
            "phase": self.execution_context.get("phase"),
        }

    def clear_runtime_feedback(self) -> None:
        self._runtime_feedback = None

    def _current_runtime_feedback(
        self, binding: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        """Discard feedback from another semantic task or execution phase."""

        runtime_feedback = self._runtime_feedback
        feedback_binding = (
            runtime_feedback.get("binding") if isinstance(runtime_feedback, Mapping) else None
        )
        semantic_binding_keys = (
            "run_instance_id",
            "execution_epoch",
            "goal_version",
            "acceptance_version",
            "received_input_seq",
            "handled_input_seq",
            "artifact_ref",
            "control_intent",
            "status",
        )
        if runtime_feedback is not None and (
            not isinstance(feedback_binding, Mapping)
            or runtime_feedback.get("role") != self.role
            or runtime_feedback.get("phase") != self.execution_context.get("phase")
            or any(
                feedback_binding.get(key) != binding.get(key)
                for key in semantic_binding_keys
            )
        ):
            # A correction/control/artifact transition invalidates feedback
            # produced under the prior semantic task binding. Plan/checkpoint
            # journal revisions alone do not invalidate a pending repair.
            self._runtime_feedback = None
            runtime_feedback = None

        return runtime_feedback

    def _runtime_feedback_message(
        self, feedback: Mapping[str, Any], *, task_id: str,
    ) -> Mapping[str, Any]:
        """Render program guidance separately from the original user input."""

        return {
            "role": "user",
            "content": canonical_json_bytes({
                "schema": "SITINA_LOOP_RUNTIME_FEEDBACK_CONTEXT_V1",
                "origin": "program_runtime",
                "authorization": "Existing task permissions only; this is not a new user input.",
                "role": self.role,
                "phase": self.execution_context.get("phase"),
                "task_context": {"task_id": task_id},
                "runtime_feedback": dict(feedback),
            }).decode("utf-8"),
        }

    def source_ref_for_operation(self, operation_id: str) -> str:
        self.index.refresh()
        entry = next(
            (
                item for item in reversed(self.index.entries)
                if item.kind == "operation_result" and item.subject_id == operation_id
            ),
            None,
        )
        if entry is None:
            raise ContextCoreError("committed operation result is missing from the task history index")
        return entry.source_ref

    def source_ref_for_committed_ref(self, internal_cas_ref: str, *, kind: str | None = None) -> str:
        self.index.refresh()
        entry = next(
            (
                item for item in reversed(self.index.entries)
                if item.internal_cas_ref == internal_cas_ref and (kind is None or item.kind == kind)
            ),
            None,
        )
        if entry is None:
            raise ContextCoreError("CAS reference has no proof-bound entry in this task history")
        return entry.source_ref

    @staticmethod
    def model_history_page(page: Mapping[str, Any]) -> Mapping[str, Any]:
        """Expose one readable page, keeping the original transport bytes in CAS."""
        view = dict(page)
        if isinstance(view.get("readable_text"), str):
            # data_base64 encodes the same UTF-8 page. Injecting both can make
            # an atomic multi-tool turn exceed capacity even after eviction.
            view.pop("data_base64", None)
            if view.get("content_encoding") == "canonical-json-utf8+base64":
                view["content_encoding"] = "canonical-json-utf8"
        return view

    def observe_committed_tool_result(
        self, operation_id: str, *, tool_name: str, status: str,
        value: Any, binding: Mapping[str, Any],
    ) -> None:
        """Keep original file locators beside later paging receipts.

        The adapter supplies an already committed result; cold replay supplies
        the same hash-verified result. These are read/provenance facts, never
        generated business summaries or claims that a plan step is complete.
        """
        if status != "ok" or not isinstance(value, Mapping):
            return
        if tool_name == "sitina_history_query" and value.get("schema") == "SITINA_LOOP_TEXT_MEASUREMENT_V1":
            if value.get("status") == "MEASURED":
                reference = self.source_ref_for_operation(operation_id)
                self._text_measurements[reference] = {
                    **dict(value), "measurement_source_ref": reference,
                    "observed_binding": {key: binding[key] for key in
                                         ("goal_version", "acceptance_version", "handled_input_seq")},
                }
                # Keep the historical cache; current presentation is rebuilt from committed evidence.
            return
        if tool_name == "sitina_read_file":
            if value.get("exists") is not True or not isinstance(value.get("path"), str):
                return
            source_ref = self.source_ref_for_operation(operation_id)
            self._file_read_sources[source_ref] = {
                "operation_id": operation_id,
                "path": value["path"],
                "content_version": value.get("version"),
                "source_ref": source_ref,
                "observed_binding": {key: binding[key] for key in
                                     ("goal_version", "acceptance_version", "handled_input_seq")},
            }
            content = value.get("content")
            if isinstance(content, str):
                raw = content.encode("utf-8")
                # Keep bounded verbatim evidence, not a generated summary.
                # Both ends help a later turn retain findings after eviction;
                # the gap remains explicit and can be read from source_ref.
                head = raw[:1024].decode("utf-8", errors="ignore")
                head_end = len(head.encode("utf-8"))
                tail = raw[max(head_end, len(raw) - 1024):].decode("utf-8", errors="ignore")
                tail_start = len(raw) - len(tail.encode("utf-8"))
                fragments = [{"start_byte": 0, "end_byte": head_end, "text": head}]
                if tail:
                    fragments.append({"start_byte": tail_start, "end_byte": len(raw), "text": tail})
                self._file_read_sources[source_ref]["verbatim_excerpt"] = {
                    "basis": ("verified-file-view-utf8" if value.get("content_view")
                              else "verified-file-content-utf8"),
                    **({"content_view": dict(value["content_view"])} if value.get("content_view") else {}),
                    "total_bytes": len(raw),
                    "fragments": fragments, "has_omitted_content": tail_start > head_end,
                    "omitted_byte_range": ([head_end, tail_start] if tail_start > head_end else None),
                }
        elif tool_name == "sitina_history_query":
            self._observe_history_source(value, binding=binding, operation_id=operation_id)

    def _observe_history_source(
        self, page: Mapping[str, Any], *, binding: Mapping[str, Any], operation_id: str,
    ) -> None:
        """Restore source coverage and navigation from a committed successful receipt."""
        source_ref = page.get("source_ref")
        if page.get("status") != "OK" or not isinstance(source_ref, str):
            return
        self.index.refresh()
        receipt = next((item for item in self.index.entries
                        if item.kind == "operation_result" and item.subject_id == operation_id), None)
        if receipt is None:
            return
        committed = self.index.store.read_json(receipt.internal_cas_ref, expected_hash=receipt.content_hash)
        result = committed.get("result") if isinstance(committed, Mapping) else None
        if (not isinstance(committed, Mapping) or committed.get("task_id") != self.index.task_id
                or committed.get("operation_id") != operation_id or committed.get("effect_status") != "SUCCEEDED"
                or not isinstance(result, Mapping) or result.get("tool") != "sitina_history_query"
                or result.get("status") != "ok" or not isinstance(result.get("value"), Mapping)
                # Preparation is not a model read. Delivered prepared pages
                # have their own authenticated reviewer-progress projection.
                # Cold recovery must apply the same boundary as live tool_call.
                or result.get("invocation_origin") == "product_review_preparation"
                or canonical_json_bytes(result["value"]) != canonical_json_bytes(page)
                or any(committed.get(field) != binding[key] for field, key in
                       (("bound_goal_version", "goal_version"),
                        ("bound_acceptance_version", "acceptance_version"),
                        ("bound_input_seq", "handled_input_seq")))):
            return
        self._project_history_source(page, binding=binding, operation_id=operation_id,
                                     receipt_ordinal=receipt.ordinal)

    def _project_history_source(
        self, page: Mapping[str, Any], *, binding: Mapping[str, Any],
        operation_id: str | None = None, receipt_ordinal: int | None = None,
    ) -> None:
        """Project verified page facts; forecasting invokes this only on detached state."""
        source_ref = page.get("source_ref")
        if page.get("status") != "OK" or not isinstance(source_ref, str):
            return
        entry = next((item for item in self.index.entries if item.source_ref == source_ref), None)
        if entry is None:
            raise ContextCoreError("committed history read has no proof-visible source")
        content_hash = page.get("content_hash")
        if (not isinstance(content_hash, str) or len(content_hash) != 64
                or any(character not in "0123456789abcdef" for character in content_hash)):
            raise ContextCoreError("committed history read lacks its exact content version")
        previous = self._history_read_sources.get(source_ref)
        # Replaying an old receipt is idempotent, including after a later seek.
        # The native journal order, not consumption order, determines the cursor.
        if (previous is not None and receipt_ordinal is not None
                and previous.get("last_history_receipt_ordinal", 0) >= receipt_ordinal):
            return
        observation_binding = {key: binding[key] for key in
                               ("goal_version", "acceptance_version", "handled_input_seq")}
        first_read = (
            previous is None or previous.get("read_content_hash") != content_hash
            or previous.get("source_content_hash") != entry.content_hash
            or previous.get("observed_binding") != observation_binding
            or previous["last_history_page"]["total_bytes"] != page["total_bytes"]
        )
        if first_read:
            self._history_read_sources[source_ref] = {
                "source_ref": source_ref, "kind": entry.kind, "source_content_hash": entry.content_hash,
                "read_content_hash": content_hash, "read_ranges": [],
            }
        row = self._history_read_sources[source_ref]
        row["observed_binding"] = observation_binding
        if receipt_ordinal is not None:
            row["last_history_receipt_operation_id"] = operation_id
            row["last_history_receipt_ordinal"] = receipt_ordinal
        row["last_history_page"] = json.loads(canonical_json_bytes({
            key: page[key] for key in
            ("offset", "next_offset", "has_more", "total_bytes", "read_mode", "read_range",
             "requested_range", "range_complete", "next_read", "content_projection", "continuation_scope") if key in page
        }))
        covered_before = sum(end - start for start, end in row["read_ranges"])
        interval = [page["offset"], page["offset"] + page["returned_bytes"]]
        ranges = sorted([*row["read_ranges"], *([interval] if interval[0] < interval[1] else [])])
        merged: list[list[int]] = []
        for start, end in ranges:
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        row["read_ranges"] = merged
        row["covered_source_bytes"] = sum(end - start for start, end in merged)
        row["last_read_coverage_delta_bytes"] = row["covered_source_bytes"] - covered_before
        row["complete_source_read"] = merged == [[0, page["total_bytes"]]]
        self._observe_file_history_page(page)
        if not first_read:
            return
        document = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
        public, _ = self.history_query._history_safe_document(entry, document)
        view: dict[str, Any] = {}
        if isinstance(public, Mapping) and entry.kind == "artifact":
            main = public.get("main_result")
            if isinstance(main, Mapping):
                view = {key: public[key] for key in ("schema", "task_id", "binding", "changed_paths")
                        if key in public}
                view["main_result"] = {key: main[key] for key in ("status", "response") if key in main}
                row["source_view_scope"] = "artifact-binding-and-main-response"
        elif isinstance(public, Mapping) and entry.kind == "operation_result":
            result = public.get("result")
            if isinstance(result, Mapping) and isinstance(result.get("text"), str):
                view = {key: public[key] for key in
                        ("schema", "task_id", "operation_id", "effect_status",
                         "bound_goal_version", "bound_acceptance_version", "bound_input_seq") if key in public}
                view["result"] = {key: result[key] for key in ("text", "stop_reason") if key in result}
                row["source_view_scope"] = "unverified-original-assistant-text"
            if (source_ref not in self._file_read_sources
                    and isinstance(result, Mapping)
                    and public.get("effect_status") == "SUCCEEDED"
                    and result.get("tool") == "sitina_read_file" and result.get("status") == "ok"):
                self.observe_committed_tool_result(
                    entry.subject_id, tool_name="sitina_read_file", status="ok", value=result.get("value"),
                    binding={"goal_version": public["bound_goal_version"],
                             "acceptance_version": public["bound_acceptance_version"],
                             "handled_input_seq": public["bound_input_seq"]},
                )
        # Cold reads restore the file locator above; retain their first page too.
        self._observe_file_history_page(page)
        if view and len(canonical_json_bytes(view)) <= 2 * self.receipt_max_bytes:
            row["source_view"] = view
            row["source_view_is_complete_document"] = False

    def history_read_sources(self, *, include_views: bool = True) -> list[Mapping[str, Any]]:
        """Detached current-binding read facts with a bounded original-field view."""
        current = self.index.current_binding()
        rows = tuple(self._history_read_sources.values())
        if self.role == "main":
            # A diagnostic read of a retrieval receipt must not become the
            # main Agent's next business read after eviction or cold replay.
            # Keep its authenticated coverage internally and its explicit
            # tool response intact; only omit automatic recall suggestions.
            retrieval_receipts = {
                entry.source_ref for entry in self.index.entries
                if entry.kind == "operation_result"
                and self.index._operation_tool_names.get(entry.subject_id) == "sitina_history_query"
            }
            rows = tuple(row for row in rows if row["source_ref"] not in retrieval_receipts)
        if len(rows) > 12:
            required_refs = {
                self.execution_context.get(key) for key in
                ("artifact_source_ref", "program_source_ref", "main_result_source_ref")
            }
            for key in ("preflight_source_refs", "native_work_source_refs", "business_source_refs"):
                required_refs.update(self.execution_context.get(key, ()))
            retained_refs = {row["source_ref"] for row in (*rows[:4], *rows[-8:])}
            retained_refs.update(required_refs)
            # Handles do not create read credit: only actually observed,
            # committed reads are eligible. Mandatory review evidence keeps
            # its read ranges even when optional middle history is evicted.
            rows = tuple(row for row in rows if row["source_ref"] in retained_refs)
        view_bytes = 0
        output = []
        for source in rows:
            row = json.loads(canonical_json_bytes(source))
            # Journal identities enforce replay order internally; they do not
            # enlarge or authorize the model-facing navigation receipt.
            row.pop("last_history_receipt_operation_id", None)
            row.pop("last_history_receipt_ordinal", None)
            if not include_views:
                row.pop("source_view", None)
            row["applicability"] = (
                "CURRENT_BINDING" if all(row["observed_binding"][key] == current[key]
                    for key in ("goal_version", "acceptance_version", "handled_input_seq"))
                else "PRIOR_BINDING_RECHECK_REQUIRED"
            )
            # The last returned cursor may point inside a previously covered
            # interval. Keep the first actual gap visible across local yields.
            next_unread = 0
            for start, end in row["read_ranges"]:
                if start > next_unread:
                    break
                next_unread = max(next_unread, end)
            row["next_unread_offset"] = (
                (None if next_unread == row["last_history_page"]["total_bytes"] else next_unread)
                if row["applicability"] == "CURRENT_BINDING" else 0
            )
            last = row["last_history_page"]
            row["next_read"] = (last.get("next_read") if row["applicability"] == "CURRENT_BINDING" else None)
            gap = row["next_unread_offset"]
            row["next_unread_read"] = None
            if gap is not None:
                if (row["next_read"] is not None and last.get("read_range", {}).get("end") == gap
                        and last.get("requested_range", {}).get("end") == last["total_bytes"]):
                    row["next_unread_read"] = {**row["next_read"], "max_bytes": self.history_query_max_bytes}
                else:
                    row["next_unread_read"] = {"operation": "read", "source_ref": row["source_ref"],
                        "offset": gap, "max_bytes": self.history_query_max_bytes,
                        "view": last.get("continuation_scope", {}).get("view", "raw")}
            view = row.get("source_view")
            if view is not None:
                size = len(canonical_json_bytes(view))
                if view_bytes + size > self.history_query_max_bytes:
                    row.pop("source_view")
                else:
                    view_bytes += size
            output.append(row)
        return output

    def _observe_file_history_page(self, page: Mapping[str, Any]) -> None:
        source = self._file_read_sources.get(str(page.get("source_ref") or ""))
        if source is not None and page.get("status") == "OK" and page.get("kind") == "operation_result":
            source["last_history_page"] = {
                key: page[key] for key in ("offset", "next_offset", "has_more", "total_bytes", "content_hash", "content_projection")
                if key in page
            }

    def verified_file_source_paths(self) -> tuple[str, ...]:
        """Exact locators from successful committed reads in the current task binding.

        This uses the full provenance index, not its bounded model projection.
        Model prose, requested paths and write-result paths never enter it.
        """
        current = self.index.current_binding()
        paths: set[str] = set()
        for source in tuple(self._file_read_sources.values()):
            path = source["path"]
            version = source["content_version"]
            if (isinstance(path, str) and path.startswith("/")
                    and isinstance(version, str) and version.startswith("sha256:")
                    and len(version) == 71
                    and all(character in "0123456789abcdef" for character in version[7:])
                    and all(source["observed_binding"][key] == current[key]
                            for key in ("goal_version", "acceptance_version", "handled_input_seq"))):
                paths.add(path)
        return tuple(sorted(paths))

    def file_read_sources(self, *, include_views: bool = True) -> list[Mapping[str, Any]]:
        """Bounded, detached locators, including their original input binding."""
        current = self.index.current_binding()
        progress_by_ref = {row["source_ref"]: row for row in
                           self.history_read_sources(include_views=False)}
        entries_by_ref = {entry.source_ref: entry for entry in self.index.entries}
        latest: dict[tuple[str, str | None], Mapping[str, Any]] = {}
        for source in reversed(tuple(self._file_read_sources.values())):
            path = str(source["path"])
            key = (path, source["content_version"])
            if key in latest:
                continue
            row = json.loads(canonical_json_bytes(source))
            if not include_views:
                row.pop("verbatim_excerpt", None)
            row["applicability"] = (
                "CURRENT_BINDING" if all(row["observed_binding"][key] == current[key]
                    for key in ("goal_version", "acceptance_version", "handled_input_seq"))
                else "PRIOR_BINDING_RECHECK_REQUIRED"
            )
            progress = progress_by_ref.get(row["source_ref"])
            page = row.get("last_history_page")
            entry = entries_by_ref.get(row["source_ref"])
            if (progress is not None and entry is not None
                    and row["applicability"] == progress["applicability"] == "CURRENT_BINDING"
                    and progress["source_content_hash"] == entry.content_hash):
                # Cold replay restores history facts before reconstructing file
                # protocol groups. Derive navigation from the latest verified
                # receipt, not the initial file page recreated during replay.
                page = {key: progress["last_history_page"][key] for key in
                        ("offset", "next_offset", "has_more", "total_bytes", "content_projection")
                        if key in progress["last_history_page"]}
                page["content_hash"] = progress["read_content_hash"]
                row["last_history_page"] = page
            if (progress is not None and page is not None and entry is not None
                    and progress["applicability"] == "CURRENT_BINDING"
                    and progress["source_content_hash"] == entry.content_hash
                    and progress["read_content_hash"] == page.get("content_hash")
                    and all(progress["last_history_page"].get(field) == page[field] for field in
                            ("offset", "next_offset", "has_more", "total_bytes"))):
                # A projected file view and its raw receipt have independent
                # byte spaces. Neither is a current business verdict.
                row["historical_read_progress"] = {
                    "coordinate_space": ("review-content-view-utf8" if page.get("content_projection") == REVIEW_VIEW
                                         else "canonical-history-document-utf8"),
                    "source_ref": progress["source_ref"],
                    "source_content_hash": progress["source_content_hash"],
                    "content_hash": progress["read_content_hash"],
                    "total_bytes": page["total_bytes"],
                    "observed_binding": progress["observed_binding"],
                    "read_ranges": progress["read_ranges"],
                    "complete_source_read": progress["complete_source_read"],
                    "next_unread_offset": progress["next_unread_offset"],
                    "applicability": progress["applicability"],
                }
            latest[key] = row
        rows = list(reversed(tuple(latest.values())))
        # Preserve early sources as well as the most recent ones. The full
        # source index remains available for any omitted middle sources.
        return rows if len(rows) <= 12 else [*rows[:4], *rows[-8:]]

    def prompt_receipt_for_operation(self, operation_id: str) -> Mapping[str, Any]:
        receipt = self.history_query.receipt_for_operation_result(
            operation_id,
            max_bytes=self.receipt_max_bytes,
        )
        if receipt.get("status") != "OK":
            raise ContextCoreError("committed operation result cannot be represented as a verified receipt")
        self._observe_file_history_page(receipt)
        return self.model_history_page(receipt)

    def model_tool_value(
        self, operation_id: str, *, tool_name: str, status: str, value: Any,
    ) -> Mapping[str, Any]:
        """Show a complete small read once, rather than page its duplicate wrapper.

        The authenticated operation and native history bytes are unchanged.
        Large values still use their original bounded receipt and cursor.
        """
        if (status == "error" and isinstance(value, Mapping)
                and value.get("status") == "REVIEW_EVIDENCE_SCOPE_DENIED"
                and value.get("effect_dispatched") is False and value.get("read_credit") is False):
            # A local protocol refusal is complete guidance, not evidence to
            # page through. Keep its committed source, failed state and scope.
            view = {"status": "REVIEW_EVIDENCE_SCOPE_DENIED", "kind": "operation_result",
                    "source_ref": self.source_ref_for_operation(operation_id),
                    "complete_value_visible": True, "read_credit": False,
                    "effect_dispatched": False, "value": dict(value)}
            if len(canonical_json_bytes(view)) <= self.history_query_max_bytes:
                return view
        if (status == "ok" and isinstance(value, Mapping)
                and tool_name in {"sitina_shell", "sitina_exec", "sitina_process_start", "sitina_process_status",
                                  "sitina_process_log", "sitina_process_stop"}
                and "generated_files" in value):
            # A bounded reference view avoids forcing the model to read binary stdout.
            # Full logs and the authenticated source receipt remain available by history.
            fields = ("program_status", "effect_settled", "completion_status", "exit_code", "returncode",
                      "process_id", "generated_files", "generated_files_status", "generated_files_error")
            view = {"status": "OK", "kind": "operation_result",
                    "source_ref": self.source_ref_for_operation(operation_id),
                    "complete_value_visible": False, "value_view": "generated-file-references",
                    "value": {key: value[key] for key in fields if key in value}}
            if len(canonical_json_bytes(view)) <= self.history_query_max_bytes:
                return view
        from sitina.execution import TASK_EXECUTION_CONTRACT
        if (status == "ok" and isinstance(value, Mapping)
                and value.get("execution_contract") == TASK_EXECUTION_CONTRACT
                and isinstance(value.get("process_id"), str)
                and tool_name in {"sitina_shell", "sitina_exec", "sitina_process_start",
                                  "sitina_process_status", "sitina_process_log", "sitina_process_stop"}):
            # Preserve operational state beside the verified raw reference.
            # Environment inventories must not obscure the original process handle.
            fields = ("execution_contract", "process_id", "owner_operation_id", "mode",
                      "state", "program_status", "execution_started", "keep", "input_owner",
                      "exit_code", "returncode", "root_status", "root_exit_code",
                      "trusted_root_result", "trusted_completion", "completion_status",
                      "effect_settled", "effect_settlement_scope", "process_ownership_scope",
                      "control_ack", "reason", "command", "cwd", "output")
            view = {"status": "OK", "kind": "operation_result",
                    "source_ref": self.source_ref_for_operation(operation_id),
                    "complete_value_visible": False, "value_view": "native-execution-control",
                    "value": {key: value[key] for key in fields if key in value}}
            if len(canonical_json_bytes(view)) > self.history_query_max_bytes:
                for key in ("command", "cwd", "output"):
                    view["value"].pop(key, None)
            view["output_visible"] = "output" in view["value"]
            if len(canonical_json_bytes(view)) <= self.history_query_max_bytes:
                return view
        if (status == "ok" and isinstance(value, Mapping) and (
                tool_name == "sitina_read_file" and value.get("exists") is True
                or tool_name == "sitina_http_request"
                and value.get("physical_send_state") == "RESPONSE_RECEIVED"
                and type(value.get("status")) is int and 200 <= value["status"] < 300
                and isinstance(value.get("body"), str) and bool(value["body"].strip())
                and isinstance(value.get("source_url"), str) and bool(value["source_url"])
                and isinstance(value.get("fetched_at"), str) and bool(value["fetched_at"])
                or tool_name == "sitina_task_skills" and isinstance(value.get("task_skill_identity"), Mapping)
                or tool_name == "sitina_team" and (
                    isinstance(value.get("task_id"), str)
                    or isinstance(value.get("team"), Mapping) and isinstance(value["team"].get("task_id"), str))
                or tool_name == "sitina_read_skill_resource" and value.get("authority") == "guidance_only"
                and isinstance(value.get("content"), str)
                or "__" in tool_name
        )):
            source_ref = self.source_ref_for_operation(operation_id)
            view = {
                "status": "OK", "kind": "operation_result", "source_ref": source_ref,
                "complete_value_visible": True, "value": dict(value),
            }
            if len(canonical_json_bytes(view)) <= self.history_query_max_bytes:
                source = self._file_read_sources.get(source_ref)
                if source is not None:
                    source["complete_value_visible"] = True
                return view
        if status == "ok" and tool_name == "sitina_team" and isinstance(value, Mapping):
            team = value.get("team", value)
            if isinstance(team, Mapping) and isinstance(team.get("task_id"), str):
                # Objectives, operation navigation and reports can make a team
                # reply too large. Keep its control state beside the original
                # source instead of turning a settled result into an opaque
                # receipt that encourages another wait/status poll.
                source_ref = self.source_ref_for_operation(operation_id)
                control = {key: team[key] for key in ("task_id", "created", "running", "waiting",
                                                    "executor_tool_permissions", "capability_scope") if key in team}
                for key in ("status", "delegation_id", "problem_id", "result_ref", "result_hash"):
                    if key in value:
                        control[key] = value[key]
                # Dependency targets are control information, not expendable
                # report prose. Preserve them before optional child reports.
                failures = []
                groups = value.get("blocked_dependencies")
                if isinstance(groups, list):
                    for group in groups:
                        if isinstance(group, Mapping) and isinstance(group.get("failed_dependencies"), list):
                            failures.extend((group.get("delegation_id"), item)
                                            for item in group["failed_dependencies"])
                elif isinstance(value.get("failed_dependencies"), list):
                    failures = [(value.get("delegation_id"), item)
                                for item in value["failed_dependencies"]]
                dependency_rows = []
                valid_failure_count = 0
                for dependent, failure in failures:
                    if (not isinstance(failure, Mapping)
                            or not isinstance(failure.get("delegation_id"), str)
                            or not isinstance(failure.get("status"), str)):
                        continue
                    valid_failure_count += 1
                    if len(dependency_rows) >= 8:
                        continue
                    row = {key: failure[key] for key in (
                        "delegation_id", "problem_id", "generation", "status", "result_ref", "result_hash"
                    ) if key in failure}
                    if isinstance(dependent, str):
                        row["dependent_delegation_id"] = dependent
                    reason = failure.get("reason")
                    if isinstance(reason, str):
                        row["reason"] = reason[:512]
                        row["reason_truncated"] = len(reason) > 512
                    dependency_rows.append(row)
                if dependency_rows:
                    control.update(failed_dependencies=dependency_rows,
                                   dependency_failure_count=valid_failure_count,
                                   omitted_dependency_failure_count=valid_failure_count-len(dependency_rows))
                members = team.get("children")
                if isinstance(members, list) and all(
                    isinstance(member, Mapping) and isinstance(member.get("delegation_id"), str)
                    and bool(member["delegation_id"]) and isinstance(member.get("status"), str)
                    for member in members
                ):
                    self.index.refresh()
                    reports = {(entry.subject_id, entry.internal_cas_ref): entry.source_ref
                               for entry in self.index.entries if entry.kind == "child_result"}
                    children = []
                    for member in members:
                        child = {key: member[key] for key in ("delegation_id", "problem_id", "generation", "status",
                                                             "unknown_effect", "result_ref") if key in member}
                        result = member.get("result")
                        if isinstance(result, Mapping) and isinstance(result.get("status"), str):
                            child["result_status"] = result["status"]
                        reference = reports.get((member.get("delegation_id"), member.get("result_ref")))
                        if reference is not None:
                            child["report_source_ref"] = reference
                            child["read_report"] = {"operation": "read", "source_ref": reference,
                                                    "offset": 0, "max_bytes": self.history_query_max_bytes}
                        children.append(child)
                    control.update(children=children, child_count=len(children), omitted_child_count=0)
                    view = {
                        "status": "OK", "kind": "operation_result", "source_ref": source_ref,
                        "complete_value_visible": False, "value_view": "team-control-and-report-navigation",
                        "value": control,
                        "next_action": "SETTLED children have finished. Use complete_work_report_visible bodies; otherwise read the report using read_report. Integrate the result and perform only remaining checks. Do not keep waiting on the same settled result or retire it as a substitute for integration. A child success is not parent-task approval. Unknown effects still require reconciliation, never replay.",
                        "read_full_result": {"operation": "read", "source_ref": source_ref,
                                             "offset": 0, "max_bytes": self.history_query_max_bytes},
                    }
                    while children and len(canonical_json_bytes(view)) > self.history_query_max_bytes:
                        children.pop()
                        control["omitted_child_count"] += 1
                    if dependency_rows:
                        view["next_action"] = (
                            "Resolve the prerequisite named by failed_dependencies, not its waiting dependent. "
                            "For STALE_BINDING preserve completed files and arrange fresh verification of that "
                            "prerequisite against current requirements; do not treat its old report as current. "
                            "Handoff preserves resources and read_resources: omit those grant fields. "
                            "Read omitted details from read_full_result. No child report approves the parent; "
                            "unknown effects require reconciliation, never replay."
                        )
                        while len(dependency_rows) > 1 and len(canonical_json_bytes(view)) > self.history_query_max_bytes:
                            dependency_rows.pop()
                            control["omitted_dependency_failure_count"] += 1
                    if len(canonical_json_bytes(view)) <= self.history_query_max_bytes:
                        from .child_reports import validate_child_work_report
                        for number, child in enumerate(children):
                            result = members[number].get("result")
                            report = result.get("work_report") if isinstance(result, Mapping) else None
                            if not isinstance(report, Mapping):
                                continue
                            try:
                                report = validate_child_work_report(canonical_json_bytes(report).decode("utf-8"))
                            except ValueError:
                                continue
                            if report["status"] != child.get("result_status"):
                                continue
                            child.update(work_report=report, complete_work_report_visible=True)
                            if len(canonical_json_bytes(view)) > self.history_query_max_bytes:
                                child.pop("work_report")
                                child.pop("complete_work_report_visible")
                        return view
        return self.prompt_receipt_for_operation(operation_id)

    def _remember_assistant_note(
        self, source_ref: str, document: Mapping[str, Any], expected_text: str,
    ) -> None:
        result = document.get("result")
        if not isinstance(result, Mapping) or result.get("text") != expected_text:
            return
        # Only actual committed Assistant speech is retained. Reasoning and
        # generated summaries of absent speech never enter this projection.
        if not expected_text.strip() or len(expected_text.encode("utf-8")) > self.receipt_max_bytes:
            return
        entries = [entry for entry in self.index.entries if entry.source_ref == source_ref]
        if len(entries) != 1:
            raise ContextCoreError("task note has no unique committed source")
        entry = entries[0]
        if (entry.kind != "operation_result" or not entry.subject_id.startswith("provider-")
                or document.get("task_id") != self.index.task_id
                or document.get("operation_id") != entry.subject_id
                or document.get("effect_status") != "SUCCEEDED"
                or hashlib.sha256(canonical_json_bytes(document)).hexdigest() != entry.content_hash):
            raise ContextCoreError("task note source identity or content does not match committed history")
        for key in ("bound_goal_version", "bound_acceptance_version", "bound_input_seq"):
            if type(document.get(key)) is not int or document[key] < 0:
                raise ContextCoreError("task note source has no valid version binding")
        self._assistant_notes[source_ref] = {
            "schema": "SITINA_TASK_NOTE_V1",
            "task_id": self.index.task_id,
            "source_ref": source_ref, "text": expected_text,
            "source_content_hash": entry.content_hash,
            "source_revision": entry.stream_version,
            "confirmation_status": "UNCONFIRMED",
            "verification": "UNVERIFIED_MODEL_NOTE",
            "observed_binding": {"goal_version": document["bound_goal_version"],
                                 "acceptance_version": document["bound_acceptance_version"],
                                 "handled_input_seq": document["bound_input_seq"]},
        }
        while len(self._assistant_notes) > 12:
            # Keep the opening findings plus recent speech; paging chatter
            # must not evict every earlier observation from a long task.
            del self._assistant_notes[tuple(self._assistant_notes)[4]]

    def assistant_notes(self) -> list[Mapping[str, Any]]:
        """Detached, source-bound speech; notes cannot establish business success."""
        current = self.index.current_binding()
        notes = tuple(self._assistant_notes.values())
        sources = {entry.source_ref: entry for entry in self.index.entries}
        selected: dict[str, Mapping[str, Any]] = {}
        for note in (*notes[:4], *reversed(notes[4:])):
            row = json.loads(canonical_json_bytes(note))
            source = sources.get(row["source_ref"])
            if (source is None or source.content_hash != row["source_content_hash"]
                    or source.stream_version != row["source_revision"]
                    or row["task_id"] != self.index.task_id
                    or row["confirmation_status"] != "UNCONFIRMED"):
                raise ContextCoreError("task note provenance changed before context delivery")
            row["applicability"] = (
                "CURRENT_BINDING" if all(row["observed_binding"][key] == current[key]
                    for key in ("goal_version", "acceptance_version", "handled_input_seq"))
                else "PRIOR_BINDING_RECHECK_REQUIRED"
            )
            if len(canonical_json_bytes([*selected.values(), row])) > 2 * self.receipt_max_bytes:
                continue
            selected[str(row["source_ref"])] = row
        return [selected[str(note["source_ref"])] for note in notes
                if str(note["source_ref"]) in selected]

    def _externalize_older_tool_bodies(
        self, *, groups: Sequence[ProtocolMessageGroup] | None = None,
        one_body: bool = False, protect_latest: bool = True,
    ) -> tuple[tuple[ProtocolMessageGroup, ...], list[Mapping[str, Any]]]:
        """Retain thinking protocol while externalizing already delivered read bodies."""
        groups = list(self._groups if groups is None else groups)
        replacements: list[Mapping[str, Any]] = []
        target_bytes = 0 if one_body else self.protocol_groups_max_bytes

        def size() -> int:
            return len(_wire_json_bytes([message for group in groups for message in group.messages()]))

        if size() <= target_bytes:
            return tuple(groups), replacements
        self.index.refresh()
        entries = {entry.source_ref: entry for entry in self.index.entries}
        logical_ids: dict[str, str] | None = None
        # Earlier groups have already been presented. Preparation protects the
        # newest possibly unseen result; forecasting passes only groups from
        # last_prepared and keeps all pending results outside this sequence.
        for group_index, group in enumerate(groups[:-1] if protect_latest else groups):
            messages = list(group.tool_results)
            for result_index, message in enumerate(messages):
                if size() <= target_bytes:
                    return tuple(groups), replacements
                if message.get("is_error"):
                    continue
                if message.get("name") == "sitina_history_query":
                    content = message.get("content")
                    if not isinstance(content, str):
                        continue
                    try:
                        envelope = json.loads(content)
                    except (ValueError, TypeError):
                        continue
                    view = envelope.get("result") if isinstance(envelope, Mapping) else None
                    if (not isinstance(view, Mapping) or view.get("status") != "OK"
                            or not isinstance(view.get("readable_text"), str)
                            or view.get("query", {}).get("operation") != "read"):
                        continue
                    # A history page names the underlying source, not its own
                    # receipt. Bind the tool call to the native intent exactly
                    # as cold protocol reconstruction does.
                    if logical_ids is None:
                        logical_ids = {str(event.payload.get("operation_id") or ""):
                                       str(event.payload.get("logical_operation_id") or "")
                                       for event in self.index.store.task_events(self.index.task_id)
                                       if event.event_type == "loop.operation-intent-recorded"}
                    providers = [entries[ref] for ref in group.source_refs
                                 if ref in entries and entries[ref].subject_id.startswith("provider-")]
                    if len(providers) != 1:
                        raise ContextCoreError("old history page has no unique Provider receipt")
                    prefix = logical_ids.get(providers[0].subject_id, "").split(":provider-turn:", 1)[0]
                    matches = [entries[ref] for ref in group.source_refs if ref in entries
                               and entries[ref].kind == "operation_result" and prefix
                               and logical_ids.get(entries[ref].subject_id, "").startswith(prefix + ":")
                               and logical_ids.get(entries[ref].subject_id, "").endswith(":" + str(message["tool_call_id"]))]
                    if len(matches) != 1:
                        raise ContextCoreError("old history page has no unique committed tool receipt")
                    entry = matches[0]
                    reference = entry.source_ref
                    original = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
                    result = original.get("result", {})
                    if (original.get("effect_status") != "SUCCEEDED"
                            or result.get("tool") != "sitina_history_query" or result.get("status") != "ok"
                            or not isinstance(result.get("value"), Mapping)):
                        raise ContextCoreError("old history page is not a committed successful read")
                    expected_envelope = json.loads(PromptIsolationPolicy().wrap_tool_result(
                        tool_name="sitina_history_query", status="ok",
                        value=self.model_history_page(result["value"]),
                    ))
                    if canonical_json_bytes(envelope) != canonical_json_bytes(expected_envelope):
                        raise ContextCoreError("old history page differs from its committed successful read")
                    locator = {
                        **{key: item for key, item in view.items() if key not in {"readable_text", "data_base64"}},
                        "complete_value_visible": False,
                        "body_residency": "EXTERNALIZED_TO_HISTORY",
                        "body_notice": "Previously delivered page; its body is no longer in this request. Use the saved source and exact range only if a reread is needed.",
                        "history_query": {
                            "tool": "sitina_history_query", "operation": "read",
                            "source_ref": view["source_ref"], "offset": view["offset"],
                            "end_offset": view["offset"] + view["returned_bytes"],
                            "max_bytes": self.history_query_max_bytes,
                        },
                    }
                else:
                    if message.get("name") != "sitina_read_file" or message.get("is_error"):
                        continue
                    content = message.get("content")
                    if not isinstance(content, str):
                        continue
                    try:
                        envelope = json.loads(content)
                    except (ValueError, TypeError):
                        continue
                    view = envelope.get("result") if isinstance(envelope, Mapping) else None
                    if (not isinstance(view, Mapping) or view.get("kind") != "operation_result"
                            or view.get("complete_value_visible") is not True):
                        continue
                    value = view.get("value")
                    if (not isinstance(value, Mapping) or value.get("exists") is not True
                            or not isinstance(value.get("content"), str)):
                        continue
                    reference = view.get("source_ref")
                    entry = entries.get(reference)
                    if (entry is None or entry.kind != "operation_result"
                            or reference not in group.source_refs):
                        raise ContextCoreError("old tool body has no committed task-local source")
                    original = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
                    result = original.get("result", {})
                    if (original.get("effect_status") != "SUCCEEDED"
                            or result.get("tool") != "sitina_read_file" or result.get("status") != "ok"):
                        raise ContextCoreError("old file body differs from its committed successful read")
                    # ToolResult.content applies the handoff redaction boundary.
                    # Compare that exact model view, never raw CAS with redacted data.
                    expected_envelope = json.loads(PromptIsolationPolicy().wrap_tool_result(
                        tool_name="sitina_read_file", status="ok",
                        value={"status": "OK", "kind": "operation_result", "source_ref": reference,
                               "complete_value_visible": True, "value": result.get("value")},
                    ))
                    if canonical_json_bytes(envelope) != canonical_json_bytes(expected_envelope):
                        raise ContextCoreError("old file body differs from its committed successful read")
                    locator = {
                        **dict(view),
                        "complete_value_visible": False,
                        "value": {key: item for key, item in value.items() if key != "content"},
                        "body_residency": "EXTERNALIZED_TO_HISTORY",
                        "body_notice": "History locator only; the original file body is not present. Read the saved source, not the file again.",
                        "source_content_hash": entry.content_hash,
                        "history_query": {
                            "tool": "sitina_history_query", "operation": "read",
                            "source_ref": reference, "offset": 0, "max_bytes": self.history_query_max_bytes,
                        },
                    }
                replacement = canonical_json_bytes({**envelope, "result": locator}).decode("utf-8")
                before_bytes = len(_wire_json_bytes(message))
                after_bytes = len(_wire_json_bytes({**message, "content": replacement}))
                if after_bytes >= before_bytes:
                    continue
                messages[result_index] = {**message, "content": replacement}
                groups[group_index] = ProtocolMessageGroup(group.assistant, tuple(messages), group.source_refs)
                replacements.append({
                    "source_ref": reference, "source_content_hash": entry.content_hash,
                    "tool_call_id": message["tool_call_id"],
                    "before_content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "after_content_hash": hashlib.sha256(replacement.encode("utf-8")).hexdigest(),
                    "byte_scope": "serialized-tool-message", "before_bytes": before_bytes, "after_bytes": after_bytes,
                    "replacement_content": replacement,
                })
                if one_body:
                    return tuple(groups), replacements
        # Reasoning, assistant speech and the newest result can exceed the soft
        # target. Exact hard-cap admission still decides whether they fit.
        return tuple(groups), replacements

    def _thinking_protocol_trials(
        self, *, groups: Sequence[ProtocolMessageGroup] | None = None,
        protect_latest: bool = True,
    ):
        """Forecast and prepare use the same authenticated body-residency policy."""
        selected = tuple(self._groups if groups is None else groups)
        replacements: list[Mapping[str, Any]] = []
        while True:
            # Try the exact full request first. Only already delivered bodies
            # may become locators; reasoning and the newest results stay intact.
            yield selected, list(replacements)
            selected, removed = self._externalize_older_tool_bodies(
                groups=selected, one_body=True, protect_latest=protect_latest,
            )
            if not removed:
                return
            replacements.extend(removed)

    def record_protocol_group(
        self,
        assistant: Mapping[str, Any],
        tool_results: Sequence[Mapping[str, Any]],
        source_refs: Sequence[str],
    ) -> None:
        group = ProtocolMessageGroup.from_committed_history(
            self.index, assistant, tool_results, source_refs,
        )
        self._groups.append(group)
        text = assistant.get("content")
        if isinstance(text, str) and text.strip():
            providers = [entry for entry in self.index.entries
                         if entry.source_ref in group.source_refs
                         and entry.kind == "operation_result"
                         and entry.subject_id.startswith("provider-")]
            if len(providers) == 1:
                entry = providers[0]
                document = self.index.store.read_json(
                    entry.internal_cas_ref, expected_hash=entry.content_hash,
                )
                self._remember_assistant_note(entry.source_ref, document, text)

    def restore_protocol_groups_from_history(self) -> int:
        """Rebuild committed assistant/tool groups after a host restart.

        The in-memory assembler is intentionally empty on construction.  A
        restart may only reuse groups whose Provider turn and every paired tool
        result are still proof-visible in the task history; incomplete groups
        fence recovery instead of silently replaying a completed effect.
        """

        self.index.refresh()
        events = self.index.store.task_events(self.index.task_id)
        logical_ids: dict[str, str] = {}
        business_attempts: dict[str, str | None] = {}
        result_docs: dict[str, Mapping[str, Any]] = {}
        result_bindings: dict[str, tuple[str, str]] = {}
        execution_owners: dict[str, str | None] = {}
        event_positions: dict[str, int] = {}
        for event in events:
            if event.event_type == "loop.operation-intent-recorded":
                operation_id = str(event.payload.get("operation_id") or "")
                logical_ids[operation_id] = str(event.payload.get("logical_operation_id") or "")
                if self.scope_execution_owner is not None:
                    intent_document = self.index.store.read_json(str(event.payload["intent_ref"]), expected_hash=str(event.payload["intent_hash"]))
                    execution_owners[operation_id] = intent_document.get("execution_owner")
                business_attempts[operation_id] = (
                    str(event.payload.get("business_attempt_id"))
                    if event.payload.get("business_attempt_id") is not None
                    else None
                )
            elif event.event_type == "loop.operation-result-recorded":
                operation_id = str(event.payload.get("operation_id") or "")
                result_docs[operation_id] = self.index.store.read_json(
                    str(event.payload["result_ref"]), expected_hash=str(event.payload["result_hash"])
                )
                result_bindings[operation_id] = (str(event.payload["result_ref"]), str(event.payload["result_hash"]))
                event_positions[operation_id] = int(event.position)
        # A rejected atomic batch has a successful provider receipt but no
        # tool intents. Restore that exact native fact, never fake tool results.
        undispatched_turns: set[str] = set()
        for event in events:
            if (event.event_type != "loop.attempt-settled"
                    or not str(event.payload.get("blocker_id", "")).startswith("goal-completion:")
                    or (self.scope_attempt_ids and event.payload.get("attempt_id") not in self.scope_attempt_ids)):
                continue
            settlement = self.index.store.read_json(
                event.payload["settlement_ref"], expected_hash=event.payload["settlement_hash"],
            )
            rejection_prefix = (
                "Invalid completion tool request: goal completion permits only "
                "sitina_history_query; rejected tools: "
            )
            outcome = settlement.get("outcome")
            closing = settlement.get("closing_binding")
            refs = settlement.get("evidence_refs")
            if (not isinstance(outcome, str) or not outcome.startswith(rejection_prefix)
                    or settlement.get("task_id") != self.index.task_id
                    or settlement.get("attempt_id") != event.payload.get("attempt_id")
                    or settlement.get("count_effect") != "COUNT_NEUTRAL"
                    or not str(settlement.get("blocker_id", "")).startswith("goal-completion:")
                    or not isinstance(closing, Mapping) or not isinstance(refs, list)
                    or not isinstance(settlement.get("planned_artifact_ref"), str)
                    or not settlement["planned_artifact_ref"]
                    or settlement.get("planned_artifact_ref") != closing.get("artifact_ref")):
                continue
            rejected_candidates: list[str] = []
            for provider_id, document in result_docs.items():
                if (not provider_id.startswith("provider-")
                        or document.get("effect_status") != "SUCCEEDED"
                        or business_attempts.get(provider_id) != settlement.get("attempt_id")
                        or result_bindings[provider_id][0] not in refs
                        or event_positions[provider_id] >= int(event.position)
                        or any(document.get(field) != settlement.get(key)
                               or closing.get(key) != settlement.get(key)
                               for field, key in (("bound_goal_version", "goal_version"),
                                                  ("bound_acceptance_version", "acceptance_version"),
                                                  ("bound_input_seq", "handled_input_seq")))):
                    continue
                result = document.get("result")
                calls = result.get("tool_calls") if isinstance(result, Mapping) else None
                if (not isinstance(calls, list) or not calls
                        or not all(isinstance(call, Mapping)
                                   and isinstance(call.get("id"), str) and bool(call["id"])
                                   and isinstance(call.get("name"), str) and bool(call["name"])
                                   and isinstance(call.get("arguments"), Mapping) for call in calls)
                        or len({call["id"] for call in calls}) != len(calls)):
                    continue
                forbidden = [call["name"] for call in calls if call["name"] != "sitina_history_query"]
                if not forbidden or outcome != rejection_prefix + ", ".join(forbidden):
                    continue
                logical = logical_ids.get(provider_id, "")
                if ":provider-turn:" not in logical:
                    continue
                run_prefix = logical.split(":provider-turn:", 1)[0] + ":"
                if any(value.startswith(run_prefix)
                       and any(value.endswith(":" + call["id"]) for call in calls)
                       for value in logical_ids.values()):
                    continue
                rejected_candidates.append(provider_id)
            if len(rejected_candidates) == 1:
                # The completion runtime rejects this whole batch before its
                # first tool hook. Keep the native rejection and proposal in
                # the index, but there is no executed protocol group to replay.
                undispatched_turns.add(rejected_candidates[0])
        for event in events:
            if event.event_type != "loop.review-repair-recorded":
                continue
            repair = self.index.store.read_json(event.payload["repair_ref"], expected_hash=event.payload["repair_hash"])
            detail = repair.get("detail") if isinstance(repair, Mapping) else None
            prefix = "UNDISPATCHED_HISTORY_BATCH_CAPACITY: "
            if not isinstance(detail, str) or not detail.startswith(prefix):
                continue
            batch = json.loads(detail[len(prefix):])
            provider_id = batch.get("provider_operation_id")
            document = result_docs.get(provider_id)
            result = document.get("result") if isinstance(document, Mapping) else None
            binding = batch.get("context_binding")
            if (repair.get("task_id") != self.index.task_id or not isinstance(binding, Mapping)
                    or not isinstance(result, Mapping) or document.get("effect_status") != "SUCCEEDED"
                    or business_attempts.get(provider_id) != batch.get("attempt_id")
                    or repair.get("artifact_ref") != binding.get("artifact_ref")
                    or event_positions.get(provider_id, int(event.position)) >= int(event.position)
                    or any(document.get(field) != binding.get(key) for field, key in
                           (("bound_goal_version", "goal_version"),
                            ("bound_acceptance_version", "acceptance_version"),
                            ("bound_input_seq", "handled_input_seq")))):
                raise ContextCoreError("undispatched review batch lost its native provider binding")
            calls = result.get("tool_calls")
            expected = [{"call_id": call["id"], "tool": call["name"], "arguments": call["arguments"],
                         "state": "NOT_DISPATCHED"} for call in calls] if isinstance(calls, list) else []
            if (len(expected) < 2 or batch.get("calls") != expected
                    or any(call["tool"] != "sitina_history_query" or call["arguments"].get("operation") != "read"
                           for call in expected)):
                raise ContextCoreError("undispatched review batch does not match the original calls")
            run_prefix = logical_ids[provider_id].split(":provider-turn:", 1)[0] + ":"
            if any(logical.startswith(run_prefix) and any(logical.endswith(":" + call["call_id"])
                    for call in expected) for logical in logical_ids.values()):
                raise ContextCoreError("undispatched review batch has a tool intent; recovery must reconcile it")
            undispatched_turns.add(provider_id)
        # Reading facts survive protocol-window eviction within this attempt
        # chain. Other agents and later completion checks did not deliver pages
        # to this reviewer, and cannot alter its recovered navigation state.
        for operation_id, document in sorted(result_docs.items(), key=lambda item: event_positions.get(item[0], 0)):
            if (self.scope_attempt_ids or self._review_scope_enforced) and business_attempts.get(operation_id) not in self.scope_attempt_ids:
                continue
            if self.scope_execution_owner is not None and execution_owners.get(operation_id) != self.scope_execution_owner:
                continue
            result = document.get("result") if isinstance(document, Mapping) else None
            if (not isinstance(result, Mapping) or result.get("tool") != "sitina_history_query"
                    or result.get("status") != "ok" or not isinstance(result.get("value"), Mapping)):
                continue
            self._observe_history_source(
                result["value"], operation_id=operation_id,
                binding={"goal_version": document["bound_goal_version"],
                         "acceptance_version": document["bound_acceptance_version"],
                         "handled_input_seq": document["bound_input_seq"]},
            )
        groups: list[ProtocolMessageGroup] = []
        for operation_id, document in sorted(result_docs.items(), key=lambda item: event_positions.get(item[0], 0)):
            if not operation_id.startswith("provider-"):
                continue
            if operation_id in undispatched_turns:
                continue
            result = document.get("result") if isinstance(document, Mapping) else None
            if not isinstance(result, Mapping):
                continue
            calls = result.get("tool_calls")
            if not calls:
                continue
            if not isinstance(calls, list):
                raise ContextCoreError("committed Provider protocol group is malformed")
            if (self.scope_attempt_ids or self._review_scope_enforced) and business_attempts.get(operation_id) not in self.scope_attempt_ids:
                continue
            if self.scope_execution_owner is not None and execution_owners.get(operation_id) != self.scope_execution_owner:
                continue
            provider_entry = next(
                (entry for entry in self.index.entries
                 if entry.kind == "operation_result" and entry.subject_id == operation_id),
                None,
            )
            if provider_entry is None:
                raise ContextCoreError("committed Provider protocol group has no visible turn receipt")
            tool_results: list[Mapping[str, Any]] = []
            source_refs = [provider_entry.source_ref]
            provider_logical_id = logical_ids.get(operation_id, "")
            run_prefix = provider_logical_id.split(":provider-turn:", 1)[0]
            # Preflight can stop after a Provider proposal is committed but
            # before a history/file read or native launch operation is admitted. Such a proposal
            # has no executed protocol group to restore. Keep its original
            # receipt in the index; do not invent results or read credit.
            # Any matching intent (even without a result) retains the strict
            # reconciliation path below, as does a partially executed batch.
            if run_prefix and ":provider-turn:" in provider_logical_id and all(
                isinstance(call, Mapping)
                and isinstance(call.get("id"), str) and bool(call["id"])
                and (
                    call.get("name") == "sitina_history_query"
                    or (document.get("effect_status") == "SUCCEEDED"
                        and call.get("name") in {
                            "sitina_exec", "sitina_shell", "sitina_process_start",
                            "sitina_read_file", "sitina_grep",
                        })
                )
                and isinstance(call.get("arguments"), Mapping)
                for call in calls
            ):
                proposed_ids = {call["id"] for call in calls}
                if len(proposed_ids) == len(calls) and not any(
                    logical.startswith(run_prefix + ":")
                    and any(logical.endswith(":" + call_id) for call_id in proposed_ids)
                    for logical in logical_ids.values()
                ):
                    continue
            for call in calls:
                if not isinstance(call, Mapping) or not str(call.get("id") or ""):
                    raise ContextCoreError("committed Provider tool call is malformed")
                call_id = str(call["id"])
                matches = [
                    candidate for candidate, logical in logical_ids.items()
                    if candidate in result_docs
                    and (
                        (not self.scope_attempt_ids and not self._review_scope_enforced)
                        or business_attempts.get(candidate) in self.scope_attempt_ids
                    )
                    and (self.scope_execution_owner is None or execution_owners.get(candidate) == self.scope_execution_owner)
                    and logical.startswith(run_prefix + ":")
                    and logical.endswith(":" + call_id)
                ]
                explicit = [candidate for candidate in matches
                            if isinstance(result_docs[candidate].get("result"), Mapping)
                            and "invocation_binding" in result_docs[candidate]["result"]]
                if explicit:
                    matches = explicit
                if len(matches) != 1:
                    raise ContextCoreError("committed protocol group is missing an unambiguous tool result")
                tool_operation_id = matches[0]
                entry = next(
                    (item for item in self.index.entries
                     if item.kind == "operation_result" and item.subject_id == tool_operation_id),
                    None,
                )
                if entry is None:
                    raise ContextCoreError("committed tool result is not proof-visible")
                tool_document = result_docs[tool_operation_id]
                tool_result = tool_document.get("result")
                if not isinstance(tool_result, Mapping):
                    raise ContextCoreError("committed tool result is malformed")
                if "invocation_binding" in tool_result:
                    from .tool_invocations import bound_invocation_result
                    try:
                        actual_id = bound_invocation_result(call=call, run_id=run_prefix, receipt=tool_result,
                            result_docs=result_docs, result_bindings=result_bindings)
                    except ValueError as error:
                        raise ContextCoreError(str(error)) from error
                    actual_entry = next((item for item in self.index.entries
                        if item.kind == "operation_result" and item.subject_id == actual_id), None)
                    if actual_entry is None:
                        raise ContextCoreError("bound invocation original result is not proof-visible")
                    source_refs.append(entry.source_ref)
                    tool_operation_id, entry = actual_id, actual_entry
                tool_name = str(call.get("name") or "")
                tool_status = str(tool_result.get("status") or "error")
                self.observe_committed_tool_result(
                    tool_operation_id, tool_name=tool_name, status=tool_status,
                    value=tool_result.get("value"),
                    binding={"goal_version": tool_document["bound_goal_version"],
                             "acceptance_version": tool_document["bound_acceptance_version"],
                             "handled_input_seq": tool_document["bound_input_seq"]},
                )
                if tool_name == "sitina_history_query" and tool_status == "ok":
                    # Live history calls expose the bounded native page itself.
                    # A receipt of that receipt changes its source and cursor.
                    tool_value = tool_result.get("value")
                    if not isinstance(tool_value, Mapping):
                        raise ContextCoreError("committed history result has no native page")
                    tool_value = self.model_history_page(tool_value)
                else:
                    tool_value = self.model_tool_value(
                        tool_operation_id, tool_name=tool_name, status=tool_status,
                        value=tool_result.get("value"),
                    )
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": tool_name,
                    "content": PromptIsolationPolicy().wrap_tool_result(
                        tool_name=tool_name, status=tool_status, value=tool_value,
                    ),
                    "is_error": tool_status != "ok",
                })
                source_refs.append(entry.source_ref)
            assistant = {
                "role": "assistant",
                "content": str(result.get("text") or ""),
                "tool_calls": [dict(call) for call in calls],
                **(
                    {"reasoning_content": result.get("reasoning_content")}
                    if result.get("reasoning_content")
                    else {}
                ),
            }
            self._remember_assistant_note(
                provider_entry.source_ref, document, str(result.get("text") or ""),
            )
            groups.append(
                ProtocolMessageGroup.from_committed_history(
                    self.index, assistant, tool_results, source_refs
                )
            )
        # Restore only replacements tied to a successful, byte-matched physical
        # request. Prepared-only receipts cannot establish delivered residency.
        restored_receipts: list[Mapping[str, Any]] = []
        seen_receipts: set[str] = set()
        entries = {entry.source_ref: entry for entry in self.index.entries}
        for operation_id, document in sorted(result_docs.items(), key=lambda item: event_positions.get(item[0], 0)):
            if (not operation_id.startswith("provider-")
                    or ((self.scope_attempt_ids or self._review_scope_enforced) and business_attempts.get(operation_id) not in self.scope_attempt_ids)):
                continue
            metadata = document.get("result", {}).get("metadata", {})
            sent_hash = metadata.get("request_body_hash")
            if (not isinstance(sent_hash, str) or metadata.get("sitina_admitted_body_hash") != sent_hash
                    or type(metadata.get("physical_send_count")) is not int or metadata["physical_send_count"] < 1):
                continue
            for receipt in metadata.get("sitina_context_compaction_receipts", ()):
                if (receipt.get("schema") != "SITINA_LOOP_CONTEXT_COMPACTION_RECEIPT_V1"
                        or receipt.get("trigger_request_body_hash") != sent_hash):
                    raise ContextCoreError("persisted compaction is not bound to its sent request")
                replacements = receipt.get("tool_result_replacements", ())
                receipt_identity = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
                if receipt_identity in seen_receipts:
                    continue
                for replacement in replacements:
                    reference = replacement["source_ref"]
                    entry = entries.get(reference)
                    if entry is None or entry.content_hash != replacement["source_content_hash"]:
                        raise ContextCoreError("persisted externalized tool source is no longer authenticated")
                    matches = [
                        (group_index, result_index) for group_index, group in enumerate(groups)
                        if reference in group.source_refs
                        for result_index, message in enumerate(group.tool_results)
                        if message.get("tool_call_id") == replacement["tool_call_id"]
                    ]
                    if len(matches) != 1:
                        raise ContextCoreError("persisted externalized tool has no unique protocol pair")
                    group_index, result_index = matches[0]
                    group = groups[group_index]
                    messages = list(group.tool_results)
                    prior = messages[result_index]
                    content = replacement["replacement_content"]
                    if (hashlib.sha256(str(prior["content"]).encode("utf-8")).hexdigest() != replacement["before_content_hash"]
                            or hashlib.sha256(content.encode("utf-8")).hexdigest() != replacement["after_content_hash"]
                            or len(_wire_json_bytes(prior)) != replacement["before_bytes"]
                            or len(_wire_json_bytes({**prior, "content": content})) != replacement["after_bytes"]
                            or replacement["after_bytes"] >= replacement["before_bytes"]):
                        raise ContextCoreError("persisted tool-body replacement differs from the original or saved locator")
                    messages[result_index] = {**prior, "content": content}
                    groups[group_index] = ProtocolMessageGroup(group.assistant, tuple(messages), group.source_refs)
                seen_receipts.add(receipt_identity)
                restored_receipts.append(dict(receipt))
        if self.role == "main" and self.execution_context.get("phase") == "goal_completion":
            # Authenticate all historical pairs and compaction replacements
            # before choosing live conversation residency. A prior completion
            # attempt remains readable history; it is not this candidate's
            # assistant/tool conversation. Source/read caches retain their
            # original observed bindings and never gain current read credit.
            current = self.index.current_binding()
            current_provider_refs: set[str] = set()
            for entry in self.index.entries:
                if entry.kind != "operation_result":
                    continue
                document = result_docs.get(entry.subject_id)
                result = document.get("result") if isinstance(document, Mapping) else None
                if (not isinstance(result, Mapping)
                        or result.get("work_purpose") != "goal_completion"):
                    continue
                if (document["bound_goal_version"] == current["goal_version"]
                        and document["bound_acceptance_version"] == current["acceptance_version"]
                        and document["bound_input_seq"] == current["handled_input_seq"]):
                    current_provider_refs.add(entry.source_ref)
            groups = [group for group in groups
                      if current_provider_refs.intersection(group.source_refs)]
        self._groups = groups
        if restored_receipts:
            self.compaction_receipts = restored_receipts
            self.compaction_count = len(restored_receipts)
            last = restored_receipts[-1]
            self._last_compaction_signature = hashlib.sha256(canonical_json_bytes({
                "binding": last["binding"], "before": last["before_residency"],
                "after": last["after_residency"], "removed": last["removed_residency"],
            })).hexdigest()
        return len(groups)

    def history_reads_in_last_request(self) -> list[Mapping[str, Any]]:
        """Return native read pages in the exact admitted protocol groups."""

        if self.last_prepared is None:
            return []
        return self._history_reads_in_selection(self.last_prepared.protocol_groups)

    @staticmethod
    def _history_reads_in_selection(selection: ProtocolGroupSelection) -> list[Mapping[str, Any]]:
        reads: list[Mapping[str, Any]] = []
        for group in selection.groups:
            calls: dict[str, Mapping[str, Any]] = {}
            for message in group.messages():
                if message.get("role") == "assistant":
                    calls = {
                        str(call["id"]): call
                        for call in message.get("tool_calls", ())
                        if isinstance(call, Mapping) and call.get("id")
                    }
                    continue
                if message.get("role") != "tool" or message.get("is_error"):
                    continue
                call = calls.get(str(message.get("tool_call_id") or ""))
                if (call is None or call.get("name") != "sitina_history_query"
                        or not isinstance(call.get("arguments"), Mapping)):
                    continue
                content = json.loads(str(message["content"]))
                if (not isinstance(content, Mapping)
                        or content.get("schema") != "SITINA_UNTRUSTED_TOOL_DATA_V1"
                        or content.get("tool") != "sitina_history_query"
                        or content.get("status") != "ok"):
                    continue
                page = content.get("result")
                if (not isinstance(page, Mapping)
                        or page.get("body_residency") == "EXTERNALIZED_TO_HISTORY"):
                    continue
                reads.append({
                    "name": "sitina_history_query", "status": "ok",
                    "arguments": dict(call["arguments"]), "result": dict(page),
                })
        return reads

    def _model_execution_context(self) -> dict[str, Any]:
        """Project technical evidence and large scopes without changing Host authority."""
        context = dict(self.execution_context)
        if context.get("phase") == "goal_completion":
            def technical_evidence_rows(rows: list[Any]) -> list[Any]:
                projected = []
                for row in rows:
                    if not isinstance(row, Mapping):
                        projected.append(row)
                        continue
                    item = dict(row)
                    if "host_observation_satisfied" in item:
                        item["host_evidence_preconditions_satisfied"] = item.pop("host_observation_satisfied")
                    projected.append(item)
                return projected

            contract = context.get("response_contract")
            if isinstance(contract, Mapping) and isinstance(contract.get("condition_requirements"), list):
                context["response_contract"] = {
                    **contract, "condition_requirements": technical_evidence_rows(contract["condition_requirements"]),
                }
            evidence = context.get("business_evidence")
            if isinstance(evidence, Mapping) and isinstance(evidence.get("condition_observations"), list):
                context["business_evidence"] = {
                    **evidence, "condition_observations": technical_evidence_rows(evidence["condition_observations"]),
                }
            context["host_evidence_interpretation"] = (
                "host_evidence_preconditions_satisfied reports technical evidence prerequisites only: "
                "true is not business approval; false is a missing prerequisite; null means no Host assessment. "
                "Judge each original acceptance condition against the actual outcome. A running producer "
                "does not prove a required consuming operation succeeded. Historical Host observation "
                "labels have the same technical meaning and never replace this judgment."
            )
            return context
        if self.role != "reviewer" or context.get("phase") != "independent_read_only_review":
            return context
        roles = context.get("review_source_roles")
        contract = context.get("response_contract")
        rules = contract.get("rules") if isinstance(contract, Mapping) else None
        if not isinstance(roles, list) or not isinstance(rules, list):
            return context
        if not (any(isinstance(row, Mapping) and isinstance(row.get("paths"), list)
                    and len(row["paths"]) > 100 for row in roles)
                or any(isinstance(row, Mapping) and isinstance(row.get("allowed_object_ids"), list)
                       and len(row["allowed_object_ids"]) > 100 for row in rules)):
            return context
        current = self.index.current_binding()
        reference = context.get("artifact_source_ref")
        entry = next((row for row in self.index.entries
                      if row.source_ref == reference and row.kind == "artifact"
                      and row.internal_cas_ref == current["artifact_ref"]), None)
        if entry is None or contract.get("artifact_ref") != current["artifact_ref"]:
            return context
        cache_key = (entry.source_ref, entry.content_hash)
        cached = getattr(self, "_review_scope_artifact_cache", None)
        if cached is None or cached[0] != cache_key:
            artifact = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            self._review_scope_artifact_cache = (cache_key, artifact)
        else:
            artifact = cached[1]
        changed = artifact.get("changed_paths")
        if (artifact.get("schema") != "SITINA_LOOP_ARTIFACT_V1"
                or artifact.get("task_id") != self.index.task_id
                or not isinstance(changed, list)
                or any(not isinstance(path, str) or not path for path in changed)):
            return context
        changed_ids = list(dict.fromkeys(changed))
        changed_set = set(changed_ids)
        projected_rules = []
        for rule in rules:
            projected = dict(rule)
            objects = rule.get("allowed_object_ids")
            if (isinstance(objects, list) and len(objects) > 100
                    and all(isinstance(value, str) and value for value in objects)):
                additional = [value for value in objects if value not in changed_set]
                restored = list(dict.fromkeys([*changed_ids, *additional])) or ["workspace-root"]
                if restored == objects:
                    projected.pop("allowed_object_ids")
                    projected["allowed_object_ids_source"] = {
                        "source_ref": reference, "source_content_hash": entry.content_hash,
                        "field": "changed_paths", "additional_object_ids": additional,
                        "empty_scope_object_id": "workspace-root", "object_count": len(objects),
                        "interpretation": "Exact object IDs are the stable union of the referenced changed_paths and additional_object_ids. Use original strings, not absolute paths or array indexes. This locator grants no reading or approval credit.",
                    }
            projected_rules.append(projected)
        projected_roles = []
        for role in roles:
            projected = dict(role)
            paths = role.get("paths")
            if (role.get("source_ref") == reference and role.get("source_role") == "current_artifact"
                    and isinstance(paths, list) and len(paths) > 100):
                from pathlib import Path
                root = artifact.get("workspace_path")
                if isinstance(root, str) and Path(root).is_absolute():
                    restored_paths = sorted({str((Path(root) / path).resolve(strict=False)) for path in changed})
                    if restored_paths == paths:
                        projected.pop("paths")
                        projected["paths_source"] = {
                            "source_ref": reference, "source_content_hash": entry.content_hash,
                            "workspace_field": "workspace_path", "paths_field": "changed_paths",
                            "path_count": len(paths),
                            "interpretation": "Resolve each referenced changed_path under workspace_path. Host retains and checks the exact canonical allowlist; this locator adds no permission or evidence credit.",
                        }
            projected_roles.append(projected)
        context["review_source_roles"] = projected_roles
        context["response_contract"] = {**contract, "rules": projected_rules}
        return context

    @staticmethod
    def _review_material_pages(
        progress: dict[str, Any], *, submission_ref: str | None,
        resident: Mapping[tuple[Any, ...], Sequence[Sequence[int]]], max_bytes: int,
    ) -> list[Mapping[str, Any]]:
        """Carry bounded immutable content; historical coverage is not residency."""
        pages = list(progress.pop("prepared_source_pages"))
        retained = progress.pop("retained_prepared_source_pages")
        visible = {key: [list(interval) for interval in ranges] for key, ranges in resident.items()}

        def key(page: Mapping[str, Any]) -> tuple[Any, ...]:
            return (page["source_ref"], page["content_hash"], page["content_projection"])

        def add(page: Mapping[str, Any]) -> None:
            visible.setdefault(key(page), []).append(
                [page["offset"], page["offset"] + page["returned_bytes"]])

        def covers(page: Mapping[str, Any]) -> bool:
            cursor = page["offset"]
            end = cursor + page["returned_bytes"]
            for start, stop in sorted(visible.get(key(page), ())):
                if start > cursor:
                    break
                cursor = max(cursor, stop)
                if cursor >= end:
                    return True
            return False

        for page in pages:
            add(page)
        selected_refs = list(dict.fromkeys((
            *((submission_ref,) if isinstance(submission_ref, str) else ()),
            *progress["required_source_refs"],
        )))
        order = {ref: i for i, ref in enumerate(selected_refs)}
        used = 0
        source_versions = {key(row) for row in progress["read_sources"]}
        for page in sorted((page for page in retained
                            if page["source_ref"] in order and key(page) in source_versions),
                           key=lambda page: (order[page["source_ref"]], page["offset"])):
            if covers(page):
                continue
            size = len(canonical_json_bytes(page))
            if used + size > max_bytes:
                continue
            pages.append(page)
            used += size
            add(page)

        rows = []
        for original in progress["read_sources"]:
            row = dict(original)
            ranges: list[list[int]] = []
            for start, stop in sorted(visible.get(key(row), ())):
                start, stop = max(0, start), min(row["total_bytes"], stop)
                if stop <= start:
                    continue
                if ranges and start <= ranges[-1][1]:
                    ranges[-1][1] = max(ranges[-1][1], stop)
                else:
                    ranges.append([start, stop])
            row["resident_read_ranges"] = ranges
            row["complete_source_resident"] = ranges == [[0, row["total_bytes"]]]
            cursor = ranges[0][1] if ranges and ranges[0][0] == 0 else 0
            row["next_material_read"] = (
                {"operation": "read", "source_ref": row["source_ref"], "view": row["view"],
                 "offset": cursor, "max_bytes": max_bytes}
                if cursor < row["total_bytes"] else None)
            rows.append(row)
        progress["read_sources"] = rows
        progress["context_material"] = {
            "retained_page_bytes": used, "retained_page_budget_bytes": max_bytes,
            "interpretation": "Ranges contain actual content in this request candidate, not a new send receipt or business approval. Historical complete_source_read does not imply current residency. Recall only content needed for an unresolved claim, using next_material_read when it is absent.",
        }
        return pages

    def _context_document(
        self, projection: TaskContextProjection, selection: ProtocolGroupSelection,
        *, include_progress: bool, include_file_views: bool,
        runtime_feedback: Mapping[str, Any] | None,
    ) -> Mapping[str, Any]:
        execution_context = self._model_execution_context()
        history_sources = self.history_read_sources(include_views=include_progress)
        resident: dict[tuple[Any, ...], list[list[int]]] = {}
        for item in self._history_reads_in_selection(selection):
            page = item["result"]
            if (page.get("schema") != "SITINA_LOOP_HISTORY_READ_V1" or page.get("status") != "OK"
                    or type(page.get("offset")) is not int or type(page.get("returned_bytes")) is not int):
                continue
            key = (page.get("source_ref"), page.get("content_hash"), page.get("content_projection"))
            resident.setdefault(key, []).append([page["offset"], page["offset"] + page["returned_bytes"]])
        by_ref = {}
        for row in history_sources:
            intervals = resident.get((row["source_ref"], row["read_content_hash"],
                                     row["last_history_page"].get("content_projection")), [])
            merged: list[list[int]] = []
            for start, end in sorted(intervals):
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            row["resident_read_ranges"] = merged
            row["residency_scope"] = "original history page bodies in this exact request; coverage is not residency or approval"
            by_ref[row["source_ref"]] = row
        from .context_efficiency import omit_resident_history_view
        history_sources = [omit_resident_history_view(row) for row in history_sources]
        if self.role == "reviewer" and execution_context.get("phase") == "independent_read_only_review":
            progress = dict(self.reviewer_read_progress(
                execution_context["history_read_progress"]["required_source_refs"],
                available_source_refs=tuple(row["source_ref"] for row in
                                            execution_context.get("review_source_roles", ())),
                include_prepared=True,
                **execution_context["review_read_authority"],
            ))
            # Mandatory context participates in every exact wire-admission
            # candidate. It cannot be trimmed like an optional source view.
            execution_context["product_prepared_evidence"] = self._review_material_pages(
                progress, submission_ref=execution_context.get("submission_source_ref"),
                resident=resident, max_bytes=self.history_query_max_bytes,
            )
            execution_context["history_read_progress"] = progress
        progress = execution_context.get("history_read_progress")
        if isinstance(progress, Mapping):
            progress = json.loads(canonical_json_bytes(progress))
            if execution_context.get("phase") == "goal_completion":
                required = list(execution_context.get("preflight_source_refs", ()))
                completed = set(progress.get("completed_source_refs", ()))
                for reference in required:
                    row = by_ref.get(reference)
                    if row is not None and row["applicability"] == "CURRENT_BINDING":
                        if row["complete_source_read"]:
                            completed.add(reference)
                        else:
                            completed.discard(reference)
                        progress.setdefault("next_read_offsets", {})[reference] = row["next_unread_offset"]
                progress["completed_source_refs"] = [ref for ref in required if ref in completed]
                progress["missing_source_refs"] = [ref for ref in required if ref not in completed]
            actions = {}
            for reference in progress.get("missing_source_refs", ()):
                offset = progress.get("next_read_offsets", {}).get(reference)
                if type(offset) is not int:
                    continue
                row = by_ref.get(reference)
                action = (row["next_unread_read"] if row is not None
                          and row["applicability"] == "CURRENT_BINDING"
                          and row["next_unread_offset"] == offset else None)
                actions[reference] = action or {"operation": "read", "source_ref": reference,
                    "offset": offset, "view": "review", "max_bytes": self.history_query_max_bytes}
            progress["next_reads"] = actions
            progress["interpretation"] = "Authenticated reading coverage only. Reuse resident evidence; recall only material needed for an unresolved requirement. Read completion is not business approval."
            execution_context["history_read_progress"] = progress
            if (self.role == "reviewer"
                    and execution_context.get("phase") == "independent_read_only_review"
                    and isinstance(execution_context.get("response_contract"), dict)):
                # Bind after this exact request's final read projection, including
                # prepared pages. Earlier navigation snapshots may be stale.
                from .review_evidence import bind_review_response_aliases
                bind_review_response_aliases(execution_context)
            measurement = execution_context.get("completion_measurement_progress")
            if execution_context.get("phase") == "goal_completion" and isinstance(measurement, Mapping):
                from .text_measurements import completion_measurement_next_action
                # Use this exact request's finalized read coverage without
                # changing native measurements or internal completion state.
                measurement = dict(measurement)
                measurement["next_action"] = completion_measurement_next_action(
                    unread_source_refs=progress["missing_source_refs"],
                    pending_measurements=measurement["pending_measurements"],
                    remaining_work=measurement["remaining_work"],
                )
                execution_context["completion_measurement_progress"] = measurement
            if execution_context.get("phase") == "goal_completion":
                execution_context["completion_next_step"] = completion_next_step(progress, measurement)
        working_summary = {
            **self.index.working_summary(self.execution_context, include_recent_actions=include_progress),
            "file_read_sources": self.file_read_sources(include_views=include_file_views),
            "history_read_sources": history_sources,
            "assistant_notes": self.assistant_notes() if include_progress else [],
        }
        is_review = self.role == "reviewer" and execution_context.get("phase") == "independent_read_only_review"
        task_context = projection.as_dict()
        omitted_refs = list(selection.omitted_source_refs[-16:])
        if is_review:
            from .context_efficiency import review_task_navigation
            roles = execution_context.get("review_source_roles", ())
            task_context = review_task_navigation(task_context, roles)
            working_summary = current_review_summary(
                working_summary, roles=roles, progress=execution_context["history_read_progress"],
            )
            allowed_refs = {row["source_ref"] for row in roles}
            omitted_refs = [ref for ref in omitted_refs if ref in allowed_refs]
        return {
            "schema": "SITINA_LOOP_MODEL_CONTEXT_V1",
            "role": self.role,
            "task_context": task_context,
            "execution_context": compact_review_materials(execution_context),
            "working_summary": working_summary,
            **(
                {"runtime_feedback": dict(runtime_feedback)}
                if runtime_feedback is not None
                else {}
            ),
            "protocol_history": {
                "selected_complete_group_count": len(selection.groups),
                "selected_serialized_bytes": selection.serialized_bytes,
                "omitted_source_count": len(selection.omitted_source_refs),
                "recent_omitted_source_refs": omitted_refs,
                "older_sources": ({
                    "instruction": "Use only execution_context.review_source_roles and authenticated next_reads. "
                                   "An omitted or historical locator does not grant citation or read authority.",
                } if is_review else {
                    "tool": "sitina_history_query",
                    "operation": "list",
                    "max_bytes": self.history_query_max_bytes,
                }),
                "semantic_dialog_summary_claimed": False,
            },
        }

    def prepare(
        self,
        identity: ProviderContextIdentity,
        *,
        system_prompt: str,
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int,
        expect_json: bool = False,
    ) -> PreparedProviderCall:
        # Keep the Journal projection coherent while independent workers append.
        # The lock is released before any Provider request or business action.
        self._compaction_active = False
        phase = "FAILED"
        before_count = self.compaction_count
        try:
            with self.snapshot_lock if self.snapshot_lock is not None else nullcontext():
                # Bind the reviewer's final JSON contract to the actual Provider
                # request on initial, read-continuation and local repair turns.
                prepared = self._prepare(identity, system_prompt=system_prompt, tools=tools,
                                         max_tokens=max_tokens,
                                         expect_json=expect_json or self.role == "reviewer")
                phase = "COMPLETED" if self.compaction_count > before_count else "UNCHANGED"
                return prepared
        finally:
            if self._compaction_active and self.activity_callback is not None:
                self.activity_callback(phase, self.compaction_count)
            self._compaction_active = False

    def _prepare(
        self,
        identity: ProviderContextIdentity,
        *,
        system_prompt: str,
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int,
        expect_json: bool = False,
    ) -> PreparedProviderCall:
        if identity != self.identity:
            raise ContextPolicyError("Loop request identity changed after exact policy selection")
        assembly_binding = self.index.current_binding()
        runtime_feedback = self._current_runtime_feedback(assembly_binding)

        if self.role == "reviewer" and self.execution_context.get("phase") == "independent_read_only_review":
            tools = [tool for tool in tools
                     if (tool.get("name") or tool.get("function", {}).get("name"))
                     in {"sitina_history_query", "sitina_read_file", "sitina_grep"}]

        self.execution_context.pop("text_measurements", None)
        if self.execution_context.get("phase") == "goal_completion":
            self._refresh_completion_measurement_progress(assembly_binding)

        def bind(error: ContextCoverageBlocked) -> ContextCoverageBlocked:
            error.context_binding = dict(assembly_binding)
            return error

        required_index = self.index.requirement_entries()
        required_refs = tuple(item.source_ref for item in required_index)
        latest_requirement_input = max(
            (item.input_sequence for item in required_index if item.input_sequence is not None),
            default=0,
        )
        projector = TaskContextProjector(self.index, history_query_connected=True)
        projection_candidates: list[tuple[TaskContextProjection, bool, bool]] = []
        soft_error: ContextCoverageBlocked | None = None
        try:
            projection_candidates.append(
                (projector.build(max_bytes=self.projection_max_bytes, max_history_rows=50), True, True)
            )
        except ContextCoverageBlocked as error:
            soft_error = error

        if self.policy is not None:
            if self.policy.counter_mode == "conservative_utf8":
                hard_projection_probe_bytes = self.policy.context_capacity_tokens
            else:
                # This is only an assembly safety ceiling. The qualified
                # tokenizer still makes the real admission decision below.
                hard_projection_probe_bytes = self.policy.context_capacity_tokens * 16
            try:
                minimal_projection = projector.build(
                    max_bytes=max(self.projection_max_bytes, hard_projection_probe_bytes),
                    max_history_rows=0,
                )
            except ContextCoverageBlocked as error:
                raise bind(error) from error
            if not projection_candidates or (
                minimal_projection.serialized != projection_candidates[-1][0].serialized
            ):
                # Directory rows and durable progress have different costs.
                # Try keeping the read facts/notes after removing the directory;
                # exact wire admission may still need the final minimal trial.
                projection_candidates.append((minimal_projection, True, True))
            # Drop optional progress before the bounded original file excerpts.
            # Locator-only fallback remains available when even those cannot fit.
            projection_candidates.append((minimal_projection, False, True))
            projection_candidates.append((minimal_projection, False, False))
        elif not projection_candidates:
            assert soft_error is not None
            raise bind(soft_error)

        verified_projections: list[tuple[TaskContextProjection, bool, bool]] = []
        for projection, include_progress, include_file_views in projection_candidates:
            coverage = RequirementCoverageVerifier.verify(self.index, projection)
            if coverage.verified and projection.ready_for_request:
                verified_projections.append((projection, include_progress, include_file_views))
                continue
            reasons = coverage.reasons or projection.coverage_issues or (
                "current task projection is not ready for a Provider request",
            )
            raise ContextCoverageBlocked(
                "; ".join(reasons), required_refs, context_binding=assembly_binding
            )

        group_ceiling = self.protocol_groups_max_bytes
        if self.policy is not None:
            group_ceiling = max(
                group_ceiling,
                self.policy.context_capacity_tokens
                * (16 if self.policy.counter_mode == "qualified_tokenizer" else 1),
            )
        def protocol_trials():
            if self.policy is not None and self.policy.thinking_mode == "enabled":
                yield from self._thinking_protocol_trials()
                return
            else:
                try:
                    broad = ProtocolGroupSelector.select(
                        tuple(self._groups), max_serialized_bytes=group_ceiling, require_latest=True,
                    )
                except ContextCoverageBlocked as error:
                    raise bind(error) from error
                if not broad.groups:
                    yield (), []
                    return
                # Non-thinking models also keep complete call/result pairs
                # while older read bodies become authenticated locators.
                compacted, replacements = self._externalize_older_tool_bodies(groups=broad.groups)
                soft = ProtocolGroupSelector.select(
                    compacted, max_serialized_bytes=self.protocol_groups_max_bytes, require_latest=False,
                )
                anchor = soft.groups or compacted[-1:]
                for start in range(len(anchor)):
                    retained = anchor[start:]
                    call_ids = {message["tool_call_id"] for group in retained for message in group.tool_results}
                    retained_refs = {ref for group in retained for ref in group.source_refs}
                    yield retained, [item for item in replacements
                                     if item["tool_call_id"] in call_ids and item["source_ref"] in retained_refs]

        tool_tuple = tuple(dict(item) for item in tools)
        last_admission: RequestAdmission | None = None
        # Prefer removing optional directory/progress views over losing original
        # evidence. If no exact wire request fits, remove one older body and
        # retry admission, preserving reasoning, call/result pairs and locators.
        for groups, tool_body_replacements in protocol_trials():
            for projection, include_progress, include_file_views in verified_projections:
                selected_refs = {ref for item in groups for ref in item.source_refs}
                omitted = tuple(
                    sorted({
                        ref
                        for item in self._groups
                        for ref in item.source_refs
                        if ref not in selected_refs
                    })
                )
                if (not self._compaction_active and self.activity_callback is not None
                        and (omitted or tool_body_replacements or not include_progress or not include_file_views)):
                    self._compaction_active = True
                    self.activity_callback("COMPACTING", self.compaction_count + 1)
                selection = ProtocolGroupSelection(
                    groups,
                    omitted,
                    len(_wire_json_bytes([message for item in groups for message in item.messages()])),
                )
                context_document = self._context_document(
                    projection, selection, include_progress=include_progress,
                    include_file_views=include_file_views, runtime_feedback=None,
                )
                # A handled user input follows work bound to earlier inputs,
                # but precedes its own continuing assistant/tool chain. Result
                # commit time alone cannot place a group: an older operation
                # may finish after the input was handled. Keep the whole group
                # on the side proved by all of its operation input bindings.
                preceding_group_count = 0
                if groups and latest_requirement_input:
                    if latest_requirement_input not in self.index._handled_input_positions:
                        raise bind(ContextCoverageBlocked(
                            "current user input has no committed handling boundary", required_refs
                        ))
                    entries_by_ref = {item.source_ref: item for item in self.index.entries}
                    continuation_seen = False
                    for group in groups:
                        input_sequences: list[int] = []
                        for source_ref in group.source_refs:
                            entry = entries_by_ref.get(source_ref)
                            sequence = (
                                self.index._operation_input_bindings.get(entry.subject_id)
                                if entry is not None and entry.kind == "operation_result"
                                else None
                            )
                            if sequence is None or not 0 <= sequence <= projection.binding["handled_input_seq"]:
                                raise bind(ContextCoverageBlocked(
                                    "protocol group lacks a current committed operation input binding",
                                    group.source_refs,
                                ))
                            input_sequences.append(sequence)
                        prior = [sequence < latest_requirement_input for sequence in input_sequences]
                        if any(prior) and not all(prior):
                            raise bind(ContextCoverageBlocked(
                                "protocol group crosses the handled user input boundary",
                                group.source_refs,
                            ))
                        if all(prior):
                            if continuation_seen:
                                raise bind(ContextCoverageBlocked(
                                    "protocol group order crosses back before the handled user input",
                                    group.source_refs,
                                ))
                            preceding_group_count += 1
                        else:
                            continuation_seen = True
                messages: tuple[Mapping[str, Any], ...] = (
                    *tuple(message for group in groups[:preceding_group_count] for message in group.messages()),
                    {
                        "role": "user",
                        "content": canonical_json_bytes(context_document).decode("utf-8"),
                    },
                    *tuple(message for group in groups[preceding_group_count:] for message in group.messages()),
                )
                if runtime_feedback is not None:
                    # Program guidance follows closed turns without moving the
                    # original human input or accumulating older repair copies.
                    messages = (*messages, self._runtime_feedback_message(
                        runtime_feedback,
                        task_id=str(context_document["task_context"]["task_id"]),
                    ))
                rendered = render_provider_tool_request(
                    identity,
                    system_prompt=system_prompt,
                    messages=messages,
                    tools=tool_tuple,
                    max_tokens=max_tokens,
                    thinking_mode=(
                        self.policy.thinking_mode
                        if self.policy is not None
                        else "provider_default"
                    ),
                    reasoning_effort=(
                        self.policy.reasoning_effort
                        if self.policy is not None
                        else "high"
                    ),
                    expect_json=expect_json,
                )
                admission = self.planner.plan(rendered)
                last_admission = admission
                if not admission.admitted:
                    continue
                final_coverage = RequirementCoverageVerifier.verify(self.index, projection)
                if not final_coverage.verified:
                    raise ContextCoverageBlocked(
                        "; ".join(final_coverage.reasons),
                        required_refs,
                        context_binding=assembly_binding,
                    )
                # Track residency representations, not only source identity: a
                # source may remain discoverable as a tiny directory row after
                # its larger protocol receipt is evicted.  That is a genuine
                # content removal and must count as compaction exactly once.
                before_residency = tuple(sorted({
                    *(f"protocol:{ref}" for item in self._groups for ref in item.source_refs),
                    *("protocol-body:" + item["source_ref"] for item in tool_body_replacements),
                    *(
                        f"directory:{row['source_ref']}"
                        for row in verified_projections[0][0].history_directory
                        if isinstance(row.get("source_ref"), str)
                    ),
                }))
                after_residency = tuple(sorted({
                    *(f"protocol:{ref}" for item in selection.groups for ref in item.source_refs),
                    *("protocol-locator:" + item["source_ref"] for item in tool_body_replacements),
                    *(
                        f"directory:{row['source_ref']}"
                        for row in context_document["task_context"]["history_directory"]
                        if isinstance(row.get("source_ref"), str)
                    ),
                }))
                removed_residency = tuple(sorted(set(before_residency) - set(after_residency)))
                removed_sources = tuple(sorted({
                    item.split(":", 1)[1] for item in removed_residency
                }))
                compaction_signature = hashlib.sha256(canonical_json_bytes({
                    "binding": dict(projection.binding),
                    "before": list(before_residency),
                    "after": list(after_residency),
                    "removed": list(removed_residency),
                })).hexdigest()
                if removed_residency and compaction_signature != self._last_compaction_signature:
                    if not self._compaction_active and self.activity_callback is not None:
                        self._compaction_active = True
                        self.activity_callback("COMPACTING", self.compaction_count + 1)
                    self.compaction_count += 1
                    self.compaction_receipts.append({
                        "schema": "SITINA_LOOP_CONTEXT_COMPACTION_RECEIPT_V1",
                        "ordinal": self.compaction_count,
                        "trigger_request_body_hash": rendered.body_hash,
                        "binding": dict(projection.binding),
                        "before_residency": list(before_residency),
                        "after_residency": list(after_residency),
                        "removed_residency": list(removed_residency),
                        "removed_source_refs": list(removed_sources),
                        "semantic_summary_created": False,
                        "originals_remain_history_queryable": True,
                        "tool_result_replacements": [dict(item) for item in tool_body_replacements],
                    })
                    self._last_compaction_signature = compaction_signature
                    # The selected groups contain bounded receipts, not raw
                    # Provider/tool bodies. Once older groups have durable
                    # history handles, remove them from resident process memory.
                    self._groups = list(selection.groups)
                from .context_efficiency import request_material_profile
                material_profile = request_material_profile(
                    role=self.role, phase=str(self.execution_context.get("phase", "")),
                    system_prompt=system_prompt, tools=tool_tuple,
                    context_document=context_document,
                    protocol_messages=[message for group in selection.groups for message in group.messages()],
                    wire_body=rendered.canonical_body,
                )
                prepared = PreparedProviderCall(
                    system_prompt,
                    messages,
                    tool_tuple,
                    projection,
                    selection,
                    rendered,
                    admission,
                    tuple(context_document["execution_context"].get("product_prepared_evidence", ())),
                    material_profile,
                )
                self.admission_receipts.append({
                    **admission.as_dict(),
                    "material_profile": material_profile,
                })
                self.last_prepared = prepared
                return prepared
        if last_admission is None:
            raise ContextCoverageBlocked(
                "no complete request candidate could be rendered",
                required_refs,
                context_binding=assembly_binding,
            )
        raise ContextAdmissionBlocked(
            last_admission,
            required_refs,
            context_binding=assembly_binding,
        )


__all__ = [
    "ContextAdmissionBlocked",
    "ContextCoreError",
    "ContextCoverageBlocked",
    "ContextPolicyError",
    "CoverageVerification",
    "HistoryIndexEntry",
    "HistoryQueryError",
    "LoopContextIndex",
    "LoopHistoryQuery",
    "LoopRequestAssembler",
    "ModelCapacityPolicy",
    "ModelCapacityRegistry",
    "ProtocolGroupSelection",
    "ProtocolGroupSelector",
    "ProtocolMessageGroup",
    "ProviderContextIdentity",
    "ProviderRequestPlanner",
    "PreparedProviderCall",
    "QualifiedWireRequestCounter",
    "RenderedProviderRequest",
    "RequestAdmission",
    "RequirementCoverageEntry",
    "RequirementCoverageVerifier",
    "StaleContextProjection",
    "TaskContextProjection",
    "TaskContextProjector",
    "normalize_provider_endpoint",
    "render_provider_tool_request",
]
