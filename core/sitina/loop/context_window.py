from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit

from sitina.journal.model import canonical_json_bytes
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


HISTORY_MIN_PAGE_BYTES = 768
GOAL_COMPLETION_EVIDENCE_FEEDBACK_MAX_BYTES = 4096


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
        if self.thinking_mode not in {"provider_default", "enabled"}:
            raise ContextPolicyError(
                "bounded Loop supports provider-default or explicitly enabled thinking only"
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
    if thinking_mode not in {"provider_default", "enabled"}:
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
    "loop.task-context-blocked": ("context_blocker", "waiting_ref", "waiting_hash", "task_id"),
    "loop.resource-handoff-recorded": ("resource_handoff", "handoff_ref", "handoff_hash", "handoff_id"),
    "loop.task-terminated": ("terminal", "result_ref", "result_hash", "terminal_event_id"),
    "loop.child-delegation-admitted": ("child_contract", "contract_ref", "contract_hash", "delegation_id"),
    "loop.child-delegation-result-recorded": ("child_result", "result_ref", "result_hash", "delegation_id"),
    "loop.child-delegation-settled": ("child_settlement", "settlement_ref", "settlement_hash", "delegation_id"),
    "loop.child-delegation-applicability-updated": ("child_applicability", "applicability_ref", "applicability_hash", "delegation_id"),
    "loop.child-delegation-recovery-blocked": ("child_recovery", "recovery_ref", "recovery_hash", "delegation_id"),
}

_KNOWN_LOOP_EVENT_TYPES = frozenset({
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
        if event_type == "loop.task-created":
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
        elif event_type in {"loop.task-waiting", "loop.task-context-blocked"}:
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
                self.state["resume_request_id"] = None
        elif event_type == "loop.task-resume-requested":
            self.state["resume_request_id"] = str(value["resume_request_id"])
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


def _decode_cursor(value: str) -> Mapping[str, Any]:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode((value + padding).encode("ascii"))
        document = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise HistoryQueryError("history cursor encoding is invalid") from error
    if not isinstance(document, dict) or "checksum" not in document:
        raise HistoryQueryError("history cursor document is invalid")
    checksum = str(document.pop("checksum"))
    if set(document) != {"schema", "binding", "frontier", "after_ordinal", "kind"}:
        raise HistoryQueryError("history cursor fields are invalid")
    if document.get("schema") != "SITINA_LOOP_HISTORY_CURSOR_V1":
        raise HistoryQueryError("history cursor schema is invalid")
    if checksum != hashlib.sha256(canonical_json_bytes(document)).hexdigest():
        raise HistoryQueryError("history cursor checksum is invalid")
    return document


class LoopHistoryQuery:
    MIN_PAGE_BYTES = HISTORY_MIN_PAGE_BYTES

    def __init__(self, index: LoopContextIndex, *, max_page_bytes: int):
        if max_page_bytes < self.MIN_PAGE_BYTES:
            raise HistoryQueryError(f"configured max_page_bytes must be at least {self.MIN_PAGE_BYTES}")
        self.index = index
        self.max_page_bytes = max_page_bytes

    def _validate_max_bytes(self, max_bytes: int) -> None:
        if max_bytes < self.MIN_PAGE_BYTES:
            raise HistoryQueryError(f"max_bytes must be at least {self.MIN_PAGE_BYTES}")
        if max_bytes > self.max_page_bytes:
            raise HistoryQueryError("max_bytes exceeds the configured history-query maximum")

    def list(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        kind: str | None = None,
        max_bytes: int = 4096,
    ) -> Mapping[str, Any]:
        if not 1 <= limit <= 1_000:
            return self._status("INVALID_LIMIT", max_bytes, reason="limit must be between 1 and 1000")
        self._validate_max_bytes(max_bytes)
        self.index.refresh()
        if cursor:
            try:
                decoded = _decode_cursor(cursor)
            except HistoryQueryError as error:
                return self._status("INVALID_CURSOR", max_bytes, reason=str(error))
            if decoded.get("binding") != self.index.binding_hash:
                return self._status("NOT_VISIBLE", max_bytes, reason="cursor belongs to another task/session")
            if decoded.get("kind") != kind:
                return self._status("INVALID_CURSOR", max_bytes, reason="cursor filter changed")
            try:
                frontier = int(decoded["frontier"])
                after = int(decoded["after_ordinal"])
            except (KeyError, TypeError, ValueError):
                return self._status("INVALID_CURSOR", max_bytes, reason="cursor fields are invalid")
            if frontier < 1 or after < 0 or frontier > self.index.frontier:
                return self._status("INVALID_CURSOR", max_bytes, reason="cursor frontier is invalid")
        else:
            frontier = self.index.frontier
            after = 0
        eligible = [
            item for item in self.index.entries
            if item.ordinal > after and item.event_position <= frontier and (kind is None or item.kind == kind)
        ]
        selected: list[Mapping[str, Any]] = []
        for item in eligible[:limit]:
            candidate = [*selected, item.list_row()]
            more = len(eligible) > len(candidate)
            document = self._list_document(candidate, frontier, item.ordinal if more else None, kind)
            if len(canonical_json_bytes(document)) > max_bytes:
                break
            selected = candidate
        if eligible and not selected:
            minimum = len(canonical_json_bytes(self._list_document([eligible[0].list_row()], frontier, eligible[0].ordinal, kind)))
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
        self,
        *,
        source_ref: str,
        offset: int = 0,
        max_bytes: int = 4096,
    ) -> Mapping[str, Any]:
        self._validate_max_bytes(max_bytes)
        self.index.refresh()
        parts = str(source_ref).split(":")
        if len(parts) != 4 or parts[0] != "history":
            return self._status("NOT_VISIBLE", max_bytes, reason="source ref is not task-scoped")
        if parts[1] != self.index.binding_hash:
            return self._status("NOT_VISIBLE", max_bytes, reason="source ref belongs to another task/session")
        try:
            ordinal = int(parts[2])
        except ValueError:
            return self._status("MISSING", max_bytes, reason="source ref ordinal is invalid")
        entry = next((item for item in self.index.entries if item.ordinal == ordinal), None)
        if entry is None or entry.source_ref != source_ref:
            return self._status("MISSING", max_bytes, reason="source ref is not in the committed task index")
        try:
            document = self.index.store.read_json(entry.internal_cas_ref, expected_hash=entry.content_hash)
            document, content_projection = self._history_safe_document(entry, document)
            capability_metadata = self._capability_public_metadata(document, content_projection)
            raw = canonical_json_bytes(document)
            projected_content_hash = hashlib.sha256(raw).hexdigest()
        except Exception as error:  # stale/corrupt evidence is data, not a hidden omission.
            return self._status(
                "STALE_SOURCE",
                max_bytes,
                reason=f"{type(error).__name__}: indexed CAS content is unavailable or unverifiable",
                source_ref=source_ref,
                content_hash=entry.content_hash,
            )
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > len(raw):
            return self._status("INVALID_OFFSET", max_bytes, reason="offset is outside canonical content")
        if offset < len(raw) and raw[offset] & 0xC0 == 0x80:
            return self._status("INVALID_OFFSET", max_bytes, reason="offset splits a UTF-8 code point")
        return self._read_page(
            entry,
            raw,
            offset,
            max_bytes,
            content_projection=content_projection,
            projected_content_hash=projected_content_hash,
            capability_metadata=capability_metadata,
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

        if "reasoning_content" not in result:
            return document, None

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
        return self.read(source_ref=entry.source_ref, offset=0, max_bytes=max_bytes)

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
    ) -> Mapping[str, Any]:
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

        def document_for(chunk: bytes) -> dict[str, Any]:
            next_offset = offset + len(chunk)
            has_more = next_offset < len(raw)
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
            return self._with_response_bytes({
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
                "returned_bytes": len(chunk),
                "data_base64": base64.b64encode(chunk).decode("ascii"),
                "readable_text": chunk.decode("utf-8"),
                "next_offset": next_offset if has_more else None,
                "has_more": has_more,
                "query": {"operation": "read", "source_ref": entry.source_ref},
                **(
                    {
                        **response_capability_metadata,
                        "capability_operation_id": entry.subject_id,
                    }
                    if capability_metadata is not None
                    else {}
                ),
            })

        remaining = len(raw) - offset
        low, high = 0, remaining
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
            minimum = len(canonical_json_bytes(document_for(first)))
            return self._status("PAGE_TOO_SMALL", max_bytes, reason="one UTF-8 code point cannot fit", minimum_bytes=minimum)
        result = document_for(selected)
        if len(canonical_json_bytes(result)) > max_bytes:
            raise HistoryQueryError("history read envelope exceeds max_bytes")
        if result["has_more"] and int(result["next_offset"]) <= offset:
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
            candidate_rows = [item.list_row(), *rows]
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
    ) -> None:
        if not role.strip():
            raise ContextCoreError("Loop request role is required")
        if min(projection_max_bytes, protocol_groups_max_bytes, receipt_max_bytes) < 1:
            raise ContextCoreError("Loop request limits must be positive")
        self.index = index
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
        self.scope_attempt_ids = frozenset(
            str(item) for item in (scope_attempt_ids or (() if scope_attempt_id is None else (scope_attempt_id,)))
        )
        self._groups: list[ProtocolMessageGroup] = []
        self.compaction_count = 0
        self.compaction_receipts: list[Mapping[str, Any]] = []
        self._last_compaction_signature: str | None = None
        self.admission_receipts: list[Mapping[str, Any]] = []
        self.last_prepared: PreparedProviderCall | None = None
        self._runtime_feedback: Mapping[str, Any] | None = None

    @property
    def history_query_max_bytes(self) -> int:
        return self.history_query.max_page_bytes

    def history_tool(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        operation = arguments.get("operation")
        max_bytes = arguments.get("max_bytes")
        if type(max_bytes) is not int:
            raise HistoryQueryError("history max_bytes must be an integer")
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
            return self.history_query.list(
                cursor=cursor,
                limit=limit,
                kind=kind,
                max_bytes=max_bytes,
            )
        if operation == "read":
            source_ref = arguments.get("source_ref")
            offset = arguments.get("offset", 0)
            if type(source_ref) is not str or not source_ref:
                raise HistoryQueryError("history read requires a source_ref")
            if type(offset) is not int:
                raise HistoryQueryError("history read offset must be an integer")
            return self.history_query.read(
                source_ref=source_ref,
                offset=offset,
                max_bytes=max_bytes,
            )
        raise HistoryQueryError("history operation must be list or read")

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
        }

    def clear_runtime_feedback(self) -> None:
        self._runtime_feedback = None

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

    def prompt_receipt_for_operation(self, operation_id: str) -> Mapping[str, Any]:
        receipt = self.history_query.receipt_for_operation_result(
            operation_id,
            max_bytes=self.receipt_max_bytes,
        )
        if receipt.get("status") != "OK":
            raise ContextCoreError("committed operation result cannot be represented as a verified receipt")
        return receipt

    def record_protocol_group(
        self,
        assistant: Mapping[str, Any],
        tool_results: Sequence[Mapping[str, Any]],
        source_refs: Sequence[str],
    ) -> None:
        self._groups.append(
            ProtocolMessageGroup.from_committed_history(
                self.index,
                assistant,
                tool_results,
                source_refs,
            )
        )

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
        event_positions: dict[str, int] = {}
        for event in events:
            if event.event_type == "loop.operation-intent-recorded":
                operation_id = str(event.payload.get("operation_id") or "")
                logical_ids[operation_id] = str(event.payload.get("logical_operation_id") or "")
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
                event_positions[operation_id] = int(event.position)
        groups: list[ProtocolMessageGroup] = []
        for operation_id, document in sorted(result_docs.items(), key=lambda item: event_positions.get(item[0], 0)):
            if not operation_id.startswith("provider-"):
                continue
            result = document.get("result") if isinstance(document, Mapping) else None
            if not isinstance(result, Mapping):
                continue
            calls = result.get("tool_calls")
            if not calls:
                continue
            if not isinstance(calls, list):
                raise ContextCoreError("committed Provider protocol group is malformed")
            if self.scope_attempt_ids and business_attempts.get(operation_id) not in self.scope_attempt_ids:
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
            for call in calls:
                if not isinstance(call, Mapping) or not str(call.get("id") or ""):
                    raise ContextCoreError("committed Provider tool call is malformed")
                call_id = str(call["id"])
                matches = [
                    candidate for candidate, logical in logical_ids.items()
                    if candidate in result_docs
                    and (
                        not self.scope_attempt_ids
                        or business_attempts.get(candidate) in self.scope_attempt_ids
                    )
                    and logical.startswith(run_prefix + ":")
                    and logical.endswith(":" + call_id)
                ]
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
                tool_name = str(call.get("name") or "")
                tool_status = str(tool_result.get("status") or "error")
                if tool_name == "sitina_history_query" and tool_status == "ok":
                    # Live history calls expose the bounded native page itself.
                    # A receipt of that receipt changes its source and cursor.
                    tool_value = tool_result.get("value")
                    if not isinstance(tool_value, Mapping):
                        raise ContextCoreError("committed history result has no native page")
                else:
                    tool_value = self.prompt_receipt_for_operation(tool_operation_id)
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
            groups.append(
                ProtocolMessageGroup.from_committed_history(
                    self.index, assistant, tool_results, source_refs
                )
            )
        self._groups = groups
        return len(groups)

    def history_reads_in_last_request(self) -> list[Mapping[str, Any]]:
        """Return native read pages in the exact admitted protocol groups."""

        if self.last_prepared is None:
            return []
        reads: list[Mapping[str, Any]] = []
        for group in self.last_prepared.protocol_groups.groups:
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
                if not isinstance(page, Mapping):
                    continue
                reads.append({
                    "name": "sitina_history_query", "status": "ok",
                    "arguments": dict(call["arguments"]), "result": dict(page),
                })
        return reads

    def prepare(
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
            or any(
                feedback_binding.get(key) != assembly_binding.get(key)
                for key in semantic_binding_keys
            )
        ):
            # A correction/control/artifact transition invalidates feedback
            # produced under the prior semantic task binding. Plan/checkpoint
            # journal revisions alone do not invalidate a pending repair.
            self._runtime_feedback = None
            runtime_feedback = None

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
        projection_candidates: list[TaskContextProjection] = []
        soft_error: ContextCoverageBlocked | None = None
        try:
            projection_candidates.append(
                projector.build(max_bytes=self.projection_max_bytes, max_history_rows=50)
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
                minimal_projection.serialized != projection_candidates[-1].serialized
            ):
                projection_candidates.append(minimal_projection)
        elif not projection_candidates:
            assert soft_error is not None
            raise bind(soft_error)

        verified_projections: list[TaskContextProjection] = []
        for projection in projection_candidates:
            coverage = RequirementCoverageVerifier.verify(self.index, projection)
            if coverage.verified and projection.ready_for_request:
                verified_projections.append(projection)
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
        try:
            broad_selection = ProtocolGroupSelector.select(
                self._groups,
                max_serialized_bytes=group_ceiling,
                require_latest=True,
            )
        except ContextCoverageBlocked as error:
            raise bind(error) from error
        selected_groups = broad_selection.groups
        suffixes: list[tuple[ProtocolMessageGroup, ...]] = []
        if self.policy is not None and self.policy.thinking_mode == "enabled":
            if broad_selection.omitted_source_refs:
                raise ContextCoverageBlocked(
                    "thinking-mode protocol history cannot omit required reasoning continuation groups",
                    broad_selection.omitted_source_refs,
                    context_binding=assembly_binding,
                )
            suffixes.append(selected_groups)
        elif not selected_groups:
            suffixes.append(())
        else:
            soft_selection = ProtocolGroupSelector.select(
                selected_groups,
                max_serialized_bytes=self.protocol_groups_max_bytes,
                require_latest=False,
            )
            # The protocol target is a real residency bound.  Retain the
            # richest complete suffix that fits it.  If the latest single
            # group itself exceeds the soft target, keep that atomic group and
            # let exact hard-cap admission decide whether it is possible.
            anchor = soft_selection.groups or selected_groups[-1:]
            for start in range(len(anchor)):
                suffixes.append(anchor[start:])
        # Try the richest soft-bounded complete suffix first, then remove old
        # complete groups one at a time. Every trial is rendered and admitted
        # as the exact physical wire body.
        tool_tuple = tuple(dict(item) for item in tools)
        last_admission: RequestAdmission | None = None
        for projection in verified_projections:
            for suffix_start in range(len(suffixes)):
                groups = suffixes[suffix_start]
                selected_ids = {id(item) for item in groups}
                omitted = tuple(
                    sorted({
                        ref
                        for item in self._groups
                        if id(item) not in selected_ids
                        for ref in item.source_refs
                    })
                )
                selection = ProtocolGroupSelection(
                    groups,
                    omitted,
                    len(_wire_json_bytes([message for item in groups for message in item.messages()])),
                )
                context_document = {
                    "schema": "SITINA_LOOP_MODEL_CONTEXT_V1",
                    "role": self.role,
                    "task_context": projection.as_dict(),
                    "execution_context": dict(self.execution_context),
                    **(
                        {"runtime_feedback": dict(runtime_feedback)}
                        if runtime_feedback is not None
                        else {}
                    ),
                    "protocol_history": {
                        "selected_complete_group_count": len(selection.groups),
                        "selected_serialized_bytes": selection.serialized_bytes,
                        "omitted_source_count": len(selection.omitted_source_refs),
                        "recent_omitted_source_refs": list(selection.omitted_source_refs[-16:]),
                        "older_sources": {
                            "tool": "sitina_history_query",
                            "operation": "list",
                            "max_bytes": self.history_query_max_bytes,
                        },
                        "semantic_dialog_summary_claimed": False,
                    },
                }
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
                    *(
                        f"directory:{row['source_ref']}"
                        for row in verified_projections[0].history_directory
                        if isinstance(row.get("source_ref"), str)
                    ),
                }))
                after_residency = tuple(sorted({
                    *(f"protocol:{ref}" for item in selection.groups for ref in item.source_refs),
                    *(
                        f"directory:{row['source_ref']}"
                        for row in projection.history_directory
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
                    })
                    self._last_compaction_signature = compaction_signature
                    # The selected groups contain bounded receipts, not raw
                    # Provider/tool bodies. Once older groups have durable
                    # history handles, remove them from resident process memory.
                    self._groups = list(selection.groups)
                prepared = PreparedProviderCall(
                    system_prompt,
                    messages,
                    tool_tuple,
                    projection,
                    selection,
                    rendered,
                    admission,
                )
                self.admission_receipts.append(admission.as_dict())
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
