from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Mapping, Sequence


SPEC_VERSION = "sitina-loop-v1-r4"
PROJECTION_SCHEMA_VERSION = 1
PROJECTION_REDUCER_VERSION = "sitina-loop-task-reducer-v1"

_TELEMETRY_TOKEN_FIELDS = (
    "input_tokens", "output_tokens", "total_tokens",
    "cache_read_tokens", "cache_write_tokens",
)
_TELEMETRY_METRICS = (
    "logical_turn_count", "physical_send_count",
    *_TELEMETRY_TOKEN_FIELDS, "cost", "duration_ms",
)


def _telemetry_int(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _telemetry_identifier(value: Any) -> str | None:
    if (
        isinstance(value, str) and 0 < len(value) <= 256
        and all(character.isalnum() or character in "._:/-" for character in value)
    ):
        return value
    return None


def operation_agent_telemetry(
    *,
    task_id: str,
    operation_id: str,
    logical_operation_id: str | None,
    result_status: str,
    result_ref: str | None,
    result_document: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Extract an allowlisted observation from an already authenticated CAS result.

    This function has no storage authority. Optional, malformed, and historical
    telemetry remains unknown; private protocol content never enters the view.
    """
    valid_document = (
        isinstance(result_document, Mapping)
        and result_document.get("schema") == "SITINA_LOOP_OPERATION_RESULT_V1"
        and result_document.get("task_id") == task_id
        and result_document.get("operation_id") == operation_id
        and result_document.get("effect_status") == result_status
    )
    result = result_document.get("result") if valid_document else None
    binding = {
        name: _telemetry_int(result_document.get(source)) if valid_document else None
        for name, source in (
            ("goal_version", "bound_goal_version"),
            ("acceptance_version", "bound_acceptance_version"),
            ("handled_input_seq", "bound_input_seq"),
        )
    }
    kind = "unknown"
    source_agent: dict[str, Any] = {"kind": "unknown"}
    work_purpose = None
    metadata = None
    tools = None
    tools_complete = False
    failure = None
    if isinstance(result, Mapping):
        child_schema = result.get("schema")
        child_provider = isinstance(child_schema, str) and child_schema in {
            "SITINA_LOOP_CHILD_PROVIDER_TURN_V1",
            "SITINA_LOOP_CHILD_PROVIDER_CANCELLED_V1",
        }
        parent_provider = (
            _telemetry_identifier(result.get("work_purpose")) is not None
            and _telemetry_int(result.get("turn")) is not None
            and "tool" not in result
        )
        if child_provider or parent_provider:
            kind = "provider"
            if child_provider:
                source_agent = {
                    "kind": "child",
                    "task_id": result.get("task_id"),
                    "delegation_id": _telemetry_identifier(result.get("delegation_id")),
                }
            else:
                source_agent = {"kind": "parent", "task_id": task_id}
                work_purpose = _telemetry_identifier(result.get("work_purpose"))
            metadata = result.get("metadata")
            if (
                result.get("schema") == "SITINA_LOOP_CHILD_PROVIDER_CANCELLED_V1"
                or (parent_provider and result.get("provider_response_discarded") is True
                    and metadata is None)
            ):
                metadata = result
            raw_tools = result.get("tool_calls")
            if isinstance(raw_tools, list):
                tools = []
                tools_complete = True
                for call in raw_tools:
                    if not isinstance(call, Mapping):
                        tools_complete = False
                        continue
                    call_id = _telemetry_identifier(call.get("id"))
                    name = _telemetry_identifier(call.get("name"))
                    tools_complete = tools_complete and call_id is not None and name is not None
                    tools.append({
                        "id": call_id, "name": name, "observation": "requested",
                        "result_status": None, "result_ref": None,
                    })
                if raw_tools and not tools:
                    tools = None
            failure = result.get("provider_failure")
        elif _telemetry_identifier(result.get("tool")) is not None:
            kind = "tool"
            execution_binding = result.get("execution_binding")
            call_id = (
                _telemetry_identifier(execution_binding.get("call_id"))
                if isinstance(execution_binding, Mapping) else None
            )
            tools = [{
                "id": call_id,
                "name": _telemetry_identifier(result.get("tool")),
                "observation": "operation_recorded",
                "result_status": result_status,
                "result_ref": result_ref,
            }]
            tools_complete = call_id is not None

    reported_usage = {name: None for name in _TELEMETRY_TOKEN_FIELDS}
    reported_duration = None
    physical_count = None
    physical_status = "unknown"
    uncertain_count = None
    retry_count = None
    fallback_count = None
    model = None
    if isinstance(metadata, Mapping):
        usage = metadata.get("token_usage")
        if isinstance(usage, Mapping):
            reported_usage = {name: _telemetry_int(usage.get(name)) for name in _TELEMETRY_TOKEN_FIELDS}
        reported_duration = _telemetry_int(metadata.get("duration_ms"))
        physical_count = _telemetry_int(metadata.get("physical_send_count"))
        if physical_count is None:
            physical_count = _telemetry_int(metadata.get("provider_physical_send_count_lower_bound"))
        raw_physical_status = metadata.get("physical_send_count_status")
        if isinstance(raw_physical_status, str) and raw_physical_status in {"exact", "lower_bound_with_uncertain_attempts"}:
            physical_status = raw_physical_status
        uncertain_count = _telemetry_int(metadata.get("uncertain_physical_send_attempt_count"))
        retry_count = _telemetry_int(metadata.get("retry_count"))
        fallback_count = _telemetry_int(metadata.get("fallback_count"))
        reported_models = {
            value for value in (
                _telemetry_identifier(metadata.get("model")),
                _telemetry_identifier(metadata.get("sitina_provider_model")),
            ) if value is not None
        }
        if len(reported_models) == 1:
            model = next(iter(reported_models))
        if failure is None and metadata.get("schema") == "SITINA_LOOP_PROVIDER_FAILURE_V1":
            failure = metadata

    exact_sends = physical_status == "exact" and uncertain_count == 0 and physical_count is not None
    single_response = (
        kind == "provider" and result_status == "SUCCEEDED"
        and exact_sends and physical_count == 1
        and retry_count == 0 and fallback_count == 0
    )
    metrics = {name: None for name in _TELEMETRY_METRICS}
    if kind == "provider":
        metrics["logical_turn_count"] = 1
        metrics["physical_send_count"] = physical_count if exact_sends else None
        if single_response:
            metrics.update(reported_usage)
            metrics["duration_ms"] = reported_duration
    # The current producers do not report cost. Never estimate it from tokens.
    error = None
    error_status = "none" if result_status == "SUCCEEDED" else "unknown"
    if isinstance(failure, Mapping) and failure.get("schema") == "SITINA_LOOP_PROVIDER_FAILURE_V1":
        summary = failure.get("error_summary")
        if not (
            summary == "Provider transport failure"
            or (isinstance(summary, str)
                and re.fullmatch(r"Provider HTTP response status [1-5][0-9]{2}", summary))
        ):
            summary = None
        failure_class = failure.get("failure_class")
        if not isinstance(failure_class, str) or failure_class not in {"known_http_failure", "not_dispatched_failure", "unknown_provider_failure"}:
            failure_class = None
        error = {
            "exception_type": _telemetry_identifier(failure.get("exception_type")),
            "failure_class": failure_class,
            "summary": summary,
        }
        error_status = "reported" if any(value is not None for value in error.values()) else "unknown"

    unknown = ["metrics." + name for name, value in metrics.items() if value is None]
    if model is None:
        unknown.append("model")
    if work_purpose is None:
        unknown.append("work_purpose")
    if logical_operation_id is None:
        unknown.append("logical_operation_id")
    unknown.extend("binding." + name for name, value in binding.items() if value is None)
    unknown.extend(
        "reported.token_usage." + name for name, value in reported_usage.items() if value is None
    )
    for name, value in (
        ("duration_ms", reported_duration),
        ("physical_send_count", physical_count),
        ("uncertain_physical_send_attempt_count", uncertain_count),
        ("retry_count", retry_count),
        ("fallback_count", fallback_count),
    ):
        if value is None:
            unknown.append("reported." + name)
    if physical_status == "unknown":
        unknown.append("reported.physical_send_count_status")
    tools_identified = tools_complete
    if tools:
        tools_complete = all(
            tool["id"] is not None and tool["name"] is not None
            and tool["result_status"] is not None and tool["result_ref"] is not None
            for tool in tools
        ) and tools_complete
    if not tools_complete:
        unknown.append("tools")
    if error_status == "unknown":
        unknown.append("error")
    if error is not None:
        unknown.extend("error." + name for name, value in error.items() if value is None)
    return {
        "operation_id": operation_id,
        "logical_operation_id": logical_operation_id,
        "_source_agent": source_agent,
        "kind": kind,
        "work_purpose": work_purpose,
        "binding": binding,
        "model": model,
        "model_scope": "recorded_provider_model" if model is not None else "unknown",
        "reported": {
            "token_usage": reported_usage,
            "duration_ms": reported_duration,
            "physical_send_count": physical_count,
            "physical_send_count_status": physical_status,
            "uncertain_physical_send_attempt_count": uncertain_count,
            "retry_count": retry_count,
            "fallback_count": fallback_count,
        },
        "metrics": metrics,
        "duration_scope": "provider_requests",
        "tools": tools,
        "tools_complete": tools_complete,
        "_tools_identified": tools_identified,
        "result_status": result_status,
        "result_ref": result_ref,
        "error": error,
        "error_status": error_status,
        "unknown_fields": sorted(unknown),
    }


def project_agent_telemetry(
    task_id: str,
    operations: Sequence[Mapping[str, Any]],
    child_delegations: Mapping[str, Mapping[str, Any]],
    task_versions: Mapping[str, Any],
) -> dict[str, Any]:
    """Render the same read-only telemetry for live and offline task views."""
    groups: dict[tuple[str, str | None], dict[str, Any]] = {
        (task_id, None): {"agent_id": task_id, "parent_task_id": None, "delegation_id": None, "operations": []}
    }
    child_ids: dict[str, str] = {}
    for delegation_id, child in child_delegations.items():
        if not isinstance(child, Mapping):
            continue
        binding = child.get("parent_binding")
        child_id = child.get("child_task_id")
        if (
            isinstance(binding, Mapping) and binding.get("task_id") == task_id
            and isinstance(child_id, str) and child_id
        ):
            child_ids[delegation_id] = child_id
            groups[(child_id, delegation_id)] = {
                "agent_id": child_id, "parent_task_id": task_id,
                "delegation_id": delegation_id, "operations": [],
            }

    records = []
    for original in operations:
        record = deepcopy(dict(original))
        source = record.pop("_source_agent")
        agent_id = None
        delegation_id = None
        if source.get("task_id") == task_id:
            if source.get("kind") == "parent":
                agent_id = task_id
            elif source.get("kind") == "child":
                delegation_id = source.get("delegation_id")
                agent_id = child_ids.get(delegation_id)
        record["agent_id"] = agent_id
        record["delegation_id"] = delegation_id
        record["attribution_source"] = "result_identity" if agent_id is not None else "unknown"
        binding = record["binding"]
        record["matches_task_versions"] = (
            all(binding[name] == task_versions[name] for name in binding)
            if all(value is not None for value in binding.values()) else None
        )
        records.append(record)

    # Link a tool result only through a unique recorded call identity and
    # the same immutable task versions. Names or operation-ID prefixes alone
    # never establish an agent association.
    binding_fields = ("goal_version", "acceptance_version", "handled_input_seq")
    requests: dict[tuple[Any, ...], list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    tool_results: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        if record["kind"] != "provider" or record["agent_id"] is None:
            continue
        versions = tuple(record["binding"][name] for name in binding_fields)
        if any(value is None for value in versions):
            continue
        for tool in record["tools"] or ():
            if tool["id"] is not None and tool["name"] is not None:
                key = (tool["id"], tool["name"], *versions)
                requests.setdefault(key, []).append((record, tool))
    for record in records:
        if record["kind"] != "tool" or not record["tools"]:
            continue
        tool = record["tools"][0]
        key = (tool["id"], tool["name"], *(record["binding"][name] for name in binding_fields))
        tool_results.setdefault(key, []).append(record)
    for key, observations in tool_results.items():
        record = observations[0]
        owners = requests.get(key, ())
        if key[0] is not None and len(owners) == 1 and len(observations) == 1:
            owner, request = owners[0]
            record["agent_id"] = owner["agent_id"]
            record["delegation_id"] = owner["delegation_id"]
            record["attribution_source"] = "unique_recorded_tool_call"
            request["observation"] = "requested_and_operation_recorded"
            request["result_status"] = record["result_status"]
            request["result_ref"] = record["result_ref"]

    unattributed = []
    for record in records:
        tools = record["tools"]
        complete_tools = record.pop("_tools_identified") and tools is not None and all(
            tool["id"] is not None and tool["name"] is not None
            and tool["result_status"] is not None and tool["result_ref"] is not None
            for tool in tools
        )
        record["tools_complete"] = complete_tools
        unknown = set(record["unknown_fields"])
        if complete_tools:
            unknown.discard("tools")
        else:
            unknown.add("tools")
        record["unknown_fields"] = sorted(unknown)
        if record["agent_id"] is None:
            record["unknown_fields"] = sorted(set(record["unknown_fields"]) | {"agent_id"})
            unattributed.append(record)
        else:
            groups[(record["agent_id"], record["delegation_id"])]["operations"].append(record)
    uncertain_coverage = any(record["kind"] == "unknown" for record in records)
    uncertain_agent_coverage = uncertain_coverage or any(record["kind"] == "provider" for record in unattributed)

    def totals(items: Sequence[Mapping[str, Any]], coverage_unknown: bool) -> dict[str, Any]:
        providers = [item for item in items if item["kind"] == "provider"]
        values = {
            name: (
                sum(item["metrics"][name] for item in providers)
                if providers and not coverage_unknown
                and all(item["metrics"][name] is not None for item in providers)
                else None
            )
            for name in _TELEMETRY_METRICS
        }
        unknown = [name for name, value in values.items() if value is None]
        return {"values": values, "unknown_fields": unknown, "complete": not unknown}

    agents = []
    for key in sorted(groups, key=lambda value: (value[0], value[1] or "")):
        group = groups[key]
        group["operations"].sort(key=lambda value: value["operation_id"])
        provider_records = [item for item in group["operations"] if item["kind"] == "provider"]
        group["models"] = (
            sorted({item["model"] for item in provider_records})
            if provider_records and not uncertain_agent_coverage
            and all(
                item["model"] is not None
                and item["reported"]["physical_send_count"] == 1
                and item["reported"]["physical_send_count_status"] == "exact"
                and item["reported"]["uncertain_physical_send_attempt_count"] == 0
                and item["reported"]["retry_count"] == 0
                and item["reported"]["fallback_count"] == 0
                for item in provider_records
            )
            else None
        )
        group["models_status"] = "known" if group["models"] is not None else "unknown"
        group["totals"] = totals(group["operations"], uncertain_agent_coverage)
        agents.append(group)
    total = totals(records, uncertain_coverage)
    return {
        "agents": agents,
        "unattributed_operations": sorted(unattributed, key=lambda value: value["operation_id"]),
        "totals": total,
        "complete": (
            total["complete"] and not unattributed
            and all(not record["unknown_fields"] for record in records)
        ),
    }




class LoopError(RuntimeError):
    pass


class PersistenceFenced(LoopError):
    pass


class TaskConflict(LoopError):
    pass


class StaleProposal(TaskConflict):
    pass


class RecoveryNotConnected(LoopError):
    pass


class OperationRejected(LoopError):
    pass


class ControlIntent(str, Enum):
    RUN = "RUN"
    PAUSE = "PAUSE"
    CANCEL = "CANCEL"


class TaskStatus(str, Enum):
    RUNNABLE = "RUNNABLE"
    WAITING_OPERATION = "WAITING_OPERATION"
    PAUSING = "PAUSING"
    PAUSED = "PAUSED"
    CANCELLING = "CANCELLING"
    RECOVERY_BLOCKED = "RECOVERY_BLOCKED"
    CONTEXT_BLOCKED = "CONTEXT_BLOCKED"
    STALLED = "STALLED"
    WAITING_INPUT = "WAITING_INPUT"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL_STATUSES = frozenset({TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED})


class InputKind(str, Enum):
    MESSAGE = "MESSAGE"
    CORRECTION = "CORRECTION"
    CLARIFICATION = "CLARIFICATION"
    STATUS = "STATUS"
    PAUSE = "PAUSE"
    CANCEL = "CANCEL"


class OperationMode(str, Enum):
    READ = "READ"
    WRITE = "WRITE"


class EffectStatus(str, Enum):
    INTENT_RECORDED = "INTENT_RECORDED"
    PRECONDITION_CHANGED = "PRECONDITION_CHANGED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class InputRecord:
    input_id: str
    sequence: int
    kind: InputKind
    body_ref: str
    body_hash: str
    received_at: str


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    logical_operation_id: str
    attempt_id: str
    mode: OperationMode
    effect_status: EffectStatus
    intent_ref: str | None
    result_ref: str | None
    resources: tuple[str, ...]
    execution_segment_id: str
    bound_goal_version: int
    bound_acceptance_version: int
    bound_input_seq: int
    unknown_effect: bool = False
    business_attempt_id: str | None = None
    recovery_decision: str | None = None
    telemetry: Mapping[str, Any] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class AcceptanceRecord:
    acceptance_id: str
    outcome_id: str
    bound_task_revision: int
    bound_run_instance_id: str
    bound_execution_epoch: int
    goal_version: int
    acceptance_version: int
    bound_handled_input_seq: int
    artifact_ref: str
    evidence_refs: tuple[str, ...]
    program_status: str
    reviewer_status: str
    delivery_verified: bool


@dataclass(frozen=True)
class AcceptanceSubmission:
    acceptance_id: str
    outcome_id: str
    evidence_refs: tuple[str, ...]
    program_status: str
    reviewer_status: str
    delivery_verified: bool
    expected_task_revision: int
    expected_run_instance_id: str
    expected_execution_epoch: int
    expected_goal_version: int
    expected_acceptance_version: int
    expected_handled_input_seq: int
    artifact_ref: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.acceptance_id.strip() or not self.outcome_id.strip() or not self.artifact_ref.strip():
            raise ValueError("acceptance identity, outcome, and artifact are required")


@dataclass
class TaskProjection:
    task_id: str
    session_id: str
    task_kind: str
    spec_version: str
    run_instance_id: str
    execution_epoch: int
    task_revision: int
    stream_frontier: int
    goal_version: int
    acceptance_version: int
    artifact_version: int
    artifact_ref: str
    environment_ref: str
    capability_snapshot_id: str
    received_input_seq: int
    handled_input_seq: int
    control_intent: ControlIntent
    status: TaskStatus
    required_outcome_ids: tuple[str, ...]
    goal_ref: str
    recovery_state: str
    inputs: tuple[InputRecord, ...] = ()
    operations: dict[str, OperationRecord] = field(default_factory=dict)
    acceptances: dict[str, AcceptanceRecord] = field(default_factory=dict)
    owned_resources: tuple[str, ...] = ()
    terminal_event_id: str | None = None
    terminal_result: Mapping[str, Any] | None = None
    attempt_plans: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    attempt_checkpoints: tuple[Mapping[str, Any], ...] = ()
    main_result_checkpoints: tuple[Mapping[str, Any], ...] = ()
    attempt_settlements: tuple[Mapping[str, Any], ...] = ()
    criteria_lineage_version: int = 1
    review_issues: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    review_repairs: tuple[Mapping[str, Any], ...] = ()
    stop_report_ref: str | None = None
    stop_report_hash: str | None = None
    waiting_reason: Mapping[str, Any] | None = None
    schema_version: int = PROJECTION_SCHEMA_VERSION
    reducer_version: str = PROJECTION_REDUCER_VERSION
    # Admission identity is separate from the first-run executable descriptor.
    # These values are immutable once the task-created event is committed.
    submission_id: str | None = None
    request_fingerprint: str | None = None
    request_ref: str | None = None
    request_hash: str | None = None
    descriptor_ref: str | None = None
    descriptor_hash: str | None = None
    resume_request_id: str | None = None
    # T5 direct parent/child readonly delegation state.  The Journal/CAS
    # event stream is authoritative; this mapping is only the replayed view.
    child_delegations: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    # Memory is a task-bound, low-trust view.  These fields are immutable
    # creation bindings; later accepted/revoked memory facts never silently
    # replace the active task's view.
    memory_view_ref: str | None = None
    memory_view_hash: str | None = None
    memory_view_ids: tuple[str, ...] = ()
    memory_view_versions: tuple[tuple[str, int], ...] = ()
    memory_view_reasons: tuple[str, ...] = ()
    memory_view_revalidation_ref: str | None = None
    memory_view_revalidation_hash: str | None = None
    memory_view_revalidation_input_seq: int | None = None
    memory_view_exclusions: tuple[Mapping[str, Any], ...] = ()

    @property
    def agent_telemetry(self) -> dict[str, Any]:
        observations = [
            operation.telemetry
            if operation.telemetry is not None
            else operation_agent_telemetry(
                task_id=self.task_id,
                operation_id=operation.operation_id,
                logical_operation_id=operation.logical_operation_id,
                result_status=operation.effect_status.value,
                result_ref=operation.result_ref,
                result_document=None,
            )
            for _, operation in sorted(self.operations.items())
        ]
        return project_agent_telemetry(
            self.task_id,
            observations,
            self.child_delegations,
            {
                "goal_version": self.goal_version,
                "acceptance_version": self.acceptance_version,
                "handled_input_seq": self.handled_input_seq,
            },
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def active_operations(self) -> tuple[OperationRecord, ...]:
        return tuple(
            value
            for value in self.operations.values()
            if value.effect_status is EffectStatus.INTENT_RECORDED
        )

    @property
    def unresolved_effects(self) -> tuple[OperationRecord, ...]:
        return tuple(value for value in self.operations.values() if value.unknown_effect)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_LOOP_TASK_PROJECTION_V1",
            "schema_version": self.schema_version,
            "reducer_version": self.reducer_version,
            "spec_version": self.spec_version,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "task_kind": self.task_kind,
            "run_instance_id": self.run_instance_id,
            "execution_epoch": self.execution_epoch,
            "task_revision": self.task_revision,
            "stream_frontier": self.stream_frontier,
            "goal_version": self.goal_version,
            "acceptance_version": self.acceptance_version,
            "artifact_version": self.artifact_version,
            "artifact_ref": self.artifact_ref,
            "environment_ref": self.environment_ref,
            "capability_snapshot_id": self.capability_snapshot_id,
            "received_input_seq": self.received_input_seq,
            "handled_input_seq": self.handled_input_seq,
            "control_intent": self.control_intent.value,
            "status": self.status.value,
            "required_outcome_ids": list(self.required_outcome_ids),
            "goal_ref": self.goal_ref,
            "recovery_state": self.recovery_state,
            "input_count": len(self.inputs),
            "operation_count": len(self.operations),
            "active_operation_ids": [item.operation_id for item in self.active_operations],
            "unknown_effect_operation_ids": [item.operation_id for item in self.unresolved_effects],
            "owned_resources": list(self.owned_resources),
            "acceptance_ids": sorted(self.acceptances),
            "terminal_event_id": self.terminal_event_id,
            "terminal_result": dict(self.terminal_result or {}),
            "attempt_plan_count": len(self.attempt_plans),
            "open_attempt_ids": sorted(
                set(self.attempt_plans)
                - {
                    str(item.get("attempt_id"))
                    for item in self.attempt_settlements
                    if item.get("termination_contract_version") == "sitina-termination-v1"
                }
            ),
            "attempt_checkpoint_count": len(self.attempt_checkpoints),
            "main_result_checkpoint_count": len(self.main_result_checkpoints),
            "attempt_settlement_count": len(self.attempt_settlements),
            "criteria_lineage_version": self.criteria_lineage_version,
            "review_issue_count": len(self.review_issues),
            "unresolved_review_issue_ids": sorted(
                issue_id
                for issue_id, issue in self.review_issues.items()
                if issue.get("status") == "OPEN"
            ),
            "review_repair_count": len(self.review_repairs),
            "stop_report_ref": self.stop_report_ref,
            "stop_report_hash": self.stop_report_hash,
            "waiting_reason": dict(self.waiting_reason or {}),
            "submission_id": self.submission_id,
            "request_fingerprint": self.request_fingerprint,
            "request_ref": self.request_ref,
            "request_hash": self.request_hash,
            "descriptor_ref": self.descriptor_ref,
            "descriptor_hash": self.descriptor_hash,
            "resume_request_id": self.resume_request_id,
            "child_delegation_count": len(self.child_delegations),
            "agent_telemetry": self.agent_telemetry,
            "child_delegations": {
                str(delegation_id): {
                    key: value
                    for key, value in dict(item).items()
                    if key not in {"source_manifest", "source_ids"}
                }
                for delegation_id, item in sorted(self.child_delegations.items())
            },
            "memory_view_ref": self.memory_view_ref,
            "memory_view_hash": self.memory_view_hash,
            "memory_view_ids": list(self.memory_view_ids),
            "memory_view_versions": {
                str(memory_id): int(version)
                for memory_id, version in self.memory_view_versions
            },
            "memory_view_reasons": list(self.memory_view_reasons),
            "memory_view_revalidation_ref": self.memory_view_revalidation_ref,
            "memory_view_revalidation_hash": self.memory_view_revalidation_hash,
            "memory_view_revalidation_input_seq": self.memory_view_revalidation_input_seq,
            "memory_view_exclusions": [dict(item) for item in self.memory_view_exclusions],
            "active_child_delegation_ids": sorted(
                delegation_id
                for delegation_id, item in self.child_delegations.items()
                if str(item.get("status") or "") not in {
                    "SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"
                }
            ),
            "unknown_child_delegation_ids": sorted(
                delegation_id
                for delegation_id, item in self.child_delegations.items()
                if bool(item.get("unknown_effect"))
            ),
        }


@dataclass(frozen=True)
class CompletionProposal:
    proposal_id: str
    terminal_status: TaskStatus
    expected_task_revision: int
    expected_run_instance_id: str
    expected_execution_epoch: int
    expected_goal_version: int
    expected_acceptance_version: int
    expected_received_input_seq: int
    expected_handled_input_seq: int
    artifact_ref: str
    final_result: Mapping[str, Any]
    processor_version: str = "sitina-loop-postprocess-v1"
    obligation_types: tuple[str, ...] = ("EPISODE", "EXPERIENCE_EXTRACTION")

    def __post_init__(self) -> None:
        if self.terminal_status not in TERMINAL_STATUSES:
            raise ValueError("completion proposal requires a logical terminal status")
        if not self.proposal_id or not self.artifact_ref:
            raise ValueError("completion proposal identity/artifact is required")
