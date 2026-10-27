from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Mapping, Sequence


SPEC_VERSION = "sitina-loop-v1-r4"
PROJECTION_SCHEMA_VERSION = 1
PROJECTION_REDUCER_VERSION = "sitina-loop-task-reducer-v1"
# Recovery and normal execution must use the same task review policy.
REVIEW_REQUIRED_TASK_KINDS = frozenset({"code_change", "reviewed_readonly", "reviewed_task"})

_REVIEW_CONTINUATION_FIELDS = (
    "run_instance_id", "execution_epoch", "goal_version", "acceptance_version",
    "criteria_lineage_version", "artifact_ref", "handled_input_seq", "received_input_seq",
)


_CHECKPOINT_CONTINUATION_KEYS = ("review_continuation", "completion_continuation")


def bind_reviewer_continuation(
    dispositions: Mapping[str, Any], resume_request_id: str | None, binding: Mapping[str, Any],
) -> None:
    """Bind native assessment checkpoints without rewriting old effects or receipts."""
    if resume_request_id is None:
        return
    for disposition in dispositions.values():
        if disposition.get("resume_request_id") != resume_request_id:
            continue
        for key in _CHECKPOINT_CONTINUATION_KEYS:
            relation = disposition.get(key)
            if not isinstance(relation, Mapping):
                continue
            original = relation["original_binding"]
            request = disposition["request"]
            if (any(binding[name] != original[name] for name in
                    ("goal_version", "acceptance_version", "criteria_lineage_version", "artifact_ref"))
                    or binding["received_input_seq"] != request["expected_received_input_seq"]
                    or binding["handled_input_seq"] != request["expected_handled_input_seq"]):
                continue
            disposition[key] = {
                **relation, "resumed_binding": {name: binding[name] for name in _REVIEW_CONTINUATION_FIELDS},
            }


def current_checkpoint_continuation(
    dispositions: Mapping[str, Any], *, task_id: str, binding: Mapping[str, Any],
    phase: str | None = None,
) -> Mapping[str, Any] | None:
    """Select an exact native recovery-ready assessment checkpoint."""
    if binding.get("control_intent") != "RUN":
        return None
    for disposition in reversed(tuple(dispositions.values())):
        if (disposition.get("authorization_source") != "native_control_resume"
                or disposition.get("decision") != "ABANDON_MISSING_PROVIDER_RESPONSE"
                or disposition.get("task_id") != task_id):
            continue
        for key in _CHECKPOINT_CONTINUATION_KEYS:
            if phase is not None and key != phase:
                continue
            relation = disposition.get(key)
            resumed = relation.get("resumed_binding") if isinstance(relation, Mapping) else None
            if (isinstance(resumed, Mapping)
                    and all(binding.get(name) == resumed.get(name) for name in _REVIEW_CONTINUATION_FIELDS)
                    and resumed.get("received_input_seq") == resumed.get("handled_input_seq")):
                return relation
    return None


def current_reviewer_continuation(
    dispositions: Mapping[str, Any], *, task_id: str, binding: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    return current_checkpoint_continuation(
        dispositions, task_id=task_id, binding=binding, phase="review_continuation",
    )

def validate_work_plan(record: Mapping[str, Any], *, task_id: str, goal_version: int, previous_revision: int) -> None:
    """Validate one versioned task plan; completion remains the separate acceptance decision."""
    if (not isinstance(record, Mapping) or set(record) != {
            "schema", "task_id", "goal_version", "revision", "reason", "steps"}
            or record.get("schema") != "SITINA_WORK_PLAN_V1" or record.get("task_id") != task_id
            or type(record.get("goal_version")) is not int or record["goal_version"] != goal_version
            or type(record.get("revision")) is not int or record["revision"] != previous_revision + 1
            or not isinstance(record.get("reason"), str) or not record["reason"].strip()
            or not isinstance(record.get("steps"), list) or not record["steps"]):
        raise ValueError("work plan identity, version, reason or steps are invalid")
    states: dict[str, str] = {}
    for step in record["steps"]:
        if (not isinstance(step, Mapping) or set(step) != {
                "id", "objective", "completion_condition", "depends_on", "status", "evidence_refs"}
                or any(not isinstance(step.get(key), str) or not step[key].strip()
                       for key in ("id", "objective", "completion_condition", "status"))
                or step["id"] in states
                or step["status"] not in {"pending", "in_progress", "completed", "blocked"}):
            raise ValueError("work plan step fields or status are invalid")
        for key in ("depends_on", "evidence_refs"):
            value = step[key]
            if (not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value)
                    or len(set(value)) != len(value)):
                raise ValueError("work plan references must be unique strings")
        if any(item not in states for item in step["depends_on"]):
            raise ValueError("work plan dependencies must reference earlier steps")
        if step["status"] in {"in_progress", "completed"} and any(
                states[item] != "completed" for item in step["depends_on"]):
            raise ValueError("work plan dependency is not completed")
        if step["status"] == "completed" and not step["evidence_refs"]:
            raise ValueError("completed plan steps require observed business evidence")
        states[step["id"]] = step["status"]


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


def has_no_effect_result_shape(document: Mapping[str, Any] | None) -> bool:
    """Recognize the native guard payload shape, without claiming dispatch proof."""
    result = document.get("result") if isinstance(document, Mapping) else None
    return (
        isinstance(result, Mapping)
        and set(result) == {"effect_dispatched", "recovery_decision", "reason"}
        and result.get("effect_dispatched") is False
        and result.get("recovery_decision") == "NO_EFFECT"
        and isinstance(result.get("reason"), str) and bool(result["reason"].strip())
    )


def _provider_context_usage(metadata):
    """Last admitted request budget, not a fabricated live token counter."""
    if not isinstance(metadata, Mapping):
        return None
    admission = metadata.get("sitina_request_admission")
    if not isinstance(admission, Mapping) or admission.get("status") != "ADMITTED":
        return None
    capacity = admission.get("context_capacity_tokens")
    reserved = admission.get("total_reserved_tokens")
    input_bound = admission.get("input_bound_tokens")
    if (type(capacity) is not int or capacity <= 0 or type(reserved) is not int
            or not 0 <= reserved <= capacity or type(input_bound) is not int
            or not 0 <= input_bound <= reserved):
        return None
    usage = metadata.get("token_usage")
    actual = usage.get("input_tokens") if isinstance(usage, Mapping) else None
    identity = admission.get("capacity_identity")
    return {"capacity_tokens": capacity, "reserved_tokens": reserved,
            "input_bound_tokens": input_bound, "remaining_tokens": capacity - reserved,
            "remaining_percent": (capacity - reserved) * 100 // capacity,
            "reported_input_tokens": actual if type(actual) is int and actual >= 0 else None,
            "model": identity.get("model") if isinstance(identity, Mapping) else None,
            "observed_at": metadata.get("provider_call_completed_at") or metadata.get("provider_call_started_at"),
            "scope": "last_admitted_request", "counting_mode": admission.get("counting_mode")}


def operation_agent_telemetry(
    *,
    task_id: str,
    operation_id: str,
    logical_operation_id: str | None,
    result_status: str,
    result_ref: str | None,
    result_document: Mapping[str, Any] | None,
    pre_dispatch_intent: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract an allowlisted observation from an already authenticated CAS result.

    This function has no storage authority. Optional, malformed, and historical
    telemetry remains unknown; private protocol content never enters the view.
    Only native readers may supply pre_dispatch_intent, after authenticating a
    unique intent and first result with no dispatch marker, UNKNOWN or recovery
    replacement in the observed Journal. Payload shape alone is not that proof.
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
            invocation = result.get("invocation_binding")
            if (isinstance(invocation, Mapping)
                    and invocation.get("schema") == "SITINA_TOOL_INVOCATION_RECEIPT_V1"
                    and invocation.get("tool") == result.get("tool")):
                execution_binding = invocation
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

        elif (valid_document and set(result) == {"task_skill_binding"}
              and isinstance(result.get("task_skill_binding"), Mapping)
              and result["task_skill_binding"].get("schema") == "SITINA_TASK_SKILL_BINDING_V1"
              and result["task_skill_binding"].get("task_id") == task_id):
            # Pinning the task's catalog is a native control observation, not
            # an unclassified model request. It consumes zero model turns.
            kind = "tool"
            tools = []
            tools_complete = True

    # Observe only the explicit native Skill reader, never arbitrary file reads
    # or a model's claim that it used a Skill. No instructions enter telemetry.
    skill_usage = [] if isinstance(result, Mapping) else None
    if isinstance(result, Mapping) and result.get("tool") == "sitina_read_skill_resource":
        arguments = result.get("arguments")
        skill = _telemetry_identifier(arguments.get("skill")) if isinstance(arguments, Mapping) else None
        resource = _telemetry_identifier(arguments.get("path")) if isinstance(arguments, Mapping) else None
        skill_usage = [{"name": skill, "resource": resource,
                        "status": "used" if result_status == "SUCCEEDED" and result.get("status") == "ok" else "failed"}] if skill and resource else None
    if isinstance(result, Mapping) and result.get("tool") == "sitina_task_skills":
        invocation = result.get("invocation_binding")
        value = result.get("value")
        if (isinstance(invocation, Mapping)
                and invocation.get("schema") == "SITINA_TOOL_INVOCATION_RECEIPT_V1"
                and invocation.get("tool") == "sitina_task_skills"
                and isinstance(invocation.get("arguments"), Mapping)
                and invocation["arguments"].get("action") == "load"):
            name = _telemetry_identifier(invocation["arguments"].get("name"))
            skill = value.get("skill") if isinstance(value, Mapping) else None
            loaded = (isinstance(skill, Mapping) and isinstance(skill.get("body"), str)
                      and bool(skill["body"]) and result_status == "SUCCEEDED"
                      and result.get("status") == "ok")
            if name:
                skill_usage = [{"name": name, "resource": "SKILL.md",
                                "status": "used" if loaded else "failed", "action": "load"}]

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
    elif (
        kind == "unknown" and valid_document and result_status == "FAILED"
        and _telemetry_identifier(result_ref) is not None
        and has_no_effect_result_shape(result_document)
        and isinstance(pre_dispatch_intent, Mapping)
        and pre_dispatch_intent.get("schema") == "SITINA_LOOP_OPERATION_INTENT_V1"
        and pre_dispatch_intent.get("task_id") == task_id
        and pre_dispatch_intent.get("operation_id") == operation_id
        and _telemetry_identifier(logical_operation_id) is not None
        and pre_dispatch_intent.get("logical_operation_id") == logical_operation_id
        and _telemetry_identifier(pre_dispatch_intent.get("attempt_id")) is not None
        and all(
            binding[name] is not None
            and type(pre_dispatch_intent.get(expected)) is int
            and pre_dispatch_intent[expected] == binding[name]
            for name, expected in (
                ("goal_version", "expected_goal_version"),
                ("acceptance_version", "expected_acceptance_version"),
                ("handled_input_seq", "expected_handled_input_seq"),
            )
        )
    ):
        # Only the round count is proved. Actor, usage and cost stay unknown.
        metrics["logical_turn_count"] = 0
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
        "skill_usage": skill_usage,
        "context_usage": _provider_context_usage(metadata) if kind == "provider" else None,
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
            record["actor"] = deepcopy(owner.get("actor"))
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
    uncertain_round_coverage = any(
        record["kind"] == "unknown" and not (
            type(record["metrics"]["logical_turn_count"]) is int
            and record["metrics"]["logical_turn_count"] == 0
        ) for record in records
    )
    uncertain_agent_round_coverage = uncertain_round_coverage or any(
        record["kind"] == "provider" for record in unattributed
    )

    def totals(items: Sequence[Mapping[str, Any]], coverage_unknown: bool, rounds_unknown: bool) -> dict[str, Any]:
        providers = [item for item in items if item["kind"] == "provider"]
        values = {
            name: (
                sum(item["metrics"][name] for item in providers)
                if providers and not (rounds_unknown if name == "logical_turn_count" else coverage_unknown)
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
        group["totals"] = totals(group["operations"], uncertain_agent_coverage, uncertain_agent_round_coverage)
        agents.append(group)
    total = totals(records, uncertain_coverage, uncertain_round_coverage)
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
    execution_owner: str | None = None
    agent_role: str | None = None
    agent_instance_id: str | None = None
    business_action_key: str | None = None
    business_action_family: str | None = None


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
    review_repair_authorizations: tuple[Mapping[str, Any], ...] = ()
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
    # Trusted resume controls may abandon receipt acquisition without changing
    # the original Provider operation or its unknown accounting facts.
    provider_response_dispositions: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    # Cancellation discharges response acquisition, never the original billing
    # uncertainty and never grants permission to resume business execution.
    cancel_reconciliation: Mapping[str, Any] | None = None
    # Replayed native control receipt; the original descriptor remains immutable.
    software_update_transition: Mapping[str, Any] | None = None
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
    work_plan_record: Mapping[str, Any] | None = None
    work_plan_source_ref: str | None = None

    def review_repair_limit(self, artifact_ref: str) -> int:
        from .termination import review_subject_lineage
        subject = review_subject_lineage(self.task_id, "outcome-1")
        limit = 3
        for authorization in self.review_repair_authorizations:
            if all(authorization.get(key) == value for key, value in {
                "task_id": self.task_id, "artifact_ref": artifact_ref,
                "review_subject_lineage": subject, "acceptance_item_id": "outcome-1",
                "blocker_id": "review-protocol-repair:outcome-1",
                "goal_version": self.goal_version, "acceptance_version": self.acceptance_version,
                "criteria_lineage_version": self.criteria_lineage_version,
                "prior_limit": limit, "repair_limit": limit + 3,
            }.items()):
                limit += 3
        return limit

    def explicit_review_retry(
        self, resume_request_id: str, *, authorize_new_batch: bool = False,
    ) -> dict[str, Any] | None:
        """Preserve legacy 3-to-6 receipts; later batches require explicit authority."""
        from .termination import review_subject_lineage
        if type(authorize_new_batch) is not bool:
            raise TaskConflict("review retry authorization must be a boolean")
        if (self.waiting_reason or {}).get("blocker_id") != "review-protocol-repair:outcome-1":
            if authorize_new_batch:
                raise TaskConflict("review retry requires an exhausted read-only review")
            return None
        if not authorize_new_batch and any(
                row.get("artifact_ref") == self.artifact_ref for row in self.review_repair_authorizations):
            return None
        subject = review_subject_lineage(self.task_id, "outcome-1")
        limit = self.review_repair_limit(self.artifact_ref)
        indices = [row["repair_index"] for row in self.review_repairs
                   if row.get("artifact_ref") == self.artifact_ref
                   and row.get("review_subject_lineage") == subject]
        if indices != list(range(1, limit + 1)):
            if authorize_new_batch:
                raise TaskConflict("review retry requires the prior finite batch to be exhausted")
            return None
        if (self.is_terminal or self.control_intent is ControlIntent.CANCEL
                or self.received_input_seq != self.handled_input_seq
                or self.active_operations or self.unresolved_effects):
            raise TaskConflict("read-only review retry requires a reconciled unchanged task")
        return {
            "schema": ("SITINA_LOOP_EXPLICIT_REVIEW_RETRY_V2" if authorize_new_batch
                       else "SITINA_LOOP_EXPLICIT_REVIEW_RETRY_V1"),
            "task_id": self.task_id, "resume_request_id": resume_request_id,
            "artifact_ref": self.artifact_ref, "review_subject_lineage": subject,
            "acceptance_item_id": "outcome-1",
            "blocker_id": "review-protocol-repair:outcome-1",
            "goal_version": self.goal_version, "acceptance_version": self.acceptance_version,
            "criteria_lineage_version": self.criteria_lineage_version,
            "prior_limit": limit, "repair_limit": limit + 3,
        }

    @property
    def current_work_plan(self) -> dict[str, Any] | None:
        if self.work_plan_record is not None and self.work_plan_record.get("goal_version") == self.goal_version:
            return deepcopy(dict(self.work_plan_record))
        return None

    @property
    def agent_telemetry(self) -> dict[str, Any]:
        observations = [
            deepcopy(operation.telemetry)
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
        for observation, (_operation_id, operation) in zip(observations, sorted(self.operations.items())):
            observation["actor"] = {
                "role": operation.agent_role,
                "instance_id": operation.business_attempt_id or operation.agent_instance_id,
                "execution_owner": operation.execution_owner,
            }
            if operation.execution_owner in self.child_delegations:
                observation["_source_agent"] = {"kind": "child", "task_id": self.task_id, "delegation_id": operation.execution_owner}
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
    def team_counts(self) -> dict[str, Any]:
        children = tuple(self.child_delegations.values())
        active_operation_ids = {op.operation_id for op in self.active_operations}
        open_attempt_ids = set(self.attempt_plans) - {
            str(item.get("attempt_id"))
            for item in self.attempt_settlements
            if item.get("termination_contract_version") == "sitina-termination-v1"
        }
        review_operations = tuple(
            op for op in self.operations.values()
            if op.agent_role == "reviewer" and (op.business_attempt_id or op.agent_instance_id)
        )
        # Provider steps have separate run IDs inside one durable review attempt.
        reviewers = {op.business_attempt_id or op.agent_instance_id for op in review_operations}
        active_reviewers = {
            op.business_attempt_id or op.agent_instance_id
            for op in review_operations
            if not self.is_terminal and (
                op.operation_id in active_operation_ids or op.business_attempt_id in open_attempt_ids
            )
        }
        main_waiting = not self.is_terminal and self.status.value in {
            "WAITING_CHILD", "WAITING_INPUT", "PAUSED", "STALLED", "RECOVERY_BLOCKED", "CONTEXT_BLOCKED",
        }
        return {
            "main": {"running": int(not self.is_terminal and not main_waiting and not active_reviewers),
                     "waiting": int(not self.is_terminal and (main_waiting or bool(active_reviewers))), "created": 1},
            "child": {"running": sum(item.get("status") in {"RUNNING", "CANCEL_REQUESTED"} for item in children),
                      "waiting": sum(item.get("status") in {"ADMITTED", "DISPATCH_PENDING", "RECOVERY_BLOCKED", "BLOCKED"} or bool(item.get("unknown_effect")) for item in children),
                      "created": len(children)},
            "reviewer": {"running": 0 if main_waiting else len(active_reviewers),
                         "waiting": len(active_reviewers) if main_waiting else 0, "created": len(reviewers)},
        }

    @property
    def active_operations(self) -> tuple[OperationRecord, ...]:
        return tuple(
            value
            for value in self.operations.values()
            if value.effect_status is EffectStatus.INTENT_RECORDED
        )

    @property
    def unresolved_effects(self) -> tuple[OperationRecord, ...]:
        abandoned = (self.cancel_reconciliation.get('abandoned_operation_id')
                     if self.control_intent is ControlIntent.CANCEL and self.cancel_reconciliation else None)
        return tuple(
            value for value in self.operations.values()
            if value.unknown_effect and value.operation_id not in self.provider_response_dispositions
            and value.operation_id != abandoned
        )

    def as_dict(self) -> dict[str, Any]:
        decisions = [
            item for item in self.attempt_checkpoints
            if isinstance(item.get("goal_input"), Mapping)
            and item.get("reason") in {"GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"}
            and isinstance(item.get("binding_after_return"), Mapping)
            and item["binding_after_return"].get("goal_version") == self.goal_version
            and item["binding_after_return"].get("criteria_lineage_version") == self.criteria_lineage_version
        ]
        goal_summary = deepcopy(decisions[-1]["goal_input"]) if decisions else None
        if goal_summary is not None:
            goal_summary["acceptance_conditions"] = deepcopy(decisions[0]["goal_input"]["acceptance_conditions"])
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
            "goal_summary": goal_summary,
            "work_plan": self.current_work_plan,
            "work_plan_source_ref": self.work_plan_source_ref if self.current_work_plan else None,
            "goal_summary_source_refs": list(dict.fromkeys(
                ref for item in decisions for ref in item.get("goal_input_source_refs", ())
            )),
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
            "historical_unknown_effect_operation_ids": [
                item.operation_id for item in self.operations.values() if item.unknown_effect
            ],
            "provider_response_dispositions": deepcopy(self.provider_response_dispositions),
            "cancel_reconciliation": deepcopy(self.cancel_reconciliation),
            "software_update_transition": deepcopy(self.software_update_transition),
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
            "review_repair_authorizations": deepcopy(list(self.review_repair_authorizations)),
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
            "team_counts": self.team_counts,
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
