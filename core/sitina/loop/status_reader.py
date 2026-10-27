from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sitina.cas.local import LocalCAS
from sitina.journal.model import parse_canonical_json
from sitina.journal.recovery import scan_active_segment_read_only, scan_sealed_segment
from sitina.security.key_provider import JournalAuthProvider

from .model import SPEC_VERSION, PersistenceFenced, TaskConflict, operation_agent_telemetry, project_agent_telemetry
from .storage import LoopRuntimeContext


class StatusReadUnavailable(RuntimeError):
    pass


def _read_json(cas: LocalCAS, reference: str, expected_hash: str | None) -> dict[str, Any]:
    raw = cas.open_verified(cas.resolve_reference(reference))
    if expected_hash is not None and hashlib.sha256(raw).hexdigest() != expected_hash:
        raise StatusReadUnavailable("status CAS object hash differs from its event binding")
    value = parse_canonical_json(raw)
    if not isinstance(value, dict):
        raise StatusReadUnavailable("status CAS object is not a document")
    return value


def read_authenticated_journal(
    home: str | Path, *, keychain_backend: Any | None = None,
) -> tuple[LoopRuntimeContext, LocalCAS, tuple[Any, ...]]:
    """Read one existing authenticated Journal position without a coordinator.

    Returns the existing-only runtime context, a read-only CAS, and verified
    event envelopes.  No namespace, key, task, repair or projection is created.
    """
    root = Path(home).expanduser().resolve(strict=False)
    marker = root / ".sitina-session-runtime-v1"
    bindings = root / "key-bindings-v1.json"
    active = root / "journal" / "active.seg"
    # This preflight is intentionally before LoopRuntimeContext.open(): a status
    # query against an absent namespace must not initialize keys or directories.
    if not root.is_dir() or not marker.is_file() or not bindings.is_file() or not active.is_file():
        raise StatusReadUnavailable("loop state namespace is unavailable; no coordinator was opened")

    context = LoopRuntimeContext.open(root, backend=keychain_backend)
    if not context.key_readback.existing_only_reopen:
        raise StatusReadUnavailable("status reader requires an existing-only key reopen")
    cas = LocalCAS.open(root, context.provider, namespace_kind="session", read_only=True)
    auth = JournalAuthProvider(context.provider)
    segments = sorted((root / "journal" / "sealed").glob("*.seg")) + [active]
    events: list[Any] = []
    next_position = 1
    stream_versions: dict[str, int] = {}
    for segment in segments:
        scan = (
            scan_active_segment_read_only(segment)
            if segment == active
            else scan_sealed_segment(segment)
        )
        for frame in scan.frames:
            transaction = frame.transaction
            if transaction.first_position != next_position:
                raise StatusReadUnavailable("journal position sequence is discontinuous")
            prior = stream_versions.get(transaction.stream_id)
            if prior is not None and transaction.first_stream_version != prior + 1:
                raise StatusReadUnavailable("journal stream version is discontinuous")
            for event in transaction.events:
                if (
                    event.stream_id != transaction.stream_id
                    or event.computed_event_hash != event.event_hash
                    or not event.verify(journal_id=context.journal_id, epoch=1, authenticator=auth)
                ):
                    raise StatusReadUnavailable("journal event authentication failed")
                # The journal may contain authenticated extension streams with
                # their own schema/version contract.  SPEC_VERSION is only a
                # Loop task-stream invariant; extension events still undergo
                # the same position, stream-version, hash, and authentication
                # checks above without being interpreted as Loop events.
                if event.stream_id.startswith("loop-task/") and event.payload.get("spec_version") != SPEC_VERSION:
                    raise StatusReadUnavailable("task status stream mixes specification versions")
                events.append(event)
            next_position = transaction.last_position + 1
            stream_versions[transaction.stream_id] = transaction.last_stream_version
    return context, cas, tuple(events)


def read_task_status(
    home: str | Path,
    task_id: str,
    *,
    keychain_backend: Any | None = None,
    input_id: str | None = None,
    include_responses: bool = False,
    include_managed_processes: bool = False,
) -> dict[str, Any]:
    """Authenticate and replay public task status without opening execution authority."""

    if input_id is not None and (not isinstance(input_id, str) or not input_id):
        raise ValueError("input_id must be a non-empty string")
    root = Path(home).expanduser().resolve(strict=False)
    context, cas, events = read_authenticated_journal(root, keychain_backend=keychain_backend)

    task_events = [event for event in events if event.stream_id == f"loop-task/{task_id}"]
    if not task_events:
        raise KeyError(task_id)
    created = task_events[0]
    if created.event_type != "loop.task-created":
        raise StatusReadUnavailable("task stream does not begin with creation")
    payload = created.payload
    request_document: dict[str, Any] | None = None
    descriptor_document: dict[str, Any] | None = None
    if any(payload.get(key) for key in ("request_ref", "request_hash", "descriptor_ref", "descriptor_hash")):
        required = ("request_ref", "request_hash", "descriptor_ref", "descriptor_hash", "request_fingerprint")
        if any(not payload.get(key) for key in required):
            raise StatusReadUnavailable("task admission references are incomplete")
        if str(payload["request_ref"]) not in created.object_refs or str(payload["descriptor_ref"]) not in created.object_refs:
            raise StatusReadUnavailable("task admission references lack Journal proof bindings")
        request_document = _read_json(cas, str(payload["request_ref"]), str(payload["request_hash"]))
        descriptor_document = _read_json(cas, str(payload["descriptor_ref"]), str(payload["descriptor_hash"]))
        if request_document.get("schema") != "SITINA_LOOP_SUBMISSION_INTENT_V1":
            raise StatusReadUnavailable("task request descriptor schema is unsupported")
        if request_document.get("fingerprint") != payload.get("request_fingerprint"):
            raise StatusReadUnavailable("task request fingerprint does not match its CAS object")
        if descriptor_document.get("schema") != "SITINA_LOOP_RUN_DESCRIPTOR_V1":
            raise StatusReadUnavailable("task run descriptor schema is unsupported")
        if descriptor_document.get("continuity_contract_version") != "sitina-continuity-v1":
            raise StatusReadUnavailable("task descriptor continuity version is unsupported")
        if descriptor_document.get("task_id") != task_id:
            raise StatusReadUnavailable("task descriptor task identity differs from its stream")
        for field in (
            "submission_id", "task_kind", "spec_version", "termination_contract_version",
            "goal_ref", "goal_hash", "initial_artifact", "workspace", "acceptance",
            "provider_identity", "provider_profile", "capability_snapshot_id", "environment_ref",
            "authorization", "allowed_roots", "software_identity", "config_identity", "protocol_versions",
        ):
            if field not in descriptor_document:
                raise StatusReadUnavailable("task descriptor is missing required field: " + field)
        if (
            descriptor_document.get("submission_id") != payload.get("submission_id")
            or descriptor_document.get("task_kind") != payload.get("task_kind")
            or descriptor_document.get("goal_ref") == ""
            or descriptor_document.get("initial_artifact", {}).get("reference") != payload.get("artifact_ref")
            or descriptor_document.get("initial_artifact", {}).get("hash") != payload.get("artifact_hash")
            or descriptor_document.get("environment_ref") != payload.get("environment_ref")
            or descriptor_document.get("capability_snapshot_id") != payload.get("capability_snapshot_id")
        ):
            raise StatusReadUnavailable("task descriptor is not bound to its task-created event")
    state: dict[str, Any] = {
        "schema": "SITINA_LOOP_READ_ONLY_STATUS_V1",
        "spec_version": str(payload["spec_version"]),
        "task_id": task_id,
        "session_id": str(payload["session_id"]),
        "task_kind": str(payload["task_kind"]),
        "run_instance_id": str(payload["run_instance_id"]),
        "execution_epoch": int(payload["execution_epoch"]),
        "task_revision": created.stream_version,
        "goal_version": int(payload["goal_version"]),
        "acceptance_version": int(payload["acceptance_version"]),
        "criteria_lineage_version": int(payload.get("criteria_lineage_version", 1)),
        "artifact_version": int(payload.get("artifact_version", 1)),
        "artifact_ref": str(payload["artifact_ref"]),
        "environment_ref": str(payload["environment_ref"]),
        "capability_snapshot_id": str(payload["capability_snapshot_id"]),
        "submission_id": payload.get("submission_id"),
        "request_fingerprint": payload.get("request_fingerprint"),
        "request_ref": payload.get("request_ref"),
        "request_hash": payload.get("request_hash"),
        "descriptor_ref": payload.get("descriptor_ref"),
        "descriptor_hash": payload.get("descriptor_hash"),
        "resume_request_id": payload.get("resume_request_id"),
        "provider_response_dispositions": {},
        "waiting_reason": None,
        "received_input_seq": int(payload["received_input_seq"]),
        "handled_input_seq": int(payload["handled_input_seq"]),
        "control_intent": str(payload["control_intent"]),
        "status": str(payload["status"]),
        "active_operation_ids": [],
        "unknown_effect_operation_ids": [],
        "owned_resources": [],
        "terminal_event_id": None,
        "terminal_result": None,
        "terminal_result_ref": None,
        "terminal_result_hash": None,
        "stop_report_ref": None,
        "stop_report_hash": None,
        "child_delegations": {},
    }
    active_operations: set[str] = set()
    telemetry_operations: dict[str, dict[str, Any]] = {}
    telemetry_intents: dict[str, dict[str, Any]] = {}
    managed_processes: dict[str, dict[str, Any]] = {}
    ignored_managed_processes: set[str] = set()
    intent_counts: dict[str, int] = {}
    result_counts: dict[str, int] = {}
    dispatched_operations: set[str] = set()
    for observed_event in task_events:
        operation_id = str(observed_event.payload.get("operation_id") or "")
        if observed_event.event_type == "loop.operation-intent-recorded":
            intent_counts[operation_id] = intent_counts.get(operation_id, 0) + 1
        elif observed_event.event_type == "loop.operation-result-recorded":
            result_counts[operation_id] = result_counts.get(operation_id, 0) + 1
        elif observed_event.event_type == "loop.operation-dispatch-started":
            dispatched_operations.add(operation_id)
    unknown_operations: set[str] = set()
    retired_response_operations: set[str] = set()
    owned_resources: set[str] = set()
    input_kinds: dict[str, str] = {}
    handled_message_id: str | None = None
    responses: list[dict[str, Any]] = []
    receipt: dict[str, Any] | None = None
    stop_report: dict[str, Any] | None = None
    stop_report_event_version: int | None = None
    no_state_change_events = {
        "loop.attempt-planned", "loop.main-result-checkpointed", "loop.attempt-settled",
        "loop.review-findings-recorded", "loop.review-repair-recorded",
        "loop.acceptance-result-recorded", "loop.operation-precondition-changed",
        "loop.operation-dispatch-started", "loop.operation-recovery-decided",
    }
    for event in task_events[1:]:
        if event.stream_version != state["task_revision"] + 1:
            raise StatusReadUnavailable("task event stream is discontinuous")
        value = event.payload
        kind = event.event_type
        if kind == "loop.input-received":
            input_kinds[str(value["input_id"])] = str(value["kind"])
            if input_id is not None and value["input_id"] == input_id:
                if str(value["body_ref"]) not in event.object_refs:
                    raise StatusReadUnavailable("input receipt lacks its Journal body binding")
                body = _read_json(cas, str(value["body_ref"]), str(value["body_hash"]))
                if (
                    body.get("schema") != "SITINA_LOOP_INPUT_BODY_V1"
                    or body.get("task_id") != task_id or body.get("input_id") != input_id
                    or body.get("kind") != value["kind"] or not isinstance(body.get("body"), str)
                    or receipt is not None
                ):
                    raise StatusReadUnavailable("input receipt differs from its durable body")
                receipt = {
                    "status": "RECEIVED", "task_id": task_id, "input_id": input_id,
                    "kind": str(value["kind"]), "body_hash": str(value["body_hash"]),
                    "sequence": int(value["input_seq"]),
                }
            state["received_input_seq"] = int(value["input_seq"])
            state["control_intent"] = str(value["control_intent"])
            state["status"] = str(value["status"])
        elif kind == "loop.input-handled":
            prior_goal_version = state["goal_version"]
            state["handled_input_seq"] = int(value["handled_input_seq"])
            if input_kinds.get(str(value.get("input_id"))) in {"MESSAGE", "CLARIFICATION"}:
                handled_message_id = str(value["input_id"])
            state["goal_version"] = int(value["goal_version"])
            if prior_goal_version != state["goal_version"]:
                for stale_key in ("goal_summary", "goal_summary_source_refs", "work_plan", "work_plan_source_ref"):
                    state.pop(stale_key, None)
            state["acceptance_version"] = int(value["acceptance_version"])
            state["criteria_lineage_version"] = int(
                value.get("criteria_lineage_version", state["criteria_lineage_version"])
            )
            state["control_intent"] = str(value["control_intent"])
            state["status"] = str(value["status"])
            if input_kinds.get(str(value.get("input_id"))) == "CLARIFICATION":
                state["waiting_reason"] = None
        elif kind == "loop.operation-intent-recorded":
            operation_id = str(value["operation_id"])
            logical_id = value.get("logical_operation_id")
            telemetry_operations[operation_id] = operation_agent_telemetry(
                task_id=task_id, operation_id=operation_id,
                logical_operation_id=logical_id if isinstance(logical_id, str) else None,
                result_status="INTENT_RECORDED", result_ref=None, result_document=None,
            )
            intent_ref, intent_hash = value.get("intent_ref"), value.get("intent_hash")
            if not intent_ref or not intent_hash or str(intent_ref) not in event.object_refs:
                raise StatusReadUnavailable("operation intent lacks a proof-bound body")
            intent = _read_json(cas, str(intent_ref), str(intent_hash))
            if intent.get("schema") != "SITINA_LOOP_OPERATION_INTENT_V1" or intent.get("operation_id") != operation_id:
                raise StatusReadUnavailable("operation actor differs from its durable intent")
            if include_managed_processes and operation_id.startswith("managed-process-"):
                from .command_runner import COMMAND_POLICY, TASK_COMMAND_POLICY
                if intent.get("task_id") != task_id:
                    raise StatusReadUnavailable("managed process intent belongs to another task")
                reference, digest = intent.get("effect_evidence_ref"), intent.get("effect_evidence_hash")
                if not isinstance(reference, str) or not isinstance(digest, str) or not reference or not digest:
                    raise StatusReadUnavailable("managed process lacks bound command evidence")
                evidence = _read_json(cas, reference, digest)
                if (evidence.get("schema") != "SITINA_LOOP_OPERATION_EFFECT_EVIDENCE_V1"
                        or evidence.get("task_id") != task_id or evidence.get("operation_id") != operation_id
                        or evidence.get("effect_kind") != "command"
                        or evidence.get("command_policy") not in {COMMAND_POLICY, TASK_COMMAND_POLICY}
                        or evidence.get("managed_process") is not True):
                    raise StatusReadUnavailable("managed process owner binding is invalid")
                if evidence.get("phase") != "UNSUPPORTED_NOT_STARTED" and not evidence.get("planning_error"):
                    managed_processes[operation_id] = evidence
            if (
                intent.get("task_id") == task_id
                and intent.get("logical_operation_id") == logical_id
                and intent.get("attempt_id") == value.get("attempt_id")
                and all(
                    type(value.get(bound)) is int
                    and type(intent.get(expected)) is int
                    and intent[expected] == value[bound]
                    for expected, bound in (
                        ("expected_goal_version", "bound_goal_version"),
                        ("expected_acceptance_version", "bound_acceptance_version"),
                        ("expected_handled_input_seq", "bound_input_seq"),
                    )
                )
            ):
                telemetry_intents[operation_id] = intent
            telemetry_operations[operation_id]["actor"] = {
                "role": intent.get("agent_role"),
                "instance_id": value.get("business_attempt_id") or intent.get("agent_instance_id"),
                "execution_owner": intent.get("execution_owner"),
            }
            active_operations.add(operation_id)
            if value.get("mode") == "WRITE":
                owned_resources.update(str(item) for item in value.get("resources", ()))
            if state["control_intent"] == "RUN":
                state["status"] = "WAITING_OPERATION"
        elif kind == "loop.operation-result-recorded":
            operation_id = str(value["operation_id"])
            if include_managed_processes and value.get("effect_status") == "PRECONDITION_CHANGED":
                ignored_managed_processes.add(operation_id)
            reference = value.get("result_ref")
            content_hash = value.get("result_hash")
            if not reference or not content_hash or str(reference) not in event.object_refs:
                raise StatusReadUnavailable("operation result lacks a proof-bound result")
            document = _read_json(cas, str(reference), str(content_hash))
            prior_telemetry = telemetry_operations.get(operation_id)
            telemetry_operations[operation_id] = operation_agent_telemetry(
                task_id=task_id, operation_id=operation_id,
                logical_operation_id=(
                    prior_telemetry["logical_operation_id"] if prior_telemetry is not None else None
                ),
                result_status=str(value["effect_status"]), result_ref=str(reference),
                result_document=document,
                pre_dispatch_intent=(
                    telemetry_intents.get(operation_id)
                    if prior_telemetry is not None
                    and prior_telemetry["result_status"] == "INTENT_RECORDED"
                    and intent_counts.get(operation_id) == 1
                    and result_counts.get(operation_id) == 1
                    and operation_id not in dispatched_operations
                    and value.get("unknown_effect") is False
                    and not value.get("recovery_replaces_unknown")
                    else None
                ),
            )
            telemetry_operations[operation_id]["actor"] = (prior_telemetry or {}).get("actor")
            active_operations.discard(operation_id)
            if value.get("unknown_effect") is True:
                unknown_operations.add(operation_id)
            else:
                unknown_operations.discard(operation_id)
            if not active_operations:
                if unknown_operations:
                    state["status"] = "WAITING_OPERATION"
                elif state["control_intent"] == "PAUSE":
                    state["status"] = "PAUSED"
                elif state["control_intent"] == "CANCEL":
                    state["status"] = "CANCELLING"
                else:
                    state["status"] = "RUNNABLE"
        elif kind == "loop.artifact-updated":
            state["artifact_version"] = int(value["artifact_version"])
            state["artifact_ref"] = str(value["artifact_ref"])
            state["acceptance_version"] = int(value["acceptance_version"])
        elif kind == "loop.operation-precondition-changed":
            operation_id = str(value["operation_id"])
            if include_managed_processes:
                ignored_managed_processes.add(operation_id)
            logical_id = value.get("logical_operation_id")
            telemetry_operations[operation_id] = operation_agent_telemetry(
                task_id=task_id, operation_id=operation_id,
                logical_operation_id=logical_id if isinstance(logical_id, str) else None,
                result_status="PRECONDITION_CHANGED", result_ref=None, result_document=None,
            )
        elif kind == "loop.resource-handoff-recorded":
            owned_resources.difference_update(str(item) for item in value.get("resources", ()))
        elif kind == "loop.native-execution-wait-updated":
            reference, content_hash = value.get("waiting_ref"), value.get("waiting_hash")
            if not reference or not content_hash or str(reference) not in event.object_refs:
                raise StatusReadUnavailable("native wait lacks its proof-bound document")
            document = _read_json(cas, str(reference), str(content_hash))
            status_by_state = {"WAITING": "WAITING_OPERATION", "BLOCKED": "RECOVERY_BLOCKED", "RESOLVED": "RUNNABLE"}
            wait_state = document.get("state")
            if (document.get("schema") != "SITINA_NATIVE_EXECUTION_WAIT_V1"
                    or document.get("task_id") != task_id
                    or document.get("blocker_id") != "native-execution" or not document.get("wait_id")
                    or wait_state not in status_by_state
                    or document.get("status") != status_by_state[wait_state]
                    or value.get("status") != status_by_state[wait_state]
                    or document.get("goal_version") != state["goal_version"]
                    or document.get("acceptance_version") != state["acceptance_version"]
                    or document.get("handled_input_seq") != state["handled_input_seq"]
                    or state["received_input_seq"] != state["handled_input_seq"]):
                raise StatusReadUnavailable("native wait identity or task binding is invalid")
            if wait_state != "WAITING" and (state.get("waiting_reason") or {}).get("wait_id") != document["wait_id"]:
                raise StatusReadUnavailable("native result has no matching original wait")
            state["waiting_reason"] = document
            state["status"] = status_by_state[wait_state]
            if include_responses:
                responses.append({"id": f"waiting-{task_id}-{event.stream_version}",
                    "reply_to": handled_message_id, "at": event.occurred_at,
                    "status": state["status"], "waiting_reason": document})
        elif kind in {"loop.task-waiting", "loop.task-context-blocked", "loop.task-paused", "loop.task-recovery-blocked"}:
            state["status"] = str(value["status"])
            if kind == "loop.task-recovery-blocked":
                report_ref, report_hash = value.get("stop_report_ref"), value.get("stop_report_hash")
                if not report_ref or not report_hash or str(report_ref) not in event.object_refs:
                    raise StatusReadUnavailable("recovery event lacks a proof-bound stop report")
                report = _read_json(cas, str(report_ref), str(report_hash))
                binding = report.get("pre_stop_binding")
                if (
                    report.get("schema") != "SITINA_LOOP_STOP_REPORT_V1"
                    or report.get("task_id") != task_id
                    or report.get("status") != state["status"]
                    or not isinstance(binding, dict)
                    or binding.get("task_revision") != event.stream_version - 1
                    or binding.get("artifact_ref") != state["artifact_ref"]
                    or binding.get("handled_input_seq") != state["handled_input_seq"]
                ):
                    raise StatusReadUnavailable("recovery stop report differs from its event")
                state["waiting_reason"] = {"blocker_id": report["reason_code"], "reason": report["reason"]}
            if kind in {"loop.task-waiting", "loop.task-context-blocked"}:
                waiting_ref = value.get("waiting_ref")
                waiting_hash = value.get("waiting_hash")
                if not waiting_ref or not waiting_hash or str(waiting_ref) not in event.object_refs:
                    raise StatusReadUnavailable("waiting event lacks a proof-bound reason")
                state["waiting_reason"] = _read_json(cas, str(waiting_ref), str(waiting_hash))
                if include_responses:
                    responses.append({
                        "id": f"waiting-{task_id}-{event.stream_version}",
                        "reply_to": handled_message_id,
                        "at": event.occurred_at,
                        "status": state["status"],
                        "waiting_reason": state["waiting_reason"],
                    })
        elif kind == "loop.task-recovery-docked":
            state["run_instance_id"] = str(value["run_instance_id"])
            state["execution_epoch"] = int(value["execution_epoch"])
            state["status"] = str(value["status"])
        elif kind == "loop.task-recovery-discovered":
            state["status"] = "RECOVERY_BLOCKED"
        elif kind == "loop.task-recovery-claimed":
            state["run_instance_id"] = str(value["run_instance_id"])
            state["execution_epoch"] = int(value["execution_epoch"])
            state["status"] = "RECOVERY_BLOCKED"
        elif kind == "loop.task-recovery-ready":
            state["run_instance_id"] = str(value["run_instance_id"])
            state["execution_epoch"] = int(value["execution_epoch"])
            state["status"] = str(value["status"])
            state["control_intent"] = str(value["control_intent"])
            state["resume_request_id"] = None
            prior_wait = state.get("waiting_reason") or {}
            if (prior_wait.get("blocker_id") == "native-execution"
                    and prior_wait.get("goal_version") == state["goal_version"]
                    and prior_wait.get("acceptance_version") == state["acceptance_version"]
                    and prior_wait.get("handled_input_seq") == state["handled_input_seq"]
                    and state["received_input_seq"] == state["handled_input_seq"]):
                state["status"] = prior_wait["status"]
            else:
                state["waiting_reason"] = None
        elif kind == "loop.task-resume-requested":
            state["resume_request_id"] = str(value["resume_request_id"])
            disposition = value.get("provider_response_disposition")
            if disposition is not None:
                # Keep the missing response in history, but stop counting it
                # as a current blocker once explicitly retired. The complete
                # production replay below validates this authority before any
                # state is returned to the caller.
                request = disposition.get("request") if isinstance(disposition, dict) else None
                operation_id = request.get("operation_id") if isinstance(request, dict) else None
                if not isinstance(operation_id, str) or not operation_id:
                    raise StatusReadUnavailable("Provider disposition lacks its operation identity")
                retired_response_operations.add(operation_id)
                unknown_operations.discard(operation_id)
            update = value.get("software_update_transition")
            if update is not None:
                if (not isinstance(update, dict)
                        or update.get("schema") != "SITINA_LOOP_SOFTWARE_UPDATE_TRANSITION_V1"
                        or update.get("task_id") != task_id
                        or update.get("resume_request_id") != state["resume_request_id"]):
                    raise StatusReadUnavailable("software update receipt differs from its event")
                state["software_update_transition"] = update
        elif kind == "loop.task-terminated":
            result_ref = value.get("result_ref")
            result_hash = value.get("result_hash")
            if not result_ref or not result_hash or str(result_ref) not in event.object_refs:
                raise StatusReadUnavailable("terminal event lacks a proof-bound result")
            terminal_result = _read_json(cas, str(result_ref), str(result_hash))
            if (
                terminal_result.get("schema") != "SITINA_LOOP_TERMINAL_RESULT_V1"
                or terminal_result.get("task_id") != task_id
                or terminal_result.get("terminal_status") != value.get("terminal_status")
                or terminal_result.get("artifact_ref") != value.get("artifact_ref")
            ):
                raise StatusReadUnavailable("terminal result is not bound to its terminal event")
            state["status"] = str(value["terminal_status"])
            state["terminal_event_id"] = str(value["terminal_event_id"])
            state["terminal_result"] = terminal_result
            state["terminal_result_ref"] = str(result_ref)
            state["terminal_result_hash"] = str(result_hash)
            if include_responses:
                responses.append({"id": f"answer-{task_id}", "reply_to": handled_message_id,
                    "at": event.occurred_at, "status": state["status"],
                    "text": str((terminal_result.get("final_result") or {}).get("response") or "")})
            owned_resources.clear()
        elif kind == "loop.attempt-checkpointed":
            reference, content_hash = value.get("checkpoint_ref"), value.get("checkpoint_hash")
            if not reference or not content_hash or reference not in event.object_refs:
                raise StatusReadUnavailable("attempt checkpoint lacks its content proof")
            checkpoint = _read_json(cas, str(reference), str(content_hash))
            if (checkpoint.get("schema") != "SITINA_LOOP_ATTEMPT_CHECKPOINT_V1"
                    or checkpoint.get("task_id") != task_id or checkpoint.get("checkpoint_id") != value.get("checkpoint_id")):
                raise StatusReadUnavailable("attempt checkpoint identity differs from its event")
            summary = checkpoint.get("goal_input")
            binding = checkpoint.get("binding_after_return") or {}
            if (isinstance(summary, dict) and checkpoint.get("reason") in {"GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"}
                    and binding.get("goal_version") == state["goal_version"]
                    and binding.get("criteria_lineage_version") == state["criteria_lineage_version"]):
                baseline = state.get("goal_summary") or summary
                state["goal_summary"] = {**summary, "acceptance_conditions": baseline["acceptance_conditions"]}
                state["goal_summary_source_refs"] = list(dict.fromkeys([
                    *(state.get("goal_summary_source_refs") or ()), *(checkpoint.get("goal_input_source_refs") or ()),
                ]))
        elif kind == "loop.work-plan-updated":
            from .model import validate_work_plan
            reference, content_hash = value.get("plan_ref"), value.get("plan_hash")
            if not reference or not content_hash or reference not in event.object_refs:
                raise StatusReadUnavailable("work plan lacks its content proof")
            record = _read_json(cas, str(reference), str(content_hash))
            previous = state.get("work_plan") or {}
            try:
                validate_work_plan(record, task_id=task_id, goal_version=state["goal_version"],
                                   previous_revision=previous.get("revision", 0))
                if record["goal_version"] != value.get("goal_version") or record["revision"] != value.get("revision"):
                    raise ValueError("work plan event binding differs")
            except ValueError as error:
                raise StatusReadUnavailable("work plan differs from its current task version") from error
            state["work_plan"], state["work_plan_source_ref"] = record, str(reference)
        elif kind == "loop.child-delegation-admitted":
            ref = value.get("contract_ref")
            content_hash = value.get("contract_hash")
            if not ref or not content_hash or str(ref) not in event.object_refs:
                raise StatusReadUnavailable("child admission lacks a proof-bound contract")
            contract = _read_json(cas, str(ref), str(content_hash))
            if contract.get("schema") != "SITINA_LOOP_CHILD_RUNTIME_CONTRACT_V1":
                raise StatusReadUnavailable("child admission contract schema is unsupported")
            state["child_delegations"][str(value.get("delegation_id"))] = {
                "status": "ADMITTED",
                "required": bool(contract.get("required", True)),
                "unknown_effect": False,
                "problem_id": contract.get("problem_id"),
                "parent_attempt_id": contract.get("parent_attempt_id"),
                "generation": contract.get("generation"),
                "child_task_id": contract.get("child_task_id"),
                "parent_binding": dict(contract.get("parent_binding") or {}),
                "applicability": "CURRENT_PARENT_INPUT",
                "physical_send_state": "NOT_STARTED",
                "prior_delegation_id": contract.get("prior_delegation_id"),
                "prior_evidence_fingerprint": contract.get("prior_evidence_fingerprint"),
                "read_resources": list(contract.get("read_resources", ())),
                **{key: contract.get(key) for key in ("delegation_id", "objective", "resources", "permissions",
                   "required_tools", "dependencies", "completion_condition", "failure_history")},
            }
        elif kind == "loop.child-delegation-checkpointed":
            reference, content_hash = value.get("checkpoint_ref"), value.get("checkpoint_hash")
            delegation_id = str(value.get("delegation_id") or "")
            if not reference or not content_hash or reference not in event.object_refs or delegation_id not in state["child_delegations"]:
                raise StatusReadUnavailable("child checkpoint lacks its child or content proof")
            checkpoint = _read_json(cas, str(reference), str(content_hash))
            if checkpoint.get("task_id") != task_id or checkpoint.get("delegation_id") != delegation_id:
                raise StatusReadUnavailable("child checkpoint identity mismatch")
            child = state["child_delegations"][delegation_id]
            child.update({"checkpoint_ref": str(reference), "progress_reason": checkpoint.get("reason") or "progress saved"})
            if checkpoint.get("transition"):
                child.update({"change_reason": checkpoint["transition"]["reason"],
                              "pending_transition": checkpoint["transition"]})
        elif kind == "loop.child-delegation-dispatch-started":
            state["child_delegations"].setdefault(str(value.get("delegation_id")), {}).update({
                "status": "RUNNING",
                "physical_send_state": value.get("physical_send_state"),
            })
        elif kind == "loop.child-delegation-result-recorded":
            ref = value.get("result_ref")
            content_hash = value.get("result_hash")
            if not ref or not content_hash or str(ref) not in event.object_refs:
                raise StatusReadUnavailable("child result lacks a proof-bound result")
            result = _read_json(cas, str(ref), str(content_hash))
            if result.get("schema") != "SITINA_LOOP_CHILD_RUNTIME_RESULT_V1" or result.get("approves_parent") is not False:
                raise StatusReadUnavailable("child result schema or approval flag is invalid")
            child_state = state["child_delegations"].setdefault(str(value.get("delegation_id")), {})
            bound = result.get("parent_binding") if isinstance(result.get("parent_binding"), dict) else {}
            comparable = (
                "task_id", "run_instance_id", "execution_epoch", "goal_version",
                "acceptance_version", "received_input_seq", "handled_input_seq",
                "artifact_ref", "control_intent",
            )
            applicability = "CURRENT_PARENT_INPUT" if all(
                bound.get(key) == state.get(key) for key in comparable
            ) else "LATE_EVIDENCE_ONLY"
            child_state.update({
                "status": "RESULT_PERSISTED",
                "physical_send_state": value.get("physical_send_state"),
                "unknown_effect": str(value.get("physical_send_state") or "") == "UNKNOWN",
                "result_ref": str(ref),
                "result_hash": str(content_hash),
                "evidence_fingerprint": result.get("evidence_fingerprint") or value.get("evidence_fingerprint"),
                "parent_binding": dict(bound),
                "applicability": applicability,
            })
        elif kind == "loop.child-delegation-cancel-requested":
            state["child_delegations"].setdefault(str(value.get("delegation_id")), {})["status"] = "CANCEL_REQUESTED"
        elif kind == "loop.child-delegation-settled":
            ref = value.get("settlement_ref")
            content_hash = value.get("settlement_hash")
            if not ref or not content_hash or str(ref) not in event.object_refs:
                raise StatusReadUnavailable("child settlement lacks a proof-bound settlement")
            settlement = _read_json(cas, str(ref), str(content_hash))
            if settlement.get("schema") != "SITINA_LOOP_CHILD_SETTLEMENT_V1":
                raise StatusReadUnavailable("child settlement schema is unsupported")
            state["child_delegations"].setdefault(str(value.get("delegation_id")), {}).update({
                "status": str(value.get("status") or "SETTLED"),
                "unknown_effect": bool(settlement.get("unknown_effect", False)),
                "settlement_ref": str(ref),
                "settlement_hash": str(content_hash),
                "applicability": str(settlement.get("applicability") or "CURRENT_PARENT_INPUT"),
            })
        elif kind == "loop.child-delegation-applicability-updated":
            ref = value.get("applicability_ref")
            content_hash = value.get("applicability_hash")
            if not ref or not content_hash or str(ref) not in event.object_refs:
                raise StatusReadUnavailable("child applicability lacks a proof-bound evidence")
            applicability = _read_json(cas, str(ref), str(content_hash))
            if applicability.get("schema") != "SITINA_LOOP_CHILD_APPLICABILITY_V1":
                raise StatusReadUnavailable("child applicability schema is unsupported")
            state["child_delegations"].setdefault(str(value.get("delegation_id")), {}).update({
                "applicability": str(value.get("applicability") or applicability.get("applicability") or "LATE_EVIDENCE_ONLY"),
                "applicability_ref": str(ref),
                "applicability_hash": str(content_hash),
            })
        elif kind == "loop.child-delegation-recovery-blocked":
            ref = value.get("recovery_ref")
            content_hash = value.get("recovery_hash")
            if not ref or not content_hash or str(ref) not in event.object_refs:
                raise StatusReadUnavailable("child recovery block lacks proof-bound evidence")
            recovery = _read_json(cas, str(ref), str(content_hash))
            if recovery.get("schema") != "SITINA_LOOP_CHILD_RECOVERY_BLOCKED_V1":
                raise StatusReadUnavailable("child recovery block schema is unsupported")
            state["child_delegations"].setdefault(str(value.get("delegation_id")), {}).update({
                "status": "RECOVERY_BLOCKED",
                "unknown_effect": bool(recovery.get("unknown_effect", True)),
                "recovery_ref": str(ref),
                "recovery_hash": str(content_hash),
                "blocker_id": str(recovery.get("blocker_id") or value.get("blocker_id") or ""),
            })
        elif kind == "loop.task-cancel-reconciliation-recorded":
            # This changes the effective UNKNOWN set, not the historical
            # operation receipt. Mandatory production replay below validates
            # the exact source/intent/result before projecting that choice.
            pass
        elif kind not in no_state_change_events:
            raise StatusReadUnavailable("status reader does not understand event type: " + kind)
        if value.get("stop_report_ref"):
            reference = str(value["stop_report_ref"])
            content_hash = str(value["stop_report_hash"])
            if reference not in event.object_refs:
                raise StatusReadUnavailable("stop report lacks a proof-bound event reference")
            stop_report = _read_json(cas, reference, content_hash)
            if (
                stop_report.get("schema") != "SITINA_LOOP_STOP_REPORT_V1"
                or stop_report.get("task_id") != task_id
                or stop_report.get("status") != state["status"]
            ):
                raise StatusReadUnavailable("stop report identity differs from the stop event")
            state["stop_report_ref"] = reference
            state["stop_report_hash"] = content_hash
            stop_report_event_version = event.stream_version
        state["task_revision"] = event.stream_version
    state["active_operation_ids"] = sorted(active_operations)
    state["unknown_effect_operation_ids"] = sorted(unknown_operations)
    state["owned_resources"] = sorted(owned_resources)
    child_values = tuple(state.get("child_delegations", {}).values())
    waiting_reason = state.get("waiting_reason") or {}
    state["waiting_reason"] = waiting_reason
    if (
        state.get("status") == "WAITING_INPUT"
        and waiting_reason.get("blocker_id") == "child-delegation"
        and child_values
        and state.get("control_intent") == "RUN"
        and state.get("received_input_seq") == state.get("handled_input_seq")
        and all(
            item.get("status") in {"SETTLED", "CANCELLED_VERIFIED", "HANDED_OFF"}
            and not item.get("unknown_effect")
            for item in child_values
        )
    ):
        state["status"] = "RUNNABLE"
    if stop_report is None:
        report_applicability = "NONE"
    else:
        bound = stop_report.get("pre_stop_binding") or {}
        semantic_current = all(
            bound.get(field) == state.get(field)
            for field in (
                "run_instance_id", "execution_epoch", "goal_version", "acceptance_version",
                "criteria_lineage_version", "received_input_seq", "handled_input_seq",
                "artifact_version", "artifact_ref", "control_intent",
            )
        )
        report_applicability = (
            "CURRENT_STOP_STATE"
            if semantic_current
            and stop_report_event_version == state["task_revision"]
            and stop_report.get("status") == state["status"]
            else "HISTORICAL_NOT_CURRENT"
        )
    state["stop_report_applicability"] = report_applicability
    state["historical_unknown_effect_operation_ids"] = sorted(unknown_operations | retired_response_operations)
    state["unknown_effect_observation"] = "AUTHENTICATED_OPERATION_HISTORY"
    if report_applicability == "CURRENT_STOP_STATE":
        operations = stop_report.get("operations")
        effective_unknown = operations.get("unknown_effect_operation_ids") if isinstance(operations, dict) else None
        if (
            not isinstance(effective_unknown, list)
            or any(not isinstance(item, str) or not item for item in effective_unknown)
            or len(set(effective_unknown)) != len(effective_unknown)
            or not set(effective_unknown).issubset(unknown_operations)
        ):
            raise StatusReadUnavailable("current stop report has invalid UNKNOWN operation evidence")
        # This report was authenticated and matched against the exact latest
        # stopped frontier above. Historical operation receipts remain untouched.
        state["unknown_effect_operation_ids"] = sorted(effective_unknown)
        state["unknown_effect_observation"] = "CURRENT_STOP_REPORT"
    if any(event.event_type == 'loop.task-cancel-reconciliation-recorded'
           or (event.event_type == "loop.task-resume-requested"
               and event.payload.get("provider_response_disposition") is not None) for event in task_events):
        from .projection_replay import replay_task_projection_read_only

        try:
            replay = replay_task_projection_read_only(
                task_id, tuple(events),
                read_document=lambda reference, expected_hash=None: _read_json(cas, reference, expected_hash),
            )
        except (PersistenceFenced, TaskConflict, KeyError, TypeError, ValueError) as error:
            raise StatusReadUnavailable("Provider response disposition failed production replay validation") from error
        for field in (
            "task_revision", "run_instance_id", "execution_epoch", "goal_version", "acceptance_version",
            "criteria_lineage_version", "artifact_version", "artifact_ref", "received_input_seq", "handled_input_seq",
        ):
            if getattr(replay, field) != state[field]:
                raise StatusReadUnavailable("task status differs from production replay: " + field)
        if replay.status.value != state["status"] or replay.control_intent.value != state["control_intent"]:
            raise StatusReadUnavailable("task status control differs from production replay")
        replay_unknown = sorted(operation.operation_id for operation in replay.unresolved_effects)
        if report_applicability == "CURRENT_STOP_STATE" and state["unknown_effect_operation_ids"] != replay_unknown:
            raise StatusReadUnavailable("current stop report differs from validated UNKNOWN operations")
        state["provider_response_dispositions"] = replay.provider_response_dispositions
        state["cancel_reconciliation"] = replay.cancel_reconciliation
        state["unknown_effect_operation_ids"] = replay_unknown
        state["unknown_effect_observation"] = "AUTHENTICATED_TASK_REPLAY"
    for observation in telemetry_operations.values():
        actor = observation.get("actor")
        owner = actor.get("execution_owner") if isinstance(actor, dict) else None
        if isinstance(owner, str) and owner in state["child_delegations"]:
            observation["_source_agent"] = {"kind": "child", "task_id": task_id, "delegation_id": owner}
    state["agent_telemetry"] = project_agent_telemetry(
        task_id, tuple(telemetry_operations.values()), state["child_delegations"],
        {name: state[name] for name in ("goal_version", "acceptance_version", "handled_input_seq")},
    )
    if receipt is not None:
        receipt["handled"] = receipt["sequence"] <= state["handled_input_seq"]
    return {
        "status": "ok",
        "live_authority": False,
        "read_only": True,
        "new_coordinator_opened": False,
        "task": state,
        "stop_report": stop_report,
        "stop_report_applicability": report_applicability,
        **({"responses": responses} if include_responses else {}),
        **({"managed_processes": {key: value for key, value in managed_processes.items()
                                  if key not in ignored_managed_processes}} if include_managed_processes else {}),
        **({"input_receipt": receipt or {
            "status": "NOT_FOUND", "task_id": task_id, "input_id": input_id,
        }} if input_id is not None else {}),
    }
