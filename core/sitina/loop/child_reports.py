"""One child work-report contract, with one durable report-only correction."""
from __future__ import annotations
import json
from typing import Any, Mapping

COLLABORATION_HANDOFF_GUIDANCE = (
    "Delegate a bounded objective, non-overlapping business output paths, the exact interfaces needed "
    "by the consumer, dependencies and a checkable completion condition. Include necessary native "
    "read_resources for dependencies separately from owned output resources; a broad read grant must "
    "not become a broad write grant. Shared reads do not reserve output ownership. "
    "source/result references rather than a full chat transcript. Assignment prose cannot grant paths "
    "outside resources. Do not tell a child to write shared /tmp or home paths. For checks use the "
    "existing execution tool's private TMPDIR or an in-memory command with write_paths=[]; business "
    "outputs still require declared resources. On return, read the native child result and the current "
    "versions of files you will consume. Reuse completed evidence with unchanged inputs; rerun only "
    "what changed or remains unverified. Pass the verified interface and result references to the next "
    "child. Before requiring a child to execute repository tests, ensure its actual delegated read "
    "resources cover the repository, test/config/import dependencies and the selected interpreter "
    "environment. Shell permission and a working-directory grant do not supply those reads. If "
    "that access cannot be delegated within existing authorization, run the test in the parent's "
    "authorized context and give its immutable command/result references plus source files to an "
    "independent read-only reviewer; scope that review to checking the actual evidence, not to "
    "claiming that the reviewer ran the test. When a child reports missing access, do not replace "
    "it with the same impossible completion condition: correct the grant/check scope or ask the "
    "user for genuinely missing authorization. Preserve completed code and checks. A child's "
    "success does not approve the parent task. Unknown effects require observation "
    "of the original operation, never a repeat submission."
)

def child_work_contract(resources, permissions, read_resources=()) -> dict[str, Any]:
    """Model-facing guidance derived from the existing grant; creates no authority."""
    return {
        "business_resources": list(resources),
        "read_resources": list(read_resources),
        "permissions": list(permissions),
        "path_guidance": (
            "These are your actual delegated business resources. A path mentioned in an assignment "
            "does not expand this list. Additional read_resources allow reads and discovery only, "
            "never writes. The combined read boundary still applies to discovery. A file "
            "grant authorizes that file, not listing or searching its parent directory or siblings. "
            "Read the supplied exact file paths or native source references directly. If the supplied "
            "inputs already answer the assigned question, finish from that evidence instead of doing "
            "ambient directory discovery. Discover a directory only when it is itself covered by the "
            "delegated resources and discovery is necessary for a specific unresolved requirement. "
            "An optional refused discovery is not missing business evidence: preserve the usable "
            "inputs, omit that action and continue. Ask the parent for a missing path only when it is "
            "actually required to complete the assignment; never request broader access merely to "
            "avoid a refusal. sitina_write_file/edit_file write only owned business paths, "
            "not /tmp, /private/tmp or a parent's unrelated files. For a check that needs no business "
            "output, use sitina_exec with write_paths=[] and the installed interpreter; use -c/stdin "
            "or tempfile inside that execution's existing TMPDIR. The execution tool supplies private "
            "runtime scratch; do not grant or hard-code a shared temporary root. "
            "For file-only grants, the working directory is navigation, not permission to import all "
            "of it. Load a declared Python file by its actual absolute path (runpy/importlib) when "
            "needed; do not depend on an undelegated ambient module search path. "
            "A file-only grant cannot run a repository test suite or import an undelegated environment. "
            "If a required check fails because its repository, configuration, interpreter prefix or "
            "dependency files are denied, stop that check and report BLOCKED with the exact missing "
            "paths, attempted command and receipt. Do not repeat unchanged commands, change PYTHONHOME "
            "or use interpreter/path aliases to evade the boundary. An isolated extracted-function "
            "check cannot substitute for a required real repository test; label its narrower scope. "
            "If a required business output lies outside these resources, report the exact path and reason to the parent. "
            "Never retry a refused path under a spelling alias or widen your own permissions."
        ),
        "handoff_guidance": (
            "Before running an assigned check, identify which completion condition it verifies and "
            "bind verification_inputs to the actual source, test and configuration files it consumes, "
            "within your delegated read resources. An empty or guessed binding is not evidence of "
            "the current version. Preserve native check receipts and failures; do not rerun an "
            "unchanged valid check merely to rewrite its report. A negative-test observation is not "
            "a successful positive check. Use the existing six-field work-report JSON. In completed_work, separate Files "
            "(actual path and native version/operation reference), Interfaces (names, inputs, outputs "
            "and invariants), and Checks (actual command/receipt and outcome, including scope limits). "
            "Keep evidence as actual paths or native operation references. In remaining_work identify "
            "the unfinished step, blocker and next action/required input. Never invent a version, "
            "receipt or check. Preserve UNKNOWN operation references without replay. Recovered errors "
            "belong in summary/completed_work; errors contains current unresolved failures only."
        ),
    }

def validate_child_work_report(response: str) -> dict[str, Any]:
    parsed = json.loads(response)
    fields = {"status", "summary", "completed_work", "remaining_work", "errors", "evidence"}
    if not isinstance(parsed, dict) or set(parsed) != fields:
        raise ValueError("child report requires exactly status, summary, completed_work, remaining_work, errors and evidence")
    if not isinstance(parsed["status"], str) or parsed["status"] not in {"SUCCEEDED", "FAILED", "BLOCKED"} or not isinstance(parsed["summary"], str):
        raise ValueError("child report status or summary is invalid")
    for key in fields - {"status", "summary"}:
        if not isinstance(parsed[key], list) or any(not isinstance(item, str) for item in parsed[key]):
            raise ValueError("child report " + key + " must be an array of strings")
    if parsed["status"] == "SUCCEEDED":
        if parsed["remaining_work"]:
            raise ValueError("SUCCEEDED requires remaining_work=[] for the assigned work item")
        if parsed["errors"]:
            raise ValueError("SUCCEEDED requires errors=[]; errors records current unresolved failures, while resolved history belongs in summary/completed_work")
        if not parsed["evidence"]:
            raise ValueError("SUCCEEDED requires actual evidence references")
    return parsed

def _repair_logical_id(adapter: Any) -> str:
    if not adapter.execution_owner:
        raise ValueError("child report correction requires an actual delegation")
    return "child-report-repair:" + adapter.execution_owner

def _repair_operations(adapter: Any):
    logical = _repair_logical_id(adapter)
    return [item for item in adapter.backend.get_task(adapter.task_id).operations.values()
            if item.logical_operation_id == logical and item.execution_owner == adapter.execution_owner]

def authorize_child_report_repair(adapter: Any, reason: str) -> bool:
    """Consume the delegation allowance before making its correction request."""
    from .model import EffectStatus, OperationMode
    from .operations import OperationOutcome
    with adapter.backend._state_lock:
        if _repair_operations(adapter):
            return False
        original = adapter.operation_ids[-1] if adapter.operation_ids else None
        operation = adapter.backend.get_task(adapter.task_id).operations.get(original)
        if operation is None or not original.startswith("provider-") or not operation.result_ref or operation.unknown_effect:
            raise ValueError("child report correction requires the actual completed Provider reply")
        intent = adapter._intent(category="child-report-repair", logical_id=_repair_logical_id(adapter),
            mode=OperationMode.READ, description="consume the delegation single report-only correction")
        payload = {"schema": "SITINA_CHILD_REPORT_REPAIR_V1", "limit": 1, "reason": reason,
            "original_provider_operation_id": original, "original_result_ref": operation.result_ref,
            "business_tools_allowed": False, "delegation_id": adapter.execution_owner}
        outcome = adapter.backend.execute_operation(adapter.task_id, intent,
            lambda: OperationOutcome(EffectStatus.SUCCEEDED, payload))
        adapter.record_operation_result(intent, outcome)
        return outcome.status is EffectStatus.SUCCEEDED

def recover_child_work_report(adapter: Any) -> str | None:
    """After restart use an actual saved correction reply, or stop without resending."""
    from .model import EffectStatus, OperationRejected
    repairs = _repair_operations(adapter)
    if not repairs:
        return None
    if len(repairs) != 1 or not repairs[0].result_ref or repairs[0].unknown_effect:
        raise OperationRejected("child report correction ownership is unresolved; do not resend")
    task = adapter.backend.get_task(adapter.task_id)
    events = list(adapter.backend.store.task_events(adapter.task_id))
    marker = next((int(event.position) for event in events
        if event.event_type == "loop.operation-result-recorded" and event.payload.get("operation_id") == repairs[0].operation_id), None)
    if marker is None:
        raise OperationRejected("child report correction has no authenticated allowance receipt")
    candidates = []
    operation_ids = []
    for event in events:
        operation_id = event.payload.get("operation_id")
        operation = task.operations.get(operation_id)
        if operation is None or operation.execution_owner != adapter.execution_owner:
            continue
        if event.event_type == "loop.operation-result-recorded":
            operation_ids.append(operation_id)
        if (event.event_type == "loop.operation-intent-recorded" and int(event.position) > marker
                and operation_id.startswith("provider-")):
            candidates.append(operation)
    if not candidates:
        raise OperationRejected("child report correction allowance already consumed; no saved response, do not resend")
    latest = candidates[-1]
    if latest.unknown_effect or not latest.result_ref or latest.effect_status is not EffectStatus.SUCCEEDED:
        raise OperationRejected("child report correction response is unresolved; do not resend")
    document = adapter.backend.context_memory.read(latest.result_ref)
    result = document.get("result")
    if not isinstance(result, Mapping) or result.get("tool_calls") or not isinstance(result.get("text"), str):
        raise OperationRejected("saved correction is not a final child work report")
    try:
        validate_child_work_report(result["text"])
    except (ValueError, TypeError) as error:
        raise OperationRejected("saved correction still violates the child report contract: " + str(error)) from error
    adapter.operation_ids.extend(operation_ids)
    return result["text"]
