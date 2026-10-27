"""The task execution surface on the existing Loop operation/receipt ledger."""
from __future__ import annotations

import json
import hashlib
import os
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from sitina.execution import (TASK_EXECUTION_CONTRACT, EXECUTION_TOOLS, ExecutionDenied,
    TASK_PROCESS_OWNERSHIP_SCOPE, FULL_PROCESS_TREE_ENFORCEMENT_AVAILABLE,
    ExecutionPolicy, ExecutionRequest, command_control, execution_authorization,
    read_command_output, task_environment)
from sitina.extensions.tools import ToolResult
from sitina.utils import iso_now
from .command_runner import (TASK_COMMAND_POLICY, CommandRunner, observe_managed_command,
    start_managed_command, _read_json, _write_json, _hash_bytes)
from .model import ControlIntent, EffectStatus, OperationMode
from .operations import FilePrecondition, OperationOutcome

_GATEWAYS: dict[tuple[str, str, str, str], Any] = {}
# Revoked ports remain deny-only reservations while this Host is alive.
# Host death and detached-descendant settlement still need a stronger owner.
_REVOKED_GATEWAYS: list[tuple[tuple[str, str, str, str], Any]] = []
_GATEWAY_LOCK = threading.RLock()


def _committed_setting_operations(backend: Any, task_id: str, prefix: str):
    """Use authenticated result-event order, never a serialized map's key order."""
    task = backend.get_task(task_id)
    candidates = {key: operation for key, operation in task.operations.items()
                  if key.startswith(prefix) and operation.result_ref and not operation.unknown_effect}
    seen = set()
    for event in backend.store.task_events(task_id):
        if event.event_type != "loop.operation-result-recorded":
            continue
        operation_id = event.payload.get("operation_id")
        operation = candidates.get(operation_id)
        if operation is not None and event.payload.get("result_ref") == operation.result_ref:
            seen.add(operation_id)
            yield operation
    if seen != set(candidates):
        raise ExecutionDenied("task setting result lacks its authenticated commit event")


def execution_state(backend: Any, task_id: str, workspace: Path) -> dict[str, Any]:
    """Rebuild explicit task environment/scope from committed native results."""
    state = {"environment": {}, "read_roots": [str(workspace)], "write_roots": [str(workspace)]}
    for operation in _committed_setting_operations(backend, task_id, "execution-environment-"):
        if not operation.operation_id.startswith("execution-environment-") or not operation.result_ref or operation.unknown_effect:
            continue
        document = backend.context_memory.read(str(operation.result_ref))
        value = document.get("result") if isinstance(document, Mapping) else None
        saved = value.get("execution_state") if isinstance(value, Mapping) else None
        if isinstance(saved, Mapping) and document.get("effect_status") == EffectStatus.SUCCEEDED.value:
            state = {key: dict(saved[key]) if key == "environment" else list(saved[key]) for key in state}
    state["local_access"] = {
        "mode": "current_user", "home": str(Path.home()),
        "read_scope": "all paths readable by the current OS user",
        "write_scope": "all paths writable by the current OS user, when task writes are authorized",
        "scope_roots_meaning": "tracked task paths for snapshots and coordination, not a local access allowlist",
        "includes_host_state_and_credentials": True, "sudo_or_root_granted": False,
        "network": "existing restrictions remain; a writable Host is not a tamper-proof boundary",
    }
    return state


def task_skill_binding(backend: Any, task_id: str) -> dict[str, Any] | None:
    """Read the current task-local selection from its existing operation history."""
    binding = None
    for operation in _committed_setting_operations(backend, task_id, "task-skill-binding-"):
        if not operation.operation_id.startswith("task-skill-binding-") or not operation.result_ref or operation.unknown_effect:
            continue
        document = backend.context_memory.read(str(operation.result_ref))
        value = document.get("result") if isinstance(document, Mapping) else None
        if (document.get("effect_status") == EffectStatus.SUCCEEDED.value and isinstance(value, Mapping)
                and isinstance(value.get("task_skill_binding"), Mapping)):
            binding = dict(value["task_skill_binding"])
    return binding


def ensure_task_skills(adapter: Any, manager: Any) -> dict[str, Any]:
    binding = task_skill_binding(adapter.backend, adapter.task_id)
    if binding is None:
        binding = manager.bind_task_skills(adapter.task_id)
        intent = adapter._intent(category="task-skill-binding", logical_id="initial",
            mode=OperationMode.READ, description="pin authenticated global Skill versions for this task")
        outcome = adapter.backend.execute_operation(adapter.task_id, intent, lambda: OperationOutcome(
            EffectStatus.SUCCEEDED, {"task_skill_binding": binding}))
        if outcome.status is not EffectStatus.SUCCEEDED:
            raise ExecutionDenied("task Skill pin did not complete")
        adapter.record_operation_result(intent, outcome)
        binding = dict(outcome.result["task_skill_binding"])
    manager.task_skill_summaries(binding, task_id=adapter.task_id)
    adapter._task_skill_manager = manager
    adapter._task_skill_roots = manager.task_skill_resource_roots(binding, task_id=adapter.task_id)
    return binding


def task_skill_model_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return requested guidance once; keep the complete pin ledger internal."""
    public = {key: item for key, item in value.items() if key != "task_skill_binding"}
    binding = value.get("task_skill_binding")
    if not isinstance(binding, Mapping):
        return public
    public["task_skill_identity"] = {key: binding[key] for key in
        ("schema", "task_id", "authority_position", "authority_stream_id") if key in binding}
    skill = public.get("skill")
    if isinstance(skill, Mapping) and isinstance(skill.get("body"), str):
        pins = [pin for pin in binding.get("skills", ())
                if isinstance(pin, Mapping) and pin.get("qualified_name") == skill.get("qualified_name")]
        identity = {key: pins[0][key] for key in ("candidate_id", "snapshot_id", "version")
                    if key in pins[0]} if len(pins) == 1 else {}
        public["skill"] = {**dict(skill), **identity,
            "body_sha256": hashlib.sha256(skill["body"].encode("utf-8")).hexdigest()}
    return public


def execution_policy(runtime: Any, adapter: Any, *, state: Mapping[str, Any] | None = None,
                     write_paths: list[str] | None = None) -> ExecutionPolicy:
    current = state or execution_state(adapter.backend, adapter.task_id, adapter.workspace)
    reads = tuple(Path(p).resolve() for p in current["read_roots"])
    writable = bool(adapter.mutation_allowed and getattr(runtime, "approve_writes", False))
    writes = tuple(Path(p).resolve() for p in current["write_roots"]) if writable else ()
    credentials = tuple(runtime.boundary.credential_references)
    # Local access is explicitly user-authorized. Keep tracked roots bounded:
    # permitting the host filesystem must never snapshot or reserve all of it.
    excluded = ()
    parent = ExecutionPolicy(adapter.task_id, reads, writes, excluded, credential_roots=credentials,
        full_local_read=True, full_local_write=writable)
    if adapter.execution_owner:
        if not adapter.backend.child_execution_current(adapter.task_id, adapter.execution_owner):
            raise ExecutionDenied("child execution authority is no longer current")
        child = adapter.backend.get_task(adapter.task_id).child_delegations[adapter.execution_owner]
        resources = tuple(Path(p).expanduser() for p in child.get("resources", ()))
        resources = tuple(p if p.is_absolute() else adapter.workspace / p for p in resources)
        # Dependency reads are not business write ownership. In particular,
        # reading a repository must not grant writes to every sibling module.
        read_resources = tuple(Path(p).expanduser() for p in child.get("read_resources", ()))
        if any(not p.is_absolute() for p in read_resources):
            raise ExecutionDenied("child read resource is not an absolute path")
        reads = tuple(dict.fromkeys(parent.check_path(p) for p in (*resources, *read_resources)))
        # Shell permission permits process execution; business-file writes
        # additionally require this delegation's explicit write permission.
        writes = tuple(parent.check_path(p, write=True) for p in resources) if (
            writable and "write" in child.get("permissions", ())
        ) else ()
        parent = ExecutionPolicy(adapter.task_id, reads, writes, excluded, credential_roots=credentials)
    if write_paths is not None:
        selected = tuple(Path(p).expanduser() for p in write_paths)
        writes = tuple(parent.check_path(p if p.is_absolute() else adapter.workspace / p, write=True) for p in selected)
    reads = (*reads, *getattr(adapter, "_task_skill_roots", ()))
    return ExecutionPolicy(adapter.task_id, reads, writes, excluded, credential_roots=credentials,
        full_local_read=not bool(adapter.execution_owner),
        full_local_write=bool(writable and not adapter.execution_owner and write_paths is None),
        allow_system_power_notifications=bool(writable and not adapter.execution_owner),
        allow_local_ipc=bool(writable and not adapter.execution_owner))



def assert_execution_resources_available(backend, task_id, paths, *, ignore=None):
    requested = tuple(Path(p).resolve() for p in paths)
    if not requested:
        return
    for owner_task_id in backend.store.task_ids():
        for process_id, evidence in backend.managed_process_evidence(owner_task_id).items():
            if (owner_task_id == task_id and process_id == ignore) or evidence.get("execution_contract") != TASK_EXECUTION_CONTRACT:
                continue
            owned = tuple(Path(p).resolve() for p in evidence.get("write_roots", ()))
            conflict = any(a == b or a in b.parents or b in a.parents for a in requested for b in owned)
            if not conflict:
                continue
            observation = observe_managed_command(evidence, task_id=owner_task_id, operation_id=process_id)
            if observation.get("decision") not in {"SUCCEEDED", "NO_EFFECT"}:
                raise ExecutionDenied("resource is owned by an active or unresolved execution: " + process_id)


_BASELINE_MAX_ENTRIES = 50_000
_BASELINE_MAX_FILES = 5_000
_BASELINE_MAX_BYTES = 256 * 1024 * 1024
_BASELINE_TIMEOUT_SECONDS = 5.0


def _bounded_baseline_paths(roots, deadline):
    selected, pending = [], list(dict.fromkeys(Path(root) for root in roots))
    seen, entries, total_bytes = set(), len(pending), 0
    excluded = {".git", ".venv", "venv", "node_modules", "__pycache__"}

    def budget():
        if (entries > _BASELINE_MAX_ENTRIES or len(selected) > _BASELINE_MAX_FILES
                or total_bytes > _BASELINE_MAX_BYTES or time.monotonic() > deadline):
            raise ExecutionDenied(
                "automatic backup preparation limit exceeded; no command was started. "
                "Use write_paths for the concrete files or smaller task directory instead of a broad parent."
            )

    while pending:
        budget()
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        try:
            info = path.lstat()
        except FileNotFoundError:
            selected.append(path)
            budget()
            continue
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as children:
                for child in children:
                    entries += 1
                    budget()
                    if child.name in excluded and child.is_dir(follow_symlinks=False):
                        continue
                    pending.append(Path(child.path))
        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            selected.append(path)
            total_bytes += info.st_size
            budget()
        else:
            raise ExecutionDenied(
                "automatic backup cannot capture this filesystem object type; no command was started. "
                "Use write_paths for the concrete files or a smaller task directory."
            )
    return selected


def capture_execution_baseline(runtime, adapter, roots):
    from sitina.task_workspace import WorkspaceManager
    deadline = time.monotonic() + _BASELINE_TIMEOUT_SECONDS
    selected = _bounded_baseline_paths(roots, deadline)
    manager = WorkspaceManager(adapter.workspace,
        runtime.boundary.state_root / "checks" / "task-file-baselines" / adapter.task_id, adapter.task_id)
    for path in selected:
        if time.monotonic() > deadline:
            raise ExecutionDenied(
                "automatic backup preparation time limit exceeded; completed backups are retained, "
                "but no command was started. Narrow write_paths before continuing."
            )
        manager.capture_baseline([path])
    return manager


def _gateway_scope(runtime, adapter):
    task = adapter.backend.get_task(adapter.task_id)
    authorization = execution_authorization(adapter.backend, adapter.task_id)
    child = task.child_delegations.get(adapter.execution_owner, {}) if adapter.execution_owner else None
    if adapter.execution_owner and not adapter.backend.child_execution_current(adapter.task_id, adapter.execution_owner):
        raise ExecutionDenied("child network authority is no longer current")
    allowed = child is None or "network" in child.get("permissions", ())
    public = bool(allowed and authorization.get("public_web_read") is True)
    exact = tuple(authorization.get("network_read_urls", ())) if allowed else ()
    policy = execution_policy(runtime, adapter)
    binding = {"goal_version": task.goal_version, "acceptance_version": task.acceptance_version,
               "execution_epoch": task.execution_epoch, "public_read": public, "exact_urls": exact,
               "permissions": sorted(child.get("permissions", ())) if child else "parent",
               "read_roots": [str(p) for p in policy.read_roots], "write_roots": [str(p) for p in policy.write_roots]}
    digest = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return (str(runtime.boundary.state_root), adapter.task_id, adapter.execution_owner or "main", digest), public, exact


def close_task_gateways(state_root, task_id, *, execution_owner=None):
    """Revoke forwarding while retaining the original deny-only port reservations."""
    reports = []
    with _GATEWAY_LOCK:
        for key, gateway in tuple(_GATEWAYS.items()):
            if key[:2] != (str(state_root), task_id) or (execution_owner is not None and key[2] != execution_owner):
                continue
            gateway.revoke()
            _REVOKED_GATEWAYS.append((key, gateway))
            reports.append(gateway.lifecycle_status())
            del _GATEWAYS[key]
    return reports


def revoke_process_services(state_root, task_id: str, process_id: str) -> list[dict[str, Any]]:
    """Cancel this original owner's service authority on existing gateways."""
    with _GATEWAY_LOCK:
        gateways = tuple(gateway for key, gateway in _GATEWAYS.items()
                         if key[:2] == (str(state_root), task_id))
    # Do not hold the registry lock while cancelling active network workers.
    # Revocation neither creates a gateway nor claims to undo sent requests.
    reports = []
    for gateway in gateways:
        try:
            reports.append(gateway.revoke_service(process_id))
        except Exception as error:
            # Keep earlier observations and try the other independent gateways.
            # A failed cleanup must not erase the original process-stop receipt.
            reports.append({"process_id": process_id, "method_status": "error",
                "registration_revoked": None, "connection_cancellation_requested": None,
                "active_connections_observed": None, "forwarded_effects": "NOT_INFERRED",
                "error_type": type(error).__name__, "error": str(error)})
    return reports


def _gateway(runtime: Any, adapter: Any, arguments: Mapping[str, Any], *, before_revoke=None) -> Any:
    from sitina.execution_network import TaskNetworkGateway, NetworkPolicyError
    urls, git_urls = arguments.get("network_urls", []), arguments.get("git_urls", [])
    if (not isinstance(urls, list) or not isinstance(git_urls, list)
            or not all(isinstance(p, str) for p in (*urls, *git_urls))):
        raise ExecutionDenied("network_urls and git_urls must be explicit URL arrays")
    key, public, exact = _gateway_scope(runtime, adapter)
    # A nominated URL selects a destination only; the descriptor's anonymous-read grant supplies authority.
    if (urls or git_urls) and not public and any(p not in exact for p in (*urls, *git_urls)):
        raise ExecutionDenied("network scope exceeds the parent task authorization")
    def current_authority(event):
        if _gateway_scope(runtime, adapter)[0] != key or adapter.backend.get_task(adapter.task_id).control_intent is ControlIntent.CANCEL:
            raise NetworkPolicyError("TASK_NETWORK_AUTHORITY_REVOKED")
    with _GATEWAY_LOCK:
        for old_key, old_gateway in tuple(_GATEWAYS.items()):
            if old_key[:3] == key[:3] and old_key != key:
                if before_revoke is not None:
                    before_revoke()
                old_gateway.revoke()
                _REVOKED_GATEWAYS.append((old_key, old_gateway))
                del _GATEWAYS[old_key]
        gateway = _GATEWAYS.get(key)
        if gateway is None:
            root = runtime.boundary.state_root / "checks" / "task-network" / adapter.task_id / (key[2] + "-" + key[3][:16])
            gateway = TaskNetworkGateway(root, adapter.task_id, public_read=public or bool(exact),
                public_git=public or bool(exact), allowed_urls=exact,
                dependency_registry_reads=public, audit=current_authority)
            gateway.start()
            _GATEWAYS[key] = gateway
        gateway.authorize_urls(urls)
        gateway.authorize_git_urls(git_urls)
        return gateway


def observe_task_control_evidence(evidence: Mapping[str, Any], *, task_id: str, operation_id: str) -> dict[str, Any]:
    """Read an original Host completion; never reapply a control or create a gateway."""
    def unknown(reason):
        return {"decision": "UNKNOWN", "reason": reason}

    required = {"task_id", "operation_id", "effect_kind", "control_kind", "process_id",
                "command_manifest_path", "command_manifest_hash", "control_root",
                "completion_path", "completion_nonce", "run_instance_id", "execution_epoch",
                "tool_name", "tool_arguments"}
    if not required <= set(evidence):
        return unknown("native-control-effect-binding-incomplete")
    if (evidence["task_id"] != task_id or evidence["operation_id"] != operation_id
            or evidence["effect_kind"] != "task-control"
            or evidence["control_kind"] != "service_registration"
            or evidence["tool_name"] != "sitina_register_service"):
        return unknown("native-control-effect-binding-mismatch")
    if not isinstance(evidence["completion_nonce"], str) or len(evidence["completion_nonce"]) != 64:
        return unknown("native-control-completion-nonce-invalid")
    arguments = evidence["tool_arguments"]
    if (not isinstance(arguments, Mapping) or arguments.get("process_id") != evidence["process_id"]
            or type(arguments.get("port")) is not int or not 1 <= arguments["port"] <= 65535):
        return unknown("native-control-arguments-invalid")
    try:
        root, path = Path(evidence["control_root"]), Path(evidence["completion_path"])
        if (not root.is_absolute() or root.name != operation_id
                or path != root / "native-control-result.json" or path.is_symlink()):
            return unknown("native-control-completion-path-mismatch")
        manifest_raw = Path(evidence["command_manifest_path"]).read_bytes()
        manifest = json.loads(manifest_raw)
        if (_hash_bytes(manifest_raw) != evidence["command_manifest_hash"]
                or not isinstance(manifest, Mapping) or manifest.get("task_id") != task_id
                or manifest.get("operation_id") != evidence["process_id"]
                or manifest.get("execution_contract") != TASK_EXECUTION_CONTRACT):
            return unknown("native-control-process-binding-mismatch")
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            return unknown("native-control-completion-too-large")
        completion = json.loads(raw)
    except (OSError, TypeError, ValueError):
        return unknown("native-control-completion-unavailable")
    expected = {"schema": "SITINA_TASK_CONTROL_COMPLETION_V1",
        "task_id": task_id, "operation_id": operation_id, "process_id": evidence["process_id"],
        "command_manifest_hash": evidence["command_manifest_hash"],
        "run_instance_id": evidence["run_instance_id"], "execution_epoch": evidence["execution_epoch"],
        "tool_name": evidence["tool_name"], "tool_arguments": dict(arguments),
        "nonce": evidence["completion_nonce"]}
    if (not isinstance(completion, Mapping) or set(completion) != set(expected) | {"effect_status", "result"}
            or any(completion[key] != value for key, value in expected.items())):
        return unknown("native-control-completion-binding-mismatch")
    value, status = completion["result"], completion["effect_status"]
    if not isinstance(value, Mapping) or value.get("tool") != evidence["tool_name"] or value.get("arguments") != arguments:
        return unknown("native-control-completion-result-invalid")
    if status == EffectStatus.SUCCEEDED.value:
        if (value.get("status") != "REGISTERED" or value.get("process_id") != evidence["process_id"]
                or value.get("host") != "127.0.0.1" or value.get("port") != arguments["port"]):
            return unknown("native-control-completion-result-invalid")
    elif status == EffectStatus.FAILED.value:
        if value.get("state") != "REJECTED" or value.get("registration_changed") is not False:
            return unknown("native-control-completion-result-invalid")
    else:
        return unknown("native-control-completion-not-final")
    return {"decision": status, "effect_status": status, "result": dict(value),
            "completion_hash": _hash_bytes(raw),
            "completion_path": str(path), "reason": "original-host-terminal-control-receipt",
            "current_service_availability": "NOT_INFERRED"}

def _owned(adapter: Any, process_id: str) -> Mapping[str, Any]:
    evidence = adapter.backend.managed_process_evidence(adapter.task_id).get(process_id)
    if not isinstance(evidence, Mapping) or evidence.get("execution_contract") != TASK_EXECUTION_CONTRACT:
        raise ExecutionDenied("process is not a task-owned general execution")
    if adapter.execution_owner and evidence.get("execution_owner") != adapter.execution_owner:
        raise ExecutionDenied("a child may control only its own execution")
    return evidence


def execution_verification(adapter, process_id):
    """Expose only original receipt and prepared check bindings to the file verifier."""
    evidence = _owned(adapter, process_id)
    return {**public_execution(adapter, process_id), "task_id": adapter.task_id,
            "workspace_check_binding": evidence.get("workspace_check_binding")}


def public_execution(adapter: Any, process_id: str, *, include_output: bool = False,
                     offsets: Mapping[str, int] | None = None, stop: bool = False,
                     control_request_id: str | None = None) -> dict[str, Any]:
    evidence = _owned(adapter, process_id)
    observation = observe_managed_command(evidence, task_id=adapter.task_id, operation_id=process_id,
                                          stop=stop, reason="task-execution-stop")
    manifest = observation.get("manifest")
    if not isinstance(manifest, Mapping):
        manifest = _read_json(Path(evidence["command_manifest_path"])) or {}
    completion = observation.get("completion")
    completion = completion if isinstance(completion, Mapping) else {}
    root_result = observation.get("root_result")
    root_result = root_result if isinstance(root_result, Mapping) else {}
    decision = observation.get("decision")
    state = "STOPPED" if decision == "SUCCEEDED" else "NOT_STARTED" if decision == "NO_EFFECT" else "RUNNING" if decision == "RUNNING" else "UNKNOWN"
    exit_code = completion.get("exit_code", root_result.get("exit_code"))
    program = ("NOT_RUN" if completion.get("status") == "NOT_STARTED" or state == "NOT_STARTED" else
               "RUNNING" if state == "RUNNING" else "UNKNOWN" if state == "UNKNOWN" else
               completion["status"] if completion.get("status") in {"CANCELLED", "TIMED_OUT"} else
               "PASS" if exit_code == 0 else "FAIL")
    value = {
        "process_id": process_id, "owner_operation_id": process_id, "state": state,
        "effect_kind": "command", "execution_contract": TASK_EXECUTION_CONTRACT,
        "program_status": program, "exit_code": exit_code, "returncode": exit_code,
        "completion_status": completion.get("status"), "effect_settled": state in {"STOPPED", "NOT_STARTED"},
        "root_status": root_result.get("root_status"),
        "root_exit_code": root_result.get("exit_code"),
        "root_result_hash": observation.get("root_result_hash"),
        "trusted_root_result": observation.get("trusted_root_result") is True,
        "root_result_source": observation.get("root_result_source"),
        "process_group_cleanup": completion.get("process_group_cleanup"),
        "raw_logs_complete": observation.get("raw_logs_complete"),
        "process_ownership_scope": TASK_PROCESS_OWNERSHIP_SCOPE,
        "effect_settlement_scope": TASK_PROCESS_OWNERSHIP_SCOPE,
        "full_process_tree_enforced": FULL_PROCESS_TREE_ENFORCEMENT_AVAILABLE,
        "execution_started": observation.get("reason") != "authorized-not-started" and state != "NOT_STARTED",
        "recovery_decision": decision, "reason": observation.get("reason"),
        "command": manifest.get("argv"), "shell_text": evidence.get("shell_text"),
        "reply_to": evidence.get("reply_to"),
        "reply_binding_known": "reply_to" in evidence,
        "cwd": manifest.get("cwd"), "pty": bool(manifest.get("pty")), "keep": bool(manifest.get("keep")),
        "mode": "pty" if manifest.get("pty") else "process", "command_policy": TASK_COMMAND_POLICY,
        "environment_ref": evidence.get("command_manifest_path"),
        "declared_environment": manifest.get("environment"), "actual_environment": "NOT_OBSERVED",
        "manifest_ref": evidence.get("command_manifest_path"), "manifest_hash": evidence.get("command_manifest_hash"),
        "completion_hash": observation.get("completion_hash"),
        "trusted_completion": decision == "SUCCEEDED" and bool(observation.get("completion_hash")),
        "input_owner": (_read_json(Path(evidence["command_manifest_path"]).parent / "input-owner.json") or {"owner": "agent"})["owner"],
        "output_paths": {"stdout": manifest.get("stdout_path"), "stderr": manifest.get("stderr_path")},
    }
    verification_before = evidence.get("verification_inputs_before")
    if value["trusted_completion"] and isinstance(verification_before, Mapping) and verification_before:
        from .task_runtime import _native_file_versions

        value["verification_inputs"] = {"before": dict(verification_before),
            "after": _native_file_versions(tuple(verification_before)),
            "scope": "declared inputs before dispatch and observed after exit"}
    value["control_ack"] = _read_json(Path(evidence["command_manifest_path"]).parent / "control-ack.json")
    if include_output:
        value["output"] = read_command_output(evidence, offsets=offsets, control_request_id=control_request_id)
        value["control_ack"] = value["output"]["control_ack"]
    # The raw receipts remain byte-bound in their original files.  Public
    # projections also enter the canonical operation journal, which forbids
    # floats (including timestamps in control acknowledgements and cleanup).
    from .task_runtime import _canonical_safe

    return _canonical_safe(value)


def _execution_permission(name: str) -> str:
    if name in {"sitina_task_skills", "sitina_process_status", "sitina_process_log"}:
        return "read"
    return "write" if name in {"sitina_task_environment", "sitina_manage_skills"} else "shell"


def execute_task_tool(runtime: Any, adapter: Any, run_id: str, call: Any, authorization_ref: str) -> ToolResult:
    """Replay an existing invocation before allowing any new side effect."""
    name, arguments = call.name, dict(call.arguments)
    logical_id = f"{run_id}:{call.call_id}" if name == "sitina_task_environment" else f"{run_id}:{name}:{call.call_id}"
    with adapter.backend._state_lock:
        # Serialize replay/admission without blocking the gateway authority reads.
        invocation_lock = getattr(adapter.backend, "_task_execution_lock", None)
        if invocation_lock is None:
            invocation_lock = threading.RLock()
            adapter.backend._task_execution_lock = invocation_lock
    with invocation_lock:
        task = adapter.backend.get_task(adapter.task_id)
        matches = [item for item in task.operations.values() if item.logical_operation_id == logical_id]
        if len(matches) > 1:
            raise ExecutionDenied("execution invocation has ambiguous original ownership")
        if matches:
            previous = matches[0]
            if name in {"sitina_shell", "sitina_exec", "sitina_process_start"} and previous.operation_id.startswith("managed-process-"):
                evidence = _owned(adapter, previous.operation_id)
                if evidence.get("tool_name") != name or evidence.get("tool_arguments") != arguments:
                    raise ExecutionDenied("execution invocation id was reused with different arguments")
                value = public_execution(adapter, previous.operation_id, include_output=True)
                value.update({"tool": name, "arguments": arguments, "permission": "shell", "replayed": True})
            else:
                document = adapter.backend.context_memory.read(str(previous.result_ref)) if previous.result_ref else None
                value = document.get("result") if isinstance(document, Mapping) else None
                if not isinstance(value, Mapping) or value.get("arguments") != arguments or value.get("tool") != name:
                    raise ExecutionDenied("original invocation is unresolved; do not dispatch a replacement")
                value = {**value, "replayed": True}
                if name == "sitina_task_skills":
                    value = task_skill_model_result(value)
            adapter.operation_ids.append(previous.operation_id)
            now = iso_now()
            return ToolResult(name, _execution_permission(name),
                "error" if value.get("state") in {"UNKNOWN", "NOT_STARTED", "REJECTED", "FAILED"} else "ok", value, now, now,
                permission_decision="allowed", authorization_ref=authorization_ref)
        return _execute_task_tool_once(runtime, adapter, run_id, call, authorization_ref)


def _execute_task_tool_once(runtime: Any, adapter: Any, run_id: str, call: Any, authorization_ref: str) -> ToolResult:
    from sitina.execution_network import NetworkPolicyError
    from sitina.extensions.manager import ExtensionInstallError
    from sitina.extensions.authority import ExtensionAuthorityError
    from sitina.task_workspace import WorkspaceError
    before_ids = set(adapter.backend.get_task(adapter.task_id).operations)
    try:
        return _execute_task_tool_effect(runtime, adapter, run_id, call, authorization_ref)
    except (ExecutionDenied, NetworkPolicyError, ExtensionInstallError, ExtensionAuthorityError, WorkspaceError) as error:
        task = adapter.backend.get_task(adapter.task_id)
        logical_id = f"{run_id}:{call.call_id}" if call.name == "sitina_task_environment" else f"{run_id}:{call.name}:{call.call_id}"
        created = [item for key, item in task.operations.items() if key not in before_ids
                   and item.logical_operation_id == logical_id and item.execution_owner == adapter.execution_owner]
        unresolved = any(item.unknown_effect for item in created)
        value = {"tool": call.name, "arguments": dict(call.arguments),
                 "state": "UNKNOWN" if unresolved else "REJECTED", "reason": str(error),
                 "method_status": "error", "effect_settled": not unresolved}
        if isinstance(error, WorkspaceError):
            value["workspace_error"] = error.as_dict()
            value["next_step"] = "Inspect the reported path and select only the files or directories this command changes; do not retry an unknown effect."
        if created:
            adapter.operation_ids.extend(item.operation_id for item in created if item.operation_id not in adapter.operation_ids)
        else:
            logical_id = f"{run_id}:{call.call_id}" if call.name == "sitina_task_environment" else f"{run_id}:{call.name}:{call.call_id}"
            intent = adapter._intent(category="execution-denied", logical_id=logical_id, mode=OperationMode.READ,
                description="record task execution request refused before dispatch")
            outcome = adapter.backend.execute_operation(adapter.task_id, intent, lambda: OperationOutcome(EffectStatus.FAILED, value))
            adapter.record_operation_result(intent, outcome)
        now = iso_now()
        return ToolResult(call.name, _execution_permission(call.name), "error", value, now, now,
            permission_decision="denied", authorization_ref=authorization_ref)


def _execute_task_tool_effect(runtime: Any, adapter: Any, run_id: str, call: Any, authorization_ref: str) -> ToolResult:
    """Every invocation passes through the existing backend dispatch barrier."""
    name, arguments = call.name, dict(call.arguments)
    now = iso_now()
    if name == "sitina_manage_skills":
        from .task_skills import manage_task_skills
        manager = getattr(adapter, "_task_skill_manager", None)
        if manager is None:
            raise ExecutionDenied("task Skills are not bound to the authenticated global store")
        installing = arguments.get("action") in {"install", "retry"}
        intent = adapter._intent(category="task-skill-management",
            logical_id=f"{run_id}:{name}:{call.call_id}",
            mode=OperationMode.WRITE if installing else OperationMode.READ,
            resources=(Path(manager.root),) if installing else (),
            description="inspect or import a user-requested public Skill")

        def manage_effect():
            try:
                result = manage_task_skills(runtime, adapter, arguments)
            except ExecutionDenied as error:
                result = {"state": "FAILED", "code": "SKILL_MANAGEMENT_NOT_AUTHORIZED",
                          "message": str(error), "installed": False}
            value = {"tool": name, "arguments": arguments, **result}
            state = value.get("state")
            effect = (EffectStatus.SUCCEEDED if state == "SUCCEEDED" else
                      EffectStatus.UNKNOWN if state == "UNKNOWN" else EffectStatus.FAILED)
            return OperationOutcome(effect, value)

        outcome = adapter.backend.execute_operation(adapter.task_id, intent, manage_effect)
        adapter.record_operation_result(intent, outcome)
        return ToolResult(name, "write",
            "ok" if outcome.status is EffectStatus.SUCCEEDED else "error",
            outcome.result, now, iso_now(), permission_decision="allowed",
            authorization_ref=authorization_ref)
    if name == "sitina_task_skills":
        manager = getattr(adapter, "_task_skill_manager", None)
        if manager is None:
            raise ExecutionDenied("task Skills are not bound to the authenticated global store")
        binding = ensure_task_skills(adapter, manager)
        action = arguments.get("action", "list")
        value = {"tool": name, "arguments": arguments}
        if action == "list":
            value["skills"] = manager.task_skill_summaries(binding, task_id=adapter.task_id)
        elif action == "load":
            skill = manager.load_task_skill(str(arguments.get("name") or ""), binding, task_id=adapter.task_id)
            value["skill"] = {"qualified_name": skill.qualified_name, "body": skill.body,
                              "resource_root": str(skill.path.parent), "required_tools": list(skill.required_tools)}
        elif action == "exclude":
            if adapter.execution_owner:
                raise ExecutionDenied("only the parent may change the task Skill exclusion list")
            binding = manager.with_task_skill_exclusions(binding, task_id=adapter.task_id,
                exclusions=arguments.get("exclusions", []))
            value["skills"] = manager.task_skill_summaries(binding, task_id=adapter.task_id)
        else:
            raise ExecutionDenied("unknown task Skill action")
        value["task_skill_binding"] = binding
        intent = adapter._intent(category="task-skill-binding", logical_id=f"{run_id}:{name}:{call.call_id}",
            mode=OperationMode.READ, description="inspect or select this task's pinned Skills")
        outcome = adapter.backend.execute_operation(adapter.task_id, intent,
            lambda: OperationOutcome(EffectStatus.SUCCEEDED, value))
        adapter.record_operation_result(intent, outcome)
        if outcome.status is EffectStatus.SUCCEEDED:
            adapter._task_skill_roots = manager.task_skill_resource_roots(binding, task_id=adapter.task_id)
            consumer = getattr(adapter, "_task_skill_consumer", None)
            if consumer is not None:
                consumer.bind_task_skills(binding, task_id=adapter.task_id)
        return ToolResult(name, "read", "ok" if outcome.status is EffectStatus.SUCCEEDED else "error",
            task_skill_model_result(outcome.result) if outcome.status is EffectStatus.SUCCEEDED else outcome.result,
            now, iso_now(), permission_decision="allowed", authorization_ref=authorization_ref)

    controls = {
        "sitina_process_input": "input", "sitina_process_interrupt": "interrupt",
        "sitina_process_resize": "resize", "sitina_process_takeover": "takeover",
        "sitina_process_release": "release",
    }
    if name in controls or name in {"sitina_process_status", "sitina_process_log", "sitina_process_stop", "sitina_register_service"}:
        process_id = str(arguments.get("process_id") or "")
        evidence = _owned(adapter, process_id)
        read_only = name in {"sitina_process_status", "sitina_process_log"}
        process = adapter.backend.get_task(adapter.task_id).operations.get(process_id)
        if process is None:
            raise ExecutionDenied("managed process lacks its authenticated launch operation")
        try:
            # Keep launch roots and the process-specific control record locked.
            # The coordinator checks the bound owner before permitting access
            # to that record; ordinary file writes retain their usual boundary.
            resources = runtime._managed_control_resources(
                stop=not read_only, execution_owner=adapter.execution_owner,
                process_owner=process.execution_owner, process_resources=process.resources,
                manifest_path=str(evidence["command_manifest_path"]),
                process_mode=process.mode,
            )
        except ValueError as error:
            raise ExecutionDenied(str(error)) from error
        intent = adapter._intent(category="managed-control", logical_id=f"{run_id}:{name}:{call.call_id}",
            mode=OperationMode.READ if read_only else OperationMode.WRITE,
            description="observe or control the original task execution",
            resources=resources, controlled_process_id=process_id if not read_only else None)
        registration_holder = {}

        def prepare_registration():
            import secrets
            root = runtime.boundary.state_root / "checks" / intent.operation_id
            root.mkdir(parents=True, exist_ok=False)
            prepared = {"effect_kind": "task-control", "control_kind": "service_registration",
                "process_id": process_id, "command_manifest_path": evidence["command_manifest_path"],
                "command_manifest_hash": evidence["command_manifest_hash"],
                "control_root": str(root), "completion_path": str(root / "native-control-result.json"),
                "completion_nonce": secrets.token_hex(32), "tool_name": name,
                "tool_arguments": dict(arguments), "run_instance_id": intent.expected_run_instance_id,
                "execution_epoch": intent.expected_execution_epoch}
            registration_holder["evidence"] = prepared
            return prepared

        def control_effect():
            if name in controls:
                try:
                    with adapter.backend._state_lock:
                        result = command_control(evidence, task_id=adapter.task_id, operation_id=process_id,
                            action=controls[name], actor="agent", data=str(arguments.get("data") or ""),
                            rows=arguments.get("rows", 24), columns=arguments.get("columns", 80),
                            request_id=str(arguments.get("request_id") or hashlib.sha256(f"{run_id}:{call.call_id}".encode("utf-8")).hexdigest()))
                except ExecutionDenied as error:
                    return OperationOutcome(EffectStatus.FAILED, {"tool": name, "arguments": arguments,
                        "state": "REJECTED", "control_enqueued": False, "reason": str(error)})
            elif name == "sitina_register_service":
                from sitina.execution_network import ServiceRegistrationRejected
                gateway_revocation_started = False

                def mark_gateway_revocation():
                    nonlocal gateway_revocation_started
                    gateway_revocation_started = True

                try:
                    state = public_execution(adapter, process_id)
                    if state["state"] != "RUNNING":
                        raise ExecutionDenied("only a running owned process can register a service")
                    port = arguments.get("port")
                    manifest = _read_json(Path(evidence["command_manifest_path"])) or {}
                    if type(port) is not int or port not in evidence.get("listen_ports", []):
                        raise ExecutionDenied("service port was not reserved for this process")
                    gateway = _gateway(runtime, adapter, {}, before_revoke=mark_gateway_revocation)
                    start = _read_json(Path(manifest["start_path"])) or {}
                    gateway.bind_service(process_id, "127.0.0.1", port,
                        root_pid=start.get("child_pid"), root_birth=start.get("child_birth"),
                        process_group=start.get("process_group"))
                    result = {"process_id": process_id, "host": "127.0.0.1", "port": port, "status": "REGISTERED"}
                except (ExecutionDenied, ServiceRegistrationRejected) as error:
                    if gateway_revocation_started:
                        # A pure bind rejection does not undo an earlier gateway revocation.
                        # Preserve UNKNOWN unless the whole callback's effects are settled.
                        raise
                    rejected = {"tool": name, "arguments": arguments, "state": "REJECTED",
                        "registration_changed": False, "reason": str(error)}
                    if isinstance(error, ServiceRegistrationRejected):
                        rejected["reason_code"] = error.code
                        if error.observation is not None:
                            rejected["observation"] = error.observation
                    return OperationOutcome(EffectStatus.FAILED, rejected)
            else:
                offsets = arguments.get("offsets")
                if offsets is not None and not isinstance(offsets, Mapping):
                    raise ExecutionDenied("offsets must be a stream cursor mapping")
                result = public_execution(adapter, process_id, include_output=name == "sitina_process_log",
                                          offsets=offsets, stop=name == "sitina_process_stop")
                if name == "sitina_process_stop":
                    result["service_revocations"] = revoke_process_services(
                        runtime.boundary.state_root, adapter.task_id, process_id)
                    result["service_revocation_scope"] = "CURRENT_HOST_GATEWAYS"
            result.update({"tool": name, "arguments": arguments, "permission": "read" if read_only else "shell"})
            return OperationOutcome(EffectStatus.SUCCEEDED, result)
        def control():
            outcome = control_effect()
            if name == "sitina_register_service" and outcome.status in {EffectStatus.SUCCEEDED, EffectStatus.FAILED}:
                prepared = registration_holder["evidence"]
                path = Path(prepared["completion_path"])
                if path.exists():
                    raise ExecutionDenied("original native control completion already exists")
                _write_json(path, {"schema": "SITINA_TASK_CONTROL_COMPLETION_V1",
                    "task_id": adapter.task_id, "operation_id": intent.operation_id,
                    "process_id": process_id, "command_manifest_hash": prepared["command_manifest_hash"],
                    "run_instance_id": prepared["run_instance_id"], "execution_epoch": prepared["execution_epoch"],
                    "tool_name": name, "tool_arguments": dict(arguments),
                    "nonce": prepared["completion_nonce"], "effect_status": outcome.status.value,
                    "result": dict(outcome.result)})
            return outcome

        outcome = adapter.backend.execute_operation(adapter.task_id, intent, control,
            prepare=prepare_registration if name == "sitina_register_service" else None)
        adapter.record_operation_result(intent, outcome)
        value = dict(outcome.result)
        if outcome.status is not EffectStatus.SUCCEEDED:
            value.update({"state": "UNKNOWN" if outcome.status is EffectStatus.UNKNOWN else "REJECTED", "method_status": "error"})
        return ToolResult(name, "read" if read_only else "shell", "ok" if outcome.status is EffectStatus.SUCCEEDED else "error", value, now, iso_now(),
                          permission_decision="allowed", authorization_ref=authorization_ref)

    if name == "sitina_task_environment":
        action = arguments.get("action", "inspect")
        state = execution_state(adapter.backend, adapter.task_id, adapter.workspace)
        if action != "inspect" and adapter.execution_owner:
            raise ExecutionDenied("children use inherited task settings; request parent coordination to change them")
        if action == "set":
            values = arguments.get("values")
            if not isinstance(values, Mapping):
                raise ExecutionDenied("values must be an environment mapping")
            state["environment"].update(values)
        elif action == "unset":
            keys = arguments.get("keys")
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise ExecutionDenied("keys must be an array of variable names")
            for key in keys:
                state["environment"].pop(key, None)
        elif action == "grant_paths":
            if not isinstance(arguments.get("purpose"), str) or not arguments["purpose"].strip():
                raise ExecutionDenied("task-related path grants require their task purpose")
            for key in ("read_roots", "write_roots"):
                values = arguments.get(key, [])
                if not isinstance(values, list) or not all(isinstance(p, str) and Path(p).expanduser().is_absolute() for p in values):
                    raise ExecutionDenied("scope roots must be explicit absolute paths")
                for value in values:
                    path = Path(value).expanduser().resolve(strict=False)
                    if path == Path(path.anchor) or path == Path.home():
                        raise ExecutionDenied("grant task-related paths individually rather than the whole host/home")
                    state[key] = sorted(set((*state[key], str(path))))
        elif action != "inspect":
            raise ExecutionDenied("unknown task environment action")
        with tempfile.TemporaryDirectory(prefix="sitina-env-") as temporary:
            task_environment(Path(temporary), workspace=adapter.workspace, shared=state["environment"])
        policy = execution_policy(runtime, adapter, state=state)
        for value in (*state["read_roots"], *state["write_roots"]):
            policy.check_path(Path(value))
        intent = adapter._intent(category="execution-environment", logical_id=f"{run_id}:{call.call_id}",
            mode=OperationMode.READ if action == "inspect" else OperationMode.WRITE,
            description="read or explicitly update task-shared environment/scope",
            resources=(() if action == "inspect" else (runtime.boundary.state_root / "task-environment" / adapter.task_id,)))
        def change_environment():
            # Validation completed before recording the environment mutation intent.
            return OperationOutcome(EffectStatus.SUCCEEDED, {"tool": name, "action": action, "arguments": arguments,
                "execution_state": state, "scope": "task_shared", "existing_processes_changed": False})
        outcome = adapter.backend.execute_operation(adapter.task_id, intent, change_environment)
        adapter.record_operation_result(intent, outcome)
        value = dict(outcome.result)
        if outcome.status is not EffectStatus.SUCCEEDED:
            value.update({"state": "UNKNOWN" if outcome.status is EffectStatus.UNKNOWN else "REJECTED", "method_status": "error"})
        return ToolResult(name, "write", "ok" if outcome.status is EffectStatus.SUCCEEDED else "error", value, now, iso_now(),
                          permission_decision="allowed", authorization_ref=authorization_ref)

    if name not in {"sitina_shell", "sitina_exec", "sitina_process_start"}:
        raise ExecutionDenied("unknown task execution tool")
    state = execution_state(adapter.backend, adapter.task_id, adapter.workspace)
    write_paths = arguments.get("write_paths")
    if write_paths is not None and (not isinstance(write_paths, list) or not all(isinstance(p, str) for p in write_paths)):
        raise ExecutionDenied("write_paths must be explicit path strings")
    verification_inputs = arguments.get("verification_inputs", [])
    if (not isinstance(verification_inputs, list) or len(verification_inputs) > 256
            or any(not isinstance(path, str) or not path for path in verification_inputs)
            or len(set(verification_inputs)) != len(verification_inputs)):
        raise ExecutionDenied("verification_inputs must be distinct project input file paths (at most 256)")
    policy = execution_policy(runtime, adapter, state=state, write_paths=write_paths)
    ports = arguments.get("listen_ports", [])
    if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ExecutionDenied("listen_ports must contain explicit ports in 1..65535")
    from .task_runtime import _native_file_versions, _sha256_json
    raw_cwd = arguments.get("cwd", str(adapter.workspace))
    if not isinstance(raw_cwd, str) or not raw_cwd:
        raise ExecutionDenied("cwd must be a nonempty path string")
    command_cwd = Path(raw_cwd).expanduser()
    command_cwd = command_cwd if command_cwd.is_absolute() else adapter.workspace / command_cwd
    command_cwd = policy.check_cwd(command_cwd)
    checked_inputs = []
    for raw in verification_inputs:
        path = Path(raw).expanduser()
        path = path if path.is_absolute() else command_cwd / path
        if path.is_symlink():
            raise ExecutionDenied("verification inputs must be regular files, not symbolic links")
        path = policy.check_path(path)
        if not path.is_file():
            raise ExecutionDenied("verification inputs must be existing regular files")
        checked_inputs.append(str(path))
    if len(set(checked_inputs)) != len(checked_inputs):
        raise ExecutionDenied("verification inputs resolve to duplicate files")
    verification_before = _native_file_versions(tuple(checked_inputs))
    if adapter.execution_owner and verification_before:
        adapter._business_action_fingerprint = _sha256_json({
            "business_action": adapter._business_action_family or adapter._business_action_fingerprint,
            "verification_inputs": verification_before, "task_environment": state["environment"],
        })
    resources = policy.write_roots
    intent = adapter._intent(category="managed-process", logical_id=f"{run_id}:{name}:{call.call_id}",
        mode=OperationMode.WRITE if resources else OperationMode.READ,
        description="execute a task-authorized program or non-login Shell",
        resources=resources, preconditions=tuple(FilePrecondition.capture(path) for path in (*resources, *(Path(name) for name in checked_inputs))))
    holder = {}
    def prepare():
        # Scratch is short and isolated from durable evidence, including AF_UNIX path consumers.
        assert_execution_resources_available(adapter.backend, adapter.task_id, resources, ignore=intent.operation_id)
        workspace_manager = capture_execution_baseline(runtime, adapter, resources)
        scratch = Path(tempfile.mkdtemp(prefix="sitina-exec-")).resolve()
        gateway = _gateway(runtime, adapter, arguments)
        environment = task_environment(scratch, workspace=adapter.workspace, shared=state["environment"],
            command=arguments.get("environment"), gateway=gateway.environment(),
            local_home=Path.home() if policy.full_local_read else None)
        request = ExecutionRequest.parse(arguments, tool_name=name, workspace=adapter.workspace, environment=environment)
        policy.check_cwd(request.cwd)
        if request.cwd != command_cwd or _native_file_versions(tuple(checked_inputs)) != verification_before:
            raise ExecutionDenied("verification inputs changed before dispatch; inspect current files before a new invocation")
        environment.update(policy.cwd_environment(request.cwd))
        profile = policy.sandbox_profile(runtime_roots=(scratch,), gateway_port=gateway.port,
            trust_paths=gateway.read_paths, listen_ports=ports)
        check_root = runtime.boundary.state_root / "checks" / intent.operation_id
        runner = CommandRunner(task_id=adapter.task_id, operation_id=intent.operation_id,
            check_root=check_root, check_input=adapter.workspace, check_output=scratch / "output",
            command=request.argv, interpreter=runtime.boundary.interpreter, profile=profile, environment=environment,
            command_cwd=request.cwd, timeout_seconds=request.timeout_seconds,
            cancel_probe=lambda: adapter.backend.get_task(adapter.task_id).control_intent is ControlIntent.CANCEL,
            execution_contract=TASK_EXECUTION_CONTRACT, pty=request.pty, keep=request.keep,
            terminal_dimensions=(request.rows, request.columns))
        prepared = dict(runner.prepare())
        task = adapter.backend.get_task(adapter.task_id)
        message_inputs = [item for item in task.inputs
                          if item.sequence <= task.handled_input_seq and item.kind.value == "MESSAGE"]
        reply_to = max(message_inputs, key=lambda item: item.sequence).input_id if message_inputs else None
        prepared.update({"execution_contract": TASK_EXECUTION_CONTRACT, "managed_process": True,
            "reply_to": reply_to,
            "command_policy": TASK_COMMAND_POLICY, "shell_tool": name, "tool_name": name, "tool_permission": "shell",
            "tool_arguments": arguments, "execution_owner": adapter.execution_owner,
            "shell_text": request.shell_text, "listen_ports": ports, "keep": request.keep,
            "business_workspace": str(adapter.workspace), "runtime_root": str(scratch),
            "write_roots": [str(p) for p in policy.write_roots], "read_roots": [str(p) for p in policy.read_roots],
            "local_access": {"full_read": policy.full_local_read, "full_write": policy.full_local_write},
            "workspace_check_binding": workspace_manager.capture_check_binding(request.cwd),
            "verification_inputs_before": verification_before,
            "network_gateway_port": gateway.port, "network_urls": arguments.get("network_urls", []),
            "git_urls": arguments.get("git_urls", []), "phase": "AUTHORIZED_NOT_STARTED"})
        holder.update(runner=runner, request=request, evidence=prepared)
        return prepared
    def dispatch():
        runner, request = holder["runner"], holder["request"]
        start_managed_command(runner)
        deadline = time.monotonic() + request.yield_seconds
        while True:
            value = public_execution(adapter, intent.operation_id, include_output=True)
            if value["state"] != "UNKNOWN" and (value["effect_settled"] or time.monotonic() >= deadline):
                break
            if time.monotonic() >= deadline + 6:
                break
            time.sleep(0.01)
        value.update({"tool": name, "arguments": arguments, "permission": "shell",
                      "managed_process": True, "command_policy": TASK_COMMAND_POLICY})
        return OperationOutcome(EffectStatus.UNKNOWN if value["state"] == "UNKNOWN" else EffectStatus.SUCCEEDED, value)
    outcome = adapter.backend.execute_operation(adapter.task_id, intent, dispatch, prepare=prepare)
    adapter.record_operation_result(intent, outcome)
    value = dict(outcome.result)
    if outcome.status is not EffectStatus.SUCCEEDED:
        value.update({"state": "UNKNOWN" if outcome.status is EffectStatus.UNKNOWN else "NOT_STARTED",
                      "program_status": "UNKNOWN" if outcome.status is EffectStatus.UNKNOWN else "NOT_RUN", "method_status": "error"})
    return ToolResult(name, "shell", "ok" if outcome.status is EffectStatus.SUCCEEDED and value.get("state") not in {"UNKNOWN", "NOT_STARTED"} else "error",
                      value, now, iso_now(), permission_decision="allowed",
                      authorization_ref=authorization_ref)
