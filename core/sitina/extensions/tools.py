from __future__ import annotations

import contextlib
import fnmatch
import glob
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import threading
from urllib.parse import urlsplit
import urllib.request
import urllib.error
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.spec import (
    HOOKS_SCHEMA,
    MCP_SCHEMA,
    TOOLS_SCHEMA,
    ExtensionSpecError,
    PluginManifest,
    load_skill,
    read_json_object,
    validate_identifier,
)
from sitina.runners.mcp_adapter import StdioMcpClient, validate_json_schema
from sitina.guards.risk import RiskScanner
from sitina.legacy.fence import (
    LegacyWriteDenied, authorized_extension_effect,
    authorized_frozen_network_egress, issue_frozen_network_egress_capability,
    _validate_network_capability,
)
from sitina.security.tool_security import (
    PromptIsolationPolicy,
    ToolAccessPolicy,
    ToolAccessRequest,
    ToolPermissionRule,
)
from sitina.utils import isolated_env, iso_now, load_json_yaml, normalize_command, redact_text, stable_json


class ToolRuntimeError(RuntimeError):
    pass


class ToolApprovalDenied(ToolRuntimeError):
    def __init__(self, message: str, *, authorization_ref: str | None = None):
        super().__init__(message)
        self.authorization_ref = authorization_ref


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    tool_name: str
    permission: str
    risk: str
    origin: str
    arguments: Mapping[str, Any]
    reason: str

    def mapping(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "permission": self.permission,
            "risk": self.risk,
            "origin": self.origin,
            "arguments": dict(self.arguments),
            "reason": self.reason,
        }


ApprovalCallback = Callable[[ApprovalRequest], bool]
ToolHandler = Callable[[dict[str, Any]], Any]
_UNSET = object()


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: Mapping[str, Any]
    permission: str
    origin: str
    handler: ToolHandler
    security_server: str | None = None
    security_tool: str | None = None

    def provider_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": dict(self.input_schema),
        }


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    permission: str
    status: str
    value: Any
    started_at: str
    completed_at: str
    duration_ms: int = 0
    permission_decision: str = "allowed"
    authorization_ref: str | None = None
    model_value: Any = None
    model_value_present: bool = False
    model_source_ref: str | None = None
    execution_binding: Mapping[str, Any] | None = None
    runtime_blocked: bool = False

    def content(self) -> str:
        return PromptIsolationPolicy().wrap_tool_result(
            tool_name=self.tool_name,
            status=self.status,
            value=self.model_value if self.model_value_present else self.value,
        )


RISK_BY_PERMISSION = {
    "read": "low",
    "write": "medium",
    "network": "medium",
    "shell": "high",
    "external_service": "high",
}

# Risk rules whose match means the effect escapes the worktree (host-effect):
# no free rollback, always require human approval (M1.7).
_HOST_EFFECT_RULE_IDS = frozenset({
    "host_package_install",
    "host_system_modify",
    "external_network",
    "write_project_outside_path",
})


class ToolCatalog:
    """One permission-enforcing catalog for built-ins and plugin capabilities."""

    def __init__(
        self,
        manager: ExtensionManager,
        *,
        approval_callback: ApprovalCallback | None = None,
        workspace: Path | None = None,
        write_executor: Any | None = None,
        before_hashes: Mapping[str, str | None] | None = None,
        strict_workspace: bool = False,
        managed_process_manager: Any | None = None,
        _native_network_authority: tuple[Any, str] | None = None,
    ):
        self.manager = manager
        self.approval_callback = approval_callback
        self._native_network_authority = _native_network_authority
        self._network_tools: dict[str, tuple[str, tuple[str, ...]]] = {}
        self._network_grants: dict[str, tuple[Any, str, Mapping[str, Any] | None]] = {}
        self._network_execution = threading.local()
        self.workspace = Path(workspace or manager.sitina_home).expanduser().resolve(strict=False)
        # Optional strong-write engine (ToolExecutor). When present and a run is
        # bound, sitina_write_file uses atomic/before_hash/patch-journal writes
        # instead of whole-file overwrite. Approval is still enforced by
        # _authorize upstream; this only upgrades the write mechanics (M1.1).
        self._write_executor = write_executor
        self._strict_workspace = bool(strict_workspace)
        self._managed_process_manager = managed_process_manager
        permissions_path = self.manager.sitina_home / "config" / "permissions.yaml"
        try:
            permissions = load_json_yaml(permissions_path) if permissions_path.is_file() else {}
        except Exception:
            permissions = {}
        configured_commands = permissions.get("tester_allowed_commands", []) if isinstance(permissions, Mapping) else []
        self._tester_allowed_commands = tuple(
            str(item).strip() for item in configured_commands
            if isinstance(item, str) and item.strip()
        )
        # A run may bind the files it observed before the first write.  The
        # strong write primitive then turns a concurrent edit into a
        # before-hash mismatch instead of silently overwriting user work.
        self._expected_before_hashes = {
            str(Path(path).expanduser().resolve(strict=False)): value
            for path, value in dict(before_hashes or {}).items()
        }
        self._run_id: str | None = None
        self._active_direct_capability: Any | None = None
        self._active_risk_scan: Any | None = None
        self._managed_process_baselines: dict[str, dict[str, Any]] = {}
        # Deterministic risk floor (M1.4): scans every non-trivial tool call
        # against config/permissions.yaml before approval. Block verdicts
        # (sudo, curl|sh, .env/secret/ssh/key reads+writes, path escape) cannot
        # be overridden by the approval callback. Reuse the executor's scanner
        # if present so rules load once.
        if write_executor is not None and getattr(write_executor, "risk_scanner", None) is not None:
            self._risk_scanner = write_executor.risk_scanner
        else:
            self._risk_scanner = RiskScanner(Path(manager.sitina_home))
        self._tools: dict[str, ToolDefinition] = {}
        self._skill_roots: dict[str, Path] = {}
        self._execution_snapshot_skills: tuple[Any, ...] = ()
        self._execution_snapshot_guards: dict[str, Callable[[], None]] = {}
        self._execution_bindings: dict[str, dict[str, Any]] = {}
        self._bound_execution_snapshot_identity: tuple[str, str, str] | None = None
        self._active_consumer_context: dict[str, Any] | None = None
        self._mcp_rules: list[ToolPermissionRule] = []
        self._register_builtins()
        self._register_extensions()
        self._mcp_policy = ToolAccessPolicy(self._mcp_rules)

    def definitions(self) -> list[ToolDefinition]:
        return [self._tools[name] for name in sorted(self._tools)]

    def bind_loop_shell_description(self) -> None:
        """Expose the Loop-only shell contract on this runtime's catalog.

        The builtin catalog is shared by legacy FAST/MULTI paths, whose
        foreground tester semantics must remain unchanged.  Loop runtimes
        opt into their narrower command boundary explicitly on their own
        catalog instance.
        """

        definition = self.get("sitina_shell")
        self._tools["sitina_shell"] = ToolDefinition(
            definition.name,
            "Run one approved isolated Python unittest command through the Loop command boundary. "
            "The Loop surface accepts only the exact python -m unittest grammar with bounded flags and "
            "input-relative targets; reject shell operators, interpreter/module substitution, and paths outside "
            "the bound workspace. config validate and doctor report UNSUPPORTED_REAL_INSTALL_STATE, while eval "
            "reports UNSUPPORTED_RUNTIME_WRITE_REQUIRED. Requires per-call shell approval.",
            definition.input_schema,
            definition.permission,
            definition.origin,
            definition.handler,
            definition.security_server,
            definition.security_tool,
        )
        for name, description in {
            "sitina_process_start": (
                "Start one task-owned background Python unittest command using the same finite argv grammar, "
                "read-only input snapshot, separate output, timeout and no-fork sandbox as sitina_shell. "
                "It survives tool-group yields. Use process_status/log/stop to observe or stop it. "
                "keep=true is forbidden; task invalidation, terminal or Host drain must settle ownership."
            ),
            "sitina_process_status": "Read the current task's bound managed-command state; UNKNOWN never means stopped.",
            "sitina_process_log": "Read bounded redacted logs of the current task's bound managed command.",
            "sitina_process_stop": "Stop only the current task's owned command using its nonce-bound cancellation receipt.",
        }.items():
            current = self.get(name)
            schema = current.input_schema
            if name == "sitina_process_start":
                schema = {
                    **schema,
                    "properties": {**schema["properties"], "timeout_seconds": {"type": "number"}},
                }
            self._tools[name] = ToolDefinition(
                current.name, description, schema, current.permission, current.origin,
                current.handler, current.security_server, current.security_tool,
            )


    def register_extension_publisher(self) -> None:
        """Expose the Loop-owned extension publication capability.

        The Provider only sees this logical request surface.  The handler is
        deliberately unusable through the ordinary catalog executor; the
        Loop adapter intercepts the call and routes it through the Backend's
        authenticated publication bridge, which reconstructs all evidence
        from persisted operations.
        """

        definition = ToolDefinition(
            "sitina_publish_extension",
            "Publish the explicitly admitted extension candidate after a completed authenticated trial. "
            "Provide only slot_id, candidate_id, trial_operation_id, and request_id. "
            "The Backend reconstructs the trial result, receipt, source binding, and publication decision.",
            self._object_schema(
                {
                    "slot_id": {"type": "string"},
                    "candidate_id": {"type": "string"},
                    "trial_operation_id": {"type": "string"},
                    "request_id": {"type": "string"},
                },
                ("slot_id", "candidate_id", "trial_operation_id", "request_id"),
            ),
            "write",
            "sitina-extension-authority",
            lambda _value: (_ for _ in ()).throw(
                ToolRuntimeError("extension publication is available only through the Loop Backend")
            ),
        )
        existing = self._tools.get(definition.name)
        if existing is not None and existing.origin != definition.origin:
            raise ToolRuntimeError("sitina_publish_extension is reserved by the extension authority")
        self._tools[definition.name] = definition

    def provider_schemas(self) -> list[dict[str, Any]]:
        return [item.provider_schema() for item in self.definitions()]

    def bind_execution_snapshot(self, snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
        """Bind one authenticated 4B execution snapshot to this catalog."""

        if not isinstance(snapshot, Mapping) or snapshot.get("schema") != "SITINA_EXTENSION_EXECUTION_SNAPSHOT_V1":
            raise ToolRuntimeError("execution snapshot schema is invalid")
        candidate_id = str(snapshot.get("candidate_id") or "")
        root = Path(str(snapshot.get("root") or "")).expanduser().resolve(strict=False)
        snapshot_hash = str(snapshot.get("snapshot_hash") or "")
        location_binding = str(snapshot.get("location_binding") or "")
        if not candidate_id or not root.is_dir() or not snapshot_hash or not location_binding:
            raise ToolRuntimeError("execution snapshot identity is incomplete")
        try:
            authority = self.manager.shared_authority
        except Exception as exc:
            raise ToolRuntimeError("execution snapshots require a bound shared authority") from exc

        def current_snapshot() -> Mapping[str, Any]:
            return authority.build_execution_snapshot(candidate_id).as_dict()

        def guard() -> None:
            current = current_snapshot()
            if (
                str(current.get("snapshot_hash") or "") != snapshot_hash
                or str(current.get("location_binding") or "") != location_binding
                or str(current.get("root") or "") != str(root)
            ):
                raise ToolRuntimeError("bound execution snapshot is stale or changed")

        guard()
        # Do not trust caller-supplied bindings, permissions, or environment
        # fields after checking the authenticated identity.  All consumers
        # resolve from the shared authority's current snapshot.
        snapshot = current_snapshot()
        identity = (
            str(snapshot.get("candidate_id") or ""),
            str(snapshot.get("snapshot_hash") or ""),
            str(snapshot.get("location_binding") or ""),
        )
        if self._bound_execution_snapshot_identity is not None:
            if self._bound_execution_snapshot_identity != identity:
                raise ToolRuntimeError(
                    "ToolCatalog cannot switch execution snapshots in place; create a fresh catalog/runtime"
                )
            # Rebinding the same authenticated snapshot is idempotent.  In
            # particular, do not leave tools from another candidate in the
            # catalog or overwrite their shared generic tool binding.
            return dict(snapshot)
        root = Path(str(snapshot["root"])).expanduser().resolve(strict=True)
        location_binding = str(snapshot["location_binding"])
        kind = str(snapshot.get("kind") or "")
        if kind == "skill":
            skill_file = root / "SKILL.md"
            skill = load_skill(skill_file)
            qualified = skill.qualified_name
            if qualified != str(snapshot.get("bindings", {}).get("skills", [{}])[0].get("qualified_name") or qualified):
                raise ToolRuntimeError("execution snapshot Skill binding differs from its candidate")
            self._skill_roots[qualified] = root
            self._execution_snapshot_skills = (skill,)
            self._execution_snapshot_guards[qualified] = guard
            expected_paths = sorted({
                match.group(0)
                for match in re.finditer(
                    r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+",
                    skill.body,
                )
                if (root / match.group(0)).is_file()
            })
            self._execution_bindings["sitina_read_skill_resource"] = {
                "snapshot_id": snapshot.get("snapshot_id"),
                "snapshot_hash": snapshot.get("snapshot_hash"),
                "candidate_id": snapshot.get("candidate_id"),
                "handler": "skill-resource-read",
                "tool_name": "sitina_read_skill_resource",
                "qualified_name": qualified,
                "root": str(root),
                "method_schema": "SITINA_EXTENSION_TRIAL_METHOD_V1",
                "method_version": 1,
                "method_contract": {
                    "schema": "SITINA_EXTENSION_METHOD_EXPECTATION_V1",
                    "kind": "skill-resource-read",
                    "skill": qualified,
                    "expected_paths": expected_paths,
                    "result_status": "ok",
                },
                "method_id": hashlib.sha256(stable_json({
                    "handler": "skill-resource-read",
                    "qualified_name": qualified,
                    "snapshot_hash": snapshot.get("snapshot_hash"),
                    "expected_paths": expected_paths,
                }).encode("utf-8")).hexdigest(),
            }
            if "sitina_read_skill_resource" not in self._tools:
                self._add(
                    ToolDefinition(
                        "sitina_read_skill_resource",
                        "Read a resource from the selected immutable Skill execution snapshot.",
                        self._object_schema(
                            {"skill": {"type": "string"}, "path": {"type": "string"}},
                            ("skill", "path"),
                        ),
                        "read",
                        "sitina-execution-snapshot",
                        self._read_skill_resource,
                    )
                )
        elif kind == "plugin":
            manifest = PluginManifest.load(root)
            if manifest.name != str(snapshot.get("name") or ""):
                raise ToolRuntimeError("execution snapshot Plugin binding differs from its candidate")
            permissions = set(dict(snapshot.get("permissions") or {}).get("granted") or ())
            python_path = str(
                dict(dict(snapshot.get("environment") or {}).get("executables") or {})
                .get("python", {})
                .get("path")
                or ""
            )
            python_requested = str(
                dict(dict(snapshot.get("environment") or {}).get("executables") or {})
                .get("python", {})
                .get("requested")
                or python_path
            )
            # The formal consumer path admits only candidate-contained Python
            # entrypoints.  Other subprocess and MCP transports remain
            # preparation facts and cannot reach a Loop receipt path.
            for item in snapshot.get("bindings", {}).get("tools", ()):
                if not isinstance(item, Mapping):
                    continue
                identities = item.get("executable_identities") or ()
                executable = identities[0] if isinstance(identities, list) and identities else {}
                executable_path = str(executable.get("path") or "")
                command = list(item.get("command") or ())
                if executable_path != python_path or len(command) < 2:
                    raise ToolRuntimeError("unsupported plugin command executor for 4B consumer trial")
                script = Path(str(command[1]))
                if script.is_absolute() or ".." in script.parts or script.suffix != ".py":
                    raise ToolRuntimeError("Plugin Python entrypoint must be a relative candidate script")
                script_path = (root / script).resolve(strict=True)
                script_path.relative_to(root)
                if script_path.is_symlink() or not script_path.is_file():
                    raise ToolRuntimeError("Plugin Python entrypoint is not a regular candidate file")
            if snapshot.get("bindings", {}).get("mcp"):
                raise ToolRuntimeError("MCP consumer execution is not connected in 4B")
            binding_base = {
                "snapshot_id": snapshot.get("snapshot_id"),
                "snapshot_hash": snapshot.get("snapshot_hash"),
                "candidate_id": snapshot.get("candidate_id"),
                "root": str(root),
                "python_path": python_path,
                "python_requested": python_requested,
                "method_schema": "SITINA_EXTENSION_TRIAL_METHOD_V1",
                "method_version": 1,
            }
            self._register_command_tools(
                manifest, permissions, integrity_guard=guard,
                execution_binding={**binding_base, "handler": "subprocess-command"},
                cancel_probe=self._consumer_cancelled,
            )
            self._register_mcp_tools(
                manifest, permissions, integrity_guard=guard,
                execution_binding={**binding_base, "handler": "mcp"},
            )
        else:
            raise ToolRuntimeError("unsupported execution snapshot kind")
        # Commit the catalog identity only after every candidate-specific
        # binding/handler validation has succeeded.  A rejected first bind
        # must not leave an idempotent half-activation behind.
        self._bound_execution_snapshot_identity = identity
        return dict(snapshot)

    def selected_execution_skills(self, _task: str) -> tuple[Any, ...] | None:
        """Return Skills selected by the authenticated snapshot, if bound."""

        if self._bound_execution_snapshot_identity is None:
            return None
        for skill in self._execution_snapshot_skills:
            guard = self._execution_snapshot_guards.get(skill.qualified_name)
            if guard is not None:
                guard()
        return tuple(self._execution_snapshot_skills)

    def execution_binding_for(self, name: str) -> Mapping[str, Any] | None:
        binding = self._execution_bindings.get(str(name))
        return dict(binding) if isinstance(binding, Mapping) else None

    def bind_loop_consumer(self, *, backend: Any, task_id: str, snapshot_id: str, call_id: str) -> None:
        """Bind one provider call to the Loop-owned consumer receipt path."""

        if backend is None or not str(task_id) or not str(snapshot_id) or not str(call_id):
            raise ToolRuntimeError("Loop consumer binding is incomplete")
        self._active_consumer_context = {
            "backend": backend,
            "task_id": str(task_id),
            "snapshot_id": str(snapshot_id),
            "call_id": str(call_id),
        }

    def consumer_method_plan(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        task_id: str | None = None,
        call_id: str | None = None,
    ) -> Mapping[str, Any] | None:
        """Build the trusted, pre-dispatch expectation for one bound tool call.

        The Loop operation persists this document before dispatch.  It is not
        a receipt and it never grants execution by itself; it records the
        selected snapshot, exact call arguments, and the expected resource or
        deterministic output that the post-dispatch verifier must check.
        """

        binding = self._execution_bindings.get(str(name))
        if not isinstance(binding, Mapping):
            return None
        guard = self._execution_snapshot_guards.get(str(binding.get("qualified_name") or ""))
        if guard is not None:
            guard()
        contract = binding.get("method_contract")
        if not isinstance(contract, Mapping):
            raise ToolRuntimeError("bound execution tool has no registered method expectation")
        plan: dict[str, Any] = {
            "schema": "SITINA_EXTENSION_METHOD_PLAN_V1",
            "method_plan_schema": "SITINA_EXTENSION_METHOD_PLAN_V1",
            "snapshot_id": binding.get("snapshot_id"),
            "snapshot_hash": binding.get("snapshot_hash"),
            "candidate_id": binding.get("candidate_id"),
            "task_id": str(task_id) if task_id is not None else None,
            "call_id": str(call_id) if call_id is not None else None,
            "tool_name": str(name),
            "handler": binding.get("handler"),
            "method_schema": binding.get("method_schema"),
            "method_version": binding.get("method_version"),
            "method_id": binding.get("method_id"),
            "method_contract": dict(contract),
            "arguments": dict(arguments),
            "root": binding.get("root"),
            "python_path": binding.get("python_path"),
            "python_requested": binding.get("python_requested"),
            "controlled_executor": contract.get("controlled_executor"),
        }
        kind = str(contract.get("kind") or "")
        if kind == "skill-resource-read":
            skill = str(arguments.get("skill") or "")
            relative = Path(str(arguments.get("path") or ""))
            expected_paths = tuple(str(item) for item in (contract.get("expected_paths") or ()))
            if skill != str(contract.get("skill") or "") or relative.is_absolute() or ".." in relative.parts:
                raise ToolRuntimeError("resource call does not match the selected Skill method")
            if expected_paths and relative.as_posix() not in expected_paths:
                raise ToolRuntimeError("resource call is not registered by the selected Skill method")
            root = Path(str(binding.get("root") or "")).resolve(strict=True)
            resource = (root / relative).resolve(strict=True)
            resource.relative_to(root)
            raw = resource.read_bytes()
            plan["expected"] = {
                "kind": "resource",
                "relative_path": relative.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        elif kind == "plugin-command":
            expected_output = contract.get("expected_output")
            if expected_output is None:
                raise ToolRuntimeError("Plugin method has no bounded deterministic output expectation")
            plan["expected"] = {
                "kind": "plugin-output",
                "command": list(contract.get("command") or ()),
                "output": expected_output,
                "timeout_seconds": contract.get("timeout_seconds"),
            }
        else:
            raise ToolRuntimeError("execution method expectation kind is not connected")
        return plan

    def clear_loop_consumer(self) -> None:
        self._active_consumer_context = None

    def _consumer_cancelled(self) -> bool:
        context = self._active_consumer_context
        if not isinstance(context, Mapping):
            return False
        backend = context.get("backend")
        task_id = str(context.get("task_id") or "")
        if backend is None or not task_id:
            return False
        try:
            task = backend.get_task(task_id)
        except Exception:
            return True
        return task.control_intent.value != "RUN" or task.received_input_seq != task.handled_input_seq

    def _persist_consumer_receipt(self, name: str, value: Any) -> dict[str, Any] | None:
        # LoopBackend issues consumer receipts while committing the durable
        # operation result.  A catalog callback may return a value, but it
        # cannot submit a caller-chosen binding/value pair as a credential.
        del name, value
        return None

    def register_task_history_query(
        self,
        handler: ToolHandler,
        *,
        max_page_bytes: int,
    ) -> None:
        """Add the task-bound, read-only Loop history surface for one run."""

        if type(max_page_bytes) is not int or max_page_bytes < 1:
            raise ValueError("history query maximum must be a positive integer")
        self._add(
            ToolDefinition(
                "sitina_history_query",
                "List or read verified sources from this task only. Read pages include readable UTF-8 text "
                "and lossless base64 bytes. Follow next_cursor/next_offset while has_more is true.",
                self._object_schema(
                    {
                        "operation": {"type": "string", "enum": ["list", "read"]},
                        "cursor": {"type": "string"},
                        "limit": {"type": "number"},
                        "kind": {"type": "string"},
                        "source_ref": {"type": "string"},
                        "offset": {"type": "number"},
                        "max_bytes": {
                            "type": "number",
                            "minimum": 768,
                            "maximum": max_page_bytes,
                        },
                    },
                    ("operation", "max_bytes"),
                ),
                "read",
                "sitina-loop",
                handler,
            )
        )

    def register_readonly_delegator(self, handler: ToolHandler) -> None:
        """Register the formal Loop parent-assistant readonly delegation tool.

        The handler only admits a durable parent association.  Actual source
        reads and any child execution are performed by the Loop backend/host;
        this catalog entry is intentionally read-only and exposes no child
        tool catalog or recursive delegation surface.
        """

        self._add(
            ToolDefinition(
                "sitina_delegate_readonly",
                "Delegate one bounded direct-parent read-only investigation over explicitly declared parent history or regular-file sources. "
                "Choose a stable problem_id for this specific investigation question. Distinct independent questions need distinct IDs; "
                "reuse an ID only to continue or retry the same question. Reusing an ID creates continuation lineage, not a new independent investigator. "
                "Do not use the parent task ID as the ID for every question or rename the same question to erase its history. "
                "The child cannot write, run shell/processes, use network/plugins, delegate again, or approve the parent.",
                self._object_schema(
                    {
                        "problem_id": {
                            "type": "string",
                            "description": "Stable identity of one concrete investigation question, shared only by its continuations or retries. Different independent questions require different IDs selected by the parent model.",
                        },
                        "objective": {"type": "string"},
                        "sources": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "kind": {"type": "string", "enum": ["history", "file"]},
                                    "source_ref": {"type": "string"},
                                    "path": {"type": "string"},
                                },
                                "required": ["kind"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    ("problem_id", "objective", "sources"),
                ),
                "read",
                "sitina-loop",
                handler,
            )
        )

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolRuntimeError(f"model requested an unavailable tool: {name}") from exc

    def execute(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        definition = self.get(name)
        payload = dict(arguments)
        try:
            validate_json_schema(payload, dict(definition.input_schema))
        except Exception as exc:  # noqa: BLE001
            raise ToolRuntimeError(f"tool input failed schema validation for {name}: {exc}") from exc
        authorization_ref = self._authorize(definition, payload)
        started_at = iso_now()
        started_monotonic = time.monotonic()
        previous_capability = self._active_direct_capability
        previous_scan = self._active_risk_scan
        self._active_risk_scan = getattr(self, "_last_authorization_scan", None)
        if self._write_executor is not None and self._run_id is not None and definition.permission == "write":
            self._active_direct_capability = self._write_executor._mint_direct_capability(
                run_id=self._run_id,
                authorization_ref=authorization_ref,
                target_repo=str(self.workspace),
                allowed_roots=[str(self.workspace)],
                purpose=f"tool:{definition.name}",
            )
        previous_network_grant = getattr(self._network_execution, "grant", None)
        self._network_execution.grant = self._network_grants.pop(authorization_ref, None)
        try:
            scope = (
                contextlib.nullcontext()
                if definition.permission == "read"
                else authorized_extension_effect(
                    permission=definition.permission,
                    approval_granted=True,
                    purpose=f"tool:{definition.name}",
                )
            )
            with scope:
                value = definition.handler(payload)
        except Exception as exc:  # noqa: BLE001
            completed_at = iso_now()
            return ToolResult(
                name,
                definition.permission,
                "error",
                f"{type(exc).__name__}: {redact_text(str(exc))}",
                started_at,
                completed_at,
                max(0, int((time.monotonic() - started_monotonic) * 1000)),
                authorization_ref=authorization_ref,
                execution_binding=self._execution_bindings.get(name),
            )
        finally:
            self._active_direct_capability = previous_capability
            self._active_risk_scan = previous_scan
            self._network_execution.grant = previous_network_grant
        result_status = (
            "error"
            if isinstance(value, Mapping) and str(value.get("status") or "") in {"blocked", "failed", "dirty", "error"}
            else "ok"
        )
        execution_binding = self._persist_consumer_receipt(name, value)
        return ToolResult(
            name,
            definition.permission,
            result_status,
            value,
            started_at,
            iso_now(),
            max(0, int((time.monotonic() - started_monotonic) * 1000)),
            authorization_ref=authorization_ref,
            execution_binding=execution_binding or self._execution_bindings.get(name),
        )

    def authorize_for_loop(self, name: str, arguments: Mapping[str, Any]) -> str:
        """Authorize a Loop-owned effect without invoking the legacy handler.

        The Loop adapter owns the durable operation and isolated command
        dispatch.  This method preserves the catalog's schema, risk, scope,
        and per-call approval checks while preventing ``sitina_shell`` from
        falling through to the legacy in-memory rollback executor.
        """

        definition = self.get(name)
        payload = dict(arguments)
        try:
            validate_json_schema(payload, dict(definition.input_schema))
        except Exception as exc:  # noqa: BLE001
            raise ToolRuntimeError(f"tool input failed schema validation for {name}: {exc}") from exc
        return self._authorize(definition, payload)

    def bind_run(self, run_id: str) -> None:
        """Bind the active run_id so strong writes can tag lease/patch journal.
        Called by the runtime at the start of each run()."""
        self._run_id = run_id

    def _expected_before_hash(self, path: Path) -> object:
        normalized = str(path.expanduser().resolve(strict=False))
        return self._expected_before_hashes.get(normalized, _UNSET)

    def _strong_write_kwargs(self, path: Path) -> dict[str, Any]:
        """Pass a before-hash guard only when this run has a baseline value.

        ToolCatalog and ToolExecutor deliberately use private sentinels.  An
        unset catalog value must therefore not be passed as an ordinary hash,
        otherwise every first write is compared with the wrong sentinel and
        fails closed before it can create the file.
        """
        expected = self._expected_before_hash(path)
        return {} if expected is _UNSET else {"expected_before_hash": expected}

    def _record_after_hash(self, path: Path, result: Mapping[str, Any]) -> None:
        after = result.get("after_hash")
        if isinstance(after, str):
            self._expected_before_hashes[str(path.expanduser().resolve(strict=False))] = after

    @staticmethod
    def _risk_params(definition: ToolDefinition, arguments: Mapping[str, Any]) -> tuple[str, str | None, str | None] | None:
        """Map a builtin tool call to (operation, target, command) for the risk
        scanner. Returns None to skip scanning (glob/list/plugin/MCP — MCP has
        its own policy path)."""
        name = definition.name
        if name == "sitina_read_file":
            return ("read", str(arguments.get("path") or ""), None)
        if name in {"sitina_write_file", "sitina_edit_file"}:
            return ("write", str(arguments.get("path") or ""), None)
        if name == "sitina_delete_file":
            return ("delete", str(arguments.get("path") or ""), None)
        if name == "sitina_rename_file":
            return ("move", str(arguments.get("path") or ""), None)
        if name == "sitina_shell":
            return ("shell", None, str(arguments.get("command") or ""))
        if name == "sitina_process_start":
            argv = arguments.get("command")
            command = " ".join(str(item) for item in argv) if isinstance(argv, list) else str(argv or "")
            return ("shell", str(arguments.get("cwd") or ""), command)
        if name == "sitina_process_stop":
            return ("shell", None, "process stop")
        if name == "sitina_http_request":
            return ("web", str(arguments.get("url") or ""), None)
        return None

    def _enforce_workspace_boundary(self, definition: ToolDefinition, arguments: Mapping[str, Any]) -> None:
        if not self._strict_workspace:
            return
        name = definition.name
        path_value: str | None = None
        if name in {"sitina_read_file", "sitina_list_directory", "sitina_grep", "sitina_write_file", "sitina_edit_file", "sitina_delete_file", "sitina_rename_file"}:
            path_value = str(arguments.get("path") or self.workspace)
        elif name in {"sitina_shell", "sitina_process_start"}:
            raw_cwd = str(arguments.get("cwd") or self.workspace)
            path_value = raw_cwd if Path(raw_cwd).expanduser().is_absolute() else str(self.workspace / raw_cwd)
        elif name == "sitina_glob":
            pattern = str(arguments.get("pattern") or "")
            if not pattern:
                raise ToolApprovalDenied("workspace glob requires a pattern")
            expanded = Path(os.path.expanduser(pattern))
            if expanded.is_absolute():
                wildcard = next((index for index, char in enumerate(str(expanded)) if char in "*?["), len(str(expanded)))
                prefix = Path(str(expanded)[:wildcard]).parent if wildcard < len(str(expanded)) else expanded
                path_value = str(prefix)
            else:
                path_value = str(self.workspace / expanded)
        if path_value is None:
            return
        try:
            resolved = Path(path_value).expanduser().resolve(strict=False)
            root = self.workspace.resolve(strict=False)
            resolved.relative_to(root)
        except (OSError, ValueError):
            raise ToolApprovalDenied("tool target escapes the bound execution workspace") from None

    def _authorize(self, definition: ToolDefinition, arguments: Mapping[str, Any]) -> str:
        self._enforce_workspace_boundary(definition, arguments)
        # Deterministic risk floor (M1.4): scan first, hard-block cannot be
        # overridden by the approval callback.
        scan = None
        params = self._risk_params(definition, arguments)
        if params is not None:
            operation, target, command = params
            scan = self._risk_scanner.scan(
                operation,
                target=target,
                command=command,
                allowed_roots=[str(self.workspace), str(self.manager.sitina_home)],
            )
            if scan.action == "block":
                reasons = "; ".join(m.reason for m in scan.matches if m.action == "block") or "policy"
                denial_ref = "policy:" + hashlib.sha256(
                    stable_json(scan.model_dump()).encode("utf-8")
                ).hexdigest()
                raise ToolApprovalDenied(
                    f"risk scanner blocked {definition.name}: {reasons}",
                    authorization_ref=denial_ref,
                )
        self._last_authorization_scan = scan
        network_tool = definition.name == "sitina_http_request" or definition.name in self._network_tools
        approval_granted = definition.permission == "read" and not network_tool
        authorization_ref = "automatic-read"
        if not approval_granted:
            required_permission = "network" if network_tool else definition.permission
            risk = scan.risk_level if scan is not None else RISK_BY_PERMISSION[required_permission]
            host_effect = scan is not None and any(
                m.rule_id in _HOST_EFFECT_RULE_IDS for m in scan.matches
            )
            reason = f"tool requires {required_permission} permission (risk: {risk})"
            if host_effect:
                reason += " — HOST-EFFECT: escapes the worktree, no free rollback"
            request = ApprovalRequest(
                "approval-" + uuid.uuid4().hex,
                definition.name,
                required_permission,
                risk,
                definition.origin,
                dict(arguments),
                reason,
            )
            authorization_ref = request.request_id
            approval_granted = self.approval_callback is not None and self.approval_callback(request)
        if definition.security_server is not None and definition.security_tool is not None:
            action = str(arguments.get("action") or "call")
            tool = str(arguments.get("name") or ("list_tools" if action == "list_tools" else definition.security_tool))
            nested = arguments.get("arguments")
            resource_arguments = dict(nested) if isinstance(nested, Mapping) else dict(arguments)
            resource = next(
                (
                    str(resource_arguments[key])
                    for key in ("resource", "path", "url", "target", "destination")
                    if key in resource_arguments
                ),
                "*",
            )
            decision = self._mcp_policy.decide(
                ToolAccessRequest(
                    principal="autonomous_tool_runtime",
                    server=definition.security_server,
                    tool=tool,
                    action=action,
                    resource=resource,
                    arguments=dict(arguments),
                    risk=RISK_BY_PERMISSION.get(definition.permission, "unknown"),
                    approval_granted=approval_granted,
                    argument_aliases={"file": "path", "file_path": "path"},
                )
            )
            if not decision.allowed:
                raise ToolApprovalDenied(
                    f"MCP security policy {decision.disposition} for {definition.name}: {decision.reason}",
                    authorization_ref=authorization_ref,
                )
            if network_tool and not approval_granted:
                raise ToolApprovalDenied(
                    "remote MCP requires explicit network approval",
                    authorization_ref=authorization_ref,
                )
            self._authorize_network_tool(definition, arguments, authorization_ref)
            return authorization_ref
        if not approval_granted:
            raise ToolApprovalDenied(
                f"approval denied or unavailable for {definition.name} ({definition.permission})",
                authorization_ref=authorization_ref,
            )
        self._authorize_network_tool(definition, arguments, authorization_ref)
        if (
            definition.permission == "write"
            and scan is not None
            and self._write_executor is not None
            and self._run_id is not None
        ):
            approved_files = [
                str(arguments[key])
                for key in ("path", "destination")
                if isinstance(arguments.get(key), str)
            ]
            try:
                record = self._write_executor.approvals.create(
                    run_id=self._run_id,
                    action="approve",
                    risk_scan=scan,
                    plan_hash=hashlib.sha256(
                        stable_json({"tool": definition.name, "arguments": dict(arguments)}).encode()
                    ).hexdigest(),
                    approved_touched_files=approved_files,
                )
            except Exception:
                # Disposable mock fixtures may not provision the SQLite
                # approval tables.  Production execution never uses this
                # fallback because the Journal/CAS capability is mandatory.
                pass
            else:
                authorization_ref = record.approval_id
        return authorization_ref

    def _authorize_network_tool(
        self, definition: ToolDefinition, arguments: Mapping[str, Any], authorization_ref: str,
    ) -> None:
        if definition.name == "sitina_http_request":
            url = str(arguments.get("url") or "")
            header_names = tuple(str(key).lower() for key in dict(arguments.get("headers") or {}))
            if str(arguments.get("method") or "GET").upper() not in {"GET", "HEAD"} or "body" in arguments:
                raise ToolApprovalDenied("native HTTP supports only anonymous GET/HEAD reads", authorization_ref=authorization_ref)
        elif definition.name in self._network_tools:
            url, header_names = self._network_tools[definition.name]
        elif definition.permission in {"network", "external_service"}:
            raise ToolApprovalDenied("network tool has no bound local egress scope", authorization_ref=authorization_ref)
        else:
            return
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or any(name not in {"accept", "content-type"} for name in header_names)
        ):
            raise ToolApprovalDenied(
                "network tool requires an anonymous exact-host scope; credential headers need a bound account reference",
                authorization_ref=authorization_ref,
            )
        if self._native_network_authority is None:
            raise ToolApprovalDenied("network tool has no live task authority", authorization_ref=authorization_ref)
        backend, task_id = self._native_network_authority
        try:
            capability = issue_frozen_network_egress_capability(
                None, manifest_hash=None, operation="tool_http_request",
                allowed_hosts=(parsed.hostname,), expires_at=int(time.time()) + 300,
                provider_name="tool:" + definition.name, credential_reference="anonymous",
                _native_backend=backend, _native_task_id=task_id,
            )
        except LegacyWriteDenied as error:
            raise ToolApprovalDenied(str(error), authorization_ref=authorization_ref) from error
        request_binding = None
        if definition.name == "sitina_http_request":
            request_binding = {
                "url": url, "method": str(arguments.get("method") or "GET").upper(),
                "headers": {str(key).lower(): str(value) for key, value in dict(arguments.get("headers") or {}).items()},
            }
        self._network_grants[authorization_ref] = (capability, definition.name, request_binding)

    @contextlib.contextmanager
    def _open_authorized_http(
        self, url: str, *, data: bytes | None, headers: Mapping[str, str],
        method: str, timeout: float,
    ):
        grant = getattr(self._network_execution, "grant", None)
        if grant is None:
            raise ToolApprovalDenied("HTTP dispatch requires its current tool authorization")
        capability, tool_name, request_binding = grant
        if request_binding is not None and (
            data is not None or request_binding != {
                "url": url, "method": method,
                "headers": {str(key).lower(): str(value) for key, value in headers.items()},
            }
        ):
            raise ToolApprovalDenied("HTTP dispatch changed the exact authorized read request")
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
        ):
            raise ToolApprovalDenied("HTTP dispatch requires an exact host")
        allowed_headers = {"accept", "content-type"}
        if tool_name != "sitina_http_request":
            allowed_headers.add("mcp-session-id")
        if any(str(key).lower() not in allowed_headers for key in headers):
            raise ToolApprovalDenied("HTTP credential use has no bound account reference")

        class ScopedRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, response, code, message, response_headers, new_url):
                # A redirect is a different endpoint, not a new user grant.
                # Keep it as an observed HTTP response; never silently send it.
                if request_binding is not None:
                    return None
                redirected = urlsplit(new_url)
                _validate_network_capability(
                    capability, host=redirected.hostname or "", operation="tool_http_request",
                    provider_name="tool:" + tool_name, credential_reference="anonymous",
                )
                if redirected.scheme not in {"http", "https"} or redirected.username is not None or redirected.password is not None:
                    raise ToolApprovalDenied("HTTP redirect changes the authorized account scope")
                return super().redirect_request(request, response, code, message, response_headers, new_url)

        with authorized_frozen_network_egress(
            capability, host=parsed.hostname, operation="tool_http_request",
            provider_name="tool:" + tool_name, credential_reference="anonymous",
        ):
            request = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ScopedRedirect())
            self._network_execution.physical_send_state = "UNKNOWN"
            with opener.open(request, timeout=timeout) as response:
                self._network_execution.physical_send_state = "RESPONSE_RECEIVED"
                yield response

    def _add(self, definition: ToolDefinition) -> None:
        if definition.name in self._tools:
            raise ExtensionSpecError(f"duplicate tool name: {definition.name}")
        if len(definition.name) > 64 or not all(char.isalnum() or char in "_-" for char in definition.name):
            raise ExtensionSpecError(f"tool name is not provider-compatible: {definition.name}")
        self._tools[definition.name] = definition

    @staticmethod
    def _object_schema(properties: Mapping[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": dict(properties),
            "required": list(required),
            "additionalProperties": False,
        }

    def _register_builtins(self) -> None:
        self._add(
            ToolDefinition(
                "sitina_read_file",
                "Read a UTF-8 text file. Read-only and automatically permitted.",
                self._object_schema({"path": {"type": "string"}}, ("path",)),
                "read",
                "sitina",
                lambda value: Path(str(value["path"])).expanduser().resolve(strict=True).read_text(
                    encoding="utf-8", errors="replace"
                ),
            )
        )
        self._add(
            ToolDefinition(
                "sitina_list_directory",
                "List one local directory. Read-only and automatically permitted.",
                self._object_schema({"path": {"type": "string"}}, ("path",)),
                "read",
                "sitina",
                lambda value: [
                    {"name": item.name, "type": "directory" if item.is_dir() else "file"}
                    for item in sorted(Path(str(value["path"])).expanduser().resolve(strict=True).iterdir())
                ],
            )
        )
        self._add(
            ToolDefinition(
                "sitina_glob",
                "Find local paths using a glob pattern. Read-only and automatically permitted.",
                self._object_schema({"pattern": {"type": "string"}}, ("pattern",)),
                "read",
                "sitina",
                self._glob,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_grep",
                "Search file contents by regular expression under a directory. "
                "Read-only and automatically permitted. Returns matches as file:line entries.",
                self._object_schema(
                    {
                        "pattern": {"type": "string"},
                        "path": {"type": "string"},
                        "include": {"type": "string"},
                        "ignore_case": {"type": "boolean"},
                        "max_results": {"type": "number"},
                    },
                    ("pattern",),
                ),
                "read",
                "sitina",
                self._grep,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_write_file",
                "Write UTF-8 text to a local file. Requires per-call write approval.",
                self._object_schema(
                    {"path": {"type": "string"}, "content": {"type": "string"}, "append": {"type": "boolean"}},
                    ("path", "content"),
                ),
                "write",
                "sitina",
                self._write_file,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_edit_file",
                "Edit a file by replacing an exact string. Requires per-call write approval. "
                "old_string must match verbatim and (unless replace_all) appear exactly once; "
                "supply enough surrounding context to make it unique.",
                self._object_schema(
                    {
                        "path": {"type": "string"},
                        "old_string": {"type": "string"},
                        "new_string": {"type": "string"},
                        "replace_all": {"type": "boolean"},
                    },
                    ("path", "old_string", "new_string"),
                ),
                "write",
                "sitina",
                self._edit_file,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_delete_file",
                "Delete one regular file inside the bound workspace. Root, user-home, system and sensitive paths are blocked; requires write approval.",
                self._object_schema({"path": {"type": "string"}}, ("path",)),
                "write", "sitina", self._delete_file,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_rename_file",
                "Rename one regular file inside the bound workspace. Both source and destination are scope-bound; requires write approval.",
                self._object_schema({"path": {"type": "string"}, "destination": {"type": "string"}}, ("path", "destination")),
                "write", "sitina", self._rename_file,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_shell",
                "Run one approved foreground test, lint, or build command in the selected directory. "
                "The command must exactly match tester_allowed_commands policy; do not add semicolons, pipes, echo, "
                "or unauthorized flags. When status is ok and exit_code is 0, treat the result as verified and do "
                "not repeat it merely to inspect output. Requires per-call shell approval.",
                self._object_schema(
                    {
                        "command": {"type": "string"},
                        "cwd": {"type": "string"},
                        "timeout_seconds": {"type": "number"},
                    },
                    ("command",),
                ),
                "shell",
                "sitina",
                self._shell,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_http_request",
                "Make an HTTP request. Requires per-call network approval.",
                self._object_schema(
                    {
                        "url": {"type": "string"},
                        "method": {"type": "string"},
                        "headers": {"type": "object"},
                        "body": {"type": "string"},
                    },
                    ("url",),
                ),
                "network",
                "sitina",
                self._http,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_process_start",
                "Start an argv-only managed background process in the bound workspace for a service or other "
                "long-running task. Do not use it for unittest or other one-shot tests. It is audited and cleaned "
                "up at task end unless keep is explicitly authorized.",
                self._object_schema({
                    "command": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"}, "keep": {"type": "boolean"},
                }, ("command",)),
                "shell", "sitina", self._process_start,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_process_status",
                "Read status for a managed process owned by this execution run.",
                self._object_schema({"process_id": {"type": "string"}}, ("process_id",)),
                "read", "sitina", self._process_status,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_process_log",
                "Read redacted tail logs for a managed process owned by this execution run.",
                self._object_schema({"process_id": {"type": "string"}, "tail_lines": {"type": "number"}}, ("process_id",)),
                "read", "sitina", self._process_log,
            )
        )
        self._add(
            ToolDefinition(
                "sitina_process_stop",
                "Stop a managed process owned by this execution run.",
                self._object_schema({"process_id": {"type": "string"}}, ("process_id",)),
                "shell", "sitina", self._process_stop,
            )
        )

    def _register_extensions(self) -> None:
        # A marker-only managed root without a connected authority client is
        # fail-closed for legacy extension reads.  The ordinary Loop runtime
        # still needs its built-in tools to initialize; selected extensions
        # are registered later only after an authenticated snapshot is bound.
        if self.manager.authority_bound:
            skills = []
        else:
            skills = self.manager.skills()
        for skill in skills:
            self._skill_roots[skill.qualified_name] = skill.path.parent
        if skills:
            self._add(
                ToolDefinition(
                    "sitina_read_skill_resource",
                    "Read a reference, asset description, or script source belonging to an active Skill.",
                    self._object_schema(
                        {"skill": {"type": "string"}, "path": {"type": "string"}},
                        ("skill", "path"),
                    ),
                    "read",
                    "sitina",
                    self._read_skill_resource,
                )
            )
        # A bound r4 manager exposes active plugins through the authoritative
        # projection, but command tools still require the selected immutable
        # execution snapshot.  Registering the active projection here would
        # create an unbound duplicate when bind_execution_snapshot performs
        # the fixed registration below.
        if not self.manager.authority_bound:
            for manifest, record in self.manager.active_plugins():
                granted = set(record.get("granted_permissions", []))
                declared = set(manifest.permissions)
                if not granted <= declared:
                    raise ExtensionSpecError(f"plugin {manifest.name} registry grants exceed its manifest")
                self._register_command_tools(manifest, granted)
                self._register_mcp_tools(manifest, granted)

    def _register_command_tools(
        self,
        manifest: PluginManifest,
        granted: set[str],
        *,
        integrity_guard: Callable[[], None] | None = None,
        execution_binding: Mapping[str, Any] | None = None,
        cancel_probe: Callable[[], bool] | None = None,
    ) -> None:
        path = manifest.component_path("tools")
        if not path:
            return
        raw = read_json_object(path, schema=TOOLS_SCHEMA)
        items = raw.get("tools", [])
        if not isinstance(items, list):
            raise ExtensionSpecError("tools must be an array")
        for item in items:
            if not isinstance(item, dict):
                raise ExtensionSpecError("tool entries must be objects")
            local_name = validate_identifier(str(item.get("name") or ""), label="tool name")
            permission = str(item.get("permission") or "")
            if permission not in granted:
                continue
            command = item.get("command")
            if not isinstance(command, list) or not command or any(not isinstance(part, str) for part in command):
                raise ExtensionSpecError(f"plugin tool {local_name} command must be a string array")
            schema = item.get("input_schema") or {"type": "object", "properties": {}}
            if not isinstance(schema, dict):
                raise ExtensionSpecError(f"plugin tool {local_name} input_schema must be an object")
            public_name = self._public_name(manifest.name, local_name)
            handler = self._command_handler(
                manifest, command, item,
                integrity_guard=integrity_guard,
                cancel_probe=cancel_probe,
            )
            bound_python = bool(
                execution_binding is not None
                and str(execution_binding.get("python_path") or "")
                and str(Path(command[0]).expanduser().resolve(strict=False))
                == str(execution_binding.get("python_path") or "")
            )
            if bound_python:
                # A bound candidate Python command is reachable only through
                # the Loop CommandRunner dispatch boundary.  Direct catalog
                # execution must not silently fall back to subprocess.run.
                def handler(_value: dict[str, Any]) -> Any:
                    raise ToolRuntimeError("bound Plugin Python command requires the Loop command runner")

            self._add(
                ToolDefinition(
                    public_name,
                    str(item.get("description") or f"Plugin tool {manifest.name}:{local_name}"),
                    schema,
                    permission,
                    f"plugin:{manifest.name}",
                    handler,
                )
            )
            if execution_binding is not None:
                expected_output = None
                if item.get("expected_output") is not None:
                    expected_output = item.get("expected_output")
                controlled_executor = (
                    "loop-command-runner"
                    if bound_python
                    else None
                )
                self._execution_bindings[public_name] = {
                    **dict(execution_binding),
                    "tool_name": public_name,
                    "command": list(command),
                    "method_contract": {
                        "schema": "SITINA_EXTENSION_METHOD_EXPECTATION_V1",
                        "kind": "plugin-command",
                        "command": list(command),
                        "timeout_seconds": str(item.get("timeout_seconds", 30)),
                        "output_json": bool(item.get("output_json", True)),
                        "expected_output": expected_output,
                        "controlled_executor": controlled_executor,
                        "input_schema": dict(item.get("input_schema") or {}),
                        "output_schema": dict(item.get("output_schema") or {}) if isinstance(item.get("output_schema"), Mapping) else None,
                        "cache": dict(item.get("cache") or {}) if isinstance(item.get("cache"), Mapping) else None,
                        "result_status": "ok",
                    },
                }
                self._execution_bindings[public_name]["method_id"] = hashlib.sha256(
                    stable_json(self._execution_bindings[public_name]).encode("utf-8")
                ).hexdigest()

    def _register_mcp_tools(
        self,
        manifest: PluginManifest,
        granted: set[str],
        *,
        integrity_guard: Callable[[], None] | None = None,
        execution_binding: Mapping[str, Any] | None = None,
    ) -> None:
        path = manifest.component_path("mcp")
        if not path:
            return
        raw = read_json_object(path, schema=MCP_SCHEMA)
        servers = raw.get("servers", [])
        if not isinstance(servers, list):
            raise ExtensionSpecError("MCP servers must be an array")
        for server in servers:
            if not isinstance(server, dict):
                raise ExtensionSpecError("MCP server entries must be objects")
            server_name = validate_identifier(str(server.get("name") or ""), label="MCP server name")
            permission = str(server.get("permission") or "")
            if permission not in granted:
                continue
            advertised = server.get("tools")
            if advertised is None:
                advertised = [
                    {
                        "name": "call",
                        "description": (
                            f"Discover or call tools on the {server_name} MCP server. Use action=list_tools first "
                            "when tool names or schemas are unknown."
                        ),
                        "input_schema": self._object_schema(
                            {
                                "action": {"type": "string", "enum": ["list_tools", "call"]},
                                "name": {"type": "string"},
                                "arguments": {"type": "object"},
                            },
                            ("action",),
                        ),
                        "generic": True,
                    }
                ]
            if not isinstance(advertised, list):
                raise ExtensionSpecError("MCP advertised tools must be an array")
            for advertised_tool in advertised:
                if not isinstance(advertised_tool, dict):
                    raise ExtensionSpecError("MCP advertised tool entries must be objects")
                tool_name = validate_identifier(str(advertised_tool.get("name") or ""), label="MCP tool name")
                generic = bool(advertised_tool.get("generic"))
                schema = advertised_tool.get("input_schema") or {"type": "object", "properties": {}}
                public_name = self._public_name(manifest.name, f"{server_name}_{tool_name}")
                if str(server.get("transport") or "stdio") in {"http", "streamable_http"}:
                    self._network_tools[public_name] = (
                        str(server.get("url") or ""),
                        tuple(str(key).lower() for key in dict(server.get("headers") or {})),
                    )
                self._add(
                    ToolDefinition(
                        public_name,
                        str(advertised_tool.get("description") or f"MCP tool {server_name}:{tool_name}"),
                        schema,
                        permission,
                        f"plugin:{manifest.name}:mcp:{server_name}",
                        self._mcp_handler(
                            manifest, server, None if generic else tool_name,
                            integrity_guard=integrity_guard,
                        ),
                        f"{manifest.name}:{server_name}",
                        "*" if generic else tool_name,
                    )
                )
                self._mcp_rules.append(
                    ToolPermissionRule(
                        rule_id=f"plugin:{manifest.name}:mcp:{server_name}:{tool_name}",
                        principals=("autonomous_tool_runtime",),
                        server_pattern=f"{manifest.name}:{server_name}",
                        tool_pattern="*" if generic else tool_name,
                        actions=("list_tools", "call") if generic else ("call",),
                        effect="allow" if permission == "read" else "approval",
                        resource_patterns=("*",),
                        allowed_arguments=frozenset(str(key).casefold() for key in dict(schema.get("properties") or {})),
                        max_risk=RISK_BY_PERMISSION.get(permission, "critical"),
                    )
                )
                if execution_binding is not None:
                    self._execution_bindings[public_name] = {
                        **dict(execution_binding),
                        "tool_name": public_name,
                        "server": server_name,
                    }
                    self._execution_bindings[public_name]["method_id"] = hashlib.sha256(
                        stable_json(self._execution_bindings[public_name]).encode("utf-8")
                    ).hexdigest()

    @staticmethod
    def _public_name(plugin: str, local: str) -> str:
        raw = f"{plugin}__{local}"
        if len(raw) <= 64:
            return raw
        suffix = uuid.uuid5(uuid.NAMESPACE_URL, raw).hex[:10]
        return raw[:53] + "_" + suffix

    _GREP_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"})

    def _grep(self, value: dict[str, Any]) -> dict[str, Any]:
        flags = re.IGNORECASE if bool(value.get("ignore_case")) else 0
        try:
            pattern = re.compile(str(value["pattern"]), flags)
        except re.error as error:
            raise ToolRuntimeError(f"invalid grep pattern: {error}") from error
        root = Path(str(value.get("path") or self.workspace)).expanduser().resolve(strict=True)
        include = str(value["include"]) if value.get("include") else None
        max_results = int(value["max_results"]) if value.get("max_results") is not None else 200
        matches: list[dict[str, Any]] = []
        truncated = False
        traversal = (
            ((str(root.parent), [], [root.name]),)
            if root.is_file()
            else os.walk(root)
        )
        for current, dirs, files in traversal:
            dirs[:] = sorted(name for name in dirs if name not in self._GREP_SKIP_DIRS)
            for name in sorted(files):
                if include is not None and not fnmatch.fnmatch(name, include):
                    continue
                file_path = Path(current) / name
                try:
                    with file_path.open("r", encoding="utf-8", errors="strict") as handle:
                        for number, line in enumerate(handle, start=1):
                            if pattern.search(line):
                                matches.append(
                                    {
                                        "file": str(file_path),
                                        "line": number,
                                        "text": line.rstrip("\n")[:400],
                                    }
                                )
                                if len(matches) >= max_results:
                                    truncated = True
                                    break
                except (UnicodeDecodeError, OSError):
                    continue  # skip binary/unreadable files
                if truncated:
                    break
            if truncated:
                break
        return {"matches": matches, "count": len(matches), "truncated": truncated}

    def _glob(self, value: dict[str, Any]) -> list[str]:
        pattern = str(value["pattern"])
        expanded = Path(os.path.expanduser(pattern))
        search = str(expanded if expanded.is_absolute() else self.workspace / expanded)
        results = sorted(glob.glob(search, recursive=True))
        if not self._strict_workspace:
            return results
        root = self.workspace.resolve(strict=True)
        safe: list[str] = []
        for raw in results:
            path = Path(raw)
            if path.is_symlink():
                raise ToolRuntimeError("glob result is a symlink in strict execution")
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(root)
            except ValueError:
                raise ToolRuntimeError("glob result escapes the bound execution workspace") from None
            safe.append(str(resolved))
        return safe

    def _write_file(self, value: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(value["path"])).expanduser().resolve(strict=False)
        content = str(value["content"])
        append = bool(value.get("append"))
        # Strong write path (M1.1): every approved write, including append, is
        # converted into one atomic full-content replacement with before/after
        # hashes, a PathLease, and a patch-journal record.  No accepted write
        # may bypass mutation evidence merely because the requested operation
        # was append.
        if self._write_executor is not None and self._run_id is not None:
            if path.exists() and not path.is_file():
                raise ToolRuntimeError(f"write target is not a regular file: {path}")
            original = path.read_text(encoding="utf-8") if append and path.is_file() else ""
            updated = original + content if append else content
            result = self._write_executor.write_direct(
                target=str(path),
                content=updated,
                run_id=self._run_id,
                capability=self._active_direct_capability,
                **self._strong_write_kwargs(path),
            )
            if result.get("status") != "ok":
                raise ToolRuntimeError(
                    f"strong write failed ({result.get('status')}): {result.get('reason')}"
                )
            self._record_after_hash(path, result)
            return {
                "path": str(path),
                "bytes": len(content.encode("utf-8")),
                "append": append,
                "patch_id": result.get("patch_id"),
                "before_hash": result.get("before_hash"),
                "after_hash": result.get("after_hash"),
                "worker_observed": result.get("worker_observed") is True,
                "worker_binding_hash": result.get("worker_binding_hash"),
            }
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with path.open(mode, encoding="utf-8") as handle:
            handle.write(content)
        return {"path": str(path), "bytes": len(content.encode("utf-8")), "append": mode == "a"}

    def _edit_file(self, value: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(value["path"])).expanduser().resolve(strict=False)
        old = str(value["old_string"])
        new = str(value["new_string"])
        replace_all = bool(value.get("replace_all"))
        if old == new:
            raise ToolRuntimeError("old_string and new_string are identical; nothing to edit")
        if not path.is_file():
            raise ToolRuntimeError(f"edit target does not exist or is not a file: {path}")
        original = path.read_text(encoding="utf-8")
        occurrences = original.count(old)
        if occurrences == 0:
            raise ToolRuntimeError("old_string not found in file (must match verbatim)")
        if occurrences > 1 and not replace_all:
            raise ToolRuntimeError(
                f"old_string is not unique ({occurrences} matches); add surrounding context "
                f"or set replace_all=true"
            )
        updated = original.replace(old, new) if replace_all else original.replace(old, new, 1)
        replaced = occurrences if replace_all else 1
        # Route through the strong write path (atomic + before_hash + patch journal)
        # when available; otherwise plain atomic-ish overwrite.
        if self._write_executor is not None and self._run_id is not None:
            result = self._write_executor.write_direct(
                target=str(path),
                content=updated,
                run_id=self._run_id,
                capability=self._active_direct_capability,
                **self._strong_write_kwargs(path),
            )
            if result.get("status") != "ok":
                raise ToolRuntimeError(
                    f"strong write failed ({result.get('status')}): {result.get('reason')}"
                )
            self._record_after_hash(path, result)
            return {
                "path": str(path),
                "replaced": replaced,
                "patch_id": result.get("patch_id"),
                "before_hash": result.get("before_hash"),
                "after_hash": result.get("after_hash"),
            }
        with path.open("w", encoding="utf-8") as handle:
            handle.write(updated)
        return {"path": str(path), "replaced": replaced}

    def _destructive_path_guard(self, path: Path) -> None:
        resolved = path.expanduser().resolve(strict=False)
        workspace = self.workspace.resolve(strict=False)
        forbidden = {
            Path("/"), Path.home().resolve(strict=False), workspace,
            Path("/System"), Path("/Library"), Path("/usr"), Path("/etc"),
        }
        if resolved in forbidden:
            raise ToolRuntimeError("destructive operation on a protected root requires separate confirmation")
        if self._strict_workspace and not (resolved == workspace or workspace in resolved.parents):
            raise ToolRuntimeError("destructive operation escapes the bound workspace")

    def _delete_file(self, value: dict[str, Any]) -> dict[str, Any]:
        if self._write_executor is None or self._run_id is None or self._active_direct_capability is None:
            raise ToolRuntimeError("delete requires a bound execution capability")
        path = Path(str(value["path"])).expanduser().resolve(strict=False)
        self._destructive_path_guard(path)
        result = self._write_executor.execute(
            operation="delete", run_id=self._run_id, agent="forge-execution-role",
            target=str(path), allowed_roots=[str(self.workspace)],
            capability=self._active_direct_capability,
            approval_id=self._active_direct_capability.authorization_ref,
            approved_files=[str(path)],
            precomputed_risk_scan=self._active_risk_scan,
        )
        if result.get("status") != "ok":
            raise ToolRuntimeError(str(result.get("reason") or "delete failed"))
        return {"path": str(path), "operation": "delete", **result}

    def _rename_file(self, value: dict[str, Any]) -> dict[str, Any]:
        if self._write_executor is None or self._run_id is None or self._active_direct_capability is None:
            raise ToolRuntimeError("rename requires a bound execution capability")
        source = Path(str(value["path"])).expanduser().resolve(strict=False)
        destination = Path(str(value["destination"])).expanduser().resolve(strict=False)
        self._destructive_path_guard(source)
        self._destructive_path_guard(destination)
        result = self._write_executor.execute(
            operation="move", run_id=self._run_id, agent="forge-execution-role",
            target=str(source), destination=str(destination),
            allowed_roots=[str(self.workspace)],
            capability=self._active_direct_capability,
            approval_id=self._active_direct_capability.authorization_ref,
            approved_files=[str(source), str(destination)],
            precomputed_risk_scan=self._active_risk_scan,
        )
        if result.get("status") != "ok":
            raise ToolRuntimeError(str(result.get("reason") or "rename failed"))
        return {"path": str(source), "destination": str(destination), "operation": "rename", **result}

    def _require_process_manager(self) -> Any:
        if self._managed_process_manager is None:
            raise ToolRuntimeError("managed process API is unavailable outside a bound execution run")
        return self._managed_process_manager

    def _process_start(self, value: dict[str, Any]) -> dict[str, Any]:
        manager = self._require_process_manager()
        argv = [str(item) for item in value["command"]]
        normalized = normalize_command(" ".join(argv))
        if not any(
            normalized == normalize_command(item)
            or normalized.startswith(normalize_command(item) + " ")
            for item in self._tester_allowed_commands
        ):
            raise ToolRuntimeError("managed process command is not in tester_allowed_commands")
        before = self._workspace_state()
        result = manager.start(argv, cwd=value.get("cwd"), keep=bool(value.get("keep", False)))
        process_id = str(result.get("process_id") or "")
        if not process_id:
            raise ToolRuntimeError("managed process start returned no process identity")
        self._managed_process_baselines[process_id] = before
        return {
            "operation": "start",
            "mutation_audit": "workspace-diff-bound-to-process-lifecycle",
            **result,
        }

    def _process_status(self, value: dict[str, Any]) -> dict[str, Any]:
        process_id = str(value["process_id"])
        manager = self._require_process_manager()
        result = manager.status(process_id)
        mutation = self._reconcile_managed_process(process_id, stop_on_change=True)
        if mutation is not None:
            return {"operation": "status", **mutation, "process": result}
        return {"operation": "status", **result}

    def _process_log(self, value: dict[str, Any]) -> dict[str, Any]:
        process_id = str(value["process_id"])
        mutation = self._reconcile_managed_process(process_id, stop_on_change=True)
        if mutation is not None:
            return {"operation": "log", **mutation}
        return {"operation": "log", **self._require_process_manager().log(
            process_id, tail_lines=int(value.get("tail_lines", 200) or 200)
        )}

    def _process_stop(self, value: dict[str, Any]) -> dict[str, Any]:
        process_id = str(value["process_id"])
        manager = self._require_process_manager()
        result = manager.stop(process_id)
        mutation = self._reconcile_managed_process(process_id, stop_on_change=False)
        if mutation is not None:
            return {"operation": "stop", **mutation, "process": result}
        return {"operation": "stop", **result}

    def _reconcile_managed_process(
        self, process_id: str, *, stop_on_change: bool,
    ) -> dict[str, Any] | None:
        before = self._managed_process_baselines.get(process_id)
        if before is None:
            return None
        after = self._workspace_state()
        before_descriptors = self._state_descriptors(before)
        after_descriptors = self._state_descriptors(after)
        changed = sorted(
            path for path in set(before_descriptors) | set(after_descriptors)
            if before_descriptors.get(path) != after_descriptors.get(path)
        )
        if not changed:
            return None
        manager = self._require_process_manager()
        stop_error: str | None = None
        if stop_on_change:
            try:
                manager.stop(process_id)
            except Exception as error:  # noqa: BLE001
                stop_error = type(error).__name__
        after_stop = self._workspace_state()
        rollback = self._rollback_workspace(before, after_stop, changed)
        failed = list(rollback.get("failed_paths") or [])
        if stop_error:
            failed.append("<process-stop:" + stop_error + ">")
        self._managed_process_baselines.pop(process_id, None)
        return {
            "status": "dirty" if failed else "blocked",
            "reason": "managed process produced unregistered workspace mutations",
            "unregistered_paths": changed[:200],
            "rollback_status": "failed" if failed else "complete",
            "rolled_back_paths": list(rollback.get("rolled_back_paths") or [])[:200],
            "rollback_failed_paths": sorted(set(failed))[:200],
        }

    def reconcile_managed_processes(self) -> None:
        """Stop/reconcile every async process before task cleanup.

        This is called from AutonomousRuntime's finally path, so a process
        that mutates after its start call cannot disappear silently between
        the last model turn and terminal evidence.
        """

        failures: list[str] = []
        non_kept: list[str] = []
        for process_id in sorted(tuple(self._managed_process_baselines)):
            try:
                metadata = self._require_process_manager()._load(process_id)
            except Exception as error:  # noqa: BLE001
                failures.append(process_id + ":" + type(error).__name__)
                continue
            if bool(metadata.get("keep")):
                # Explicit keep is the only task-end exception.  It remains
                # outside cleanup and is not silently converted into a
                # stopped process.
                continue
            non_kept.append(process_id)
            # Give a just-started child a short, bounded settle window.  This
            # is part of the production lifecycle contract, not a test sleep:
            # fast async writes must be observable before termination, while
            # the post-stop snapshot below closes the remaining race window.
            settle_deadline = time.monotonic() + 0.25
            while time.monotonic() < settle_deadline:
                settled_state = self._workspace_state()
                before_descriptors = self._state_descriptors(self._managed_process_baselines[process_id])
                settled_descriptors = self._state_descriptors(settled_state)
                if any(
                    before_descriptors.get(path) != settled_descriptors.get(path)
                    for path in set(before_descriptors) | set(settled_descriptors)
                ):
                    break
                time.sleep(0.01)
            try:
                # Stop and verify first.  A pre-stop snapshot is insufficient:
                # a child can be scheduled between that snapshot and SIGTERM.
                self._require_process_manager().stop(process_id)
            except Exception as error:  # noqa: BLE001
                failures.append(process_id + ":stop-" + type(error).__name__)

        # Only after every non-keep process has been confirmed stopped do we
        # inspect/restore the baseline.  This closes the final scheduling
        # window for asynchronous mutations.
        for process_id in non_kept:
            try:
                result = self._reconcile_managed_process(process_id, stop_on_change=False)
            except Exception as error:  # noqa: BLE001
                failures.append(process_id + ":" + type(error).__name__)
            else:
                if result is not None and result.get("status") == "dirty":
                    failures.append(process_id + ":rollback-failed")
                elif result is not None:
                    # A mutation was observed even when rollback succeeded;
                    # raise so the outer runtime cannot claim successful
                    # execution.  The returned path set is already audited by
                    # the eventual ToolRuntimeError boundary.
                    failures.append(process_id + ":unregistered-mutation")
        if failures:
            raise ToolRuntimeError("managed process mutation reconciliation failed: " + ",".join(failures))

    def _shell(self, value: dict[str, Any]) -> dict[str, Any]:
        cwd = Path(str(value.get("cwd") or self.workspace)).expanduser().resolve(strict=True)
        if self._write_executor is None or self._run_id is None:
            return {"status": "blocked", "reason": "shell requires a bound execution runtime"}
        # Keep the rollback image in memory only.  It is deliberately never
        # placed in the tool result, Journal, CAS, or command artifact; this
        # permits restoring a pre-existing secret without exposing it to the
        # model or audit stream.
        before_state = self._workspace_state()
        before = self._state_descriptors(before_state)
        result = self._write_executor.execute(
            operation="shell",
            run_id=self._run_id,
            agent="tester",
            target=str(cwd),
            command=str(value["command"]),
            cwd=str(cwd),
            allowed_commands=list(self._tester_allowed_commands),
        )
        after_state = self._workspace_state()
        after = self._state_descriptors(after_state)
        changed = sorted(
            path for path in set(before) | set(after)
            if before.get(path) != after.get(path)
        )
        if changed:
            rollback = self._rollback_workspace(before_state, after_state, changed)
            rollback_failed = list(rollback.get("failed_paths") or [])
            return {
                # A successful rollback is still a rejected shell call.  A
                # failed rollback is explicitly dirty and requires user
                # resolution; neither state is admissible execution evidence.
                "status": "dirty" if rollback_failed else "blocked",
                "reason": "shell produced unregistered workspace mutations",
                "unregistered_paths": changed[:200],
                "rollback_status": "failed" if rollback_failed else "complete",
                "rolled_back_paths": list(rollback.get("rolled_back_paths") or [])[:200],
                "rollback_failed_paths": rollback_failed[:200],
                "command_result": {key: value for key, value in result.items() if key not in {"risk_scan"}},
            }
        return {key: value for key, value in result.items() if key != "risk_scan"}

    def _workspace_snapshot(self) -> dict[str, str]:
        """Return hash/type-only state suitable for comparison and audit."""

        return self._state_descriptors(self._workspace_state())

    def _workspace_state(self) -> dict[str, dict[str, Any]]:
        """Capture a private, in-memory rollback image of the workspace.

        Regular-file bytes are retained only for the duration of one shell
        call.  Symlink targets and file types are captured explicitly so a
        command cannot hide a replacement behind ``Path.is_file()``.  The
        ``.sitina`` bookkeeping directory is outside the command mutation
        surface; ``.git`` is intentionally included so git metadata changes
        cannot evade the dirty-workspace check.
        """

        root = self.workspace.resolve(strict=True)
        state: dict[str, dict[str, Any]] = {}
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name != ".sitina")
            for name in tuple(dirs):
                path = Path(current) / name
                relative = path.relative_to(root).as_posix()
                state[relative] = self._capture_workspace_entry(path)
            for name in sorted(files):
                path = Path(current) / name
                relative = path.relative_to(root).as_posix()
                state[relative] = self._capture_workspace_entry(path)
        return state

    @staticmethod
    def _capture_workspace_entry(path: Path) -> dict[str, Any]:
        try:
            item = path.lstat()
            mode = int(item.st_mode & 0o7777)
            if stat.S_ISLNK(item.st_mode):
                return {"kind": "symlink", "target": os.readlink(path), "mode": mode}
            if stat.S_ISREG(item.st_mode):
                # This is an ephemeral rollback buffer, never an evidence
                # payload.  A read failure is fail-closed because restoring
                # the user's prior bytes would not be provable.
                return {"kind": "file", "content": path.read_bytes(), "mode": mode}
            if stat.S_ISDIR(item.st_mode):
                return {"kind": "directory", "mode": mode}
            return {"kind": "special", "mode": mode}
        except OSError as error:
            raise ToolRuntimeError("workspace snapshot could not safely read a path") from error

    @staticmethod
    def _state_descriptors(state: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
        descriptors: dict[str, str] = {}
        for relative, entry in state.items():
            kind = str(entry.get("kind") or "special")
            if kind == "file":
                content = entry.get("content")
                if not isinstance(content, bytes):
                    raise ToolRuntimeError("workspace snapshot contains invalid file identity")
                descriptors[relative] = "file:" + hashlib.sha256(content).hexdigest()
            elif kind == "symlink":
                target = str(entry.get("target") or "")
                descriptors[relative] = "symlink:" + hashlib.sha256(
                    target.encode("utf-8", "surrogateescape")
                ).hexdigest()
            elif kind == "directory":
                descriptors[relative] = "directory"
            else:
                descriptors[relative] = "special:" + oct(int(entry.get("mode") or 0) & 0o170000)
        return descriptors

    def _snapshot_path(self, relative: str) -> Path:
        root = self.workspace.resolve(strict=True)
        path = root / relative
        # Validate the parent, not the final component: the final component
        # may itself be a symlink that must be removed during rollback.
        parent = path.parent.resolve(strict=False)
        if parent != root and root not in parent.parents:
            raise ToolRuntimeError("workspace rollback path escapes the bound workspace")
        return path

    def _remove_workspace_path(self, path: Path) -> None:
        try:
            item = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISDIR(item.st_mode) and not stat.S_ISLNK(item.st_mode):
            for child in list(os.scandir(path)):
                self._remove_workspace_path(Path(child.path))
            path.rmdir()
        else:
            path.unlink()

    def _rollback_workspace(
        self,
        before: Mapping[str, Mapping[str, Any]],
        after: Mapping[str, Mapping[str, Any]],
        changed: list[str],
    ) -> dict[str, Any]:
        rolled_back: list[str] = []
        failed: list[str] = []
        # Remove changed post-command paths deepest-first.  This handles
        # newly-created directories and type replacements without following a
        # symlink into a user or system directory.
        for relative in sorted(changed, key=lambda item: (item.count("/"), item), reverse=True):
            if relative not in after:
                continue
            try:
                self._remove_workspace_path(self._snapshot_path(relative))
            except (OSError, ToolRuntimeError):
                failed.append(relative)
        # Recreate only the prior state for changed paths, shallowest-first.
        for relative in sorted(changed, key=lambda item: (item.count("/"), item)):
            entry = before.get(relative)
            if entry is None:
                continue
            try:
                path = self._snapshot_path(relative)
                kind = str(entry.get("kind") or "special")
                path.parent.mkdir(parents=True, exist_ok=True)
                if kind == "directory":
                    path.mkdir(exist_ok=True)
                    os.chmod(path, int(entry.get("mode") or 0o755))
                elif kind == "file":
                    content = entry.get("content")
                    if not isinstance(content, bytes):
                        raise ToolRuntimeError("file rollback content is unavailable")
                    path.write_bytes(content)
                    os.chmod(path, int(entry.get("mode") or 0o644))
                elif kind == "symlink":
                    os.symlink(str(entry.get("target") or ""), path)
                else:
                    # Device/FIFO restoration is not safe for an autonomous
                    # command.  Keep the run dirty and require a decision.
                    raise ToolRuntimeError("special file rollback is unsupported")
                rolled_back.append(relative)
            except (OSError, ToolRuntimeError):
                failed.append(relative)
        try:
            if not failed and self._state_descriptors(self._workspace_state()) != self._state_descriptors(before):
                failed.extend(changed)
        except ToolRuntimeError:
            failed.extend(changed)
        return {
            "rolled_back_paths": sorted(set(rolled_back)),
            "failed_paths": sorted(set(failed)),
        }

    def _http(self, value: dict[str, Any]) -> dict[str, Any]:
        headers = {str(key): str(item) for key, item in dict(value.get("headers") or {}).items()}
        method = str(value.get("method") or "GET").upper()
        self._network_execution.physical_send_state = "NOT_DISPATCHED"
        try:
            with self._open_authorized_http(
                str(value["url"]), data=None, headers=headers, method=method, timeout=60,
            ) as response:
                data = response.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise ToolRuntimeError("HTTP response exceeds the 1 MiB read limit")
                return {
                    "status": response.status,
                    "headers": dict(response.headers.items()),
                    "body": data.decode("utf-8", errors="replace"),
                    "physical_send_state": "RESPONSE_RECEIVED",
                }
        except urllib.error.HTTPError as error:
            return {"status": "error", "http_status": error.code,
                    "error_type": type(error).__name__,
                    "physical_send_state": "RESPONSE_RECEIVED"}
        except Exception as error:
            return {"status": "error", "error_type": type(error).__name__,
                    "error": redact_text(str(error)),
                    "physical_send_state": self._network_execution.physical_send_state}

    def _read_skill_resource(self, value: dict[str, Any]) -> Mapping[str, Any]:
        name = str(value["skill"])
        root = self._skill_roots.get(name)
        if root is None:
            raise ToolRuntimeError(f"unknown active skill: {name}")
        guard = self._execution_snapshot_guards.get(name)
        if guard is not None:
            guard()
        relative = Path(str(value["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ToolRuntimeError("skill resource path must be relative and cannot contain '..'")
        path = (root / relative).resolve(strict=True)
        try:
            path.relative_to(root.resolve(strict=True))
        except ValueError as exc:
            raise ToolRuntimeError("skill resource escapes its Skill directory") from exc
        content = path.read_text(encoding="utf-8", errors="replace")
        return {
            "status": "ok",
            "skill": name,
            "path": relative.as_posix(),
            "resource_path": str(path),
            "resource_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "content": content,
        }

    @staticmethod
    def _command_handler(
        manifest: PluginManifest,
        command: list[str],
        config: Mapping[str, Any],
        *,
        integrity_guard: Callable[[], None] | None = None,
        cancel_probe: Callable[[], bool] | None = None,
    ) -> ToolHandler:
        def execute(value: dict[str, Any]) -> Any:
            if integrity_guard is not None:
                integrity_guard()
            if cancel_probe is not None and cancel_probe():
                raise ToolRuntimeError("plugin command cancelled before dispatch")
            resolved_command = list(command)
            first = Path(resolved_command[0])
            if not first.is_absolute() and ("/" in resolved_command[0] or resolved_command[0].startswith(".")):
                candidate = (manifest.root / first).resolve(strict=True)
                try:
                    candidate.relative_to(manifest.root.resolve(strict=True))
                except ValueError as exc:
                    raise ToolRuntimeError("plugin command escapes the plugin root") from exc
                resolved_command[0] = str(candidate)
            timeout_raw = config.get("timeout_seconds", 30)
            try:
                timeout = float(timeout_raw)
            except (TypeError, ValueError) as error:
                raise ToolRuntimeError("plugin command timeout is invalid") from error
            if timeout <= 0 or timeout > 30:
                raise ToolRuntimeError("plugin command timeout must be between 0 and 30 seconds")
            result = subprocess.run(
                resolved_command,
                cwd=str(manifest.root),
                env=isolated_env(),
                input=stable_json(value),
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            if cancel_probe is not None and cancel_probe():
                raise ToolRuntimeError("plugin command completed after task cancellation")
            if result.returncode != 0:
                raise ToolRuntimeError(
                    f"plugin command exited {result.returncode}: {redact_text(result.stderr.strip())[-500:]}"
                )
            if bool(config.get("output_json", True)):
                try:
                    return json.loads(result.stdout or "null")
                except json.JSONDecodeError as exc:
                    raise ToolRuntimeError(f"plugin command output is not JSON: {exc}") from exc
            return result.stdout

        return execute

    def _mcp_handler(
        self,
        manifest: PluginManifest,
        server: Mapping[str, Any],
        fixed_tool_name: str | None,
        *,
        integrity_guard: Callable[[], None] | None = None,
    ) -> ToolHandler:
        def execute(value: dict[str, Any]) -> Any:
            if integrity_guard is not None:
                integrity_guard()
            action = "call" if fixed_tool_name else str(value.get("action") or "call")
            tool_name = fixed_tool_name or str(value.get("name") or "")
            arguments = value if fixed_tool_name else dict(value.get("arguments") or {})
            if action not in {"list_tools", "call"}:
                raise ToolRuntimeError("MCP action must be list_tools or call")
            if action == "call" and not tool_name:
                raise ToolRuntimeError("MCP tool name is required")
            transport = str(server.get("transport") or "stdio")
            if transport == "stdio":
                command = server.get("command")
                if not isinstance(command, list) or not command or any(not isinstance(part, str) for part in command):
                    raise ToolRuntimeError("stdio MCP command must be a non-empty string array")
                resolved = list(command)
                first = Path(resolved[0])
                if not first.is_absolute() and ("/" in resolved[0] or resolved[0].startswith(".")):
                    executable = (manifest.root / first).resolve(strict=True)
                    executable.relative_to(manifest.root.resolve(strict=True))
                    resolved[0] = str(executable)
                config = {
                    "_resolved_command": resolved[0],
                    "_resolved_args": resolved[1:],
                    "_resolved_cwd": str(manifest.root),
                    "_resolved_env": dict(server.get("env") or {}),
                    "timeout_seconds": server.get("timeout_seconds", 30),
                }
                with StdioMcpClient(config) as client:
                    if action == "list_tools":
                        return {"tools": client.list_tools()}
                    return client.call_tool(tool_name, arguments)
            if transport in {"http", "streamable_http"}:
                return self._http_mcp_call(
                    str(server.get("url") or ""),
                    tool_name if action == "call" else None,
                    arguments,
                    server,
                )
            raise ToolRuntimeError(f"unsupported MCP transport: {transport}")

        return execute

    def _http_mcp_call(
        self, url: str,
        tool_name: str | None,
        arguments: Mapping[str, Any],
        config: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not url.startswith(("https://", "http://")):
            raise ToolRuntimeError("remote MCP URL must be absolute http(s)")
        headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            **{str(key): str(value) for key, value in dict(config.get("headers") or {}).items()},
        }
        session_id: str | None = None

        def rpc(request_id: int, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
            nonlocal session_id
            request_headers = dict(headers)
            if session_id:
                request_headers["Mcp-Session-Id"] = session_id
            with self._open_authorized_http(
                url,
                data=stable_json({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}).encode(),
                headers=request_headers, method="POST",
                timeout=float(config.get("timeout_seconds", 60)),
            ) as response:
                received_session = response.headers.get("Mcp-Session-Id")
                if received_session:
                    session_id = received_session
                text = response.read().decode("utf-8", errors="replace")
            if text.lstrip().startswith("data:"):
                data_lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
                text = data_lines[-1] if data_lines else "{}"
            payload = json.loads(text)
            if not isinstance(payload, dict) or payload.get("error"):
                raise ToolRuntimeError(f"remote MCP error: {redact_text(stable_json(payload))}")
            result = payload.get("result", {})
            if not isinstance(result, dict):
                raise ToolRuntimeError("remote MCP result must be an object")
            return result

        rpc(
            1,
            "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "sitina", "version": "1"}},
        )
        if tool_name is None:
            return rpc(2, "tools/list", {})
        return rpc(2, "tools/call", {"name": tool_name, "arguments": dict(arguments)})


class HookRunner:
    """Runs declarative subprocess hooks; plugin code is never imported."""

    def __init__(self, catalog: ToolCatalog):
        self.catalog = catalog

    def run(self, event: str, payload: Mapping[str, Any]) -> list[ToolResult]:
        results: list[ToolResult] = []
        if self.catalog.manager.authority_bound:
            return results
        for manifest, record in self.catalog.manager.active_plugins():
            path = manifest.component_path("hooks")
            if not path:
                continue
            raw = read_json_object(path, schema=HOOKS_SCHEMA)
            events = raw.get("events", {})
            if not isinstance(events, dict):
                raise ExtensionSpecError("hook events must be an object")
            hooks = events.get(event, [])
            if not isinstance(hooks, list):
                raise ExtensionSpecError(f"hooks for {event} must be an array")
            granted = set(record.get("granted_permissions", []))
            for index, hook in enumerate(hooks):
                if not isinstance(hook, dict):
                    raise ExtensionSpecError("hook entries must be objects")
                permission = str(hook.get("permission") or "")
                if permission not in granted:
                    continue
                command = hook.get("command")
                if not isinstance(command, list) or not command or any(not isinstance(part, str) for part in command):
                    raise ExtensionSpecError("hook command must be a non-empty string array")
                definition = ToolDefinition(
                    f"hook_{manifest.name}_{event}_{index}",
                    f"Lifecycle hook {manifest.name}:{event}",
                    {"type": "object"},
                    permission,
                    f"plugin:{manifest.name}:hook",
                    ToolCatalog._command_handler(manifest, command, hook),
                )
                self.catalog._authorize(definition, payload)
                started = iso_now()
                try:
                    with authorized_extension_effect(
                        permission=permission,
                        approval_granted=True,
                        purpose=f"hook:{manifest.name}:{event}",
                    ):
                        value = definition.handler(dict(payload))
                    results.append(ToolResult(definition.name, permission, "ok", value, started, iso_now()))
                except Exception as exc:  # noqa: BLE001
                    results.append(
                        ToolResult(
                            definition.name,
                            permission,
                            "error",
                            f"{type(exc).__name__}: {redact_text(str(exc))}",
                            started,
                            iso_now(),
                        )
                    )
        return results
