from __future__ import annotations

import contextlib
import fnmatch
import glob
import json
import os
import re
import subprocess
import time
import urllib.request
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
    read_json_object,
    validate_identifier,
)
from sitina.runners.mcp_adapter import StdioMcpClient, validate_json_schema
from sitina.guards.risk import RiskScanner
from sitina.legacy.fence import authorized_extension_effect
from sitina.security.tool_security import (
    PromptIsolationPolicy,
    ToolAccessPolicy,
    ToolAccessRequest,
    ToolPermissionRule,
)
from sitina.utils import isolated_env, iso_now, redact_text, stable_json


class ToolRuntimeError(RuntimeError):
    pass


class ToolApprovalDenied(ToolRuntimeError):
    pass


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

    def content(self) -> str:
        return PromptIsolationPolicy().wrap_tool_result(
            tool_name=self.tool_name,
            status=self.status,
            value=self.value,
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
    ):
        self.manager = manager
        self.approval_callback = approval_callback
        self.workspace = Path(workspace or manager.sitina_home).expanduser().resolve(strict=False)
        # Optional strong-write engine (ToolExecutor). When present and a run is
        # bound, sitina_write_file uses atomic/before_hash/patch-journal writes
        # instead of whole-file overwrite. Approval is still enforced by
        # _authorize upstream; this only upgrades the write mechanics (M1.1).
        self._write_executor = write_executor
        self._run_id: str | None = None
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
        self._mcp_rules: list[ToolPermissionRule] = []
        self._register_builtins()
        self._register_extensions()
        self._mcp_policy = ToolAccessPolicy(self._mcp_rules)

    def definitions(self) -> list[ToolDefinition]:
        return [self._tools[name] for name in sorted(self._tools)]

    def provider_schemas(self) -> list[dict[str, Any]]:
        return [item.provider_schema() for item in self.definitions()]

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
        self._authorize(definition, payload)
        started_at = iso_now()
        started_monotonic = time.monotonic()
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
            )
        return ToolResult(
            name,
            definition.permission,
            "ok",
            value,
            started_at,
            iso_now(),
            max(0, int((time.monotonic() - started_monotonic) * 1000)),
        )

    def bind_run(self, run_id: str) -> None:
        """Bind the active run_id so strong writes can tag lease/patch journal.
        Called by the runtime at the start of each run()."""
        self._run_id = run_id

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
        if name == "sitina_shell":
            return ("shell", None, str(arguments.get("command") or ""))
        if name == "sitina_http_request":
            return ("web", str(arguments.get("url") or ""), None)
        return None

    def _authorize(self, definition: ToolDefinition, arguments: Mapping[str, Any]) -> None:
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
                raise ToolApprovalDenied(f"risk scanner blocked {definition.name}: {reasons}")
        approval_granted = definition.permission == "read"
        if not approval_granted:
            risk = scan.risk_level if scan is not None else RISK_BY_PERMISSION[definition.permission]
            host_effect = scan is not None and any(
                m.rule_id in _HOST_EFFECT_RULE_IDS for m in scan.matches
            )
            reason = f"tool requires {definition.permission} permission (risk: {risk})"
            if host_effect:
                reason += " — HOST-EFFECT: escapes the worktree, no free rollback"
            request = ApprovalRequest(
                "approval-" + uuid.uuid4().hex,
                definition.name,
                definition.permission,
                risk,
                definition.origin,
                dict(arguments),
                reason,
            )
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
                    f"MCP security policy {decision.disposition} for {definition.name}: {decision.reason}"
                )
            return
        if not approval_granted:
            raise ToolApprovalDenied(
                f"approval denied or unavailable for {definition.name} ({definition.permission})"
            )

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
                lambda value: sorted(glob.glob(os.path.expanduser(str(value["pattern"])), recursive=True)),
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
                "sitina_shell",
                "Run an arbitrary local shell command in a selected directory. Requires per-call shell approval.",
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

    def _register_extensions(self) -> None:
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
        for manifest, record in self.manager.active_plugins():
            granted = set(record.get("granted_permissions", []))
            declared = set(manifest.permissions)
            if not granted <= declared:
                raise ExtensionSpecError(f"plugin {manifest.name} registry grants exceed its manifest")
            self._register_command_tools(manifest, granted)
            self._register_mcp_tools(manifest, granted)

    def _register_command_tools(self, manifest: PluginManifest, granted: set[str]) -> None:
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
            self._add(
                ToolDefinition(
                    public_name,
                    str(item.get("description") or f"Plugin tool {manifest.name}:{local_name}"),
                    schema,
                    permission,
                    f"plugin:{manifest.name}",
                    self._command_handler(manifest, command, item),
                )
            )

    def _register_mcp_tools(self, manifest: PluginManifest, granted: set[str]) -> None:
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
                self._add(
                    ToolDefinition(
                        public_name,
                        str(advertised_tool.get("description") or f"MCP tool {server_name}:{tool_name}"),
                        schema,
                        permission,
                        f"plugin:{manifest.name}:mcp:{server_name}",
                        self._mcp_handler(manifest, server, None if generic else tool_name),
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
        for current, dirs, files in os.walk(root):
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

    def _write_file(self, value: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(value["path"])).expanduser().resolve(strict=False)
        content = str(value["content"])
        append = bool(value.get("append"))
        # Strong write path (M1.1): atomic replace + before_hash + PathLease +
        # patch journal via ToolExecutor.write_direct. Only for full overwrite;
        # append has no atomic-replace semantics so it keeps the plain path.
        if self._write_executor is not None and self._run_id is not None and not append:
            if path.exists() and not path.is_file():
                raise ToolRuntimeError(f"write target is not a regular file: {path}")
            result = self._write_executor.write_direct(
                target=str(path),
                content=content,
                run_id=self._run_id,
            )
            if result.get("status") != "ok":
                raise ToolRuntimeError(
                    f"strong write failed ({result.get('status')}): {result.get('reason')}"
                )
            return {
                "path": str(path),
                "bytes": len(content.encode("utf-8")),
                "append": False,
                "patch_id": result.get("patch_id"),
                "before_hash": result.get("before_hash"),
                "after_hash": result.get("after_hash"),
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
                target=str(path), content=updated, run_id=self._run_id
            )
            if result.get("status") != "ok":
                raise ToolRuntimeError(
                    f"strong write failed ({result.get('status')}): {result.get('reason')}"
                )
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

    def _shell(self, value: dict[str, Any]) -> dict[str, Any]:
        cwd = Path(str(value.get("cwd") or self.workspace)).expanduser().resolve(strict=True)
        timeout = float(value["timeout_seconds"]) if value.get("timeout_seconds") is not None else None
        result = subprocess.run(
            str(value["command"]),
            shell=True,
            cwd=str(cwd),
            env=isolated_env(),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": redact_text(result.stderr)}

    @staticmethod
    def _http(value: dict[str, Any]) -> dict[str, Any]:
        headers = {str(key): str(item) for key, item in dict(value.get("headers") or {}).items()}
        body = str(value.get("body") or "").encode("utf-8") if "body" in value else None
        request = urllib.request.Request(
            str(value["url"]),
            data=body,
            headers=headers,
            method=str(value.get("method") or "GET").upper(),
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
            return {
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body": data.decode("utf-8", errors="replace"),
            }

    def _read_skill_resource(self, value: dict[str, Any]) -> str:
        name = str(value["skill"])
        root = self._skill_roots.get(name)
        if root is None:
            raise ToolRuntimeError(f"unknown active skill: {name}")
        relative = Path(str(value["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ToolRuntimeError("skill resource path must be relative and cannot contain '..'")
        path = (root / relative).resolve(strict=True)
        try:
            path.relative_to(root.resolve(strict=True))
        except ValueError as exc:
            raise ToolRuntimeError("skill resource escapes its Skill directory") from exc
        return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _command_handler(
        manifest: PluginManifest,
        command: list[str],
        config: Mapping[str, Any],
    ) -> ToolHandler:
        def execute(value: dict[str, Any]) -> Any:
            resolved_command = list(command)
            first = Path(resolved_command[0])
            if not first.is_absolute() and ("/" in resolved_command[0] or resolved_command[0].startswith(".")):
                candidate = (manifest.root / first).resolve(strict=True)
                try:
                    candidate.relative_to(manifest.root.resolve(strict=True))
                except ValueError as exc:
                    raise ToolRuntimeError("plugin command escapes the plugin root") from exc
                resolved_command[0] = str(candidate)
            timeout_raw = config.get("timeout_seconds")
            timeout = float(timeout_raw) if timeout_raw is not None else None
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
    ) -> ToolHandler:
        def execute(value: dict[str, Any]) -> Any:
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

    @staticmethod
    def _http_mcp_call(
        url: str,
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
            request = urllib.request.Request(
                url,
                data=stable_json({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}).encode(),
                headers=request_headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=float(config.get("timeout_seconds", 60))) as response:
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
