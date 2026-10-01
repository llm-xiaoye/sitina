from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.guards.evidence import ArtifactRegistry
from sitina.guards.risk import RiskScanner
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, isolated_env, is_secret_name, load_json_yaml, redact_text, sha256_text, stable_json


SUPPORTED_TRANSPORTS = {"stdio"}
RISK_POLICIES = {"local_readonly_default", "approval_required_for_mutation", "disabled_remote_placeholder"}
MUTATION_MARKERS = ("write", "delete", "move", "overwrite")


class McpRuntimeError(RuntimeError):
    pass


class McpSchemaError(ValueError):
    pass


class StdioMcpClient:
    def __init__(self, server: dict[str, Any], *, timeout_seconds: float = 10.0):
        self.server = server
        self.timeout_seconds = float(server.get("timeout_seconds", timeout_seconds))
        self.proc: subprocess.Popen[str] | None = None
        self.next_id = 1

    def __enter__(self) -> "StdioMcpClient":
        command = self.server.get("_resolved_command")
        args = list(self.server.get("_resolved_args", []))
        if not command:
            raise McpRuntimeError("stdio MCP server missing command")
        env = isolated_env()
        env.update({str(k): str(v) for k, v in self.server.get("_resolved_env", {}).items()})
        cwd = self.server.get("_resolved_cwd")
        try:
            self.proc = subprocess.Popen(
                [str(command), *[str(arg) for arg in args]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
        except OSError as exc:
            raise McpRuntimeError(f"MCP server failed to start: {exc}") from exc
        try:
            self._request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "sitina", "version": "1.0"},
                },
            )
            self._notify("notifications/initialized", {})
        except Exception:
            self._close_process()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._close_process()

    def _close_process(self) -> None:
        if not self.proc:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream:
                stream.close()
        self.proc = None

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._request("tools/list", {})
        tools = result.get("tools", [])
        if not isinstance(tools, list):
            raise McpRuntimeError("MCP tools/list returned invalid tools")
        return [tool for tool in tools if isinstance(tool, dict)]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._request("tools/call", {"name": name, "arguments": arguments})

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline:
            response = self._read_line(deadline - time.time())
            if response is None:
                continue
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise McpRuntimeError(f"MCP {method} error: {redact_text(stable_json(response['error']))}")
            result = response.get("result", {})
            if not isinstance(result, dict):
                raise McpRuntimeError(f"MCP {method} returned non-object result")
            return result
        raise McpRuntimeError(f"MCP {method} timed out")

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _write(self, payload: dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            raise McpRuntimeError("MCP process is not running")
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        self.proc.stdin.flush()

    def _read_line(self, timeout_seconds: float) -> dict[str, Any] | None:
        if not self.proc or not self.proc.stdout:
            raise McpRuntimeError("MCP process is not running")
        if self.proc.poll() is not None:
            stderr = self.proc.stderr.read() if self.proc.stderr else ""
            raise McpRuntimeError(f"MCP process exited early: {redact_text(stderr)[-500:]}")
        ready, _, _ = select.select([self.proc.stdout], [], [], max(timeout_seconds, 0.0))
        if not ready:
            return None
        line = self.proc.stdout.readline()
        if not line:
            return None
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise McpRuntimeError(f"MCP server emitted malformed JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise McpRuntimeError("MCP server emitted non-object JSON")
        return value


class McpAdapter:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.risk = RiskScanner(home)
        from sitina.effects.legacy_adapters import ShadowEffectBridge
        self.effect_shadow = ShadowEffectBridge.from_environment()

    def effect_shadow_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        from sitina.effects.legacy_adapters import LegacyAdapterKind
        return self.effect_shadow.identity(LegacyAdapterKind.MCP, payload)

    def list_registry(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for name, server in sorted(self._load_servers().items()):
            _, _, resolved = self._validate_server(name, server)
            filesystem_policy = resolved.get("_filesystem_policy")
            rows.append(
                {
                    "name": name,
                    "enabled": bool(server.get("enabled", False)),
                    "transport": server.get("transport"),
                    "allowed_tools": sorted(self._allowed_tools(server).keys()),
                    "risk_policy": server.get("risk_policy"),
                    "description": server.get("description", ""),
                    **({"filesystem": filesystem_policy} if filesystem_policy else {}),
                }
            )
        return rows

    def validate_registry(self) -> dict[str, Any]:
        servers = self._load_servers()
        items: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        blocked = 0
        for name, server in sorted(servers.items()):
            item_errors, item_warnings, resolved = self._validate_server(name, server)
            status = "ok" if server.get("enabled") and not item_errors else "blocked"
            if status == "blocked":
                blocked += 1
            errors.extend(item_errors)
            warnings.extend(item_warnings)
            item = {
                "name": name,
                "enabled": bool(server.get("enabled", False)),
                "transport": server.get("transport"),
                "status": status,
                "allowed_tools": sorted(self._allowed_tools(server).keys()),
                "errors": item_errors,
                "warnings": item_warnings,
                "command": resolved.get("_resolved_command"),
            }
            if resolved.get("_filesystem_policy"):
                item["filesystem"] = resolved["_filesystem_policy"]
            items.append(item)
        return {"ok": not errors, "checked": len(items), "blocked": blocked, "warnings": warnings, "errors": errors, "items": items}

    def invoke(
        self,
        server_name: str,
        tool_name: str | None = None,
        payload: dict[str, Any] | None = None,
        *,
        approval_id: str | None = None,
        run_id: str = "mcp_manual",
        mock: bool = False,
    ) -> dict[str, Any]:
        payload = payload or {}
        if self.effect_shadow.enabled:
            return {"status": "shadowed", **self.effect_shadow_identity({"server_name": server_name, "tool_name": tool_name, "payload": payload, "run_id": run_id}), "physical_send_count": 0}
        if mock:
            return self._mock_result(server_name, tool_name, payload, run_id)
        if tool_name is None:
            return self._blocked_without_scan(server_name, run_id, "MCP tool name required")
        servers = self._load_servers()
        server = servers.get(server_name)
        if not server:
            return self._blocked_without_scan(server_name, run_id, "MCP registry item not found", tool_name=tool_name)
        if server.get("enabled") is False:
            return self._blocked_without_scan(server_name, run_id, "MCP registry item disabled", tool_name=tool_name)

        allowed_tools = self._allowed_tools(server)
        tool_policy = allowed_tools.get(tool_name)
        if not tool_policy:
            return self._blocked_without_scan(server_name, run_id, "MCP tool not in allowlist", tool_name=tool_name)
        tool_type = tool_policy.get("type", "read_only")
        operation = "mcp_write" if tool_type in {"write", "external_network", "secret_sensitive"} or self._is_mutation_tool(tool_name) else "mcp_read"
        scan = self.risk.scan(operation, target=f"{server_name}.{tool_name}", tool_type=tool_type)
        self.store.insert_risk_scan(scan.model_dump(), run_id=run_id)
        approval_required = scan.approval_required and tool_policy.get("approval", True) is not False
        if scan.action == "block" or (approval_required and not approval_id):
            self.store.record_audit(
                "mcp_blocked",
                {"server": server_name, "tool": tool_name, "tool_type": tool_type, "reason": "risk/approval gate"},
                run_id=run_id,
                risk_scan_id=scan.risk_scan_id,
                approval_id=approval_id,
                exit_status="blocked",
            )
            return {"status": "blocked", "reason": "MCP risk/approval gate", "server": server_name, "tool": tool_name, "risk_scan": scan.model_dump()}

        item_errors, item_warnings, resolved = self._validate_server(server_name, server)
        if item_errors:
            return self._runtime_blocked(server_name, tool_name, run_id, scan, approval_id, "; ".join(item_errors), warnings=item_warnings)

        try:
            with StdioMcpClient(resolved) as client:
                tool_def = self._resolve_tool_def(client.list_tools(), tool_name)
                input_schema = tool_policy.get("input_schema") or tool_def.get("inputSchema") or {}
                validate_json_schema(payload, input_schema)
                result = client.call_tool(tool_name, payload)
        except (McpRuntimeError, McpSchemaError) as exc:
            self.store.record_audit(
                "mcp_runtime_error",
                {"server": server_name, "tool": tool_name, "reason": str(exc), "payload_keys": sorted(payload.keys())},
                run_id=run_id,
                risk_scan_id=scan.risk_scan_id,
                approval_id=approval_id,
                exit_status="blocked",
            )
            return {"status": "blocked", "reason": str(exc), "server": server_name, "tool": tool_name, "risk_scan": scan.model_dump()}

        if result.get("isError") is True:
            artifact_hash = self._bind_result(run_id, server_name, tool_name, payload, result)
            self.store.record_audit(
                "mcp_tool_error",
                {"server": server_name, "tool": tool_name, "artifact_hash": artifact_hash},
                run_id=run_id,
                risk_scan_id=scan.risk_scan_id,
                approval_id=approval_id,
                artifact_hash=artifact_hash,
                exit_status="error",
            )
            return {"status": "error", "reason": "MCP tool returned error", "server": server_name, "tool": tool_name, "result": result, "artifact_hash": artifact_hash, "risk_scan": scan.model_dump()}

        artifact_hash = self._bind_result(run_id, server_name, tool_name, payload, result)
        top_status = self._top_status_from_tool_result(result)
        self.store.record_audit(
            "mcp_tool_call",
            {"server": server_name, "tool": tool_name, "tool_type": tool_type, "payload_keys": sorted(payload.keys()), "artifact_hash": artifact_hash},
            run_id=run_id,
            risk_scan_id=scan.risk_scan_id,
            approval_id=approval_id,
            artifact_hash=artifact_hash,
            exit_status=top_status,
        )
        return {"status": top_status, "server": server_name, "tool": tool_name, "result": result, "artifact_hash": artifact_hash, "risk_scan": scan.model_dump()}

    def _load_servers(self) -> dict[str, Any]:
        path = self.home / "config" / "mcp" / "servers.yaml"
        if not path.exists():
            return {}
        data = load_json_yaml(path)
        return dict(data.get("servers", {}))

    def _allowed_tools(self, server: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw = server.get("allowed_tools") or server.get("allowlist") or {}
        if isinstance(raw, list):
            return {str(item): {"type": "read_only", "approval": False} for item in raw}
        if isinstance(raw, dict):
            return {str(name): (policy if isinstance(policy, dict) else {"type": "read_only", "approval": False}) for name, policy in raw.items()}
        return {}

    def _validate_server(self, name: str, server: dict[str, Any]) -> tuple[list[str], list[str], dict[str, Any]]:
        errors: list[str] = []
        warnings: list[str] = []
        resolved = dict(server)
        enabled = bool(server.get("enabled", False))
        if not server.get("name"):
            errors.append(f"{name}: name missing")
        transport = server.get("transport")
        if enabled and not transport:
            errors.append(f"{name}: transport missing")
        if enabled and transport not in SUPPORTED_TRANSPORTS:
            errors.append(f"{name}: only local stdio MCP transport is supported")
        command = server.get("command")
        if enabled and not command:
            errors.append(f"{name}: command missing")
        elif command:
            resolved_command = self._resolve_command(str(command))
            if not resolved_command:
                errors.append(f"{name}: command not executable")
            else:
                resolved["_resolved_command"] = resolved_command
        cwd = self._expand_path(str(server.get("cwd") or self.home))
        resolved["_resolved_cwd"] = str(cwd)
        args: list[str] = []
        for raw_arg in server.get("args", []):
            arg = self._expand_value(str(raw_arg))
            if self._looks_like_local_server_path(arg):
                arg_path = Path(arg)
                if not arg_path.is_absolute():
                    arg_path = cwd / arg_path
                if not arg_path.exists():
                    errors.append(f"{name}: server file missing: {arg}")
                arg = str(arg_path)
            args.append(arg)
        if enabled and not args:
            errors.append(f"{name}: args missing")
        resolved["_resolved_args"] = args
        raw_env = server.get("env") or {}
        env: dict[str, str] = {}
        for key, value in raw_env.items():
            if is_secret_name(str(key)):
                warnings.append(f"{name}: env contains suspicious secret-like key {key}")
            env[str(key)] = self._expand_value(str(value))
        if name == "filesystem":
            policy, policy_warnings, policy_errors = self._resolve_filesystem_policy(server, env)
            warnings.extend(policy_warnings)
            errors.extend(policy_errors)
            env.update(policy["_env"])
            resolved["_filesystem_policy"] = {key: value for key, value in policy.items() if key != "_env"}
        resolved["_resolved_env"] = env
        allowed_tools = self._allowed_tools(server)
        if enabled and not allowed_tools:
            errors.append(f"{name}: allowlist/allowed_tools is empty")
        if name == "filesystem":
            for tool_name, policy in allowed_tools.items():
                if self._is_mutation_tool(tool_name) and policy.get("approval") is False:
                    errors.append(f"{name}: mutation tool {tool_name} must require approval")
        timeout = server.get("timeout_seconds")
        if enabled and (not isinstance(timeout, (int, float)) or float(timeout) <= 0 or float(timeout) > 120):
            errors.append(f"{name}: timeout_seconds must be between 1 and 120")
        if enabled and server.get("risk_policy") not in RISK_POLICIES:
            errors.append(f"{name}: risk_policy missing or unknown")
        return errors, warnings, resolved

    def _resolve_command(self, command: str) -> str | None:
        expanded = self._expand_value(command)
        if "/" in expanded:
            path = Path(expanded).expanduser()
            return str(path) if path.exists() and os.access(path, os.X_OK) else None
        return shutil.which(expanded)

    def _expand_path(self, value: str) -> Path:
        return Path(self._expand_value(value)).expanduser().resolve(strict=False)

    def _expand_value(self, value: str) -> str:
        user_home = str(Path.home())
        return (
            value.replace("${SITINA_ROOT}", str(self.home))
            .replace("$SITINA_ROOT", str(self.home))
            .replace("${USER_HOME}", user_home)
            .replace("$USER_HOME", user_home)
            .replace("${HOME}", user_home)
            .replace("$HOME", user_home)
        )

    def _resolve_filesystem_policy(self, server: dict[str, Any], env: dict[str, str]) -> tuple[dict[str, Any], list[str], list[str]]:
        warnings: list[str] = []
        errors: list[str] = []
        env_override = os.environ.get("SITINA_ALLOWED_ROOTS")
        if env_override:
            raw_roots = [item for item in env_override.split(os.pathsep) if item]
            source = "environment:SITINA_ALLOWED_ROOTS"
        elif server.get("allowed_roots"):
            raw_roots = [str(item) for item in server.get("allowed_roots", [])]
            source = "config:servers.filesystem.allowed_roots"
        elif env.get("SITINA_ALLOWED_ROOTS"):
            raw_roots = [item for item in env["SITINA_ALLOWED_ROOTS"].split(os.pathsep) if item]
            source = "config:servers.filesystem.env.SITINA_ALLOWED_ROOTS"
        else:
            raw_roots = [str(self.home)]
            source = "default:SITINA_ROOT"

        roots: list[Path] = []
        for raw_root in raw_roots:
            root = Path(self._expand_value(raw_root)).expanduser().resolve(strict=False)
            roots.append(root)
            if str(root) == os.sep:
                errors.append("filesystem: allowed root / is not permitted")
            elif not root.exists():
                warnings.append(f"filesystem: allowed root does not exist: {root}")

        allow_system_roots = bool(server.get("allow_system_roots", False))
        blocked_system_roots = ["/System", "/Library", "/Applications", "/private", "/etc", "/var", "/usr", "/bin", "/sbin"]
        for root in roots:
            if any(self._path_is_relative_to(root, Path(system_root)) for system_root in blocked_system_roots) and not allow_system_roots:
                warnings.append(f"filesystem: system root is configured but remains blocked by default: {root}")

        default_mode = str(server.get("default_mode", "readonly"))
        if default_mode != "readonly":
            errors.append("filesystem: default_mode must remain readonly")
        write_requires_approval = bool(server.get("write_requires_approval", True))
        if not write_requires_approval:
            errors.append("filesystem: write_requires_approval must be true")
        sensitive_enabled = bool(server.get("sensitive_path_protection", True))
        if not sensitive_enabled:
            errors.append("filesystem: sensitive_path_protection must be enabled")

        allowed_roots_env = os.pathsep.join(str(root) for root in roots)
        policy = {
            "allowed_roots": [str(root) for root in roots],
            "allowed_roots_source": source,
            "default_mode": default_mode,
            "write_requires_approval": write_requires_approval,
            "sensitive_path_protection": sensitive_enabled,
            "system_roots_blocked_by_default": not allow_system_roots,
            "readonly_tools": ["list_dir", "read_file", "stat_path"],
            "_env": {
                "SITINA_ALLOWED_ROOTS": allowed_roots_env,
                "SITINA_FILESYSTEM_DEFAULT_MODE": default_mode,
                "SITINA_WRITE_REQUIRES_APPROVAL": "1" if write_requires_approval else "0",
                "SITINA_SENSITIVE_PATH_PROTECTION": "1" if sensitive_enabled else "0",
                "SITINA_ALLOW_SYSTEM_ROOTS": "1" if allow_system_roots else "0",
            },
        }
        return policy, warnings, errors

    def _path_is_relative_to(self, path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _looks_like_local_server_path(self, arg: str) -> bool:
        return arg.endswith(".py") or arg.endswith(".js") or arg.endswith(".mjs")

    def _is_mutation_tool(self, tool_name: str) -> bool:
        lowered = tool_name.lower()
        return any(marker in lowered for marker in MUTATION_MARKERS)

    def _resolve_tool_def(self, tools: list[dict[str, Any]], tool_name: str) -> dict[str, Any]:
        for tool in tools:
            if tool.get("name") == tool_name:
                return tool
        raise McpRuntimeError(f"MCP tool not found in tools/list: {tool_name}")

    def _top_status_from_tool_result(self, result: dict[str, Any]) -> str:
        content = result.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and isinstance(first.get("json"), dict):
                status = first["json"].get("status")
                if isinstance(status, str) and status != "ok":
                    return status
        return "ok"

    def _runtime_blocked(
        self,
        server_name: str,
        tool_name: str,
        run_id: str,
        scan,
        approval_id: str | None,
        reason: str,
        *,
        warnings: list[str] | None = None,
    ) -> dict[str, Any]:
        self.store.record_audit(
            "mcp_runtime_blocked",
            {"server": server_name, "tool": tool_name, "reason": reason, "warnings": warnings or []},
            run_id=run_id,
            risk_scan_id=scan.risk_scan_id,
            approval_id=approval_id,
            exit_status="blocked",
        )
        return {"status": "blocked", "reason": reason, "server": server_name, "tool": tool_name, "warnings": warnings or [], "risk_scan": scan.model_dump()}

    def _blocked_without_scan(self, server_name: str, run_id: str, reason: str, *, tool_name: str | None = None) -> dict[str, Any]:
        self.store.record_audit("mcp_blocked", {"server": server_name, "tool": tool_name, "reason": reason}, run_id=run_id, exit_status="blocked")
        return {"status": "blocked", "reason": reason, "server": server_name, "tool": tool_name}

    def _mock_result(self, server_name: str, tool_name: str | None, payload: dict[str, Any], run_id: str) -> dict[str, Any]:
        self.store.record_audit("mcp_mock_tool_call", {"server": server_name, "tool": tool_name, "payload_keys": sorted(payload.keys()), "mode": "mock"}, run_id=run_id, exit_status="mock")
        return {"status": "mock", "mode": "mock", "server": server_name, "tool": tool_name, "result": {"mock": True, "payload": payload}}

    def _bind_result(self, run_id: str, server_name: str, tool_name: str, payload: dict[str, Any], result: dict[str, Any]) -> str:
        out_dir = self.home / "artifacts" / "mcp_results" / run_id
        ensure_dir(out_dir)
        digest = sha256_text(stable_json({"server": server_name, "tool": tool_name, "payload": payload, "result": result})).split(":", 1)[1]
        out_path = out_dir / f"{server_name}-{tool_name}-{digest[:16]}.json"
        out_path.write_text(
            json.dumps({"server": server_name, "tool": tool_name, "payload": payload, "result": result}, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        record = ArtifactRegistry(self.home, self.store).register_command_output(
            run_id=run_id,
            turn_id=f"{run_id}:mcp:{server_name}.{tool_name}",
            producing_agent="researcher",
            command=f"mcp {server_name}.{tool_name}",
            cwd=str(self.home),
            artifact_path=str(out_path),
        )
        return record.artifact_hash


def validate_json_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    if not schema:
        if not isinstance(value, dict):
            raise McpSchemaError(f"{path} must be an object")
        return
    expected_type = schema.get("type")
    if expected_type:
        _validate_type(value, expected_type, path)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise McpSchemaError(f"{path} must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise McpSchemaError(f"{path} must be at most {schema['maximum']}")
    if expected_type == "object" or "properties" in schema:
        if not isinstance(value, dict):
            raise McpSchemaError(f"{path} must be an object")
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise McpSchemaError(f"{path}.{key} is required")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                validate_json_schema(item, properties[key], f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                raise McpSchemaError(f"{path}.{key} is not allowed")
        return
    if expected_type == "array" and isinstance(value, list) and isinstance(schema.get("items"), dict):
        for idx, item in enumerate(value):
            validate_json_schema(item, schema["items"], f"{path}[{idx}]")


def _validate_type(value: Any, expected_type: str | list[str], path: str) -> None:
    expected = expected_type if isinstance(expected_type, list) else [expected_type]
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }
    if not any(checks.get(item, lambda _v: True)(value) for item in expected):
        raise McpSchemaError(f"{path} must be one of {expected}")
