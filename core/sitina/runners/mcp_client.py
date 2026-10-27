"""Task-scoped MCP connections shared by native extension consumers."""
from __future__ import annotations

import atexit
import contextlib
import hashlib
import json
import os
import select
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Mapping

from sitina.utils import isolated_env, redact_text, stable_json

PROTOCOL_VERSION = "2025-06-18"
MAX_MESSAGE_BYTES = 16 * 1024 * 1024


class McpRuntimeError(RuntimeError):
    def __init__(self, message: str, *, effect_dispatched: bool | None = None):
        super().__init__(message)
        self.effect_dispatched = effect_dispatched


class McpInitializationError(McpRuntimeError):
    """Raised only around the local client initialization boundary.

No tools/call is sent before __enter__ returns. An error string returned by
tools/call, including one saying 'initialize', cannot create this evidence.
"""
    def __init__(self, message: str):
        super().__init__(message, effect_dispatched=False)

    def failure_context(self) -> dict[str, Any]:
        return {"schema": "SITINA_MCP_FAILURE_CONTEXT_V1", "phase": "session_initialization",
                "business_method_sent": False, "shared_initialization_failed": True}


def keychain_reference(reference: Mapping[str, Any] | None) -> str:
    if reference is None:
        return "anonymous"
    if (not isinstance(reference, Mapping)
            or set(reference) != {"service", "account"}
            or not all(isinstance(reference.get(k), str) and reference[k]
                       and "\x00" not in reference[k] for k in ("service", "account"))
            or not reference["service"].startswith("sitina.mcp.")):
        raise McpRuntimeError("MCP credentials require a bound sitina.mcp Keychain service and account")
    return "keychain:" + stable_json(dict(reference))


def read_keychain_credential(reference: Mapping[str, Any]) -> str:
    keychain_reference(reference)
    try:
        result = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", reference["service"],
             "-a", reference["account"], "-w"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise McpRuntimeError("Keychain access needs system authorization; no MCP call was sent",
                              effect_dispatched=False) from error
    if result.returncode:
        raise McpRuntimeError("The bound MCP credential is unavailable in the login Keychain",
                              effect_dispatched=False)
    value = result.stdout.decode("utf-8").rstrip("\r\n")
    if not value or "\r" in value or "\n" in value:
        raise McpRuntimeError("The bound MCP credential is empty or malformed")
    return value


def credential_environment(config: Mapping[str, Any]) -> tuple[dict[str, str], list[str]]:
    env = {str(k): str(v) for k, v in dict(config.get("env") or {}).items()}
    secrets = []
    for name, reference in dict(config.get("env_credentials") or {}).items():
        if not isinstance(name, str) or not name or "=" in name or "\x00" in name:
            raise McpRuntimeError("MCP credential environment name is invalid")
        if name in env:
            raise McpRuntimeError("MCP credential environment conflicts with a literal value")
        secret = read_keychain_credential(reference)
        env[name] = secret
        secrets.append(secret)
    return env, secrets


def validate_mcp_result(action: str, value: Any) -> None:
    if not isinstance(value, Mapping) or value.get("isError") is True:
        raise McpRuntimeError("MCP tool did not return a successful result")
    if action == "list_tools":
        tools = value.get("tools")
        if not isinstance(tools, list) or any(
            not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str)
            or not isinstance(tool.get("inputSchema"), Mapping) for tool in tools
        ):
            raise McpRuntimeError("MCP tools/list result has an invalid schema")
    elif action == "call":
        if not isinstance(value.get("content"), list) and not isinstance(value.get("structuredContent"), Mapping):
            raise McpRuntimeError("MCP tools/call result has no valid content")
    else:
        raise McpRuntimeError("Unknown MCP result action")


class _JsonRpcClient:
    def __init__(self, config: Mapping[str, Any], *, timeout_seconds: float = 30):
        self.config = dict(config)
        self.timeout_seconds = float(config.get("timeout_seconds", timeout_seconds))
        if not 0 < self.timeout_seconds <= 600:
            raise McpRuntimeError("MCP timeout must be between zero and 600 seconds")
        self.lock = threading.RLock()
        self.next_id = 1
        self.protocol_version = PROTOCOL_VERSION
        self.secrets = list(config.get("_secrets") or ())

    def _clean(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, list):
            return [self._clean(item) for item in value]
        if isinstance(value, dict):
            return {key: self._clean(item) for key, item in value.items()}
        return value

    def _initialize(self) -> None:
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "sitina", "version": "1"},
        })
        version = result.get("protocolVersion")
        if not isinstance(version, str) or not version:
            raise McpRuntimeError("MCP initialize did not negotiate a protocol version")
        self.protocol_version = version
        self._notify("notifications/initialized", {})

    def list_tools(self) -> list[dict[str, Any]]:
        tools, cursor, seen = [], None, set()
        for _ in range(100):
            result = self._request("tools/list", {"cursor": cursor} if cursor else {})
            page = result.get("tools")
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise McpRuntimeError("MCP tools/list returned invalid tools")
            tools.extend(page)
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
            if not isinstance(cursor, str) or cursor in seen:
                raise McpRuntimeError("MCP tool pagination cursor is invalid")
            seen.add(cursor)
        raise McpRuntimeError("MCP tool pagination exceeded its limit")

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._request("tools/call", {"name": name, "arguments": arguments})

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            request_id = self.next_id
            self.next_id += 1
            response = self._exchange({"jsonrpc": "2.0", "id": request_id,
                                       "method": method, "params": params}, request_id)
            if response.get("error") is not None:
                detail = self._clean(response["error"])
                raise McpRuntimeError("MCP " + method + " error: " + redact_text(stable_json(detail)))
            result = response.get("result")
            if not isinstance(result, dict):
                raise McpRuntimeError("MCP " + method + " returned a non-object result")
            return self._clean(result)

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._exchange({"jsonrpc": "2.0", "method": method, "params": params}, None)

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class StdioMcpClient(_JsonRpcClient):
    def __init__(self, server: dict[str, Any], *, timeout_seconds: float = 10):
        super().__init__(server, timeout_seconds=timeout_seconds)
        self.server = self.config
        self.proc = None
        self._buffer = b""
        self._stderr = None

    def __enter__(self) -> "StdioMcpClient":
        command = self.server.get("_resolved_command")
        if not isinstance(command, str) or not os.path.isabs(command):
            raise McpRuntimeError("stdio MCP requires a resolved absolute executable")
        env = isolated_env()
        env.update({str(k): str(v) for k, v in dict(self.server.get("_resolved_env") or {}).items()})
        self._stderr = tempfile.TemporaryFile()
        try:
            self.proc = subprocess.Popen(
                [command, *self.server.get("_resolved_args", [])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._stderr,
                cwd=self.server.get("_resolved_cwd"), env=env,
            )
            self._initialize()
        except Exception:
            self.close()
            raise
        return self

    def _write(self, payload: dict[str, Any]) -> None:
        if self.proc is None or self.proc.stdin is None or self.proc.poll() is not None:
            raise McpRuntimeError("MCP process is not running; the call was not replayed")
        self.proc.stdin.write((stable_json(payload) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def _exchange(self, payload: dict[str, Any], request_id: int | None) -> dict[str, Any]:
        self._write(payload)
        if request_id is None:
            return {}
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            while b"\n" in self._buffer:
                line, self._buffer = self._buffer.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    response = json.loads(line)
                except (ValueError, UnicodeError) as error:
                    raise McpRuntimeError("MCP server emitted invalid UTF-8 JSON") from error
                if not isinstance(response, dict):
                    raise McpRuntimeError("MCP server emitted a non-object message")
                if response.get("id") == request_id:
                    return response
            if self.proc is None or self.proc.stdout is None:
                raise McpRuntimeError("MCP session was closed; the call was not replayed")
            ready, _, _ = select.select([self.proc.stdout], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise McpRuntimeError("MCP process closed its output; the call was not replayed")
            self._buffer += chunk
            if len(self._buffer) > MAX_MESSAGE_BYTES:
                raise McpRuntimeError("MCP response exceeded the message limit")
        raise McpRuntimeError("MCP request timed out; its outcome is unknown and it was not replayed")

    def close(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    stream.close()
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    _close_process = close


class HttpMcpClient(_JsonRpcClient):
    def __init__(self, config: Mapping[str, Any], opener: Callable[..., Any]):
        super().__init__(config, timeout_seconds=60)
        self.opener = opener
        self.session_id = None

    def __enter__(self) -> "HttpMcpClient":
        self._initialize()
        return self

    def _exchange(self, payload: dict[str, Any], request_id: int | None) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   **dict(self.config.get("headers") or {})}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if payload["method"] != "initialize":
            headers["MCP-Protocol-Version"] = self.protocol_version
        with self.opener(str(self.config["url"]), data=stable_json(payload).encode("utf-8"),
                         headers=headers, method="POST", timeout=self.timeout_seconds) as response:
            received = response.headers.get("Mcp-Session-Id")
            if received:
                self.session_id = received
            if request_id is None:
                return {}
            if "text/event-stream" in response.headers.get("Content-Type", "").lower():
                data, total = [], 0
                for raw in response:
                    total += len(raw)
                    if total > MAX_MESSAGE_BYTES:
                        raise McpRuntimeError("MCP event stream exceeded the message limit")
                    line = raw.decode("utf-8").rstrip("\r\n")
                    if line.startswith("data:"):
                        data.append(line[5:].lstrip())
                    elif line == "" and data:
                        message = json.loads("\n".join(data))
                        data = []
                        if isinstance(message, dict) and message.get("id") == request_id:
                            return message
                if data:
                    message = json.loads("\n".join(data))
                    if isinstance(message, dict) and message.get("id") == request_id:
                        return message
                raise McpRuntimeError("MCP event stream ended without the requested result")
            raw = response.read(MAX_MESSAGE_BYTES + 1)
            if len(raw) > MAX_MESSAGE_BYTES:
                raise McpRuntimeError("MCP response exceeded the message limit")
            message = json.loads(raw)
            if not isinstance(message, dict) or message.get("id") != request_id:
                raise McpRuntimeError("MCP response has an invalid request identity")
            return message

    def close(self) -> None:
        self.session_id = None


_sessions: dict[tuple[str, str], _JsonRpcClient] = {}
_sessions_lock = threading.RLock()


@contextlib.contextmanager
def mcp_session(scope: str, identity: str, config: Mapping[str, Any], *,
                opener: Callable[..., Any] | None = None):
    key = (scope, identity)
    with _sessions_lock:
        client = _sessions.get(key)
        if client is None:
            if len(_sessions) >= 128:
                raise McpRuntimeError("MCP session limit reached; close a completed task")
            client = HttpMcpClient(config, opener) if opener is not None else StdioMcpClient(dict(config))
            try:
                client.__enter__()
            except Exception as error:
                # This is locally observed setup, not a tools/call error.
                client.close()
                raise McpInitializationError(redact_text(str(error))) from error
            _sessions[key] = client
    with client.lock:
        if isinstance(client, HttpMcpClient):
            client.opener = opener
        yield client


def close_mcp_scope(scope: str | None = None, *, home: str | None = None) -> None:
    with _sessions_lock:
        keys = [key for key in _sessions if (scope is None or key[0] == scope)
                and (home is None or key[0].startswith(str(home) + ":"))]
        clients = [_sessions.pop(key) for key in keys]
    for client in clients:
        with client.lock:
            client.close()


atexit.register(close_mcp_scope)
