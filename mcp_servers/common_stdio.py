from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def allowed_roots() -> list[Path]:
    raw = os.environ.get("SITINA_ALLOWED_ROOTS") or os.environ.get("SITINA_ROOT") or os.getcwd()
    return [Path(item).expanduser().resolve(strict=False) for item in raw.split(os.pathsep) if item]


def path_in_allowed_roots(path: Path) -> bool:
    resolved = path.expanduser().resolve(strict=False)
    for root in allowed_roots():
        if _is_relative_to(resolved, root):
            return True
    return False


def require_allowed_path(raw_path: str, *, operation: str = "read") -> Path:
    path = Path(raw_path).expanduser().resolve(strict=False)
    if not path_in_allowed_roots(path):
        raise ValueError("blocked: path outside allowed roots")
    sensitive_reason = sensitive_path_reason(path, operation=operation)
    if sensitive_reason:
        raise ValueError(f"blocked: {sensitive_reason}")
    return path


def checked_allowed_path(raw_path: str, *, operation: str = "read") -> tuple[Path | None, dict[str, Any] | None]:
    path = Path(raw_path).expanduser().resolve(strict=False)
    if not path_in_allowed_roots(path):
        return None, {"status": "blocked", "path": str(path), "reason": "path outside allowed roots"}
    sensitive_reason = sensitive_path_reason(path, operation=operation)
    if sensitive_reason:
        return None, {"status": "blocked", "path": str(path), "reason": sensitive_reason}
    return path, None


def sensitive_path_reason(path: Path, *, operation: str = "read") -> str | None:
    if os.environ.get("SITINA_SENSITIVE_PATH_PROTECTION", "1") not in {"1", "true", "TRUE", "yes", "on"}:
        return None
    resolved = path.expanduser().resolve(strict=False)
    if _is_system_path(resolved) and os.environ.get("SITINA_ALLOW_SYSTEM_ROOTS") not in {"1", "true", "TRUE", "yes", "on"}:
        return "system path blocked by default"
    parts = [part.lower() for part in resolved.parts]
    name = resolved.name.lower()
    if any(part in {".ssh", ".gnupg", ".aws"} for part in parts):
        return "sensitive credential directory blocked"
    if ".config" in parts and any(fragment in name for fragment in ("token", "key", "secret", "password", "credential")):
        return "sensitive config credential path blocked"
    if name.startswith(".env") or any(fragment in name for fragment in ("secret", "token", "password")):
        return "sensitive file name blocked"
    if name in {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}:
        return "private key file blocked"
    if resolved.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
        return "private key or certificate file blocked"
    if any(fragment in str(resolved).lower() for fragment in ("keychain", "cookies", "credential store", "credentials")):
        return "credential store path blocked"
    return None


def _is_system_path(path: Path) -> bool:
    system_roots = [Path(item) for item in ("/System", "/Library", "/Applications", "/private", "/etc", "/var", "/usr", "/bin", "/sbin")]
    return any(_is_relative_to(path, root) for root in system_roots)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def text_result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def json_result(value: Any) -> dict[str, Any]:
    return {"content": [{"type": "json", "json": value}], "isError": False}


def error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def run_stdio_server(tools: list[dict[str, Any]], handlers: dict[str, ToolHandler]) -> None:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            request_id = request.get("id")
            method = request.get("method")
            if request_id is None:
                continue
            if method == "initialize":
                send({"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "sitina-local", "version": "1.0"}}})
            elif method == "tools/list":
                send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
            elif method == "tools/call":
                params = request.get("params", {})
                name = params.get("name")
                arguments = params.get("arguments") or {}
                if name not in handlers:
                    send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "tool not found"}})
                    continue
                try:
                    send({"jsonrpc": "2.0", "id": request_id, "result": handlers[name](arguments)})
                except Exception as exc:  # noqa: BLE001
                    send({"jsonrpc": "2.0", "id": request_id, "result": error_result(str(exc))})
            else:
                send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}})
        except json.JSONDecodeError:
            continue


def send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stdout.flush()
