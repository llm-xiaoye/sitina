"""Task-scoped execution policy shared by native, Shell and child processes.

The Host supplies authority; command text and executable names grant none.
Only the per-task inspected gateway is reachable from a sandboxed process.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import shutil
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

TASK_EXECUTION_CONTRACT = "SITINA_TASK_EXECUTION_V1"
# The current macOS owner can settle its process group. Detached descendants
# are not contained; caller-provided receipt fields cannot upgrade this scope.
TASK_PROCESS_OWNERSHIP_SCOPE = "PROCESS_GROUP"
FULL_PROCESS_TREE_ENFORCEMENT_AVAILABLE = False
EXECUTION_TOOLS = frozenset({
    "sitina_shell", "sitina_exec", "sitina_process_start",
    "sitina_process_status", "sitina_process_log", "sitina_process_stop",
    "sitina_process_input", "sitina_process_interrupt", "sitina_process_resize",
    "sitina_process_takeover", "sitina_process_release", "sitina_task_environment",
    "sitina_register_service", "sitina_task_skills", "sitina_manage_skills",
})

class ExecutionDenied(ValueError):
    """A request rejected before starting its program."""


class ExecutionPolicyDenied(ExecutionDenied):
    """An invariant boundary: changing user approval cannot permit this request."""

    denial_kind = "POLICY"


def execution_authorization(backend: Any, task_id: str) -> dict[str, Any]:
    task = backend.get_task(task_id)
    if not task.descriptor_ref or not task.descriptor_hash:
        return {}
    descriptor = backend.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
    if not isinstance(descriptor, Mapping) or descriptor.get("task_id") != task_id:
        raise ExecutionDenied("task execution descriptor is not bound to this task")
    authorization = descriptor.get("authorization")
    return dict(authorization) if isinstance(authorization, Mapping) else {}


def task_execution_enabled(backend: Any, task_id: str) -> bool:
    return execution_authorization(backend, task_id).get("execution_contract") == TASK_EXECUTION_CONTRACT


def _strings(value: Any, label: str, *, empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(x, str) and "\x00" not in x for x in value):
        raise ExecutionDenied(label + " must be an array of strings without NUL")
    if not empty and not value:
        raise ExecutionDenied(label + " must not be empty")
    return tuple(value)


@dataclass(frozen=True)
class ExecutionRequest:
    argv: tuple[str, ...]
    cwd: Path
    shell_text: str | None
    environment: Mapping[str, str]
    pty: bool
    keep: bool
    timeout_seconds: float
    yield_seconds: float
    rows: int = 24
    columns: int = 80

    @classmethod
    def parse(cls, arguments: Mapping[str, Any], *, tool_name: str, workspace: Path,
              environment: Mapping[str, str]) -> "ExecutionRequest":
        raw_cwd = arguments.get("cwd") or str(workspace)
        if not isinstance(raw_cwd, str) or "\x00" in raw_cwd:
            raise ExecutionDenied("cwd must be a path without NUL")
        try:
            path = Path(raw_cwd).expanduser()
            cwd = (path if path.is_absolute() else workspace / path).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ExecutionDenied("cwd is unavailable: " + str(error)) from None
        if not cwd.is_dir():
            raise ExecutionDenied("cwd is not a directory")
        command = arguments.get("command")
        executable = arguments.get("executable")
        shell_text = None
        if executable is not None:
            if command is not None or not isinstance(executable, str) or not executable or "\x00" in executable:
                raise ExecutionDenied("use executable/argv or command, without combining them")
            argv = (executable, *_strings(arguments.get("argv", []), "argv"))
        elif isinstance(command, list):
            argv = _strings(command, "command", empty=False)
            if not argv[0]:
                raise ExecutionDenied("executable is empty")
        elif isinstance(command, str) and command.strip() and "\x00" not in command:
            shell = arguments.get("shell", "/bin/zsh")
            if shell not in {"/bin/zsh", "/bin/bash", "/bin/sh"}:
                raise ExecutionDenied("shell must be an explicitly supported non-login system shell")
            shell_text = command
            argv = (shell, "-f", "-c", command) if shell == "/bin/zsh" else (shell, "--noprofile", "--norc", "-c", command) if shell == "/bin/bash" else (shell, "-c", command)
        elif arguments.get("terminal") is True:
            # The PTY shell retains cd/export/activation until explicitly exited.
            argv = ("/bin/zsh", "-f")
        else:
            raise ExecutionDenied("supply command, executable/argv, or terminal=true")
        program = Path(argv[0]).expanduser()
        if not program.is_absolute():
            resolved = shutil.which(argv[0], path=environment.get("PATH", "/usr/bin:/bin"))
            if not resolved:
                raise ExecutionDenied("program was not found in the task PATH: " + argv[0])
            program = Path(resolved)
        # Preserve a venv/script lexical entry. Its canonical target is bound separately.
        program = program.absolute()
        if not program.is_file() or not os.access(program, os.X_OK):
            raise ExecutionDenied("program is not executable: " + str(program))
        timeout = arguments.get("timeout_seconds", 86400.0 if tool_name == "sitina_process_start" else 300.0)
        wait = arguments.get("yield_time_ms", 1000)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ExecutionDenied("timeout_seconds must be finite and positive")
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not math.isfinite(wait) or not 0 <= wait <= 10000:
            raise ExecutionDenied("yield_time_ms must be between 0 and 10000")
        rows, columns = arguments.get("rows", 24), arguments.get("columns", 80)
        if any(isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 1000 for n in (rows, columns)):
            raise ExecutionDenied("terminal rows/columns must be integers in 1..1000")
        for key in ("pty", "keep", "terminal"):
            if key in arguments and type(arguments[key]) is not bool:
                raise ExecutionDenied(key + " must be boolean")
        return cls((str(program), *argv[1:]), cwd, shell_text, dict(environment),
                   bool(arguments.get("pty") or arguments.get("terminal")), bool(arguments.get("keep")),
                   float(timeout), float(wait) / 1000, rows, columns)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class ExecutionPolicy:
    task_id: str
    read_roots: tuple[Path, ...]
    write_roots: tuple[Path, ...]
    excluded_roots: tuple[Path, ...] = ()
    credential_roots: tuple[Path, ...] = ()
    full_local_read: bool = False
    full_local_write: bool = False
    allow_system_power_notifications: bool = False
    allow_local_ipc: bool = False

    def check_path(self, path: Path, *, write: bool = False) -> Path:
        try:
            canonical = path.expanduser().resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise ExecutionDenied("execution path is unavailable: " + str(error)) from None
        if any(_inside(canonical, root.resolve(strict=False)) for root in self.excluded_roots):
            raise ExecutionPolicyDenied("target is reserved for the Host or Provider")
        roots = self.write_roots if write else (*self.read_roots, *self.write_roots)
        if self.full_local_write if write else self.full_local_read:
            return canonical
        if not any(_inside(canonical, root.resolve(strict=False)) for root in roots):
            raise ExecutionDenied("path is outside this task execution scope: " + str(path))
        return canonical

    def check_cwd(self, path: Path) -> Path:
        """Permit an ancestor working directory without granting its file data."""
        try:
            canonical = path.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ExecutionDenied("working directory is unavailable: " + str(error)) from None
        if not canonical.is_dir():
            raise ExecutionDenied("working directory is not a directory")
        if any(_inside(canonical, root.resolve(strict=False)) for root in self.excluded_roots):
            raise ExecutionPolicyDenied("working directory is reserved for the Host or Provider")
        roots = (*self.read_roots, *self.write_roots)
        if self.full_local_read:
            return canonical
        if not any(_inside(canonical, root.resolve(strict=False)) or canonical in root.resolve(strict=False).parents
                   for root in roots):
            raise ExecutionDenied("working directory is outside this task execution scope")
        return canonical

    def cwd_environment(self, path: Path) -> dict[str, str]:
        self.check_cwd(path)
        try:
            self.check_path(path)
        except ExecutionDenied:
            # A file-only delegation must not implicitly import code by
            # probing its undelegated parent working directory.
            return {"PYTHONSAFEPATH": "1"}
        return {}

    def sandbox_profile(self, *, runtime_roots: Sequence[Path], gateway_port: int | None = None,
                        trust_paths: Sequence[Path] = (), listen_ports: Sequence[int] = ()) -> str:
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
            raise ExecutionDenied("task execution requires the macOS process sandbox")
        if gateway_port is not None and (type(gateway_port) is not int or not 1 <= gateway_port <= 65535):
            raise ExecutionDenied("invalid inspected gateway endpoint")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in listen_ports):
            raise ExecutionDenied("listen ports must be explicit integers in 1..65535")
        system = [Path(p) for p in ("/System/Library", "/usr/bin", "/usr/lib", "/usr/libexec",
                  "/usr/share", "/bin", "/sbin", "/Library/Developer/CommandLineTools",
                  "/Library/Apple", "/private/etc", "/private/var/db/dyld") if Path(p).exists()]
        interpreter = [Path(sys.base_prefix), Path(sys.prefix)]
        interpreter.extend(Path(p) for p in sysconfig.get_paths().values() if Path(p).exists())
        # Only the trusted gateway supplies these public certificate files.
        # They live beside private Host state, so keep their exact data-read
        # exception separate from business roots and all write permissions.
        trust_files = tuple(path.resolve(strict=True) for path in trust_paths)
        if any(not path.is_file() for path in trust_files):
            raise ExecutionDenied("gateway trust material must be a regular file")
        if any(_inside(path, credential.resolve(strict=False))
               for path in trust_files for credential in self.credential_roots):
            raise ExecutionDenied("gateway trust material overlaps a credential reference")
        reads = sorted({p.resolve() for p in (*system, *interpreter, *self.read_roots, *self.write_roots,
                        *runtime_roots) if p.exists()}, key=str)
        writes = sorted({p.resolve(strict=False) for p in (*self.write_roots, *runtime_roots)}, key=str)
        if self.full_local_read:
            reads = [Path("/")]
        if self.full_local_write:
            writes = [Path("/")]
        quote = lambda p: json.dumps(str(p), ensure_ascii=True)
        exclusions = " ".join("(require-not (subpath " + quote(p.resolve()) + "))" for p in self.excluded_roots)
        def paths(operation: str, roots: Sequence[Path]) -> list[str]:
            return ["(allow " + operation, *["  (require-all (subpath " + quote(p) + ") " + exclusions + ")" for p in roots], ")"]
        lines = ["(version 1)", "(deny default)", '(import "system.sb")',
                 "(deny network*)", "(allow process-fork)", "(allow process-exec)",
                 "(allow signal (target children))", "(allow file-read-metadata file-test-existence)",
                 "(allow sysctl-read)",
                 '(allow file-read* file-write* (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom") (regex #"^/dev/(tty|ttys[0-9]+|fd/[0-9]+)$"))',
                 *paths("file-read* file-test-existence", reads), *paths("file-write*", writes)]
        if self.full_local_read and (self.full_local_write or self.allow_system_power_notifications):
            # Native desktop runtimes subscribe to macOS sleep/wake events.
            # Denying this client makes IORegisterForSystemPower return NULL;
            # some headless runtimes then dereference its missing run-loop source.
            # The parent runtime grant is independent of selected business-file
            # write paths. Only this IOKit client is allowed; other boundaries stay.
            lines.append('(allow iokit-open (iokit-user-client-class "RootDomainUserClient"))')
        if self.full_local_read and (self.full_local_write or self.allow_local_ipc):
            # Full current-user local execution includes Mach/XPC, POSIX IPC,
            # Unix-domain sockets, and signals. System services reached through
            # IPC can act outside the HTTP gateway; this is an explicit user
            # authorization, not a promise of complete indirect network isolation.
            # TCP/UDP still have no direct allow rule and retain gateway policy.
            lines.extend([
                "(allow mach*)", "(allow ipc*)", "(allow signal)",
                "(allow network* (local unix-socket))",
                "(allow network* (remote unix-socket))",
            ])
        lines.extend("(allow file-read-data (literal " + quote(path) + "))" for path in trust_files)
        if gateway_port is not None:
            lines.append('(allow network-outbound (remote tcp "localhost:' + str(gateway_port) + '"))')
        for port in listen_ports:
            endpoint = '"localhost:' + str(port) + '"'
            lines.extend(["(allow network-bind (local tcp " + endpoint + "))", "(allow network-inbound (local tcp " + endpoint + "))"])
        return "\n".join(lines) + "\n"


def task_environment(runtime_root: Path, *, workspace: Path, shared: Mapping[str, str] | None = None,
                     command: Mapping[str, str] | None = None, gateway: Mapping[str, str] | None = None,
                     local_home: Path | None = None) -> dict[str, str]:
    """Build a declared environment; never copy the Host environment."""
    for name in ("home", "tmp", "cache", "config", "data", "state", "output"):
        (runtime_root / name).mkdir(parents=True, exist_ok=True)
    tool_path = [str(workspace / ".venv" / "bin"), str(workspace / "node_modules" / ".bin"),
                 str(Path(sys.executable).parent), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    env = {"PATH": ":".join(tool_path), "HOME": str(runtime_root / "home"),
           "CFFIXED_USER_HOME": str(runtime_root / "home"), "TMPDIR": str(runtime_root / "tmp"),
           # zsh uses TMPPREFIX for here-documents, independently of TMPDIR.
           # Keep its files in the already authorized private runtime scratch,
           # even when the command has no business write_paths.
           "TMPPREFIX": str(runtime_root / "tmp" / "zsh"),
           "XDG_CACHE_HOME": str(runtime_root / "cache"), "XDG_CONFIG_HOME": str(runtime_root / "config"),
           "XDG_DATA_HOME": str(runtime_root / "data"), "XDG_STATE_HOME": str(runtime_root / "state"),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
           "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
           "SITINA_CHECK_OUTPUT": str(runtime_root / "output"),
           "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_ASKPASS": "/usr/bin/false", "SSH_ASKPASS": "/usr/bin/false",
           "PIP_CONFIG_FILE": "/dev/null", "PIP_KEYRING_PROVIDER": "disabled", "NPM_CONFIG_USERCONFIG": "/dev/null"}
    if local_home is not None:
        env.update(HOME=str(local_home), CFFIXED_USER_HOME=str(local_home))
    reserved = set(env) - {"PATH", "LANG", "LC_ALL"}
    reserved.update({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
                     "all_proxy", "no_proxy", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
                     "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"})
    for layer in (shared or {}, command or {}):
        if not isinstance(layer, Mapping):
            raise ExecutionDenied("environment must be a string mapping")
        for key, value in layer.items():
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or not isinstance(value, str) or "\x00" in value:
                raise ExecutionDenied("environment keys and values must be valid strings")
            if key in reserved or key.startswith(("SITINA_", "GIT_CONFIG_", "DYLD_")):
                raise ExecutionDenied("environment setting is managed by the task runtime: " + key)
            env[key] = value
    env.update(gateway or {})
    return env


def command_control(evidence: Mapping[str, Any], *, task_id: str, operation_id: str, action: str,
                    actor: str = "agent", data: str = "", rows: int = 24, columns: int = 80,
                    request_id: str | None = None) -> dict[str, Any]:
    """Durably enqueue one original-process control, replaying the same request id."""
    import fcntl
    import secrets
    from sitina.loop.command_runner import _read_json, _write_json, _hash_bytes
    path = Path(str(evidence.get("command_manifest_path") or ""))
    raw = path.read_bytes()
    manifest = json.loads(raw)
    if (_hash_bytes(raw) != evidence.get("command_manifest_hash") or manifest.get("task_id") != task_id
            or manifest.get("operation_id") != operation_id or manifest.get("execution_contract") != TASK_EXECUTION_CONTRACT):
        raise ExecutionDenied("execution control is not bound to this task")
    if actor not in {"agent", "user"} or action not in {"input", "interrupt", "resize", "takeover", "release", "stop"}:
        raise ExecutionDenied("unknown execution control")
    request_id = request_id or secrets.token_hex(16)
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id):
        raise ExecutionDenied("control request_id must be a bounded stable identifier")
    if action == "input" and (not isinstance(data, str) or len(data.encode("utf-8")) > 65536):
        raise ExecutionDenied("input is limited to 65536 UTF-8 bytes per request")
    if action == "resize" and any(type(n) is not int or not 1 <= n <= 1000 for n in (rows, columns)):
        raise ExecutionDenied("invalid terminal dimensions")
    request = {"nonce": manifest["nonce"], "request_id": request_id, "action": action, "actor": actor,
               "data": base64.b64encode(data.encode("utf-8")).decode("ascii"), "rows": rows, "columns": columns}
    key = hashlib.sha256(request_id.encode("ascii")).hexdigest()
    requests = path.parent / "control-requests"
    acknowledgements = path.parent / "control-acks"
    requests.mkdir(exist_ok=True)
    acknowledgements.mkdir(exist_ok=True)
    record_path, ack_path = requests / (key + ".json"), acknowledgements / (key + ".json")
    with (path.parent / "control.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        previous = _read_json(record_path)
        if previous:
            if previous.get("request") != request:
                raise ExecutionDenied("control request_id was already used with different arguments")
            ack = _read_json(ack_path) or previous["ack"]
            return {**ack, "status": ack["state"], "process_id": operation_id, "replayed": True}
        owner_path = path.parent / "input-owner.json"
        owner = _read_json(owner_path) or {"owner": "agent", "version": 0}
        if actor == "agent" and owner["owner"] != "agent":
            raise ExecutionDenied("the user holds exclusive terminal input")
        if action in {"takeover", "release"} and actor != "user":
            raise ExecutionDenied("only the user can change terminal input ownership")
        ack = {"request_id": request_id, "action": action, "state": "UNKNOWN", "cursor": None,
               "reason": "control_dispatch_not_confirmed"}
        _write_json(record_path, {"request": request, "ack": ack})
        completed = _read_json(Path(manifest["completion_path"]))
        if completed and completed.get("nonce") == manifest["nonce"]:
            ack = {"request_id": request_id, "action": action, "state": "APPLIED" if action == "stop" else "REJECTED",
                   "cursor": None, "reason": "original_process_already_finished", "input_owner": owner["owner"]}
        else:
            control_path = path.parent / "control.jsonl"
            with control_path.open("ab") as handle:
                handle.write((json.dumps(request, separators=(",", ":")) + "\n").encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
            if action in {"takeover", "release"}:
                owner = {"owner": "user" if action == "takeover" else "agent", "version": int(owner["version"]) + 1}
                _write_json(owner_path, owner)
            ack = {"request_id": request_id, "action": action, "state": "REQUESTED",
                   "cursor": control_path.stat().st_size, "input_owner": owner["owner"]}
        _write_json(record_path, {"request": request, "ack": ack})
        if ack["state"] != "REQUESTED":
            _write_json(ack_path, ack)
            _write_json(path.parent / "control-ack.json", ack)
        return {**ack, "status": ack["state"], "control_cursor": ack["cursor"], "process_id": operation_id, "replayed": False}

def read_command_output(evidence: Mapping[str, Any], *, offsets: Mapping[str, int] | None = None,
                        limit: int = 16384, control_request_id: str | None = None) -> dict[str, Any]:
    from sitina.loop.command_runner import _read_json, _hash_bytes
    manifest_path = Path(str(evidence.get("command_manifest_path") or ""))
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if (_hash_bytes(raw) != evidence.get("command_manifest_hash")
            or manifest.get("execution_contract") != TASK_EXECUTION_CONTRACT):
        raise ExecutionDenied("execution output manifest is not bound to its owner")
    ack_path = manifest_path.parent / "control-ack.json"
    if control_request_id is not None:
        if not isinstance(control_request_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", control_request_id):
            raise ExecutionDenied("invalid control request id")
        key = hashlib.sha256(control_request_id.encode("ascii")).hexdigest()
        ack_path = manifest_path.parent / "control-acks" / (key + ".json")
        ack = _read_json(ack_path)
        if ack is None:
            record = _read_json(manifest_path.parent / "control-requests" / (key + ".json"))
            ack = record.get("ack") if isinstance(record, Mapping) else None
    else:
        ack = _read_json(ack_path)
    if type(limit) is not int or not 1 <= limit <= 65536:
        raise ExecutionDenied("output limit must be in 1..65536")
    streams = ("combined",) if manifest.get("pty") else ("stdout", "stderr")
    pages = {}
    for stream in streams:
        offset = (offsets or {}).get(stream, 0)
        if type(offset) is not int or offset < 0:
            raise ExecutionDenied("output cursor must be a nonnegative byte offset")
        path = Path(manifest["stdout_path"] if stream != "stderr" else manifest["stderr_path"])
        if not path.exists():
            pages[stream] = {"offset": offset, "next_offset": offset, "bytes": 0, "text": "", "eof": False}
            continue
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if offset > size:
                raise ExecutionDenied("output cursor is beyond the persisted stream")
            handle.seek(offset)
            raw = handle.read(limit)
        pages[stream] = {"offset": offset, "next_offset": offset + len(raw), "bytes": len(raw),
                         "text": raw.decode("utf-8", errors="replace"),
                         "raw_base64": base64.b64encode(raw).decode("ascii"), "eof": offset + len(raw) >= size}
    return {"streams": pages, "stream_split_observed": not bool(manifest.get("pty")),
            "output_source": "pty_combined_stream" if manifest.get("pty") else "child_pipes",
            "control_ack": ack}
