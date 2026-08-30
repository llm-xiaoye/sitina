#!/usr/bin/env python3
"""Untrusted, one-attempt Code Mode worker.

The worker is intentionally a very small stdlib-only process.  It owns no
Sitina imports, authority material, provider client, Journal/CAS handle, or
acceptance logic.  The controller gives it a narrow operation over a bound
workspace and treats every response as untrusted observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _path_hash(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return _hash_bytes(path.read_bytes())
    except OSError:
        return None


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _safe_path(value: object, root: Path, *, allow_missing: bool = True) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise PermissionError("worker path is required")
    raw = Path(value).expanduser()
    path = raw if raw.is_absolute() else root / raw
    resolved = path.resolve(strict=False)
    if not _inside(resolved, root):
        raise PermissionError("worker path escapes bound workspace")
    relative = resolved.relative_to(root)
    cursor = root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise PermissionError("worker refuses symlink path components")
    if not allow_missing and not resolved.exists():
        raise FileNotFoundError(str(resolved))
    if resolved.exists() and not (resolved.is_file() or resolved.is_dir()):
        raise PermissionError("worker target is not a regular file or directory")
    return resolved


def _result(status: str, **values: Any) -> dict[str, Any]:
    return {"schema": "CODE_MODE_WORKER_RESULT_V1", "status": status, **values}


def _fd_inventory() -> list[dict[str, Any]]:
    """Return a hash-only inventory of every actually open descriptor.

    ``/dev/fd`` is deliberately not used here.  Apart from being unavailable
    under some Seatbelt profiles, enumerating it creates an observation race
    and a failed ``readlink`` can make unrelated descriptors look identical.
    The finite soft descriptor limit is the authoritative scan boundary; each
    number is checked with ``fstat`` and only stable identity metadata leaves
    the worker.
    """
    values: list[dict[str, Any]] = []
    soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit == resource.RLIM_INFINITY or soft_limit < 0:
        raise RuntimeError("worker descriptor limit is not finite")
    for descriptor in range(int(soft_limit)):
        try:
            info = os.fstat(descriptor)
        except OSError:
            continue
        identity = (
            f"{stat.S_IFMT(info.st_mode)}:{stat.S_IMODE(info.st_mode)}:"
            f"{info.st_dev}:{info.st_ino}:{info.st_rdev}"
        )
        values.append({
            "fd": descriptor,
            "identity_hash": hashlib.sha256(identity.encode("ascii")).hexdigest(),
        })
    return values


def _secret_environment_absent() -> bool:
    markers = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")
    return not any(any(marker in name.upper() for marker in markers) for name in os.environ)


def _limit_tester_resources() -> None:
    """Apply bounded limits in the child before running untrusted doctests.

    Code Mode permits a tester child only for the structured unittest/doctest
    runner.  Seatbelt denies networking and limits its filesystem roots; the
    process limits below close the remaining fork/CPU/file-size/resource abuse
    window.  Failure to apply a limit is intentionally fail-closed.
    """
    limits = (
        (resource.RLIMIT_CPU, (5, 6)),
        (resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024)),
        (resource.RLIMIT_NOFILE, (32, 32)),
        (resource.RLIMIT_CORE, (0, 0)),
    )
    # Fork is admitted only for the single structured tester child.  Keep a
    # small per-user process ceiling as a second line of defence against a
    # malicious doctest attempting to fan out before the controller timeout.
    if hasattr(resource, "RLIMIT_NPROC"):
        limits += ((resource.RLIMIT_NPROC, (16, 16)),)
    for kind, value in limits:
        try:
            resource.setrlimit(kind, value)
        except (OSError, ValueError):
            raise RuntimeError("tester resource limit could not be applied") from None


def _group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except OSError:
        return False


def _terminate_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Kill and reap the entire tester group, returning a verified result."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    # A leader can exit while descendants remain in the same process group.
    # Give SIGKILL one final chance and only claim reaping after the group is
    # demonstrably gone.
    if _group_exists(process.pid):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            return False
    return not _group_exists(process.pid)


def _run_tester(command: list[str], *, cwd: Path, env: dict[str, str], timeout_seconds: int) -> dict[str, Any]:
    process = subprocess.Popen(
        command, cwd=str(cwd), env=env, shell=False,
        close_fds=True, start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=_limit_tester_resources,
    )
    try:
        stdout, stderr = process.communicate(timeout=max(1, min(int(timeout_seconds), 5)))
    except subprocess.TimeoutExpired:
        reaped = _terminate_process_group(process)
        return {"status": "blocked", "reason": "tester timeout", "timed_out": True,
                "process_group_reaped": reaped}
    output = (stdout + stderr)[:4000]
    reaped = _terminate_process_group(process) if _group_exists(process.pid) else True
    return {"status": "ok" if process.returncode == 0 else "failed",
            "exit_code": process.returncode, "output": output.decode("utf-8", "replace"),
            "timed_out": False, "process_group_reaped": reaped}


def execute(request: Mapping[str, Any]) -> dict[str, Any]:
    if request.get("schema") != "CODE_MODE_WORKER_REQUEST_V1":
        raise PermissionError("worker request schema is invalid")
    binding = request.get("binding")
    if not isinstance(binding, Mapping):
        raise PermissionError("worker binding is required")
    raw_root = Path(str(binding.get("workspace") or "")).expanduser()
    if raw_root.is_symlink() or not raw_root.is_dir():
        raise PermissionError("worker workspace is not a real directory")
    root = raw_root.resolve(strict=True)
    root_stat = os.stat(root, follow_symlinks=False)
    if int(binding.get("workspace_dev") or -1) != int(root_stat.st_dev) or int(binding.get("workspace_inode") or -1) != int(root_stat.st_ino):
        raise PermissionError("worker workspace identity changed")
    if int(binding.get("controller_pid") or -1) != os.getppid():
        raise PermissionError("worker parent is not the bound controller")
    try:
        worker_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        worker_hash = ""
    if worker_hash != str(binding.get("runner_hash") or ""):
        raise PermissionError("worker executable identity changed")
    expires_at = int(binding.get("expires_at") or 0)
    if expires_at <= int(time.time()):
        raise PermissionError("worker binding is expired")
    nonce = binding.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 32:
        raise PermissionError("worker binding nonce is invalid")
    operation_id = binding.get("operation_id")
    if not isinstance(operation_id, str) or len(operation_id) < 16:
        raise PermissionError("worker operation identity is invalid")
    if str(binding.get("child_run_id") or "") != str(binding.get("run_id") or ""):
        raise PermissionError("worker child run identity is invalid")
    if not isinstance(binding.get("purpose"), str) or not str(binding.get("purpose")):
        raise PermissionError("worker purpose is invalid")
    read_roots = binding.get("read_roots")
    write_roots = binding.get("write_roots")
    if read_roots != [str(root)] or write_roots != [str(root)]:
        raise PermissionError("worker roots are not exact")
    operation = str(request.get("operation") or "")
    if operation in {"write", "append"}:
        path = _safe_path(request.get("path"), root)
        if path.exists() and not path.is_file():
            raise PermissionError("worker write target is not a regular file")
        before = _path_hash(path)
        expected = request.get("expected_before_hash", "__unset__")
        if expected != "__unset__" and before != expected:
            return _result("blocked", reason="before_hash mismatch", before_hash=before)
        content = request.get("content")
        if not isinstance(content, str):
            raise PermissionError("worker write content is invalid")
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name("." + path.name + ".sitina-worker-tmp")
        temp.write_text(content, encoding="utf-8")
        os.replace(temp, path)
        return _result("ok", operation=operation, path=str(path), before_hash=before,
                       after_hash=_path_hash(path), content_sha256=_hash_bytes(content.encode("utf-8")))
    if operation == "delete":
        path = _safe_path(request.get("path"), root, allow_missing=True)
        if path == root or path.is_dir() or path.is_symlink():
            raise PermissionError("worker delete requires a regular file")
        before = _path_hash(path)
        expected = request.get("expected_before_hash", "__unset__")
        if expected != "__unset__" and before != expected:
            return _result("blocked", reason="before_hash mismatch", before_hash=before)
        if path.exists():
            path.unlink()
        return _result("ok", operation="delete", path=str(path), before_hash=before, after_hash=None)
    if operation == "rename":
        source = _safe_path(request.get("path"), root, allow_missing=False)
        destination = _safe_path(request.get("destination"), root, allow_missing=True)
        if not source.is_file() or source.is_symlink() or destination.exists() or destination.is_symlink():
            raise PermissionError("worker rename requires regular source and absent destination")
        before = _path_hash(source)
        expected = request.get("expected_before_hash", "__unset__")
        if expected != "__unset__" and before != expected:
            return _result("blocked", reason="before_hash mismatch", before_hash=before)
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, destination)
        return _result("ok", operation="rename", path=str(source), destination=str(destination),
                       before_hash=before, after_hash=_path_hash(destination))
    if operation == "shell":
        command = request.get("argv")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
            raise PermissionError("worker shell requires argv")
        if any(item in {";", "&&", "||", "|", ">", ">>", "<", "`"} for item in command):
            raise PermissionError("worker shell operators are forbidden")
        cwd = _safe_path(request.get("cwd") or str(root), root, allow_missing=False)
        if not cwd.is_dir():
            raise PermissionError("worker cwd is not a directory")
        if any(item in {"-c", "--command", "-i", "--interactive"} for item in command):
            raise PermissionError("worker shell does not admit inline Python or interactive code")
        if "-m" in command:
            try:
                module = command[command.index("-m") + 1]
            except (ValueError, IndexError):
                raise PermissionError("worker module invocation is incomplete") from None
            if module not in {"unittest", "doctest"}:
                raise PermissionError("worker module is not an admitted tester")
        argv_hash = _hash_bytes(_canonical(command))
        if request.get("argv_hash") != argv_hash or binding.get("argv_hash") != argv_hash:
            raise PermissionError("worker argv is not exactly bound")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(root),
            "TMPDIR": str(root / ".sitina-tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        env["SITINA_CODE_MODE_WORKER"] = "1"
        observation = _run_tester(
            command, cwd=cwd, env=env,
            timeout_seconds=int(binding.get("timeout_seconds") or 5),
        )
        # Output is bounded and never includes a raw provider credential.  The
        # controller still treats it as untrusted and redacts before audit.
        return _result(observation.pop("status"), operation="shell", **observation,
                       argv_hash=_hash_bytes(_canonical(command)))
    raise PermissionError("worker operation is not supported")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    args = parser.parse_args()
    if args.control_fd < 0:
        raise SystemExit(2)
    channel = socket.socket(fileno=args.control_fd)
    with channel:
        line = channel.makefile("rb").readline()
        request: object = None
        try:
            request = json.loads(line.decode("utf-8"))
            if (
                not isinstance(request, Mapping)
                or int(request.get("control_fd") or -1) != args.control_fd
                or int((request.get("binding") or {}).get("control_fd") or -1) != args.control_fd
            ):
                raise PermissionError("worker control FD binding is invalid")
            response = execute(request)
        except BaseException as error:  # untrusted result; no traceback over wire
            response = _result("blocked", reason_code=type(error).__name__,
                               error_hash=hashlib.sha256(str(error).encode("utf-8")).hexdigest())
        binding = request.get("binding") if isinstance(request, Mapping) else {}
        if not isinstance(binding, Mapping):
            binding = {}
        response.update({
            "worker_pid": os.getpid(),
            "worker_start_identity": str(binding.get("worker_start_identity") or ""),
            "operation_id": str(binding.get("operation_id") or ""),
            "control_fd": int(binding.get("control_fd") or -1),
            "binding_hash": hashlib.sha256(_canonical(dict(binding))).hexdigest(),
            "nonce_hash": hashlib.sha256(str(binding.get("nonce") or "").encode("utf-8")).hexdigest(),
            "worker_code_hash": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "fd_inventory": _fd_inventory(),
            "secret_env_absent": _secret_environment_absent(),
        })
        try:
            actual_fds = {int(item["fd"]) for item in response["fd_inventory"]}
        except (KeyError, TypeError, ValueError):
            actual_fds = set()
        expected_fds = {0, 1, 2, args.control_fd}
        if args.control_fd in {0, 1, 2} or actual_fds != expected_fds:
            response["status"] = "blocked"
            response["reason_code"] = "FD_INVENTORY_NOT_EXACT"
            # Do not include descriptor targets or values in the diagnostic.
            response["fd_set_hash"] = hashlib.sha256(
                _canonical(sorted(actual_fds))
            ).hexdigest()
            channel.sendall(_canonical(response) + b"\n")
            return 77
        channel.sendall(_canonical(response) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
