"""Durable, narrowly-capable command execution for loop program checks.

This module intentionally keeps the wrapper protocol private to the loop.  A
program check receives only the immutable input copy and the output directory;
the manifest, permit, completion receipt, and bounded logs live beside (but
outside) those roots and are never inherited by the checked process.
"""

from __future__ import annotations

import argparse
import contextvars
import threading
import base64
import fcntl
import hashlib
import json
import math
import os
import pty
import errno
import struct
import termios
import select
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


COMMAND_POLICY = "COMMAND_FENCED_NO_FORK_V1"
TASK_EXECUTION_CONTRACT = "SITINA_TASK_EXECUTION_V1"
TASK_COMMAND_POLICY = "TASK_SCOPED_PROCESS_V1"
TASK_OUTCOME_CONTRACT = "ROOT_PROCESS_AND_GROUP_V1"


def _manifest_command_boundary(
    manifest: Mapping[str, Any], *, require_current_executable: bool = True,
) -> bool:
    command = manifest.get("argv")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        return False
    task_contract = manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT
    recorded = manifest.get("resolved_executable" if task_contract else "resolved_interpreter")
    if not isinstance(recorded, str) or not os.path.isabs(recorded) or "\0" in recorded:
        return False
    if require_current_executable:
        try:
            if _resolved(command[0]) != recorded:
                return False
        except (OSError, RuntimeError, ValueError):
            return False
    profile = str(manifest.get("profile") or "")
    if task_contract:
        return bool(manifest.get("policy") == TASK_COMMAND_POLICY and "(deny default)" in profile
                    and "(deny network*)" in profile and "(allow process-fork)" in profile
                    and manifest.get("environment") and type(manifest.get("pty")) is bool)
    return bool(manifest.get("policy") == COMMAND_POLICY and manifest.get("execution_contract") is None and "(deny process-fork)" in profile
                )

MAX_LOG_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 300.0


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash_json(value: Mapping[str, Any]) -> str:
    return _hash_bytes(_canonical_bytes(value))


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json(path: Path, value: Mapping[str, Any], *, exclusive: bool = False) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = _canonical_bytes(value) + b"\n"
    if exclusive:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    _fsync_dir(path.parent)
    return _hash_bytes(raw)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _permit_matches(manifest: Mapping[str, Any], permit: Mapping[str, Any] | None, *, states: set[str]) -> bool:
    return bool(
        permit is not None
        and permit.get("schema") == "SITINA_LOOP_COMMAND_PERMIT_V1"
        and permit.get("task_id") == manifest.get("task_id")
        and permit.get("operation_id") == manifest.get("operation_id")
        and permit.get("nonce") == manifest.get("nonce")
        and permit.get("wrapper_id") == manifest.get("wrapper_id")
        and permit.get("state") in states
    )


def _bounded_read(path: Path, limit: int = MAX_LOG_BYTES) -> tuple[str, str, int, bool]:
    digest = hashlib.sha256()
    visible = bytearray()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                if len(visible) < limit:
                    visible.extend(chunk[: limit - len(visible)])
    except OSError:
        return "", _hash_bytes(b""), 0, False
    return bytes(visible).decode("utf-8", errors="replace"), "sha256:" + digest.hexdigest(), total, total > limit


def _resolved(path: str) -> str:
    return str(Path(path).expanduser().resolve(strict=True))


def _snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not root.exists() or root.is_symlink():
        return result
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            result[str(path.relative_to(root))] = _hash_bytes(path.read_bytes())
        except OSError:
            return {}
    return result


def observe_command_evidence(evidence: Mapping[str, Any], *, task_id: str, operation_id: str, revoke_not_started: bool = True) -> dict[str, Any]:
    """Observe one private command protocol without dispatching or retrying it."""
    manifest_path = Path(str(evidence.get("command_manifest_path") or ""))
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return {"decision": "UNKNOWN", "reason": "manifest-missing"}
    try:
        manifest_raw = manifest_path.read_bytes()
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"decision": "UNKNOWN", "reason": "manifest-unreadable"}
    if not isinstance(manifest, dict) or _hash_bytes(manifest_raw) != str(evidence.get("command_manifest_hash") or ""):
        return {"decision": "UNKNOWN", "reason": "manifest-hash-mismatch"}
    if (
        manifest.get("schema") != "SITINA_LOOP_COMMAND_MANIFEST_V1"
        or manifest.get("policy") not in {COMMAND_POLICY, TASK_COMMAND_POLICY}
        or manifest.get("task_id") != task_id
        or manifest.get("operation_id") != operation_id
        or manifest.get("nonce") != evidence.get("command_nonce")
        or manifest.get("profile_hash") != _hash_bytes(str(manifest.get("profile") or "").encode("utf-8"))
        # The trusted manifest records the executable used at dispatch. A
        # later task-owned venv change must not rewrite a past process fact.
        # The actual launch still checks the live executable in _run_task_child.
        or not _manifest_command_boundary(manifest, require_current_executable=False)
        or (
            evidence.get("completion_path")
            and str(manifest.get("completion_path")) != str(evidence.get("completion_path"))
        )
        or str(manifest.get("wrapper_id")) != str(evidence.get("wrapper_id"))
    ):
        return {"decision": "UNKNOWN", "reason": "manifest-binding-mismatch"}
    # Stdin is deliberately opt-in.  When declared, bind the exact immutable
    # input bytes into the manifest and refuse to treat a missing/unreadable
    # file as DEVNULL (which would silently change the program's meaning).
    stdin_value = manifest.get("stdin_path")
    stdin_hash = manifest.get("stdin_hash")
    if stdin_value:
        stdin_path = Path(str(stdin_value))
        input_root = Path(str(manifest.get("input_root") or ""))
        try:
            stdin_path.relative_to(input_root)
        except ValueError:
            return {"decision": "UNKNOWN", "reason": "stdin-path-outside-input"}
        if stdin_path.is_symlink() or not stdin_path.is_file():
            return {"decision": "UNKNOWN", "reason": "stdin-input-unreadable"}
        try:
            stdin_raw = stdin_path.read_bytes()
        except OSError:
            return {"decision": "UNKNOWN", "reason": "stdin-input-unreadable"}
        if not isinstance(stdin_hash, str) or _hash_bytes(stdin_raw) != stdin_hash:
            return {"decision": "UNKNOWN", "reason": "stdin-input-hash-mismatch"}
    elif stdin_hash not in (None, ""):
        return {"decision": "UNKNOWN", "reason": "stdin-binding-mismatch"}
    permit_path = Path(str(manifest.get("permit_path") or ""))
    permit = _read_json(permit_path)
    start_path = Path(str(manifest.get("start_path") or ""))
    completion_path = Path(str(manifest.get("completion_path") or ""))
    if not start_path.exists() and not completion_path.exists() and not revoke_not_started:
        if permit is not None and _permit_matches(manifest, permit, states={"REVOKED_NOT_STARTED"}):
            return {"decision": "NO_EFFECT", "reason": "permit-revoked-before-start"}
        if permit is not None and not _permit_matches(manifest, permit, states={"AUTHORIZED", "CLAIMED", "STARTED"}):
            return {"decision": "UNKNOWN", "reason": "permit-binding-mismatch"}
        return {"decision": "PENDING", "reason": "authorized-not-started"}
    if not start_path.exists() and not completion_path.exists():
        lock_path = manifest_path.parent / "permit.lock"
        lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            permit = _read_json(permit_path)
            start_exists = start_path.exists()
            completion_exists = completion_path.exists()
            if not start_exists and not completion_exists:
                if permit is not None and _permit_matches(manifest, permit, states={"AUTHORIZED"}):
                    revoked = dict(permit)
                    revoked["state"] = "REVOKED_NOT_STARTED"
                    revoked["revoked_at"] = time.time()
                    _write_json(permit_path, revoked)
                    return {
                        "decision": "NO_EFFECT",
                        "reason": "permit-revoked-before-start",
                        "permit_state": "REVOKED_NOT_STARTED",
                        "wrapper_launch": dict(revoked.get("wrapper_launch") or {}),
                    }
                elif permit_path.exists() and permit is None:
                    return {"decision": "UNKNOWN", "reason": "permit-unreadable"}
                elif permit is None:
                    return {"decision": "UNKNOWN", "reason": "permit-missing"}
                elif _permit_matches(manifest, permit, states={"REVOKED_NOT_STARTED"}):
                    return {
                        "decision": "NO_EFFECT",
                        "reason": "permit-revoked-before-start",
                        "permit_state": "REVOKED_NOT_STARTED",
                        "wrapper_launch": dict(permit.get("wrapper_launch") or {}),
                    }
                elif _permit_matches(manifest, permit, states={"CLAIMED", "STARTED", "COMPLETED"}):
                    return {
                        "decision": "UNKNOWN",
                        "reason": "permit-claimed-without-start",
                        "permit_state": str(permit.get("state")),
                        "wrapper_launch": dict(permit.get("wrapper_launch") or {}),
                    }
                return {"decision": "UNKNOWN", "reason": "permit-binding-mismatch"}
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
    root_fields = _read_root_outcome(manifest)

    def untrusted_completion(reason):
        return {"decision": "UNKNOWN", "reason": reason, "effect_settled": False,
                "manifest": manifest, "manifest_hash": _hash_bytes(manifest_raw), **root_fields}

    if not completion_path.is_file() or completion_path.is_symlink():
        start = _read_json(start_path)
        if (
            start_path.is_symlink() or start is None
            or start.get("schema") != "SITINA_LOOP_COMMAND_START_V1"
            or start.get("task_id") != task_id or start.get("operation_id") != operation_id
            or start.get("nonce") != manifest.get("nonce")
            or start.get("wrapper_id") != manifest.get("wrapper_id")
        ):
            return untrusted_completion("start-binding-mismatch")
        if manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT:
            if start.get("wrapper_birth"):
                try:
                    if _process_birth_identity(start.get("wrapper_pid")) == start["wrapper_birth"]:
                        return {"decision": "RUNNING", "reason": "original-wrapper-live", "manifest": manifest,
                                "manifest_hash": _hash_bytes(manifest_raw), "start": start, **root_fields}
                except ValueError:
                    pass
            return {"decision": "UNKNOWN", "reason": "original-wrapper-identity-not-observed",
                    "manifest": manifest, "manifest_hash": _hash_bytes(manifest_raw), "start": start, **root_fields}
        return {"decision": "UNKNOWN" if revoke_not_started else "PENDING", "reason": "started-without-completion"}
    completion_raw = completion_path.read_bytes()
    completion = _read_json(completion_path)
    if completion is None or completion.get("schema") != "SITINA_LOOP_COMMAND_COMPLETION_V1" or completion.get("task_id") != task_id or completion.get("operation_id") != operation_id:
        return untrusted_completion("completion-binding-mismatch")
    if completion.get("nonce") != manifest.get("nonce") or completion.get("wrapper_id") != manifest.get("wrapper_id"):
        return untrusted_completion("completion-identity-mismatch")
    if completion.get("status") not in ({"COMPLETED", "CANCELLED", "TIMED_OUT", "NOT_STARTED"} if manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT else {"COMPLETED", "CANCELLED", "TIMED_OUT"}):
        return untrusted_completion("completion-status-untrusted")
    if type(completion.get("exit_code")) is not int:
        return untrusted_completion("completion-exit-untrusted")
    ready_path = Path(str(manifest.get("ready_path") or ""))
    try:
        if ready_path.read_text(encoding="utf-8") != str(manifest.get("nonce")) + "\n":
            return untrusted_completion("completion-ready-mismatch")
    except OSError:
        return untrusted_completion("completion-ready-missing")
    separate_outcomes = manifest.get("outcome_contract") == TASK_OUTCOME_CONTRACT
    streams_complete = True
    cleanup = {}
    if separate_outcomes:
        cleanup = completion.get("process_group_cleanup")
        root = completion.get("root_result")
        if (completion.get("outcome_contract") != TASK_OUTCOME_CONTRACT
                or not isinstance(cleanup, Mapping) or cleanup.get("state") not in {"SETTLED", "UNKNOWN"}
                or cleanup.get("scope") != "PROCESS_GROUP" or not isinstance(cleanup.get("errors"), list)
                or type(completion.get("streams_complete")) is not bool):
            return untrusted_completion("completion-outcome-contract-mismatch")
        if completion["status"] != "NOT_STARTED":
            if not _root_outcome_matches(root, manifest) or root["exit_code"] != completion["exit_code"]:
                return untrusted_completion("completion-root-outcome-mismatch")
            if root_fields and root_fields["root_result"] != root:
                return untrusted_completion("root-result-conflict")
        streams_complete = completion["streams_complete"]
    stdout_path = Path(str(manifest.get("stdout_path") or ""))
    stderr_path = Path(str(manifest.get("stderr_path") or ""))
    if stdout_path.is_symlink() or stderr_path.is_symlink() or not stdout_path.is_file() or not stderr_path.is_file():
        return untrusted_completion("log-symlink")
    stdout_text, stdout_hash, stdout_retained_bytes, _ = _bounded_read(stdout_path)
    stderr_text, stderr_hash, stderr_retained_bytes, _ = _bounded_read(stderr_path)
    if completion.get("stdout_hash") != stdout_hash or completion.get("stderr_hash") != stderr_hash:
        return untrusted_completion("log-hash-mismatch")
    if (
        not isinstance(completion.get("stdout_bytes"), int)
        or not isinstance(completion.get("stderr_bytes"), int)
        or int(completion.get("stdout_bytes")) < stdout_retained_bytes
        or int(completion.get("stderr_bytes")) < stderr_retained_bytes
        or int(completion.get("stdout_retained_bytes", -1)) != stdout_retained_bytes
        or int(completion.get("stderr_retained_bytes", -1)) != stderr_retained_bytes
        or bool(completion.get("stdout_truncated")) != (int(completion.get("stdout_bytes")) > stdout_retained_bytes)
        or bool(completion.get("stderr_truncated")) != (int(completion.get("stderr_bytes")) > stderr_retained_bytes)
        or completion.get("stdout_hash_scope") != ("complete_stream" if manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT and streams_complete else "retained_prefix")
        or completion.get("stderr_hash_scope") != ("complete_stream" if manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT and streams_complete else "retained_prefix")
    ):
        return untrusted_completion("log-accounting-mismatch")
    if separate_outcomes and completion["status"] != "NOT_STARTED" and not root_fields:
        root_fields = {"root_result": dict(root), "root_result_hash": _hash_json(root),
                       "root_result_source": "trusted_completion", "trusted_root_result": True}
    settled = not separate_outcomes or (
        cleanup["state"] == "SETTLED" and streams_complete and completion.get("wrapper_error") is None)
    return {
        **root_fields,
        "decision": "SUCCEEDED" if settled else "UNKNOWN",
        "reason": ("trusted-completion" if settled else "process-group-unsettled"
                   if cleanup.get("state") != "SETTLED" else "execution-finalization-incomplete"),
        "effect_settled": settled,
        "process_group_cleanup": cleanup if separate_outcomes else None,
        "completion": completion,
        "completion_hash": _hash_bytes(completion_raw),
        "completion_raw_b64": base64.b64encode(completion_raw).decode("ascii"),
        "manifest": manifest,
        "manifest_hash": _hash_bytes(manifest_raw),
        "manifest_raw_b64": base64.b64encode(manifest_raw).decode("ascii"),
        "stdout_hash": stdout_hash,
        "stderr_hash": stderr_hash,
        "stdout_hash_scope": completion.get("stdout_hash_scope"),
        "stderr_hash_scope": completion.get("stderr_hash_scope"),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_prefix_b64": base64.b64encode(_log_prefix(stdout_path)).decode("ascii"),
        "stderr_prefix_b64": base64.b64encode(_log_prefix(stderr_path)).decode("ascii"),
        "stdout_bytes": int(completion.get("stdout_bytes")),
        "stderr_bytes": int(completion.get("stderr_bytes")),
        "stdout_retained_bytes": stdout_retained_bytes,
        "stderr_retained_bytes": stderr_retained_bytes,
        "stdout_truncated": bool(completion.get("stdout_truncated")) or stdout_retained_bytes > MAX_LOG_BYTES,
        "stderr_truncated": bool(completion.get("stderr_truncated")) or stderr_retained_bytes > MAX_LOG_BYTES,
        "raw_logs_complete": manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT and streams_complete,
    }


def request_command_cancel_evidence(evidence: Mapping[str, Any], *, task_id: str, operation_id: str, reason: str) -> bool:
    """Persist a nonce/wrapper-bound cancellation request for an existing wrapper."""
    manifest_path = Path(str(evidence.get("command_manifest_path") or ""))
    manifest = _read_json(manifest_path)
    if manifest is None or manifest_path.is_symlink():
        return False
    if (
        manifest.get("task_id") != task_id or manifest.get("operation_id") != operation_id
        or manifest.get("nonce") != evidence.get("command_nonce")
        or manifest.get("wrapper_id") != evidence.get("wrapper_id")
        or _hash_bytes(manifest_path.read_bytes()) != evidence.get("command_manifest_hash")
    ):
        return False
    cancel_path = Path(str(manifest.get("cancel_path") or ""))
    _write_json(
        cancel_path,
        {
            "schema": "SITINA_LOOP_COMMAND_CANCEL_V1",
            "task_id": task_id,
            "operation_id": operation_id,
            "nonce": manifest.get("nonce"),
            "wrapper_id": manifest.get("wrapper_id"),
            "reason": reason,
            "created_at": time.time(),
        },
    )
    return True


@dataclass(frozen=True)
class CommandCompletion:
    status: str
    exit_code: int | None
    wrapper_pid: int | None
    child_pid: int | None
    stdout: str
    stderr: str
    stdout_hash: str
    stderr_hash: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_retained_bytes: int
    stderr_retained_bytes: int
    stdout_prefix_b64: str
    stderr_prefix_b64: str
    stdout_truncated: bool
    stderr_truncated: bool
    completion_ref: str
    completion_hash: str
    manifest_ref: str
    manifest_hash: str

    @property
    def trusted(self) -> bool:
        return bool(self.completion_ref and self.completion_hash and self.status in {"COMPLETED", "CANCELLED", "TIMED_OUT"})


class CommandRunner:
    """Prepare and run one immutable command manifest.

    The parent process never pipes command stdout/stderr directly.  The
    wrapper owns private files and publishes a completion receipt only after
    the child has been waited and the logs have been fsynced.
    """

    def __init__(
        self,
        *,
        task_id: str,
        operation_id: str,
        check_root: Path,
        check_input: Path,
        check_output: Path,
        command: Sequence[str],
        interpreter: Path,
        profile: str,
        environment: Mapping[str, str],
        command_cwd: Path | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        cancel_probe: Any | None = None,
        input_snapshot: Mapping[str, str] | None = None,
        stdin_path: Path | None = None,
        input_payload: Any | None = None,
        execution_contract: str | None = None,
        pty: bool = False,
        keep: bool = False,
        terminal_dimensions: tuple[int, int] = (24, 80),
    ) -> None:
        self.task_id = str(task_id)
        self.operation_id = str(operation_id)
        self.check_root = check_root.resolve(strict=False)
        self.check_input = check_input.resolve(strict=False)
        self.check_output = check_output.resolve(strict=False)
        self.command_cwd = (command_cwd or self.check_input).resolve(strict=False)
        self.execution_contract = execution_contract
        self.policy = TASK_COMMAND_POLICY if execution_contract == TASK_EXECUTION_CONTRACT else COMMAND_POLICY
        self.pty = bool(pty)
        self.keep = bool(keep)
        self.terminal_dimensions = terminal_dimensions
        if execution_contract not in {None, TASK_EXECUTION_CONTRACT}:
            raise ValueError("unknown execution contract")
        if execution_contract is None:
            try:
                self.command_cwd.relative_to(self.check_input)
            except ValueError as error:
                raise ValueError("command cwd must remain inside the immutable input root") from error
        self.interpreter_command = Path(interpreter).expanduser()
        if not self.interpreter_command.is_absolute():
            raise ValueError("command interpreter must be an absolute path")
        self.interpreter = self.interpreter_command.resolve(strict=True)
        self.command = tuple(str(item) for item in command)
        self.profile = str(profile)
        self.environment = {str(key): str(value) for key, value in environment.items()}
        self.timeout_seconds = float(timeout_seconds)
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("command timeout must be finite and positive")
        self.cancel_probe = cancel_probe
        self.input_snapshot = dict(input_snapshot or {})
        self.stdin_path = None
        if stdin_path is not None or input_payload is not None:
            self.stdin_path = (stdin_path or (self.check_input / ".sitina-input.json")).resolve(strict=False)
            self.stdin_path.relative_to(self.check_input)
        self.input_payload = input_payload
        self.private_root = self.check_root / "private"
        self.manifest_path = self.private_root / "manifest.json"
        self.permit_path = self.private_root / "permit.json"
        self.cancel_path = self.private_root / "cancel.json"
        self.start_path = self.private_root / "start.json"
        self.completion_path = self.private_root / "completion.json"
        self.stdout_path = self.private_root / "stdout.log"
        self.stderr_path = self.private_root / "stderr.log"
        self.ready_path = self.private_root / "completion.ready"
        self.nonce = uuid.uuid4().hex
        self.wrapper_id = "wrapper-" + uuid.uuid4().hex
        self.manifest_hash = ""

    def prepare(self) -> Mapping[str, Any]:
        if self.execution_contract is None:
            if not self.command or _resolved(self.command[0]) != str(self.interpreter):
                raise ValueError("command must invoke the pinned resolved interpreter")
            if not self.profile or "(deny process-fork)" not in self.profile:
                raise ValueError("command profile must explicitly deny process-fork")
        elif (not self.command or not Path(self.command[0]).is_absolute()
              or "(deny default)" not in self.profile or "(deny network*)" not in self.profile
              or "(allow process-fork)" not in self.profile):
            raise ValueError("general command requires an absolute executable and a task process sandbox")
        self.private_root.mkdir(parents=True, exist_ok=True)
        stdin_hash: str | None = None
        if self.stdin_path is not None:
            self.stdin_path.parent.mkdir(parents=True, exist_ok=True)
            if self.stdin_path.exists() or self.stdin_path.is_symlink():
                raise ValueError("command stdin path already exists")
            payload = self.input_payload
            if not isinstance(payload, Mapping):
                payload = {
                    "schema": "SITINA_LOOP_COMMAND_INPUT_V1",
                    "task_id": self.task_id,
                    "operation_id": self.operation_id,
                }
            _write_json(self.stdin_path, payload, exclusive=True)
            stdin_hash = _hash_bytes(self.stdin_path.read_bytes())
            os.chmod(self.stdin_path, 0o444)
        os.chmod(self.private_root, 0o700)
        env = dict(self.environment)
        manifest = {
            "schema": "SITINA_LOOP_COMMAND_MANIFEST_V1",
            "policy": self.policy,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "nonce": self.nonce,
            "wrapper_id": self.wrapper_id,
            "argv": list(self.command),
            "resolved_interpreter": str(self.interpreter),
            "cwd": str(self.command_cwd),
            "input_root": str(self.check_input),
            "output_root": str(self.check_output),
            "input_identity": _hash_json({"path": str(self.check_input), "exists": self.check_input.is_dir()}),
            "input_snapshot": self.input_snapshot,
            "input_snapshot_hash": _hash_json(self.input_snapshot),
            "profile": self.profile,
            "profile_hash": _hash_bytes(self.profile.encode("utf-8")),
            "environment": env,
            "timeout_seconds": self.timeout_seconds,
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "permit_path": str(self.permit_path),
            "cancel_path": str(self.cancel_path),
            "start_path": str(self.start_path),
            "completion_path": str(self.completion_path),
            "ready_path": str(self.ready_path),
            "stdin_path": str(self.stdin_path) if self.stdin_path is not None else None,
            "stdin_hash": stdin_hash,
        }
        if self.execution_contract is not None:
            manifest.update({
                "execution_contract": self.execution_contract,
                "outcome_contract": TASK_OUTCOME_CONTRACT,
                "resolved_executable": _resolved(self.command[0]),
                "pty": self.pty, "keep": self.keep,
                "terminal_dimensions": list(self.terminal_dimensions),
                "stream_split_observed": not self.pty,
                "process_ownership_scope": "PROCESS_GROUP",
                "full_process_tree_enforced": False,
            })
        self.manifest_hash = _write_json(self.manifest_path, manifest, exclusive=True)
        os.chmod(self.manifest_path, 0o400)
        manifest_raw = self.manifest_path.read_bytes()
        return {
            "effect_kind": "command",
            "command_policy": self.policy,
            "command_manifest_path": str(self.manifest_path),
            "command_manifest_hash": self.manifest_hash,
            "manifest_raw_b64": base64.b64encode(manifest_raw).decode("ascii"),
            "manifest_raw_hash": _hash_bytes(manifest_raw),
            "command_nonce": self.nonce,
            "wrapper_id": self.wrapper_id,
            "check_input": str(self.check_input),
            "check_output": str(self.check_output),
            "completion_path": str(self.completion_path),
            "permit_path": str(self.permit_path),
            "start_path": str(self.start_path),
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "stdin_path": str(self.stdin_path) if self.stdin_path is not None else None,
            "stdin_hash": stdin_hash,
            "phase": "AUTHORIZED_NOT_STARTED",
        }

    def authorize(self, *, wrapper_launch: Mapping[str, Any]) -> None:
        permit = {
            "schema": "SITINA_LOOP_COMMAND_PERMIT_V1",
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "nonce": self.nonce,
            "wrapper_id": self.wrapper_id,
            "state": "AUTHORIZED",
            "created_at": time.time(),
            "wrapper_launch": dict(wrapper_launch),
        }
        lock_path = self.private_root / "permit.lock"
        lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            existing = _read_json(self.permit_path)
            if self.permit_path.exists() and existing is None:
                raise RuntimeError("existing command permit is unreadable and cannot be replaced")
            if existing is not None:
                if existing.get("nonce") != self.nonce or existing.get("wrapper_id") != self.wrapper_id:
                    raise RuntimeError("command permit is bound to another execution")
                if existing.get("schema") != "SITINA_LOOP_COMMAND_PERMIT_V1":
                    raise RuntimeError("command permit schema is not recognized")
                raise RuntimeError("command permit already exists; command execution cannot be repeated")
            _write_json(self.permit_path, permit)
            os.chmod(self.permit_path, 0o600)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    def request_cancel(self, *, reason: str = "cancel-requested") -> None:
        _write_json(
            self.cancel_path,
            {
                "schema": "SITINA_LOOP_COMMAND_CANCEL_V1",
                "task_id": self.task_id,
                "operation_id": self.operation_id,
                "nonce": self.nonce,
                "wrapper_id": self.wrapper_id,
                "reason": reason,
                "created_at": time.time(),
            },
        )

    def run(self) -> CommandCompletion | None:
        wrapper_script = Path(__file__).resolve(strict=True)
        wrapper_env = {
            "HOME": self.environment.get("HOME", str(self.check_root)),
            "LANG": self.environment.get("LANG", self.environment.get("LC_ALL", "C.UTF-8")),
            "PATH": self.environment.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "LC_ALL": self.environment.get("LC_ALL", "C.UTF-8"),
            "TMPDIR": self.environment.get("TMPDIR", str(self.check_root)),
        }
        wrapper_argv = [
            str(self.interpreter_command),
            "-I",
            "-S",
            "-B",
            str(wrapper_script),
            "--wrapper",
            str(self.manifest_path),
        ]
        wrapper_launch = {
            "argv": list(wrapper_argv),
            "cwd": str(self.check_root),
            "environment": dict(sorted(wrapper_env.items())),
            "resolved_interpreter": str(self.interpreter),
            "source_path": str(wrapper_script),
            "source_hash": _hash_bytes(wrapper_script.read_bytes()),
            "status": "AUTHORIZED",
        }
        self.authorize(wrapper_launch=wrapper_launch)
        process: subprocess.Popen[bytes] | None = None
        launch_status = ""
        wrapper_stdout = b""
        wrapper_stderr = b""
        wrapper_exception: str | None = None
        try:
            process = subprocess.Popen(
                wrapper_argv,
                cwd=str(self.check_root),
                env=wrapper_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            launch_status = "SPAWN_EXCEPTION"
            wrapper_exception = f"{type(error).__name__}: {error}"
            wrapper_stderr = (wrapper_exception + "\n").encode("utf-8", errors="replace")

        deadline = time.monotonic() + self.timeout_seconds + 10.0
        startup_deadline = time.monotonic() + min(self.timeout_seconds, 6.0)
        cancel_sent = False
        while process is not None and process.poll() is None:
            if not cancel_sent and self.cancel_probe is not None:
                try:
                    cancel_sent = bool(self.cancel_probe())
                except BaseException:
                    cancel_sent = False
                if cancel_sent:
                    self.request_cancel()
            if (
                time.monotonic() >= startup_deadline
                and not self.start_path.exists()
                and not self.completion_path.exists()
            ):
                launch_status = "START_TIMEOUT"
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except OSError:
                    pass
                try:
                    wrapper_stdout, wrapper_stderr = process.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        wrapper_stdout, wrapper_stderr = process.communicate(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        return None
                break
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)
        if process is not None and not launch_status:
            wrapper_stdout, wrapper_stderr = process.communicate()
            launch_status = "EXITED"

        lock_path = self.private_root / "permit.lock"
        lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            permit = _read_json(self.permit_path)
            if permit is not None and _permit_matches(
                {
                    "task_id": self.task_id,
                    "operation_id": self.operation_id,
                    "nonce": self.nonce,
                    "wrapper_id": self.wrapper_id,
                },
                permit,
                states={"AUTHORIZED", "CLAIMED", "STARTED", "COMPLETED", "REVOKED_NOT_STARTED"},
            ):
                recorded = dict(permit)
                recorded_launch = dict(recorded.get("wrapper_launch") or {})
                recorded_launch.update(
                    {
                        "status": launch_status,
                        "return_code": (int(process.returncode) if process is not None and process.returncode is not None else None),
                        "exception": wrapper_exception,
                        "stdout_bytes": len(wrapper_stdout),
                        "stderr_bytes": len(wrapper_stderr),
                        "stdout_prefix_b64": base64.b64encode(wrapper_stdout[:MAX_LOG_BYTES]).decode("ascii"),
                        "stderr_prefix_b64": base64.b64encode(wrapper_stderr[:MAX_LOG_BYTES]).decode("ascii"),
                        "stdout_truncated": len(wrapper_stdout) > MAX_LOG_BYTES,
                        "stderr_truncated": len(wrapper_stderr) > MAX_LOG_BYTES,
                        "finished_at": time.time(),
                    }
                )
                recorded["wrapper_launch"] = recorded_launch
                if (
                    recorded.get("state") == "AUTHORIZED"
                    and not self.start_path.exists()
                    and not self.completion_path.exists()
                    and (process is None or process.poll() is not None)
                ):
                    recorded["state"] = "REVOKED_NOT_STARTED"
                    recorded["revoked_at"] = time.time()
                _write_json(self.permit_path, recorded)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

        completion = _read_json(self.completion_path)
        if completion is None:
            return None
        if self.execution_contract is not None and (
                completion.get("outcome_contract") != TASK_OUTCOME_CONTRACT
                or not isinstance(completion.get("process_group_cleanup"), Mapping)
                or completion["process_group_cleanup"].get("state") != "SETTLED"
                or completion.get("streams_complete") is not True
                or completion.get("wrapper_error") is not None):
            return None
        manifest = _read_json(self.manifest_path)
        if manifest is None or self.manifest_path.is_symlink():
            return None
        manifest_raw = self.manifest_path.read_bytes()
        manifest_hash = _hash_bytes(manifest_raw)
        if (
            manifest_hash != self.manifest_hash
            or manifest.get("task_id") != self.task_id
            or manifest.get("operation_id") != self.operation_id
            or manifest.get("nonce") != self.nonce
            or manifest.get("wrapper_id") != self.wrapper_id
            or manifest.get("policy") != self.policy
            or manifest.get("profile_hash") != _hash_bytes(str(manifest.get("profile") or "").encode("utf-8"))
        ):
            return None
        if (
            completion.get("task_id") != self.task_id
            or completion.get("operation_id") != self.operation_id
            or completion.get("nonce") != self.nonce
            or completion.get("wrapper_id") != self.wrapper_id
        ):
            return None
        if (
            self.stdout_path.is_symlink()
            or self.stderr_path.is_symlink()
            or self.completion_path.is_symlink()
            or not self.stdout_path.is_file()
            or not self.stderr_path.is_file()
        ):
            return None
        stdout, stdout_hash, stdout_retained_bytes, _ = _bounded_read(self.stdout_path)
        stderr, stderr_hash, stderr_retained_bytes, _ = _bounded_read(self.stderr_path)
        numeric_fields = (
            "stdout_retained_bytes", "stderr_retained_bytes", "stdout_bytes", "stderr_bytes",
        )
        if (
            any(not isinstance(completion.get(field), int) for field in numeric_fields)
            or not isinstance(completion.get("exit_code"), int)
        ):
            return None
        ready_ok = False
        try:
            ready_ok = self.ready_path.read_text(encoding="utf-8") == self.nonce + "\n"
        except OSError:
            ready_ok = False
        if (
            not ready_ok
            or completion.get("stdout_hash") != stdout_hash
            or completion.get("stderr_hash") != stderr_hash
            or str(manifest.get("completion_path")) != str(self.completion_path)
            or int(completion.get("stdout_retained_bytes", -1)) != stdout_retained_bytes
            or int(completion.get("stderr_retained_bytes", -1)) != stderr_retained_bytes
            or int(completion.get("stdout_bytes", -1)) < stdout_retained_bytes
            or int(completion.get("stderr_bytes", -1)) < stderr_retained_bytes
            or completion.get("stdout_hash_scope") != ("complete_stream" if self.execution_contract else "retained_prefix")
            or completion.get("stderr_hash_scope") != ("complete_stream" if self.execution_contract else "retained_prefix")
        ):
            return None
        stdout_bytes = int(completion.get("stdout_bytes"))
        stderr_bytes = int(completion.get("stderr_bytes"))
        stdout_truncated = bool(completion.get("stdout_truncated"))
        stderr_truncated = bool(completion.get("stderr_truncated"))
        if stdout_truncated != (stdout_bytes > stdout_retained_bytes) or stderr_truncated != (stderr_bytes > stderr_retained_bytes):
            return None
        completion_ref = str(self.completion_path)
        completion_hash = _hash_bytes(self.completion_path.read_bytes())
        stdout_prefix_b64 = base64.b64encode(_log_prefix(self.stdout_path)).decode("ascii")
        stderr_prefix_b64 = base64.b64encode(_log_prefix(self.stderr_path)).decode("ascii")
        return CommandCompletion(
            status=str(completion.get("status") or "UNKNOWN"),
            exit_code=(int(completion["exit_code"]) if completion.get("exit_code") is not None else None),
            wrapper_pid=(int(completion["wrapper_pid"]) if completion.get("wrapper_pid") is not None else None),
            child_pid=(int(completion["child_pid"]) if completion.get("child_pid") is not None else None),
            stdout=stdout,
            stderr=stderr,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_retained_bytes=stdout_retained_bytes,
            stderr_retained_bytes=stderr_retained_bytes,
            stdout_prefix_b64=stdout_prefix_b64,
            stderr_prefix_b64=stderr_prefix_b64,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            completion_ref=completion_ref,
            completion_hash=completion_hash,
            manifest_ref=str(self.manifest_path),
            manifest_hash=self.manifest_hash,
        )


class ManagedCommandUnsettled(RuntimeError):
    pass


_MANAGED_COMMAND_RUNS: dict[tuple[str, str], dict[str, Any]] = {}
_MANAGED_COMMAND_LOCK = threading.RLock()


def start_managed_command(runner: "CommandRunner") -> None:
    """Start only an already-prepared command; durable ownership belongs to Journal."""
    key = (str(runner.manifest_path), str(runner.manifest_hash))
    context = contextvars.copy_context()
    state: dict[str, Any] = {"error_type": None}

    def execute() -> None:
        try:
            state["completion"] = context.run(runner.run)
        except BaseException as error:
            # A thread exception does not prove the wrapper or child never ran.
            state["error_type"] = type(error).__name__

    thread = threading.Thread(target=execute, name="sitina-command-" + runner.operation_id, daemon=True)
    state["thread"] = thread
    with _MANAGED_COMMAND_LOCK:
        if key in _MANAGED_COMMAND_RUNS:
            raise RuntimeError("managed command launch has already been attempted")
        _MANAGED_COMMAND_RUNS[key] = state
        try:
            thread.start()
        except BaseException:
            state["error_type"] = "ThreadStartFailed"
            raise


def observe_managed_command(
    evidence: Mapping[str, Any], *, task_id: str, operation_id: str,
    stop: bool = False, reason: str = "managed-process-stop",
) -> dict[str, Any]:
    """Use nonce-bound receipts, never persisted PIDs, as lifecycle authority."""
    key = (str(evidence.get("command_manifest_path") or ""), str(evidence.get("command_manifest_hash") or ""))
    observation = observe_command_evidence(
        evidence, task_id=task_id, operation_id=operation_id, revoke_not_started=False,
    )
    if observation.get("decision") in {"SUCCEEDED", "NO_EFFECT"}:
        with _MANAGED_COMMAND_LOCK:
            active = _MANAGED_COMMAND_RUNS.get(key)
            if active is not None and not active["thread"].is_alive():
                _MANAGED_COMMAND_RUNS.pop(key, None)
        return observation
    with _MANAGED_COMMAND_LOCK:
        active = _MANAGED_COMMAND_RUNS.get(key)
        live = bool(active is not None and active["thread"].is_alive() and not active.get("error_type"))
    if not stop:
        if observation.get("decision") == "RUNNING" or (live and observation.get("decision") == "PENDING"):
            manifest = _read_json(Path(key[0]))
            logs: dict[str, Any] = {}
            if manifest is not None:
                for stream in ("stdout", "stderr"):
                    path = Path(str(manifest.get(stream + "_path") or ""))
                    if path.is_file() and not path.is_symlink():
                        value, _, _, truncated = _bounded_read(path)
                        logs[stream] = value
                        logs[stream + "_truncated"] = truncated
            return {**observation, **logs, "decision": "RUNNING"}
        return {**observation, "decision": "UNKNOWN"}
    if observation.get("decision") not in {"PENDING", "RUNNING", "NO_EFFECT"}:
        return {**observation, "decision": "UNKNOWN"}
    if not request_command_cancel_evidence(
        evidence, task_id=task_id, operation_id=operation_id, reason=reason,
    ):
        return {"decision": "UNKNOWN", "reason": "managed-cancel-binding-rejected"}
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        observation = observe_command_evidence(
            evidence, task_id=task_id, operation_id=operation_id, revoke_not_started=False,
        )
        if observation.get("decision") == "SUCCEEDED":
            return observation
        if observation.get("decision") not in {"PENDING", "RUNNING"}:
            return {**observation, "decision": "UNKNOWN"}
        with _MANAGED_COMMAND_LOCK:
            active = _MANAGED_COMMAND_RUNS.get(key)
            live = bool(active is not None and active["thread"].is_alive())
        if not live and observation.get("reason") == "authorized-not-started":
            return observe_command_evidence(evidence, task_id=task_id, operation_id=operation_id)
        time.sleep(0.05)
    return {"decision": "UNKNOWN", "reason": "managed-stop-has-no-trusted-completion"}


def managed_command_public_result(
    observation: Mapping[str, Any], *, operation_id: str, include_logs: bool = False,
    tail_lines: int = 200,
) -> dict[str, Any]:
    completion = observation.get("completion")
    completion = completion if isinstance(completion, Mapping) else {}
    decision = str(observation.get("decision") or "UNKNOWN")
    result = {
        "process_id": operation_id,
        "owner_operation_id": operation_id,
        "state": "stopped" if decision in {"SUCCEEDED", "NO_EFFECT"} else "running" if decision == "RUNNING" else "unknown",
        "effect_settled": decision in {"SUCCEEDED", "NO_EFFECT"},
        "recovery_decision": decision,
        "reason": observation.get("reason"),
        "returncode": completion.get("exit_code"),
        "completion_status": completion.get("status"),
        "completion_hash": observation.get("completion_hash"),
        "manifest_hash": observation.get("manifest_hash"),
    }
    if include_logs and decision in {"SUCCEEDED", "RUNNING"}:
        from sitina.security.redaction import redact_text
        count = max(1, min(int(tail_lines), 2000))
        result["stdout"] = redact_text("\n".join(str(observation.get("stdout") or "").splitlines()[-count:]))[-65536:]
        result["stderr"] = redact_text("\n".join(str(observation.get("stderr") or "").splitlines()[-count:]))[-65536:]
        result["stdout_truncated"] = bool(observation.get("stdout_truncated"))
        result["stderr_truncated"] = bool(observation.get("stderr_truncated"))
    elif include_logs:
        result["log_status"] = "awaiting_trusted_completion"
    return result


def _log_prefix(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(MAX_LOG_BYTES)


def _process_identity_snapshot(pid: int) -> dict[str, Any]:
    """Return the kernel's microsecond creation identity on supported macOS.

    This helper uses only ctypes and the standard library internally, so an
    installed command wrapper can import the same implementation immediately
    after Popen.  No ps timestamp or PID-only fallback is permitted.
    ABI: Apple's xnu bsd/sys/proc_info.h, proc_bsdinfo / PROC_PIDTBSDINFO.
    """
    import ctypes

    if sys.platform != "darwin" or not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError("PROCESS_BIRTH_INSPECTION_UNAVAILABLE")

    class ProcBSDInfo(ctypes.Structure):
        _fields_ = [
            ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
            ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
            ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
            ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
            ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
            ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
            ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
            ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
            ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
            ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
            ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
        ]

    if ctypes.sizeof(ProcBSDInfo) != 136:
        raise ValueError("PROCESS_BIRTH_ABI_UNSUPPORTED")
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_pidinfo
        function.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int
        record = ProcBSDInfo()
        count = function(pid, 3, 0, ctypes.byref(record), ctypes.sizeof(record))
    except (OSError, AttributeError) as exc:
        raise ValueError("PROCESS_BIRTH_INSPECTION_UNAVAILABLE") from exc
    if count != ctypes.sizeof(record) or record.pbi_pid != pid or record.pbi_start_tvsec <= 0 or record.pbi_start_tvusec >= 1_000_000:
        raise ValueError("PROCESS_BIRTH_IDENTITY_NOT_OBSERVED")
    return {
        "pid": int(record.pbi_pid), "ppid": int(record.pbi_ppid),
        "process_group": int(record.pbi_pgid), "effective_uid": int(record.pbi_uid),
        "real_uid": int(record.pbi_ruid), "effective_gid": int(record.pbi_gid),
        "state": int(record.pbi_status),
        "birth": f"macos-proc-bsdinfo-v1:{pid}:{record.pbi_start_tvsec}:{record.pbi_start_tvusec:06d}",
    }


def _process_birth_identity(pid: int) -> str:
    return str(_process_identity_snapshot(pid)["birth"])


def _process_group_snapshot(pgid: int) -> dict[str, Any]:
    """Bounded, contemporaneous diagnostic; never proof that a group is gone."""
    import ctypes

    value = {"process_group": pgid, "at": time.time(), "monotonic": time.monotonic(),
             "observer_pid": os.getpid(), "observer_uid": os.getuid(),
             "observer_euid": os.geteuid(), "members": [], "errors": [], "truncated": False}
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_listpgrppids
        function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        function.restype = ctypes.c_int
        pids = (ctypes.c_int * 256)()
        ctypes.set_errno(0)
        count = function(pgid, pids, ctypes.sizeof(pids))
        error_number = ctypes.get_errno()
        if count < 0 or (count == 0 and error_number):
            raise OSError(error_number, "process-group membership inspection failed")
        value["truncated"] = count >= len(pids)
        for pid in pids[:min(count, len(pids))]:
            if pid <= 0:
                continue
            try:
                value["members"].append(_process_identity_snapshot(pid))
            except (OSError, ValueError) as error:
                value["errors"].append({"pid": pid, "error_type": type(error).__name__,
                                        "error": str(error)[:500]})
    except (OSError, ValueError, AttributeError) as error:
        value["errors"].append({"error_type": type(error).__name__, "error": str(error)[:500]})
    return value


def _root_outcome_matches(value: Any, manifest: Mapping[str, Any]) -> bool:
    return bool(isinstance(value, Mapping) and value.get("schema") == "SITINA_ROOT_PROCESS_RESULT_V1"
                and all(value.get(key) == manifest.get(key)
                        for key in ("task_id", "operation_id", "nonce", "wrapper_id"))
                and type(value.get("exit_code")) is int and value.get("root_status") == "EXITED")


def _read_root_outcome(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("outcome_contract") != "ROOT_PROCESS_AND_GROUP_V1":
        return {}
    path = Path(manifest["completion_path"]).parent / "root-result.json"
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError):
        return {}
    if path.is_symlink() or not _root_outcome_matches(value, manifest):
        return {}
    return {"root_result": value, "root_result_hash": _hash_bytes(raw),
            "root_result_raw_b64": base64.b64encode(raw).decode("ascii"),
            "root_result_source": "root_receipt", "trusted_root_result": True}


def _run_task_child(manifest: Mapping[str, Any]) -> int:
    """Run the task contract under the existing one-shot permit and receipts.

    Logs retain every byte. PTY output is one actual merged stream; ordinary
    pipes retain their identities and an ordered stream index. The command
    cannot read or write these private control/receipt paths.
    """
    if not _manifest_command_boundary(manifest):
        return 75
    private = Path(manifest["stdout_path"]).parent
    stdout_path, stderr_path = Path(manifest["stdout_path"]), Path(manifest["stderr_path"])
    control_path = private / "control.jsonl"
    child = None
    master = slave = None
    status, code = "COMPLETED", None
    control_cursor = 0
    deadline = time.monotonic() + float(manifest["timeout_seconds"])
    counts = {"stdout": 0, "stderr": 0}
    hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    streams = {}
    pty_mode = bool(manifest["pty"])
    sequence = 0
    pending_input = bytearray()
    pending_requests = []
    root_result = None
    cleanup_state = "UNKNOWN"
    cleanup_errors = []
    wrapper_error = None
    streams_complete = False

    def remember_error(action, error, sig=None):
        key = (action, sig, getattr(error, "errno", None), type(error).__name__)
        if any(tuple(item["key"]) == key for item in cleanup_errors):
            return
        if len(cleanup_errors) >= 32:
            return
        item = {"key": list(key), "action": action, "signal": sig,
                "error_type": type(error).__name__, "errno": getattr(error, "errno", None),
                "error": str(error)[:1000], "at": time.time(), "monotonic": time.monotonic()}
        if child is not None:
            item["process_group_snapshot"] = _process_group_snapshot(child.pid)
        cleanup_errors.append(item)
        try:
            _write_json(private / "cleanup-observation.json", {
                "schema": "SITINA_PROCESS_GROUP_OBSERVATION_V1",
                **{key: manifest[key] for key in ("task_id", "operation_id", "nonce", "wrapper_id")},
                "state": cleanup_state, "errors": cleanup_errors})
        except OSError:
            # Receipt I/O must not interrupt attempts to preserve the root outcome.
            pass

    def remember_root(exit_code):
        nonlocal root_result, code
        code = int(exit_code)
        if root_result is not None:
            return
        root_result = {"schema": "SITINA_ROOT_PROCESS_RESULT_V1",
            **{key: manifest[key] for key in ("task_id", "operation_id", "nonce", "wrapper_id")},
            "root_status": "EXITED", "exit_code": code, "status": status,
            "child_pid": child.pid, "at": time.time(), "monotonic": time.monotonic()}
        try:
            _write_json(private / "root-result.json", root_result, exclusive=True)
        except OSError as error:
            remember_error("root_result_persistence", error)


    def acknowledge(request, cursor, state, reason=None):
        ack = {"request_id": request["request_id"], "action": request["action"], "state": state,
               "cursor": cursor, "applied": state == "APPLIED", "at": time.time()}
        if reason is not None:
            ack["reason"] = reason
        directory = private / "control-acks"
        directory.mkdir(exist_ok=True)
        key = hashlib.sha256(request["request_id"].encode("ascii")).hexdigest()
        _write_json(directory / (key + ".json"), ack)
        _write_json(private / "control-ack.json", ack)

    def reject_pending(reason):
        for item in pending_requests:
            acknowledge(item["request"], item["cursor"], "REJECTED", reason)
        pending_requests.clear()
        pending_input.clear()

    def group_alive() -> bool | None:
        nonlocal cleanup_state
        if child is None:
            return False
        try:
            os.killpg(child.pid, 0)
            return True
        except ProcessLookupError:
            cleanup_state = "SETTLED"
            return False
        except OSError as error:
            cleanup_state = "UNKNOWN"
            remember_error("group_probe", error, 0)
            return None

    def terminate_group(sig: int) -> str:
        nonlocal cleanup_state
        if child is None:
            return "ABSENT"
        try:
            os.killpg(child.pid, sig)
            return "SENT"
        except ProcessLookupError:
            cleanup_state = "SETTLED"
            return "ABSENT"
        except OSError as error:
            cleanup_state = "UNKNOWN"
            remember_error("group_signal", error, int(sig))
            return "UNKNOWN"

    try:
        with stdout_path.open("xb") as out, stderr_path.open("xb") as err, (private / "stream-index.jsonl").open("xb") as index:
            handles = {"stdout": out, "stderr": err}
            try:
                if pty_mode:
                    master, slave = pty.openpty()
                    rows, columns = manifest.get("terminal_dimensions", [24, 80])
                    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
                    def terminal_session():
                        os.setsid()
                        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                    child = subprocess.Popen(
                        ["/usr/bin/sandbox-exec", "-p", manifest["profile"], "--", *manifest["argv"]],
                        cwd=manifest["cwd"], env=manifest["environment"],
                        stdin=slave, stdout=slave, stderr=slave, close_fds=True, preexec_fn=terminal_session)
                    os.close(slave)
                    slave = None
                    os.set_blocking(master, False)
                    streams[master] = "stdout"
                else:
                    child = subprocess.Popen(
                        ["/usr/bin/sandbox-exec", "-p", manifest["profile"], "--", *manifest["argv"]],
                        cwd=manifest["cwd"], env=manifest["environment"], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
                    streams[child.stdout.fileno()] = "stdout"
                    streams[child.stderr.fileno()] = "stderr"
                    os.set_blocking(child.stdin.fileno(), False)
                start_path = Path(manifest["start_path"])
                start = _read_json(start_path) or {}
                try:
                    child_birth = _process_birth_identity(child.pid)
                except ValueError:
                    child_birth = None
                start.update({"child_pid": child.pid, "child_birth": child_birth, "process_group": child.pid,
                              "execution_contract": TASK_EXECUTION_CONTRACT, "pty": pty_mode,
                              "declared_child_environment": dict(manifest["environment"]),
                              "actual_child_environment": "NOT_OBSERVED"})
                _write_json(start_path, start)
            except (OSError, subprocess.SubprocessError) as error:
                status, code = "NOT_STARTED", 127
                raw = (type(error).__name__ + ": " + str(error) + "\n").encode("utf-8")
                err.write(raw)
                hashes["stderr"].update(raw)
                counts["stderr"] += len(raw)

            last_signal = None
            while child is not None:
                if control_path.is_file():
                    with control_path.open("rb") as controls:
                        controls.seek(control_cursor)
                        for line in controls:
                            if not line.endswith(b"\n"):
                                break
                            request = json.loads(line)
                            if request.get("nonce") != manifest["nonce"]:
                                raise ValueError("control nonce mismatch")
                            action = request["action"]
                            control_cursor = controls.tell()
                            live = child.poll() is None
                            if action == "input" and live:
                                data = base64.b64decode(request["data"], validate=True)
                                if not data:
                                    acknowledge(request, control_cursor, "APPLIED")
                                elif len(pending_input) + len(data) <= 1024 * 1024:
                                    pending_input.extend(data)
                                    pending_requests.append({"request": request, "cursor": control_cursor, "remaining": len(data)})
                                    acknowledge(request, control_cursor, "QUEUED")
                                else:
                                    acknowledge(request, control_cursor, "REJECTED", "input_queue_capacity")
                            elif action == "interrupt" and live:
                                sent = terminate_group(signal.SIGINT)
                                acknowledge(request, control_cursor, "REJECTED" if sent == "UNKNOWN" else "APPLIED",
                                            "process_group_signal_unconfirmed" if sent == "UNKNOWN" else None)
                            elif action == "stop" and live:
                                sent = terminate_group(signal.SIGTERM)
                                if sent != "UNKNOWN":
                                    status = "CANCELLED"
                                last_signal = time.monotonic()
                                acknowledge(request, control_cursor, "REJECTED" if sent == "UNKNOWN" else "APPLIED",
                                            "process_group_signal_unconfirmed" if sent == "UNKNOWN" else None)
                            elif action == "resize" and pty_mode and live:
                                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", request["rows"], request["columns"], 0, 0))
                                acknowledge(request, control_cursor, "APPLIED")
                            elif action in {"takeover", "release"} and live:
                                acknowledge(request, control_cursor, "APPLIED")
                            else:
                                acknowledge(request, control_cursor, "REJECTED", "control_unavailable_for_original_process")
                if pending_input and child.poll() is None:
                    fd = master if pty_mode else child.stdin.fileno()
                    _, writable, _ = select.select([], [fd], [], 0)
                    if writable:
                        try:
                            written = os.write(fd, pending_input)
                            del pending_input[:written]
                            while written and pending_requests:
                                item = pending_requests[0]
                                consumed = min(written, item["remaining"])
                                item["remaining"] -= consumed
                                written -= consumed
                                if item["remaining"] == 0:
                                    acknowledge(item["request"], item["cursor"], "APPLIED")
                                    pending_requests.pop(0)
                        except BrokenPipeError:
                            reject_pending("original_process_closed_input")
                elif pending_input:
                    reject_pending("original_process_exited_before_input_delivery")
                cancel = _read_json(Path(manifest["cancel_path"]))
                cancelling = bool(cancel and cancel.get("nonce") == manifest["nonce"] and cancel.get("wrapper_id") == manifest["wrapper_id"])
                timed_out = time.monotonic() >= deadline
                if last_signal is None and (cancelling or timed_out):
                    requested_status = "CANCELLED" if cancelling else "TIMED_OUT"
                    if terminate_group(signal.SIGTERM) != "UNKNOWN":
                        status = requested_status
                    last_signal = time.monotonic()
                if last_signal is not None and time.monotonic() - last_signal >= 2:
                    terminate_group(signal.SIGKILL)
                ready, _, _ = select.select(list(streams), [], [], 0.05)
                for fd in ready:
                    try:
                        raw = os.read(fd, 65536)
                    except OSError as error:
                        if pty_mode and error.errno == errno.EIO:
                            raw = b""
                        elif error.errno == errno.EAGAIN:
                            continue
                        else:
                            raise
                    if not raw:
                        streams.pop(fd, None)
                        continue
                    stream = streams[fd]
                    before = counts[stream]
                    handles[stream].write(raw)
                    handles[stream].flush()
                    hashes[stream].update(raw)
                    counts[stream] += len(raw)
                    index.write((json.dumps({"sequence": sequence, "stream": "combined" if pty_mode else stream,
                                 "offset": before, "bytes": len(raw), "at": time.time()}) + "\n").encode("ascii"))
                    index.flush()
                    sequence += 1
                observed_code = child.poll()
                if observed_code is not None:
                    remember_root(observed_code)
                    # Root outcome survives even if group inspection or cleanup is denied.
                    alive = group_alive()
                    if last_signal is None and alive is not False:
                        terminate_group(signal.SIGTERM)
                        last_signal = time.monotonic()
                    if not streams and alive is False:
                        streams_complete = True
                        break
                    if not streams and alive is None:
                        streams_complete = True
                        # A transient inspection failure may clear inside the existing
                        # bounded cleanup window.  It is never an absence observation.
                    if last_signal is not None and time.monotonic() - last_signal >= 5:
                        break
            if child is None:
                cleanup_state = "SETTLED"
                streams_complete = True
            for handle in (out, err, index):
                handle.flush()
                os.fsync(handle.fileno())
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        wrapper_error = {"error_type": type(error).__name__, "errno": getattr(error, "errno", None),
                         "error": str(error)[:1000], "at": time.time()}
        remember_error("wrapper_execution", error)
        terminate_group(signal.SIGKILL)
        if child is not None:
            try:
                remember_root(child.wait(timeout=2))
                group_alive()
            except (subprocess.TimeoutExpired, OSError) as wait_error:
                remember_error("root_wait", wait_error)
    finally:
        for fd in (master, slave):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if child is not None:
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError as error:
                        remember_error("stream_close", error)
    if code is None:
        return 77
    completion = {
        "schema": "SITINA_LOOP_COMMAND_COMPLETION_V1",
        "task_id": manifest["task_id"], "operation_id": manifest["operation_id"],
        "nonce": manifest["nonce"], "wrapper_id": manifest["wrapper_id"],
        "wrapper_pid": os.getpid(), "child_pid": child.pid if child is not None else None,
        "status": status, "exit_code": code, "execution_contract": TASK_EXECUTION_CONTRACT,
        "outcome_contract": "ROOT_PROCESS_AND_GROUP_V1",
        "root_result": root_result, "root_status": "EXITED" if root_result is not None else "NOT_STARTED",
        "process_group_cleanup": {"state": cleanup_state, "errors": cleanup_errors,
                                  "scope": "PROCESS_GROUP"},
        "streams_complete": streams_complete, "wrapper_error": wrapper_error,
        "stream_split_observed": not pty_mode, "completed_at": time.time(),
        "stdout_hash": "sha256:" + hashes["stdout"].hexdigest(),
        "stderr_hash": "sha256:" + hashes["stderr"].hexdigest(),
        "stdout_bytes": counts["stdout"], "stderr_bytes": counts["stderr"],
        "stdout_retained_bytes": counts["stdout"], "stderr_retained_bytes": counts["stderr"],
        "stdout_hash_scope": "complete_stream" if streams_complete else "retained_prefix",
        "stderr_hash_scope": "complete_stream" if streams_complete else "retained_prefix",
        "stdout_truncated": False, "stderr_truncated": False,
    }
    _write_json(Path(manifest["completion_path"]), completion)
    permit_path = Path(manifest["permit_path"])
    permit = _read_json(permit_path) or {}
    permit.update({"state": "COMPLETED", "completed_at": time.time()})
    _write_json(permit_path, permit)
    ready_path = Path(manifest["ready_path"])
    with ready_path.open("xb") as handle:
        handle.write((manifest["nonce"] + "\n").encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_dir(private)
    return 0

def _wrapper(manifest_path: Path) -> int:
    manifest = _read_json(manifest_path)
    if manifest is None or manifest.get("policy") not in {COMMAND_POLICY, TASK_COMMAND_POLICY}:
        return 71
    permit_path = Path(str(manifest["permit_path"]))
    permit = _read_json(permit_path)
    if not _permit_matches(manifest, permit, states={"AUTHORIZED"}):
        return 72
    private_root = manifest_path.parent
    lock_path = private_root / "permit.lock"
    lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 73
        permit = _read_json(permit_path)
        if not _permit_matches(manifest, permit, states={"AUTHORIZED"}):
            return 74
        if Path(str(manifest["start_path"])).exists() or Path(str(manifest["completion_path"])).exists():
            return 75
        claimed = dict(permit)
        claimed["state"] = "CLAIMED"
        claimed["claimed_at"] = time.time()
        _write_json(permit_path, claimed)
        start = {
            "schema": "SITINA_LOOP_COMMAND_START_V1",
            "task_id": manifest["task_id"],
            "operation_id": manifest["operation_id"],
            "nonce": manifest["nonce"],
            "wrapper_id": manifest["wrapper_id"],
            "wrapper_pid": os.getpid(),
            "started_at": time.time(),
        }
        if manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT:
            try:
                start["wrapper_birth"] = _process_birth_identity(os.getpid())
            except ValueError:
                start["wrapper_birth"] = None
        _write_json(Path(str(manifest["start_path"])), start)
    except OSError:
        return 76

    if manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT:
        try:
            return _run_task_child(manifest)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    stdout_path = Path(str(manifest["stdout_path"]))
    stderr_path = Path(str(manifest["stderr_path"]))
    stdout_path.touch(mode=0o600, exist_ok=True)
    stderr_path.touch(mode=0o600, exist_ok=True)
    command = [str(item) for item in manifest["argv"]]
    executable = _resolved(command[0])
    if executable != str(manifest["resolved_interpreter"]):
        return 75
    env = {str(key): str(value) for key, value in dict(manifest.get("environment") or {}).items()}
    env["PATH"] = env.get("PATH", "/usr/bin:/bin")
    profile = str(manifest["profile"])
    child: subprocess.Popen[bytes] | None = None
    status = "COMPLETED"
    exit_code: int | None = None
    deadline = time.monotonic() + float(manifest.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
    stdout_hash = hashlib.sha256()
    stderr_hash = hashlib.sha256()
    stdout_bytes = 0
    stderr_bytes = 0
    stdout_retained_bytes = 0
    stderr_retained_bytes = 0

    def drain_ready(out, err, *, block: bool = False) -> bool:
        nonlocal stdout_bytes, stderr_bytes, stdout_retained_bytes, stderr_retained_bytes
        streams = [
            stream
            for stream in (
                getattr(child, "stdout", None) if child is not None else None,
                getattr(child, "stderr", None) if child is not None else None,
            )
            if stream is not None
        ]
        if not streams:
            return False
        try:
            ready, _, _ = select.select(streams, [], [], 0.2 if block else 0.0)
        except (OSError, ValueError):
            return False
        for stream in ready:
            chunk = os.read(stream.fileno(), 65536)
            if not chunk:
                try:
                    stream.close()
                except OSError:
                    pass
                if child is not None:
                    if stream is getattr(child, "stdout", None):
                        child.stdout = None
                    elif stream is getattr(child, "stderr", None):
                        child.stderr = None
                continue
            if stream is child.stdout:
                stdout_bytes += len(chunk)
                prior = min(stdout_retained_bytes, MAX_LOG_BYTES)
                stdout_hash.update(chunk[: MAX_LOG_BYTES - prior])
                if prior < MAX_LOG_BYTES:
                    retained = chunk[: MAX_LOG_BYTES - prior]
                    out.write(retained)
                    out.flush()
                    stdout_retained_bytes += len(retained)
            else:
                stderr_bytes += len(chunk)
                prior = min(stderr_retained_bytes, MAX_LOG_BYTES)
                stderr_hash.update(chunk[: MAX_LOG_BYTES - prior])
                if prior < MAX_LOG_BYTES:
                    retained = chunk[: MAX_LOG_BYTES - prior]
                    err.write(retained)
                    err.flush()
                    stderr_retained_bytes += len(retained)
        return bool(ready)

    def reap_after_signal(sig: int) -> int:
        assert child is not None
        if child.poll() is None:
            child.send_signal(sig)
        deadline_reap = time.monotonic() + 2.0
        while child.poll() is None and time.monotonic() < deadline_reap:
            drain_ready(out, err, block=True)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2.0)
        return int(child.returncode)

    try:
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            stdin_handle = subprocess.DEVNULL
            stdin_value = manifest.get("stdin_path")
            stdin_error: str | None = None
            if stdin_value:
                try:
                    stdin_path = Path(str(stdin_value))
                    if stdin_path.is_symlink() or not stdin_path.is_file():
                        raise OSError("declared stdin input is not a regular file")
                    stdin_handle = stdin_path.open("rb")
                    declared_hash = manifest.get("stdin_hash")
                    stdin_raw = stdin_handle.read()
                    stdin_handle.seek(0)
                    if not isinstance(declared_hash, str) or _hash_bytes(stdin_raw) != declared_hash:
                        raise OSError("declared stdin input hash does not match the manifest")
                except OSError as error:
                    # A declared input is part of the execution binding.  Do
                    # not silently substitute DEVNULL when it cannot be read.
                    stdin_error = f"declared stdin input is unreadable: {error}\n"
                    if stdin_handle is not subprocess.DEVNULL and hasattr(stdin_handle, "close"):
                        stdin_handle.close()
                    stdin_handle = subprocess.DEVNULL
            if stdin_error is not None:
                status = "NOT_STARTED"
                exit_code = 127
                diagnostic = stdin_error.encode("utf-8", errors="replace")
                stderr_hash.update(diagnostic[:MAX_LOG_BYTES])
                stderr_bytes = len(diagnostic)
                retained = diagnostic[:MAX_LOG_BYTES]
                err.write(retained)
                err.flush()
                stderr_retained_bytes = len(retained)
            else:
                try:
                    child = subprocess.Popen(
                        ["/usr/bin/sandbox-exec", "-p", profile, "--", *command],
                        cwd=str(manifest["cwd"]),
                        env=env,
                        stdin=stdin_handle,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        close_fds=True,
                        start_new_session=True,
                    )
                except (OSError, subprocess.SubprocessError):
                    status = "NOT_STARTED"
                    child = None
                finally:
                    if hasattr(stdin_handle, "close"):
                        stdin_handle.close()
            while True:
                if child is None:
                    break
                drain_ready(out, err, block=True)
                code = child.poll()
                if code is not None:
                    while getattr(child, "stdout", None) is not None or getattr(child, "stderr", None) is not None:
                        drain_ready(out, err, block=True)
                    exit_code = int(code)
                    break
                cancel = _read_json(Path(str(manifest["cancel_path"])))
                if cancel and cancel.get("nonce") == manifest.get("nonce") and cancel.get("wrapper_id") == manifest.get("wrapper_id"):
                    status = "CANCELLED"
                    exit_code = reap_after_signal(signal.SIGTERM)
                    break
                if time.monotonic() >= deadline:
                    status = "TIMED_OUT"
                    exit_code = reap_after_signal(signal.SIGTERM)
                    break
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
    except (OSError, subprocess.SubprocessError, TimeoutError):
        # A child that was already started but cannot be proven waited is not
        # a settled effect.  Leave the completion absent so recovery records
        # UNKNOWN and retains the responsibility lane.
        return 77
    finally:
        _fsync_dir(private_root)
    completion = {
        "schema": "SITINA_LOOP_COMMAND_COMPLETION_V1",
        "task_id": manifest["task_id"],
        "operation_id": manifest["operation_id"],
        "nonce": manifest["nonce"],
        "wrapper_id": manifest["wrapper_id"],
        "wrapper_pid": os.getpid(),
        "child_pid": child.pid if child is not None else None,
        "status": status,
        "exit_code": exit_code,
        "stdout_hash": "sha256:" + stdout_hash.hexdigest(),
        "stderr_hash": "sha256:" + stderr_hash.hexdigest(),
        "stdout_hash_scope": "retained_prefix",
        "stderr_hash_scope": "retained_prefix",
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_retained_bytes": stdout_retained_bytes,
        "stderr_retained_bytes": stderr_retained_bytes,
        "stdout_truncated": stdout_bytes > stdout_retained_bytes,
        "stderr_truncated": stderr_bytes > stderr_retained_bytes,
        "completed_at": time.time(),
    }
    _write_json(Path(str(manifest["completion_path"])), completion)
    finished_permit = dict(permit)
    finished_permit["state"] = "COMPLETED"
    finished_permit["completed_at"] = time.time()
    _write_json(permit_path, finished_permit)
    ready_raw = (str(manifest["nonce"]) + "\n").encode("utf-8")
    ready_path = Path(str(manifest["ready_path"]))
    ready_path.write_bytes(ready_raw)
    os.chmod(ready_path, 0o400)
    with ready_path.open("rb") as ready:
        os.fsync(ready.fileno())
    _fsync_dir(private_root)
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    os.close(lock_fd)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--wrapper", type=Path)
    args = parser.parse_args(argv)
    if args.wrapper is None:
        return 2
    return _wrapper(args.wrapper)


if __name__ == "__main__":
    raise SystemExit(main())
