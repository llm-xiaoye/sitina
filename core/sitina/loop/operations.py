from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .model import EffectStatus, OperationMode, OperationRejected


def file_identity(path: str | os.PathLike[str]) -> str:
    candidate = Path(path).expanduser().resolve(strict=False)
    if not candidate.exists():
        return "absent"
    if candidate.is_symlink():
        return "symlink:" + os.readlink(candidate)
    if candidate.is_file():
        return "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
    if candidate.is_dir():
        stat = candidate.stat()
        return f"directory:{stat.st_dev}:{stat.st_ino}"
    stat = candidate.stat()
    return f"other:{stat.st_mode}:{stat.st_dev}:{stat.st_ino}"


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_observation(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Return hash-only, non-secret identity facts for one filesystem path."""

    supplied = Path(path).expanduser()
    normalized = supplied.resolve(strict=False)
    observation: dict[str, Any] = {
        "path": str(normalized),
        "supplied_path": str(supplied.absolute()),
        "exists": False,
        "type": "absent",
        "size": 0,
        "content_hash": None,
        "device": None,
        "inode": None,
    }
    try:
        stat = normalized.lstat()
    except FileNotFoundError:
        return observation
    observation["exists"] = True
    observation["device"] = int(stat.st_dev)
    observation["inode"] = int(stat.st_ino)
    if normalized.is_symlink():
        observation["type"] = "symlink"
        observation["size"] = int(stat.st_size)
        observation["content_hash"] = _sha256_bytes(os.readlink(normalized).encode("utf-8"))
    elif normalized.is_file():
        observation["type"] = "file"
        raw = normalized.read_bytes()
        observation["size"] = len(raw)
        observation["content_hash"] = _sha256_bytes(raw)
    elif normalized.is_dir():
        observation["type"] = "directory"
        observation["size"] = int(stat.st_size)
    else:
        observation["type"] = "other"
        observation["size"] = int(stat.st_size)
    return observation


def parent_observation(path: str | os.PathLike[str]) -> dict[str, Any]:
    parent = Path(path).expanduser().resolve(strict=False).parent
    observed = file_observation(parent)
    observed["path_role"] = "parent"
    return observed


def resource_scene_observation(
    path: str | os.PathLike[str],
    *,
    max_entries: int = 4096,
) -> dict[str, Any]:
    """Observe one owned resource without following links outside its root.

    Handoff evidence is deliberately hash-only.  The lexical resource path is
    inspected with ``lstat`` first, and directory traversal uses ``scandir``
    without following symlinks.  This keeps a directory handoff bounded while
    still recording link identity and target text rather than silently
    traversing an external tree.
    """

    root = Path(path).expanduser().resolve(strict=False)
    root_text = str(root)
    entries: list[dict[str, Any]] = []
    truncated = False

    def observe_one(candidate: Path, relative: str) -> dict[str, Any]:
        nonlocal truncated
        try:
            stat = candidate.lstat()
        except FileNotFoundError:
            return {
                "path": relative,
                "type": "absent",
                "exists": False,
                "size": 0,
            "device": None,
            "inode": None,
            "mtime_ns": None,
            "content_hash": None,
            }
        record: dict[str, Any] = {
            "path": relative,
            "type": "other",
            "exists": True,
            "size": int(stat.st_size),
            "device": int(stat.st_dev),
            "inode": int(stat.st_ino),
            "mtime_ns": int(stat.st_mtime_ns),
            "content_hash": None,
        }
        if candidate.is_symlink():
            target = os.readlink(candidate)
            record.update({
                "type": "symlink",
                "target_hash": "sha256:" + hashlib.sha256(target.encode("utf-8")).hexdigest(),
                "target_type": "absolute" if os.path.isabs(target) else "relative",
            })
        elif candidate.is_file():
            record["type"] = "file"
            digest = hashlib.sha256()
            with candidate.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            record["content_hash"] = "sha256:" + digest.hexdigest()
        elif candidate.is_dir():
            record["type"] = "directory"
        return record

    pending: list[tuple[Path, str]] = [(root, ".")]
    while pending:
        candidate, relative = pending.pop(0)
        if len(entries) >= max_entries:
            truncated = True
            break
        entries.append(observe_one(candidate, relative))
        try:
            is_directory = candidate.is_dir() and not candidate.is_symlink()
        except OSError:
            is_directory = False
        if not is_directory:
            continue
        try:
            children = sorted(candidate.iterdir(), key=lambda item: item.name)
        except OSError as error:
            entries[-1]["read_error"] = type(error).__name__
            continue
        for child in children:
            child_relative = child.name if relative == "." else f"{relative}/{child.name}"
            pending.append((child, child_relative))
    return {
        "path": root_text,
        "root": entries[0] if entries else {"path": ".", "type": "absent", "exists": False},
        "entries": entries,
        "entry_count": len(entries),
        "truncated": truncated,
    }


def _safe_argument_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _safe_argument_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_argument_value(item) for item in value]
    if isinstance(value, str):
        return value
    return value


def safe_tool_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Canonicalize tool args without copying protected file content."""

    result = _safe_argument_value(arguments)
    assert isinstance(result, dict)
    for key in ("content", "old_string", "new_string"):
        value = result.get(key)
        if isinstance(value, str):
            raw = value.encode("utf-8")
            result[key] = {
                "content_hash": _sha256_bytes(raw),
                "utf8_bytes": len(raw),
            }
    return result


def _expected_file_observation(path: Path, content: bytes) -> dict[str, Any]:
    return {
        "path": str(path.resolve(strict=False)),
        "exists": True,
        "type": "file",
        "size": len(content),
        "content_hash": _sha256_bytes(content),
        "device": None,
        "inode": None,
    }


def build_file_effect_plan(tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Build a hash-only plan using the same UTF-8/string semantics as builtins.

    This function never mutates the workspace.  It is called only after the
    modification lane and resource checks have succeeded, immediately before
    dispatch, so its observations cannot authorize a queued write.
    """

    path = Path(str(arguments.get("path") or "")).expanduser().resolve(strict=False)
    if tool_name in {"sitina_write_file", "sitina_edit_file", "sitina_delete_file"}:
        paths = (path,)
    elif tool_name == "sitina_rename_file":
        destination = Path(str(arguments.get("destination") or "")).expanduser().resolve(strict=False)
        paths = (path, destination)
    else:
        raise ValueError(f"unsupported file effect tool: {tool_name}")
    before = {str(item): file_observation(item) for item in paths}
    parents = {str(item): parent_observation(item) for item in paths}
    expected: dict[str, Any] = {}
    planning_error: str | None = None
    try:
        if tool_name == "sitina_write_file":
            content = str(arguments.get("content") or "").encode("utf-8")
            append = bool(arguments.get("append"))
            if append and path.exists():
                if not path.is_file() or path.is_symlink():
                    raise ValueError("write target is not a regular file")
                # Match ToolCatalog._write_file exactly: read as UTF-8 text,
                # then write the concatenated text through write_text.  This
                # deliberately normalizes universal newlines before hashing.
                original_text = path.read_text(encoding="utf-8")
                original = original_text.encode("utf-8")
            else:
                original = b""
            expected[str(path)] = _expected_file_observation(path, original + content if append else content)
        elif tool_name == "sitina_edit_file":
            if not path.is_file() or path.is_symlink():
                raise ValueError("edit target does not exist or is not a file")
            original_text = path.read_text(encoding="utf-8")
            old = str(arguments.get("old_string") or "")
            new = str(arguments.get("new_string") or "")
            occurrences = original_text.count(old)
            replace_all = bool(arguments.get("replace_all"))
            if old == new:
                raise ValueError("old_string and new_string are identical")
            if occurrences == 0:
                raise ValueError("old_string not found")
            if occurrences > 1 and not replace_all:
                raise ValueError(f"old_string is not unique ({occurrences} matches)")
            updated = original_text.replace(old, new) if replace_all else original_text.replace(old, new, 1)
            expected[str(path)] = _expected_file_observation(path, updated.encode("utf-8"))
        elif tool_name == "sitina_delete_file":
            expected[str(path)] = {
                "path": str(path),
                "exists": False,
                "type": "absent",
                "size": 0,
                "content_hash": None,
                "device": None,
                "inode": None,
            }
        else:
            source = path
            destination = paths[1]
            source_before = before[str(source)]
            if source_before["type"] != "file":
                raise ValueError("rename requires a regular source file")
            if before[str(destination)].get("exists"):
                raise ValueError("rename destination already exists")
            expected[str(source)] = {
                "path": str(source),
                "exists": False,
                "type": "absent",
                "size": 0,
                "content_hash": None,
                "device": None,
                "inode": None,
            }
            expected[str(destination)] = {
                **_expected_file_observation(destination, b""),
                "content_hash": source_before.get("content_hash"),
                "size": int(source_before.get("size") or 0),
            }
    except (OSError, UnicodeError, ValueError) as error:
        planning_error = str(error)
    return {
        "schema": "SITINA_LOOP_FILE_EFFECT_EVIDENCE_V1",
        "tool": tool_name,
        "arguments": safe_tool_arguments(arguments),
        "targets": [str(item) for item in paths],
        "before": before,
        "parents_before": parents,
        "parent_creation_allowed": {
            path: not bool(observed.get("exists"))
            for path, observed in parents.items()
        },
        "expected_after": expected,
        "planning_error": planning_error,
        "dispatch_phase": "AUTHORIZED_NOT_STARTED",
    }


def _same_content_identity(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    if actual.get("type") == "directory" or expected.get("type") == "directory":
        return (
            actual.get("exists") == expected.get("exists")
            and actual.get("type") == expected.get("type")
            and actual.get("device") == expected.get("device")
            and actual.get("inode") == expected.get("inode")
        )
    return (
        actual.get("exists") == expected.get("exists")
        and actual.get("type") == expected.get("type")
        and actual.get("size") == expected.get("size")
        and actual.get("content_hash") == expected.get("content_hash")
    )


def probe_file_effect(evidence: Mapping[str, Any], *, dispatch_started: bool) -> dict[str, Any]:
    """Classify a file operation from a new observation without mutating it."""

    before = evidence.get("before") if isinstance(evidence.get("before"), Mapping) else {}
    expected = evidence.get("expected_after") if isinstance(evidence.get("expected_after"), Mapping) else {}
    targets = [str(item) for item in evidence.get("targets", ())]
    observed = {path: file_observation(path) for path in targets}
    parents = {path: parent_observation(path) for path in targets}
    planning_error = evidence.get("planning_error")
    if planning_error:
        return {
            "decision": "UNKNOWN" if dispatch_started else "NO_EFFECT",
            "proof": "planning_error",
            "observed": observed,
            "parents": parents,
            "reason": str(planning_error),
        }
    expected_match = all(
        path in observed and path in expected and _same_content_identity(observed[path], expected[path])
        for path in targets
    )
    before_match = all(
        path in observed and path in before and _same_content_identity(observed[path], before[path])
        for path in targets
    )
    parent_before = evidence.get("parents_before") if isinstance(evidence.get("parents_before"), Mapping) else {}
    parent_creation_allowed = evidence.get("parent_creation_allowed")
    if not isinstance(parent_creation_allowed, Mapping):
        parent_creation_allowed = {}
    parent_changed = any(
        path in parents
        and path in parent_before
        and not _same_content_identity(parents[path], parent_before[path])
        and not (
            bool(parent_creation_allowed.get(path))
            and parents[path].get("type") == "directory"
            and parents[path].get("exists") is True
        )
        for path in targets
    )
    if expected_match and not parent_changed:
        return {
            "decision": "SUCCEEDED",
            "proof": "post_state_verified",
            "historical_executor_proven": False,
            "observed": observed,
            "parents": parents,
        }
    if before_match and not parent_changed:
        if not dispatch_started:
            return {
                "decision": "NO_EFFECT",
                "proof": "durable_not_started_boundary",
                "observed": observed,
                "parents": parents,
            }
        return {
            "decision": "UNKNOWN",
            "proof": "started_without_post_state",
            "observed": observed,
            "parents": parents,
        }
    if expected_match and parent_changed:
        return {
            "decision": "PARTIAL",
            "proof": "target_expected_parent_changed",
            "observed": observed,
            "parents": parents,
        }
    if before_match and parent_changed:
        return {
            "decision": "PARTIAL" if dispatch_started else "CONFLICT",
            "proof": "parent_changed_without_target_completion",
            "observed": observed,
            "parents": parents,
        }
    return {
        "decision": "CONFLICT",
        "proof": "third_content_or_partial_target",
        "observed": observed,
        "parents": parents,
    }


def resources_conflict(first: str, second: str) -> bool:
    left = Path(first).expanduser().resolve(strict=False)
    right = Path(second).expanduser().resolve(strict=False)
    return left == right or left in right.parents or right in left.parents


@dataclass(frozen=True)
class FilePrecondition:
    path: str
    expected_identity: str

    @classmethod
    def capture(cls, path: str | os.PathLike[str]) -> "FilePrecondition":
        normalized = str(Path(path).expanduser().resolve(strict=False))
        return cls(normalized, file_identity(normalized))

    def observe(self) -> dict[str, str | bool]:
        normalized = str(Path(self.path).expanduser().resolve(strict=False))
        actual = file_identity(normalized)
        return {
            "path": normalized,
            "expected_identity": self.expected_identity,
            "actual_identity": actual,
            "matches": actual == self.expected_identity,
        }


@dataclass(frozen=True)
class RecoveryPolicy:
    probe: str
    retry: str
    partial: str
    cancel: str
    unknown_exit: str
    reconsider_at: str

    def __post_init__(self) -> None:
        if any(not str(value).strip() for value in (
            self.probe,
            self.retry,
            self.partial,
            self.cancel,
            self.unknown_exit,
            self.reconsider_at,
        )):
            raise ValueError("operation recovery policy is incomplete")

    def as_dict(self) -> dict[str, str]:
        return {
            "probe": self.probe,
            "retry": self.retry,
            "partial": self.partial,
            "cancel": self.cancel,
            "unknown_exit": self.unknown_exit,
            "reconsider_at": self.reconsider_at,
        }


@dataclass(frozen=True)
class OperationIntent:
    operation_id: str
    logical_operation_id: str
    attempt_id: str
    mode: OperationMode
    description: str
    resources: tuple[str, ...]
    expected_task_revision: int
    expected_run_instance_id: str
    expected_execution_epoch: int
    expected_goal_version: int
    expected_acceptance_version: int
    expected_handled_input_seq: int
    capability_snapshot_id: str
    preconditions: tuple[FilePrecondition, ...]
    recovery: RecoveryPolicy
    business_attempt_id: str | None = None

    def __post_init__(self) -> None:
        if any(not value.strip() for value in (
            self.operation_id,
            self.logical_operation_id,
            self.attempt_id,
            self.description,
            self.capability_snapshot_id,
        )):
            raise ValueError("operation intent identity and description are required")
        normalized = tuple(
            sorted({str(Path(value).expanduser().resolve(strict=False)) for value in self.resources})
        )
        if normalized != self.resources:
            raise ValueError("operation resource identities must be normalized, unique, and sorted")
        if self.mode is OperationMode.WRITE and not self.resources:
            raise ValueError("business write operation requires at least one resource identity")

    def as_dict(self, observations: tuple[Mapping[str, Any], ...]) -> dict[str, Any]:
        return {
            "schema": "SITINA_LOOP_OPERATION_INTENT_V1",
            "operation_id": self.operation_id,
            "logical_operation_id": self.logical_operation_id,
            "attempt_id": self.attempt_id,
            "business_attempt_id": self.business_attempt_id,
            "mode": self.mode.value,
            "description": self.description,
            "resources": list(self.resources),
            "expected_task_revision": self.expected_task_revision,
            "expected_run_instance_id": self.expected_run_instance_id,
            "expected_execution_epoch": self.expected_execution_epoch,
            "expected_goal_version": self.expected_goal_version,
            "expected_acceptance_version": self.expected_acceptance_version,
            "expected_handled_input_seq": self.expected_handled_input_seq,
            "capability_snapshot_id": self.capability_snapshot_id,
            "precondition_observations": [dict(item) for item in observations],
            "recovery": self.recovery.as_dict(),
        }


@dataclass(frozen=True)
class OperationOutcome:
    status: EffectStatus
    result: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.status not in {
            EffectStatus.SUCCEEDED,
            EffectStatus.FAILED,
            EffectStatus.PARTIAL,
            EffectStatus.UNKNOWN,
        }:
            raise ValueError("operation outcome requires a final effect status")


class BusinessModificationLane:
    """One conservative business modification lane; reads do not acquire it."""

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._owner: tuple[str, str] | None = None
        self._unknown_effect_owner: tuple[str, str] | None = None

    def acquire(
        self,
        task_id: str,
        operation_id: str,
        *,
        timeout: float | None = None,
    ) -> None:
        """Acquire the lane, optionally with a finite wait.

        Existing callers retain the historical unbounded behavior when
        ``timeout`` is omitted.  Background obligation workers pass a finite
        value so a held business writer cannot strand Host shutdown or the
        control/health surface.
        """

        if timeout is not None:
            timeout = float(timeout)
            if not math.isfinite(timeout) or timeout < 0:
                raise ValueError("business modification lane timeout must be finite and non-negative")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._owner is not None:
                if self._unknown_effect_owner is not None:
                    raise OperationRejected(
                        "business modification lane is held by an operation with unknown effect"
                    )
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OperationRejected(
                        "business modification lane acquire timed out"
                    )
                self._condition.wait(timeout=remaining)
            self._owner = (task_id, operation_id)

    def release(self, task_id: str, operation_id: str) -> None:
        with self._condition:
            if self._owner != (task_id, operation_id):
                raise RuntimeError("business modification lane owner mismatch")
            if self._unknown_effect_owner is not None:
                raise RuntimeError("unknown-effect business modification lane cannot be released")
            self._owner = None
            self._condition.notify_all()

    def hold_for_unknown_effect(self, task_id: str, operation_id: str) -> None:
        with self._condition:
            if self._owner != (task_id, operation_id):
                raise RuntimeError("business modification lane owner mismatch")
            self._unknown_effect_owner = self._owner
            self._condition.notify_all()

    def restore_unknown_effect_owner(self, task_id: str, operation_id: str) -> None:
        with self._condition:
            restored = (task_id, operation_id)
            if self._owner not in {None, restored}:
                raise OperationRejected("multiple unresolved business writers require recovery")
            self._owner = restored
            self._unknown_effect_owner = restored

    def resolve_unknown_effect_owner(
        self,
        task_id: str,
        operation_id: str,
        *,
        release: bool,
    ) -> None:
        """Apply a durable reconciliation decision to the local lane.

        The coordinator must append and verify its Journal decision before
        calling this method.  Non-final observations deliberately keep the
        owner held so a later, newly identified probe can update the outcome.
        """

        with self._condition:
            owner = (task_id, operation_id)
            if self._owner != owner or self._unknown_effect_owner != owner:
                raise OperationRejected("unknown-effect lane owner is not available for reconciliation")
            if release:
                self._owner = None
                self._unknown_effect_owner = None
                self._condition.notify_all()

    @property
    def owner(self) -> tuple[str, str] | None:
        with self._condition:
            return self._owner

    @property
    def unknown_effect_owner(self) -> tuple[str, str] | None:
        with self._condition:
            return self._unknown_effect_owner
