"""Workspace binding and before-hash delivery for real MULTI executions.

The model loop may run in an isolated Git worktree, but the user-visible
target is always explicit.  This module keeps that distinction concrete and
fail-closed: accepted files are copied back only when the target still has the
same before hash observed by the execution attempt.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.guards.path_lease import PathLease
from sitina.runners.tool_executor import DirectMutationCapability, ToolExecutor


class ExecutionTargetError(RuntimeError):
    pass


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_hash(path: Path) -> str | None:
    path = Path(path)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ExecutionTargetError(f"execution target is not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class FileBaseline:
    relative_path: str
    before_hash: str
    content: bytes | None


class WorkspaceBaseline:
    """In-memory baseline for the selected workspace.

    Content is retained only for ordinary text/code files so a rejected direct
    attempt can be restored without resetting, stashing, or checking out the
    user's repository.  Sensitive files are hash-bound but never copied into
    runtime prompts or evidence.
    """

    _SKIP_DIRS = frozenset({".git", ".sitina", "node_modules", ".venv", "venv", "__pycache__"})
    _SENSITIVE_PARTS = frozenset({".env", "secrets", "secret", "credentials", "credential", ".ssh", ".aws"})

    @classmethod
    def is_sensitive_relative(cls, relative: str) -> bool:
        for part in Path(relative).parts:
            lower = part.casefold()
            if lower in cls._SENSITIVE_PARTS or lower.startswith(".env."):
                return True
            if lower.endswith((".pem", ".key", ".p12", ".pfx")):
                return True
            if re.search(r"(?:secret|credential|password|token|private[-_]?key)", lower):
                return True
        return False

    def __init__(self, root: Path, records: Mapping[str, FileBaseline]):
        self.root = Path(root).expanduser().resolve(strict=True)
        self.records = dict(records)

    @classmethod
    def capture(cls, root: Path, max_depth: int | None = None) -> "WorkspaceBaseline":
        """捕获工作区文件基线

        Args:
            root: 工作区根目录
            max_depth: 最大递归深度（None=无限制，0=只扫描根目录，1=一层子目录）
        """
        root = Path(root).expanduser().resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise ExecutionTargetError("execution workspace must be a real directory")
        records: dict[str, FileBaseline] = {}

        for current, dirs, files in os.walk(root, followlinks=False):
            # 检查深度限制
            if max_depth is not None:
                current_depth = len(Path(current).relative_to(root).parts)
                if current_depth >= max_depth:
                    dirs[:] = []  # 不再递归子目录

            # 过滤掉无法访问的目录和特殊目录
            accessible_dirs = []
            for name in dirs:
                if name in cls._SKIP_DIRS:
                    continue
                dir_path = Path(current) / name
                # 跳过 macOS 容器目录和其他受保护的系统目录
                if 'Library/Containers' in str(dir_path) or 'containermanagerd' in str(dir_path):
                    continue
                try:
                    # 测试是否可以访问
                    list(dir_path.iterdir())
                    accessible_dirs.append(name)
                except (PermissionError, OSError):
                    # 跳过无法访问的目录
                    pass
            dirs[:] = sorted(accessible_dirs)

            for name in sorted(files):
                if name == ".git":
                    continue
                path = Path(current) / name
                # 跳过符号链接、socket、管道等特殊文件，而不是抛出错误
                # 这允许在包含开发工具链接的目录（如 home）中工作
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    raw = path.read_bytes()
                except (PermissionError, OSError):
                    # 跳过无法读取的文件
                    continue
                relative = path.relative_to(root).as_posix()
                sensitive = cls.is_sensitive_relative(relative)
                records[relative] = FileBaseline(
                    relative,
                    "sha256:" + _sha256_bytes(raw),
                    None if sensitive else raw,
                )
        return cls(root, records)

    def before_hashes(self) -> dict[str, str | None]:
        return {
            str(self.root / relative): record.before_hash
            for relative, record in self.records.items()
        }

    def expected_hash(self, path: Path) -> str | None:
        try:
            relative = Path(path).expanduser().resolve(strict=False).relative_to(self.root).as_posix()
        except ValueError:
            raise ExecutionTargetError(f"path escapes execution workspace: {path}") from None
        record = self.records.get(relative)
        return record.before_hash if record is not None else None

    def _safe_path(self, path: Path) -> Path:
        candidate = Path(path).expanduser().resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            raise ExecutionTargetError(f"path escapes execution workspace: {path}") from None
        if Path(path).is_symlink():
            raise ExecutionTargetError(f"execution path is a symlink: {path}")
        return candidate

    def restore_rejected_attempt(
        self,
        paths: Sequence[str],
        *,
        expected_after_hashes: Mapping[str, str | None],
        executor: ToolExecutor,
        run_id: str,
        capability: DirectMutationCapability,
    ) -> None:
        """Restore only files changed by this attempt, with conflict checks."""

        for raw_path in sorted(set(str(item) for item in paths)):
            path = self._safe_path(Path(raw_path))
            relative = path.relative_to(self.root).as_posix()
            record = self.records.get(relative)
            current = file_hash(path)
            expected_after = expected_after_hashes.get(str(path))
            if current != expected_after:
                raise ExecutionTargetError(f"workspace changed concurrently while rolling back: {path}")
            if record is None:
                if path.exists():
                    with PathLease(path, run_id, executor.home):
                        path.unlink()
                continue
            if record.content is None:
                raise ExecutionTargetError(f"sensitive baseline cannot be restored automatically: {path}")
            result = executor.write_direct(
                target=str(path),
                content=record.content.decode("utf-8"),
                run_id=run_id,
                expected_before_hash=current,
                capability=capability,
            )
            if result.get("status") != "ok":
                raise ExecutionTargetError(str(result.get("reason") or "baseline restore failed"))


def overlay_workspace(source: Path, destination: Path) -> dict[str, Any]:
    """Copy the selected workspace state into a managed Git worktree."""

    source = Path(source).expanduser().resolve(strict=True)
    destination = Path(destination).expanduser().resolve(strict=True)
    if source == destination:
        return {"copied_paths": [], "excluded_sensitive_paths": [], "symlink_paths": []}
    copied: list[str] = []
    excluded: list[str] = []
    symlinks: list[str] = []
    quarantined: list[str] = []
    # A tracked secret may already exist in the newly-created worktree even
    # though it was not copied from the selected workspace.  Remove it from
    # the managed worktree before the model can read it; the selected target is
    # never touched.
    for current, dirs, files in os.walk(destination, topdown=True, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in tuple(dirs):
            candidate = Path(current) / name
            relative = candidate.relative_to(destination).as_posix()
            if WorkspaceBaseline.is_sensitive_relative(relative):
                if candidate.is_symlink():
                    symlinks.append(relative)
                else:
                    shutil.rmtree(candidate)
                    quarantined.append(relative)
                dirs.remove(name)
        for name in sorted(files):
            if name == ".git":
                continue
            candidate = Path(current) / name
            relative = candidate.relative_to(destination).as_posix()
            if WorkspaceBaseline.is_sensitive_relative(relative):
                if candidate.is_symlink():
                    symlinks.append(relative)
                elif candidate.is_file():
                    candidate.unlink()
                    quarantined.append(relative)
    for current, dirs, files in os.walk(source, followlinks=False):
        kept_dirs: list[str] = []
        for name in sorted(dirs):
            if name == ".git":
                continue
            source_dir = Path(current) / name
            relative_dir = source_dir.relative_to(source).as_posix()
            if source_dir.is_symlink():
                symlinks.append(relative_dir)
                continue
            if WorkspaceBaseline.is_sensitive_relative(relative_dir):
                excluded.append(relative_dir)
                continue
            kept_dirs.append(name)
        dirs[:] = kept_dirs
        relative_dir = Path(current).relative_to(source)
        target_dir = destination / relative_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            if name == ".git":
                continue
            source_path = Path(current) / name
            relative = source_path.relative_to(source).as_posix()
            if WorkspaceBaseline.is_sensitive_relative(relative):
                excluded.append(relative)
                continue
            if source_path.is_symlink() or not source_path.is_file():
                symlinks.append(relative)
                continue
            target_path = target_dir / name
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target_path)
            copied.append(relative)
    if symlinks:
        raise ExecutionTargetError("worktree overlay encountered symlink or special paths: " + ",".join(sorted(symlinks)))
    return {
        "schema": "SITINA_EXECUTION_WORKTREE_OVERLAY_V1",
        "copied_paths": sorted(copied),
        "excluded_sensitive_paths": sorted(set(excluded)),
        "quarantined_worktree_paths": sorted(set(quarantined)),
        "symlink_paths": [],
    }


def apply_verified_files(
    *,
    target_root: Path,
    source_root: Path,
    diff_paths: Sequence[str],
    mutation_events: Sequence[Mapping[str, Any]],
    content_loader,
    content_refs: Mapping[str, str] | None = None,
    manifest: Mapping[str, Any] | None = None,
    target_repo: str | None = None,
    executor: ToolExecutor,
    run_id: str,
    capability: DirectMutationCapability,
) -> tuple[str, ...]:
    """Apply accepted worktree files to the selected workspace.

    Each target is checked against the attempt's first mutation before hash and
    written through ToolExecutor, which supplies PathLease, atomic replacement,
    patch evidence, and the final after hash.
    """

    target_root = Path(target_root).expanduser().resolve(strict=True)
    source_root = Path(source_root).expanduser().resolve(strict=True)
    if target_repo is not None and target_root != Path(target_repo).expanduser().resolve(strict=True):
        raise ExecutionTargetError("accepted patch target repository binding mismatch")
    events_by_path: dict[str, list[Mapping[str, Any]]] = {}
    for event in mutation_events:
        if event.get("denied") is False and isinstance(event.get("path"), str):
            events_by_path.setdefault(str(Path(str(event["path"])).expanduser().resolve(strict=False)), []).append(event)

    def safe_join(root: Path, relative: str) -> Path:
        candidate = (root / relative).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError:
            raise ExecutionTargetError("accepted patch path escapes its bound repository") from None
        current = root
        for component in Path(relative).parts:
            if component in {"", "."}:
                continue
            current = current / component
            if current.is_symlink():
                raise ExecutionTargetError("accepted patch path traverses a symlink")
        return candidate

    def normalized_hash(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ExecutionTargetError("accepted patch hash is invalid")
        digest = value.removeprefix("sha256:")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ExecutionTargetError("accepted patch hash is invalid")
        return "sha256:" + digest

    entries: list[Mapping[str, Any]] = []
    if manifest is not None:
        if manifest.get("schema") != "SITINA_EXECUTION_PATCH_MANIFEST_V2":
            raise ExecutionTargetError("accepted patch requires a verified V2 manifest")
        raw_entries = manifest.get("entries")
        if not isinstance(raw_entries, list) or not raw_entries:
            raise ExecutionTargetError("accepted patch manifest has no entries")
        entries = [item for item in raw_entries if isinstance(item, Mapping)]
        if len(entries) != len(raw_entries):
            raise ExecutionTargetError("accepted patch manifest entry is invalid")
    else:
        # Compatibility for callers which have not yet published a V2 object.
        for raw_path in sorted(set(str(item) for item in diff_paths)):
            source = Path(raw_path).expanduser().resolve(strict=False)
            events = sorted(events_by_path.get(str(source), ()), key=lambda item: int(item.get("sequence", 0)))
            if not events:
                raise ExecutionTargetError(f"accepted patch has no mutation evidence for {source}")
            last = events[-1]
            entries.append({
                "path": source.relative_to(source_root).as_posix(),
                "operation": last.get("operation"),
                "before_hash": events[0].get("before_hash"),
                "after_hash": last.get("after_hash"),
                "destination": last.get("destination"),
                "content_ref": (content_refs or {}).get(str(source)),
                "tombstone": last.get("operation") == "delete",
            })

    # Preflight every source, destination, hash and content identity before any
    # target mutation. This makes accepted apply fail closed as one transaction
    # from the user's point of view.
    prepared: list[dict[str, Any]] = []
    for entry in entries:
        operation = entry.get("operation")
        if operation not in {"create", "modify", "append", "rename", "delete"}:
            raise ExecutionTargetError("accepted patch operation is unsupported")
        relative = entry.get("path")
        if not isinstance(relative, str) or not relative:
            raise ExecutionTargetError("accepted patch source identity is invalid")
        source = safe_join(source_root, relative)
        target = safe_join(target_root, relative)
        expected_before = normalized_hash(entry.get("before_hash"))
        target_before = file_hash(target)
        if target_before != expected_before:
            raise ExecutionTargetError(f"before-hash conflict while applying accepted patch: {target}")
        if operation == "delete":
            if entry.get("tombstone") is not True or entry.get("after_hash") is not None:
                raise ExecutionTargetError("delete patch is not an explicit tombstone")
            # The source is intentionally absent in the Forge worktree after a
            # successful delete.  The manifest tombstone plus the selected
            # target's before-hash is the complete identity proof.
            if target.is_symlink() or not target.is_file() or file_hash(target) != expected_before:
                raise ExecutionTargetError("accepted delete target changed or is not a regular file")
            prepared.append({"entry": entry, "operation": operation, "source": source, "target": target})
            continue
        expected_after = normalized_hash(entry.get("after_hash"))
        if expected_after is None:
            raise ExecutionTargetError("accepted non-delete patch has no after hash")
        content_ref = entry.get("content_ref") or (content_refs or {}).get(str(source))
        raw = content_loader(content_ref) if callable(content_loader) and isinstance(content_ref, str) else source.read_bytes()
        if not isinstance(raw, bytes) or "sha256:" + _sha256_bytes(raw) != expected_after:
            raise ExecutionTargetError("accepted patch content identity mismatch")
        if operation == "rename":
            destination_relative = entry.get("destination")
            if not isinstance(destination_relative, str) or not destination_relative:
                raise ExecutionTargetError("accepted rename lacks destination identity")
            destination_source = safe_join(source_root, destination_relative)
            destination_target = safe_join(target_root, destination_relative)
            if destination_target.exists() or destination_target.is_symlink():
                raise ExecutionTargetError("accepted rename destination already exists")
            if not destination_source.is_file() or destination_source.is_symlink() or file_hash(destination_source) != expected_after:
                raise ExecutionTargetError("accepted rename destination changed after manifest verification")
            prepared.append({"entry": entry, "operation": operation, "source": source, "target": target,
                             "destination_source": destination_source, "destination_target": destination_target,
                             "raw": raw, "expected_after": expected_after})
        else:
            if not source.is_file() or source.is_symlink() or file_hash(source) != expected_after:
                raise ExecutionTargetError("accepted patch source changed after manifest verification")
            prepared.append({"entry": entry, "operation": operation, "source": source, "target": target,
                             "raw": raw, "expected_after": expected_after})

    applied: list[str] = []
    try:
        for item in prepared:
            operation = item["operation"]
            source = item["source"]
            target = item["target"]
            entry = item["entry"]
            if operation == "delete":
                result = executor.execute(
                    operation="delete", target=str(target), run_id=run_id,
                    agent="forge-execution-role", approval_id=capability.authorization_ref,
                    approved_files=[str(target)], allowed_roots=list(capability.allowed_roots),
                    expected_before_hash=normalized_hash(entry.get("before_hash")), capability=capability,
                )
                applied.append(str(target))
            elif operation == "rename":
                destination_target = item["destination_target"]
                result = executor.execute(
                    operation="move", target=str(target), destination=str(destination_target), run_id=run_id,
                    agent="forge-execution-role", approval_id=capability.authorization_ref,
                    approved_files=[str(target), str(destination_target)], allowed_roots=list(capability.allowed_roots),
                    expected_before_hash=normalized_hash(entry.get("before_hash")), capability=capability,
                )
                applied.extend([str(target), str(destination_target)])
            else:
                try:
                    content = item["raw"].decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ExecutionTargetError("accepted code patch is not UTF-8") from error
                result = executor.write_direct(
                    target=str(target), content=content, run_id=run_id,
                    expected_before_hash=file_hash(target), capability=capability,
                )
                applied.append(str(target))
            if result.get("status") != "ok":
                raise ExecutionTargetError(str(result.get("reason") or f"accepted {operation} failed"))
    except Exception as error:
        # Preflight catches ordinary conflicts. If a concurrent change occurs
        # between preflight and apply, do not claim success: report the exact
        # user-decision boundary and leave the already-applied evidence visible.
        if applied:
            raise ExecutionTargetError("accepted patch partially applied; user decision required: " + str(error)) from error
        raise
    return tuple(applied)


__all__ = [
    "ExecutionTargetError",
    "WorkspaceBaseline",
    "apply_verified_files",
    "file_hash",
    "overlay_workspace",
]
