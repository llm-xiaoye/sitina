"""Task-local file recovery and dirty Git worktree delivery.

Authorization belongs to the caller. This module accepts authorized external file
paths, never commits, and only runs local Git operations through an argv interface.
Untracked inputs must be explicitly selected; a directory is not permission to
copy its dependencies, credentials, caches or runtime state recursively.
"""

from __future__ import annotations

import difflib
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import threading
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any, Mapping, Sequence


GIT = "/usr/bin/git"
_ACTIVE = frozenset({"active", "running", "pending", "unknown", "starting", "stopping"})
_TASK_LOCKS: dict[str, Any] = {}
_TASK_LOCKS_GUARD = threading.Lock()


class WorkspaceError(RuntimeError):
    """A concrete file, Git or ownership precondition failed."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.details = details

    def as_dict(self) -> dict[str, Any]:
        return {**self.details, "status": "blocked", "code": self.code, "message": str(self)}


class WorkspaceConflict(WorkspaceError):
    """The observed file version or merge baseline no longer matches."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _same(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left.get(key) == right.get(key) for key in ("kind", "mode", "sha256"))


def _managed(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with self._transaction():
            return method(self, *args, **kwargs)
    return guarded


class WorkspaceManager:
    """Manage one task's baselines, local worktrees and resource ownership.

    ``artifact_root`` must be a task-owned durable directory. Recreating a manager
    for the same task resumes its records. File ``version`` values are SHA-256
    content digests; a missing path has version ``None``. A missing expected
    version permits creation only, and never authorizes overwriting an existing
    file. Version checks are repeated immediately before atomic replacement.
    They detect concurrent changes; they are not an OS-wide filesystem lock.
    """

    def __init__(self, workspace: Path, artifact_root: Path, task_id: str) -> None:
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("task_id must be nonempty")
        self.workspace = Path(workspace).expanduser().resolve(strict=True)
        if not self.workspace.is_dir():
            raise WorkspaceError("WORKSPACE_NOT_DIRECTORY", str(self.workspace))
        self.artifact_root = Path(artifact_root).expanduser().resolve()
        self._root = self.artifact_root / "workspace-management"
        self._root.mkdir(parents=True, exist_ok=True)
        self._blobs = self._root / "baselines"
        self._blobs.mkdir(exist_ok=True)
        self._state_path = self._root / "state.json"
        with _TASK_LOCKS_GUARD:
            self._lock = _TASK_LOCKS.setdefault(str(self._state_path), threading.RLock())
        self._transaction_state = threading.local()
        self.task_id = task_id
        self._state: dict[str, Any] = {}
        with self._transaction():
            if not self._state:
                self._state = {
                    "schema": "SITINA_TASK_WORKSPACE_V1", "task_id": task_id,
                    "workspace": str(self.workspace), "baselines": {}, "worktrees": {}, "resources": {},
                }
                self._save()

    @contextmanager
    def _transaction(self):
        with self._lock:
            depth = getattr(self._transaction_state, "depth", 0)
            if depth:
                self._transaction_state.depth = depth + 1
                try:
                    yield
                finally:
                    self._transaction_state.depth = depth
                return
            with (self._root / "state.lock").open("a+b") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                self._transaction_state.depth = 1
                try:
                    if self._state_path.exists():
                        try:
                            current = json.loads(self._state_path.read_text(encoding="utf-8"))
                        except (ValueError, UnicodeDecodeError) as error:
                            raise WorkspaceError("TASK_STATE_CORRUPT", str(self._state_path)) from error
                        if not isinstance(current, dict) or any(not isinstance(current.get(key), dict) for key in ("baselines", "worktrees", "resources")):
                            raise WorkspaceError("TASK_STATE_CORRUPT", str(self._state_path))
                        if current.get("schema") != "SITINA_TASK_WORKSPACE_V1" or current.get("task_id") != self.task_id or current.get("workspace") != str(self.workspace):
                            raise WorkspaceError("TASK_STATE_MISMATCH", "Artifact root belongs to another task or workspace")
                        self._state = current
                    yield
                finally:
                    self._transaction_state.depth = 0
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _save(self) -> None:
        data = (json.dumps(self._state, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self._atomic_bytes(self._state_path, data, 0o600)

    @staticmethod
    def _atomic_bytes(path: Path, data: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".sitina-write-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)

    def _path(self, path: Path | str) -> Path:
        value = Path(path).expanduser()
        if not value.is_absolute():
            value = self.workspace / value
        value = Path(os.path.abspath(value))
        return value.parent.resolve() / value.name

    @staticmethod
    def _observe(path: Path) -> tuple[dict[str, Any], bytes | None]:
        try:
            before = path.lstat()
        except FileNotFoundError:
            return {"kind": "ABSENT", "version": None, "sha256": None, "mode": None, "size_bytes": 0}, None
        mode = stat.S_IMODE(before.st_mode)
        if stat.S_ISREG(before.st_mode):
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                data = stream.read()
                closed = os.fstat(stream.fileno())
            after = path.lstat()
            identities = [(item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_mode) for item in (before, opened, closed, after)]
            if any(value != identities[0] for value in identities[1:]):
                raise WorkspaceConflict("FILE_CHANGED_DURING_READ", str(path))
            digest = _sha(data)
            return {"kind": "REGULAR", "version": digest, "sha256": digest, "mode": mode, "size_bytes": len(data)}, data
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(path)
            after = path.lstat()
            if (before.st_ino, before.st_mtime_ns) != (after.st_ino, after.st_mtime_ns):
                raise WorkspaceConflict("FILE_CHANGED_DURING_READ", str(path))
            data = os.fsencode(target)
            digest = _sha(data)
            return {"kind": "SYMLINK", "version": digest, "sha256": digest, "mode": mode, "size_bytes": len(data), "target": target}, data
        if stat.S_ISDIR(before.st_mode):
            return {"kind": "DIRECTORY", "version": None, "sha256": None, "mode": mode, "size_bytes": 0}, None
        raise WorkspaceError("UNSUPPORTED_OBJECT_TYPE", "Only regular files, symbolic links, directories and absent paths are supported", path=str(path), mode=before.st_mode)

    def _snapshot(self, path: Path) -> dict[str, Any]:
        entry, data = self._observe(path)
        if data is not None:
            blob = self._blobs / entry["sha256"]
            try:
                with blob.open("xb") as stream:
                    stream.write(data)
            except FileExistsError:
                if _sha(blob.read_bytes()) != entry["sha256"]:
                    raise WorkspaceError("BASELINE_CORRUPT", str(blob))
            entry["blob"] = entry["sha256"]
        return entry

    def _data(self, entry: Mapping[str, Any]) -> bytes:
        if entry["kind"] == "ABSENT":
            return b""
        blob = self._blobs / entry["blob"]
        data = blob.read_bytes()
        if _sha(data) != entry["sha256"]:
            raise WorkspaceError("BASELINE_CORRUPT", str(blob))
        return data

    def _capture(self, path: Path) -> dict[str, Any]:
        key = str(path)
        if key not in self._state["baselines"]:
            self._state["baselines"][key] = self._snapshot(path)
            self._save()
        return self._state["baselines"][key]

    def bind_git_runner(self, runner) -> None:
        """Bind the Host's task sandbox, never a model-selected executable."""
        if not callable(runner):
            raise TypeError("git runner must be callable")
        self._git_runner = runner

    def _git(self, cwd: Path, *args: str, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        argv = [GIT, "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(cwd), *args]
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(self._root), "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        }
        runner = getattr(self, "_git_runner", None)
        if runner is None:
            result = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, check=False)
        else:
            result = runner(argv=argv, cwd=cwd, environment=environment, input_bytes=input_bytes)
        if check and result.returncode:
            evidence = self._root / "git-errors" / uuid.uuid4().hex
            evidence.mkdir(parents=True)
            (evidence / "child-stdout.bin").write_bytes(result.stdout)
            (evidence / "child-stderr.bin").write_bytes(result.stderr)
            (evidence / "command.json").write_text(json.dumps({"argv": argv, "cwd": str(cwd), "passed_environment": environment, "exit_code": result.returncode}), encoding="utf-8")
            raise WorkspaceError("GIT_FAILED", result.stderr.decode("utf-8", errors="replace").strip(), argv=argv, exit_code=result.returncode, evidence_path=str(evidence))
        return result

    def _repo(self) -> Path | None:
        result = self._git(self.workspace, "rev-parse", "--show-toplevel", check=False)
        return Path(os.fsdecode(result.stdout).strip()).resolve() if result.returncode == 0 else None

    def _scope(self, repo: Path) -> str:
        relative = self.workspace.relative_to(repo)
        return relative.as_posix() if relative.parts else "."

    def _tracked(self, cwd: Path, scope: str) -> list[str]:
        index = self._git(cwd, "ls-files", "-z", "--", scope).stdout
        head = self._git(cwd, "ls-tree", "--name-only", "-r", "-z", "HEAD", "--", scope).stdout
        return sorted({os.fsdecode(item) for item in (index + head).split(b"\0") if item})

    def _git_identity(self, repo: Path) -> dict[str, Any]:
        head = self._git(repo, "rev-parse", "--verify", "HEAD").stdout.decode("ascii").strip()
        index_path = Path(os.fsdecode(self._git(repo, "rev-parse", "--git-path", "index").stdout).strip())
        if not index_path.is_absolute():
            index_path = repo / index_path
        data = index_path.read_bytes() if index_path.exists() else b""
        return {"repository": str(repo), "head": head, "index_path": str(index_path.resolve()), "index_sha256": _sha(data), "index_size_bytes": len(data)}

    def _git_entries(self, repo: Path, *, index: bool) -> dict[str, dict[str, Any]]:
        scope = self._scope(repo)
        arguments = ("ls-files", "--stage", "-z", "--", scope) if index else ("ls-tree", "-r", "-z", "HEAD", "--", scope)
        result = {}
        for record in self._git(repo, *arguments).stdout.split(b"\0"):
            if not record:
                continue
            header, separator, raw_path = record.partition(b"\t")
            fields = header.split()
            if not separator or len(fields) != 3:
                raise WorkspaceError("GIT_ENTRY_FORMAT", "Git index/tree output did not match the local record contract")
            mode = fields[0].decode("ascii")
            oid = fields[1 if index else 2].decode("ascii")
            if mode not in {"100644", "100755", "120000", "160000"} or len(oid) not in {40, 64} or any(value not in "0123456789abcdef" for value in oid):
                raise WorkspaceError("GIT_ENTRY_FORMAT", "Unsupported Git object mode or identity")
            path = os.fsdecode(raw_path)
            stage = fields[2].decode("ascii") if index else "0"
            if stage != "0":
                result[path] = {"mode": mode, "oid": oid, "unmerged": True}
            elif not result.get(path, {}).get("unmerged"):
                result[path] = {"mode": mode, "oid": oid, "unmerged": False}
        return result

    @staticmethod
    def _git_change(before: Mapping[str, Any] | None, after: Mapping[str, Any] | None) -> str | None:
        if before == after:
            return None
        if before is None:
            return "added"
        if after is None:
            return "deleted"
        return "modified"

    @_managed
    def git_status(self, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """Compare raw bytes without running repository clean/smudge filters."""
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Status offset/limit must be bounded nonnegative integers")
        repo = self._repo()
        if repo is None:
            raise WorkspaceError("NOT_GIT_REPOSITORY", str(self.workspace))
        before = self._git_identity(repo)
        tree, index = self._git_entries(repo, index=False), self._git_entries(repo, index=True)
        format_name = self._git(repo, "rev-parse", "--show-object-format").stdout.decode("ascii").strip()
        if format_name not in {"sha1", "sha256"}:
            raise WorkspaceError("GIT_OBJECT_FORMAT", format_name)
        untracked = {os.fsdecode(value) for value in self._git(repo, "ls-files", "--others", "--exclude-standard", "-z", "--", self._scope(repo)).stdout.split(b"\0") if value}
        changes = []
        for relative in sorted(set(tree) | set(index) | untracked):
            source = self._contained_path(repo, relative)
            observed, data = self._observe(source)
            staged = self._git_change(tree.get(relative), index.get(relative))
            entry = index.get(relative)
            if entry is not None and entry["mode"] == "160000":
                working = "submodule_not_inspected"
            elif observed["kind"] == "ABSENT":
                working = "deleted" if entry is not None else None
            elif relative in untracked or entry is None:
                working = "untracked"
            elif entry.get("unmerged"):
                working = "unmerged"
            elif observed["kind"] not in {"REGULAR", "SYMLINK"}:
                working = "object_type_changed"
            else:
                blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
                oid = hashlib.new(format_name, blob).hexdigest()
                mode = "120000" if observed["kind"] == "SYMLINK" else "100755" if observed["mode"] & 0o111 else "100644"
                working = "modified" if (oid, mode) != (entry["oid"], entry["mode"]) else None
            if staged or working:
                changes.append({"path": relative, "staged": staged, "working": working, "version": observed["version"]})
        if self._git_identity(repo) != before:
            raise WorkspaceConflict("GIT_INDEX_CHANGED_DURING_READ", str(repo))
        page = []
        for item in changes[offset:offset + limit]:
            candidate = [*page, item]
            if len(json.dumps(candidate, ensure_ascii=True).encode("utf-8")) > 12000:
                break
            page.append(item)
        return {"status": "ok", "repository": str(repo), "head": before["head"], "index_sha256": before["index_sha256"],
                "content_comparison": "RAW_WORKTREE_BYTES_NO_FILTERS", "changes": page, "change_count": len(changes),
                "offset": offset, "page_byte_bound": 12000, "next_offset": offset + len(page) if offset + len(page) < len(changes) else None}

    @_managed
    def git_diff(self, path: Path, *, staged: bool = False, max_bytes: int = 16000) -> dict[str, Any]:
        if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
            raise ValueError("Diff byte bound must be in 1..65536")
        repo = self._repo()
        if repo is None:
            raise WorkspaceError("NOT_GIT_REPOSITORY", str(self.workspace))
        path = self._path(path)
        if not path.is_relative_to(self.workspace):
            raise WorkspaceError("DIFF_PATH_OUTSIDE_WORKSPACE", str(path))
        relative = path.relative_to(repo).as_posix()
        tree, index = self._git_entries(repo, index=False), self._git_entries(repo, index=True)
        baseline = tree.get(relative) if staged else index.get(relative)
        proposed = index.get(relative) if staged else None
        if any(item is not None and (item["mode"] == "160000" or item.get("unmerged")) for item in (baseline, proposed)):
            raise WorkspaceError("DIFF_REQUIRES_RESOLUTION", "Submodule or unmerged entries require explicit resolution", path=str(path))
        before = self._git(repo, "cat-file", "blob", baseline["oid"]).stdout if baseline else b""
        if staged:
            after = self._git(repo, "cat-file", "blob", proposed["oid"]).stdout if proposed else b""
            version = _sha(after) if proposed else None
        else:
            observed, data = self._observe(path)
            if observed["kind"] not in {"ABSENT", "REGULAR", "SYMLINK"}:
                raise WorkspaceError("NOT_FILE", str(path))
            after, version = data or b"", observed["version"]
        binary = b"\0" in before or b"\0" in after
        difference = ""
        if not binary:
            try:
                difference = "".join(difflib.unified_diff(before.decode("utf-8").splitlines(keepends=True), after.decode("utf-8").splitlines(keepends=True), fromfile=relative + (" (HEAD)" if staged else " (index)"), tofile=relative))
            except UnicodeDecodeError:
                binary = True
        size = len(difference.encode("utf-8"))
        return {"status": "ok", "path": str(path), "staged": staged, "version": version,
                "baseline_version": _sha(before) if baseline else None, "changed": before != after,
                "binary": binary, "diff": difference if size <= max_bytes else "", "diff_bytes": size,
                "diff_suppressed": size > max_bytes, "content_comparison": "RAW_BYTES_NO_FILTERS"}

    @_managed
    def capture_baseline(self, paths: Sequence[Path] | None = None) -> dict[str, Any]:
        """Capture each selected path once. None selects tracked files only.

        Directories are recorded as directories, not recursively copied. For a
        non-Git workspace the caller must supply exact file paths.
        """
        with self._lock:
            repo = self._repo() if paths is None else None
            if paths is None:
                if repo is None:
                    raise WorkspaceError("EXPLICIT_PATHS_REQUIRED", "A non-Git workspace requires explicit task paths")
                selected = [repo / value for value in self._tracked(repo, self._scope(repo))]
            else:
                selected = [self._path(value) for value in paths]
            files = [{"path": str(path), **self._capture(path)} for path in dict.fromkeys(selected)]
            git = self._git_identity(repo) if repo is not None else None
            return {"task_id": self.task_id, "workspace": str(self.workspace), "files": files, "git": git}

    def read_lines(self, path: Path, start_line: int, end_line: int, expected_version: str | None = None) -> dict[str, Any]:
        path = self._path(path)
        if isinstance(start_line, bool) or isinstance(end_line, bool) or not isinstance(start_line, int) or not isinstance(end_line, int) or start_line < 1 or end_line < start_line:
            raise ValueError("Line ranges are positive, inclusive and ordered")
        entry, data = self._observe(path)
        if entry["kind"] != "REGULAR":
            raise WorkspaceError("NOT_REGULAR_FILE", str(path), kind=entry["kind"])
        self._require_version(path, entry, expected_version, optional=True)
        try:
            lines = data.decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError as error:
            raise WorkspaceError("NOT_UTF8", str(path)) from error
        if start_line > len(lines) + 1:
            raise WorkspaceError("LINE_RANGE_OUT_OF_BOUNDS", str(path), total_lines=len(lines))
        selected = lines[start_line - 1:end_line]
        actual_end = start_line + len(selected) - 1
        return {
            "path": str(path), "version": entry["version"], "content": "".join(selected),
            "start_line": start_line, "end_line": actual_end, "total_lines": len(lines),
            "read_range": {"start_line": start_line, "end_line": actual_end},
            "next_start_line": actual_end + 1 if actual_end < len(lines) else None,
        }

    @staticmethod
    def _require_version(path: Path, observed: Mapping[str, Any], expected: str | None, *, optional: bool = False) -> None:
        if optional and expected is None:
            return
        if observed["kind"] == "DIRECTORY" or observed["version"] != expected or (expected is None and observed["kind"] != "ABSENT"):
            raise WorkspaceConflict("VERSION_CONFLICT", str(path), expected_version=expected, actual_version=observed["version"], actual_kind=observed["kind"])

    def _require_unchanged(self, path: Path, expected: Mapping[str, Any]) -> None:
        current, _ = self._observe(path)
        if not _same(current, expected):
            raise WorkspaceConflict("VERSION_CONFLICT", str(path), expected_version=expected["version"], actual_version=current["version"], actual_kind=current["kind"])

    def _install(self, path: Path, entry: Mapping[str, Any], before: Mapping[str, Any]) -> None:
        self._require_unchanged(path, before)
        kind = entry["kind"]
        if kind == "ABSENT":
            if before["kind"] == "DIRECTORY":
                raise WorkspaceError("DIRECTORY_DELETE_REQUIRES_EXPLICIT_OPERATION", str(path))
            if os.path.lexists(path):
                path.unlink()
            return
        if kind == "DIRECTORY":
            if before["kind"] not in {"ABSENT", "DIRECTORY"}:
                raise WorkspaceConflict("OBJECT_TYPE_CONFLICT", str(path))
            path.mkdir(parents=True, exist_ok=True)
            return
        if before["kind"] == "DIRECTORY":
            raise WorkspaceConflict("OBJECT_TYPE_CONFLICT", str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.parent / (".sitina-write-" + uuid.uuid4().hex)
        try:
            if kind == "SYMLINK":
                os.symlink(entry["target"], temporary)
            else:
                with temporary.open("xb") as stream:
                    stream.write(self._data(entry))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, entry["mode"])
            self._require_unchanged(path, before)
            os.replace(temporary, path)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()

    @_managed
    def write_file(self, path: Path, content: bytes | str, expected_version: str | None = None) -> dict[str, Any]:
        with self._lock:
            path = self._path(path)
            before, _ = self._observe(path)
            self._require_version(path, before, expected_version)
            if before["kind"] not in {"REGULAR", "ABSENT"}:
                raise WorkspaceError("NOT_REGULAR_FILE", str(path), kind=before["kind"])
            self._capture(path)
            data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
            digest = _sha(data)
            blob = self._blobs / digest
            if not blob.exists():
                self._atomic_bytes(blob, data, 0o600)
            after = {"kind": "REGULAR", "version": digest, "sha256": digest, "blob": digest, "size_bytes": len(data), "mode": before["mode"] if before["kind"] == "REGULAR" else 0o644}
            self._install(path, after, before)
            return {"status": "written", "path": str(path), "before_version": before["version"], "version": digest, "baseline_version": self._state["baselines"][str(path)]["version"]}

    @_managed
    def replace_exact(self, path: Path, old: str, new: str, expected_version: str) -> dict[str, Any]:
        with self._lock:
            path = self._path(path)
            before, data = self._observe(path)
            self._require_version(path, before, expected_version)
            if before["kind"] != "REGULAR":
                raise WorkspaceError("NOT_REGULAR_FILE", str(path), kind=before["kind"])
            text = data.decode("utf-8")
            occurrences = text.count(old) if old else 0
            if occurrences != 1:
                raise WorkspaceConflict("ANCHOR_NOT_UNIQUE", str(path), occurrences=occurrences)
            return self.write_file(path, text.replace(old, new, 1), expected_version)

    @_managed
    def delete_file(self, path: Path, expected_version: str) -> dict[str, Any]:
        with self._lock:
            path = self._path(path)
            before, _ = self._observe(path)
            self._require_version(path, before, expected_version)
            if before["kind"] not in {"REGULAR", "SYMLINK"}:
                raise WorkspaceError("NOT_FILE", str(path), kind=before["kind"])
            self._capture(path)
            self._require_unchanged(path, before)
            path.unlink()
            return {"status": "deleted", "path": str(path), "before_version": before["version"], "version": None}

    @_managed
    def move_file(self, path: Path, destination: Path, expected_version: str, expected_destination_version: str | None = None) -> dict[str, Any]:
        with self._lock:
            path, destination = self._path(path), self._path(destination)
            if path == destination:
                raise WorkspaceError("SAME_PATH", str(path))
            before, _ = self._observe(path)
            target, _ = self._observe(destination)
            self._require_version(path, before, expected_version)
            self._require_version(destination, target, expected_destination_version)
            if before["kind"] not in {"REGULAR", "SYMLINK"} or target["kind"] not in {"REGULAR", "SYMLINK", "ABSENT"}:
                raise WorkspaceError("NOT_FILE", str(path))
            self._capture(path)
            self._capture(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            self._require_unchanged(path, before)
            self._require_unchanged(destination, target)
            os.replace(path, destination)
            return {"status": "moved", "path": str(path), "destination": str(destination), "version": before["version"], "previous_destination_version": target["version"]}

    @_managed
    def task_diff(self, path: Path) -> dict[str, Any]:
        path = self._path(path)
        baseline = self._state["baselines"].get(str(path))
        if baseline is None:
            raise WorkspaceError("BASELINE_NOT_CAPTURED", str(path))
        current = self._snapshot(path)
        binary = False
        difference = ""
        if not _same(baseline, current):
            try:
                left = self._data(baseline).decode("utf-8").splitlines(keepends=True)
                right = self._data(current).decode("utf-8").splitlines(keepends=True)
                difference = "".join(difflib.unified_diff(left, right, fromfile=str(path) + " (task baseline)", tofile=str(path)))
            except (UnicodeDecodeError, KeyError):
                binary = True
        return {"path": str(path), "baseline_version": baseline["version"], "version": current["version"], "before_kind": baseline["kind"], "after_kind": current["kind"], "changed": not _same(baseline, current), "binary": binary, "diff": difference}

    @_managed
    def create_worktree(self, path: Path, branch: str | None = None, paths: Sequence[Path] | None = None) -> dict[str, Any]:
        """Copy current tracked state plus explicitly selected untracked files.

        The source index remains untouched. ``paths`` adds exact task files,
        including ignored configuration when the caller explicitly authorizes it.
        Previously captured task files are also selected. Dependency readiness is
        initially unknown and is never inferred from successful worktree creation.
        """
        with self._lock:
            repo = self._repo()
            if repo is None:
                raise WorkspaceError("NOT_GIT_REPOSITORY", str(self.workspace))
            path = self._path(path)
            if os.path.lexists(path) or str(path) in self._state["worktrees"]:
                raise WorkspaceConflict("WORKTREE_PATH_IN_USE", str(path))
            if path.is_relative_to(repo) or repo.is_relative_to(path):
                raise WorkspaceError("WORKTREE_MUST_BE_SEPARATE", str(path))
            scope = self._scope(repo)
            if self._git(repo, "ls-files", "--unmerged", "-z", "--", scope).stdout:
                raise WorkspaceConflict("UNMERGED_SOURCE_INDEX", str(repo))
            before_git = self._git_identity(repo)
            selected = set(self._tracked(repo, scope))
            explicit = list(paths) if paths is not None else [Path(value) for value, snapshot in self._state["baselines"].items() if Path(value).is_relative_to(self.workspace) and snapshot["kind"] != "DIRECTORY"]
            for item in explicit:
                source = self._path(item)
                if not source.is_relative_to(self.workspace):
                    raise WorkspaceError("WORKTREE_INPUT_OUTSIDE_WORKSPACE", str(source))
                if ".git" in source.relative_to(repo).parts or source.is_relative_to(self._root):
                    raise WorkspaceError("WORKTREE_METADATA_INPUT", str(source))
                entry, _ = self._observe(source)
                if entry["kind"] == "DIRECTORY":
                    raise WorkspaceError("EXPLICIT_FILE_PATH_REQUIRED", "Enumerate exact task files instead of recursively copying a directory", path=str(source))
                selected.add(source.relative_to(repo).as_posix())
            origin = {relative: self._snapshot(repo / relative) for relative in sorted(selected)}
            # Index-only diff avoids clean/smudge filters on working files. Raw
            # working snapshots carry unstaged content, including binary bytes.
            staged = self._git(repo, "diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "HEAD", "--", scope).stdout
            working = (json.dumps(origin, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            record_root = self._root / "worktrees" / uuid.uuid4().hex
            record_root.mkdir(parents=True)
            (record_root / "staged.patch").write_bytes(staged)
            (record_root / "working-snapshot.json").write_bytes(working)
            record = {
                "path": str(path), "workspace_path": str(path / self.workspace.relative_to(repo)),
                "repository": str(repo), "scope": scope, "branch": branch, "source_git": before_git,
                "source_index_state": {"staged_patch_path": str(record_root / "staged.patch"), "staged_patch_sha256": _sha(staged), "working_snapshot_path": str(record_root / "working-snapshot.json"), "working_snapshot_sha256": _sha(working)},
                "origin": origin, "status": "creating", "integrated": False, "verified": False,
                "dependency_readiness": {"status": "not_checked", "ready": False, "details": {}},
                "resource_owner": self.task_id,
            }
            self._state["worktrees"][str(path)] = record
            self._save()
            try:
                if branch is not None:
                    self._git(repo, "check-ref-format", "--branch", branch)
                    self._git(repo, "worktree", "add", "--no-checkout", "-b", branch, str(path), before_git["head"])
                else:
                    self._git(repo, "worktree", "add", "--no-checkout", "--detach", str(path), before_git["head"])
                self._git(path, "read-tree", "HEAD")
                if scope != ".":
                    all_tracked = self._git(path, "ls-files", "-z").stdout.split(b"\0")
                    outside = [item for item in all_tracked if item and os.fsdecode(item) not in selected]
                    if outside:
                        self._git(path, "update-index", "--skip-worktree", "-z", "--stdin", input_bytes=b"\0".join(outside) + b"\0")
                if staged:
                    self._git(path, "apply", "--cached", "--binary", "-", input_bytes=staged)
                for relative, snapshot in origin.items():
                    target = self._contained_path(path, relative)
                    existing, _ = self._observe(target)
                    self._install(target, snapshot, existing)
                if self._git_identity(repo) != before_git:
                    raise WorkspaceConflict("SOURCE_INDEX_CHANGED_DURING_CAPTURE", str(repo))
                for relative, snapshot in origin.items():
                    self._require_unchanged(repo / relative, snapshot)
                record["status"] = "ready"
                self._save()
            except Exception as error:
                record["status"] = "creation_failed_preserved"
                record["failure"] = error.as_dict() if isinstance(error, WorkspaceError) else {"message": str(error), "type": type(error).__name__}
                self._save()
                raise
            return json.loads(json.dumps(record))

    @staticmethod
    def _contained_path(root: Path, relative: str) -> Path:
        value = root / relative
        if Path(relative).is_absolute() or ".." in Path(relative).parts or not value.parent.resolve().is_relative_to(root):
            raise WorkspaceConflict("PATH_ESCAPES_WORKTREE", str(value))
        return value

    def _current_check_binding(self, record: Mapping[str, Any], role: str) -> dict[str, Any]:
        root = Path(record["path"] if role == "worktree" else record["repository"])
        selected = set(record["origin"]) | set(record.get("integration", {}))
        members = {}
        unsupported = []
        for relative in sorted(selected):
            snapshot, _ = self._observe(self._contained_path(root, relative))
            members[relative] = {key: snapshot[key] for key in ("kind", "version", "sha256", "mode", "size_bytes")}
            if snapshot["kind"] == "DIRECTORY":
                unsupported.append(relative)
        content = json.dumps(members, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"worktree_path": record["path"], "role": role, "root": str(root),
                "members": members, "members_sha256": _sha(content), "unsupported_members": unsupported}

    @_managed
    def capture_check_binding(self, cwd: Path) -> dict[str, Any]:
        """Snapshot known task members into the normal command prepare evidence.

        No Git or product process runs here. Cwd must be a real directory. A
        worktree cwd yields that worktree's current members; the original task
        cwd yields source bindings for already integrated worktrees. Other task
        command directories yield an empty bindings list and cannot verify a
        worktree. The Host persists this exact object before starting the check.
        """
        cwd = Path(cwd).expanduser().resolve(strict=True)
        if not cwd.is_dir():
            raise WorkspaceError("CHECK_CWD_NOT_DIRECTORY", str(cwd))
        bindings = []
        for _, record in sorted(self._state["worktrees"].items()):
            if record["status"] in {"removed", "creating", "creation_failed_preserved"}:
                continue
            if cwd.is_relative_to(Path(record["workspace_path"])):
                bindings.append(self._current_check_binding(record, "worktree"))
            elif record["integrated"] and cwd.is_relative_to(self.workspace):
                bindings.append(self._current_check_binding(record, "source"))
        return {"schema": "SITINA_WORKSPACE_CHECK_BINDING_V1", "task_id": self.task_id,
                "cwd": str(cwd), "bindings": bindings}

    @_managed
    def match_check_binding(self, path: Path, binding: Mapping[str, Any]) -> dict[str, Any]:
        """Compare a Host-recorded binding with current delivered file bytes."""
        path, record = self._worktree(path)
        if not isinstance(binding, Mapping) or binding.get("worktree_path") != str(path) or binding.get("role") not in {"worktree", "source"}:
            return {"matched": False, "reason": "CHECK_WORKTREE_BINDING_MISMATCH"}
        role = binding["role"]
        if role == "worktree" and any(not _same(value["source"], value["result"]) for value in record.get("integration", {}).values()):
            return {"matched": False, "reason": "MERGED_SOURCE_REQUIRES_FRESH_CHECK"}
        current = self._current_check_binding(record, role)
        matched = current == dict(binding) and not current["unsupported_members"]
        return {"matched": matched, "reason": None if matched else "CHECK_FILE_VERSIONS_CHANGED",
                "role": role, "members_sha256": current["members_sha256"], "member_count": len(current["members"])}

    def _worktree(self, path: Path) -> tuple[Path, dict[str, Any]]:
        path = self._path(path)
        record = self._state["worktrees"].get(str(path))
        if record is None or record["status"] == "removed":
            raise WorkspaceError("UNKNOWN_WORKTREE", str(path))
        return path, record

    @_managed
    def describe_worktree(self, path: Path) -> dict[str, Any]:
        _, record = self._worktree(path)
        keys = ("path", "workspace_path", "repository", "scope", "branch", "status", "integrated", "verified", "dependency_readiness", "source_git")
        return {**{key: record[key] for key in keys}, "member_count": len(record["origin"]), "state_ref": str(self._state_path)}

    @_managed
    def set_dependency_readiness(self, path: Path, ready: bool, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            path, record = self._worktree(path)
            information = dict(details or {})
            declared = information.get("rebuildable_paths", [])
            if not isinstance(declared, list) or any(not isinstance(item, str) for item in declared):
                raise ValueError("rebuildable_paths must be an explicit list of directory paths")
            normalized = []
            for item in declared:
                candidate = Path(item)
                if candidate.is_absolute():
                    if not candidate.is_relative_to(path):
                        raise WorkspaceError("ENVIRONMENT_OUTSIDE_WORKTREE", str(candidate))
                    candidate = candidate.relative_to(path)
                relative = candidate.as_posix()
                if not candidate.parts or ".git" in candidate.parts:
                    raise WorkspaceError("NOT_REBUILDABLE_ENVIRONMENT", str(path / candidate))
                target = self._contained_path(path, relative)
                observed, _ = self._observe(target)
                if observed["kind"] != "DIRECTORY" or any(Path(value).is_relative_to(candidate) for value in record["origin"]):
                    raise WorkspaceError("NOT_REBUILDABLE_ENVIRONMENT", str(target))
                normalized.append(relative)
            if "rebuildable_paths" in information:
                information["rebuildable_paths"] = sorted(set(normalized))
            record["dependency_readiness"] = {"status": "ready" if ready else "not_ready", "ready": bool(ready), "details": information}
            self._save()
            return record["dependency_readiness"].copy()

    def _merge(self, base: dict[str, Any], current: dict[str, Any], result: dict[str, Any], temporary: Path) -> tuple[dict[str, Any] | None, str | None]:
        if _same(current, result) or _same(base, result):
            return current, None
        if _same(base, current):
            return result, None
        if not all(item["kind"] == "REGULAR" for item in (base, current, result)):
            return None, "ADD_DELETE_OR_OBJECT_TYPE_CONFLICT"
        if current["mode"] == base["mode"]:
            mode = result["mode"]
        elif result["mode"] == base["mode"] or current["mode"] == result["mode"]:
            mode = current["mode"]
        else:
            return None, "FILE_MODE_CONFLICT"
        contents = [self._data(item) for item in (current, base, result)]
        try:
            for data in contents:
                data.decode("utf-8")
                if b"\0" in data:
                    return None, "BINARY_CONTENT_CONFLICT"
        except UnicodeDecodeError:
            return None, "BINARY_CONTENT_CONFLICT"
        files = [temporary / value for value in ("current", "base", "result")]
        for target, data in zip(files, contents, strict=True):
            target.write_bytes(data)
        merged = self._git(self.workspace, "merge-file", "-p", "--diff3", *(str(value) for value in files), check=False)
        if 1 <= merged.returncode <= 127:
            return None, "CONTENT_CONFLICT"
        if merged.returncode != 0:
            raise WorkspaceError("MERGE_METHOD_FAILED", merged.stderr.decode("utf-8", errors="replace"), exit_code=merged.returncode)
        digest = _sha(merged.stdout)
        blob = self._blobs / digest
        if not blob.exists():
            self._atomic_bytes(blob, merged.stdout, 0o600)
        return {"kind": "REGULAR", "mode": mode, "sha256": digest, "version": digest, "blob": digest, "size_bytes": len(merged.stdout)}, None

    @_managed
    def integrate_worktree(self, path: Path, paths: Sequence[Path] | None = None) -> dict[str, Any]:
        """Three-way merge against the dirty state captured at creation.

        Untracked outputs require an explicit ``paths`` list. All known conflicts
        are found before any source write. A later concurrent change is reported
        as a partial integration with the already applied paths preserved.
        The original Git index is never staged, reset or rewritten.
        """
        with self._lock:
            path, record = self._worktree(path)
            if record["status"] not in {"ready", "conflict"} or record["integrated"]:
                raise WorkspaceError("WORKTREE_NOT_INTEGRATABLE", str(path), worktree_status=record["status"])
            repo = Path(record["repository"])
            selected = set(record["origin"]) | set(self._tracked(path, record["scope"]))
            for item in paths or ():
                value = Path(item)
                if not value.is_absolute():
                    value = Path(record["workspace_path"]) / value
                if value.is_relative_to(path):
                    relative = value.relative_to(path).as_posix()
                elif value.is_relative_to(self.workspace):
                    relative = value.relative_to(repo).as_posix()
                else:
                    raise WorkspaceError("WORKTREE_OUTPUT_OUTSIDE_WORKSPACE", str(value))
                if ".git" in Path(relative).parts:
                    raise WorkspaceError("WORKTREE_METADATA_INPUT", relative)
                selected.add(relative)
            untracked = {os.fsdecode(value) for value in self._git(path, "ls-files", "--others", "--exclude-standard", "-z", "--", record["scope"]).stdout.split(b"\0") if value}
            omitted = sorted(untracked - selected)
            if omitted:
                return {"status": "selection_required", "path": str(path), "untracked_not_integrated": omitted, "applied_paths": [], "message": "Select exact task output paths before integration"}
            plans: list[tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]] = []
            conflicts = []
            absent = {"kind": "ABSENT", "version": None, "sha256": None, "mode": None, "size_bytes": 0}
            with tempfile.TemporaryDirectory(prefix="merge-", dir=self._root) as temporary:
                for relative in sorted(selected):
                    source = self._contained_path(repo, relative)
                    target = self._contained_path(path, relative)
                    base = record["origin"].get(relative, absent)
                    current = self._snapshot(source)
                    result = self._snapshot(target)
                    merged, reason = self._merge(base, current, result, Path(temporary))
                    if reason:
                        conflicts.append({"path": relative, "reason": reason, "baseline_version": base["version"], "current_version": current["version"], "result_version": result["version"]})
                    else:
                        plans.append((relative, current, result, merged))
            if conflicts:
                record["status"] = "conflict"
                record["conflicts"] = conflicts
                self._save()
                return {"status": "conflict", "path": str(path), "conflicts": conflicts, "applied_paths": [], "untracked_not_integrated": omitted}
            for relative, current, _, _ in plans:
                self._require_unchanged(self._contained_path(repo, relative), current)
            applied = []
            integrated = {}
            try:
                for relative, current, result, merged in plans:
                    source = self._contained_path(repo, relative)
                    if not _same(current, merged):
                        self._capture(source)
                        self._install(source, merged, current)
                        applied.append(relative)
                    integrated[relative] = {"source": merged, "result": result}
            except Exception as error:
                record.update({"status": "integration_partial", "applied_paths": applied, "verified": False})
                self._save()
                raise WorkspaceConflict("INTEGRATION_INTERRUPTED", "Some paths were integrated before a concurrent change or write failure; no automatic retry was performed", applied_paths=applied, cause=str(error)) from error
            record.update({"status": "integrated", "integrated": True, "verified": False, "integration": integrated, "applied_paths": applied, "untracked_not_integrated": omitted})
            self._save()
            return {"status": "integrated", "path": str(path), "applied_paths": applied, "conflicts": [], "untracked_not_integrated": omitted, "requires_verification": True}

    @_managed
    def verify_worktree(self, path: Path, expected_versions: Mapping[str, str | None] | None = None, *, checks: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Verify delivered bytes. Optional test evidence is recorded separately."""
        with self._lock:
            path, record = self._worktree(path)
            if not record["integrated"]:
                raise WorkspaceError("NOT_INTEGRATED", str(path))
            mismatches = []
            for relative, values in record["integration"].items():
                source, _ = self._observe(self._contained_path(Path(record["repository"]), relative))
                result, _ = self._observe(self._contained_path(path, relative))
                if not _same(source, values["source"]) or not _same(result, values["result"]):
                    mismatches.append(relative)
            for relative, version in (expected_versions or {}).items():
                source, _ = self._observe(self._contained_path(Path(record["repository"]), relative))
                if source["version"] != version:
                    mismatches.append(relative)
            accepted = not mismatches and (checks is None or checks.get("accepted") is True)
            record["verified"] = accepted
            record["verification"] = {"byte_integrity_verified": not mismatches, "checks": dict(checks) if checks is not None else None, "mismatches": sorted(set(mismatches))}
            self._save()
            return {"status": "verified" if accepted else "verification_failed", **record["verification"]}

    @_managed
    def record_resource(self, resource_id: str, *, worktree: Path, kind: str, status: str, owner: str | None = None, retained: bool = False, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            path, _ = self._worktree(worktree)
            if not resource_id or not kind or not status:
                raise ValueError("Resource identity, kind and status must be nonempty")
            record = {"resource_id": resource_id, "worktree": str(path), "kind": kind, "status": status.lower(), "owner": owner or self.task_id, "retained": bool(retained), "details": dict(details or {})}
            previous = self._state["resources"].get(resource_id)
            if previous is not None and (previous["owner"] != record["owner"] or previous["worktree"] != record["worktree"]):
                if previous["retained"] or previous["status"] not in {"closed", "exited", "completed", "stopped", "cancelled"}:
                    raise WorkspaceConflict("RESOURCE_ALREADY_OWNED", resource_id, owner=previous["owner"], worktree=previous["worktree"], resource_status=previous["status"])
            self._state["resources"][resource_id] = record
            self._save()
            return record.copy()

    @_managed
    def cleanup_worktree(self, path: Path, resource_blockers: Sequence[str | Mapping[str, Any]] = ()) -> dict[str, Any]:
        with self._lock:
            path, record = self._worktree(path)
            blockers = [dict(value) if isinstance(value, Mapping) else str(value) for value in resource_blockers]
            for value in self._state["resources"].values():
                if value["worktree"] == str(path) and (value["retained"] or value["status"] in _ACTIVE or value["status"] not in {"closed", "exited", "completed", "stopped", "cancelled"}):
                    blockers.append(value.copy())
            if not record["integrated"] or not record["verified"]:
                blockers.append("INTEGRATION_NOT_VERIFIED")
            if not blockers:
                for relative, values in record["integration"].items():
                    observed, _ = self._observe(self._contained_path(path, relative))
                    if not _same(observed, values["result"]):
                        blockers.append({"path": relative, "reason": "WORKTREE_CHANGED_AFTER_INTEGRATION"})
                untracked = {os.fsdecode(value) for value in self._git(path, "ls-files", "--others", "-z", "--").stdout.split(b"\0") if value}
                readiness = record["dependency_readiness"]
                rebuildable = []
                if readiness["ready"]:
                    for relative in readiness["details"].get("rebuildable_paths", []):
                        target = self._contained_path(path, relative)
                        observed, _ = self._observe(target)
                        if observed["kind"] == "DIRECTORY":
                            rebuildable.append(Path(relative))
                        else:
                            blockers.append({"path": relative, "reason": "ENVIRONMENT_OBJECT_CHANGED"})
                for relative in sorted(untracked - set(record["integration"])):
                    if not any(Path(relative).is_relative_to(directory) for directory in rebuildable):
                        blockers.append({"path": relative, "reason": "UNSAVED_UNTRACKED_RESOURCE"})
            if blockers:
                return {"status": "blocked", "path": str(path), "blockers": blockers}
            self._git(Path(record["repository"]), "worktree", "remove", "--force", str(path))
            record["status"] = "removed"
            self._save()
            return {"status": "removed", "path": str(path), "branch_preserved": record["branch"], "baselines_preserved": True}
