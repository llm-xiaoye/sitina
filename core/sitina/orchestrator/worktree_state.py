from __future__ import annotations

import base64
import hashlib
import os
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from sitina.cas.local import LocalCAS
from sitina.journal.model import canonical_json_bytes, parse_canonical_json


class WorktreeStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorktreeState:
    base_commit: str
    temporary_branch: str
    diff_ref: str
    untracked_files_manifest_ref: str
    git_status_ref: str
    reconstruction_verified: bool

    def mapping(self) -> dict[str, Any]:
        return {"schema": "SITINA_WORKTREE_STATE_V1", **self.__dict__}


class WorktreeStateRepository:
    """CAS-native recoverability record; it never copies or removes a repository."""

    TENANT = "sitina-worktree"
    _STATE_FIELDS = frozenset(
        {
            "schema",
            "base_commit",
            "temporary_branch",
            "diff_ref",
            "untracked_files_manifest_ref",
            "git_status_ref",
            "reconstruction_verified",
        }
    )

    def __init__(self, cas: LocalCAS):
        self.cas = cas

    @staticmethod
    def _git(repo: Path, arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
        process = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            detail = process.stderr.decode("utf-8", errors="replace")[-2000:]
            raise WorktreeStateError(f"git {' '.join(arguments)} failed: {detail}")
        return process.stdout

    @classmethod
    def _root(cls, repo: str | Path) -> Path:
        requested = Path(repo).expanduser().resolve(strict=True)
        value = cls._git(requested, ["rev-parse", "--show-toplevel"]).decode("utf-8", errors="strict").strip()
        root = Path(value).resolve(strict=True)
        if not root.is_dir():
            raise WorktreeStateError("Git worktree root is unavailable")
        return root

    def _publish(self, raw: bytes, *, purpose: str) -> str:
        publication = self.cas.publish_plaintext(
            raw,
            tenant_id=self.TENANT,
            purpose_class=purpose,
            compression="auto",
            media_type="application/json" if raw.startswith(b"{") else "application/octet-stream",
        )
        return publication.receipt.object_ref.reference_id

    def _open(self, reference: str) -> bytes:
        return self.cas.open_verified(self.cas.resolve_reference(reference))

    @staticmethod
    def _safe_relative_path(value: str) -> PurePosixPath:
        path = PurePosixPath(value)
        if not value or path.is_absolute() or ".." in path.parts or ".git" in path.parts or str(path) != value:
            raise WorktreeStateError("worktree manifest contains an unsafe path")
        return path

    @staticmethod
    def _untracked_paths(repo: Path) -> tuple[str, ...]:
        raw = WorktreeStateRepository._git(repo, ["ls-files", "--others", "--exclude-standard", "-z"])
        values = tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)
        if values != tuple(sorted(set(values))):
            raise WorktreeStateError("Git returned a non-canonical untracked inventory")
        return values

    def _capture_untracked(self, repo: Path) -> tuple[str, tuple[dict[str, Any], ...]]:
        records: list[dict[str, Any]] = []
        for relative in self._untracked_paths(repo):
            safe = self._safe_relative_path(relative)
            source = repo.joinpath(*safe.parts)
            metadata = source.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise WorktreeStateError("untracked symlinks and special files are not recoverable")
            raw = source.read_bytes()
            records.append(
                {
                    "path": relative,
                    "mode": 0o755 if metadata.st_mode & 0o111 else 0o644,
                    "content_ref": self._publish(raw, purpose="worktree-untracked-file"),
                    "content_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        manifest = {
            "schema": "SITINA_WORKTREE_UNTRACKED_MANIFEST_V1",
            "files": records,
        }
        reference = self._publish(canonical_json_bytes(manifest), purpose="worktree-untracked-manifest")
        return reference, tuple(records)

    @staticmethod
    def _diff_document(repo: Path) -> tuple[bytes, bytes, bytes]:
        index_patch = WorktreeStateRepository._git(repo, ["diff", "--binary", "--cached", "HEAD", "--"])
        worktree_patch = WorktreeStateRepository._git(repo, ["diff", "--binary", "--",])
        document = {
            "schema": "SITINA_WORKTREE_DIFF_V1",
            "index_patch_base64": base64.b64encode(index_patch).decode("ascii"),
            "index_patch_sha256": hashlib.sha256(index_patch).hexdigest(),
            "worktree_patch_base64": base64.b64encode(worktree_patch).decode("ascii"),
            "worktree_patch_sha256": hashlib.sha256(worktree_patch).hexdigest(),
        }
        return canonical_json_bytes(document), index_patch, worktree_patch

    @staticmethod
    def _status(repo: Path) -> bytes:
        return WorktreeStateRepository._git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])

    def capture(self, repo: str | Path) -> tuple[str, WorktreeState]:
        source = self._root(repo)
        base_commit = self._git(source, ["rev-parse", "HEAD"]).decode("ascii", errors="strict").strip()
        if not base_commit or len(base_commit) not in {40, 64}:
            raise WorktreeStateError("worktree has no supported base commit")
        branch_process = subprocess.run(
            ["git", "-C", str(source), "symbolic-ref", "--quiet", "--short", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        branch = branch_process.stdout.decode("utf-8", errors="strict").strip() if branch_process.returncode == 0 else "DETACHED"
        diff_raw, _index_patch, _worktree_patch = self._diff_document(source)
        diff_ref = self._publish(diff_raw, purpose="worktree-diff")
        manifest_ref, _records = self._capture_untracked(source)
        status = self._status(source)
        status_ref = self._publish(status, purpose="worktree-git-status")

        provisional = WorktreeState(base_commit, branch, diff_ref, manifest_ref, status_ref, False)
        with tempfile.TemporaryDirectory(prefix="sitina-worktree-verify-") as temporary:
            target = Path(temporary) / "reconstructed"
            report = self._reconstruct_components(source, provisional, target)
            if not report["verified"]:
                raise WorktreeStateError("worktree reconstruction did not reproduce the captured status")
        state = WorktreeState(base_commit, branch, diff_ref, manifest_ref, status_ref, True)
        state_ref = self._publish(canonical_json_bytes(state.mapping()), purpose="worktree-state-v1")
        return state_ref, state

    def load(self, state_ref: str) -> WorktreeState:
        value = parse_canonical_json(self._open(state_ref), allowed_fields=self._STATE_FIELDS)
        if value.get("schema") != "SITINA_WORKTREE_STATE_V1" or set(value) != self._STATE_FIELDS:
            raise WorktreeStateError("invalid Worktree State schema")
        state = WorktreeState(
            base_commit=str(value["base_commit"]),
            temporary_branch=str(value["temporary_branch"]),
            diff_ref=str(value["diff_ref"]),
            untracked_files_manifest_ref=str(value["untracked_files_manifest_ref"]),
            git_status_ref=str(value["git_status_ref"]),
            reconstruction_verified=bool(value["reconstruction_verified"]),
        )
        if not state.reconstruction_verified:
            raise WorktreeStateError("unverified Worktree State cannot be used for cleanup or recovery")
        return state

    def _diff_parts(self, diff_ref: str) -> tuple[bytes, bytes]:
        value = parse_canonical_json(self._open(diff_ref))
        expected = {
            "schema",
            "index_patch_base64",
            "index_patch_sha256",
            "worktree_patch_base64",
            "worktree_patch_sha256",
        }
        if value.get("schema") != "SITINA_WORKTREE_DIFF_V1" or set(value) != expected:
            raise WorktreeStateError("invalid worktree Diff document")
        try:
            index_patch = base64.b64decode(value["index_patch_base64"], validate=True)
            worktree_patch = base64.b64decode(value["worktree_patch_base64"], validate=True)
        except Exception as error:
            raise WorktreeStateError("worktree Diff encoding is invalid") from error
        if hashlib.sha256(index_patch).hexdigest() != value["index_patch_sha256"] or hashlib.sha256(worktree_patch).hexdigest() != value["worktree_patch_sha256"]:
            raise WorktreeStateError("worktree Diff commitment mismatch")
        return index_patch, worktree_patch

    def _restore_untracked(self, target: Path, manifest_ref: str) -> None:
        value = parse_canonical_json(self._open(manifest_ref))
        if value.get("schema") != "SITINA_WORKTREE_UNTRACKED_MANIFEST_V1" or set(value) != {"schema", "files"}:
            raise WorktreeStateError("invalid untracked-files manifest")
        records = value["files"]
        if not isinstance(records, list) or [item.get("path") for item in records] != sorted({item.get("path") for item in records}):
            raise WorktreeStateError("untracked-files manifest is not canonical")
        for record in records:
            if set(record) != {"path", "mode", "content_ref", "content_sha256"}:
                raise WorktreeStateError("invalid untracked-files manifest record")
            safe = self._safe_relative_path(str(record["path"]))
            destination = target.joinpath(*safe.parts)
            cursor = target
            for part in safe.parts[:-1]:
                cursor = cursor / part
                if cursor.exists() and cursor.is_symlink():
                    raise WorktreeStateError("untracked restore would traverse a symlink")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                raise WorktreeStateError("untracked restore would overwrite a tracked path")
            raw = self._open(str(record["content_ref"]))
            if hashlib.sha256(raw).hexdigest() != record["content_sha256"]:
                raise WorktreeStateError("untracked file commitment mismatch")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), int(record["mode"]))
            try:
                os.write(descriptor, raw)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _reconstruct_components(self, source_repo: Path, state: WorktreeState, target: Path) -> dict[str, Any]:
        if target.exists():
            raise WorktreeStateError("worktree reconstruction target must not exist")
        parent = target.parent.resolve(strict=True)
        process = subprocess.run(
            ["git", "clone", "--no-checkout", "--local", str(source_repo), str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if process.returncode != 0:
            detail = process.stderr.decode("utf-8", errors="replace")[-2000:]
            raise WorktreeStateError(f"temporary reconstruction clone failed: {detail}")
        if target.parent.resolve(strict=True) != parent:
            raise WorktreeStateError("reconstruction target escaped its requested parent")
        self._git(target, ["checkout", "--detach", state.base_commit])
        index_patch, worktree_patch = self._diff_parts(state.diff_ref)
        if index_patch:
            self._git(target, ["apply", "--binary", "--index", "-"], input_bytes=index_patch)
        if worktree_patch:
            self._git(target, ["apply", "--binary", "-"], input_bytes=worktree_patch)
        self._restore_untracked(target, state.untracked_files_manifest_ref)
        status = self._status(target)
        expected_status = self._open(state.git_status_ref)
        return {
            "schema": "SITINA_WORKTREE_RECONSTRUCTION_REPORT_V1",
            "target": str(target),
            "base_commit": state.base_commit,
            "verified": status == expected_status,
            "status_sha256": hashlib.sha256(status).hexdigest(),
            "expected_status_sha256": hashlib.sha256(expected_status).hexdigest(),
            "source_repository_modified": False,
        }

    def reconstruct(self, source_repo: str | Path, state_ref: str, target: str | Path) -> dict[str, Any]:
        source = self._root(source_repo)
        state = self.load(state_ref)
        return self._reconstruct_components(source, state, Path(target).expanduser())


__all__ = ["WorktreeState", "WorktreeStateError", "WorktreeStateRepository"]
