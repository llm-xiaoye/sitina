"""Bounded, content-addressed identity observations for Code Mode.

The production home contains large mutable CAS, Journal and artifact trees.
They are not a code identity.  This module therefore observes only a reviewed
set of identity roots and records the excluded runtime roots as part of the
manifest specification.  It never follows symlinks and never stores file
contents.
"""
from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence


DEFAULT_IDENTITY_ROOTS: tuple[str, ...] = (
    "core",
    "config",
    "scripts",
    "bin",
    "schemas",
    "prompts/agents",
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "package.json",
    "package-lock.json",
)

DEFAULT_RUNTIME_EXCLUDED_ROOTS: tuple[str, ...] = (
    "state",
    "cas",
    "journal",
    "artifacts",
    "cache",
    ".cache",
    "venv",
    ".venv",
    "logs",
    "output",
    "backups",
    "data",
    "runtime",
    ".superpowers",
)


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    import json
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _relative_name(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise ValueError("production identity path must be a safe relative path")
    return path.as_posix()


def _git_head(root: Path) -> str | None:
    marker = root / ".git"
    git_dir = marker
    if marker.is_symlink():
        raise ValueError("production .git marker may not be a symlink")
    if marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        if not text.startswith("gitdir:"):
            raise ValueError("production .git file is invalid")
        git_dir = (root / text[7:].strip()).resolve(strict=True)
    if not git_dir.is_dir():
        return None
    head = git_dir / "HEAD"
    if not head.is_file() or head.is_symlink():
        raise ValueError("production Git HEAD is unavailable")
    value = head.read_text(encoding="utf-8").strip()
    if value.startswith("ref:"):
        ref = value[5:].strip()
        ref_path = git_dir / ref
        if ref_path.is_file() and not ref_path.is_symlink():
            return ref_path.read_text(encoding="utf-8").strip()
        packed = git_dir / "packed-refs"
        if packed.is_file() and not packed.is_symlink():
            for line in packed.read_text(encoding="utf-8", errors="strict").splitlines():
                if line and not line.startswith("#"):
                    commit, name = line.split(" ", 1)
                    if name.strip() == ref:
                        return commit
        raise ValueError("production symbolic Git HEAD target is unavailable")
    return value or None


def _file_identity(path: Path, relative: str) -> dict[str, Any]:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        return {"path": relative, "kind": "symlink", "mode": mode, "target_hash": _hash_bytes(os.fsencode(target))}
    if stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            current = os.fstat(descriptor)
            if not stat.S_ISREG(current.st_mode):
                raise ValueError("production identity file changed type during observation")
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        return {"path": relative, "kind": "file", "mode": stat.S_IMODE(current.st_mode), "content_hash": "sha256:" + digest.hexdigest()}
    if stat.S_ISDIR(info.st_mode):
        return {"path": relative, "kind": "directory", "mode": mode}
    return {"path": relative, "kind": "special", "mode": mode, "type": stat.S_IFMT(info.st_mode)}


def _enumerate(root: Path, relative_root: str) -> list[dict[str, Any]]:
    start = root / relative_root
    if not start.exists() and not start.is_symlink():
        return [{"path": relative_root, "kind": "absent"}]
    result: list[dict[str, Any]] = []
    pending = [start]
    while pending:
        current = pending.pop()
        relative = current.relative_to(root).as_posix()
        identity = _file_identity(current, relative)
        result.append(identity)
        if identity.get("kind") == "directory":
            children = []
            with os.scandir(current) as entries:
                for entry in entries:
                    children.append(Path(entry.path))
            pending.extend(sorted(children, key=str, reverse=True))
    return result


def build_production_identity_manifest(
    root: Path,
    *,
    identity_roots: Sequence[str] = DEFAULT_IDENTITY_ROOTS,
    runtime_excluded_roots: Sequence[str] = DEFAULT_RUNTIME_EXCLUDED_ROOTS,
    entrypoint: str = "bin/sitina",
    executable: Path | None = None,
) -> dict[str, Any]:
    root = Path(root).expanduser().resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("production identity root must be a real directory")
    identities = tuple(sorted({_relative_name(str(item)) for item in identity_roots}))
    excluded = tuple(sorted({_relative_name(str(item)) for item in runtime_excluded_roots}))
    entrypoint = _relative_name(entrypoint)
    if not identities:
        raise ValueError("production identity roots must be explicit and non-empty")
    for item in identities:
        if any(item == excluded_item or item.startswith(excluded_item + "/") for excluded_item in excluded):
            raise ValueError("production identity root overlaps runtime exclusion")
    files: list[dict[str, Any]] = []
    for relative in identities:
        files.extend(_enumerate(root, relative))
    files.sort(key=lambda item: str(item.get("path")))
    entry = root / entrypoint
    executable = Path(executable or sys.executable).expanduser().resolve(strict=True)
    executable_info = _file_identity(executable, "<runtime-executable>")
    body: dict[str, Any] = {
        "schema": "CODE_MODE_PRODUCTION_IDENTITY_MANIFEST_V1",
        "root": str(root),
        "root_dev": int(root.stat(follow_symlinks=False).st_dev),
        "root_inode": int(root.stat(follow_symlinks=False).st_ino),
        "git_head": _git_head(root),
        "entrypoint": entrypoint,
        "entrypoint_identity": _file_identity(entry, entrypoint) if entry.exists() or entry.is_symlink() else {"path": entrypoint, "kind": "absent"},
        "runtime_excluded_roots": list(excluded),
        "identity_roots": list(identities),
        "identity_files": files,
        "runtime_executable": {"path": str(executable), **{key: value for key, value in executable_info.items() if key != "path"}},
    }
    body["manifest_hash"] = _hash_bytes(_canonical(body))
    return body


def production_identity_digest(root: Path, **kwargs: Any) -> str:
    return str(build_production_identity_manifest(root, **kwargs)["manifest_hash"])


__all__ = [
    "DEFAULT_IDENTITY_ROOTS",
    "DEFAULT_RUNTIME_EXCLUDED_ROOTS",
    "build_production_identity_manifest",
    "production_identity_digest",
]
