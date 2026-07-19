#!/usr/bin/env python3
"""Create a source-only content manifest without importing Sitina."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


SOURCE_ROOTS = ("core", "tests", "scripts", "bin", "schemas", "docs", "config", "examples")
ROOT_FILES = ("README.md", ".gitignore", "pyproject.toml", "requirements-bplus.lock", ".python-version")
RUNTIME_ROOTS = {"data", "logs", "state", "artifacts", "outputs", "memory", "backups", "temp"}
ALLOWED_SUFFIXES = {".py", ".md", ".json", ".yaml", ".yml", ".toml", ".lock"}


class AuditError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_secret_name(path: Path) -> bool:
    lowered = path.name.lower()
    return path.suffix == ".env" or "credential" in lowered or "secret" in lowered


def _hash_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuditError(f"not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return digest.hexdigest()


def discover(root: Path) -> list[Path]:
    repository = root.resolve(strict=True)
    paths: list[Path] = []
    for source_name in SOURCE_ROOTS:
        if source_name in RUNTIME_ROOTS:
            raise AuditError(f"runtime root configured as source: {source_name}")
        source = repository / source_name
        if not source.exists():
            continue
        if source.is_symlink():
            raise AuditError(f"source root is a symlink: {source}")
        for directory, directory_names, file_names in os.walk(source, followlinks=False):
            current = Path(directory)
            for name in list(directory_names):
                candidate = current / name
                if candidate.is_symlink():
                    raise AuditError(f"symlink directory rejected: {candidate}")
                native_plugin_metadata = source_name == "examples" and name == ".sitina-plugin"
                if name == "__pycache__" or (name.startswith(".") and not native_plugin_metadata):
                    directory_names.remove(name)
            for name in file_names:
                candidate = current / name
                if name == ".DS_Store" or "__pycache__" in candidate.parts:
                    continue
                if candidate.is_symlink():
                    raise AuditError(f"symlink file rejected: {candidate}")
                resolved = candidate.resolve(strict=True)
                if not _inside(resolved, repository):
                    raise AuditError(f"path escapes repository: {candidate}")
                if source_name == "config" and _is_secret_name(candidate):
                    continue
                if candidate.suffix in ALLOWED_SUFFIXES or (source_name == "bin" and name == "sitina"):
                    paths.append(candidate)
    for name in ROOT_FILES:
        candidate = repository / name
        if candidate.exists():
            if candidate.is_symlink():
                raise AuditError(f"root source file is a symlink: {candidate}")
            paths.append(candidate)
    return sorted(set(paths), key=lambda path: path.relative_to(repository).as_posix())


def build_manifest(root: Path, previous_manifest_hash: str | None = None) -> dict[str, Any]:
    repository = root.resolve(strict=True)
    entries = []
    for path in discover(repository):
        metadata = path.stat()
        entries.append(
            {
                "path": path.relative_to(repository).as_posix(),
                "mode": oct(metadata.st_mode & 0o7777),
                "size": metadata.st_size,
                "sha256": _hash_regular_file(path),
            }
        )
    core = {
        "schema": "CONTENT_MANIFEST_V1",
        "root": str(repository),
        "scope": "SOURCE_DOCS_TESTS_NONSECRET_CONFIG_SCHEMAS",
        "previous_manifest_hash": previous_manifest_hash,
        "entries": entries,
        "excluded_roots": sorted(RUNTIME_ROOTS),
        "excluded_patterns": ["**/*.env", "**/__pycache__/**", "**/.DS_Store"],
    }
    return {**core, "manifest_sha256": hashlib.sha256(canonical_bytes(core)).hexdigest()}


def write_new(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.resolve(strict=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--previous-manifest-hash")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    manifest = build_manifest(arguments.root, arguments.previous_manifest_hash)
    if arguments.output:
        write_new(arguments.output, manifest)
        print(f"wrote: {arguments.output}")
    else:
        json.dump(manifest, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
