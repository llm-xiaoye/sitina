#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

from sitina.journal.model import canonical_json_bytes


ROOT_FILES = (
    ".gitignore",
    ".python-version",
    "README.md",
    "pyproject.toml",
    "requirements-bplus.lock",
)
ROOT_DIRECTORIES = (
    "agents",
    "benchmarks",
    "bin",
    "config",
    "core",
    "docs",
    "examples",
    "mcp_servers",
    "prompts",
    "schemas",
    "scripts",
    "tests",
)
EXCLUDED_ROOTS = ("artifacts", "backups", "data", "logs", "memory", "outputs", "state", "temp")
SAFE_ENV_FILES = (
    "config/permissions.env",
    "config/roles.env",
    "config/sitina.env",
)
EXCLUDED_PATTERNS = (
    "**/*.env (except declared safe config mappings)",
    "**/__pycache__/**",
    "**/.DS_Store",
    "docs/storage-production-closure/sentinel-*.json",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return digest.hexdigest()


def _excluded(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        path.name == ".DS_Store"
        or (path.suffix == ".env" and relative.as_posix() not in SAFE_ENV_FILES)
        or "__pycache__" in relative.parts
        or any(part in EXCLUDED_ROOTS for part in relative.parts[:1])
        or (
            relative.parent.as_posix() == "docs/storage-production-closure"
            and relative.name.startswith("sentinel-")
            and relative.suffix == ".json"
        )
    )


def build(root: Path, *, previous_manifest_hash: str | None) -> dict[str, object]:
    candidates = [root / name for name in ROOT_FILES]
    for name in ROOT_DIRECTORIES:
        directory = root / name
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError(f"source manifest root is unavailable: {name}")
        candidates.extend(path for path in directory.rglob("*") if not _excluded(path, root))
    entries = []
    for path in sorted(set(candidates), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_dir() and not path.is_symlink():
            continue
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"source manifest rejects non-regular entry: {path.relative_to(root)}")
        digest = _sha256(path)
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise RuntimeError(f"source changed during manifest capture: {path.relative_to(root)}")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": before.st_size,
                "mode": oct(before.st_mode & 0o7777),
                "sha256": digest,
            }
        )
    unsigned: dict[str, object] = {
        "schema": "CONTENT_MANIFEST_V1",
        "scope": "SOURCE_DOCS_TESTS_NONSECRET_CONFIG_SCHEMAS",
        "root": str(root),
        "previous_manifest_hash": previous_manifest_hash,
        "excluded_roots": list(EXCLUDED_ROOTS),
        "excluded_patterns": list(EXCLUDED_PATTERNS),
        "entries": entries,
    }
    return {**unsigned, "manifest_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture an exact nonsecret Sitina source/config manifest.")
    parser.add_argument("--root", type=Path, default=Path("/Users/moss/SitinaHub"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-manifest-hash")
    args = parser.parse_args()
    root = args.root.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve(strict=False)
    value = build(root, previous_manifest_hash=args.previous_manifest_hash)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
    os.chmod(output, 0o600)
    print(json.dumps({"output": str(output), "file_count": len(value["entries"]), "manifest_sha256": value["manifest_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
