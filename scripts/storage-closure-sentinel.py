#!/usr/bin/env python3
"""Capture and compare read-only Sitina production-state Sentinels.

The Sentinel deliberately hashes raw bytes without importing the Sitina
runtime, opening SQLite, parsing Journal frames, or following symlinks. Large
CAS namespaces are summarized into deterministic buckets so the JSON remains
reviewable while every regular file still contributes to the root Merkle hash.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "SITINA_STORAGE_PRODUCTION_SENTINEL_V1"
DIFF_SCHEMA = "SITINA_STORAGE_PRODUCTION_SENTINEL_DIFF_V1"
LOCAL_ROOTS = (
    "journal",
    "cas",
    "projections",
    "data",
    "logs",
    "state",
    "runtime",
    "memory",
    "backups",
    "artifacts",
    "output",
    "outputs",
    "temp",
    "cold-archives",
    "trash",
    "legacy-retired",
    "acceptance",
    "Downloads",
)


class SentinelError(RuntimeError):
    """Raised when a stable read-only snapshot cannot be proved."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    return {
        "relative_path": "",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": oct(metadata.st_mode & 0o7777),
        "mtime_ns": metadata.st_mtime_ns,
        "size": metadata.st_size,
        "type": (
            "symlink"
            if stat.S_ISLNK(metadata.st_mode)
            else "regular"
            if stat.S_ISREG(metadata.st_mode)
            else "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "special"
        ),
    }


def _paths(root: Path) -> list[Path]:
    if not root.exists() and not root.is_symlink():
        return []
    if root.is_symlink() or root.is_file():
        return [root]
    found: list[Path] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current = Path(directory)
        for name in directory_names:
            candidate = current / name
            if candidate.is_symlink():
                found.append(candidate)
        for name in file_names:
            found.append(current / name)
    return sorted(found, key=lambda item: item.relative_to(root).as_posix())


def _inventory(root: Path, paths: Iterable[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        record = _identity(path)
        record["relative_path"] = "." if path == root else path.relative_to(root).as_posix()
        records.append(record)
    return records


def _hash_regular(path: Path, before: os.stat_result) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        observed = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if observed != expected or not stat.S_ISREG(opened.st_mode):
            raise SentinelError(f"file changed before Sentinel read: {path}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = path.lstat()
    final = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if final != expected:
        raise SentinelError(f"file changed during Sentinel read: {path}")
    return digest.hexdigest()


def _file_record(root: Path, path: Path) -> dict[str, Any]:
    before = path.lstat()
    relative = "." if path == root else path.relative_to(root).as_posix()
    base = {
        "relative_path": relative,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": oct(before.st_mode & 0o7777),
        "mtime_ns": before.st_mtime_ns,
        "size": before.st_size,
    }
    if stat.S_ISLNK(before.st_mode):
        return {**base, "type": "symlink", "target": os.readlink(path)}
    if not stat.S_ISREG(before.st_mode):
        return {**base, "type": "special"}
    return {**base, "type": "regular", "sha256": _hash_regular(path, before)}


def _bucket(root_label: str, relative: str) -> str:
    parts = relative.split("/")
    if root_label == "cas" and len(parts) >= 2:
        object_name = parts[1]
        return f"{parts[0]}/{object_name[:2] or '__'}"
    return parts[0] if len(parts) > 1 else "__root__"


def _capture_root(label: str, root: Path, workers: int) -> dict[str, Any]:
    if not root.exists() and not root.is_symlink():
        return {
            "label": label,
            "path": str(root),
            "exists": False,
            "entry_count": 0,
            "total_bytes": 0,
            "merkle_root_sha256": hashlib.sha256(b"").hexdigest(),
            "buckets": [],
        }
    if root.is_symlink():
        raise SentinelError(f"production root must not be a symlink: {root}")
    paths = _paths(root)
    before_inventory = _inventory(root, paths)
    root_hash = hashlib.sha256()
    buckets: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        records = executor.map(lambda item: _file_record(root, item), paths)
        for record in records:
            encoded = _canonical(record)
            root_hash.update(encoded)
            root_hash.update(b"\n")
            total_bytes += int(record.get("size", 0))
            bucket_name = _bucket(label, str(record["relative_path"]))
            bucket = buckets.setdefault(
                bucket_name,
                {"name": bucket_name, "entry_count": 0, "total_bytes": 0, "hasher": hashlib.sha256()},
            )
            bucket["entry_count"] += 1
            bucket["total_bytes"] += int(record.get("size", 0))
            bucket["hasher"].update(encoded)
            bucket["hasher"].update(b"\n")
    after_paths = _paths(root)
    after_inventory = _inventory(root, after_paths)
    if before_inventory != after_inventory:
        raise SentinelError(f"production root changed during Sentinel capture: {root}")
    bucket_records = [
        {
            "name": name,
            "entry_count": value["entry_count"],
            "total_bytes": value["total_bytes"],
            "merkle_root_sha256": value["hasher"].hexdigest(),
        }
        for name, value in sorted(buckets.items())
    ]
    root_metadata = _identity(root)
    root_metadata.pop("relative_path", None)
    return {
        "label": label,
        "path": str(root),
        "exists": True,
        "root_metadata": root_metadata,
        "entry_count": len(paths),
        "total_bytes": total_bytes,
        "merkle_profile": "SORTED_CANONICAL_RAW_FILE_RECORDS_SHA256_V1",
        "merkle_root_sha256": root_hash.hexdigest(),
        "buckets": bucket_records,
    }


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def capture(args: argparse.Namespace) -> int:
    home = Path(args.home).expanduser().resolve(strict=True)
    roots = [(name, home / name) for name in LOCAL_ROOTS]
    extension_root = Path(
        os.environ.get("SITINA_EXTENSIONS_HOME", str(Path.home() / ".sitina" / "extensions"))
    ).expanduser().resolve(strict=False)
    roots.append(("external_extensions", extension_root))
    for raw in args.additional_root:
        label, separator, path_text = raw.partition("=")
        if not separator or not label.strip() or not path_text.strip():
            raise SentinelError("additional roots must use LABEL=/absolute/path")
        roots.append((label.strip(), Path(path_text).expanduser().resolve(strict=False)))
    if len({label for label, _path in roots}) != len(roots):
        raise SentinelError("Sentinel root labels must be unique")
    reports = [_capture_root(label, root, args.workers) for label, root in roots]
    core = {
        "schema": SCHEMA,
        "captured_at": _timestamp(),
        "goal_thread_id": args.goal_thread_id,
        "production_home": str(home),
        "observation_mode": "RAW_BYTES_READ_ONLY_NO_RUNTIME_IMPORT_NO_SQLITE_NO_JOURNAL_PARSE_NO_SYMLINK_FOLLOW",
        "hash_algorithm": "sha256",
        "roots": reports,
    }
    core["report_sha256"] = hashlib.sha256(_canonical(core)).hexdigest()
    _atomic_json(Path(args.output).expanduser().resolve(strict=False), core)
    print(json.dumps({
        "status": "ok",
        "output": str(Path(args.output).expanduser().resolve(strict=False)),
        "report_sha256": core["report_sha256"],
        "root_count": len(reports),
        "entry_count": sum(int(item["entry_count"]) for item in reports),
        "total_bytes": sum(int(item["total_bytes"]) for item in reports),
    }, sort_keys=True))
    return 0


def _load(path: str) -> dict[str, Any]:
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if value.get("schema") != SCHEMA:
        raise SentinelError(f"unsupported Sentinel schema: {path}")
    declared = value.get("report_sha256")
    core = dict(value)
    core.pop("report_sha256", None)
    if declared != hashlib.sha256(_canonical(core)).hexdigest():
        raise SentinelError(f"Sentinel report hash mismatch: {path}")
    return value


def compare(args: argparse.Namespace) -> int:
    before = _load(args.before)
    after = _load(args.after)
    before_roots = {item["label"]: item for item in before["roots"]}
    after_roots = {item["label"]: item for item in after["roots"]}
    root_changes: list[dict[str, Any]] = []
    for label in sorted(set(before_roots) | set(after_roots)):
        left = before_roots.get(label)
        right = after_roots.get(label)
        if left is None or right is None:
            root_changes.append({"label": label, "change": "added" if left is None else "removed"})
            continue
        if left["merkle_root_sha256"] == right["merkle_root_sha256"] and left["exists"] == right["exists"]:
            continue
        left_buckets = {item["name"]: item for item in left.get("buckets", [])}
        right_buckets = {item["name"]: item for item in right.get("buckets", [])}
        bucket_changes = []
        for name in sorted(set(left_buckets) | set(right_buckets)):
            old = left_buckets.get(name)
            new = right_buckets.get(name)
            if old == new:
                continue
            bucket_changes.append({
                "name": name,
                "before": old,
                "after": new,
            })
        root_changes.append({
            "label": label,
            "change": "modified",
            "before_exists": left["exists"],
            "after_exists": right["exists"],
            "before_entry_count": left["entry_count"],
            "after_entry_count": right["entry_count"],
            "before_total_bytes": left["total_bytes"],
            "after_total_bytes": right["total_bytes"],
            "before_merkle_root_sha256": left["merkle_root_sha256"],
            "after_merkle_root_sha256": right["merkle_root_sha256"],
            "bucket_changes": bucket_changes,
        })
    core = {
        "schema": DIFF_SCHEMA,
        "created_at": _timestamp(),
        "before_report_sha256": before["report_sha256"],
        "after_report_sha256": after["report_sha256"],
        "unchanged": not root_changes,
        "changed_root_count": len(root_changes),
        "root_changes": root_changes,
    }
    core["report_sha256"] = hashlib.sha256(_canonical(core)).hexdigest()
    _atomic_json(Path(args.output).expanduser().resolve(strict=False), core)
    print(json.dumps({
        "status": "ok",
        "output": str(Path(args.output).expanduser().resolve(strict=False)),
        "report_sha256": core["report_sha256"],
        "unchanged": core["unchanged"],
        "changed_root_count": len(root_changes),
    }, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--home", required=True)
    capture_parser.add_argument("--goal-thread-id", required=True)
    capture_parser.add_argument("--output", required=True)
    capture_parser.add_argument("--workers", type=int, default=min(16, max(2, (os.cpu_count() or 2) * 2)))
    capture_parser.add_argument("--additional-root", action="append", default=[])
    capture_parser.set_defaults(function=capture)
    diff_parser = commands.add_parser("diff")
    diff_parser.add_argument("--before", required=True)
    diff_parser.add_argument("--after", required=True)
    diff_parser.add_argument("--output", required=True)
    diff_parser.set_defaults(function=compare)
    return result


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "workers", 1) < 1:
        raise SentinelError("workers must be positive")
    return int(args.function(args))


if __name__ == "__main__":
    raise SystemExit(main())
