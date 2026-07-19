"""Non-mutating Legacy inventories and fixture-only coherent snapshot tooling."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import stat
from pathlib import Path
from typing import Iterable

from sitina.legacy.fence import LegacyWriteGate
from sitina.legacy.model import (
    CapacityCheck,
    FileObservation,
    LegacyObservationManifest,
    LegacySnapshotManifest,
    SQLiteTableSummary,
    canonical_bytes,
    sha256_prefixed,
)
from sitina.legacy.readonly import LegacySQLiteReader


class InventoryError(RuntimeError):
    pass


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _existing_ancestor(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        if candidate.parent == candidate:
            raise InventoryError(f"no existing ancestor for output: {path}")
        candidate = candidate.parent
    return candidate


def _source_files(home: Path) -> list[Path]:
    roots = ("data", "logs", "state", "artifacts", "outputs", "memory")
    result: list[Path] = []
    for name in roots:
        root = home / name
        if not root.exists():
            continue
        if root.is_symlink():
            raise InventoryError(f"Legacy source root is a symlink: {root}")
        for directory, directory_names, file_names in os.walk(root, followlinks=False):
            current = Path(directory)
            for directory_name in directory_names:
                if (current / directory_name).is_symlink():
                    raise InventoryError(f"Legacy source directory symlink rejected: {current / directory_name}")
            for file_name in file_names:
                path = current / file_name
                if path.is_symlink():
                    raise InventoryError(f"Legacy source file symlink rejected: {path}")
                if path.is_file():
                    result.append(path)
    return sorted(set(result), key=lambda item: item.relative_to(home).as_posix())


def _capacity_check(files: Iterable[Path], output: Path) -> CapacityCheck:
    file_list = list(files)
    source_bytes = sum(path.lstat().st_size for path in file_list)
    required_bytes = max(1024 * 1024, int(source_bytes * 2.2) + 16 * 1024 * 1024)
    required_inodes = len(file_list) * 2 + 64
    ancestor = _existing_ancestor(output.parent)
    usage = shutil.disk_usage(ancestor)
    fs = os.statvfs(ancestor)
    free_inodes = int(fs.f_favail)
    return CapacityCheck(
        required_bytes=required_bytes,
        free_bytes=int(usage.free),
        required_inodes=required_inodes,
        free_inodes=free_inodes,
        safety_multiplier=2.2,
        passed=usage.free >= required_bytes and free_inodes >= required_inodes,
    )


def _hash_observation(home: Path, path: Path) -> FileObservation:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise InventoryError(f"source is not a regular file: {path}")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    after = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    status = "STABLE" if identity(before) == identity(after) else "CHANGED_DURING_OBSERVATION"
    return FileObservation(
        source_ref=path.relative_to(home).as_posix(),
        size=before.st_size,
        mtime_ns=before.st_mtime_ns,
        inode=before.st_ino,
        device=before.st_dev,
        mode=oct(before.st_mode & 0o7777),
        content_hash="sha256:" + digest.hexdigest(),
        observation_status=status,
    )


def _copy_sqlite_snapshot(source: Path, target: Path) -> str:
    if target.exists():
        raise InventoryError(f"SQLite snapshot target already exists: {target}")
    with LegacySQLiteReader.open(source) as reader:
        destination = sqlite3.connect(target)
        try:
            reader.connection.backup(destination, pages=2048)
            destination.commit()
            check = destination.execute("PRAGMA integrity_check").fetchall()
            if check != [("ok",)]:
                raise InventoryError(f"SQLite snapshot integrity_check failed: {check[:10]}")
        finally:
            destination.close()
    for suffix in ("-wal", "-shm"):
        if target.with_name(target.name + suffix).exists():
            raise InventoryError("independent SQLite snapshot retained a WAL/SHM sidecar")
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _table_summaries(snapshot: Path) -> dict[str, SQLiteTableSummary]:
    summaries: dict[str, SQLiteTableSummary] = {}
    with LegacySQLiteReader.open_snapshot(snapshot) as reader:
        for table in reader.table_names():
            schema = reader.schema(table)
            integer_primary = next(
                (item["name"] for item in schema if int(item.get("pk") or 0) == 1 and "INT" in str(item.get("type") or "").upper()),
                None,
            )
            summaries[table] = SQLiteTableSummary(
                row_count=reader.table_count(table),
                max_integer_key=reader.table_max_integer_key(table, integer_primary) if integer_primary else None,
            )
    return summaries


def _semantic_hash(
    coherence: str,
    sqlite_snapshot_hash: str,
    entries: tuple[FileObservation, ...],
    tables: dict[str, SQLiteTableSummary],
    *,
    cutoff: str | None = None,
    fence_snapshot_id: str | None = None,
    fence_record_hash: str | None = None,
) -> str:
    core = {
        "schema": "LEGACY_INVENTORY_SEMANTIC_V1",
        "coherence": coherence,
        "sqlite_snapshot_hash": sqlite_snapshot_hash,
        "entries": [
            {
                "source_ref": item.source_ref,
                "size": item.size,
                "content_hash": item.content_hash,
                "observation_status": item.observation_status,
            }
            for item in entries
        ],
        "table_summaries": {
            key: {"row_count": value.row_count, "max_integer_key": value.max_integer_key}
            for key, value in sorted(tables.items())
        },
        "cutoff": cutoff,
        "fence_snapshot_id": fence_snapshot_id,
        "fence_record_hash": fence_record_hash,
    }
    return sha256_prefixed(canonical_bytes(core))


def _write_manifest(output: Path, value: dict) -> None:
    path = output / "manifest.json"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    descriptor = os.open(output, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _build(home: Path, output_dir: Path, *, coherence: str, cutoff: str | None = None) -> LegacyObservationManifest:
    source = Path(home).expanduser().resolve(strict=True)
    output = Path(output_dir).expanduser().resolve(strict=False)
    if output == source or _inside(output, source) or _inside(source, output):
        raise InventoryError("inventory output and source trees must be physically disjoint")
    files = _source_files(source)
    database = source / "data/sitina.db"
    if not database.is_file() or database.is_symlink():
        raise InventoryError(f"Legacy SQLite database missing or unsafe: {database}")
    capacity = _capacity_check(files, output)
    if not capacity.passed:
        raise InventoryError(f"insufficient capacity: {capacity}")
    output.mkdir(parents=True, exist_ok=False)
    snapshot_path = output / "sqlite-snapshot.db"
    snapshot_hash = _copy_sqlite_snapshot(database, snapshot_path)
    entries = tuple(_hash_observation(source, path) for path in files)
    tables = _table_summaries(snapshot_path)
    if coherence == "FROZEN_COHERENT_SNAPSHOT" and any(item.observation_status != "STABLE" for item in entries):
        raise InventoryError("frozen coherent snapshot source changed during capture")
    observed_at = _utc_now()
    if coherence == "FROZEN_COHERENT_SNAPSHOT":
        status = LegacyWriteGate(source).status()
        semantic_hash = _semantic_hash(
            coherence,
            snapshot_hash,
            entries,
            tables,
            cutoff=cutoff,
            fence_snapshot_id=status.snapshot_id,
            fence_record_hash=status.record_hash,
        )
        manifest: LegacyObservationManifest = LegacySnapshotManifest(
            schema="LEGACY_SNAPSHOT_MANIFEST_V1",
            coherence=coherence,
            source_home=str(source),
            sqlite_snapshot_hash=snapshot_hash,
            entries=entries,
            table_summaries=tables,
            capacity_check=capacity,
            semantic_manifest_hash=semantic_hash,
            observed_at=observed_at,
            cutoff=str(cutoff),
            fence_snapshot_id=str(status.snapshot_id),
            fence_record_hash=str(status.record_hash),
        )
    else:
        semantic_hash = _semantic_hash(coherence, snapshot_hash, entries, tables)
        manifest = LegacyObservationManifest(
            schema="LEGACY_OBSERVATION_MANIFEST_V1",
            coherence=coherence,
            source_home=str(source),
            sqlite_snapshot_hash=snapshot_hash,
            entries=entries,
            table_summaries=tables,
            capacity_check=capacity,
            semantic_manifest_hash=semantic_hash,
            observed_at=observed_at,
        )
    _write_manifest(output, manifest.to_mapping())
    return manifest


def build_observational_inventory(home: Path, output_dir: Path) -> LegacyObservationManifest:
    return _build(home, output_dir, coherence="LIVE_OBSERVATIONAL_INVENTORY")


def build_frozen_snapshot(home: Path, output_dir: Path, cutoff: str) -> LegacySnapshotManifest:
    status = LegacyWriteGate(home).status()
    if status.state != "FROZEN_NO_WRITER" or not status.snapshot_id or not status.record_hash:
        raise InventoryError("FROZEN_COHERENT_SNAPSHOT requires a verified Legacy writer fence")
    manifest = _build(home, output_dir, coherence="FROZEN_COHERENT_SNAPSHOT", cutoff=cutoff)
    if not isinstance(manifest, LegacySnapshotManifest):
        raise AssertionError("frozen snapshot builder returned wrong manifest type")
    return manifest
