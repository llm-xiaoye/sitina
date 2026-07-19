from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


class LegacyCoverageError(RuntimeError):
    pass


DISPOSITIONS = {
    "MIGRATED_CANONICAL_FACT",
    "IMPORTED_LEGACY_FACT",
    "PRESERVED_ARTIFACT",
    "REPRESENTATION_DUPLICATE",
    "CONFLICT_PRESERVED",
    "LEGACY_INCOMPLETE_WITH_REASON",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _hash_regular(path: Path) -> tuple[str, os.stat_result]:
    before = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise LegacyCoverageError(f"coverage source is not a regular file: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    digest = hashlib.sha256()
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
    after = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(after):
        raise LegacyCoverageError(f"coverage source changed while hashing: {path}")
    return digest.hexdigest(), before


def _cell(value: object) -> object:
    if value is None or isinstance(value, (str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return {"type": "float", "value": repr(value)}
        return {"type": "float", "hex": value.hex()}
    if isinstance(value, bytes):
        return {"type": "blob", "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    raise LegacyCoverageError(f"unsupported SQLite value type: {type(value).__name__}")


@dataclass(frozen=True)
class FileCoverage:
    source_ref: str
    size: int
    sha256: str
    disposition: str
    reason: str | None
    jsonl_line_count: int | None = None
    jsonl_incomplete_count: int = 0


@dataclass(frozen=True)
class SQLiteChunkCoverage:
    ordinal: int
    row_count: int
    first_key: str
    last_key: str
    merkle_sha256: str


@dataclass(frozen=True)
class SQLiteTableCoverage:
    table: str
    row_count: int
    chunks: tuple[SQLiteChunkCoverage, ...]
    merkle_sha256: str


@dataclass(frozen=True)
class LegacyCoverageReport:
    source_root: str
    source_coverage_percent: int
    source_file_count: int
    covered_file_count: int
    unexplained_omission_count: int
    legacy_incomplete_with_reason_count: int
    conflict_preserved_count: int
    representation_duplicate_count: int
    files: tuple[FileCoverage, ...]
    sqlite_tables: dict[str, SQLiteTableCoverage]
    coverage_hash: str

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "LEGACY_SOURCE_COVERAGE_MANIFEST_V1",
            "source_root": self.source_root,
            "source_coverage_percent": self.source_coverage_percent,
            "source_file_count": self.source_file_count,
            "covered_file_count": self.covered_file_count,
            "unexplained_omission_count": self.unexplained_omission_count,
            "legacy_incomplete_with_reason_count": self.legacy_incomplete_with_reason_count,
            "conflict_preserved_count": self.conflict_preserved_count,
            "representation_duplicate_count": self.representation_duplicate_count,
            "files": [item.__dict__ for item in self.files],
            "sqlite_tables": {
                name: {
                    "table": item.table,
                    "row_count": item.row_count,
                    "chunks": [chunk.__dict__ for chunk in item.chunks],
                    "merkle_sha256": item.merkle_sha256,
                }
                for name, item in sorted(self.sqlite_tables.items())
            },
        }


class LegacyCoverageBuilder:
    def __init__(self, snapshot_root: Path, *, chunk_rows: int = 10_000, chunk_lines: int = 10_000):
        self.root = Path(snapshot_root).expanduser().resolve(strict=True)
        if chunk_rows < 1 or chunk_lines < 1:
            raise ValueError("coverage chunk sizes must be positive")
        self.chunk_rows = chunk_rows
        self.chunk_lines = chunk_lines

    def _files(self) -> list[Path]:
        result: list[Path] = []
        for directory, directory_names, file_names in os.walk(self.root, followlinks=False):
            current = Path(directory)
            for name in directory_names:
                if (current / name).is_symlink():
                    raise LegacyCoverageError(f"symlink directory rejected: {current / name}")
            for name in file_names:
                path = current / name
                if path.is_symlink():
                    raise LegacyCoverageError(f"symlink file rejected: {path}")
                if path.is_file():
                    result.append(path)
        return sorted(result, key=lambda item: item.relative_to(self.root).as_posix())

    @staticmethod
    def _disposition(relative: str) -> tuple[str, str | None]:
        lowered = relative.lower()
        if relative == "data/sitina.db":
            return "PRESERVED_ARTIFACT", "Original Legacy SQLite bytes retained; tables receive separate chunk coverage."
        if lowered.startswith("logs/events/") or lowered.startswith("logs/audit/"):
            return "IMPORTED_LEGACY_FACT", None
        if lowered.startswith("artifacts/") or "checkpoint" in lowered or "manifest" in lowered or "replay" in lowered or "evidence" in lowered:
            return "PRESERVED_ARTIFACT", None
        return "IMPORTED_LEGACY_FACT", None

    def _jsonl_counts(self, path: Path) -> tuple[int, int]:
        lines = 0
        incomplete = 0
        with path.open("rb") as handle:
            for raw in handle:
                lines += 1
                try:
                    value = json.loads(raw)
                    if not isinstance(value, (dict, list)):
                        incomplete += 1
                except (UnicodeDecodeError, json.JSONDecodeError):
                    incomplete += 1
        return lines, incomplete

    @staticmethod
    def _quote(name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def _sqlite(self, path: Path) -> dict[str, SQLiteTableCoverage]:
        if path.with_name(path.name + "-wal").exists() or path.with_name(path.name + "-shm").exists():
            raise LegacyCoverageError("coverage database must be an independent sidecar-free snapshot")
        encoded = urllib.parse.quote(str(path), safe="/")
        connection = sqlite3.connect(f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            result: dict[str, SQLiteTableCoverage] = {}
            for table in tables:
                quoted = self._quote(str(table))
                schema = list(connection.execute(f"PRAGMA table_info({quoted})"))
                primary = [str(row[1]) for row in schema if int(row[5]) > 0]
                order = ",".join(self._quote(name) for name in primary) if primary else "rowid"
                cursor = connection.execute(f"SELECT * FROM {quoted} ORDER BY {order}")
                chunks: list[SQLiteChunkCoverage] = []
                rows: list[dict[str, object]] = []
                ordinal = 0
                def flush() -> None:
                    nonlocal rows, ordinal
                    if not rows:
                        return
                    leaves = [hashlib.sha256(_canonical(row)).hexdigest() for row in rows]
                    merkle = hashlib.sha256("\n".join(leaves).encode()).hexdigest()
                    keys = [str(tuple(row.get(name) for name in primary) if primary else index) for index, row in enumerate(rows)]
                    chunks.append(SQLiteChunkCoverage(ordinal, len(rows), keys[0], keys[-1], merkle))
                    ordinal += 1
                    rows = []
                for row in cursor:
                    rows.append({key: _cell(row[key]) for key in row.keys()})
                    if len(rows) >= self.chunk_rows:
                        flush()
                flush()
                total = sum(item.row_count for item in chunks)
                table_merkle = hashlib.sha256("\n".join(item.merkle_sha256 for item in chunks).encode()).hexdigest()
                result[str(table)] = SQLiteTableCoverage(str(table), total, tuple(chunks), table_merkle)
            return result
        finally:
            connection.close()

    def build(self) -> LegacyCoverageReport:
        paths = self._files()
        files: list[FileCoverage] = []
        seen: dict[str, str] = {}
        duplicates = 0
        incomplete_total = 0
        for path in paths:
            relative = path.relative_to(self.root).as_posix()
            digest, metadata = _hash_regular(path)
            disposition, reason = self._disposition(relative)
            line_count: int | None = None
            incomplete = 0
            if path.suffix.lower() == ".jsonl":
                line_count, incomplete = self._jsonl_counts(path)
                if incomplete:
                    disposition = "LEGACY_INCOMPLETE_WITH_REASON"
                    reason = f"{incomplete} JSONL line(s) are invalid or non-record values; raw bytes remain preserved."
                    incomplete_total += incomplete
            if digest in seen and relative != seen[digest]:
                disposition = "REPRESENTATION_DUPLICATE"
                reason = f"Byte-identical to {seen[digest]}; both paths remain preserved."
                duplicates += 1
            else:
                seen[digest] = relative
            if disposition not in DISPOSITIONS:
                raise LegacyCoverageError(f"unknown disposition: {disposition}")
            files.append(FileCoverage(relative, metadata.st_size, digest, disposition, reason, line_count, incomplete))
        database = self.root / "data/sitina.db"
        sqlite_tables = self._sqlite(database) if database.is_file() else {}
        covered = len(files)
        core = {
            "source_root": str(self.root),
            "source_file_count": len(paths),
            "covered_file_count": covered,
            "unexplained_omission_count": len(paths) - covered,
            "legacy_incomplete_with_reason_count": incomplete_total,
            "files": [item.__dict__ for item in files],
            "sqlite_tables": {
                key: {"row_count": value.row_count, "chunks": [item.__dict__ for item in value.chunks], "merkle_sha256": value.merkle_sha256}
                for key, value in sorted(sqlite_tables.items())
            },
        }
        coverage_hash = hashlib.sha256(_canonical(core)).hexdigest()
        return LegacyCoverageReport(
            str(self.root),
            100 if len(paths) == covered else 0,
            len(paths),
            covered,
            len(paths) - covered,
            incomplete_total,
            0,
            duplicates,
            tuple(files),
            sqlite_tables,
            coverage_hash,
        )


@dataclass(frozen=True)
class FrozenSnapshotResult:
    snapshot_id: str
    source_root: str
    destination: str
    source_file_count: int
    copied_file_count: int
    sqlite_integrity: str
    entries: tuple[dict[str, object], ...]
    manifest_sha256: str


@dataclass(frozen=True)
class CanonicalLegacyBackupResult:
    backup_id: str
    source_snapshot_manifest_sha256: str
    destination: str
    file_count: int
    files: tuple[dict[str, object], ...]
    hold_sha256: str
    manifest_sha256: str


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_exact(source: Path, destination: Path) -> tuple[str, str, os.stat_result]:
    source_hash, before = _hash_regular(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        before.st_mode & 0o777,
    )
    digest = hashlib.sha256()
    try:
        with source.open("rb") as incoming, os.fdopen(descriptor, "wb", closefd=True) as outgoing:
            for chunk in iter(lambda: incoming.read(8 * 1024 * 1024), b""):
                outgoing.write(chunk)
                digest.update(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.utime(destination, ns=(before.st_atime_ns, before.st_mtime_ns), follow_symlinks=False)
    after_hash, after = _hash_regular(source)
    if source_hash != after_hash or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise LegacyCoverageError(f"frozen source changed while copying: {source}")
    copied_hash = digest.hexdigest()
    if copied_hash != source_hash:
        raise LegacyCoverageError(f"copied bytes differ from frozen source: {source}")
    _sync_directory(destination.parent)
    return source_hash, copied_hash, before


class FrozenSnapshotBuilder:
    ROOTS = ("data", "logs", "state", "artifacts", "outputs", "memory", "backups", "temp")

    def build(self, source_root: Path, destination: Path, capability: object, *, now: int) -> FrozenSnapshotResult:
        from sitina.legacy.fence import LegacyWriteGate
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise LegacyCoverageError("frozen snapshot requires a verified Phase 6B capability")
        source = Path(source_root).resolve(strict=True)
        target = Path(destination).resolve(strict=False)
        capability.assert_operation("CREATE_FROZEN_SNAPSHOT", target, now=now)
        if source != capability.production_home or target != capability.snapshot_root:
            raise LegacyCoverageError("snapshot roots differ from the Maintenance Manifest")
        fence = LegacyWriteGate(source).status()
        if fence.state != "FROZEN_NO_WRITER" or not fence.snapshot_id or not fence.record_hash:
            raise LegacyCoverageError("frozen snapshot requires a verified no-writer fence")
        if fence.snapshot_destination != str(target):
            raise LegacyCoverageError("writer fence snapshot destination differs from the Maintenance Manifest")
        if target.exists():
            raise LegacyCoverageError("frozen snapshot destination already exists")
        target.mkdir(parents=True)
        entries: list[dict[str, object]] = []
        for root_name in self.ROOTS:
            root = source / root_name
            if not root.exists():
                continue
            if root.is_symlink():
                raise LegacyCoverageError(f"snapshot root is a symlink: {root}")
            for directory, directory_names, file_names in os.walk(root, followlinks=False):
                current = Path(directory)
                relative_dir = current.relative_to(source)
                (target / relative_dir).mkdir(parents=True, exist_ok=True)
                for name in directory_names:
                    if (current / name).is_symlink():
                        raise LegacyCoverageError(f"snapshot directory symlink rejected: {current / name}")
                for name in file_names:
                    path = current / name
                    if path.is_symlink():
                        raise LegacyCoverageError(f"snapshot file symlink rejected: {path}")
                    if not path.is_file():
                        continue
                    destination_file = target / path.relative_to(source)
                    source_hash, copied_hash, metadata = _copy_exact(path, destination_file)
                    entries.append({
                        "path": path.relative_to(source).as_posix(),
                        "size": metadata.st_size,
                        "source_sha256": source_hash,
                        "copied_sha256": copied_hash,
                        "source_inode": metadata.st_ino,
                        "source_mtime_ns": metadata.st_mtime_ns,
                        "disposition": "COPIED_TO_FROZEN_SNAPSHOT",
                    })
        sqlite_copy = target / "data/sitina.db"
        integrity = "NOT_PRESENT"
        if sqlite_copy.is_file():
            connection = sqlite3.connect(sqlite_copy, timeout=60)
            try:
                connection.execute("PRAGMA busy_timeout=60000")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                result = connection.execute("PRAGMA integrity_check").fetchall()
                if result != [("ok",)]:
                    raise LegacyCoverageError(f"frozen SQLite integrity_check failed: {result[:10]}")
                connection.commit()
                integrity = "ok"
            finally:
                connection.close()
            for suffix in ("-wal", "-shm"):
                sidecar = sqlite_copy.with_name(sqlite_copy.name + suffix)
                if sidecar.exists():
                    if sidecar.is_symlink():
                        raise LegacyCoverageError("snapshot SQLite sidecar is a symlink")
                    sidecar.unlink()
            db_fd = os.open(sqlite_copy, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(db_fd)
            finally:
                os.close(db_fd)
            _sync_directory(sqlite_copy.parent)
        expected = {str(item["path"]): item for item in entries}
        observed: dict[str, Path] = {}
        for root_name in self.ROOTS:
            root = source / root_name
            if not root.exists():
                continue
            for directory, directory_names, file_names in os.walk(root, followlinks=False):
                current = Path(directory)
                for name in directory_names:
                    if (current / name).is_symlink():
                        raise LegacyCoverageError(f"source closure contains a directory symlink: {current / name}")
                for name in file_names:
                    path = current / name
                    if path.is_symlink() or not path.is_file():
                        raise LegacyCoverageError(f"source closure contains a non-regular file: {path}")
                    observed[path.relative_to(source).as_posix()] = path
        if set(observed) != set(expected):
            raise LegacyCoverageError("frozen source path set changed during snapshot creation")
        for relative, path in observed.items():
            digest, metadata = _hash_regular(path)
            item = expected[relative]
            if (
                digest != item["source_sha256"]
                or metadata.st_size != item["size"]
                or metadata.st_ino != item["source_inode"]
                or metadata.st_mtime_ns != item["source_mtime_ns"]
            ):
                raise LegacyCoverageError(f"frozen source closure changed after copying: {relative}")
        core = {
            "schema": "FROZEN_COHERENT_SNAPSHOT_V1",
            "snapshot_id": fence.snapshot_id,
            "fence_record_hash": fence.record_hash,
            "phase6b_manifest_sha256": capability.manifest_sha256,
            "intended_snapshot_hash": str(capability.production_genesis["intended_snapshot_hash"]),
            "source_root": str(source),
            "destination": str(target),
            "source_file_count": len(entries),
            "copied_file_count": len(entries),
            "sqlite_integrity": integrity,
            "source_closure_verified": True,
            "entries": sorted(entries, key=lambda item: str(item["path"])),
        }
        manifest_hash = hashlib.sha256(_canonical(core)).hexdigest()
        manifest_path = target / "frozen-snapshot-manifest.json"
        manifest_path.write_bytes(json.dumps({**core, "manifest_sha256": manifest_hash}, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n")
        with manifest_path.open("rb") as handle:
            os.fsync(handle.fileno())
        _sync_directory(target)
        return FrozenSnapshotResult(fence.snapshot_id, str(source), str(target), len(entries), len(entries), integrity, tuple(core["entries"]), manifest_hash)


class CanonicalLegacyBackupBuilder:
    def build(self, snapshot: FrozenSnapshotResult, destination: Path, capability: object, *, now: int) -> CanonicalLegacyBackupResult:
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise LegacyCoverageError("canonical backup requires a verified Phase 6B capability")
        source = Path(snapshot.destination).resolve(strict=True)
        target = Path(destination).resolve(strict=False)
        capability.assert_operation("CREATE_AND_VERIFY_CANONICAL_BACKUP", target, now=now)
        if not (source == capability.snapshot_root or _inside(source, capability.snapshot_root)):
            raise LegacyCoverageError("backup source is outside the frozen snapshot root")
        if not (target == capability.backup_root or _inside(target, capability.backup_root)) or target.exists():
            raise LegacyCoverageError("backup destination is invalid or already exists")
        target.mkdir(parents=True)
        files: list[dict[str, object]] = []
        for path in sorted((item for item in source.rglob("*") if item.is_file()), key=lambda item: item.relative_to(source).as_posix()):
            if path.is_symlink():
                raise LegacyCoverageError("backup source symlink rejected")
            copied = target / path.relative_to(source)
            source_hash, copied_hash, metadata = _copy_exact(path, copied)
            files.append({"path": path.relative_to(source).as_posix(), "size": metadata.st_size, "sha256": source_hash, "copied_sha256": copied_hash})
        backup_id = "backup-" + snapshot.manifest_sha256[:32]
        hold_core = {"schema": "CANONICAL_BACKUP_HOLD_V1", "backup_id": backup_id, "snapshot_manifest_sha256": snapshot.manifest_sha256, "held": True}
        hold_hash = hashlib.sha256(_canonical(hold_core)).hexdigest()
        core = {
            "schema": "CANONICAL_LEGACY_BACKUP_V1",
            "backup_id": backup_id,
            "source_snapshot_manifest_sha256": snapshot.manifest_sha256,
            "destination": str(target),
            "file_count": len(files),
            "files": files,
            "hold_sha256": hold_hash,
        }
        manifest_hash = hashlib.sha256(_canonical(core)).hexdigest()
        (target / "backup-manifest.json").write_bytes(json.dumps({**core, "manifest_sha256": manifest_hash}, sort_keys=True, indent=2).encode() + b"\n")
        (target / "backup-hold.json").write_bytes(json.dumps({**hold_core, "hold_sha256": hold_hash}, sort_keys=True, indent=2).encode() + b"\n")
        for name in ("backup-manifest.json", "backup-hold.json"):
            with (target / name).open("rb") as handle:
                os.fsync(handle.fileno())
        _sync_directory(target)
        return CanonicalLegacyBackupResult(backup_id, snapshot.manifest_sha256, str(target), len(files), tuple(files), hold_hash, manifest_hash)

    def verify_restore(self, backup: CanonicalLegacyBackupResult, restore_root: Path, capability: object, *, now: int) -> dict[str, object]:
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise LegacyCoverageError("restore drill requires a verified Phase 6B capability")
        source = Path(backup.destination).resolve(strict=True)
        target = Path(restore_root).resolve(strict=False)
        capability.assert_operation("CREATE_AND_VERIFY_CANONICAL_BACKUP", target, now=now)
        if target.exists() or not (target == capability.control_root or _inside(target, capability.control_root)):
            raise LegacyCoverageError("restore drill destination is invalid")
        target.mkdir(parents=True)
        mismatches: list[str] = []
        for item in backup.files:
            path = source / str(item["path"])
            if not path.is_file() or _hash_regular(path)[0] != item["sha256"]:
                mismatches.append(str(item["path"])); continue
            copied = target / str(item["path"])
            source_hash, copied_hash, _ = _copy_exact(path, copied)
            if source_hash != copied_hash:
                mismatches.append(str(item["path"]))
        sqlite_path = target / "data/sitina.db"
        integrity = "NOT_PRESENT"
        if sqlite_path.is_file():
            encoded = urllib.parse.quote(str(sqlite_path), safe="/")
            connection = sqlite3.connect(f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=60)
            try:
                result = connection.execute("PRAGMA integrity_check").fetchall()
                integrity = "ok" if result == [("ok",)] else "failed"
            finally:
                connection.close()
            if integrity != "ok":
                mismatches.append("data/sitina.db#integrity")
        proof = {
            "schema": "CANONICAL_LEGACY_BACKUP_RESTORE_VERIFIED_V1",
            "backup_id": backup.backup_id,
            "backup_manifest_sha256": backup.manifest_sha256,
            "restored_file_count": len(backup.files),
            "mismatches": mismatches,
            "sqlite_integrity": integrity,
            "verified": not mismatches,
            "writer_activated": False,
        }
        proof["report_sha256"] = hashlib.sha256(_canonical(proof)).hexdigest()
        return proof
