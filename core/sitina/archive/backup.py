from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Mapping

from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash, validate_identifier


class BackupError(RuntimeError):
    pass


def _require_disposable(path: Path) -> None:
    resolved = path.resolve(strict=False)
    if not any((parent / ".sitina-bplus-disposable-v1").is_file() for parent in (resolved, *resolved.parents)):
        raise BackupError("backup operation requires a marked disposable home")


def _relative_path(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise BackupError("backup path is not a safe relative path")
    return Path(*pure.parts)


@dataclass(frozen=True)
class BackupFile:
    path: str
    sha256: str
    size: int

    def mapping(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class CanonicalBackupManifest:
    backup_id: str
    source_root: Path
    destination: Path
    frontier: FrontierRef
    reachable_paths: tuple[str, ...]
    files: tuple[BackupFile, ...]
    active_prefix_disposition: str
    hold_snapshot_hash: str
    manifest_hash: str

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "CANONICAL_BACKUP_MANIFEST_V1",
            "backup_id": self.backup_id,
            "frontier": self.frontier.__dict__,
            "reachable_paths": list(self.reachable_paths),
            "files": [item.mapping() for item in self.files],
            "active_prefix_disposition": self.active_prefix_disposition,
            "hold_snapshot_hash": self.hold_snapshot_hash,
        }


class BackupHoldRegistry:
    def __init__(self) -> None:
        self._holds: dict[str, frozenset[str]] = {}

    def acquire(self, backup_id: str, paths: tuple[str, ...]) -> str:
        if backup_id in self._holds:
            raise BackupError("backup hold already exists")
        self._holds[backup_id] = frozenset(paths)
        return domain_hash(
            "BACKUP_HOLD_SNAPSHOT",
            canonical_json_bytes({"backup_id": backup_id, "paths": sorted(paths)}),
        )

    def has_backup(self, backup_id: str) -> bool:
        return backup_id in self._holds

    def is_held(self, backup_id: str, path: str) -> bool:
        return path in self._holds.get(backup_id, frozenset())

    def release(self, backup_id: str) -> None:
        self._holds.pop(backup_id, None)


class CanonicalBackupBuilder:
    ALLOWED_PREFIX_DISPOSITIONS = frozenset({"FORCED_ROLLOVER", "FROZEN_EXACT_PREFIX"})

    def __init__(self, holds: BackupHoldRegistry):
        self.holds = holds

    def build(
        self,
        backup_id: str,
        *,
        source_root: Path,
        destination: Path,
        frontier: FrontierRef,
        reachable_paths: tuple[str, ...],
        active_prefix_disposition: str,
    ) -> CanonicalBackupManifest:
        validate_identifier(backup_id, field="backup_id")
        source = Path(source_root).resolve()
        target = Path(destination).resolve(strict=False)
        _require_disposable(source)
        _require_disposable(target)
        if active_prefix_disposition not in self.ALLOWED_PREFIX_DISPOSITIONS:
            raise BackupError("active Journal prefix is not frozen or rolled over")
        paths = tuple(sorted(set(reachable_paths)))
        if len(paths) != len(reachable_paths):
            raise BackupError("reachable paths must be unique")
        for value in paths:
            _relative_path(value)
        # Acquire the closure hold before any existence/read checks. A failed
        # build deliberately retains this hold for operator reconciliation.
        hold_hash = self.holds.acquire(backup_id, paths)
        if target.exists():
            raise BackupError("backup destination already exists")
        files: list[BackupFile] = []
        for value in paths:
            relative = _relative_path(value)
            source_file = (source / relative).resolve()
            if source not in source_file.parents or not source_file.is_file() or source_file.is_symlink():
                raise BackupError(f"reachable backup object is unavailable: {value}")
            raw = source_file.read_bytes()
            files.append(BackupFile(value, hashlib.sha256(raw).hexdigest(), len(raw)))
        for item in files:
            source_file = source / _relative_path(item.path)
            target_file = target / _relative_path(item.path)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, target_file)
        provisional = CanonicalBackupManifest(
            backup_id, source, target, frontier, paths, tuple(files), active_prefix_disposition, hold_hash, ""
        )
        return replace(
            provisional,
            manifest_hash=domain_hash("CANONICAL_BACKUP_MANIFEST", canonical_json_bytes(provisional.mapping())),
        )

    def verify_restore(self, manifest: CanonicalBackupManifest, *, restore_root: Path) -> dict[str, object]:
        target = Path(restore_root).resolve(strict=False)
        _require_disposable(target)
        if target.exists():
            raise BackupError("isolated restore destination already exists")
        for item in manifest.files:
            source = manifest.destination / _relative_path(item.path)
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != item.sha256:
                raise BackupError("backup verification failed before restore")
            destination = target / _relative_path(item.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        verified = all(
            hashlib.sha256((target / _relative_path(item.path)).read_bytes()).hexdigest() == item.sha256
            for item in manifest.files
        )
        if not verified:
            raise BackupError("isolated restore verification failed")
        return {"schema": "CANONICAL_BACKUP_RESTORE_VERIFIED_V1", "backup_id": manifest.backup_id, "manifest_hash": manifest.manifest_hash, "verified": True}

    def release_hold(self, manifest: CanonicalBackupManifest, *, restore_verified: bool) -> None:
        if not restore_verified:
            raise BackupError("backup hold cannot release before an isolated restore verifies")
        self.holds.release(manifest.backup_id)
