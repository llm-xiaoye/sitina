from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Iterator

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


def _validate_paths(paths: tuple[str, ...], *, reserved: frozenset[str] = frozenset()) -> None:
    normalized = tuple(_relative_path(value) for value in paths)
    if len(set(normalized)) != len(normalized):
        raise BackupError("backup paths must name distinct members")
    members = set(normalized)
    for path in normalized:
        if path.parts[0] in reserved or any(parent in members for parent in path.parents):
            raise BackupError("backup member conflicts with a parent or reserved restore path")


def _root_path(path: Path) -> Path:
    # Canonicalize the root's parent, never its final component or any member.
    path = Path(path)
    return path.parent.resolve(strict=False) / path.name


@contextmanager
def _root_fd(path: Path, *, create: bool = False, exclusive: bool = False) -> Iterator[int]:
    try:
        if create:
            path.mkdir(parents=True, exist_ok=not exclusive)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise BackupError("backup root is unavailable or is a symbolic link") from error
    try:
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _parent_fd(root_fd: int, value: str, *, create: bool = False) -> Iterator[tuple[int, bytes]]:
    parts = _relative_path(value).parts
    descriptor = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, os.fsencode(parts[-1])
    except OSError as error:
        raise BackupError(f"backup member parent or leaf is unavailable: {value}") from error
    finally:
        os.close(descriptor)


def _read_member(root_fd: int, value: str) -> tuple[str, bytes]:
    with _parent_fd(root_fd, value) as (parent, leaf):
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            # A bytes path makes readlink return the original target bytes.
            return "SYMLINK", os.readlink(leaf, dir_fd=parent)
        if not stat.S_ISREG(before.st_mode):
            raise BackupError(f"backup member has an unsupported object type: {value}")
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise BackupError(f"backup member changed while opening: {value}")
            return "REGULAR", handle.read()


def _write_member(root_fd: int, value: str, kind: str, raw: bytes, *, replace_existing: bool = False) -> None:
    if kind not in {"REGULAR", "SYMLINK"}:
        raise BackupError("cannot restore an unsupported object type")
    with _parent_fd(root_fd, value, create=True) as (parent, leaf):
        if replace_existing:
            try:
                os.unlink(leaf, dir_fd=parent)
            except FileNotFoundError:
                pass
        if kind == "SYMLINK":
            os.symlink(raw, leaf, dir_fd=parent)
        else:
            descriptor = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=parent)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)


@dataclass(frozen=True)
class BackupFile:
    path: str
    sha256: str
    size: int
    # None preserves the legacy three-field REGULAR mapping and its hash input.
    object_type: str | None = None
    raw_target_base64: str | None = None

    @property
    def kind(self) -> str:
        kind = "REGULAR" if self.object_type is None else self.object_type
        if kind == "REGULAR" and self.raw_target_base64 is None:
            return kind
        if kind == "SYMLINK" and isinstance(self.raw_target_base64, str):
            try:
                raw = base64.b64decode(self.raw_target_base64, validate=True)
            except (ValueError, binascii.Error) as error:
                raise BackupError("invalid symbolic-link target encoding") from error
            if raw and b"\0" not in raw and len(raw) == self.size and hashlib.sha256(raw).hexdigest() == self.sha256:
                return kind
        raise BackupError("invalid backup member type or target metadata")

    @classmethod
    def from_raw(cls, path: str, kind: str, raw: bytes) -> BackupFile:
        item = cls(path, hashlib.sha256(raw).hexdigest(), len(raw), kind,
                   base64.b64encode(raw).decode("ascii") if kind == "SYMLINK" else None)
        item.kind
        return item

    def matches(self, kind: str, raw: bytes) -> bool:
        return (
            self.kind == kind
            and len(raw) == self.size
            and hashlib.sha256(raw).hexdigest() == self.sha256
            and (kind != "SYMLINK" or base64.b64encode(raw).decode("ascii") == self.raw_target_base64)
        )

    def mapping(self) -> dict[str, object]:
        kind = self.kind
        value: dict[str, object] = {"path": self.path, "sha256": self.sha256, "size": self.size}
        if self.object_type is not None:
            value["object_type"] = kind
        if kind == "SYMLINK":
            value["raw_target_base64"] = self.raw_target_base64
        return value


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
        source = _root_path(source_root)
        target = _root_path(destination)
        _require_disposable(source)
        _require_disposable(target)
        if active_prefix_disposition not in self.ALLOWED_PREFIX_DISPOSITIONS:
            raise BackupError("active Journal prefix is not frozen or rolled over")
        paths = tuple(sorted(set(reachable_paths)))
        if len(paths) != len(reachable_paths):
            raise BackupError("reachable paths must be unique")
        _validate_paths(paths)
        # Acquire before any member existence/read checks; failures retain the hold.
        hold_hash = self.holds.acquire(backup_id, paths)
        files: list[BackupFile] = []
        with _root_fd(source) as source_fd, _root_fd(target, create=True, exclusive=True) as target_fd:
            for value in paths:
                kind, raw = _read_member(source_fd, value)
                item = BackupFile.from_raw(value, kind, raw)
                _write_member(target_fd, value, kind, raw)
                files.append(item)
        provisional = CanonicalBackupManifest(
            backup_id, source, target, frontier, paths, tuple(files), active_prefix_disposition, hold_hash, ""
        )
        return replace(
            provisional,
            manifest_hash=domain_hash("CANONICAL_BACKUP_MANIFEST", canonical_json_bytes(provisional.mapping())),
        )

    def verify_restore(self, manifest: CanonicalBackupManifest, *, restore_root: Path) -> dict[str, object]:
        target = _root_path(restore_root)
        _require_disposable(target)
        _validate_paths(tuple(item.path for item in manifest.files))
        with _root_fd(_root_path(manifest.destination)) as source_fd:
            # Reject a corrupt archive before creating the isolated restore.
            for item in manifest.files:
                if not item.matches(*_read_member(source_fd, item.path)):
                    raise BackupError("backup verification failed before restore")
            with _root_fd(target, create=True, exclusive=True) as target_fd:
                for item in manifest.files:
                    kind, raw = _read_member(source_fd, item.path)
                    if not item.matches(kind, raw):
                        raise BackupError("backup changed before restore copy")
                    _write_member(target_fd, item.path, kind, raw)
                for item in manifest.files:
                    if not item.matches(*_read_member(target_fd, item.path)):
                        raise BackupError("isolated restore verification failed")
        return {"schema": "CANONICAL_BACKUP_RESTORE_VERIFIED_V1", "backup_id": manifest.backup_id, "manifest_hash": manifest.manifest_hash, "verified": True}

    def release_hold(self, manifest: CanonicalBackupManifest, *, restore_verified: bool) -> None:
        if not restore_verified:
            raise BackupError("backup hold cannot release before an isolated restore verifies")
        self.holds.release(manifest.backup_id)
