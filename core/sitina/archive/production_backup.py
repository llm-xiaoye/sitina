from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash


class ProductionBackupError(RuntimeError):
    pass


class ProductionBackupContended(ProductionBackupError):
    pass


_CONFIG_CLOSURE = (
    "config/context_policy.json",
    "config/conversation_router.json",
    "config/cutover_contracts.bplus_v1.json",
    "config/evidence_policy.bplus_v1.json",
    "config/feature_flags.json",
    "config/format_capabilities.json",
    "config/legacy_fact_classification.json",
    "config/parallel_policy.yaml",
    "config/retry_policy.yaml",
    "config/sitina.yaml",
    "config/true_multi_agent_agents.json",
    "config/true_multi_agent_policy.json",
)
_STATE_CLOSURE = (
    "state/.legacy-control/frozen.json",
    "state/bplus-production-genesis/genesis.json",
)
_LOCK_EXCLUSIONS = frozenset(
    {
        "journal/writer.lock",
        "journal/writer.lock.generation.json",
    }
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _relative(value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or "." in pure.parts:
        raise ProductionBackupError("backup manifest contains an unsafe relative path")
    return Path(*pure.parts)


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return digest.hexdigest(), size


def _sync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_disposable(path: Path) -> None:
    resolved = path.resolve(strict=False)
    for parent in (resolved, *resolved.parents):
        marker = parent / ".sitina-bplus-disposable-v1"
        if marker.is_file() and not marker.is_symlink():
            return
    raise ProductionBackupError("restore drill requires a marked disposable root")


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
    )


@dataclass
class FrozenProductionPrefix:
    """Exclusive fixed-inode writer fence that never rewrites lock metadata."""

    path: Path
    descriptor: int
    device: int
    inode: int
    _closed: bool = False

    @classmethod
    def acquire(cls, home: Path) -> "FrozenProductionPrefix":
        root = Path(home).resolve(strict=True)
        journal = root / "journal"
        path = journal / "writer.lock"
        if journal.is_symlink() or not journal.is_dir() or path.is_symlink() or not path.is_file():
            raise ProductionBackupError("fixed Production writer lock is unavailable")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise ProductionBackupError(f"cannot open fixed Production writer lock: {error}") from error
        try:
            opened = os.fstat(descriptor)
            named = os.lstat(path)
            if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened)[:2] != _stat_identity(named)[:2]:
                raise ProductionBackupError("fixed Production writer-lock inode changed during open")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ProductionBackupContended("a Production writer is active; backup refused") from error
            frozen = cls(path, descriptor, opened.st_dev, opened.st_ino)
            frozen.assert_healthy()
            return frozen
        except BaseException:
            os.close(descriptor)
            raise

    def assert_healthy(self) -> None:
        if self._closed:
            raise ProductionBackupError("Production prefix lock is closed")
        opened = os.fstat(self.descriptor)
        named = os.lstat(self.path)
        if (opened.st_dev, opened.st_ino) != (self.device, self.inode) or (
            named.st_dev,
            named.st_ino,
        ) != (self.device, self.inode):
            raise ProductionBackupError("fixed Production writer-lock inode was replaced")

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.assert_healthy()
        finally:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self._closed = True

    def __enter__(self) -> "FrozenProductionPrefix":
        self.assert_healthy()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


@dataclass(frozen=True)
class ProductionBackupFile:
    path: str
    sha256: str
    size: int
    mode: str
    hardlink_to: str | None = None

    def mapping(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "hardlink_to": self.hardlink_to,
        }


@dataclass(frozen=True)
class ProductionSnapshotMetadata:
    goal_thread_id: str
    frontier: FrontierRef
    journal_event_count: int
    genesis_hash: str
    authority_resolution_hash: str
    before_sentinel_sha256: str
    source_manifest_sha256: str
    keychain_public_inventory: Mapping[str, object]

    def __post_init__(self) -> None:
        hashes = (
            self.genesis_hash,
            self.authority_resolution_hash,
            self.before_sentinel_sha256,
            self.source_manifest_sha256,
        )
        if any(len(value) != 64 or any(character not in "0123456789abcdef" for character in value) for value in hashes):
            raise ProductionBackupError("snapshot metadata requires exact lowercase SHA-256 values")
        if self.journal_event_count < 1 or self.frontier.position < 1:
            raise ProductionBackupError("Production backup requires a non-empty verified Journal")
        if self.journal_event_count != self.frontier.position:
            raise ProductionBackupError("Journal event count and frontier position differ")
        if self.keychain_public_inventory.get("secret_values_included") is not False:
            raise ProductionBackupError("backup metadata must never contain Keychain secret values")

    def mapping(self) -> dict[str, object]:
        return {
            "goal_thread_id": self.goal_thread_id,
            "frontier": self.frontier.__dict__,
            "journal_event_count": self.journal_event_count,
            "genesis_hash": self.genesis_hash,
            "authority_resolution_hash": self.authority_resolution_hash,
            "before_sentinel_sha256": self.before_sentinel_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "keychain_public_inventory": dict(self.keychain_public_inventory),
        }


@dataclass(frozen=True)
class ProductionBackupManifest:
    backup_root: Path
    backup_id: str
    created_at: str
    source_root_identity_hash: str
    metadata: ProductionSnapshotMetadata
    directories: tuple[str, ...]
    files: tuple[ProductionBackupFile, ...]
    exclusions: tuple[str, ...]
    logical_bytes: int
    unique_inode_bytes: int
    manifest_hash: str

    def body_mapping(self) -> dict[str, object]:
        return {
            "schema": "SITINA_PRODUCTION_AUTHORITY_BACKUP_V1",
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "source_root_identity_hash": self.source_root_identity_hash,
            "metadata": self.metadata.mapping(),
            "directories": list(self.directories),
            "files": [item.mapping() for item in self.files],
            "exclusions": list(self.exclusions),
            "logical_bytes": self.logical_bytes,
            "unique_inode_bytes": self.unique_inode_bytes,
            "projection_policy": "EXCLUDED_DISPOSABLE_REBUILD_REQUIRED",
            "active_prefix_disposition": "FROZEN_EXACT_PREFIX_FIXED_INODE_LOCK_V1",
            "credentials_copied": False,
            "writer_activated": False,
        }

    def mapping(self) -> dict[str, object]:
        return {**self.body_mapping(), "manifest_hash": self.manifest_hash}

    @classmethod
    def load(cls, backup_root: Path) -> "ProductionBackupManifest":
        root = Path(backup_root).resolve(strict=True)
        path = root / "backup-manifest.json"
        if path.is_symlink() or not path.is_file():
            raise ProductionBackupError("Production backup manifest is unavailable")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            metadata_value = dict(value["metadata"])
            frontier = FrontierRef(**dict(metadata_value["frontier"]))
            metadata = ProductionSnapshotMetadata(
                str(metadata_value["goal_thread_id"]),
                frontier,
                int(metadata_value["journal_event_count"]),
                str(metadata_value["genesis_hash"]),
                str(metadata_value["authority_resolution_hash"]),
                str(metadata_value["before_sentinel_sha256"]),
                str(metadata_value["source_manifest_sha256"]),
                dict(metadata_value["keychain_public_inventory"]),
            )
            files = tuple(
                ProductionBackupFile(
                    str(item["path"]),
                    str(item["sha256"]),
                    int(item["size"]),
                    str(item["mode"]),
                    str(item["hardlink_to"]) if item.get("hardlink_to") is not None else None,
                )
                for item in value["files"]
            )
            manifest = cls(
                root,
                str(value["backup_id"]),
                str(value["created_at"]),
                str(value["source_root_identity_hash"]),
                metadata,
                tuple(str(item) for item in value["directories"]),
                files,
                tuple(str(item) for item in value["exclusions"]),
                int(value["logical_bytes"]),
                int(value["unique_inode_bytes"]),
                str(value["manifest_hash"]),
            )
        except Exception as error:
            if isinstance(error, ProductionBackupError):
                raise
            raise ProductionBackupError("Production backup manifest is malformed") from error
        if value.get("schema") != "SITINA_PRODUCTION_AUTHORITY_BACKUP_V1":
            raise ProductionBackupError("Production backup manifest schema is invalid")
        expected = domain_hash(
            "SITINA_PRODUCTION_AUTHORITY_BACKUP",
            canonical_json_bytes(manifest.body_mapping()),
        )
        if manifest.manifest_hash != expected:
            raise ProductionBackupError("Production backup manifest hash is invalid")
        marker = root / "BACKUP_COMPLETE"
        if marker.is_symlink() or not marker.is_file() or marker.read_text(encoding="ascii").strip() != expected:
            raise ProductionBackupError("Production backup completion marker is invalid")
        return manifest


@dataclass(frozen=True)
class _SourceEntry:
    path: str
    identity: tuple[int, int, int, int, int, int]


class ProductionBackupBuilder:
    """Create an atomic, manifest-bound backup of all durable authorities."""

    def __init__(
        self,
        *,
        fault_injector: Callable[[str], None] | None = None,
        progress: Callable[[dict[str, object]], None] | None = None,
    ):
        self.fault_injector = fault_injector
        self.progress = progress

    def _fault(self, name: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(name)

    @staticmethod
    def _discover(home: Path) -> tuple[tuple[str, ...], tuple[_SourceEntry, ...]]:
        directories: set[str] = set()
        entries: dict[str, _SourceEntry] = {}

        def include_tree(relative_root: str) -> None:
            root = home / relative_root
            if root.is_symlink() or not root.is_dir():
                raise ProductionBackupError(f"authority root is unavailable: {relative_root}")
            for current, names, files in os.walk(root, topdown=True, followlinks=False):
                current_path = Path(current)
                relative_current = current_path.relative_to(home).as_posix()
                directories.add(relative_current)
                for name in tuple(names):
                    candidate = current_path / name
                    if candidate.is_symlink():
                        raise ProductionBackupError(f"backup rejects symlink directory: {candidate.relative_to(home)}")
                    if not candidate.is_dir():
                        raise ProductionBackupError(f"backup rejects non-directory authority entry: {candidate.relative_to(home)}")
                for name in files:
                    candidate = current_path / name
                    relative = candidate.relative_to(home).as_posix()
                    if relative in _LOCK_EXCLUSIONS:
                        continue
                    observed = os.lstat(candidate)
                    if candidate.is_symlink() or not stat.S_ISREG(observed.st_mode):
                        raise ProductionBackupError(f"backup rejects non-regular authority file: {relative}")
                    entries[relative] = _SourceEntry(relative, _stat_identity(observed))

        include_tree("journal")
        include_tree("cas")
        for relative in (*_STATE_CLOSURE, *_CONFIG_CLOSURE):
            candidate = home / relative
            observed = os.lstat(candidate)
            if candidate.is_symlink() or not stat.S_ISREG(observed.st_mode):
                raise ProductionBackupError(f"required recovery file is unavailable: {relative}")
            entries[relative] = _SourceEntry(relative, _stat_identity(observed))
            parent = candidate.parent
            while parent != home:
                directories.add(parent.relative_to(home).as_posix())
                parent = parent.parent
        return tuple(sorted(directories)), tuple(entries[key] for key in sorted(entries))

    @staticmethod
    def _copy_entry(
        home: Path,
        payload: Path,
        entry: _SourceEntry,
        inode_targets: dict[tuple[int, int], tuple[str, str]],
    ) -> ProductionBackupFile:
        source = home / _relative(entry.path)
        target = payload / _relative(entry.path)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = os.lstat(source)
        if _stat_identity(current) != entry.identity:
            raise ProductionBackupError(f"Production authority changed before copy: {entry.path}")
        inode_key = (current.st_dev, current.st_ino)
        linked = inode_targets.get(inode_key)
        if linked is not None:
            prior_path, digest = linked
            os.link(payload / _relative(prior_path), target, follow_symlinks=False)
            return ProductionBackupFile(
                entry.path,
                digest,
                current.st_size,
                oct(0o600),
                prior_path,
            )
        digest = hashlib.sha256()
        copied = 0
        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        target_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        source_fd = os.open(source, source_flags)
        target_fd = os.open(target, target_flags, 0o600)
        try:
            with os.fdopen(source_fd, "rb", closefd=True) as reader, os.fdopen(target_fd, "wb", closefd=True) as writer:
                for chunk in iter(lambda: reader.read(8 * 1024 * 1024), b""):
                    writer.write(chunk)
                    digest.update(chunk)
                    copied += len(chunk)
                writer.flush()
                os.fsync(writer.fileno())
        except BaseException:
            for descriptor in (source_fd, target_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        after = os.lstat(source)
        if _stat_identity(after) != entry.identity or copied != current.st_size:
            raise ProductionBackupError(f"Production authority changed during copy: {entry.path}")
        value = digest.hexdigest()
        inode_targets[inode_key] = (entry.path, value)
        return ProductionBackupFile(entry.path, value, copied, oct(0o600))

    def build(
        self,
        backup_id: str,
        *,
        source_home: Path,
        destination: Path,
        staging_parent: Path,
        metadata_provider: Callable[[], ProductionSnapshotMetadata],
    ) -> ProductionBackupManifest:
        home = Path(source_home).resolve(strict=True)
        final = Path(destination).resolve(strict=False)
        staging_root = Path(staging_parent).resolve(strict=True)
        if final.exists() or final.is_symlink():
            raise ProductionBackupError("Production backup destination already exists")
        if final.parent != home / "backups" or _inside(staging_root, home):
            raise ProductionBackupError("backup destination or staging boundary is invalid")
        if not backup_id or final.name != backup_id or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for character in backup_id):
            raise ProductionBackupError("backup identity is invalid")
        if staging_root.is_symlink() or not staging_root.is_dir():
            raise ProductionBackupError("backup staging parent must be a real directory")
        stage = Path(tempfile.mkdtemp(prefix=f".{backup_id}.", dir=staging_root)).resolve(strict=True)
        os.chmod(stage, 0o700)
        payload = stage / "payload"
        payload.mkdir(mode=0o700)
        try:
            with FrozenProductionPrefix.acquire(home) as frozen:
                metadata = metadata_provider()
                genesis = json.loads((home / "state/bplus-production-genesis/genesis.json").read_text(encoding="utf-8"))
                source_identity = str(genesis.get("root_path_hash", ""))
                if len(source_identity) != 64:
                    raise ProductionBackupError("Production Genesis source-root identity is invalid")
                directories, source_entries = self._discover(home)
                frozen.assert_healthy()
                self._fault("after_inventory")
                for relative in directories:
                    (payload / _relative(relative)).mkdir(parents=True, exist_ok=True, mode=0o700)
                inode_targets: dict[tuple[int, int], tuple[str, str]] = {}
                files: list[ProductionBackupFile] = []
                for index, entry in enumerate(source_entries, start=1):
                    files.append(self._copy_entry(home, payload, entry, inode_targets))
                    if self.progress is not None and (index == 1 or index % 5000 == 0 or index == len(source_entries)):
                        self.progress(
                            {
                                "phase": "copy",
                                "files_copied": index,
                                "file_count": len(source_entries),
                                "logical_bytes_copied": sum(item.size for item in files),
                            }
                        )
                self._fault("after_copy")
                frozen.assert_healthy()
                final_directories, final_entries = self._discover(home)
                if final_directories != directories or final_entries != source_entries:
                    raise ProductionBackupError("Production authority inventory changed during backup")
                logical_bytes = sum(item.size for item in files)
                unique_inode_bytes = sum(item.size for item in files if item.hardlink_to is None)
                provisional = ProductionBackupManifest(
                    stage,
                    backup_id,
                    _utc_now(),
                    source_identity,
                    metadata,
                    directories,
                    tuple(files),
                    tuple(sorted(_LOCK_EXCLUSIONS | {"projections/**", "Keychain secret material"})),
                    logical_bytes,
                    unique_inode_bytes,
                    "",
                )
                manifest = replace(
                    provisional,
                    manifest_hash=domain_hash(
                        "SITINA_PRODUCTION_AUTHORITY_BACKUP",
                        canonical_json_bytes(provisional.body_mapping()),
                    ),
                )
                manifest_path = stage / "backup-manifest.json"
                raw_manifest = json.dumps(manifest.mapping(), sort_keys=True, indent=2).encode("utf-8") + b"\n"
                descriptor = os.open(
                    manifest_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw_manifest)
                    handle.flush()
                    os.fsync(handle.fileno())
                marker = stage / "BACKUP_COMPLETE"
                descriptor = os.open(
                    marker,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write((manifest.manifest_hash + "\n").encode("ascii"))
                    handle.flush()
                    os.fsync(handle.fileno())
                for current, _names, _files in os.walk(stage, topdown=False):
                    _sync_directory(Path(current))
                self._fault("before_publish")
                frozen.assert_healthy()
                from sitina.legacy.fence import authorized_production_backup

                with authorized_production_backup(
                    frozen,
                    destination=final,
                    goal_thread_id=metadata.goal_thread_id,
                ):
                    if not final.parent.exists():
                        final.parent.mkdir(mode=0o700)
                        _sync_directory(home)
                    if final.parent.is_symlink() or not final.parent.is_dir():
                        raise ProductionBackupError("Production backup root is invalid")
                    if stage.stat().st_dev != final.parent.stat().st_dev:
                        raise ProductionBackupError("atomic backup publication requires one filesystem")
                    os.replace(stage, final)
                    _sync_directory(final.parent)
            return replace(manifest, backup_root=final)
        except BaseException as error:
            if isinstance(error, ProductionBackupError):
                raise
            raise ProductionBackupError(f"Production backup failed closed; staging retained at {stage}: {error}") from error


class ProductionRestoreDrill:
    def __init__(self, *, progress: Callable[[dict[str, object]], None] | None = None):
        self.progress = progress

    def restore(
        self,
        manifest: ProductionBackupManifest,
        *,
        target: Path,
        semantic_validator: Callable[[Path, ProductionBackupManifest], Mapping[str, object]],
    ) -> dict[str, object]:
        destination = Path(target).resolve(strict=False)
        _require_disposable(destination.parent)
        if destination.exists() or destination.is_symlink():
            raise ProductionBackupError("isolated restore destination already exists")
        verified_manifest = ProductionBackupManifest.load(manifest.backup_root)
        if verified_manifest.manifest_hash != manifest.manifest_hash:
            raise ProductionBackupError("loaded backup identity differs from requested manifest")
        destination.mkdir(mode=0o700)
        marker = destination / ".sitina-bplus-disposable-v1"
        descriptor = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(f"restore-drill:{manifest.backup_id}\n".encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        for relative in manifest.directories:
            (destination / _relative(relative)).mkdir(parents=True, exist_ok=True, mode=0o700)
        copied: dict[str, Path] = {}
        try:
            for index, item in enumerate(manifest.files, start=1):
                source = manifest.backup_root / "payload" / _relative(item.path)
                target_file = destination / _relative(item.path)
                if source.is_symlink() or not source.is_file():
                    raise ProductionBackupError(f"backup payload object is unavailable: {item.path}")
                if item.hardlink_to is not None:
                    prior_source = manifest.backup_root / "payload" / _relative(item.hardlink_to)
                    if not prior_source.is_file() or not os.path.samefile(source, prior_source):
                        raise ProductionBackupError("backup hardlink topology differs from its manifest")
                    prior_target = copied.get(item.hardlink_to)
                    if prior_target is None:
                        raise ProductionBackupError("backup hardlink predecessor is out of order")
                    os.link(prior_target, target_file, follow_symlinks=False)
                    digest, size = item.sha256, item.size
                else:
                    target_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    digest_value = hashlib.sha256()
                    size = 0
                    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                    source_fd = os.open(source, source_flags)
                    target_fd = os.open(target_file, target_flags, 0o600)
                    try:
                        with os.fdopen(source_fd, "rb", closefd=True) as reader, os.fdopen(target_fd, "wb", closefd=True) as writer:
                            for chunk in iter(lambda: reader.read(8 * 1024 * 1024), b""):
                                digest_value.update(chunk)
                                size += len(chunk)
                                writer.write(chunk)
                            writer.flush()
                            os.fsync(writer.fileno())
                    except BaseException:
                        for descriptor in (source_fd, target_fd):
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass
                        raise
                    digest = digest_value.hexdigest()
                if digest != item.sha256 or size != item.size:
                    raise ProductionBackupError(f"backup payload verification failed: {item.path}")
                copied[item.path] = target_file
                if self.progress is not None and (index == 1 or index % 5000 == 0 or index == len(manifest.files)):
                    self.progress(
                        {
                            "phase": "restore",
                            "files_restored": index,
                            "file_count": len(manifest.files),
                        }
                    )
            semantic = dict(semantic_validator(destination, manifest))
            if semantic.get("verified") is not True or semantic.get("writer_activated") is not False:
                raise ProductionBackupError("semantic restore validation did not prove read-only recovery")
            report = {
                "schema": "SITINA_PRODUCTION_AUTHORITY_RESTORE_VERIFIED_V1",
                "backup_id": manifest.backup_id,
                "manifest_hash": manifest.manifest_hash,
                "raw_file_count": len(manifest.files),
                "raw_logical_bytes": manifest.logical_bytes,
                "semantic": semantic,
                "verified": True,
                "writer_activated": False,
                "verified_at": _utc_now(),
            }
            raw = json.dumps(report, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            (destination / "restore-verification.json").write_bytes(raw)
            with (destination / "restore-verification.json").open("rb") as handle:
                os.fsync(handle.fileno())
            _sync_directory(destination)
            return report
        except BaseException as error:
            if isinstance(error, ProductionBackupError):
                raise
            raise ProductionBackupError(f"isolated restore failed closed at {destination}: {error}") from error


def derive_verified_frontier(context: Any) -> FrontierRef:
    """Derive the exact transaction frontier from verified, frozen Journal bytes."""

    from sitina.journal.recovery import scan_active_segment_read_only, scan_sealed_segment

    frames: list[Any] = []
    for path in sorted((context.home / "journal/sealed").glob("*.seg")):
        frames.extend(scan_sealed_segment(path).frames)
    frames.extend(scan_active_segment_read_only(context.home / "journal/active.seg").frames)
    if not frames:
        raise ProductionBackupError("Production Journal is empty")
    last = frames[-1]
    physical_position = last.transaction.last_position
    fast = getattr(getattr(context, "authority", None), "fast_start_report", None)
    if fast is not None:
        state = fast.authority_state
        if (
            state.journal_id != context.genesis.journal_id
            or state.epoch != int(context.genesis.epoch_root.rsplit("-", 1)[1])
            or state.head_position != physical_position
            or state.last_transaction_hash != last.transaction_hash
        ):
            raise ProductionBackupError("Fast Start authority differs from the physical transaction frontier")
    else:
        event_count = len(context.events)
        if physical_position != event_count or context.events[-1].position != event_count:
            raise ProductionBackupError("verified Journal events differ from the physical transaction frontier")
    return FrontierRef(
        context.genesis.journal_id,
        int(context.genesis.epoch_root.rsplit("-", 1)[1]),
        "local",
        physical_position,
        last.transaction_hash,
    )


class _RestoredAuthorityReadView:
    """Minimal, mutation-free Journal interface for semantic recovery code."""

    def __init__(
        self,
        events: tuple[Any, ...],
        *,
        journal_id: str,
        epoch: int,
        position_hash: Mapping[int, str] | None = None,
    ):
        self._events = events
        self.journal_id = journal_id
        self.epoch = epoch
        self.head_position = events[-1].position if events else 0
        self._position_hash = dict(position_hash or {})

    def iter_events(self, after_position: int = 0):
        return iter(event for event in self._events if event.position > after_position)


def _validate_checkpoint_recovery(
    journal: _RestoredAuthorityReadView,
    cas: Any,
    *,
    genesis_hash: str,
    verified_references: set[str] | None = None,
) -> dict[str, object]:
    """Reconstruct and verify every pre-V2 durable live-checkpoint manifest."""

    from sitina.cas.model import ObjectRef
    from sitina.orchestrator.checkpoint_resume import stream_heads, verify_checkpoint_manifest

    events = tuple(journal.iter_events(0))
    by_position = {event.position: event for event in events}
    publications = tuple(
        event
        for event in events
        if event.payload.get("schema") == "CHECKPOINT_MANIFEST_PUBLISHED_V1"
    )
    seen: set[tuple[str, str]] = set()
    internal_references: set[str] = set()
    already_verified = set(verified_references or ())
    transitively_verified = 0
    for publication in publications:
        checkpoint_id = str(publication.payload.get("checkpoint_id") or "")
        run_id = str(publication.payload.get("run_id") or publication.stream_id.removeprefix("run/"))
        identity = (run_id, checkpoint_id)
        if not run_id or not checkpoint_id or identity in seen:
            raise ProductionBackupError("restored checkpoint publication identity is missing or duplicated")
        seen.add(identity)
        locator = publication.payload.get("manifest_object_ref")
        if not isinstance(locator, Mapping):
            raise ProductionBackupError("restored checkpoint publication lacks an ObjectRef locator")
        allowed = {"object_id", "tenant_id", "plaintext_commitment", "commitment_key_id", "profile"}
        if set(locator).difference(allowed):
            raise ProductionBackupError("restored checkpoint ObjectRef contains unexpected fields")
        try:
            reference = ObjectRef(**{key: locator[key] for key in allowed if key in locator})
            raw = cas.open_verified(reference)
            durable = json.loads(raw)
            if not isinstance(durable, dict):
                raise TypeError("checkpoint body is not an object")
            verify_checkpoint_manifest(durable)
        except Exception as error:
            raise ProductionBackupError("restored checkpoint manifest failed semantic verification") from error
        if (
            durable["checkpoint_id"] != checkpoint_id
            or durable["run_id"] != run_id
            or durable["journal_id"] != journal.journal_id
            or int(durable["epoch"]) != journal.epoch
            or durable["genesis_hash"] != genesis_hash
            or publication.payload.get("manifest_hash") != durable["manifest_hash"]
            or reference.reference_id not in publication.object_refs
        ):
            raise ProductionBackupError("restored checkpoint publication binding is invalid")
        frontier_position = int(durable["validated_through_position"])
        frontier_event = by_position.get(frontier_position)
        if (
            frontier_event is None
            or journal._position_hash.get(frontier_position) != durable["validated_through_hash"]
        ):
            raise ProductionBackupError("restored checkpoint frontier is not committed by the Journal")
        if stream_heads(events, frontier_position) != durable["stream_heads"]:
            raise ProductionBackupError("restored checkpoint Stream heads differ from its manifest")
        for reference_id in durable["cas_refs"]:
            normalized = str(reference_id)
            if not normalized.startswith("cas:"):
                raise ProductionBackupError("restored checkpoint contains a non-CAS content reference")
            if normalized not in already_verified:
                cas.open_verified(cas.resolve_reference(normalized))
                already_verified.add(normalized)
                transitively_verified += 1
            internal_references.add(normalized)
    return {
        "legacy_checkpoint_manifest_count": len(publications),
        "legacy_checkpoint_internal_reference_count": len(internal_references),
        "legacy_checkpoint_transitive_reference_count": transitively_verified,
        "checkpoint_v2_publication_count": sum(
            event.event_type == "run.checkpoint-published" for event in events
        ),
        "checkpoint_state_reconstructed": True,
    }


def _validate_session_recovery(
    journal: _RestoredAuthorityReadView,
    cas: Any,
    provider: Any,
) -> dict[str, object]:
    """Recover every Journal-native conversation session and CAS message body."""

    from sitina.conversation.persistence import JournalSessionRepository

    events = tuple(journal.iter_events(0))
    session_streams = sorted(
        {event.stream_id for event in events if event.stream_id.startswith("session/")}
    )
    repository = JournalSessionRepository(journal, cas, provider)
    recovered = []
    for stream_id in session_streams:
        session_id = stream_id.removeprefix("session/")
        stream_events = tuple(event for event in events if event.stream_id == stream_id)
        created = tuple(event for event in stream_events if event.event_type == "session.created")
        if len(created) != 1 or str(created[0].payload.get("session_id")) != session_id:
            raise ProductionBackupError("restored session Stream has no unique creation identity")
        try:
            state = repository.recover(session_id)
        except Exception as error:
            raise ProductionBackupError("restored session failed Journal/CAS recovery") from error
        if state["source_frontier"] != stream_events[-1].position:
            raise ProductionBackupError("restored session recovery stopped before its Stream frontier")
        recovered.append(state)
    expected_latest = None
    if recovered:
        expected_latest = max(
            recovered,
            key=lambda value: int(value["source_frontier"]),
        )["session_id"]
    if repository.latest_session_id() != expected_latest:
        raise ProductionBackupError("restored latest-session identity differs from authoritative replay")
    return {
        "session_count": len(recovered),
        "session_message_count": sum(len(state["messages"]) for state in recovered),
        "session_successful_turn_count": sum(len(state["successful_turns"]) for state in recovered),
        "session_failed_turn_count": sum(len(state["failed_turns"]) for state in recovered),
        "latest_session_id": expected_latest,
        "session_state_reconstructed": True,
    }


def _validate_memory_recovery(
    journal: _RestoredAuthorityReadView,
    cas: Any,
    provider: Any,
) -> dict[str, object]:
    """Reconstruct all native memories and episodes without enabling a writer."""

    from sitina.memory.native import EpisodeDocument, MemoryRepository

    events = tuple(journal.iter_events(0))
    memory_streams = sorted(
        {
            event.stream_id
            for event in events
            if event.stream_id.startswith("memory/memory-")
        }
    )
    repository = MemoryRepository(journal, cas, provider)
    statuses: dict[str, int] = {}
    content_bytes = 0
    for stream_id in memory_streams:
        memory_id = stream_id.removeprefix("memory/")
        stream_events = tuple(event for event in events if event.stream_id == stream_id)
        if sum(event.event_type == "memory.candidate-created" for event in stream_events) != 1:
            raise ProductionBackupError("restored memory Stream has no unique candidate creation")
        try:
            document = repository._raw_get(memory_id)
            raw = cas.open_verified(repository._object_ref(document))
        except Exception as error:
            raise ProductionBackupError("restored memory failed Journal/CAS reconstruction") from error
        if hashlib.sha256(raw).hexdigest() != document.content_hash:
            raise ProductionBackupError("restored memory plaintext hash differs from its Journal fact")
        content_bytes += len(raw)
        statuses[document.status] = statuses.get(document.status, 0) + 1

    episode_events = tuple(event for event in events if event.event_type == "memory.episode-created")
    episode_ids: set[str] = set()
    for event in episode_events:
        try:
            document = EpisodeDocument.model_validate(event.payload)
        except Exception as error:
            raise ProductionBackupError("restored memory episode document is malformed") from error
        if document.episode_id in episode_ids or event.stream_id != f"episode/{document.episode_id}":
            raise ProductionBackupError("restored memory episode identity is duplicated or misbound")
        episode_ids.add(document.episode_id)
        if (
            document.action_event_range[1] > document.source_frontier
            or document.source_frontier >= event.position
            or document.source_frontier > journal.head_position
        ):
            raise ProductionBackupError("restored memory episode has an invalid source frontier")
        required = {document.goal_ref, document.terminal_evidence_ref, document.lesson_ref}
        if not required.issubset(set(event.object_refs)):
            raise ProductionBackupError("restored memory episode CAS roots differ from its Journal fact")
        lesson = cas.open_verified(cas.resolve_reference(document.lesson_ref))
        if not lesson or len(lesson) > 64 * 1024:
            raise ProductionBackupError("restored memory episode lesson is invalid")
        cas.open_verified(cas.resolve_reference(document.goal_ref))
        cas.open_verified(cas.resolve_reference(document.terminal_evidence_ref))
    return {
        "memory_item_count": len(memory_streams),
        "memory_status_counts": dict(sorted(statuses.items())),
        "memory_content_bytes_verified": content_bytes,
        "active_memory_root_count": len(repository.active_roots()),
        "memory_episode_count": len(episode_events),
        "memory_state_reconstructed": True,
    }


def _validate_evidence_recovery(
    journal: _RestoredAuthorityReadView,
    cas: Any,
    provider: Any,
) -> dict[str, object]:
    """Recover old and V2 evidence bodies and bind them back to Journal facts."""

    from sitina.evidence.reference_v2 import ReferencedEvidenceRepository

    events = tuple(journal.iter_events(0))
    all_transaction_refs = {reference for event in events for reference in event.object_refs}
    raw_by_ref: dict[str, bytes] = {}
    document_by_ref: dict[str, dict[str, Any]] = {}
    verified_runs: set[str] = set()
    payload_reference_count = 0
    payload_only_reference_count = 0

    def open_document(reference_id: str, expected_hash: object = None) -> dict[str, Any]:
        if not reference_id.startswith("cas:"):
            raise ProductionBackupError("restored evidence contains a non-CAS body reference")
        raw = raw_by_ref.get(reference_id)
        if raw is None:
            raw = cas.open_verified(cas.resolve_reference(reference_id))
            raw_by_ref[reference_id] = raw
        if expected_hash is not None and str(expected_hash) != hashlib.sha256(raw).hexdigest():
            raise ProductionBackupError("restored evidence plaintext hash differs from its Journal fact")
        document = document_by_ref.get(reference_id)
        if document is None:
            try:
                parsed = json.loads(raw)
            except Exception as error:
                raise ProductionBackupError("restored evidence body is not valid JSON") from error
            if not isinstance(parsed, dict):
                raise ProductionBackupError("restored evidence body is not a JSON object")
            document = parsed
            document_by_ref[reference_id] = document
        return document

    for event in events:
        candidates: list[tuple[str, object]] = []
        reference = event.payload.get("evidence_package_ref")
        if isinstance(reference, str):
            candidates.append((reference, event.payload.get("evidence_package_hash")))
        if event.event_type in {
            "evidence.package.published",
            "protocol.evidence.package.published",
            "production.activation.report.generated",
            "canary.acceptance.verified",
        }:
            reference = event.payload.get("evidence_package_id")
            if isinstance(reference, str):
                candidates.append((reference, None))
        if event.event_type == "autonomous.run-succeeded":
            reference = event.payload.get("record_ref")
            if isinstance(reference, str):
                candidates.append((reference, event.payload.get("record_hash")))
        for reference_id, expected_hash in candidates:
            payload_reference_count += 1
            if reference_id not in all_transaction_refs:
                payload_only_reference_count += 1
            document = open_document(reference_id, expected_hash)
            event_run_id = str(event.payload.get("run_id") or "")
            document_run_id = str(document.get("run_id") or "")
            if event_run_id and document_run_id and event_run_id != document_run_id:
                raise ProductionBackupError("restored evidence body is bound to a different run")
            if event_run_id:
                verified_runs.add(event_run_id)

    v2_repository = ReferencedEvidenceRepository(journal, cas, provider)
    v2_events = tuple(event for event in events if event.event_type == "run.evidence-published")
    for event in v2_events:
        try:
            evidence = v2_repository.open(event)
            v2_repository.verify_replay(evidence)
        except Exception as error:
            raise ProductionBackupError("restored Evidence V2 replay verification failed") from error
        verified_runs.add(evidence.document.run_id)

    terminals = tuple(event for event in events if event.event_type == "run.terminal")
    journal_native_terminals = 0
    for terminal in terminals:
        run_id = str(terminal.payload.get("run_id") or terminal.stream_id.removeprefix("run/"))
        if not terminal.event_hash:
            raise ProductionBackupError("restored terminal fact is not authenticated")
        if run_id not in verified_runs:
            journal_native_terminals += 1
    return {
        "terminal_event_count": len(terminals),
        "terminal_with_cas_evidence_count": len(terminals) - journal_native_terminals,
        "journal_native_terminal_count": journal_native_terminals,
        "evidence_payload_reference_count": payload_reference_count,
        "evidence_unique_object_count": len(raw_by_ref),
        "evidence_payload_only_reference_count": payload_only_reference_count,
        "evidence_v2_publication_count": len(v2_events),
        "evidence_state_reconstructed": True,
    }


def load_restored_genesis(
    restore_root: Path,
    manifest: ProductionBackupManifest,
) -> Any:
    """Load Genesis while preserving its original, manifest-bound root identity."""

    from sitina.legacy.production_genesis import GenesisArtifact

    root = Path(restore_root).resolve(strict=True)
    genesis_value = json.loads((root / "state/bplus-production-genesis/genesis.json").read_text(encoding="utf-8"))
    try:
        genesis = GenesisArtifact(
            str(genesis_value["genesis_id"]),
            str(genesis_value["installation_id"]),
            str(genesis_value["journal_id"]),
            str(genesis_value["epoch_root"]),
            str(genesis_value["key_namespace"]),
            str(genesis_value["intended_snapshot_hash"]),
            str(genesis_value["format_profile_hash"]),
            str(genesis_value["operator_id"]),
            str(genesis_value["verifier_id"]) if genesis_value.get("verifier_id") is not None else None,
            str(genesis_value["environment_kind"]),
            str(genesis_value["root_path_hash"]),
            bool(genesis_value["authority"]),
            bool(genesis_value["independently_verified"]),
            str(genesis_value["genesis_hash"]),
        )
    except Exception as error:
        raise ProductionBackupError("restored Production Genesis is malformed") from error
    expected_genesis = domain_hash(
        "PRODUCTION_GENESIS_ARTIFACT",
        canonical_json_bytes(genesis.body_mapping()),
    )
    if (
        genesis.genesis_hash != expected_genesis
        or genesis.genesis_hash != manifest.metadata.genesis_hash
        or genesis.root_path_hash != manifest.source_root_identity_hash
    ):
        raise ProductionBackupError("restored Production Genesis identity is invalid")
    return genesis


def validate_restored_authorities(
    restore_root: Path,
    manifest: ProductionBackupManifest,
    *,
    provider: Any,
) -> dict[str, object]:
    """Verify Journal, CAS references, and a fresh projection without a writer."""

    from sitina.cas.local import LocalCAS
    from sitina.journal.fast_start import FullJournalVerifier, RollbackAnchorStore
    from sitina.journal.recovery import scan_active_segment_read_only, scan_sealed_segment
    from sitina.legacy.fence import LegacyWriteGate
    from sitina.operations.phase6b import ProductionAuthorityReader
    from sitina.projections.production import production_handlers
    from sitina.projections.rebuild import ProjectionGeneration
    from sitina.security.key_provider import JournalAuthProvider

    root = Path(restore_root).resolve(strict=True)
    genesis = load_restored_genesis(root, manifest)
    fence = LegacyWriteGate(root).read_verified_record()
    if fence is None:
        raise ProductionBackupError("restored Legacy writer fence is unavailable")
    epoch = int(genesis.epoch_root.rsplit("-", 1)[1])
    authority = ProductionAuthorityReader.resolve(
        root,
        JournalAuthProvider(provider),
        journal_id=genesis.journal_id,
        epoch=epoch,
        command_id=str(fence["cutover_command_id"]),
        request_hash=str(fence["cutover_request_hash"]),
        genesis_hash=genesis.genesis_hash,
        snapshot_hash=genesis.intended_snapshot_hash,
        fence_record_hash=str(fence["record_hash"]),
        now=int(dt.datetime.now(dt.timezone.utc).timestamp()),
        authority_key_provider=provider,
        rollback_anchor=RollbackAnchorStore(provider.backend, journal_id=genesis.journal_id),
    )
    if not authority.resolution.authorizes_journal or authority.resolution.writer_count != 1:
        raise ProductionBackupError("restored Journal cannot reconstruct unique writer authority")
    frames: list[Any] = []
    for path in sorted((root / "journal/sealed").glob("*.seg")):
        frames.extend(scan_sealed_segment(path).frames)
    frames.extend(scan_active_segment_read_only(root / "journal/active.seg").frames)
    if not frames:
        raise ProductionBackupError("restored Journal has no physical frames")
    last = frames[-1]
    full = FullJournalVerifier(
        root,
        journal_authenticator=JournalAuthProvider(provider),
        authority_key_provider=provider,
    ).verify()
    verified_events = tuple(full.verified_events)
    if (
        len(verified_events) != manifest.metadata.journal_event_count
        or last.transaction.last_position != manifest.metadata.frontier.position
        or last.transaction_hash != manifest.metadata.frontier.commitment
        or full.authority_state.head_position != manifest.metadata.frontier.position
        or full.authority_state.last_transaction_hash != manifest.metadata.frontier.commitment
    ):
        raise ProductionBackupError("restored Journal frontier differs from the backup manifest")
    cas = LocalCAS.open_read_only(root, provider, namespace_kind="controlled_fixture")
    references = tuple(sorted({reference for event in verified_events for reference in event.object_refs}))
    plaintext_bytes = 0
    for reference_id in references:
        reference = cas.resolve_reference(reference_id)
        plaintext_bytes += len(cas.open_verified(reference))

    position_hash = {
        position: frame.transaction_hash
        for frame in frames
        for position in range(
            frame.transaction.first_position,
            frame.transaction.last_position + 1,
        )
    }
    read_view = _RestoredAuthorityReadView(
        verified_events,
        journal_id=genesis.journal_id,
        epoch=epoch,
        position_hash=position_hash,
    )

    projection = ProjectionGeneration.build(
        root / "projections/restore-drill",
        read_view,
        manifest.metadata.frontier,
        production_handlers(),
    )
    checkpoint_recovery = _validate_checkpoint_recovery(
        read_view,
        cas,
        genesis_hash=genesis.genesis_hash,
        verified_references=set(references),
    )
    session_recovery = _validate_session_recovery(read_view, cas, provider)
    memory_recovery = _validate_memory_recovery(read_view, cas, provider)
    evidence_recovery = _validate_evidence_recovery(read_view, cas, provider)
    inventory = provider.public_inventory()
    if inventory.get("secret_values_included") is not False:
        raise ProductionBackupError("restore evidence attempted to expose Keychain secret material")
    return {
        "verified": True,
        "writer_activated": False,
        "journal_id": genesis.journal_id,
        "journal_epoch": epoch,
        "journal_event_count": len(verified_events),
        "journal_frontier": manifest.metadata.frontier.__dict__,
        "authority_state": authority.resolution.state.value,
        "authority_read_mode": authority.read_mode,
        "full_replay_verified": True,
        "cas_reference_count": len(references),
        "cas_plaintext_bytes_verified": plaintext_bytes,
        "projection_frontier": projection.frontier.__dict__,
        "projection_semantic_checksum": projection.semantic_checksum,
        "projection_database": str(projection.database_path),
        "checkpoint_recovery": checkpoint_recovery,
        "session_recovery": session_recovery,
        "memory_recovery": memory_recovery,
        "evidence_recovery": evidence_recovery,
        "sqlite_authority_used": False,
        "legacy_read_count": 0,
        "external_effect_count": 0,
        "credentials_copied": False,
        "keychain_public_inventory": inventory,
    }
