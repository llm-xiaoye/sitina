from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from sitina.journal.model import canonical_json_bytes

from .rebuild import semantic_checksum
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.security.key_provider import KeyPurpose


class ProjectionGenerationError(RuntimeError):
    pass


def _pointer_unsigned(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"auth_key_id", "auth_tag"}}


def _sign_pointer(value: Mapping[str, Any], provider: Any) -> dict[str, Any]:
    unsigned = _pointer_unsigned(value)
    key_id, signature = provider.sign(KeyPurpose.AUTHORITY_SIGNING, canonical_json_bytes(unsigned))
    return {**unsigned, "auth_key_id": key_id, "auth_tag": signature.hex()}


def _verify_pointer(value: Mapping[str, Any], provider: Any) -> bool:
    key_id = value.get("auth_key_id")
    tag = value.get("auth_tag")
    if not isinstance(key_id, str) or not isinstance(tag, str):
        return False
    try:
        signature = bytes.fromhex(tag)
    except ValueError:
        return False
    return bool(
        provider.verify(
            key_id,
            KeyPurpose.AUTHORITY_SIGNING,
            canonical_json_bytes(_pointer_unsigned(value)),
            signature,
        )
    )


def _immutable_uri(path: Path) -> str:
    return path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"


def _remove_sqlite_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.is_symlink():
            raise ProjectionGenerationError("Projection SQLite sidecar must not be a symlink")
        if sidecar.exists():
            if not sidecar.is_file():
                raise ProjectionGenerationError("Projection SQLite sidecar must be a regular file")
            sidecar.unlink()


def _database_checksum(path: Path) -> str:
    try:
        connection = sqlite3.connect(_immutable_uri(path), uri=True)
        try:
            return semantic_checksum(connection)
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise ProjectionGenerationError("Projection database is unreadable") from error


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


@dataclass(frozen=True)
class SelectedProjection:
    pointer: dict[str, Any]
    database_path: Path
    used_previous: bool


@dataclass
class TailAppliedProjection:
    selected: SelectedProjection
    connection: sqlite3.Connection
    applied_through: int

    def close(self) -> None:
        self.connection.close()


class ProjectionGenerationPublisher:
    def __init__(
        self,
        root: str | Path,
        *,
        feature_activations: FeatureActivationRegistry | None = None,
        authority_key_provider: Any | None = None,
    ):
        self.root = Path(root).resolve()
        self.feature_activations = feature_activations
        self.authority_key_provider = authority_key_provider
        for name in ("current", "previous", "building"):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def _sync(self, path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_pointer(self, name: str, value: Mapping[str, Any]) -> None:
        path = self.root / name
        temporary = self.root / ("." + name + "." + uuid.uuid4().hex + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, canonical_json_bytes(dict(value)) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        self._sync(self.root)

    def _load_pointer(self, name: str) -> dict[str, Any] | None:
        path = self.root / name
        if not path.is_file() or path.is_symlink():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def publish(
        self,
        *,
        generation_id: str,
        building_database: str | Path,
        authority_checkpoint_commitment: str,
        journal_frontier: int,
        schema_coverage_hash: str,
        created_at: str,
    ) -> dict[str, Any]:
        genesis_path = self.root.parent / "state/bplus-production-genesis/genesis.json"
        if genesis_path.is_file():
            try:
                protected = json.loads(genesis_path.read_text(encoding="utf-8")).get("environment_kind") in {
                    "PRODUCTION",
                    "CONTROLLED_PRODUCTION_SIMULATION",
                }
            except Exception as error:
                raise ProjectionGenerationError("Production Genesis is unreadable before Projection V2 publish") from error
            if protected:
                if self.feature_activations is None:
                    raise ProjectionGenerationError("Projection V2 publisher has no verified Journal feature activation state")
                self.feature_activations.assert_write_enabled("projection_v2_build")
        source = Path(building_database).resolve(strict=True)
        if source.parent != (self.root / "building").resolve():
            raise ProjectionGenerationError("generation must be built under projections/building")
        if source.is_symlink() or len(authority_checkpoint_commitment) != 64 or len(schema_coverage_hash) != 64:
            raise ProjectionGenerationError("invalid Projection generation metadata")
        descriptor = os.open(source, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata_connection = sqlite3.connect(source)
        try:
            metadata_connection.execute(
                "CREATE TABLE IF NOT EXISTS projection_offsets(projection_name TEXT PRIMARY KEY,last_position INTEGER NOT NULL,state TEXT NOT NULL)"
            )
            metadata_connection.execute(
                "CREATE TABLE IF NOT EXISTS projection_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            metadata_connection.execute(
                "INSERT OR IGNORE INTO projection_offsets(projection_name,last_position,state) VALUES('kernel',?,'RUNNING')",
                (journal_frontier,),
            )
            row = metadata_connection.execute(
                "SELECT last_position FROM projection_offsets WHERE projection_name='kernel'"
            ).fetchone()
            if row is None or int(row[0]) != journal_frontier:
                raise ProjectionGenerationError("Projection offset does not match published Journal frontier")
            metadata_connection.execute(
                "INSERT OR REPLACE INTO projection_metadata(key,value) VALUES('schema_coverage_hash',?)",
                (schema_coverage_hash,),
            )
            metadata_connection.execute(
                "INSERT OR REPLACE INTO projection_metadata(key,value) VALUES('authority_checkpoint_commitment',?)",
                (authority_checkpoint_commitment,),
            )
            metadata_connection.execute(
                "INSERT OR REPLACE INTO projection_metadata(key,value) VALUES('journal_frontier',?)",
                (str(journal_frontier),),
            )
            metadata_connection.commit()
            metadata_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error as error:
            raise ProjectionGenerationError("Projection generation metadata is unavailable") from error
        finally:
            metadata_connection.close()
        _remove_sqlite_sidecars(source)
        descriptor = os.open(source, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        checksum = _database_checksum(source)
        database_sha256 = _file_sha256(source)
        current_pointer = self._load_pointer("current-generation.json")
        if current_pointer:
            if (
                self.authority_key_provider is None
                and isinstance(current_pointer.get("auth_key_id"), str)
                and isinstance(current_pointer.get("auth_tag"), str)
            ):
                raise ProjectionGenerationError("rotating a signed Projection pointer requires the authority signer")
            old_path = (self.root / current_pointer["database_path"]).resolve(strict=True)
            previous_path = self.root / "previous" / old_path.name
            for item in (self.root / "previous").glob("*.sqlite"):
                item.unlink()
            try:
                os.link(old_path, previous_path, follow_symlinks=False)
            except OSError:
                shutil.copy2(old_path, previous_path)
            with previous_path.open("rb") as handle:
                os.fsync(handle.fileno())
            previous_pointer = {
                **current_pointer,
                "database_path": previous_path.relative_to(self.root).as_posix(),
                "database_sha256": _file_sha256(previous_path),
            }
            if self.authority_key_provider is not None:
                previous_pointer = _sign_pointer(previous_pointer, self.authority_key_provider)
            self._write_pointer("previous-generation.json", previous_pointer)
            self._sync(self.root / "previous")

        target = self.root / "current" / f"{generation_id}.sqlite"
        if target.exists():
            raise ProjectionGenerationError("generation_id already exists")
        os.replace(source, target)
        self._sync(self.root / "building")
        self._sync(self.root / "current")
        pointer = {
            "schema": "PROJECTION_GENERATION_POINTER_V2",
            "generation_id": generation_id,
            "database_path": target.relative_to(self.root).as_posix(),
            "authority_checkpoint_commitment": authority_checkpoint_commitment,
            "journal_frontier": journal_frontier,
            "semantic_checksum": checksum,
            "database_sha256": database_sha256,
            "schema_coverage_hash": schema_coverage_hash,
            "created_at": created_at,
        }
        if self.authority_key_provider is not None:
            pointer = _sign_pointer(pointer, self.authority_key_provider)
        self._write_pointer("current-generation.json", pointer)
        for item in (self.root / "current").iterdir():
            if item != target and (item.name.endswith(".sqlite") or item.name.endswith(".sqlite-wal") or item.name.endswith(".sqlite-shm")):
                item.unlink()
        for item in (self.root / "building").iterdir():
            if item.name.endswith(".sqlite") or item.name.endswith(".sqlite-wal") or item.name.endswith(".sqlite-shm"):
                item.unlink()
        self._sync(self.root / "current")
        self._sync(self.root / "building")
        return pointer


class ProjectionGenerationReader:
    def __init__(
        self,
        root: str | Path,
        *,
        authority_key_provider: Any | None = None,
        require_signed_pointer: bool = False,
    ):
        self.root = Path(root).resolve()
        self.authority_key_provider = authority_key_provider
        self.require_signed_pointer = require_signed_pointer

    def _verified(self, name: str, allowed: set[str], allowed_coverage: set[str] | None) -> SelectedProjection | None:
        pointer_path = self.root / name
        if not pointer_path.is_file() or pointer_path.is_symlink():
            return None
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            if pointer.get("schema") != "PROJECTION_GENERATION_POINTER_V2":
                return None
            signed = isinstance(pointer.get("auth_key_id"), str) and isinstance(pointer.get("auth_tag"), str)
            if self.require_signed_pointer and (not signed or self.authority_key_provider is None):
                return None
            if signed and self.authority_key_provider is not None and not _verify_pointer(
                pointer, self.authority_key_provider
            ):
                return None
            if pointer.get("authority_checkpoint_commitment") not in allowed:
                return None
            database = (self.root / pointer["database_path"]).resolve(strict=True)
            database.relative_to(self.root)
            if database.is_symlink():
                return None
            database_sha256 = pointer.get("database_sha256")
            if isinstance(database_sha256, str):
                if _file_sha256(database) != database_sha256:
                    return None
            elif self.require_signed_pointer or _database_checksum(database) != pointer.get("semantic_checksum"):
                return None
            connection = sqlite3.connect(_immutable_uri(database), uri=True)
            try:
                metadata = dict(connection.execute("SELECT key,value FROM projection_metadata"))
                offset = connection.execute(
                    "SELECT last_position,state FROM projection_offsets WHERE projection_name='kernel'"
                ).fetchone()
            finally:
                connection.close()
            if (
                metadata.get("authority_checkpoint_commitment") != pointer.get("authority_checkpoint_commitment")
                or metadata.get("schema_coverage_hash") != pointer.get("schema_coverage_hash")
                or metadata.get("journal_frontier") != str(pointer.get("journal_frontier"))
                or offset is None
                or int(offset[0]) != int(pointer.get("journal_frontier"))
                or str(offset[1]) != "RUNNING"
            ):
                return None
            if allowed_coverage is not None and pointer.get("schema_coverage_hash") not in allowed_coverage:
                return None
            return SelectedProjection(pointer, database, name.startswith("previous"))
        except (OSError, ValueError, KeyError, json.JSONDecodeError, sqlite3.Error, ProjectionGenerationError):
            return None

    def select(
        self,
        *,
        authority_checkpoint_commitments: Iterable[str],
        schema_coverage_hashes: Iterable[str] | None = None,
    ) -> SelectedProjection:
        allowed = set(authority_checkpoint_commitments)
        allowed_coverage = set(schema_coverage_hashes) if schema_coverage_hashes is not None else None
        current = self._verified("current-generation.json", allowed, allowed_coverage)
        if current is not None:
            return current
        previous = self._verified("previous-generation.json", allowed, allowed_coverage)
        if previous is not None:
            return previous
        raise ProjectionGenerationError("no verified current or previous Projection generation")

    def select_with_tail(
        self,
        *,
        authority_checkpoint_commitments: Iterable[str],
        current_journal_frontier: int,
        tail_events: Iterable[object],
        handlers: Mapping[str, object],
        schema_coverage_hashes: Iterable[str] | None = None,
        max_tail_positions: int = 10_000,
    ) -> TailAppliedProjection:
        from .runner import ProjectionRunner

        selected = self.select(
            authority_checkpoint_commitments=authority_checkpoint_commitments,
            schema_coverage_hashes=schema_coverage_hashes,
        )
        base_frontier = int(selected.pointer["journal_frontier"])
        lag = current_journal_frontier - base_frontier
        if lag < 0:
            raise ProjectionGenerationError("Projection frontier is ahead of verified Journal authority")
        if lag > max_tail_positions:
            raise ProjectionGenerationError("Projection lag exceeds the stable-read tail bound")
        events = tuple(tail_events)
        if [int(getattr(event, "position")) for event in events] != list(
            range(base_frontier + 1, current_journal_frontier + 1)
        ):
            raise ProjectionGenerationError("Projection tail is not the exact committed Journal suffix")
        overlay = sqlite3.connect(":memory:", isolation_level=None)
        source = sqlite3.connect(_immutable_uri(selected.database_path), uri=True)
        try:
            source.backup(overlay)
        finally:
            source.close()
        if events:
            try:
                ProjectionRunner(overlay, handlers).apply_batch(events)
            except BaseException:
                overlay.close()
                raise
        return TailAppliedProjection(selected, overlay, current_journal_frontier)
