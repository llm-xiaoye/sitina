from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from sitina.journal.model import canonical_json_bytes

from .errors import FeatureGateError, StaleFencingToken


def _parse_time(value: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FeatureGateError("lease timestamp must be UTC RFC3339")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise FeatureGateError("lease timestamp is invalid") from error
    return parsed


@dataclass(frozen=True)
class RuntimeCompatibilityLease:
    process_id: str
    binary_version: str
    reader_capabilities: tuple[str, ...]
    writer_capabilities: tuple[str, ...]
    started_at: str
    lease_expires_at: str
    fencing_token: int

    @classmethod
    def build(
        cls,
        *,
        process_id: str,
        binary_version: str,
        reader_capabilities: Iterable[str],
        writer_capabilities: Iterable[str],
        started_at: str,
        lease_expires_at: str,
        fencing_token: int,
    ) -> "RuntimeCompatibilityLease":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", process_id):
            raise FeatureGateError("invalid compatibility lease process_id")
        if not isinstance(binary_version, str) or not binary_version:
            raise FeatureGateError("binary_version is required")
        readers = tuple(sorted(set(reader_capabilities)))
        writers = tuple(sorted(set(writer_capabilities)))
        if any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", item) for item in readers + writers):
            raise FeatureGateError("invalid runtime capability")
        if _parse_time(started_at) >= _parse_time(lease_expires_at):
            raise FeatureGateError("compatibility lease expiry must follow start")
        if not isinstance(fencing_token, int) or isinstance(fencing_token, bool) or fencing_token < 1:
            raise FeatureGateError("fencing_token must be positive")
        return cls(process_id, binary_version, readers, writers, started_at, lease_expires_at, fencing_token)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RuntimeCompatibilityLease":
        expected = {
            "schema",
            "process_id",
            "binary_version",
            "reader_capabilities",
            "writer_capabilities",
            "started_at",
            "lease_expires_at",
            "fencing_token",
            "lease_commitment",
        }
        if set(value) != expected or value.get("schema") != "SITINA_RUNTIME_COMPATIBILITY_LEASE_V1":
            raise FeatureGateError("invalid compatibility lease document")
        lease = cls.build(
            process_id=value["process_id"],
            binary_version=value["binary_version"],
            reader_capabilities=value["reader_capabilities"],
            writer_capabilities=value["writer_capabilities"],
            started_at=value["started_at"],
            lease_expires_at=value["lease_expires_at"],
            fencing_token=value["fencing_token"],
        )
        if value.get("lease_commitment") != lease.commitment:
            raise FeatureGateError("compatibility lease commitment mismatch")
        return lease

    def unsigned_mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_RUNTIME_COMPATIBILITY_LEASE_V1",
            "process_id": self.process_id,
            "binary_version": self.binary_version,
            "reader_capabilities": list(self.reader_capabilities),
            "writer_capabilities": list(self.writer_capabilities),
            "started_at": self.started_at,
            "lease_expires_at": self.lease_expires_at,
            "fencing_token": self.fencing_token,
        }

    @property
    def commitment(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.unsigned_mapping())).hexdigest()

    def mapping(self) -> dict[str, Any]:
        return {**self.unsigned_mapping(), "lease_commitment": self.commitment}

    def is_active(self, now: str) -> bool:
        return _parse_time(now) < _parse_time(self.lease_expires_at)


class CompatibilityLeaseRegistry:
    def __init__(self, home: str | Path):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.root = self.home / "runtime" / "compatibility-leases"
        runtime_root = self.root.parent
        if runtime_root.is_symlink() or (runtime_root.exists() and not runtime_root.is_dir()):
            raise FeatureGateError("compatibility runtime root must be a real directory")
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise FeatureGateError("compatibility lease root must be a real directory")
        self._mutex = threading.RLock()
        self._leases: dict[str, RuntimeCompatibilityLease] = {}
        self._fence_floor: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        for path in sorted(self.root.glob("*.lease.json")):
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                raise FeatureGateError("compatibility lease document must be a regular file")
            value = json.loads(path.read_text(encoding="utf-8"))
            lease = RuntimeCompatibilityLease.from_mapping(value)
            if path.name != f"{self._safe_name(lease.process_id)}.lease.json":
                raise FeatureGateError("compatibility lease filename does not match its identity")
            self._leases[lease.process_id] = lease
            self._fence_floor[lease.process_id] = max(self._fence_floor.get(lease.process_id, 0), lease.fencing_token)
        for path in sorted(self.root.glob("*.fence.json")):
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                raise FeatureGateError("compatibility fence document must be a regular file")
            value = json.loads(path.read_text(encoding="utf-8"))
            process_id = value.get("process_id")
            token = value.get("fencing_token")
            if isinstance(process_id, str) and isinstance(token, int):
                if path.name != f"{self._safe_name(process_id)}.fence.json":
                    raise FeatureGateError("compatibility fence filename does not match its identity")
                self._fence_floor[process_id] = max(self._fence_floor.get(process_id, 0), token)

    @staticmethod
    def _safe_name(process_id: str) -> str:
        return hashlib.sha256(process_id.encode("utf-8")).hexdigest()

    def _atomic_write(self, path: Path, value: Mapping[str, Any]) -> None:
        if self.root.is_symlink() or not self.root.is_dir() or path.parent != self.root:
            raise FeatureGateError("compatibility lease target escaped its real root")
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            payload = canonical_json_bytes(dict(value)) + b"\n"
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short compatibility lease write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def register(self, lease: RuntimeCompatibilityLease) -> RuntimeCompatibilityLease:
        with self._mutex:
            floor = self._fence_floor.get(lease.process_id, 0)
            current = self._leases.get(lease.process_id)
            if current is not None and current.commitment == lease.commitment:
                return current
            if lease.fencing_token <= floor:
                raise StaleFencingToken("compatibility lease fencing token did not advance")
            name = self._safe_name(lease.process_id)
            self._atomic_write(self.root / f"{name}.lease.json", lease.mapping())
            self._leases[lease.process_id] = lease
            self._fence_floor[lease.process_id] = lease.fencing_token
            return lease

    def release(self, process_id: str, *, fencing_token: int) -> None:
        with self._mutex:
            current = self._leases.get(process_id)
            if current is None or current.fencing_token != fencing_token:
                raise StaleFencingToken("only the current compatibility lease holder may release")
            name = self._safe_name(process_id)
            self._atomic_write(
                self.root / f"{name}.fence.json",
                {
                    "schema": "SITINA_RUNTIME_COMPATIBILITY_FENCE_V1",
                    "process_id": process_id,
                    "fencing_token": fencing_token,
                },
            )
            path = self.root / f"{name}.lease.json"
            path.unlink(missing_ok=True)
            directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self._leases.pop(process_id, None)

    def active(self, *, now: str) -> tuple[RuntimeCompatibilityLease, ...]:
        return tuple(sorted((item for item in self._leases.values() if item.is_active(now)), key=lambda item: item.process_id))

    def assert_all_readers(self, required: Iterable[str], *, now: str) -> None:
        required_set = set(required)
        active = self.active(now=now)
        if not active:
            raise FeatureGateError("no active Runtime Compatibility Lease")
        incompatible = [item.process_id for item in active if not required_set.issubset(item.reader_capabilities)]
        if incompatible:
            raise FeatureGateError(f"active processes lack required Reader Capability: {sorted(incompatible)}")

    def assert_writer(self, process_id: str, *, fencing_token: int, now: str) -> RuntimeCompatibilityLease:
        current = self._leases.get(process_id)
        if current is None or current.fencing_token != fencing_token:
            raise StaleFencingToken("writer fencing token is stale")
        if not current.is_active(now):
            raise FeatureGateError("expired process may not continue writing")
        return current
