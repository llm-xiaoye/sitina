from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sitina.journal.model import canonical_json_bytes


class LeaseError(RuntimeError):
    pass


class LeaseFenceError(LeaseError):
    pass


def _time(value: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise LeaseError("invalid lease timestamp") from error


@dataclass(frozen=True)
class DurableLease:
    lease_id: str
    holder_id: str
    resource_type: str
    resource_id: str
    issued_at: str
    expires_at: str
    fencing_token: int

    def mapping(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "holder_id": self.holder_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "fencing_token": self.fencing_token,
        }


class DurableLeaseRegistry:
    def __init__(self, home: str | Path):
        self.home = Path(home).resolve(strict=True)
        self.root = self.home / "runtime" / "leases"
        self.root.mkdir(parents=True, exist_ok=True)
        self._mutex = threading.RLock()

    @staticmethod
    def _key(resource_type: str, resource_id: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", resource_type) or not resource_id:
            raise LeaseError("invalid leased resource identity")
        return hashlib.sha256(f"{resource_type}\0{resource_id}".encode()).hexdigest()

    def _path(self, resource_type: str, resource_id: str) -> Path:
        return self.root / (self._key(resource_type, resource_id) + ".json")

    def _read(self, path: Path) -> dict[str, Any] | None:
        if not path.is_file() or path.is_symlink():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "SITINA_DURABLE_RESOURCE_LEASE_V1":
            raise LeaseError("unsupported durable lease")
        return value

    def _write(self, path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        payload = canonical_json_bytes(value) + b"\n"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def acquire(
        self,
        *,
        resource_type: str,
        resource_id: str,
        holder_id: str,
        issued_at: str,
        expires_at: str,
    ) -> DurableLease:
        if _time(issued_at) >= _time(expires_at):
            raise LeaseError("lease expiry must follow issuance")
        path = self._path(resource_type, resource_id)
        with self._mutex:
            current = self._read(path)
            if current and current.get("active") and _time(issued_at) < _time(current["expires_at"]):
                raise LeaseError("resource already has an active lease")
            token = int(current.get("fencing_token", 0) if current else 0) + 1
            lease = DurableLease(
                "lease-" + uuid.uuid4().hex,
                holder_id,
                resource_type,
                resource_id,
                issued_at,
                expires_at,
                token,
            )
            self._write(path, {"schema": "SITINA_DURABLE_RESOURCE_LEASE_V1", "active": True, **lease.mapping()})
            return lease

    def release(self, lease_id: str, *, fencing_token: int) -> None:
        with self._mutex:
            matches = [path for path in self.root.glob("*.json") if (value := self._read(path)) and value.get("lease_id") == lease_id]
            if len(matches) != 1:
                raise LeaseFenceError("lease is not current")
            path = matches[0]
            current = self._read(path)
            if not current or not current.get("active") or current.get("fencing_token") != fencing_token:
                raise LeaseFenceError("lease fencing token is stale")
            self._write(path, {**current, "active": False})

    def assert_holder(self, lease_id: str, *, fencing_token: int, now: str) -> DurableLease:
        for path in self.root.glob("*.json"):
            value = self._read(path)
            if value and value.get("lease_id") == lease_id:
                if not value.get("active") or value.get("fencing_token") != fencing_token or _time(now) >= _time(value["expires_at"]):
                    raise LeaseFenceError("lease is expired or fenced")
                return DurableLease(
                    value["lease_id"], value["holder_id"], value["resource_type"], value["resource_id"],
                    value["issued_at"], value["expires_at"], value["fencing_token"],
                )
        raise LeaseFenceError("lease is not current")
