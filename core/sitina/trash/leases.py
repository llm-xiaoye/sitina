from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from sitina.journal.model import canonical_json_bytes, parse_canonical_json

from .transactions import TrashError


TRASH_LEASE_STATES = frozenset({"ACTIVE", "MISSING_GRACE", "RESTORED", "RELEASED"})


def _time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise TrashError("Trash Lease timestamp must be UTC")
    return parsed


@dataclass(frozen=True)
class TrashLease:
    trash_lease_id: str
    session_id: str
    state: str
    object_refs: tuple[str, ...]
    bundle_commitment: str
    trash_location: str
    activated_at: str
    retain_until: str
    missing_since: str | None = None
    missing_grace_until: str | None = None
    restored_position: int | None = None
    released_position: int | None = None

    def __post_init__(self) -> None:
        if self.state not in TRASH_LEASE_STATES or not self.trash_lease_id or not self.session_id:
            raise TrashError("invalid Trash Lease")
        if tuple(sorted(set(self.object_refs))) != self.object_refs or any(not ref.startswith("cas:") for ref in self.object_refs):
            raise TrashError("Trash Lease object_refs must be unique sorted CAS references")

    def mapping(self) -> dict[str, Any]:
        return {"schema": "SITINA_TRASH_LEASE_V1", **self.__dict__, "object_refs": list(self.object_refs)}


class TrashLeaseRegistry:
    DEFAULT_RETENTION_DAYS = 30

    def __init__(self, home: str | Path):
        self.home = Path(home).resolve(strict=True)
        self.root = self.home / "state" / "trash-leases"
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _name(session_id: str) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest() + ".json"

    def _path(self, session_id: str) -> Path:
        return self.root / self._name(session_id)

    def _write(self, lease: TrashLease) -> None:
        path = self._path(lease.session_id)
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, canonical_json_bytes(lease.mapping()))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def load(self, session_id: str) -> TrashLease | None:
        path = self._path(session_id)
        if not path.is_file() or path.is_symlink():
            return None
        value = parse_canonical_json(path.read_bytes())
        if value.pop("schema", None) != "SITINA_TRASH_LEASE_V1":
            raise TrashError("unsupported Trash Lease schema")
        value["object_refs"] = tuple(value["object_refs"])
        return TrashLease(**value)

    def activate(
        self,
        *,
        session_id: str,
        object_refs: Iterable[str],
        bundle_commitment: str,
        trash_location: str,
        activated_at: str,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> TrashLease:
        if retention_days < 1:
            raise TrashError("Trash Lease retention must be at least one day")
        refs = tuple(sorted(set(object_refs)))
        current = self.load(session_id)
        if current is not None:
            if current.object_refs != refs or current.bundle_commitment != bundle_commitment or current.trash_location != trash_location:
                raise TrashError("Trash Lease identity conflicts with an existing lease")
            return current
        activated = _time(activated_at)
        lease = TrashLease(
            "trash-lease:" + session_id,
            session_id,
            "ACTIVE",
            refs,
            bundle_commitment,
            trash_location,
            activated_at,
            (activated + dt.timedelta(days=retention_days)).isoformat().replace("+00:00", "Z"),
        )
        self._write(lease)
        return lease

    def observe_bundle(self, session_id: str, *, present_in_trash: bool, observed_at: str) -> TrashLease:
        lease = self.load(session_id)
        if lease is None:
            raise TrashError("Trash Lease is missing")
        if lease.state in {"RESTORED", "RELEASED"}:
            return lease
        observed = _time(observed_at)
        if present_in_trash:
            if lease.state == "MISSING_GRACE":
                lease = TrashLease(
                    lease.trash_lease_id, lease.session_id, "ACTIVE", lease.object_refs,
                    lease.bundle_commitment, lease.trash_location, lease.activated_at, lease.retain_until,
                )
                self._write(lease)
            return lease
        if lease.state == "ACTIVE":
            lease = TrashLease(
                lease.trash_lease_id,
                lease.session_id,
                "MISSING_GRACE",
                lease.object_refs,
                lease.bundle_commitment,
                lease.trash_location,
                lease.activated_at,
                lease.retain_until,
                observed_at,
                (observed + dt.timedelta(days=self.DEFAULT_RETENTION_DAYS)).isoformat().replace("+00:00", "Z"),
            )
            self._write(lease)
        return lease

    def active_roots(self) -> tuple[dict[str, Any], ...]:
        roots: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("*.json")):
            value = parse_canonical_json(path.read_bytes())
            lease = self.load(str(value["session_id"]))
            if lease is None or lease.state not in {"ACTIVE", "MISSING_GRACE"}:
                continue
            for reference in lease.object_refs:
                roots.append(
                    {
                        "root_type": "trash",
                        "root_id": lease.trash_lease_id,
                        "object_ref": reference,
                        "lease_state": lease.state,
                    }
                )
        return tuple(roots)

    @staticmethod
    def verify_bundle(bundle: Path) -> tuple[dict[str, Any], str]:
        if bundle.is_symlink():
            raise TrashError("Trash import rejects a symlink bundle")
        root = bundle.resolve(strict=True)
        if not root.is_dir():
            raise TrashError("Trash import requires a real bundle directory")
        expected_names = {"manifest.json", "restore.json", "checksums.json"}
        children = tuple(root.iterdir())
        if {path.name for path in children} != expected_names or any(path.is_symlink() or not path.is_file() for path in children):
            raise TrashError("Trash Bundle contains unexpected files")
        raw = {name: (root / name).read_bytes() for name in expected_names}
        values = {name: json.loads(content) for name, content in raw.items()}
        if values["manifest.json"].get("schema") != "SITINA_TRASH_BUNDLE_V1":
            raise TrashError("Trash manifest schema is invalid")
        if values["restore.json"].get("schema") != "SITINA_TRASH_RESTORE_V1" or values["restore.json"].get("reexecute_side_effects") is not False:
            raise TrashError("Trash restore contract is invalid")
        checksums = values["checksums.json"]
        if checksums.get("schema") != "SITINA_TRASH_CHECKSUMS_V1":
            raise TrashError("Trash checksum schema is invalid")
        for name in ("manifest.json", "restore.json"):
            if checksums.get(name) != hashlib.sha256(raw[name]).hexdigest():
                raise TrashError("Trash Bundle checksum mismatch")
        manifest = values["manifest.json"]
        restore = values["restore.json"]
        required_manifest_v1 = {"schema", "session_id", "journal_frontier", "object_refs"}
        required_manifest_extended = required_manifest_v1 | {"run_ids"}
        required_restore = {"schema", "session_id", "journal_frontier", "reexecute_side_effects"}
        if frozenset(manifest) not in {frozenset(required_manifest_v1), frozenset(required_manifest_extended)} or set(restore) != required_restore or set(checksums) != {"schema", "manifest.json", "restore.json"}:
            raise TrashError("Trash Bundle contains an unknown or missing field")
        if restore["session_id"] != manifest["session_id"] or restore["journal_frontier"] != manifest["journal_frontier"]:
            raise TrashError("Trash Bundle identity fields disagree")
        refs = manifest["object_refs"]
        if (
            not isinstance(refs, list)
            or refs != sorted(set(refs))
            or any(not isinstance(ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", ref) for ref in refs)
        ):
            raise TrashError("Trash Bundle contains an invalid CAS closure")
        run_ids = manifest.get("run_ids", [])
        if not isinstance(run_ids, list) or run_ids != sorted(set(run_ids)) or any(not isinstance(run_id, str) or not run_id for run_id in run_ids):
            raise TrashError("Trash Bundle contains an invalid Run closure")
        return dict(values["manifest.json"]), hashlib.sha256(canonical_json_bytes(checksums)).hexdigest()

    def release_after_retention(
        self,
        session_id: str,
        *,
        observed_at: str,
        confirmed: bool,
        append_event: Callable[[Mapping[str, Any]], int],
    ) -> TrashLease:
        """Release only the logical Trash root; this never deletes CAS content."""
        if not confirmed:
            raise TrashError("Trash Lease release requires explicit confirmation")
        lease = self.load(session_id)
        if lease is None:
            raise TrashError("Trash Lease is missing")
        if lease.state == "RELEASED":
            return lease
        if lease.state == "RESTORED":
            raise TrashError("restored Trash Lease must be released by the import transaction")
        deadline = _time(lease.retain_until)
        if lease.missing_grace_until is not None:
            deadline = max(deadline, _time(lease.missing_grace_until))
        if _time(observed_at) < deadline:
            raise TrashError("Trash Lease retention or missing grace is still active")
        position = append_event(
            {
                "schema": "TRASH_LEASE_RELEASED_V1",
                "event_type": "trash.lease-released",
                "session_id": session_id,
                "trash_lease_id": lease.trash_lease_id,
                "reason": "RETENTION_EXPIRED_CONFIRMED",
                "idempotency_key": "trash-lease-release:" + lease.trash_lease_id,
            }
        )
        released = TrashLease(
            lease.trash_lease_id,
            lease.session_id,
            "RELEASED",
            lease.object_refs,
            lease.bundle_commitment,
            lease.trash_location,
            lease.activated_at,
            lease.retain_until,
            lease.missing_since,
            lease.missing_grace_until,
            lease.restored_position,
            position,
        )
        self._write(released)
        return released

    def import_bundle(
        self,
        bundle: str | Path,
        *,
        deleted_event_lookup: Callable[[str], Mapping[str, Any] | None],
        cas_reference_resolves: Callable[[str], bool],
        append_event: Callable[[Mapping[str, Any]], int],
        rebuild_active_roots: Callable[[str, tuple[str, ...]], None],
    ) -> TrashLease:
        manifest, commitment = self.verify_bundle(Path(bundle))
        session_id = str(manifest["session_id"])
        lease = self.load(session_id)
        if lease is None or lease.state not in {"ACTIVE", "MISSING_GRACE", "RESTORED"}:
            raise TrashError("Trash import has no active recovery lease")
        refs = tuple(sorted(manifest["object_refs"]))
        if commitment != lease.bundle_commitment or refs != lease.object_refs:
            raise TrashError("Trash import differs from the leased deletion closure")
        deleted_value = deleted_event_lookup(session_id)
        deleted = dict(deleted_value or {})
        if isinstance(deleted.get("payload"), Mapping):
            deleted = {**dict(deleted["payload"]), "event_type": deleted.get("event_type")}
        if (
            deleted.get("event_type") != "session.deleted"
            or deleted.get("bundle_commitment") != commitment
            or deleted.get("session_id") != session_id
            or deleted.get("trash_lease_id") != lease.trash_lease_id
        ):
            raise TrashError("Trash import is not bound to the Journal deletion event")
        if not all(cas_reference_resolves(reference) for reference in refs):
            raise TrashError("Trash import references unavailable or purged CAS content")
        if lease.state != "RESTORED":
            position = append_event(
                {
                    "schema": "SESSION_RESTORED_V1",
                    "event_type": "session.restored",
                    "session_id": session_id,
                    "trash_lease_id": lease.trash_lease_id,
                    "object_refs": list(refs),
                    "run_ids": list(manifest.get("run_ids", [])),
                    "bundle_commitment": commitment,
                    "reexecute_side_effects": False,
                    "idempotency_key": "trash-restore:" + lease.trash_lease_id,
                }
            )
            restored = TrashLease(
                lease.trash_lease_id, lease.session_id, "RESTORED", lease.object_refs,
                lease.bundle_commitment, lease.trash_location, lease.activated_at, lease.retain_until,
                lease.missing_since, lease.missing_grace_until, restored_position=position,
            )
            self._write(restored)
        else:
            restored = lease
        rebuild_active_roots(session_id, refs)
        released_position = append_event(
            {
                "schema": "TRASH_LEASE_RELEASED_V1",
                "event_type": "trash.lease-released",
                "session_id": session_id,
                "trash_lease_id": lease.trash_lease_id,
                "reason": "SESSION_RESTORED",
                "idempotency_key": "trash-lease-release:" + lease.trash_lease_id,
            }
        )
        released = TrashLease(
            restored.trash_lease_id, restored.session_id, "RELEASED", restored.object_refs,
            restored.bundle_commitment, restored.trash_location, restored.activated_at, restored.retain_until,
            restored.missing_since, restored.missing_grace_until, restored.restored_position, released_position,
        )
        self._write(released)
        return released


__all__ = ["TrashLease", "TrashLeaseRegistry", "TRASH_LEASE_STATES"]
