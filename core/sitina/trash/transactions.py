from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
import datetime as dt
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from sitina.journal.model import canonical_json_bytes


class TrashError(RuntimeError):
    pass


class TrashAdapter(Protocol):
    def move_to_trash(self, bundle: Path, *, idempotency_key: str) -> str: ...


class TrashDeletionCoordinator:
    _CAS_REFERENCE = re.compile(r"^cas:[0-9a-f]{64}$")
    def __init__(
        self,
        home: str | Path,
        *,
        adapter: TrashAdapter,
        fault_injector: Callable[[str], None] | None = None,
        lease_registry: object | None = None,
    ):
        self.home = Path(home).resolve(strict=True)
        self.adapter = adapter
        self.fault_injector = fault_injector
        if lease_registry is None:
            from .leases import TrashLeaseRegistry

            lease_registry = TrashLeaseRegistry(self.home)
        self.lease_registry = lease_registry
        self.staging = self.home / "trash-staging"
        self.receipts = self.home / "state" / "trash-receipts"
        self.staging.mkdir(parents=True, exist_ok=True)
        self.receipts.mkdir(parents=True, exist_ok=True)

    def _fault(self, boundary: str) -> None:
        if self.fault_injector:
            self.fault_injector(boundary)

    @staticmethod
    def _safe_title(title: str) -> str:
        value = re.sub(r"[^A-Za-z0-9._ -]+", "_", title).strip()[:80]
        return value or "Untitled"

    def _id(self, session_id: str) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest()

    def _receipt_path(self, session_id: str) -> Path:
        return self.receipts / (self._id(session_id) + ".json")

    def _write(self, path: Path, value: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, canonical_json_bytes(dict(value)) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _load(self, session_id: str) -> dict[str, Any] | None:
        path = self._receipt_path(session_id)
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    def _prepare_bundle(
        self,
        *,
        session_id: str,
        title: str,
        journal_frontier: int,
        object_refs: tuple[str, ...],
        run_ids: tuple[str, ...],
    ) -> tuple[Path, str]:
        bundle = self.staging / f"Sitina Studio - {self._safe_title(title)} - {session_id}.sitina-trash"
        bundle.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema": "SITINA_TRASH_BUNDLE_V1",
            "session_id": session_id,
            "journal_frontier": journal_frontier,
            "object_refs": list(object_refs),
            "run_ids": list(run_ids),
        }
        restore = {
            "schema": "SITINA_TRASH_RESTORE_V1",
            "session_id": session_id,
            "journal_frontier": journal_frontier,
            "reexecute_side_effects": False,
        }
        manifest_bytes = canonical_json_bytes(manifest) + b"\n"
        restore_bytes = canonical_json_bytes(restore) + b"\n"
        self._write(bundle / "manifest.json", manifest)
        self._write(bundle / "restore.json", restore)
        checksums = {
            "schema": "SITINA_TRASH_CHECKSUMS_V1",
            "manifest.json": hashlib.sha256(manifest_bytes).hexdigest(),
            "restore.json": hashlib.sha256(restore_bytes).hexdigest(),
        }
        self._write(bundle / "checksums.json", checksums)
        descriptor = os.open(bundle, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        bundle_commitment = hashlib.sha256(canonical_json_bytes(checksums)).hexdigest()
        return bundle, bundle_commitment

    @staticmethod
    def verify_bundle(bundle: Path) -> tuple[dict[str, Any], str]:
        from .leases import TrashLeaseRegistry

        return TrashLeaseRegistry.verify_bundle(bundle)

    @staticmethod
    def deletion_preview(
        *,
        session_id: str,
        memory_roots: Iterable[Mapping[str, Any]],
        backup_roots: Iterable[Mapping[str, Any]],
        cold_archive_present: bool,
        trash_retention_days: int = 30,
    ) -> dict[str, Any]:
        """Return the mandatory confirmation facts without mutating storage."""
        if trash_retention_days < 1:
            raise TrashError("Trash retention must be at least one day")
        return {
            "schema": "SITINA_SESSION_DELETION_PREVIEW_V1",
            "session_id": session_id,
            "memory_roots": [dict(item) for item in memory_roots],
            "backup_roots": [dict(item) for item in backup_roots],
            "trash_retention_days": trash_retention_days,
            "cold_archive_present": bool(cold_archive_present),
            "deletion_kind": "LOGICAL",
            "immediate_physical_destruction": False,
        }

    @staticmethod
    def memory_deletion_plan(
        memories: Iterable[Mapping[str, Any]],
        *,
        independently_rooted_refs: Mapping[str, Iterable[str]] | None = None,
    ) -> dict[str, Any]:
        """Classify memory roots for one session without changing Journal state."""

        independent = {
            reference: tuple(sorted(set(types)))
            for reference, types in (independently_rooted_refs or {}).items()
        }
        dispositions: list[dict[str, Any]] = []
        trash_refs: set[str] = set()
        retained_refs: set[str] = set()
        for raw in memories:
            memory_id = str(raw.get("memory_id", ""))
            scope = str(raw.get("scope", ""))
            status = str(raw.get("status", ""))
            content_ref = str(raw.get("content_ref", ""))
            if (
                not memory_id
                or scope not in {"agent_private", "run_shared", "project_shared", "user"}
                or status not in {"candidate", "accepted", "rejected", "superseded", "revoked", "expired"}
                or not TrashDeletionCoordinator._CAS_REFERENCE.fullmatch(content_ref)
            ):
                raise TrashError("memory deletion planning received a malformed memory record")
            other_roots = tuple(item for item in independent.get(content_ref, ()) if item not in {"active-session", "active-run"})
            if status != "accepted" or scope == "run_shared":
                disposition = "MOVE_TO_TRASH_ROOT"
                trash_refs.add(content_ref)
            elif scope in {"project_shared", "user"}:
                disposition = "RETAIN_INDEPENDENT_MEMORY_ROOT"
                retained_refs.add(content_ref)
            elif other_roots:
                disposition = "RETAIN_INDEPENDENT_USE_REVIEW_REVOKE"
                retained_refs.add(content_ref)
            else:
                disposition = "MOVE_TO_TRASH_ROOT"
                trash_refs.add(content_ref)
            dispositions.append(
                {
                    "memory_id": memory_id,
                    "scope": scope,
                    "status": status,
                    "content_ref": content_ref,
                    "other_root_types": list(other_roots),
                    "disposition": disposition,
                    "automatic_revoke": False,
                }
            )
        return {
            "schema": "SITINA_SESSION_MEMORY_DELETION_PLAN_V1",
            "dry_run": True,
            "dispositions": dispositions,
            "trash_object_refs": sorted(trash_refs),
            "retained_object_refs": sorted(retained_refs),
            "memory_revoked_events_appended": 0,
        }

    def delete(
        self,
        *,
        session_id: str,
        title: str,
        journal_frontier: int,
        object_refs: Iterable[str],
        run_ids: Iterable[str] = (),
        append_event: Callable[[Mapping[str, Any]], int],
        confirmed: bool,
        checkpoint_active_runs: Callable[[str], bool] | None = None,
        atomic_operations_drained: Callable[[str], bool] | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        if not confirmed:
            raise TrashError("session deletion requires explicit user confirmation")
        refs = tuple(sorted(set(object_refs)))
        runs = tuple(sorted(set(run_ids)))
        if any(not self._CAS_REFERENCE.fullmatch(item) for item in refs):
            raise TrashError("Trash Bundle may contain only CAS references")
        if any(not isinstance(item, str) or not item for item in runs):
            raise TrashError("session deletion run_ids are invalid")
        receipt = self._load(session_id)
        if receipt is None:
            timestamp = occurred_at or dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            receipt = {
                "schema": "SITINA_TRASH_DELETION_RECEIPT_V1",
                "session_id": session_id,
                "state": "DELETION_REQUESTED",
                "lifecycle_state": "DELETION_REQUESTED",
                "journal_frontier": journal_frontier,
                "object_refs": list(refs),
                "run_ids": list(runs),
                "requested_at": timestamp,
            }
            self._write(self._receipt_path(session_id), receipt)
        if receipt["session_id"] != session_id or receipt["object_refs"] != list(refs):
            raise TrashError("session deletion retry does not match prepared closure")
        if receipt.get("run_ids", []) != list(runs):
            raise TrashError("session deletion retry does not match its Run closure")
        if int(receipt["journal_frontier"]) != journal_frontier:
            raise TrashError("session deletion retry does not match its Journal frontier")
        if receipt["state"] == "DELETION_REQUESTED":
            receipt = {**receipt, "state": "CHECKPOINTING", "lifecycle_state": "CHECKPOINTING"}
            self._write(self._receipt_path(session_id), receipt)
        if receipt["state"] == "CHECKPOINTING":
            if atomic_operations_drained is not None and not atomic_operations_drained(session_id):
                raise TrashError("session deletion is waiting for its current atomic operation")
            if checkpoint_active_runs is not None and not checkpoint_active_runs(session_id):
                raise TrashError("session deletion requires a verified terminal checkpoint for active Runs")
            bundle, commitment = self._prepare_bundle(
                session_id=session_id,
                title=title,
                journal_frontier=journal_frontier,
                object_refs=refs,
                run_ids=runs,
            )
            self.verify_bundle(bundle)
            relative_manifest = (bundle / "manifest.json").relative_to(self.home).as_posix()
            prepared_event = {
                "schema": "SESSION_DELETION_PREPARED_V1",
                "event_type": "session.deletion-prepared",
                "session_id": session_id,
                "journal_frontier": journal_frontier,
                "bundle_commitment": commitment,
                "idempotency_key": "trash-prepare:" + session_id,
            }
            prepared_position = append_event(prepared_event)
            receipt = {
                "schema": "SITINA_TRASH_DELETION_RECEIPT_V1",
                "session_id": session_id,
                "state": "TRASH_BUNDLE_PREPARED",
                "lifecycle_state": "TRASH_BUNDLE_PREPARED",
                "journal_frontier": journal_frontier,
                "object_refs": list(refs),
                "run_ids": list(runs),
                "bundle_path": bundle.relative_to(self.home).as_posix(),
                "bundle_manifest_path": relative_manifest,
                "bundle_commitment": commitment,
                "prepared_position": prepared_position,
                "trash_location": None,
                "deleted_position": None,
                "requested_at": receipt["requested_at"],
            }
            self._write(self._receipt_path(session_id), receipt)
            self._fault("after_deletion_prepared")
        if receipt["state"] == "TRASH_BUNDLE_PREPARED":
            bundle = self.home / receipt["bundle_path"]
            location = self.adapter.move_to_trash(bundle, idempotency_key="trash-move:" + session_id)
            self._fault("after_trash_move")
            receipt = {**receipt, "state": "TRASH_MOVE_COMPLETED", "trash_location": location}
            receipt["lifecycle_state"] = "TRASH_MOVE_COMPLETED"
            self._write(self._receipt_path(session_id), receipt)
        if receipt["state"] == "TRASH_MOVE_COMPLETED":
            lease = self.lease_registry.activate(
                session_id=session_id,
                object_refs=receipt["object_refs"],
                bundle_commitment=receipt["bundle_commitment"],
                trash_location=receipt["trash_location"],
                activated_at=str(receipt["requested_at"]),
            )
            deleted_event = {
                "schema": "SESSION_DELETED_V1",
                "event_type": "session.deleted",
                "session_id": session_id,
                "bundle_commitment": receipt["bundle_commitment"],
                "trash_location": receipt["trash_location"],
                "trash_lease_id": lease.trash_lease_id,
                "object_refs": list(receipt["object_refs"]),
                "run_ids": list(receipt.get("run_ids", [])),
                "idempotency_key": "trash-delete:" + session_id,
            }
            deleted_position = append_event(deleted_event)
            receipt = {
                **receipt,
                "state": "DELETION_COMMITTED",
                "lifecycle_state": "HIDDEN_FROM_PROJECTION",
                "deleted_position": deleted_position,
                "trash_lease_id": lease.trash_lease_id,
                "projection_hidden": True,
            }
            self._write(self._receipt_path(session_id), receipt)
            self._fault("after_deletion_committed")
        return receipt
