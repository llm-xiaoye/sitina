from __future__ import annotations

import hashlib
import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash, parse_canonical_json, validate_identifier


class GCFenceError(RuntimeError):
    pass


class GCState(str, Enum):
    IDLE = "IDLE"
    MARKED = "MARKED"
    QUARANTINING = "QUARANTINING"
    SWEPT = "SWEPT"


class ContentLifecycleState(str, Enum):
    AVAILABLE = "AVAILABLE"
    TRASH_HELD = "TRASH_HELD"
    BACKUP_HELD = "BACKUP_HELD"
    PURGED = "PURGED"
    CRYPTO_SHREDDED = "CRYPTO_SHREDDED"
    MISSING_UNATTESTED = "MISSING_UNATTESTED"


REQUIRED_CATALOGS = frozenset({"journal", "cas", "package", "supplement", "archive", "migration", "rebuild"})
SEMANTIC_ROOT_TYPES = frozenset(
    {
        "system",
        "session",
        "active-session",
        "active-run",
        "memory",
        "backup",
        "trash",
        "legal-retention",
        "inflight-lease",
    }
)
_CAS_REFERENCE = re.compile(r"^cas:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DestructionAttestation:
    object_ref: str
    disposition: str
    journal_position: int
    frontier_commitment: str
    occurred_at: str
    reason: str

    def __post_init__(self) -> None:
        if not _CAS_REFERENCE.fullmatch(self.object_ref):
            raise GCFenceError("destruction attestation requires a CAS reference")
        if self.disposition not in {"PHYSICAL_DELETE", "CRYPTO_SHRED"} or self.journal_position < 1:
            raise GCFenceError("invalid destruction disposition or Journal position")
        if not re.fullmatch(r"[0-9a-f]{64}", self.frontier_commitment):
            raise GCFenceError("destruction attestation frontier is invalid")
        if not self.occurred_at or not self.reason:
            raise GCFenceError("destruction attestation time and reason are required")

    def unsigned_mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_CAS_DESTRUCTION_ATTESTATION_V1",
            "object_ref": self.object_ref,
            "disposition": self.disposition,
            "journal_position": self.journal_position,
            "frontier_commitment": self.frontier_commitment,
            "occurred_at": self.occurred_at,
            "reason": self.reason,
        }

    def mapping(self) -> dict[str, Any]:
        value = self.unsigned_mapping()
        return {**value, "attestation_id": domain_hash("CAS_DESTRUCTION_ATTESTATION", canonical_json_bytes(value))}


class ContentLifecycleResolver:
    """Explain missing content from authenticated destruction facts, never guess corruption."""

    _ATTESTATION_FIELDS = frozenset(
        {
            "schema",
            "attestation_id",
            "object_ref",
            "disposition",
            "journal_position",
            "frontier_commitment",
            "occurred_at",
            "reason",
        }
    )

    def __init__(self, cas: object, roots: "SemanticRootIndex | None" = None):
        self.cas = cas
        self.roots = roots

    def _attestation(self, object_ref: str) -> DestructionAttestation | None:
        root = Path(self.cas.root) / "destruction-attestations"
        matches: list[DestructionAttestation] = []
        for path in sorted(root.glob("*.json")):
            if path.is_symlink() or not path.is_file():
                raise GCFenceError("destruction attestation inventory rejects symlinks")
            try:
                value = parse_canonical_json(path.read_bytes(), allowed_fields=self._ATTESTATION_FIELDS)
            except Exception:
                continue
            if value.get("schema") != "SITINA_CAS_DESTRUCTION_ATTESTATION_V1" or value.get("object_ref") != object_ref:
                continue
            try:
                attestation = DestructionAttestation(
                    object_ref=str(value["object_ref"]),
                    disposition=str(value["disposition"]),
                    journal_position=int(value["journal_position"]),
                    frontier_commitment=str(value["frontier_commitment"]),
                    occurred_at=str(value["occurred_at"]),
                    reason=str(value["reason"]),
                )
            except (KeyError, TypeError, ValueError, GCFenceError):
                continue
            expected = attestation.mapping()["attestation_id"]
            if value.get("attestation_id") != expected or path.stem != expected:
                continue
            matches.append(attestation)
        if not matches:
            return None
        matches.sort(key=lambda item: item.journal_position)
        return matches[-1]

    def status(self, object_ref: str) -> dict[str, Any]:
        if not _CAS_REFERENCE.fullmatch(object_ref):
            raise GCFenceError("content lifecycle lookup requires a CAS reference")
        attestation = self._attestation(object_ref)
        object_path = Path(self.cas.root) / "objects" / object_ref[4:6] / (object_ref[4:] + ".obj")
        exists = object_path.is_file() and not object_path.is_symlink()
        if attestation is not None and attestation.disposition == "CRYPTO_SHRED":
            state = ContentLifecycleState.CRYPTO_SHREDDED
        elif not exists and attestation is not None and attestation.disposition == "PHYSICAL_DELETE":
            state = ContentLifecycleState.PURGED
        elif not exists:
            state = ContentLifecycleState.MISSING_UNATTESTED
        else:
            root_types = set(self.roots.root_types_for(object_ref)) if self.roots is not None else set()
            if "trash" in root_types:
                state = ContentLifecycleState.TRASH_HELD
            elif "backup" in root_types:
                state = ContentLifecycleState.BACKUP_HELD
            else:
                state = ContentLifecycleState.AVAILABLE
        return {
            "schema": "SITINA_CONTENT_LIFECYCLE_STATUS_V1",
            "object_ref": object_ref,
            "state": state.value,
            "destruction_attestation": None if attestation is None else attestation.mapping(),
            "classified_as_corruption": False if state in {ContentLifecycleState.PURGED, ContentLifecycleState.CRYPTO_SHREDDED} else None,
        }


@dataclass(frozen=True)
class SemanticRoot:
    root_type: str
    root_id: str
    object_ref: str
    source_position: int
    source_event_id: str
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.root_type not in SEMANTIC_ROOT_TYPES or not self.root_id:
            raise GCFenceError("invalid semantic GC root identity")
        if not _CAS_REFERENCE.fullmatch(self.object_ref):
            raise GCFenceError("semantic GC root requires a CAS reference")
        if self.source_position < 0 or self.schema_version != 1:
            raise GCFenceError("invalid semantic GC root source")

    def mapping(self) -> dict[str, Any]:
        return {
            "root_type": self.root_type,
            "root_id": self.root_id,
            "object_ref": self.object_ref,
            "source_position": self.source_position,
            "source_event_id": self.source_event_id,
            "schema_version": self.schema_version,
        }


class SemanticRootIndex:
    """Authority-derived current roots; historical object_refs are intentionally ignored."""

    def __init__(self, roots: Iterable[SemanticRoot] = (), *, checkpoint_position: int = 0):
        self.checkpoint_position = checkpoint_position
        self.tail_frontier = checkpoint_position
        self._roots: dict[tuple[str, str, str], SemanticRoot] = {}
        for root in roots:
            self._roots[(root.root_type, root.root_id, root.object_ref)] = root

    @property
    def roots(self) -> tuple[SemanticRoot, ...]:
        return tuple(sorted(self._roots.values(), key=lambda item: (item.root_type, item.root_id, item.object_ref)))

    @property
    def commitment(self) -> str:
        value = {"schema": "SITINA_ACTIVE_ROOTS_INDEX_V1", "roots": [root.mapping() for root in self.roots]}
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()

    @classmethod
    def from_checkpoint(
        cls,
        snapshot: Sequence[Mapping[str, Any]],
        *,
        active_roots_index_commitment: str,
        checkpoint_position: int,
    ) -> "SemanticRootIndex":
        roots = tuple(SemanticRoot(**dict(value)) for value in snapshot)
        if any(root.source_position > checkpoint_position for root in roots):
            raise GCFenceError("active-roots snapshot contains a post-checkpoint source")
        index = cls(roots, checkpoint_position=checkpoint_position)
        if index.commitment != active_roots_index_commitment:
            raise GCFenceError("Authority active-roots snapshot commitment mismatch")
        return index

    @classmethod
    def from_fast_start(cls, report: object) -> "SemanticRootIndex":
        snapshot = getattr(report, "active_roots_snapshot", ())
        commitment = getattr(report, "semantic_active_roots_commitment", None)
        checkpoint_position = int(getattr(report, "verified_through_position", 0))
        if not snapshot or not isinstance(commitment, str):
            raise GCFenceError("Authority Checkpoint has no typed semantic active-roots snapshot")
        index = cls.from_checkpoint(
            snapshot,
            active_roots_index_commitment=commitment,
            checkpoint_position=checkpoint_position,
        )
        index.apply_tail(getattr(report, "active_tail_events", ()))
        return index

    def active_reference_ids(self) -> frozenset[str]:
        return frozenset(root.object_ref for root in self._roots.values())

    def root_types_for(self, object_ref: str) -> tuple[str, ...]:
        return tuple(sorted({root.root_type for root in self._roots.values() if root.object_ref == object_ref}))

    def activate(self, root: SemanticRoot) -> None:
        self._roots[(root.root_type, root.root_id, root.object_ref)] = root

    def release(self, *, root_type: str, root_id: str, object_ref: str | None = None) -> None:
        for key in tuple(self._roots):
            if key[0] == root_type and key[1] == root_id and (object_ref is None or key[2] == object_ref):
                self._roots.pop(key)

    @staticmethod
    def _event_value(event: object, field: str, default: Any = None) -> Any:
        if isinstance(event, Mapping):
            return event.get(field, default)
        return getattr(event, field, default)

    @staticmethod
    def _refs(payload: Mapping[str, Any], *fields: str) -> tuple[str, ...]:
        values: list[str] = []
        for field in fields:
            value = payload.get(field)
            if isinstance(value, str) and _CAS_REFERENCE.fullmatch(value):
                values.append(value)
            elif isinstance(value, (list, tuple)):
                values.extend(item for item in value if isinstance(item, str) and _CAS_REFERENCE.fullmatch(item))
        return tuple(sorted(set(values)))

    def apply_tail(self, events: Iterable[object]) -> None:
        for event in events:
            position = int(self._event_value(event, "position", 0))
            if position <= self.tail_frontier:
                raise GCFenceError("active-roots tail is not strictly ordered after checkpoint")
            event_type = str(self._event_value(event, "event_type", ""))
            event_id = str(self._event_value(event, "event_id", f"position:{position}"))
            payload_value = self._event_value(event, "payload", {})
            payload = dict(payload_value) if isinstance(payload_value, Mapping) else {}

            run_id_value = payload.get("run_id")
            event_object_refs = self._event_value(event, "object_refs", ())
            if isinstance(run_id_value, str) and run_id_value:
                for reference in self._refs({"refs": event_object_refs}, "refs"):
                    self.activate(SemanticRoot("active-run", run_id_value, reference, position, event_id))

            if event_type == "session.message-appended":
                session_id = str(payload.get("session_id", self._event_value(event, "stream_id", "")))
                for reference in self._refs(payload, "body_ref"):
                    self.activate(SemanticRoot("active-session", session_id, reference, position, event_id))
            elif event_type == "session.deleted":
                session_id = str(payload.get("session_id", ""))
                self.release(root_type="session", root_id=session_id)
                self.release(root_type="active-session", root_id=session_id)
                for run_id in payload.get("run_ids", ()):
                    self.release(root_type="active-run", root_id=str(run_id))
                trash_id = str(payload.get("trash_lease_id", session_id))
                for reference in self._refs(payload, "object_refs"):
                    self.activate(SemanticRoot("trash", trash_id, reference, position, event_id))
            elif event_type == "session.restored":
                session_id = str(payload.get("session_id", ""))
                trash_id = str(payload.get("trash_lease_id", session_id))
                refs = self._refs(payload, "object_refs")
                self.release(root_type="trash", root_id=trash_id)
                for reference in refs:
                    self.activate(SemanticRoot("active-session", session_id, reference, position, event_id))
            elif event_type in {"trash.root-released", "trash.lease-released"}:
                self.release(root_type="trash", root_id=str(payload.get("trash_lease_id", payload.get("root_id", ""))))
            elif event_type == "memory.accepted":
                memory_id = str(payload.get("memory_id", ""))
                for reference in self._refs(payload, "content_ref"):
                    self.activate(SemanticRoot("memory", memory_id, reference, position, event_id))
            elif event_type in {"memory.revoked", "memory.expired", "memory.superseded"}:
                self.release(root_type="memory", root_id=str(payload.get("memory_id", "")))
            elif event_type in {"backup.root-activated", "backup.activated"}:
                backup_id = str(payload.get("backup_id", payload.get("root_id", "")))
                for reference in self._refs(payload, "object_refs"):
                    self.activate(SemanticRoot("backup", backup_id, reference, position, event_id))
            elif event_type in {"backup.root-released", "backup.retired"}:
                self.release(root_type="backup", root_id=str(payload.get("backup_id", payload.get("root_id", ""))))
            elif event_type == "legal-retention.activated":
                hold_id = str(payload.get("hold_id", ""))
                for reference in self._refs(payload, "object_refs"):
                    self.activate(SemanticRoot("legal-retention", hold_id, reference, position, event_id))
            elif event_type == "legal-retention.released":
                self.release(root_type="legal-retention", root_id=str(payload.get("hold_id", "")))
            elif event_type == "gc.reference_lease_acquired":
                lease_id = str(payload.get("lease_id", ""))
                for reference in self._refs(payload, "reference_id"):
                    self.activate(SemanticRoot("inflight-lease", lease_id, reference, position, event_id))
            elif event_type in {"gc.reference_lease_released", "gc.reference_root_committed"}:
                self.release(root_type="inflight-lease", root_id=str(payload.get("lease_id", "")))
            elif event_type == "run.checkpoint-chain-compacted":
                run_id = str(payload.get("run_id", ""))
                for reference in self._refs(payload, "released_checkpoint_root_refs"):
                    self.release(root_type="active-run", root_id=run_id, object_ref=reference)
            elif event_type in {"run.root-released", "run.deleted"}:
                self.release(root_type="active-run", root_id=str(payload.get("run_id", "")))
            elif event_type == "system.root-activated":
                root_id = str(payload.get("root_id", ""))
                for reference in self._refs(payload, "object_refs", "object_ref"):
                    self.activate(SemanticRoot("system", root_id, reference, position, event_id))
            elif event_type == "system.root-released":
                self.release(root_type="system", root_id=str(payload.get("root_id", "")))
            elif event_type == "gc.root-activated":
                root_type = str(payload.get("root_type", ""))
                root_id = str(payload.get("root_id", ""))
                for reference in self._refs(payload, "object_refs", "object_ref"):
                    self.activate(SemanticRoot(root_type, root_id, reference, position, event_id))
            elif event_type == "gc.root-released":
                self.release(
                    root_type=str(payload.get("root_type", "")),
                    root_id=str(payload.get("root_id", "")),
                    object_ref=str(payload["object_ref"]) if "object_ref" in payload else None,
                )
            # Other events, including historical object_refs, do not create a current root.
            self.tail_frontier = position


class SemanticGCDryRunPlanner:
    """Read-only mark planner. This release deliberately exposes no physical sweep path."""

    def __init__(self, cas: object):
        self.cas = cas

    def plan(
        self,
        roots: SemanticRootIndex,
        *,
        historical_references: Iterable[str],
        now_epoch_seconds: int,
        grace_seconds: int,
    ) -> dict[str, Any]:
        if grace_seconds < 0:
            raise GCFenceError("GC grace must not be negative")
        active = roots.active_reference_ids()
        history = set(historical_references)
        retained: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        objects_root = Path(self.cas.root) / "objects"
        for path in sorted(objects_root.rglob("*.obj")):
            if path.is_symlink():
                raise GCFenceError("GC inventory rejects CAS symlinks")
            reference = "cas:" + path.stem
            age = max(0, now_epoch_seconds - int(path.stat().st_mtime))
            metadata = path.stat()
            item = {
                "object_ref": reference,
                "logical_bytes": metadata.st_size,
                "allocated_bytes": int(getattr(metadata, "st_blocks", 0)) * 512 or metadata.st_size,
                "age_seconds": age,
                "appears_in_journal_history": reference in history,
                "active_root_types": list(roots.root_types_for(reference)),
            }
            if reference in active:
                retained.append({**item, "reason": "ACTIVE_SEMANTIC_ROOT"})
            elif age < grace_seconds:
                retained.append({**item, "reason": "ORPHAN_GRACE"})
            else:
                candidates.append({**item, "reason": "NO_ACTIVE_ROOT"})
        return {
            "schema": "SITINA_SEMANTIC_GC_DRY_RUN_V1",
            "dry_run": True,
            "physical_delete_executed": False,
            "active_roots_index_commitment": roots.commitment,
            "checkpoint_position": roots.checkpoint_position,
            "tail_frontier": roots.tail_frontier,
            "retained": retained,
            "candidates": candidates,
            "candidate_bytes": sum(int(item["allocated_bytes"]) for item in candidates),
            "journal_history_is_not_an_implicit_root": True,
        }


@dataclass(frozen=True)
class GCMarkFrontier:
    journal_frontier: FrontierRef
    gc_epoch: int
    catalog_versions: Mapping[str, str]
    hold_snapshot_hash: str
    policy_hash: str
    signed_frontier_hash: str | None = None
    mark_started_position: int | None = None
    catalog_snapshot_hash: str | None = None
    catalogs_readable: bool = True
    hold_snapshot_readable: bool = True
    epoch_valid: bool = True

    def __post_init__(self) -> None:
        if self.gc_epoch < 1:
            raise GCFenceError("GC epoch must be positive")
        if set(self.catalog_versions) != REQUIRED_CATALOGS:
            raise GCFenceError("GC catalog coverage is incomplete")
        for digest in (self.hold_snapshot_hash, self.policy_hash, self.signed_frontier_hash, self.catalog_snapshot_hash):
            if digest is None:
                continue
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise GCFenceError("GC frozen hash is invalid")
        if self.mark_started_position is not None and self.mark_started_position <= self.journal_frontier.position:
            raise GCFenceError("GC mark start must follow the frozen Journal frontier")

    @property
    def commitment(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "journal": self.journal_frontier.__dict__, "gc_epoch": self.gc_epoch,
                    "catalog_versions": dict(self.catalog_versions), "hold_snapshot_hash": self.hold_snapshot_hash,
                    "policy_hash": self.policy_hash, "signed_frontier_hash": self.signed_frontier_hash,
                    "mark_started_position": self.mark_started_position, "catalog_snapshot_hash": self.catalog_snapshot_hash,
                    "catalogs_readable": self.catalogs_readable, "hold_snapshot_readable": self.hold_snapshot_readable,
                    "epoch_valid": self.epoch_valid,
                }
            )
        ).hexdigest()


@dataclass
class ReferenceLease:
    lease_id: str
    reference_id: str
    gc_epoch: int
    controller: "GCController" = field(repr=False)
    active: bool = True

    def commit(self, *, transaction_hash: str, position: int) -> None:
        self.controller.commit_reference(self, transaction_hash=transaction_hash, position=position)

    def release(self) -> None:
        self.controller.release_reference(self)

    def __enter__(self) -> "ReferenceLease":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        if self.active:
            self.release()


@dataclass
class GCCycle:
    cycle_id: str
    frontier: GCMarkFrontier
    candidates: set[str]
    state: GCState = GCState.MARKED
    quarantined: set[str] = field(default_factory=set)
    swept: set[str] = field(default_factory=set)


class GCController:
    def __init__(self, record_operational: Callable[[str, dict], None], *, reconciled: bool = True):
        if record_operational is None:
            raise GCFenceError("Journal-backed operational recorder is required")
        self._record = record_operational
        self._lock = threading.RLock()
        self._leases: dict[str, ReferenceLease] = {}
        self._in_flight: dict[str, int] = {}
        self._committed: set[str] = set()
        self._post_frontier: set[str] = set()
        self._holds: set[str] = set()
        self._reads: set[str] = set()
        self._backups: set[str] = set()
        self._restores: set[str] = set()
        self._semantic_roots: set[str] = set()
        self.cycle: GCCycle | None = None
        self.reconciled = reconciled

    @property
    def gc_epoch(self) -> int:
        return self.cycle.frontier.gc_epoch if self.cycle else 1

    def reconcile(self, *, journal_verified: bool, leases_reconciled: bool) -> None:
        if not journal_verified or not leases_reconciled:
            raise GCFenceError("Journal and lease reconciliation are both required")
        self.reconciled = True
        self._record("gc.reconciled", {"journal_verified": True, "leases_reconciled": True})

    def with_reference_lease(self, reference_id: str) -> ReferenceLease:
        validate_identifier(reference_id, field="reference_id")
        with self._lock:
            if not self.reconciled:
                raise GCFenceError("GC/reference admission is blocked until restart reconciliation")
            if self.cycle and reference_id in self.cycle.quarantined:
                raise GCFenceError("reference is already QUARANTINING")
            lease = ReferenceLease(uuid.uuid4().hex, reference_id, self.gc_epoch, self)
            self._leases[lease.lease_id] = lease
            self._in_flight[reference_id] = self._in_flight.get(reference_id, 0) + 1
            if self.cycle and self.cycle.state in {GCState.MARKED, GCState.QUARANTINING}:
                self._post_frontier.add(reference_id)
            self._record("gc.reference_lease_acquired", {"lease_id": lease.lease_id, "reference_id": reference_id, "gc_epoch": lease.gc_epoch})
            return lease

    def release_reference(self, lease: ReferenceLease) -> None:
        with self._lock:
            current = self._leases.pop(lease.lease_id, None)
            if current is None or not lease.active:
                return
            count = self._in_flight[lease.reference_id] - 1
            if count:
                self._in_flight[lease.reference_id] = count
            else:
                self._in_flight.pop(lease.reference_id, None)
            lease.active = False
            self._record("gc.reference_lease_released", {"lease_id": lease.lease_id, "reference_id": lease.reference_id})

    def commit_reference(self, lease: ReferenceLease, *, transaction_hash: str, position: int) -> None:
        if len(transaction_hash) != 64 or position < 1:
            raise GCFenceError("invalid committed reference root")
        with self._lock:
            if lease.lease_id not in self._leases or not lease.active:
                raise GCFenceError("reference lease is not active")
            self._committed.add(lease.reference_id)
            self._record("gc.reference_root_committed", {"lease_id": lease.lease_id, "reference_id": lease.reference_id, "transaction_hash": transaction_hash, "position": position, "gc_epoch": lease.gc_epoch})
            self.release_reference(lease)

    def mark(self, frontier: GCMarkFrontier, candidates: Iterable[str]) -> GCCycle:
        with self._lock:
            if not self.reconciled:
                raise GCFenceError("GC cannot mark before reconciliation")
            if self.cycle and self.cycle.state is not GCState.SWEPT:
                raise GCFenceError("another GC cycle is active")
            if not frontier.catalogs_readable or not frontier.hold_snapshot_readable or not frontier.epoch_valid:
                raise GCFenceError("GC frozen frontier cannot be established from unreadable or invalid snapshots")
            candidate_set = set(candidates)
            for reference in candidate_set:
                validate_identifier(reference, field="reference_id")
            self.cycle = GCCycle(uuid.uuid4().hex, frontier, candidate_set)
            self._record("gc.mark_frontier_frozen", {"cycle_id": self.cycle.cycle_id, "frontier_commitment": frontier.commitment, "candidate_count": len(candidate_set)})
            return self.cycle

    def validate_frozen_snapshot(
        self,
        *,
        current_catalog_versions: Mapping[str, str],
        current_hold_snapshot_hash: str,
        current_catalog_snapshot_hash: str | None = None,
    ) -> None:
        if self.cycle is None:
            raise GCFenceError("no frozen GC cycle exists")
        frontier = self.cycle.frontier
        if dict(current_catalog_versions) != dict(frontier.catalog_versions):
            raise GCFenceError("GC catalog versions drifted from the frozen snapshot")
        if current_hold_snapshot_hash != frontier.hold_snapshot_hash:
            raise GCFenceError("GC hold snapshot drifted")
        if current_catalog_snapshot_hash is not None and current_catalog_snapshot_hash != frontier.catalog_snapshot_hash:
            raise GCFenceError("GC catalog snapshot commitment drifted")

    def propose_retention_operation(
        self,
        reference_id: str,
        *,
        operation_id: str,
        grace_elapsed: bool,
        second_confirmation: bool,
    ) -> dict[str, object]:
        with self._lock:
            if not self.cycle or reference_id not in self.cycle.candidates:
                raise GCFenceError("reference is outside an active marked cycle")
            if not grace_elapsed or not second_confirmation:
                raise GCFenceError("retention grace and second confirmation are required")
            if self._protected(reference_id):
                raise GCFenceError("reference is protected at retention proposal recheck")
            return {
                "schema": "GC_RETENTION_OPERATION_PROPOSED_V1",
                "operation_id": operation_id,
                "reference_id": reference_id,
                "frontier_commitment": self.cycle.frontier.commitment,
                "delete_authorized": False,
                "physical_delete_executed": False,
                "dry_run_only": True,
            }

    def add_hold(self, reference_id: str) -> None:
        self._holds.add(reference_id)

    def add_read(self, reference_id: str) -> None:
        self._reads.add(reference_id)

    def add_backup(self, reference_id: str) -> None:
        self._backups.add(reference_id)

    def add_restore(self, reference_id: str) -> None:
        self._restores.add(reference_id)

    def set_semantic_roots(self, roots: SemanticRootIndex) -> None:
        self._semantic_roots = set(roots.active_reference_ids())

    def _protected(self, reference_id: str) -> bool:
        return bool(
            self._in_flight.get(reference_id)
            or reference_id in self._committed
            or reference_id in self._post_frontier
            or reference_id in self._holds
            or reference_id in self._reads
            or reference_id in self._backups
            or reference_id in self._restores
            or reference_id in self._semantic_roots
        )

    def quarantine(self, reference_id: str) -> None:
        with self._lock:
            if not self.reconciled or not self.cycle or reference_id not in self.cycle.candidates:
                raise GCFenceError("reference is outside an active marked cycle")
            if self._protected(reference_id):
                raise GCFenceError("reference is protected at quarantine recheck")
            self.cycle.state = GCState.QUARANTINING
            self.cycle.quarantined.add(reference_id)
            self._record("gc.object_quarantining", {"cycle_id": self.cycle.cycle_id, "reference_id": reference_id})

    def sweep(self, reference_id: str) -> None:
        with self._lock:
            if not self.cycle or reference_id not in self.cycle.quarantined:
                raise GCFenceError("only quarantined candidates can be swept")
            if self._protected(reference_id):
                raise GCFenceError("reference became protected before sweep")
            self.cycle.swept.add(reference_id)
            if self.cycle.swept == self.cycle.quarantined and self.cycle.quarantined == self.cycle.candidates:
                self.cycle.state = GCState.SWEPT
            self._record("gc.object_swept", {"cycle_id": self.cycle.cycle_id, "reference_id": reference_id})
