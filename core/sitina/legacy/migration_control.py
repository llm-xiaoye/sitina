from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sitina.cas.crypto import encrypt_object
from sitina.cas.model import ObjectRef
from sitina.commands.model import CommandEnvelope, CommandStatus
from sitina.journal.model import EventEnvelope
from sitina.journal.model import canonical_json_bytes, domain_hash

from .coverage import LegacyCoverageReport, _hash_regular
from .importer import MigrationCandidate


class MigrationControlError(RuntimeError): pass


@dataclass(frozen=True)
class MigrationControlFact:
    candidate_hash: str
    verifier_id: str
    migration_frontier_hash: str
    control_fact_hash: str
    business_authority: bool = False
    cutover_authority: bool = False


class MigrationControl:
    def accept(self,candidate:MigrationCandidate,*,verifier_id:str|None)->MigrationControlFact:
        if not verifier_id: raise MigrationControlError("independent migration verifier is required")
        core={"schema":"PRODUCTION_MIGRATION_CONTROL_FACT_V1","candidate_hash":candidate.candidate_hash,"verifier_id":verifier_id,"migration_frontier_hash":candidate.migration_frontier_hash,"business_authority":False,"cutover_authority":False}
        return MigrationControlFact(candidate.candidate_hash,verifier_id,candidate.migration_frontier_hash,domain_hash("PRODUCTION_MIGRATION_CONTROL_FACT",canonical_json_bytes(core)))


@dataclass(frozen=True)
class PublishedMigrationResult:
    coverage_hash: str
    source_file_count: int
    published_file_count: int
    batch_count: int
    committed_batch_count: int
    migration_frontier_hash: str
    coverage_object_ref: str
    control_transaction_hash: str
    unresolved_omission_count: int
    business_authority: bool = False
    cutover_authority: bool = False


def _reference_mapping(reference: ObjectRef) -> dict[str, object]:
    return {
        "object_id": reference.object_id,
        "tenant_id": reference.tenant_id,
        "plaintext_commitment": reference.plaintext_commitment,
        "commitment_key_id": reference.commitment_key_id,
    }


def _reference(value: Mapping[str, object]) -> ObjectRef:
    return ObjectRef(str(value["object_id"]), str(value["tenant_id"]), str(value["plaintext_commitment"]), str(value["commitment_key_id"]))


class ProductionMigrationPublisher:
    """Chunk, encrypt, root, and commit every frozen Legacy source file."""

    stream_id = "migration/control"

    def __init__(
        self,
        snapshot_root: Path,
        workspace_root: Path,
        coverage: LegacyCoverageReport,
        cas: Any,
        journal: Any,
        capability: object,
        *,
        now: int,
        chunk_bytes: int = 8 * 1024 * 1024,
        batch_size: int = 64,
    ):
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise MigrationControlError("Production migration requires a verified Phase 6B capability")
        self.snapshot_root = Path(snapshot_root).resolve(strict=True)
        self.workspace_root = Path(workspace_root).resolve(strict=True)
        if not (self.workspace_root / ".sitina-bplus-migration-workspace-v1").is_file():
            raise MigrationControlError("migration workspace marker is missing")
        capability.assert_operation("PUBLISH_MIGRATION_CONTROL_FACTS", journal.home, now=now)
        if coverage.source_coverage_percent != 100 or coverage.unexplained_omission_count != 0:
            raise MigrationControlError("migration requires complete Source Coverage and zero unexplained omissions")
        if not (self.snapshot_root == capability.snapshot_root or self.snapshot_root.is_relative_to(capability.snapshot_root)):
            raise MigrationControlError("migration snapshot is outside the Maintenance Manifest")
        if not (self.workspace_root == capability.migration_root or self.workspace_root.is_relative_to(capability.migration_root)):
            raise MigrationControlError("migration workspace is outside the Maintenance Manifest")
        if chunk_bytes < 1024 or batch_size < 1:
            raise ValueError("migration chunk and batch sizes must be positive")
        self.coverage = coverage
        self.cas = cas
        self.journal = journal
        self.capability = capability
        self.now = int(now)
        self.chunk_bytes = chunk_bytes
        self.batch_size = batch_size
        self.occurred_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        self.plan_root = self.workspace_root / "batch-plans"
        self.plan_root.mkdir(parents=True, exist_ok=True)

    def _expected(self) -> int:
        return sum(1 for event in self.journal.iter_events(0) if event.stream_id == self.stream_id)

    def _publish_bytes(self, raw: bytes, *, purpose: str):
        return self.cas.publish_verified(encrypt_object(raw, self.cas.provider, tenant_id="legacy-import", purpose=purpose))

    def _build_file_plan(self, item: Any) -> dict[str, object]:
        path = self.snapshot_root / item.source_ref
        actual_hash, metadata = _hash_regular(path)
        if actual_hash != item.sha256 or metadata.st_size != item.size:
            raise MigrationControlError(f"frozen source identity drift: {item.source_ref}")
        chunk_refs: list[dict[str, object]] = []
        with path.open("rb") as handle:
            ordinal = 0
            while True:
                raw = handle.read(self.chunk_bytes)
                if not raw:
                    break
                receipt = self._publish_bytes(raw, purpose="legacy-source-chunk")
                chunk_refs.append({"ordinal": ordinal, "length": len(raw), "reference": _reference_mapping(receipt.object_ref)})
                ordinal += 1
        manifest = {
            "schema": "LEGACY_PRESERVED_FILE_MANIFEST_V1",
            "source_ref": item.source_ref,
            "source_sha256": item.sha256,
            "source_size": item.size,
            "disposition": item.disposition,
            "reason": item.reason,
            "chunks": chunk_refs,
        }
        manifest_receipt = self._publish_bytes(canonical_json_bytes(manifest), purpose="legacy-file-manifest")
        references = [entry["reference"] for entry in chunk_refs] + [_reference_mapping(manifest_receipt.object_ref)]
        return {
            "source_ref": item.source_ref,
            "source_sha256": item.sha256,
            "source_size": item.size,
            "disposition": item.disposition,
            "reason": item.reason,
            "manifest_reference": _reference_mapping(manifest_receipt.object_ref),
            "references": references,
        }

    def _write_plan(self, path: Path, value: dict[str, object]) -> None:
        value = {**value, "plan_sha256": hashlib.sha256(canonical_json_bytes(value)).hexdigest()}
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)

    def _load_or_build_batch(self, ordinal: int, items: tuple[Any, ...]) -> dict[str, object]:
        path = self.plan_root / f"batch-{ordinal:06d}.json"
        if path.exists():
            value = json.loads(path.read_text(encoding="utf-8"))
            claimed = value.pop("plan_sha256", None)
            if claimed != hashlib.sha256(canonical_json_bytes(value)).hexdigest():
                raise MigrationControlError("persisted migration batch plan hash is invalid")
            value["plan_sha256"] = claimed
            expected = [item.source_ref for item in items]
            if value.get("coverage_hash") != self.coverage.coverage_hash or [entry["source_ref"] for entry in value.get("files", [])] != expected:
                raise MigrationControlError("persisted migration batch plan differs from frozen inputs")
            return value
        core = {
            "schema": "PRODUCTION_MIGRATION_BATCH_PLAN_V1",
            "coverage_hash": self.coverage.coverage_hash,
            "batch_ordinal": ordinal,
            "occurred_at": self.occurred_at,
            "files": [self._build_file_plan(item) for item in items],
        }
        self._write_plan(path, core)
        return json.loads(path.read_text(encoding="utf-8"))

    def _append_batch(self, plan: Mapping[str, object]):
        ordinal = int(plan["batch_ordinal"])
        command_id = f"migration-{self.coverage.coverage_hash[:32]}-{ordinal:06d}"
        payload = {
            "schema": "PRODUCTION_MIGRATION_BATCH_COMMIT_V1",
            "coverage_hash": self.coverage.coverage_hash,
            "batch_ordinal": ordinal,
            "files": plan["files"],
            "business_authority": False,
            "cutover_authority": False,
        }
        occurred_at = str(plan["occurred_at"])
        command = CommandEnvelope(command_id, "system", self.stream_id, "migration.batch.commit", "phase6b-migration-executor", occurred_at, payload)
        existing = self.journal.query_command(command_id, command.command_request_hash)
        if existing.status is CommandStatus.COMMITTED:
            return existing.receipt
        events: list[EventEnvelope] = []
        proofs: dict[str, Any] = {}
        for file_item in plan["files"]:
            refs = [_reference(value) for value in file_item["references"]]
            for reference in refs:
                proofs.setdefault(reference.reference_id, self.cas.verify_existing(reference))
            events.append(EventEnvelope(
                "event-" + domain_hash("MIGRATION_FILE_EVENT_ID", canonical_json_bytes({"coverage_hash": self.coverage.coverage_hash, "source_ref": file_item["source_ref"]}))[:48],
                "migration.legacy-file-preserved",
                "system",
                self.stream_id,
                0,
                0,
                occurred_at,
                {key: value for key, value in file_item.items() if key != "references"},
                tuple(sorted(reference.reference_id for reference in refs)),
            ))
        return self.journal.append(command, self._expected(), events, list(proofs.values()))

    def publish(self) -> PublishedMigrationResult:
        files = self.coverage.files
        committed = 0
        last_receipt = None
        for ordinal, start in enumerate(range(0, len(files), self.batch_size)):
            batch = tuple(files[start : start + self.batch_size])
            plan = self._load_or_build_batch(ordinal, batch)
            last_receipt = self._append_batch(plan)
            committed += 1
        coverage_value = {**self.coverage.mapping(), "coverage_hash": self.coverage.coverage_hash}
        coverage_plan_path = self.workspace_root / "coverage-object.json"
        if coverage_plan_path.exists():
            coverage_plan = json.loads(coverage_plan_path.read_text(encoding="utf-8"))
            claimed = coverage_plan.pop("plan_sha256", None)
            if claimed != hashlib.sha256(canonical_json_bytes(coverage_plan)).hexdigest() or coverage_plan.get("coverage_hash") != self.coverage.coverage_hash:
                raise MigrationControlError("persisted coverage object plan is invalid")
            coverage_receipt = self.cas.verify_existing(_reference(coverage_plan["reference"]))
            control_occurred_at = str(coverage_plan["occurred_at"])
        else:
            coverage_receipt = self._publish_bytes(canonical_json_bytes(coverage_value), purpose="legacy-source-coverage")
            control_occurred_at = self.occurred_at
            self._write_plan(coverage_plan_path, {
                "schema": "PRODUCTION_MIGRATION_COVERAGE_OBJECT_PLAN_V1",
                "coverage_hash": self.coverage.coverage_hash,
                "reference": _reference_mapping(coverage_receipt.object_ref),
                "occurred_at": control_occurred_at,
            })
        control_payload = {
            "schema": "PRODUCTION_MIGRATION_CONTROL_COMMITTED_V1",
            "coverage_hash": self.coverage.coverage_hash,
            "source_file_count": len(files),
            "published_file_count": len(files),
            "batch_count": committed,
            "coverage_object_ref": coverage_receipt.object_ref.reference_id,
            "unexplained_omission_count": self.coverage.unexplained_omission_count,
            "legacy_incomplete_with_reason_count": self.coverage.legacy_incomplete_with_reason_count,
            "business_authority": False,
            "cutover_authority": False,
        }
        command_id = "migration-control-" + self.coverage.coverage_hash[:40]
        command = CommandEnvelope(command_id, "system", self.stream_id, "migration.control.commit", "phase6b-migration-verifier", control_occurred_at, control_payload)
        existing = self.journal.query_command(command_id, command.command_request_hash)
        if existing.status is CommandStatus.COMMITTED:
            receipt = existing.receipt
        else:
            event = EventEnvelope(
                "event-" + self.coverage.coverage_hash[:48], "migration.control.committed", "system", self.stream_id, 0, 0,
                control_occurred_at, control_payload, (coverage_receipt.object_ref.reference_id,),
            )
            receipt = self.journal.append(command, self._expected(), [event], [coverage_receipt])
        frontier = domain_hash(
            "PRODUCTION_MIGRATION_FRONTIER",
            canonical_json_bytes({"coverage_hash": self.coverage.coverage_hash, "transaction_hash": receipt.transaction_hash, "position": receipt.last_position}),
        )
        return PublishedMigrationResult(
            self.coverage.coverage_hash,
            len(files),
            len(files),
            committed,
            committed,
            frontier,
            coverage_receipt.object_ref.reference_id,
            receipt.transaction_hash,
            self.coverage.unexplained_omission_count,
        )
