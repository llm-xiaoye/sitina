from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from sitina.journal.model import canonical_json_bytes, parse_canonical_json

from .crypto import decrypt_object
from .local import LocalCAS
from .model import CASError, EncryptedObject, ObjectEnvelope, ObjectRef
from .native import sync_directory


STAGING_STATES = ("STAGING", "VALIDATED", "PUBLISHED", "JOURNAL_ROOTED", "RELEASED")


@dataclass(frozen=True)
class CASStagingRecord:
    operation_id: str
    command_hash: str
    state: str
    sequence: int
    created_at: str
    object_ref: ObjectRef
    data: dict[str, Any]


class CASStagingCoordinator:
    """Durable CAS pre-publication state without creating another authority store."""

    def __init__(self, cas: LocalCAS):
        self.cas = cas
        self.root = cas.home / "runtime" / "cas-staging-receipts"
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _name(operation_id: str) -> str:
        if not isinstance(operation_id, str) or not operation_id:
            raise CASError("CAS staging operation_id is required")
        return hashlib.sha256(operation_id.encode()).hexdigest()

    def _receipt_path(self, operation_id: str) -> Path:
        return self.root / f"{self._name(operation_id)}.json"

    def _object_path(self, operation_id: str) -> Path:
        return self.cas.root / "staging" / f"{self._name(operation_id)}.obj.stage"

    def _envelope_path(self, operation_id: str) -> Path:
        return self.cas.root / "staging" / f"{self._name(operation_id)}.envelope.stage"

    @staticmethod
    def _reference_mapping(reference: ObjectRef) -> dict[str, Any]:
        return {
            "object_id": reference.object_id,
            "tenant_id": reference.tenant_id,
            "plaintext_commitment": reference.plaintext_commitment,
            "commitment_key_id": reference.commitment_key_id,
            "profile": reference.profile,
        }

    def _write(self, value: Mapping[str, Any]) -> None:
        path = self._receipt_path(str(value["operation_id"]))
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        raw = canonical_json_bytes(dict(value))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        sync_directory(self.root)

    def load(self, operation_id: str) -> CASStagingRecord | None:
        path = self._receipt_path(operation_id)
        if not path.is_file() or path.is_symlink():
            return None
        value = parse_canonical_json(path.read_bytes())
        if value.get("schema") != "SITINA_CAS_STAGING_RECEIPT_V1" or value.get("state") not in STAGING_STATES:
            raise CASError("unsupported CAS staging receipt")
        return CASStagingRecord(
            operation_id=str(value["operation_id"]),
            command_hash=str(value["command_hash"]),
            state=str(value["state"]),
            sequence=int(value["sequence"]),
            created_at=str(value["created_at"]),
            object_ref=ObjectRef(**dict(value["object_ref"])),
            data=dict(value.get("data", {})),
        )

    def _mapping(self, record: CASStagingRecord) -> dict[str, Any]:
        return {
            "schema": "SITINA_CAS_STAGING_RECEIPT_V1",
            "operation_id": record.operation_id,
            "command_hash": record.command_hash,
            "state": record.state,
            "sequence": record.sequence,
            "created_at": record.created_at,
            "object_ref": self._reference_mapping(record.object_ref),
            "data": record.data,
        }

    def _transition(self, record: CASStagingRecord, *, expected: str, state: str, data: Mapping[str, Any] | None = None) -> CASStagingRecord:
        if record.state == state:
            return record
        if record.state != expected:
            raise CASError(f"invalid CAS staging transition: {record.state} -> {state}")
        changed = CASStagingRecord(
            record.operation_id,
            record.command_hash,
            state,
            record.sequence + 1,
            record.created_at,
            record.object_ref,
            {**record.data, **dict(data or {})},
        )
        self._write(self._mapping(changed))
        return changed

    def stage(self, operation_id: str, encrypted: EncryptedObject, *, created_at: str) -> CASStagingRecord:
        command_hash = hashlib.sha256(
            canonical_json_bytes({"operation_id": operation_id, "object_ref": encrypted.reference.reference_id})
        ).hexdigest()
        current = self.load(operation_id)
        if current is not None:
            if current.command_hash != command_hash:
                raise CASError("CAS staging operation is bound to another object")
            return current
        self.cas._publish_bytes(encrypted.object_bytes(), self._object_path(operation_id))
        self.cas._publish_bytes(encrypted.envelope.canonical_bytes(), self._envelope_path(operation_id))
        record = CASStagingRecord(operation_id, command_hash, "STAGING", 0, created_at, encrypted.reference, {})
        self._write(self._mapping(record))
        return record

    def _encrypted(self, record: CASStagingRecord) -> EncryptedObject:
        object_path = self._object_path(record.operation_id)
        envelope_path = self._envelope_path(record.operation_id)
        if object_path.is_symlink() or envelope_path.is_symlink() or not object_path.is_file() or not envelope_path.is_file():
            raise CASError("CAS staged bytes are missing or unsafe")
        raw = object_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != record.object_ref.object_id or len(raw) < 4:
            raise CASError("CAS staged object identity mismatch")
        length = int.from_bytes(raw[:4], "big")
        header = parse_canonical_json(raw[4 : 4 + length])
        envelope = ObjectEnvelope.from_bytes(envelope_path.read_bytes())
        return EncryptedObject(record.object_ref, header, raw[4 + length :], envelope)

    def validate(self, operation_id: str) -> CASStagingRecord:
        record = self.load(operation_id)
        if record is None:
            raise CASError("CAS staging receipt is missing")
        if record.state != "STAGING":
            return record
        decrypt_object(self._encrypted(record), self.cas.provider)
        return self._transition(record, expected="STAGING", state="VALIDATED")

    def publish(self, operation_id: str) -> CASStagingRecord:
        record = self.validate(operation_id)
        if record.state != "VALIDATED":
            return record
        receipt = self.cas.publish_verified(self._encrypted(record))
        return self._transition(
            record,
            expected="VALIDATED",
            state="PUBLISHED",
            data={"published_ref": receipt.object_ref.reference_id, "envelope_id": receipt.envelope_id},
        )

    def mark_journal_rooted(self, operation_id: str, *, transaction_hash: str, position: int) -> CASStagingRecord:
        record = self.load(operation_id)
        if record is None:
            raise CASError("CAS staging receipt is missing")
        if record.state == "JOURNAL_ROOTED" or record.state == "RELEASED":
            return record
        if len(transaction_hash) != 64 or position < 1:
            raise CASError("invalid durable Journal root receipt")
        self.cas.open_verified(record.object_ref)
        return self._transition(
            record,
            expected="PUBLISHED",
            state="JOURNAL_ROOTED",
            data={"rooted_transaction_hash": transaction_hash, "rooted_position": position},
        )

    def release(self, operation_id: str) -> CASStagingRecord:
        record = self.load(operation_id)
        if record is None:
            raise CASError("CAS staging receipt is missing")
        if record.state == "RELEASED":
            return record
        if record.state != "JOURNAL_ROOTED":
            raise CASError("CAS staging may only be released after a durable Journal root")
        for path in (self._object_path(operation_id), self._envelope_path(operation_id)):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        sync_directory(self.cas.root / "staging")
        return self._transition(record, expected="JOURNAL_ROOTED", state="RELEASED")

    def reconcile(
        self,
        *,
        is_journal_rooted: Callable[[str], Mapping[str, Any] | None],
        journal_references: Iterable[str],
        semantic_roots: Iterable[str],
        now: str,
        staging_grace_seconds: int = 86_400,
        repair: bool = False,
    ) -> dict[str, Any]:
        current = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
        published_not_released: list[str] = []
        expired_validated: list[str] = []
        unverified_staging: list[str] = []
        recovered: list[str] = []
        for path in sorted(self.root.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            record = self.load(str(value["operation_id"]))
            if record is None or record.state == "RELEASED":
                continue
            age = (current - dt.datetime.fromisoformat(record.created_at.replace("Z", "+00:00"))).total_seconds()
            if record.state == "STAGING":
                unverified_staging.append(record.operation_id)
            if record.state == "VALIDATED" and age >= staging_grace_seconds:
                expired_validated.append(record.operation_id)
            if record.state == "PUBLISHED":
                published_not_released.append(record.operation_id)
                root = is_journal_rooted(record.object_ref.reference_id)
                if repair and root is not None:
                    self.mark_journal_rooted(
                        record.operation_id,
                        transaction_hash=str(root["transaction_hash"]),
                        position=int(root["position"]),
                    )
                    self.release(record.operation_id)
                    recovered.append(record.operation_id)
            elif record.state == "JOURNAL_ROOTED" and repair:
                self.release(record.operation_id)
                recovered.append(record.operation_id)

        history = set(journal_references)
        roots = set(semantic_roots)
        objects = {"cas:" + path.stem for path in (self.cas.root / "objects").rglob("*.obj") if not path.is_symlink()}
        missing_index: list[str] = []
        for reference_id in sorted(history):
            try:
                reference = self.cas.resolve_reference(reference_id)
            except CASError:
                continue
            header_path = self.cas._object_path(reference.object_id)
            raw = header_path.read_bytes()
            length = int.from_bytes(raw[:4], "big")
            header = parse_canonical_json(raw[4 : 4 + length])
            profile = self.cas._compression_profile_from_header(header)
            key = self.cas._commitment_key(
                tenant_id=reference.tenant_id,
                purpose_class=str(header["purpose"]),
                plaintext_commitment=reference.plaintext_commitment,
                compression_profile=profile,
                crypto_profile=reference.profile,
            )
            if not self.cas._commitment_path(key).is_file():
                missing_index.append(reference_id)
        index_report = self.cas.reconcile_commitment_index() if repair and missing_index else None
        tracked_stage_files = {
            self._object_path(str(json.loads(path.read_text(encoding="utf-8"))["operation_id"])).name
            for path in self.root.glob("*.json")
        } | {
            self._envelope_path(str(json.loads(path.read_text(encoding="utf-8"))["operation_id"])).name
            for path in self.root.glob("*.json")
        }
        untracked_stage_files = sorted(
            path.name
            for path in (self.cas.root / "staging").glob("*.stage")
            if path.name not in tracked_stage_files
        )
        return {
            "schema": "SITINA_CAS_LIFECYCLE_RECONCILE_REPORT_V1",
            "repair": repair,
            "published_staging_not_released": published_not_released,
            "expired_validated_staging": expired_validated,
            "unverified_staging_never_auto_cleaned": unverified_staging,
            "untracked_staging_never_auto_cleaned": untracked_stage_files,
            "recovered_operations": recovered,
            "journal_referenced_missing_commitment_index": missing_index,
            "unrooted_objects": sorted(objects - roots),
            "never_journal_referenced_objects": sorted(objects - history),
            "historical_references_are_not_implicit_roots": True,
            "index_reconcile_report": index_report,
        }


__all__ = ["CASStagingCoordinator", "CASStagingRecord", "STAGING_STATES"]
