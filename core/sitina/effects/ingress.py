from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sitina.journal.model import canonical_json_bytes, domain_hash


class AdmissionClass(str, Enum):
    ORDINARY = "ORDINARY"
    OBSERVATION = "OBSERVATION"
    RECEIPT = "RECEIPT"
    CLOSING = "CLOSING"


class ReceiptKind(str, Enum):
    DURABLY_RECEIVED = "DURABLY_RECEIVED"
    JOURNAL_ADMITTED = "JOURNAL_ADMITTED"
    UNRECEIVED_RETRYABLE = "UNRECEIVED_RETRYABLE"


@dataclass(frozen=True)
class IngressReceipt:
    receipt_id: str
    intake_id: str | None
    kind: ReceiptKind
    raw_evidence_hash: str | None
    terminal_disposition: str | None = None
    journal_frame_hash: str | None = None
    retryable: bool = False

    @property
    def business_admitted(self) -> bool:
        return self.kind is ReceiptKind.JOURNAL_ADMITTED and self.terminal_disposition == "ADMITTED_BUSINESS"

    def satisfies(self, predicate: str) -> bool:
        business_predicates = {
            "BUSINESS_ACCEPTANCE",
            "EFFECT_OUTCOME",
            "OBSERVATION_ADMISSION",
            "CLOSING",
            "PROJECTION_AUTHORITY",
            "EXTERNAL_RESULT_SETTLEMENT",
        }
        return predicate in business_predicates and self.business_admitted

    def mapping(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "intake_id": self.intake_id,
            "kind": self.kind.value,
            "raw_evidence_hash": self.raw_evidence_hash,
            "terminal_disposition": self.terminal_disposition,
            "journal_frame_hash": self.journal_frame_hash,
            "retryable": self.retryable,
        }

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "IngressReceipt":
        fields = dict(value)
        fields["kind"] = ReceiptKind(fields["kind"])
        return cls(**fields)


class SpoolLike(Protocol):
    def put(self, **values: Any) -> IngressReceipt: ...


class DurableJournalIntake:
    """Isolated durable stand-in for the canonical Journal admission barrier."""

    def __init__(self, home: Path):
        self.home = home.resolve(strict=True)
        if not (self.home / ".sitina-bplus-disposable-v1").is_file():
            raise PermissionError("durable intake requires a disposable B+ home")
        self.root = self.home / "journal" / "ingress"
        self.evidence_root = self.root / "encrypted-evidence"
        self.root.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self._evidence_key = self._load_or_create_key(self.root / ".ingress-evidence.key")
        self._sync_directory(self.root.parent)
        self._sync_directory(self.root)

    @staticmethod
    def _load_or_create_key(path: Path) -> bytes:
        if path.exists():
            value = path.read_bytes()
            if len(value) != 32 or path.is_symlink():
                raise RuntimeError("invalid durable ingress evidence key")
            return value
        value = AESGCM.generate_key(bit_length=256)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        return value

    @staticmethod
    def _sync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def admit_record(self, record: dict[str, Any]) -> IngressReceipt:
        command_id = record["command_id"]
        path = self.root / f"{command_id}.json"
        if path.exists():
            stored = json.loads(path.read_text(encoding="utf-8"))
            if stored.get("intake_id") != record.get("intake_id") or stored.get("raw_evidence_hash") != record.get("raw_evidence_hash"):
                raise RuntimeError("same Intake Command ID has different evidence identity")
            return IngressReceipt(
                f"journal-receipt-{stored['frame_hash']}",
                stored["intake_id"],
                ReceiptKind.JOURNAL_ADMITTED,
                stored["raw_evidence_hash"],
                stored["terminal_disposition"],
                stored["frame_hash"],
            )
        classification = str(record["classification"])
        disposition = "REJECTED_QUARANTINED" if classification == "INVALID" else "ADMITTED_BUSINESS"
        try:
            evidence = bytes.fromhex(record["raw_hex"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("Journal intake requires raw evidence from direct ingress or spool decrypt") from error
        evidence_nonce = os.urandom(12)
        evidence_aad = canonical_json_bytes({"schema": "INGRESS_EVIDENCE_AAD_V1", "intake_id": record["intake_id"], "raw_evidence_hash": record["raw_evidence_hash"]})
        evidence_ciphertext = evidence_nonce + AESGCM(self._evidence_key).encrypt(evidence_nonce, evidence, evidence_aad)
        evidence_id = hashlib.sha256(evidence_aad + evidence_ciphertext).hexdigest()
        evidence_path = self.evidence_root / f"{evidence_id}.evidence"
        if not evidence_path.exists():
            fd = os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(evidence_ciphertext)
                handle.flush()
                os.fsync(handle.fileno())
            self._sync_directory(self.evidence_root)
        frame_core = {
            "schema": "INGRESS_ADMISSION_FRAME_V1",
            "command_id": command_id,
            "intake_id": record["intake_id"],
            "source_identity": record["source_identity"],
            "raw_evidence_hash": record["raw_evidence_hash"],
            "classification": classification,
            "received_at": record["received_at"],
            "nonce": record["nonce"],
            "target_hint": record["target_hint"],
            "encrypted_evidence_id": evidence_id,
            "encrypted_evidence_profile": "AES256_GCM_INGRESS_EVIDENCE_V1",
            "terminal_disposition": disposition,
        }
        frame_hash = domain_hash("INGRESS_ADMISSION_FRAME", canonical_json_bytes(frame_core))
        stored = {**frame_core, "frame_hash": frame_hash}
        raw = canonical_json_bytes(stored) + b"\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        self._sync_directory(self.root)
        receipt_id = f"journal-receipt-{frame_hash}"
        return IngressReceipt(receipt_id, record["intake_id"], ReceiptKind.JOURNAL_ADMITTED, record["raw_evidence_hash"], disposition, frame_hash)


class IngressGateway:
    def __init__(self, *, journal: DurableJournalIntake | None, spool: SpoolLike | None):
        self.journal = journal
        self.spool = spool
        self.outbound_dispatch_stopped = False

    @staticmethod
    def _record(
        *,
        source_identity: str,
        raw: bytes,
        classification: str,
        nonce: str,
        target_hint: str,
        admission_class: AdmissionClass,
        received_at: int,
    ) -> dict[str, Any]:
        raw_hash = hashlib.sha256(raw).hexdigest()
        core = {
            "source_identity": source_identity,
            "raw_evidence_hash": raw_hash,
            "classification": classification,
            "received_at": received_at,
            "nonce": nonce,
            "target_hint": target_hint,
            "admission_class": admission_class.value,
        }
        intake_id = domain_hash("DURABLE_INGRESS_INTAKE", canonical_json_bytes(core))
        return {
            **core,
            "schema": "DURABLE_INGRESS_RECORD_V1",
            "intake_id": intake_id,
            "command_id": domain_hash("DURABLE_INGRESS_COMMAND", canonical_json_bytes({"intake_id": intake_id, "raw_evidence_hash": raw_hash})),
            "raw_hex": raw.hex(),
        }

    def receive(self, **values: Any) -> IngressReceipt:
        record = self._record(**values)
        if self.journal is not None:
            return self.journal.admit_record(record)
        if self.spool is not None:
            receipt = self.spool.put(record=record)
            if receipt.kind is ReceiptKind.UNRECEIVED_RETRYABLE:
                self.outbound_dispatch_stopped = True
            return receipt
        self.outbound_dispatch_stopped = True
        failure_hash = domain_hash("INGRESS_UNRECEIVED", canonical_json_bytes({key: value for key, value in record.items() if key != "raw_hex"}))
        return IngressReceipt(f"unreceived-{failure_hash}", None, ReceiptKind.UNRECEIVED_RETRYABLE, record["raw_evidence_hash"], retryable=True)
