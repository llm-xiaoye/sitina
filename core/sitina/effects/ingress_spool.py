from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sitina.journal.model import canonical_json_bytes, domain_hash, parse_canonical_json

from .ingress import AdmissionClass, DurableJournalIntake, IngressReceipt, ReceiptKind


@dataclass(frozen=True)
class IngressCapacity:
    ordinary: int
    observation: int
    receipt: int
    closing: int

    def limit(self, admission_class: AdmissionClass) -> int:
        return {
            AdmissionClass.ORDINARY: self.ordinary,
            AdmissionClass.OBSERVATION: self.observation,
            AdmissionClass.RECEIPT: self.receipt,
            AdmissionClass.CLOSING: self.closing,
        }[admission_class]


@dataclass(frozen=True)
class IngressAdmissionMapping:
    custody_receipt_id: str
    journal_receipt: IngressReceipt

    def mapping(self) -> dict[str, Any]:
        return {"custody_receipt_id": self.custody_receipt_id, "journal_receipt": self.journal_receipt.mapping()}

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "IngressAdmissionMapping":
        return cls(value["custody_receipt_id"], IngressReceipt.from_mapping(value["journal_receipt"]))


class DurableIngressSpool:
    def __init__(self, home: Path, capacity: IngressCapacity):
        self.home = home.resolve(strict=True)
        if not (self.home / ".sitina-bplus-disposable-v1").is_file():
            raise PermissionError("durable spool requires a disposable B+ home")
        self.root = self.home / "ingress-spool"
        self.candidates = self.root / "candidates"
        self.mappings = self.root / "mappings"
        for path in (self.root, self.candidates, self.mappings):
            path.mkdir(parents=True, exist_ok=True)
        self.capacity = capacity
        self._spool_key = self._load_or_create_key(self.root / ".spool.key")
        self._sync_directory(self.root)

    @staticmethod
    def _load_or_create_key(path: Path) -> bytes:
        if path.exists():
            value = path.read_bytes()
            if len(value) != 32 or path.is_symlink():
                raise RuntimeError("invalid Durable Ingress Spool key")
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

    def _usage(self, admission_class: AdmissionClass) -> int:
        count = 0
        for path in self.candidates.glob("*.json"):
            try:
                record = parse_canonical_json(path.read_bytes().rstrip(b"\n"))
            except Exception:
                continue
            count += record.get("admission_class") == admission_class.value
        return count

    def put(self, *, record: dict[str, Any]) -> IngressReceipt:
        admission_class = AdmissionClass(record["admission_class"])
        if self._usage(admission_class) >= self.capacity.limit(admission_class):
            identity = domain_hash("INGRESS_CAPACITY_FAILURE", canonical_json_bytes({"intake_id": record["intake_id"], "class": admission_class.value}))
            return IngressReceipt(f"unreceived-{identity}", None, ReceiptKind.UNRECEIVED_RETRYABLE, record["raw_evidence_hash"], retryable=True)
        path = self.candidates / f"{record['intake_id']}.json"
        try:
            plaintext = bytes.fromhex(record["raw_hex"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError("spool intake is missing raw evidence") from error
        aad = canonical_json_bytes({"schema": "DURABLE_INGRESS_SPOOL_AAD_V1", "intake_id": record["intake_id"], "raw_evidence_hash": record["raw_evidence_hash"]})
        nonce = os.urandom(12)
        protected = {
            **{key: value for key, value in record.items() if key != "raw_hex"},
            "raw_ciphertext_hex": AESGCM(self._spool_key).encrypt(nonce, plaintext, aad).hex(),
            "raw_nonce_hex": nonce.hex(),
            "raw_encryption_profile": "AES256_GCM_DURABLE_INGRESS_SPOOL_V1",
        }
        raw = canonical_json_bytes(protected) + b"\n"
        if path.exists():
            existing = parse_canonical_json(path.read_bytes().rstrip(b"\n"))
            if existing["raw_evidence_hash"] != record["raw_evidence_hash"] or existing["command_id"] != record["command_id"]:
                raise RuntimeError("same spool Intake ID has different evidence identity")
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            self._sync_directory(self.candidates)
        receipt_hash = domain_hash("DURABLE_INGRESS_CUSTODY_RECEIPT", canonical_json_bytes({"intake_id": record["intake_id"], "raw_evidence_hash": record["raw_evidence_hash"]}))
        return IngressReceipt(f"custody-receipt-{receipt_hash}", record["intake_id"], ReceiptKind.DURABLY_RECEIVED, record["raw_evidence_hash"])

    def _custody_receipt(self, record: dict[str, Any]) -> IngressReceipt:
        receipt_hash = domain_hash("DURABLE_INGRESS_CUSTODY_RECEIPT", canonical_json_bytes({"intake_id": record["intake_id"], "raw_evidence_hash": record["raw_evidence_hash"]}))
        return IngressReceipt(f"custody-receipt-{receipt_hash}", record["intake_id"], ReceiptKind.DURABLY_RECEIVED, record["raw_evidence_hash"])

    def drain(self, journal: DurableJournalIntake) -> list[IngressAdmissionMapping]:
        for path in sorted(self.candidates.glob("*.json")):
            record = parse_canonical_json(path.read_bytes().rstrip(b"\n"))
            custody = self._custody_receipt(record)
            aad = canonical_json_bytes({"schema": "DURABLE_INGRESS_SPOOL_AAD_V1", "intake_id": record["intake_id"], "raw_evidence_hash": record["raw_evidence_hash"]})
            try:
                plaintext = AESGCM(self._spool_key).decrypt(bytes.fromhex(record["raw_nonce_hex"]), bytes.fromhex(record["raw_ciphertext_hex"]), aad)
            except Exception as error:
                raise RuntimeError("Durable Ingress Spool evidence authentication failed") from error
            admitted = journal.admit_record({**record, "raw_hex": plaintext.hex()})
            mapping = IngressAdmissionMapping(custody.receipt_id, admitted)
            mapping_path = self.mappings / f"{record['intake_id']}.json"
            raw = canonical_json_bytes(mapping.mapping()) + b"\n"
            if mapping_path.exists():
                if mapping_path.read_bytes() != raw:
                    raise RuntimeError("custody-to-admission mapping collision")
            else:
                fd = os.open(mapping_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                self._sync_directory(self.mappings)
            path.unlink()
            self._sync_directory(self.candidates)
        output = []
        for path in sorted(self.mappings.glob("*.json")):
            output.append(IngressAdmissionMapping.from_mapping(parse_canonical_json(path.read_bytes().rstrip(b"\n"))))
        return output
