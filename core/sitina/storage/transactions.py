from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from sitina.journal.model import canonical_json_bytes


class StorageTransactionError(RuntimeError):
    pass


class OperationConflict(StorageTransactionError):
    pass


class SimulatedOperationCrash(StorageTransactionError):
    pass


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    operation_kind: str
    command_hash: str
    state: str
    sequence: int
    data: dict[str, Any]

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_DURABLE_OPERATION_RECEIPT_V1",
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind,
            "command_hash": self.command_hash,
            "state": self.state,
            "sequence": self.sequence,
            "data": self.data,
        }


class DurableOperationStore:
    """Small durable receipts for resumable, cross-store commands.

    Receipts coordinate work but never become business authority. Journal
    events remain the only authority for a completed business transition.
    """

    def __init__(self, home: str | Path):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.root = self.home / "runtime" / "operation-receipts"
        self.root.mkdir(parents=True, exist_ok=True)
        self._mutex = threading.RLock()

    @staticmethod
    def _name(operation_id: str) -> str:
        if not isinstance(operation_id, str) or not operation_id:
            raise StorageTransactionError("operation_id is required")
        return hashlib.sha256(operation_id.encode("utf-8")).hexdigest() + ".json"

    def _path(self, operation_id: str) -> Path:
        return self.root / self._name(operation_id)

    def _write(self, record: OperationRecord) -> None:
        path = self._path(record.operation_id)
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        payload = canonical_json_bytes(record.mapping()) + b"\n"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            view = memoryview(payload)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short durable receipt write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def load(self, operation_id: str) -> OperationRecord | None:
        path = self._path(operation_id)
        if not path.is_file() or path.is_symlink():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "SITINA_DURABLE_OPERATION_RECEIPT_V1":
            raise StorageTransactionError("unsupported durable operation receipt")
        return OperationRecord(
            str(value["operation_id"]),
            str(value["operation_kind"]),
            str(value["command_hash"]),
            str(value["state"]),
            int(value["sequence"]),
            dict(value["data"]),
        )

    def start(self, operation_id: str, *, operation_kind: str, command_hash: str) -> OperationRecord:
        if not isinstance(command_hash, str) or len(command_hash) != 64:
            raise StorageTransactionError("command_hash must be SHA-256")
        with self._mutex:
            current = self.load(operation_id)
            if current is not None:
                if current.command_hash != command_hash or current.operation_kind != operation_kind:
                    raise OperationConflict("operation identity is bound to another command")
                return current
            record = OperationRecord(operation_id, operation_kind, command_hash, "INIT", 0, {})
            self._write(record)
            return record

    def transition(
        self,
        operation_id: str,
        *,
        command_hash: str,
        expected: tuple[str, ...],
        state: str,
        data: Mapping[str, Any] | None = None,
    ) -> OperationRecord:
        with self._mutex:
            current = self.load(operation_id)
            if current is None or current.command_hash != command_hash:
                raise OperationConflict("durable operation receipt is absent or conflicts")
            if current.state == state:
                return current
            if current.state not in expected:
                raise StorageTransactionError(f"invalid operation transition: {current.state} -> {state}")
            record = OperationRecord(
                current.operation_id,
                current.operation_kind,
                current.command_hash,
                state,
                current.sequence + 1,
                {**current.data, **dict(data or {})},
            )
            self._write(record)
            return record


FaultInjector = Callable[[str], None]


class CASJournalTransaction:
    """CAS publish -> Journal commit -> staging release -> Projection update."""

    def __init__(self, store: DurableOperationStore, *, fault_injector: FaultInjector | None = None):
        self.store = store
        self.fault_injector = fault_injector

    def _fault(self, boundary: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(boundary)

    def commit(
        self,
        *,
        operation_id: str,
        command_hash: str,
        publish_cas: Callable[[], Mapping[str, Any]],
        verify_cas: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        append_journal: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        release_staging: Callable[[], None],
        update_projection: Callable[[Mapping[str, Any]], None],
    ) -> OperationRecord:
        record = self.store.start(operation_id, operation_kind="CAS_JOURNAL_COMMIT", command_hash=command_hash)
        if record.state == "INIT":
            cas_receipt = dict(publish_cas())
            record = self.store.transition(
                operation_id,
                command_hash=command_hash,
                expected=("INIT",),
                state="CAS_PUBLISHED",
                data={"cas_receipt": cas_receipt},
            )
            self._fault("after_cas_publish")
        if record.state == "CAS_PUBLISHED":
            proof = dict(verify_cas(dict(record.data["cas_receipt"])))
            journal_receipt = dict(append_journal(proof))
            record = self.store.transition(
                operation_id,
                command_hash=command_hash,
                expected=("CAS_PUBLISHED",),
                state="JOURNAL_COMMITTED",
                data={"journal_receipt": journal_receipt},
            )
            self._fault("after_journal_commit")
        if record.state == "JOURNAL_COMMITTED":
            release_staging()
            record = self.store.transition(
                operation_id,
                command_hash=command_hash,
                expected=("JOURNAL_COMMITTED",),
                state="STAGING_RELEASED",
            )
            self._fault("after_staging_release")
        if record.state == "STAGING_RELEASED":
            update_projection(dict(record.data["journal_receipt"]))
            record = self.store.transition(
                operation_id,
                command_hash=command_hash,
                expected=("STAGING_RELEASED",),
                state="COMPLETED",
            )
            self._fault("after_projection_update")
        return record
