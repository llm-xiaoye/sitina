from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import threading
import time
import uuid
from types import SimpleNamespace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from sitina.install_identity import LEGACY_PRODUCTION_HOME, canonical_journal_native_home
from sitina.cas.gc import GCController, ReferenceLease
from sitina.cas.model import CASError, ExistingDurableObjectRootProof, ObjectRef, PublishedObjectReceipt
from sitina.commands.model import CommandEnvelope, CommandResult, CommandStatus
from sitina.security.key_provider import JournalAuthProvider, KeyPurpose
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .codec import DecodedFrame, encode_frame
from .locks import WriterLock, WriterLockError
from .model import (
    AppendReceipt,
    EventEnvelope,
    FrontierRef,
    JournalModelError,
    JournalTransaction,
    canonical_json_bytes,
    event_replay_projection,
    event_replay_projection_bytes,
    event_replay_projection_hash,
    proof_manifest_bytes,
    proof_manifest_hash,
    acceptance_event_projection_hash,
    execution_authorization_attempt_ref,
    planned_operation_hash,
    is_code_mode_authority_reserved,
    stage_actual_projection_hash,
    stage_actual_event_projection,
    stable_stage_proof_manifest,
    stable_stage_proof_manifest_hash,
    code_mode_producer_spec,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE,
    forge_child_authorization_projection,
    CODE_MODE_EXECUTION_PARENT_SCHEMA,
    CODE_MODE_EXECUTION_PARENT_EVENT_TYPE,
    CODE_MODE_EXECUTION_PARENT_PURPOSE,
    CODE_MODE_EXECUTION_PARENT_PROJECTION_FIELDS,
    execution_parent_hash,
    execution_parent_projection,
    durable_code_mode_authorization_projection,
)
from .authority import AuthorityOperationEnvelope
from .recovery import JournalRecoveryError, recover_active_segment, scan_active_segment_read_only, scan_sealed_segment


class LocalJournalError(RuntimeError):
    pass


class CommandConflict(LocalJournalError):
    pass


class ExpectedStreamVersionConflict(LocalJournalError):
    pass


class WriterPoisoned(LocalJournalError):
    pass


class SimulatedCrash(LocalJournalError):
    pass


_CODE_MODE_ATTEMPT_ADVANCE_SCHEMA = "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
_CODE_MODE_ATTEMPT_ADVANCE_EVENT_TYPE = "execution.authorization.attempt_advanced"


FaultInjector = Callable[[str, "LocalJournal"], None]


class LocalJournal:
    def __init__(
        self,
        home: Path,
        authenticator: JournalAuthProvider,
        *,
        journal_id: str,
        epoch: int,
        namespace_kind: str,
        gc_controller: GCController | None,
        fault_injector: FaultInjector | None,
        operational_capability: object | None,
        authority_resolution: object | None,
        cas: Any | None,
        genesis_hash: str | None,
        fast_start_report: object | None,
        rollover_coordinator: object | None,
    ):
        self.home = home.resolve(strict=True)
        self._operational_capability = operational_capability
        self._authority_resolution = authority_resolution
        self._cas = cas
        self.genesis_hash = genesis_hash
        self.fast_start_report = fast_start_report
        self.rollover_coordinator = rollover_coordinator
        production_namespace = namespace_kind in {"production", "production_simulation"}
        if production_namespace:
            self._authorize_production_open(namespace_kind)
        else:
            if self.home in {LEGACY_PRODUCTION_HOME, canonical_journal_native_home()}:
                raise LocalJournalError("active Sitina installation Journal requires a Phase 6B or resolved runtime capability")
            if namespace_kind not in {"shadow", "controlled_fixture", "code_mode", "session"}:
                raise LocalJournalError("Journal namespace must be shadow, controlled_fixture, code_mode, session, or manifest-bound Production")
            marker = {
                "shadow": ".sitina-bplus-shadow-v1",
                "controlled_fixture": ".sitina-bplus-disposable-v1",
                "code_mode": ".sitina-code-mode-v1",
                "session": ".sitina-session-runtime-v1",
            }[namespace_kind]
            if not (self.home / marker).is_file():
                raise LocalJournalError("isolated Journal namespace marker is missing")
        self.journal_id = journal_id
        self.epoch = epoch
        self.namespace_kind = namespace_kind
        self.authenticator = authenticator
        self.gc_controller = gc_controller
        self.fault_injector = fault_injector
        self.root = self.home / "journal"
        self.sealed_root = self.root / "sealed"
        self.index_root = self.root / "indexes"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.sealed_root.mkdir(exist_ok=True, mode=0o700)
        self.index_root.mkdir(exist_ok=True, mode=0o700)
        self.writer_lock = WriterLock.acquire(self.root / "writer.lock", journal_id, epoch)
        self._active_fd = -1
        try:
            self.active_path = self.root / "active.seg"
            self._reconcile_rollover_layout()
            self._active_fd = os.open(
                self.active_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            self._mutex = threading.RLock()
            self.poisoned_reason: str | None = None
            self._commands: dict[str, tuple[str, AppendReceipt]] = {}
            self._transactions: dict[str, JournalTransaction] = {}
            self._authority_operation_commands: dict[str, str] = {}
            # Authority operations are verified against the current authority
            # signing key.  The ordinary append path never receives a flag or
            # capability which can turn an event into a seal.
            try:
                from sitina.security.key_provider import KeyPurpose
                self._authority_key_id = self.authenticator.provider.current_descriptor(
                    KeyPurpose.AUTHORITY_SIGNING
                ).key_id
            except Exception:
                self._authority_key_id = None
            self._external_authority_key_id: str | None = None
            self._external_authority_public_key: bytes | None = None
            self._authority_pin_path = self.index_root / "authority-pin-v1.json"
            self._load_external_authority_pin()
            self._seal_index_root = self.index_root / "code-mode-seals"
            self._seal_index_root.mkdir(exist_ok=True, mode=0o700)
            # Sidecars are only an untrusted cache.  Keep all candidates until
            # authenticated Journal transactions are available; a foreign or
            # malformed cache entry must never deny reopen.
            self._durable_seal_records: dict[str, list[dict[str, Any]]] = {}
            self._load_durable_seal_index()
            self._pending_authority_operation: AuthorityOperationEnvelope | None = None
            self._authenticated_authority_command_ids: set[str] = set()
            self._authenticated_seal_command_ids: set[str] = set()
            self._authenticated_root_command_ids: set[str] = set()
            self._authenticated_seal_transactions: dict[str, JournalTransaction] = {}
            # Durable run seals are reconstructed from authenticated V2 root
            # events and therefore survive a writer restart.  This is a
            # run-scoped index, never a process-local CanonicalStream flag.
            self._sealed_code_mode_streams: set[str] = set()
            self._stream_heads: dict[str, int] = {}
            self._events: list[EventEnvelope] = []
            self._object_roots: dict[str, tuple[ObjectRef, DecodedFrame]] = {}
            self._position_hash: dict[int, str] = {}
            self._head_position = 0
            self._active_first_position = 0
            self.history_complete_in_memory = fast_start_report is None
            startup_started = time.monotonic()
            if fast_start_report is None:
                self._recover_and_rebuild()
            else:
                self._recover_from_fast_start(fast_start_report)
                self._restore_authenticated_sealed_prefix()
            self._restore_durable_seals()
            self.startup_scan_ms = max(0, int((time.monotonic() - startup_started) * 1000))
            if self.rollover_coordinator is not None:
                self.rollover_coordinator.consider(self, startup_scan_ms=self.startup_scan_ms)
        except BaseException:
            if self._active_fd >= 0:
                try:
                    os.close(self._active_fd)
                except OSError:
                    pass
                self._active_fd = -1
            self.writer_lock.close()
            raise

    def _authorize_production_open(self, namespace_kind: str) -> None:
        if not isinstance(self.genesis_hash, str) or len(self.genesis_hash) != 64:
            raise LocalJournalError("Production Journal requires an exact Genesis hash")
        genesis_path = self.home / "state/bplus-production-genesis/genesis.json"
        try:
            value = json.loads(genesis_path.read_text(encoding="utf-8"))
        except Exception as error:
            raise LocalJournalError("verified Production Genesis is unavailable") from error
        if value.get("genesis_hash") != self.genesis_hash:
            raise LocalJournalError("Production Journal Genesis bytes do not match the requested identity")
        if namespace_kind == "production_simulation":
            if self.home == LEGACY_PRODUCTION_HOME or not (self.home / ".sitina-bplus-disposable-v1").is_file():
                raise LocalJournalError("Production simulation requires a disposable non-Production root")
        elif self.home != LEGACY_PRODUCTION_HOME:
            raise LocalJournalError("Production namespace requires the manifest-bound Production installation")
        if self._operational_capability is not None:
            try:
                self._operational_capability.assert_operation(
                    "OPEN_PRODUCTION_JOURNAL_CONTROL_PLANE", self.home, now=int(time.time())
                )
            except Exception as error:
                raise LocalJournalError("Production Journal control capability is invalid") from error
            expected_environment = "PRODUCTION" if namespace_kind == "production" else "CONTROLLED_PRODUCTION_SIMULATION"
            if getattr(self._operational_capability, "environment_kind", None) != expected_environment:
                raise LocalJournalError("Production Journal capability environment differs")
            return
        if self._authority_resolution is not None:
            try:
                self._authority_resolution.assert_fresh(now=int(time.time()))
            except Exception as error:
                raise LocalJournalError("Production Journal runtime resolution is stale") from error
            if not self._authority_resolution.authorizes_journal or self._authority_resolution.writer_count != 1:
                raise LocalJournalError("Production Journal runtime resolution does not authorize one Journal writer")
            return
        raise LocalJournalError("Production Journal requires a Maintenance capability or committed authority resolution")

    @classmethod
    def open(
        cls,
        home: str | os.PathLike[str],
        authenticator: JournalAuthProvider,
        *,
        journal_id: str = "journal-shadow-1",
        epoch: int = 1,
        namespace_kind: str = "controlled_fixture",
        gc_controller: GCController | None = None,
        fault_injector: FaultInjector | None = None,
        operational_capability: object | None = None,
        authority_resolution: object | None = None,
        cas: Any | None = None,
        genesis_hash: str | None = None,
        fast_start_report: object | None = None,
        rollover_coordinator: object | None = None,
    ) -> "LocalJournal":
        return cls(
            Path(home), authenticator, journal_id=journal_id, epoch=epoch, namespace_kind=namespace_kind,
            gc_controller=gc_controller, fault_injector=fault_injector,
            operational_capability=operational_capability, authority_resolution=authority_resolution,
            cas=cas,
            genesis_hash=genesis_hash,
            fast_start_report=fast_start_report,
            rollover_coordinator=rollover_coordinator,
        )

    @classmethod
    def read_authenticated_frames(
        cls,
        home: str | os.PathLike[str],
        authenticator: JournalAuthProvider,
        *,
        journal_id: str,
        epoch: int,
        namespace_kind: str = "code_mode",
        backup_manifest: Any = None,
        expected_backup_manifest_hash: str | None = None,
    ) -> tuple[DecodedFrame, ...]:
        """Reopen an isolated Journal without acquiring a writer lock.

        The external authority host uses this read-only verifier instead of
        maintaining a second frame/authentication implementation.  Segment
        decoding, global positions, per-stream versions, event hashes, and
        Journal authentication therefore follow the same rules as normal
        ``LocalJournal`` recovery.
        """
        root = Path(home).expanduser().resolve(strict=True)
        if namespace_kind == "session":
            from sitina.loop.storage import _verify_loop_archive_members

            _source, _bindings, original_journal_id = _verify_loop_archive_members(
                root, backup_manifest, expected_backup_manifest_hash
            )
            if journal_id != original_journal_id or epoch != backup_manifest.frontier.epoch:
                raise LocalJournalError("Loop archive Journal identity differs from its backup")
        elif namespace_kind != "code_mode" or not (root / ".sitina-code-mode-v1").is_file():
            raise LocalJournalError("authenticated read requires an isolated Code Mode Journal")
        journal_root = root / "journal"
        sealed_root = journal_root / "sealed"
        active_path = journal_root / "active.seg"
        frames: list[DecodedFrame] = []
        for path in sorted(sealed_root.glob("*.seg")):
            if path.is_symlink():
                raise JournalRecoveryError("sealed Journal segment may not be a symlink")
            frames.extend(scan_sealed_segment(path).frames)
        if active_path.exists() and active_path.is_symlink():
            raise JournalRecoveryError("active Journal segment may not be a symlink")
        if active_path.exists():
            frames.extend(scan_active_segment_read_only(active_path).frames)
        expected_position = 1
        stream_versions: dict[str, int] = {}
        for frame in frames:
            transaction = frame.transaction
            if transaction.first_position != expected_position:
                raise JournalRecoveryError("authenticated Journal position gap")
            previous = stream_versions.get(transaction.stream_id)
            if previous is not None and transaction.first_stream_version != previous + 1:
                raise JournalRecoveryError("authenticated Journal stream version gap")
            if any(
                event.stream_id != transaction.stream_id
                or event.computed_event_hash != event.event_hash
                or not event.verify(journal_id=journal_id, epoch=epoch, authenticator=authenticator)
                for event in transaction.events
            ):
                raise JournalRecoveryError("authenticated Journal event verification failed")
            expected_position = transaction.last_position + 1
            stream_versions[transaction.stream_id] = transaction.last_stream_version
        if namespace_kind == "session":
            frontier = backup_manifest.frontier
            if (
                not frames
                or frames[-1].transaction.last_position != frontier.position
                or frames[-1].transaction_hash != frontier.commitment
            ):
                raise JournalRecoveryError("Loop archive Journal differs from its frozen frontier")
        return tuple(frames)

    def _fault(self, boundary: str) -> None:
        if self.fault_injector:
            self.fault_injector(boundary, self)

    def _sync_directory(self, path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _reconcile_rollover_layout(self) -> None:
        if not self.active_path.exists():
            return
        active = self.active_path.stat()
        aliases = [path for path in self.sealed_root.glob("*.seg") if path.stat().st_dev == active.st_dev and path.stat().st_ino == active.st_ino]
        if aliases:
            self.active_path.unlink()
            self._sync_directory(self.root)

    def _recover_and_rebuild(self) -> None:
        frames: list[DecodedFrame] = []
        for path in sorted(self.sealed_root.glob("*.seg")):
            sealed = scan_sealed_segment(path).frames
            frames.extend(sealed)
            if sealed:
                self._active_first_position = sealed[-1].transaction.last_position
        os.close(self._active_fd)
        # Do not retain a descriptor number after close: recovery may briefly
        # reuse that number.  If recovery fails, constructor cleanup must not
        # risk closing an unrelated descriptor in the process.
        self._active_fd = -1
        recovery = recover_active_segment(self.active_path)
        self._active_fd = os.open(self.active_path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        frames.extend(recovery.scan.frames)
        expected_position = 1
        for frame in frames:
            transaction = frame.transaction
            if transaction.first_position != expected_position:
                raise JournalRecoveryError("committed local Journal prefix has a position gap")
            for event in transaction.events:
                if not event.verify(journal_id=self.journal_id, epoch=self.epoch, authenticator=self.authenticator):
                    raise JournalRecoveryError("event hash or historical Journal auth verification failed")
            receipt = self._receipt(frame)
            existing = self._commands.get(transaction.command_id)
            if existing and existing[0] != transaction.command_request_hash:
                raise JournalRecoveryError("same Command ID has different request hashes in canonical frames")
            self._commands[transaction.command_id] = (transaction.command_request_hash, receipt)
            self._transactions[transaction.command_id] = transaction
            for event in transaction.events:
                envelope = event.payload.get("authority_operation") if isinstance(event.payload, dict) else None
                if isinstance(envelope, dict):
                    operation_id = str(envelope.get("operation_id") or "")
                    previous = self._authority_operation_commands.get(operation_id)
                    if previous is not None and previous != transaction.command_id:
                        raise JournalRecoveryError("authority logical operation has multiple physical mappings")
                    self._authority_operation_commands[operation_id] = transaction.command_id
                    self._authenticated_authority_command_ids.add(transaction.command_id)
            if transaction.authenticated_seal_stream_id is not None:
                if transaction.authenticated_seal_stream_id != transaction.stream_id:
                    raise JournalRecoveryError("authenticated seal transaction stream binding is invalid")
                self._authenticated_seal_transactions[transaction.command_id] = transaction
            # Authority command identity and durable stream sealing are
            # separate facts.  Acceptance/terminal transactions are
            # authenticated authority commands but do not seal the stream;
            # only the final root transaction carries the seal marker.
            # An authority-shaped event is not a seal.  Only the dedicated
            # authenticated root transaction below may enter the seal index.
            self._stream_heads[transaction.stream_id] = transaction.last_stream_version
            self._events.extend(transaction.events)
            for position in range(transaction.first_position, transaction.last_position + 1):
                self._position_hash[position] = frame.transaction_hash
            for event in transaction.events:
                for reference_id in event.object_refs:
                    self._object_roots.setdefault(reference_id, (self._placeholder_ref(reference_id), frame))
            expected_position = transaction.last_position + 1
            self._head_position = transaction.last_position
        os.lseek(self._active_fd, 0, os.SEEK_END)

    @staticmethod
    def _is_authenticated_code_mode_root(event: Any) -> bool:
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict) or payload.get("schema") != "CODE_MODE_FINAL_ROOT_V2":
            return False
        authority = payload.get("authority_operation")
        required = (
            "run_id", "seal_command_id", "final_receipt_ref", "final_receipt_hash",
            "terminal_event_id", "terminal_event_hash", "gate_status",
        )
        return (
            isinstance(authority, dict)
            and authority.get("operation") == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1"
            and authority.get("operation_id") == payload.get("logical_operation_id")
            and authority.get("run_id") == payload.get("run_id")
            and authority.get("stream_id") == event.stream_id
            and authority.get("generation") == payload.get("generation")
            and isinstance(payload.get("logical_operation_hash"), str)
            and re.fullmatch(r"[0-9a-f]{64}", payload.get("logical_operation_hash")) is not None
            and
            payload.get("seal_command_id") == payload.get("causation_command_id")
            and payload.get("authenticated_seal") is True
            and payload.get("gate_status") == "CODE_MODE_READY"
            and payload.get("finalization_transaction") is True
            and all(isinstance(payload.get(field), str) and payload.get(field) for field in required)
            and payload.get("final_receipt_ref") in set(getattr(event, "object_refs", ()))
            and payload.get("final_receipt_hash")
            and payload.get("terminal_event_id")
            and payload.get("terminal_event_hash")
        )

    def _recover_from_fast_start(self, report: object) -> None:
        state = getattr(report, "authority_state", None)
        if (
            state is None
            or not getattr(report, "fast_start_checkpoint_used", False)
            or state.journal_id != self.journal_id
            or int(state.epoch) != self.epoch
        ):
            raise JournalRecoveryError("fast-start report does not authorize this Journal identity")
        os.close(self._active_fd)
        self._active_fd = -1
        recovery = recover_active_segment(self.active_path)
        self._active_fd = os.open(
            self.active_path,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        active_frames = tuple(recovery.scan.frames)
        checkpoint_position = int(getattr(report, "verified_through_position", 0))
        self._active_first_position = checkpoint_position
        expected = checkpoint_position + 1
        for frame in active_frames:
            if frame.transaction.first_position != expected:
                raise JournalRecoveryError("fast-start active tail has a position gap")
            for event in frame.transaction.events:
                if not event.verify(journal_id=self.journal_id, epoch=self.epoch, authenticator=self.authenticator):
                    raise JournalRecoveryError("fast-start active-tail authentication failed")
            expected = frame.transaction.last_position + 1
        if expected - 1 != int(state.head_position):
            raise JournalRecoveryError("fast-start active tail differs from recovered writer head")

        self._stream_heads.update({str(key): int(value) for key, value in state.stream_heads})
        for value in getattr(report, "command_receipts", ()):
            checkpoint_projection = tuple(dict(item) for item in value.get("event_projection", ()))
            checkpoint_projection_hash = str(value.get("event_projection_hash") or "")
            if checkpoint_projection_hash and checkpoint_projection_hash != event_replay_projection_hash(checkpoint_projection):
                raise JournalRecoveryError("fast-start command event projection commitment is invalid")
            checkpoint_proofs = tuple(dict(item) for item in value.get("proof_manifest", ()))
            checkpoint_proof_hash = str(value.get("proof_manifest_hash") or "")
            if checkpoint_proof_hash and checkpoint_proof_hash != proof_manifest_hash(checkpoint_proofs):
                raise JournalRecoveryError("fast-start command proof commitment is invalid")
            receipt = AppendReceipt(
                self.journal_id,
                self.epoch,
                str(value["transaction_id"]),
                str(value["command_id"]),
                str(value["request_hash"]),
                str(value["stream_id"]),
                int(value["first_position"]),
                int(value["last_position"]),
                int(value["first_stream_version"]),
                int(value["last_stream_version"]),
                str(value["transaction_hash"]),
                str(value["object_reference_manifest_hash"]),
            )
            self._commands[receipt.command_id] = (receipt.command_request_hash, receipt)
            # The checkpoint carries this compact proof projection for
            # sealed-prefix commands whose frame is not loaded in Fast Start.
            # Without it exact replay remains fail-closed rather than
            # silently accepting a proof that was never part of the original
            # transaction.
            self._transactions[receipt.command_id] = SimpleNamespace(
                proof_manifest=checkpoint_proofs,
                event_projection=tuple(dict(item) for item in value.get("event_projection", ())),
                event_projection_hash=str(value.get("event_projection_hash") or ""),
            )
            historical_frame = SimpleNamespace(
                transaction_hash=receipt.transaction_hash,
                transaction=SimpleNamespace(
                    last_position=receipt.last_position,
                    object_reference_manifest_hash=receipt.object_reference_manifest_hash,
                ),
            )
            for reference_id in value.get("object_refs", ()):
                self._object_roots.setdefault(
                    str(reference_id),
                    (self._placeholder_ref(str(reference_id)), historical_frame),
                )
        for frame in active_frames:
            receipt = self._receipt(frame)
            self._commands[receipt.command_id] = (receipt.command_request_hash, receipt)
            self._transactions[receipt.command_id] = frame.transaction
            if frame.transaction.authenticated_seal_stream_id is not None:
                if frame.transaction.authenticated_seal_stream_id != frame.transaction.stream_id:
                    raise JournalRecoveryError("fast-start active-tail seal stream binding is invalid")
                self._authenticated_seal_transactions[receipt.command_id] = frame.transaction
            for position in range(receipt.first_position, receipt.last_position + 1):
                self._position_hash[position] = receipt.transaction_hash
            for event in frame.transaction.events:
                for reference_id in event.object_refs:
                    self._object_roots.setdefault(reference_id, (self._placeholder_ref(reference_id), frame))
        if checkpoint_position:
            command_at_checkpoint = next(
                (value for value in getattr(report, "command_receipts", ()) if int(value["last_position"]) == checkpoint_position),
                None,
            )
            self._position_hash[checkpoint_position] = (
                str(command_at_checkpoint["transaction_hash"]) if command_at_checkpoint else "0" * 64
            )
        indexed = list(getattr(report, "authority_control_events", ())) + list(getattr(report, "active_tail_events", ()))
        by_id = {event.event_id: event for event in indexed}
        self._events.extend(sorted(by_id.values(), key=lambda event: event.position))
        receipt_by_command = {
            receipt.command_id: receipt
            for _request_hash, receipt in self._commands.values()
        }
        for event in self._events:
            payload = event.payload if isinstance(event.payload, dict) else {}
            envelope = payload.get("authority_operation")
            command_id = str(payload.get("causation_command_id") or "")
            if not isinstance(envelope, dict) or command_id not in receipt_by_command:
                continue
            operation_id = str(envelope.get("operation_id") or "")
            previous = self._authority_operation_commands.get(operation_id)
            if previous is not None and previous != command_id:
                raise JournalRecoveryError("authority logical operation has multiple physical mappings")
            self._authority_operation_commands[operation_id] = command_id
            self._authenticated_authority_command_ids.add(command_id)
            # Root/seal status is restored only from the durable seal index;
            # a root-shaped ordinary event is never sufficient.
        self._head_position = int(state.head_position)
        os.lseek(self._active_fd, 0, os.SEEK_END)

    def _restore_authenticated_sealed_prefix(self) -> None:
        """Materialize authenticated sealed-prefix facts for Fast Start.

        Fast Start intentionally avoids loading every historical event.  A
        final-root transaction is different: its authenticated transaction
        metadata is the durable seal authority and must remain available to
        the verifier after rollover.  The auxiliary JSON seal index is never
        sufficient on its own; this method accepts only authenticated Journal
        frames whose transaction carries the sealed-stream marker and whose
        events verify under this Journal's authenticator.
        """
        known = {event.event_id for event in self._events}
        report = self.fast_start_report
        checkpoint_seals = {
            str(value.get("command_id")): value
            for value in getattr(report, "command_receipts", ())
            if value.get("authenticated_seal_stream_id") == value.get("stream_id")
        }
        for path in sorted(self.sealed_root.glob("*.seg")):
            for frame in scan_sealed_segment(path).frames:
                transaction = frame.transaction
                if transaction.authenticated_seal_stream_id is None:
                    continue
                checkpoint_value = checkpoint_seals.get(transaction.command_id)
                if checkpoint_value is None:
                    # Fast Start may only promote a sealed-prefix transaction
                    # already named by the authenticated checkpoint.  Merely
                    # finding a marker while scanning a segment is not a
                    # substitute for that checkpoint certificate.
                    continue
                if transaction.authenticated_seal_stream_id != transaction.stream_id:
                    raise JournalRecoveryError("sealed-prefix authority transaction stream binding is invalid")
                if any(
                    str(checkpoint_value.get(field)) != str(expected)
                    for field, expected in (
                        ("transaction_hash", frame.transaction_hash),
                        ("stream_id", transaction.stream_id),
                        ("last_stream_version", transaction.last_stream_version),
                        ("object_reference_manifest_hash", transaction.object_reference_manifest_hash),
                    )
                ):
                    raise JournalRecoveryError("sealed-prefix seal checkpoint binding is invalid")
                if not all(
                    event.verify(journal_id=self.journal_id, epoch=self.epoch, authenticator=self.authenticator)
                    for event in transaction.events
                ):
                    raise JournalRecoveryError("sealed-prefix authority transaction authentication failed")
                receipt = self._receipt(frame)
                existing = self._commands.get(transaction.command_id)
                if existing is not None and existing[1].transaction_hash != receipt.transaction_hash:
                    raise JournalRecoveryError("sealed-prefix command maps to conflicting transaction")
                self._commands.setdefault(transaction.command_id, (transaction.command_request_hash, receipt))
                self._transactions[transaction.command_id] = transaction
                self._authenticated_seal_transactions[transaction.command_id] = transaction
                for event in transaction.events:
                    if event.event_id not in known:
                        self._events.append(event)
                        known.add(event.event_id)
                self._events.sort(key=lambda event: event.position)
                for reference_id in {reference for event in transaction.events for reference in event.object_refs}:
                    self._object_roots.setdefault(reference_id, (self._placeholder_ref(reference_id), frame))

    @staticmethod
    def _placeholder_ref(reference_id: str) -> ObjectRef:
        if not reference_id.startswith("cas:"):
            raise JournalRecoveryError("unknown object reference scheme")
        object_id = reference_id.removeprefix("cas:")
        return ObjectRef(object_id, "unknown-tenant", "0" * 64, "unknown:commitment:key")

    def _receipt(self, frame: DecodedFrame) -> AppendReceipt:
        transaction = frame.transaction
        return AppendReceipt(
            self.journal_id, self.epoch, transaction.transaction_id, transaction.command_id,
            transaction.command_request_hash, transaction.stream_id, transaction.first_position,
            transaction.last_position, transaction.first_stream_version, transaction.last_stream_version,
            frame.transaction_hash, transaction.object_reference_manifest_hash,
        )

    @property
    def head_position(self) -> int:
        return self._head_position

    def attach_rollover_coordinator(self, coordinator: object) -> None:
        if self.rollover_coordinator is not None:
            raise LocalJournalError("Journal rollover coordinator is already attached")
        self.rollover_coordinator = coordinator
        coordinator.consider(self, startup_scan_ms=self.startup_scan_ms)

    def _assert_healthy(self) -> None:
        if self.poisoned_reason:
            raise WriterPoisoned(self.poisoned_reason)
        try:
            self.writer_lock.assert_healthy()
        except WriterLockError as error:
            self.poisoned_reason = str(error)
            raise WriterPoisoned(self.poisoned_reason) from error

    def _validate_proofs(self, references: tuple[str, ...], proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof]) -> dict[str, ObjectRef]:
        proof_map: dict[str, PublishedObjectReceipt | ExistingDurableObjectRootProof] = {}
        refs: dict[str, ObjectRef] = {}
        for proof in proofs:
            reference = proof.object_ref.reference_id
            if reference in proof_map:
                raise LocalJournalError("duplicate object proof")
            proof_map[reference] = proof
            refs[reference] = proof.object_ref
        if set(proof_map) != set(references):
            raise LocalJournalError("object proofs must exactly equal Canonical Event references")
        for reference, proof in proof_map.items():
            if isinstance(proof, PublishedObjectReceipt):
                proof.assert_valid(reference)
            elif isinstance(proof, ExistingDurableObjectRootProof):
                if proof.journal_id != self.journal_id or proof.rooted_position > self.head_position:
                    raise LocalJournalError("existing root proof is not valid for this verified Journal")
            else:
                raise LocalJournalError("unknown object proof type")
        return refs

    def _validate_code_mode_planned_predecessors(
        self,
        authority: AuthorityOperationEnvelope | None,
        command: CommandEnvelope,
        events: Sequence[EventEnvelope],
        proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        completion_plan: Mapping[str, Any],
        completion_plan_reference: str | None,
    ) -> None:
        """Validate physical predecessors before replay lookup or append.

        A completion-plan receipt is an authorization proof, not an
        event-owned object reference.  It must nevertheless be checked as a
        complete physical predecessor on every first submission and replay.
        This also keeps a root from being attached to an arbitrary successful
        event or a caller-selected command id.
        """
        if authority is None:
            return
        if authority.operation in {
            "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
            "LOGICAL_CONVERSATION_COMPLETION_V1",
        }:
            self._validate_code_mode_completion_plan_predecessor(
                authority, command, events, proofs,
                completion_plan=completion_plan,
                completion_plan_reference=completion_plan_reference,
            )
        if authority.operation != "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1":
            return
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("planned Code Mode root must contain one event")
        root = events[0].payload
        if root.get("schema") != "CODE_MODE_FINAL_ROOT_V2":
            raise LocalJournalError("planned Code Mode root schema is invalid")
        plan_ref = root.get("completion_plan_ref")
        plan_hash = root.get("completion_plan_hash")
        plan_proofs = [
            proof for proof in proofs
            if isinstance(proof, PublishedObjectReceipt)
            and proof.object_ref.reference_id == plan_ref
        ]
        if (
            not isinstance(plan_ref, str)
            or not re.fullmatch(r"cas:[0-9a-f]{64}", plan_ref)
            or not isinstance(plan_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", plan_hash)
            or not isinstance(completion_plan_reference, str)
            or plan_ref != completion_plan_reference
            or completion_plan.get("content_hash") != plan_hash
            or hashlib.sha256(canonical_json_bytes({
                key: value for key, value in completion_plan.items()
                if key != "content_hash"
            })).hexdigest() != plan_hash
            or len(plan_proofs) != 1
        ):
            raise LocalJournalError("planned Code Mode root completion-plan identity is invalid")
        plan_proof = plan_proofs[0]
        plan_ref_object = plan_proof.object_ref
        if (
            plan_ref_object.reference_id != plan_ref
            or plan_ref_object.object_id != plan_ref.removeprefix("cas:")
            or not isinstance(plan_ref_object.plaintext_commitment, str)
            or not plan_ref_object.plaintext_commitment
            or not isinstance(plan_ref_object.commitment_key_id, str)
            or not plan_ref_object.commitment_key_id
            or not isinstance(plan_ref_object.profile, str)
            or not plan_ref_object.profile
            or plan_proof.purpose_class != "code-mode-completion-plan"
            or not isinstance(plan_proof.core_header_hash, str)
            or not plan_proof.core_header_hash
            or not isinstance(plan_proof.envelope_id, str)
            or not plan_proof.envelope_id
            or not plan_proof.fresh_verified
            or not plan_proof.no_replace_published
        ):
            raise LocalJournalError("planned Code Mode root completion-plan proof is not exact")
        if root.get("seal_command_id") != command.command_id:
            raise LocalJournalError("planned Code Mode root seal command is not the current command")
        terminal_candidates = [
            event for event in self._events
            if event.stream_id == command.stream_id
            and isinstance(event.payload, Mapping)
            and event.payload.get("event_type") == "code-mode.terminal-success"
            and event.payload.get("terminal_state") == "SUCCEEDED"
        ]
        if len(terminal_candidates) != 1:
            raise LocalJournalError("planned Code Mode root has no unique terminal predecessor")
        terminal = terminal_candidates[0]
        terminal_operation = terminal.payload.get("authority_operation")
        terminal_operation_id = (
            terminal_operation.get("operation_id")
            if isinstance(terminal_operation, Mapping) else None
        )
        terminal_causation_command_id = terminal.payload.get("causation_command_id")
        terminal_command_id = (
            self._authority_operation_commands.get(terminal_operation_id)
            if isinstance(terminal_operation_id, str) else None
        )
        terminal_transaction = (
            self._transactions.get(terminal_command_id)
            if isinstance(terminal_command_id, str) else None
        )
        terminal_transaction_events = tuple(
            getattr(terminal_transaction, "events", ())
            if terminal_transaction is not None else ()
        )
        mapped_event_hashes = tuple(
            item.event_hash for item in self._events
            if item.stream_id == command.stream_id
            and isinstance(item.payload, Mapping)
            and isinstance(item.payload.get("authority_operation"), Mapping)
            and item.payload["authority_operation"].get("operation_id") == terminal_operation_id
        )
        if (
            not isinstance(terminal_operation, Mapping)
            or terminal_operation.get("operation") != "LOGICAL_TERMINAL_OPERATION_V1"
            or terminal_operation.get("payload_hash") != authority.parent_operation_hash
            or not isinstance(terminal_command_id, str)
            or terminal_command_id != terminal_causation_command_id
            or terminal_command_id not in self._authenticated_authority_command_ids
            or terminal_transaction is None
            or tuple(item.event_hash for item in terminal_transaction_events) != mapped_event_hashes
            or terminal.event_hash not in {item.event_hash for item in terminal_transaction_events}
            or root.get("terminal_event_id") != terminal.event_id
            or root.get("terminal_event_hash") != terminal.event_hash
        ):
            raise LocalJournalError("planned Code Mode root terminal predecessor is not exact")

    def _validate_code_mode_completion_plan_predecessor(
        self,
        authority: AuthorityOperationEnvelope,
        command: CommandEnvelope,
        events: Sequence[EventEnvelope],
        proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        completion_plan: Mapping[str, Any],
        completion_plan_reference: str | None,
    ) -> None:
        """Validate the plan CAS identity shared by root and conversation.

        The plan is an authorization predecessor, not an event-owned object.
        Both planned stages nevertheless receive the same exact check before
        Journal replay lookup, so a valid proof for another plan cannot be
        substituted merely by changing the stage payload.
        """
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("planned Code Mode stage must contain one event")
        payload = events[0].payload
        expected_schema = (
            "CODE_MODE_FINAL_ROOT_V2"
            if authority.operation == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1"
            else "CODE_MODE_CONVERSATION_COMPLETION_V1"
        )
        if payload.get("schema") != expected_schema:
            raise LocalJournalError("planned Code Mode stage schema is invalid")
        plan_ref = payload.get("completion_plan_ref")
        plan_hash = payload.get("completion_plan_hash")
        if (
            not isinstance(plan_ref, str)
            or not re.fullmatch(r"cas:[0-9a-f]{64}", plan_ref)
            or not isinstance(plan_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", plan_hash)
            or not isinstance(completion_plan_reference, str)
            or plan_ref != completion_plan_reference
            or not isinstance(completion_plan, Mapping)
            or completion_plan.get("schema") != "CODE_MODE_COMPLETION_PLAN_V1"
            or completion_plan.get("content_hash") != plan_hash
            or hashlib.sha256(canonical_json_bytes({
                key: value for key, value in completion_plan.items()
                if key != "content_hash"
            })).hexdigest() != plan_hash
        ):
            raise LocalJournalError("planned Code Mode stage completion-plan identity is invalid")
        plan_proofs = [
            proof for proof in proofs
            if isinstance(proof, PublishedObjectReceipt)
            and proof.object_ref.reference_id == plan_ref
        ]
        if len(plan_proofs) != 1:
            raise LocalJournalError("planned Code Mode stage lacks its exact completion-plan proof")
        plan_proof = plan_proofs[0]
        plan_ref_object = plan_proof.object_ref
        if (
            plan_ref_object.reference_id != plan_ref
            or plan_ref_object.object_id != plan_ref.removeprefix("cas:")
            or not isinstance(plan_ref_object.plaintext_commitment, str)
            or not plan_ref_object.plaintext_commitment
            or not isinstance(plan_ref_object.commitment_key_id, str)
            or not plan_ref_object.commitment_key_id
            or not isinstance(plan_ref_object.profile, str)
            or not plan_ref_object.profile
            or plan_proof.purpose_class != "code-mode-completion-plan"
            or not isinstance(plan_proof.core_header_hash, str)
            or not plan_proof.core_header_hash
            or not isinstance(plan_proof.envelope_id, str)
            or not plan_proof.envelope_id
            or not plan_proof.fresh_verified
            or not plan_proof.no_replace_published
        ):
            raise LocalJournalError("planned Code Mode stage completion-plan proof is not exact")

    @staticmethod
    def _event_replay_projection(event: EventEnvelope) -> dict[str, Any]:
        """Project the caller's unsealed event for deterministic replay.

        Stream coordinates and Journal authentication are assigned by this
        writer, so they are intentionally omitted.  All caller-controlled
        event identity, order, body, and CAS references remain committed.
        """
        return event_replay_projection(event)

    @staticmethod
    def _proof_manifest(
        proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> tuple[dict[str, Any], ...]:
        """Return the canonical, durable identity of each submitted proof."""
        values: list[dict[str, Any]] = []
        for proof in proofs:
            reference = proof.object_ref.reference_id
            object_ref = {
                "object_id": proof.object_ref.object_id,
                "tenant_id": proof.object_ref.tenant_id,
                "plaintext_commitment": proof.object_ref.plaintext_commitment,
                "commitment_key_id": proof.object_ref.commitment_key_id,
                "profile": proof.object_ref.profile,
            }
            if isinstance(proof, PublishedObjectReceipt):
                values.append({
                    "reference_id": reference,
                    "proof_type": "published",
                    "object_ref": object_ref,
                    "object_path": proof.object_path,
                    "core_header_hash": proof.core_header_hash,
                    "envelope_id": proof.envelope_id,
                    "purpose_class": proof.purpose_class,
                })
            elif isinstance(proof, ExistingDurableObjectRootProof):
                values.append({
                    "reference_id": reference,
                    "proof_type": "existing_root",
                    "object_ref": object_ref,
                    "journal_id": proof.journal_id,
                    "rooted_transaction_hash": proof.rooted_transaction_hash,
                    "rooted_position": proof.rooted_position,
                    "verified_frontier_position": proof.verified_frontier_position,
                    "object_reference_manifest_hash": proof.object_reference_manifest_hash,
                })
            else:
                raise LocalJournalError("unknown object proof type")
        return tuple(sorted(values, key=lambda item: str(item["reference_id"])))

    def _validate_authenticated_execution_parent(
        self,
        *,
        stream_id: str,
        child: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Reopen the authenticated parent before accepting a Forge child.

        A child must not be allowed to make its own ``parent_authorization_hash``
        the expected value.  The parent event and its persisted proof manifest
        are the Journal-owned source of that value.  This works for both a
        live Journal and a Fast Start writer: in the latter case the compact
        authenticated event projection and proof manifest retained in
        ``_transactions`` are used instead of inventing an in-memory parent.
        """
        parent_ref = child.get("parent_authorization_ref")
        parent_hash = child.get("parent_authorization_hash")
        if not isinstance(parent_ref, str) or not parent_ref or not isinstance(parent_hash, str) or not parent_hash:
            raise LocalJournalError("Forge child parent binding is incomplete")

        candidates: list[tuple[Mapping[str, Any], tuple[str, ...], Any]] = []
        for event in self._events:
            payload = event.payload
            if (
                event.stream_id == stream_id
                and isinstance(payload, Mapping)
                and payload.get("schema") == CODE_MODE_EXECUTION_PARENT_SCHEMA
                and payload.get("event_type") == CODE_MODE_EXECUTION_PARENT_EVENT_TYPE
                and payload.get("parent_authorization_ref") == parent_ref
            ):
                candidates.append((payload, tuple(event.object_refs), event))
        if not candidates:
            for transaction in self._transactions.values():
                for projection in getattr(transaction, "event_projection", ()):
                    if not isinstance(projection, Mapping):
                        continue
                    payload = projection.get("payload")
                    if (
                        isinstance(payload, Mapping)
                        and projection.get("stream_id") == stream_id
                        and payload.get("schema") == CODE_MODE_EXECUTION_PARENT_SCHEMA
                        and payload.get("event_type") == CODE_MODE_EXECUTION_PARENT_EVENT_TYPE
                        and payload.get("parent_authorization_ref") == parent_ref
                    ):
                        candidates.append((payload, tuple(projection.get("object_refs") or ()), transaction))
        if len(candidates) != 1:
            raise LocalJournalError("Forge child parent mapping is missing or not unique")

        payload, object_refs, source = candidates[0]
        plumbing = {"runtime_namespace", "actor_id", "causation_command_id", "policy_hash", "fact_hash"}
        logical = {key: value for key, value in payload.items() if key not in plumbing}
        required = set(CODE_MODE_EXECUTION_PARENT_PROJECTION_FIELDS) | {
            "parent_authorization_hash", "parent_authorization_ref",
            "authorization_receipt_ref", "authorization_receipt_hash",
        }
        if set(logical) != required:
            raise LocalJournalError("authenticated Forge parent projection is not exact")
        try:
            projection = execution_parent_projection(**{
                key: logical[key] for key in (
                    "authorization_token_hash", "authorization_ref", "session_instance_id",
                    "conversation_session_id", "turn_index", "generation", "provider_profile",
                    "provider_model", "session_id", "run_id", "intent_hash", "workspace",
                    "scope", "risk_level", "attempt", "expires_at",
                )
            })
        except Exception as error:
            raise LocalJournalError("authenticated Forge parent projection is invalid") from error
        expected_logical = dict(projection)
        expected_logical.update({
            "parent_authorization_hash": execution_parent_hash(projection),
            "parent_authorization_ref": projection["authorization_ref"],
            "authorization_receipt_ref": logical["authorization_receipt_ref"],
            "authorization_receipt_hash": logical["authorization_receipt_hash"],
        })
        if canonical_json_bytes(logical) != canonical_json_bytes(expected_logical):
            raise LocalJournalError("authenticated Forge parent projection changed")
        if parent_hash != expected_logical["parent_authorization_hash"]:
            raise LocalJournalError("Forge child parent hash is not the authenticated parent hash")
        receipt_ref = logical["authorization_receipt_ref"]
        if (
            not isinstance(receipt_ref, str)
            or object_refs != (receipt_ref,)
            or logical["parent_authorization_ref"] != parent_ref
            or logical["authorization_receipt_hash"] == ""
        ):
            raise LocalJournalError("authenticated Forge parent receipt ownership is invalid")

        transaction = source
        if isinstance(source, EventEnvelope):
            transaction = self._transactions.get(str(payload.get("causation_command_id") or ""))
        if transaction is None:
            raise LocalJournalError("authenticated Forge parent transaction is missing")
        manifest = tuple(dict(item) for item in getattr(transaction, "proof_manifest", ()))
        matching = [item for item in manifest if item.get("reference_id") == receipt_ref]
        if len(matching) != 1:
            raise LocalJournalError("authenticated Forge parent receipt proof is missing")
        proof = matching[0]
        proof_ref = proof.get("object_ref")
        if (
            proof.get("proof_type") != "published"
            or not isinstance(proof_ref, Mapping)
            or proof_ref.get("object_id") != receipt_ref.removeprefix("cas:")
            or proof_ref.get("plaintext_commitment") != logical["authorization_receipt_hash"]
            or proof.get("purpose_class") != CODE_MODE_EXECUTION_PARENT_PURPOSE
            or not isinstance(proof.get("core_header_hash"), str)
            or not proof.get("core_header_hash")
            or not isinstance(proof.get("envelope_id"), str)
            or not proof.get("envelope_id")
        ):
            raise LocalJournalError("authenticated Forge parent receipt proof is not exact")

        # When this writer has its production CAS verifier attached, reopen
        # the actual encrypted object as well.  A Journal event and a copied
        # receipt must not be able to agree on a fabricated parent hash while
        # the CAS body says something else.  The fallback above is retained
        # only for isolated Journal fixtures that intentionally have no CAS;
        # the Code Mode runtime always supplies one.
        if self._cas is not None:
            try:
                cas_ref = self._cas.resolve_reference(receipt_ref)
                if any(
                    cas_ref_value != proof_ref.get(field)
                    for cas_ref_value, field in (
                        (cas_ref.object_id, "object_id"),
                        (cas_ref.tenant_id, "tenant_id"),
                        (cas_ref.plaintext_commitment, "plaintext_commitment"),
                        (cas_ref.commitment_key_id, "commitment_key_id"),
                        (cas_ref.profile, "profile"),
                    )
                ):
                    raise LocalJournalError("authenticated Forge parent CAS identity changed")
                parent_body = dict(projection)
                parent_body["parent_authorization_hash"] = expected_logical["parent_authorization_hash"]
                if self._cas.open_verified(cas_ref) != canonical_json_bytes(parent_body):
                    raise LocalJournalError("authenticated Forge parent CAS body changed")
            except LocalJournalError:
                raise
            except Exception as error:
                raise LocalJournalError("authenticated Forge parent CAS could not be reopened") from error

        # The Forge child may run in an authenticated managed worktree.  Its
        # workspace is therefore intentionally different from the parent
        # workspace, but it must equal its own execution root and that root
        # must be one of the parent-authorized roots.  All other lineage and
        # provider bindings remain exact.
        for field in (
            "session_instance_id", "conversation_session_id", "turn_index", "run_id", "generation",
            "provider_profile", "provider_model",
        ):
            if child.get(field) != projection.get(field):
                raise LocalJournalError("Forge child exceeds authenticated parent scope: " + field)
        child_workspace = child.get("workspace")
        child_execution_root = child.get("execution_root")
        if not isinstance(child_workspace, str) or not isinstance(child_execution_root, str):
            raise LocalJournalError("Forge child execution root binding is incomplete")
        if child_workspace != child_execution_root:
            raise LocalJournalError("Forge child workspace must equal execution root")
        parent_scope = projection.get("scope")
        if not isinstance(parent_scope, (list, tuple)) or child_execution_root not in parent_scope:
            raise LocalJournalError("Forge child execution root exceeds authenticated parent scope")
        if child.get("parent_authorization_ref") != projection["authorization_ref"]:
            raise LocalJournalError("Forge child parent authorization reference is stale")
        if type(child.get("expires_at")) is not int or child["expires_at"] > projection["expires_at"]:
            raise LocalJournalError("Forge child lifetime exceeds authenticated parent")
        return projection

    def append(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        if any(is_code_mode_authority_reserved(event) for event in events):
            raise LocalJournalError(
                "Code Mode authority event requires its dedicated Journal entry point"
            )
        return self._append_internal(command, expected_stream_version, events, object_reference_proofs)

    def append_code_mode_attempt_advance(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        """Persist one exact next-attempt mapping, never as an ordinary fact."""
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("attempt advance requires a Code Mode Journal")
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("attempt advance requires one mapping event")
        payload = dict(events[0].payload)
        if payload.get("schema") != _CODE_MODE_ATTEMPT_ADVANCE_SCHEMA:
            raise LocalJournalError("attempt advance schema is reserved")
        self._validate_durable_attempt_authorization(payload)
        with self._mutex:
            existing = self._commands.get(command.command_id)
            if existing is None:
                self._validate_attempt_advance_payload(
                    payload, command=command, expected_stream_version=expected_stream_version,
                    event=events[0], proofs=object_reference_proofs,
                )
            self._pending_attempt_advance = payload
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_attempt_advance = None

    @staticmethod
    def _validate_durable_attempt_authorization(payload: Mapping[str, Any]) -> None:
        nested = payload.get("code_mode_authorization")
        if not isinstance(nested, Mapping):
            raise LocalJournalError("attempt Code Mode authorization projection is missing")
        if "authorization_token" in nested:
            raise LocalJournalError("attempt advance may not persist authorization_token")
        try:
            durable = durable_code_mode_authorization_projection(nested)
        except Exception as error:
            raise LocalJournalError("attempt Code Mode authorization token commitment is invalid") from error
        if dict(nested) != durable:
            raise LocalJournalError("attempt Code Mode authorization projection is not durable")

    def append_code_mode_tty_nonce_consumption(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        """Commit the controller-owned one-use TTY nonce fact.

        This is deliberately a narrow reserved-schema entry point.  It is
        not an authority signer and it never accepts an envelope or a
        caller-selected finalization operation.  Ordinary append remains
        unable to write the nonce-consumption schema.
        """
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("TTY nonce consumption requires a Code Mode Journal")
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("TTY nonce consumption requires one mapping event")
        payload = events[0].payload
        if (
            payload.get("schema") != "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
            or events[0].event_type != "code-mode.tty-review-nonce-consumed"
            or payload.get("consumed") is not True
        ):
            raise LocalJournalError("TTY nonce consumption schema is reserved")
        command_id = str(command.command_id)
        expected_consumption = payload.get("consumption_id")
        if not isinstance(expected_consumption, str) or not expected_consumption:
            raise LocalJournalError("TTY nonce consumption identity is missing")
        if command_id != "code-mode-tty-consume-" + expected_consumption:
            raise LocalJournalError("TTY nonce command identity is not derived from consumption")
        with self._mutex:
            existing = self._commands.get(command.command_id)
            if existing is None:
                self._validate_proofs(
                    tuple(sorted({reference for event in events for reference in event.object_refs})),
                    object_reference_proofs,
                )
            self._pending_code_mode_reserved = True
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_code_mode_reserved = False

    def _append_code_mode_reserved_mapping(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        schema: str,
        event_type: str,
    ) -> AppendReceipt:
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("reserved Code Mode mapping requires a Code Mode Journal")
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("reserved Code Mode mapping requires one event")
        if events[0].payload.get("schema") != schema or events[0].event_type != event_type:
            raise LocalJournalError("reserved Code Mode mapping schema/event type is invalid")
        with self._mutex:
            self._pending_code_mode_reserved = True
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_code_mode_reserved = False

    def append_code_mode_execution_authorization(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        """Commit the controller-owned attempt-one authorization fact."""
        return self._append_code_mode_reserved_mapping(
            command, expected_stream_version, events, object_reference_proofs,
            schema="SITINA_EXECUTION_AUTHORIZATION_V1",
            event_type="execution.authorization.bound",
        )

    def append_code_mode_execution_parent(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        """Persist the non-secret parent commitment used by Forge children."""
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("execution parent requires a Code Mode Journal")
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("execution parent requires one mapping event")
        event = events[0]
        payload = dict(event.payload)
        plumbing = {"runtime_namespace", "actor_id", "causation_command_id", "policy_hash", "fact_hash"}
        logical = {key: value for key, value in payload.items() if key not in plumbing}
        required = set(CODE_MODE_EXECUTION_PARENT_PROJECTION_FIELDS) | {
            "parent_authorization_hash", "parent_authorization_ref",
            "authorization_receipt_ref", "authorization_receipt_hash",
        }
        if set(logical) != required or payload.get("schema") != CODE_MODE_EXECUTION_PARENT_SCHEMA:
            raise LocalJournalError("execution parent mapping is not exact")
        if event.event_type != CODE_MODE_EXECUTION_PARENT_EVENT_TYPE:
            raise LocalJournalError("execution parent event type is invalid")
        if logical.get("purpose") != CODE_MODE_EXECUTION_PARENT_PURPOSE:
            raise LocalJournalError("execution parent purpose is invalid")
        projection_fields = set(CODE_MODE_EXECUTION_PARENT_PROJECTION_FIELDS)
        projection_values = {key: logical[key] for key in projection_fields}
        try:
            expected_projection = execution_parent_projection(**{
                key: projection_values[key] for key in (
                    "authorization_token_hash", "authorization_ref", "session_instance_id",
                    "conversation_session_id", "turn_index", "generation", "provider_profile",
                    "provider_model", "session_id", "run_id", "intent_hash", "workspace",
                    "scope", "risk_level", "attempt", "expires_at",
                )
            })
        except Exception as error:
            raise LocalJournalError("execution parent projection is invalid") from error
        if canonical_json_bytes(expected_projection) != canonical_json_bytes(projection_values):
            raise LocalJournalError("execution parent projection changed")
        if logical["parent_authorization_ref"] != expected_projection["authorization_ref"]:
            raise LocalJournalError("execution parent authorization reference changed")
        if logical["parent_authorization_hash"] != execution_parent_hash(expected_projection):
            raise LocalJournalError("execution parent hash is not derived from canonical facts")
        receipt_ref = logical["authorization_receipt_ref"]
        if not isinstance(receipt_ref, str) or tuple(event.object_refs) != (receipt_ref,):
            raise LocalJournalError("execution parent receipt ownership is invalid")
        matching = [proof for proof in object_reference_proofs if getattr(proof.object_ref, "reference_id", None) == receipt_ref]
        if len(matching) != 1:
            raise LocalJournalError("execution parent receipt proof is not unique")
        proof = matching[0]
        if (
            getattr(proof, "purpose_class", None) != CODE_MODE_EXECUTION_PARENT_PURPOSE
            or getattr(proof.object_ref, "object_id", None) != receipt_ref.removeprefix("cas:")
            or getattr(proof.object_ref, "plaintext_commitment", None) != logical["authorization_receipt_hash"]
            or not logical["authorization_receipt_hash"]
            or getattr(proof, "fresh_verified", None) is not True
            or getattr(proof, "no_replace_published", None) is not True
        ):
            raise LocalJournalError("execution parent receipt commitment is invalid")
        return self._append_code_mode_reserved_mapping(
            command, expected_stream_version, events, object_reference_proofs,
            schema=CODE_MODE_EXECUTION_PARENT_SCHEMA,
            event_type=CODE_MODE_EXECUTION_PARENT_EVENT_TYPE,
        )

    def append_code_mode_forge_child_authorization(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        """Commit the authenticated Forge child mapping through a dedicated API.

        The child event is intentionally separate from the attempt-one root:
        transport binding is allowed to reopen this mapping by locator, while
        ordinary writers cannot manufacture a child by copying the parent
        authorization payload.
        """
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("Forge child authorization requires a Code Mode Journal")
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("Forge child authorization requires one mapping event")
        event = events[0]
        payload = dict(event.payload)
        if payload.get("schema") != CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA or event.event_type != CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE:
            raise LocalJournalError("Forge child authorization schema/event type is invalid")
        plumbing = {"runtime_namespace", "actor_id", "causation_command_id", "policy_hash", "fact_hash"}
        logical = {key: value for key, value in payload.items() if key not in plumbing}
        required = {
            "schema", "event_type", "purpose", "domain", "session_instance_id",
            "conversation_session_id", "turn_index", "run_id", "child_run_id",
            "run_attempt", "generation", "parent_authorization_ref",
            "parent_authorization_hash", "authorization_ref", "workspace", "scope",
            "execution_root", "risk_level", "provider_profile", "provider_model", "expires_at",
            "authorization_receipt_ref", "authorization_receipt_hash", "payload_hash",
        }
        if set(logical) != required:
            raise LocalJournalError("Forge child authorization mapping is not exact")
        # The submitted child is never its own parent authority.  Reopen the
        # unique authenticated parent event/proof first, including during
        # replay, and derive the expected parent hash from that durable fact.
        self._validate_authenticated_execution_parent(
            stream_id=command.stream_id,
            child=logical,
        )
        try:
            expected = forge_child_authorization_projection(
                session_instance_id=logical["session_instance_id"],
                conversation_session_id=logical["conversation_session_id"],
                turn_index=logical["turn_index"], run_id=logical["run_id"],
                child_run_id=logical["child_run_id"], run_attempt=logical["run_attempt"],
                generation=logical["generation"],
                parent_authorization_ref=logical["parent_authorization_ref"],
                parent_authorization_hash=logical["parent_authorization_hash"],
                authorization_ref=logical["authorization_ref"],
                workspace=logical["workspace"], scope=logical["scope"],
                execution_root=logical["execution_root"], risk_level=logical["risk_level"],
                provider_profile=logical["provider_profile"],
                provider_model=logical["provider_model"], expires_at=logical["expires_at"],
                payload_hash=logical["payload_hash"],
            )
        except Exception as error:
            raise LocalJournalError("Forge child authorization binding is invalid") from error
        expected_logical = {key: logical[key] for key in expected}
        if logical["purpose"] != CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE or canonical_json_bytes(expected_logical) != canonical_json_bytes(dict(expected)):
            raise LocalJournalError("Forge child authorization logical projection is invalid")
        receipt_ref = logical["authorization_receipt_ref"]
        if not isinstance(receipt_ref, str) or not receipt_ref or tuple(event.object_refs) != (receipt_ref,):
            raise LocalJournalError("Forge child receipt ownership is invalid")
        matching = [proof for proof in object_reference_proofs if getattr(proof.object_ref, "reference_id", None) == receipt_ref]
        if len(matching) != 1:
            raise LocalJournalError("Forge child receipt proof is not unique")
        proof = matching[0]
        if getattr(proof, "purpose_class", None) != "true-multi-agent-child-execution-authorization":
            raise LocalJournalError("Forge child receipt purpose is invalid")
        if getattr(proof.object_ref, "object_id", None) != receipt_ref.removeprefix("cas:"):
            raise LocalJournalError("Forge child receipt object identity is invalid")
        if (
            not isinstance(proof.object_ref.plaintext_commitment, str)
            or not re.fullmatch(r"[0-9a-f]{64}", proof.object_ref.plaintext_commitment)
            or proof.object_ref.plaintext_commitment != logical["authorization_receipt_hash"]
            or not isinstance(proof.core_header_hash, str)
            or not proof.core_header_hash
            or not isinstance(proof.envelope_id, str)
            or not proof.envelope_id
            or proof.fresh_verified is not True
            or proof.no_replace_published is not True
        ):
            raise LocalJournalError("Forge child receipt commitment or ownership is invalid")
        with self._mutex:
            self._pending_code_mode_reserved = True
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_code_mode_reserved = False

    def append_code_mode_completion_plan(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        """Commit the host-published completion-plan producer fact."""
        return self._append_code_mode_reserved_mapping(
            command, expected_stream_version, events, object_reference_proofs,
            schema="CODE_MODE_COMPLETION_PLAN_FACT_V1",
            event_type="code-mode.completion-plan",
        )

    def append_code_mode_root_producer_fact(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        producer_role: str,
    ) -> AppendReceipt:
        """Append one authenticated root-FSM producer fact.

        Root dispatch, settled-call and selection facts are deliberately
        separate from ordinary model/proposal events.  This narrow entry is
        the only writer path accepted by the host's root transition verifier.
        """
        if producer_role not in {
            "root_scheduling", "root_dispatch_acceptance", "root_dispatch",
            "root_settled", "root_result_accepted", "root_selection",
        }:
            raise LocalJournalError("unknown root producer role")
        return self.append_code_mode_producer_fact(
            command, expected_stream_version, events, object_reference_proofs,
            producer_role=producer_role,
        )

    def append_code_mode_fact(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        terminal_bundle: bool = False,
    ) -> AppendReceipt:
        """Commit one role-specific Code Mode producer fact.

        This is the only non-authority producer entry point for reserved
        Code Mode facts.  Ordinary append remains denied before command
        lookup; the dedicated caller must still provide the formal CAS proofs
        and the role/schema event is retained in the authenticated Journal.
        """
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("Code Mode producer facts require a Code Mode Journal")
        if not terminal_bundle:
            raise LocalJournalError(
                "non-terminal Code Mode facts require their role-specific Journal entry"
            )
        if terminal_bundle:
            terminal_state = events[-1].payload.get("terminal_state") if isinstance(events[-1].payload, Mapping) else None
            terminal_event = (
                ("code-mode.terminal-success", "CODE_MODE_TERMINAL_SUCCESS_V1")
                if terminal_state == "SUCCEEDED"
                else ("code-mode.terminal-failed", "CODE_MODE_TERMINAL_FAILED_V1")
                if terminal_state == "FAILED"
                else None
            )
            if terminal_event is None:
                raise LocalJournalError("Code Mode terminal state is invalid")
            expected = (
                ("run.closing", None),
                ("protocol.terminal.negative.probe.rejected", None),
                ("protocol.terminal.full.validation.accepted", "TERMINAL_FULL_VALIDATION_ACCEPTED_V1"),
                ("protocol.run.evidence.package.sealed", "RUN_EVIDENCE_PACKAGE_SEALED_V1"),
                terminal_event,
            )
            if len(events) != len(expected):
                raise LocalJournalError("Code Mode terminal bundle has the wrong event count")
            for event, (event_type, schema) in zip(events, expected):
                if event.event_type != event_type or (
                    schema is not None
                    and (not isinstance(event.payload, Mapping) or event.payload.get("schema") != schema)
                ):
                    raise LocalJournalError("Code Mode terminal bundle event order is invalid")
        elif not events or any(not is_code_mode_authority_reserved(event) for event in events):
            raise LocalJournalError("Code Mode producer fact is not reserved")
        with self._mutex:
            self._pending_code_mode_reserved = True
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_code_mode_reserved = False

    def append_code_mode_producer_fact(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        producer_role: str,
    ) -> AppendReceipt:
        """Commit one typed producer fact through its role-specific entry.

        The role is part of the Journal API rather than an event-side hint.
        This keeps candidate, machine, package, core, request and review
        facts from sharing a permissive reserved-schema escape hatch.  The
        common evidence envelope remains intentionally separate from the
        role-specific ``evidence_schema``.
        """
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("Code Mode producer facts require a Code Mode Journal")
        try:
            spec = code_mode_producer_spec(producer_role)
        except Exception as error:
            raise LocalJournalError("unknown Code Mode producer role") from error
        if len(events) != 1 or not isinstance(events[0].payload, Mapping):
            raise LocalJournalError("typed Code Mode producer requires one event")
        event = events[0]
        payload = event.payload
        expected_schema = str(spec["fact_schema"])
        expected_event_type = spec.get("event_type")
        if payload.get("schema") != expected_schema:
            raise LocalJournalError("typed Code Mode producer schema is invalid")
        if isinstance(expected_event_type, str) and event.event_type != expected_event_type:
            raise LocalJournalError("typed Code Mode producer event type is invalid")
        expected_evidence_schema = spec.get("evidence_schema")
        if expected_evidence_schema is not None and payload.get("evidence_schema") != expected_evidence_schema:
            raise LocalJournalError("typed Code Mode producer evidence schema is invalid")
        expected_purpose = spec.get("purpose_class")
        if expected_purpose is not None and payload.get("purpose_class") != expected_purpose:
            raise LocalJournalError("typed Code Mode producer purpose is invalid")
        required_fields = spec.get("required_fields")
        if required_fields is not None:
            plumbing = {"runtime_namespace", "actor_id", "causation_command_id", "policy_hash", "fact_hash"}
            logical = {key for key in payload if key not in plumbing}
            if logical != set(required_fields):
                raise LocalJournalError("typed Code Mode producer fields are not exact")
            for field in required_fields:
                if payload.get(field) is None:
                    raise LocalJournalError("typed Code Mode producer field is missing: " + field)
        with self._mutex:
            self._pending_code_mode_reserved = True
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_code_mode_reserved = False

    def _validate_attempt_advance_payload(
        self,
        payload: Mapping[str, Any],
        *,
        command: CommandEnvelope,
        expected_stream_version: int,
        event: EventEnvelope,
        proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> None:
        required = {
            "schema", "event_type", "run_id", "session_instance_id", "session_id", "stream_id",
            "generation", "workspace", "previous_run_attempt", "run_attempt",
            "previous_authorization_ref", "authorization_ref", "authorization_receipt_ref",
            "authorization_receipt_hash", "workspace_observation_hash", "frontier_hash",
            "code_mode_authorization", "replan_plan_ref", "replan_plan_receipt_hash",
            "plan_hash", "replan_plan_hash", "replan_plan", "prior_plan_hash", "prior_failure_type",
            "prior_failure_hash",
            "execution_authorization",
        }
        plumbing = {"runtime_namespace", "actor_id", "causation_command_id", "policy_hash", "fact_hash"}
        logical_payload = {key: value for key, value in payload.items() if key not in plumbing}
        if set(logical_payload) != required or payload.get("schema") != _CODE_MODE_ATTEMPT_ADVANCE_SCHEMA:
            raise LocalJournalError("attempt advance mapping is not exact")
        if payload.get("event_type") != _CODE_MODE_ATTEMPT_ADVANCE_EVENT_TYPE:
            raise LocalJournalError("attempt advance event type is invalid")
        if command.stream_id != payload.get("stream_id") or payload.get("stream_id") != f"run/{payload.get('run_id')}":
            raise LocalJournalError("attempt advance stream binding is invalid")
        if command.payload.get("run_id") != payload.get("run_id"):
            raise LocalJournalError("attempt advance command binding is invalid")
        if type(payload.get("previous_run_attempt")) is not int or type(payload.get("run_attempt")) is not int:
            raise LocalJournalError("attempt numbers must be strict integers")
        if payload["run_attempt"] != payload["previous_run_attempt"] + 1:
            raise LocalJournalError("attempt advance is not the exact next attempt")
        for field in (
            "session_instance_id", "session_id", "stream_id", "run_id", "generation", "workspace",
            "previous_authorization_ref", "authorization_ref", "authorization_receipt_ref",
            "authorization_receipt_hash", "workspace_observation_hash", "frontier_hash",
        ):
            if not isinstance(payload.get(field), str) or not payload[field]:
                raise LocalJournalError("attempt advance binding is incomplete")
        if payload["authorization_ref"] == payload["previous_authorization_ref"]:
            raise LocalJournalError("attempt advance must publish a new authorization")
        for field in ("authorization_receipt_hash", "workspace_observation_hash", "frontier_hash"):
            if not re.fullmatch(r"[0-9a-f]{64}", payload[field]):
                raise LocalJournalError("attempt advance hash is invalid")
        if payload["authorization_receipt_ref"] not in event.object_refs:
            raise LocalJournalError("attempt authorization receipt is not event-owned")
        if payload["authorization_receipt_ref"] not in {
            proof.object_ref.reference_id for proof in proofs
        }:
            raise LocalJournalError("attempt authorization receipt proof is missing")
        replan_plan = payload.get("replan_plan")
        if not isinstance(replan_plan, Mapping):
            raise LocalJournalError("attempt replan plan projection is missing")
        if set(replan_plan) != {"approach", "acceptance_checks"}:
            raise LocalJournalError("attempt replan plan projection is not exact")
        if (
            not isinstance(replan_plan.get("approach"), str)
            or not replan_plan["approach"].strip()
            or type(replan_plan.get("acceptance_checks")) is not list
            or not replan_plan["acceptance_checks"]
            or any(not isinstance(item, str) or not item.strip() for item in replan_plan["acceptance_checks"])
        ):
            raise LocalJournalError("attempt replan plan projection is invalid")
        if not isinstance(payload.get("replan_plan_ref"), str) or not payload["replan_plan_ref"]:
            raise LocalJournalError("attempt replan plan receipt is missing")
        if payload["replan_plan_ref"] not in event.object_refs:
            raise LocalJournalError("attempt replan plan receipt is not event-owned")
        if payload["replan_plan_ref"] not in {proof.object_ref.reference_id for proof in proofs}:
            raise LocalJournalError("attempt replan plan receipt proof is missing")
        for field in ("plan_hash", "replan_plan_receipt_hash", "replan_plan_hash", "prior_plan_hash", "prior_failure_hash"):
            if not isinstance(payload.get(field), str) or not payload[field]:
                raise LocalJournalError("attempt replan commitment is incomplete")
        if not all(re.fullmatch(r"[0-9a-f]{64}", payload[field]) for field in (
            "plan_hash", "replan_plan_receipt_hash", "replan_plan_hash", "prior_plan_hash", "prior_failure_hash"
        )):
            raise LocalJournalError("attempt replan commitment hash is invalid")
        if payload["plan_hash"] != payload["replan_plan_hash"]:
            raise LocalJournalError("attempt plan does not match the replan commitment")
        if payload["replan_plan_hash"] != hashlib.sha256(
            canonical_json_bytes(dict(replan_plan))
        ).hexdigest():
            raise LocalJournalError("attempt replan plan hash is not derived from normalized content")
        replan_proof = next(
            (proof for proof in proofs if proof.object_ref.reference_id == payload["replan_plan_ref"]),
            None,
        )
        if not isinstance(replan_proof, PublishedObjectReceipt):
            raise LocalJournalError("attempt replan plan receipt type is invalid")
        if (
            replan_proof.object_ref.plaintext_commitment != payload["replan_plan_receipt_hash"]
            or replan_proof.purpose_class != "true-multi-agent-execution-replan"
        ):
            raise LocalJournalError("attempt replan plan receipt commitment or purpose changed")
        if not isinstance(payload.get("code_mode_authorization"), Mapping):
            raise LocalJournalError("attempt Code Mode authorization projection is missing")
        if (
            payload["code_mode_authorization"].get("run_attempt") != payload["run_attempt"]
            or payload["code_mode_authorization"].get("authorization_ref") != payload["authorization_ref"]
        ):
            raise LocalJournalError("attempt Code Mode authorization is not exact")
        for field in (
            "plan_hash", "replan_plan_hash", "replan_plan_ref", "replan_plan_receipt_hash",
            "prior_plan_hash", "prior_failure_type", "prior_failure_hash", "replan_plan",
        ):
            if payload["code_mode_authorization"].get(field) != payload.get(field):
                raise LocalJournalError("attempt Code Mode replan binding changed")
        execution_authorization = payload.get("execution_authorization")
        if not isinstance(execution_authorization, Mapping):
            raise LocalJournalError("attempt execution authorization projection is missing")
        if execution_authorization_attempt_ref(execution_authorization) != payload["authorization_ref"]:
            raise LocalJournalError("attempt authorization identity was not derived from canonical bytes")
        for field in (
            "session_instance_id", "session_id", "run_id", "run_attempt", "generation", "workspace",
            "authorization_ref", "plan_hash", "replan_plan_hash", "replan_plan_ref",
            "prior_plan_hash", "prior_failure_type", "prior_failure_hash",
        ):
            if execution_authorization.get(field) != payload.get(field):
                raise LocalJournalError("attempt execution authorization binding changed")
        matching_proof = next(
            (proof for proof in proofs if proof.object_ref.reference_id == payload["authorization_receipt_ref"]),
            None,
        )
        if not isinstance(matching_proof, PublishedObjectReceipt):
            raise LocalJournalError("attempt authorization receipt type is invalid")
        if (
            matching_proof.object_ref.plaintext_commitment != payload["authorization_receipt_hash"]
            or matching_proof.purpose_class != "true-multi-agent-execution-authorization-attempt"
        ):
            raise LocalJournalError("attempt authorization receipt commitment or purpose changed")
        if self._stream_heads.get(command.stream_id, 0) != expected_stream_version:
            raise ExpectedStreamVersionConflict("attempt advance frontier does not match stream head")
        prior = [
            item for item in self._events
            if item.stream_id == command.stream_id
            and isinstance(item.payload, Mapping)
            and item.payload.get("event_type") in {
                "execution.authorization.bound", "execution.authorization.attempt_advanced",
            }
        ]
        if not prior:
            raise LocalJournalError("attempt advance has no authenticated predecessor")
        latest = prior[-1].payload
        if type(latest.get("run_attempt")) is not int or latest.get("run_attempt") != payload["previous_run_attempt"]:
            raise LocalJournalError("attempt advance predecessor is stale")
        for field in ("session_instance_id", "session_id", "run_id", "generation", "workspace"):
            if latest.get(field) != payload.get(field):
                raise LocalJournalError("attempt advance predecessor binding changed")
        if latest.get("authorization_ref") != payload["previous_authorization_ref"]:
            raise LocalJournalError("attempt advance predecessor authorization changed")
        if any(
            isinstance(item.payload, Mapping) and item.payload.get("run_attempt") == payload["run_attempt"]
            for item in prior
        ):
            raise LocalJournalError("attempt advance already exists")

    def _append_authority_operation(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        envelope: Mapping[str, Any],
    ) -> AppendReceipt:
        """Commit one host-signed authority operation.

        This is intentionally a separate operation, not a boolean on
        ``append``.  The envelope is verified before any event is assigned or
        written and binds the logical operation to this exact run stream.
        """
        authority = AuthorityOperationEnvelope.from_mapping(envelope)
        self._verify_authority_operation(authority, command, expected_stream_version)
        # Hold the Journal mutex while installing and consuming the
        # authority operation.  A racing ordinary append must never inherit
        # the pending authority envelope.
        with self._mutex:
            self._pending_authority_operation = authority
            try:
                return self._append_internal(command, expected_stream_version, events, object_reference_proofs)
            finally:
                self._pending_authority_operation = None

    def append_authority_operation(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        envelope: Mapping[str, Any],
    ) -> AppendReceipt:
        """Commit a non-Code-Mode authority operation.

        Code Mode acceptance has a separate entry point so a caller cannot
        reach it by selecting an operation name on the legacy authority API.
        The ordinary method remains for the legacy compatibility namespace.
        """
        authority = AuthorityOperationEnvelope.from_mapping(envelope)
        if self.namespace_kind == "code_mode" and authority.operation == "LOGICAL_ACCEPTANCE_OPERATION_V1":
            raise LocalJournalError("Code Mode acceptance requires the dedicated acceptance transaction entry point")
        return self._append_authority_operation(
            command, expected_stream_version, events, object_reference_proofs,
            envelope=envelope,
        )

    def append_code_mode_acceptance_operation(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        envelope: Mapping[str, Any],
    ) -> AppendReceipt:
        """Commit the host-built acceptance pair through its dedicated gate."""
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("Code Mode acceptance requires a Code Mode Journal")
        authority = AuthorityOperationEnvelope.from_mapping(envelope)
        if authority.operation != "LOGICAL_ACCEPTANCE_OPERATION_V1":
            raise LocalJournalError("dedicated acceptance entry received another operation")
        return self._append_authority_operation(
            command, expected_stream_version, events, object_reference_proofs,
            envelope=envelope,
        )

    def append_planned_authority_operation(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        completion_plan: Mapping[str, Any],
        logical_operation_id: str,
        completion_plan_reference: str | None = None,
    ) -> AppendReceipt:
        """Commit one exact next operation from a signed completion plan.

        This recovery entry point accepts locators/commitments only.  It does
        not accept a caller-selected seal or capability.  The plan and its
        Ed25519 signature are checked against the pinned authority key before
        the normal authority transaction path performs the atomic append.
        """
        if self.namespace_kind != "code_mode":
            raise LocalJournalError("planned authority operations are Code Mode only")
        if not isinstance(completion_plan, Mapping):
            raise LocalJournalError("signed completion plan is required")
        plan = dict(completion_plan)
        if plan.get("schema") != "CODE_MODE_COMPLETION_PLAN_V1":
            raise LocalJournalError("completion plan schema is invalid")
        signature_hex = plan.get("authority_signature_hex")
        plan_hash = str(plan.get("content_hash") or "").removeprefix("sha256:")
        if not isinstance(signature_hex, str) or not plan_hash or hashlib.sha256(
            canonical_json_bytes({key: value for key, value in plan.items() if key != "content_hash"})
        ).hexdigest() != plan_hash:
            raise LocalJournalError("completion plan content commitment is invalid")
        if self._external_authority_public_key is None or plan.get("issuer_key_id") != self._external_authority_key_id:
            raise LocalJournalError("completion plan issuer is not the pinned authority")
        try:
            unsigned_plan = {
                key: value for key, value in plan.items()
                if key not in {"content_hash", "authority_signature_hex"}
            }
            Ed25519PublicKey.from_public_bytes(self._external_authority_public_key).verify(
                bytes.fromhex(signature_hex),
                canonical_json_bytes(unsigned_plan),
            )
        except Exception as error:
            raise LocalJournalError("completion plan signature is invalid") from error
        operations = plan.get("operations") or plan.get("logical_operations")
        if not isinstance(operations, list) or len(operations) != 3:
            raise LocalJournalError("completion plan operation set is incomplete")
        expected_operations = (
            "LOGICAL_TERMINAL_OPERATION_V1",
            "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
            "LOGICAL_CONVERSATION_COMPLETION_V1",
        )
        previous_logical_hash: str | None = None
        seen_operation_ids: set[str] = set()
        for index, raw_operation in enumerate(operations):
            if not isinstance(raw_operation, Mapping):
                raise LocalJournalError("completion plan operation is not an object")
            operation = dict(raw_operation)
            if operation.get("operation") != expected_operations[index]:
                raise LocalJournalError("completion plan operation order is invalid")
            logical_hash = operation.get("logical_operation_hash")
            operation_id = operation.get("logical_operation_id")
            if (
                not isinstance(logical_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", logical_hash)
                or not isinstance(operation_id, str)
                or operation_id in seen_operation_ids
            ):
                raise LocalJournalError("completion plan logical identity is invalid")
            logical_body = {
                key: value
                for key, value in operation.items()
                if key not in {"logical_operation_id", "logical_operation_hash"}
            }
            recalculated_hash = planned_operation_hash(operation)
            if logical_hash != recalculated_hash or operation_id != "code-mode-op-" + logical_hash[:32]:
                raise LocalJournalError("completion plan logical commitment is invalid")
            if operation.get("operation") in {
                "LOGICAL_TERMINAL_OPERATION_V1",
                "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
                "LOGICAL_CONVERSATION_COMPLETION_V1",
            }:
                stage_transaction = operation.get("stage_transaction")
                stage_transaction_hash = operation.get("stage_transaction_hash")
                if (
                    not isinstance(stage_transaction, Mapping)
                    or not isinstance(stage_transaction_hash, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", stage_transaction_hash)
                    or hashlib.sha256(canonical_json_bytes(dict(stage_transaction))).hexdigest()
                    != stage_transaction_hash
                ):
                    raise LocalJournalError("stage authority transaction commitment is invalid")
                stage_transaction = dict(stage_transaction)
                stage_signature = stage_transaction.pop("signature_hex", None)
                if (
                    stage_transaction.get("schema") != "AUTHORITY_STAGE_TRANSACTION_V1"
                    or stage_transaction.get("operation") != operation.get("operation")
                    or stage_transaction.get("logical_operation_id") != operation_id
                    or stage_transaction.get("logical_operation_hash") != logical_hash
                    or stage_transaction.get("stage_draft_ref") != operation.get("stage_draft_ref")
                    or stage_transaction.get("stage_draft_hash") != operation.get("stage_draft_hash")
                    or stage_transaction.get("stage_actual_event_projection") != operation.get("stage_actual_event_projection")
                    or stage_transaction.get("stage_actual_event_projection_hash") != operation.get("stage_actual_event_projection_hash")
                    or stage_transaction.get("stage_actual_proof_manifest") != operation.get("stage_actual_proof_manifest")
                    or stage_transaction.get("stage_actual_proof_manifest_hash") != operation.get("stage_actual_proof_manifest_hash")
                    or stage_transaction.get("run_id") != operation.get("run_id")
                    or stage_transaction.get("stream_id") != operation.get("stream_id")
                    or stage_transaction.get("generation") != operation.get("generation")
                    or stage_transaction.get("parent_logical_hash") != operation.get("parent_logical_hash")
                    or stage_transaction.get("expected_start_version") != operation.get("expected_start_version")
                    or stage_transaction.get("expected_end_version") != operation.get("expected_end_version")
                    or stage_transaction.get("snapshot_hash") != operation.get("logical_binding", {}).get("snapshot_hash")
                    or stage_transaction.get("plan_base_hash") != hashlib.sha256(
                        canonical_json_bytes(operation.get("bindings"))
                    ).hexdigest()
                    or stage_transaction.get("issuer_key_id") != plan.get("issuer_key_id")
                    or not isinstance(stage_signature, str)
                ):
                    raise LocalJournalError("stage authority transaction does not match its operation")
                if self._external_authority_public_key is None:
                    raise LocalJournalError("stage authority transaction issuer is not pinned")
                try:
                    Ed25519PublicKey.from_public_bytes(self._external_authority_public_key).verify(
                        bytes.fromhex(stage_signature), canonical_json_bytes(stage_transaction)
                    )
                except Exception as error:
                    raise LocalJournalError("stage authority transaction signature is invalid") from error
            if previous_logical_hash is not None and operation.get("parent_logical_hash") != previous_logical_hash:
                raise LocalJournalError("completion plan parent logical chain is invalid")
            if (
                operation.get("run_id") not in (None, plan.get("run_id"))
                or (
                    operation.get("stream_id") is not None
                    and not (
                        operation.get("stream_id") == plan.get("stream_id")
                        or (
                            operation.get("operation") == "LOGICAL_CONVERSATION_COMPLETION_V1"
                            and operation.get("stream_id") == plan.get("conversation_stream_id")
                        )
                    )
                )
                or operation.get("generation") not in (None, plan.get("generation"))
            ):
                raise LocalJournalError("completion plan operation scope is invalid")
            seen_operation_ids.add(operation_id)
            previous_logical_hash = logical_hash
        operation = next(
            (
                item for item in (plan.get("operations") or ())
                if isinstance(item, Mapping) and item.get("logical_operation_id") == logical_operation_id
            ),
            None,
        )
        if not isinstance(operation, Mapping):
            raise LocalJournalError("logical operation is not in the signed completion plan")
        operation_stream_id = operation.get("stream_id") or plan.get("stream_id")
        if (
            not isinstance(operation.get("logical_operation_hash"), str)
            or not isinstance(operation.get("expected_end_version"), int)
            or operation.get("expected_end_version") < expected_stream_version
            or not isinstance(operation.get("parent_logical_hash"), str)
            or len(operation.get("parent_logical_hash")) != 64
        ):
            raise LocalJournalError("signed logical operation commitment is incomplete")
        if (
            type(operation.get("event_count")) is not int
            or operation.get("event_count") != len(events)
            or not isinstance(operation.get("event_schema_order"), list)
            or len(operation["event_schema_order"]) != len(events)
            or not isinstance(operation.get("event_projection_hash"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", operation["event_projection_hash"])
            or not isinstance(operation.get("proof_manifest_hash"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", operation["proof_manifest_hash"])
            or not isinstance(operation.get("proof_purpose_order"), list)
            or not isinstance(operation.get("cas_object_hashes"), list)
            or not isinstance(operation.get("frontier_commitment"), str)
        ):
            raise LocalJournalError("signed logical operation exact commitments are incomplete")
        actual_event_order = [str(event.event_type) for event in events]
        if actual_event_order and actual_event_order[0] in {
            "protocol.run.closing.began", "protocol.run.closing.resumed",
        }:
            actual_event_order[0] = "protocol.run.closing.*"
        if actual_event_order != [str(item) for item in operation["event_schema_order"]]:
            raise LocalJournalError("planned event order/schema commitment changed")
        logical_binding = operation.get("logical_binding")
        declared_projection = operation.get("logical_event_projection")
        if not isinstance(logical_binding, Mapping) or not isinstance(declared_projection, list):
            raise LocalJournalError("planned logical event projection is incomplete")
        actual_logical_projection = [
            {
                "event_type": str(event.event_type),
                "logical_binding_hash": hashlib.sha256(canonical_json_bytes(logical_binding)).hexdigest(),
            }
            for event in events
        ]
        actual_event_projection_hash = hashlib.sha256(canonical_json_bytes(actual_logical_projection)).hexdigest()
        if declared_projection != actual_logical_projection:
            raise LocalJournalError("planned logical event projection changed")
        for event in events:
            payload = event.payload if isinstance(event.payload, Mapping) else {}
            for key in ("run_id", "generation", "session_id", "session_instance_id", "run_attempt", "turn_index", "candidate_id", "tree_hash"):
                if key in payload and key in logical_binding and payload.get(key) != logical_binding.get(key):
                    raise LocalJournalError("planned event logical binding changed")
        # The operation plan is a typed exact-commitment boundary.  The
        # event order check above remains a useful diagnostic, while this
        # shared projection commits every stable event payload and the full
        # authenticated proof manifest before any replay/append decision.
        if operation.get("operation") == "LOGICAL_ACCEPTANCE_OPERATION_V1":
            actual_event_projection_hash = acceptance_event_projection_hash(
                [dict(event.payload) for event in events]
            )
            if actual_event_projection_hash != operation["event_projection_hash"]:
                raise LocalJournalError("planned event projection commitment changed")
        # If the signed operation carries the stage-level actual commitment,
        # verify it from the exact EventEnvelope/proof objects supplied to
        # this append.  This check is deliberately after parsing the signed
        # operation but before replay lookup or any write, so a changed body
        # or proof cannot hide behind an existing command id.
        declared_stage_projection = operation.get("stage_actual_event_projection")
        declared_stage_projection_hash = operation.get("stage_actual_event_projection_hash")
        if operation.get("operation") in {
            "LOGICAL_TERMINAL_OPERATION_V1",
            "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
            "LOGICAL_CONVERSATION_COMPLETION_V1",
        } and (
            not isinstance(declared_stage_projection, list)
            or not isinstance(declared_stage_projection_hash, str)
            or not isinstance(operation.get("stage_draft_ref"), str)
            or not isinstance(operation.get("stage_draft_hash"), str)
            or not isinstance(operation.get("stage_actual_proof_manifest"), list)
            or not isinstance(operation.get("stage_actual_proof_manifest_hash"), str)
        ):
            raise LocalJournalError("planned Code Mode stage lacks its authenticated draft commitment")
        if declared_stage_projection is not None:
            if not isinstance(declared_stage_projection, list):
                raise LocalJournalError("stage actual event projection is invalid")
            actual_projection = stage_actual_event_projection(events)
            if canonical_json_bytes(actual_projection) != canonical_json_bytes(declared_stage_projection):
                raise LocalJournalError("stage actual event projection changed")
            derived_stage_hash = stage_actual_projection_hash(events)
            if declared_stage_projection_hash != derived_stage_hash:
                raise LocalJournalError("stage actual event projection hash changed")
        elif declared_stage_projection_hash is not None:
            if not isinstance(declared_stage_projection_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", declared_stage_projection_hash):
                raise LocalJournalError("stage actual event projection hash is invalid")
            if declared_stage_projection_hash != stage_actual_projection_hash(events):
                raise LocalJournalError("stage actual event projection commitment changed")
        declared_stage_proofs = operation.get("stage_actual_proof_manifest")
        declared_stage_proof_hash = operation.get("stage_actual_proof_manifest_hash")
        if declared_stage_proofs is not None:
            if not isinstance(declared_stage_proofs, list):
                raise LocalJournalError("stage actual proof manifest is invalid")
            # The already-published completion plan proof authorizes the
            # physical append, but is not a semantic proof of the stage
            # draft.  Keep it out of the stage commitment so the pre-acceptance
            # draft remains non-self-referential while Journal still requires
            # the plan proof for root/conversation authorization.
            stage_proofs = tuple(
                proof for proof in object_reference_proofs
                if getattr(proof, "purpose_class", None) != "code-mode-completion-plan"
            )
            actual_proof_manifest = list(stable_stage_proof_manifest(stage_proofs))
            if canonical_json_bytes(actual_proof_manifest) != canonical_json_bytes(declared_stage_proofs):
                raise LocalJournalError("stage actual proof manifest changed")
            if declared_stage_proof_hash != stable_stage_proof_manifest_hash(stage_proofs):
                raise LocalJournalError("stage actual proof manifest hash changed")
        elif declared_stage_proof_hash is not None:
            if not isinstance(declared_stage_proof_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", declared_stage_proof_hash):
                raise LocalJournalError("stage actual proof manifest hash is invalid")
            stage_proofs = tuple(
                proof for proof in object_reference_proofs
                if getattr(proof, "purpose_class", None) != "code-mode-completion-plan"
            )
            if declared_stage_proof_hash != stable_stage_proof_manifest_hash(stage_proofs):
                raise LocalJournalError("stage actual proof commitment changed")
        # The current completion plan is issued before terminal/final CAS
        # objects exist.  Its proof fields are therefore phase constraints,
        # not a replay exemption: acceptance (the operation that has all
        # known locators) is checked above against the full shared manifest,
        # while each later operation still validates the submitted proofs via
        # ``_validate_proofs`` before this point.  Do not compare a future
        # terminal receipt to the pre-review acceptance locator set.
        expected_authority = {
            "schema": "AUTHORITY_FINALIZATION_TRANSACTION_V1",
            "operation": operation.get("operation"),
            "operation_id": operation.get("logical_operation_id"),
            "run_id": operation.get("run_id") or plan.get("run_id"),
            "stream_id": operation_stream_id,
            "generation": operation.get("generation") or plan.get("generation"),
            "expected_stream_version": expected_stream_version,
            "parent_operation_hash": operation.get("parent_logical_hash"),
            "payload_hash": operation.get("logical_operation_hash"),
            "issuer_key_id": plan.get("issuer_key_id"),
            "signature_hex": plan.get("authority_signature_hex"),
        }
        # There is deliberately no envelope argument on this entry point.  A
        # caller can only submit actual events/proofs plus the already signed
        # plan; this deterministic projection is rebuilt inside Journal and
        # is never accepted as caller authority material.
        supplied_envelope = expected_authority
        authority = AuthorityOperationEnvelope.from_mapping(supplied_envelope)
        if (
            authority.operation_id != logical_operation_id
            or authority.run_id != plan.get("run_id")
            or authority.stream_id != operation_stream_id
            or authority.generation != plan.get("generation")
            or authority.expected_stream_version != expected_stream_version
            or operation.get("expected_start_version") != expected_stream_version + 1
            or operation.get("expected_end_version") != expected_stream_version + len(events)
            or operation.get("parent_logical_hash") != authority.parent_operation_hash
        ):
            raise LocalJournalError("planned operation binding or frontier is invalid")
        for event in events:
            payload = event.payload if isinstance(event.payload, Mapping) else {}
            if authority.operation != "LOGICAL_ACCEPTANCE_OPERATION_V1":
                if (
                    payload.get("logical_operation_id") != logical_operation_id
                    or payload.get("logical_operation_hash") != operation.get("logical_operation_hash")
                ):
                    raise LocalJournalError("planned event is not bound to the signed logical operation")
        # Planned operations reuse the already pinned and signed completion
        # plan.  No new host RPC or online signature is needed after the
        # acceptance transaction.  Keep the derived envelope in the pending
        # transaction so the normal Journal writer still checks exact event
        # binding and performs one physical mapping.
        with self._mutex:
            self._pending_authority_operation = authority
            try:
                return self._append_internal(
                    command, expected_stream_version, events, object_reference_proofs,
                    completion_plan=plan,
                    completion_plan_reference=completion_plan_reference,
                )
            finally:
                self._pending_authority_operation = None

    def _install_external_authority_pin(self, key_id: str, public_key: bytes) -> None:
        """Pin the attested host issuer for this runtime writer.

        The ordinary in-process Journal key is never promoted to an authority
        issuer.  A Code Mode controller installs this pin from the attested
        host hello; a second or changed pin is rejected.
        """
        if not isinstance(key_id, str) or not key_id.startswith("host-ed25519:"):
            raise LocalJournalError("external authority issuer identity is invalid")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise LocalJournalError("external authority public key is invalid")
        expected = "host-ed25519:" + hashlib.sha256(public_key).hexdigest()
        if expected != key_id:
            raise LocalJournalError("external authority issuer key identity mismatch")
        # Session-level Code Mode deliberately has no cross-restart authority
        # root.  The attested host identity is valid only for this live Journal
        # instance; persisting a pin here would turn an audit namespace into a
        # reusable authorization after a new CLI process starts.
        if self.namespace_kind == "code_mode":
            self._external_authority_key_id = key_id
            self._external_authority_public_key = bytes(public_key)
            return
        if self._external_authority_key_id is not None and (
            self._external_authority_key_id != key_id or self._external_authority_public_key != public_key
        ):
            raise LocalJournalError("external authority issuer pin cannot be replaced")
        value = {
            "schema": "CODE_MODE_AUTHORITY_PIN_V1",
            "key_id": key_id,
            "public_key_hex": public_key.hex(),
            "journal_id": self.journal_id,
            "epoch": self.epoch,
        }
        encoded = canonical_json_bytes(value)
        try:
            descriptor = os.open(
                self._authority_pin_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            try:
                existing = json.loads(self._authority_pin_path.read_text(encoding="utf-8"))
            except Exception as error:
                raise LocalJournalError("authority pin is unreadable") from error
            if existing != value:
                raise LocalJournalError("external authority issuer pin cannot be replaced")
        except OSError as error:
            raise LocalJournalError("authority pin cannot be durably created") from error
        else:
            try:
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._sync_directory(self.index_root)
        self._external_authority_key_id = key_id
        self._external_authority_public_key = bytes(public_key)

    def _load_external_authority_pin(self) -> None:
        """Load only the durable pin; never infer authority from event shape."""
        if self.namespace_kind == "code_mode":
            return
        if not self._authority_pin_path.is_file():
            return
        try:
            value = json.loads(self._authority_pin_path.read_text(encoding="utf-8"))
            key_id = value.get("key_id")
            public_key = bytes.fromhex(str(value.get("public_key_hex") or ""))
            if value.get("schema") != "CODE_MODE_AUTHORITY_PIN_V1" or value.get("journal_id") != self.journal_id or int(value.get("epoch")) != self.epoch:
                raise ValueError("pin identity mismatch")
            if len(public_key) != 32 or key_id != "host-ed25519:" + hashlib.sha256(public_key).hexdigest():
                raise ValueError("pin key identity mismatch")
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise LocalJournalError("durable authority pin is invalid") from error
        self._external_authority_key_id = str(key_id)
        self._external_authority_public_key = public_key

    def _load_durable_seal_index(self) -> None:
        """Load only the authenticated, run-scoped seal index.

        A root-shaped event is not a seal.  The index is written by the
        finalization transaction and is the sole durable source used during
        normal reopen and Fast Start.
        """
        for path in sorted(self._seal_index_root.glob("code-mode-seal-*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("seal cache entry is not an object")
                if (
                    value.get("schema") != "CODE_MODE_AUTHENTICATED_SEAL_INDEX_V1"
                    or value.get("journal_id") != self.journal_id
                    or int(value.get("epoch")) != self.epoch
                    or not isinstance(value.get("stream_id"), str)
                    or not isinstance(value.get("command_id"), str)
                    or not isinstance(value.get("transaction_hash"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value.get("transaction_hash"))
                    or not isinstance(value.get("root_event_hash"), str)
                ):
                    raise ValueError("seal index identity is invalid")
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                # This is a user-writable cache, never a source of authority.
                # Ignore malformed/foreign entries and let authenticated
                # Journal transactions establish the seal below.
                continue
            stream_id = str(value["stream_id"])
            self._durable_seal_records.setdefault(stream_id, []).append(dict(value))

    def _restore_durable_seals(self) -> None:
        """Bind seals only to authenticated final-root transactions.

        The JSON index is an optimization/receipt cache.  It is deliberately
        not a source of authority: a copied or edited sidecar cannot seal a
        stream unless the protected Journal frame contains the matching
        authenticated final-root transaction.
        """
        # Never promote a sidecar-only record.  A syntactically valid file is
        # still untrusted user-writable cache data; only a protected Journal
        # transaction can supply a candidate seal.
        candidates: dict[str, dict[str, Any]] = {}
        for command_id, transaction in self._authenticated_seal_transactions.items():
            if not transaction.authenticated_seal_stream_id:
                continue
            receipt = self._commands.get(command_id, (None, None))[1]
            if receipt is None:
                raise JournalRecoveryError("authenticated seal transaction receipt is missing")
            roots = [
                event for event in self._events
                if event.stream_id == transaction.stream_id
                and event.event_hash in {item.event_hash for item in transaction.events}
                and self._is_authenticated_code_mode_root(event)
            ]
            if len(roots) != 1:
                raise JournalRecoveryError("authenticated seal transaction root is missing or ambiguous")
            root = roots[0]
            derived = {
                "schema": "CODE_MODE_AUTHENTICATED_SEAL_INDEX_V1",
                "journal_id": self.journal_id,
                "epoch": self.epoch,
                "stream_id": transaction.stream_id,
                "command_id": command_id,
                "transaction_id": receipt.transaction_id,
                "transaction_hash": receipt.transaction_hash,
                "start_stream_version": receipt.first_stream_version,
                "end_stream_version": receipt.last_stream_version,
                "root_event_id": root.event_id,
                "root_event_hash": root.event_hash,
            }
            prior = candidates.get(transaction.stream_id)
            if prior is not None and canonical_json_bytes(prior) != canonical_json_bytes(derived):
                raise JournalRecoveryError("durable seal index does not match authenticated transaction")
            for cached in self._durable_seal_records.get(transaction.stream_id, ()):
                claims_this_transaction = (
                    cached.get("command_id") == command_id
                    or cached.get("transaction_hash") == receipt.transaction_hash
                )
                if claims_this_transaction and canonical_json_bytes(cached) != canonical_json_bytes(derived):
                    raise JournalRecoveryError("durable seal index does not match authenticated transaction")
            candidates[transaction.stream_id] = derived
        for stream_id, record in candidates.items():
            command_id = str(record["command_id"])
            stored = self._commands.get(command_id)
            if stored is None:
                raise JournalRecoveryError("durable seal refers to a missing transaction")
            _request_hash, receipt = stored
            if (
                receipt.stream_id != stream_id
                or receipt.transaction_hash != record["transaction_hash"]
                or receipt.last_stream_version != int(record.get("end_stream_version") or receipt.last_stream_version)
                or command_id not in self._authenticated_seal_transactions
            ):
                raise JournalRecoveryError("durable seal transaction binding is invalid")
            roots = [
                event for event in self._events
                if event.stream_id == stream_id and event.event_hash == record["root_event_hash"]
                and self._is_authenticated_code_mode_root(event)
            ]
            if len(roots) != 1:
                raise JournalRecoveryError("durable seal root binding is missing or ambiguous")
            self._authenticated_seal_command_ids.add(command_id)
            self._authenticated_root_command_ids.add(command_id)
            self._sealed_code_mode_streams.add(stream_id)

    def _persist_durable_seal_index(
        self, command: CommandEnvelope, receipt: AppendReceipt, events: Sequence[EventEnvelope]
    ) -> None:
        roots = [event for event in events if self._is_authenticated_code_mode_root(event)]
        if len(roots) != 1:
            raise LocalJournalError("authenticated finalization requires one Code Mode root")
        root = roots[0]
        value = {
            "schema": "CODE_MODE_AUTHENTICATED_SEAL_INDEX_V1",
            "journal_id": self.journal_id,
            "epoch": self.epoch,
            "stream_id": command.stream_id,
            "command_id": command.command_id,
            "transaction_id": receipt.transaction_id,
            "transaction_hash": receipt.transaction_hash,
            "start_stream_version": receipt.first_stream_version,
            "end_stream_version": receipt.last_stream_version,
            "root_event_id": root.event_id,
            "root_event_hash": root.event_hash,
        }
        path = self._seal_index_root / (
            "code-mode-seal-" + hashlib.sha256(command.stream_id.encode("utf-8")).hexdigest() + ".json"
        )
        encoded = canonical_json_bytes(value)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except Exception as error:
                raise LocalJournalError("durable Code Mode seal index is unreadable") from error
            if canonical_json_bytes(existing) != canonical_json_bytes(value):
                raise LocalJournalError("Code Mode stream has a conflicting durable seal")
            return
        except OSError as error:
            raise LocalJournalError("durable Code Mode seal index cannot be created") from error
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._sync_directory(self._seal_index_root)
        self._durable_seal_records[command.stream_id] = [dict(value)]

    def _verify_authority_operation(
        self, envelope: AuthorityOperationEnvelope, command: CommandEnvelope, expected_stream_version: int
    ) -> None:
        conversation_stream = (
            envelope.operation == "LOGICAL_CONVERSATION_COMPLETION_V1"
            and command.stream_id.startswith("session/")
        )
        if envelope.stream_id != command.stream_id or (
            envelope.run_id not in command.stream_id and not conversation_stream
        ):
            raise LocalJournalError("authority operation stream binding is invalid")
        if envelope.expected_stream_version != expected_stream_version:
            raise ExpectedStreamVersionConflict("authority operation frontier does not match stream head")
        external = envelope.issuer_key_id == self._external_authority_key_id
        if self.namespace_kind == "code_mode" and not external:
            raise LocalJournalError("Code Mode authority operations require the attested host issuer")
        if not external and (self._authority_key_id is None or envelope.issuer_key_id != self._authority_key_id):
            raise LocalJournalError("authority operation issuer is not pinned to this Journal")
        if envelope.operation_hash() != envelope.payload_hash:
            raise LocalJournalError("authority operation payload commitment is invalid")
        try:
            signature = bytes.fromhex(envelope.signature_hex)
            if external:
                if self._external_authority_public_key is None:
                    raise LocalJournalError("external authority public key is unavailable")
                Ed25519PublicKey.from_public_bytes(self._external_authority_public_key).verify(
                    signature, envelope.canonical_unsigned()
                )
                verified = True
            else:
                verified = self.authenticator.provider.verify(
                    envelope.issuer_key_id,
                    KeyPurpose.AUTHORITY_SIGNING,
                    envelope.canonical_unsigned(), signature,
                )
            if not verified:
                raise LocalJournalError("authority operation signature is invalid")
        except Exception as error:
            raise LocalJournalError("authority operation signature is invalid") from error

    def is_authenticated_authority_command(self, command_id: str, *, stream_id: str | None = None) -> bool:
        """Return the durable authority-transaction fact for a command.

        This index is rebuilt from Journal transaction metadata/events during
        open and Fast Start; it is not a caller-provided event flag.  It is
        deliberately read-only so a normal writer cannot promote itself.
        """
        if not isinstance(command_id, str) or command_id not in self._authenticated_authority_command_ids:
            return False
        if stream_id is None:
            return True
        receipt = self._commands.get(command_id, (None, None))[1]
        return receipt is not None and receipt.stream_id == stream_id

    def authority_operation_mapping(self, operation_id: str, *, stream_id: str) -> dict[str, Any]:
        """Reopen the durable logical-to-physical commit mapping."""
        command_id = self._authority_operation_commands.get(operation_id)
        if command_id is None:
            raise LocalJournalError("authority logical operation mapping is missing")
        receipt = self._commands.get(command_id, (None, None))[1]
        if receipt is None or receipt.stream_id != stream_id:
            raise LocalJournalError("authority logical operation mapping is foreign")
        events = [
            event for event in self._events
            if event.stream_id == stream_id and event.payload.get("authority_operation", {}).get("operation_id") == operation_id
        ]
        if not events:
            raise LocalJournalError("authority logical operation events are missing")
        return {
            "schema": "AUTHORITY_OPERATION_COMMIT_MAPPING_V1",
            "logical_operation_id": operation_id,
            "command_id": command_id,
            "transaction_id": receipt.transaction_id,
            "transaction_hash": receipt.transaction_hash,
            "stream_id": stream_id,
            "start_stream_version": receipt.first_stream_version,
            "end_stream_version": receipt.last_stream_version,
            "event_hashes": [event.event_hash for event in events],
            "first_position": receipt.first_position,
            "last_position": receipt.last_position,
        }

    def _append_internal(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
        *,
        completion_plan: Mapping[str, Any] | None = None,
        completion_plan_reference: str | None = None,
    ) -> AppendReceipt:
        with self._mutex:
            self._assert_healthy()
            self._assert_production_append_authorized(command)
            authority = getattr(self, "_pending_authority_operation", None)
            finalization = isinstance(authority, AuthorityOperationEnvelope)
            attempt_advance = isinstance(getattr(self, "_pending_attempt_advance", None), Mapping)
            request_hash = command.command_request_hash
            # Validate the complete submitted transaction before looking up a
            # command replay.  A replay is not an exemption from proof
            # validation: otherwise a caller could reuse a command id with a
            # foreign/purpose-swapped CAS proof and receive the old receipt
            # without proving the current payload still closes the same
            # object set.
            if not events:
                raise LocalJournalError("append requires at least one event")
            if any(event.stream_id != command.stream_id or event.tenant_id != command.tenant_id for event in events):
                raise LocalJournalError("all events must belong to the command tenant and one logical stream")
            if any(event.event_hash is not None for event in events):
                raise LocalJournalError("caller may not submit pre-sealed events")
            if not attempt_advance and authority is None and not getattr(self, "_pending_code_mode_reserved", False) and any(
                is_code_mode_authority_reserved(event) for event in events
            ):
                raise LocalJournalError("reserved Code Mode authority event requires its dedicated Journal entry point")
            references = tuple(sorted({reference for event in events for reference in event.object_refs}))
            # The signed completion plan is an authorization proof for a
            # planned operation, not an object owned by its semantic event
            # body.  It may therefore accompany root/conversation commits
            # without being smuggled into the pre-acceptance stage draft's
            # per-event object_refs.  All other proofs must still match the
            # event-owned references exactly.
            if finalization and authority is not None and authority.operation in {
                "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
                "LOGICAL_CONVERSATION_COMPLETION_V1",
            }:
                plan_refs = {
                    str(event.payload.get("completion_plan_ref"))
                    for event in events
                    if isinstance(event.payload, Mapping)
                    and event.payload.get("completion_plan_ref") is not None
                }
                plan_proof_refs = {
                    proof.object_ref.reference_id
                    for proof in object_reference_proofs
                    if isinstance(proof, PublishedObjectReceipt)
                    and proof.purpose_class == "code-mode-completion-plan"
                }
                if (
                    not isinstance(completion_plan_reference, str)
                    or plan_refs != {completion_plan_reference}
                    or plan_proof_refs != {completion_plan_reference}
                ):
                    raise LocalJournalError("planned Code Mode operation lacks its exact completion-plan proof")
            event_proofs = tuple(
                proof for proof in object_reference_proofs
                if proof.object_ref.reference_id in references
            )
            object_refs = self._validate_proofs(references, event_proofs)
            # The persisted transaction manifest describes event-owned CAS
            # objects only.  Planned root/conversation operations may also
            # carry the already-published completion-plan proof as an
            # authorization input; it is verified above but is not an event
            # reference and must not alter the transaction's object manifest.
            proof_manifest = self._proof_manifest(event_proofs)
            self._validate_code_mode_planned_predecessors(
                authority, command, events, object_reference_proofs,
                completion_plan=completion_plan or {},
                completion_plan_reference=completion_plan_reference,
            )
            existing = self._commands.get(command.command_id)
            if existing:
                if existing[0] != request_hash:
                    raise CommandConflict("same Command ID is bound to a different request hash")
                # A command replay is idempotent only for the exact original
                # event projection.  Checking the request hash alone is not
                # enough: a caller can reuse a CommandEnvelope while
                # changing the event/CAS payload supplied to the Journal.
                stored_events = tuple(
                    event for event in self._events
                    if event.stream_id == command.stream_id
                    and existing[1].first_position <= event.position <= existing[1].last_position
                )
                submitted_projection = tuple(
                    self._event_replay_projection(event)
                    for event in events
                )
                stored_transaction = self._transactions.get(command.command_id)
                stored_projection = tuple(
                    self._event_replay_projection(event)
                    for event in stored_events
                )
                if not stored_events and stored_transaction is not None:
                    stored_projection = tuple(
                        dict(item) for item in getattr(stored_transaction, "event_projection", ())
                    )
                if (
                    not stored_projection
                    or event_replay_projection_bytes(submitted_projection)
                    != event_replay_projection_bytes(stored_projection)
                    or event_replay_projection_hash(submitted_projection)
                    != event_replay_projection_hash(stored_projection)
                ):
                    raise CommandConflict("same Command ID replay has a different event projection")
                if (
                    stored_transaction is None
                    or proof_manifest_bytes(stored_transaction.proof_manifest)
                    != proof_manifest_bytes(proof_manifest)
                ):
                    raise CommandConflict("same Command ID replay has a different proof manifest")
                return existing[1]
            if self._stream_heads.get(command.stream_id, 0) != expected_stream_version:
                raise ExpectedStreamVersionConflict("expected Stream Version does not match canonical head")
            if command.stream_id in self._sealed_code_mode_streams:
                raise LocalJournalError("Code Mode Journal stream is durably sealed")
            # Code Mode receipt roots are terminal, not merely a convention of
            # CanonicalStream.  Enforce closure at the Journal append boundary
            # as well, including a newly opened writer or a lower-level caller.
            if finalization:
                envelope_mapping = authority.unsigned() | {"signature_hex": authority.signature_hex}
                if any(
                    not isinstance(event.payload, dict)
                    or event.payload.get("authority_operation") != envelope_mapping
                    for event in events
                ):
                    raise LocalJournalError("authority operation envelope is not bound to every event")
                previous_command = self._authority_operation_commands.get(authority.operation_id)
                if previous_command is not None and previous_command != command.command_id:
                    raise CommandConflict("authority logical operation is already mapped to another command")
                if authority.operation not in {
                    "LOGICAL_ACCEPTANCE_OPERATION_V1",
                    "LOGICAL_TERMINAL_OPERATION_V1",
                    "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
                    "LOGICAL_CONVERSATION_COMPLETION_V1",
                    "AUTHORITY_FINALIZATION",
                }:
                    raise LocalJournalError("authority operation is not a final-root operation")
                if authority.operation == "LOGICAL_ACCEPTANCE_OPERATION_V1":
                    acceptance_schemas = [
                        event.payload.get("schema")
                        if isinstance(event.payload, dict) else None
                        for event in events
                    ]
                    if acceptance_schemas != [
                        "CODE_MODE_FINAL_REVIEWER_FACT_V1",
                        "CODE_MODE_REVIEW_ACCEPTED_V1",
                    ]:
                        raise LocalJournalError("authority acceptance must contain the exact reviewer pair")
                    reviewer, accepted = events[0].payload, events[1].payload
                    if (
                        reviewer.get("causation_command_id") != accepted.get("causation_command_id")
                        or reviewer.get("accepted_at") != accepted.get("accepted_at")
                        or reviewer.get("request_ref") != accepted.get("request_ref")
                        or reviewer.get("request_hash") != accepted.get("request_hash")
                        or reviewer.get("review_receipt_ref") != accepted.get("review_receipt_ref")
                        or reviewer.get("review_receipt_hash") != accepted.get("review_receipt_hash")
                        or reviewer.get("session_id") != accepted.get("session_id")
                        or type(reviewer.get("turn_index")) is not int
                        or type(accepted.get("turn_index")) is not int
                        or reviewer.get("turn_index") != accepted.get("turn_index")
                        or accepted.get("gate_status") != "CODE_MODE_READY"
                    ):
                        raise LocalJournalError("authority acceptance pair has inconsistent binding")
                    # ``CanonicalStream`` keeps object references in the
                    # authenticated EventEnvelope (and removes the private
                    # construction hint from the payload).  Compare that
                    # durable per-event ownership, not a caller mapping.
                    reviewer_refs = list(events[0].object_refs)
                    accepted_refs = list(events[1].object_refs)
                    if (
                        not isinstance(reviewer_refs, list)
                        or not isinstance(accepted_refs, list)
                        or reviewer_refs != sorted(set(reviewer_refs))
                        or accepted_refs != sorted(set(accepted_refs))
                        or set(reviewer_refs) & set(accepted_refs)
                    ):
                        raise LocalJournalError("authority acceptance event object ownership is invalid")
                    if not all(
                        isinstance(getattr(authority, field), str)
                        and re.fullmatch(r"[0-9a-f]{64}", getattr(authority, field))
                        for field in ("completion_plan_hash", "event_projection_hash", "proof_manifest_hash")
                    ):
                        raise LocalJournalError("authority acceptance lacks host commitments")
                    projected_events = []
                    for event in events:
                        projected = dict(event.payload)
                        projected["_object_refs"] = list(event.object_refs)
                        projected_events.append(projected)
                    expected_event_projection = acceptance_event_projection_hash(projected_events)
                    if authority.event_projection_hash != expected_event_projection:
                        raise LocalJournalError("authority acceptance event commitment changed")
                    # Acceptance uses the same stable, purpose-bearing proof
                    # manifest as the host and checkpoint/replay paths.  An
                    # object-id-only digest would let a purpose, envelope, or
                    # CAS header be swapped without changing the commitment.
                    expected_proof_manifest = proof_manifest_hash(
                        self._proof_manifest(object_reference_proofs)
                    )
                    if authority.proof_manifest_hash != expected_proof_manifest:
                        raise LocalJournalError("authority acceptance proof commitment changed")
                    plan_ref = accepted.get("completion_plan_ref")
                    plan_object_ids = {
                        proof.object_ref.object_id
                        for proof in object_reference_proofs
                        if isinstance(proof, PublishedObjectReceipt)
                        and proof.object_ref.reference_id == plan_ref
                    }
                    if authority.completion_plan_hash not in plan_object_ids:
                        raise LocalJournalError("authority acceptance plan commitment changed")
                elif authority.operation == "LOGICAL_TERMINAL_OPERATION_V1":
                    terminal_events = [
                        event for event in events
                        if isinstance(event.payload, dict)
                        and (
                            (
                                event.payload.get("event_type") == "code-mode.terminal-success"
                                and event.payload.get("schema") == "CODE_MODE_TERMINAL_SUCCESS_V1"
                                and event.payload.get("terminal_state") == "SUCCEEDED"
                            )
                            or (
                                event.payload.get("event_type") == "code-mode.terminal-failed"
                                and event.payload.get("schema") == "CODE_MODE_TERMINAL_FAILED_V1"
                                and event.payload.get("terminal_state") == "FAILED"
                            )
                        )
                    ]
                    if len(events) != 5 or len(terminal_events) != 1:
                        raise LocalJournalError("authenticated terminal operation must contain the complete terminal projection")
                elif authority.operation == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1":
                    roots = [
                        event for event in events
                        if isinstance(event.payload, dict)
                        and event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
                    ]
                    if len(events) != 1 or len(roots) != 1:
                        raise LocalJournalError("authenticated finalization must contain exactly one V2 root")
                    root = roots[0]
                    final_reference = root.payload.get("final_receipt_ref")
                    if not isinstance(final_reference, str) or not any(
                        isinstance(proof, PublishedObjectReceipt)
                        and proof.object_ref.reference_id == final_reference
                        for proof in object_reference_proofs
                    ):
                        raise LocalJournalError("finalization root lacks a fresh final receipt proof")
                    plan_reference = root.payload.get("completion_plan_ref")
                    if not isinstance(plan_reference, str) or not any(
                        isinstance(proof, PublishedObjectReceipt)
                        and proof.object_ref.reference_id == plan_reference
                        for proof in object_reference_proofs
                    ):
                        raise LocalJournalError("finalization root lacks a fresh completion-plan proof")
                    prior_terminal = next(
                        (
                            event for event in reversed(self._events)
                            if event.stream_id == command.stream_id
                            and isinstance(event.payload, dict)
                            and event.payload.get("event_type") == "code-mode.terminal-success"
                            and event.payload.get("terminal_state") == "SUCCEEDED"
                        ),
                        None,
                    )
                    if prior_terminal is None or root.payload.get("terminal_event_id") != prior_terminal.event_id or root.payload.get("terminal_event_hash") != prior_terminal.event_hash:
                        raise LocalJournalError("finalization root is not bound to the current successful terminal")
                elif authority.operation == "LOGICAL_CONVERSATION_COMPLETION_V1":
                    if len(events) != 1:
                        raise LocalJournalError("conversation completion must contain one event")
                    conversation = events[0].payload
                    if (
                        conversation.get("schema") != "CODE_MODE_CONVERSATION_COMPLETION_V1"
                        or conversation.get("event_type") != "code-mode.conversation-completion"
                        or conversation.get("run_id") != authority.run_id
                        or conversation.get("session_id") != command.stream_id.removeprefix("session/")
                        or conversation.get("assistant_message_id") != f"{conversation.get('session_id')}-assistant-{conversation.get('turn_index')}"
                        or not isinstance(conversation.get("response_hash"), str)
                        or not conversation.get("response_hash")
                    ):
                        raise LocalJournalError("conversation completion binding is incomplete")
                else:
                    raise LocalJournalError("authority operation is not a supported Code Mode finalization operation")
            leases: list[ReferenceLease] = []
            try:
                if self.gc_controller:
                    leases = [self.gc_controller.with_reference_lease(reference) for reference in references]
                assigned = tuple(
                    event.assign(stream_version=expected_stream_version + index, position=self.head_position + index).seal(
                        journal_id=self.journal_id, epoch=self.epoch, authenticator=self.authenticator
                    )
                    for index, event in enumerate(events, start=1)
                )
                seals_stream = (
                    command.stream_id
                    if finalization and authority.operation == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1"
                    else None
                )
                transaction = JournalTransaction(
                    f"tx-{uuid.uuid4().hex}", command.command_id, request_hash, command.stream_id,
                    assigned, references,
                    seals_stream,
                    proof_manifest,
                )
                frame_bytes = encode_frame(transaction)
                self._fault("before_frame_write")
                os.lseek(self._active_fd, 0, os.SEEK_END)
                written = 0
                while written < len(frame_bytes):
                    try:
                        count = os.write(self._active_fd, frame_bytes[written:])
                    except InterruptedError:
                        continue
                    if count <= 0:
                        raise OSError(errno.EIO, "zero-length Journal write")
                    written += count
                self._fault("after_frame_write_before_fsync")
                os.fsync(self._active_fd)
                self._fault("after_frame_fsync_before_ack")
                decoded = self._decode_last(frame_bytes)
                receipt = self._receipt(decoded)
                for lease in leases:
                    lease.commit(transaction_hash=receipt.transaction_hash, position=receipt.last_position)
                self._commands[command.command_id] = (request_hash, receipt)
                self._transactions[command.command_id] = transaction
                if finalization:
                    self._authenticated_authority_command_ids.add(command.command_id)
                    self._authority_operation_commands[authority.operation_id] = command.command_id
                self._stream_heads[command.stream_id] = receipt.last_stream_version
                self._events.extend(assigned)
                if finalization and authority.operation == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1":
                    self._persist_durable_seal_index(command, receipt, assigned)
                    self._authenticated_seal_command_ids.add(command.command_id)
                    self._authenticated_root_command_ids.add(command.command_id)
                    self._sealed_code_mode_streams.add(command.stream_id)
                self._head_position = receipt.last_position
                for position in range(receipt.first_position, receipt.last_position + 1):
                    self._position_hash[position] = receipt.transaction_hash
                for reference, object_ref in object_refs.items():
                    self._object_roots.setdefault(reference, (object_ref, decoded))
                if self.rollover_coordinator is not None:
                    self.rollover_coordinator.consider(self)
                return receipt
            except BaseException as error:
                for lease in leases:
                    if lease.active:
                        lease.release()
                self.poisoned_reason = f"append outcome requires fresh locked recovery: {type(error).__name__}: {error}"
                self.writer_lock.poison(self.poisoned_reason)
                raise

    def _assert_production_append_authorized(self, command: CommandEnvelope) -> None:
        if self.namespace_kind not in {"production", "production_simulation"}:
            return
        if self._authority_resolution is not None:
            if command.command_type == "authority.cutover-verified.commit" and self._operational_capability is not None:
                try:
                    self._operational_capability.assert_operation(
                        "SUBMIT_STABLE_CUTOVER_VERIFIED_COMMAND", self.home, now=int(time.time())
                    )
                except Exception as error:
                    raise LocalJournalError("CutoverVerified append lacks a current Maintenance capability") from error
                return
            try:
                self._authority_resolution.assert_fresh(now=int(time.time()))
            except Exception as error:
                raise LocalJournalError("stale authority resolution denies Production append") from error
            if not self._authority_resolution.authorizes_journal or self._authority_resolution.writer_count != 1:
                raise LocalJournalError("Production business append has no unique Journal authority")
            if command.command_type.startswith("authority.cutover"):
                raise LocalJournalError("runtime business authority cannot submit maintenance cutover commands")
            return
        if self._operational_capability is None:
            raise LocalJournalError("Production control append lacks a Maintenance capability")
        allowed = ("authority.", "migration.", "production.genesis", "operational.")
        if not command.command_type.startswith(allowed):
            raise LocalJournalError("Maintenance capability cannot append Production business commands")
        if command.command_type.startswith("migration."):
            operation = "PUBLISH_MIGRATION_CONTROL_FACTS"
        elif command.command_type == "authority.cutover.commit":
            operation = "SUBMIT_STABLE_CUTOVER_COMMAND"
        elif command.command_type == "authority.cutover-verified.commit":
            operation = "SUBMIT_STABLE_CUTOVER_VERIFIED_COMMAND"
        else:
            operation = "OPEN_PRODUCTION_JOURNAL_CONTROL_PLANE"
        try:
            self._operational_capability.assert_operation(operation, self.home, now=int(time.time()))
        except Exception as error:
            raise LocalJournalError("Production control append capability is stale or out of scope") from error

    def activate_business_authority(self, resolution: object) -> None:
        if self.namespace_kind not in {"production", "production_simulation"}:
            raise LocalJournalError("business authority activation applies only to a Production Journal")
        try:
            resolution.assert_fresh(now=int(time.time()))
        except Exception as error:
            raise LocalJournalError("cannot activate a stale Production authority resolution") from error
        if not resolution.authorizes_journal or resolution.writer_count != 1:
            raise LocalJournalError("Production business authority must name exactly the Journal writer")
        self._authority_resolution = resolution

    @staticmethod
    def _decode_last(frame_bytes: bytes) -> DecodedFrame:
        from .codec import decode_one
        return decode_one(frame_bytes)

    def query_command(self, command_id: str, request_hash: str) -> CommandResult:
        existing = self._commands.get(command_id)
        if not existing:
            return CommandResult(CommandStatus.UNKNOWN, command_id, request_hash, reason="not found in canonical coverage")
        if existing[0] != request_hash:
            return CommandResult(CommandStatus.CONFLICT, command_id, request_hash, reason="Command ID is bound to another request hash")
        return CommandResult(CommandStatus.COMMITTED, command_id, request_hash, receipt=existing[1], canonical_outcome_ref=existing[1].transaction_hash)

    def lookup_existing_object_root_proof(self, object_ref: ObjectRef, verified_frontier: FrontierRef) -> ExistingDurableObjectRootProof:
        if verified_frontier.journal_id != self.journal_id or verified_frontier.epoch != self.epoch:
            raise LocalJournalError("frontier belongs to another Journal")
        if self._position_hash.get(verified_frontier.position) != verified_frontier.commitment:
            raise LocalJournalError("frontier commitment is not verified by canonical frames")
        try:
            rooted_ref, frame = self._object_roots[object_ref.reference_id]
        except KeyError as error:
            raise LocalJournalError("object has no canonical committed root") from error
        if frame.transaction.last_position > verified_frontier.position:
            raise LocalJournalError("object root is beyond verified frontier")
        return ExistingDurableObjectRootProof._issue(
            object_ref=object_ref, journal_id=self.journal_id, rooted_transaction_hash=frame.transaction_hash,
            rooted_position=frame.transaction.last_position, verified_frontier_position=verified_frontier.position,
            object_reference_manifest_hash=frame.transaction.object_reference_manifest_hash,
        )

    def iter_events(self, after_position: int = 0) -> Iterable[EventEnvelope]:
        return tuple(event for event in self._events if event.position > after_position)

    def iter_events_authoritative_slow(self, after_position: int = 0) -> Iterable[EventEnvelope]:
        """Explicit full-history path; ordinary fast-start readers should use Projection + tail."""
        events: list[EventEnvelope] = []
        for path in sorted(self.sealed_root.glob("*.seg")):
            events.extend(event for frame in scan_sealed_segment(path).frames for event in frame.transaction.events)
        events.extend(
            event
            for frame in scan_active_segment_read_only(self.active_path).frames
            for event in frame.transaction.events
        )
        return tuple(event for event in events if event.position > after_position)

    def rollover(self) -> Path | None:
        with self._mutex:
            self._assert_healthy()
            size = os.fstat(self._active_fd).st_size
            if size == 0:
                return None
            try:
                os.fsync(self._active_fd)
                self._fault("rollover_after_group_sync")
                os.lseek(self._active_fd, 0, os.SEEK_SET)
                digest = hashlib.sha256()
                while chunk := os.read(self._active_fd, 1024 * 1024):
                    digest.update(chunk)
                target = self.sealed_root / f"{self.head_position:020d}-{digest.hexdigest()}.seg"
                if target.exists():
                    raise LocalJournalError("sealed segment target already exists")
                os.link(self.active_path, target, follow_symlinks=False)
                os.fsync(self._active_fd)
                self._fault("rollover_after_footer_sync")
                self._sync_directory(self.sealed_root)
                self._fault("rollover_after_no_replace_publish")
                os.close(self._active_fd)
                self.active_path.unlink()
                self._sync_directory(self.root)
                self._fault("rollover_after_directory_sync")
                self._active_fd = os.open(self.active_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
                os.fsync(self._active_fd)
                self._fault("rollover_after_new_active_sync")
                self._sync_directory(self.root)
                self._fault("rollover_after_new_active_publish")
                index = self.index_root / f"{target.stem}.sidx"
                value = {"schema": "SITINA_SEGMENT_INDEX_V1", "segment": target.name, "segment_sha256": digest.hexdigest(), "last_position": self.head_position}
                raw_index = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                index_descriptor = os.open(
                    index,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                with os.fdopen(index_descriptor, "wb") as handle:
                    handle.write(raw_index)
                    handle.flush()
                    os.fsync(handle.fileno())
                self._sync_directory(self.index_root)
                self._fault("rollover_after_index_build")
                self._active_first_position = self.head_position
                return target
            except BaseException as error:
                self.poisoned_reason = f"rollover requires recovery: {type(error).__name__}: {error}"
                self.writer_lock.poison(self.poisoned_reason)
                raise

    def close(self) -> None:
        try:
            coordinator = getattr(self, "rollover_coordinator", None)
            if coordinator is not None:
                # Never release the fixed writer-lock inode while an
                # asynchronous rollover/checkpoint still owns Journal state.
                # Status polling may use bounded waits; close is the ownership
                # boundary and must wait for a definite outcome.
                coordinator.wait(timeout=None)
            if getattr(self, "_active_fd", -1) >= 0:
                os.close(self._active_fd)
                self._active_fd = -1
        finally:
            self.writer_lock.close()

    def __enter__(self) -> "LocalJournal":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()
