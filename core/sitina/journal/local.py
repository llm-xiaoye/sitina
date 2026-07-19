from __future__ import annotations

import errno
import hashlib
import json
import os
import threading
import time
import uuid
from types import SimpleNamespace
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from sitina.cas.gc import GCController, ReferenceLease
from sitina.cas.model import CASError, ExistingDurableObjectRootProof, ObjectRef, PublishedObjectReceipt
from sitina.commands.model import CommandEnvelope, CommandResult, CommandStatus
from sitina.security.key_provider import JournalAuthProvider

from .codec import DecodedFrame, encode_frame
from .locks import WriterLock, WriterLockError
from .model import AppendReceipt, EventEnvelope, FrontierRef, JournalModelError, JournalTransaction
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
        genesis_hash: str | None,
        fast_start_report: object | None,
        rollover_coordinator: object | None,
    ):
        self.home = home.resolve(strict=True)
        self._operational_capability = operational_capability
        self._authority_resolution = authority_resolution
        self.genesis_hash = genesis_hash
        self.fast_start_report = fast_start_report
        self.rollover_coordinator = rollover_coordinator
        production_namespace = namespace_kind in {"production", "production_simulation"}
        if production_namespace:
            self._authorize_production_open(namespace_kind)
        else:
            if self.home == Path("/Users/moss/SitinaHub"):
                raise LocalJournalError("Production Journal requires a Phase 6B or resolved runtime capability")
            if namespace_kind not in {"shadow", "controlled_fixture"}:
                raise LocalJournalError("Journal namespace must be shadow, controlled_fixture, or manifest-bound Production")
            marker = ".sitina-bplus-shadow-v1" if namespace_kind == "shadow" else ".sitina-bplus-disposable-v1"
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
            if self.home == Path("/Users/moss/SitinaHub") or not (self.home / ".sitina-bplus-disposable-v1").is_file():
                raise LocalJournalError("Production simulation requires a disposable non-Production root")
        elif self.home != Path("/Users/moss/SitinaHub"):
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
        genesis_hash: str | None = None,
        fast_start_report: object | None = None,
        rollover_coordinator: object | None = None,
    ) -> "LocalJournal":
        return cls(
            Path(home), authenticator, journal_id=journal_id, epoch=epoch, namespace_kind=namespace_kind,
            gc_controller=gc_controller, fault_injector=fault_injector,
            operational_capability=operational_capability, authority_resolution=authority_resolution,
            genesis_hash=genesis_hash,
            fast_start_report=fast_start_report,
            rollover_coordinator=rollover_coordinator,
        )

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
        self._head_position = int(state.head_position)
        os.lseek(self._active_fd, 0, os.SEEK_END)

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

    def append(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        events: Sequence[EventEnvelope],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> AppendReceipt:
        with self._mutex:
            self._assert_healthy()
            self._assert_production_append_authorized(command)
            request_hash = command.command_request_hash
            existing = self._commands.get(command.command_id)
            if existing:
                if existing[0] != request_hash:
                    raise CommandConflict("same Command ID is bound to a different request hash")
                return existing[1]
            if self._stream_heads.get(command.stream_id, 0) != expected_stream_version:
                raise ExpectedStreamVersionConflict("expected Stream Version does not match canonical head")
            if not events:
                raise LocalJournalError("append requires at least one event")
            if any(event.stream_id != command.stream_id or event.tenant_id != command.tenant_id for event in events):
                raise LocalJournalError("all events must belong to the command tenant and one logical stream")
            if any(event.event_hash is not None for event in events):
                raise LocalJournalError("caller may not submit pre-sealed events")
            references = tuple(sorted({reference for event in events for reference in event.object_refs}))
            object_refs = self._validate_proofs(references, object_reference_proofs)
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
                transaction = JournalTransaction(
                    f"tx-{uuid.uuid4().hex}", command.command_id, request_hash, command.stream_id, assigned, references
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
                self._stream_heads[command.stream_id] = receipt.last_stream_version
                self._events.extend(assigned)
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
