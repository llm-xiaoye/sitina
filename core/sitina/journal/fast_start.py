from __future__ import annotations

import hashlib
import datetime as dt
import json
import os
import struct
import uuid
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from sitina.journal.model import (
    EventEnvelope,
    canonical_json_bytes,
    event_replay_projection,
    event_replay_projection_hash,
    proof_manifest_hash,
)
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.security.key_provider import InMemoryKeyProvider, KeyPurpose, JournalAuthProvider
from sitina.security.macos_keychain import KeychainBackend, MemoryKeychainBackend

from .recovery import scan_active_segment_read_only, scan_sealed_segment


class FastStartError(RuntimeError):
    pass


class AuthorityIntegrityError(FastStartError):
    pass


class RollbackDetected(AuthorityIntegrityError):
    pass


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    payload = canonical_json_bytes(dict(value)) + b"\n"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short authority metadata write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _sync_directory(path.parent)


def _signed(
    unsigned: Mapping[str, Any],
    provider: InMemoryKeyProvider,
) -> dict[str, Any]:
    message = canonical_json_bytes(dict(unsigned))
    key_id, signature = provider.sign(KeyPurpose.AUTHORITY_SIGNING, message)
    return {**dict(unsigned), "auth_key_id": key_id, "auth_tag": signature.hex()}


def _verify_signed(
    value: Mapping[str, Any],
    provider: InMemoryKeyProvider,
) -> None:
    key_id = value.get("auth_key_id")
    tag = value.get("auth_tag")
    if not isinstance(key_id, str) or not isinstance(tag, str):
        raise AuthorityIntegrityError("authority signature is missing")
    try:
        signature = bytes.fromhex(tag)
    except ValueError as error:
        raise AuthorityIntegrityError("authority signature is malformed") from error
    unsigned = {key: item for key, item in value.items() if key not in {"auth_key_id", "auth_tag"}}
    if not provider.verify(key_id, KeyPurpose.AUTHORITY_SIGNING, canonical_json_bytes(unsigned), signature):
        raise AuthorityIntegrityError("authority signature verification failed")


def _commitment(value: Mapping[str, Any]) -> str:
    return _sha(canonical_json_bytes(dict(value)))


@dataclass(frozen=True)
class RolloverPolicy:
    max_active_bytes: int = 128 * 1024 * 1024
    max_active_events: int = 100_000
    max_startup_scan_ms: int = 500

    def reason(self, *, active_bytes: int, active_events: int, startup_scan_ms: int) -> str | None:
        if active_bytes >= self.max_active_bytes:
            return "active-bytes"
        if active_events >= self.max_active_events:
            return "active-events"
        if startup_scan_ms > self.max_startup_scan_ms:
            return "startup-scan-latency"
        return None


class AutomaticRolloverCoordinator:
    """Schedule rollover+certificate+checkpoint off the append acknowledgement path."""

    def __init__(
        self,
        maintainer: "JournalFastStartMaintainer",
        *,
        policy: RolloverPolicy,
        checkpoint_context: Callable[[str], Mapping[str, Any]],
    ):
        self.maintainer = maintainer
        self.policy = policy
        self.checkpoint_context = checkpoint_context
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.last_reason: str | None = None
        self.last_error: BaseException | None = None

    def consider(self, journal: Any, *, startup_scan_ms: int = 0) -> str | None:
        active_bytes = os.fstat(journal._active_fd).st_size
        active_events = sum(1 for event in journal._events if event.position > getattr(journal, "_active_first_position", 0))
        reason = self.policy.reason(
            active_bytes=active_bytes,
            active_events=active_events,
            startup_scan_ms=startup_scan_ms,
        )
        if reason is None:
            return None
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return reason
            self.last_reason = reason
            self.last_error = None
            self._thread = threading.Thread(
                target=self._run,
                args=(journal, reason),
                name="sitina-journal-rollover",
                daemon=True,
            )
            self._thread.start()
        return reason

    def _run(self, journal: Any, reason: str) -> None:
        try:
            values = dict(self.checkpoint_context(reason))
            self.maintainer.rollover_and_checkpoint(journal, **values)
        except BaseException as error:  # surfaced through wait/status, never masks the append receipt
            self.last_error = error

    def wait(self, timeout: float | None = 5.0) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive():
                raise TimeoutError("automatic Journal rollover did not finish")
        if self.last_error is not None:
            raise FastStartError(f"automatic Journal rollover failed: {self.last_error}") from self.last_error


class AuthorityClockGuard:
    """Detect wall-clock rollback while ordering and lease age use monotonic progress."""

    def __init__(self) -> None:
        self._last_wall: dt.datetime | None = None
        self._last_monotonic_ns: int | None = None
        self._conservative_wall: dt.datetime | None = None

    def observe(self, *, wall_utc: str, monotonic_ns: int) -> dict[str, Any] | None:
        wall = dt.datetime.fromisoformat(wall_utc.replace("Z", "+00:00"))
        if wall.tzinfo is None or monotonic_ns < 0:
            raise FastStartError("invalid authority clock sample")
        if self._last_monotonic_ns is not None and monotonic_ns < self._last_monotonic_ns:
            raise FastStartError("monotonic clock moved backwards inside one process")
        anomaly = self._last_wall is not None and wall < self._last_wall
        previous_wall = self._last_wall
        self._last_wall = wall
        self._last_monotonic_ns = monotonic_ns
        self._conservative_wall = max(filter(None, (self._conservative_wall, wall)))
        if not anomaly:
            return None
        return {
            "schema": "CLOCK_ANOMALY_DETECTED_V1",
            "event_type": "clock.anomaly-detected",
            "previous_wall_utc": previous_wall.isoformat().replace("+00:00", "Z"),
            "observed_wall_utc": wall_utc,
            "monotonic_ns": monotonic_ns,
            "writer_permission_extended": False,
        }

    @property
    def conservative_wall_utc(self) -> str:
        if self._conservative_wall is None:
            raise FastStartError("authority clock has no sample")
        return self._conservative_wall.isoformat().replace("+00:00", "Z")


class JournalEpochTransition:
    @staticmethod
    def create(
        provider: InMemoryKeyProvider,
        *,
        journal_id: str,
        old_epoch: int,
        previous_segment_commitment: str,
        effective_position: int,
        policy_hash: str,
    ) -> dict[str, Any]:
        if old_epoch < 1 or effective_position < 1 or len(previous_segment_commitment) != 64 or len(policy_hash) != 64:
            raise FastStartError("invalid Journal epoch transition boundary")
        old = provider.current_descriptor(KeyPurpose.AUTHORITY_SIGNING)
        new = provider.rotate(KeyPurpose.AUTHORITY_SIGNING)
        unsigned = {
            "schema": "JOURNAL_EPOCH_TRANSITION_V1",
            "journal_id": journal_id,
            "old_epoch": old_epoch,
            "new_epoch": old_epoch + 1,
            "previous_segment_commitment": previous_segment_commitment,
            "effective_position": effective_position,
            "policy_hash": policy_hash,
            "old_authority_key_id": old.key_id,
            "new_authority_key_id": new.key_id,
        }
        message = canonical_json_bytes(unsigned)
        return {
            **unsigned,
            "old_authority_proof": provider.sign_with_key_id(old.key_id, KeyPurpose.AUTHORITY_SIGNING, message).hex(),
            "new_authority_proof": provider.sign_with_key_id(new.key_id, KeyPurpose.AUTHORITY_SIGNING, message).hex(),
        }

    @staticmethod
    def verify(provider: InMemoryKeyProvider, value: Mapping[str, Any]) -> bool:
        proofs = {"old_authority_proof", "new_authority_proof"}
        unsigned = {key: item for key, item in value.items() if key not in proofs}
        try:
            return provider.verify(
                str(value["old_authority_key_id"]),
                KeyPurpose.AUTHORITY_SIGNING,
                canonical_json_bytes(unsigned),
                bytes.fromhex(str(value["old_authority_proof"])),
            ) and provider.verify(
                str(value["new_authority_key_id"]),
                KeyPurpose.AUTHORITY_SIGNING,
                canonical_json_bytes(unsigned),
                bytes.fromhex(str(value["new_authority_proof"])),
            )
        except Exception:
            return False


@dataclass(frozen=True)
class MerkleBlockIndex:
    segment_name: str
    block_size: int
    segment_size: int
    block_hashes: tuple[str, ...]
    merkle_root: str

    @staticmethod
    def _leaf(raw: bytes) -> str:
        return _sha(b"SITINA_MERKLE_BLOCK_V1\0" + raw)

    @staticmethod
    def _parent(left: str, right: str) -> str:
        return _sha(b"SITINA_MERKLE_NODE_V1\0" + bytes.fromhex(left) + bytes.fromhex(right))

    @classmethod
    def build(cls, path: Path, *, block_size: int = 1024 * 1024) -> "MerkleBlockIndex":
        if block_size < 4096:
            raise ValueError("Merkle block size is too small")
        hashes: list[str] = []
        size = 0
        with path.open("rb") as handle:
            while block := handle.read(block_size):
                size += len(block)
                hashes.append(cls._leaf(block))
        if not hashes:
            raise AuthorityIntegrityError("sealed segment cannot be empty")
        return cls(path.name, block_size, size, tuple(hashes), cls._root(hashes))

    @classmethod
    def _root(cls, hashes: Sequence[str]) -> str:
        level = list(hashes)
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [cls._parent(level[index], level[index + 1]) for index in range(0, len(level), 2)]
        return level[0]

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_SEGMENT_MERKLE_INDEX_V1",
            "segment_name": self.segment_name,
            "block_size": self.block_size,
            "segment_size": self.segment_size,
            "block_hashes": list(self.block_hashes),
            "merkle_root": self.merkle_root,
        }

    @classmethod
    def load(cls, path: Path) -> "MerkleBlockIndex":
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "SITINA_SEGMENT_MERKLE_INDEX_V1":
            raise AuthorityIntegrityError("unsupported Merkle index")
        result = cls(
            value["segment_name"],
            int(value["block_size"]),
            int(value["segment_size"]),
            tuple(value["block_hashes"]),
            value["merkle_root"],
        )
        if not result.block_hashes or result._root(result.block_hashes) != result.merkle_root:
            raise AuthorityIntegrityError("Merkle index root mismatch")
        return result

    def proof(self, block_number: int) -> tuple[tuple[str, str], ...]:
        if not 0 <= block_number < len(self.block_hashes):
            raise IndexError("Merkle block number is outside the segment")
        proof: list[tuple[str, str]] = []
        index = block_number
        level = list(self.block_hashes)
        while len(level) > 1:
            original_length = len(level)
            if original_length % 2:
                level.append(level[-1])
            sibling = index - 1 if index % 2 else index + 1
            proof.append(("left" if index % 2 else "right", level[sibling]))
            level = [self._parent(level[position], level[position + 1]) for position in range(0, len(level), 2)]
            index //= 2
        return tuple(proof)

    def verify_block(self, block_number: int, block: bytes, proof: Sequence[tuple[str, str]]) -> bool:
        if not 0 <= block_number < len(self.block_hashes):
            return False
        current = self._leaf(block)
        for side, sibling in proof:
            current = self._parent(sibling, current) if side == "left" else self._parent(current, sibling)
        return current == self.merkle_root


@dataclass(frozen=True)
class AuthorityState:
    journal_id: str
    epoch: int
    head_position: int
    last_transaction_hash: str
    stream_heads: tuple[tuple[str, int], ...]
    command_bindings: tuple[tuple[str, str, str, int], ...]
    active_roots: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class FastStartReport:
    authority_state: AuthorityState
    fast_start_checkpoint_used: bool
    journal_bytes_scanned: int
    journal_events_verified: int
    sealed_segment_count: int
    active_tail_event_count: int
    checkpoint_commitment: str
    verified_through_position: int = 0
    command_receipts: tuple[dict[str, Any], ...] = ()
    authority_control_events: tuple[Any, ...] = ()
    active_tail_events: tuple[Any, ...] = ()
    active_roots_snapshot: tuple[dict[str, Any], ...] = ()
    active_roots_index_commitment: str | None = None
    semantic_active_roots_commitment: str | None = None
    # Populated only by the explicit full verifier.  Fast-start loaders must
    # leave this empty so default reads cannot accidentally retain history.
    verified_events: tuple[Any, ...] = ()


class RollbackAnchorStore:
    SERVICE = "com.sitina.journal.rollback-anchor.v1"

    def __init__(self, backend: KeychainBackend, *, journal_id: str):
        self.backend = backend
        self.journal_id = journal_id
        self.account = hashlib.sha256(journal_id.encode()).hexdigest()

    def read(self) -> dict[str, Any] | None:
        raw = self.backend.get(self.SERVICE, self.account)
        if raw is None:
            return None
        value = json.loads(raw)
        if value.get("schema") != "SITINA_JOURNAL_ROLLBACK_ANCHOR_V1" or value.get("journal_id") != self.journal_id:
            raise RollbackDetected("Keychain rollback anchor is malformed or foreign")
        return value

    def update(
        self,
        *,
        latest_epoch: int,
        latest_checkpoint_sequence: int,
        latest_checkpoint_commitment: str,
        active_format_capabilities_hash: str,
    ) -> dict[str, Any]:
        current = self.read()
        if current:
            old = (int(current["latest_epoch"]), int(current["latest_checkpoint_sequence"]))
            new = (latest_epoch, latest_checkpoint_sequence)
            if new < old:
                raise RollbackDetected("refusing to move rollback anchor backwards")
            if new == old and current["latest_checkpoint_commitment"] != latest_checkpoint_commitment:
                raise RollbackDetected("checkpoint identity changed at an anchored sequence")
        value = {
            "schema": "SITINA_JOURNAL_ROLLBACK_ANCHOR_V1",
            "journal_id": self.journal_id,
            "latest_epoch": latest_epoch,
            "latest_checkpoint_sequence": latest_checkpoint_sequence,
            "latest_checkpoint_commitment": latest_checkpoint_commitment,
            "active_format_capabilities_hash": active_format_capabilities_hash,
        }
        self.backend.put(self.SERVICE, self.account, canonical_json_bytes(value), replace=current is not None)
        return value

    def force_test_anchor(self, **values: Any) -> None:
        if not isinstance(self.backend, MemoryKeychainBackend):
            raise PermissionError("force_test_anchor is limited to the in-memory test Keychain")
        value = {"schema": "SITINA_JOURNAL_ROLLBACK_ANCHOR_V1", "journal_id": self.journal_id, **values}
        self.backend.put(self.SERVICE, self.account, canonical_json_bytes(value), replace=self.read() is not None)


@dataclass(frozen=True)
class _SegmentCertificate:
    value: dict[str, Any]

    @property
    def commitment(self) -> str:
        return _commitment(self.value)

    @property
    def first_position(self) -> int:
        return int(self.value["first_position"])

    @property
    def last_position(self) -> int:
        return int(self.value["last_position"])


def _certificate_values(root: Path, provider: InMemoryKeyProvider) -> tuple[_SegmentCertificate, ...]:
    values: list[_SegmentCertificate] = []
    for path in (root / "journal" / "certificates").glob("*.certificate.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "SITINA_SEALED_SEGMENT_CERTIFICATE_V1":
            raise AuthorityIntegrityError("unknown sealed segment certificate")
        _verify_signed(value, provider)
        values.append(_SegmentCertificate(value))
    values.sort(key=lambda item: item.first_position)
    expected_position = 1
    previous = "0" * 64
    for item in values:
        if item.first_position != expected_position:
            raise AuthorityIntegrityError("sealed certificate chain has a position gap")
        if item.value["previous_segment_commitment"] != previous:
            raise AuthorityIntegrityError("sealed certificate commitment chain is broken")
        segment = root / "journal" / "sealed" / item.value["segment_name"]
        if not segment.is_file() or segment.is_symlink() or segment.stat().st_size != item.value["segment_size"]:
            raise AuthorityIntegrityError("certified sealed segment is missing or has the wrong size")
        merkle_path = root / "journal" / "indexes" / (item.value["segment_name"] + ".merkle.json")
        merkle = MerkleBlockIndex.load(merkle_path)
        if merkle.segment_size != item.value["segment_size"] or merkle.merkle_root != item.value["segment_merkle_root"]:
            raise AuthorityIntegrityError("certified Merkle index does not match the segment")
        expected_position = item.last_position + 1
        previous = item.commitment
    return tuple(values)


def _sealed_manifest_root(certificates: Sequence[_SegmentCertificate]) -> str:
    return _sha(
        canonical_json_bytes(
            [
                {"segment_name": item.value["segment_name"], "certificate_commitment": item.commitment}
                for item in certificates
            ]
        )
    )


def _state_from_frames(
    frames: Iterable[Any],
    *,
    journal_id: str,
    epoch: int,
    authenticator: JournalAuthProvider,
    base_position: int = 0,
    base_transaction_hash: str = "0" * 64,
    stream_heads: Mapping[str, int] | None = None,
    command_bindings: Mapping[str, tuple[str, str, int]] | None = None,
    active_roots: Mapping[str, int] | None = None,
) -> tuple[AuthorityState, int]:
    streams = dict(stream_heads or {})
    commands = dict(command_bindings or {})
    roots = dict(active_roots or {})
    position = base_position
    last_hash = base_transaction_hash
    verified = 0
    for frame in frames:
        transaction = frame.transaction
        if transaction.first_position != position + 1:
            raise AuthorityIntegrityError("Journal transaction positions are not continuous")
        expected_stream = streams.get(transaction.stream_id, 0) + 1
        if transaction.first_stream_version != expected_stream:
            raise AuthorityIntegrityError("Journal stream versions are not continuous")
        for event in transaction.events:
            if not event.verify(journal_id=journal_id, epoch=epoch, authenticator=authenticator):
                raise AuthorityIntegrityError("Journal event authentication failed")
            verified += 1
        existing = commands.get(transaction.command_id)
        binding = (transaction.command_request_hash, frame.transaction_hash, transaction.last_position)
        if existing is not None and existing != binding:
            raise AuthorityIntegrityError("Command identity collision in canonical Journal")
        commands[transaction.command_id] = binding
        streams[transaction.stream_id] = transaction.last_stream_version
        position = transaction.last_position
        last_hash = frame.transaction_hash
    state = AuthorityState(
        journal_id,
        epoch,
        position,
        last_hash,
        tuple(sorted(streams.items())),
        tuple(sorted((command_id, *binding) for command_id, binding in commands.items())),
        tuple(sorted(roots.items())),
    )
    return state, verified


class JournalFastStartMaintainer:
    def __init__(
        self,
        home: str | Path,
        *,
        journal_authenticator: JournalAuthProvider,
        authority_key_provider: InMemoryKeyProvider,
        rollback_anchor: RollbackAnchorStore,
        schema_registry_hash: str,
        feature_activations: FeatureActivationRegistry | None = None,
    ):
        self.home = Path(home).resolve(strict=True)
        self.authenticator = journal_authenticator
        self.provider = authority_key_provider
        self.anchor = rollback_anchor
        self.schema_registry_hash = schema_registry_hash
        self.feature_activations = feature_activations
        for name in ("certificates", "checkpoints", "indexes"):
            (self.home / "journal" / name).mkdir(parents=True, exist_ok=True)

    def _latest_sequence(self) -> int:
        paths = sorted((self.home / "journal/checkpoints").glob("checkpoint-*.json"))
        if not paths:
            return 0
        value = json.loads(paths[-1].read_text(encoding="utf-8"))
        return int(value["checkpoint_sequence"])

    def _write_index(self, kind: str, data: Any) -> str:
        value = {"schema": "SITINA_AUTHORITY_INDEX_CHUNK_V1", "kind": kind, "data": data}
        commitment = _commitment(value)
        path = self.home / "journal/indexes" / f"authority-{kind}-{commitment}.json"
        if not path.exists():
            _atomic_json(path, value)
        return commitment

    def _certificate(self, segment: Path, journal: Any, *, verified_at: str) -> _SegmentCertificate:
        scan = scan_sealed_segment(segment)
        if not scan.frames:
            raise AuthorityIntegrityError("cannot certify an empty sealed segment")
        for frame in scan.frames:
            for event in frame.transaction.events:
                if not event.verify(journal_id=journal.journal_id, epoch=journal.epoch, authenticator=self.authenticator):
                    raise AuthorityIntegrityError("full pre-certificate Journal authentication failed")
        raw_digest = hashlib.sha256()
        with segment.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                raw_digest.update(chunk)
        merkle = MerkleBlockIndex.build(segment)
        _atomic_json(
            self.home / "journal/indexes" / (segment.name + ".merkle.json"),
            merkle.mapping(),
        )
        previous_certificates = _certificate_values(self.home, self.provider)
        previous = previous_certificates[-1].commitment if previous_certificates else "0" * 64
        first = scan.frames[0]
        last = scan.frames[-1]
        unsigned = {
            "schema": "SITINA_SEALED_SEGMENT_CERTIFICATE_V1",
            "journal_id": journal.journal_id,
            "epoch": journal.epoch,
            "segment_name": segment.name,
            "segment_size": segment.stat().st_size,
            "segment_sha256": raw_digest.hexdigest(),
            "segment_merkle_root": merkle.merkle_root,
            "previous_segment_commitment": previous,
            "first_position": first.transaction.first_position,
            "last_position": last.transaction.last_position,
            "first_transaction_hash": first.transaction_hash,
            "last_transaction_hash": last.transaction_hash,
            "event_count": sum(len(frame.transaction.events) for frame in scan.frames),
            "schema_registry_hash": self.schema_registry_hash,
            "verified_at": verified_at,
        }
        value = _signed(unsigned, self.provider)
        path = self.home / "journal/certificates" / (segment.name + ".certificate.json")
        _atomic_json(path, value)
        return _SegmentCertificate(value)

    def rollover_and_checkpoint(
        self,
        journal: Any,
        *,
        created_at: str,
        verified_at: str,
        authority_control_state_hash: str,
        active_format_capabilities_hash: str,
        fencing_state_hash: str,
        minimum_writer_version: str,
        rollback_floor_version: str,
        active_roots: Mapping[str, int] | None = None,
        semantic_active_roots: Sequence[Mapping[str, Any]] | None = None,
        semantic_active_roots_builder: Callable[[int], Sequence[Mapping[str, Any]]] | None = None,
    ) -> dict[str, Any]:
        genesis_path = self.home / "state/bplus-production-genesis/genesis.json"
        if genesis_path.is_file():
            try:
                protected = json.loads(genesis_path.read_text(encoding="utf-8")).get("environment_kind") in {
                    "PRODUCTION",
                    "CONTROLLED_PRODUCTION_SIMULATION",
                }
            except Exception as error:
                raise FastStartError("Production Genesis is unreadable before Authority Checkpoint write") from error
            if protected:
                if self.feature_activations is None:
                    raise FastStartError("Authority Checkpoint writer has no verified Journal feature activation state")
                self.feature_activations.assert_write_enabled("authority_checkpoint_v1_write")
        segment = journal.rollover()
        if segment is None:
            raise FastStartError("rollover requires a non-empty active segment")
        self._certificate(segment, journal, verified_at=verified_at)
        certificates = _certificate_values(self.home, self.provider)
        last = certificates[-1]
        sealed_frontier = last.last_position
        previous_command_values: Mapping[str, Any] = {}
        checkpoint_paths = sorted((self.home / "journal/checkpoints").glob("checkpoint-*.json"))
        if checkpoint_paths:
            previous_checkpoint, _previous_commitment = _latest_checkpoint(self.home, self.provider)
            previous_command_values = _load_index(
                self.home,
                "command-idempotency",
                str(previous_checkpoint["command_idempotency_index_commitment"]),
            )
        commands = {
            command_id: {
                "request_hash": request_hash,
                "transaction_id": receipt.transaction_id,
                "transaction_hash": receipt.transaction_hash,
                "stream_id": receipt.stream_id,
                "first_position": receipt.first_position,
                "last_position": receipt.last_position,
                "first_stream_version": receipt.first_stream_version,
                "last_stream_version": receipt.last_stream_version,
                "object_reference_manifest_hash": receipt.object_reference_manifest_hash,
                "object_refs": [],
                "proof_manifest": [
                    dict(item) for item in getattr(
                        getattr(journal, "_transactions", {}).get(command_id), "proof_manifest", ()
                    )
                ],
                "proof_manifest_hash": proof_manifest_hash([
                    dict(item) for item in getattr(
                        getattr(journal, "_transactions", {}).get(command_id), "proof_manifest", ()
                    )
                ]),
                "authenticated_seal_stream_id": (
                    receipt.stream_id
                    if command_id in getattr(journal, "_authenticated_seal_command_ids", set())
                    else None
                ),
            }
            for command_id, (request_hash, receipt) in journal._commands.items()
            if receipt.last_position <= sealed_frontier
        }
        for _command_id, value in commands.items():
            projection = [
                event_replay_projection(event)
                for event in journal._events
                if (
                    event.stream_id == value["stream_id"]
                    and value["first_position"] <= event.position <= value["last_position"]
                )
            ]
            value["event_projection"] = projection
            value["event_projection_hash"] = event_replay_projection_hash(projection)
            expected_count = int(value["last_position"]) - int(value["first_position"]) + 1
            if len(projection) != expected_count:
                previous = previous_command_values.get(_command_id)
                previous_projection = previous.get("event_projection") if isinstance(previous, Mapping) else None
                previous_hash = previous.get("event_projection_hash") if isinstance(previous, Mapping) else None
                if (
                    not isinstance(previous_projection, list)
                    or len(previous_projection) != expected_count
                    or previous_hash != event_replay_projection_hash(previous_projection)
                ):
                    raise FastStartError(
                        "cannot checkpoint a historical command without its authenticated event projection"
                    )
                value["event_projection"] = [dict(item) for item in previous_projection]
                value["event_projection_hash"] = str(previous_hash)
        stream_heads: dict[str, int] = {}
        for value in commands.values():
            stream_id = str(value["stream_id"])
            stream_heads[stream_id] = max(stream_heads.get(stream_id, 0), int(value["last_stream_version"]))
        # Bind historical ObjectRef roots to their transaction receipts without
        # copying any CAS body.  A command can own zero or more references.
        references_by_transaction: dict[str, list[str]] = {}
        for reference_id, (_object_ref, frame) in journal._object_roots.items():
            if frame.transaction.last_position <= sealed_frontier:
                references_by_transaction.setdefault(frame.transaction_hash, []).append(reference_id)
        for value in commands.values():
            value["object_refs"] = sorted(references_by_transaction.get(str(value["transaction_hash"]), ()))
        # Fast Start must retain every event required to reconstruct durable
        # writer/reader compatibility state, not only the Phase 6B cutover
        # Stream.  Feature transitions are small control-plane facts; omitting
        # them makes an activated writer appear disabled after rollover.
        control_events = [
            event.stored_mapping()
            for event in journal._events
            if (
                event.stream_id == "authority/control"
                or event.event_type in {"runtime.feature-prepared", "runtime.feature-activated"}
            )
            and event.position <= sealed_frontier
        ]
        control_commitment = self._write_index("authority-control", control_events)
        root_sources = sum(item is not None for item in (active_roots, semantic_active_roots, semantic_active_roots_builder))
        if root_sources > 1:
            raise FastStartError("legacy and semantic active-root snapshots are mutually exclusive")
        if semantic_active_roots_builder is not None:
            semantic_active_roots = semantic_active_roots_builder(last.last_position)
        if semantic_active_roots is not None:
            snapshot = [dict(item) for item in semantic_active_roots]
            snapshot.sort(key=lambda item: (str(item.get("root_type")), str(item.get("root_id")), str(item.get("object_ref"))))
            required = {"root_type", "root_id", "object_ref", "source_position", "source_event_id", "schema_version"}
            if any(set(item) != required for item in snapshot):
                raise FastStartError("semantic active-root snapshot contains an unknown or missing field")
            roots: Any = {"schema": "SITINA_ACTIVE_ROOTS_INDEX_V1", "roots": snapshot}
        else:
            roots = dict(active_roots or {})
        stream_commitment = self._write_index("stream-heads", stream_heads)
        command_commitment = self._write_index("command-idempotency", commands)
        roots_commitment = self._write_index("active-roots", roots)
        sequence = self._latest_sequence() + 1
        unsigned = {
            "schema": "SITINA_AUTHORITY_CHECKPOINT_V1",
            "journal_id": journal.journal_id,
            "epoch": journal.epoch,
            "genesis_hash": journal.genesis_hash or "0" * 64,
            "checkpoint_sequence": sequence,
            "verified_through_position": last.last_position,
            "last_transaction_hash": last.value["last_transaction_hash"],
            "sealed_manifest_root": _sealed_manifest_root(certificates),
            "authority_control_state_hash": control_commitment,
            "stream_heads_index_commitment": stream_commitment,
            "command_idempotency_index_commitment": command_commitment,
            "active_roots_index_commitment": roots_commitment,
            "schema_registry_hash": self.schema_registry_hash,
            "fencing_state_hash": fencing_state_hash,
            "minimum_writer_version": minimum_writer_version,
            "rollback_floor_version": rollback_floor_version,
            "created_at": created_at,
        }
        checkpoint = _signed(unsigned, self.provider)
        checkpoint_path = self.home / "journal/checkpoints" / f"checkpoint-{sequence:020d}.json"
        _atomic_json(checkpoint_path, checkpoint)
        checkpoint_commitment = _commitment(checkpoint)
        self.anchor.update(
            latest_epoch=journal.epoch,
            latest_checkpoint_sequence=sequence,
            latest_checkpoint_commitment=checkpoint_commitment,
            active_format_capabilities_hash=active_format_capabilities_hash,
        )
        return checkpoint


def _latest_checkpoint(home: Path, provider: InMemoryKeyProvider) -> tuple[dict[str, Any], str]:
    paths = sorted((home / "journal/checkpoints").glob("checkpoint-*.json"))
    if not paths:
        raise AuthorityIntegrityError("Authority Checkpoint is unavailable")
    checkpoint = json.loads(paths[-1].read_text(encoding="utf-8"))
    allowed = {
        "schema",
        "journal_id",
        "epoch",
        "genesis_hash",
        "checkpoint_sequence",
        "verified_through_position",
        "last_transaction_hash",
        "sealed_manifest_root",
        "authority_control_state_hash",
        "stream_heads_index_commitment",
        "command_idempotency_index_commitment",
        "active_roots_index_commitment",
        "schema_registry_hash",
        "fencing_state_hash",
        "minimum_writer_version",
        "rollback_floor_version",
        "created_at",
        "auth_key_id",
        "auth_tag",
    }
    if set(checkpoint) != allowed or checkpoint.get("schema") != "SITINA_AUTHORITY_CHECKPOINT_V1":
        raise AuthorityIntegrityError("Authority Checkpoint schema boundary was violated")
    _verify_signed(checkpoint, provider)
    return checkpoint, _commitment(checkpoint)


def _load_index(home: Path, kind: str, commitment: str) -> Any:
    path = home / "journal/indexes" / f"authority-{kind}-{commitment}.json"
    if not path.is_file() or path.is_symlink():
        raise AuthorityIntegrityError(f"Authority {kind} index is missing")
    value = json.loads(path.read_text(encoding="utf-8"))
    if _commitment(value) != commitment or value.get("kind") != kind or value.get("schema") != "SITINA_AUTHORITY_INDEX_CHUNK_V1":
        raise AuthorityIntegrityError(f"Authority {kind} index commitment mismatch")
    return value["data"]


def _decode_active_roots(value: Any) -> tuple[dict[str, int], tuple[dict[str, Any], ...], str | None]:
    if isinstance(value, Mapping) and value.get("schema") == "SITINA_ACTIVE_ROOTS_INDEX_V1":
        roots = value.get("roots")
        if not isinstance(roots, list) or any(not isinstance(item, Mapping) for item in roots):
            raise AuthorityIntegrityError("semantic active-roots index is malformed")
        snapshot = tuple(dict(item) for item in roots)
        if list(snapshot) != sorted(snapshot, key=lambda item: (str(item.get("root_type")), str(item.get("root_id")), str(item.get("object_ref")))):
            raise AuthorityIntegrityError("semantic active-roots index is not canonical")
        state_roots: dict[str, int] = {}
        for item in snapshot:
            reference = str(item.get("object_ref", ""))
            position = int(item.get("source_position", -1))
            if not reference.startswith("cas:") or position < 0:
                raise AuthorityIntegrityError("semantic active-roots entry is invalid")
            state_roots[reference] = max(state_roots.get(reference, 0), position)
        return state_roots, snapshot, hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()
    if not isinstance(value, Mapping):
        raise AuthorityIntegrityError("legacy active-roots index is malformed")
    return {str(key): int(item) for key, item in value.items()}, (), None


class FastStartLoader:
    def __init__(
        self,
        home: str | Path,
        *,
        journal_authenticator: JournalAuthProvider,
        authority_key_provider: InMemoryKeyProvider,
        rollback_anchor: RollbackAnchorStore,
        sealed_segment_read_observer: Callable[[Path], None] | None = None,
    ):
        self.home = Path(home).resolve(strict=True)
        self.authenticator = journal_authenticator
        self.provider = authority_key_provider
        self.anchor = rollback_anchor
        self.sealed_segment_read_observer = sealed_segment_read_observer

    def load(self) -> FastStartReport:
        checkpoint, checkpoint_commitment = _latest_checkpoint(self.home, self.provider)
        anchor = self.anchor.read()
        if anchor is None:
            raise RollbackDetected("Keychain rollback anchor is unavailable")
        disk = (int(checkpoint["epoch"]), int(checkpoint["checkpoint_sequence"]))
        anchored = (int(anchor["latest_epoch"]), int(anchor["latest_checkpoint_sequence"]))
        if disk < anchored:
            raise RollbackDetected("ROLLBACK_DETECTED: disk checkpoint is behind Keychain")
        if disk == anchored and anchor["latest_checkpoint_commitment"] != checkpoint_commitment:
            raise RollbackDetected("ROLLBACK_DETECTED: checkpoint commitment differs from Keychain")
        certificates = _certificate_values(self.home, self.provider)
        if not certificates:
            raise AuthorityIntegrityError("Authority Checkpoint has no certified segment prefix")
        if _sealed_manifest_root(certificates) != checkpoint["sealed_manifest_root"]:
            raise AuthorityIntegrityError("sealed manifest root differs from Authority Checkpoint")
        last = certificates[-1]
        if last.last_position != checkpoint["verified_through_position"] or last.value["last_transaction_hash"] != checkpoint["last_transaction_hash"]:
            raise AuthorityIntegrityError("Authority Checkpoint frontier differs from certificate chain")
        streams = _load_index(self.home, "stream-heads", checkpoint["stream_heads_index_commitment"])
        command_values = _load_index(self.home, "command-idempotency", checkpoint["command_idempotency_index_commitment"])
        roots = _load_index(self.home, "active-roots", checkpoint["active_roots_index_commitment"])
        state_roots, semantic_roots, semantic_commitment = _decode_active_roots(roots)
        commands = {
            command_id: (value["request_hash"], value["transaction_hash"], int(value["last_position"]))
            for command_id, value in command_values.items()
        }
        control_values = _load_index(self.home, "authority-control", checkpoint["authority_control_state_hash"])
        control_events = tuple(EventEnvelope.from_stored_bytes(canonical_json_bytes(value)) for value in control_values)
        active_path = self.home / "journal/active.seg"
        scan = scan_active_segment_read_only(active_path)
        state, verified = _state_from_frames(
            scan.frames,
            journal_id=checkpoint["journal_id"],
            epoch=int(checkpoint["epoch"]),
            authenticator=self.authenticator,
            base_position=int(checkpoint["verified_through_position"]),
            base_transaction_hash=checkpoint["last_transaction_hash"],
            stream_heads={key: int(value) for key, value in streams.items()},
            command_bindings=commands,
            active_roots=state_roots,
        )
        return FastStartReport(
            state,
            True,
            active_path.stat().st_size,
            verified,
            len(certificates),
            verified,
            checkpoint_commitment,
            int(checkpoint["verified_through_position"]),
            tuple({"command_id": command_id, **dict(value)} for command_id, value in sorted(command_values.items())),
            control_events,
            tuple(event for frame in scan.frames for event in frame.transaction.events),
            semantic_roots,
            str(checkpoint["active_roots_index_commitment"]),
            semantic_commitment,
        )


class FullJournalVerifier:
    def __init__(
        self,
        home: str | Path,
        *,
        journal_authenticator: JournalAuthProvider,
        authority_key_provider: InMemoryKeyProvider,
    ):
        self.home = Path(home).resolve(strict=True)
        self.authenticator = journal_authenticator
        self.provider = authority_key_provider

    def verify(self) -> FastStartReport:
        checkpoint, commitment = _latest_checkpoint(self.home, self.provider)
        certificates = _certificate_values(self.home, self.provider)
        if _sealed_manifest_root(certificates) != checkpoint["sealed_manifest_root"]:
            raise AuthorityIntegrityError("full verify observed a different sealed manifest")
        frames: list[Any] = []
        bytes_scanned = 0
        for certificate in certificates:
            path = self.home / "journal/sealed" / certificate.value["segment_name"]
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                    bytes_scanned += len(chunk)
            if digest.hexdigest() != certificate.value["segment_sha256"]:
                raise AuthorityIntegrityError("full sealed segment SHA-256 verification failed")
            frames.extend(scan_sealed_segment(path).frames)
        active = self.home / "journal/active.seg"
        active_scan = scan_active_segment_read_only(active)
        bytes_scanned += active.stat().st_size
        frames.extend(active_scan.frames)
        roots = _load_index(self.home, "active-roots", checkpoint["active_roots_index_commitment"])
        state_roots, semantic_roots, semantic_commitment = _decode_active_roots(roots)
        state, verified = _state_from_frames(
            frames,
            journal_id=checkpoint["journal_id"],
            epoch=int(checkpoint["epoch"]),
            authenticator=self.authenticator,
            active_roots=state_roots,
        )
        return FastStartReport(
            state,
            False,
            bytes_scanned,
            verified,
            len(certificates),
            sum(len(frame.transaction.events) for frame in active_scan.frames),
            commitment,
            active_roots_snapshot=semantic_roots,
            active_roots_index_commitment=str(checkpoint["active_roots_index_commitment"]),
            semantic_active_roots_commitment=semantic_commitment,
            verified_events=tuple(event for frame in frames for event in frame.transaction.events),
        )
