from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import PublishedObjectReceipt
from sitina.commands.model import CommandEnvelope
from sitina.journal.local import ExpectedStreamVersionConflict, LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes, parse_canonical_json
from sitina.security.key_provider import JournalAuthProvider, KeyProviderError, KeyPurpose
from sitina.security.macos_keychain import KeychainBackend, MacOSKeychainProvider
from sitina.utils import iso_now

from .model import PersistenceFenced, SPEC_VERSION


DATA_KEY_PURPOSES = (
    KeyPurpose.JOURNAL_AUTH,
    KeyPurpose.CAS_KEK,
    KeyPurpose.CAS_COMMITMENT,
)
NAMESPACE_MARKER_BODY = b"SITINA_LOOP_NAMESPACE_READY_V1\n"


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_write_bindings(path: Path, value: Mapping[str, Any]) -> None:
    """Commit the public namespace binding before task state can exist."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _fsync_directory(path.parent.parent if path.parent.parent != path.parent else path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    raw = json.dumps(dict(value), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise OSError("short loop key-binding write")
            written += count
        os.fsync(descriptor)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_and_verify_bindings(path: Path, expected: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        recorded = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise KeyProviderError("loop key binding durable read-back failed") from error
    if not isinstance(recorded, dict) or recorded != dict(expected):
        raise KeyProviderError("loop key binding durable read-back differs from the committed value")
    return recorded


def _durable_create_marker(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        if os.write(descriptor, NAMESPACE_MARKER_BODY) != len(NAMESPACE_MARKER_BODY):
            raise OSError("short loop namespace marker write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)
    try:
        if path.read_bytes() != NAMESPACE_MARKER_BODY:
            raise OSError("loop namespace marker durable read-back differs")
    except OSError as error:
        raise KeyProviderError("loop namespace marker durable read-back failed") from error


@dataclass(frozen=True)
class KeyReadbackReceipt:
    schema: str
    provider_id: str
    namespace: str
    key_ids: Mapping[str, str]
    verification_fingerprint: str
    persisted_before_business_state: bool
    existing_only_reopen: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "namespace": self.namespace,
            "key_ids": dict(self.key_ids),
            "verification_fingerprint": self.verification_fingerprint,
            "persisted_before_business_state": self.persisted_before_business_state,
            "existing_only_reopen": self.existing_only_reopen,
            "secret_material_included": False,
        }


@dataclass(frozen=True)
class StoredContent:
    reference_id: str
    content_hash: str
    proof: PublishedObjectReceipt


def _verify_loop_archive_members(
    home: Path,
    manifest: Any,
    expected_manifest_hash: str,
) -> tuple[Path, dict[str, Any], str]:
    from sitina.archive.backup import (
        BackupError,
        CanonicalBackupManifest,
        _read_member,
        _root_fd,
        _validate_paths,
    )
    from sitina.journal.model import domain_hash

    if not isinstance(manifest, CanonicalBackupManifest):
        raise KeyProviderError("Loop archive requires a canonical backup manifest")
    if (
        not isinstance(expected_manifest_hash, str)
        or not expected_manifest_hash
        or manifest.manifest_hash != expected_manifest_hash
        or domain_hash("CANONICAL_BACKUP_MANIFEST", canonical_json_bytes(manifest.mapping()))
        != expected_manifest_hash
        or manifest.active_prefix_disposition not in {"FORCED_ROLLOVER", "FROZEN_EXACT_PREFIX"}
    ):
        raise KeyProviderError("Loop archive manifest identity is invalid")
    source = manifest.source_root
    if (
        not isinstance(source, Path)
        or not source.is_absolute()
        or source.resolve(strict=False) != source
        or home.is_symlink()
        or not home.is_dir()
        or home.resolve(strict=True) == source
    ):
        raise KeyProviderError("Loop archive source and isolated location are invalid")
    paths = tuple(item.path for item in manifest.files)
    if len(paths) != len(set(paths)) or tuple(sorted(paths)) != manifest.reachable_paths:
        raise KeyProviderError("Loop archive member set differs from its manifest")
    required = {".sitina-session-runtime-v1", "key-bindings-v1.json", "journal/active.seg"}
    if not required.issubset(paths):
        raise KeyProviderError("Loop archive is missing its source identity or Journal")
    actual_paths: set[str] = set()
    for parent, directories, files in os.walk(home, followlinks=False):
        for name in files + directories:
            path = Path(parent) / name
            if path.is_symlink() or not path.is_dir():
                actual_paths.add(path.relative_to(home).as_posix())
    if actual_paths != set(paths):
        raise KeyProviderError("Loop archive has missing or unbound members")
    identity_bytes: dict[str, bytes] = {}
    try:
        _validate_paths(paths)
        with _root_fd(home) as directory:
            for item in manifest.files:
                kind, raw = _read_member(directory, item.path)
                if not item.matches(kind, raw):
                    raise KeyProviderError("Loop archive member differs from its frozen binding")
                if item.path in required:
                    if kind != "REGULAR":
                        raise KeyProviderError("Loop archive identity and Journal must be regular files")
                    identity_bytes[item.path] = raw
        if identity_bytes[".sitina-session-runtime-v1"] != NAMESPACE_MARKER_BODY:
            raise KeyProviderError("Loop archive namespace marker is invalid")
        recorded = json.loads(identity_bytes["key-bindings-v1.json"])
    except (OSError, ValueError, BackupError) as error:
        raise KeyProviderError("Loop archive member verification failed") from error
    namespace = LoopRuntimeContext._namespace(source)
    purposes = {purpose.value for purpose in DATA_KEY_PURPOSES}
    if (
        not isinstance(recorded, dict)
        or recorded.get("schema") != "SITINA_LOOP_KEY_BINDINGS_V1"
        or recorded.get("spec_version") != SPEC_VERSION
        or recorded.get("environment") != "sitina-loop"
        or recorded.get("namespace") != namespace
        or recorded.get("secret_material_included") is not False
        or not isinstance(recorded.get("key_ids"), dict)
        or set(recorded["key_ids"]) != purposes
        or any(not isinstance(value, str) or not value for value in recorded["key_ids"].values())
    ):
        raise KeyProviderError("Loop archive source key binding is invalid")
    challenge = hashlib.sha256(
        b"SITINA_LOOP_KEY_READBACK_V1\0" + str(source).encode("utf-8")
    ).hexdigest()
    fingerprint = "sha256:" + hashlib.sha256(
        canonical_json_bytes({"challenge": challenge, "key_ids": recorded["key_ids"]})
    ).hexdigest()
    journal_id = "loop-journal-" + hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:24]
    if (
        recorded.get("verification_fingerprint") != fingerprint
        or manifest.frontier.journal_id != journal_id
        or manifest.frontier.epoch != 1
        or manifest.frontier.shard != "local"
    ):
        raise KeyProviderError("Loop archive original authentication identity differs")
    return source, recorded, journal_id


class LoopArchiveReadView:
    """Authenticated archived tasks and CAS content, without a writer capability."""

    def __init__(self, home: Path, source: Path, journal_id: str, receipt: KeyReadbackReceipt,
                 events: tuple[EventEnvelope, ...], cas: LocalCAS) -> None:
        self.home = home
        self.source_root = source
        self.journal_id = journal_id
        self.key_readback = receipt
        self._events = events
        self._cas = cas

    def task_events(self, task_id: str, *, after_position: int = 0) -> tuple[EventEnvelope, ...]:
        if after_position < 0:
            raise ValueError("task event cursor cannot be negative")
        return tuple(event for event in self._events
                     if event.position > after_position and event.stream_id == "loop-task/" + task_id)

    def task_ids(self) -> tuple[str, ...]:
        return tuple(sorted({event.stream_id.removeprefix("loop-task/")
                             for event in self._events if event.stream_id.startswith("loop-task/")}))

    def read_json(self, reference_id: str, *, expected_hash: str | None = None) -> Mapping[str, Any]:
        raw = self._cas.open_verified(self._cas.resolve_reference(reference_id))
        if expected_hash is not None and hashlib.sha256(raw).hexdigest() != expected_hash:
            raise PersistenceFenced("CAS content hash differs from its task event binding")
        value = parse_canonical_json(raw)
        if not isinstance(value, Mapping):
            raise PersistenceFenced("CAS task content is not an object")
        return dict(value)


def open_loop_archive_read_only(
    home: str | os.PathLike[str],
    *,
    manifest: Any,
    expected_manifest_hash: str,
    backend: KeychainBackend | None = None,
) -> LoopArchiveReadView:
    """Verify a frozen Loop backup at an isolated location using only existing keys.

    The original identity comes from the manifest source and its authenticated
    bindings. The physical read location never supplies a replacement namespace.
    This entry does not open a normal runtime, Journal writer, or recovery path.
    """
    supplied = Path(home).expanduser()
    if supplied.is_symlink():
        raise KeyProviderError("Loop archive root may not be a symlink")
    root = supplied.resolve(strict=True)
    source, recorded, journal_id = _verify_loop_archive_members(root, manifest, expected_manifest_hash)
    provider = MacOSKeychainProvider(
        environment="sitina-loop", namespace=recorded["namespace"],
        **({"backend": backend} if backend is not None else {}),
    )
    descriptors = tuple(provider.require_existing_descriptor(purpose, key_id=recorded["key_ids"][purpose.value])
                        for purpose in DATA_KEY_PURPOSES)
    if provider.provider_id != recorded.get("provider_id"):
        raise KeyProviderError("Loop archive provider identity differs")
    frames = LocalJournal.read_authenticated_frames(
        root, JournalAuthProvider(provider), journal_id=journal_id, epoch=1,
        namespace_kind="session", backup_manifest=manifest,
        expected_backup_manifest_hash=expected_manifest_hash,
    )
    cas = LocalCAS.open_read_only(root, provider, namespace_kind="session")
    events = tuple(event for frame in frames for event in frame.transaction.events)
    for reference_id in sorted({reference for event in events for reference in event.object_refs}):
        cas.open_verified(cas.resolve_reference(reference_id))
    receipt = KeyReadbackReceipt(
        "SITINA_LOOP_KEY_READBACK_RECEIPT_V1", provider.provider_id, recorded["namespace"],
        {descriptor.purpose.value: descriptor.key_id for descriptor in descriptors},
        recorded["verification_fingerprint"], True, True,
    )
    return LoopArchiveReadView(root, source, journal_id, receipt, events, cas)


class LoopRuntimeContext:
    """Stable Journal/CAS runtime root for the r4 task-loop skeleton.

    A fresh root initializes Keychain material and verifies it through a new
    provider object before creating the namespace marker or any task event.
    An existing root uses only ``require_existing_descriptor`` and therefore
    cannot replace a missing historic key with a new random key.
    """

    namespace_kind = "session"

    def __init__(
        self,
        home: Path,
        provider: MacOSKeychainProvider,
        *,
        journal_id: str,
        run_instance_id: str,
        key_readback: KeyReadbackReceipt,
    ) -> None:
        self.home = home
        self.provider = provider
        self.journal_id = journal_id
        self.run_instance_id = run_instance_id
        self.key_readback = key_readback

    @staticmethod
    def _namespace(root: Path) -> str:
        return "loop-" + hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:24]

    @classmethod
    def open(
        cls,
        home: str | os.PathLike[str],
        *,
        backend: KeychainBackend | None = None,
        run_instance_id: str | None = None,
    ) -> "LoopRuntimeContext":
        root = Path(home).expanduser().resolve(strict=False)
        if root.exists() and not root.is_dir():
            raise KeyProviderError("loop runtime root is not a directory")
        marker = root / ".sitina-session-runtime-v1"
        bindings_path = root / "key-bindings-v1.json"
        existing = marker.is_file() or (root / "journal").exists() or bindings_path.exists()
        namespace = cls._namespace(root)

        def new_provider() -> MacOSKeychainProvider:
            return MacOSKeychainProvider(
                environment="sitina-loop",
                namespace=namespace,
                **({"backend": backend} if backend is not None else {}),
            )

        recorded: dict[str, Any] | None = None
        if existing:
            if not marker.is_file() or not bindings_path.is_file():
                raise KeyProviderError("loop recovery key binding or namespace marker is unavailable")
            try:
                if marker.read_bytes() != NAMESPACE_MARKER_BODY:
                    raise KeyProviderError("loop recovery namespace marker is invalid")
                recorded = json.loads(bindings_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise KeyProviderError("loop recovery key binding is unreadable") from error
            if (
                not isinstance(recorded, dict)
                or recorded.get("schema") != "SITINA_LOOP_KEY_BINDINGS_V1"
                or recorded.get("namespace") != namespace
                or not isinstance(recorded.get("key_ids"), Mapping)
            ):
                raise KeyProviderError("loop recovery key binding is invalid")
            provider = new_provider()
            descriptors = tuple(
                provider.require_existing_descriptor(
                    purpose,
                    key_id=str(recorded["key_ids"].get(purpose.value) or ""),
                )
                for purpose in DATA_KEY_PURPOSES
            )
            existing_only = True
        else:
            provider = new_provider()
            descriptors = provider.initialize_persistent_descriptors(DATA_KEY_PURPOSES)
            existing_only = False

        # A distinct provider object must retrieve the exact immutable key IDs.
        # The challenge checks Journal authentication, CAS commitment, and CAS
        # envelope wrapping without logging or returning any key bytes.
        reopened = new_provider()
        reopened_descriptors = tuple(
            reopened.require_existing_descriptor(purpose, key_id=descriptor.key_id)
            for purpose, descriptor in zip(DATA_KEY_PURPOSES, descriptors, strict=True)
        )
        challenge = hashlib.sha256(
            b"SITINA_LOOP_KEY_READBACK_V1\0" + str(root).encode("utf-8")
        ).hexdigest()
        first_auth = JournalAuthProvider(provider)
        second_auth = JournalAuthProvider(reopened)
        auth_key_id, auth_tag = first_auth.authenticate(
            "loop-key-readback-journal",
            1,
            challenge,
        )
        if not second_auth.verify("loop-key-readback-journal", 1, auth_key_id, challenge, auth_tag):
            raise KeyProviderError("persisted Journal key read-back verification failed")
        commitment_id, commitment = provider.commitment("sitina-loop-key-readback", challenge.encode("ascii"))
        if not reopened.verify_commitment(
            commitment_id,
            "sitina-loop-key-readback",
            challenge.encode("ascii"),
            commitment,
        ):
            raise KeyProviderError("persisted CAS commitment key read-back verification failed")
        wrapped = provider.wrap_dek(b"k" * 32, challenge.encode("ascii"))
        unwrapped = reopened.unwrap_dek(
            str(wrapped["key_id"]),
            bytes(wrapped["nonce"]),
            bytes(wrapped["wrapped_dek"]),
            challenge.encode("ascii"),
        )
        if not hmac.compare_digest(unwrapped, b"k" * 32):
            raise KeyProviderError("persisted CAS encryption key read-back verification failed")

        key_ids = {descriptor.purpose.value: descriptor.key_id for descriptor in reopened_descriptors}
        fingerprint = "sha256:" + hashlib.sha256(
            canonical_json_bytes({"challenge": challenge, "key_ids": key_ids})
        ).hexdigest()
        if not existing:
            binding = {
                "schema": "SITINA_LOOP_KEY_BINDINGS_V1",
                "spec_version": SPEC_VERSION,
                "provider_id": reopened.provider_id,
                "environment": reopened.environment,
                "namespace": namespace,
                "key_ids": key_ids,
                "verification_fingerprint": fingerprint,
                "created_at": iso_now(),
                "secret_material_included": False,
            }
            try:
                root.mkdir(parents=True, exist_ok=True, mode=0o700)
                _fsync_directory(root.parent)
                _durable_create_marker(marker)
                _durable_write_bindings(bindings_path, binding)
                recorded = _read_and_verify_bindings(bindings_path, binding)
            except BaseException as error:
                raise KeyProviderError(
                    "loop namespace binding was not durably committed and read back"
                ) from error
        else:
            if recorded is None or recorded.get("key_ids") != key_ids:
                raise KeyProviderError("loop recovery key IDs differ from the persisted binding")
            expected_binding = {
                "schema": "SITINA_LOOP_KEY_BINDINGS_V1",
                "spec_version": SPEC_VERSION,
                "provider_id": reopened.provider_id,
                "environment": reopened.environment,
                "namespace": namespace,
                "key_ids": key_ids,
                "verification_fingerprint": fingerprint,
                "created_at": recorded.get("created_at"),
                "secret_material_included": False,
            }
            recorded = _read_and_verify_bindings(bindings_path, expected_binding)
        receipt = KeyReadbackReceipt(
            "SITINA_LOOP_KEY_READBACK_RECEIPT_V1",
            reopened.provider_id,
            namespace,
            key_ids,
            fingerprint,
            True,
            existing_only,
        )
        journal_id = "loop-journal-" + hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:24]
        return cls(
            root.resolve(strict=True),
            reopened,
            journal_id=journal_id,
            run_instance_id=str(run_instance_id or ("loop-run-instance-" + secrets.token_hex(16))),
            key_readback=receipt,
        )

    def open_store(
        self,
        *,
        append_fault: Callable[[str], None] | None = None,
    ) -> "LoopEventStore":
        journal = LocalJournal.open(
            self.home,
            JournalAuthProvider(self.provider),
            journal_id=self.journal_id,
            epoch=1,
            namespace_kind=self.namespace_kind,
        )
        try:
            cas = LocalCAS.open(
                self.home,
                self.provider,
                namespace_kind=self.namespace_kind,
            )
        except BaseException:
            journal.close()
            raise
        return LoopEventStore(journal, cas, self.provider, append_fault=append_fault)


class LoopEventStore:
    TENANT = "sitina-loop"

    def __init__(
        self,
        journal: LocalJournal,
        cas: LocalCAS,
        provider: MacOSKeychainProvider,
        *,
        append_fault: Callable[[str], None] | None = None,
    ) -> None:
        self.journal = journal
        self.cas = cas
        self.provider = provider
        self.append_fault = append_fault
        self.fenced_reason: str | None = None

    @staticmethod
    def stream_id(task_id: str) -> str:
        return f"loop-task/{task_id}"

    def task_events(self, task_id: str, *, after_position: int = 0) -> tuple[EventEnvelope, ...]:
        if after_position < 0:
            raise ValueError("task event cursor cannot be negative")
        stream_id = self.stream_id(task_id)
        return tuple(
            event for event in self.journal.iter_events(after_position)
            if event.stream_id == stream_id
        )

    def task_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    event.stream_id.removeprefix("loop-task/")
                    for event in self.journal.iter_events(0)
                    if event.stream_id.startswith("loop-task/")
                }
            )
        )

    def publish_json(self, value: Mapping[str, Any], *, purpose: str) -> StoredContent:
        raw = canonical_json_bytes(dict(value))
        proof = self.cas.publish_verified(
            encrypt_object(raw, self.provider, tenant_id=self.TENANT, purpose=purpose)
        )
        return StoredContent(
            proof.object_ref.reference_id,
            hashlib.sha256(raw).hexdigest(),
            proof,
        )

    def read_json(self, reference_id: str, *, expected_hash: str | None = None) -> Mapping[str, Any]:
        reference = self.cas.resolve_reference(reference_id)
        raw = self.cas.open_verified(reference)
        if expected_hash is not None and hashlib.sha256(raw).hexdigest() != expected_hash:
            raise PersistenceFenced("CAS content hash differs from its task event binding")
        value = parse_canonical_json(raw)
        if not isinstance(value, Mapping):
            raise PersistenceFenced("CAS task content is not an object")
        return dict(value)

    def conditional_append(
        self,
        *,
        task_id: str,
        expected_stream_version: int,
        request_id: str,
        command_type: str,
        event_type: str,
        payload: Mapping[str, Any],
        proofs: Sequence[PublishedObjectReceipt] = (),
        occurred_at: str | None = None,
    ) -> EventEnvelope:
        """The sole task-state commit path for batch 1a."""

        if self.fenced_reason is not None:
            raise PersistenceFenced(self.fenced_reason)
        timestamp = occurred_at or iso_now()
        event_payload = {"spec_version": SPEC_VERSION, **dict(payload)}
        digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "task_id": task_id,
                    "request_id": request_id,
                    "command_type": command_type,
                    "event_type": event_type,
                    "payload": event_payload,
                }
            )
        ).hexdigest()
        command = CommandEnvelope(
            "loop-command-" + hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:42],
            self.TENANT,
            self.stream_id(task_id),
            command_type,
            "loop-state-coordinator",
            timestamp,
            {"task_id": task_id, "request_id": request_id, "request_hash": digest},
        )
        refs = tuple(sorted(proof.object_ref.reference_id for proof in proofs))
        event = EventEnvelope(
            "loop-event-" + hashlib.sha256((request_id + "\0" + event_type).encode("utf-8")).hexdigest()[:44],
            event_type,
            self.TENANT,
            self.stream_id(task_id),
            0,
            0,
            timestamp,
            event_payload,
            refs,
        )
        try:
            if self.append_fault is not None:
                self.append_fault(event_type)
            receipt = self.journal.append(
                command,
                expected_stream_version,
                [event],
                object_reference_proofs=tuple(proofs),
            )
        except ExpectedStreamVersionConflict:
            raise
        except BaseException as error:
            self.fenced_reason = (
                "required task-state persistence failed; dependent business dispatch is fenced: "
                f"{type(error).__name__}"
            )
            raise
        return next(
            item
            for item in self.journal.iter_events(receipt.first_position - 1)
            if item.position == receipt.first_position
        )

    def close(self) -> None:
        self.journal.close()
