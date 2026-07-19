from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sitina.journal.model import canonical_json_bytes, domain_hash, parse_canonical_json
from sitina.security.key_provider import InMemoryKeyProvider

from .crypto import decrypt_object
from .model import CASError, EncryptedObject, ObjectEnvelope, ObjectRef, PublishedObjectReceipt
from .native import NO_REPLACE_PROFILE, publish_no_replace, sync_directory


_COMMITMENT_LOCK_GUARD = threading.Lock()
_COMMITMENT_LOCKS: dict[str, threading.RLock] = {}


class CASCollision(CASError):
    pass


@dataclass(frozen=True)
class ContentPublication:
    receipt: PublishedObjectReceipt
    reused: bool
    compression_profile: str
    commitment_index_key: str


class LocalCAS:
    def __init__(
        self,
        home: Path,
        provider: InMemoryKeyProvider,
        namespace_kind: str,
        *,
        operational_capability: object | None = None,
        authority_resolution: object | None = None,
        genesis_hash: str | None = None,
        feature_activations: object | None = None,
        read_only: bool = False,
    ):
        self.home = home.resolve(strict=True)
        self.operational_capability = operational_capability
        self.authority_resolution = authority_resolution
        self.genesis_hash = genesis_hash
        self.feature_activations = feature_activations
        self.read_only = read_only
        if namespace_kind in {"production", "production_simulation"}:
            self._authorize_production_open(namespace_kind)
        else:
            if self.home == Path("/Users/moss/SitinaHub"):
                raise CASError("Production CAS requires a Phase 6B or resolved runtime capability")
            if namespace_kind not in {"shadow", "controlled_fixture"}:
                raise CASError("CAS namespace must be shadow, controlled_fixture, or manifest-bound Production")
            marker = ".sitina-bplus-shadow-v1" if namespace_kind == "shadow" else ".sitina-bplus-disposable-v1"
            if not (self.home / marker).is_file():
                raise CASError("isolated CAS namespace marker is missing")
        self.provider = provider
        self.namespace_kind = namespace_kind
        self.root = self.home / "cas"
        layout = (
            "staging",
            "objects",
            "envelopes",
            "aliases",
            "collisions",
            "quarantine",
            "destruction-attestations",
            "commitments",
            "commitments/.locks",
            "packs",
        )
        if read_only:
            if self.root.is_symlink() or not self.root.is_dir():
                raise CASError("read-only CAS root is unavailable")
            for name in ("objects", "envelopes", "aliases"):
                path = self.root / name
                if path.is_symlink() or not path.is_dir():
                    raise CASError(f"read-only CAS layout is unavailable: {name}")
        else:
            self._ensure_owner_only_directory(self.root)
            for name in layout:
                self._ensure_owner_only_directory(self.root / name)
        self._quarantine_keys: dict[str, bytes] = {}
        if not read_only:
            sync_directory(self.root)

    def _authorize_production_open(self, namespace_kind: str) -> None:
        if not isinstance(self.genesis_hash, str) or len(self.genesis_hash) != 64:
            raise CASError("Production CAS requires an exact Genesis hash")
        path = self.home / "state/bplus-production-genesis/genesis.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as error:
            raise CASError("verified Production Genesis is unavailable") from error
        if value.get("genesis_hash") != self.genesis_hash:
            raise CASError("Production CAS Genesis bytes differ")
        if namespace_kind == "production_simulation":
            if self.home == Path("/Users/moss/SitinaHub") or not (self.home / ".sitina-bplus-disposable-v1").is_file():
                raise CASError("Production CAS simulation requires a disposable root")
        elif self.home != Path("/Users/moss/SitinaHub"):
            raise CASError("Production CAS namespace requires the Production installation")
        if self.operational_capability is not None:
            try:
                self.operational_capability.assert_operation(
                    "OPEN_PRODUCTION_CAS_MIGRATION_PLANE", self.home, now=int(time.time())
                )
            except Exception as error:
                raise CASError("Production CAS Maintenance capability is invalid") from error
            return
        if self.authority_resolution is not None:
            try:
                self.authority_resolution.assert_fresh(now=int(time.time()))
            except Exception as error:
                raise CASError("Production CAS authority resolution is stale") from error
            if not self.authority_resolution.authorizes_journal or self.authority_resolution.writer_count != 1:
                raise CASError("Production CAS has no unique Journal writer authority")
            return
        raise CASError("Production CAS requires a Maintenance capability or committed authority resolution")

    @classmethod
    def open(
        cls,
        home: str | os.PathLike[str],
        provider: InMemoryKeyProvider,
        *,
        namespace_kind: str = "controlled_fixture",
        operational_capability: object | None = None,
        authority_resolution: object | None = None,
        genesis_hash: str | None = None,
        feature_activations: object | None = None,
        read_only: bool = False,
    ) -> "LocalCAS":
        return cls(
            Path(home), provider, namespace_kind,
            operational_capability=operational_capability,
            authority_resolution=authority_resolution,
            genesis_hash=genesis_hash,
            feature_activations=feature_activations,
            read_only=read_only,
        )

    @classmethod
    def open_read_only(
        cls,
        home: str | os.PathLike[str],
        provider: InMemoryKeyProvider,
        *,
        namespace_kind: str = "controlled_fixture",
        authority_resolution: object | None = None,
        genesis_hash: str | None = None,
    ) -> "LocalCAS":
        return cls.open(
            home,
            provider,
            namespace_kind=namespace_kind,
            authority_resolution=authority_resolution,
            genesis_hash=genesis_hash,
            read_only=True,
        )

    def _assert_writable(self) -> None:
        if self.read_only:
            raise CASError("read-only CAS view cannot publish or mutate content")

    @staticmethod
    def _ensure_owner_only_directory(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink() or not path.is_dir():
            raise CASError("CAS directory path is unsafe")
        os.chmod(path, 0o700, follow_symlinks=False)

    def _object_path(self, object_id: str) -> Path:
        return self.root / "objects" / object_id[:2] / f"{object_id}.obj"

    def _envelope_path(self, envelope_id: str) -> Path:
        return self.root / "envelopes" / envelope_id[:2] / f"{envelope_id}.json"

    def _write_staged(self, raw: bytes) -> Path:
        self._assert_writable()
        path = self.root / "staging" / f"{uuid.uuid4().hex}.stage"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        return path

    def _replace_json(self, path: Path, value: Mapping[str, Any]) -> None:
        self._ensure_owner_only_directory(path.parent)
        staged = self._write_staged(canonical_json_bytes(dict(value)))
        os.replace(staged, path)
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
        sync_directory(path.parent)

    def _record_collision(self, target: Path, *, classification: str) -> None:
        self._assert_writable()
        incident = self.root / "collisions" / f"{target.stem}-{uuid.uuid4().hex}.json"
        value = canonical_json_bytes(
            {"schema": "CAS_COLLISION_V1", "target": str(target), "classification": classification}
        )
        fd = os.open(incident, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value); handle.write(b"\n"); handle.flush(); os.fsync(handle.fileno())
        sync_directory(incident.parent)

    def _publish_bytes(self, raw: bytes, target: Path) -> bool:
        self._ensure_owner_only_directory(target.parent)
        sync_directory(target.parent.parent)
        if target.exists():
            if target.is_symlink() or target.read_bytes() != raw:
                self._record_collision(target, classification="PREEXISTING_IDENTITY_MISMATCH")
                raise CASCollision(f"CAS identity collision at {target}")
            return False
        staged = self._write_staged(raw)
        try:
            publish_no_replace(staged, target)
            return True
        except FileExistsError:
            if target.is_symlink() or target.read_bytes() != raw:
                self._record_collision(target, classification="CONCURRENT_IDENTITY_MISMATCH")
                raise CASCollision(f"concurrent CAS identity collision at {target}")
            return False
        finally:
            if os.environ.get("SITINA_AUDIT_RETAIN_STAGING") != "1":
                try:
                    staged.unlink()
                except FileNotFoundError:
                    pass

    def _publish_envelope(self, envelope: ObjectEnvelope) -> None:
        self._publish_bytes(envelope.canonical_bytes(), self._envelope_path(envelope.envelope_id))
        alias = self.root / "aliases" / f"{envelope.object_id}.json"
        value = canonical_json_bytes({"schema": "SITINA_CAS_ENVELOPE_ALIAS_V1", "object_id": envelope.object_id, "envelope_id": envelope.envelope_id, "version": envelope.version})
        staged = self._write_staged(value)
        os.replace(staged, alias)
        with alias.open("rb") as handle:
            os.fsync(handle.fileno())
        sync_directory(alias.parent)

    def publish_verified(self, encrypted: EncryptedObject) -> PublishedObjectReceipt:
        self._assert_writable()
        if encrypted.core_header.get("compression") != "none":
            if self.feature_activations is None:
                raise CASError("compressed CAS publication has no verified Journal feature activation state")
            try:
                self.feature_activations.assert_write_enabled("cas_zstd_write")
            except Exception as error:
                raise CASError("compressed CAS publication requires cas_zstd_write activation") from error
        if self.namespace_kind in {"production", "production_simulation"} and self.operational_capability is not None:
            try:
                self.operational_capability.assert_operation(
                    "OPEN_PRODUCTION_CAS_MIGRATION_PLANE", self.home, now=int(time.time())
                )
            except Exception as error:
                raise CASError("Production CAS publication capability is stale or out of scope") from error
        plaintext = decrypt_object(encrypted, self.provider)
        if len(plaintext) != encrypted.core_header["plaintext_length"]:
            raise CASError("Fresh Verify failed")
        raw = encrypted.object_bytes()
        if hashlib.sha256(raw).hexdigest() != encrypted.reference.object_id:
            raise CASError("object digest mismatch before publication")
        target = self._object_path(encrypted.reference.object_id)
        created = self._publish_bytes(raw, target)
        self._publish_envelope(encrypted.envelope)
        now = dt.datetime.now(dt.timezone.utc)
        return PublishedObjectReceipt._issue(
            object_ref=encrypted.reference, object_path=str(target), core_header_hash=encrypted.core_header_hash,
            envelope_id=encrypted.envelope.envelope_id, issued_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=(now + dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            durability_profile="MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1+" + NO_REPLACE_PROFILE,
            fresh_verified=True, no_replace_published=True,
        )

    @staticmethod
    def _already_compressed_media(media_type: str | None, plaintext: bytes) -> bool:
        normalized = (media_type or "").lower().split(";", 1)[0].strip()
        compressed_types = (
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/avif",
            "audio/",
            "video/",
            "application/zip",
            "application/gzip",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
            "application/pdf",
        )
        if any(normalized == item or (item.endswith("/") and normalized.startswith(item)) for item in compressed_types):
            return True
        return plaintext.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"PK\x03\x04", b"\x1f\x8b"))

    def _compression_profile(
        self,
        plaintext: bytes,
        *,
        requested: str,
        media_type: str | None,
    ) -> tuple[str, str]:
        if requested not in {"auto", "none", "zstd"}:
            raise CASError("CAS compression request must be auto, none, or zstd")
        if requested == "none" or len(plaintext) < 1024 or self._already_compressed_media(media_type, plaintext):
            return "none", "none"
        if requested == "auto":
            try:
                if self.feature_activations is None:
                    return "none", "none"
                self.feature_activations.assert_write_enabled("cas_zstd_write")
            except Exception:
                return "none", "none"
        elif self.feature_activations is None:
            raise CASError("explicit zstd write has no verified Journal feature activation state")
        else:
            try:
                self.feature_activations.assert_write_enabled("cas_zstd_write")
            except Exception as error:
                raise CASError("explicit zstd write requires cas_zstd_write activation") from error
        mode = "single" if len(plaintext) <= 1024 * 1024 else "chunked-1mib"
        return "zstd", f"zstd-level3-{mode}"

    @staticmethod
    def _compression_profile_from_header(header: Mapping[str, Any]) -> str:
        compression = str(header.get("compression"))
        if compression == "none":
            return "none"
        if compression == "zstd":
            mode = "single" if header.get("compression_mode") == "single" else "chunked-1mib"
            return f"zstd-level{header['compression_level']}-{mode}"
        raise CASError("unknown CAS compression profile")

    @staticmethod
    def _commitment_key(
        *,
        tenant_id: str,
        purpose_class: str,
        plaintext_commitment: str,
        compression_profile: str,
        crypto_profile: str,
    ) -> str:
        return domain_hash(
            "CAS_COMMITMENT_INDEX_KEY",
            canonical_json_bytes(
                {
                    "tenant_id": tenant_id,
                    "purpose_class": purpose_class,
                    "plaintext_commitment": plaintext_commitment,
                    "compression_profile": compression_profile,
                    "crypto_profile": crypto_profile,
                }
            ),
        )

    def _commitment_path(self, key: str) -> Path:
        return self.root / "commitments" / key[:2] / f"{key}.json"

    @contextmanager
    def _commitment_lock(self, key: str) -> Iterator[None]:
        path = self.root / "commitments/.locks" / f"{key}.lock"
        identity = str(path)
        with _COMMITMENT_LOCK_GUARD:
            process_lock = _COMMITMENT_LOCKS.setdefault(identity, threading.RLock())
        with process_lock:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @staticmethod
    def _index_mapping(
        *,
        key: str,
        tenant_id: str,
        purpose_class: str,
        plaintext_commitment: str,
        compression_profile: str,
        reference: ObjectRef,
    ) -> dict[str, Any]:
        return {
            "schema": "SITINA_CAS_COMMITMENT_INDEX_V1",
            "commitment_index_key": key,
            "tenant_id": tenant_id,
            "purpose_class": purpose_class,
            "plaintext_commitment": plaintext_commitment,
            "compression_profile": compression_profile,
            "crypto_profile": reference.profile,
            "object_id": reference.object_id,
            "commitment_key_id": reference.commitment_key_id,
        }

    def _read_commitment_index(self, path: Path, *, expected_key: str) -> tuple[dict[str, Any], ObjectRef] | None:
        if path.is_symlink():
            raise CASError("CAS commitment index rejects symlinks")
        if not path.is_file():
            return None
        fields = {
            "schema",
            "commitment_index_key",
            "tenant_id",
            "purpose_class",
            "plaintext_commitment",
            "compression_profile",
            "crypto_profile",
            "object_id",
            "commitment_key_id",
        }
        value = parse_canonical_json(path.read_bytes(), allowed_fields=fields)
        if value.get("schema") != "SITINA_CAS_COMMITMENT_INDEX_V1" or value.get("commitment_index_key") != expected_key:
            raise CASError("CAS commitment index identity mismatch")
        reference = ObjectRef(
            str(value["object_id"]),
            str(value["tenant_id"]),
            str(value["plaintext_commitment"]),
            str(value["commitment_key_id"]),
            str(value["crypto_profile"]),
        )
        self.open_verified(reference)
        return dict(value), reference

    def publish_plaintext(
        self,
        plaintext: bytes,
        *,
        tenant_id: str,
        purpose_class: str,
        compression: str = "auto",
        media_type: str | None = None,
    ) -> ContentPublication:
        """Deduplicate inside one security/purpose/compression domain and publish atomically."""
        from .crypto import CRYPTO_PROFILE_ID, encrypt_object

        self._assert_writable()
        if not isinstance(plaintext, bytes):
            raise TypeError("CAS plaintext must be bytes")
        compression_kind, compression_profile = self._compression_profile(
            plaintext,
            requested=compression,
            media_type=media_type,
        )
        commitment_key_id, commitment = self.provider.commitment(tenant_id, plaintext)
        del commitment_key_id
        key = self._commitment_key(
            tenant_id=tenant_id,
            purpose_class=purpose_class,
            plaintext_commitment=commitment,
            compression_profile=compression_profile,
            crypto_profile=CRYPTO_PROFILE_ID,
        )
        path = self._commitment_path(key)
        with self._commitment_lock(key):
            indexed = self._read_commitment_index(path, expected_key=key)
            if indexed is not None:
                _value, reference = indexed
                return ContentPublication(self.verify_existing(reference), True, compression_profile, key)
            encrypted = encrypt_object(
                plaintext,
                self.provider,
                tenant_id=tenant_id,
                purpose=purpose_class,
                compression=compression_kind,
                compression_level=3,
            )
            receipt = self.publish_verified(encrypted)
            value = self._index_mapping(
                key=key,
                tenant_id=tenant_id,
                purpose_class=purpose_class,
                plaintext_commitment=commitment,
                compression_profile=compression_profile,
                reference=receipt.object_ref,
            )
            self._publish_bytes(canonical_json_bytes(value), path)
            return ContentPublication(receipt, False, compression_profile, key)

    def reconcile_commitment_index(self) -> dict[str, Any]:
        """Rebuild missing derived entries; never deletes duplicate ciphertext objects."""
        self._assert_writable()
        groups: dict[str, list[tuple[ObjectRef, dict[str, Any], str]]] = {}
        invalid: list[str] = []
        for path in sorted((self.root / "objects").rglob("*.obj")):
            try:
                raw = path.read_bytes()
                object_id = path.stem
                if hashlib.sha256(raw).hexdigest() != object_id or len(raw) < 4:
                    raise CASError("object digest mismatch")
                length = int.from_bytes(raw[:4], "big")
                header = parse_canonical_json(raw[4 : 4 + length])
                compression_profile = self._compression_profile_from_header(header)
                reference = ObjectRef(
                    object_id,
                    str(header["tenant_id"]),
                    str(header["plaintext_commitment"]),
                    str(header["commitment_key_id"]),
                    str(header["profile"]),
                )
                key = self._commitment_key(
                    tenant_id=reference.tenant_id,
                    purpose_class=str(header["purpose"]),
                    plaintext_commitment=reference.plaintext_commitment,
                    compression_profile=compression_profile,
                    crypto_profile=reference.profile,
                )
                groups.setdefault(key, []).append((reference, dict(header), compression_profile))
            except Exception:
                invalid.append(str(path))
        indexed = 0
        duplicates: dict[str, list[str]] = {}
        for key, candidates in sorted(groups.items()):
            candidates.sort(key=lambda item: item[0].object_id)
            if len(candidates) > 1:
                duplicates[key] = [item[0].reference_id for item in candidates[1:]]
            path = self._commitment_path(key)
            with self._commitment_lock(key):
                if self._read_commitment_index(path, expected_key=key) is not None:
                    continue
                reference, header, compression_profile = candidates[0]
                value = self._index_mapping(
                    key=key,
                    tenant_id=reference.tenant_id,
                    purpose_class=str(header["purpose"]),
                    plaintext_commitment=reference.plaintext_commitment,
                    compression_profile=compression_profile,
                    reference=reference,
                )
                self._publish_bytes(canonical_json_bytes(value), path)
                indexed += 1
        return {
            "schema": "SITINA_CAS_COMMITMENT_RECONCILE_REPORT_V1",
            "indexed": indexed,
            "duplicate_candidates": duplicates,
            "invalid_objects": invalid,
            "objects_deleted": 0,
        }

    def publish_rewrapped_envelope(self, encrypted: EncryptedObject) -> None:
        self._assert_writable()
        target = self._object_path(encrypted.reference.object_id)
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != encrypted.reference.object_id:
            raise CASError("cannot rewrap a missing or invalid object")
        decrypt_object(encrypted, self.provider)
        self._publish_envelope(encrypted.envelope)

    def _load_envelope(self, object_id: str) -> ObjectEnvelope:
        alias = self.root / "aliases" / f"{object_id}.json"
        if alias.is_symlink():
            raise CASError("CAS envelope alias rejects symlinks")
        if alias.is_file():
            value = parse_canonical_json(alias.read_bytes(), allowed_fields={"schema", "object_id", "envelope_id", "version"})
        else:
            from .packs import MetadataPackReader

            value = MetadataPackReader(self.home, kind="alias").get(object_id)
            if value is None:
                raise CASError("CAS envelope alias is missing from loose and packed metadata")
        if value["schema"] != "SITINA_CAS_ENVELOPE_ALIAS_V1" or value["object_id"] != object_id:
            raise CASError("invalid envelope alias")
        envelope_path = self._envelope_path(value["envelope_id"])
        if envelope_path.is_symlink():
            raise CASError("CAS envelope rejects symlinks")
        if envelope_path.is_file():
            raw = envelope_path.read_bytes()
        else:
            from .packs import MetadataPackReader

            packed = MetadataPackReader(self.home, kind="envelope").get(str(value["envelope_id"]))
            if packed is None:
                raise CASError("CAS envelope is missing from loose and packed metadata")
            raw = canonical_json_bytes(packed)
        return ObjectEnvelope.from_bytes(raw)

    def pack_metadata(self, reference: ObjectRef) -> dict[str, Any]:
        """Copy current loose metadata into active packs; never removes loose files."""
        self._assert_writable()
        from .packs import MetadataPackWriter

        if self.feature_activations is None:
            raise CASError("metadata pack publication has no verified Journal feature activation state")
        try:
            self.feature_activations.assert_write_enabled("alias_pack_v1_write")
        except Exception as error:
            raise CASError("metadata pack publication requires alias_pack_v1_write activation") from error
        self.open_verified(reference)
        alias_path = self.root / "aliases" / f"{reference.object_id}.json"
        if alias_path.is_symlink() or not alias_path.is_file():
            raise CASError("metadata packing requires a current loose alias")
        alias = parse_canonical_json(
            alias_path.read_bytes(),
            allowed_fields={"schema", "object_id", "envelope_id", "version"},
        )
        envelope_path = self._envelope_path(str(alias["envelope_id"]))
        if envelope_path.is_symlink() or not envelope_path.is_file():
            raise CASError("metadata packing requires a current loose envelope")
        envelope = ObjectEnvelope.from_bytes(envelope_path.read_bytes())
        envelope_writer = MetadataPackWriter(
            self.home,
            kind="envelope",
            write_enabled=True,
            feature_activations=self.feature_activations,
        )
        alias_writer = MetadataPackWriter(
            self.home,
            kind="alias",
            write_enabled=True,
            feature_activations=self.feature_activations,
        )
        envelope_writer.append(envelope.envelope_id, envelope.mapping())
        alias_writer.append(reference.object_id, dict(alias), replace=True)
        return {
            "schema": "SITINA_CAS_METADATA_PACKED_V1",
            "object_ref": reference.reference_id,
            "envelope_id": envelope.envelope_id,
            "loose_metadata_deleted": False,
        }

    def open_verified(self, reference: ObjectRef) -> bytes:
        path = self._object_path(reference.object_id)
        if path.is_symlink() or not path.is_file():
            raise CASError("CAS object is missing")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != reference.object_id or len(raw) < 4:
            raise CASError("CAS object digest mismatch")
        header_length = int.from_bytes(raw[:4], "big")
        if header_length > len(raw) - 4:
            raise CASError("invalid CAS object header length")
        header = parse_canonical_json(raw[4 : 4 + header_length])
        envelope = self._load_envelope(reference.object_id)
        encrypted = EncryptedObject(reference, header, raw[4 + header_length :], envelope)
        return decrypt_object(encrypted, self.provider)

    def resolve_reference(self, reference_id: str) -> ObjectRef:
        """Resolve the authenticated commitment binding for an existing CAS id.

        A Journal payload can remain refs-only while a Reader reconstructs the
        full ObjectRef from the immutable ciphertext header.  Decryption still
        happens only in ``open_verified``.
        """
        if not isinstance(reference_id, str) or not reference_id.startswith("cas:"):
            raise CASError("unsupported CAS reference")
        object_id = reference_id.removeprefix("cas:")
        path = self._object_path(object_id)
        if path.is_symlink() or not path.is_file():
            raise CASError("CAS object is missing")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != object_id or len(raw) < 4:
            raise CASError("CAS object digest mismatch")
        header_length = int.from_bytes(raw[:4], "big")
        if header_length > len(raw) - 4:
            raise CASError("invalid CAS object header length")
        header = parse_canonical_json(raw[4 : 4 + header_length])
        required = {"tenant_id", "plaintext_commitment", "commitment_key_id", "profile"}
        if not required.issubset(header):
            raise CASError("CAS object header lacks reference binding fields")
        return ObjectRef(
            object_id,
            str(header["tenant_id"]),
            str(header["plaintext_commitment"]),
            str(header["commitment_key_id"]),
            str(header["profile"]),
        )

    def verify_existing(self, reference: ObjectRef) -> PublishedObjectReceipt:
        """Re-verify a durable object and issue a fresh short-lived root receipt."""
        plaintext = self.open_verified(reference)
        path = self._object_path(reference.object_id)
        raw = path.read_bytes()
        header_length = int.from_bytes(raw[:4], "big")
        header = parse_canonical_json(raw[4 : 4 + header_length])
        envelope = self._load_envelope(reference.object_id)
        now = dt.datetime.now(dt.timezone.utc)
        return PublishedObjectReceipt._issue(
            object_ref=reference,
            object_path=str(path),
            core_header_hash=domain_hash("CAS_CORE_HEADER", canonical_json_bytes(header)),
            envelope_id=envelope.envelope_id,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=(now + dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            durability_profile="MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1+" + NO_REPLACE_PROFILE,
            fresh_verified=True,
            no_replace_published=True,
        )

    def publish_quarantine(self, raw: bytes, *, classification: str) -> str:
        """Place raw external bytes in an isolated, process-keyed quarantine.

        Quarantine identities are deliberately outside the normal ObjectRef and
        capability path.  Losing the in-memory key makes the ciphertext
        unreadable; a terminal pipeline disposition removes both.
        """
        self._assert_writable()
        if not isinstance(raw, bytes) or not classification:
            raise CASError("quarantine input and classification are required")
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        aad = canonical_json_bytes({"schema": "CAS_QUARANTINE_AAD_V1", "classification": classification})
        encrypted = nonce + AESGCM(key).encrypt(nonce, raw, aad)
        quarantine_id = hashlib.sha256(aad + encrypted).hexdigest()
        target = self.root / "quarantine" / f"{quarantine_id}.q"
        self._publish_bytes(encrypted, target)
        self._quarantine_keys[quarantine_id] = key
        self._replace_json(
            self.root / "quarantine" / f"{quarantine_id}.meta.json",
            {
                "schema": "CAS_QUARANTINE_STATE_V1",
                "quarantine_id": quarantine_id,
                "classification": classification,
                "ciphertext_hash": hashlib.sha256(encrypted).hexdigest(),
                "state": "QUARANTINED",
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            },
        )
        return quarantine_id

    def open_quarantine(self, quarantine_id: str, *, classification: str) -> bytes:
        key = self._quarantine_keys.get(quarantine_id)
        target = self.root / "quarantine" / f"{quarantine_id}.q"
        metadata_path = self.root / "quarantine" / f"{quarantine_id}.meta.json"
        metadata = parse_canonical_json(metadata_path.read_bytes()) if metadata_path.is_file() else {}
        if (
            key is None
            or not target.is_file()
            or target.is_symlink()
            or metadata.get("state") != "QUARANTINED"
            or metadata.get("classification") != classification
        ):
            raise CASError("quarantine object is unavailable")
        encrypted = target.read_bytes()
        aad = canonical_json_bytes({"schema": "CAS_QUARANTINE_AAD_V1", "classification": classification})
        try:
            return AESGCM(key).decrypt(encrypted[:12], encrypted[12:], aad)
        except Exception as error:
            raise CASError("quarantine authentication failed") from error

    def destroy_quarantine(self, quarantine_id: str, *, reason: str) -> dict[str, object]:
        self._assert_writable()
        target = self.root / "quarantine" / f"{quarantine_id}.q"
        metadata_path = self.root / "quarantine" / f"{quarantine_id}.meta.json"
        metadata = parse_canonical_json(metadata_path.read_bytes()) if metadata_path.is_file() else None
        cipher_hash = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() and not target.is_symlink() else None
        self._quarantine_keys.pop(quarantine_id, None)
        retained_unreadable = os.environ.get("SITINA_AUDIT_RETAIN_STAGING") == "1"
        if not retained_unreadable:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        sync_directory(self.root / "quarantine")
        attestation = {
            "schema": "CAS_QUARANTINE_DESTRUCTION_ATTESTATION_V1",
            "quarantine_id": quarantine_id,
            "ciphertext_hash": cipher_hash,
            "reason": reason,
            "destroyed": True,
            "ciphertext_retained_unreadable_for_no_delete_audit": retained_unreadable,
        }
        attestation_id = domain_hash("CAS_QUARANTINE_DESTRUCTION", canonical_json_bytes(attestation))
        attestation_path = self.root / "destruction-attestations" / f"{attestation_id}.json"
        self._publish_bytes(canonical_json_bytes(attestation), attestation_path)
        if isinstance(metadata, Mapping):
            self._replace_json(
                metadata_path,
                {
                    **dict(metadata),
                    "state": "DESTROYED_WITH_ATTESTATION",
                    "attestation_id": attestation_id,
                },
            )
        return {**attestation, "attestation_id": attestation_id}

    def quarantine_exists(self, quarantine_id: str) -> bool:
        return quarantine_id in self._quarantine_keys and (self.root / "quarantine" / f"{quarantine_id}.q").is_file()

    def promote_quarantine(
        self,
        quarantine_id: str,
        *,
        classification: str,
        sanitized_plaintext: bytes,
        tenant_id: str,
        purpose_class: str,
        compression: str = "auto",
        media_type: str | None = None,
    ) -> ContentPublication:
        """Publish only caller-sanitized bytes; quarantined raw bytes never enter CAS."""
        self._assert_writable()
        if not isinstance(sanitized_plaintext, bytes):
            raise CASError("sanitized quarantine output must be bytes")
        metadata_path = self.root / "quarantine" / f"{quarantine_id}.meta.json"
        if not metadata_path.is_file() or metadata_path.is_symlink():
            raise CASError("quarantine state record is missing")
        metadata = parse_canonical_json(metadata_path.read_bytes())
        if (
            metadata.get("state") != "QUARANTINED"
            or metadata.get("classification") != classification
            or quarantine_id not in self._quarantine_keys
        ):
            raise CASError("quarantine object is not eligible for sanitation")
        sanitized_hash = hashlib.sha256(sanitized_plaintext).hexdigest()
        self._replace_json(metadata_path, {**metadata, "state": "SANITIZED", "sanitized_hash": sanitized_hash})
        publication = self.publish_plaintext(
            sanitized_plaintext,
            tenant_id=tenant_id,
            purpose_class=purpose_class,
            compression=compression,
            media_type=media_type,
        )
        self._replace_json(
            metadata_path,
            {
                **metadata,
                "state": "PUBLISHED",
                "sanitized_hash": sanitized_hash,
                "published_ref": publication.receipt.object_ref.reference_id,
            },
        )
        self.destroy_quarantine(quarantine_id, reason="SANITIZED_CONTENT_PUBLISHED")
        return publication

    def reconcile_quarantine(self, *, dry_run: bool = True) -> dict[str, Any]:
        """Identify restart-orphaned quarantine and attest disposal only in disposable fixtures."""
        if not dry_run:
            self._assert_writable()
        if not dry_run and (
            self.namespace_kind != "controlled_fixture"
            or not (self.home / ".sitina-bplus-disposable-v1").is_file()
        ):
            raise CASError("quarantine reconciliation execution is restricted to disposable fixtures")
        restart_unrecoverable: list[str] = []
        attested_residuals: list[str] = []
        untracked_ciphertexts: list[str] = []
        actions: list[dict[str, Any]] = []
        known_ciphertexts: set[str] = set()
        for metadata_path in sorted((self.root / "quarantine").glob("*.meta.json")):
            if metadata_path.is_symlink():
                raise CASError("quarantine metadata rejects symlinks")
            metadata = parse_canonical_json(metadata_path.read_bytes())
            quarantine_id = str(metadata.get("quarantine_id", ""))
            target = self.root / "quarantine" / f"{quarantine_id}.q"
            known_ciphertexts.add(target.name)
            state = metadata.get("state")
            if state in {"QUARANTINED", "SANITIZED"} and target.is_file() and quarantine_id not in self._quarantine_keys:
                restart_unrecoverable.append(quarantine_id)
                actions.append({"quarantine_id": quarantine_id, "action": "DESTROY_WITH_ATTESTATION"})
                if not dry_run:
                    self.destroy_quarantine(quarantine_id, reason="UNRECOVERABLE_AFTER_RESTART")
            elif state == "DESTROYED_WITH_ATTESTATION" and target.is_file():
                attested_residuals.append(quarantine_id)
        for target in sorted((self.root / "quarantine").glob("*.q")):
            if target.name not in known_ciphertexts:
                untracked_ciphertexts.append(target.stem)
        return {
            "schema": "CAS_QUARANTINE_RECONCILE_REPORT_V1",
            "dry_run": dry_run,
            "restart_unrecoverable": restart_unrecoverable,
            "attested_residuals": attested_residuals,
            "untracked_ciphertexts": untracked_ciphertexts,
            "planned_actions": actions,
            "physical_delete_executed": not dry_run and bool(actions),
        }
