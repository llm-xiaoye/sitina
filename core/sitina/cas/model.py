from __future__ import annotations

import datetime as dt
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, parse_canonical_json, validate_identifier


class CASError(RuntimeError):
    pass


@dataclass(frozen=True)
class ObjectRef:
    object_id: str
    tenant_id: str
    plaintext_commitment: str
    commitment_key_id: str
    profile: str = "SITINA_CRYPTO_V1"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.object_id):
            raise CASError("invalid CAS object identity")
        if not re.fullmatch(r"[0-9a-f]{64}", self.plaintext_commitment):
            raise CASError("invalid plaintext commitment")
        validate_identifier(self.tenant_id, field="tenant_id")
        validate_identifier(self.commitment_key_id, field="commitment_key_id")

    @property
    def reference_id(self) -> str:
        return f"cas:{self.object_id}"


@dataclass(frozen=True)
class ObjectEnvelope:
    envelope_id: str
    object_id: str
    core_header_hash: str
    key_id: str
    purpose: str
    wrap_profile: str
    version: int
    nonce_hex: str
    wrapped_dek_hex: str

    def __post_init__(self) -> None:
        for value, name in ((self.envelope_id, "envelope_id"), (self.object_id, "object_id"), (self.core_header_hash, "core_header_hash")):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise CASError(f"invalid {name}")
        validate_identifier(self.key_id, field="key_id")
        validate_identifier(self.purpose, field="purpose")
        if self.version < 1 or len(bytes.fromhex(self.nonce_hex)) != 12:
            raise CASError("invalid envelope version or nonce")
        bytes.fromhex(self.wrapped_dek_hex)

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_OBJECT_ENVELOPE_V1", "envelope_id": self.envelope_id, "object_id": self.object_id,
            "core_header_hash": self.core_header_hash, "key_id": self.key_id, "purpose": self.purpose,
            "wrap_profile": self.wrap_profile, "version": self.version, "nonce_hex": self.nonce_hex,
            "wrapped_dek_hex": self.wrapped_dek_hex,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.mapping())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ObjectEnvelope":
        fields = {"schema", "envelope_id", "object_id", "core_header_hash", "key_id", "purpose", "wrap_profile", "version", "nonce_hex", "wrapped_dek_hex"}
        value = parse_canonical_json(raw, allowed_fields=fields)
        if value.pop("schema") != "SITINA_OBJECT_ENVELOPE_V1":
            raise CASError("wrong envelope schema")
        return cls(**value)


@dataclass(frozen=True)
class EncryptedObject:
    reference: ObjectRef
    core_header: Mapping[str, Any]
    ciphertext: bytes
    envelope: ObjectEnvelope

    @property
    def core_header_bytes(self) -> bytes:
        return canonical_json_bytes(dict(self.core_header))

    @property
    def core_header_hash(self) -> str:
        return domain_hash("CAS_CORE_HEADER", self.core_header_bytes)

    def object_bytes(self) -> bytes:
        header = self.core_header_bytes
        return struct.pack(">I", len(header)) + header + self.ciphertext


_RECEIPT_ISSUER = object()


@dataclass(frozen=True)
class PublishedObjectReceipt:
    object_ref: ObjectRef
    object_path: str
    core_header_hash: str
    envelope_id: str
    issued_at: str
    expires_at: str
    durability_profile: str
    fresh_verified: bool
    no_replace_published: bool
    _issuer: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._issuer is not _RECEIPT_ISSUER:
            raise CASError("PublishedObjectReceipt may only be issued by LocalCAS")
        if not self.fresh_verified or not self.no_replace_published:
            raise CASError("receipt requires verified durable no-replace publication")

    @classmethod
    def _issue(cls, **values: Any) -> "PublishedObjectReceipt":
        return cls(**values, _issuer=_RECEIPT_ISSUER)

    def assert_valid(self, reference_id: str, *, now: dt.datetime | None = None) -> None:
        if self.object_ref.reference_id != reference_id:
            raise CASError("receipt does not match referenced object")
        current = now or dt.datetime.now(dt.timezone.utc)
        expiry = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if current > expiry:
            raise CASError("published object receipt expired")


_ROOT_PROOF_ISSUER = object()


@dataclass(frozen=True)
class ExistingDurableObjectRootProof:
    object_ref: ObjectRef
    journal_id: str
    rooted_transaction_hash: str
    rooted_position: int
    verified_frontier_position: int
    object_reference_manifest_hash: str
    _issuer: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._issuer is not _ROOT_PROOF_ISSUER:
            raise CASError("existing-root proof may only be issued by canonical Journal lookup")
        if self.rooted_position > self.verified_frontier_position:
            raise CASError("root is beyond verified frontier")

    @classmethod
    def _issue(cls, **values: Any) -> "ExistingDurableObjectRootProof":
        return cls(**values, _issuer=_ROOT_PROOF_ISSUER)

