from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class KeyProviderError(RuntimeError):
    pass


class KeyPurpose(str, Enum):
    CAS_KEK = "cas-kek"
    CAS_COMMITMENT = "cas-commitment"
    JOURNAL_AUTH = "journal-auth"
    EVIDENCE_SIGNING = "evidence-signing"
    AUTHORITY_SIGNING = "authority-signing"


@dataclass(frozen=True)
class KeyCapability:
    capability_id: str
    allowed_purposes: frozenset[KeyPurpose]
    environment: str
    namespace: str
    current_only: bool = False

    def permits(self, purpose: KeyPurpose, *, environment: str, namespace: str, current: bool) -> bool:
        return (
            purpose in self.allowed_purposes
            and self.environment == environment
            and self.namespace == namespace
            and (not self.current_only or current)
        )


@dataclass(frozen=True)
class KeyDescriptor:
    key_id: str
    purpose: KeyPurpose
    provider: str
    environment: str
    namespace: str
    version: int
    profile: str


@dataclass(frozen=True)
class EvidenceSealerCapability:
    capability_id: str
    principal_role: str
    environment: str
    namespace: str
    _provider_nonce: str = ""


class InMemoryKeyProvider:
    """Ephemeral test provider. Secret bytes never leave this process."""

    provider_id = "memory"

    def __init__(self, *, environment: str = "test", namespace: str = "fixture"):
        validate_identifier(environment, field="environment")
        validate_identifier(namespace, field="namespace")
        self.environment = environment
        self.namespace = namespace
        self._current = {purpose: 1 for purpose in KeyPurpose}
        self._symmetric: dict[tuple[KeyPurpose, int], bytes] = {}
        self._signing: dict[tuple[KeyPurpose, int], Ed25519PrivateKey] = {}
        self._destroyed: set[tuple[KeyPurpose, int]] = set()
        self._sealer_nonce = os.urandom(32).hex()
        self._sealer_capabilities: set[str] = set()

    def issue_evidence_sealer_capability(self, principal_role: str) -> EvidenceSealerCapability:
        if principal_role != "evidence-sealer":
            raise KeyProviderError("only the evidence-sealer role may receive an evidence signing handle")
        capability_id = "evidence-sealer:" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "provider": self.provider_id,
                    "environment": self.environment,
                    "namespace": self.namespace,
                    "role": principal_role,
                    "nonce": os.urandom(16).hex(),
                }
            )
        ).hexdigest()
        self._sealer_capabilities.add(capability_id)
        return EvidenceSealerCapability(capability_id, principal_role, self.environment, self.namespace, self._sealer_nonce)

    def sign_evidence_seal(self, message: bytes, capability: EvidenceSealerCapability) -> tuple[str, bytes]:
        if (
            not isinstance(capability, EvidenceSealerCapability)
            or capability.capability_id not in self._sealer_capabilities
            or capability.principal_role != "evidence-sealer"
            or capability.environment != self.environment
            or capability.namespace != self.namespace
            or not hmac.compare_digest(capability._provider_nonce, self._sealer_nonce)
        ):
            raise KeyProviderError("evidence sealer capability is invalid or foreign")
        return self.sign(KeyPurpose.EVIDENCE_SIGNING, message)

    def capability(self, *purposes: KeyPurpose, current_only: bool = False) -> KeyCapability:
        if not purposes:
            raise KeyProviderError("capability requires at least one purpose")
        digest = domain_hash(
            "KEY_CAPABILITY",
            canonical_json_bytes(
                {
                    "provider": self.provider_id,
                    "environment": self.environment,
                    "namespace": self.namespace,
                    "purposes": sorted(purpose.value for purpose in purposes),
                    "current_only": current_only,
                }
            ),
        )
        return KeyCapability(f"cap:{digest}", frozenset(purposes), self.environment, self.namespace, current_only)

    @property
    def runtime_journal_capability(self) -> KeyCapability:
        return self.capability(KeyPurpose.JOURNAL_AUTH, current_only=True)

    def _descriptor(self, purpose: KeyPurpose, version: int) -> KeyDescriptor:
        profile = "AES256_GCM_V1" if purpose in {KeyPurpose.CAS_KEK, KeyPurpose.CAS_COMMITMENT} else (
            "HMAC_SHA256_V1" if purpose is KeyPurpose.JOURNAL_AUTH else "ED25519_V1"
        )
        key_id = f"{self.provider_id}:{self.environment}:{self.namespace}:{purpose.value}:v{version}:{profile.lower()}"
        return KeyDescriptor(key_id, purpose, self.provider_id, self.environment, self.namespace, version, profile)

    def current_descriptor(self, purpose: KeyPurpose, capability: KeyCapability | None = None) -> KeyDescriptor:
        version = self._current[purpose]
        self._authorize(purpose, version, capability)
        self._ensure(purpose, version)
        return self._descriptor(purpose, version)

    def _authorize(self, purpose: KeyPurpose, version: int, capability: KeyCapability | None) -> None:
        if capability is None:
            return
        current = version == self._current[purpose]
        if not capability.permits(purpose, environment=self.environment, namespace=self.namespace, current=current):
            raise KeyProviderError("key capability does not authorize purpose/environment/version")

    def _ensure(self, purpose: KeyPurpose, version: int) -> None:
        key = (purpose, version)
        if key in self._destroyed:
            raise KeyProviderError("key material has been destroyed")
        if purpose in {KeyPurpose.EVIDENCE_SIGNING, KeyPurpose.AUTHORITY_SIGNING}:
            self._signing.setdefault(key, Ed25519PrivateKey.generate())
        else:
            self._symmetric.setdefault(key, AESGCM.generate_key(bit_length=256))

    def _parse_id(self, key_id: str, expected: KeyPurpose) -> int:
        prefix = f"{self.provider_id}:{self.environment}:{self.namespace}:{expected.value}:v"
        if not key_id.startswith(prefix):
            raise KeyProviderError("key ID belongs to another purpose, environment, or namespace")
        match = re.match(re.escape(prefix) + r"(\d+):", key_id)
        if not match:
            raise KeyProviderError("malformed key ID")
        version = int(match.group(1))
        if self._descriptor(expected, version).key_id != key_id:
            raise KeyProviderError("key profile mismatch")
        return version

    def symmetric_for_id(self, key_id: str, purpose: KeyPurpose, capability: KeyCapability | None = None) -> bytes:
        version = self._parse_id(key_id, purpose)
        self._authorize(purpose, version, capability)
        self._ensure(purpose, version)
        return self._symmetric[(purpose, version)]

    def wrap_dek(self, dek: bytes, aad: bytes, capability: KeyCapability | None = None) -> dict[str, Any]:
        descriptor = self.current_descriptor(KeyPurpose.CAS_KEK, capability)
        nonce = os.urandom(12)
        wrapped = AESGCM(self.symmetric_for_id(descriptor.key_id, KeyPurpose.CAS_KEK, capability)).encrypt(nonce, dek, aad)
        return {"key_id": descriptor.key_id, "nonce": nonce, "wrapped_dek": wrapped}

    def unwrap_dek(self, key_id: str, nonce: bytes, wrapped_dek: bytes, aad: bytes, capability: KeyCapability | None = None) -> bytes:
        key = self.symmetric_for_id(key_id, KeyPurpose.CAS_KEK, capability)
        try:
            return AESGCM(key).decrypt(nonce, wrapped_dek, aad)
        except Exception as error:
            raise KeyProviderError("DEK envelope authentication failed") from error

    def commitment(self, tenant_id: str, plaintext: bytes, capability: KeyCapability | None = None) -> tuple[str, str]:
        descriptor = self.current_descriptor(KeyPurpose.CAS_COMMITMENT, capability)
        key = self.symmetric_for_id(descriptor.key_id, KeyPurpose.CAS_COMMITMENT, capability)
        preimage = b"SITINA-TENANT-COMMITMENT-V1\0" + tenant_id.encode() + b"\0" + plaintext
        return descriptor.key_id, hmac.new(key, preimage, hashlib.sha256).hexdigest()

    def verify_commitment(self, key_id: str, tenant_id: str, plaintext: bytes, expected: str) -> bool:
        key = self.symmetric_for_id(key_id, KeyPurpose.CAS_COMMITMENT)
        preimage = b"SITINA-TENANT-COMMITMENT-V1\0" + tenant_id.encode() + b"\0" + plaintext
        return hmac.compare_digest(hmac.new(key, preimage, hashlib.sha256).hexdigest(), expected)

    def sign(self, purpose: KeyPurpose, message: bytes, capability: KeyCapability | None = None) -> tuple[str, bytes]:
        if purpose not in {KeyPurpose.EVIDENCE_SIGNING, KeyPurpose.AUTHORITY_SIGNING}:
            raise KeyProviderError("purpose is not an Ed25519 signing purpose")
        descriptor = self.current_descriptor(purpose, capability)
        return descriptor.key_id, self._signing[(purpose, descriptor.version)].sign(message)

    def sign_with_key_id(self, key_id: str, purpose: KeyPurpose, message: bytes) -> bytes:
        if purpose not in {KeyPurpose.EVIDENCE_SIGNING, KeyPurpose.AUTHORITY_SIGNING}:
            raise KeyProviderError("purpose is not an Ed25519 signing purpose")
        version = self._parse_id(key_id, purpose)
        self._ensure(purpose, version)
        return self._signing[(purpose, version)].sign(message)

    def verify(self, key_id: str, purpose: KeyPurpose, message: bytes, signature: bytes) -> bool:
        version = self._parse_id(key_id, purpose)
        self._ensure(purpose, version)
        public: Ed25519PublicKey = self._signing[(purpose, version)].public_key()
        try:
            public.verify(signature, message)
            return True
        except Exception:
            return False

    def rotate(self, purpose: KeyPurpose) -> KeyDescriptor:
        self._current[purpose] += 1
        version = self._current[purpose]
        self._ensure(purpose, version)
        return self._descriptor(purpose, version)

    def destroy(self, purpose: KeyPurpose, version: int) -> dict[str, Any]:
        self._symmetric.pop((purpose, version), None)
        self._signing.pop((purpose, version), None)
        self._destroyed.add((purpose, version))
        return {
            "schema": "KEY_DESTRUCTION_ATTESTATION_V1",
            "key_id": self._descriptor(purpose, version).key_id,
            "purpose": purpose.value,
            "environment": self.environment,
            "namespace": self.namespace,
            "destroyed": True,
        }


class JournalAuthProvider:
    def __init__(self, provider: InMemoryKeyProvider, capability: KeyCapability | None = None):
        self.provider = provider
        self.capability = capability or provider.runtime_journal_capability

    @staticmethod
    def preimage(journal_id: str, epoch: int, key_id: str, event_hash: str) -> bytes:
        return (
            b"SITINA-JOURNAL-AUTH-V1\0"
            + journal_id.encode()
            + b"\0"
            + epoch.to_bytes(8, "big")
            + b"\0"
            + key_id.encode()
            + b"\0"
            + bytes.fromhex(event_hash)
        )

    def authenticate(self, journal_id: str, epoch: int, event_hash: str) -> tuple[str, str]:
        descriptor = self.provider.current_descriptor(KeyPurpose.JOURNAL_AUTH, self.capability)
        key = self.provider.symmetric_for_id(descriptor.key_id, KeyPurpose.JOURNAL_AUTH, self.capability)
        return descriptor.key_id, hmac.new(key, self.preimage(journal_id, epoch, descriptor.key_id, event_hash), hashlib.sha256).hexdigest()

    def verify(self, journal_id: str, epoch: int, key_id: str, event_hash: str, tag: str) -> bool:
        try:
            key = self.provider.symmetric_for_id(key_id, KeyPurpose.JOURNAL_AUTH)
        except KeyProviderError:
            return False
        expected = hmac.new(key, self.preimage(journal_id, epoch, key_id, event_hash), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, tag)

    def rotate(self, *, at_segment_boundary: bool, epoch: int, previous_segment_commitment: str, effective_position: int, policy_hash: str) -> dict[str, Any]:
        if not at_segment_boundary:
            raise KeyProviderError("Journal auth rotation is allowed only at a segment boundary")
        old = self.provider.current_descriptor(KeyPurpose.JOURNAL_AUTH, self.capability)
        old_key = self.provider.symmetric_for_id(old.key_id, KeyPurpose.JOURNAL_AUTH, self.capability)
        new = self.provider.rotate(KeyPurpose.JOURNAL_AUTH)
        new_key = self.provider.symmetric_for_id(new.key_id, KeyPurpose.JOURNAL_AUTH, self.capability)
        unsigned = {
            "schema": "JOURNAL_AUTH_KEY_TRANSITION_V1",
            "old_key_id": old.key_id,
            "new_key_id": new.key_id,
            "epoch": epoch,
            "previous_segment_commitment": previous_segment_commitment,
            "effective_position": effective_position,
            "policy_hash": policy_hash,
        }
        message = canonical_json_bytes(unsigned)
        return {
            **unsigned,
            "old_key_proof": hmac.new(old_key, b"SITINA-JOURNAL-KEY-TRANSITION-V1\0" + message, hashlib.sha256).hexdigest(),
            "new_key_proof": hmac.new(new_key, b"SITINA-JOURNAL-KEY-TRANSITION-V1\0" + message, hashlib.sha256).hexdigest(),
        }

    def verify_rotation(self, transition: Mapping[str, Any]) -> bool:
        required = {
            "schema", "old_key_id", "new_key_id", "epoch", "previous_segment_commitment",
            "effective_position", "policy_hash", "old_key_proof", "new_key_proof",
        }
        if set(transition) != required or transition.get("schema") != "JOURNAL_AUTH_KEY_TRANSITION_V1":
            return False
        unsigned = {key: value for key, value in transition.items() if key not in {"old_key_proof", "new_key_proof"}}
        message = canonical_json_bytes(unsigned)
        try:
            old_key = self.provider.symmetric_for_id(str(transition["old_key_id"]), KeyPurpose.JOURNAL_AUTH)
            new_key = self.provider.symmetric_for_id(str(transition["new_key_id"]), KeyPurpose.JOURNAL_AUTH)
        except KeyProviderError:
            return False
        old = hmac.new(old_key, b"SITINA-JOURNAL-KEY-TRANSITION-V1\0" + message, hashlib.sha256).hexdigest()
        new = hmac.new(new_key, b"SITINA-JOURNAL-KEY-TRANSITION-V1\0" + message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(old, str(transition["old_key_proof"])) and hmac.compare_digest(
            new, str(transition["new_key_proof"])
        )
