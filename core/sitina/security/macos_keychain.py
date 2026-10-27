from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import platform
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .key_provider import (
    EvidenceSealerCapability,
    KeyCapability,
    KeyDescriptor,
    KeyProviderError,
    KeyPurpose,
)


class KeychainBackend(Protocol):
    def get(self, service: str, account: str) -> bytes | None: ...
    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None: ...
    def public_inventory(self) -> dict[str, object]: ...


class MemoryKeychainBackend:
    """Persistent-in-object non-Production backend used by deterministic tests."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], bytes] = {}
        self._lock = threading.Lock()

    def get(self, service: str, account: str) -> bytes | None:
        with self._lock:
            value = self._items.get((service, account))
            return bytes(value) if value is not None else None

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        with self._lock:
            key = (service, account)
            if key in self._items and not replace:
                raise KeyProviderError("Keychain item already exists")
            self._items[key] = bytes(value)

    def delete(self, service: str, account: str) -> None:
        with self._lock:
            self._items.pop((service, account), None)

    def public_inventory(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema": "MEMORY_KEYCHAIN_PUBLIC_INVENTORY_V1",
                "item_count": len(self._items),
                "items": [{"service": service, "account": account} for service, account in sorted(self._items)],
                "secret_values_included": False,
            }


class IsolatedOverlayKeychainBackend:
    """Read-through, memory-only overlay for exact restore simulations.

    Existing verification/signing material may be read from the protected
    source backend, but every put is captured in volatile memory. Services
    such as the rollback anchor can be isolated from source reads so a drill
    can neither observe nor advance Production anti-rollback state.
    """

    def __init__(self, source: KeychainBackend, *, isolated_services: tuple[str, ...] = ()):
        self.source = source
        self.overlay = MemoryKeychainBackend()
        self.isolated_services = frozenset(isolated_services)
        self._lock = threading.RLock()

    def get(self, service: str, account: str) -> bytes | None:
        with self._lock:
            value = self.overlay.get(service, account)
            if value is not None or service in self.isolated_services:
                return value
            value = self.source.get(service, account)
            if value is not None:
                self.overlay.put(service, account, value)
                return bytes(value)
            return None

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        with self._lock:
            self.overlay.put(service, account, value, replace=replace)

    def public_inventory(self) -> dict[str, object]:
        overlay = self.overlay.public_inventory()
        return {
            "schema": "ISOLATED_OVERLAY_KEYCHAIN_PUBLIC_INVENTORY_V1",
            "source": self.source.public_inventory(),
            "volatile_overlay_items": overlay["items"],
            "isolated_services": sorted(self.isolated_services),
            "durable_secret_copy_count": 0,
            "source_mutation_count": 0,
            "secret_values_included": False,
        }


class SecurityCLIKeychainBackend:
    """macOS Keychain backend; secret material travels only over process pipes.

    `security add-generic-password -w` is deliberately the final argument, so
    the tool prompts on stdin rather than exposing the secret in argv.
    """

    def __init__(self, *, security_binary: str = "/usr/bin/security", keychain: str | None = None):
        if not os.path.isfile(security_binary):
            raise KeyProviderError("macOS security tool is unavailable")
        self.security_binary = security_binary
        self.keychain = keychain
        self._known: set[tuple[str, str]] = set()

    def _keychain_arg(self) -> list[str]:
        return [self.keychain] if self.keychain else []

    def get(self, service: str, account: str) -> bytes | None:
        command = [self.security_binary, "find-generic-password", "-a", account, "-s", service, "-w", *self._keychain_arg()]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode == 44:
            return None
        if result.returncode != 0:
            raise KeyProviderError(f"macOS Keychain lookup failed with status {result.returncode}")
        try:
            value = base64.b64decode(result.stdout.strip(), validate=True)
        except Exception as error:
            raise KeyProviderError("macOS Keychain returned malformed secret material") from error
        self._known.add((service, account))
        return value

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        command = [self.security_binary, "add-generic-password", "-a", account, "-s", service]
        if replace:
            command.append("-U")
        command.extend(self._keychain_arg())
        command.append("-w")
        secret = base64.b64encode(value) + b"\n"
        result = subprocess.run(command, input=secret, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode != 0:
            raise KeyProviderError(f"macOS Keychain store failed with status {result.returncode}")
        self._known.add((service, account))

    def public_inventory(self) -> dict[str, object]:
        return {
            "schema": "MACOS_KEYCHAIN_PUBLIC_INVENTORY_V1",
            "provider_profile": "MACOS_KEYCHAIN_LOCAL_V1",
            "items": [{"service": service, "account": account} for service, account in sorted(self._known)],
            "secret_values_included": False,
        }


class SecurityFrameworkKeychainBackend:
    """Direct Security.framework backend with no secret material in argv.

    The optional private keychain mode exists for destructive integration
    tests.  Production uses the user's default keychain and never needs a
    keychain password in this process.
    """

    ERR_ITEM_NOT_FOUND = -25300
    ERR_DUPLICATE_ITEM = -25299

    def __init__(
        self,
        *,
        keychain_path: str | None = None,
        create: bool = False,
        keychain_password: bytes | None = None,
    ) -> None:
        if platform.system() != "Darwin":
            raise KeyProviderError("macOS Security.framework is unavailable")
        self._security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        self._core = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self._configure_signatures()
        self._known: set[tuple[str, str]] = set()
        self._lock = threading.RLock()
        self._keychain = ctypes.c_void_p()
        self._private_path = os.path.abspath(keychain_path) if keychain_path else None
        self._deleted = False
        if create:
            if not self._private_path or keychain_password is None:
                raise KeyProviderError("private test keychain creation requires a path and password")
            password = ctypes.create_string_buffer(keychain_password)
            status = self._security.SecKeychainCreate(
                os.fsencode(self._private_path),
                len(keychain_password),
                ctypes.cast(password, ctypes.c_void_p),
                False,
                None,
                ctypes.byref(self._keychain),
            )
        elif self._private_path:
            status = self._security.SecKeychainOpen(os.fsencode(self._private_path), ctypes.byref(self._keychain))
        else:
            status = self._security.SecKeychainCopyDefault(ctypes.byref(self._keychain))
        self._check(status, "open")

    def _configure_signatures(self) -> None:
        sec = self._security
        sec.SecKeychainCopyDefault.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        sec.SecKeychainCopyDefault.restype = ctypes.c_int32
        sec.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        sec.SecKeychainOpen.restype = ctypes.c_int32
        sec.SecKeychainCreate.argtypes = [
            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_bool,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainCreate.restype = ctypes.c_int32
        sec.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainItemModifyAttributesAndData.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ]
        sec.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
        sec.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        sec.SecKeychainItemFreeContent.restype = ctypes.c_int32
        sec.SecKeychainDelete.argtypes = [ctypes.c_void_p]
        sec.SecKeychainDelete.restype = ctypes.c_int32
        sec.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
        sec.SecKeychainItemDelete.restype = ctypes.c_int32
        self._core.CFRelease.argtypes = [ctypes.c_void_p]
        self._core.CFRelease.restype = None

    @staticmethod
    def _buffer(value: bytes) -> ctypes.Array[Any]:
        return ctypes.create_string_buffer(value, max(1, len(value)))

    @staticmethod
    def _check(status: int, operation: str) -> None:
        if int(status) != 0:
            raise KeyProviderError(f"macOS Keychain {operation} failed with status {int(status)}")

    def _find(self, service: str, account: str) -> tuple[bytes | None, ctypes.c_void_p | None]:
        service_raw = service.encode("utf-8")
        account_raw = account.encode("utf-8")
        service_buffer = self._buffer(service_raw)
        account_buffer = self._buffer(account_raw)
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._security.SecKeychainFindGenericPassword(
            self._keychain,
            len(service_raw), ctypes.cast(service_buffer, ctypes.c_void_p),
            len(account_raw), ctypes.cast(account_buffer, ctypes.c_void_p),
            ctypes.byref(length), ctypes.byref(data), ctypes.byref(item),
        )
        if int(status) == self.ERR_ITEM_NOT_FOUND:
            return None, None
        self._check(status, "lookup")
        try:
            value = ctypes.string_at(data, length.value)
        finally:
            if data:
                self._security.SecKeychainItemFreeContent(None, data)
        return value, item

    def get(self, service: str, account: str) -> bytes | None:
        with self._lock:
            value, item = self._find(service, account)
            if item:
                self._core.CFRelease(item)
            if value is not None:
                self._known.add((service, account))
            return value

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        with self._lock:
            existing, item = self._find(service, account)
            del existing
            value_buffer = self._buffer(value)
            try:
                if item:
                    if not replace:
                        raise KeyProviderError("Keychain item already exists")
                    status = self._security.SecKeychainItemModifyAttributesAndData(
                        item, None, len(value), ctypes.cast(value_buffer, ctypes.c_void_p)
                    )
                    self._check(status, "update")
                else:
                    service_raw = service.encode("utf-8")
                    account_raw = account.encode("utf-8")
                    service_buffer = self._buffer(service_raw)
                    account_buffer = self._buffer(account_raw)
                    created = ctypes.c_void_p()
                    status = self._security.SecKeychainAddGenericPassword(
                        self._keychain,
                        len(service_raw), ctypes.cast(service_buffer, ctypes.c_void_p),
                        len(account_raw), ctypes.cast(account_buffer, ctypes.c_void_p),
                        len(value), ctypes.cast(value_buffer, ctypes.c_void_p),
                        ctypes.byref(created),
                    )
                    self._check(status, "store")
                    if created:
                        self._core.CFRelease(created)
            finally:
                if item:
                    self._core.CFRelease(item)
            self._known.add((service, account))

    def public_inventory(self) -> dict[str, object]:
        return {
            "schema": "MACOS_SECURITY_FRAMEWORK_KEYCHAIN_PUBLIC_INVENTORY_V1",
            "provider_profile": "MACOS_SECURITY_FRAMEWORK_LOCAL_V1",
            "keychain_scope": "PRIVATE_TEST" if self._private_path else "DEFAULT",
            "items": [{"service": service, "account": account} for service, account in sorted(self._known)],
            "secret_values_included": False,
            "secret_argv_transport": False,
        }

    def delete(self, service: str, account: str) -> None:
        """Remove one exact item, never the default Keychain itself."""
        with self._lock:
            value, item = self._find(service, account)
            del value
            if item:
                try:
                    self._check(self._security.SecKeychainItemDelete(item), "item delete")
                finally:
                    self._core.CFRelease(item)
            self._known.discard((service, account))

    def delete_private_keychain(self) -> None:
        with self._lock:
            if not self._private_path:
                raise KeyProviderError("default keychain cannot be deleted")
            if self._deleted:
                return
            self._check(self._security.SecKeychainDelete(self._keychain), "delete")
            self._deleted = True

    def close(self) -> None:
        with self._lock:
            if self._keychain:
                self._core.CFRelease(self._keychain)
                self._keychain = ctypes.c_void_p()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class OpaqueKeychainReference:
    key_id: str
    service: str
    account: str
    purpose: KeyPurpose


class MacOSKeychainProvider:
    provider_id = "macos-keychain"

    def __init__(self, *, environment: str, namespace: str, backend: KeychainBackend | None = None):
        validate_identifier(environment, field="environment")
        validate_identifier(namespace, field="namespace")
        self.environment = environment
        self.namespace = namespace
        self.backend = backend or SecurityFrameworkKeychainBackend()
        self.service = f"com.sitina.bplus.keys.{environment}.{namespace}"
        self._lock = threading.RLock()
        self._references: dict[str, OpaqueKeychainReference] = {}
        # Key versions are immutable. Keep material only in this provider
        # process after the first protected lookup; the Keychain remains the
        # durable authority and no cache is persisted or exposed.
        self._material_cache: dict[tuple[KeyPurpose, int], bytes] = {}
        self._sealer_nonce = os.urandom(32).hex()
        self._sealer_capabilities: set[str] = set()
        registry = self.backend.get(self.service, "registry")
        if registry is None:
            self._current = {purpose: 1 for purpose in KeyPurpose}
        else:
            try:
                value = json.loads(registry)
                self._current = {purpose: int(value[purpose.value]) for purpose in KeyPurpose}
            except Exception as error:
                raise KeyProviderError("macOS Keychain version registry is malformed") from error

    def destroy_namespace(self) -> dict[str, object]:
        """Delete this exact provider namespace after its writer is closed.

        Callers must hold the native authority lease. Provider credentials
        belong to different services and are never enumerated or touched.
        """
        delete = getattr(self.backend, "delete", None)
        if not callable(delete):
            raise KeyProviderError("Keychain backend cannot delete exact namespace items")
        accounts = [self._account(purpose, version)
                    for purpose in KeyPurpose
                    for version in range(1, self._current[purpose] + 1)]
        removed = 0
        for account in accounts:
            if self.backend.get(self.service, account) is not None:
                delete(self.service, account)
                removed += 1
            if self.backend.get(self.service, account) is not None:
                raise KeyProviderError("namespace key deletion did not verify absent")
        delete(self.service, "registry")
        if self.backend.get(self.service, "registry") is not None:
            raise KeyProviderError("namespace registry deletion did not verify absent")
        self._material_cache.clear()
        self._references.clear()
        return {"namespace": self.namespace, "removed_key_count": removed,
                "verified_absent": True, "provider_credentials_touched": False}

    def _persist_registry(self) -> None:
        value = canonical_json_bytes({purpose.value: version for purpose, version in self._current.items()})
        self.backend.put(self.service, "registry", value, replace=self.backend.get(self.service, "registry") is not None)

    def _account(self, purpose: KeyPurpose, version: int) -> str:
        return f"{purpose.value}:v{version}"

    def _descriptor(self, purpose: KeyPurpose, version: int) -> KeyDescriptor:
        profile = "AES256_GCM_V1" if purpose in {KeyPurpose.CAS_KEK, KeyPurpose.CAS_COMMITMENT} else (
            "HMAC_SHA256_V1" if purpose is KeyPurpose.JOURNAL_AUTH else "ED25519_V1"
        )
        key_id = f"{self.provider_id}:{self.environment}:{self.namespace}:{purpose.value}:v{version}:{profile.lower()}"
        return KeyDescriptor(key_id, purpose, self.provider_id, self.environment, self.namespace, version, profile)

    def _material(self, purpose: KeyPurpose, version: int) -> bytes:
        account = self._account(purpose, version)
        with self._lock:
            cached = self._material_cache.get((purpose, version))
            if cached is not None:
                return bytes(cached)
            material = self.backend.get(self.service, account)
            if material is None:
                generated = (
                    Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                    if purpose in {KeyPurpose.EVIDENCE_SIGNING, KeyPurpose.AUTHORITY_SIGNING}
                    else AESGCM.generate_key(bit_length=256)
                )
                try:
                    self.backend.put(self.service, account, generated)
                    material = generated
                except KeyProviderError:
                    material = self.backend.get(self.service, account)
                    if material is None:
                        raise
            if len(material) != 32:
                raise KeyProviderError("Keychain key material has an invalid length")
            self._material_cache[(purpose, version)] = bytes(material)
            return bytes(material)

    def capability(self, *purposes: KeyPurpose, current_only: bool = False) -> KeyCapability:
        if not purposes:
            raise KeyProviderError("capability requires at least one purpose")
        digest = domain_hash(
            "KEY_CAPABILITY",
            canonical_json_bytes({
                "provider": self.provider_id,
                "environment": self.environment,
                "namespace": self.namespace,
                "purposes": sorted(item.value for item in purposes),
                "current_only": current_only,
            }),
        )
        return KeyCapability(f"cap:{digest}", frozenset(purposes), self.environment, self.namespace, current_only)

    @property
    def runtime_journal_capability(self) -> KeyCapability:
        return self.capability(KeyPurpose.JOURNAL_AUTH, current_only=True)

    def _authorize(self, purpose: KeyPurpose, version: int, capability: KeyCapability | None) -> None:
        if capability is None:
            return
        if not capability.permits(
            purpose,
            environment=self.environment,
            namespace=self.namespace,
            current=version == self._current[purpose],
        ):
            raise KeyProviderError("key capability does not authorize purpose/environment/version")

    def current_descriptor(self, purpose: KeyPurpose, capability: KeyCapability | None = None) -> KeyDescriptor:
        version = self._current[purpose]
        self._authorize(purpose, version, capability)
        self._material(purpose, version)
        descriptor = self._descriptor(purpose, version)
        self._references[descriptor.key_id] = OpaqueKeychainReference(descriptor.key_id, self.service, self._account(purpose, version), purpose)
        return descriptor

    def initialize_persistent_descriptors(
        self,
        purposes: tuple[KeyPurpose, ...],
    ) -> tuple[KeyDescriptor, ...]:
        """Create the requested immutable key versions and persist their registry.

        Ordinary provider calls retain their lazy behaviour.  Runtime bootstrap
        uses this explicit method so a fresh Journal/CAS namespace has a durable
        version registry before it can record any business state.
        """

        if not purposes or len(set(purposes)) != len(purposes):
            raise KeyProviderError("persistent key bootstrap requires unique purposes")
        with self._lock:
            descriptors = tuple(self.current_descriptor(purpose) for purpose in purposes)
            self._persist_registry()
            return descriptors

    def require_existing_descriptor(
        self,
        purpose: KeyPurpose,
        *,
        key_id: str | None = None,
    ) -> KeyDescriptor:
        """Load an existing Keychain item without creating replacement material.

        Recovery callers must never use the lazy ``current_descriptor`` path:
        that path intentionally creates a missing key for a new namespace.  A
        missing registry or item here is therefore a hard recovery error.
        """

        registry = self.backend.get(self.service, "registry")
        if registry is None:
            raise KeyProviderError("persistent Keychain version registry is unavailable")
        try:
            versions = json.loads(registry)
            version = int(versions[purpose.value])
        except Exception as error:
            raise KeyProviderError("persistent Keychain version registry is malformed") from error
        descriptor = self._descriptor(purpose, version)
        if key_id is not None and descriptor.key_id != key_id:
            raise KeyProviderError("persistent Keychain descriptor differs from the recorded key ID")
        account = self._account(purpose, version)
        material = self.backend.get(self.service, account)
        if material is None:
            raise KeyProviderError("persistent Keychain key material is unavailable")
        if len(material) != 32:
            raise KeyProviderError("persistent Keychain key material has an invalid length")
        with self._lock:
            self._material_cache[(purpose, version)] = bytes(material)
            self._references[descriptor.key_id] = OpaqueKeychainReference(
                descriptor.key_id,
                self.service,
                account,
                purpose,
            )
        return descriptor

    def _parse_id(self, key_id: str, expected: KeyPurpose) -> int:
        prefix = f"{self.provider_id}:{self.environment}:{self.namespace}:{expected.value}:v"
        if not key_id.startswith(prefix):
            raise KeyProviderError("key ID belongs to another purpose, environment, or namespace")
        rest = key_id[len(prefix):]
        try:
            version = int(rest.split(":", 1)[0])
        except ValueError as error:
            raise KeyProviderError("malformed key ID") from error
        if self._descriptor(expected, version).key_id != key_id:
            raise KeyProviderError("key profile mismatch")
        return version

    def symmetric_for_id(self, key_id: str, purpose: KeyPurpose, capability: KeyCapability | None = None) -> bytes:
        version = self._parse_id(key_id, purpose)
        self._authorize(purpose, version, capability)
        return self._material(purpose, version)

    def wrap_dek(self, dek: bytes, aad: bytes, capability: KeyCapability | None = None) -> dict[str, Any]:
        descriptor = self.current_descriptor(KeyPurpose.CAS_KEK, capability)
        nonce = os.urandom(12)
        wrapped = AESGCM(self.symmetric_for_id(descriptor.key_id, KeyPurpose.CAS_KEK, capability)).encrypt(nonce, dek, aad)
        return {"key_id": descriptor.key_id, "nonce": nonce, "wrapped_dek": wrapped}

    def unwrap_dek(self, key_id: str, nonce: bytes, wrapped_dek: bytes, aad: bytes, capability: KeyCapability | None = None) -> bytes:
        try:
            return AESGCM(self.symmetric_for_id(key_id, KeyPurpose.CAS_KEK, capability)).decrypt(nonce, wrapped_dek, aad)
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
        private = Ed25519PrivateKey.from_private_bytes(self._material(purpose, descriptor.version))
        return descriptor.key_id, private.sign(message)

    def verify(self, key_id: str, purpose: KeyPurpose, message: bytes, signature: bytes) -> bool:
        version = self._parse_id(key_id, purpose)
        public: Ed25519PublicKey = Ed25519PrivateKey.from_private_bytes(self._material(purpose, version)).public_key()
        try:
            public.verify(signature, message)
            return True
        except Exception:
            return False

    def rotate(self, purpose: KeyPurpose) -> KeyDescriptor:
        with self._lock:
            self._current[purpose] += 1
            self._material(purpose, self._current[purpose])
            self._persist_registry()
            return self._descriptor(purpose, self._current[purpose])

    def issue_evidence_sealer_capability(self, principal_role: str) -> EvidenceSealerCapability:
        if principal_role != "evidence-sealer":
            raise KeyProviderError("only the evidence-sealer role may receive an evidence signing handle")
        capability_id = "evidence-sealer:" + hashlib.sha256(os.urandom(32)).hexdigest()
        self._sealer_capabilities.add(capability_id)
        return EvidenceSealerCapability(capability_id, principal_role, self.environment, self.namespace, self._sealer_nonce)

    def sign_evidence_seal(self, message: bytes, capability: EvidenceSealerCapability) -> tuple[str, bytes]:
        if (
            capability.capability_id not in self._sealer_capabilities
            or capability.principal_role != "evidence-sealer"
            or capability.environment != self.environment
            or capability.namespace != self.namespace
            or not hmac.compare_digest(capability._provider_nonce, self._sealer_nonce)
        ):
            raise KeyProviderError("evidence sealer capability is invalid or foreign")
        return self.sign(KeyPurpose.EVIDENCE_SIGNING, message)

    def register_opaque_reference(self, reference: OpaqueKeychainReference) -> None:
        if reference.key_id in self._references and self._references[reference.key_id] != reference:
            raise KeyProviderError("opaque key ID collision")
        self._references[reference.key_id] = reference

    def reference(self, key_id: str, purpose: KeyPurpose) -> OpaqueKeychainReference:
        try:
            reference = self._references[key_id]
        except KeyError as error:
            raise KeyProviderError("Keychain opaque reference is unavailable") from error
        if reference.purpose is not purpose:
            raise KeyProviderError("Keychain purpose mismatch")
        return reference

    def public_inventory(self) -> dict[str, object]:
        return self.backend.public_inventory()

    def secret_operation(self, *_args: object, **_kwargs: object) -> None:
        raise KeyProviderError("untyped Keychain secret operations are forbidden")
