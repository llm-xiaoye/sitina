from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class AdapterManifestError(ValueError):
    pass


class RecoveryLevel(str, Enum):
    A = "A"
    B = "B"
    C = "C"


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    version: int
    binary_hash: str
    operation: str
    externality: str
    reversibility: str
    recovery_level: RecoveryLevel
    request_schema_hash: str
    result_schema_hash: str
    remote_idempotency: bool
    status_query: bool
    not_found_proves_absence: bool
    external_request_id_required: bool
    idempotency_retention_seconds: int
    max_physical_sends_per_attempt: int
    sdk_retries_enabled: bool
    redirect_replay_enabled: bool
    publisher: str
    signature: str | None = None

    def __post_init__(self) -> None:
        for value, field in ((self.adapter_id, "adapter_id"), (self.operation, "operation"), (self.externality, "externality"), (self.reversibility, "reversibility"), (self.publisher, "publisher")):
            validate_identifier(value, field=field)
        if self.version < 1:
            raise AdapterManifestError("manifest version must be positive")
        for value, field in ((self.binary_hash, "binary_hash"), (self.request_schema_hash, "request_schema_hash"), (self.result_schema_hash, "result_schema_hash")):
            if len(value) != 64:
                raise AdapterManifestError(f"invalid {field}")
        if self.max_physical_sends_per_attempt != 1:
            raise AdapterManifestError("max_physical_sends_per_attempt must equal one")
        if self.sdk_retries_enabled or self.redirect_replay_enabled:
            raise AdapterManifestError("hidden transport body replay must be disabled")
        if self.idempotency_retention_seconds < 0:
            raise AdapterManifestError("invalid idempotency retention")
        if self.recovery_level is RecoveryLevel.A and (not self.remote_idempotency or not self.status_query):
            raise AdapterManifestError("Level A requires remote idempotency and status query")
        if self.recovery_level is RecoveryLevel.B and not self.status_query:
            raise AdapterManifestError("Level B requires status query")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AdapterManifest":
        allowed = set(cls.__dataclass_fields__)
        unknown = set(value) - allowed
        if unknown:
            raise AdapterManifestError(f"unknown manifest fields: {sorted(unknown)}")
        fields = dict(value)
        try:
            fields["recovery_level"] = RecoveryLevel(fields["recovery_level"])
            return cls(**fields)
        except (KeyError, TypeError, ValueError) as error:
            if isinstance(error, AdapterManifestError):
                raise
            raise AdapterManifestError(str(error)) from error

    def signed_mapping(self) -> dict[str, Any]:
        return {
            key: (value.value if isinstance(value, Enum) else value)
            for key, value in self.__dict__.items()
            if key != "signature"
        }

    @property
    def manifest_hash(self) -> str:
        return domain_hash("ADAPTER_MANIFEST", canonical_json_bytes(self.signed_mapping()))

    def verify(self, key: bytes) -> bool:
        if self.signature is None:
            return False
        expected = hmac.new(key, b"SITINA-ADAPTER-MANIFEST-V1\0" + canonical_json_bytes(self.signed_mapping()), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def with_updates(self, **changes: Any) -> "AdapterManifest":
        return replace(self, **changes)

    def recovery_policy(self, *, elapsed_seconds: int) -> str:
        if self.recovery_level is RecoveryLevel.C:
            return "MANUAL_ACTION_NO_RETRY"
        if self.recovery_level is RecoveryLevel.B:
            return "QUERY_BEFORE_NEW_ATTEMPT"
        if elapsed_seconds <= self.idempotency_retention_seconds:
            return "IDEMPOTENT_QUERY_OR_RETRY"
        return "QUERY_ONLY_RETENTION_EXPIRED"


def sign_manifest(value: Mapping[str, Any], key: bytes) -> AdapterManifest:
    unsigned = AdapterManifest.from_mapping(value)
    signature = hmac.new(key, b"SITINA-ADAPTER-MANIFEST-V1\0" + canonical_json_bytes(unsigned.signed_mapping()), hashlib.sha256).hexdigest()
    return replace(unsigned, signature=signature)


class AdapterRegistry:
    def __init__(self, verification_key: bytes, *, profile: str):
        self.verification_key = verification_key
        self.profile = profile
        self._items: dict[tuple[str, int], AdapterManifest] = {}

    def register(self, manifest: AdapterManifest) -> None:
        if self.profile != "test" and not manifest.verify(self.verification_key):
            raise AdapterManifestError("untrusted or unsigned adapter manifest")
        identity = (manifest.adapter_id, manifest.version)
        prior = self._items.get(identity)
        if prior is not None and prior.manifest_hash != manifest.manifest_hash:
            raise AdapterManifestError("same adapter manifest identity has different content")
        self._items[identity] = manifest

    def get(self, adapter_id: str, version: int) -> AdapterManifest:
        try:
            return self._items[(adapter_id, version)]
        except KeyError as error:
            raise AdapterManifestError("adapter manifest is not registered") from error
