from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Callable, Protocol

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class SecretProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class OpaqueCredentialHandle:
    handle_id: str
    principal: str
    scope: str
    host: str
    operation: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value, field in ((self.handle_id, "handle_id"), (self.principal, "principal"), (self.scope, "scope"), (self.operation, "operation")):
            validate_identifier(value, field=field)
        if not self.host or self.expires_at <= self.issued_at:
            raise ValueError("invalid credential handle host or lifetime")


@dataclass(frozen=True)
class RuntimeCredentialView:
    handle_id: str
    principal: str
    scope: str
    host: str
    operation: str
    expires_at: int

    @classmethod
    def from_handle(cls, handle: OpaqueCredentialHandle) -> "RuntimeCredentialView":
        return cls(handle.handle_id, handle.principal, handle.scope, handle.host, handle.operation, handle.expires_at)

    def mapping(self) -> dict[str, object]:
        return dict(self.__dict__)


class SecretProvider(Protocol):
    def issue_handle(self, *, principal: str, scope: str, host: str, operation: str, ttl_seconds: int) -> OpaqueCredentialHandle: ...


class InMemorySecretProvider:
    """Test provider whose raw values can be redeemed only by its transport token."""

    provider_id = "memory-secret-provider"

    def __init__(self, *, now: Callable[[], int]):
        self.now = now
        self._secrets: dict[tuple[str, str], str] = {}
        self._handles: dict[str, OpaqueCredentialHandle] = {}
        self._transport_capability = object()

    @property
    def transport_capability(self) -> object:
        # The Gateway transports receive this object at composition time; it is
        # never serialized into a Process, Journal fact, Projection, or receipt.
        return self._transport_capability

    def register(self, principal: str, scope: str, value: str) -> None:
        validate_identifier(principal, field="principal")
        validate_identifier(scope, field="scope")
        if not value:
            raise SecretProviderError("empty secret is forbidden")
        self._secrets[(principal, scope)] = value

    def issue_handle(self, *, principal: str, scope: str, host: str, operation: str, ttl_seconds: int) -> OpaqueCredentialHandle:
        if (principal, scope) not in self._secrets:
            raise SecretProviderError("credential principal/scope is unavailable")
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise SecretProviderError("credential handle lifetime exceeds short-lived policy")
        now = self.now()
        identity = domain_hash(
            "OPAQUE_CREDENTIAL_HANDLE",
            canonical_json_bytes(
                {
                    "principal": principal,
                    "scope": scope,
                    "host": host,
                    "operation": operation,
                    "issued_at": now,
                    "nonce": os.urandom(16).hex(),
                }
            ),
        )
        handle = OpaqueCredentialHandle(f"credential-{identity}", principal, scope, host, operation, now, now + ttl_seconds)
        self._handles[handle.handle_id] = handle
        return handle

    def redeem_for_transport(
        self,
        handle: OpaqueCredentialHandle,
        *,
        host: str,
        operation: str,
        transport_capability: object | None,
    ) -> str:
        if transport_capability is not self._transport_capability:
            raise SecretProviderError("caller lacks the Secret Transport capability")
        stored = self._handles.get(handle.handle_id)
        if stored != handle:
            raise SecretProviderError("unknown or altered credential handle")
        if self.now() > handle.expires_at:
            raise SecretProviderError("credential handle expired")
        if host != handle.host or operation != handle.operation:
            raise SecretProviderError("credential handle host/operation scope mismatch")
        try:
            return self._secrets[(handle.principal, handle.scope)]
        except KeyError as error:
            raise SecretProviderError("credential was revoked") from error

    def audit_fingerprint(self, handle: OpaqueCredentialHandle) -> str:
        return hashlib.sha256(handle.handle_id.encode()).hexdigest()
