from __future__ import annotations

from typing import Callable

from .secret_provider import InMemorySecretProvider, SecretProviderError


class MacOSSecretProvider(InMemorySecretProvider):
    """Credential-handle boundary for a qualified macOS resolver.

    Phase 4 accepts this class only in test/shadow mode; it intentionally does
    not invoke the `security` CLI or authorize live credentials.
    """

    provider_id = "macos-secret-provider-shadow"

    def __init__(self, *, now: Callable[[], int], profile: str):
        if profile not in {"test", "shadow"}:
            raise SecretProviderError("macOS SecretProvider is not live-qualified in Phase 4")
        super().__init__(now=now)
        self.profile = profile
