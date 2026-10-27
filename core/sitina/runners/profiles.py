from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from sitina.constants import SITINA_HOME
from sitina.legacy.fence import (
    FrozenNetworkEgressCapability, _authorize_network_credential, _bind_network_credential,
)
from sitina.security.macos_keychain import KeychainBackend, SecurityFrameworkKeychainBackend
from sitina.utils import chmod_octal


class ProfileSecretError(PermissionError):
    pass


class ProfileLoader:
    TOKEN_KEY = "ANTHROPIC_AUTH_TOKEN"
    TOKEN_REF_KEY = "ANTHROPIC_AUTH_TOKEN_REF"
    TOKEN_KEYS = (
        "SITINA_PROVIDER_AUTH_TOKEN",
        "ANTHROPIC_AUTH_TOKEN",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
    )

    def __init__(self, home: Path = SITINA_HOME, *, keychain_backend: KeychainBackend | None = None):
        self.home = home
        self.profile_dir = home / "profiles"
        self._keychain_backend = keychain_backend

    def check_profile(self, profile_name: str) -> tuple[bool, str]:
        path = self.profile_dir / f"{profile_name}.env"
        if not path.exists():
            return False, f"profile missing: {path}"
        mode = chmod_octal(path)
        if mode != "600":
            return False, f"profile permissions must be 600: {path} ({mode})"
        return True, "ok"

    def _raw_env(self, profile_name: str) -> dict[str, str]:
        ok, message = self.check_profile(profile_name)
        if not ok:
            raise PermissionError(message)
        env: dict[str, str] = {}
        path = self.profile_dir / f"{profile_name}.env"
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            key = key.removeprefix("export ").strip()
            env[key] = value.strip().strip("'\"")
        return env

    @staticmethod
    def _parse_keychain_reference(reference: str) -> tuple[str, str]:
        parsed = urlsplit(reference)
        service = parsed.netloc.strip()
        account = parsed.path.lstrip("/").strip()
        if (
            parsed.scheme != "keychain"
            or not service
            or not account
            or parsed.query
            or parsed.fragment
            or "/" in account
        ):
            raise ProfileSecretError("Provider secret reference must be keychain://<service>/<account>")
        return service, account

    @classmethod
    def _inspect_env_security(cls, profile_name: str, env: dict[str, str]) -> dict[str, object]:
        literal_present = any(env.get(key) for key in cls.TOKEN_KEYS)
        reference = env.get(cls.TOKEN_REF_KEY, "")
        reference_valid = False
        reference_error: str | None = None
        if reference:
            try:
                cls._parse_keychain_reference(reference)
                reference_valid = True
            except ProfileSecretError as error:
                reference_error = str(error)
        findings: list[str] = []
        if literal_present:
            findings.append("PLAINTEXT_PROVIDER_SECRET")
        if not reference:
            findings.append("PROVIDER_SECRET_REFERENCE_MISSING")
        elif not reference_valid:
            findings.append("PROVIDER_SECRET_REFERENCE_INVALID")
        if literal_present and reference:
            findings.append("AMBIGUOUS_PROVIDER_SECRET_SOURCE")
        return {
            "profile": profile_name,
            "status": "ok" if not findings else "failed",
            "secret_source": "keychain_reference" if reference_valid and not literal_present else "unsafe_or_missing",
            "reference_scheme": "keychain" if reference_valid else None,
            "findings": findings,
            "reference_error": reference_error,
            "secret_value_included": False,
        }

    def inspect_profile_security(self, profile_name: str) -> dict[str, object]:
        return self._inspect_env_security(profile_name, self._raw_env(profile_name))

    def audit_profiles(self) -> dict[str, object]:
        profiles = sorted(
            path.stem for path in self.profile_dir.glob("*.env")
            if not path.name.endswith(".template")
        )
        results = [self.inspect_profile_security(profile) for profile in profiles]
        return {
            "status": "ok" if results and all(item["status"] == "ok" for item in results) else "failed",
            "profiles": results,
            "plaintext_secret_count": sum(
                "PLAINTEXT_PROVIDER_SECRET" in item["findings"] for item in results
            ),
            "secret_values_included": False,
        }

    def _resolve_keychain_reference(
        self, reference: str, *, capability: FrozenNetworkEgressCapability | None,
        profile_name: str, host: str,
    ) -> str:
        service, account = self._parse_keychain_reference(reference)
        _authorize_network_credential(
            capability, host=host, provider_name=profile_name,
            credential_reference=reference,
        )
        backend = self._keychain_backend
        if backend is None:
            backend = SecurityFrameworkKeychainBackend()
            self._keychain_backend = backend
        raw = backend.get(service, account)
        if raw is None:
            raise ProfileSecretError("Provider credential reference is unavailable in macOS Keychain")
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise ProfileSecretError("Provider credential in macOS Keychain is not valid UTF-8") from error
        if not value:
            raise ProfileSecretError("Provider credential in macOS Keychain is empty")
        return value

    def _credential_scope(self, profile_name: str, env: dict[str, str]) -> dict[str, str]:
        base_url = next((env.get(key) for key in (
            "SITINA_PROVIDER_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "DEEPSEEK_BASE_URL"
        ) if env.get(key)), "")
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ProfileSecretError("Provider credential scope requires an exact HTTP host")
        source_path = str((self.profile_dir / f"{profile_name}.env").resolve(strict=True))
        literals = [key for key in self.TOKEN_KEYS if env.get(key)]
        reference = env.get(self.TOKEN_REF_KEY, "")
        if reference:
            self._parse_keychain_reference(reference)
            if literals:
                raise ProfileSecretError("Provider credential source is ambiguous")
        else:
            if len(literals) != 1:
                raise ProfileSecretError("Provider credential scope requires one declared reference")
            reference = "profile-file:" + source_path + "#" + literals[0]
        return {
            "provider_name": profile_name, "host": parsed.hostname.lower(),
            "credential_reference": reference, "source_path": source_path,
        }

    def _authorization_metadata(self, profile_name: str) -> dict[str, str]:
        """Return only the configured non-secret credential and host binding."""
        return self._credential_scope(profile_name, self._raw_env(profile_name))

    def load_env(
        self, profile_name: str, *,
        network_egress_capability: FrozenNetworkEgressCapability | None = None,
    ) -> dict[str, str]:
        if network_egress_capability is None:
            raise ProfileSecretError("Provider credential use requires an issued capability")
        env = self._raw_env(profile_name)
        scope = self._credential_scope(profile_name, env)
        _authorize_network_credential(
            network_egress_capability, host=scope["host"], provider_name=profile_name,
            credential_reference=scope["credential_reference"],
        )
        reference = env.get(self.TOKEN_REF_KEY, "")
        if reference:
            env.pop(self.TOKEN_REF_KEY)
            env[self.TOKEN_KEY] = self._resolve_keychain_reference(
                reference, capability=network_egress_capability,
                profile_name=profile_name, host=scope["host"],
            )
        token = next(env[key] for key in self.TOKEN_KEYS if env.get(key))
        _bind_network_credential(
            network_egress_capability, host=scope["host"], provider_name=profile_name,
            credential_reference=scope["credential_reference"], token=token,
        )
        return env

    def safe_summary(self, profile_name: str) -> dict[str, str]:
        env = self._raw_env(profile_name)
        return dict(env)
