from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from sitina.constants import SITINA_HOME
from sitina.security.macos_keychain import KeychainBackend, SecurityFrameworkKeychainBackend
from sitina.utils import chmod_octal, is_secret_name


class ProfileSecretError(PermissionError):
    pass


class ProfileLoader:
    TOKEN_KEY = "ANTHROPIC_AUTH_TOKEN"
    TOKEN_REF_KEY = "ANTHROPIC_AUTH_TOKEN_REF"

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
        literal_present = bool(env.get(cls.TOKEN_KEY))
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

    def _resolve_keychain_reference(self, reference: str) -> str:
        service, account = self._parse_keychain_reference(reference)
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

    def load_env(self, profile_name: str) -> dict[str, str]:
        env = self._raw_env(profile_name)
        literal = env.get(self.TOKEN_KEY, "")
        reference = env.get(self.TOKEN_REF_KEY, "")
        # Explicit local-profile compatibility: a mode-0600 profile may carry
        # the token directly. Security audit/doctor continues to flag this
        # posture, and ambiguous literal-plus-reference profiles fail closed.
        if literal and not reference:
            return env
        security = self._inspect_env_security(profile_name, env)
        if security["status"] != "ok":
            codes = ",".join(str(item) for item in security["findings"])
            raise ProfileSecretError(f"unsafe Provider profile {profile_name}: {codes}")
        reference = env.pop(self.TOKEN_REF_KEY)
        env[self.TOKEN_KEY] = self._resolve_keychain_reference(reference)
        return env

    def safe_summary(self, profile_name: str) -> dict[str, str]:
        env = self._raw_env(profile_name)
        return {k: ("<redacted>" if is_secret_name(k) else v) for k, v in env.items()}
