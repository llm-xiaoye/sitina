from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import Mock, patch

from sitina import cli
from sitina.authority.model import AuthorityResolution, AuthorityState
from sitina.legacy.fence import issue_frozen_network_egress_capability
from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.journal.local import LocalJournal
from sitina.journal.model import canonical_json_bytes
from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
from sitina.runners.profiles import ProfileLoader, ProfileSecretError
from sitina.runners.provider import AnthropicCompatibleClient, provider_identity_summary
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider, KeyPurpose
from sitina.security.macos_keychain import IsolatedOverlayKeychainBackend, MacOSKeychainProvider, MemoryKeychainBackend


class ProviderSecretReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp())
        (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        (self.home / "profiles").mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.home)

    def profile(self, name: str, secret_line: str) -> Path:
        path = self.home / "profiles" / f"{name}.env"
        path.write_text(
            "\n".join(
                (
                    'export ANTHROPIC_BASE_URL="https://api.example.test/anthropic"',
                    secret_line,
                    'export ANTHROPIC_MODEL="model-test"',
                )
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def _credential_capability(self, loader: ProfileLoader, profile_name: str):
        moment = int(time.time())
        metadata = loader._authorization_metadata(profile_name)
        resolution = AuthorityResolution(
            state=AuthorityState.JOURNAL_WRITER_AUTHORIZED,
            resolution_id="provider-secret-reference-fixture",
            input_frontier_hash="a" * 64, input_hash="b" * 64,
            resolver_binary_hash="c" * 64, resolver_profile="unit-fixture",
            issued_at=moment, expires_at=moment + 300, reason="existing positive credential fixture",
        )
        return issue_frozen_network_egress_capability(
            resolution, manifest_hash="d" * 64, operation="model_text_generation",
            allowed_hosts=(metadata["host"],), expires_at=moment + 300, now=moment,
            provider_name=metadata["provider_name"],
            credential_reference=metadata["credential_reference"],
        )

    def test_restore_overlay_reads_existing_keys_but_never_mutates_source(self) -> None:
        source = MemoryKeychainBackend()
        source.put("production-service", "existing", b"existing-secret")
        overlay = IsolatedOverlayKeychainBackend(
            source,
            isolated_services=("rollback-anchor-service",),
        )
        self.assertEqual(overlay.get("production-service", "existing"), b"existing-secret")
        overlay.put("production-service", "new", b"simulation-only-secret")
        overlay.put("rollback-anchor-service", "journal", b"simulation-anchor")
        self.assertIsNone(source.get("production-service", "new"))
        self.assertIsNone(source.get("rollback-anchor-service", "journal"))
        inventory = overlay.public_inventory()
        self.assertEqual(inventory["durable_secret_copy_count"], 0)
        self.assertEqual(inventory["source_mutation_count"], 0)
        self.assertFalse(inventory["secret_values_included"])
        self.assertNotIn("existing-secret", str(inventory))
        self.assertNotIn("simulation-only-secret", str(inventory))

    def test_keychain_key_versions_are_fetched_once_per_provider_process(self) -> None:
        class CountingBackend(MemoryKeychainBackend):
            def __init__(self) -> None:
                super().__init__()
                self.get_counts: dict[tuple[str, str], int] = {}

            def get(self, service: str, account: str) -> bytes | None:
                key = (service, account)
                self.get_counts[key] = self.get_counts.get(key, 0) + 1
                return super().get(service, account)

        backend = CountingBackend()
        provider = MacOSKeychainProvider(environment="test", namespace="key-cache", backend=backend)
        descriptor = provider.current_descriptor(KeyPurpose.JOURNAL_AUTH)
        authenticator = JournalAuthProvider(provider)
        key = (provider.service, "journal-auth:v1")
        before = backend.get_counts.get(key, 0)
        for ordinal in range(100):
            event_hash = hashlib.sha256(str(ordinal).encode()).hexdigest()
            key_id, tag = authenticator.authenticate("journal-1", 1, event_hash)
            self.assertEqual(key_id, descriptor.key_id)
            self.assertTrue(authenticator.verify("journal-1", 1, key_id, event_hash, tag))
        self.assertEqual(backend.get_counts.get(key, 0), before)

    def test_keychain_reference_resolves_only_at_provider_load_boundary(self) -> None:
        self.profile("safe", 'export ANTHROPIC_AUTH_TOKEN_REF="keychain://com.sitina.provider/safe"')
        backend = MemoryKeychainBackend()
        backend.put("com.sitina.provider", "safe", b"runtime-only-provider-token")
        loader = ProfileLoader(self.home, keychain_backend=backend)
        client = AnthropicCompatibleClient(self.home)
        client.loader = loader

        audit = loader.inspect_profile_security("safe")
        self.assertEqual(audit["status"], "ok")
        self.assertFalse(audit["secret_value_included"])
        client.network_egress_capability = self._credential_capability(loader, "safe")
        profile = client.load_profile("safe")
        self.assertEqual(profile.auth_token, "runtime-only-provider-token")
        self.assertNotIn("runtime-only-provider-token", repr(profile))
        self.assertNotIn("runtime-only-provider-token", str(audit))
        self.assertNotIn("runtime-only-provider-token", str(loader.safe_summary("safe")))

    def test_provider_secret_is_used_for_transport_but_never_persisted_to_journal_or_cas(self) -> None:
        secret = "runtime-only-provider-token-never-persist"
        self.profile("safe", 'export ANTHROPIC_AUTH_TOKEN_REF="keychain://com.sitina.provider/safe"')
        backend = MemoryKeychainBackend()
        backend.put("com.sitina.provider", "safe", secret.encode("utf-8"))
        client = AnthropicCompatibleClient(self.home)
        client.loader = ProfileLoader(self.home, keychain_backend=backend)
        client.network_egress_capability = self._credential_capability(client.loader, "safe")
        profile = client.load_profile("safe")

        def controlled_request(_url, _body, headers, **_kwargs):
            self.assertEqual(headers["authorization"], "Bearer " + secret)
            return (
                {
                    "id": "provider-response-safe",
                    "choices": [{"message": {"content": "safe provider response"}}],
                    "usage": {"prompt_tokens": 7, "completion_tokens": 4, "total_tokens": 11},
                },
                {
                    "provider_request_id": "provider-response-safe",
                    "provider_call_started_at": "2026-07-18T00:00:00Z",
                    "provider_call_completed_at": "2026-07-18T00:00:01Z",
                    "protocol": "openai_chat_completions",
                    "protocol_fallback_used": False,
                    "fallback_used": False,
                    "physical_send_count": 1,
                },
            )

        with patch.object(client, "_request_json", side_effect=controlled_request):
            completion = client.complete_with_metadata(
                profile,
                system_prompt="safe system prompt",
                user_prompt="safe user prompt",
                expect_json=True,
            )

        persisted = {
            "schema": "PROVIDER_RESULT_SAFE_PERSISTENCE_TEST_V1",
            "text": completion.text,
            "metadata": completion.metadata,
            "provider": provider_identity_summary(profile, provider_mode="live"),
        }
        self.assertNotIn(secret, canonical_json_bytes(persisted).decode("utf-8"))

        key_provider = InMemoryKeyProvider()
        cas = LocalCAS.open(self.home, key_provider)
        receipt = cas.publish_verified(
            encrypt_object(
                canonical_json_bytes(persisted),
                key_provider,
                tenant_id="default",
                purpose="provider-secret-persistence-regression",
            )
        )
        journal = LocalJournal.open(self.home, JournalAuthProvider(key_provider))
        try:
            stream = CanonicalStream(
                journal,
                "run-provider-secret-persistence",
                "effect/run-provider-secret-persistence/provider-result",
                "1" * 64,
            )
            stream.append(
                "provider-result-committed",
                ({
                    "schema": "PROVIDER_RESULT_COMMITTED_V1",
                    "result_ref": receipt.object_ref.reference_id,
                    "provider": persisted["provider"],
                    "_object_refs": [receipt.object_ref.reference_id],
                },),
                actor="provider-result-admission",
                proofs=(receipt,),
            )
            self.assertEqual(cas.open_verified(receipt.object_ref), canonical_json_bytes(persisted))
        finally:
            journal.close()

        secret_bytes = secret.encode("utf-8")
        persisted_files = [path for path in self.home.rglob("*") if path.is_file() and not path.is_symlink()]
        self.assertTrue(persisted_files)
        for path in persisted_files:
            self.assertNotIn(secret_bytes, path.read_bytes(), path)

    def test_plaintext_provider_token_loads_from_mode_600_profile_but_audit_fails_without_echoing_value(self) -> None:
        self.profile("unsafe", 'export SITINA_PROVIDER_AUTH_TOKEN="literal-provider-token"')
        loader = ProfileLoader(self.home, keychain_backend=MemoryKeychainBackend())
        audit = loader.audit_profiles()
        self.assertEqual(audit["status"], "failed")
        self.assertEqual(audit["plaintext_secret_count"], 1)
        self.assertFalse(audit["secret_values_included"])
        self.assertNotIn("literal-provider-token", str(audit))
        loaded = loader.load_env(
            "unsafe", network_egress_capability=self._credential_capability(loader, "unsafe"),
        )
        self.assertEqual(loaded["SITINA_PROVIDER_AUTH_TOKEN"], "literal-provider-token")
        self.assertNotIn("literal-provider-token", str(loader.safe_summary("unsafe")))

    def test_doctor_fails_when_a_profile_contains_a_plaintext_secret(self) -> None:
        self.profile("unsafe", 'export ANTHROPIC_AUTH_TOKEN="literal-provider-token"')
        policy = Mock(
            fully_disabled=False,
            missing_legacy_is_valid=True,
            legacy_enabled=False,
            read_enabled=False,
            fallback_enabled=False,
            write_enabled=False,
            active_business_jsonl_enabled=False,
        )
        policy.unexpected_sqlite_artifacts.return_value = ()
        extension_manager = Mock()
        extension_manager.active_plugins.return_value = []
        extension_manager.skills.return_value = []
        captured: list[dict] = []
        with (
            patch.object(cli, "SITINA_HOME", self.home),
            patch.object(cli.LegacyRuntimePolicy, "load", return_value=policy),
            patch.object(cli, "ConfigValidator") as validator,
            patch.object(cli, "_bplus_installed", return_value=False),
            patch.object(cli, "ExtensionManager", return_value=extension_manager),
            patch.object(cli, "print_json", side_effect=captured.append),
        ):
            validator.return_value.validate.return_value = {"ok": True}
            status = cli.cmd_doctor(Namespace(fix=False, approval_id=None))

        self.assertEqual(status, 2)
        self.assertEqual(captured[0]["status"], "requires_user_action")
        self.assertEqual(captured[0]["provider_secret_audit"]["plaintext_secret_count"], 1)
        self.assertNotIn("literal-provider-token", str(captured[0]))

    def test_production_doctor_accepts_only_the_exact_user_approved_deepseek_exception(self) -> None:
        exact_audit = {
            "status": "failed",
            "plaintext_secret_count": 1,
            "secret_values_included": False,
            "profiles": [
                {
                    "profile": "deepseek",
                    "status": "failed",
                    "secret_source": "unsafe_or_missing",
                    "reference_scheme": None,
                    "reference_error": None,
                    "secret_value_included": False,
                    "findings": ["PLAINTEXT_PROVIDER_SECRET", "PROVIDER_SECRET_REFERENCE_MISSING"],
                },
                *[
                    {
                        "profile": name,
                        "status": "ok",
                        "secret_source": "keychain_reference",
                        "reference_scheme": "keychain",
                        "reference_error": None,
                        "secret_value_included": False,
                        "findings": [],
                    }
                    for name in ("claude", "openai", "gemini")
                ],
            ],
        }
        policy = Mock(
            fully_disabled=True,
            missing_legacy_is_valid=True,
            legacy_enabled=False,
            read_enabled=False,
            fallback_enabled=False,
            write_enabled=False,
            active_business_jsonl_enabled=False,
        )
        policy.unexpected_sqlite_artifacts.return_value = ()
        extension_manager = Mock()
        extension_manager.active_plugins.return_value = []
        extension_manager.skills.return_value = []
        captured: list[dict] = []
        with (
            patch.object(cli, "SITINA_HOME", self.home),
            patch.object(cli, "_is_production_home", return_value=True),
            patch.object(cli.LegacyRuntimePolicy, "load", return_value=policy),
            patch.object(cli, "ConfigValidator") as validator,
            patch.object(cli, "ProfileLoader") as loader,
            patch.object(cli, "_bplus_installed", return_value=False),
            patch.object(cli, "ExtensionManager", return_value=extension_manager),
            patch.object(cli, "print_json", side_effect=captured.append),
        ):
            validator.return_value.validate.return_value = {"ok": True}
            loader.return_value.audit_profiles.return_value = exact_audit
            status = cli.cmd_doctor(Namespace(fix=False, approval_id=None))

        self.assertEqual(status, 0)
        self.assertEqual(captured[0]["status"], "ok")
        self.assertEqual(captured[0]["provider_storage_exception"]["status"], "accepted")
        self.assertFalse(captured[0]["provider_storage_exception"]["credential_value_included"])


if __name__ == "__main__":
    unittest.main()
