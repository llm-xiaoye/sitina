from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from pathlib import Path

from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBroker
from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
from sitina.runners.provider import ProviderProfile
from sitina.security.key_provider import InMemoryKeyProvider
from tests.code_mode_host_fixture import launch_code_mode_host
from scripts.code_mode_authority_host import AuthorityError, AuthorityService


class CodeModeHostBoundaryTests(unittest.TestCase):
    def _assert_profile_round_trip(self, profile: ProviderProfile) -> None:
        repo = Path(__file__).resolve().parents[1]
        root = Path(tempfile.mkdtemp(prefix="profile-summary-boundary-"))
        keys = InMemoryKeyProvider(environment="code-mode", namespace="profile-summary-boundary")
        preview = CodeModeRuntimeContext.open(root, provider=keys, source_root=repo)
        provider = SimpleNamespace(profile=profile)
        broker = launch_code_mode_host(
            state_root=root,
            workspace=root,
            runtime_state_identity=preview.identity.state_identity,
            runtime_journal_id=preview.identity.journal_id,
            source_root=repo,
            provider=provider,
        )
        try:
            context = broker.context_factory(provider=keys, source_root=repo)(root)
            summary = broker.read_provider_profile(profile.name)
            self.assertEqual(
                set(summary),
                {
                    "name", "base_url", "model", "wire_protocol",
                    "adapter_capabilities", "allowed_endpoint_hosts",
                },
            )
            self.assertNotIn("auth_token", summary)
            observed = context.authoritative_provider_profile(profile.name)
            self.assertEqual(observed.name, profile.name)
            self.assertEqual(observed.base_url, profile.base_url)
            self.assertEqual(observed.model, profile.model)
            self.assertEqual(observed.wire_protocol, profile.wire_protocol)
            self.assertEqual(observed.adapter_capabilities, profile.adapter_capabilities)
            self.assertEqual(observed.allowed_endpoint_hosts, profile.allowed_endpoint_hosts)
            self.assertEqual(observed.auth_token, "")
        finally:
            broker.close()

    def test_unknown_https_openai_profile_survives_host_broker_runtime(self) -> None:
        self._assert_profile_round_trip(
            ProviderProfile(
                "custom-gpt-proxy",
                "https://gpt-proxy.example.test/v1",
                "must-not-cross-boundary",
                "gpt-custom-1",
                "openai_chat_completions",
                ("openai_strict_tool",),
                ("gpt-proxy.example.test",),
            )
        )

    def test_unknown_https_anthropic_profile_survives_host_broker_runtime(self) -> None:
        self._assert_profile_round_trip(
            ProviderProfile(
                "custom-claude-proxy",
                "https://claude-proxy.example.test/v1",
                "must-not-cross-boundary",
                "claude-custom-1",
                "anthropic_messages",
                ("anthropic_tool_use",),
                ("claude-proxy.example.test",),
            )
        )

    def test_broker_rejects_incomplete_or_malformed_profile_summary(self) -> None:
        broker = object.__new__(CodeModeAuthorityBroker)
        broker._profile_session = "profile-session"
        valid = {
            "name": "custom",
            "base_url": "https://custom.example.test/v1",
            "model": "custom-model",
            "wire_protocol": "openai_chat_completions",
            "adapter_capabilities": [],
            "allowed_endpoint_hosts": ["custom.example.test"],
        }
        for field, value in (
            ("wire_protocol", ""),
            ("adapter_capabilities", [1]),
            ("allowed_endpoint_hosts", [False]),
        ):
            with self.subTest(field=field):
                malformed = dict(valid)
                malformed[field] = value
                broker._rpc = Mock(return_value=malformed)
                with self.assertRaises(PermissionError):
                    broker.read_provider_profile("custom")

    def test_canary_attempt_two_requires_nested_provider_tuple(self) -> None:
        scope = {
            "session_instance_id": "instance-1",
            "conversation_session_id": "conversation-1",
            "turn_index": 0,
            "run_id": "run-1",
            "run_attempt": 2,
            "generation": "generation-1",
            "provider_profile": "custom-gpt",
            "provider_model": "custom-model",
        }
        current = {
            "schema": "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1",
            "run_attempt": 2,
            "authorization_ref": "authorization-2",
            "execution_authorization": {
                "run_attempt": 2,
                "authorization_ref": "authorization-2",
                "provider_profile": "custom-gpt",
                "provider_model": "custom-model",
            },
        }
        AuthorityService._validate_canary_attempt_provider_binding(
            latest_attempt=2,
            latest_authorization_ref="authorization-2",
            latest_authorization=current,
            expected_scope=scope,
            pre_provider_scope={**scope, "run_attempt": 1},
        )
        with self.assertRaises(AuthorityError):
            AuthorityService._validate_canary_attempt_provider_binding(
                latest_attempt=2,
                latest_authorization_ref="authorization-2",
                latest_authorization={
                    **current,
                    "execution_authorization": {
                        **current["execution_authorization"],
                        "provider_model": "wrong-model",
                    },
                },
                expected_scope=scope,
                pre_provider_scope={**scope, "run_attempt": 1},
            )

    def test_canary_requires_pre_provider_scope(self) -> None:
        scope = {
            "session_instance_id": "instance-1",
            "conversation_session_id": "conversation-1",
            "turn_index": 0,
            "run_id": "run-1",
            "run_attempt": 1,
            "generation": "generation-1",
            "provider_profile": "custom-gpt",
            "provider_model": "custom-model",
        }
        current = {
            "schema": "SITINA_EXECUTION_AUTHORIZATION_V1",
            "run_attempt": 1,
            "authorization_ref": "authorization-1",
            "provider_profile": "custom-gpt",
            "provider_model": "custom-model",
        }
        with self.assertRaises(AuthorityError):
            AuthorityService._validate_canary_attempt_provider_binding(
                latest_attempt=1,
                latest_authorization_ref="authorization-1",
                latest_authorization=current,
                expected_scope=scope,
                pre_provider_scope=None,
            )

    def test_import_cannot_start_or_issue_an_authority(self) -> None:
        self.assertFalse(hasattr(CodeModeAuthorityBroker, "launch"))
        self.assertFalse(hasattr(CodeModeAuthorityBroker, "connect_host"))
        self.assertFalse(hasattr(CodeModeAuthorityBroker, "sign_authority_operation"))
        left, right = socket.socketpair()
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            client = CodeModeAuthorityBroker(left, process, {})
            with self.assertRaises(PermissionError):
                client.context_factory()
            for operation in (
                lambda: client.request({"method": "bind"}),
                lambda: client._request({"method": "bind"}),
                lambda: client.issue_canary("s", {}),
                lambda: client._issue_canary("s", {}),
                lambda: client.validate_canary("s", {}),
                lambda: client._validate_canary("s", {}),
                lambda: client.consume_canary("s", {}),
                lambda: client._consume_canary("s", {}),
            ):
                with self.assertRaises(PermissionError):
                    operation()
            client.close()
        finally:
            right.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)

    def test_constructed_client_is_not_a_trusted_context_and_cannot_reuse_factory(self) -> None:
        left, right = socket.socketpair()
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            client = CodeModeAuthorityBroker(left, process, {"issuer_id": "forged"})
            self.assertFalse(client.is_attested_host_client())
            with self.assertRaises(PermissionError):
                client.context_factory()
            client.close()
        finally:
            right.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
