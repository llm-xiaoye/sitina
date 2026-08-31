from __future__ import annotations

import unittest
import tempfile
import json
import hashlib
import secrets
import socket
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sitina.effects.model import EffectRequest
from sitina.orchestrator.true_multi_agent_runtime import (
    OneShotDeepSeekTransport,
    ProviderExecutor,
    RuntimeActivation,
    TrueMultiAgentRuntimeError,
    _ControllerCapabilityIssuer,
    sha256_bytes,
)
from sitina.extensions.runtime import BoundedToolTurnClient
from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBroker
from tests.code_mode_host_fixture import launch_code_mode_host
from sitina.security.key_provider import InMemoryKeyProvider
from sitina.runners.provider import ProviderCompletion, ProviderHTTPError, ProviderProfile
from scripts.code_mode_authority_host import AuthorityError, AuthorityService


class _FakeClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def _complete_openai(self, profile, **kwargs):
        self.calls.append(profile.name)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return ProviderCompletion(
            str(outcome),
            {
                "protocol": "openai_chat_completions",
                "provider_response_id": f"response-{profile.name}-{len(self.calls)}",
                "token_usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
            },
        )


class _FakeHostLedger:
    """A narrow host API double; it has no begin/settle surface."""

    def __init__(self):
        self.calls = []

    def complete_tool_turn(self, capability, **kwargs):
        self.calls.append((capability, dict(kwargs)))
        return {
            "completion_text": "",
            "tool_calls": [{"id": "host-call-1", "name": "sitina_write_file", "arguments": {"path": "x.py", "content": "x"}}],
            "stop_reason": "tool_calls",
            "metadata": {
                "provider_response_id": "host-response-1",
                "token_usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
            },
            "receipt": {
                "schema": "CODE_MODE_PROVIDER_TRANSPORT_RECEIPT_V1",
                "authority": "network-transport-boundary-v1",
                "run_id": kwargs["run_id"], "provider_profile": kwargs["provider_profile"],
                "provider_model": kwargs["provider_model"], "physical_sequence": 1,
            },
        }


def _request(profile_name: str = "primary") -> EffectRequest:
    system = "system"
    user = "user"
    return EffectRequest(
        "effect-provider-test",
        "model_text_generation",
        {
            "system_prompt_hash": sha256_bytes(system.encode()),
            "user_prompt_hash": sha256_bytes(user.encode()),
            "max_output_tokens": 32,
        },
        profile_name,
        "a" * 64,
        "b" * 64,
        "low-non-mutating-text",
        "true-multi-agent-provider-principal",
        "model-text-generation",
        "idempotency-provider-test",
    )


_TEST_BROKERS = []


def _trusted_transport(client, profile, **kwargs):
    repo = Path(__file__).resolve().parents[1]
    root = Path(tempfile.mkdtemp(prefix="provider-ledger-fixture-"))
    keys = InMemoryKeyProvider(environment="code-mode", namespace="provider-fixture")
    preview = CodeModeRuntimeContext.open(root, provider=keys, source_root=repo)
    broker = launch_code_mode_host(
        state_root=root, workspace=root,
        runtime_state_identity=preview.identity.state_identity,
        runtime_journal_id=preview.identity.journal_id,
        source_root=repo, provider=keys,
    )
    _TEST_BROKERS.append(broker)
    context = broker.context_factory(provider=keys, source_root=repo)(root)
    ledger, capability = context._authoritative_transport_ledger()
    transport = OneShotDeepSeekTransport(
        client, profile, transport_ledger=ledger,
        transport_ledger_capability=capability, authoritative_physical=False, **kwargs
    )
    transport._test_broker = broker
    return transport


class ProviderTransportTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        for broker in _TEST_BROKERS:
            broker.close()
        _TEST_BROKERS.clear()

    def test_host_service_rejects_caller_built_canary_before_transport(self) -> None:
        """The removed raw Mapping API cannot mint a transport authorization."""
        challenge = "11" * 32
        left, right = socket.socketpair()
        try:
            repo = Path(__file__).resolve().parents[1]
            root = Path(tempfile.mkdtemp(prefix="provider-service-fixture-"))
            keys = InMemoryKeyProvider(environment="code-mode", namespace="provider-service")
            preview = CodeModeRuntimeContext.open(root, provider=keys, source_root=repo)
            state_stat = root.stat()
            service = AuthorityService(
                left,
                json.dumps({
                    "state_root": str(root),
                    "state_root_identity": f"{state_stat.st_dev}:{state_stat.st_ino}",
                    "workspace": str(root),
                    "workspace_identity": f"{state_stat.st_dev}:{state_stat.st_ino}",
                    "source_root": str(repo),
                    "source_root_identity": f"{repo.stat().st_dev}:{repo.stat().st_ino}",
                    "source_manifest_hash": "0" * 64,
                    "runtime_state_identity": preview.identity.state_identity,
                    "runtime_journal_id": preview.identity.journal_id,
                    "session_instance_id": "provider-service-session",
                    "verification_material": keys.export_read_only_verification_material(),
                    "challenge_secret": challenge,
                    "authority_private_key_hex": secrets.token_bytes(32).hex(),
                    "controller_capability_public_key": "00" * 32,
                    "profiles": {"deepseek": {
                        "name": "deepseek", "base_url": "https://api.deepseek.com",
                        "auth_token": "fixture-only", "model": "deepseek-v4-pro",
                    }},
                }).encode(),
            )
            bound = service.dispatch({
                "method": "bind",
                "controller_capability_public_key": "00" * 32,
            })
            with self.assertRaises(AuthorityError):
                service.dispatch({
                    "method": "issue_canary", "session": bound["session"],
                    "body": {"schema": "CODE_MODE_CANARY_AUTHORIZATION_V1", "run_id": "caller-run"},
                })
        finally:
            left.close()
            right.close()

    def test_imported_issuer_cannot_register_through_real_broker_host(self) -> None:
        """A same-shaped issuer with a different key is not controller origin."""
        repo = Path(__file__).resolve().parents[1]
        root = Path(tempfile.mkdtemp(prefix="capability-origin-negative-"))
        keys = InMemoryKeyProvider(environment="code-mode", namespace="capability-origin-negative")
        preview = CodeModeRuntimeContext.open(root, provider=keys, source_root=repo)
        broker = launch_code_mode_host(
            state_root=root, workspace=root,
            runtime_state_identity=preview.identity.state_identity,
            runtime_journal_id=preview.identity.journal_id,
            source_root=repo, provider=keys,
        )
        try:
            context = broker.context_factory(provider=keys, source_root=repo)(root)
            session = str(context._broker_session)
            forged = _ControllerCapabilityIssuer().mint(
                purpose="deepseek-token-test", session_id="conversation", run_id="foreign-run",
                issued_at=int(time.time()), expires_at=int(time.time()) + 60,
                cli_session_instance_id=context.session_instance_id,
            )
            with self.assertRaises(PermissionError):
                broker.register_live_capability(session, forged)
        finally:
            broker.close()

    def test_authoritative_forge_turn_uses_host_api_not_worker_client(self) -> None:
        profile = ProviderProfile("deepseek", "https://api.deepseek.com", "", "deepseek-v4-pro")
        worker_client = _FakeClient(["worker-must-not-be-called"])
        host = _FakeHostLedger()
        receipts = []
        bounded = BoundedToolTurnClient(
            worker_client, profile, run_id="forge-exec-host-run-1",
            authoritative_physical=True, transport_ledger=host,
            transport_ledger_capability=object(), receipt_sink=receipts.append,
        )
        turn = bounded.complete_tool_turn(
            profile, system_prompt="system", messages=[{"role": "user", "content": "task"}],
            tools=[], max_tokens=32,
        )
        self.assertEqual(worker_client.calls, [])
        self.assertEqual(len(host.calls), 1)
        self.assertEqual(turn.tool_calls[0].name, "sitina_write_file")
        self.assertEqual(receipts[0]["authority"], "network-transport-boundary-v1")

    def test_authoritative_transport_rejects_worker_fake_provider(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "token", "model-a")
        fake = _FakeClient(["{}"])
        root = Path(tempfile.mkdtemp(prefix="host-transport-negative-"))
        repo = Path(__file__).resolve().parents[1]
        keys = InMemoryKeyProvider(environment="code-mode", namespace="worker-fake-provider")
        preview = CodeModeRuntimeContext.open(root, provider=keys, source_root=repo)
        broker = launch_code_mode_host(
            state_root=root, workspace=root,
            runtime_state_identity=preview.identity.state_identity,
            runtime_journal_id=preview.identity.journal_id,
            source_root=repo, provider=keys,
        )
        context = broker.context_factory(provider=keys, source_root=repo)(root)
        ledger, capability = context._authoritative_transport_ledger()
        transport = OneShotDeepSeekTransport(
            fake, primary, timeout=1, max_sends=1, run_id="host-negative-run",
            authoritative_physical=True, transport_ledger=ledger,
            transport_ledger_capability=capability,
        )
        transport.prompts["effect-provider-test"] = ("system", "user")
        with self.assertRaises(TrueMultiAgentRuntimeError):
            transport.send_once(_request(), "host-negative-attempt")
        self.assertEqual(fake.calls, [])
        broker.close()

    def test_signed_token_test_activation_disables_configured_fallback(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "token", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "token", "model-b")
        activation = RuntimeActivation(
            {
                "provider": {
                    "base_url_host": "api.deepseek.com",
                    "deepseek_token_test_no_fallback": True,
                }
            },
            "a" * 64,
            Mock(),
        )
        policy = {
            "provider_profile": "primary",
            "provider_model_allowlist": ["model-a", "model-b"],
            "provider_fallback_profiles": ["fallback"],
            "request_timeout_seconds": 1,
            "max_provider_requests_per_run": 1,
            "transport_retries": 3,
            "fallbacks": 1,
            "pricing": {
                "input_micro_usd_per_million_tokens": 1,
                "output_micro_usd_per_million_tokens": 1,
            },
            "max_total_tokens_per_run": 100,
            "max_total_cost_micro_usd_per_run": 100,
        }
        fake_client = Mock()
        fake_client.load_profile.side_effect = [primary, fallback]
        transport_type = Mock()
        context = Mock()
        context.events = []
        with (
            patch("sitina.orchestrator.true_multi_agent_runtime.issue_frozen_network_egress_capability"),
            patch("sitina.orchestrator.true_multi_agent_runtime.CapturingDeepSeekClient", return_value=fake_client),
            patch("sitina.orchestrator.true_multi_agent_runtime.RoleProfileResolver") as resolver_type,
            patch("sitina.orchestrator.true_multi_agent_runtime.OneShotDeepSeekTransport", transport_type),
        ):
            resolver_type.return_value.fallback_profiles.return_value = []
            ProviderExecutor(
                home=Path("/tmp/sitina-provider-fixture"),
                context=context,
                run_id="provider-run",
                policy_hash="b" * 64,
                policy=policy,
                activation=activation,
                journal=Mock(),
                cas=Mock(),
                client_override=fake_client,
            )
        self.assertFalse(transport_type.call_args.kwargs["fallback_allowed"])
        self.assertEqual(transport_type.call_args.kwargs["max_fallbacks"], 1)

    def test_retry_is_bounded_and_records_physical_attempts(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "token", "model-a")
        client = _FakeClient([ProviderHTTPError(503, "temporary"), "{}"])
        transport = _trusted_transport(client, primary, timeout=1, max_sends=1, max_retries=1)
        transport.prompts["effect-provider-test"] = ("system", "user")
        with patch("sitina.orchestrator.true_multi_agent_runtime.time.sleep"):
            result = transport.send_once(_request(), "attempt-provider-test")
        self.assertEqual(client.calls, ["primary", "primary"])
        self.assertEqual(result["retry_count"], 1)
        self.assertEqual(result["fallback_count"], 0)
        self.assertEqual(result["physical_attempts"], 2)
        self.assertEqual(transport.physical_send_count, 2)

    def test_embedded_retry_requires_a_second_physical_attempt(self) -> None:
        executor = object.__new__(ProviderExecutor)
        executor.transport = SimpleNamespace(authoritative_physical=False)
        executor._embedded_transport_receipts = [{
            "schema": "CODE_MODE_PROVIDER_TRANSPORT_FAILURE_RECEIPT_V1",
            "provider_call_id": "call-1", "effect_attempt_id": "attempt-1",
            "physical_attempts": 1, "status_code": 503,
            "usage_status": "unknown",
        }]
        executor._settled_embedded_transport_receipt_count = 0
        self.assertEqual(executor._consume_embedded_receipt_delta(), (1, 0, 0, 1))

        executor._embedded_transport_receipts.append({
            "schema": "CODE_MODE_PROVIDER_TRANSPORT_RECEIPT_V1",
            "provider_call_id": "call-1", "effect_attempt_id": "attempt-1",
            "physical_attempts": 2, "usage_status": "settled",
        })
        self.assertEqual(executor._consume_embedded_receipt_delta(), (1, 1, 0, 0))

    def test_forge_attempt_uses_child_authorization_domain(self) -> None:
        executor = object.__new__(ProviderExecutor)
        executor.run_id = "root-run"
        executor._transport_authorization_by_attempt = {
            ("root-run", 1): "pre-provider-auth",
        }
        executor._active_transport_attempt = 1

        with self.assertRaises(TrueMultiAgentRuntimeError):
            executor.bind_transport_authorization_for_attempt(
                run_id="root-run", attempt=1, authorization_id="forge-auth", domain="forge",
            )
        executor.bind_forge_transport_authorization_for_attempt(
            child_run_id="forge-exec-root-run-1", attempt=1, authorization_id="forge-auth-1",
        )
        executor.bind_forge_transport_authorization_for_attempt(
            child_run_id="forge-exec-root-run-2", attempt=2, authorization_id="forge-auth-2",
        )
        self.assertEqual(executor._transport_authorization_by_attempt[("root-run", 1)], "pre-provider-auth")
        self.assertEqual(
            executor._transport_authorization_by_attempt[("forge-exec-root-run-1", 1)], "forge-auth-1"
        )
        self.assertEqual(
            executor._transport_authorization_by_attempt[("forge-exec-root-run-2", 2)], "forge-auth-2"
        )
        self.assertEqual(executor._active_transport_attempt, 2)

    def test_host_failure_receipt_is_idempotent_and_usage_free(self) -> None:
        service = object.__new__(AuthorityService)
        service._transport = {"session-1": []}
        service._signed = lambda body: {
            **dict(body), "issuer_id": "fixture-host", "issuer_signature": "sig",
        }
        pending = {
            "session": "session-1", "provider_call_id": "call-1",
            "effect_attempt_id": "attempt-1", "run_id": "forge-exec-run-1-1",
            "attempt": 1, "physical_attempts": 1,
        }
        first = service._append_transport_failure_receipt(
            "session-1", pending, outcome_state="FAILED_CONFIRMED",
            settlement_state="SETTLED", status_code=503, error_type="HTTPError",
        )
        duplicate = service._append_transport_failure_receipt(
            "session-1", pending, outcome_state="FAILED_CONFIRMED",
            settlement_state="SETTLED", status_code=503, error_type="HTTPError",
        )
        self.assertEqual(first, duplicate)
        self.assertEqual(len(service._transport["session-1"]), 1)
        self.assertIsNone(first["token_usage"])
        self.assertFalse(first["usage_settled"])
        with self.assertRaises(AuthorityError):
            service._append_transport_failure_receipt(
                "session-1", {**pending, "status_code": 500},
                outcome_state="FAILED_CONFIRMED", settlement_state="SETTLED",
                status_code=500, error_type="HTTPError",
            )

    def test_configured_fallback_records_actual_provider_and_model(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "token", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "token", "model-b")
        primary_client = _FakeClient([ProviderHTTPError(503, "temporary")])
        fallback_client = _FakeClient(["{}"])
        transport = _trusted_transport(
            primary,
            primary,
            timeout=1,
            max_sends=1,
            max_retries=0,
            fallback_profiles=[fallback],
            fallback_clients={"fallback": fallback_client},
            max_fallbacks=1,
        )
        # The first positional client is intentionally a separate object in
        # this test so the evidence proves the fallback provider was used.
        transport.client = primary_client
        transport.prompts["effect-provider-test"] = ("system", "user")
        result = transport.send_once(_request(), "attempt-provider-fallback")
        self.assertEqual(primary_client.calls, ["primary"])
        self.assertEqual(fallback_client.calls, ["fallback"])
        self.assertEqual(result["fallback_count"], 1)
        self.assertEqual(result["physical_attempts"], 2)
        self.assertEqual(transport.last_profile.name, "fallback")
        self.assertEqual(result["metadata"]["sitina_provider_model"], "model-b")

    def test_deepseek_token_path_can_forbid_fallback(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "token", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "token", "model-b")
        primary_client = _FakeClient([ProviderHTTPError(503, "temporary")])
        fallback_client = _FakeClient(["{}"])
        transport = _trusted_transport(
            primary_client,
            primary,
            timeout=1,
            max_sends=1,
            max_retries=0,
            fallback_profiles=[fallback],
            fallback_clients={"fallback": fallback_client},
            fallback_allowed=False,
            max_fallbacks=1,
        )
        transport.prompts["effect-provider-test"] = ("system", "user")
        with self.assertRaises(ProviderHTTPError):
            transport.send_once(_request(), "attempt-provider-no-fallback")
        self.assertEqual(primary_client.calls, ["primary"])
        self.assertEqual(fallback_client.calls, [])
        self.assertEqual(transport.fallback_count, 0)


if __name__ == "__main__":
    unittest.main()
