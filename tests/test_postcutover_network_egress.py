from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.legacy import fence
from sitina.legacy.fence import (
    LegacyWriteDenied,
    authorized_frozen_network_egress,
    issue_frozen_network_egress_capability,
)
from sitina.runners import provider as provider_module
from sitina.runners.provider import AnthropicCompatibleClient, ProviderProfile


class _Resolution:
    authorizes_journal = True
    writer_count = 1

    def assert_fresh(self, *, now: int) -> None:
        if now < 1:
            raise ValueError("stale")


class _Response:
    status = 200

    def getheaders(self):
        return [("x-request-id", "request-from-provider")]

    def read(self) -> bytes:
        return json.dumps(
            {
                "id": "response-from-provider",
                "choices": [{"message": {"content": '{"agent_id":"a","kind":"proposal"}'}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            }
        ).encode()


class _Connection:
    sock = None

    def __init__(self, host: str, port: int | None, timeout: float):
        self.host = host

    def connect(self) -> None:
        fence._audit_guard("socket.connect", (self, (self.host, 443)))

    def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
        self.request_body = body

    def getresponse(self) -> _Response:
        return _Response()

    def close(self) -> None:
        return None


class PostCutoverNetworkEgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        marker = self.home / "state/.legacy-control/frozen.json"
        marker.parent.mkdir(parents=True)
        marker.write_text("{}\n", encoding="utf-8")
        self.now = int(time.time())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def issue(self, *, provider_name: str = "", credential_reference: str = ""):
        return issue_frozen_network_egress_capability(
            _Resolution(),
            manifest_hash="a" * 64,
            operation="model_text_generation",
            allowed_hosts=("api.deepseek.com",),
            expires_at=self.now + 300,
            now=self.now,
            provider_name=provider_name,
            credential_reference=credential_reference,
        )

    def test_socket_stays_denied_without_capability_and_after_scope(self) -> None:
        capability = self.issue()
        with patch.object(fence, "_guard_home", self.home):
            with self.assertRaises(LegacyWriteDenied):
                fence._audit_guard("socket.connect", (object(), ("api.deepseek.com", 443)))
            with authorized_frozen_network_egress(
                capability,
                host="api.deepseek.com",
                operation="model_text_generation",
                now=self.now,
            ):
                fence._audit_guard("socket.connect", (object(), ("api.deepseek.com", 443)))
                with self.assertRaises(LegacyWriteDenied):
                    fence._audit_guard("subprocess.Popen", ("forbidden",))
            with self.assertRaises(LegacyWriteDenied):
                fence._audit_guard("socket.connect", (object(), ("api.deepseek.com", 443)))

    def test_capability_rejects_wrong_operation_host_and_authority(self) -> None:
        with self.assertRaises(LegacyWriteDenied):
            issue_frozen_network_egress_capability(
                _Resolution(),
                manifest_hash="a" * 64,
                operation="message_send",
                allowed_hosts=("api.deepseek.com",),
                expires_at=self.now + 300,
                now=self.now,
            )
        capability = self.issue()
        with self.assertRaises(LegacyWriteDenied):
            with authorized_frozen_network_egress(
                capability,
                host="example.com",
                operation="model_text_generation",
                now=self.now,
            ):
                pass
        denied = _Resolution()
        denied.authorizes_journal = False
        with self.assertRaises(LegacyWriteDenied):
            issue_frozen_network_egress_capability(
                denied,
                manifest_hash="a" * 64,
                operation="model_text_generation",
                allowed_hosts=("api.deepseek.com",),
                expires_at=self.now + 300,
                now=self.now,
            )

    def test_provider_direct_path_scopes_only_the_concrete_connect(self) -> None:
        profile = ProviderProfile(
            "deepseek", "https://api.deepseek.com/anthropic", "not-a-real-token", "test-model",
            credential_reference="keychain://unit-fixture/deepseek",
        )
        body = {
            "model": "test-model",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "controlled test"}],
        }
        headers = {"content-type": "application/json", "authorization": f"Bearer {profile.auth_token}"}
        with patch.object(fence, "_guard_home", self.home), patch.object(
            provider_module.http.client, "HTTPSConnection", _Connection
        ):
            denied_client = AnthropicCompatibleClient(self.home)
            with self.assertRaises(LegacyWriteDenied):
                denied_client._request_json_direct(
                    "https://api.deepseek.com/v1/chat/completions",
                    body,
                    headers,
                    profile=profile,
                    protocol="openai_chat_completions",
                    request_timeout_seconds=5,
                )
            capability = self.issue(
                provider_name=profile.name, credential_reference=profile.credential_reference,
            )
            fence._bind_network_credential(
                capability, host="api.deepseek.com", provider_name=profile.name,
                credential_reference=profile.credential_reference, token=profile.auth_token,
            )
            allowed_client = AnthropicCompatibleClient(
                self.home, network_egress_capability=capability
            )
            payload, metadata = allowed_client._request_json_direct(
                "https://api.deepseek.com/v1/chat/completions",
                body,
                headers,
                profile=profile,
                protocol="openai_chat_completions",
                request_timeout_seconds=5,
            )
        self.assertEqual(payload["id"], "response-from-provider")
        self.assertEqual(metadata["provider_request_id"], "request-from-provider")
        self.assertEqual(metadata["protocol"], "openai_chat_completions")

        from dataclasses import replace
        from types import SimpleNamespace
        from sitina.loop import LoopBackend
        from sitina.loop.control import LoopAuthorityLease, LoopControlAuthority
        from sitina.loop.model import ControlIntent, TaskStatus
        from test_b4d_provider_failure_correction import _Keys

        state = self.home / "native"
        state.mkdir()
        lease = LoopAuthorityLease(state)
        with lease:
            with LoopBackend.open(state, keychain_backend=_Keys()) as backend:
                backend.create_task(
                    task_id="network-renewal", session_id="network-renewal",
                    task_kind="no_change", goal="check native request authorization",
                    required_outcome_ids=("outcome-1",),
                    artifact_ref="artifact-network-renewal",
                    environment_ref="environment-network-renewal",
                    capability_snapshot_id="network-renewal",
                )
                authority = LoopControlAuthority(backend, state, lease=lease).start()
                try:
                    native = issue_frozen_network_egress_capability(
                        None, manifest_hash=None, operation="model_text_generation",
                        allowed_hosts=("api.deepseek.com",), expires_at=self.now + 300,
                        now=self.now, provider_name=profile.name,
                        credential_reference=profile.credential_reference,
                        _native_backend=backend, _native_task_id="network-renewal",
                    )
                    fence._bind_network_credential(
                        native, host="api.deepseek.com", provider_name=profile.name,
                        credential_reference=profile.credential_reference, token=profile.auth_token,
                    )
                    native_client = AnthropicCompatibleClient(
                        self.home, network_egress_capability=native,
                        renew_native_network_capability=True,
                    )
                    with patch.object(fence, "_guard_home", self.home), patch.object(
                        provider_module.http.client, "HTTPSConnection", _Connection
                    ), patch.object(
                        _Connection, "request", autospec=True, side_effect=_Connection.request
                    ) as sends, patch.object(
                        provider_module.time, "time", return_value=self.now + 1300
                    ):
                        with self.assertRaises(LegacyWriteDenied):
                            with authorized_frozen_network_egress(
                                native, host="api.deepseek.com", operation="model_text_generation",
                                provider_name=profile.name,
                                credential_reference=profile.credential_reference,
                            ):
                                pass
                        payload, _metadata = native_client._request_json_direct(
                            "https://api.deepseek.com/v1/chat/completions", body, headers,
                            profile=profile, protocol="openai_chat_completions",
                            request_timeout_seconds=5,
                        )
                        self.assertEqual(payload["id"], "response-from-provider")
                        self.assertEqual(sends.call_count, 1)
                        renewed = native_client.network_egress_capability
                        self.assertIsNot(renewed, native)
                        self.assertEqual(renewed.expires_at, self.now + 2500)
                        self.assertEqual(renewed.manifest_hash, native.manifest_hash)
                        self.assertEqual(renewed.allowed_hosts, native.allowed_hosts)
                        with self.assertRaises(LegacyWriteDenied):
                            fence._authorize_network_credential(
                                native, host="api.deepseek.com", provider_name=profile.name,
                                credential_reference=profile.credential_reference, token=profile.auth_token,
                            )
                        with self.assertRaises(LegacyWriteDenied):
                            native_client._authorize_request(
                                "https://api.deepseek.com/v1/chat/completions", headers,
                                replace(profile, auth_token="changed-token"),
                            )

                        task = backend.get_task("network-renewal")
                        changed_tasks = (
                            replace(task, goal_version=task.goal_version + 1),
                            replace(task, acceptance_version=task.acceptance_version + 1),
                            replace(task, handled_input_seq=task.handled_input_seq + 1),
                            replace(task, execution_epoch=task.execution_epoch + 1),
                            replace(task, control_intent=ControlIntent.CANCEL),
                            replace(task, control_intent=ControlIntent.PAUSE),
                            replace(task, status=TaskStatus.SUCCEEDED),
                            replace(task, operations={"unknown": SimpleNamespace(unknown_effect=True)}),
                        )
                        with patch.object(provider_module.time, "time", return_value=self.now + 2501):
                            for changed_task in changed_tasks:
                                with patch.object(backend, "get_task", return_value=changed_task):
                                    with self.assertRaises(LegacyWriteDenied):
                                        native_client._request_json(
                                            "https://api.deepseek.com/v1/chat/completions", body, headers,
                                            profile=profile, protocol="openai_chat_completions",
                                            request_timeout_seconds=5,
                                        )
                                self.assertIs(native_client.network_egress_capability, renewed)
                            for wrong_url, wrong_profile in (
                                ("https://example.com/v1/chat/completions", profile),
                                ("https://api.deepseek.com/v1/chat/completions",
                                 replace(profile, credential_reference="keychain://different/scope")),
                                ("https://api.deepseek.com/v1/chat/completions",
                                 replace(profile, auth_token="different-token")),
                            ):
                                with self.assertRaises(LegacyWriteDenied):
                                    native_client._authorize_request(wrong_url, headers, wrong_profile)
                                self.assertIs(native_client.network_egress_capability, renewed)
                            with fence._state_lock:
                                fence._network_egress_nonces.discard(renewed._nonce)
                            with self.assertRaises(LegacyWriteDenied):
                                native_client._authorize_request(
                                    "https://api.deepseek.com/v1/chat/completions", headers, profile,
                                )
                        self.assertEqual(sends.call_count, 1)
                finally:
                    authority.close()


if __name__ == "__main__":
    unittest.main()
