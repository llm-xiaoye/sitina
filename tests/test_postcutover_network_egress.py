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

    def issue(self):
        return issue_frozen_network_egress_capability(
            _Resolution(),
            manifest_hash="a" * 64,
            operation="model_text_generation",
            allowed_hosts=("api.deepseek.com",),
            expires_at=self.now + 300,
            now=self.now,
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
            "deepseek", "https://api.deepseek.com/anthropic", "not-a-real-token", "test-model"
        )
        body = {
            "model": "test-model",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "controlled test"}],
        }
        headers = {"content-type": "application/json", "authorization": "Bearer redacted"}
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
            allowed_client = AnthropicCompatibleClient(
                self.home, network_egress_capability=self.issue()
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


if __name__ == "__main__":
    unittest.main()
