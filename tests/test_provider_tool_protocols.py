from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from sitina.runners.provider import (
    OPENAI_CHAT_COMPLETIONS,
    AnthropicCompatibleClient,
    ProviderError,
    ProviderProfile,
    ScriptedMockToolClient,
    provider_messages_for_wire,
)
from sitina.extensions.runtime import BoundedToolTurnClient


class CapturingClient(AnthropicCompatibleClient):
    def __init__(self, home: Path, responses: list[dict[str, Any]]):
        super().__init__(home)
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def _request_json(self, url, body, headers, **kwargs):
        self.requests.append({"url": url, "body": body, "headers": headers, "kwargs": kwargs})
        return self.responses.pop(0), {
            "protocol": kwargs["protocol"],
            "protocol_fallback_used": kwargs.get("protocol_fallback_used", False),
        }


TOOLS = [
    {
        "name": "read_fact",
        "description": "Read one fact.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    }
]


class ProviderToolProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_openai_tool_calls_are_parsed_and_tool_results_are_sent_back(self) -> None:
        client = CapturingClient(
            self.home,
            [
                {
                    "choices": [
                        {
                            "finish_reason": "tool_calls",
                            "message": {
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {"name": "read_fact", "arguments": json.dumps({"path": "/tmp/f"})},
                                    }
                                ],
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
                },
                {
                    "choices": [{"finish_reason": "stop", "message": {"content": "confirmed"}}],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 2, "total_tokens": 17},
                },
            ],
        )
        profile = ProviderProfile("deepseek", "https://api.deepseek.com", "secret", "deepseek-chat")
        first = client.complete_tool_turn(
            profile,
            system_prompt="system",
            messages=[{"role": "user", "content": "read it"}],
            tools=TOOLS,
        )
        self.assertEqual(first.tool_calls[0].name, "read_fact")
        self.assertEqual(first.tool_calls[0].arguments, {"path": "/tmp/f"})
        self.assertEqual(client.requests[0]["body"]["tools"], [{
            "type": "function",
            "function": {
                "name": "read_fact",
                "description": "Read one fact.",
                "parameters": TOOLS[0]["input_schema"],
            },
        }])
        messages = [
            {"role": "user", "content": "read it"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"id": "call-1", "name": "read_fact", "arguments": {"path": "/tmp/f"}}],
            },
            {"role": "tool", "tool_call_id": "call-1", "name": "read_fact", "content": "fact"},
        ]
        reviewer_client = BoundedToolTurnClient(client, profile, request_timeout_seconds=0.25)
        second = reviewer_client.complete_tool_turn(
            profile,
            system_prompt="system",
            messages=messages,
            tools=TOOLS,
            request_timeout_seconds=10.0,
        )
        self.assertEqual(second.text, "confirmed")
        wire_messages = client.requests[1]["body"]["messages"]
        self.assertEqual(wire_messages[2], {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call-1",
                "type": "function",
                "function": {
                    "name": "read_fact",
                    "arguments": '{"path":"/tmp/f"}',
                },
            }],
        })
        self.assertEqual(wire_messages[-1]["role"], "tool")
        self.assertEqual(wire_messages[-1]["tool_call_id"], "call-1")
        self.assertEqual(client.requests[0]["kwargs"]["request_timeout_seconds"], client.timeout_config.total_request_timeout)
        self.assertEqual(client.requests[1]["kwargs"]["request_timeout_seconds"], 0.25)
        for invalid in (True, 0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                BoundedToolTurnClient(client, profile, request_timeout_seconds=invalid)

    def test_openai_wire_omits_empty_tool_calls_but_preserves_nonempty_calls(self) -> None:
        wire = provider_messages_for_wire(
            [
                {"role": "assistant", "content": "neutral history", "tool_calls": []},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"id": "call-1", "name": "read_fact", "arguments": {"path": "/tmp/f"}}
                    ],
                },
                {"role": "tool", "tool_call_id": "call-1", "content": "fact"},
            ],
            OPENAI_CHAT_COMPLETIONS,
        )
        self.assertEqual(wire[0], {"role": "assistant", "content": "neutral history"})
        self.assertNotIn("tool_calls", wire[0])
        self.assertEqual(wire[1]["tool_calls"][0]["id"], "call-1")
        self.assertEqual(wire[2], {"role": "tool", "tool_call_id": "call-1", "content": "fact"})

    def test_anthropic_tool_use_and_tool_result_wire_shapes(self) -> None:
        client = CapturingClient(
            self.home,
            [
                {
                    "content": [
                        {"type": "text", "text": "checking"},
                        {"type": "tool_use", "id": "use-1", "name": "read_fact", "input": {"path": "/tmp/f"}},
                    ],
                    "stop_reason": "tool_use",
                    "usage": {"input_tokens": 8, "output_tokens": 4},
                },
                {
                    "content": [{"type": "text", "text": "confirmed"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                },
            ],
        )
        profile = ProviderProfile("anthropic", "https://api.anthropic.com", "secret", "model")
        first = client.complete_tool_turn(
            profile,
            system_prompt="system",
            messages=[{"role": "user", "content": "read it"}],
            tools=TOOLS,
        )
        self.assertEqual(first.text, "checking")
        self.assertEqual(first.tool_calls[0].call_id, "use-1")
        self.assertEqual(client.requests[0]["body"]["tools"], TOOLS)
        second = client.complete_tool_turn(
            profile,
            system_prompt="system",
            messages=[
                {"role": "user", "content": "read it"},
                {
                    "role": "assistant",
                    "content": "checking",
                    "tool_calls": [{"id": "use-1", "name": "read_fact", "arguments": {"path": "/tmp/f"}}],
                },
                {"role": "tool", "tool_call_id": "use-1", "name": "read_fact", "content": "fact"},
            ],
            tools=TOOLS,
        )
        self.assertEqual(second.text, "confirmed")
        wire_messages = client.requests[1]["body"]["messages"]
        self.assertEqual(wire_messages[1], {
            "role": "assistant",
            "content": [{
                "type": "text",
                "text": "checking",
            }, {
                "type": "tool_use",
                "id": "use-1",
                "name": "read_fact",
                "input": {"path": "/tmp/f"},
            }],
        })
        self.assertEqual(wire_messages[-1]["role"], "user")
        self.assertEqual(wire_messages[-1]["content"][0]["type"], "tool_result")
        self.assertEqual(wire_messages[-1]["content"][0]["tool_use_id"], "use-1")

    def test_tool_wire_adapter_rejects_extra_or_malformed_shapes(self) -> None:
        client = CapturingClient(self.home, [])
        profile = ProviderProfile("custom", "https://custom.example.test/v1", "secret", "model", "openai_chat_completions")
        for malformed in (
            {**TOOLS[0], "extra": True},
            {"type": "function", "function": {"name": "read_fact", "description": "Read one fact.", "parameters": {}, "extra": True}},
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ProviderError):
                    client.complete_tool_turn(
                        profile, system_prompt="system", messages=[], tools=[malformed],
                    )

        malformed_messages = (
            [{"role": "system", "content": "not allowed"}],
            [{"role": "assistant", "content": "", "tool_calls": [{"id": "", "name": "read_fact", "arguments": {}}]}],
            [{"role": "assistant", "content": "", "tool_calls": [{"id": "call", "name": "read_fact", "arguments": [], "extra": True}]}],
            [{"role": "tool", "tool_call_id": "call"}],
            [{"role": "tool", "tool_call_id": "call", "content": "fact", "is_error": 1}],
        )
        for messages in malformed_messages:
            with self.subTest(messages=messages):
                with self.assertRaises(ProviderError):
                    client.complete_tool_turn(
                        profile, system_prompt="system", messages=messages, tools=TOOLS,
                    )

    def test_scripted_mock_provider_supports_offline_multi_turn_tools(self) -> None:
        script = self.home / "mock.json"
        script.write_text(
            json.dumps(
                {
                    "schema": "SITINA_MOCK_TOOL_SCRIPT_V1",
                    "turns": [
                        {"tool_calls": [{"name": "read_fact", "arguments": {"path": "/tmp/f"}}]},
                        {"text": "offline final"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        client = ScriptedMockToolClient.load(script)
        profile = client.load_profile("mock")
        first = client.complete_tool_turn(
            profile,
            system_prompt="system",
            messages=[{"role": "user", "content": "test"}],
            tools=TOOLS,
        )
        self.assertEqual(first.metadata["protocol"], "mock")
        self.assertEqual(first.tool_calls[0].name, "read_fact")
        second = client.complete_tool_turn(
            profile,
            system_prompt="system",
            messages=[{"role": "tool", "tool_call_id": first.tool_calls[0].call_id, "content": "fact"}],
            tools=TOOLS,
        )
        self.assertEqual(second.text, "offline final")
        self.assertEqual(len(client.received_messages), 2)


if __name__ == "__main__":
    unittest.main()
