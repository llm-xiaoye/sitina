from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from sitina import cli
from sitina.cas.local import LocalCAS
from sitina.extensions.manager import ExtensionInstallError, ExtensionManager, PermissionGrantRequired
from sitina.extensions.runtime import (
    AutonomousRuntime,
    AutonomousRuntimeError,
    BoundedToolTurnClient,
    JournalAutonomousAudit,
    decode_workspace_relative_path,
)
from sitina.extensions.tools import ToolApprovalDenied, ToolCatalog
from sitina.journal.local import LocalJournal
from sitina.runners.provider import (
    ProviderCancelledError,
    ProviderHTTPError,
    ProviderProfile,
    ProviderToolCall,
    ProviderToolTurn,
)
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_plugin(root: Path, *, version: str, permissions: list[str]) -> None:
    write_json(
        root / ".sitina-plugin/plugin.json",
        {
            "schema": "SITINA_PLUGIN_V1",
            "name": "demo_plugin",
            "version": version,
            "description": "Test-only native Sitina plugin.",
            "permissions": permissions,
            "components": {"skills": "skills", "tools": ".sitina-plugin/tools.json"},
        },
    )
    skill = root / "skills/demo_skill/SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(
        "---\n"
        + json.dumps(
            {
                "schema": "SITINA_SKILL_V1",
                "name": "demo_skill",
                "description": "Handles native demo requests.",
                "triggers": ["native demo"],
            }
        )
        + "\n---\nUse the plugin's evidence tool before answering.\n",
        encoding="utf-8",
    )
    write_json(
        root / ".sitina-plugin/tools.json",
        {
            "schema": "SITINA_TOOLS_V1",
            "tools": [
                {
                    "name": "write_demo",
                    "description": "Write a demo payload.",
                    "permission": "shell",
                    "command": ["/usr/bin/true"],
                    "input_schema": {"type": "object", "properties": {}},
                    "output_json": False,
                }
            ]
            if "shell" in permissions
            else [],
        },
    )


def write_mcp_plugin(root: Path) -> None:
    write_json(
        root / ".sitina-plugin/plugin.json",
        {
            "schema": "SITINA_PLUGIN_V1",
            "name": "mcp_native",
            "version": "1.0.0",
            "description": "Test-only dynamic stdio MCP plugin.",
            "permissions": ["shell"],
            "components": {"mcp": ".sitina-plugin/mcp.json"},
        },
    )
    write_json(
        root / ".sitina-plugin/mcp.json",
        {
            "schema": "SITINA_MCP_V1",
            "servers": [
                {
                    "name": "echo_server",
                    "transport": "stdio",
                    "permission": "shell",
                    "command": ["python3", "scripts/server.py"],
                }
            ],
        },
    )
    script = root / "scripts/server.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(
        "from __future__ import annotations\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        " request=json.loads(line)\n"
        " if 'id' not in request: continue\n"
        " method=request.get('method')\n"
        " if method == 'initialize': result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'test','version':'1'}}\n"
        " elif method == 'tools/list': result={'tools':[{'name':'echo','description':'Echo','inputSchema':{'type':'object','properties':{'text':{'type':'string'}},'required':['text']}}]}\n"
        " elif method == 'tools/call': result={'content':[{'type':'text','text':request['params']['arguments']['text']}]}\n"
        " else: result={}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}), flush=True)\n",
        encoding="utf-8",
    )


class FakeToolClient:
    def __init__(self, turns: list[ProviderToolTurn]):
        self.turns = list(turns)
        self.messages: list[list[dict[str, object]]] = []

    def load_profile(self, _profile_name: str) -> ProviderProfile:
        return ProviderProfile("mock", "https://example.invalid", "none", "mock")

    def complete_tool_turn(self, _profile, *, messages, **_kwargs):
        self.messages.append([dict(item) for item in messages])
        return self.turns.pop(0)


class ExtensionManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sitina_home = self.root / "sitina"
        self.sitina_home.mkdir()
        self.extension_root = self.root / "global-extensions"
        self.manager = ExtensionManager(self.sitina_home, global_root=self.extension_root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_install_requires_declared_non_read_grant_and_pins_hash(self) -> None:
        source = self.root / "plugin"
        write_plugin(source, version="1.0.0", permissions=["read", "shell"])
        with self.assertRaises(PermissionGrantRequired) as caught:
            self.manager.install_plugin(source)
        self.assertEqual(caught.exception.missing, ("shell",))

        installed = self.manager.install_plugin(source, grants=["shell"])
        record = installed["record"]
        self.assertRegex(record["content_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(record["granted_permissions"], ["read", "shell"])
        self.assertTrue(Path(record["path"]).is_dir())
        self.assertEqual(self.manager.select_skills("please run a native demo")[0].qualified_name, "demo_plugin:demo_skill")
        self.assertEqual(self.manager.select_skills("$demo_plugin:demo_skill")[0].name, "demo_skill")

    def test_explicit_update_retains_prior_version_and_rollback_is_atomic(self) -> None:
        source = self.root / "plugin"
        write_plugin(source, version="1.0.0", permissions=["read"])
        first = self.manager.install_plugin(source)
        write_plugin(source, version="2.0.0", permissions=["read"])
        second = self.manager.install_plugin(source, update=True)
        self.assertNotEqual(first["active"], second["active"])
        state = self.manager.load_registry()["plugins"]["demo_plugin"]
        self.assertEqual(len(state["versions"]), 2)
        self.assertTrue(all(Path(item["path"]).is_dir() for item in state["versions"]))

        rolled_back = self.manager.rollback_plugin("demo_plugin", install_id=first["active"])
        self.assertEqual(rolled_back["active"], first["active"])
        self.assertEqual(self.manager.list_plugins()[0]["version"], "1.0.0")

    def test_update_with_new_permission_stops_until_reapproved(self) -> None:
        source = self.root / "plugin"
        write_plugin(source, version="1.0.0", permissions=["read"])
        first = self.manager.install_plugin(source)
        write_plugin(source, version="2.0.0", permissions=["read", "shell"])
        with self.assertRaises(PermissionGrantRequired) as caught:
            self.manager.install_plugin(source, update=True)
        self.assertEqual(caught.exception.missing, ("shell",))
        self.assertEqual(
            self.manager.load_registry()["plugins"]["demo_plugin"]["active"],
            first["active"],
        )
        updated = self.manager.install_plugin(source, update=True, grants=["shell"])
        self.assertNotEqual(updated["active"], first["active"])

    def test_zip_and_native_marketplace_install_sources(self) -> None:
        source = self.root / "plugin"
        write_plugin(source, version="1.0.0", permissions=["read"])
        archive = self.root / "plugin.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for path in source.rglob("*"):
                if path.is_file():
                    output.write(path, Path("bundle") / path.relative_to(source))
        installed = self.manager.install_plugin(archive)
        self.assertEqual(installed["record"]["source_type"], "local_zip")

        other_root = self.root / "other-global"
        other = ExtensionManager(self.sitina_home, global_root=other_root)
        marketplace = self.root / "marketplace.json"
        write_json(
            marketplace,
            {
                "schema": "SITINA_MARKETPLACE_V1",
                "name": "test_market",
                "plugins": [{"name": "demo_plugin", "source": str(source)}],
            },
        )
        added = other.add_marketplace(str(marketplace))
        self.assertEqual(added["plugin_count"], 1)
        market_installed = other.install_from_marketplace("test_market", "demo_plugin")
        self.assertEqual(market_installed["record"]["source_type"], "local_directory")

    def test_git_url_requires_explicit_download_approval_before_clone(self) -> None:
        with self.assertRaisesRegex(ExtensionInstallError, "network approval"):
            self.manager.install_plugin("https://example.invalid/plugin.git")

    def test_read_is_automatic_but_write_requires_per_call_approval(self) -> None:
        source_file = self.root / "evidence.txt"
        source_file.write_text("evidence", encoding="utf-8")
        denied = ToolCatalog(self.manager, approval_callback=lambda _request: False)
        read = denied.execute("sitina_read_file", {"path": str(source_file)})
        self.assertEqual(read.value, "evidence")
        with self.assertRaises(ToolApprovalDenied):
            denied.execute("sitina_write_file", {"path": str(self.root / "out.txt"), "content": "x"})
        self.assertFalse((self.root / "out.txt").exists())

        approved = ToolCatalog(self.manager, approval_callback=lambda request: request.permission == "write")
        result = approved.execute(
            "sitina_write_file",
            {"path": str(self.root / "out.txt"), "content": "written after approval"},
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual((self.root / "out.txt").read_text(encoding="utf-8"), "written after approval")

    def test_grep_accepts_an_explicit_single_file_path(self) -> None:
        source_file = self.root / "single-grep.txt"
        source_file.write_text("before\nSINGLE-FILE-MARKER-7419\nafter\n", encoding="utf-8")
        catalog = ToolCatalog(self.manager, workspace=self.root, strict_workspace=True)
        result = catalog.execute(
            "sitina_grep",
            {"path": str(source_file), "pattern": "SINGLE-FILE-MARKER"},
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.value["count"], 1)
        self.assertEqual(result.value["matches"][0]["file"], str(source_file.resolve()))
        self.assertEqual(result.value["matches"][0]["line"], 2)

    def test_autonomous_runtime_replays_tool_result_into_next_model_turn(self) -> None:
        source_file = self.root / "fact.txt"
        source_file.write_text("confirmed fact", encoding="utf-8")
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "",
                    (ProviderToolCall("call-1", "sitina_read_file", {"path": str(source_file)}),),
                    "tool_use",
                    {"protocol": "mock"},
                ),
                ProviderToolTurn("The file says: confirmed fact", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        result = runtime.run("Read the fact and report it")
        self.assertEqual(result["terminal_state"], "SUCCEEDED")
        self.assertEqual(result["provider_call_count"], 2)
        self.assertEqual(result["tool_call_count"], 1)
        second_messages = client.messages[1]
        self.assertEqual(second_messages[-1]["role"], "tool")
        self.assertIn("confirmed fact", str(second_messages[-1]["content"]))

    def test_empty_final_response_gets_one_bounded_repair_without_tool_replay(self) -> None:
        client = FakeToolClient(
            [
                ProviderToolTurn("", (), "stop", {"protocol": "mock"}),
                ProviderToolTurn("Final result", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        result = runtime.run_embedded("finish the task", run_id="empty-final-repair")
        self.assertEqual(result["terminal_state"], "SUCCEEDED")
        self.assertEqual(result["response"], "Final result")
        self.assertEqual(result["provider_call_count"], 2)
        self.assertEqual(len(client.messages), 2)
        self.assertEqual(client.messages[1][-1]["role"], "user")
        self.assertIn("do not call tools", client.messages[1][-1]["content"])
        self.assertFalse(any(item.get("role") == "tool" for item in client.messages[1]))
        audit = (self.manager.root / "runs" / "empty-final-repair.jsonl").read_text(encoding="utf-8")
        self.assertEqual(audit.count("empty_final_response_repair_requested"), 1)

    def test_second_empty_final_response_remains_fail_closed(self) -> None:
        client = FakeToolClient(
            [
                ProviderToolTurn("", (), "stop", {"protocol": "mock"}),
                ProviderToolTurn("", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        with self.assertRaisesRegex(
            AutonomousRuntimeError,
            "provider ended the tool loop without a final response",
        ):
            runtime.run_embedded("finish the task", run_id="empty-final-fail-closed")
        self.assertEqual(len(client.messages), 2)
        self.assertFalse(any(item.get("role") == "tool" for item in client.messages[1]))
        audit = (self.manager.root / "runs" / "empty-final-fail-closed.jsonl").read_text(encoding="utf-8")
        self.assertEqual(audit.count("empty_final_response_repair_requested"), 1)

    def test_length_exhausted_empty_final_does_not_repeat_the_same_output_limit(self) -> None:
        client = FakeToolClient(
            [ProviderToolTurn("", (), "length", {"protocol": "mock"})]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        with self.assertRaisesRegex(
            AutonomousRuntimeError,
            "exhausted the configured output reserve",
        ):
            runtime.run_embedded("finish the task", run_id="empty-final-length")
        self.assertEqual(len(client.messages), 1)
        audit = (self.manager.root / "runs" / "empty-final-length.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertEqual(audit.count("provider_output_exhausted"), 1)
        self.assertNotIn("empty_final_response_repair_requested", audit)

    def test_length_exhausted_nonempty_turn_never_dispatches_tools_or_succeeds(self) -> None:
        client = FakeToolClient(
            [ProviderToolTurn(
                "incomplete visible prefix",
                (ProviderToolCall("truncated-call", "read_file", {"path": "never-read.txt"}),),
                "length",
                {"protocol": "mock"},
            )]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        with patch.object(runtime, "_execute_calls") as execute_calls:
            with self.assertRaisesRegex(
                AutonomousRuntimeError,
                "exhausted the configured output reserve",
            ):
                runtime.run_embedded("finish the task", run_id="nonempty-final-length")
            execute_calls.assert_not_called()
        audit = (self.manager.root / "runs" / "nonempty-final-length.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertIn("provider_output_exhausted", audit)
        self.assertNotIn("run_succeeded", audit)

    def test_embedded_runtime_reports_full_provider_usage_and_budget_callbacks(self) -> None:
        events: list[tuple[str, object]] = []
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "done",
                    (),
                    "stop",
                    {
                        "physical_send_count": 1,
                        "token_usage": {
                            "input_tokens": 11,
                            "output_tokens": 7,
                            "cache_read_tokens": 3,
                            "cache_write_tokens": 2,
                            "total_tokens": 18,
                        },
                        "cost_micro_usd": 9,
                    },
                )
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
            provider_preflight=lambda limit: events.append(("preflight", limit)),
            provider_settlement=lambda metadata: events.append(("settled", dict(metadata))),
        )
        result = runtime.run_embedded("report usage", run_id="embedded-usage")
        self.assertEqual(events[0], ("preflight", 4096))
        self.assertEqual(events[1][0], "settled")
        self.assertEqual(result["provider_input_tokens"], 11)
        self.assertEqual(result["provider_output_tokens"], 7)
        self.assertEqual(result["provider_cache_read_tokens"], 3)
        self.assertEqual(result["provider_cache_write_tokens"], 2)
        self.assertEqual(result["provider_token_total"], 18)
        self.assertEqual(result["provider_cost_micro_usd"], 9)

    def test_embedded_provider_audit_has_call_effect_model_and_usage_lineage(self) -> None:
        class CaptureAudit:
            def __init__(self):
                self.events: list[tuple[str, dict[str, object]]] = []

            def append(self, event, payload):
                self.events.append((event, dict(payload)))

        audit = CaptureAudit()
        client = FakeToolClient(
            [ProviderToolTurn(
                "done", (), "stop",
                {
                    "provider_response_id": "response-fixture-1",
                    "physical_send_count": 1,
                    "token_usage": {"input_tokens": 4, "output_tokens": 3, "total_tokens": 7},
                },
            )]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("fixture-profile", "https://example.invalid", "none", "fixture-model"),
        )
        runtime.run_embedded("report usage", run_id="embedded-lineage", journal_audit=audit)
        intended = next(payload for event, payload in audit.events if event == "provider_call_intended")
        completed = next(payload for event, payload in audit.events if event == "model_turn_completed")
        self.assertEqual(intended["embedded_call_id"], "embedded-lineage:embedded-call:1")
        self.assertEqual(completed["embedded_call_id"], intended["embedded_call_id"])
        self.assertEqual(completed["effect_attempt_id"], "embedded-lineage:embedded-effect:1:attempt:1")
        self.assertEqual(completed["provider_profile"], "fixture-profile")
        self.assertEqual(completed["provider_model"], "fixture-model")
        self.assertEqual(completed["provider_response_id"], "response-fixture-1")
        self.assertEqual(completed["input_tokens"], 4)
        self.assertEqual(completed["output_tokens"], 3)
        self.assertEqual(completed["total_tokens"], 7)

    def test_embedded_provider_transport_retries_then_records_actual_fallback_profile(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "none", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "none", "model-b")

        class FlakyClient:
            def __init__(self):
                self.calls: list[str] = []

            def load_profile(self, name):
                return primary if name == "primary" else fallback

            def complete_tool_turn(self, profile, **_kwargs):
                self.calls.append(profile.name)
                if len(self.calls) <= 4:
                    raise ProviderHTTPError(503, "temporary fixture outage")
                return ProviderToolTurn("done", (), "stop", {"provider_response_id": "fallback-response"})

        client = FlakyClient()
        bounded = BoundedToolTurnClient(
            client,
            primary,
            retry_limit=3,
            fallback_profiles=(fallback,),
            fallback_allowed=True,
            max_fallbacks=1,
            backoff_seconds=0,
        )
        turn = bounded.complete_tool_turn(primary, system_prompt="", messages=[], tools=[], max_tokens=1)
        self.assertEqual(client.calls, ["primary", "primary", "primary", "primary", "fallback"])
        self.assertEqual(turn.metadata["physical_send_count"], 0)
        self.assertEqual(turn.metadata["retry_count"], 3)
        self.assertEqual(turn.metadata["fallback_count"], 1)
        self.assertEqual(turn.metadata["sitina_provider_profile"], "fallback")
        self.assertEqual(turn.metadata["sitina_provider_model"], "model-b")

    def test_bounded_direct_live_transport_preserves_observed_physical_send_count(self) -> None:
        profile = ProviderProfile("deepseek", "https://api.deepseek.com", "none", "deepseek-v4-pro")

        class DirectLiveFixture:
            def complete_tool_turn(self, _profile, **_kwargs):
                return ProviderToolTurn(
                    "done",
                    (),
                    "stop",
                    {"provider_mode": "live", "physical_send_count": 1},
                )

        bounded = BoundedToolTurnClient(DirectLiveFixture(), profile)
        turn = bounded.complete_tool_turn(
            profile,
            system_prompt="",
            messages=[],
            tools=[],
            max_tokens=1,
        )
        self.assertEqual(turn.metadata["physical_send_count"], 1)

        from types import SimpleNamespace
        import hashlib
        from sitina.loop.context_window import ProviderContextIdentity, render_provider_tool_request
        from sitina.extensions.runtime import _provider_usage_totals
        from sitina.runners.provider import (
            AnthropicCompatibleClient, OPENAI_CHAT_COMPLETIONS,
            ProviderMalformedResponse, ProviderRequiredOutputEmpty,
        )

        identity = ProviderContextIdentity(
            profile.name, profile.base_url, profile.model, OPENAI_CHAT_COMPLETIONS
        )
        valid_message = {"content": '{"decision":"proceed"}'}
        cases = [
            ("missing", [{}, valid_message], "stop", None),
            ("null", [{"content": None}, valid_message], "stop", None),
            ("empty", [{"content": ""}, valid_message], "stop", None),
            ("whitespace", [{"content": " \n\t"}, valid_message], "stop", None),
            ("exhausted", [{"content": ""}] * 3, "stop", ProviderRequiredOutputEmpty),
            ("missing-usage", [{"content": ""}, valid_message], "stop", None),
            ("non-json", [{"content": "not JSON"}], "stop", None),
            ("wrong-schema", [{"content": "[]"}], "stop", None),
            ("refusal", [{"content": None, "refusal": "fixture refusal"}], "stop", None),
            ("length", [{"content": ""}], "length", None),
            ("filter", [{"content": ""}], "content_filter", None),
            ("other-stop", [{"content": ""}], "cancelled", None),
            ("malformed-tools", [{"content": "", "tool_calls": "bad"}], "stop", ProviderMalformedResponse),
            ("tool-only", [{"content": None, "tool_calls": [{
                "id": "call-1", "type": "function",
                "function": {"name": "read", "arguments": "{}"},
            }]}], "tool_calls", None),
        ]
        for name, response_messages, finish, expected_error in cases:
            with self.subTest(name=name):
                tools = [{"name": "read", "description": "Read", "input_schema": {
                    "type": "object", "properties": {},
                }}] if name == "tool-only" else []
                prepared = render_provider_tool_request(
                    identity, system_prompt="Return JSON", messages=[{"role": "user", "content": "decide"}],
                    tools=tools, max_tokens=32768, thinking_mode="enabled",
                    expect_json=name != "tool-only",
                )
                sent = []
                def transport(_url, body, _headers, **_kwargs):
                    sent.append(json.loads(json.dumps(body)))
                    index = len(sent) - 1
                    payload = {
                        "id": f"response-{index + 1}",
                        "choices": [{"message": {
                            **response_messages[index], "reasoning_content": "private reasoning",
                        }, "finish_reason": finish}],
                    }
                    if not (name == "missing-usage" and index == 0):
                        payload["usage"] = {
                            "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
                        }
                    wire = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    return payload, {
                        "physical_send_count": 1, "provider_request_id": f"request-{index + 1}",
                        "http_request_id": f"http-{index + 1}", "http_status_code": 200,
                        "request_body_hash": hashlib.sha256(wire).hexdigest(),
                    }
                adapter = object.__new__(AnthropicCompatibleClient)
                adapter._request_json = transport
                bounded = BoundedToolTurnClient(
                    SimpleNamespace(complete_tool_turn=adapter._tool_turn_openai),
                    profile, retry_limit=2, backoff_seconds=0,
                    fallback_profiles=(ProviderProfile("other", profile.base_url, "none", "other-model"),),
                    fallback_allowed=True, max_fallbacks=1,
                )
                kwargs = dict(system_prompt="", messages=[], tools=tools, max_tokens=32768,
                              request_timeout_seconds=30, prepared_request=prepared)
                if expected_error is not None:
                    with self.assertRaises(expected_error) as caught:
                        bounded.complete_tool_turn(profile, **kwargs)
                    error = caught.exception
                    self.assertEqual(error.sitina_physical_send_count, len(response_messages))
                    self.assertEqual(error.sitina_retry_count, len(response_messages) - 1)
                    self.assertEqual(error.sitina_fallback_count, 0)
                    attempts = error.sitina_provider_output_attempts
                    if expected_error is ProviderRequiredOutputEmpty:
                        self.assertEqual(error.sitina_token_usage, {
                            "input_tokens": 30, "output_tokens": 6, "total_tokens": 36,
                        })
                        self.assertEqual(error.sitina_usage_status, "known")
                else:
                    turn = bounded.complete_tool_turn(profile, **kwargs)
                    self.assertEqual(turn.metadata["physical_send_count"], len(response_messages))
                    self.assertEqual(turn.metadata["retry_count"], len(response_messages) - 1)
                    self.assertEqual(turn.metadata["fallback_count"], 0)
                    if name == "tool-only":
                        self.assertEqual(len(turn.tool_calls), 1)
                        self.assertNotIn("provider_output_attempts", turn.metadata)
                        attempts = []
                    else:
                        attempts = turn.metadata["provider_output_attempts"]
                        if name == "missing-usage":
                            self.assertIsNone(turn.metadata["token_usage"])
                            self.assertEqual(turn.metadata["usage_status"], "partial_unknown")
                            self.assertEqual(attempts[-1]["token_usage"]["total_tokens"], 12)
                            usage = _provider_usage_totals((turn.metadata,))
                            self.assertIsNone(usage["input_tokens"])
                            self.assertIsNone(usage["output_tokens"])
                            self.assertIsNone(usage["total_tokens"])
                        else:
                            self.assertEqual(turn.metadata["token_usage"]["total_tokens"], 12 * len(sent))
                            self.assertEqual(_provider_usage_totals((turn.metadata,))["total_tokens"], 12 * len(sent))
                    self.assertEqual(turn.stop_reason, finish)
                    self.assertEqual(turn.text, str(response_messages[-1].get("content") or "").strip())
                    self.assertNotEqual(turn.text, "private reasoning")
                self.assertEqual(sent, [prepared.body] * len(response_messages))
                for index, observation in enumerate(attempts):
                    message = response_messages[index]
                    content = message.get("content")
                    self.assertEqual(observation["attempt"], index + 1)
                    self.assertEqual(observation["physical_send_count"], 1)
                    self.assertEqual(observation["profile"], profile.name)
                    self.assertEqual(observation["model"], profile.model)
                    self.assertEqual(observation["request_body_hash"], prepared.body_hash)
                    self.assertEqual(observation["http_status_code"], 200)
                    self.assertEqual(observation["http_request_id"], f"http-{index + 1}")
                    self.assertEqual(observation["response_id"], f"response-{index + 1}")
                    self.assertEqual(observation["content_present"], "content" in message)
                    self.assertEqual(observation["content_type"], type(content).__name__ if "content" in message else "missing")
                    self.assertEqual(observation["content_utf8_bytes"], len(content.encode()) if isinstance(content, str) else None)
                    self.assertEqual(observation["content_sha256"], hashlib.sha256(content.encode()).hexdigest() if isinstance(content, str) else None)
                    self.assertEqual(observation["finish_reason"], finish)
                    self.assertEqual(observation["explicit_refusal"], message.get("refusal") is not None)
                    self.assertNotIn("private reasoning", str(observation))

    def test_bounded_cancelled_live_transport_reports_uncertain_send_not_exact_zero(self) -> None:
        profile = ProviderProfile("deepseek", "https://api.deepseek.com", "none", "deepseek-v4-pro")

        class CancelledLiveFixture:
            def complete_tool_turn(self, _profile, **_kwargs):
                error = ProviderCancelledError("cancelled after worker start")
                error.sitina_physical_send_count = None
                error.sitina_physical_send_status = "unknown_after_worker_start"
                raise error

        bounded = BoundedToolTurnClient(CancelledLiveFixture(), profile)
        with self.assertRaises(ProviderCancelledError) as caught:
            bounded.complete_tool_turn(
                profile,
                system_prompt="",
                messages=[],
                tools=[],
                max_tokens=1,
            )
        self.assertEqual(caught.exception.sitina_physical_send_count, 0)
        self.assertEqual(
            caught.exception.sitina_physical_send_count_status,
            "lower_bound_with_uncertain_attempts",
        )
        self.assertEqual(caught.exception.sitina_uncertain_physical_send_attempt_count, 1)

        from sitina.runners.provider import ProviderRequiredOutputEmpty

        class EmptyThenCancelled(CancelledLiveFixture):
            def __init__(self):
                self.calls = 0

            def complete_tool_turn(self, _profile, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise ProviderRequiredOutputEmpty({
                        "required_output": "json_object_without_tools", "physical_send_count": 1,
                        "token_usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
                    })
                return super().complete_tool_turn(_profile, **_kwargs)

        client = EmptyThenCancelled()
        bounded = BoundedToolTurnClient(client, profile, retry_limit=2, backoff_seconds=0)
        with self.assertRaises(ProviderCancelledError) as caught:
            bounded.complete_tool_turn(profile, system_prompt="", messages=[], tools=[], max_tokens=1)
        self.assertEqual(client.calls, 2)
        self.assertEqual(caught.exception.sitina_physical_send_count, 1)
        self.assertEqual(caught.exception.sitina_uncertain_physical_send_attempt_count, 1)
        self.assertEqual(caught.exception.sitina_usage_status, "partial_unknown")
        self.assertIsNone(caught.exception.sitina_token_usage)
        self.assertEqual(caught.exception.sitina_provider_output_attempts[0]["token_usage"]["total_tokens"], 12)
        from sitina.runners.provider import ProviderReadTimeout, ProviderConnectTimeout, ProviderDeadlineExceeded
        for error_type, count, status, can_retry in (
            (ProviderReadTimeout, 1, "response_received", False),
            (ProviderReadTimeout, None, "unknown_after_worker_start", False),
            (ProviderDeadlineExceeded, 1, "request_sent", False),
            (ProviderConnectTimeout, 0, "not_dispatched", True),
        ):
            for callback_enabled in (False, True):
                with self.subTest(error_type=error_type.__name__, count=count, callback=callback_enabled):
                    class Transport:
                        def __init__(self):
                            self.calls = 0
                        def complete_tool_turn(self, _profile, **_kwargs):
                            self.calls += 1
                            if self.calls == 1:
                                error = error_type("bounded transport fixture")
                                error.sitina_physical_send_count = count
                                error.sitina_physical_send_status = status
                                error.sitina_uncertain_physical_send_attempt_count = 0 if count is not None else 1
                                raise error
                            return ProviderToolTurn("done", (), "stop", {"physical_send_count": 1})
                    client = Transport()
                    bounded = BoundedToolTurnClient(client, profile, retry_limit=2,
                        backoff_seconds=0, fallback_profiles=(profile,),
                        fallback_allowed=True, max_fallbacks=1)
                    kwargs = dict(system_prompt="", messages=[], tools=[], max_tokens=1)
                    if callback_enabled:
                        kwargs["retry_recovery"] = lambda error, accounting: True
                    if can_retry:
                        turn = bounded.complete_tool_turn(profile, **kwargs)
                        self.assertEqual(client.calls, 2)
                        self.assertEqual(turn.metadata["retry_count"], 1)
                        self.assertEqual(turn.metadata["fallback_count"], 0)
                    else:
                        with self.assertRaises(error_type) as caught:
                            bounded.complete_tool_turn(profile, **kwargs)
                        self.assertEqual(client.calls, 1)
                        self.assertEqual(caught.exception.sitina_retry_count, 0)
                        self.assertEqual(caught.exception.sitina_fallback_count, 0)
                        self.assertEqual(caught.exception.sitina_provider_output_attempts[0]["retry_safety_basis"],
                                         "NO_RETRY_UNKNOWN_EFFECT")

    def test_autonomous_runtime_promotes_fallback_lineage_to_run_result(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "none", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "none", "model-b")

        class FlakyClient:
            def __init__(self):
                self.calls = 0

            def complete_tool_turn(self, _profile, **_kwargs):
                self.calls += 1
                if self.calls <= 4:
                    raise ProviderHTTPError(503, "temporary fixture outage")
                return ProviderToolTurn(
                    "done", (), "stop", {"provider_response_id": "fallback-response"}
                )

        bounded = BoundedToolTurnClient(
            FlakyClient(), primary, retry_limit=3, fallback_profiles=(fallback,),
            fallback_allowed=True, max_fallbacks=1, backoff_seconds=0,
        )
        runtime = AutonomousRuntime(
            self.sitina_home, manager=self.manager, client=bounded, profile=primary
        )
        result = runtime.run_embedded("report fallback lineage", run_id="embedded-fallback-result")
        self.assertEqual(result["provider_physical_send_count"], 0)
        self.assertEqual(result["provider_retry_count"], 3)
        self.assertEqual(result["provider_fallback_count"], 1)
        self.assertEqual(result["provider_profile"], "fallback")
        self.assertEqual(result["provider_model"], "model-b")
        self.assertEqual(result["provider_profiles"], ["fallback"])

    def test_deepseek_token_transport_forbids_fallback_after_bounded_retries(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "none", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "none", "model-b")

        class AlwaysFlaky:
            def __init__(self):
                self.calls: list[str] = []

            def load_profile(self, name):
                return primary if name == "primary" else fallback

            def complete_tool_turn(self, profile, **_kwargs):
                self.calls.append(profile.name)
                raise ProviderHTTPError(503, "temporary fixture outage")

        client = AlwaysFlaky()
        bounded = BoundedToolTurnClient(
            client,
            primary,
            retry_limit=3,
            fallback_profiles=(fallback,),
            fallback_allowed=False,
            max_fallbacks=1,
            backoff_seconds=0,
        )
        with self.assertRaises(ProviderHTTPError):
            bounded.complete_tool_turn(primary, system_prompt="", messages=[], tools=[], max_tokens=1)
        self.assertEqual(client.calls, ["primary", "primary", "primary", "primary"])

    def test_fallback_shares_global_retry_budget_when_both_profiles_fail(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "none", "model-a")
        fallback = ProviderProfile("fallback", "https://api.deepseek.com", "none", "model-b")

        class AlwaysFlaky:
            def __init__(self):
                self.calls: list[str] = []

            def complete_tool_turn(self, profile, **_kwargs):
                self.calls.append(profile.name)
                raise ProviderHTTPError(503, "temporary fixture outage")

        client = AlwaysFlaky()
        bounded = BoundedToolTurnClient(
            client,
            primary,
            retry_limit=3,
            fallback_profiles=(fallback,),
            fallback_allowed=True,
            max_fallbacks=1,
            backoff_seconds=0,
        )
        with self.assertRaises(ProviderHTTPError) as caught:
            bounded.complete_tool_turn(primary, system_prompt="", messages=[], tools=[], max_tokens=1)
        self.assertEqual(client.calls, ["primary", "primary", "primary", "primary", "fallback"])
        self.assertEqual(getattr(caught.exception, "sitina_physical_send_count"), 0)
        self.assertEqual(getattr(caught.exception, "sitina_retry_count"), 3)
        self.assertEqual(getattr(caught.exception, "sitina_fallback_count"), 1)

    def test_embedded_provider_failure_settles_physical_sends_without_fake_usage(self) -> None:
        primary = ProviderProfile("primary", "https://api.deepseek.com", "none", "model-a")

        class AlwaysFlaky:
            def complete_tool_turn(self, _profile, **_kwargs):
                raise ProviderHTTPError(503, "temporary fixture outage")

        bounded = BoundedToolTurnClient(
            AlwaysFlaky(), primary, retry_limit=3, fallback_allowed=False, backoff_seconds=0
        )
        settled: list[dict[str, object]] = []
        audit = type("CaptureAudit", (), {"events": []})()
        audit.append = lambda event, payload: audit.events.append((event, dict(payload)))
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=bounded,
            profile=primary,
            provider_failure_settlement=lambda metadata: settled.append(dict(metadata)),
        )
        with self.assertRaises(ProviderHTTPError):
            runtime.run_embedded("exercise bounded failure", run_id="embedded-failed-usage", journal_audit=audit)
        self.assertEqual(len(settled), 1)
        self.assertEqual(settled[0]["physical_send_count"], 0)
        self.assertEqual(settled[0]["retry_count"], 3)
        self.assertEqual(settled[0]["usage_status"], "unknown")
        failed = next(payload for event, payload in audit.events if event == "provider_call_failed")
        self.assertEqual(failed["physical_send_count"], 0)
        self.assertEqual(failed["retry_count"], 3)
        self.assertTrue(failed["automatic_retry_performed"])

        from sitina.runners.provider import ProviderRequiredOutputEmpty

        class EmptyClient:
            def complete_tool_turn(self, _profile, **_kwargs):
                raise ProviderRequiredOutputEmpty({
                    "required_output": "json_object_without_tools",
                    "physical_send_count": 1, "http_status_code": 200,
                    "content_present": True, "content_type": "str", "content_utf8_bytes": 0,
                    "token_usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
                })

        settled.clear()
        audit.events.clear()
        runtime = AutonomousRuntime(
            self.sitina_home, manager=self.manager,
            client=BoundedToolTurnClient(EmptyClient(), primary, retry_limit=2, backoff_seconds=0),
            profile=primary, provider_failure_settlement=lambda metadata: settled.append(dict(metadata)),
        )
        with self.assertRaises(ProviderRequiredOutputEmpty):
            runtime.run_embedded("exercise empty response", run_id="embedded-empty-usage", journal_audit=audit)
        self.assertEqual(len(settled), 1)
        self.assertEqual(settled[0]["physical_send_count"], 3)
        self.assertEqual(settled[0]["retry_count"], 2)
        self.assertEqual(settled[0]["usage_status"], "known")
        self.assertFalse(settled[0]["usage_unsettled"])
        self.assertEqual(settled[0]["token_usage"]["total_tokens"], 36)
        failed = next(payload for event, payload in audit.events if event == "provider_call_failed")
        self.assertEqual(failed["provider_output_attempts"], settled[0]["provider_output_attempts"])
        self.assertEqual(len(failed["provider_output_attempts"]), 3)
        self.assertEqual(failed["token_usage"]["total_tokens"], 36)
        self.assertEqual(failed["required_output_observation"]["http_status_code"], 200)
        self.assertEqual(failed["error_type"], "ProviderRequiredOutputEmpty")

    def test_autonomous_audit_redacts_structured_payload_without_corrupting_json(self) -> None:
        client = FakeToolClient(
            [ProviderToolTurn("done", (), "stop", {"protocol": "mock"})]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        result = runtime.run('review token: abcdefgh\\"quoted-tail')
        private_payload = {
            "turn": 2,
            "effect_id": "audit-private-input-effect",
            "task": "private-task-marker",
            "system_prompt": "private-system-marker",
            "messages": [
                {"role": "user", "content": json.dumps({"execution_context": "private-user-marker"})},
                {"role": "system", "content": "private-system-message-marker"},
                {"role": "developer", "content": "private-developer-marker"},
                {"role": "assistant", "content": "public decision", "reasoning_content": "private-reasoning-marker"},
                {"role": "tool", "name": "read_file", "tool_call_id": "observed-read", "content": "public tool result"},
            ],
        }
        original_payload = json.loads(json.dumps(private_payload))
        runtime._audit(result["run_id"], "provider_call_intended", private_payload)
        audit_path = self.manager.root / "runs" / f"{result['run_id']}.jsonl"
        records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(records)
        serialized = json.dumps(records, ensure_ascii=False)
        for private in (
            "abcdefgh", "private-task-marker", "private-system-marker",
            "private-user-marker", "private-system-message-marker",
            "private-developer-marker", "private-reasoning-marker",
        ):
            self.assertNotIn(private, serialized)
        self.assertEqual(records[-2]["event"], "run_succeeded")
        intended = records[-1]
        self.assertEqual(intended["effect_id"], "audit-private-input-effect")
        self.assertEqual(intended["messages"][3]["content"], "public decision")
        self.assertEqual(intended["messages"][4], original_payload["messages"][4])
        self.assertEqual(private_payload, original_payload)
        self.assertIn("abcdefgh", str(client.messages))

    def test_embedded_runtime_records_ordered_authorized_file_mutations(self) -> None:
        target = self.root / "execution" / "result.txt"
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "",
                    (
                        ProviderToolCall(
                            "write-1",
                            "sitina_write_file",
                            {"path": str(target), "content": "first"},
                        ),
                    ),
                    "tool_use",
                    {"protocol": "mock"},
                ),
                ProviderToolTurn("done", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
            approval_callback=lambda request: request.permission == "write",
            workspace=self.root,
            enforce_write_boundary=True,
        )
        result = runtime.run_embedded("write one file", run_id="mutation-ledger")
        self.assertEqual(result["file_mutation_event_count"], 1)
        self.assertEqual(result["unique_mutated_path_count"], 1)
        event = result["mutation_events"][0]
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["operation"], "create")
        self.assertEqual(event["path"], str(target.resolve()))
        self.assertRegex(event["authorization_ref"], r"^approval-")
        self.assertRegex(event["after_hash"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            result["accepted_file_operation_contract"],
            ["create", "modify", "append", "rename", "delete"],
        )
        self.assertEqual(result["unsupported_file_operations"], [])

    def test_mutation_journal_identity_survives_digit_redaction(self) -> None:
        workspace = self.root / "workspace-1788122400"
        workspace.mkdir()
        target = workspace / "1788122400" / "hello.py"
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "",
                    (
                        ProviderToolCall(
                            "write-digit-path",
                            "sitina_write_file",
                            {"path": str(target), "content": "hello = 'world'\n"},
                        ),
                    ),
                    "tool_use",
                    {"protocol": "mock"},
                ),
                ProviderToolTurn("done", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
            approval_callback=lambda request: request.permission == "write",
            workspace=workspace,
            enforce_write_boundary=True,
        )
        runtime.run_embedded("write the digit-named fixture file", run_id="digit-path-ledger")
        records = [
            json.loads(line)
            for line in (self.manager.root / "runs" / "digit-path-ledger.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        completed = next(record for record in records if record["event"] == "tool_completed")
        fact = completed["mutation_fact"]
        identity = fact["path_identity"]
        self.assertTrue(identity)
        self.assertRegex(identity, r"^[!~]+$")
        self.assertNotIn("1788122400", json.dumps(fact, ensure_ascii=False))
        self.assertEqual(decode_workspace_relative_path(identity), "1788122400/hello.py")
        self.assertEqual(fact["path"], identity)

    def test_embedded_runtime_routes_append_through_strong_mutation_evidence(self) -> None:
        target = self.root / "execution" / "append.txt"
        target.parent.mkdir(parents=True)
        target.write_text("first\n", encoding="utf-8")
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "",
                    (
                        ProviderToolCall(
                            "append-1",
                            "sitina_write_file",
                            {
                                "path": str(target),
                                "content": "second\n",
                                "append": True,
                            },
                        ),
                    ),
                    "tool_use",
                    {"protocol": "mock"},
                ),
                ProviderToolTurn("done", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
            approval_callback=lambda request: request.permission == "write",
            workspace=self.root,
            enforce_write_boundary=True,
        )
        result = runtime.run_embedded("append one file", run_id="append-ledger")
        self.assertEqual(target.read_text(encoding="utf-8"), "first\nsecond\n")
        event = result["mutation_events"][0]
        self.assertEqual(event["operation"], "append")
        self.assertRegex(event["before_hash"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(event["after_hash"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotEqual(event["before_hash"], event["after_hash"])

    def test_denied_process_attempt_is_counted_without_external_mutation(self) -> None:
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "",
                    (ProviderToolCall("shell-1", "sitina_shell", {"command": "true"}),),
                    "tool_use",
                    {"protocol": "mock"},
                ),
                ProviderToolTurn("blocked safely", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
            approval_callback=lambda _request: False,
            workspace=self.root,
        )
        result = runtime.run_embedded("do not run process", run_id="denied-process")
        self.assertEqual(result["denied_effect_attempt_count"], 1)
        self.assertEqual(result["external_mutation_count"], 0)

    def test_production_autonomous_audit_keeps_bodies_in_cas_and_events_in_journal(self) -> None:
        authority_home = self.root / "autonomous-authority"
        authority_home.mkdir()
        (authority_home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        keys = InMemoryKeyProvider()
        journal = LocalJournal.open(authority_home, JournalAuthProvider(keys))
        cas = LocalCAS.open(authority_home, keys)
        audit = JournalAutonomousAudit(
            journal,
            cas,
            keys,
            run_id="agent-run-audit-fixture",
            policy_hash="a" * 64,
        )
        audit.append(
            "provider_call_intended",
            {
                "turn": 1,
                "messages": [{"role": "user", "content": "private provider input body"}],
                "physical_send_count": 0,
            },
        )
        event = next(item for item in journal.iter_events(0) if item.event_type == "autonomous.provider-call-intended")
        self.assertNotIn("private provider input body", str(event.payload))
        self.assertEqual(len(event.object_refs), 1)
        summary = audit.summary()
        self.assertEqual(summary["journal_first_position"], event.position)
        self.assertEqual(summary["cas_references"], list(event.object_refs))
        object_ref = cas.resolve_reference(event.object_refs[0])
        self.assertNotIn(b"private provider input body", cas.open_verified(object_ref))
        self.assertIn(b"<redacted-private-model-input>", cas.open_verified(object_ref))
        journal.close()

    def test_parallel_read_tools_commit_intended_and_completed_in_call_order(self) -> None:
        """Read workers may overlap, while the real audit stream stays ordered."""
        first = self.root / "parallel-first.txt"
        second = self.root / "parallel-second.txt"
        first.write_text("first", encoding="utf-8")
        second.write_text("second", encoding="utf-8")
        authority_home = self.root / "parallel-authority"
        authority_home.mkdir()
        (authority_home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        keys = InMemoryKeyProvider()
        journal = LocalJournal.open(authority_home, JournalAuthProvider(keys))
        cas = LocalCAS.open(authority_home, keys)
        audit = JournalAutonomousAudit(
            journal,
            cas,
            keys,
            run_id="parallel-read-audit",
            policy_hash="b" * 64,
        )
        client = FakeToolClient(
            [
                ProviderToolTurn(
                    "",
                    (
                        ProviderToolCall("read-1", "sitina_read_file", {"path": str(first)}),
                        ProviderToolCall("read-2", "sitina_read_file", {"path": str(second)}),
                    ),
                    "tool_use",
                    {"protocol": "mock"},
                ),
                ProviderToolTurn("done", (), "stop", {"protocol": "mock"}),
            ]
        )
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=client,
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
            workspace=self.root,
        )
        try:
            result = runtime.run_embedded(
                "read both files",
                run_id="parallel-read-audit",
                journal_audit=audit,
            )
            self.assertEqual(result["terminal_state"], "SUCCEEDED")
            events = list(journal.iter_events(0))
            intended = [
                event for event in events if event.event_type == "autonomous.tool-call-intended"
            ]
            completed = [
                event for event in events if event.event_type == "autonomous.tool-completed"
            ]
            self.assertEqual([event.payload["call_id"] for event in intended], ["read-1", "read-2"])
            self.assertEqual([event.payload["call_id"] for event in completed], ["read-1", "read-2"])
            self.assertEqual(len(intended), 2)
            self.assertEqual(len(completed), 2)
            self.assertFalse(any(event.event_type == "autonomous.run-failed" for event in events))
        finally:
            journal.close()

    def test_production_autonomous_hook_failure_records_failure_and_closes_writer(self) -> None:
        (self.sitina_home / "state/.legacy-control").mkdir(parents=True)
        (self.sitina_home / "state/.legacy-control/frozen.json").write_text("{}\n", encoding="utf-8")
        (self.sitina_home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=FakeToolClient([]),
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        runtime.hooks.run = Mock(side_effect=RuntimeError("hook failed"))
        context = Mock()
        journal = context.open_writer.return_value
        audit = Mock()
        lifecycle = Mock()
        route = {
            "requested_mode": "AUTO",
            "resolved_mode": "FAST",
            "source": "local_router",
            "reasons": ["fixture"],
            "policy_version": "fixture-v1",
            "input_hash": "a" * 64,
            "confidence": "0.9",
            "threshold": "0.65",
            "decision_path": "AUTO_FAST_ADMITTED",
            "upgrade_reason": None,
            "initial_fast_decision": None,
        }
        with (
            patch("sitina.orchestrator.bplus_production.ProductionRuntimeContext.load", return_value=context),
            patch("sitina.extensions.runtime.JournalAutonomousAudit", return_value=audit),
            patch("sitina.conversation.lifecycle.ConversationLifecycle", return_value=lifecycle),
        ):
            with self.assertRaisesRegex(RuntimeError, "hook failed"):
                runtime.run(
                    "exercise failure cleanup",
                    session_id="session-autonomous-failure",
                    turn_index=1,
                    route_decision=route,
                )
        lifecycle.fail_turn.assert_called_once()
        journal.close.assert_called_once()
        self.assertTrue(any(call.args[0] == "run_failed" for call in audit.append.call_args_list))

    def test_production_standalone_agent_runs_without_conversation_session(self) -> None:
        # M1.6: `sitina agent` in a frozen production home has no chat session.
        # It must still run with a full journal audit, WITHOUT requiring a
        # ConversationLifecycle (which only links chat turns).
        (self.sitina_home / "state/.legacy-control").mkdir(parents=True)
        (self.sitina_home / "state/.legacy-control/frozen.json").write_text("{}\n", encoding="utf-8")
        (self.sitina_home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        runtime = AutonomousRuntime(
            self.sitina_home,
            manager=self.manager,
            client=FakeToolClient([ProviderToolTurn("done: standalone agent ok", (), "stop", {})]),
            profile=ProviderProfile("mock", "https://example.invalid", "none", "mock"),
        )
        context = Mock()
        audit = Mock()
        audit.summary.return_value = {}
        with (
            patch("sitina.orchestrator.bplus_production.ProductionRuntimeContext.load", return_value=context),
            patch("sitina.extensions.runtime.JournalAutonomousAudit", return_value=audit),
            patch("sitina.conversation.lifecycle.ConversationLifecycle") as lifecycle_cls,
        ):
            # No session_id / turn_index / route_decision — standalone agent.
            result = runtime.run("build a small module")
        self.assertEqual(result["terminal_state"], "SUCCEEDED")
        self.assertEqual(result["response"], "done: standalone agent ok")
        # The chat-linking lifecycle must NOT be constructed for a standalone run.
        lifecycle_cls.assert_not_called()
        # But the run is still fully journal-audited.
        self.assertTrue(audit.append.call_args_list)

    def test_protected_cli_dispatches_journal_native_agent_and_passes_max_turns(self) -> None:
        # Direct CLI half of M1.6: protected Legacy policy must not intercept
        # the Journal/CAS-native standalone agent before AutonomousRuntime.
        protected_home = self.root / "protected-home"
        protected_home.mkdir()
        (protected_home / ".sitina-clean-acceptance-v1").write_text(
            "protected\n", encoding="utf-8"
        )
        (protected_home / "config").mkdir()
        write_json(
            protected_home / "config/sitina.yaml",
            {
                "state_source_of_truth": "canonical_journal",
                "storage_authority": {
                    "canonical_source": "journal",
                    "content_source": "cas",
                    "projection_role": "disposable_rebuildable_view",
                    "legacy_enabled": False,
                    "legacy_read_enabled": False,
                    "legacy_fallback_enabled": False,
                    "legacy_write_enabled": False,
                    "active_business_jsonl_enabled": False,
                    "missing_legacy_is_valid": True,
                },
            },
        )
        captured: dict[str, object] = {}

        class ProbeAutonomousRuntime:
            def __init__(inner_self, home: Path, **kwargs: object):
                del inner_self
                captured["home"] = Path(home)
                captured.update(kwargs)

            def run(inner_self, task: str) -> dict[str, object]:
                del inner_self
                captured["task"] = task
                return {
                    "terminal_state": "SUCCEEDED",
                    "response": "journal-native-agent-ok",
                }

        output = io.StringIO()
        with (
            patch.object(cli, "SITINA_HOME", protected_home),
            patch.object(cli, "AutonomousRuntime", ProbeAutonomousRuntime),
            contextlib.redirect_stdout(output),
        ):
            code = cli.main(["agent", "--max-turns", "7", "review", "the", "change"])

        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["terminal_state"], "SUCCEEDED")
        self.assertEqual(captured["home"], protected_home)
        self.assertEqual(captured["max_turns"], 7)
        self.assertEqual(captured["task"], "review the change")
        self.assertFalse((protected_home / "data/sitina.db").exists())
        retired_files = {
            "active_conversation.json",
            "autonomy.json",
            "blackboard.json",
            "handoffs.json",
            "leases.json",
            "run_state.json",
            "side_effects.json",
        }
        self.assertFalse(
            any(
                path.name in retired_files
                for path in (protected_home / "state").glob("*")
            )
        )

    def test_dynamic_stdio_mcp_lists_then_calls_tools_through_shell_approval(self) -> None:
        source = self.root / "mcp-plugin"
        write_mcp_plugin(source)
        self.manager.install_plugin(source, grants=["shell"])
        approvals: list[str] = []
        catalog = ToolCatalog(
            self.manager,
            approval_callback=lambda request: approvals.append(request.permission) is None or True,
        )
        name = "mcp_native__echo_server_call"
        listed = catalog.execute(name, {"action": "list_tools"})
        self.assertEqual(listed.status, "ok")
        self.assertEqual(listed.value["tools"][0]["name"], "echo")
        called = catalog.execute(name, {"action": "call", "name": "echo", "arguments": {"text": "proved"}})
        self.assertEqual(called.status, "ok")
        self.assertEqual(called.value["content"][0]["text"], "proved")
        self.assertEqual(approvals, ["shell", "shell"])


if __name__ == "__main__":
    unittest.main()
