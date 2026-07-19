from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from sitina.cas.local import LocalCAS
from sitina.extensions.manager import ExtensionInstallError, ExtensionManager, PermissionGrantRequired
from sitina.extensions.runtime import AutonomousRuntime, JournalAutonomousAudit
from sitina.extensions.tools import ToolApprovalDenied, ToolCatalog
from sitina.journal.local import LocalJournal
from sitina.runners.provider import ProviderProfile, ProviderToolCall, ProviderToolTurn
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
        self.assertIn(b"private provider input body", cas.open_verified(object_ref))
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
