from __future__ import annotations

import hashlib
import io
import json
import shutil
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina import cli
from sitina.conversation.models import ChatMode
from sitina.conversation.routing_policy import LatencyClass, RoutingHistoryState
from sitina.conversation.suggestion import SuggestionEngine


ROOT = Path(__file__).resolve().parents[2]


def _manifest(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class SuggestionManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        shutil.copytree(ROOT / "config", self.home / "config")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_x19_simple_code_architecture_risk_mixed_followup_budget_sla_unknown_and_policy_alignment(self) -> None:
        engine = SuggestionEngine(self.home)
        cases = {
            "simple": engine.suggest("简单问答：法国首都是哪里？"),
            "code": engine.suggest("修改 API 代码并补充测试和文档"),
            "architecture": engine.suggest("请做系统架构设计、权衡方案并独立审阅"),
            "high-risk": engine.suggest("修改代码并执行安全审计，涉及 private key"),
            "no-risk-downgrade": engine.suggest("修改代码并执行安全审计，涉及 private key", risk_override="low"),
            "mixed": engine.suggest("Please 修改 API code，并做 cross-check"),
            "follow-up": engine.suggest(
                "继续，这个呢？",
                context="前文是复杂架构目标",
                prior_mode=ChatMode.MULTI,
                prior_complexity=82,
                unfinished_goal=True,
            ),
            "budget": engine.suggest("请比较两个架构方案并交叉验证", budget_tokens=4096),
            "sla": engine.suggest(
                "请比较两个架构方案并交叉验证",
                sla_class=LatencyClass.INTERACTIVE,
                sla_remaining_ms=100,
            ),
            "unknown": engine.suggest("讨论 zorbium 的 flern 模式"),
        }
        self.assertEqual((cases["simple"]["task_type"], cases["simple"]["route"]["recommended"]), ("chat", "FAST"))
        self.assertEqual((cases["code"]["task_type"], cases["code"]["route"]["recommended"]), ("code_change", "MULTI"))
        self.assertEqual((cases["architecture"]["topology"], cases["architecture"]["proposal_round"]), ("network", True))
        self.assertEqual((cases["high-risk"]["task_type"], cases["high-risk"]["worktree"]), ("high_risk_code_change", True))
        self.assertEqual((cases["no-risk-downgrade"]["task_type"], cases["no-risk-downgrade"]["worktree"]), ("high_risk_code_change", True))
        self.assertEqual((cases["mixed"]["task_type"], cases["mixed"]["route"]["recommended"]), ("code_change", "MULTI"))
        self.assertEqual(cases["follow-up"]["route"]["recommended"], "MULTI")
        self.assertEqual((cases["budget"]["route"]["recommended"], cases["budget"]["estimated_tokens"]["budget_status"]), ("FAST", "budget-fast-candidate"))
        self.assertEqual((cases["sla"]["route"]["recommended"], cases["sla"]["status"]), ("FAST", "constraint_blocked"))
        self.assertEqual((cases["unknown"]["task_type"], cases["unknown"]["topology"]), ("chat", "pipeline"))
        self.assertTrue(any("general routing profile" in item for item in cases["unknown"]["assumptions"]))

        architecture = cases["architecture"]
        actual_route = engine.router.decide(
            ChatMode.AUTO,
            "请做系统架构设计、权衡方案并独立审阅",
            engine._snapshot(""),
            history=RoutingHistoryState(None, 0, False, False),
            remaining_tokens=int(engine.routing_policy["default_run_budget_tokens"]),
            latency_class=LatencyClass.STANDARD,
        )
        self.assertEqual(
            (architecture["route"]["recommended"], architecture["route"]["decision_path"]),
            (actual_route.resolved_mode.value, actual_route.decision_path),
        )
        high_policy = engine.workflow.task_policies["high_risk_code_change"]
        self.assertEqual(architecture["policy_versions"]["routing"], engine.router.routing_policy_version)
        self.assertTrue(cases["high-risk"]["worktree"])
        self.assertIn("always", high_policy["worktree_required_when"])
        self.assertIn("security", cases["high-risk"]["team"])
        for result in cases.values():
            self.assertEqual(result["schema"], SuggestionEngine.SCHEMA)
            self.assertTrue(result["friendly_text"])
            self.assertEqual(result["estimated_tokens"]["kind"], "estimate")
            self.assertTrue(result["estimated_tokens"]["not_provider_usage"])
            self.assertTrue(result["estimated_time"]["not_precise_work_time"])
            self.assertEqual(result["side_effects"], {"provider_calls": 0, "network_calls": 0, "state_writes": 0})

    def test_x19_cli_is_provider_free_side_effect_free_and_exposes_friendly_versioned_overrides(self) -> None:
        before = _manifest(self.home)
        output = io.StringIO()
        with (
            patch.object(cli, "SITINA_HOME", self.home),
            patch("sitina.runners.provider.AnthropicCompatibleClient.complete_with_metadata") as provider,
            patch.object(socket, "create_connection") as network,
            patch("sitina.orchestrator.ledger.RunLedger.record") as ledger_write,
            patch("sitina.storage.SitinaStore.record_audit") as audit_write,
            patch("sitina.orchestrator.policy.write_json") as policy_write,
            patch("sys.stdout", output),
        ):
            exit_code = cli.main([
                "suggest",
                "修改 API 代码并补充测试",
                "--budget-tokens", "24000",
                "--risk", "high",
                "--topology", "hierarchy",
            ])
        value = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual((provider.call_count, network.call_count, ledger_write.call_count, audit_write.call_count, policy_write.call_count), (0, 0, 0, 0, 0))
        self.assertEqual(_manifest(self.home), before)
        self.assertEqual(value["override_parameters"]["risk"], "high")
        self.assertEqual(value["topology"], "hierarchy")
        self.assertEqual(value["task_type"], "high_risk_code_change")
        self.assertIn("不是真实 Provider usage", value["friendly_text"])

    def test_x19_configuration_error_is_diagnostic_and_does_not_fall_back_or_write(self) -> None:
        routing_path = self.home / "config/routing_policy.json"
        routing_path.write_text('{"schema":"BROKEN"}\n', encoding="utf-8")
        before = _manifest(self.home)
        output = io.StringIO()
        with patch.object(cli, "SITINA_HOME", self.home), patch("sys.stdout", output):
            exit_code = cli.main(["suggest", "unknown domain task"])
        value = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(value["status"], "configuration_error")
        self.assertEqual(value["side_effects"], {"provider_calls": 0, "network_calls": 0, "state_writes": 0})
        self.assertEqual(_manifest(self.home), before)
        self.assertNotIn("fallback", value)


if __name__ == "__main__":
    unittest.main()
