from __future__ import annotations

import unittest
import uuid
import time
import signal
import http.client
from pathlib import Path
from unittest.mock import MagicMock, patch

from sitina.constants import SITINA_HOME
from sitina.orchestrator.arbitration import ArbitrationManager
from sitina.orchestrator.collaboration import CollaborationRuntime
from sitina.orchestrator.acceptance_report import AcceptanceReportGenerator
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.engine import SitinaEngine
from sitina.orchestrator.handoff import EnvelopeFactory, HandoffContract
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.proposals import Proposal, ProposalManager, ProposalRound
from sitina.orchestrator.replay import ReplayEngine
from sitina.orchestrator.task_graph import TaskGraph, TaskGraphNode, TaskGraphRuntime
from sitina.orchestrator.team import TeamSelection
from sitina.orchestrator.timeout_support import ProviderTimeoutConfig, RunControlStore, RunDeadline
from sitina.runners.agent_runner import AgentRunner, AgentRunnerError
from sitina.runners.provider import (
    AnthropicCompatibleClient,
    ProviderAuthError,
    ProviderCancelledError,
    ProviderCompletion,
    ProviderConnectTimeout,
    ProviderError,
    ProviderPermissionError,
    ProviderRateLimitError,
    ProviderReadTimeout,
    ProviderProfile,
)
from sitina.runners.profiles import ProfileLoader
from sitina.security.macos_keychain import MemoryKeychainBackend
from sitina.utils import iso_now, sha256_text, stable_json, write_json


def planner_input() -> dict:
    return {
        "user_goal": "controlled provider reliability test",
        "project_context": {"home": str(SITINA_HOME)},
        "allowed_read_scope": [str(SITINA_HOME)],
        "risk_policy": {"risk_level": "low"},
        "conversation_summary": "No prior summary.",
    }


class RuntimeReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SitinaEngine(SITINA_HOME).initialize()

    @staticmethod
    def runner() -> AgentRunner:
        """Return a live-path runner backed by an in-memory test Keychain."""
        backend = MemoryKeychainBackend()
        for service in ("com.sitina.fixture", "com.sitina.provider"):
            for account in ("deepseek", "gpt", "minimax", "qwen"):
                backend.put(service, account, b"controlled-test-token-not-used")
        runner = AgentRunner(SITINA_HOME)
        runner.client.loader = ProfileLoader(SITINA_HOME, keychain_backend=backend)
        return runner

    def test_live_provider_metadata_and_no_mock_fallback(self) -> None:
        runner = self.runner()
        run_id = "run_provider_evidence_" + uuid.uuid4().hex[:12]
        RunControlStore(SITINA_HOME).create(RunDeadline.create(run_id, 60))
        raw = runner.mock.complete("planner", planner_input())

        def fake_complete(*_args, **_kwargs):
            return ProviderCompletion(
                text=raw,
                metadata={
                    "provider_request_id": "controlled-provider-call",
                    "provider_call_started_at": "2026-07-10T00:00:00Z",
                    "provider_call_completed_at": "2026-07-10T00:00:01Z",
                    "input_hash": "sha256:controlled-input",
                    "output_hash": "sha256:controlled-output",
                    "provider_mode": "live",
                    "profile_name": "deepseek",
                    "model": "controlled-model",
                    "fallback_used": False,
                },
            )

        with patch.object(runner.client, "complete_with_metadata", side_effect=fake_complete):
            result = runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)

        self.assertEqual(result.provider_mode, "live")
        self.assertFalse(result.fallback_used)
        self.assertEqual(len(result.provider_calls), 1)
        call = result.provider_calls[0]
        self.assertEqual(call["provider_request_id"], "controlled-provider-call")
        self.assertEqual(call["schema_name"], "planner")
        self.assertEqual(call["schema_validation_status"], "valid")
        self.assertFalse(call["fallback_used"])

    def test_deepseek_agent_call_requests_native_json_object(self) -> None:
        client = AnthropicCompatibleClient(SITINA_HOME)
        profile = ProviderProfile(
            name="deepseek",
            base_url="https://api.deepseek.com",
            auth_token="controlled-token-not-used",
            model="controlled-model",
        )
        captured: dict = {}

        def fake_request(url, body, _headers, **kwargs):
            captured["url"] = url
            captured["body"] = body
            captured["protocol"] = kwargs["protocol"]
            return (
                {"choices": [{"message": {"content": "{\"agent_status\":\"ok\"}"}}], "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}},
                {
                    "provider_request_id": "controlled-json-mode",
                    "provider_call_started_at": "2026-07-10T00:00:00Z",
                    "provider_call_completed_at": "2026-07-10T00:00:01Z",
                    "fallback_used": False,
                },
            )

        with patch.object(client, "_request_json", side_effect=fake_request):
            completion = client.complete_with_metadata(
                profile,
                system_prompt="controlled",
                user_prompt="controlled",
                expect_json=True,
            )

        self.assertEqual(captured["protocol"], "openai_chat_completions")
        self.assertEqual(captured["url"], "https://api.deepseek.com/v1/chat/completions")
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})
        self.assertEqual(captured["body"]["thinking"], {"type": "disabled"})
        self.assertNotIn("tools", captured["body"])
        self.assertEqual(captured["body"]["temperature"], 0.0)
        self.assertTrue(completion.metadata["structured_output_requested"])
        self.assertTrue(completion.metadata["structured_output_enforced"])
        self.assertEqual(completion.metadata["thinking_mode"], "disabled")
        self.assertEqual(client._chat_completions_url("https://api.deepseek.com/anthropic"), "https://api.deepseek.com/v1/chat/completions")

    def test_live_agent_token_limits_are_role_bounded(self) -> None:
        runner = self.runner()
        self.assertEqual(runner._live_max_tokens("controller", None), 2048)
        self.assertEqual(runner._live_max_tokens("planner", None), 4096)
        self.assertEqual(runner._live_max_tokens("summary", 512), 512)
        self.assertLessEqual(runner._live_max_tokens("planner", 100000), 4096)

    def test_controller_provider_schema_requires_concrete_next_agent(self) -> None:
        schema = AgentRunner(SITINA_HOME)._output_json_schema("controller")
        self.assertIn("next_agent", schema["required"])
        next_agent = schema["properties"]["next_agent"]
        self.assertEqual(next_agent["type"], "string")
        self.assertNotIn("anyOf", next_agent)

    def test_summary_uses_json_object_framing_with_runtime_schema_validation(self) -> None:
        runner = self.runner()
        self.assertIsNone(runner._provider_json_schema("summary"))
        self.assertIsNone(runner._provider_json_schema("architect"))
        self.assertIsNone(runner._provider_json_schema("coder"))
        self.assertIsNotNone(runner._provider_json_schema("planner"))

    def test_live_report_aggregates_available_token_usage(self) -> None:
        usage = AcceptanceReportGenerator._aggregate_token_usage(
            [
                {"token_usage": {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18}},
                {"token_usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8}},
                {"token_usage": None},
            ]
        )
        self.assertEqual(usage, {"input_tokens": 16, "output_tokens": 10, "total_tokens": 26})

    def test_acceptance_report_preserves_blocked_terminal_status(self) -> None:
        generator = AcceptanceReportGenerator(SITINA_HOME)
        blocked_report = {
            "replay": {"status": "replay_ok"},
            "provider": {"provider_mode": ["live"], "fallback_used": False, "provider_call_count": 2},
            "terminal_event": {"count": 1, "type": "run_failed", "status": "blocked"},
            "simulate": {"status": "replay_simulated"},
            "diff": {"status": "match"},
            "secret_scan": {"total_findings": 0},
            "changed_real_files": False,
            "agent_identities": [
                {"agent_id": "controller", "provider_calls": [{"schema_validation_status": "valid"}]},
                {"agent_id": "planner", "provider_calls": [{"schema_validation_status": "valid"}]},
            ],
            "lease": [],
            "arbitration": [],
            "retry_rework": {"retry_state": [], "rework_nodes": {}},
            "checkpoint_resume": {"integrity_ok": True},
        }
        with patch.object(generator, "generate_live_report", return_value=blocked_report):
            report = generator.generate_acceptance_report("run_controlled_blocked")
        self.assertEqual(report["overall_status"], "blocked")
        self.assertEqual(generator._live_status({"terminal_event": blocked_report["terminal_event"]}), "blocked")

    def test_acceptance_report_recognizes_resolved_lease_arbitration(self) -> None:
        generator = AcceptanceReportGenerator(SITINA_HOME)
        conflict = {"event_type": "lease_conflict_detected", "lease_id": "lease_loser"}
        holder_blocked = {"event_type": "lease_holder_blocked", "lease_id": "lease_loser"}
        grant = {"event_type": "arbitration_decision", "decision": "grant_agent_a"}
        block = {"event_type": "arbitration_decision", "decision": "block"}
        self.assertTrue(generator._lease_conflicts_resolved([conflict, holder_blocked], [grant], {"type": "run_completed", "status": "ok"}))
        self.assertTrue(generator._lease_conflicts_resolved([conflict], [block], {"type": "run_failed", "status": "blocked"}))
        self.assertFalse(generator._lease_conflicts_resolved([conflict], [grant], {"type": "run_completed", "status": "ok"}))
        self.assertTrue(
            generator._agent_identity_sufficient(
                {
                    "agent_identities": [{"agent_id": "arbiter"}],
                    "lease": [conflict],
                    "arbitration": [grant],
                }
            )
        )

    def test_v1_baseline_goal_marker_prevents_cross_scenario_match(self) -> None:
        events = [
            {
                "event_type": "collaboration_phase",
                "payload_json": {"payload": {"goal_preview": "side-effect-descriptor-fixture mock baseline"}},
            },
            {"event_type": "run_completed", "payload_json": {}},
        ]
        self.assertTrue(AcceptanceReportGenerator._goal_marker(events, "side-effect-descriptor-fixture"))
        self.assertFalse(AcceptanceReportGenerator._goal_marker(events, "code-change-fixture"))

    def test_v1_baseline_scans_complete_run_history(self) -> None:
        generator = AcceptanceReportGenerator(SITINA_HOME)
        with patch.object(generator.store, "list_runs", return_value=[]) as list_runs:
            report = generator._mock_baseline()
        list_runs.assert_called_once_with(limit=None)
        self.assertTrue(all(item["status"] == "missing" for item in report.values()))

    def test_deepseek_schema_uses_strict_tool_with_thinking_disabled(self) -> None:
        client = AnthropicCompatibleClient(SITINA_HOME)
        profile = ProviderProfile(name="deepseek", base_url="https://api.deepseek.com/anthropic", auth_token="controlled-token-not-used", model="controlled-model")
        captured: dict = {}

        def fake_request(url, body, _headers, **kwargs):
            captured["url"] = url
            captured["body"] = body
            captured["protocol"] = kwargs["protocol"]
            return (
                {
                    "choices": [
                        {
                            "message": {
                                "content": None,
                                "tool_calls": [
                                    {
                                        "type": "function",
                                        "function": {
                                            "name": "sitina_structured_response",
                                            "arguments": "{\"agent_status\":\"ok\"}",
                                        },
                                    }
                                ],
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
                },
                {"provider_request_id": "controlled-tool-call", "provider_call_started_at": "2026-07-10T00:00:00Z", "provider_call_completed_at": "2026-07-10T00:00:01Z", "fallback_used": False},
            )

        with patch.object(client, "_request_json", side_effect=fake_request):
            completion = client.complete_with_metadata(profile, system_prompt="controlled", user_prompt="controlled", expect_json=True, json_schema={"type": "object"})

        self.assertEqual(captured["protocol"], "openai_chat_completions")
        self.assertEqual(captured["url"], "https://api.deepseek.com/v1/chat/completions")
        self.assertNotIn("response_format", captured["body"])
        self.assertEqual(captured["body"]["thinking"], {"type": "disabled"})
        self.assertFalse(captured["body"]["parallel_tool_calls"])
        self.assertEqual(captured["body"]["tool_choice"]["function"]["name"], "sitina_structured_response")
        tool = captured["body"]["tools"][0]["function"]
        self.assertTrue(tool["strict"])
        self.assertEqual(tool["parameters"], {"type": "object"})
        self.assertIn("required output tool", captured["body"]["messages"][0]["content"])
        self.assertIn("never wrap it", captured["body"]["messages"][0]["content"])
        self.assertIn("Do not add an arguments wrapper", tool["description"])
        self.assertIn("unquoted token null", captured["body"]["messages"][0]["content"])
        self.assertEqual(completion.text, '{"agent_status":"ok"}')
        self.assertEqual(completion.metadata["structured_output_method"], "strict_tool_call")
        self.assertTrue(completion.metadata["structured_schema_strict"])
        self.assertEqual(completion.metadata["thinking_mode"], "disabled")
        self.assertTrue(completion.metadata["runtime_schema_validation_required"])
        self.assertEqual(completion.metadata["token_usage"], {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18})

    def test_debate_prompt_requests_compact_schema_valid_response(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "planner",
            planner_input()
            | {
                "project_context": {
                    "home": str(SITINA_HOME),
                    "debate_context": {"debate_id": "controlled", "own_proposal": {}, "critic": {}},
                }
            },
        )
        self.assertIn("COMPACT DEBATE RESPONSE", prompt)
        self.assertIn("Return exactly one JSON object", prompt)

    def test_readonly_analysis_inventory_event_is_ledger_valid(self) -> None:
        run_id = "run_readonly_inventory_" + uuid.uuid4().hex[:12]
        event = RunLedger(SITINA_HOME).record(
            "readonly_analysis_inventory_created",
            run_id=run_id,
            task_type="code_change",
            reason="controlled readonly inventory created",
            payload={"inventory_hash": "sha256:controlled", "module_count": 6, "side_effects": "forbidden"},
        )
        self.assertEqual(event.event_type, "readonly_analysis_inventory_created")
        self.assertEqual(event.status, "ok")

    def test_readonly_analysis_prompt_requires_real_artifacts_and_controls(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "planner",
            planner_input()
            | {
                "project_context": {
                    "home": str(SITINA_HOME),
                    "readonly_analysis_contract": {"required_artifacts": ["readonly_module_inventory", "architecture_consistency_report"]},
                }
            },
        )
        self.assertIn("readonly_module_inventory", prompt)
        self.assertIn("architecture_consistency_report", prompt)
        self.assertIn("no subprocess or dynamic execution", prompt)

    def test_proposal_evaluation_prompt_is_compact(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "critic",
            {
                "debate_question": "Evaluate a controlled proposal.",
                "current_plan": {"proposal": {"proposal_id": "controlled"}},
                "risk_context": {"proposal_risk": "low"},
                "allowed_read_scope": [str(SITINA_HOME)],
            },
        )
        self.assertIn("COMPACT EVALUATION", prompt)
        self.assertIn("at most two claims", prompt)

    def test_depth_revision_contract_is_evidence_grounded(self) -> None:
        runtime = CollaborationRuntime(SITINA_HOME)
        proposal = Proposal(
            proposal_id="proposal_depth_controlled",
            proposal_round_id="round_depth_controlled",
            run_id="run_depth_controlled",
            proposer_agent="planner",
            proposal_type="task_graph",
            summary="controlled readonly proposal",
            task_graph_patch={"strategy": "readonly_architecture_analysis"},
            risk_level="low",
        )
        payload = runtime._evaluation_agent_input(
            "critic",
            "live-complex-readonly-fixture controlled depth",
            {"task_type": "code_change", "risk_level": "low", "extensions": {}},
            proposal,
        )
        contract = payload["current_plan"]["depth_revision_contract"]
        self.assertEqual(contract["required_task_graph_patch_field"], "revision_evidence")
        self.assertNotIn("revision_evidence", proposal.task_graph_patch)
        self.assertIn("needs_revision", payload["debate_question"])
        self.assertTrue(SitinaEngine._is_live_readonly_analysis("live-two-proposer-fixture controlled depth"))
        self.assertTrue(SitinaEngine._is_core_depth_protocol("live-revision-fixture controlled depth"))
        self.assertFalse(SitinaEngine._is_core_depth_protocol("live-complex-readonly-fixture controlled depth"))
        two_proposer = runtime._evaluation_agent_input(
            "critic",
            "live-two-proposer-fixture controlled depth",
            {"task_type": "code_change", "risk_level": "low", "extensions": {"readonly_analysis_inventory": {}}},
            proposal,
        )
        self.assertIn("depth_revision_contract", two_proposer["current_plan"])
        self.assertIn("readonly_analysis_contract", two_proposer["current_plan"])

    def test_live_minimal_contract_is_explicit_and_fail_closed(self) -> None:
        runtime = CollaborationRuntime(SITINA_HOME)
        selection = TeamSelection(
            run_id="run_live_minimal_contract",
            task_id="main",
            task_type="code_change",
            risk_level="low",
            candidate_agents=["controller", "planner", "critic", "summary"],
            required_agents=["planner", "summary"],
            optional_agents=["critic"],
            forbidden_agents=[],
            reviewer_set=[],
            tester_set=[],
            proposer_set=["planner"],
            evaluator_set=["critic"],
            excluded={},
            selected_agents=["planner", "critic", "summary"],
            created_at="2026-07-13T00:00:00Z",
        )
        goal = "live-minimal-collaboration-fixture deepseek-only unittest validation"
        controller = {"task_type": "code_change", "risk_level": "low", "requested_tools": [], "extensions": {}}
        proposal_input = runtime._proposal_agent_input("planner", goal, controller, selection)
        contract = proposal_input["project_context"]["minimal_live_contract"]
        self.assertTrue(contract["real_side_effects_forbidden"])
        self.assertFalse(contract["source_mutation_allowed"])
        self.assertEqual(contract["writable_scope"], [])
        self.assertIn("touched_files=[]", proposal_input["conversation_summary"])

        proposal = Proposal(
            proposal_id="proposal_live_minimal_contract",
            proposal_round_id="round_live_minimal_contract",
            run_id=selection.run_id,
            proposer_agent="planner",
            proposal_type="task_graph",
            summary="controlled no-side-effect validation",
            task_graph_patch={"controlled_noop_policy_graph": True, "real_side_effects_forbidden": True},
            risk_level="low",
            bid={
                "required_agents": ["controller", "planner", "critic", "summary"],
                "required_tools": [],
                "required_side_effects": [],
                "touched_files": [],
            },
        )
        evaluation_input = runtime._evaluation_agent_input("critic", goal, controller, proposal)
        self.assertEqual(evaluation_input["current_plan"]["minimal_live_contract"], contract)
        self.assertIn("Return support only", evaluation_input["debate_question"])
        self.assertIn("otherwise return needs_revision or block", evaluation_input["debate_question"])
        self.assertNotIn("minimal_live_contract", runtime._evaluation_agent_input("critic", "ordinary code change", controller, proposal)["current_plan"])

    def test_proposal_authoring_prompt_is_compact(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "planner",
            planner_input() | {"project_context": {"home": str(SITINA_HOME), "collaboration_mode": "proposal_authoring"}},
        )
        self.assertIn("COMPACT PROPOSAL", prompt)
        self.assertIn("at most two plan steps", prompt)
        self.assertIn("evidence=[]", prompt)

    def test_lease_arbitration_prompt_distinguishes_reservation_from_mutation(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "arbiter",
            {
                "conflict_id": "arb_controlled",
                "conflict_type": "lease_conflict",
                "participants": ["coder", "maintenance_ops"],
                "claims": ["lease_a", "lease_b"],
                "resources": ["controlled.txt"],
                "policy_context": {"conflict_context": {"approval_scope": {"status": "approved", "holder_agent": "coder"}}},
            },
        )
        self.assertIn("lease decision only reserves a resource", prompt)
        self.assertIn("never authorizes a file mutation", prompt)
        self.assertIn("block_required_without_approval", prompt)

    def test_live_arbitration_failure_never_becomes_synthetic_block(self) -> None:
        class FailingArbiterRunner:
            def run_agent(self, *_args, **_kwargs):
                raise AgentRunnerError("controlled live arbiter failure", error_type="provider_read_timeout")

        with self.assertRaises(AgentRunnerError):
            ArbitrationManager(SITINA_HOME).arbitrate(
                run_id="run_live_arbiter_failure_" + uuid.uuid4().hex[:12],
                task_id="lease_conflict",
                task_type="code_change",
                conflict_type="lease_conflict",
                participants=["coder", "maintenance_ops"],
                resources=["controlled.txt"],
                claims=["controlled conflict"],
                context={"approval_scope": {"status": "approved", "holder_agent": "coder"}},
                runner=FailingArbiterRunner(),
                provider_mode="live",
            )

    def test_lease_arbitration_worker_has_resolved_grant_and_block_terminals(self) -> None:
        engine = SitinaEngine(SITINA_HOME)
        granted = engine.run("live-lease-arbitration-worker-fixture controlled mock worker", provider_mode="mock")
        self.assertEqual(granted["status"], "done", granted)
        granted_replay = ReplayEngine(SITINA_HOME).replay(granted["run_id"], record=False)
        self.assertEqual(granted_replay.status, "replay_ok", granted_replay.model_dump())
        self.assertTrue(any(item.get("decision") == "grant_agent_a" for item in granted_replay.arbitrations))
        self.assertEqual(granted_replay.node_states.get("lease_loser_maintenance_ops"), "blocked")
        self.assertTrue(any(item.get("event_type") == "lease_released" and item.get("holder_agent") == "coder" for item in granted_replay.leases))

        blocked = engine.run("live-lease-arbitration-block-worker-fixture controlled mock worker", provider_mode="mock")
        self.assertEqual(blocked["status"], "blocked", blocked)
        blocked_events = RunLedger(SITINA_HOME).timeline(blocked["run_id"])
        self.assertNotIn("run_completed", {event["event_type"] for event in blocked_events})
        blocked_replay = ReplayEngine(SITINA_HOME).replay(blocked["run_id"], record=False)
        self.assertEqual(blocked_replay.status, "replay_ok", blocked_replay.model_dump())
        self.assertTrue(any(item.get("decision") == "block" for item in blocked_replay.arbitrations))

    def test_core_depth_protocol_skips_only_terminal_synthesis_agents(self) -> None:
        result = SitinaEngine(SITINA_HOME).run(
            "live-revision-fixture controlled mock core-depth protocol",
            provider_mode="mock",
        )
        self.assertEqual(result["status"], "done", result)
        timeline = RunLedger(SITINA_HOME).timeline(result["run_id"])
        completed_agents = [event.get("agent_id") for event in timeline if event["event_type"] == "agent_completed"]
        self.assertNotIn("summary", completed_agents)
        self.assertNotIn("memory", completed_agents)
        replay = ReplayEngine(SITINA_HOME).replay(result["run_id"], record=False)
        self.assertEqual(replay.status, "replay_ok", replay.model_dump())
        self.assertEqual(replay.memory_outcome.get("event_type"), "memory_no_candidate")
        self.assertEqual(replay.node_states.get("parallel_tester_group"), "completed")
        self.assertEqual(replay.node_states.get("parallel_reviewer_group"), "completed")
        self.assertEqual(replay.node_states.get("summary"), "skipped")
        self.assertEqual(replay.node_states.get("memory"), "skipped")

    def test_readonly_verification_prompt_allows_evidence_based_pass(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "tester",
            {
                "test_strategy": "Verify readonly evidence.",
                "allowed_commands": ["sitina config validate"],
                "patch_id": "live_readonly_analysis",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "approved_env": {"SITINA_HOME": str(SITINA_HOME)},
                "expected_artifact_hash": None,
                "blackboard_context": [{"document_id": "controlled"}],
            },
        )
        self.assertIn("CONTROLLED READONLY VERIFICATION", prompt)
        self.assertIn("Do not report cannot_complete", prompt)

    def test_readonly_reviewer_receives_protocol_and_artifact_hash_evidence(self) -> None:
        runner = self.runner()
        prompt = runner._user_prompt(
            "reviewer",
            {
                "patch_id": "live_readonly_analysis",
                "changed_files": ["__NO_REAL_FILE_CHANGE__"],
                "acceptance_criteria": ["proposal/evaluation evidence recorded"],
                "test_artifacts": ["sha256:inventory", "sha256:report", "sha256:tester"],
                "mandatory_step_context": {
                    "readonly_analysis": {"inventory_hash": "sha256:inventory", "report_hash": "sha256:report"},
                    "collaboration_evidence": {
                        "proposal_ids": ["proposal_a", "proposal_b"],
                        "evaluation_ids": ["eval_a", "eval_b"],
                        "selected_proposal_ids": ["proposal_b"],
                    },
                },
            },
        )
        self.assertIn("CONTROLLED READONLY VERIFICATION", prompt)
        self.assertIn("collaboration_evidence", prompt)
        self.assertIn("sha256:report", prompt)

    def test_optional_approval_node_does_not_request_receiver_handoff(self) -> None:
        run_id = "run_optional_approval_" + uuid.uuid4().hex[:12]
        now = iso_now()
        graph = TaskGraph(
            run_id=run_id,
            task_type="code_change",
            created_at=now,
            nodes=[
                TaskGraphNode(task_id="planner", run_id=run_id, task_type="code_change", node_type="planner", owner_agent="planner", status="completed", created_at=now),
                TaskGraphNode(task_id="approval", run_id=run_id, task_type="code_change", node_type="approval", owner_agent="controller", depends_on=["planner"], mandatory=False, created_at=now),
            ],
        )
        with patch.object(TaskGraphRuntime, "require_handoff", side_effect=AssertionError("optional approval handoff invoked")):
            result = SitinaEngine(SITINA_HOME)._complete_fixture_approval_if_required(
                graph,
                "sha256:controlled",
                reason="controlled optional approval",
                runner=MagicMock(),
                provider_mode="live",
            )
        self.assertEqual(result.node_map["approval"].status, "skipped")

    def test_live_handoff_reject_input_is_evidence_driven_not_goal_driven(self) -> None:
        run_id = "run_live_handoff_evidence_" + uuid.uuid4().hex[:12]
        now = iso_now()
        graph = TaskGraph(
            run_id=run_id,
            task_type="code_change",
            created_at=now,
            nodes=[
                TaskGraphNode(task_id="controller", run_id=run_id, task_type="code_change", node_type="controller", owner_agent="controller", status="completed", created_at=now),
                TaskGraphNode(task_id="planner", run_id=run_id, task_type="code_change", node_type="planner", owner_agent="planner", depends_on=["controller"], created_at=now),
            ],
        )
        contract = HandoffContract(
            handoff_id="handoff_controlled_evidence",
            run_id=run_id,
            task_id="planner",
            task_type="code_change",
            from_agent="controller",
            to_agent="planner",
            reason="controlled scope evidence",
            required_inputs=["scope_evidence"],
            provided_artifacts=[],
            gate_requirements=[],
            created_at=now,
        )
        evidence = {
            "evidence_type": "scope_conflict",
            "requested_operation": "prepare source mutation",
            "authorized_operation": "readonly inspection only",
            "approval_status": "absent",
        }
        payload = TaskGraphRuntime(SITINA_HOME)._receiver_decision_input(
            graph=graph,
            node=graph.node_map["planner"],
            contract=contract,
            handoff_context={
                "user_goal": "live-handoff-reject-fixture marker must not drive the decision",
                "controlled_reject_evidence": evidence,
                "real_side_effects_forbidden": True,
            },
        )
        self.assertNotIn("handoff-reject-fixture", payload["user_goal"])
        self.assertEqual(payload["project_context"]["handoff_context"]["controlled_reject_evidence"], evidence)
        prompt = AgentRunner(SITINA_HOME)._user_prompt("planner", payload)
        self.assertIn("independently decide", prompt)

    def test_handoff_receiver_preserves_typed_provider_terminal_error(self) -> None:
        run_id = "run_handoff_deadline_" + uuid.uuid4().hex[:12]
        now = iso_now()
        graph = TaskGraph(
            run_id=run_id,
            task_type="code_change",
            created_at=now,
            nodes=[
                TaskGraphNode(task_id="controller", run_id=run_id, task_type="code_change", node_type="controller", owner_agent="controller", status="completed", created_at=now),
                TaskGraphNode(task_id="planner", run_id=run_id, task_type="code_change", node_type="planner", owner_agent="planner", depends_on=["controller"], created_at=now),
            ],
        )

        class DeadlineRunner:
            def run_agent(self, *_args, **_kwargs):
                raise AgentRunnerError("controlled receiver deadline", error_type="run_deadline_exceeded")

        runtime = TaskGraphRuntime(SITINA_HOME)
        runtime.save(graph)
        with self.assertRaises(AgentRunnerError) as raised:
            runtime.require_handoff(
                graph,
                "planner",
                completed_task_ids={"controller"},
                runner=DeadlineRunner(),
                provider_mode="live",
                handoff_context={"user_goal": "controlled code change", "real_side_effects_forbidden": True},
            )
        self.assertEqual(raised.exception.error_type, "run_deadline_exceeded")

    def test_change_request_aliases_are_normalized_to_needs_revision(self) -> None:
        runtime = CollaborationRuntime(SITINA_HOME)
        manager = MagicMock()
        manager.evaluate.return_value = "controlled"
        round_ = ProposalRound(
            proposal_round_id="prop_round_controlled",
            run_id="run_controlled",
            task_id="main",
            task_type="code_change",
            participants=["planner", "critic"],
            status="open",
            created_at="2026-07-10T00:00:00Z",
        )
        proposal = Proposal(
            proposal_id="proposal_controlled",
            proposal_round_id=round_.proposal_round_id,
            run_id=round_.run_id,
            proposer_agent="planner",
            proposal_type="task_graph",
            summary="controlled",
            risk_level="low",
        )
        for decision in ("approve_with_changes", "needs_changes", "request_changes"):
            with self.subTest(decision=decision):
                result = runtime._evaluation_from_agent_output(
                    manager,
                    round_,
                    proposal,
                    "critic",
                    {"decision": "counterargument", "extensions": {"proposal_evaluation": {"decision": decision}}},
                )
                self.assertEqual(result, "controlled")
                self.assertEqual(manager.evaluate.call_args.kwargs["decision"], "needs_revision")

    def test_proposal_type_aliases_are_normalized_but_unknown_types_fail(self) -> None:
        runtime = CollaborationRuntime(SITINA_HOME)
        self.assertEqual(runtime._proposal_type("readonly_architecture_analysis"), "task_graph")
        self.assertEqual(runtime._proposal_type("code_change"), "task_graph")
        self.assertEqual(runtime._proposal_type("architecture_change"), "task_graph")
        self.assertEqual(runtime._proposal_type("implementation_plan"), "implementation_strategy")
        with self.assertRaisesRegex(ValueError, "unsupported proposal_type"):
            runtime._proposal_type("execute_directly")

    def test_unverified_critic_rejection_is_advisory_not_blocking(self) -> None:
        runtime = CollaborationRuntime(SITINA_HOME)
        manager = MagicMock()
        manager.evaluate.return_value = "controlled"
        round_ = ProposalRound(proposal_round_id="prop_round_controlled", run_id="run_controlled", task_id="main", task_type="code_change", participants=["planner", "critic"], status="open", created_at="2026-07-10T00:00:00Z")
        proposal = Proposal(proposal_id="proposal_controlled", proposal_round_id=round_.proposal_round_id, run_id=round_.run_id, proposer_agent="planner", proposal_type="task_graph", summary="controlled", risk_level="low")
        runtime._evaluation_from_agent_output(
            manager,
            round_,
            proposal,
            "critic",
            {
                "decision": "counterargument",
                "claims": [{"label": "unverified", "evidence_ref": ["controlled"]}],
                "extensions": {"proposal_evaluation": {"decision": "reject", "reason": "unverified concern"}},
            },
        )
        self.assertEqual(manager.evaluate.call_args.kwargs["decision"], "support")

    def test_depth_selection_prefers_resolved_revision_over_unresolved_parent(self) -> None:
        manager = ProposalManager(SITINA_HOME)
        round_ = manager.open_round(
            run_id="run_depth_selection_" + uuid.uuid4().hex[:12],
            task_id="main",
            task_type="code_change",
            participants=["planner", "critic"],
        )
        parent = manager.submit(round_, proposer_agent="planner", proposal_type="task_graph", summary="parent", risk_level="low", task_graph_patch={"strategy": "readonly"})
        revision = manager.submit(
            round_,
            proposer_agent="planner",
            proposal_type="task_graph",
            summary="revision",
            risk_level="low",
            task_graph_patch={"strategy": "readonly", "revision_evidence": "critic_gap_addressed"},
            parent_proposal_id=parent.proposal_id,
            revision_id="revision_controlled",
            revision_round=1,
        )
        parent_eval = manager.evaluate(round_, parent, reviewer_agent="critic", score=50, decision="needs_revision", reason="missing evidence")
        revision_eval = manager.evaluate(round_, revision, reviewer_agent="critic", score=90, decision="support", reason="evidence repaired")
        selection = manager.select(round_, [parent, revision], [parent_eval, revision_eval])
        self.assertEqual(selection.selected_proposal_id, revision.proposal_id)
        self.assertIn(parent.proposal_id, selection.rejected)
        rejected = [event for event in RunLedger(SITINA_HOME).timeline(round_.run_id) if event["event_type"] == "proposal_rejected"]
        self.assertTrue(any(event["payload_json"].get("proposal_id") == parent.proposal_id for event in rejected))

    def test_cannot_complete_output_gets_blocked_envelope_reason(self) -> None:
        envelope = EnvelopeFactory.wrap_agent_output(
            run_id="run_controlled",
            agent_id="tester",
            task_id="tester",
            task_type="code_change",
            payload={"agent_status": "cannot_complete", "decision": "blocked", "extensions": {}},
        )
        self.assertEqual(envelope.status, "blocked")
        self.assertIn("cannot_complete", envelope.blocked_reason or "")

    def test_live_provider_failures_never_invoke_mock_or_fallback(self) -> None:
        failures = [
            (ProviderConnectTimeout("connect timeout"), "provider_connect_timeout"),
            (ProviderReadTimeout("read timeout"), "provider_read_timeout"),
            (ProviderAuthError(401, "unauthorized"), "provider_auth_failed"),
            (ProviderPermissionError(403, "forbidden"), "provider_permission_denied"),
            (ProviderRateLimitError(429, "rate limited", retry_after_seconds=0.0), "provider_rate_limited"),
        ]
        for failure, event_type in failures:
            with self.subTest(event_type=event_type):
                runner = self.runner()
                run_id = "run_provider_failure_" + uuid.uuid4().hex[:12]
                RunControlStore(SITINA_HOME).create(RunDeadline.create(run_id, 60))
                with patch.object(runner.client, "complete_with_metadata", side_effect=failure), patch.object(runner.mock, "complete", side_effect=AssertionError("mock fallback invoked")):
                    with self.assertRaises(AgentRunnerError) as raised:
                        runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)
                self.assertEqual(raised.exception.error_type, event_type)
                events = RunLedger(SITINA_HOME).timeline(run_id)
                self.assertIn(event_type, [item["event_type"] for item in events])
                failure_event = next(item for item in events if item["event_type"] == event_type)
                self.assertFalse(failure_event["payload_json"]["fallback_used"])

    def test_provider_401_403_429_and_parse_failures_have_engine_terminal(self) -> None:
        error_types = (
            "provider_auth_failed",
            "provider_permission_denied",
            "provider_rate_limited",
            "provider_parse_failed",
            "agent_schema_invalid",
        )
        for error_type in error_types:
            with self.subTest(error_type=error_type):
                class FailingRunner:
                    def __init__(self, home):
                        self.home = home

                    def run_agent(self, *_args, **kwargs):
                        RunLedger(self.home).record(
                            error_type,
                            run_id=kwargs["run_id"],
                            task_id=kwargs.get("task_id", "main"),
                            task_type=kwargs.get("task_type", "chat"),
                            agent_id="controller",
                            status="failed",
                            reason=f"controlled {error_type}",
                            payload={"provider_mode": "live", "fallback_used": False},
                        )
                        raise AgentRunnerError(f"controlled {error_type}", error_type=error_type)

                with patch("sitina.orchestrator.engine.AgentRunner", FailingRunner):
                    result = SitinaEngine(SITINA_HOME).run(f"controlled {error_type} terminal fixture", provider_mode="live")
                self.assertEqual(result["status"], "failed", result)
                events = RunLedger(SITINA_HOME).timeline(result["run_id"])
                event_names = [event["event_type"] for event in events]
                self.assertIn(error_type, event_names)
                terminals = [name for name in event_names if name in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}]
                self.assertEqual(len(terminals), 1)
                self.assertEqual(terminals[0], "run_failed")
                self.assertEqual(ReplayEngine(SITINA_HOME).replay(result["run_id"]).status, "replay_ok")

    def test_provider_429_retry_is_bounded_and_deadline_aware(self) -> None:
        runner = self.runner()
        run_id = "run_provider_retry_" + uuid.uuid4().hex[:12]
        RunControlStore(SITINA_HOME).create(RunDeadline.create(run_id, 60))
        raw = runner.mock.complete("planner", planner_input())
        completion = ProviderCompletion(
            text=raw,
            metadata={
                "provider_request_id": "controlled-after-rate-limit",
                "provider_call_started_at": "2026-07-10T00:00:00Z",
                "provider_call_completed_at": "2026-07-10T00:00:01Z",
                "fallback_used": False,
            },
        )
        rate_limited = ProviderRateLimitError(429, "controlled rate limit", retry_after_seconds=0.0)
        with patch.object(runner.client, "complete_with_metadata", side_effect=[rate_limited, completion]) as provider_call:
            result = runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)
        self.assertEqual(provider_call.call_count, 2)
        self.assertEqual(len(result.provider_calls), 1)
        events = RunLedger(SITINA_HOME).timeline(run_id)
        retries = [event for event in events if event["event_type"] == "provider_retry_scheduled"]
        self.assertEqual(len(retries), 1)
        self.assertEqual(retries[0]["payload_json"]["retry_count"], 1)
        self.assertFalse(result.fallback_used)

    def test_raw_incomplete_read_gets_one_bounded_transport_retry(self) -> None:
        runner = self.runner()
        run_id = "run_incomplete_read_retry_" + uuid.uuid4().hex[:12]
        RunControlStore(SITINA_HOME).create(RunDeadline.create(run_id, 60))
        raw = runner.mock.complete("planner", planner_input())
        completion = ProviderCompletion(
            text=raw,
            metadata={
                "provider_request_id": "controlled-after-incomplete-read",
                "provider_call_started_at": "2026-07-10T00:00:00Z",
                "provider_call_completed_at": "2026-07-10T00:00:01Z",
                "fallback_used": False,
            },
        )
        with patch.object(runner.client, "complete_with_metadata", side_effect=[http.client.IncompleteRead(b""), completion]) as provider_call:
            result = runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)
        self.assertEqual(provider_call.call_count, 2)
        self.assertEqual(len(result.provider_calls), 1)
        retries = [event for event in RunLedger(SITINA_HOME).timeline(run_id) if event["event_type"] == "provider_retry_scheduled"]
        self.assertEqual(len(retries), 1)
        self.assertFalse(result.fallback_used)

    def test_provider_total_timeout_interrupts_blocking_response_read(self) -> None:
        class BlockingSocket:
            def settimeout(self, _timeout: float) -> None:
                pass

            def shutdown(self, _how: int) -> None:
                pass

            def close(self) -> None:
                pass

        class BlockingConnection:
            instances: list["BlockingConnection"] = []

            def __init__(self, *_args, **_kwargs) -> None:
                self.sock = BlockingSocket()
                self.closed = False
                self.__class__.instances.append(self)

            def connect(self) -> None:
                pass

            def request(self, *_args, **_kwargs) -> None:
                pass

            def getresponse(self):
                return self

            def read(self) -> bytes:
                while not self.closed:
                    time.sleep(0.005)
                raise OSError("connection closed by total timeout")

            def close(self) -> None:
                self.closed = True

        client = AnthropicCompatibleClient(SITINA_HOME)
        client.timeout_config = ProviderTimeoutConfig(
            connect_timeout=0.1,
            read_timeout=1.0,
            total_request_timeout=0.05,
            retry_backoff_seconds=0.0,
            max_retries=0,
            run_deadline=1.0,
        )
        profile = ProviderProfile(name="controlled", base_url="https://provider.invalid", auth_token="controlled-token-not-used", model="controlled-model")
        started = time.monotonic()
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.getitimer(signal.ITIMER_REAL)
        signal.signal(signal.SIGALRM, lambda _signum, _frame: None)
        signal.setitimer(signal.ITIMER_REAL, 1.0)
        try:
            with patch("sitina.runners.provider.http.client.HTTPSConnection", BlockingConnection):
                with self.assertRaises(ProviderReadTimeout) as raised:
                    client._request_json(
                        "https://provider.invalid/v1/chat/completions",
                        {"model": "controlled-model", "messages": []},
                        {"authorization": "Bearer controlled-token-not-used"},
                        profile=profile,
                        protocol="controlled",
                        request_timeout_seconds=0.05,
                    )
        finally:
            signal.setitimer(signal.ITIMER_REAL, *original_timer)
            signal.signal(signal.SIGALRM, original_handler)
        self.assertIn("total request timeout", str(raised.exception))
        self.assertLess(time.monotonic() - started, 0.5)

    def test_provider_inflight_cancellation_terminates_request_worker(self) -> None:
        class BlockingSocket:
            def settimeout(self, _timeout: float) -> None:
                pass

            def shutdown(self, _how: int) -> None:
                pass

            def close(self) -> None:
                pass

        class BlockingConnection:
            def __init__(self, *_args, **_kwargs) -> None:
                self.sock = BlockingSocket()

            def connect(self) -> None:
                pass

            def request(self, *_args, **_kwargs) -> None:
                pass

            def getresponse(self):
                return self

            def read(self) -> bytes:
                while True:
                    time.sleep(0.01)

            def close(self) -> None:
                pass

        client = AnthropicCompatibleClient(SITINA_HOME)
        client.timeout_config = ProviderTimeoutConfig(connect_timeout=0.1, read_timeout=2.0, total_request_timeout=2.0, retry_backoff_seconds=0.0, max_retries=0, run_deadline=2.0)
        profile = ProviderProfile(name="controlled", base_url="https://provider.invalid", auth_token="controlled-token-not-used", model="controlled-model")
        started = time.monotonic()
        with patch("sitina.runners.provider.http.client.HTTPSConnection", BlockingConnection):
            with self.assertRaises(ProviderCancelledError):
                client._request_json(
                    "https://provider.invalid/v1/chat/completions",
                    {"model": "controlled-model", "messages": []},
                    {"authorization": "Bearer controlled-token-not-used"},
                    profile=profile,
                    protocol="controlled",
                    request_timeout_seconds=2.0,
                    cancel_check=lambda: time.monotonic() - started >= 0.05,
                )
        self.assertLess(time.monotonic() - started, 0.5)

    def test_provider_worker_eof_is_fail_closed_with_exit_code(self) -> None:
        class Receiver:
            def poll(self, _timeout: float) -> bool:
                return True

            def recv(self):
                raise EOFError

            def close(self) -> None:
                pass

        class Sender:
            def close(self) -> None:
                pass

        class Process:
            daemon = False
            exitcode = 17

            def start(self) -> None:
                pass

            def join(self, timeout: float | None = None) -> None:
                del timeout

            def is_alive(self) -> bool:
                return False

            def terminate(self) -> None:
                pass

        class Context:
            def Pipe(self, *, duplex: bool):
                self.duplex = duplex
                return Receiver(), Sender()

            def Process(self, **_kwargs):
                return Process()

        client = AnthropicCompatibleClient(SITINA_HOME)
        profile = ProviderProfile(
            name="controlled",
            base_url="https://provider.invalid",
            auth_token="controlled-token-not-used",
            model="controlled-model",
        )
        with patch("sitina.runners.provider.multiprocessing.get_context", return_value=Context()) as get_context:
            with self.assertRaises(ProviderError) as raised:
                client._request_json(
                    "https://provider.invalid/v1/chat/completions",
                    {"model": "controlled-model", "messages": []},
                    {"authorization": "Bearer controlled-token-not-used"},
                    profile=profile,
                    protocol="controlled",
                    request_timeout_seconds=1.0,
                )
        get_context.assert_called_once_with("fork")
        self.assertEqual(str(raised.exception), "provider worker exited without a result (exit_code=17)")

    def test_capability_bound_provider_request_stays_in_issuing_process(self) -> None:
        client = AnthropicCompatibleClient(SITINA_HOME)
        client.network_egress_capability = object()
        profile = ProviderProfile(
            name="controlled",
            base_url="https://provider.invalid",
            auth_token="controlled-token-not-used",
            model="controlled-model",
        )
        expected = ({"choices": []}, {"protocol": "controlled"})
        with patch.object(client, "_request_json_direct", return_value=expected) as direct, patch(
            "sitina.runners.provider.multiprocessing.get_context"
        ) as get_context:
            actual = client._request_json(
                "https://provider.invalid/v1/chat/completions",
                {"model": "controlled-model", "messages": []},
                {"authorization": "Bearer controlled-token-not-used"},
                profile=profile,
                protocol="controlled",
                request_timeout_seconds=1.0,
            )
        self.assertEqual(actual, expected)
        direct.assert_called_once()
        get_context.assert_not_called()

    def test_agent_runner_inflight_cancel_is_fail_closed(self) -> None:
        runner = self.runner()
        run_id = "run_provider_cancel_" + uuid.uuid4().hex[:12]
        control = RunControlStore(SITINA_HOME)
        control.create(RunDeadline.create(run_id, 60))

        def cancelled_call(*_args, **kwargs):
            control.request_cancel(run_id, "controlled in-flight cancellation")
            self.assertTrue(kwargs["cancel_check"]())
            raise ProviderCancelledError("provider request cancelled while in flight")

        with patch.object(runner.client, "complete_with_metadata", side_effect=cancelled_call):
            with self.assertRaises(AgentRunnerError) as raised:
                runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)
        self.assertEqual(raised.exception.error_type, "run_cancelled")
        events = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertIn("run_cancelled", [event["event_type"] for event in events])
        self.assertNotIn("run_completed", [event["event_type"] for event in events])

    def test_provider_timeout_at_run_deadline_is_classified_as_deadline(self) -> None:
        runner = self.runner()
        run_id = "run_deadline_" + uuid.uuid4().hex[:12]
        RunControlStore(SITINA_HOME).create(RunDeadline.create(run_id, 0.02))

        def deadline_read_timeout(*_args, **_kwargs):
            time.sleep(0.03)
            raise ProviderReadTimeout("controlled provider total request timeout")

        with patch.object(runner.client, "complete_with_metadata", side_effect=deadline_read_timeout):
            with self.assertRaises(AgentRunnerError) as raised:
                runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)
        self.assertEqual(raised.exception.error_type, "run_deadline_exceeded")
        events = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertIn("run_deadline_exceeded", [event["event_type"] for event in events])

    def test_live_invalid_json_is_redacted_and_fails_closed(self) -> None:
        runner = self.runner()
        run_id = "run_provider_parse_" + uuid.uuid4().hex[:12]
        RunControlStore(SITINA_HOME).create(RunDeadline.create(run_id, 60))
        completion = ProviderCompletion(
            text='{"not": "a planner response"}',
            metadata={
                "provider_request_id": "controlled-invalid-json",
                "provider_call_started_at": "2026-07-10T00:00:00Z",
                "provider_call_completed_at": "2026-07-10T00:00:01Z",
                "fallback_used": False,
            },
        )
        with patch.object(runner.client, "complete_with_metadata", return_value=completion):
            with self.assertRaises(AgentRunnerError) as raised:
                runner.run_agent("planner", planner_input(), provider_mode="live", run_id=run_id)
        self.assertEqual(raised.exception.error_type, "agent_schema_invalid")
        events = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertIn("provider_parse_failed", [event["event_type"] for event in events])
        self.assertIn("agent_schema_invalid", [event["event_type"] for event in events])
        artifact = raised.exception.details["artifact"]
        self.assertTrue(artifact)
        content = Path(artifact).read_text(encoding="utf-8")
        self.assertIn("raw_output_hash", content)
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", content)

    def test_timeout_and_cancelled_runs_never_complete(self) -> None:
        class FailingRunner:
            def __init__(self, _home):
                pass

            def run_agent(self, *_args, **_kwargs):
                raise AgentRunnerError("controlled failure", error_type=error_type)

        for error_type, terminal in (("provider_read_timeout", "run_timeout"), ("run_cancelled", "run_cancelled")):
            with self.subTest(error_type=error_type), patch("sitina.orchestrator.engine.AgentRunner", FailingRunner):
                result = SitinaEngine(SITINA_HOME).run("controlled terminal fixture", provider_mode="live")
                self.assertEqual(result["phase"], "timeout" if terminal == "run_timeout" else "cancelled")
                events = RunLedger(SITINA_HOME).timeline(result["run_id"])
                event_types = [event["event_type"] for event in events]
                self.assertIn(terminal, event_types)
                self.assertNotIn("run_completed", event_types)
                replay = ReplayEngine(SITINA_HOME).replay(result["run_id"])
                self.assertEqual(replay.status, "replay_ok", replay.model_dump())

    def test_keyboard_interrupt_after_planner_writes_single_terminal_event(self) -> None:
        engine = SitinaEngine(SITINA_HOME)
        with patch.object(engine, "_run_lease_arbitration_fixture", side_effect=KeyboardInterrupt):
            result = engine.run("lease-arbitration-fixture controlled interrupt", provider_mode="mock")
        self.assertEqual(result["status"], "interrupted")
        events = RunLedger(SITINA_HOME).timeline(result["run_id"])
        terminals = [
            event["event_type"]
            for event in events
            if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}
        ]
        self.assertEqual(terminals, ["run_interrupted"])

    def test_checkpoint_resume_and_cancel_are_integrity_checked(self) -> None:
        engine = SitinaEngine(SITINA_HOME)
        result = engine.run("live-checkpoint-resume-worker-fixture controlled mock validation", provider_mode="mock")
        self.assertEqual(result["status"], "paused", result)
        run_id = result["run_id"]
        before = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertFalse(any(event["event_type"].startswith("run_") and event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"} for event in before))
        latest = CheckpointManager(SITINA_HOME).latest_resumable(run_id)
        self.assertTrue(latest)
        self.assertTrue(CheckpointManager(SITINA_HOME).verify_for_resume(latest, run_id)[0])
        self.assertEqual(len(latest["completed_agent_calls"]), 1)
        self.assertEqual(len(latest["pending_agent_calls"]), 1)

        resumed = engine.resume(run_id)
        self.assertEqual(resumed["status"], "ok")
        self.assertEqual(resumed["duplicate_provider_calls"], 0)
        self.assertEqual(resumed["resumed_agent_calls"], 1)
        events = RunLedger(SITINA_HOME).timeline(run_id)
        completed_agents = [event.get("agent_id") for event in events if event["event_type"] == "agent_completed"]
        self.assertEqual(completed_agents.count("planner"), 1)
        self.assertEqual(completed_agents.count("summary"), 1)
        terminals = [event["event_type"] for event in events if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}]
        self.assertEqual(terminals, ["run_completed"])

        resumed_again = engine.resume(run_id)
        self.assertEqual(resumed_again["status"], "ok")
        self.assertEqual(resumed_again["resumed_agent_calls"], 0)
        events_after_second_resume = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertEqual(len([event for event in events_after_second_resume if event["event_type"] == "agent_completed"]), 2)

        engine.initialize()
        state = engine.states.create("low")
        RunControlStore(SITINA_HOME).create(RunDeadline.create(state.run_id, 60))
        cancelled = engine.cancel(state.run_id, reason="controlled cancellation")
        self.assertEqual(cancelled["status"], "cancelled")
        events = RunLedger(SITINA_HOME).timeline(state.run_id)
        self.assertIn("run_cancelled", [event["event_type"] for event in events])
        self.assertNotIn("run_completed", [event["event_type"] for event in events])

    def test_resume_rejects_rehashed_pending_input_tampering(self) -> None:
        engine = SitinaEngine(SITINA_HOME)
        prepared = engine.run("live-checkpoint-resume-worker-fixture controlled tamper validation", provider_mode="mock")
        run_id = prepared["run_id"]
        manager = CheckpointManager(SITINA_HOME)
        checkpoint = manager.latest_resumable(run_id)
        self.assertTrue(checkpoint)
        checkpoint["pending_agent_calls"][0]["input_payload"]["audit_refs"].append("tampered")
        body = {key: value for key, value in checkpoint.items() if key != "checkpoint_hash"}
        checkpoint["checkpoint_hash"] = sha256_text(stable_json(body))
        write_json(manager.path(checkpoint["checkpoint_id"]), checkpoint)

        resumed = engine.resume(run_id)
        self.assertEqual(resumed["status"], "blocked")
        self.assertIn("input hash mismatch", resumed["reason"])
        events = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertIn("checkpoint_failed", [event["event_type"] for event in events])
        self.assertEqual([event["event_type"] for event in events if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}], ["run_blocked"])
        self.assertNotIn("summary", [event.get("agent_id") for event in events if event["event_type"] == "agent_completed"])

    def test_cancel_preserves_pending_checkpoint_and_prevents_resume(self) -> None:
        engine = SitinaEngine(SITINA_HOME)
        prepared = engine.run("live-checkpoint-resume-worker-fixture controlled cancellation", provider_mode="mock")
        run_id = prepared["run_id"]
        manager = CheckpointManager(SITINA_HOME)
        before = manager.latest_resumable(run_id)
        self.assertTrue(before)

        cancelled = engine.cancel(run_id, reason="controlled cancellation with pending call")
        self.assertEqual(cancelled["status"], "cancelled")
        after = manager.show(cancelled["checkpoint_id"])
        self.assertFalse(after["resumable"])
        self.assertEqual(after["completed_agent_calls"], before["completed_agent_calls"])
        self.assertEqual(after["pending_agent_calls"], before["pending_agent_calls"])

        resumed = engine.resume(run_id)
        self.assertEqual(resumed["status"], "blocked")
        self.assertEqual(resumed["terminal_event"], "run_cancelled")
        events = RunLedger(SITINA_HOME).timeline(run_id)
        self.assertEqual([event["event_type"] for event in events if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}], ["run_cancelled"])
        self.assertNotIn("summary", [event.get("agent_id") for event in events if event["event_type"] == "agent_completed"])
        replay = ReplayEngine(SITINA_HOME).replay(run_id)
        self.assertEqual(replay.status, "replay_ok", replay.model_dump())


if __name__ == "__main__":
    unittest.main()
