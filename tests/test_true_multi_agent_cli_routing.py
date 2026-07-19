from __future__ import annotations

import argparse
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sitina import cli
from sitina.orchestrator.true_multi_agent import (
    GoalAnalysis,
    TrueMultiAgentProductionRuntime,
    _require_defect_responses,
    _require_json_array_or_strings,
    _require_verification_checks,
    _checkpoint_restart_required,
    _integrated_closure_required,
    _provider_recovery_required,
    _single_rework_required,
)


class TrueMultiAgentCliRoutingTests(unittest.TestCase):
    def args(self, provider_mode: str = "auto") -> argparse.Namespace:
        return argparse.Namespace(
            goal=["ordinary", "shared", "evidence", "decision"],
            provider_mode=provider_mode,
            profile_override=[],
            goal_id=None,
            backlog_item_id=None,
        )

    @patch("sitina.cli.print_json")
    @patch("sitina.cli.TrueMultiAgentProductionRuntime")
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ExtensionManager.load_registry", return_value={"plugins": {}, "skills": {}})
    def test_default_auto_mode_routes_ordinary_production_goal_to_true_multi_agent_runtime(
        self,
        _extension_registry: Mock,
        _installed: Mock,
        runtime_type: Mock,
        print_json: Mock,
    ) -> None:
        runtime_type.return_value.execute.return_value = {
            "run_id": "tma-run-cli",
            "terminal_state": "SUCCEEDED",
        }
        exit_code = cli.cmd_run(self.args())
        self.assertEqual(exit_code, 0)
        runtime_type.assert_called_once_with(cli.SITINA_HOME)
        runtime_type.return_value.execute.assert_called_once_with(
            "ordinary shared evidence decision",
            label="cli-production-ordinary-goal",
        )
        print_json.assert_called_once_with({"run_id": "tma-run-cli", "terminal_state": "SUCCEEDED"})

    @patch("sitina.cli.print_json")
    @patch("sitina.cli.TrueMultiAgentProductionRuntime")
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ExtensionManager.load_registry", return_value={"plugins": {}, "skills": {}})
    def test_explicit_live_mode_uses_same_production_path_and_failed_terminal_is_nonzero(
        self,
        _extension_registry: Mock,
        _installed: Mock,
        runtime_type: Mock,
        _print_json: Mock,
    ) -> None:
        runtime_type.return_value.execute.return_value = {
            "run_id": "tma-run-cli-failed",
            "terminal_state": "FAILED",
        }
        self.assertEqual(cli.cmd_run(self.args("live")), 2)
        runtime_type.return_value.execute.assert_called_once()

    @patch("sitina.cli.print_json")
    @patch("sitina.cli.TrueMultiAgentProductionRuntime")
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch("sitina.cli.ExtensionManager.load_registry", return_value={"plugins": {}, "skills": {}})
    def test_checkpoint_plan_yields_to_external_cli_process_supervisor(
        self,
        _extension_registry: Mock,
        _installed: Mock,
        runtime_type: Mock,
        print_json: Mock,
    ) -> None:
        plan = {
            "status": "checkpoint_restart_required",
            "run_id": "tma-run-restart",
            "terminal_state": "RESTART_REQUIRED",
            "checkpoint_ids": [f"checkpoint-{index}" for index in range(8)],
        }
        runtime_type.return_value.execute.return_value = plan
        self.assertEqual(cli.cmd_run(self.args("live")), 75)
        print_json.assert_called_once_with(plan)

    def test_integrated_closure_is_selected_from_business_semantics_only(self) -> None:
        goal = (
            "Two authors conduct a multi-round negotiation and repair the review defects. They maintain a shared "
            "state record while a concurrent edit from the same base must preserve both conclusions. The selected "
            "owner becomes unavailable, so ownership failover reassigns the work. The new owner prepares an "
            "operational transfer; the first transfer package lacks mandatory checks, the receiver rejects it, and "
            "the corrected package addresses every omission. Provider recovery covers after-start loss and ack lost "
            "after remote success. A checkpoint restart resume must preserve the receiving engineer's work."
        )
        self.assertTrue(_integrated_closure_required(goal))
        self.assertFalse(
            _integrated_closure_required(
                "Please create BlackboardConflict and Handoff generation 2 events for a test."
            )
        )

    def test_interactive_multi_records_bounded_route_decision_before_provider_work(self) -> None:
        run_stream = Mock()
        TrueMultiAgentProductionRuntime._record_conversation_route(
            run_stream,
            {
                "interactive_chat": True,
                "conversation_session_id": "chat-session-test",
                "conversation_turn_index": 3,
                "conversation_route_decision": {
                    "requested_mode": "AUTO",
                    "resolved_mode": "MULTI",
                    "source": "local_router",
                    "reasons": ["多方案比较", "x" * 500] + [f"extra-{index}" for index in range(10)],
                    "policy_version": "router-test-v1",
                    "input_hash": "a" * 64,
                    "confidence": 0.8,
                    "threshold": 0.65,
                    "upgrade_reason": "多方案比较",
                    "decision_path": "AUTO_DIRECT_MULTI",
                    "initial_fast_decision": {
                        "schema": "SITINA_AUTO_INITIAL_FAST_DECISION_V1",
                        "evaluated": True,
                        "decision": "REJECTED_FOR_DIRECT_MULTI",
                        "multi_score": 0.8,
                        "threshold": 0.65,
                        "provider_evaluated": False,
                        "evidence_reasons": ["多方案比较"],
                    },
                },
            },
        )
        run_stream.append.assert_called_once()
        fact = run_stream.append.call_args.args[1][0]
        self.assertEqual(fact["schema"], "CONVERSATION_ROUTE_DECIDED_V1")
        self.assertEqual(fact["resolved_mode"], "MULTI")
        self.assertEqual(fact["confidence"], "0.8")
        self.assertEqual(fact["threshold"], "0.65")
        self.assertEqual(fact["upgrade_reason"], "多方案比较")
        self.assertEqual(fact["decision_path"], "AUTO_DIRECT_MULTI")
        self.assertEqual(fact["initial_fast_decision"]["decision"], "REJECTED_FOR_DIRECT_MULTI")
        self.assertLessEqual(len(fact["reasons"]), 8)
        self.assertTrue(all(len(reason) <= 160 for reason in fact["reasons"]))
        self.assertFalse(fact["external_mutation_allowed"])

    @patch("sitina.orchestrator.true_multi_agent.activate_runtime", side_effect=RuntimeError("stop-before-provider"))
    @patch("sitina.orchestrator.true_multi_agent.ConversationLifecycle")
    @patch("sitina.orchestrator.true_multi_agent.ProductionRuntimeContext.load")
    def test_interactive_multi_commits_session_lifecycle_before_runtime_activation(
        self,
        load_context: Mock,
        lifecycle_type: Mock,
        _activate: Mock,
    ) -> None:
        context = load_context.return_value
        context.open_writer.return_value = Mock()
        context.open_cas.return_value = Mock()
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.home = Path("/tmp/sitina-interactive-fixture")
        runtime.registry = Mock()
        runtime.policy = {}
        runtime.policy_hash = "f" * 64
        route = {
            "requested_mode": "MULTI",
            "resolved_mode": "MULTI",
            "source": "user_forced",
            "reasons": ["用户强制 MULTI"],
            "policy_version": "fixture-v1",
            "input_hash": "a" * 64,
            "confidence": "1",
            "threshold": "0.65",
            "upgrade_reason": None,
            "initial_fast_decision": None,
            "decision_path": "USER_FORCED_MULTI",
        }
        with self.assertRaisesRegex(RuntimeError, "stop-before-provider"):
            runtime.execute(
                "rendered goal",
                overrides={
                    "interactive_chat": True,
                    "conversation_user_message": "original user body",
                    "conversation_session_id": "chat-session-fixture",
                    "conversation_turn_index": 7,
                    "conversation_route_decision": route,
                },
            )
        lifecycle_type.return_value.start_turn.assert_called_once()
        arguments = lifecycle_type.return_value.start_turn.call_args.kwargs
        self.assertEqual(arguments["message"], "original user body")
        self.assertEqual(arguments["session_id"], "chat-session-fixture")
        self.assertEqual(arguments["turn_index"], 7)
        lifecycle_type.return_value.fail_turn.assert_called_once()
        context.open_writer.return_value.close.assert_called_once()

    def test_interactive_multi_uses_live_negotiation_and_handoff_protocols(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {"max_proposals_per_round": 3}
        discovered = GoalAnalysis(
            "complex", "high", ("proposal", "review"), ("analyze",), 3, "architecture",
            True, True, True, True, True, "provider-discovered plan",
        )
        constrained = runtime._interactive_chat_analysis(discovered)
        self.assertEqual(constrained.protocols, ("proposal", "review", "debate", "handoff"))
        self.assertEqual(constrained.proposal_count, 2)
        self.assertFalse(constrained.requires_handoff_reject)
        self.assertIn("Negotiation", constrained.rationale)
        self.assertIn("Handoff", constrained.rationale)

    @patch("sitina.cli.TrueMultiAgentProductionRuntime")
    @patch("sitina.cli._bplus_installed", return_value=True)
    def test_explicit_mock_mode_does_not_claim_live_multi_agent_evidence(
        self,
        _installed: Mock,
        runtime_type: Mock,
    ) -> None:
        with patch("sitina.cli.SitinaEngine") as engine_type, patch("sitina.cli.print_json"):
            engine_type.return_value.run.return_value = {"status": "ok", "provider_mode": "mock"}
            self.assertEqual(cli.cmd_run(self.args("mock")), 0)
            runtime_type.assert_not_called()

    def test_runtime_semantic_policy_adds_blackboard_for_shared_versioned_conflict_goal(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "debate", "handoff", "arbitration", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        analysis = GoalAnalysis(
            "standard", "medium", ("proposal", "review"), ("compare", "decide"), 2, None,
            False, False, False, False, False, "provider analysis omitted shared-state protocol",
        )
        run_stream = Mock()
        constrained = runtime._analysis_with_constraints(
            analysis,
            {},
            run_stream,
            "Two analysts make competing edits from the same initial shared decision record and preserve both.",
        )
        self.assertIn("blackboard", constrained.protocols)
        self.assertTrue(constrained.requires_conflict)
        emitted = run_stream.append.call_args.args[1][0]
        self.assertEqual(emitted["reason"], "RUNTIME_GOAL_SEMANTIC_POLICY")
        self.assertIn("SHARED_VERSIONED_STATE_REQUIRES_BLACKBOARD", emitted["semantic_reasons"])

    def test_runtime_semantic_policy_respects_natural_negative_protocol_constraints(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "debate", "handoff", "arbitration", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        analysis = GoalAnalysis(
            "standard", "low", ("proposal", "review", "debate", "rework", "handoff", "checkpoint", "lease"),
            ("compare", "decide"), 1, None, True, False, True, True, False, "over-selected protocols",
        )
        run_stream = Mock()
        constrained = runtime._analysis_with_constraints(
            analysis,
            {},
            run_stream,
            (
                "Create a shared decision record. Each analyst acts once; no iterative discussion, no work transfer, "
                "no runtime interruption, and no ownership failover is needed."
            ),
        )
        self.assertEqual(constrained.protocols, ("proposal", "review", "blackboard"))
        self.assertFalse(constrained.requires_rework)
        self.assertFalse(constrained.requires_handoff_reject)
        self.assertFalse(constrained.requires_reassignment)
        emitted = run_stream.append.call_args.args[1][0]
        self.assertIn("EXPLICIT_GOAL_NEGATIVE_PROTOCOL_CONSTRAINTS", emitted["semantic_reasons"])

    def test_negative_lease_constraint_clears_flag_derived_from_the_same_phrase(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "debate", "handoff", "arbitration", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        analysis = GoalAnalysis(
            "standard", "low", ("proposal", "review"), ("compare", "decide"), 2, None,
            False, False, False, False, False, "provider supplied a minimal analysis",
        )
        constrained = runtime._analysis_with_constraints(
            analysis,
            {},
            Mock(),
            "Compare two read-only proposals. No ownership failover is needed.",
        )
        self.assertNotIn("lease", constrained.protocols)
        self.assertFalse(constrained.requires_reassignment)

    def test_runtime_semantic_policy_requires_lease_and_reassignment_for_owner_failover(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "debate", "handoff", "arbitration", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        analysis = GoalAnalysis(
            "standard", "low", ("proposal", "review", "blackboard"), ("claim", "complete"), 1, None,
            False, True, False, False, False, "provider analysis over-selected shared state and omitted ownership protocol",
        )
        run_stream = Mock()
        constrained = runtime._analysis_with_constraints(
            analysis,
            {},
            run_stream,
            (
                "Have two agents compete to claim the same task; after lease expiry when the owner becomes unavailable, "
                "reassign the same task and reject a stale owner result. No shared record is needed."
            ),
        )
        self.assertIn("lease", constrained.protocols)
        self.assertNotIn("blackboard", constrained.protocols)
        self.assertTrue(constrained.requires_reassignment)
        self.assertFalse(constrained.requires_conflict)
        self.assertEqual(constrained.proposal_count, 2)
        emitted = run_stream.append.call_args.args[1][0]
        self.assertIn("TASK_OWNERSHIP_FAILOVER_REQUIRES_LEASE_PROTOCOL", emitted["semantic_reasons"])
        self.assertIn("TASK_OWNERSHIP_FAILOVER_REQUIRES_REASSIGNMENT", emitted["semantic_reasons"])
        self.assertIn("LEASE_FAILOVER_REQUIRES_REDUNDANT_INITIAL_PROPOSALS", emitted["semantic_reasons"])

    def test_runtime_semantic_policy_requires_handoff_rejection_for_incomplete_operational_transfer(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "debate", "handoff", "arbitration", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        analysis = GoalAnalysis(
            "standard", "medium", ("proposal", "review"), ("select", "transfer", "verify"), 1, None,
            False, False, False, False, False, "provider omitted formal transfer protocol",
        )
        run_stream = Mock()
        constrained = runtime._analysis_with_constraints(
            analysis,
            {},
            run_stream,
            (
                "Prepare an operational transfer of the selected plan to a receiving engineer. "
                "The first package intentionally lacks exact acceptance checks; the receiver should reject it, "
                "then the sender must correct every omission before independent verification."
            ),
        )
        self.assertIn("handoff", constrained.protocols)
        self.assertTrue(constrained.requires_handoff_reject)
        emitted = run_stream.append.call_args.args[1][0]
        self.assertIn("QUALIFIED_OPERATIONAL_TRANSFER_REQUIRES_HANDOFF_PROTOCOL", emitted["semantic_reasons"])
        self.assertIn("INCOMPLETE_INITIAL_TRANSFER_REQUIRES_NEW_HANDOFF_GENERATION", emitted["semantic_reasons"])

    def test_runtime_semantic_policy_requires_multi_round_negotiation_and_review_rework(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "debate", "handoff", "arbitration", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        analysis = GoalAnalysis(
            "standard", "medium", ("proposal", "review"), ("propose", "evaluate"), 1, None,
            False, False, False, False, False, "provider omitted successor protocols",
        )
        run_stream = Mock()
        constrained = runtime._analysis_with_constraints(
            analysis,
            {},
            run_stream,
            (
                "Conduct a multi-round negotiation in which two authors respond to peer objections with a second "
                "round proposal. The reviewer must request changes on one proposal, and its author must repair every "
                "review defect before an independent second review."
            ),
        )
        self.assertIn("debate", constrained.protocols)
        self.assertIn("rework", constrained.protocols)
        self.assertEqual(constrained.proposal_count, 2)
        self.assertTrue(constrained.requires_rework)
        emitted = run_stream.append.call_args.args[1][0]
        self.assertIn("MULTI_ROUND_NEGOTIATION_REQUIRES_DEBATE_PROTOCOL", emitted["semantic_reasons"])
        self.assertIn("REVIEW_DRIVEN_REVISION_REQUIRES_REWORK_PROTOCOL", emitted["semantic_reasons"])

    def test_single_rework_bound_is_derived_from_ordinary_goal_language(self) -> None:
        self.assertTrue(_single_rework_required("The reviewer must request changes on one proposal."))
        self.assertTrue(_single_rework_required("Request changes on exactly one initial proposal."))
        self.assertFalse(_single_rework_required("Review every proposal and allow rework where needed."))

    def test_provider_recovery_is_derived_from_ordinary_goal_language(self) -> None:
        self.assertTrue(_provider_recovery_required("Exercise provider recovery after an explicit remote failure."))
        self.assertTrue(_provider_recovery_required("Handle ACK lost after remote success without a duplicate send."))
        self.assertFalse(_provider_recovery_required("Compare two read-only proposals."))

    def test_checkpoint_restart_is_derived_from_ordinary_goal_language(self) -> None:
        self.assertTrue(_checkpoint_restart_required("Verify the checkpoint restart resume frontier matrix."))
        self.assertTrue(_checkpoint_restart_required("Rebuild process state through checkpoint recovery."))
        self.assertFalse(_checkpoint_restart_required("Compare two read-only proposals."))

    def test_goal_analysis_normalizes_policy_owned_protocol_aliases_but_rejects_unknowns(self) -> None:
        policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "handoff", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        value = {
            "complexity": "standard", "risk_level": "medium",
            "protocols": ["reassignment", "fencing"], "task_graph": ["claim", "reassign"],
            "proposal_count": 1, "domain_capability": None, "requires_rework": False,
            "requires_conflict": False, "requires_handoff_reject": False,
            "requires_reassignment": True, "requires_provider_unknown": False, "rationale": "lease failover",
        }
        parsed = GoalAnalysis.parse(value, policy)
        self.assertEqual(parsed.protocols, ("proposal", "lease"))
        value["protocols"] = ["unbounded-unknown-protocol"]
        with self.assertRaises(Exception):
            GoalAnalysis.parse(value, policy)

    def test_goal_analysis_accepts_no_optional_protocols_and_adds_mandatory_proposal(self) -> None:
        policy = {
            "allowed_protocols": ["proposal", "review", "blackboard", "handoff", "lease", "checkpoint", "rework"],
            "max_proposals_per_round": 3,
        }
        value = {
            "complexity": "simple", "risk_level": "low",
            "protocols": [], "task_graph": ["draft_checklist"],
            "proposal_count": 1, "domain_capability": None, "requires_rework": False,
            "requires_conflict": False, "requires_handoff_reject": False,
            "requires_reassignment": False, "requires_provider_unknown": False,
            "rationale": "No optional collaboration protocol is required.",
        }
        parsed = GoalAnalysis.parse(value, policy)
        self.assertEqual(parsed.protocols, ("proposal",))

    def test_handoff_verification_checks_accept_bounded_list_or_mapping(self) -> None:
        self.assertEqual(
            _require_verification_checks({"checks": ["schema passed", "source hash passed"]}),
            ["schema passed", "source hash passed"],
        )
        self.assertEqual(
            _require_verification_checks(
                {"checks": {"contract_compliance": "passed", "delivery_integrity": True}}
            ),
            ["contract_compliance: passed", "delivery_integrity: passed"],
        )
        with self.assertRaises(Exception):
            _require_verification_checks({"checks": {"contract_compliance": []}})

    def test_rework_defect_responses_cover_each_frozen_defect_exactly_once(self) -> None:
        defects = ("missing rollback check", "unclear owner")
        normalized = _require_defect_responses(
            {
                "defect_responses": [
                    {"defect": "missing rollback check", "response": "added a rollback assertion"},
                    "named the incident commander as owner",
                ]
            },
            defects,
        )
        self.assertEqual([item["defect"] for item in normalized], list(defects))
        with self.assertRaises(Exception):
            _require_defect_responses(
                {"defect_responses": [{"defect": "unclear owner", "response": "named owner"}]},
                defects,
            )

    def test_json_array_string_admission_is_equivalent_but_arbitrary_text_is_rejected(self) -> None:
        self.assertEqual(
            _require_json_array_or_strings({"acceptance_checks": ["one", "two"]}, "acceptance_checks"),
            ["one", "two"],
        )
        self.assertEqual(
            _require_json_array_or_strings(
                {"acceptance_checks": '["one", "two"]'}, "acceptance_checks"
            ),
            ["one", "two"],
        )
        with self.assertRaises(Exception):
            _require_json_array_or_strings({"acceptance_checks": "one, two"}, "acceptance_checks")


if __name__ == "__main__":
    unittest.main()
