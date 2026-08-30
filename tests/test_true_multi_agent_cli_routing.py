from __future__ import annotations

import argparse
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sitina import cli
from sitina.orchestrator.true_multi_agent import (
    AgentOutputContractRejected,
    DynamicCollaborationError,
    GoalAnalysis,
    RunEvidence,
    TrueMultiAgentProductionRuntime,
    TrueMultiAgentRuntimeError,
    _handoff_repair_progress_signature,
    _proposed_handoff_semantic_snapshot,
    _require_exact_handoff_binding,
    _require_exact_parent_output_hash,
    _require_defect_responses,
    _require_json_array_or_strings,
    _require_verification_checks,
    _structured_handoff_corrections,
    _verified_handoff_semantic_delta,
    _validate_handoff_delivery,
    _checkpoint_restart_required,
    _integrated_closure_required,
    _provider_recovery_required,
    _single_rework_required,
    _execution_isolation_required,
)
from sitina.orchestrator.true_multi_agent_runtime import AgentCallResult, AgentIdentity, sha256_bytes


class TrueMultiAgentCliRoutingTests(unittest.TestCase):
    def args(self, provider_mode: str = "auto") -> argparse.Namespace:
        return argparse.Namespace(
            goal=["ordinary", "shared", "evidence", "decision"],
            provider_mode=provider_mode,
            profile_override=[],
            goal_id=None,
            backlog_item_id=None,
        )

    def test_negated_external_action_does_not_select_managed_worktree(self) -> None:
        controls = {}
        self.assertFalse(
            _execution_isolation_required(
                "Implement the requested change. Do not commit or push.", controls
            )
        )
        self.assertFalse(
            _execution_isolation_required("修改代码，不要提交或推送。", controls)
        )
        self.assertTrue(_execution_isolation_required("git push the reviewed release", controls))
        self.assertTrue(_execution_isolation_required("deploy the service", controls))

    def test_negation_is_clause_scoped_for_external_actions(self) -> None:
        self.assertTrue(_execution_isolation_required("Do not push, but deploy the service.", {}))
        self.assertTrue(_execution_isolation_required("Never send data, but deploy the service.", {}))
        self.assertTrue(_execution_isolation_required("deploy the service, but do not push.", {}))
        self.assertTrue(_execution_isolation_required("不要推送，但部署服务。", {}))

    def test_parent_binding_validator_requires_exact_hash_without_normalization(self) -> None:
        expected = "sha256:" + "a" * 64
        with self.assertRaises(AgentOutputContractRejected) as missing:
            _require_exact_parent_output_hash({}, expected)
        self.assertEqual(missing.exception.reason_code, "PARENT_OUTPUT_HASH_MISSING")
        self.assertEqual(missing.exception.expected_binding_hash, expected)
        with self.assertRaises(AgentOutputContractRejected) as wrong:
            _require_exact_parent_output_hash({"parent_output_hash": expected.upper()}, expected)
        self.assertEqual(wrong.exception.reason_code, "PARENT_OUTPUT_HASH_MISMATCH")
        _require_exact_parent_output_hash({"parent_output_hash": expected}, expected)

    def test_handoff_assessment_binds_exact_contract_generation(self) -> None:
        expected = "e" * 64
        with self.assertRaises(AgentOutputContractRejected) as stale:
            _require_exact_handoff_binding(
                {"contract_hash": "f" * 64, "generation": 2},
                expected_contract_hash=expected,
                expected_generation=2,
            )
        self.assertEqual(stale.exception.reason_code, "HANDOFF_CONTRACT_HASH_MISMATCH")
        with self.assertRaises(AgentOutputContractRejected) as wrong_generation:
            _require_exact_handoff_binding(
                {"contract_hash": expected, "generation": 3},
                expected_contract_hash=expected,
                expected_generation=2,
            )
        self.assertEqual(wrong_generation.exception.reason_code, "HANDOFF_GENERATION_MISMATCH")
        _require_exact_handoff_binding(
            {"contract_hash": expected, "generation": 2},
            expected_contract_hash=expected,
            expected_generation=2,
        )

    def test_handoff_repair_progress_signature_detects_repeated_zero_delta(self) -> None:
        first = _handoff_repair_progress_signature(
            ("MISSING_CHECK|acceptance_criteria",),
            selected_proposal_hash="a" * 71,
        )
        repeated = _handoff_repair_progress_signature(
            ("MISSING_CHECK|acceptance_criteria",),
            selected_proposal_hash="a" * 71,
        )
        changed = _handoff_repair_progress_signature(
            ("MISSING_SCOPE|scope",),
            selected_proposal_hash="a" * 71,
        )
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, changed)

    def test_handoff_repair_requires_real_field_delta_not_reason_labels(self) -> None:
        before = {
            "scope": ["read selected immutable proposal"],
            "acceptance_criteria": ["source hash is bound"],
            "output_schema": {"required": ["deliverable"]},
            "proposal_projection": {"semantic_resolution_fields": []},
        }
        reason = "MISSING_CHECK|acceptance_criteria|" + "a" * 64
        after = _proposed_handoff_semantic_snapshot(
            generation=2,
            selected_projection={"source_output_hash": "b" * 64, "semantic_resolution_fields": []},
            resolution_map={reason: "add exact acceptance check"},
        )
        delta = _verified_handoff_semantic_delta(before, after, (reason,))
        self.assertIn("acceptance_criteria", delta["changed_paths"])
        semantic_hash, progress = _handoff_repair_progress_signature(
            (reason,), selected_proposal_hash="b" * 64, semantic_delta=delta
        )
        self.assertEqual(len(semantic_hash), 64)
        self.assertEqual(len(progress), 64)
        with self.assertRaises(DynamicCollaborationError):
            _verified_handoff_semantic_delta(before, before, (reason,))

    def test_handoff_repair_requires_the_concrete_corrected_value(self) -> None:
        reason = "MISSING_CHECK|acceptance_criteria.must_run_pytest|" + "a" * 64
        corrections = _structured_handoff_corrections((reason,))
        self.assertEqual(corrections[0]["operation"], "ensure_acceptance_criterion")
        self.assertIn("pytest -q", corrections[0]["value"])
        before = {
            "scope": ["read selected immutable proposal"],
            "acceptance_criteria": ["source hash is bound"],
            "output_schema": {"required": ["deliverable"]},
            "proposal_projection": {"semantic_resolution_fields": []},
        }
        unrelated = dict(before)
        unrelated["output_schema"] = {"required": ["deliverable", "unrelated"]}
        with self.assertRaises(DynamicCollaborationError):
            _verified_handoff_semantic_delta(before, unrelated, (reason,), corrections=corrections)
        after = _proposed_handoff_semantic_snapshot(
            generation=2,
            selected_projection={"source_output_hash": "b" * 64},
            resolution_map={reason: "provider text is intentionally ignored"},
        )
        delta = _verified_handoff_semantic_delta(before, after, (reason,), corrections=corrections)
        self.assertIn("acceptance_criteria", delta["changed_paths"])
        self.assertEqual(delta["verified_corrections"][0]["field_path"], "acceptance_criteria.must_run_pytest")

    def test_handoff_delivery_schema_rejects_missing_or_stale_binding_before_acceptance(self) -> None:
        expected = {
            "expected_contract_hash": "a" * 64,
            "expected_generation": 2,
            "expected_projection_hash": "b" * 64,
            "expected_source_output_hash": "c" * 64,
        }
        base = {
            "deliverable": "ok", "source_output_hash": "c" * 64,
            "acceptance_checks": ["verified"], "contract_hash": "a" * 64,
            "generation": 2, "selected_proposal_projection_hash": "b" * 64,
        }
        _validate_handoff_delivery(base, **expected)
        for key, value in (
            ("contract_hash", "d" * 64),
            ("generation", 1),
            ("selected_proposal_projection_hash", "e" * 64),
        ):
            with self.subTest(key=key):
                invalid = dict(base)
                invalid[key] = value
                with self.assertRaises(AgentOutputContractRejected):
                    _validate_handoff_delivery(invalid, **expected)
        invalid = dict(base)
        invalid.pop("contract_hash")
        with self.assertRaises(AgentOutputContractRejected):
            _validate_handoff_delivery(invalid, **expected)

    def test_handoff_runtime_binds_published_generation_projection_to_prompt_and_successor(self) -> None:
        """Exercise assessment -> successor -> delivery using the real _handoff state machine."""

        import sitina.orchestrator.true_multi_agent as tma

        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.policy_hash = "d" * 64
        runtime.policy = {"max_total_tokens_per_run": 4000}
        sender = AgentIdentity("agent-source", "author", ("proposal",), "deepseek", 1, ("low",))
        receiver = AgentIdentity("agent-receiver", "receiver", ("handoff-receive",), "deepseek", 1, ("low",))
        verifier = AgentIdentity("agent-verifier", "reviewer", ("verification", "review"), "deepseek", 1, ("low",))
        winner_value = {
            "agent_id": sender.agent_id, "kind": "proposal", "summary": "selected proposal",
            "approach": "bounded approach", "acceptance_checks": ["check result"],
        }
        winner = AgentCallResult(
            "call-winner", "run-handoff-runtime", sender.agent_id, sender.role,
            "proposal-selection", "attempt-winner", "effect-winner", "effect-attempt-winner",
            "provider-winner", "cas:" + "a" * 64, "a" * 64, "cas:" + "b" * 64,
            type("ObjectRef", (), {})(), "b" * 64, winner_value,
            {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}, 0,
            "2026-07-20T00:00:00Z", "2026-07-20T00:00:01Z", "SUCCEEDED", "CONFIRMED_REMOTE_OBSERVATION",
        )
        evidence = RunEvidence("run-handoff-runtime", "handoff runtime fixture", "e" * 64, runtime.policy_hash)
        published: list[dict[str, object]] = []

        class FakeExecutor:
            def _publish(self, value, *, purpose):
                published.append(dict(value))
                object_id = sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
                return type("Receipt", (), {"object_ref": type("Ref", (), {
                    "reference_id": "cas:" + object_id, "object_id": object_id,
                })()})()

        class FakeStream:
            def __init__(self, *args, **kwargs):
                self.counter = 0

            def append(self, *args, **kwargs):
                self.counter += 1
                return type("Receipt", (), {})(), ({"event_id": f"event-{self.counter}"},)

        calls: list[dict[str, object]] = []
        assessment_counts: dict[str, int] = {}

        def fake_call(_executor, _evidence, agent, **kwargs):
            task_id = kwargs["task_id"]
            context = kwargs["context"]
            calls.append({"task_id": task_id, "prompt": kwargs["prompt"], "context": dict(context)})
            if task_id.startswith("handoff-contract-assessment"):
                count = assessment_counts.get(task_id, 0)
                assessment_counts[task_id] = count + 1
                value = {
                    "agent_id": agent.agent_id, "kind": "review",
                    "accept": task_id.endswith("-2"), "reason": "assessment",
                    "missing_information": [] if task_id.endswith("-2") else [
                        "MISSING_CHECK|acceptance_criteria|add exact check"
                    ],
                    "contract_hash": context["contract_hash"] if count else "f" * 64,
                    "generation": context["generation"],
                    "selected_proposal_projection_hash": context["selected_proposal_projection_hash"],
                }
            elif task_id.startswith("handoff-execution"):
                value = {
                    "agent_id": agent.agent_id, "kind": "proposal", "deliverable": "delivered",
                    "source_output_hash": winner.output_hash, "acceptance_checks": ["check result"],
                    "contract_hash": context["contract_hash"], "generation": context["handoff_generation"],
                    "selected_proposal_projection_hash": context["selected_proposal_projection_hash"],
                }
            else:
                value = {
                    "agent_id": agent.agent_id, "kind": "review", "accepted": True,
                    "reason": "verified", "checks": ["delivery is bound"],
                }
            try:
                kwargs["validate"](value)
            except Exception as error:
                wrapped = TrueMultiAgentRuntimeError("fixture contract rejection")
                wrapped.__cause__ = error
                raise wrapped
            output_hash = sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            return AgentCallResult(
                "call-" + str(len(calls)), evidence.run_id, agent.agent_id, agent.role, task_id,
                "attempt-" + str(len(calls)), "effect-" + str(len(calls)), "effect-attempt-" + str(len(calls)),
                "provider-" + str(len(calls)), "cas:" + "1" * 64, "1" * 64, "cas:" + output_hash,
                type("ObjectRef", (), {})(), output_hash, value,
                {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}, 0,
                "2026-07-20T00:00:00Z", "2026-07-20T00:00:01Z", "SUCCEEDED", "CONFIRMED_REMOTE_OBSERVATION",
            )

        def fake_schedule(_journal, _run_stream, _evidence, **kwargs):
            selected = verifier if kwargs["task_id"].startswith("handoff-verification") else receiver
            return type("Decision", (), {"decision_id": "decision-" + kwargs["task_id"]})(), (selected,)

        runtime._schedule = fake_schedule
        runtime._call = fake_call
        with patch.object(tma, "CanonicalStream", FakeStream):
            result = runtime._handoff(
                object(), object(), FakeExecutor(), evidence,
                GoalAnalysis("standard", "low", ("handoff",), ("handoff",), 1, None, False, False, False, False, False, "fixture"),
                winner, sender, type("Decision", (), {"decision_id": "decision-source"})(), {},
            )
        self.assertIsNone(result)
        gen2_call = next(item for item in calls if item["task_id"] == "handoff-contract-assessment-2")
        gen2_projection = published[2]
        prompt_json = json.loads(str(gen2_call["prompt"])[str(gen2_call["prompt"]).index("{"):])
        projected = prompt_json["selected_proposal_projection"]
        self.assertEqual(projected, gen2_projection)
        self.assertEqual(gen2_call["context"]["selected_proposal_projection_hash"], sha256_bytes(json.dumps(gen2_projection, sort_keys=True, separators=(",", ":")).encode()))

    def test_semantic_parent_contract_repair_is_bounded_and_reuses_immutable_binding(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        first = TrueMultiAgentRuntimeError("wrapped parent mismatch")
        first.__cause__ = AgentOutputContractRejected(
            "parent mismatch",
            reason_code="PARENT_OUTPUT_HASH_MISMATCH",
            expected_binding_hash="sha256:" + "b" * 64,
        )
        accepted = object()
        runtime._call = Mock(side_effect=[first, accepted])
        context = {"parent_output_hash": "sha256:" + "b" * 64}
        result = runtime._call_with_bounded_contract_repair(
            Mock(),
            Mock(),
            Mock(),
            task_id="negotiation-round-2-1",
            kind="proposal",
            contract="exact parent",
            prompt="return revision",
            context=context,
            validate=Mock(),
            expected_parent_output_hash=context["parent_output_hash"],
        )
        self.assertIs(result, accepted)
        self.assertEqual(runtime._call.call_count, 2)
        self.assertIn(context["parent_output_hash"], runtime._call.call_args_list[1].kwargs["prompt"])

        repeated = TrueMultiAgentRuntimeError("wrapped parent mismatch")
        repeated.__cause__ = AgentOutputContractRejected(
            "parent mismatch",
            reason_code="PARENT_OUTPUT_HASH_MISMATCH",
            expected_binding_hash=context["parent_output_hash"],
        )
        runtime._call = Mock(side_effect=[repeated, repeated])
        with self.assertRaises(TrueMultiAgentRuntimeError):
            runtime._call_with_bounded_contract_repair(
                Mock(),
                Mock(),
                Mock(),
                task_id="negotiation-round-2-1",
                kind="proposal",
                contract="exact parent",
                prompt="return revision",
                context=context,
                validate=Mock(),
                expected_parent_output_hash=context["parent_output_hash"],
            )
        self.assertEqual(runtime._call.call_count, 2)

    def test_handoff_assessment_binding_repair_is_bounded(self) -> None:
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        first = TrueMultiAgentRuntimeError("wrapped stale handoff assessment")
        first.__cause__ = AgentOutputContractRejected(
            "stale handoff contract",
            reason_code="HANDOFF_CONTRACT_HASH_MISMATCH",
            expected_binding_hash="c" * 64,
        )
        accepted = object()
        runtime._call = Mock(side_effect=[first, accepted])
        result = runtime._call_with_bounded_handoff_binding_repair(
            Mock(),
            Mock(),
            Mock(),
            task_id="handoff-contract-assessment-2",
            kind="review",
            contract="assess exact contract",
            prompt="return the assessment",
            context={"contract_hash": "c" * 64, "generation": 2},
            validate=Mock(),
            expected_contract_hash="c" * 64,
            expected_generation=2,
        )
        self.assertIs(result, accepted)
        self.assertEqual(runtime._call.call_count, 2)
        retry_prompt = runtime._call.call_args_list[1].kwargs["prompt"]
        self.assertIn("contract_hash='" + "c" * 64 + "'", retry_prompt)
        self.assertIn("generation=2", retry_prompt)

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
    @patch("sitina.cli.AutonomousRuntime")
    @patch("sitina.cli.TrueMultiAgentProductionRuntime")
    @patch("sitina.cli._bplus_installed", return_value=True)
    @patch(
        "sitina.cli.ExtensionManager.load_registry",
        return_value={"plugins": {"enabled-plugin": {"disabled": False}}, "skills": {}},
    )
    def test_enabled_extensions_cannot_preempt_the_production_journal_runtime(
        self,
        _extension_registry: Mock,
        _installed: Mock,
        runtime_type: Mock,
        autonomous_type: Mock,
        print_json: Mock,
    ) -> None:
        runtime_type.return_value.execute.return_value = {
            "run_id": "tma-run-with-extensions",
            "terminal_state": "SUCCEEDED",
        }
        self.assertEqual(cli.cmd_run(self.args("live")), 0)
        autonomous_type.assert_not_called()
        runtime_type.return_value.execute.assert_called_once_with(
            "ordinary shared evidence decision",
            label="cli-production-ordinary-goal",
        )
        print_json.assert_called_once_with(
            {"run_id": "tma-run-with-extensions", "terminal_state": "SUCCEEDED"}
        )

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
    @patch("sitina.conversation.session_runtime.SessionRuntimeContext.open")
    def test_interactive_multi_commits_session_lifecycle_before_runtime_activation(
        self,
        session_context_open: Mock,
        lifecycle_type: Mock,
        _activate: Mock,
    ) -> None:
        context = session_context_open.return_value
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
                    "live_opt_in": True,
                    "conversation_route_decision": route,
                },
            )
        lifecycle_type.return_value.start_turn.assert_called_once()
        arguments = lifecycle_type.return_value.start_turn.call_args.kwargs
        self.assertEqual(arguments["message"], "original user body")
        self.assertEqual(arguments["session_id"], "chat-session-fixture")
        self.assertEqual(arguments["turn_index"], 7)
        lifecycle_type.return_value.fail_turn.assert_called_once()
        _activate.assert_called_once()
        activation_kwargs = _activate.call_args.kwargs
        self.assertEqual(activation_kwargs["session_id"], "chat-session-fixture")
        # This fixture stops before a trusted Code Mode controller exists.
        # A caller-provided interactive flag must not mint or smuggle a live
        # transport capability through activation; real live admission is
        # issued only by the attested controller after its authorization.
        self.assertIsNone(activation_kwargs["live_capability"])
        context.open_writer.return_value.close.assert_called_once()

    @patch("sitina.orchestrator.true_multi_agent.activate_runtime")
    @patch("sitina.conversation.session_runtime.SessionRuntimeContext.open")
    def test_live_opt_in_without_current_session_fails_before_activation(
        self,
        session_context_open: Mock,
        activate: Mock,
    ) -> None:
        context = session_context_open.return_value
        context.open_writer.return_value = Mock()
        context.open_cas.return_value = Mock()
        runtime = TrueMultiAgentProductionRuntime.__new__(TrueMultiAgentProductionRuntime)
        runtime.home = Path("/tmp/sitina-live-session-fixture")
        runtime.registry = Mock()
        runtime.policy = {}
        runtime.policy_hash = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "current conversation session"):
            runtime.execute(
                "live canary goal",
                overrides={
                    "live_opt_in": True,
                    "conversation_turn_index": 4,
                },
            )
        activate.assert_not_called()

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
        with patch("sitina.cli.JournalNativeLocalRuntime") as runtime_local, patch("sitina.cli.print_json"):
            runtime_local.return_value.execute.return_value = {"status": "terminal", "provider_mode": "mock"}
            self.assertEqual(cli.cmd_run(self.args("mock")), 0)
            runtime_type.assert_not_called()
            runtime_local.return_value.execute.assert_called_once()

    @patch("sitina.cli.cmd_run", return_value=0)
    def test_ask_is_an_alias_of_the_unified_run_router(self, cmd_run: Mock) -> None:
        arguments = argparse.Namespace(
            goal=["question"],
            provider_mode="mock",
            profile_override=[],
        )
        self.assertEqual(cli.cmd_ask(arguments), 0)
        cmd_run.assert_called_once_with(arguments)

    @patch("sitina.cli.print_json")
    @patch("sitina.cli._bplus_installed", return_value=False)
    @patch("sitina.cli.ExtensionManager.load_registry", return_value={"plugins": {}, "skills": {}})
    def test_unverified_home_never_falls_back_to_legacy_engine(
        self,
        _extension_registry: Mock,
        _installed: Mock,
        print_json: Mock,
    ) -> None:
        self.assertEqual(cli.cmd_run(self.args("mock")), 3)
        payload = print_json.call_args.args[0]
        self.assertEqual(payload["status"], "blocked")
        self.assertFalse(payload["legacy_fallback_attempted"])

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
