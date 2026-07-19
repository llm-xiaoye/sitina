from __future__ import annotations

import importlib
import json
import os
import socket
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from sitina.conversation.context import ContextPolicy, ConversationContext
from sitina.conversation.router import ConversationRouter
from sitina.evals.system_evaluation import (
    ExecutableSuiteCase,
    ExecutableSuiteContract,
    RoutingEvaluationSuite,
    RunEvaluator,
    sign_evaluation_event,
)
from sitina.orchestrator.orchestration_management import CollaborationScenarioHarness, TopologyStrategy
from sitina.orchestrator.performance_management import CacheBinding, SecureProviderCache


def _resolve_test(test_id: str) -> None:
    parts = test_id.split(".")
    if len(parts) < 4:
        raise AssertionError(f"test ID is not method-specific: {test_id}")
    module = importlib.import_module(".".join(parts[:-2]))
    case = getattr(module, parts[-2])
    method = getattr(case, parts[-1])
    if not callable(method) or not parts[-1].startswith("test_"):
        raise AssertionError(f"test ID is not executable: {test_id}")


def _event(event_id: str, event_type: str, *, status: str = "ok", **payload):
    return sign_evaluation_event({
        "event_id": event_id,
        "event_type": event_type,
        "run_id": "run-eval",
        "status": status,
        "timestamp": f"2026-07-19T00:00:{len(event_id):02d}Z",
        "payload_json": {"run_id": "run-eval", "status": status, **payload},
    })


class SystemEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"])

    def test_e01_r08_fixtures_report_accuracy_dangerous_downgrade_upgrade_language_domain_and_policy_version(self) -> None:
        context_policy = ContextPolicy.load(self.home)
        router = ConversationRouter(
            config=json.loads((self.home / "config/conversation_router.json").read_text(encoding="utf-8")),
            context_policy=context_policy,
            routing_policy=json.loads((self.home / "config/routing_policy.json").read_text(encoding="utf-8")),
        )
        snapshot = ConversationContext(policy=context_policy).snapshot([])
        document = json.loads((Path(__file__).parents[1] / "fixtures/routing_regression_v1.json").read_text(encoding="utf-8"))
        report = RoutingEvaluationSuite().evaluate(router, document, snapshot=snapshot)
        self.assertEqual((report.overall.total, report.overall.accuracy_ppm), (10, 1_000_000))
        self.assertEqual((report.overall.false_upgrade_count, report.overall.false_downgrade_count, report.overall.dangerous_false_downgrade_count), (0, 0, 0))
        self.assertEqual(set(report.language_slices), {"en", "mixed", "zh-Hans", "zh-Hant"})
        self.assertEqual(set(report.domain_slices), {"architecture", "general", "migration", "security", "software"})
        self.assertEqual(report.policy_version, router.policy_version)
        self.assertTrue(all(item.accuracy_ppm == 1_000_000 for item in report.language_slices.values()))

    def test_e02_all_topologies_and_success_rework_reject_block_ask_user_consensus_cancel_restart_partial_outcomes_finalize_once(self) -> None:
        topology = TopologyStrategy()
        for name in ("pipeline", "supervisor", "network", "hierarchy"):
            result = topology.execute(name, ("controller", "planner", "worker", "reviewer"))
            self.assertEqual((result["terminal"], result["permission_boundary"]), ("completed", "shared-global-policy"))
            self.assertEqual(set(result["order"]), {"controller", "planner", "worker", "reviewer"})
        scenarios = (
            "success", "rework", "rejection", "resource-exhaustion", "ask-user", "no-consensus",
            "cancellation", "restart", "partial-success",
        )
        results = tuple(CollaborationScenarioHarness().run(name) for name in scenarios)
        self.assertEqual(tuple(item.scenario for item in results), scenarios)
        self.assertTrue(all(item.terminal in {"completed", "blocked", "cancelled"} for item in results))
        self.assertTrue(all(item.reason_code and item.external_calls_after_terminal == 0 for item in results))
        self.assertTrue(all(item.physical_state_commits == 1 for item in results))

    def test_e03_barrier_concurrency_suite_covers_blackboard_budget_lease_scheduler_cache_fill_and_terminal_without_sleep(self) -> None:
        self_test = "tests.optimization.test_system_evaluation.SystemEvaluationTests.test_e03_barrier_concurrency_suite_covers_blackboard_budget_lease_scheduler_cache_fill_and_terminal_without_sleep"
        contract = ExecutableSuiteContract(
            suite="concurrency",
            required_components=("blackboard", "budget", "lease", "scheduler", "cache-fill", "terminal"),
            cases=(
                ExecutableSuiteCase(component="blackboard", test_id="tests.optimization.test_blackboard_state_management.BlackboardStateManagementTests.test_b10_seeded_interleaving_crash_recovery_and_high_concurrency_are_repeatable", proves="Barrier and seeded interleavings allow one MVCC winner and deterministic recovery."),
                ExecutableSuiteCase(component="budget", test_id="tests.optimization.test_performance_cost_management.PerformanceCostManagementTests.test_pc01_hierarchical_budget_reservation_settlement_refund_hard_cap_concurrency_and_missing_usage_unsettled", proves="Atomic parallel reservations cannot oversell an ancestor ceiling."),
                ExecutableSuiteCase(component="lease", test_id="tests.test_resource_leases.ResourceLeaseTests.test_release_revoke_and_compensation_inputs_are_stable", proves="Lease release and revocation return stable resources."),
                ExecutableSuiteCase(component="scheduler", test_id="tests.optimization.test_orchestration_management.OrchestrationManagementTests.test_o12_priority_deadline_stable_tie_break_and_aging_prevent_low_priority_starvation", proves="Aging and stable ordering preserve fairness."),
                ExecutableSuiteCase(component="cache-fill", test_id=self_test, proves="A barrier race performs one cache fill and shares the encrypted result."),
                ExecutableSuiteCase(component="terminal", test_id="tests.test_terminal_coordinator.TerminalCoordinatorTests.test_duplicate_terminal_command_returns_original_and_conflict_fails", proves="Terminal competition is idempotent and conflicting outcomes fail closed."),
            ),
        )
        for case in contract.cases:
            _resolve_test(case.test_id)
        for worker_count in (2, 4, 8):
            cache = SecureProviderCache(b"c" * 32)
            binding = CacheBinding.from_request(tenant_id="tenant-a", model="model-a", prompt="prompt", tools=[], policy={"v": 1}, permissions=["read"])
            barrier = threading.Barrier(worker_count)
            producer_calls = 0
            producer_lock = threading.Lock()

            def producer():
                nonlocal producer_calls
                with producer_lock:
                    producer_calls += 1
                return {"answer": 42}

            def fill(_index: int):
                barrier.wait()
                return cache.get_or_compute(binding, producer, deterministic=True, side_effect_free=True, now_epoch=0)

            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                results = tuple(pool.map(fill, range(worker_count)))
            self.assertEqual(producer_calls, 1)
            self.assertEqual(sum(item.new_physical_call_count for item in results), 1)
            self.assertEqual(sum(item.cache_hit_count for item in results), worker_count - 1)

    def test_e04_chaos_suite_binds_provider_tool_journal_cas_projection_worker_and_disk_faults_to_recovery_fail_closed_tests(self) -> None:
        contract = ExecutableSuiteContract(
            suite="chaos",
            required_components=("provider", "tool", "journal", "cas", "projection", "worker", "disk"),
            cases=(
                ExecutableSuiteCase(component="provider", test_id="tests.test_runtime_reliability.RuntimeReliabilityTests.test_provider_total_timeout_interrupts_blocking_response_read", proves="Provider timeout terminates the physical worker and becomes a typed failure."),
                ExecutableSuiteCase(component="tool", test_id="tests.optimization.test_security_management.SecurityManagementTests.test_s02_tool_timeouts_propagate_cancellation_and_cleanup_without_live_worker", proves="Tool timeout fails closed, propagates cancellation, and leaves no live worker."),
                ExecutableSuiteCase(component="journal", test_id="tests.test_journal_crash_matrix.JournalCrashMatrixTests.test_complete_unacknowledged_frame_is_adopted_and_lost_ack_is_idempotent", proves="Crash and duplicate replay recover a committed frame exactly once."),
                ExecutableSuiteCase(component="cas", test_id="tests.test_atomic_storage_protocols.AtomicStorageProtocolTests.test_cas_is_durable_before_journal_and_resume_is_idempotent", proves="CAS failure cannot publish a Journal reference before durable content."),
                ExecutableSuiteCase(component="projection", test_id="tests.test_projection_kernel.ProjectionKernelTests.test_gap_fails_and_catalog_stores_metadata_not_payload", proves="Out-of-order projection input fails closed and requires a gap-free rebuild."),
                ExecutableSuiteCase(component="worker", test_id="tests.test_runtime_reliability.RuntimeReliabilityTests.test_provider_worker_eof_is_fail_closed_with_exit_code", proves="Worker crash/EOF is typed and cannot become success."),
                ExecutableSuiteCase(component="disk", test_id="tests.test_journal_crash_matrix.JournalCrashMatrixTests.test_enospc_and_eio_poison_writer_until_fresh_recovery", proves="Disk-full and I/O errors poison the writer until explicit recovery."),
            ),
        )
        for case in contract.cases:
            _resolve_test(case.test_id)
        self.assertTrue(all(any(word in case.proves.lower() for word in ("fail", "recover", "durable", "idempotent", "typed")) for case in contract.cases))

    def test_x16_run_evaluator_is_read_only_replayable_six_dimensional_and_caps_tampered_or_missing_evidence(self) -> None:
        events = (
            _event("event-tool", "tool_invocation_completed"),
            _event("event-state", "task_graph_node_status"),
            _event("event-permission", "permission_decision", allowed=True),
            _event("event-budget", "token_budget_reserved", reservation_id="r1", reserved_tokens=50),
            _event("event-provider", "provider_http_attempt_failed", status="failed", token_usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}),
            _event("event-recovery", "retry_succeeded"),
            _event("event-review", "reviewer_decision", decision="accept"),
            _event("event-terminal", "run_completed"),
        )
        evaluator = RunEvaluator(self.home)
        with (
            patch("sitina.runners.provider.AnthropicCompatibleClient.complete_with_metadata") as provider,
            patch.object(socket, "create_connection") as network,
            patch("sitina.orchestrator.side_effects.SideEffectManager.execute") as effect,
            patch("sitina.orchestrator.ledger.RunLedger.record") as write,
        ):
            first = evaluator.evaluate("run-eval", events=events)
            repeated = evaluator.evaluate("run-eval", events=events)
        self.assertEqual((provider.call_count, network.call_count, effect.call_count, write.call_count), (0, 0, 0, 0))
        self.assertEqual(first, repeated)
        dimensions = (first.tool_correctness, first.state_correctness, first.permission_compliance, first.cost_efficiency, first.recovery_ability, first.final_quality)
        self.assertTrue(all(item.status == "pass" and item.score == 100 and item.reason_codes and item.evidence_refs and item.evaluator_version == RunEvaluator.VERSION for item in dimensions))
        tampered = list(events)
        tampered[0] = {**tampered[0], "payload_json": {"run_id": "run-eval", "status": "failed"}}
        damaged = evaluator.evaluate("run-eval", events=tampered)
        missing = evaluator.evaluate("run-eval", events=(_event("event-only", "run_completed"),))
        damaged_dimensions = (damaged.tool_correctness, damaged.state_correctness, damaged.permission_compliance, damaged.cost_efficiency, damaged.recovery_ability, damaged.final_quality)
        missing_dimensions = (missing.tool_correctness, missing.state_correctness, missing.permission_compliance, missing.cost_efficiency, missing.recovery_ability, missing.final_quality)
        self.assertTrue(all(item.score <= 20 and "EVIDENCE_INTEGRITY_INVALID" in item.reason_codes for item in damaged_dimensions))
        self.assertTrue(all(item.score <= 20 for item in missing_dimensions))


if __name__ == "__main__":
    unittest.main()
