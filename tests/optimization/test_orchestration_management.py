from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from pydantic import ValidationError

from sitina.contracts.models import FailureContract, SourceDescriptor, TokenBudgetContract
from sitina.orchestrator.orchestration_management import (
    LEGAL_TRANSITIONS,
    TERMINAL_STATES,
    AttemptIdempotencyRegistry,
    CancellationScope,
    CapabilityWorker,
    CollaborationAccounting,
    CollaborationCost,
    CollaborationScenarioHarness,
    DeadlockDetector,
    FairPriorityScheduler,
    FailurePropagator,
    HierarchicalResourceLimiter,
    HotPathPlanner,
    MinimalTeamSelector,
    OrchestrationState,
    PlannerDAG,
    PlannerDependency,
    PlannerTask,
    PriorityCandidate,
    ReentrantTaskScheduler,
    ReusableAgentPool,
    TaskDeadlineController,
    TaskStateMachine,
    TopologyStrategy,
    TraceLineage,
)


CREATED = "2026-07-19T00:00:00Z"
ENDED = "2026-07-19T00:00:01Z"
SOURCE = SourceDescriptor(component="orchestration-test", actor_id="tester")


def _budget(task_id: str, maximum: int = 1000) -> TokenBudgetContract:
    return TokenBudgetContract(
        schema="SITINA_TOKEN_BUDGET_V1",
        schema_version="1.0",
        correlation_id="run-orchestration",
        causation_id=None,
        created_at=CREATED,
        source=SOURCE,
        trust="verified",
        budget_id=f"budget-{task_id}",
        scope_type="task",
        scope_id=task_id,
        maximum_tokens=maximum,
    )


def _task(
    task_id: str,
    *,
    capability: str = "analysis",
    risk: str = "low",
    resources: tuple[str, ...] = (),
    priority: int = 0,
) -> PlannerTask:
    return PlannerTask(
        task_id=task_id,
        input_refs=[f"input-{task_id}"],
        output_schema={"type": "object", "required": ["result"]},
        owner_capability=capability,
        risk_level=risk,
        budget=_budget(task_id),
        deadline="2026-07-20T00:00:00Z",
        completion_criteria=["result schema validates"],
        resource_claims=list(resources),
        priority=priority,
    )


def _dag(tasks, dependencies=()) -> PlannerDAG:
    return PlannerDAG(
        run_id="run-orchestration",
        task_type="code_change",
        tasks=list(tasks),
        dependencies=list(dependencies),
        policy_version="orchestration-policy-1",
    )


def _failure(task_id: str) -> FailureContract:
    return FailureContract(
        schema="SITINA_FAILURE_V1",
        schema_version="1.0",
        correlation_id="run-orchestration",
        causation_id="cause-root",
        created_at=CREATED,
        source=SOURCE,
        trust="verified",
        failure_id="failure-root",
        run_id="run-orchestration",
        task_id=task_id,
        failure_type="worker-error",
        severity="major",
        retryable=True,
        message="controlled worker failure",
        redacted=True,
    )


class OrchestrationManagementTests(unittest.TestCase):
    def test_o01_reentrant_scheduler_runs_multiple_queues_concurrently_and_recovers_after_controller_restart(self) -> None:
        graph = _dag([_task("a"), _task("b"), _task("c")]).to_task_graph(created_at=CREATED)
        scheduler = ReentrantTaskScheduler(graph, policy_version="orchestration-policy-1")
        scheduler.authorize("controller-policy-decision-1")
        barrier = threading.Barrier(3)

        def worker(node):
            barrier.wait(timeout=2)
            return {"result": node.task_id}

        self.assertEqual(set(scheduler.run_ready(worker, max_workers=3)), {"a", "b", "c"})
        starts = [scheduler.intervals[item][0] for item in ("a", "b", "c")]
        ends = [scheduler.intervals[item][1] for item in ("a", "b", "c")]
        self.assertLess(max(starts), min(ends))
        recovered = ReentrantTaskScheduler(graph, policy_version="orchestration-policy-1", checkpoint=scheduler.checkpoint())
        self.assertEqual(recovered.statuses, {"a": "completed", "b": "completed", "c": "completed"})
        self.assertEqual(recovered.controller_decisions, ["controller-policy-decision-1"])

    def test_o02_planner_schema_validates_complete_dag_and_rejects_missing_or_invalid_dependencies(self) -> None:
        dag = _dag([_task("plan"), _task("execute", capability="code")], [PlannerDependency(task_id="execute", depends_on="plan")])
        self.assertEqual(dag.model_dump(by_alias=True)["schema"], "SITINA_PLANNER_DAG_V1")
        graph = dag.to_task_graph(created_at=CREATED)
        execute = graph.node_map["execute"]
        self.assertEqual(execute.depends_on, ["plan"])
        self.assertEqual(execute.owner_capability, "code")
        self.assertEqual(execute.token_budget, 1000)
        self.assertTrue(execute.output_schema and execute.completion_criteria and execute.deadline)
        with self.assertRaises(ValidationError):
            _dag([_task("plan")], [PlannerDependency(task_id="missing", depends_on="plan")])
        with self.assertRaises(ValidationError):
            PlannerTask(
                task_id="bad",
                input_refs=[],
                output_schema={},
                owner_capability="code",
                risk_level="low",
                budget=_budget("bad"),
                deadline="2026-07-20T00:00:00Z",
                completion_criteria=[],
            )

    def test_o03_ready_non_conflicting_nodes_overlap_and_dependencies_or_write_conflicts_block(self) -> None:
        dag = _dag(
            [
                _task("a", resources=("write:repo",)),
                _task("b", resources=("write:repo",)),
                _task("c", resources=("read:docs",)),
                _task("d"),
            ],
            [PlannerDependency(task_id="d", depends_on="a")],
        )
        scheduler = ReentrantTaskScheduler(dag.to_task_graph(created_at=CREATED), policy_version="orchestration-policy-1")
        scheduler.authorize("controller-policy-decision-1")
        self.assertEqual(scheduler.ready(), ("a", "c"))
        barrier = threading.Barrier(2)

        def worker(node):
            barrier.wait(timeout=2)
            return node.task_id

        scheduler.run_ready(worker, max_workers=2)
        self.assertLess(max(scheduler.intervals[task][0] for task in ("a", "c")), min(scheduler.intervals[task][1] for task in ("a", "c")))
        self.assertEqual(set(scheduler.ready()), {"b", "d"})

    def test_o04_minimum_sufficient_team_changes_with_capability_risk_load_and_cost_evidence(self) -> None:
        workers = (
            CapabilityWorker("general", frozenset({"analysis"}), "medium", load=0, cost=1),
            CapabilityWorker("builder", frozenset({"analysis", "code", "test"}), "high", load=1, cost=3),
            CapabilityWorker("security", frozenset({"security"}), "critical", load=0, cost=5),
            CapabilityWorker("busy", frozenset({"code", "test"}), "high", load=9, cost=1),
        )
        selector = MinimalTeamSelector()
        simple = selector.select("simple", {"analysis"}, "low", workers)
        risky = selector.select("risky", {"code", "test", "security"}, "high", workers)
        self.assertEqual(simple.selected_agents, ("general",))
        self.assertEqual(risky.selected_agents, ("builder", "security"))
        self.assertEqual(risky.uncovered, ())
        self.assertNotEqual(simple.selected_agents, risky.selected_agents)

    def test_o05_agent_handoff_rework_cost_attribution_sums_exactly_to_run_totals(self) -> None:
        accounting = CollaborationAccounting()
        costs = (
            CollaborationCost("agent-1", "agent", 10, 5, 100, 1, 400000),
            CollaborationCost("handoff-1", "handoff", 4, 1, 20, 0, 100000),
            CollaborationCost("rework-1", "rework", 8, 2, 70, 1, 200000),
        )
        for item in costs:
            accounting.record(item)
        self.assertEqual(
            accounting.summary(),
            {"prompt_tokens": 22, "completion_tokens": 8, "total_tokens": 30, "latency_ms": 190, "physical_calls": 2, "marginal_benefit_ppm": 700000},
        )

    def test_o06_structured_failure_propagates_required_optional_compensatable_fanout_and_fanin(self) -> None:
        dag = _dag(
            [_task(item) for item in ("root", "required-a", "required-b", "fan-in", "optional", "effect", "compensate")],
            [
                PlannerDependency(task_id="required-a", depends_on="root", kind="required"),
                PlannerDependency(task_id="required-b", depends_on="root", kind="required"),
                PlannerDependency(task_id="fan-in", depends_on="required-a", kind="required"),
                PlannerDependency(task_id="fan-in", depends_on="required-b", kind="required"),
                PlannerDependency(task_id="optional", depends_on="root", kind="optional"),
                PlannerDependency(task_id="effect", depends_on="root", kind="compensatable", compensation_task_id="compensate"),
            ],
        )
        result = FailurePropagator().propagate(dag, _failure("root"))
        self.assertEqual(result.skipped, ("fan-in", "required-a", "required-b"))
        self.assertEqual(result.warning_ready, ("optional",))
        self.assertEqual(result.compensation_ready, ("compensate",))
        self.assertIsInstance(result.failure, FailureContract)

    def test_o07_worker_timeout_cancels_releases_resources_checkpoints_and_selects_takeover(self) -> None:
        scope = CancellationScope("run-orchestration")
        released = []
        stopped = threading.Event()

        def worker(cancel):
            cancel.wait(timeout=1)
            stopped.set()
            return "stopped"

        result = TaskDeadlineController().execute(
            "task-timeout",
            worker,
            timeout_seconds=0.01,
            scope=scope,
            checkpoint=lambda: {"offset": 7},
            cleanup=lambda: released.append("lease") or "lease-released",
            takeover_agents=("backup",),
        )
        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.checkpoint, {"offset": 7})
        self.assertEqual(result.takeover_agent, "backup")
        self.assertEqual(released, ["lease"])
        self.assertTrue(scope.event.is_set() and result.cleanup_complete)
        self.assertTrue(stopped.wait(timeout=2))

    def test_o08_user_cancel_race_stops_new_calls_and_cleans_journal_leases_and_temp_resources(self) -> None:
        scope = CancellationScope("run-orchestration")
        first_admitted = threading.Event()
        continue_attempts = threading.Event()
        admitted_after_cancel = []

        def caller():
            self.assertTrue(scope.admit_external_call())
            first_admitted.set()
            continue_attempts.wait(timeout=2)
            admitted_after_cancel.append(scope.admit_external_call())

        thread = threading.Thread(target=caller)
        thread.start()
        self.assertTrue(first_admitted.wait(timeout=2))
        scope.cancel(
            (
                lambda: "journal-finalized",
                lambda: "lease-released",
                lambda: "temporary-resource-cleaned",
            )
        )
        continue_attempts.set()
        thread.join(timeout=2)
        self.assertEqual(admitted_after_cancel, [False])
        self.assertEqual(scope.external_calls_started, 1)
        self.assertEqual(scope.cleanup_events, ["journal-finalized", "lease-released", "temporary-resource-cleaned"])

    def test_o09_stable_attempt_idempotency_keys_deduplicate_effect_proposal_and_state_commits(self) -> None:
        registry = AttemptIdempotencyRegistry()
        physical = {"tool": 0, "proposal": 0, "state": 0}
        for operation in physical:
            key = registry.key("run-orchestration", "task", 1, operation)

            def produce(name=operation):
                physical[name] += 1
                return f"{name}-result"

            first, committed = registry.commit_once(key, produce)
            duplicate, committed_again = registry.commit_once(key, produce)
            self.assertEqual(first, duplicate)
            self.assertTrue(committed)
            self.assertFalse(committed_again)
        self.assertEqual(physical, {"tool": 1, "proposal": 1, "state": 1})
        concurrent = [0]
        concurrent_key = registry.key("run-orchestration", "task", 2, "tool")

        def concurrent_producer():
            concurrent[0] += 1
            return "single-physical-effect"

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: registry.commit_once(concurrent_key, concurrent_producer), range(32)))
        self.assertEqual(concurrent, [1])
        self.assertEqual(sum(1 for _, committed in results if committed), 1)

    def test_o10_state_machine_table_covers_every_legal_and_illegal_transition_and_terminal_invariants(self) -> None:
        for current in OrchestrationState:
            for target in OrchestrationState:
                if target in LEGAL_TRANSITIONS[current]:
                    self.assertIs(TaskStateMachine.transition(current, target), target)
                else:
                    with self.assertRaises(ValueError):
                        TaskStateMachine.transition(current, target)
        self.assertTrue(all(not LEGAL_TRANSITIONS[state] for state in TERMINAL_STATES))

    def test_o11_enqueue_and_runtime_deadlock_detection_explains_self_multi_node_and_resource_cycles(self) -> None:
        with self.assertRaises(ValidationError):
            PlannerDependency(task_id="self", depends_on="self")
        with self.assertRaises(ValidationError):
            _dag(
                [_task("a"), _task("b")],
                [PlannerDependency(task_id="a", depends_on="b"), PlannerDependency(task_id="b", depends_on="a")],
            )
        valid = _dag([_task("a"), _task("b")])
        explanation = DeadlockDetector.explain(valid, {"a": ("resource-x",), "resource-x": ("b",), "b": ("a",)})
        self.assertTrue(explanation["deadlocked"])
        self.assertEqual(explanation["resource_cycle"], ("a", "resource-x", "b", "a"))

    def test_o12_priority_deadline_stable_tie_break_and_aging_prevent_low_priority_starvation(self) -> None:
        scheduler = FairPriorityScheduler(aging_quantum_ms=1000, aging_points=1000)
        candidates = (
            PriorityCandidate("new-high", 1, 3000, 9000),
            PriorityCandidate("old-low", 0, 0, 10000),
            PriorityCandidate("tie-b", 0, 3000, 8000),
            PriorityCandidate("tie-a", 0, 3000, 8000),
        )
        ordered = scheduler.order(candidates, now_ms=3000)
        self.assertEqual(ordered[0], "old-low")
        self.assertLess(ordered.index("tie-a"), ordered.index("tie-b"))

    def test_o13_hierarchical_semaphores_bound_stress_peaks_and_release_on_exception_or_cancel(self) -> None:
        limiter = HierarchicalResourceLimiter(global_limit=3, run_limit=2, provider_limit=1, tool_limit=2)
        entered = []
        active = [0]
        active_peak = [0]
        active_lock = threading.Lock()

        def use(index):
            with limiter.acquire(run_id="run-orchestration", provider=f"provider-{index % 4}", tool=f"tool-{index % 3}", timeout=2):
                with active_lock:
                    entered.append(index)
                    active[0] += 1
                    active_peak[0] = max(active_peak[0], active[0])
                try:
                    threading.Event().wait(0.005)
                finally:
                    with active_lock:
                        active[0] -= 1

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(use, range(12)))
        self.assertEqual(len(entered), 12)
        self.assertLessEqual(limiter.peaks["global:global"], 3)
        self.assertEqual(limiter.peaks["run:run-orchestration"], 2)
        self.assertEqual(active_peak, [2])
        self.assertTrue(all(value <= 1 for key, value in limiter.peaks.items() if key.startswith("provider:")))
        with self.assertRaises(RuntimeError):
            with limiter.acquire(run_id="run-orchestration", provider="mock", tool="filesystem"):
                raise RuntimeError("controlled cancellation")
        self.assertTrue(all(value == 0 for value in limiter.current.values()))

    def test_o14_trace_contract_links_task_attempt_agent_handoff_and_tool_under_one_correlation_id(self) -> None:
        trace = TraceLineage("trace-orchestration", created_at=CREATED)
        chain = (
            ("span-run", "run", "internal", None),
            ("span-task", "task", "internal", "span-run"),
            ("span-attempt", "attempt", "internal", "span-task"),
            ("span-agent", "agent", "agent", "span-attempt"),
            ("span-handoff", "handoff", "internal", "span-agent"),
            ("span-tool", "tool", "tool", "span-handoff"),
        )
        for span_id, name, kind, parent in chain:
            trace.start(span_id, name, kind, parent_span_id=parent)
        for span_id, *_ in reversed(chain):
            trace.finish(span_id, ended_at=ENDED)
        contract = trace.contract()
        self.assertEqual(contract.root_span_id, "span-run")
        self.assertEqual(len(contract.spans), 6)
        self.assertTrue(all(span.trace_id == "trace-orchestration" for span in contract.spans))

    def test_o15_low_risk_hot_path_preserves_safety_budget_trace_with_fewer_calls_and_lower_latency(self) -> None:
        planner = HotPathPlanner()
        hot = planner.select(task_count=1, risk="low", has_tools=False, has_side_effects=False)
        full = planner.select(task_count=3, risk="medium", has_tools=True, has_side_effects=False)
        self.assertEqual(hot.path, "hot")
        self.assertEqual(full.path, "full")
        self.assertTrue(planner.prove_equivalent(hot, full, policy_hashes=("a" * 64, "a" * 64), result_hashes=("b" * 64, "b" * 64)))
        self.assertEqual(hot.preserved_boundaries, ("safety", "budget", "trace"))

    def test_o16_pipeline_supervisor_network_and_hierarchy_share_terminal_permission_and_state_contracts(self) -> None:
        strategy = TopologyStrategy()
        for topology in ("pipeline", "supervisor", "network", "hierarchy"):
            with self.subTest(topology=topology):
                result = strategy.execute(topology, ("controller", "planner", "worker", "reviewer"))
                self.assertEqual(result["terminal"], "completed")
                self.assertEqual(result["permission_boundary"], "shared-global-policy")
                self.assertEqual(set(result["order"]), {"controller", "planner", "worker", "reviewer"})

    def test_o17_agent_client_reuse_isolates_prompt_credentials_tenant_and_evicts_failed_resources(self) -> None:
        pool = ReusableAgentPool()
        first = pool.checkout(tenant_id="tenant-a", provider_profile="mock", prompt="secret prompt one", credentials={"api_key": "secret-one"})
        second = pool.checkout(tenant_id="tenant-a", provider_profile="mock", prompt="prompt two", credentials={"api_key": "secret-two"})
        other = pool.checkout(tenant_id="tenant-b", provider_profile="mock", prompt="prompt other", credentials={"api_key": "secret-other"})
        self.assertEqual(first.client_id, second.client_id)
        self.assertNotEqual(first.invocation_context["prompt_hash"], second.invocation_context["prompt_hash"])
        self.assertNotEqual(first.client_id, other.client_id)
        serialized = json.dumps([first.invocation_context, second.invocation_context, other.invocation_context])
        self.assertNotIn("secret-one", serialized)
        self.assertNotIn("secret-two", serialized)
        pool.evict_failed(first)
        replacement = pool.checkout(tenant_id="tenant-a", provider_profile="mock", prompt="retry", credentials={"api_key": "replacement"})
        self.assertNotEqual(replacement.client_id, first.client_id)

    def test_o18_end_to_end_scenarios_cover_success_rework_rejection_consensus_arbitration_timeout_cancel_recovery_writes_and_exhaustion(self) -> None:
        scenarios = (
            "success",
            "rework",
            "rejection",
            "no-consensus",
            "arbitration",
            "timeout",
            "cancellation",
            "recovery",
            "concurrent-write",
            "resource-exhaustion",
        )
        results = [CollaborationScenarioHarness().run(item) for item in scenarios]
        self.assertEqual([item.scenario for item in results], list(scenarios))
        self.assertTrue(all(item.terminal in {"completed", "blocked", "timed_out", "cancelled"} for item in results))
        self.assertTrue(all(item.reason_code and item.external_calls_after_terminal == 0 for item in results))
        self.assertTrue(all(item.state_transitions[:3] == ("PENDING", "READY", "RUNNING") for item in results))
        self.assertTrue(all(item.physical_state_commits == 1 for item in results))


if __name__ == "__main__":
    unittest.main()
