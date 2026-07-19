from __future__ import annotations

import json
import os
import threading
import unittest
from concurrent.futures import CancelledError, ThreadPoolExecutor
from pathlib import Path

from sitina.cli import build_parser
from sitina.orchestrator.orchestration_management import FairPriorityScheduler, HierarchicalResourceLimiter, PriorityCandidate
from sitina.orchestrator.performance_management import (
    AttemptCostRecord,
    BatchRequest,
    BatchResponse,
    BudgetExceededError,
    BudgetNode,
    CacheBinding,
    CostAttributionLedger,
    CriticalPathAnalyzer,
    CriticalPathStage,
    HierarchicalTokenBudget,
    IsolatedResourcePool,
    PerformancePolicy,
    ProviderBatchDispatcher,
    RepeatableBenchmark,
    RuntimeCostMonitor,
    SecureProviderCache,
    TokenUsage,
)


def _usage(total: int, *, cache_read: int = 0, cache_write: int = 0) -> TokenUsage:
    return TokenUsage(input_tokens=total // 2, output_tokens=total - total // 2, cache_read_tokens=cache_read, cache_write_tokens=cache_write, total_tokens=total)


def _clock(durations: list[int]):
    values: list[int] = []
    cursor = 0
    for duration in durations:
        values.extend((cursor, cursor + duration))
        cursor += duration + 1000
    iterator = iter(values)
    return lambda: next(iterator)


class PerformanceCostManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = Path(os.environ["SITINA_HOME"])
        cls.policy = PerformancePolicy.load(cls.home).value

    def test_pc01_hierarchical_budget_reservation_settlement_refund_hard_cap_concurrency_and_missing_usage_unsettled(self) -> None:
        budget = HierarchicalTokenBudget((
            BudgetNode(scope_id="run-1", scope="run", maximum_tokens=100),
            BudgetNode(scope_id="stage-plan", scope="stage", parent_scope_id="run-1", maximum_tokens=80),
            BudgetNode(scope_id="agent-planner", scope="agent", parent_scope_id="stage-plan", maximum_tokens=50),
            BudgetNode(scope_id="tool-read", scope="tool", parent_scope_id="stage-plan", maximum_tokens=30),
        ))
        barrier = threading.Barrier(16)
        accepted: list[str] = []
        lock = threading.Lock()

        def reserve(index: int) -> None:
            barrier.wait()
            try:
                item = budget.reserve(f"reservation-{index}", leaf_scope_id="agent-planner", tokens=10)
            except BudgetExceededError:
                return
            with lock:
                accepted.append(item.reservation_id)

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(reserve, range(16)))
        self.assertEqual(len(accepted), 5)
        before = {item.scope_id: item for item in budget.snapshot().nodes}
        self.assertEqual((before["run-1"].reserved_tokens, before["agent-planner"].remaining_tokens), (50, 0))
        budget.settle(accepted[0], _usage(8))
        budget.refund(accepted[1])
        unresolved = budget.settle(accepted[2], None)
        after = {item.scope_id: item for item in budget.snapshot().nodes}
        self.assertEqual(unresolved.state, "unsettled")
        self.assertEqual((after["run-1"].used_tokens, after["run-1"].reserved_tokens), (8, 30))
        self.assertEqual(after["agent-planner"].unsettled_reservations, 1)
        reconciled = budget.settle(accepted[2], _usage(9))
        self.assertEqual(reconciled.state, "settled")

    def test_pc02_cost_attribution_run_stage_agent_logical_physical_retry_cache_fallback_and_totals_identity(self) -> None:
        ledger = CostAttributionLedger()
        records = (
            AttemptCostRecord(run_id="run-1", stage_id="plan", agent_id="planner", logical_call_id="logical-1", physical_attempt_id="attempt-1", attempt=1, kind="initial", usage=_usage(10, cache_write=2), cost_micro_usd=100, latency_ms=50),
            AttemptCostRecord(run_id="run-1", stage_id="plan", agent_id="planner", logical_call_id="logical-1", physical_attempt_id="attempt-2", attempt=2, kind="retry", usage=_usage(5), cost_micro_usd=50, latency_ms=30),
            AttemptCostRecord(run_id="run-1", stage_id="execute", agent_id="coder", logical_call_id="logical-2", physical_attempt_id="attempt-3", attempt=1, kind="fallback", usage=_usage(7), cost_micro_usd=70, latency_ms=40),
            AttemptCostRecord(run_id="run-1", stage_id="execute", agent_id="coder", logical_call_id="logical-3", physical_attempt_id=None, attempt=0, kind="cache_hit", usage=_usage(0, cache_read=4), cost_micro_usd=0, latency_ms=1),
            AttemptCostRecord(run_id="run-1", stage_id="review", agent_id="reviewer", logical_call_id="logical-4", physical_attempt_id="attempt-4", attempt=1, kind="initial", usage=None, cost_micro_usd=0, latency_ms=10),
        )
        for item in records:
            ledger.record(item)
        result = ledger.summarize("run-1")
        self.assertEqual((result.logical_call_count, result.physical_attempt_count, result.retry_attempt_count, result.fallback_attempt_count, result.cache_hit_count), (4, 4, 1, 1, 1))
        self.assertEqual((result.total_tokens, result.cache_read_tokens, result.cache_write_tokens, result.cost_micro_usd, result.latency_ms, result.unsettled_attempt_count), (22, 4, 2, 220, 131, 1))
        aliases = {"physical_attempts": "physical_attempt_count", "unsettled_attempts": "unsettled_attempt_count"}
        for field in ("physical_attempts", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "total_tokens", "cost_micro_usd", "latency_ms", "unsettled_attempts"):
            self.assertEqual(sum(item[field] for item in result.by_stage.values()), getattr(result, aliases.get(field, field)))

    def test_pc03_existing_hierarchical_concurrency_enforces_quotas_fairness_backpressure_and_releases_on_cancel(self) -> None:
        limiter = HierarchicalResourceLimiter(global_limit=2, run_limit=1, provider_limit=1, tool_limit=1)
        scheduler = FairPriorityScheduler(aging_quantum_ms=100, aging_points=10)
        order = scheduler.order((PriorityCandidate("older", 1, 0, 5000), PriorityCandidate("newer", 1, 900, 5000)), now_ms=1000)
        self.assertEqual(order, ("older", "newer"))
        with limiter.acquire(run_id="run-1", provider="provider-a", tool="read"):
            with self.assertRaises(TimeoutError):
                with limiter.acquire(run_id="run-1", provider="provider-a", tool="read", timeout=0):
                    pass
        with self.assertRaises(CancelledError):
            with limiter.acquire(run_id="run-1", provider="provider-a", tool="read"):
                raise CancelledError()
        with limiter.acquire(run_id="run-1", provider="provider-a", tool="read"):
            pass
        self.assertTrue(all(value == 0 for value in limiter.current.values()))
        self.assertLessEqual(limiter.peaks["run:run-1"], 1)

    def test_pc04_provider_cache_requires_safe_complete_binding_encrypts_ttl_invalidates_and_distinguishes_usage(self) -> None:
        cache = SecureProviderCache(b"k" * 32, default_ttl_seconds=10)
        binding = CacheBinding.from_request(tenant_id="tenant-a", model="model-a", prompt="private prompt", tools=[{"name": "read"}], policy={"version": "1"}, permissions=["read"])
        self.assertFalse(cache.put(binding, {"answer": "secret response"}, deterministic=False, side_effect_free=True, response_complete=True, now_epoch=0))
        self.assertFalse(cache.put(binding, {"answer": "secret response"}, deterministic=True, side_effect_free=False, response_complete=True, now_epoch=0))
        self.assertTrue(cache.put(binding, {"answer": "secret response"}, deterministic=True, side_effect_free=True, response_complete=True, now_epoch=0))
        self.assertNotIn(b"secret response", b"".join(cache.encrypted_payloads()))
        hit = cache.get(binding, now_epoch=9)
        self.assertEqual((hit.hit, hit.response, hit.cache_hit_count, hit.new_physical_call_count), (True, {"answer": "secret response"}, 1, 0))
        miss = cache.get(binding.model_copy(update={"tenant_id": "tenant-b"}), now_epoch=9)
        self.assertEqual((miss.hit, miss.usage_source, miss.new_physical_call_count), (False, "new_physical_call_required", 1))
        self.assertFalse(cache.get(binding, now_epoch=10).hit)
        cache.put(binding, {"answer": "new"}, deterministic=True, side_effect_free=True, response_complete=True, now_epoch=20)
        self.assertEqual(cache.invalidate(policy_hash=binding.policy_hash), 1)
        self.assertFalse(cache.get(binding, now_epoch=20).hit)

    def test_pc05_batch_uses_declared_capability_preserves_item_idempotency_errors_usage_and_falls_back_safely(self) -> None:
        requests = tuple(BatchRequest(request_id=f"request-{index}", idempotency_key=f"idempotency-{index}", provider="provider-a", model="model-a", tenant_id="tenant-a", policy_hash="policy", permission_hash="permission", compatibility_key="chat-v1", payload={"index": index}) for index in range(3))
        calls = {"batch": 0, "one": 0}

        def send_batch(items: tuple[BatchRequest, ...]):
            calls["batch"] += 1
            return tuple(BatchResponse(request_id=item.request_id, status="error", error_code="RATE_LIMIT") if item.request_id == "request-1" else BatchResponse(request_id=item.request_id, status="ok", usage=_usage(2)) for item in reversed(items))

        def send_one(item: BatchRequest):
            calls["one"] += 1
            return BatchResponse(request_id=item.request_id, status="ok", usage=_usage(3))

        batched = ProviderBatchDispatcher({"provider-a": True}).dispatch(requests, send_batch=send_batch, send_one=send_one)
        self.assertEqual((batched.batch_used, batched.batch_calls, batched.individual_calls, calls), (True, 1, 0, {"batch": 1, "one": 0}))
        self.assertEqual(tuple(item.request_id for item in batched.responses), tuple(item.request_id for item in requests))
        self.assertEqual(batched.responses[1].error_code, "RATE_LIMIT")
        fallback = ProviderBatchDispatcher({"provider-a": False}).dispatch(requests, send_batch=send_batch, send_one=send_one)
        self.assertEqual((fallback.batch_used, fallback.individual_calls, calls["one"]), (False, 3, 3))
        with self.assertRaises(ValueError):
            ProviderBatchDispatcher({"provider-a": True}).dispatch(requests + (requests[0],), send_batch=send_batch, send_one=send_one)

    def test_pc06_repeatable_benchmark_records_environment_samples_warmup_quantiles_error_and_proves_equivalent_faster_path(self) -> None:
        benchmark = RepeatableBenchmark()
        environment = {"fixture": "deterministic", "provider": "none"}
        plan = CriticalPathAnalyzer().analyze((
            CriticalPathStage(stage_id="safety", duration_ns=10),
            CriticalPathStage(stage_id="provider-a", duration_ns=40, queue_wait_ns=10, physical_calls=1, depends_on=("safety",)),
            CriticalPathStage(stage_id="provider-b", duration_ns=80, queue_wait_ns=20, physical_calls=1, depends_on=("provider-a",), parallelizable=True),
        ))
        self.assertEqual((plan.critical_path, plan.bottleneck_stage, plan.action, plan.estimated_physical_calls_saved), (("safety", "provider-a", "provider-b"), "provider-b", "parallelize", 1))
        baseline = benchmark.measure("full-path", lambda: ({"answer": 42}, 2), warmup_iterations=2, measurement_iterations=5, clock_ns=_clock([100, 120, 110, 130, 105]), environment=environment)
        candidate = benchmark.measure("critical-path-optimized", lambda: ({"answer": 42}, 1), warmup_iterations=2, measurement_iterations=5, clock_ns=_clock([50, 55, 45, 60, 52]), environment=environment)
        comparison = benchmark.compare(baseline, candidate)
        self.assertEqual((baseline.sample_count, baseline.warmup_iterations, baseline.p50_duration_ns, baseline.p95_duration_ns, baseline.error_count, baseline.error_rate_ppm), (5, 2, 110, 130, 0, 0))
        self.assertEqual(baseline.environment, environment)
        self.assertEqual((candidate.p50_duration_ns, candidate.p95_duration_ns, baseline.physical_call_count, candidate.physical_call_count), (52, 60, 10, 5))
        self.assertTrue(comparison.accepted)

    def test_pc07_resource_pool_isolates_tenant_credentials_profile_handles_concurrency_expiry_failure_and_close(self) -> None:
        pool = IsolatedResourcePool(default_ttl_seconds=10)
        created: list[dict[str, str]] = []
        closed: list[str] = []
        lock = threading.Lock()

        def factory() -> dict[str, str]:
            with lock:
                resource = {"id": f"client-{len(created) + 1}"}
                created.append(resource)
                return resource

        def close(resource: dict[str, str]) -> None:
            with lock:
                closed.append(resource["id"])

        barrier = threading.Barrier(8)

        def use(_index: int) -> str:
            lease = pool.checkout(tenant_id="tenant-a", provider_profile="profile-a", credential_reference="credential-a", now_epoch=0, factory=factory, close=close)
            barrier.wait()
            pool.release(lease)
            return lease.resource_id

        with ThreadPoolExecutor(max_workers=8) as executor:
            resource_ids = tuple(executor.map(use, range(8)))
        self.assertEqual((len(set(resource_ids)), len(created)), (1, 1))
        tenant_lease = pool.checkout(tenant_id="tenant-b", provider_profile="profile-a", credential_reference="credential-a", now_epoch=0, factory=factory, close=close)
        credential_lease = pool.checkout(tenant_id="tenant-a", provider_profile="profile-a", credential_reference="credential-b", now_epoch=0, factory=factory, close=close)
        self.assertEqual(len({resource_ids[0], tenant_lease.resource_id, credential_lease.resource_id}), 3)
        self.assertNotIn("credential-a", json.dumps(pool.isolation_fingerprints()))
        pool.release(tenant_lease)
        pool.release(credential_lease)
        expired = pool.checkout(tenant_id="tenant-a", provider_profile="profile-a", credential_reference="credential-a", now_epoch=11, factory=factory, close=close)
        self.assertNotEqual(expired.resource_id, resource_ids[0])
        pool.release(expired, failed=True)
        self.assertIn(expired.resource["id"], closed)
        self.assertEqual(pool.close(), 2)

    def test_pc08_runtime_cost_monitor_reports_used_reserved_remaining_forecast_hard_stop_freshness_source_and_cli(self) -> None:
        events = [
            {"event_type": "token_budget_reserved", "timestamp": "2026-07-19T00:00:01Z", "payload_json": {"run_id": "run-1", "reservation_id": "r1", "reserved_tokens": 80}},
            {"event_type": "provider_http_attempt_completed", "timestamp": "2026-07-19T00:00:02Z", "payload_json": {"run_id": "run-1", "token_usage": {"input_tokens": 40, "output_tokens": 20, "total_tokens": 60}}},
            {"event_type": "token_budget_settled", "timestamp": "2026-07-19T00:00:03Z", "payload_json": {"run_id": "run-1", "reservation_id": "r1"}},
            {"event_type": "token_budget_reserved", "timestamp": "2026-07-19T00:00:04Z", "payload_json": {"run_id": "run-1", "reservation_id": "r2", "reserved_tokens": 30}},
            {"event_type": "provider_http_attempt_failed", "timestamp": "2026-07-19T00:00:05Z", "payload_json": {"run_id": "run-1"}},
        ]
        snapshot = RuntimeCostMonitor.snapshot("run-1", events, hard_limit_tokens=100, forecast_additional_tokens=15)
        self.assertEqual((snapshot.used_tokens, snapshot.reserved_tokens, snapshot.remaining_tokens, snapshot.forecast_total_tokens), (60, 30, 10, 105))
        self.assertEqual((snapshot.predicted_to_exceed, snapshot.hard_stop, snapshot.unsettled_usage_count, snapshot.data_freshness, snapshot.source, snapshot.read_only), (True, False, 1, "2026-07-19T00:00:05Z", "run_ledger", True))
        stopped = RuntimeCostMonitor.snapshot("run-1", events + [{"event_type": "token_budget_reserved", "timestamp": "2026-07-19T00:00:06Z", "payload_json": {"run_id": "run-1", "reservation_id": "r3", "reserved_tokens": 10}}], hard_limit_tokens=100)
        self.assertTrue(stopped.hard_stop)
        args = build_parser().parse_args(["cost-status", "run-1", "--hard-limit-tokens", "100", "--forecast-additional-tokens", "15"])
        self.assertEqual((args.run_id, args.hard_limit_tokens, args.forecast_additional_tokens), ("run-1", 100, 15))


if __name__ == "__main__":
    unittest.main()
