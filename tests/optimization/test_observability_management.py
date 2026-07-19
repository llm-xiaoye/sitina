from __future__ import annotations

import os
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.cli import build_parser
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.observability_management import (
    AlertEngine,
    AlertSignalSnapshot,
    AlertState,
    BusinessMetricCollector,
    LowOverheadProfiler,
    ObservabilityPolicy,
    ReplayConsistencyVerifier,
    RunTrajectoryMonitor,
    StructuredLogBuilder,
    TraceIntegrityValidator,
    TraceObservation,
    TracePropagationContext,
    TracePropagator,
    TraceQuery,
    TraceQueryEngine,
    TraceSamplingPolicy,
    TrajectoryEvent,
)
from sitina.orchestrator.replay import ReplayEngine
from sitina.storage import SitinaStore


NOW = "2026-07-19T00:00:00Z"
END = "2026-07-19T00:00:01Z"


def _span(
    span_id: str,
    layer: str,
    parent: str | None,
    *,
    task_id: str | None = "task-1",
    agent_id: str | None = None,
    status: str = "OK",
    usage: dict[str, int] | None = None,
) -> TraceObservation:
    return TraceObservation(
        trace_id="trace-1",
        correlation_id="correlation-1",
        span_id=span_id,
        parent_span_id=parent,
        layer=layer,
        name=f"{layer}-work",
        status=status,
        run_id="run-1",
        task_id=None if layer == "run" else task_id,
        agent_id=agent_id,
        started_at=NOW,
        ended_at=END,
        usage=usage or {},
        policy_version="policy-1",
        observed_schema_version="1.0",
    )


class ObservabilityManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = Path(os.environ["SITINA_HOME"])
        cls.policy = ObservabilityPolicy.load(cls.home).value
        SitinaStore(cls.home).init_db()

    def test_t01_trace_integrity_run_task_agent_provider_tool_state_effect_versions_usage_and_orphan_detection(self) -> None:
        observations = (
            _span("run", "run", None, task_id=None),
            _span("task", "task", "run"),
            _span("agent", "agent", "task", agent_id="planner"),
            _span("provider", "provider", "agent", agent_id="planner", usage={"input_tokens": 4, "output_tokens": 3, "total_tokens": 7}),
            _span("state", "state", "agent"),
            _span("effect", "effect", "agent"),
        )
        report = TraceIntegrityValidator().validate(observations)
        self.assertEqual((report.status, report.span_count, report.errors), ("complete", 6, ()))
        orphan = list(observations)
        orphan[-1] = orphan[-1].model_copy(update={"parent_span_id": "missing"})
        broken = TraceIntegrityValidator().validate(orphan)
        self.assertEqual(broken.status, "invalid")
        self.assertIn("ORPHAN:effect", broken.errors)
        cycle = list(observations)
        cycle[0] = cycle[0].model_copy(update={"parent_span_id": "effect"})
        self.assertTrue(any(item.startswith("CYCLE:") for item in TraceIntegrityValidator().validate(cycle).errors))

    def test_t02_sampling_always_keeps_error_high_risk_approval_overbudget_billing_audit_and_deterministically_samples_success(self) -> None:
        policy = TraceSamplingPolicy(self.policy["sampling"])
        for status, risk, classes in (
            ("ERROR", "low", ()),
            ("OK", "high", ()),
            ("OK", "low", ("approval",)),
            ("OK", "low", ("over_budget",)),
            ("OK", "low", ("billing",)),
            ("OK", "low", ("audit",)),
        ):
            with self.subTest(status=status, risk=risk, classes=classes):
                self.assertTrue(policy.decide(trace_id=f"{status}-{risk}-{classes}", status=status, risk=risk, event_classes=classes).keep)
        first = policy.decide(trace_id="ordinary-success", status="OK", risk="low", event_classes=())
        second = policy.decide(trace_id="ordinary-success", status="OK", risk="low", event_classes=())
        self.assertEqual(first, second)

    def test_t03_trace_query_filters_run_agent_tool_status_time_correlation_paginates_redacts_and_cli_parses(self) -> None:
        events = [
            {"run_id": "run-1", "agent_id": "planner", "status": "ok", "event_type": "tool_invocation", "timestamp": "2026-07-19T00:00:01Z", "_trace_id": "corr-1", "payload_json": {"tool_name": "read", "password": "hunter2"}},
            {"event_type": "tool_invocation", "timestamp": "2026-07-19T00:00:02Z", "payload_json": {"run_id": "run-1", "agent_id": "planner", "status": "ok", "correlation_id": "corr-1", "tool_name": "read"}},
            {"run_id": "run-2", "agent_id": "planner", "status": "ok", "event_type": "tool_invocation", "timestamp": "2026-07-19T00:00:02Z", "_trace_id": "corr-1", "payload_json": {"tool_name": "read"}},
        ]
        query = TraceQuery(run_id="run-1", agent="planner", tool="read", status="ok", started_at="2026-07-19T00:00:00Z", ended_at="2026-07-19T00:01:00Z", correlation_id="corr-1", limit=1)
        first = TraceQueryEngine().query(events, query)
        second = TraceQueryEngine().query(events, query.model_copy(update={"cursor": first.next_cursor}))
        self.assertEqual((first.total_matches, len(first.items), first.next_cursor, len(second.items)), (2, 1, 1, 1))
        self.assertNotIn("hunter2", str(first.items))
        args = build_parser().parse_args(["trace", "run-1", "--query", "--agent", "planner", "--tool", "read", "--status", "ok", "--started-at", NOW, "--ended-at", END, "--correlation-id", "corr-1", "--cursor", "1", "--limit", "10"])
        self.assertTrue(args.query)
        self.assertEqual((args.cursor, args.limit), (1, 10))

    def test_t04_replay_reads_recorded_events_with_zero_provider_network_and_real_effect_calls(self) -> None:
        run_id = "run-observability-replay"
        ledger = RunLedger(self.home)
        ledger.record("run_started", run_id=run_id, reason="fixture")
        ledger.record("task_graph_created", run_id=run_id, reason="fixture", payload={"graph_id": "graph-1"})
        ledger.record("run_completed", run_id=run_id, reason="fixture")
        with (
            patch("sitina.runners.provider.AnthropicCompatibleClient.complete_with_metadata") as provider,
            patch.object(socket, "create_connection") as network,
            patch("sitina.orchestrator.side_effects.SideEffectManager.execute") as effect,
        ):
            replay = ReplayEngine(self.home).replay(run_id, record=False)
        self.assertIn(replay.status, {"replay_ok", "replay_incomplete"})
        self.assertEqual((provider.call_count, network.call_count, effect.call_count), (0, 0, 0))
        self.assertIn("never re-executes provider calls", " ".join(replay.limitations))

    def test_t05_replay_state_hash_is_stable_with_explicit_volatile_normalization_and_version_upcast(self) -> None:
        verifier = ReplayConsistencyVerifier()
        old = verifier.upcast_event({"schema_version": "0.9", "ts": "2020-01-01", "event_type": "run_started", "payload": {"state": "ok"}})
        current = {"schema_version": "1.0", "timestamp": "2030-01-01", "event_type": "run_started", "payload_json": {"state": "ok"}}
        self.assertEqual(old["schema_version"], "1.0")
        self.assertEqual(verifier.compare(old, current).status, "match")
        self.assertEqual(verifier.compare(current, current | {"payload_json": {"state": "changed"}}).status, "mismatch")
        with self.assertRaises(ValueError):
            verifier.upcast_event({"schema_version": "2.0"})

    def test_t06_business_metrics_cover_success_routing_rework_handoff_budget_partial_and_recovery_with_bounded_dimensions(self) -> None:
        events = [
            {"event_type": "task_graph_node_status", "status": "ok"},
            {"event_type": "task_graph_node_status", "status": "failed"},
            {"event_type": "dispatcher_agent_selected", "status": "ok"},
            {"event_type": "dispatcher_no_eligible_agent", "status": "blocked"},
            {"event_type": "rework_requested", "status": "ok"},
            {"event_type": "agent_handoff", "status": "ok"},
            {"event_type": "handoff_accepted", "status": "ok"},
            {"event_type": "token_budget_blocked", "status": "blocked"},
            {"event_type": "run_completed", "status": "ok", "payload_json": {"partial_success": True}},
            {"event_type": "checkpoint_resumed", "status": "ok"},
        ]
        snapshot = BusinessMetricCollector().collect(events)
        self.assertEqual(snapshot.metrics["task_success_rate_ppm"], 500000)
        self.assertEqual(snapshot.metrics["routing_quality_ppm"], 500000)
        for name in ("rework_count", "handoff_count", "handoff_acceptance_count", "budget_exceeded_count", "partial_success_count", "recovery_success_count"):
            self.assertEqual(snapshot.metrics[name], 1, name)
        self.assertEqual(snapshot.dimension_keys, ("policy_version", "risk_band", "terminal_status"))

    def test_t07_alerts_apply_multiwindow_slo_failures_backlog_token_cost_dedupe_flap_cooldown_and_recovery(self) -> None:
        engine = AlertEngine(self.policy["alerts"])
        firing_signals = AlertSignalSnapshot(fast_burn_rate_ppm=2000000, slow_burn_rate_ppm=1000000, repeated_failures=3, queue_depth=20, token_ratio_ppm=1500000, cost_ratio_ppm=1500000)
        first = engine.evaluate(firing_signals, state=AlertState(), now_epoch=0)
        self.assertEqual({item.code for item in first.notifications}, {"SLO_MULTI_WINDOW_BURN", "REPEATED_FAILURE", "QUEUE_BACKLOG", "TOKEN_ANOMALY", "COST_ANOMALY"})
        duplicate = engine.evaluate(firing_signals, state=first.state, now_epoch=1)
        self.assertEqual(duplicate.notifications, ())
        clear = AlertSignalSnapshot(fast_burn_rate_ppm=0, slow_burn_rate_ppm=0, repeated_failures=0, queue_depth=0, token_ratio_ppm=0, cost_ratio_ppm=0)
        recovered = engine.evaluate(clear, state=duplicate.state, now_epoch=2)
        self.assertTrue(all(item.kind == "recovered" for item in recovered.notifications))
        flap = engine.evaluate(firing_signals, state=recovered.state, now_epoch=3)
        self.assertEqual(flap.notifications, ())
        after_cooldown = engine.evaluate(firing_signals, state=flap.state, now_epoch=303)
        self.assertTrue(all(item.kind == "firing" for item in after_cooldown.notifications))

    def test_t08_structured_logs_are_schema_level_code_correlation_redacted_and_human_readable(self) -> None:
        record = StructuredLogBuilder().build(
            timestamp=NOW,
            level="ERROR",
            event_code="PROVIDER_FAILED",
            correlation_id="corr-1",
            run_id="run-1",
            trace_id="trace-1",
            span_id="span-1",
            message="request failed password=hunter2",
            fields={"authorization": "Bearer abc", "safe": "value"},
        )
        serialized = record.model_dump_json(by_alias=True)
        human = StructuredLogBuilder.human(record)
        self.assertNotIn("hunter2", serialized + human)
        self.assertNotIn("Bearer abc", serialized + human)
        self.assertEqual((record.schema_id, record.level, record.event_code, record.correlation_id), ("SITINA_STRUCTURED_LOG_V1", "ERROR", "PROVIDER_FAILED", "corr-1"))

    def test_t09_trace_context_propagates_across_agent_thread_process_and_uses_link_for_async_queue(self) -> None:
        root = TracePropagationContext(trace_id="trace-1", span_id="run", correlation_id="corr-1")
        agent = TracePropagator.child(root, span_id="agent")
        headers = TracePropagator.inject(agent)
        extracted = TracePropagator.extract(headers)
        provider = TracePropagator.child(extracted, span_id="provider")
        queued = TracePropagator.queue_link(provider, consumer_span_id="worker")
        self.assertEqual((agent.parent_span_id, provider.parent_span_id), ("run", "agent"))
        self.assertEqual(extracted, agent)
        self.assertIsNone(queued.parent_span_id)
        self.assertEqual((queued.links, queued.trace_id, queued.correlation_id), (("provider",), "trace-1", "corr-1"))

    def test_t10_profiler_defaults_off_and_reports_only_stage_wall_cpu_memory_queue_fields_when_enabled(self) -> None:
        disabled = LowOverheadProfiler()
        with disabled.measure("secret-stage"):
            pass
        self.assertEqual(disabled.reports, [])
        wall = iter((100, 180))
        cpu = iter((20, 50))
        memory = iter((1000, 1250))
        enabled = LowOverheadProfiler(enabled=True, wall_clock_ns=lambda: next(wall), cpu_clock_ns=lambda: next(cpu), memory_bytes=lambda: next(memory))
        with enabled.measure("planner", queue_wait_ns=7):
            pass
        report = enabled.reports[0]
        self.assertEqual((report.wall_time_ns, report.cpu_time_ns, report.memory_delta_bytes, report.queue_wait_ns), (80, 30, 250, 7))
        self.assertEqual(set(report.model_dump()), {"stage", "wall_time_ns", "cpu_time_ns", "memory_delta_bytes", "queue_wait_ns"})

    def test_x17_trajectory_monitor_detects_every_anomaly_boundary_normal_negative_actions_and_restart_dedup(self) -> None:
        monitor = RunTrajectoryMonitor(self.policy["trajectory"])
        normal = (
            TrajectoryEvent(event_id="n1", kind="tool_call", tool_name="read"),
            TrajectoryEvent(event_id="n2", kind="tool_call", tool_name="read"),
            TrajectoryEvent(event_id="n3", kind="permission_denied"),
            TrajectoryEvent(event_id="n4", kind="state_transition", state_hash="a"),
            TrajectoryEvent(event_id="n5", kind="state_transition", state_hash="a"),
            TrajectoryEvent(event_id="n6", kind="token_usage", tokens=149, budget=100),
        )
        self.assertEqual(monitor.evaluate("run-normal", normal).anomalies, ())
        boundary = normal + (
            TrajectoryEvent(event_id="b1", kind="tool_call", tool_name="read"),
            TrajectoryEvent(event_id="b2", kind="permission_denied"),
            TrajectoryEvent(event_id="b3", kind="state_transition", state_hash="a"),
            TrajectoryEvent(event_id="b4", kind="token_usage", tokens=1, budget=100),
        )
        first = monitor.evaluate("run-anomaly", boundary)
        by_code = {item.code: item for item in first.anomalies}
        self.assertEqual(set(by_code), {"SAME_TOOL_REPEAT", "PERMISSION_DENIAL_REPEAT", "UNCHANGED_STATE_LOOP", "TOKEN_BUDGET_ANOMALY"})
        self.assertEqual(by_code["SAME_TOOL_REPEAT"].action, "warn")
        self.assertEqual(by_code["PERMISSION_DENIAL_REPEAT"].action, "circuit_break")
        self.assertEqual(by_code["UNCHANGED_STATE_LOOP"].action, "pause_and_request_review")
        self.assertEqual(by_code["TOKEN_BUDGET_ANOMALY"].threshold, 150)
        restarted = RunTrajectoryMonitor(self.policy["trajectory"]).evaluate("run-anomaly", boundary, state=first.state)
        self.assertEqual(restarted.anomalies, ())


if __name__ == "__main__":
    unittest.main()
