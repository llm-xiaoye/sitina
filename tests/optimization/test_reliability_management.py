from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sitina.archive.backup import BackupHoldRegistry, CanonicalBackupBuilder
from sitina.archive.restore import RestoreDrill
from sitina.effects.gateway import MockTransport
from sitina.effects.model import EffectState, ExecutionCardinality, OutcomeState, SettlementBasis, SettlementState
from sitina.effects.reconcile import ReconciliationEngine
from sitina.journal.model import FrontierRef
from sitina.reliability import (
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitScope,
    CircuitState,
    DegradationPolicy,
    DisasterRecoveryVerifier,
    FailureCategory,
    FailureEnvelope,
    FailureNotifier,
    FailureTaxonomy,
    HealthService,
    ReliabilityEventLog,
    RetryScheduler,
    RetrySettings,
    RiskLevel,
    RollbackCoordinator,
    build_partial_success,
)
from tests.test_effect_state_matrix import request


class _VirtualClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.delays: list[float] = []

    def sleep(self, delay: float) -> None:
        self.delays.append(delay)
        self.now += delay


class ReliabilityManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = ReliabilityEventLog()

    def test_f01_unified_retry_exponential_jitter_retry_after_classification_and_virtual_clock(self) -> None:
        clock = _VirtualClock()
        scheduler = RetryScheduler(
            RetrySettings(max_retries=2, base_delay_seconds=2.0, max_delay_seconds=30.0, jitter_ratio=0.25),
            sleep=clock.sleep,
            events=self.events,
        )
        timeout = scheduler.plan(
            failure_type="provider_read_timeout",
            failed_attempt=1,
            remaining_seconds=100,
            jitter_seed="run-1",
        )
        self.assertTrue(timeout.should_retry)
        self.assertEqual(timeout.category, FailureCategory.TRANSIENT)
        self.assertGreaterEqual(timeout.delay_seconds, 1.5)
        self.assertLessEqual(timeout.delay_seconds, 2.5)
        scheduler.wait(timeout)
        throttled = scheduler.plan(
            failure_type="provider_rate_limited",
            failed_attempt=2,
            remaining_seconds=100,
            retry_after_seconds=7.0,
            status_code=429,
            jitter_seed="run-1",
        )
        self.assertEqual(throttled.category, FailureCategory.QUOTA)
        self.assertEqual(throttled.delay_seconds, 7.0)
        scheduler.wait(throttled)
        exhausted = scheduler.plan(
            failure_type="network_error",
            failed_attempt=3,
            remaining_seconds=100,
            jitter_seed="run-1",
        )
        self.assertFalse(exhausted.should_retry)
        self.assertEqual(clock.delays, [timeout.delay_seconds, 7.0])
        self.assertEqual(len(self.events.events("retry.scheduled")), 2)

    def test_f02_versioned_failure_taxonomy_has_all_classes_and_preserves_redacted_root_chain(self) -> None:
        expected = {
            "network_error": FailureCategory.TRANSIENT,
            "unsupported_operation": FailureCategory.PERMANENT,
            "provider_auth_failed": FailureCategory.AUTH,
            "provider_rate_limited": FailureCategory.QUOTA,
            "schema_invalid": FailureCategory.SCHEMA,
            "safety_blocked": FailureCategory.SAFETY,
            "run_cancelled": FailureCategory.CANCELLED,
            "mystery_failure": FailureCategory.UNKNOWN,
        }
        self.assertEqual(
            {name: FailureTaxonomy.classify(name) for name in expected},
            expected,
        )
        self.assertEqual(FailureTaxonomy.classify("provider_http", status_code=503), FailureCategory.TRANSIENT)
        try:
            try:
                raise ValueError("api_key=sk-super-secret-value")
            except ValueError as root:
                raise RuntimeError("response wrapper failed") from root
        except RuntimeError as error:
            envelope = FailureEnvelope.from_exception(
                error,
                failure_id="failure-1",
                run_id="run-1",
                failure_type="schema_invalid",
                stage="handoff-accept",
                source_agent="reviewer",
                destination_agent="planner",
            )
        self.assertEqual(envelope.mapping()["taxonomy_version"], "1.0")
        self.assertEqual([item.error_type for item in envelope.causes], ["RuntimeError", "ValueError"])
        self.assertNotIn("super-secret-value", json.dumps(envelope.mapping()))

    def test_f03_degradation_uses_risk_capability_matrix_and_fails_closed_for_unsafe_conditions(self) -> None:
        policy = DegradationPolicy({"web-search": ("cached-index",)}, events=self.events)
        low = policy.decide(
            risk=RiskLevel.LOW,
            required_capabilities=("web-search",),
            available_capabilities=("cached-index",),
            permission_granted=True,
            uncertain_side_effects=False,
        )
        self.assertEqual(low.disposition, "degraded")
        for risk, permission, uncertain in (
            (RiskLevel.HIGH, True, False),
            (RiskLevel.LOW, False, False),
            (RiskLevel.LOW, True, True),
        ):
            with self.subTest(risk=risk, permission=permission, uncertain=uncertain):
                decision = policy.decide(
                    risk=risk,
                    required_capabilities=("web-search",),
                    available_capabilities=("cached-index",),
                    permission_granted=permission,
                    uncertain_side_effects=uncertain,
                )
                self.assertEqual(decision.disposition, "fail-closed")

    def test_f04_circuit_breaker_isolates_provider_tool_profile_and_serializes_half_open_probe(self) -> None:
        now = [0.0]
        registry = CircuitBreakerRegistry(
            failure_threshold=2,
            cooldown_seconds=10,
            clock=lambda: now[0],
            events=self.events,
        )
        scope = CircuitScope("provider-a", "chat", "profile-a")
        isolated = CircuitScope("provider-a", "chat", "profile-b")
        self.assertEqual(registry.before_call(scope), CircuitState.CLOSED)
        registry.record_failure(scope, category=FailureCategory.TRANSIENT)
        self.assertEqual(registry.record_failure(scope, category=FailureCategory.TRANSIENT), CircuitState.OPEN)
        with self.assertRaises(CircuitOpenError):
            registry.before_call(scope)
        self.assertEqual(registry.before_call(isolated), CircuitState.CLOSED)
        now[0] = 10.0
        barrier = threading.Barrier(2)

        def race() -> str:
            barrier.wait()
            try:
                return registry.before_call(scope).value
            except CircuitOpenError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: race(), range(2)))
        self.assertEqual(sorted(results), ["half-open", "rejected"])
        self.assertEqual(registry.record_success(scope), CircuitState.CLOSED)

    def test_f05_idempotency_key_reuses_result_after_lost_response_and_executes_side_effect_once(self) -> None:
        class LostResponseTransport(MockTransport):
            def __init__(self) -> None:
                super().__init__()
                self.lose_first_response = True

            def send_once(self, effect_request, effect_attempt_id):
                result = super().send_once(effect_request, effect_attempt_id)
                if self.lose_first_response:
                    self.lose_first_response = False
                    raise TimeoutError("response lost after remote acceptance")
                return result

        transport = LostResponseTransport()
        effect_request = request()
        with self.assertRaises(TimeoutError):
            transport.send_once(effect_request, "attempt-1")
        recovered = transport.send_once(effect_request, "attempt-2")
        self.assertEqual(transport.remote_execution_count, 1)
        self.assertEqual(recovered["remote_execution_id"], "mock-execution-1")

    def test_f06_cross_agent_failure_envelope_keeps_stage_cause_retryability_and_redacts_diagnostic(self) -> None:
        try:
            try:
                raise ConnectionError("network down password=hunter-two-secret")
            except ConnectionError as root:
                raise RuntimeError("agent call failed") from root
        except RuntimeError as error:
            envelope = FailureEnvelope.from_exception(
                error,
                failure_id="failure-cross-agent",
                run_id="run-cross-agent",
                failure_type="network_error",
                stage="agent-handoff",
                source_agent="coder",
                destination_agent="reviewer",
            )
        payload = envelope.mapping()
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["stage"], "agent-handoff")
        self.assertEqual(payload["destination_agent"], "reviewer")
        self.assertEqual(len(payload["causes"]), 2)
        self.assertNotIn("hunter-two-secret", json.dumps(payload))

    def test_f07_transaction_boundary_never_reports_partial_effect_settlement_as_full_success(self) -> None:
        initial = EffectState(
            OutcomeState.OUTCOME_UNKNOWN,
            SettlementState.RECONCILING,
            SettlementBasis.NONE,
            ExecutionCardinality.UNKNOWN_CARDINALITY,
            2,
        )
        partially_confirmed = ReconciliationEngine().confirm_success(initial, resolved_exposures=1)
        self.assertEqual(partially_confirmed.outcome_state, OutcomeState.SUCCEEDED)
        self.assertEqual(partially_confirmed.settlement_state, SettlementState.RECONCILING)
        self.assertEqual(partially_confirmed.unresolved_transmission_exposure_count, 1)
        self.assertNotEqual(partially_confirmed.settlement_state, SettlementState.SETTLED)

    def test_f08_rollback_records_success_failure_and_deduplicates_repeated_compensation(self) -> None:
        coordinator = RollbackCoordinator(self.events)
        calls: list[str] = []
        first = coordinator.execute(effect_id="effect-1", rollback_id="rollback-1", action=lambda: calls.append("undo"))
        repeated = coordinator.execute(effect_id="effect-1", rollback_id="rollback-1", action=lambda: calls.append("duplicate"))
        self.assertEqual(first.status, "succeeded")
        self.assertTrue(repeated.deduplicated)
        self.assertEqual(calls, ["undo"])

        def fail() -> None:
            raise RuntimeError("controlled compensation failure")

        failed = coordinator.execute(effect_id="effect-2", rollback_id="rollback-2", action=fail)
        self.assertEqual(failed.status, "failed")
        event_types = [event["event_type"] for event in self.events.events()]
        self.assertEqual(
            event_types,
            ["rollback.started", "rollback.succeeded", "rollback.deduplicated", "rollback.started", "rollback.failed"],
        )

    def test_f09_dr_backup_restore_and_replay_use_only_isolated_copy_with_writer_disabled(self) -> None:
        home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        try:
            (home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
            source = home / "source"
            (source / "journal").mkdir(parents=True)
            (source / "cas").mkdir()
            events = ({"event_id": "event-1"}, {"event_id": "event-2"})
            (source / "journal/events.jsonl").write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            (source / "cas/object").write_bytes(b"controlled-cas-object")
            builder = CanonicalBackupBuilder(BackupHoldRegistry())
            manifest = builder.build(
                "backup-phase05",
                source_root=source,
                destination=home / "final-cold",
                frontier=FrontierRef("journal-phase05", 2, "local", 1, "a" * 64),
                reachable_paths=("journal/events.jsonl", "cas/object"),
                active_prefix_disposition="FORCED_ROLLOVER",
            )
            restored_path = home / "restored"
            restored = RestoreDrill().restore(
                manifest,
                source_copy=home / "final-cold",
                target=restored_path,
                source_kind="FINAL_COLD_COPY",
            )
            replayed = tuple(
                json.loads(line)
                for line in (restored_path / "journal/events.jsonl").read_text(encoding="utf-8").splitlines()
            )
            verifier = DisasterRecoveryVerifier(production_home=Path("/Users/moss/SitinaHub"), events=self.events)
            evidence = verifier.verify(
                backup_id=manifest.backup_id,
                manifest_hash=restored.manifest_hash,
                restored_path=restored_path,
                expected_event_count=2,
                replayed_events=replayed,
                writer_activated=restored.writer_activated,
            )
            self.assertTrue(evidence.restored)
            self.assertEqual(evidence.replayed_event_count, 2)
            self.assertFalse(evidence.writer_activated)
            with self.assertRaises(ValueError):
                verifier.verify(
                    backup_id=manifest.backup_id,
                    manifest_hash=manifest.manifest_hash,
                    restored_path=Path("/Users/moss/SitinaHub"),
                    expected_event_count=2,
                    replayed_events=replayed,
                    writer_activated=False,
                )
        finally:
            shutil.rmtree(home)

    def test_f10_health_checks_all_components_separate_liveness_readiness_and_redact_secrets(self) -> None:
        def probe(component: str, *, ready: bool = True):
            return lambda: {
                "live": True,
                "ready": ready,
                "diagnostic": f"{component} ok api_key=sk-health-secret-value",
            }

        report = HealthService(
            {
                "provider": probe("provider"),
                "journal": probe("journal"),
                "cas": probe("cas"),
                "projection": probe("projection"),
                "queue": probe("queue", ready=False),
                "config": probe("config"),
            },
            events=self.events,
        ).check()
        self.assertEqual(report.liveness, "alive")
        self.assertEqual(report.readiness, "not-ready")
        self.assertEqual({item.component for item in report.components}, set(HealthService.REQUIRED_COMPONENTS))
        self.assertNotIn("health-secret-value", json.dumps(report.mapping()))

    def test_f11_partial_success_names_missing_capability_and_actionable_next_step(self) -> None:
        partial = build_partial_success(
            run_id="run-partial",
            completed=("planner", "coder"),
            failed=("browser-tool",),
            missing_capabilities=("signed-in-browser",),
            next_steps=("Connect a signed-in browser and retry the browser step.",),
        )
        self.assertEqual(partial.status, "partial-success")
        self.assertEqual(partial.mapping()["schema"], "SITINA_PARTIAL_SUCCESS_V1")
        with self.assertRaises(ValueError):
            build_partial_success(
                run_id="run-invalid-partial",
                completed=("planner",),
                failed=("tool",),
                missing_capabilities=(),
                next_steps=(),
            )

    def test_f12_failure_notification_is_understandable_deduplicated_and_secret_free(self) -> None:
        envelope = FailureEnvelope(
            "failure-notify",
            "run-notify",
            "provider_rate_limited",
            FailureCategory.QUOTA,
            "provider-call",
            True,
            "controller",
            None,
            (),
            "api_key=sk-notification-secret-value",
        )
        notifier = FailureNotifier(self.events)
        first = notifier.notify(envelope)
        duplicate = notifier.notify(envelope)
        self.assertFalse(first.deduplicated)
        self.assertTrue(duplicate.deduplicated)
        self.assertEqual(first.notification_id, duplicate.notification_id)
        self.assertEqual(first.run_id, "run-notify")
        self.assertTrue(first.retryable)
        self.assertTrue(first.safe_advice)
        self.assertNotIn("notification-secret-value", json.dumps(first.mapping()))
        self.assertEqual(len(self.events.events("failure.notification-sent")), 1)


if __name__ == "__main__":
    unittest.main()
