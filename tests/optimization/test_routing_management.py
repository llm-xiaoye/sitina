from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace

from sitina.conversation.context import ContextPolicy, ConversationContext
from sitina.conversation.models import ChatMode, RouteSource
from sitina.conversation.router import ConversationRouter
from sitina.conversation.routing_policy import (
    ComplexityScorer,
    DomainProfileRegistry,
    ExperimentAssigner,
    ExperimentMetricRecorder,
    LatencyClass,
    LatencyPolicy,
    MultiToFastDegradationPolicy,
    RouteFeedbackRegistry,
    RoutingBudgetPlanner,
    RoutingHistoryState,
    RoutingRuleLifecycle,
    RoutingSignals,
    compare_routing_policies,
    evaluate_routing_fixtures,
)
from sitina.conversation.runtime import ConversationRuntime


class _SequenceClassifier:
    def __init__(self, values):
        self.values = list(values)
        self.calls = []

    def classify(self, payload, *, repair=False):
        self.calls.append({"payload": dict(payload), "repair": repair})
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def _classification(route="MULTI", confidence=800_000, total=30):
    return {
        "schema": "SITINA_ROUTE_CLASSIFIER_RESULT_V1",
        "route": route,
        "confidence_ppm": confidence,
        "reason_codes": ["ambiguous-structured-request"],
        "usage": {"input_tokens": total - 5, "output_tokens": 5, "total_tokens": total},
    }


class RoutingManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"])
        self.base = json.loads((self.home / "config/conversation_router.json").read_text(encoding="utf-8"))
        self.policy = json.loads((self.home / "config/routing_policy.json").read_text(encoding="utf-8"))
        self.context_policy = ContextPolicy.load(self.home)
        self.context = ConversationContext(policy=self.context_policy)
        self.snapshot = self.context.snapshot([])

    def router(self, *, classifier=None, sink=None, policy=None, clock=None):
        values = {
            "config": self.base,
            "context_policy": self.context_policy,
            "routing_policy": policy or self.policy,
            "classifier": classifier,
            "observation_sink": sink,
        }
        if clock is not None:
            values["clock"] = clock
        return ConversationRouter(**values)

    def test_r01_structured_complexity_scores_simple_boundary_and_complex_fixtures(self) -> None:
        scorer = ComplexityScorer(boundary_threshold=35, complex_threshold=65)
        simple = scorer.assess(RoutingSignals(1, 0, "low", (), (), 0, 0, ()))
        boundary = scorer.assess(
            RoutingSignals(1, 0, "medium", ("filesystem",), ("write",), 0, 650_000, ("test", "docs"))
        )
        complex_value = scorer.assess(
            RoutingSignals(
                3,
                2,
                "high",
                ("filesystem", "network"),
                ("write",),
                4_500,
                700_000,
                ("code", "test", "docs"),
            )
        )
        self.assertEqual((simple.band, boundary.band, complex_value.band), ("simple", "boundary", "complex"))
        self.assertEqual(simple.total, 0)
        self.assertGreater(complex_value.components["dependencies"], 0)
        self.assertNotEqual(complex_value.total, len(complex_value.reason_codes))

    def test_r02_classifier_only_runs_in_ambiguity_budget_sla_band_repairs_once_and_falls_back(self) -> None:
        classifier = _SequenceClassifier([{"invalid": True}, _classification()])
        router = self.router(classifier=classifier)
        decision = router.decide(
            ChatMode.AUTO,
            "不确定，请修改文件并写测试文档",
            self.snapshot,
            remaining_tokens=32_000,
            latency_class=LatencyClass.STANDARD,
        )
        self.assertIs(decision.source, RouteSource.MODEL_CLASSIFIER)
        self.assertEqual([item["repair"] for item in classifier.calls], [False, True])
        classifier_record = decision.observability["classifier"]
        self.assertEqual(classifier_record["physical_call_count"], 2)
        self.assertGreater(classifier_record["usage_upper_bound_tokens"], 0)
        never = _SequenceClassifier([_classification()])
        self.router(classifier=never).decide(ChatMode.AUTO, "你好", self.snapshot)
        self.assertEqual(never.calls, [])
        invalid = _SequenceClassifier([{"bad": 1}, {"still": "bad"}])
        fallback = self.router(classifier=invalid).decide(
            ChatMode.AUTO,
            "不确定，请修改文件并写测试文档",
            self.snapshot,
        )
        self.assertIs(fallback.source, RouteSource.LOCAL_ROUTER)
        self.assertEqual(fallback.observability["classifier"]["status"], "invalid-fallback")

    def test_r03_fast_to_multi_handoff_preserves_sourced_candidate_causality_without_duplicate_effect_or_display(self) -> None:
        fast = {
            "run_id": "fast-run-1",
            "response_output_hash": "a" * 64,
            "evidence_package_ref": "candidate-evidence-1",
            "confidence": "low",
            "needs_multi": True,
            "escalation_reasons": ["independent review"],
            "provider_physical_send_count": 1,
            "external_mutation_count": 0,
        }
        summary = ConversationRuntime._safe_fast_summary(fast)
        runtime = object.__new__(ConversationRuntime)
        runtime.context = SimpleNamespace(goal=lambda message, snapshot: f"goal:{message}:{snapshot.context_hash}")
        goal = runtime._multi_goal("question", snapshot=self.snapshot, safe_fast_summary=summary)
        self.assertEqual(summary["fast_run_id"], "fast-run-1")
        self.assertEqual(summary["candidate_ref"], "candidate-evidence-1")
        self.assertFalse(summary["displayed_to_user"])
        self.assertFalse(summary["repeat_side_effect_allowed"])
        self.assertIn("sourced candidate evidence", goal)
        self.assertIn("never repeat any side effect", goal)

    def test_r04_every_route_observation_and_explanation_contains_required_fields(self) -> None:
        records = []
        router = self.router(sink=records.append)
        decision = router.decide(ChatMode.AUTO, "比较 A 与 B", self.snapshot, subject_id="subject-1")
        observation = decision.observability
        self.assertEqual(len(records), 1)
        for key in (
            "input_hash",
            "policy_version",
            "evidence_codes",
            "conflicts",
            "scores",
            "thresholds",
            "budget",
            "sla",
            "experiment",
            "final_route",
            "decision_path",
        ):
            self.assertIn(key, observation)
        explanation = router.explain(decision)
        self.assertEqual(explanation["observability"]["input_hash"], decision.input_hash)

    def test_r05_feedback_rules_are_offline_evaluated_approved_versioned_and_never_self_modify_online(self) -> None:
        decision = self.router().decide(ChatMode.AUTO, "你好", self.snapshot)
        feedback = RouteFeedbackRegistry().record(
            "feedback-1",
            decision,
            corrected_route=ChatMode.MULTI,
            label="under-upgrade",
            successful_side_effects=False,
        )
        lifecycle = RoutingRuleLifecycle()
        bad = lifecycle.generate_offline("candidate-bad", [feedback])
        lifecycle.evaluate(
            bad.candidate_id,
            accuracy_delta_ppm=10_000,
            false_upgrade_delta_ppm=1,
            false_downgrade_delta_ppm=0,
        )
        lifecycle.approve(bad.candidate_id, approval_hash="a" * 64)
        with self.assertRaises(ValueError):
            lifecycle.publish(bad.candidate_id, version="rules-2")
        good = lifecycle.generate_offline("candidate-good", [feedback])
        lifecycle.evaluate(
            good.candidate_id,
            accuracy_delta_ppm=10_000,
            false_upgrade_delta_ppm=0,
            false_downgrade_delta_ppm=0,
        )
        lifecycle.approve(good.candidate_id, approval_hash="b" * 64)
        self.assertEqual(lifecycle.publish(good.candidate_id, version="rules-2").status, "published")
        with self.assertRaises(PermissionError):
            lifecycle.online_self_modify()

    def test_r06_route_correction_is_privacy_safe_reversible_and_never_replays_successful_effects(self) -> None:
        events = []
        registry = RouteFeedbackRegistry(events.append)
        decision = self.router().decide(ChatMode.AUTO, "比较 secret project A and B", self.snapshot)
        record = registry.record(
            "feedback-safe-1",
            decision,
            corrected_route=ChatMode.FAST,
            label="over-upgrade",
            successful_side_effects=True,
        )
        serialized = json.dumps(events, sort_keys=True)
        self.assertNotIn("secret project", serialized)
        self.assertFalse(record.automatic_rerun)
        self.assertTrue(record.successful_side_effects_preserved)
        self.assertTrue(registry.revoke(record.feedback_id).revoked)

    def test_r07_token_upper_bounds_are_budgeted_and_high_risk_never_chooses_cheap_unreviewed_route(self) -> None:
        planner = RoutingBudgetPlanner(fast_upper_tokens=100, multi_upper_tokens=500, classifier_upper_tokens=50)
        blocked = planner.admit(ChatMode.FAST, remaining_tokens=200, risk="high")
        reviewed = planner.admit(ChatMode.FAST, remaining_tokens=500, risk="high")
        ordinary = planner.admit(ChatMode.MULTI, remaining_tokens=200, risk="low")
        self.assertEqual(blocked.status, "blocked-review-budget")
        self.assertIsNone(blocked.selected_route)
        self.assertIs(reviewed.selected_route, ChatMode.MULTI)
        self.assertIs(ordinary.selected_route, ChatMode.FAST)

    def test_r08_versioned_bilingual_regression_fixtures_meet_accuracy_and_error_rate_gates(self) -> None:
        path = Path(__file__).parents[1] / "fixtures/routing_regression_v1.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "SITINA_ROUTING_REGRESSION_FIXTURES_V1")
        metrics = evaluate_routing_fixtures(self.router(), document["fixtures"], snapshot=self.snapshot)
        self.assertEqual(metrics.accuracy_ppm, 1_000_000)
        self.assertEqual(metrics.false_upgrades, 0)
        self.assertEqual(metrics.false_downgrades, 0)
        self.assertEqual(metrics.allowed_set_violations, 0)
        self.assertEqual(metrics.reason_code_misses, 0)
        candidate_policy = json.loads(json.dumps(self.policy))
        candidate_policy["domain_profiles"][0]["multi_threshold"] = 35
        differences = compare_routing_policies(
            self.router(),
            self.router(policy=candidate_policy),
            document["fixtures"],
            snapshot=self.snapshot,
        )
        self.assertEqual(differences, ("zh-boundary-policy-diff",))

    def test_r09_conflict_priority_and_tie_break_are_forced_then_safety_budget_sla_complexity(self) -> None:
        router = self.router()
        forced = router.decide(ChatMode.FAST, "给出医疗诊断用药建议并做安全审计", self.snapshot, remaining_tokens=1)
        automatic = router.decide(ChatMode.AUTO, "给出医疗诊断用药建议", self.snapshot, remaining_tokens=1)
        repeated = router.decide(ChatMode.AUTO, "给出医疗诊断用药建议", self.snapshot, remaining_tokens=1)
        self.assertIs(forced.resolved_mode, ChatMode.FAST)
        self.assertIn("forced-fast-overrode-auto-high-risk-review", forced.observability["conflicts"])
        self.assertIs(automatic.resolved_mode, ChatMode.MULTI)
        self.assertEqual(automatic, repeated)
        self.assertEqual(automatic.observability["decision_path"], "AUTO_REVIEW_BUDGET_BLOCKED")

    def test_r10_simplified_traditional_mixed_spacing_punctuation_case_and_synonyms_are_supported(self) -> None:
        router = self.router()
        variants = (
            "請做獨立審閱與交叉驗證",
            "请 做 安 全 审 计！！！",
            "PLEASE 比較 API v1 VS v2 and give a TRADE-OFF",
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertIs(router.decide(ChatMode.AUTO, value, self.snapshot).resolved_mode, ChatMode.MULTI)

    def test_r11_followup_inherits_bounded_unfinished_complexity_and_new_context_clears_it(self) -> None:
        router = self.router()
        inherited = RoutingHistoryState(ChatMode.MULTI, 82, True, True)
        follow_up = router.decide(ChatMode.AUTO, "继续，这个呢？", self.snapshot, history=inherited)
        cleared = router.decide(
            ChatMode.AUTO,
            "继续，这个呢？",
            self.snapshot,
            history=RoutingHistoryState(None, 0, False, False),
        )
        self.assertIs(follow_up.resolved_mode, ChatMode.MULTI)
        self.assertIn("history_inherited", follow_up.observability["evidence_codes"])
        self.assertIs(cleared.resolved_mode, ChatMode.FAST)

    def test_r12_versioned_general_code_compliance_profiles_cannot_weaken_global_safety_floor(self) -> None:
        profiles = DomainProfileRegistry(self.policy)
        self.assertEqual(profiles.select("ordinary question").name, "general")
        self.assertEqual(profiles.select("debug this code").name, "code")
        self.assertEqual(profiles.select("合规法规审计").name, "compliance")
        invalid = json.loads(json.dumps(self.policy))
        invalid["domain_profiles"][1]["risk_floor"] = "low"
        with self.assertRaises(ValueError):
            DomainProfileRegistry(invalid)

    def test_r13_experiment_bucket_is_stable_killable_versioned_and_uses_only_subject_identity(self) -> None:
        assigner = ExperimentAssigner(
            experiment_id="exp-1",
            policy_version="policy-1",
            treatment_percent=50,
            kill_switch=False,
        )
        first = assigner.assign("subject-1")
        self.assertEqual(first, assigner.assign("subject-1"))
        self.assertNotIn("subject-1", json.dumps(first.mapping()))
        metric = ExperimentMetricRecorder().record(
            first,
            outcome="success",
            route=ChatMode.FAST,
            latency_ms=120,
            token_usage=42,
        )
        self.assertEqual(metric["policy_version"], "policy-1")
        self.assertEqual(metric["subject_hash"], first.subject_hash)
        killed = ExperimentAssigner(
            experiment_id="exp-1",
            policy_version="policy-1",
            treatment_percent=100,
            kill_switch=True,
        ).assign("subject-1")
        self.assertEqual(killed.bucket, "control")
        self.assertTrue(killed.kill_switch_active)

    def test_r14_multi_to_fast_degradation_is_unreviewed_only_when_safe_and_otherwise_fails_closed(self) -> None:
        policy = MultiToFastDegradationPolicy()
        safe = policy.decide(
            failure_reason="reviewer unavailable",
            high_risk=False,
            uncertain_side_effects=False,
            policy_allows=True,
        )
        self.assertEqual(safe.action, "fast-unreviewed")
        self.assertFalse(safe.independently_reviewed)
        self.assertIn("未经过独立审阅", safe.user_notice)
        for high_risk, uncertain, allowed in ((True, False, True), (False, True, True), (False, False, False)):
            with self.subTest(high_risk=high_risk, uncertain=uncertain, allowed=allowed):
                denied = policy.decide(
                    failure_reason="controlled failure",
                    high_risk=high_risk,
                    uncertain_side_effects=uncertain,
                    policy_allows=allowed,
                )
                self.assertEqual(denied.action, "fail-closed")
                self.assertTrue(denied.original_failure_preserved)

    def test_r15_latency_class_inheritance_and_virtual_deadline_select_fast_partial_or_fail_closed(self) -> None:
        now = [100.0]
        policy = LatencyPolicy(
            {"interactive": 1500, "standard": 10000, "batch": 60000},
            clock=lambda: now[0],
        )
        now[0] = 101.2
        fast = policy.evaluate(LatencyClass.INTERACTIVE, started_at=100.0)
        self.assertEqual(fast.action, "fast-path")
        now[0] = 101.6
        partial = policy.evaluate(None, inherited_class=LatencyClass.INTERACTIVE, started_at=100.0)
        closed = policy.evaluate(LatencyClass.INTERACTIVE, started_at=100.0, high_risk=True)
        self.assertEqual(partial.action, "partial-result")
        self.assertTrue(partial.inherited)
        self.assertEqual(closed.action, "fail-closed")


if __name__ == "__main__":
    unittest.main()
