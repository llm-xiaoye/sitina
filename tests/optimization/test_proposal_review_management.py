from __future__ import annotations

import json
import os
import threading
import unittest
from pathlib import Path

from sitina.orchestrator.proposal_review_management import (
    RUBRIC_DIMENSIONS,
    ArbitrationTriggerPolicy,
    ArbiterIsolationPolicy,
    AskUserManager,
    BlockRecoveryPolicy,
    CompetitionAdmission,
    EvaluationIsolation,
    EvaluationRubric,
    ParallelReviewExecutor,
    ProposalBudgetAllocator,
    ProposalCache,
    ProposalCacheKey,
    ProposalCandidate,
    ProposalCountPolicy,
    ProposalDiversityGate,
    ProposalSelectionEngine,
    RejectionRecord,
    ReviewDeadlineCoordinator,
    ReviewQualityGate,
    ScoredEvaluation,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


def _candidate(
    proposal_id: str,
    *,
    author: str = "author",
    strategy: str = "incremental",
    assumptions: tuple[str, ...] = ("stable API",),
    risks: tuple[str, ...] = ("compatibility",),
    content: str = "implement an incremental migration with compatibility tests",
    tenant: str = "tenant-a",
    side_effect_free: bool = True,
    sensitive: bool = False,
) -> ProposalCandidate:
    return ProposalCandidate(
        proposal_id=proposal_id,
        author_id=author,
        strategy=strategy,
        assumptions=list(assumptions),
        risk_focus=list(risks),
        content=content,
        immutable_context_ref=DIGEST_A,
        policy_hash=DIGEST_B,
        model_id="model-a",
        prompt_hash=DIGEST_C,
        permission_hash=DIGEST_D,
        tenant_id=tenant,
        estimated_tokens=100,
        side_effect_free=side_effect_free,
        sensitive=sensitive,
    )


def _evaluation(
    evaluation_id: str,
    proposal_id: str,
    *,
    evaluator: str = "reviewer",
    score: int = 80,
    confidence: int = 900_000,
    gate: bool = True,
    evidence: tuple[str, ...] = (DIGEST_A,),
    reason: str = "Detailed independent assessment with cited evidence.",
) -> ScoredEvaluation:
    return ScoredEvaluation(
        evaluation_id=evaluation_id,
        proposal_id=proposal_id,
        evaluator_id=evaluator,
        scores={name: score for name in RUBRIC_DIMENSIONS},
        hard_gate_pass={"safety": gate, "evidence": gate},
        confidence_ppm=confidence,
        reason=reason,
        evidence_refs=list(evidence),
        model_version="model-review-1",
        policy_version="proposal-review-policy-1",
    )


class ProposalReviewManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        home = Path(os.environ["SITINA_HOME"])
        cls.policy = json.loads((home / "config/proposal_review_policy.json").read_text(encoding="utf-8"))
        cls.rubric = EvaluationRubric(**cls.policy["rubric"])

    def test_pr01_strategy_assumption_risk_diversity_rejects_near_duplicates_then_regenerates_or_degrades(self) -> None:
        first = _candidate("proposal-a")
        duplicate = _candidate("proposal-b")
        different = _candidate(
            "proposal-c",
            strategy="parallel replacement",
            assumptions=("breaking change allowed",),
            risks=("rollback",),
            content="replace the component in parallel and switch after rollback verification",
        )
        gate = ProposalDiversityGate(maximum_similarity_ppm=700_000, maximum_regenerations=1)
        regeneration = gate.evaluate((first, duplicate, different), regeneration_count=0)
        degraded = gate.evaluate((first, duplicate), regeneration_count=1)
        self.assertEqual(regeneration.accepted, ("proposal-a", "proposal-c"))
        self.assertEqual(regeneration.action, "regenerate")
        self.assertEqual(degraded.action, "degrade")
        self.assertTrue(regeneration.rejected["proposal-b"].startswith("NEAR_DUPLICATE"))

    def test_pr02_risk_budget_minimum_and_maximum_prevent_underfilled_multi_competition(self) -> None:
        policy = ProposalCountPolicy(self.policy["candidate_limits"])
        insufficient = policy.decide(risk="medium", candidate_count=1, total_budget=1000, per_candidate_budget=200, multi=True)
        blocked = policy.decide(risk="high", candidate_count=4, total_budget=400, per_candidate_budget=200, multi=True)
        ready = policy.decide(risk="high", candidate_count=9, total_budget=1000, per_candidate_budget=200, multi=True)
        self.assertEqual(insufficient.status, "insufficient")
        self.assertEqual(blocked.status, "budget-blocked")
        self.assertEqual((ready.status, ready.minimum, ready.maximum, ready.admitted), ("competition-ready", 3, 4, 4))

    def test_pr03_chat_competes_by_complexity_risk_budget_while_safe_simple_chat_uses_hot_path(self) -> None:
        admission = CompetitionAdmission()
        complex_chat = admission.decide(task_type="chat", complexity=75, risk="medium", total_budget=1000, minimum_cost=500, hot_path_safe=False)
        simple_chat = admission.decide(task_type="chat", complexity=10, risk="low", total_budget=1000, minimum_cost=500, hot_path_safe=True)
        ordinary_query = admission.decide(task_type="local_file_query", complexity=60, risk="low", total_budget=1000, minimum_cost=500, hot_path_safe=False)
        self.assertEqual(complex_chat.action, "compete")
        self.assertEqual(simple_chat.action, "hot-path")
        self.assertEqual(ordinary_query.action, "compete")

    def test_pr04_evaluator_input_is_anonymous_self_review_forbidden_and_single_provider_context_is_independent(self) -> None:
        candidate = _candidate("proposal-a", author="author-a")
        isolation = EvaluationIsolation()
        with self.assertRaises(PermissionError):
            isolation.prepare(
                candidate,
                evaluator_id="author-a",
                evaluator_profile="profile-a",
                evaluator_model="model-a",
                author_profile="profile-a",
                author_model="model-a",
                original_requirements_ref=DIGEST_B,
            )
        distinct = isolation.prepare(
            candidate,
            evaluator_id="reviewer",
            evaluator_profile="profile-b",
            evaluator_model="model-b",
            author_profile="profile-a",
            author_model="model-a",
            original_requirements_ref=DIGEST_B,
        )
        fallback = isolation.prepare(
            candidate,
            evaluator_id="reviewer-2",
            evaluator_profile="profile-a",
            evaluator_model="model-a",
            author_profile="profile-a",
            author_model="model-a",
            original_requirements_ref=DIGEST_B,
        )
        self.assertEqual(distinct.isolation_level, "model-profile-independent")
        self.assertEqual(fallback.isolation_level, "context-role-sampling-independent")
        self.assertNotIn("author", json.dumps(distinct.payload))

    def test_pr05_versioned_unified_rubric_has_all_weights_and_non_averageable_hard_gates(self) -> None:
        self.assertEqual(self.rubric.version, "evaluation-rubric-1")
        self.assertEqual(set(self.rubric.weights_ppm), set(RUBRIC_DIMENSIONS))
        self.assertEqual(sum(self.rubric.weights_ppm.values()), 1_000_000)
        self.assertEqual(set(self.rubric.hard_gates), {"safety", "evidence"})

    def test_pr06_hard_gates_precede_normalized_confidence_disagreement_and_stable_tie_break(self) -> None:
        evaluations = (
            _evaluation("eval-a", "proposal-a", score=100, confidence=1_000_000),
            _evaluation("eval-b", "proposal-b", score=100, confidence=1_000_000),
            _evaluation("eval-hard", "proposal-hard", score=100, confidence=1_000_000, gate=False),
        )
        selected = ProposalSelectionEngine().select(("proposal-b", "proposal-a", "proposal-hard", "proposal-missing"), evaluations, self.rubric)
        self.assertEqual(selected.selected_proposal_id, "proposal-a")
        self.assertEqual(selected.rejected["proposal-hard"], "HARD_GATE_FAILED")
        self.assertEqual(selected.rejected["proposal-missing"], "MISSING_EVALUATION")
        self.assertEqual(selected.normalized_scores_ppm["proposal-a"], 1_000_000)

    def test_pr07_structured_rejection_is_redacted_versioned_and_offline_learning_ready(self) -> None:
        evaluation = _evaluation("eval-a", "proposal-a")
        record = RejectionRecord.create(
            evaluation,
            reason_code="EVIDENCE_GAP",
            suggestions=("replace password=hunter2 with a secret reference", "add a cited rollback test"),
        )
        serialized = json.dumps(record.model_dump(by_alias=True), sort_keys=True)
        self.assertNotIn("hunter2", serialized)
        self.assertIn("<redacted>", serialized)
        self.assertEqual(record.reason_code, "EVIDENCE_GAP")
        self.assertEqual(record.policy_version, "proposal-review-policy-1")

    def test_pr08_arbitration_trigger_table_covers_each_threshold_and_clean_negative(self) -> None:
        config = self.policy["arbitration"]
        policy = ArbitrationTriggerPolicy(**config)
        cases = (
            ({"eligible_candidates": 0, "score_gap_ppm": 999999, "reviewer_conflict": False, "risk_disagreements": 0, "schema_failures": 0}, "NO_ELIGIBLE_CANDIDATE"),
            ({"eligible_candidates": 2, "score_gap_ppm": 50000, "reviewer_conflict": False, "risk_disagreements": 0, "schema_failures": 0}, "SCORE_GAP"),
            ({"eligible_candidates": 1, "score_gap_ppm": 999999, "reviewer_conflict": True, "risk_disagreements": 0, "schema_failures": 0}, "REVIEWER_CONFLICT"),
            ({"eligible_candidates": 1, "score_gap_ppm": 999999, "reviewer_conflict": False, "risk_disagreements": 1, "schema_failures": 0}, "RISK_DISAGREEMENT"),
            ({"eligible_candidates": 1, "score_gap_ppm": 999999, "reviewer_conflict": False, "risk_disagreements": 0, "schema_failures": 2}, "SCHEMA_FAILURES"),
        )
        for values, reason in cases:
            with self.subTest(reason=reason):
                result = policy.decide(**values)
                self.assertTrue(result.triggered)
                self.assertIn(reason, result.reasons)
                self.assertEqual((result.schema, result.version), ("SITINA_ARBITRATION_TRIGGER_DECISION_V1", "1.0"))
        clean = policy.decide(eligible_candidates=1, score_gap_ppm=999999, reviewer_conflict=False, risk_disagreements=0, schema_failures=0)
        self.assertFalse(clean.triggered)

    def test_pr09_arbiter_prefers_distinct_profile_model_and_truthfully_labels_context_only_fallback(self) -> None:
        policy = ArbiterIsolationPolicy()
        distinct = policy.select(author_pairs=(("author", "model-a"),), reviewer_pairs=(("review", "model-b"),), available_pairs=(("arbiter", "model-c"),))
        fallback = policy.select(author_pairs=(("shared", "model-a"),), reviewer_pairs=(("shared", "model-a"),), available_pairs=(("shared", "model-a"),))
        self.assertEqual(distinct.isolation_level, "model-profile-independent")
        self.assertEqual(fallback.isolation_level, "context-independent-only")
        self.assertIn("only", fallback.claim)

    def test_pr10_block_recovery_distinguishes_bounded_rework_user_authorization_and_terminal_without_loops(self) -> None:
        policy = BlockRecoveryPolicy(maximum_rework_attempts=2)
        self.assertEqual(policy.decide(block_type="repairable", attempt=0, checkpoint_ref=DIGEST_A).action, "rework")
        self.assertEqual(policy.decide(block_type="repairable", attempt=2, checkpoint_ref=DIGEST_A).action, "terminate")
        self.assertEqual(policy.decide(block_type="authorization", attempt=0, checkpoint_ref=DIGEST_A).action, "ask-user")
        self.assertEqual(policy.decide(block_type="terminal", attempt=0, checkpoint_ref=DIGEST_A).action, "terminate")

    def test_pr11_resumable_ask_user_exposes_options_reason_risk_budget_safe_timeout_and_hash_bound_answer(self) -> None:
        manager = AskUserManager()
        request = manager.create(
            request_id="ask-1",
            run_id="run-1",
            decision_hash=DIGEST_A,
            options=("approve", "deny"),
            reasons=("scope expansion requires authority",),
            risks=("external side effect",),
            budget_tokens=500,
            timeout_seconds=30,
            safe_default="deny",
        )
        answered = manager.answer(request, "approve")
        timed_out = manager.timeout(request)
        self.assertEqual(answered.status, "answered")
        self.assertEqual(len(answered.answer_binding_hash or ""), 64)
        self.assertEqual((timed_out.status, timed_out.answer), ("timed-out", "deny"))
        self.assertNotEqual(answered.answer_binding_hash, timed_out.answer_binding_hash)

    def test_pr12_shared_context_per_candidate_and_total_budgets_stop_on_hard_limit_or_low_marginal_value(self) -> None:
        allocator = ProposalBudgetAllocator(immutable_context_ref=DIGEST_A, total_budget=200, per_candidate_budget=150, minimum_marginal_value_ppm=100000)
        first = allocator.admit(estimated_tokens=120, marginal_value_ppm=500000)
        second = allocator.admit(estimated_tokens=120, marginal_value_ppm=500000)
        marginal = allocator.admit(estimated_tokens=10, marginal_value_ppm=99999)
        self.assertTrue(first.admitted)
        self.assertFalse(second.admitted)
        self.assertEqual(second.reason, "hard budget limit")
        self.assertEqual(marginal.reason, "marginal value stop")
        self.assertEqual(allocator.immutable_context_ref, DIGEST_A)

    def test_pr13_conflict_free_reviews_really_overlap_aggregate_stably_and_obey_concurrency_limit(self) -> None:
        barrier = threading.Barrier(2)

        def review(reviewer_id):
            barrier.wait(timeout=2)
            return f"result-{reviewer_id}"

        executor = ParallelReviewExecutor()
        result = executor.run(
            ("reviewer-b", "reviewer-a"),
            review,
            maximum_concurrency=2,
            resource_claims={"reviewer-a": ("read:artifact",), "reviewer-b": ("read:artifact",)},
        )
        self.assertEqual(result.results, (("reviewer-a", "result-reviewer-a"), ("reviewer-b", "result-reviewer-b")))
        self.assertEqual(result.peak_concurrency, 2)
        self.assertLess(max(result.intervals[item][0] for item in result.intervals), min(result.intervals[item][1] for item in result.intervals))
        with self.assertRaises(ValueError):
            executor.run(
                ("reviewer-a", "reviewer-b"),
                lambda reviewer_id: reviewer_id,
                maximum_concurrency=2,
                resource_claims={"reviewer-a": ("write:artifact",), "reviewer-b": ("read:artifact",)},
            )

    def test_pr14_deadline_cancels_and_isolates_late_reviews_then_requires_quorum_or_arbitration(self) -> None:
        coordinator = ReviewDeadlineCoordinator()
        release = threading.Event()
        quorum = coordinator.collect(
            "review-1",
            {"fast": lambda: "accept", "late": lambda: release.wait(timeout=1) or "late"},
            timeout_seconds=0.02,
            minimum_quorum=1,
        )
        self.assertEqual(quorum.status, "quorum")
        self.assertEqual(quorum.timed_out_reviewers, ("late",))
        self.assertFalse(coordinator.accept_late("review-1", "late", "accept"))
        release.set()
        release_two = threading.Event()
        arbitration = coordinator.collect(
            "review-2",
            {"fast": lambda: "accept", "late": lambda: release_two.wait(timeout=1) or "late"},
            timeout_seconds=0.02,
            minimum_quorum=2,
        )
        release_two.set()
        self.assertEqual(arbitration.status, "arbitration")

    def test_pr15_cache_requires_exact_normalized_policy_model_prompt_permission_tenant_and_safe_candidate(self) -> None:
        cache = ProposalCache()
        candidate = _candidate("proposal-a")
        key = ProposalCacheKey("tenant-a", DIGEST_A, DIGEST_B, "model-a", DIGEST_C, DIGEST_D)
        self.assertTrue(cache.put(key, candidate))
        self.assertEqual(cache.get(key), candidate)
        self.assertIsNone(cache.get(ProposalCacheKey("tenant-a", DIGEST_A, DIGEST_A, "model-a", DIGEST_C, DIGEST_D)))
        self.assertIsNone(cache.get(ProposalCacheKey("tenant-b", DIGEST_A, DIGEST_B, "model-a", DIGEST_C, DIGEST_D)))
        self.assertFalse(cache.put(key, _candidate("proposal-sensitive", sensitive=True)))
        self.assertFalse(cache.put(key, _candidate("proposal-effect", side_effect_free=False)))
        self.assertFalse(cache.put(key, _candidate("proposal-secret", content="password=hunter2")))

    def test_pr16_review_quality_validates_schema_reason_evidence_anomalies_and_bias_for_recheck_or_arbitration(self) -> None:
        gate = ReviewQualityGate()
        valid = _evaluation("eval-good", "proposal-a").model_dump(by_alias=True)
        self.assertEqual(gate.assess(valid, allowed_evidence_refs=(DIGEST_A,), candidate_author_id="author").action, "accept")
        self.assertEqual(gate.assess({"bad": True}, allowed_evidence_refs=(), candidate_author_id="author").action, "second-validation")
        biased = _evaluation("eval-bad", "proposal-a", evaluator="author", evidence=(DIGEST_B,), reason="short reason").model_dump(by_alias=True)
        biased["scores"]["correctness"] = 100
        biased["scores"]["latency"] = 0
        decision = gate.assess(biased, allowed_evidence_refs=(DIGEST_A,), candidate_author_id="author")
        self.assertEqual(decision.action, "arbitration")
        self.assertIn("SELF_REVIEW_BIAS", decision.issues)
        self.assertIn("EVIDENCE_MISMATCH", decision.issues)


if __name__ == "__main__":
    unittest.main()
