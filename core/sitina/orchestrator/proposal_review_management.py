"""Policy controls over the existing Proposal, Review, and Arbitration owners."""

from __future__ import annotations

import hashlib
import re
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from pydantic import Field, model_validator

from sitina.schemas.models import StrictModel
from sitina.security.redaction import redact_text
from sitina.utils import stable_json


RiskLevel = Literal["low", "medium", "high", "critical"]
RUBRIC_DIMENSIONS = (
    "correctness",
    "safety",
    "completeness",
    "evidence",
    "implementability",
    "cost",
    "latency",
)


def _digest(value: str, field_name: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{field_name} must be a sha256 digest")
    return value


def _hash_payload(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _normalized_terms(value: str) -> frozenset[str]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = re.sub(r"[^\w\u3400-\u9fff]+", " ", normalized)
    return frozenset(term for term in normalized.split() if term)


class ProposalCandidate(StrictModel):
    schema_id: Literal["SITINA_PROPOSAL_CANDIDATE_V1"] = Field(default="SITINA_PROPOSAL_CANDIDATE_V1", alias="schema")
    version: Literal["1.0"] = "1.0"
    proposal_id: str
    author_id: str
    strategy: str
    assumptions: list[str]
    risk_focus: list[str]
    content: str
    immutable_context_ref: str
    policy_hash: str
    model_id: str
    prompt_hash: str
    permission_hash: str
    tenant_id: str
    estimated_tokens: int = Field(gt=0)
    side_effect_free: bool = True
    sensitive: bool = False

    @model_validator(mode="after")
    def validate_candidate(self) -> "ProposalCandidate":
        if not all((self.proposal_id, self.author_id, self.strategy, self.assumptions, self.risk_focus, self.content, self.model_id, self.tenant_id)):
            raise ValueError("proposal candidate requires identity, strategy, assumptions, risk focus and content")
        for name in ("immutable_context_ref", "policy_hash", "prompt_hash", "permission_hash"):
            _digest(getattr(self, name), name)
        return self


@dataclass(frozen=True)
class DiversityDecision:
    accepted: tuple[str, ...]
    rejected: Mapping[str, str]
    pair_similarity_ppm: Mapping[str, int]
    action: Literal["accept", "regenerate", "degrade"]


class ProposalDiversityGate:
    def __init__(self, *, maximum_similarity_ppm: int = 700_000, maximum_regenerations: int = 1):
        self.maximum_similarity_ppm = maximum_similarity_ppm
        self.maximum_regenerations = maximum_regenerations

    @staticmethod
    def similarity(left: ProposalCandidate, right: ProposalCandidate) -> int:
        left_terms = _normalized_terms(" ".join((left.strategy, *left.assumptions, *left.risk_focus, left.content)))
        right_terms = _normalized_terms(" ".join((right.strategy, *right.assumptions, *right.risk_focus, right.content)))
        union = left_terms | right_terms
        return int(len(left_terms & right_terms) * 1_000_000 / len(union)) if union else 1_000_000

    def evaluate(self, candidates: Sequence[ProposalCandidate], *, regeneration_count: int = 0) -> DiversityDecision:
        accepted: list[ProposalCandidate] = []
        rejected: dict[str, str] = {}
        metrics: dict[str, int] = {}
        for candidate in sorted(candidates, key=lambda item: item.proposal_id):
            duplicate = None
            for prior in accepted:
                similarity = self.similarity(prior, candidate)
                metrics[f"{prior.proposal_id}:{candidate.proposal_id}"] = similarity
                same_basis = (
                    prior.strategy.casefold() == candidate.strategy.casefold()
                    and set(prior.assumptions) == set(candidate.assumptions)
                    and set(prior.risk_focus) == set(candidate.risk_focus)
                )
                if same_basis or similarity >= self.maximum_similarity_ppm:
                    duplicate = prior.proposal_id
                    break
            if duplicate:
                rejected[candidate.proposal_id] = f"NEAR_DUPLICATE:{duplicate}"
            else:
                accepted.append(candidate)
        if rejected:
            action: Literal["accept", "regenerate", "degrade"] = "regenerate" if regeneration_count < self.maximum_regenerations else "degrade"
        else:
            action = "accept"
        return DiversityDecision(tuple(item.proposal_id for item in accepted), rejected, metrics, action)


@dataclass(frozen=True)
class CountDecision:
    status: Literal["competition-ready", "insufficient", "budget-blocked"]
    minimum: int
    maximum: int
    admitted: int
    reason: str


class ProposalCountPolicy:
    def __init__(self, limits: Mapping[str, Mapping[str, int]]):
        self.limits = limits

    def decide(self, *, risk: RiskLevel, candidate_count: int, total_budget: int, per_candidate_budget: int, multi: bool) -> CountDecision:
        configured = self.limits[risk]
        minimum = int(configured["min"]) if multi else 1
        maximum = min(int(configured["max"]), total_budget // max(1, per_candidate_budget))
        admitted = min(candidate_count, maximum)
        if maximum < minimum:
            return CountDecision("budget-blocked", minimum, maximum, admitted, "budget cannot fund the required minimum")
        if admitted < minimum:
            return CountDecision("insufficient", minimum, maximum, admitted, "candidate minimum is not satisfied")
        return CountDecision("competition-ready", minimum, maximum, admitted, "candidate count satisfies policy")


@dataclass(frozen=True)
class CompetitionDecision:
    action: Literal["compete", "hot-path", "budget-blocked"]
    reason: str


class CompetitionAdmission:
    def decide(self, *, task_type: str, complexity: int, risk: RiskLevel, total_budget: int, minimum_cost: int, hot_path_safe: bool) -> CompetitionDecision:
        if task_type == "chat" and hot_path_safe and complexity < 25 and risk == "low":
            return CompetitionDecision("hot-path", "simple low-risk chat is route-equivalent")
        if total_budget < minimum_cost:
            return CompetitionDecision("budget-blocked", "competition minimum cost is not funded")
        return CompetitionDecision("compete", f"{task_type} admitted by complexity/risk/budget")


@dataclass(frozen=True)
class EvaluatorIsolationPlan:
    evaluator_id: str
    isolation_level: Literal["model-profile-independent", "context-role-sampling-independent"]
    evaluator_profile: str
    evaluator_model: str
    sampling_nonce: str
    payload: Mapping[str, Any]


class EvaluationIsolation:
    def prepare(
        self,
        candidate: ProposalCandidate,
        *,
        evaluator_id: str,
        evaluator_profile: str,
        evaluator_model: str,
        author_profile: str,
        author_model: str,
        original_requirements_ref: str,
    ) -> EvaluatorIsolationPlan:
        if evaluator_id == candidate.author_id:
            raise PermissionError("proposal self-evaluation is forbidden")
        independent_model = (evaluator_profile, evaluator_model) != (author_profile, author_model)
        level: Literal["model-profile-independent", "context-role-sampling-independent"] = (
            "model-profile-independent" if independent_model else "context-role-sampling-independent"
        )
        payload = {
            "schema": "SITINA_ANONYMIZED_EVALUATION_INPUT_V1",
            "proposal_id": candidate.proposal_id,
            "strategy": candidate.strategy,
            "assumptions": tuple(candidate.assumptions),
            "risk_focus": tuple(candidate.risk_focus),
            "content": candidate.content,
            "immutable_context_ref": candidate.immutable_context_ref,
            "original_requirements_ref": _digest(original_requirements_ref, "original_requirements_ref"),
        }
        nonce = _hash_payload({"proposal": candidate.proposal_id, "evaluator": evaluator_id, "profile": evaluator_profile, "model": evaluator_model})
        return EvaluatorIsolationPlan(evaluator_id, level, evaluator_profile, evaluator_model, nonce, payload)


class EvaluationRubric(StrictModel):
    schema_id: Literal["SITINA_EVALUATION_RUBRIC_V1"] = Field(default="SITINA_EVALUATION_RUBRIC_V1", alias="schema")
    version: str
    weights_ppm: dict[str, int]
    hard_gates: list[str]

    @model_validator(mode="after")
    def validate_rubric(self) -> "EvaluationRubric":
        if set(self.weights_ppm) != set(RUBRIC_DIMENSIONS) or sum(self.weights_ppm.values()) != 1_000_000:
            raise ValueError("evaluation rubric dimensions or weights are invalid")
        if not set(self.hard_gates) <= set(RUBRIC_DIMENSIONS):
            raise ValueError("evaluation hard gate is outside the rubric")
        if any(value < 0 for value in self.weights_ppm.values()):
            raise ValueError("evaluation rubric weights must be non-negative")
        return self


class ScoredEvaluation(StrictModel):
    schema_id: Literal["SITINA_SCORED_EVALUATION_V1"] = Field(default="SITINA_SCORED_EVALUATION_V1", alias="schema")
    version: Literal["1.0"] = "1.0"
    evaluation_id: str
    proposal_id: str
    evaluator_id: str
    scores: dict[str, int]
    hard_gate_pass: dict[str, bool]
    confidence_ppm: int = Field(ge=0, le=1_000_000)
    reason: str
    evidence_refs: list[str]
    model_version: str
    policy_version: str

    @model_validator(mode="after")
    def validate_scores(self) -> "ScoredEvaluation":
        if set(self.scores) != set(RUBRIC_DIMENSIONS) or any(not 0 <= value <= 100 for value in self.scores.values()):
            raise ValueError("evaluation scores must contain every rubric dimension in range")
        if not self.reason or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in self.evidence_refs):
            raise ValueError("evaluation requires a reason and canonical evidence references")
        return self


@dataclass(frozen=True)
class SelectionDecision:
    schema: str
    version: str
    selected_proposal_id: str | None
    normalized_scores_ppm: Mapping[str, int]
    rejected: Mapping[str, str]
    disagreement_ppm: Mapping[str, int]
    reason: str


class ProposalSelectionEngine:
    def select(self, proposal_ids: Iterable[str], evaluations: Sequence[ScoredEvaluation], rubric: EvaluationRubric) -> SelectionDecision:
        by_proposal: dict[str, list[ScoredEvaluation]] = {}
        for evaluation in evaluations:
            by_proposal.setdefault(evaluation.proposal_id, []).append(evaluation)
        scores: dict[str, int] = {}
        disagreement: dict[str, int] = {}
        rejected: dict[str, str] = {}
        for proposal_id in sorted(set(proposal_ids)):
            items = by_proposal.get(proposal_id, [])
            if not items:
                rejected[proposal_id] = "MISSING_EVALUATION"
                continue
            if any(not all(item.hard_gate_pass.get(gate, False) for gate in rubric.hard_gates) for item in items):
                rejected[proposal_id] = "HARD_GATE_FAILED"
                continue
            weighted = []
            for item in items:
                raw = sum(item.scores[name] * rubric.weights_ppm[name] for name in RUBRIC_DIMENSIONS) // 100
                weighted.append(raw * item.confidence_ppm // 1_000_000)
            scores[proposal_id] = sum(weighted) // len(weighted)
            disagreement[proposal_id] = max(weighted) - min(weighted) if len(weighted) > 1 else 0
        selected = sorted(scores, key=lambda proposal_id: (-scores[proposal_id], disagreement[proposal_id], proposal_id))[0] if scores else None
        return SelectionDecision(
            "SITINA_PROPOSAL_SELECTION_V1",
            "1.0",
            selected,
            scores,
            rejected,
            disagreement,
            f"selected {selected} after hard gates and normalized stable ranking" if selected else "no eligible proposal",
        )


class RejectionRecord(StrictModel):
    schema_id: Literal["SITINA_PROPOSAL_REJECTION_V1"] = Field(default="SITINA_PROPOSAL_REJECTION_V1", alias="schema")
    version: Literal["1.0"] = "1.0"
    proposal_id: str
    reason_code: str
    rubric_details: dict[str, int]
    evidence_refs: list[str]
    repair_suggestions: list[str]
    model_version: str
    policy_version: str
    redacted: Literal[True] = True

    @classmethod
    def create(cls, evaluation: ScoredEvaluation, *, reason_code: str, suggestions: Sequence[str]) -> "RejectionRecord":
        return cls(
            proposal_id=evaluation.proposal_id,
            reason_code=reason_code,
            rubric_details=dict(evaluation.scores),
            evidence_refs=list(evaluation.evidence_refs),
            repair_suggestions=[redact_text(item) for item in suggestions],
            model_version=evaluation.model_version,
            policy_version=evaluation.policy_version,
        )


@dataclass(frozen=True)
class ArbitrationTriggerDecision:
    triggered: bool
    reasons: tuple[str, ...]
    schema: str = "SITINA_ARBITRATION_TRIGGER_DECISION_V1"
    version: str = "1.0"


class ArbitrationTriggerPolicy:
    def __init__(self, *, maximum_score_gap_ppm: int, schema_failure_threshold: int, risk_disagreement_threshold: int):
        self.maximum_score_gap_ppm = maximum_score_gap_ppm
        self.schema_failure_threshold = schema_failure_threshold
        self.risk_disagreement_threshold = risk_disagreement_threshold

    def decide(
        self,
        *,
        eligible_candidates: int,
        score_gap_ppm: int,
        reviewer_conflict: bool,
        risk_disagreements: int,
        schema_failures: int,
    ) -> ArbitrationTriggerDecision:
        reasons = []
        if eligible_candidates == 0:
            reasons.append("NO_ELIGIBLE_CANDIDATE")
        if eligible_candidates >= 2 and score_gap_ppm <= self.maximum_score_gap_ppm:
            reasons.append("SCORE_GAP")
        if reviewer_conflict:
            reasons.append("REVIEWER_CONFLICT")
        if risk_disagreements >= self.risk_disagreement_threshold:
            reasons.append("RISK_DISAGREEMENT")
        if schema_failures >= self.schema_failure_threshold:
            reasons.append("SCHEMA_FAILURES")
        return ArbitrationTriggerDecision(bool(reasons), tuple(reasons))


@dataclass(frozen=True)
class ArbiterIsolationPlan:
    profile: str
    model: str
    isolation_level: Literal["model-profile-independent", "context-independent-only"]
    claim: str
    schema: str = "SITINA_ARBITER_ISOLATION_PLAN_V1"
    version: str = "1.0"


class ArbiterIsolationPolicy:
    def select(self, *, author_pairs: Iterable[tuple[str, str]], reviewer_pairs: Iterable[tuple[str, str]], available_pairs: Sequence[tuple[str, str]]) -> ArbiterIsolationPlan:
        if not available_pairs:
            raise ValueError("no arbiter profile/model is available")
        occupied = set(author_pairs) | set(reviewer_pairs)
        independent = next((pair for pair in available_pairs if pair not in occupied), None)
        if independent:
            return ArbiterIsolationPlan(*independent, "model-profile-independent", "arbiter uses a distinct profile/model")
        fallback = available_pairs[0]
        return ArbiterIsolationPlan(*fallback, "context-independent-only", "same provider/model; only role, context and sampling are isolated")


@dataclass(frozen=True)
class RecoveryDecision:
    action: Literal["rework", "ask-user", "terminate"]
    attempt: int
    checkpoint_ref: str
    reason: str


class BlockRecoveryPolicy:
    def __init__(self, *, maximum_rework_attempts: int):
        self.maximum_rework_attempts = maximum_rework_attempts

    def decide(self, *, block_type: Literal["repairable", "authorization", "terminal"], attempt: int, checkpoint_ref: str) -> RecoveryDecision:
        _digest(checkpoint_ref, "checkpoint_ref")
        if attempt < 0:
            raise ValueError("recovery attempt must be non-negative")
        if block_type == "repairable" and attempt < self.maximum_rework_attempts:
            return RecoveryDecision("rework", attempt + 1, checkpoint_ref, "bounded repairable rework")
        if block_type == "authorization":
            return RecoveryDecision("ask-user", attempt, checkpoint_ref, "explicit user authorization is required")
        return RecoveryDecision("terminate", attempt, checkpoint_ref, "terminal or exhausted recovery")


class AskUserRequest(StrictModel):
    schema_id: Literal["SITINA_ASK_USER_REQUEST_V1"] = Field(default="SITINA_ASK_USER_REQUEST_V1", alias="schema")
    version: Literal["1.0"] = "1.0"
    request_id: str
    run_id: str
    decision_hash: str
    options: list[str]
    reasons: list[str]
    risks: list[str]
    budget_tokens: int = Field(ge=0)
    timeout_seconds: int = Field(gt=0)
    safe_default: str
    status: Literal["pending", "answered", "timed-out"] = "pending"
    answer: str | None = None
    answer_binding_hash: str | None = None

    @model_validator(mode="after")
    def validate_request(self) -> "AskUserRequest":
        _digest(self.decision_hash, "decision_hash")
        if not self.options or self.safe_default not in self.options or not self.reasons or not self.risks:
            raise ValueError("ask-user requires options, reasons, risks and a safe default")
        return self


class AskUserManager:
    def create(self, *, request_id: str, run_id: str, decision_hash: str, options: Sequence[str], reasons: Sequence[str], risks: Sequence[str], budget_tokens: int, timeout_seconds: int, safe_default: str) -> AskUserRequest:
        return AskUserRequest(
            request_id=request_id,
            run_id=run_id,
            decision_hash=decision_hash,
            options=list(options),
            reasons=list(reasons),
            risks=list(risks),
            budget_tokens=budget_tokens,
            timeout_seconds=timeout_seconds,
            safe_default=safe_default,
        )

    def answer(self, request: AskUserRequest, answer: str) -> AskUserRequest:
        if request.status != "pending" or answer not in request.options:
            raise ValueError("ask-user answer is invalid or request is terminal")
        binding = _hash_payload({"run_id": request.run_id, "decision_hash": request.decision_hash, "request_id": request.request_id, "answer": answer})
        return request.model_copy(update={"status": "answered", "answer": answer, "answer_binding_hash": binding})

    def timeout(self, request: AskUserRequest) -> AskUserRequest:
        if request.status != "pending":
            raise ValueError("ask-user request is terminal")
        binding = _hash_payload({"run_id": request.run_id, "decision_hash": request.decision_hash, "request_id": request.request_id, "answer": request.safe_default})
        return request.model_copy(update={"status": "timed-out", "answer": request.safe_default, "answer_binding_hash": binding})


@dataclass(frozen=True)
class CandidateBudgetDecision:
    admitted: bool
    spent_tokens: int
    remaining_tokens: int
    reason: str


class ProposalBudgetAllocator:
    def __init__(self, *, immutable_context_ref: str, total_budget: int, per_candidate_budget: int, minimum_marginal_value_ppm: int):
        _digest(immutable_context_ref, "immutable_context_ref")
        if min(total_budget, per_candidate_budget) <= 0 or not 0 <= minimum_marginal_value_ppm <= 1_000_000:
            raise ValueError("proposal budget configuration is invalid")
        self.immutable_context_ref = immutable_context_ref
        self.total_budget = total_budget
        self.per_candidate_budget = per_candidate_budget
        self.minimum_marginal_value_ppm = minimum_marginal_value_ppm
        self.spent = 0

    def admit(self, *, estimated_tokens: int, marginal_value_ppm: int) -> CandidateBudgetDecision:
        if marginal_value_ppm < self.minimum_marginal_value_ppm:
            return CandidateBudgetDecision(False, self.spent, self.total_budget - self.spent, "marginal value stop")
        if estimated_tokens > self.per_candidate_budget or self.spent + estimated_tokens > self.total_budget:
            return CandidateBudgetDecision(False, self.spent, self.total_budget - self.spent, "hard budget limit")
        self.spent += estimated_tokens
        return CandidateBudgetDecision(True, self.spent, self.total_budget - self.spent, "candidate admitted")


@dataclass(frozen=True)
class ParallelReviewResult:
    results: tuple[tuple[str, Any], ...]
    intervals: Mapping[str, tuple[float, float]]
    peak_concurrency: int


class ParallelReviewExecutor:
    @staticmethod
    def _assert_no_write_conflicts(resource_claims: Mapping[str, Sequence[str]]) -> None:
        reviewers = sorted(resource_claims)
        for index, left in enumerate(reviewers):
            left_claims = [(item.split(":", 1)[0], item.split(":", 1)[-1]) for item in resource_claims[left]]
            for right in reviewers[index + 1 :]:
                right_claims = [(item.split(":", 1)[0], item.split(":", 1)[-1]) for item in resource_claims[right]]
                if any(path_a == path_b and "write" in {mode_a, mode_b} for mode_a, path_a in left_claims for mode_b, path_b in right_claims):
                    raise ValueError(f"parallel review write conflict: {left}:{right}")

    def run(
        self,
        reviewer_ids: Sequence[str],
        review: Callable[[str], Any],
        *,
        maximum_concurrency: int,
        resource_claims: Mapping[str, Sequence[str]] | None = None,
    ) -> ParallelReviewResult:
        if resource_claims:
            self._assert_no_write_conflicts(resource_claims)
        lock = threading.Lock()
        active = 0
        peak = 0
        intervals: dict[str, tuple[float, float]] = {}

        def execute(reviewer_id: str) -> tuple[str, Any]:
            nonlocal active, peak
            started = time.monotonic()
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                return reviewer_id, review(reviewer_id)
            finally:
                ended = time.monotonic()
                with lock:
                    active -= 1
                    intervals[reviewer_id] = (started, ended)

        with ThreadPoolExecutor(max_workers=maximum_concurrency) as pool:
            results = [future.result() for future in [pool.submit(execute, reviewer_id) for reviewer_id in reviewer_ids]]
        return ParallelReviewResult(tuple(sorted(results)), intervals, peak)


@dataclass(frozen=True)
class ReviewDeadlineResult:
    status: Literal["quorum", "arbitration"]
    accepted_results: tuple[tuple[str, Any], ...]
    timed_out_reviewers: tuple[str, ...]


class ReviewDeadlineCoordinator:
    def __init__(self) -> None:
        self._closed: set[str] = set()

    def collect(self, review_id: str, reviewers: Mapping[str, Callable[[], Any]], *, timeout_seconds: float, minimum_quorum: int) -> ReviewDeadlineResult:
        pool = ThreadPoolExecutor(max_workers=max(1, len(reviewers)))
        futures = {pool.submit(callback): reviewer_id for reviewer_id, callback in reviewers.items()}
        done, not_done = wait(futures, timeout=timeout_seconds)
        results = tuple(sorted((futures[future], future.result()) for future in done if future.exception() is None))
        timed_out = tuple(sorted(futures[future] for future in not_done))
        for future in not_done:
            future.cancel()
        self._closed.add(review_id)
        pool.shutdown(wait=False, cancel_futures=True)
        return ReviewDeadlineResult("quorum" if len(results) >= minimum_quorum else "arbitration", results, timed_out)

    def accept_late(self, review_id: str, reviewer_id: str, _result: Any) -> bool:
        return review_id not in self._closed


@dataclass(frozen=True)
class ProposalCacheKey:
    tenant_id: str
    normalized_input_hash: str
    policy_hash: str
    model_id: str
    prompt_hash: str
    permission_hash: str


class ProposalCache:
    def __init__(self) -> None:
        self._entries: dict[ProposalCacheKey, ProposalCandidate] = {}

    def put(self, key: ProposalCacheKey, candidate: ProposalCandidate) -> bool:
        for name in ("normalized_input_hash", "policy_hash", "prompt_hash", "permission_hash"):
            _digest(getattr(key, name), name)
        contains_sensitive_text = redact_text(candidate.content) != candidate.content
        if candidate.tenant_id != key.tenant_id or not candidate.side_effect_free or candidate.sensitive or contains_sensitive_text:
            return False
        if (candidate.policy_hash, candidate.model_id, candidate.prompt_hash, candidate.permission_hash) != (key.policy_hash, key.model_id, key.prompt_hash, key.permission_hash):
            return False
        self._entries[key] = candidate
        return True

    def get(self, key: ProposalCacheKey) -> ProposalCandidate | None:
        return self._entries.get(key)


@dataclass(frozen=True)
class ReviewQualityDecision:
    action: Literal["accept", "second-validation", "arbitration"]
    issues: tuple[str, ...]


class ReviewQualityGate:
    def assess(self, raw: Mapping[str, Any], *, allowed_evidence_refs: Iterable[str], candidate_author_id: str) -> ReviewQualityDecision:
        try:
            evaluation = ScoredEvaluation.model_validate(raw)
        except Exception:  # noqa: BLE001
            return ReviewQualityDecision("second-validation", ("SCHEMA_INVALID",))
        issues = []
        if evaluation.evaluator_id == candidate_author_id:
            issues.append("SELF_REVIEW_BIAS")
        if not set(evaluation.evidence_refs) <= set(allowed_evidence_refs):
            issues.append("EVIDENCE_MISMATCH")
        if max(evaluation.scores.values()) - min(evaluation.scores.values()) >= 90:
            issues.append("ANOMALOUS_SCORE_SPREAD")
        if len(evaluation.reason.strip()) < 12:
            issues.append("REASON_TOO_SHALLOW")
        if len(issues) >= 2:
            return ReviewQualityDecision("arbitration", tuple(issues))
        if issues:
            return ReviewQualityDecision("second-validation", tuple(issues))
        return ReviewQualityDecision("accept", ())
