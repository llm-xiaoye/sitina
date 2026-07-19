"""Versioned, deterministic routing policy primitives.

Provider classification is optional and can only resolve a configured local
ambiguity band.  Safety, permission, budget, and high-risk decisions remain
code-owned boundaries.
"""

from __future__ import annotations

import hashlib
import re
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from sitina.conversation.models import ChatMode, RouteDecision
from sitina.journal.model import canonical_json_bytes


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TRADITIONAL = str.maketrans(
    {
        "較": "较",
        "審": "审",
        "閱": "阅",
        "獨": "独",
        "驗": "验",
        "證": "证",
        "規": "规",
        "劃": "划",
        "構": "构",
        "實": "实",
        "風": "风",
        "險": "险",
        "療": "疗",
        "訴": "诉",
        "訟": "讼",
        "財": "财",
        "務": "务",
        "與": "与",
        "後": "后",
        "續": "续",
        "這": "这",
        "個": "个",
        "還": "还",
        "麼": "么",
    }
)


def normalize_intent_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).translate(_TRADITIONAL).casefold()
    normalized = re.sub(r"[\s\u3000]+", " ", normalized)
    normalized = re.sub(r"(?<=[\u3400-\u9fff])\s+(?=[\u3400-\u9fff])", "", normalized)
    return re.sub(r"[，。！？；：、,.!?;:]+", " ", normalized).strip()


def _contains(text: str, markers: Sequence[str]) -> bool:
    return any(normalize_intent_text(marker) in text for marker in markers)


@dataclass(frozen=True)
class RoutingSignals:
    goal_count: int
    dependency_edges: int
    risk: str
    tool_classes: tuple[str, ...]
    side_effect_classes: tuple[str, ...]
    context_tokens: int
    ambiguity_ppm: int
    artifact_classes: tuple[str, ...]
    prior_complexity_score: int = 0
    follow_up: bool = False

    def __post_init__(self) -> None:
        if self.goal_count < 1 or self.dependency_edges < 0 or self.context_tokens < 0:
            raise ValueError("routing signal counts are invalid")
        if self.risk not in RISK_ORDER:
            raise ValueError("routing signal risk is invalid")
        if not 0 <= self.ambiguity_ppm <= 1_000_000:
            raise ValueError("routing ambiguity must be between zero and one million ppm")
        if not 0 <= self.prior_complexity_score <= 100:
            raise ValueError("prior routing complexity must be between zero and one hundred")

    @classmethod
    def infer(
        cls,
        message: str,
        *,
        context_tokens: int,
        prior_complexity_score: int = 0,
        inherit_history: bool = False,
    ) -> "RoutingSignals":
        text = normalize_intent_text(message)
        clause_source = unicodedata.normalize("NFKC", message).translate(_TRADITIONAL).casefold()
        clauses = [
            item.strip()
            for item in re.split(r"(?:[，。！？；,.!?;]+|\band\b|\bthen\b|以及|同时|并且|然后|并)", clause_source)
            if item.strip()
        ]
        goal_count = min(5, max(1, len(clauses)))
        tool_concepts = {
            "filesystem": ("文件", "目录", "filesystem", "file "),
            "command": ("命令", "shell", "terminal", "cli"),
            "network": ("网络", "http", "api", "mcp", "web"),
            "database": ("数据库", "sqlite", "sql", "database"),
        }
        effect_concepts = {
            "write": ("写入", "修改", "编辑", "create", "write", "update"),
            "delete": ("删除", "移除", "delete", "remove"),
            "publish": ("发布", "部署", "发送", "publish", "deploy", "send"),
        }
        artifact_concepts = {
            "code": ("代码", "实现", "code", "implementation"),
            "test": ("测试", "验收", "test", "acceptance"),
            "docs": ("文档", "说明", "documentation", "runbook"),
            "design": ("架构图", "设计", "architecture", "diagram"),
            "migration": ("迁移", "回滚", "migration", "rollback"),
        }
        tools = tuple(sorted(name for name, markers in tool_concepts.items() if _contains(text, markers)))
        effects = tuple(sorted(name for name, markers in effect_concepts.items() if _contains(text, markers)))
        artifacts = tuple(sorted(name for name, markers in artifact_concepts.items() if _contains(text, markers)))
        high = ("医疗", "法律", "诉讼", "投资建议", "财务建议", "安全审计", "medical advice", "legal advice")
        critical = ("真实转账", "生产删除", "private key", "credential export", "不可逆")
        risk = "critical" if _contains(text, critical) else "high" if _contains(text, high) else "medium" if effects else "low"
        uncertainty = (
            "不确定",
            "可能原因",
            "多个原因",
            "歧义",
            "看情况",
            "uncertain",
            "multiple causes",
            "ambiguous",
        )
        ambiguity_ppm = 650_000 if _contains(text, uncertainty) else 0
        dependency_edges = min(
            6,
            max(0, len(artifacts) - 1)
            if _contains(text, ("依赖", "先", "再", "同时", "together", "depends", "then"))
            else 0,
        )
        follow_up = inherit_history and (
            len(text) <= 80
            or _contains(text, ("继续", "接着", "那", "这个呢", "基于前面", "follow up", "continue", "what about"))
        )
        return cls(
            goal_count,
            dependency_edges,
            risk,
            tools,
            effects,
            context_tokens,
            ambiguity_ppm,
            artifacts,
            prior_complexity_score,
            follow_up,
        )


@dataclass(frozen=True)
class ComplexityAssessment:
    version: str
    total: int
    band: str
    components: Mapping[str, int]
    reason_codes: tuple[str, ...]

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTE_COMPLEXITY_V1",
            "version": self.version,
            "total": self.total,
            "band": self.band,
            "components": dict(self.components),
            "reason_codes": list(self.reason_codes),
        }


class ComplexityScorer:
    version = "complexity-score-1.0"

    def __init__(self, *, boundary_threshold: int = 35, complex_threshold: int = 65):
        if not 0 < boundary_threshold < complex_threshold <= 100:
            raise ValueError("complexity thresholds are invalid")
        self.boundary_threshold = boundary_threshold
        self.complex_threshold = complex_threshold

    def assess(self, signals: RoutingSignals) -> ComplexityAssessment:
        components = {
            "goals": min(15, max(0, signals.goal_count - 1) * 5),
            "dependencies": min(20, signals.dependency_edges * 8),
            "risk": {"low": 0, "medium": 10, "high": 28, "critical": 40}[signals.risk],
            "tools": min(15, len(signals.tool_classes) * 5),
            "side_effects": min(24, len(signals.side_effect_classes) * 12),
            "context": 15 if signals.context_tokens >= 8_000 else 10 if signals.context_tokens >= 4_000 else 5 if signals.context_tokens >= 1_000 else 0,
            "ambiguity": min(15, signals.ambiguity_ppm * 15 // 1_000_000),
            "artifacts": min(12, max(0, len(signals.artifact_classes) - 1) * 4),
            "history": signals.prior_complexity_score if signals.follow_up else 0,
        }
        total = min(100, sum(value for key, value in components.items() if key != "history"))
        if signals.follow_up:
            total = max(total, signals.prior_complexity_score)
        band = "complex" if total >= self.complex_threshold else "boundary" if total >= self.boundary_threshold else "simple"
        reasons = tuple(key for key, value in components.items() if value > 0)
        return ComplexityAssessment(self.version, total, band, components, reasons)


class ReplaceableIntentClassifier(Protocol):
    def classify(self, payload: Mapping[str, Any], *, repair: bool = False) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class ClassifierGateResult:
    status: str
    route: ChatMode | None
    confidence_ppm: int
    reason_codes: tuple[str, ...]
    physical_call_count: int
    usage_tokens: int
    usage_upper_bound_tokens: int
    repaired_once: bool

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_CLASSIFIER_GATE_RESULT_V1",
            "status": self.status,
            "route": self.route.value if self.route else None,
            "confidence_ppm": self.confidence_ppm,
            "reason_codes": list(self.reason_codes),
            "physical_call_count": self.physical_call_count,
            "usage_tokens": self.usage_tokens,
            "usage_upper_bound_tokens": self.usage_upper_bound_tokens,
            "repaired_once": self.repaired_once,
        }


class ClassifierGate:
    def __init__(
        self,
        classifier: ReplaceableIntentClassifier | None,
        *,
        lower_confidence_ppm: int,
        upper_confidence_ppm: int,
        token_upper_bound: int,
        minimum_latency_ms: int,
    ):
        if not 0 <= lower_confidence_ppm <= upper_confidence_ppm <= 1_000_000:
            raise ValueError("classifier ambiguity interval is invalid")
        if token_upper_bound < 1 or minimum_latency_ms < 1:
            raise ValueError("classifier budget and latency limits must be positive")
        self.classifier = classifier
        self.lower = lower_confidence_ppm
        self.upper = upper_confidence_ppm
        self.token_upper_bound = token_upper_bound
        self.minimum_latency_ms = minimum_latency_ms

    @staticmethod
    def _validate(value: Mapping[str, Any]) -> tuple[ChatMode, int, tuple[str, ...], int]:
        if set(value) != {"schema", "route", "confidence_ppm", "reason_codes", "usage"}:
            raise ValueError("classifier response fields are invalid")
        if value.get("schema") != "SITINA_ROUTE_CLASSIFIER_RESULT_V1":
            raise ValueError("classifier response schema is invalid")
        route = ChatMode(str(value["route"]).upper())
        if route is ChatMode.AUTO:
            raise ValueError("classifier must resolve to FAST or MULTI")
        confidence = int(value["confidence_ppm"])
        reasons = value["reason_codes"]
        usage = value["usage"]
        if not 0 <= confidence <= 1_000_000 or not isinstance(reasons, list) or not all(isinstance(item, str) and item for item in reasons):
            raise ValueError("classifier confidence or reasons are invalid")
        if not isinstance(usage, Mapping) or set(usage) != {"input_tokens", "output_tokens", "total_tokens"}:
            raise ValueError("classifier usage is invalid")
        total = int(usage["total_tokens"])
        if total < 0 or total != int(usage["input_tokens"]) + int(usage["output_tokens"]):
            raise ValueError("classifier usage total is invalid")
        return route, confidence, tuple(reasons[:8]), total

    def evaluate(
        self,
        *,
        local_confidence_ppm: int,
        input_hash: str,
        complexity: ComplexityAssessment,
        budget_remaining_tokens: int,
        latency_remaining_ms: int,
        hard_boundary: bool,
    ) -> ClassifierGateResult:
        if self.classifier is None:
            return ClassifierGateResult("not-configured", None, 0, (), 0, 0, 0, False)
        if hard_boundary:
            return ClassifierGateResult("hard-boundary-local-only", None, 0, (), 0, 0, 0, False)
        if not self.lower <= local_confidence_ppm <= self.upper:
            return ClassifierGateResult("outside-ambiguity-band", None, 0, (), 0, 0, 0, False)
        if budget_remaining_tokens < self.token_upper_bound * 2:
            return ClassifierGateResult("budget-denied", None, 0, (), 0, 0, 0, False)
        if latency_remaining_ms < self.minimum_latency_ms * 2:
            return ClassifierGateResult("sla-denied", None, 0, (), 0, 0, 0, False)
        payload = {
            "schema": "SITINA_ROUTE_CLASSIFIER_INPUT_V1",
            "input_hash": input_hash,
            "complexity": complexity.mapping(),
            "allowed_routes": ["FAST", "MULTI"],
            "permission_override_allowed": False,
        }
        calls = 0
        usage = 0
        first_error: Exception | None = None
        for repaired in (False, True):
            calls += 1
            try:
                raw = self.classifier.classify(payload, repair=repaired)
                route, confidence, reasons, reported_usage = self._validate(raw)
                if reported_usage > self.token_upper_bound:
                    raise ValueError("classifier usage exceeded its admitted upper bound")
            except Exception as error:  # noqa: BLE001
                first_error = first_error or error
                if not repaired:
                    continue
                return ClassifierGateResult(
                    "invalid-fallback",
                    None,
                    0,
                    (type(first_error).__name__,),
                    calls,
                    usage,
                    calls * self.token_upper_bound,
                    True,
                )
            usage += reported_usage
            return ClassifierGateResult(
                "accepted-after-repair" if repaired else "accepted",
                route,
                confidence,
                reasons,
                calls,
                usage,
                calls * self.token_upper_bound,
                repaired,
            )
        raise AssertionError("classifier repair loop is unreachable")


@dataclass(frozen=True)
class RoutingBudgetDecision:
    status: str
    selected_route: ChatMode | None
    fast_upper_tokens: int
    multi_upper_tokens: int
    classifier_upper_tokens: int
    remaining_tokens: int
    review_required: bool

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTING_BUDGET_DECISION_V1",
            "status": self.status,
            "selected_route": self.selected_route.value if self.selected_route else None,
            "fast_upper_tokens": self.fast_upper_tokens,
            "multi_upper_tokens": self.multi_upper_tokens,
            "classifier_upper_tokens": self.classifier_upper_tokens,
            "remaining_tokens": self.remaining_tokens,
            "review_required": self.review_required,
        }


class RoutingBudgetPlanner:
    def __init__(self, *, fast_upper_tokens: int, multi_upper_tokens: int, classifier_upper_tokens: int):
        if min(fast_upper_tokens, multi_upper_tokens, classifier_upper_tokens) < 1:
            raise ValueError("routing token upper bounds must be positive")
        self.fast = fast_upper_tokens
        self.multi = multi_upper_tokens
        self.classifier = classifier_upper_tokens

    def admit(self, preferred: ChatMode, *, remaining_tokens: int, risk: str) -> RoutingBudgetDecision:
        review_required = RISK_ORDER[risk] >= RISK_ORDER["high"]
        if review_required:
            if remaining_tokens < self.multi:
                return RoutingBudgetDecision("blocked-review-budget", None, self.fast, self.multi, self.classifier, remaining_tokens, True)
            return RoutingBudgetDecision("high-risk-review", ChatMode.MULTI, self.fast, self.multi, self.classifier, remaining_tokens, True)
        required = self.multi if preferred is ChatMode.MULTI else self.fast
        if remaining_tokens >= required:
            return RoutingBudgetDecision("admitted", preferred, self.fast, self.multi, self.classifier, remaining_tokens, False)
        if preferred is ChatMode.MULTI and remaining_tokens >= self.fast:
            return RoutingBudgetDecision("budget-fast-candidate", ChatMode.FAST, self.fast, self.multi, self.classifier, remaining_tokens, False)
        return RoutingBudgetDecision("budget-exhausted", None, self.fast, self.multi, self.classifier, remaining_tokens, False)


@dataclass(frozen=True)
class DomainProfile:
    name: str
    version: str
    multi_threshold: int
    risk_floor: str
    rubric: str
    markers: tuple[str, ...]


class DomainProfileRegistry:
    def __init__(self, raw: Mapping[str, Any]):
        self.global_safety_floor = str(raw.get("global_safety_floor") or "high")
        if self.global_safety_floor not in RISK_ORDER:
            raise ValueError("global routing safety floor is invalid")
        profiles = raw.get("domain_profiles")
        if not isinstance(profiles, list) or not profiles:
            raise ValueError("routing policy requires domain profiles")
        self.profiles: dict[str, DomainProfile] = {}
        for item in profiles:
            profile = DomainProfile(
                str(item["name"]),
                str(item["version"]),
                int(item["multi_threshold"]),
                str(item["risk_floor"]),
                str(item["rubric"]),
                tuple(str(value) for value in item.get("markers", ())),
            )
            if not 1 <= profile.multi_threshold <= 100 or profile.risk_floor not in RISK_ORDER:
                raise ValueError("domain routing profile is invalid")
            if RISK_ORDER[profile.risk_floor] < RISK_ORDER[self.global_safety_floor]:
                raise ValueError("domain profile weakens the global safety floor")
            if profile.name in self.profiles:
                raise ValueError("duplicate domain routing profile")
            self.profiles[profile.name] = profile
        if "general" not in self.profiles:
            raise ValueError("general domain routing profile is required")

    def select(self, message: str) -> DomainProfile:
        text = normalize_intent_text(message)
        candidates = [
            profile
            for profile in self.profiles.values()
            if profile.name != "general" and _contains(text, profile.markers)
        ]
        return sorted(candidates, key=lambda item: item.name)[0] if candidates else self.profiles["general"]


@dataclass(frozen=True)
class ExperimentAssignment:
    experiment_id: str
    bucket: str
    policy_version: str
    kill_switch_active: bool
    subject_hash: str

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTING_EXPERIMENT_ASSIGNMENT_V1",
            **self.__dict__,
        }


class ExperimentAssigner:
    def __init__(self, *, experiment_id: str, policy_version: str, treatment_percent: int, kill_switch: bool):
        if not 0 <= treatment_percent <= 100:
            raise ValueError("experiment treatment percent is invalid")
        self.experiment_id = experiment_id
        self.policy_version = policy_version
        self.treatment_percent = treatment_percent
        self.kill_switch = kill_switch

    def assign(self, subject_id: str) -> ExperimentAssignment:
        if not subject_id:
            raise ValueError("experiment subject identity is required")
        digest = hashlib.sha256(f"{self.experiment_id}:{subject_id}".encode()).hexdigest()
        treated = int(digest[:8], 16) % 100 < self.treatment_percent
        bucket = "control" if self.kill_switch else "treatment" if treated else "control"
        return ExperimentAssignment(
            self.experiment_id,
            bucket,
            self.policy_version,
            self.kill_switch,
            hashlib.sha256(subject_id.encode()).hexdigest(),
        )


class ExperimentMetricRecorder:
    def __init__(self, event_sink: Callable[[Mapping[str, Any]], Any] | None = None):
        self.event_sink = event_sink
        self.records: list[dict[str, Any]] = []

    def record(
        self,
        assignment: ExperimentAssignment,
        *,
        outcome: str,
        route: ChatMode,
        latency_ms: int,
        token_usage: int,
    ) -> dict[str, Any]:
        if route is ChatMode.AUTO or min(latency_ms, token_usage) < 0 or not outcome:
            raise ValueError("routing experiment outcome metric is invalid")
        record = {
            "schema": "SITINA_ROUTING_EXPERIMENT_OUTCOME_V1",
            "experiment_id": assignment.experiment_id,
            "policy_version": assignment.policy_version,
            "bucket": assignment.bucket,
            "subject_hash": assignment.subject_hash,
            "outcome": outcome,
            "route": route.value,
            "latency_ms": latency_ms,
            "token_usage": token_usage,
        }
        self.records.append(record)
        if self.event_sink:
            self.event_sink(record)
        return record


class LatencyClass(str, Enum):
    INTERACTIVE = "interactive"
    STANDARD = "standard"
    BATCH = "batch"


@dataclass(frozen=True)
class LatencyDecision:
    latency_class: LatencyClass
    remaining_ms: int
    action: str
    inherited: bool

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTING_LATENCY_DECISION_V1",
            "latency_class": self.latency_class.value,
            "remaining_ms": self.remaining_ms,
            "action": self.action,
            "inherited": self.inherited,
        }


class LatencyPolicy:
    def __init__(self, deadlines_ms: Mapping[str, Any], *, clock: Callable[[], float] = time.monotonic):
        self.deadlines = {LatencyClass(key): int(value) for key, value in deadlines_ms.items()}
        if set(self.deadlines) != set(LatencyClass) or min(self.deadlines.values()) < 1:
            raise ValueError("all latency class deadlines are required")
        self.clock = clock

    def evaluate(
        self,
        latency_class: LatencyClass | None,
        *,
        inherited_class: LatencyClass | None = None,
        started_at: float | None = None,
        high_risk: bool = False,
    ) -> LatencyDecision:
        selected = latency_class or inherited_class or LatencyClass.STANDARD
        inherited = latency_class is None and inherited_class is not None
        start = self.clock() if started_at is None else started_at
        elapsed_ms = max(0, int((self.clock() - start) * 1000))
        remaining = max(0, self.deadlines[selected] - elapsed_ms)
        if remaining == 0:
            action = "fail-closed" if high_risk else "partial-result"
        elif remaining < 500:
            action = "fast-path" if not high_risk else "review-required"
        else:
            action = "normal"
        return LatencyDecision(selected, remaining, action, inherited)


@dataclass(frozen=True)
class DegradationDecision:
    action: str
    reason: str
    independently_reviewed: bool
    original_failure_preserved: bool
    user_notice: str


class MultiToFastDegradationPolicy:
    def decide(
        self,
        *,
        failure_reason: str,
        high_risk: bool,
        uncertain_side_effects: bool,
        policy_allows: bool,
    ) -> DegradationDecision:
        if high_risk or uncertain_side_effects or not policy_allows:
            return DegradationDecision("fail-closed", failure_reason, False, True, "未降级：安全边界要求独立审阅。")
        return DegradationDecision("fast-unreviewed", failure_reason, False, True, "此结果未经过独立审阅。")


@dataclass(frozen=True)
class RoutingHistoryState:
    prior_mode: ChatMode | None
    prior_complexity_score: int
    has_bounded_history: bool
    unfinished_goal: bool

    @property
    def can_inherit(self) -> bool:
        return self.has_bounded_history and self.unfinished_goal and self.prior_mode is ChatMode.MULTI


@dataclass(frozen=True)
class RouteObservation:
    input_hash: str
    policy_version: str
    evidence_codes: tuple[str, ...]
    conflicts: tuple[str, ...]
    scores: Mapping[str, int]
    thresholds: Mapping[str, int]
    budget: Mapping[str, Any]
    sla: Mapping[str, Any]
    experiment: Mapping[str, Any]
    final_route: str
    decision_path: str
    classifier: Mapping[str, Any]
    domain_profile: str

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTE_OBSERVATION_V1",
            "input_hash": self.input_hash,
            "policy_version": self.policy_version,
            "evidence_codes": list(self.evidence_codes),
            "conflicts": list(self.conflicts),
            "scores": dict(self.scores),
            "thresholds": dict(self.thresholds),
            "budget": dict(self.budget),
            "sla": dict(self.sla),
            "experiment": dict(self.experiment),
            "final_route": self.final_route,
            "decision_path": self.decision_path,
            "classifier": dict(self.classifier),
            "domain_profile": self.domain_profile,
        }


@dataclass(frozen=True)
class RouteFeedback:
    feedback_id: str
    input_hash: str
    original_route: str
    corrected_route: str
    label: str
    original_decision_hash: str
    automatic_rerun: bool
    successful_side_effects_preserved: bool
    revoked: bool = False


class RouteFeedbackRegistry:
    LABELS = {"over-upgrade", "under-upgrade", "classifier-error", "policy-conflict"}

    def __init__(self, event_sink: Callable[[Mapping[str, Any]], Any] | None = None):
        self._records: dict[str, RouteFeedback] = {}
        self.event_sink = event_sink

    def record(
        self,
        feedback_id: str,
        decision: RouteDecision,
        *,
        corrected_route: ChatMode,
        label: str,
        successful_side_effects: bool,
    ) -> RouteFeedback:
        if label not in self.LABELS or corrected_route is ChatMode.AUTO or feedback_id in self._records:
            raise ValueError("routing feedback is invalid or duplicated")
        original = decision.canonical_mapping()
        record = RouteFeedback(
            feedback_id,
            decision.input_hash,
            decision.resolved_mode.value,
            corrected_route.value,
            label,
            hashlib.sha256(canonical_json_bytes(original)).hexdigest(),
            False,
            successful_side_effects,
        )
        self._records[feedback_id] = record
        if self.event_sink:
            self.event_sink({"schema": "SITINA_ROUTE_FEEDBACK_RECORDED_V1", **record.__dict__})
        return record

    def revoke(self, feedback_id: str) -> RouteFeedback:
        prior = self._records.get(feedback_id)
        if prior is None or prior.revoked:
            raise ValueError("routing feedback is absent or already revoked")
        record = RouteFeedback(**{**prior.__dict__, "revoked": True})
        self._records[feedback_id] = record
        if self.event_sink:
            self.event_sink({"schema": "SITINA_ROUTE_FEEDBACK_REVOKED_V1", **record.__dict__})
        return record


@dataclass
class CandidateRoutingRule:
    candidate_id: str
    source_feedback_hashes: tuple[str, ...]
    status: str = "candidate"
    accuracy_delta_ppm: int | None = None
    false_upgrade_delta_ppm: int | None = None
    false_downgrade_delta_ppm: int | None = None
    approval_hash: str | None = None
    published_version: str | None = None


class RoutingRuleLifecycle:
    """Offline-only candidate/evaluation/approval/publication workflow."""

    def __init__(self):
        self.candidates: dict[str, CandidateRoutingRule] = {}

    def generate_offline(self, candidate_id: str, feedback: Sequence[RouteFeedback]) -> CandidateRoutingRule:
        active = [item for item in feedback if not item.revoked]
        if not active or candidate_id in self.candidates:
            raise ValueError("offline routing candidate requires unique active feedback")
        hashes = tuple(sorted(hashlib.sha256(canonical_json_bytes(item.__dict__)).hexdigest() for item in active))
        rule = CandidateRoutingRule(candidate_id, hashes)
        self.candidates[candidate_id] = rule
        return rule

    def evaluate(
        self,
        candidate_id: str,
        *,
        accuracy_delta_ppm: int,
        false_upgrade_delta_ppm: int,
        false_downgrade_delta_ppm: int,
    ) -> CandidateRoutingRule:
        rule = self.candidates[candidate_id]
        rule.status = "evaluated"
        rule.accuracy_delta_ppm = accuracy_delta_ppm
        rule.false_upgrade_delta_ppm = false_upgrade_delta_ppm
        rule.false_downgrade_delta_ppm = false_downgrade_delta_ppm
        return rule

    def approve(self, candidate_id: str, *, approval_hash: str) -> CandidateRoutingRule:
        rule = self.candidates[candidate_id]
        if (
            rule.status != "evaluated"
            or len(approval_hash) != 64
            or any(character not in "0123456789abcdef" for character in approval_hash)
        ):
            raise ValueError("routing rule approval requires evaluated evidence and an exact approval hash")
        rule.approval_hash = approval_hash
        rule.status = "approved"
        return rule

    def publish(self, candidate_id: str, *, version: str) -> CandidateRoutingRule:
        rule = self.candidates[candidate_id]
        regressions = any(
            value is None or value > 0
            for value in (rule.false_upgrade_delta_ppm, rule.false_downgrade_delta_ppm)
        )
        if rule.status != "approved" or rule.accuracy_delta_ppm is None or rule.accuracy_delta_ppm < 0 or regressions:
            raise ValueError("routing candidate failed evaluation or approval and cannot be published")
        rule.status = "published"
        rule.published_version = version
        return rule

    @staticmethod
    def online_self_modify(*_args: Any, **_kwargs: Any) -> None:
        raise PermissionError("online routing policy self-modification is forbidden")


@dataclass(frozen=True)
class RoutingRegressionMetrics:
    policy_version: str
    total: int
    accurate: int
    false_upgrades: int
    false_downgrades: int
    allowed_set_violations: int
    reason_code_misses: int

    @property
    def accuracy_ppm(self) -> int:
        return self.accurate * 1_000_000 // self.total if self.total else 0


def evaluate_routing_fixtures(
    router: Any,
    fixtures: Sequence[Mapping[str, Any]],
    *,
    snapshot: Any,
) -> RoutingRegressionMetrics:
    accurate = false_upgrades = false_downgrades = violations = reason_misses = 0
    for fixture in fixtures:
        decision = router.decide(ChatMode.AUTO, str(fixture["message"]), snapshot)
        expected = str(fixture["expected_route"])
        allowed = {str(item) for item in fixture["allowed_routes"]}
        actual = decision.resolved_mode.value
        accurate += int(actual == expected)
        violations += int(actual not in allowed)
        false_upgrades += int(actual == "MULTI" and expected == "FAST")
        false_downgrades += int(actual == "FAST" and expected == "MULTI")
        evidence = set(dict(decision.observability or {}).get("evidence_codes") or ())
        reason_misses += int(str(fixture["reason_code"]) not in evidence)
    return RoutingRegressionMetrics(
        router.policy_version,
        len(fixtures),
        accurate,
        false_upgrades,
        false_downgrades,
        violations,
        reason_misses,
    )


def compare_routing_policies(
    baseline_router: Any,
    candidate_router: Any,
    fixtures: Sequence[Mapping[str, Any]],
    *,
    snapshot: Any,
) -> tuple[str, ...]:
    differences = []
    for fixture in fixtures:
        baseline = baseline_router.decide(ChatMode.AUTO, str(fixture["message"]), snapshot)
        candidate = candidate_router.decide(ChatMode.AUTO, str(fixture["message"]), snapshot)
        if baseline.resolved_mode is not candidate.resolved_mode:
            differences.append(str(fixture["id"]))
    return tuple(sorted(differences))


def validate_policy_document(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "SITINA_ROUTING_POLICY_V2" or not str(value.get("policy_version") or ""):
        raise ValueError("unsupported advanced routing policy")
    required = {
        "complexity",
        "classifier",
        "token_upper_bounds",
        "domain_profiles",
        "global_safety_floor",
        "experiment",
        "latency_deadlines_ms",
        "default_run_budget_tokens",
    }
    if not required.issubset(value):
        raise ValueError("advanced routing policy fields are missing")
    if int(value["default_run_budget_tokens"]) < 1:
        raise ValueError("default routing run budget must be positive")
    # Construction validates all nested safety boundaries.
    complexity = dict(value["complexity"])
    ComplexityScorer(
        boundary_threshold=int(complexity["boundary_threshold"]),
        complex_threshold=int(complexity["complex_threshold"]),
    )
    DomainProfileRegistry(value)
    bounds = dict(value["token_upper_bounds"])
    RoutingBudgetPlanner(
        fast_upper_tokens=int(bounds["fast"]),
        multi_upper_tokens=int(bounds["multi"]),
        classifier_upper_tokens=int(bounds["classifier"]),
    )
    LatencyPolicy(dict(value["latency_deadlines_ms"]))
    ExperimentAssigner(**dict(value["experiment"]))
    return dict(value)
