from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sitina.conversation.context import ConversationContextSnapshot
from sitina.conversation.models import ChatMode, RouteDecision, RouteSource, mode_from_value
from sitina.conversation.routing_policy import (
    ClassifierGate,
    ComplexityScorer,
    DomainProfileRegistry,
    ExperimentAssigner,
    LatencyClass,
    LatencyPolicy,
    ReplaceableIntentClassifier,
    RISK_ORDER,
    RouteObservation,
    RoutingBudgetPlanner,
    RoutingHistoryState,
    RoutingSignals,
    normalize_intent_text,
    validate_policy_document,
)


class ConversationRouterError(RuntimeError):
    pass


DEFAULT_CONTEXT_TURNS = 6
DEFAULT_CONTEXT_CHARS = 12_000


class ConversationRouter:
    """Deterministic, Provider-free first-stage conversation router."""

    REQUIRED_LISTS = (
        "multi_markers",
        "high_risk_markers",
        "comparison_markers",
        "verification_markers",
        "planning_markers",
    )
    DEFAULT_SCORES = {
        "multi_confidence_threshold": 0.65,
        "direct_multi_base_score": 0.70,
        "direct_multi_reason_increment": 0.10,
        "fast_route_confidence": 0.90,
    }

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        context_policy: Any | None = None,
        routing_policy: Mapping[str, Any] | None = None,
        classifier: ReplaceableIntentClassifier | None = None,
        observation_sink: Callable[[Mapping[str, Any]], Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config = dict(config)
        self.context_policy = context_policy
        if self.config.get("schema") != "SITINA_CONVERSATION_ROUTER_V1":
            raise ConversationRouterError("unsupported conversation router schema")
        self.policy_version = str(self.config.get("policy_version") or "").strip()
        if not self.policy_version:
            raise ConversationRouterError("conversation router requires policy_version")
        legacy_bounds = {"max_context_turns", "max_context_chars", "long_context_token_threshold"} & set(self.config)
        if context_policy is not None and legacy_bounds:
            raise ConversationRouterError("legacy context bounds conflict with config/context_policy.json")
        if context_policy is None and legacy_bounds and (
            int(self.config.get("max_context_turns", 0)) < 1
            or int(self.config.get("max_context_chars", 0)) < 1
        ):
            raise ConversationRouterError("conversation router context bounds are invalid")
        for key, default in self.DEFAULT_SCORES.items():
            value = self.config.get(key, default)
            if not isinstance(value, (int, float)) or not 0.0 < float(value) <= 1.0:
                raise ConversationRouterError(f"conversation router requires a bounded score: {key}")
            self.config[key] = float(value)
        for key in self.REQUIRED_LISTS:
            value = self.config.get(key)
            if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
                raise ConversationRouterError(f"conversation router requires a string list: {key}")
        try:
            self.routing_policy = validate_policy_document(
                routing_policy or self._default_routing_policy(self.policy_version)
            )
            complexity = dict(self.routing_policy["complexity"])
            self.complexity = ComplexityScorer(
                boundary_threshold=int(complexity["boundary_threshold"]),
                complex_threshold=int(complexity["complex_threshold"]),
            )
            self.domains = DomainProfileRegistry(self.routing_policy)
            bounds = dict(self.routing_policy["token_upper_bounds"])
            self.budget = RoutingBudgetPlanner(
                fast_upper_tokens=int(bounds["fast"]),
                multi_upper_tokens=int(bounds["multi"]),
                classifier_upper_tokens=int(bounds["classifier"]),
            )
            classifier_policy = dict(self.routing_policy["classifier"])
            self.classifier = ClassifierGate(
                classifier,
                lower_confidence_ppm=int(classifier_policy["lower_confidence_ppm"]),
                upper_confidence_ppm=int(classifier_policy["upper_confidence_ppm"]),
                token_upper_bound=int(classifier_policy["token_upper_bound"]),
                minimum_latency_ms=int(classifier_policy["minimum_latency_ms"]),
            )
            self.experiments = ExperimentAssigner(**dict(self.routing_policy["experiment"]))
            self.latency = LatencyPolicy(dict(self.routing_policy["latency_deadlines_ms"]), clock=clock)
        except (KeyError, TypeError, ValueError) as error:
            raise ConversationRouterError(str(error)) from error
        self.routing_policy_version = str(self.routing_policy["policy_version"])
        self.observation_sink = observation_sink

    @classmethod
    def load(cls, home: Path) -> "ConversationRouter":
        path = Path(home) / "config/conversation_router.json"
        from sitina.conversation.context import ContextPolicy

        policy_path = Path(home) / "config/context_policy.json"
        try:
            policy = ContextPolicy.load(home) if policy_path.is_file() else None
        except ValueError as error:
            raise ConversationRouterError(str(error)) from error
        routing_path = Path(home) / "config/routing_policy.json"
        routing_policy = json.loads(routing_path.read_text(encoding="utf-8")) if routing_path.is_file() else None
        return cls(
            json.loads(path.read_text(encoding="utf-8")),
            context_policy=policy,
            routing_policy=routing_policy,
        )

    @staticmethod
    def _default_routing_policy(policy_version: str) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTING_POLICY_V2",
            "policy_version": f"{policy_version}-advanced-defaults-v2",
            "complexity": {"boundary_threshold": 35, "complex_threshold": 65},
            "classifier": {
                "lower_confidence_ppm": 450_000,
                "upper_confidence_ppm": 700_000,
                "token_upper_bound": 600,
                "minimum_latency_ms": 1200,
            },
            "token_upper_bounds": {"fast": 4096, "multi": 24000, "classifier": 600},
            "default_run_budget_tokens": 32000,
            "global_safety_floor": "high",
            "domain_profiles": [
                {
                    "name": "general",
                    "version": "general-default-1.0",
                    "multi_threshold": 65,
                    "risk_floor": "high",
                    "rubric": "correctness-safety-completeness",
                    "markers": [],
                }
            ],
            "experiment": {
                "experiment_id": "router-default-control",
                "policy_version": f"{policy_version}-advanced-defaults-v2",
                "treatment_percent": 0,
                "kill_switch": False,
            },
            "latency_deadlines_ms": {"interactive": 1500, "standard": 10000, "batch": 60000},
        }

    @property
    def max_context_turns(self) -> int:
        # Backward-facing API only. ConversationRuntime uses ContextPolicy.
        return int(self.config.get("max_context_turns", DEFAULT_CONTEXT_TURNS))

    @property
    def max_context_chars(self) -> int:
        return int(self.config.get("max_context_chars", DEFAULT_CONTEXT_CHARS))

    @staticmethod
    def _matches(text: str, markers: Sequence[str]) -> bool:
        return any(normalize_intent_text(marker) in text for marker in markers)

    def _input_hash(
        self,
        mode: ChatMode,
        message: str,
        context: ConversationContextSnapshot,
        history: RoutingHistoryState | None,
        risk_override: str | None,
    ) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "schema": "SITINA_CONVERSATION_ROUTE_INPUT_V1",
                    "policy_version": self.policy_version,
                    "routing_policy_version": self.routing_policy_version,
                    "requested_mode": mode.value,
                    "message": message.strip(),
                    "risk_override": risk_override,
                    "bounded_context_hash": context.context_hash,
                    "history": (
                        {
                            "prior_mode": history.prior_mode.value if history and history.prior_mode else None,
                            "prior_complexity_score": history.prior_complexity_score if history else 0,
                            "has_bounded_history": history.has_bounded_history if history else False,
                            "unfinished_goal": history.unfinished_goal if history else False,
                        }
                    ),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def decide(
        self,
        mode: ChatMode | str,
        message: str,
        context: ConversationContextSnapshot,
        *,
        history: RoutingHistoryState | None = None,
        remaining_tokens: int | None = None,
        latency_class: LatencyClass | None = None,
        inherited_latency_class: LatencyClass | None = None,
        latency_started_at: float | None = None,
        subject_id: str | None = None,
        risk_override: str | None = None,
    ) -> RouteDecision:
        requested = mode_from_value(mode)
        if not isinstance(message, str) or not message.strip():
            raise ConversationRouterError("conversation routing requires a non-empty message")
        if risk_override is not None and risk_override not in {"low", "medium", "high", "critical"}:
            raise ConversationRouterError("routing risk override is invalid")
        input_hash = self._input_hash(requested, message, context, history, risk_override)
        text = normalize_intent_text(message)
        profile = self.domains.select(message)
        signals = RoutingSignals.infer(
            message,
            context_tokens=int(getattr(context, "token_count", 0)),
            prior_complexity_score=history.prior_complexity_score if history else 0,
            inherit_history=history.can_inherit if history else False,
        )
        if risk_override is not None and RISK_ORDER[risk_override] > RISK_ORDER[signals.risk]:
            signals = replace(signals, risk=risk_override)
        complexity = self.complexity.assess(signals)
        threshold = profile.multi_threshold / 100
        threshold_ppm = profile.multi_threshold * 10_000
        budget_remaining = int(
            self.routing_policy["default_run_budget_tokens"]
            if remaining_tokens is None
            else remaining_tokens
        )
        if budget_remaining < 0:
            raise ConversationRouterError("routing remaining token budget cannot be negative")
        experiment = self.experiments.assign(subject_id or input_hash)
        latency = self.latency.evaluate(
            latency_class,
            inherited_class=inherited_latency_class,
            started_at=latency_started_at,
            high_risk=signals.risk in {"high", "critical"},
        )
        reasons: list[str] = []
        evidence_codes: list[str] = []
        conflicts: list[str] = []
        groups = (
            ("multi_markers", "明确要求多 Agent 或独立审阅"),
            ("high_risk_markers", "高风险内容需要独立审阅"),
            ("comparison_markers", "多方案比较与取舍"),
            ("verification_markers", "需要交叉验证或审计"),
            ("planning_markers", "需要完整规划或架构设计"),
            ("execution_markers", "需要执行:写代码/改文件/操作电脑"),
        )
        for key, reason in groups:
            markers = self.config.get(key, [])
            if isinstance(markers, list) and markers and self._matches(text, markers):
                reasons.append(reason)
                evidence_codes.append(key)
        conflict_markers = self.config.get("conflicting_constraint_markers", [])
        if isinstance(conflict_markers, list) and self._matches(text, conflict_markers):
            reasons.append("包含冲突约束或重要取舍")
            evidence_codes.append("conflicting_constraints")
        diagnosis_markers = self.config.get("diagnosis_markers", [])
        uncertainty_markers = self.config.get("uncertainty_markers", [])
        if (
            isinstance(diagnosis_markers, list)
            and isinstance(uncertainty_markers, list)
            and self._matches(text, diagnosis_markers)
            and self._matches(text, uncertainty_markers)
        ):
            reasons.append("故障诊断存在多个可能原因")
            evidence_codes.append("ambiguous_diagnosis")
        synthesis_markers = self.config.get("synthesis_markers", [])
        if (
            getattr(context, "token_count", 0) >= int(
                getattr(self.context_policy, "long_context_token_threshold", self.max_context_chars + 1)
            )
            and isinstance(synthesis_markers, list)
            and self._matches(text, synthesis_markers)
        ):
            reasons.append("需要综合较长会话上下文")
            evidence_codes.append("long_context_synthesis")
        deliverable_markers = self.config.get("deliverable_markers", [])
        dependency_markers = self.config.get("dependency_markers", [])
        if isinstance(deliverable_markers, list) and isinstance(dependency_markers, list):
            deliverable_count = sum(1 for marker in deliverable_markers if normalize_intent_text(marker) in text)
            if deliverable_count >= 2 and self._matches(text, dependency_markers):
                reasons.append("包含多个相互依赖的交付物")
                evidence_codes.append("dependent_deliverables")

        reasons = list(dict.fromkeys(reasons))[:8]
        marker_score_ppm = (
            min(
                990_000,
                int(float(self.config["direct_multi_base_score"]) * 1_000_000)
                + max(0, len(reasons) - 1)
                * int(float(self.config["direct_multi_reason_increment"]) * 1_000_000),
            ) if reasons else 0
        )
        complexity_score_ppm = complexity.total * 10_000
        multi_score_ppm = max(marker_score_ppm, complexity_score_ppm)
        hard_boundary = signals.risk in {"high", "critical"}
        if complexity.total >= profile.multi_threshold and len(reasons) < 8:
            reasons.append(f"结构化复杂度 {complexity.total} 达到 {profile.name} 领域阈值")
            evidence_codes.append("complexity_threshold")
        if signals.follow_up and complexity.total >= profile.multi_threshold and len(reasons) < 8:
            reasons.append("追问继承上一轮未完成复杂目标")
            evidence_codes.append("history_inherited")
        preferred = ChatMode.MULTI if hard_boundary or multi_score_ppm >= threshold_ppm else ChatMode.FAST
        budget = self.budget.admit(preferred, remaining_tokens=budget_remaining, risk=signals.risk)
        classifier_confidence = multi_score_ppm if preferred is ChatMode.MULTI else 1_000_000 - multi_score_ppm
        classifier = self.classifier.evaluate(
            local_confidence_ppm=classifier_confidence,
            input_hash=input_hash,
            complexity=complexity,
            budget_remaining_tokens=budget_remaining,
            latency_remaining_ms=latency.remaining_ms,
            hard_boundary=hard_boundary or requested is not ChatMode.AUTO,
        )
        source = RouteSource.LOCAL_ROUTER
        resolved = preferred
        decision_path = "AUTO_DIRECT_MULTI" if preferred is ChatMode.MULTI else "AUTO_FAST_ADMITTED"

        # Public forced-mode semantics have highest routing priority.  The
        # executable permission/effect boundary remains independent of route.
        if requested is ChatMode.FAST:
            resolved = ChatMode.FAST
            reasons = ["用户强制 FAST"]
            decision_path = "USER_FORCED_FAST"
            source = RouteSource.USER_FORCED
            if hard_boundary:
                conflicts.append("forced-fast-overrode-auto-high-risk-review")
        elif requested is ChatMode.MULTI:
            resolved = ChatMode.MULTI
            reasons = ["用户强制 MULTI"]
            decision_path = "USER_FORCED_MULTI"
            source = RouteSource.USER_FORCED
        else:
            if budget.selected_route is None:
                conflicts.append(budget.status)
                decision_path = "AUTO_REVIEW_BUDGET_BLOCKED" if hard_boundary else "AUTO_BUDGET_EXHAUSTED"
            elif budget.selected_route is ChatMode.FAST and preferred is ChatMode.MULTI:
                if not signals.side_effect_classes and not hard_boundary:
                    resolved = ChatMode.FAST
                    decision_path = "AUTO_BUDGET_FAST_CANDIDATE"
                    conflicts.append("budget-overrode-complexity")
                else:
                    conflicts.append("budget-fast-denied-by-safety")
            if classifier.route is not None:
                classifier_required = self.budget.multi if classifier.route is ChatMode.MULTI else self.budget.fast
                if classifier_required <= budget_remaining:
                    resolved = classifier.route
                    source = RouteSource.MODEL_CLASSIFIER
                    decision_path = f"AUTO_CLASSIFIER_{resolved.value}"
                    evidence_codes.extend(classifier.reason_codes)
                else:
                    conflicts.append("classifier-route-budget-denied")
            if latency.action in {"fast-path", "partial-result"} and resolved is ChatMode.MULTI:
                if not hard_boundary and not signals.side_effect_classes:
                    resolved = ChatMode.FAST
                    decision_path = "AUTO_SLA_FAST_PATH" if latency.action == "fast-path" else "AUTO_SLA_PARTIAL_RESULT"
                    conflicts.append("sla-overrode-complexity")
                else:
                    conflicts.append("sla-fast-denied-by-safety")

        if not reasons:
            reasons = ["单一目标且无需比较、验证或独立审阅"]
            evidence_codes.append("simple-single-goal")
        reasons = list(dict.fromkeys(reasons))[:8]
        evidence_codes.append(f"complexity-{complexity.band}")
        evidence_codes.extend(f"complexity:{item}" for item in complexity.reason_codes)
        confidence_ppm = (
            classifier.confidence_ppm
            if source is RouteSource.MODEL_CLASSIFIER
            else 1_000_000
            if source is RouteSource.USER_FORCED
            else multi_score_ppm
            if resolved is ChatMode.MULTI
            else int(float(self.config["fast_route_confidence"]) * 1_000_000)
        )
        observation = RouteObservation(
            input_hash,
            self.routing_policy_version,
            tuple(dict.fromkeys(evidence_codes))[:24],
            tuple(dict.fromkeys(conflicts))[:12],
            {
                "complexity_total": complexity.total,
                "local_multi_score_ppm": multi_score_ppm,
                "local_confidence_ppm": classifier_confidence,
            },
            {
                "domain_multi_threshold": profile.multi_threshold,
                "classifier_lower_confidence_ppm": self.classifier.lower,
                "classifier_upper_confidence_ppm": self.classifier.upper,
            },
            budget.mapping(),
            latency.mapping(),
            experiment.mapping(),
            resolved.value,
            decision_path,
            classifier.mapping(),
            f"{profile.name}@{profile.version}",
        )
        observation_mapping = observation.mapping()
        if self.observation_sink is not None:
            self.observation_sink(observation_mapping)
        multi_score = multi_score_ppm / 1_000_000
        initial_fast_decision = {
            "schema": "SITINA_AUTO_INITIAL_FAST_DECISION_V1",
            "evaluated": True,
            "decision": "REJECTED_FOR_DIRECT_MULTI" if resolved is ChatMode.MULTI else "ADMITTED",
            "multi_score": multi_score,
            "threshold": threshold,
            "evidence_reasons": list(reasons),
            "provider_evaluated": classifier.physical_call_count > 0,
            "classifier_usage_tokens": classifier.usage_tokens,
            "classifier_usage_upper_bound_tokens": classifier.usage_upper_bound_tokens,
            "complexity": complexity.mapping(),
        }
        return RouteDecision(
            requested,
            resolved,
            source,
            tuple(reasons),
            self.policy_version,
            input_hash,
            confidence=confidence_ppm / 1_000_000,
            threshold=threshold,
            upgrade_reason="；".join(reasons) if resolved is ChatMode.MULTI else None,
            initial_fast_decision=(initial_fast_decision if requested is ChatMode.AUTO else None),
            decision_path=decision_path,
            observability=observation_mapping,
        )

    @staticmethod
    def explain(decision: RouteDecision) -> dict[str, Any]:
        return {
            "schema": "SITINA_ROUTE_EXPLANATION_V1",
            "requested_mode": decision.requested_mode.value,
            "resolved_mode": decision.resolved_mode.value,
            "source": decision.source.value,
            "reasons": list(decision.reasons),
            "observability": dict(decision.observability or {}),
        }
