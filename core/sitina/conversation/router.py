from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.conversation.context import ConversationContextSnapshot
from sitina.conversation.models import ChatMode, RouteDecision, RouteSource, mode_from_value


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

    def __init__(self, config: Mapping[str, Any], *, context_policy: Any | None = None):
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

    @classmethod
    def load(cls, home: Path) -> "ConversationRouter":
        path = Path(home) / "config/conversation_router.json"
        from sitina.conversation.context import ContextPolicy

        policy_path = Path(home) / "config/context_policy.json"
        try:
            policy = ContextPolicy.load(home) if policy_path.is_file() else None
        except ValueError as error:
            raise ConversationRouterError(str(error)) from error
        return cls(json.loads(path.read_text(encoding="utf-8")), context_policy=policy)

    @property
    def max_context_turns(self) -> int:
        # Backward-facing API only. ConversationRuntime uses ContextPolicy.
        return int(self.config.get("max_context_turns", DEFAULT_CONTEXT_TURNS))

    @property
    def max_context_chars(self) -> int:
        return int(self.config.get("max_context_chars", DEFAULT_CONTEXT_CHARS))

    @staticmethod
    def _matches(text: str, markers: Sequence[str]) -> bool:
        return any(marker.casefold() in text for marker in markers)

    def _input_hash(
        self,
        mode: ChatMode,
        message: str,
        context: ConversationContextSnapshot,
    ) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "schema": "SITINA_CONVERSATION_ROUTE_INPUT_V1",
                    "policy_version": self.policy_version,
                    "requested_mode": mode.value,
                    "message": message.strip(),
                    "bounded_context_hash": context.context_hash,
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
    ) -> RouteDecision:
        requested = mode_from_value(mode)
        if not isinstance(message, str) or not message.strip():
            raise ConversationRouterError("conversation routing requires a non-empty message")
        input_hash = self._input_hash(requested, message, context)
        threshold = float(self.config["multi_confidence_threshold"])
        if requested is ChatMode.FAST:
            return RouteDecision(
                requested, ChatMode.FAST, RouteSource.USER_FORCED,
                ("用户强制 FAST",), self.policy_version, input_hash,
                confidence=1.0,
                threshold=threshold,
                decision_path="USER_FORCED_FAST",
            )
        if requested is ChatMode.MULTI:
            return RouteDecision(
                requested, ChatMode.MULTI, RouteSource.USER_FORCED,
                ("用户强制 MULTI",), self.policy_version, input_hash,
                confidence=1.0,
                threshold=threshold,
                upgrade_reason="用户强制 MULTI",
                decision_path="USER_FORCED_MULTI",
            )

        text = message.casefold()
        reasons: list[str] = []
        groups = (
            ("multi_markers", "明确要求多 Agent 或独立审阅"),
            ("high_risk_markers", "高风险内容需要独立审阅"),
            ("comparison_markers", "多方案比较与取舍"),
            ("verification_markers", "需要交叉验证或审计"),
            ("planning_markers", "需要完整规划或架构设计"),
        )
        for key, reason in groups:
            if self._matches(text, self.config[key]):
                reasons.append(reason)
        conflict_markers = self.config.get("conflicting_constraint_markers", [])
        if isinstance(conflict_markers, list) and self._matches(text, conflict_markers):
            reasons.append("包含冲突约束或重要取舍")
        diagnosis_markers = self.config.get("diagnosis_markers", [])
        uncertainty_markers = self.config.get("uncertainty_markers", [])
        if (
            isinstance(diagnosis_markers, list)
            and isinstance(uncertainty_markers, list)
            and self._matches(text, diagnosis_markers)
            and self._matches(text, uncertainty_markers)
        ):
            reasons.append("故障诊断存在多个可能原因")
        synthesis_markers = self.config.get("synthesis_markers", [])
        if (
            getattr(context, "token_count", 0) >= int(
                getattr(self.context_policy, "long_context_token_threshold", self.max_context_chars + 1)
            )
            and isinstance(synthesis_markers, list)
            and self._matches(text, synthesis_markers)
        ):
            reasons.append("需要综合较长会话上下文")
        deliverable_markers = self.config.get("deliverable_markers", [])
        dependency_markers = self.config.get("dependency_markers", [])
        if isinstance(deliverable_markers, list) and isinstance(dependency_markers, list):
            deliverable_count = sum(1 for marker in deliverable_markers if marker.casefold() in text)
            if deliverable_count >= 2 and self._matches(text, dependency_markers):
                reasons.append("包含多个相互依赖的交付物")

        reasons = list(dict.fromkeys(reasons))[:8]
        multi_score = (
            min(
                0.99,
                float(self.config["direct_multi_base_score"])
                + max(0, len(reasons) - 1) * float(self.config["direct_multi_reason_increment"]),
            )
            if reasons
            else 0.0
        )
        resolved = ChatMode.MULTI if multi_score >= threshold else ChatMode.FAST
        initial_fast_decision = {
            "schema": "SITINA_AUTO_INITIAL_FAST_DECISION_V1",
            "evaluated": True,
            "decision": "REJECTED_FOR_DIRECT_MULTI" if resolved is ChatMode.MULTI else "ADMITTED",
            "multi_score": multi_score,
            "threshold": threshold,
            "evidence_reasons": list(reasons),
            "provider_evaluated": False,
        }
        if not reasons:
            reasons = ["单一目标且无需比较、验证或独立审阅"]
        return RouteDecision(
            requested,
            resolved,
            RouteSource.LOCAL_ROUTER,
            tuple(reasons),
            self.policy_version,
            input_hash,
            confidence=(
                multi_score
                if resolved is ChatMode.MULTI
                else float(self.config["fast_route_confidence"])
            ),
            threshold=threshold,
            upgrade_reason="；".join(reasons) if resolved is ChatMode.MULTI else None,
            initial_fast_decision=initial_fast_decision,
            decision_path="AUTO_DIRECT_MULTI" if resolved is ChatMode.MULTI else "AUTO_FAST_ADMITTED",
        )
