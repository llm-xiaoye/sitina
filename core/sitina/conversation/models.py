from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_EVEN
from enum import Enum
from typing import Any, Mapping, Sequence


MAX_ROUTE_REASONS = 8
MAX_ROUTE_REASON_CHARS = 160


class ChatMode(str, Enum):
    AUTO = "AUTO"
    FAST = "FAST"
    MULTI = "MULTI"

    @property
    def prompt_label(self) -> str:
        return self.value.lower()


class RouteSource(str, Enum):
    USER_FORCED = "user_forced"
    LOCAL_ROUTER = "local_router"
    MODEL_CLASSIFIER = "model_classifier"
    FAST_RUNTIME_ESCALATION = "fast_runtime_escalation"


@dataclass(frozen=True)
class ConversationTurn:
    user: str
    assistant: str

    def __post_init__(self) -> None:
        if not isinstance(self.user, str) or not self.user.strip():
            raise ValueError("conversation turn requires a non-empty user message")
        if not isinstance(self.assistant, str) or not self.assistant.strip():
            raise ValueError("conversation turn requires a non-empty assistant response")

    def mapping(self) -> dict[str, str]:
        return {"user": self.user, "assistant": self.assistant}


@dataclass(frozen=True)
class RouteDecision:
    requested_mode: ChatMode
    resolved_mode: ChatMode
    source: RouteSource
    reasons: tuple[str, ...]
    policy_version: str
    input_hash: str
    confidence: float = 1.0
    threshold: float = 0.65
    upgrade_reason: str | None = None
    initial_fast_decision: Mapping[str, Any] | None = None
    decision_path: str = "UNSPECIFIED"
    observability: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.resolved_mode is ChatMode.AUTO:
            raise ValueError("a route decision must resolve AUTO to FAST or MULTI")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise ValueError("route decision requires a policy version")
        if len(self.input_hash) != 64 or any(character not in "0123456789abcdef" for character in self.input_hash):
            raise ValueError("route decision input_hash must be lowercase SHA-256")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("route decision confidence must be between zero and one")
        if not 0.0 < float(self.threshold) <= 1.0:
            raise ValueError("route decision threshold must be between zero and one")
        if not isinstance(self.decision_path, str) or not self.decision_path.strip():
            raise ValueError("route decision requires a decision_path")
        if self.upgrade_reason is not None and (
            not isinstance(self.upgrade_reason, str) or not self.upgrade_reason.strip()
        ):
            raise ValueError("route decision upgrade_reason must be non-empty when present")
        if not 1 <= len(self.reasons) <= MAX_ROUTE_REASONS:
            raise ValueError("route decision reasons must contain one to eight entries")
        for reason in self.reasons:
            if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_ROUTE_REASON_CHARS:
                raise ValueError("route decision reasons must be bounded non-empty strings")

    def mapping(self) -> dict[str, Any]:
        value = {
            "requested_mode": self.requested_mode.value,
            "resolved_mode": self.resolved_mode.value,
            "source": self.source.value,
            "reasons": list(self.reasons),
            "policy_version": self.policy_version,
            "input_hash": self.input_hash,
            "confidence": self.confidence,
            "threshold": self.threshold,
            "upgrade_reason": self.upgrade_reason,
            "initial_fast_decision": dict(self.initial_fast_decision) if self.initial_fast_decision else None,
            "decision_path": self.decision_path,
        }
        if self.observability is not None:
            value["observability"] = dict(self.observability)
        return value

    @staticmethod
    def _canonical_score(value: Any) -> str:
        score = Decimal(str(value)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
        return format(score.normalize(), "f")

    def canonical_mapping(self) -> dict[str, Any]:
        """Return a Canonical Journal/CAS-safe route representation."""

        value = self.mapping()
        value["confidence"] = self._canonical_score(self.confidence)
        value["threshold"] = self._canonical_score(self.threshold)
        initial = value.get("initial_fast_decision")
        if isinstance(initial, dict):
            if initial.get("multi_score") is not None:
                initial["multi_score"] = self._canonical_score(initial["multi_score"])
            if initial.get("threshold") is not None:
                initial["threshold"] = self._canonical_score(initial["threshold"])
        return value

    @classmethod
    def escalation(
        cls,
        prior: "RouteDecision",
        reasons: Sequence[str],
        *,
        fast_confidence: str | None = None,
        needs_multi: bool = False,
    ) -> "RouteDecision":
        normalized = tuple(dict.fromkeys(str(item).strip() for item in reasons if str(item).strip()))
        if not normalized:
            normalized = ("FAST Agent 请求独立审阅",)
        return cls(
            requested_mode=prior.requested_mode,
            resolved_mode=ChatMode.MULTI,
            source=RouteSource.FAST_RUNTIME_ESCALATION,
            reasons=normalized[:MAX_ROUTE_REASONS],
            policy_version=prior.policy_version,
            input_hash=prior.input_hash,
            confidence=0.95 if needs_multi else 0.85 if fast_confidence == "low" else 0.75,
            threshold=prior.threshold,
            upgrade_reason="；".join(normalized[:MAX_ROUTE_REASONS]),
            initial_fast_decision={
                **dict(prior.initial_fast_decision or {}),
                "provider_evaluated": True,
                "decision": "REJECTED_AFTER_PROVIDER_EVALUATION",
                "fast_runtime_confidence": fast_confidence,
                "needs_multi": needs_multi,
                "escalation_reasons": list(normalized[:MAX_ROUTE_REASONS]),
            },
            decision_path="AUTO_FAST_RUNTIME_ESCALATION",
            observability={
                **dict(prior.observability or {}),
                "final_route": "MULTI",
                "decision_path": "AUTO_FAST_RUNTIME_ESCALATION",
                "fast_runtime_escalation": {
                    "confidence": fast_confidence,
                    "needs_multi": needs_multi,
                    "reason_count": len(normalized),
                },
            },
        )


@dataclass
class ChatSession:
    session_id: str = field(default_factory=lambda: "chat-session-" + uuid.uuid4().hex)
    mode: ChatMode = ChatMode.AUTO
    turn_index: int = 0
    history: list[ConversationTurn] = field(default_factory=list)
    last_route_decision: RouteDecision | None = None
    last_failed_message: str | None = None
    active_run_id: str | None = None
    working_state: str = ""
    rolling_summary: str = ""
    accepted_memories: tuple[tuple[str, int], ...] = ()
    context_source_frontier: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ValueError("chat session requires a non-empty identity")
        if self.turn_index < 0:
            raise ValueError("turn_index cannot be negative")
        if self.context_source_frontier < 0:
            raise ValueError("context_source_frontier cannot be negative")

    def begin_turn(self, message: str) -> int:
        if not isinstance(message, str) or not message.strip():
            raise ValueError("chat turn requires a non-empty message")
        self.turn_index += 1
        self.active_run_id = None
        return self.turn_index

    def record_success(self, message: str, response: str, *, max_turns: int = 6) -> None:
        self.history.append(ConversationTurn(message.strip(), response.strip()))
        if len(self.history) > max_turns:
            del self.history[:-max_turns]
        self.last_failed_message = None
        self.active_run_id = None

    def record_failure(self, message: str, *, run_id: str | None = None) -> None:
        self.last_failed_message = message.strip()
        self.active_run_id = run_id

    def reset_context(self) -> None:
        self.history.clear()
        self.last_failed_message = None
        self.active_run_id = None
        self.working_state = ""
        self.rolling_summary = ""
        self.context_source_frontier = 0

    def mapping(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "mode": self.mode.value,
            "turn_index": self.turn_index,
            "history": [item.mapping() for item in self.history],
            "last_route_decision": self.last_route_decision.mapping() if self.last_route_decision else None,
            "last_failed_message_hash": (
                hashlib.sha256(self.last_failed_message.encode()).hexdigest()
                if self.last_failed_message
                else None
            ),
            "active_run_id": self.active_run_id,
            "working_state_hash": hashlib.sha256(self.working_state.encode()).hexdigest() if self.working_state else None,
            "rolling_summary_hash": hashlib.sha256(self.rolling_summary.encode()).hexdigest() if self.rolling_summary else None,
            "accepted_memory_count": len(self.accepted_memories),
            "context_source_frontier": self.context_source_frontier,
        }


def mode_from_value(value: ChatMode | str) -> ChatMode:
    if isinstance(value, ChatMode):
        return value
    return ChatMode(str(value).upper())


def route_decision_from_mapping(value: Mapping[str, Any]) -> RouteDecision:
    reasons = value.get("reasons")
    if not isinstance(reasons, (list, tuple)):
        raise ValueError("route decision mapping requires reasons")
    return RouteDecision(
        requested_mode=mode_from_value(str(value["requested_mode"])),
        resolved_mode=mode_from_value(str(value["resolved_mode"])),
        source=RouteSource(str(value["source"])),
        reasons=tuple(str(item) for item in reasons),
        policy_version=str(value["policy_version"]),
        input_hash=str(value["input_hash"]),
        confidence=float(value.get("confidence", 1.0)),
        threshold=float(value.get("threshold", 0.65)),
        upgrade_reason=(str(value["upgrade_reason"]) if value.get("upgrade_reason") else None),
        initial_fast_decision=(
            dict(value["initial_fast_decision"])
            if isinstance(value.get("initial_fast_decision"), Mapping)
            else None
        ),
        decision_path=str(value.get("decision_path") or "LEGACY_UNSPECIFIED"),
        observability=(dict(value["observability"]) if isinstance(value.get("observability"), Mapping) else None),
    )
