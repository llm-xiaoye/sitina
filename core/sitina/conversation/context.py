from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from sitina.conversation.models import ConversationTurn
from sitina.journal.model import canonical_json_bytes


DEFAULT_MAX_TURNS = 6
DEFAULT_MAX_CHARS = 12_000


@dataclass(frozen=True)
class ContextPolicy:
    token_budget: int
    history_token_budget: int
    max_recent_turns: int
    renderer_version: str
    long_context_token_threshold: int

    def __post_init__(self) -> None:
        if not 32 <= self.token_budget <= 1_000_000:
            raise ValueError("context token_budget is invalid")
        if not 1 <= self.history_token_budget < self.token_budget:
            raise ValueError("context history_token_budget is invalid")
        if not 1 <= self.max_recent_turns <= 10_000:
            raise ValueError("context max_recent_turns is invalid")
        if self.renderer_version != "context-renderer-v2":
            raise ValueError("unsupported Context Renderer Version")
        if not 1 <= self.long_context_token_threshold <= self.token_budget:
            raise ValueError("long context token threshold is invalid")

    @classmethod
    def load(cls, home: str | Path) -> "ContextPolicy":
        root = Path(home)
        path = root / "config/context_policy.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("config/context_policy.json is required and must be valid JSON") from error
        expected = {
            "schema",
            "token_budget",
            "history_token_budget",
            "max_recent_turns",
            "renderer_version",
            "long_context_token_threshold",
        }
        if set(value) != expected or value.get("schema") != "SITINA_CONTEXT_POLICY_V1":
            raise ValueError("Context Policy has unknown or missing fields")
        # Context policy is a single source of truth.  Keeping a second bound
        # in either legacy configuration would make startup behavior depend on
        # load order, so reject it rather than silently choosing one.
        router_path = root / "config/conversation_router.json"
        if router_path.is_file():
            try:
                router = json.loads(router_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError("config/conversation_router.json must be valid JSON") from error
            conflicts = {"max_context_turns", "max_context_chars", "long_context_token_threshold"} & set(router)
            if conflicts:
                raise ValueError(f"legacy router context policy conflicts with config/context_policy.json: {sorted(conflicts)}")
        legacy_path = root / "config/sitina.yaml"
        if legacy_path.is_file():
            try:
                legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError("config/sitina.yaml must be valid JSON") from error
            legacy_context = legacy.get("context", {})
            if isinstance(legacy_context, dict) and "recent_turn_limit" in legacy_context:
                raise ValueError("legacy recent_turn_limit conflicts with config/context_policy.json")
        return cls(
            int(value["token_budget"]),
            int(value["history_token_budget"]),
            int(value["max_recent_turns"]),
            str(value["renderer_version"]),
            int(value["long_context_token_threshold"]),
        )

    @property
    def policy_hash(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema": "SITINA_CONTEXT_POLICY_V1",
                    "token_budget": self.token_budget,
                    "history_token_budget": self.history_token_budget,
                    "max_recent_turns": self.max_recent_turns,
                    "renderer_version": self.renderer_version,
                    "long_context_token_threshold": self.long_context_token_threshold,
                }
            )
        ).hexdigest()


class TokenEstimator:
    """Deterministic offline token estimator used for budget admission.

    Provider-reported usage remains the accounting authority after a call. The
    estimator deliberately over-counts CJK characters and punctuation so it
    never relies on character-tail truncation.
    """

    _TOKENS = re.compile(r"[\u3400-\u9fff]|[A-Za-z0-9_]+|[^\s]", re.UNICODE)

    @classmethod
    def count(cls, text: str) -> int:
        total = 0
        for token in cls._TOKENS.findall(text):
            if token.isascii() and (token[0].isalnum() or token[0] == "_"):
                total += max(1, (len(token) + 3) // 4)
            else:
                total += 1
        return total


@dataclass(frozen=True)
class RenderedContext:
    rendered: str
    rendered_hash: str
    token_count: int
    manifest: dict[str, Any]


@dataclass(frozen=True)
class ConversationContextSnapshot:
    transcript: str
    turn_count: int
    char_count: int
    context_hash: str
    token_count: int = 0
    renderer_version: str = "context-renderer-v2"
    component_manifest: tuple[dict[str, Any], ...] = ()

    def mapping(self, *, include_transcript: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "turn_count": self.turn_count,
            "char_count": self.char_count,
            "token_count": self.token_count,
            "context_hash": self.context_hash,
            "renderer_version": self.renderer_version,
            "component_manifest": [dict(item) for item in self.component_manifest],
        }
        if include_transcript:
            value["transcript"] = self.transcript
        return value


class TokenAwareContextRenderer:
    ORDER = (
        "system_rules",
        "goal_constraints",
        "working_state",
        "memories",
        "rolling_summary",
        "recent_messages",
        "current_user_message",
    )

    def __init__(self, policy: ContextPolicy):
        self.policy = policy

    @staticmethod
    def _section(name: str, value: str) -> str:
        labels = {
            "system_rules": "System rules and permissions",
            "goal_constraints": "Current goal and constraints",
            "working_state": "Structured working state",
            "memories": "Relevant long-term memory",
            "rolling_summary": "Rolling summary",
            "recent_messages": "Recent original messages",
            "current_user_message": "Current user message",
        }
        return f"[{labels[name]}]\n{value.strip()}"

    def render(
        self,
        *,
        system_rules: str,
        goal_constraints: str,
        working_state: str,
        memories: Sequence[tuple[str, int]],
        rolling_summary: str,
        recent_messages: Sequence[str],
        current_user_message: str,
    ) -> RenderedContext:
        required = {
            "system_rules": system_rules.strip(),
            "goal_constraints": goal_constraints.strip(),
            "current_user_message": current_user_message.strip(),
        }
        if any(not value for value in required.values()):
            raise ValueError("system rules, goal/constraints, and current user message are required")
        memory_values = [text.strip() for text, _score in sorted(memories, key=lambda item: (-item[1], item[0])) if text.strip()]
        recent_values = [item.strip() for item in recent_messages if item.strip()]
        components: dict[str, str] = {
            **required,
            "working_state": working_state.strip(),
            "memories": "\n".join(memory_values),
            "rolling_summary": rolling_summary.strip(),
            "recent_messages": "\n\n".join(recent_values),
        }

        def assembled() -> tuple[str, int]:
            rendered = "\n\n".join(self._section(name, components[name]) for name in self.ORDER if components.get(name))
            return rendered, TokenEstimator.count(rendered)

        rendered, tokens = assembled()
        while tokens > self.policy.token_budget and memory_values:
            memory_values.pop()
            components["memories"] = "\n".join(memory_values)
            rendered, tokens = assembled()
        while tokens > self.policy.token_budget and recent_values:
            recent_values.pop(0)
            components["recent_messages"] = "\n\n".join(recent_values)
            rendered, tokens = assembled()
        if tokens > self.policy.token_budget and components["rolling_summary"]:
            components["rolling_summary"] = ""
            rendered, tokens = assembled()
        if tokens > self.policy.token_budget and components["working_state"]:
            components["working_state"] = ""
            rendered, tokens = assembled()
        manifest_components = []
        for name in self.ORDER:
            value = components.get(name, "")
            manifest_components.append(
                {
                    "component": name,
                    "included": bool(value),
                    "token_count": TokenEstimator.count(value),
                    "content_hash": hashlib.sha256(value.encode()).hexdigest(),
                    "required": name in required,
                }
            )
        rendered_hash = hashlib.sha256(rendered.encode()).hexdigest()
        manifest = {
            "schema": "SITINA_CONTEXT_RENDER_MANIFEST_V2",
            "renderer_version": self.policy.renderer_version,
            "context_policy_hash": self.policy.policy_hash,
            "token_budget": self.policy.token_budget,
            "token_count": tokens,
            "required_content_over_budget": tokens > self.policy.token_budget,
            "components": manifest_components,
            "rendered_input_hash": rendered_hash,
        }
        return RenderedContext(rendered, rendered_hash, tokens, manifest)

    def history_snapshot(self, history: Sequence[ConversationTurn]) -> ConversationContextSnapshot:
        admitted: list[ConversationTurn] = []
        tokens = 0
        for turn in reversed(history[-self.policy.max_recent_turns :]):
            rendered = f"User: {turn.user}\nSitina: {turn.assistant}"
            count = TokenEstimator.count(rendered)
            if admitted and tokens + count > self.policy.history_token_budget:
                break
            if not admitted and count > self.policy.history_token_budget:
                continue
            admitted.append(turn)
            tokens += count
        admitted.reverse()
        transcript = "\n\n".join(f"User: {turn.user}\nSitina: {turn.assistant}" for turn in admitted)
        component = {
            "component": "recent_messages",
            "content_hash": hashlib.sha256(transcript.encode()).hexdigest(),
            "token_count": tokens,
            "turn_count": len(admitted),
        }
        context_hash = hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema": "SITINA_TOKEN_AWARE_CONVERSATION_CONTEXT_V2",
                    "renderer_version": self.policy.renderer_version,
                    "context_policy_hash": self.policy.policy_hash,
                    "component": component,
                }
            )
        ).hexdigest()
        return ConversationContextSnapshot(
            transcript,
            len(admitted),
            len(transcript),
            context_hash,
            tokens,
            self.policy.renderer_version,
            (component,),
        )


class ConversationContext:
    def __init__(
        self,
        *,
        policy: ContextPolicy | None = None,
        max_turns: int | None = None,
        max_chars: int | None = None,
    ):
        self._legacy_bounds = policy is None and (max_turns is not None or max_chars is not None)
        if policy is None:
            turns = int(max_turns or DEFAULT_MAX_TURNS)
            chars = int(max_chars or DEFAULT_MAX_CHARS)
            if turns < 1 or chars < 1:
                raise ValueError("conversation context bounds must be positive")
            self.max_turns = turns
            self.max_chars = chars
            policy = ContextPolicy(
                token_budget=max(32, chars * 2),
                history_token_budget=max(1, chars * 2 - 1),
                max_recent_turns=turns,
                renderer_version="context-renderer-v2",
                long_context_token_threshold=max(1, min(chars * 2, 8_000)),
            )
        else:
            self.max_turns = policy.max_recent_turns
            self.max_chars = policy.token_budget * 4
        self.policy = policy
        self.renderer = TokenAwareContextRenderer(policy)

    @classmethod
    def load(cls, home: str | Path) -> "ConversationContext":
        return cls(policy=ContextPolicy.load(home))

    @staticmethod
    def _render(turns: Sequence[ConversationTurn]) -> str:
        return "\n\n".join(f"User: {turn.user}\nSitina: {turn.assistant}" for turn in turns)

    def snapshot(self, history: Sequence[ConversationTurn]) -> ConversationContextSnapshot:
        if not self._legacy_bounds:
            return self.renderer.history_snapshot(history)
        # Compatibility-only adapter for old callers. Production startup uses
        # ContextPolicy and never enters this character-bounded path.
        recent = list(history[-self.max_turns :])
        transcript = self._render(recent)
        if len(transcript) > self.max_chars:
            transcript = transcript[-self.max_chars :]
        context_hash = hashlib.sha256(
            json.dumps(
                {
                    "schema": "SITINA_BOUNDED_CONVERSATION_CONTEXT_V1",
                    "max_turns": self.max_turns,
                    "max_chars": self.max_chars,
                    "turn_count": len(recent),
                    "transcript": transcript,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return ConversationContextSnapshot(
            transcript,
            len(recent),
            len(transcript),
            context_hash,
            TokenEstimator.count(transcript),
            "legacy-context-adapter-v1",
            (),
        )

    def compose(
        self,
        history: Sequence[ConversationTurn],
        *,
        current_user_message: str,
        goal_constraints: str,
        working_state: str,
        memories: Sequence[tuple[str, int]],
        rolling_summary: str,
    ) -> ConversationContextSnapshot:
        history = tuple(history)
        recent = self.renderer.history_snapshot(history)
        rendered = self.renderer.render(
            system_rules=(
                "Answer directly in the user's language. Preserve Journal as event authority, CAS as content "
                "authority, and projections as rebuildable views. Never expose credentials or claim an "
                "external effect that is not supported by authoritative evidence."
            ),
            goal_constraints=goal_constraints,
            working_state=working_state,
            memories=memories,
            rolling_summary=rolling_summary,
            recent_messages=(recent.transcript,) if recent.transcript else (),
            current_user_message=current_user_message,
        )
        return ConversationContextSnapshot(
            transcript=rendered.rendered,
            turn_count=recent.turn_count,
            char_count=len(rendered.rendered),
            context_hash=rendered.rendered_hash,
            token_count=rendered.token_count,
            renderer_version=self.policy.renderer_version,
            component_manifest=tuple(dict(item) for item in rendered.manifest["components"]),
        )

    def goal(self, message: str, snapshot: ConversationContextSnapshot) -> str:
        if any(
            item.get("component") == "current_user_message" and item.get("included")
            for item in snapshot.component_manifest
        ):
            return snapshot.transcript
        result = self.renderer.render(
            system_rules=(
                "This is a read-only Sitina terminal conversation. Answer directly in the user's language. "
                "Do not execute tools, write files, modify Git, call MCP, publish, store memory, or cause external mutation."
            ),
            goal_constraints="Answer the current user request directly; prior turns are context only.",
            working_state="",
            memories=(),
            rolling_summary="",
            recent_messages=(snapshot.transcript,) if snapshot.transcript else (),
            current_user_message=message.strip(),
        )
        return result.rendered
