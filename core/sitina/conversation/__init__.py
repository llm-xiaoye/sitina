from sitina.conversation.context import ConversationContext, ConversationContextSnapshot
from sitina.conversation.models import (
    ChatMode,
    ChatSession,
    ConversationTurn,
    RouteDecision,
    RouteSource,
    route_decision_from_mapping,
)
from sitina.conversation.router import ConversationRouter, ConversationRouterError


def __getattr__(name: str):
    # Keep package import safe for low-level modules (for example ContextBuilder
    # reached from the extension tool catalog). Heavy runtime imports lead back
    # through extensions and orchestrator packages and must therefore be lazy.
    if name in {"FastConversationError", "FastConversationRuntime", "validate_fast_answer"}:
        from sitina.conversation.fast_runtime import (
            FastConversationError,
            FastConversationRuntime,
            validate_fast_answer,
        )

        return {
            "FastConversationError": FastConversationError,
            "FastConversationRuntime": FastConversationRuntime,
            "validate_fast_answer": validate_fast_answer,
        }[name]
    if name in {"ConversationRuntime", "route_description"}:
        from sitina.conversation.runtime import ConversationRuntime, route_description

        return {"ConversationRuntime": ConversationRuntime, "route_description": route_description}[name]
    raise AttributeError(name)

__all__ = [
    "ChatMode",
    "ChatSession",
    "ConversationContext",
    "ConversationContextSnapshot",
    "ConversationRouter",
    "ConversationRouterError",
    "ConversationRuntime",
    "ConversationTurn",
    "FastConversationError",
    "FastConversationRuntime",
    "RouteDecision",
    "RouteSource",
    "route_decision_from_mapping",
    "route_description",
    "validate_fast_answer",
]
