from __future__ import annotations

import hashlib
from typing import Any

from sitina.cas.model import PublishedObjectReceipt
from sitina.conversation.models import RouteDecision
from sitina.conversation.persistence import JournalSessionRepository, PersistedMessage
from sitina.conversation.state import (
    RollingSummaryContent,
    RollingSummaryRepository,
    SessionStateError,
    WorkingStateChanges,
    WorkingStateRepository,
)


def _bounded(value: str, limit: int = 2_000) -> str:
    normalized = " ".join(str(value).strip().split())
    if not normalized:
        raise ValueError("conversation lifecycle text must be non-empty")
    return normalized[:limit]


class ConversationLifecycle:
    """Journal/CAS-native lifecycle shared by every conversation execution mode."""

    def __init__(self, journal: Any, cas: Any, key_provider: Any):
        self.journal = journal
        self.cas = cas
        self.keys = key_provider
        self.sessions = JournalSessionRepository(journal, cas, key_provider)
        self.working = WorkingStateRepository(journal, cas, key_provider)
        self.summaries = RollingSummaryRepository(journal, cas, key_provider)

    def start_turn(
        self,
        *,
        session_id: str,
        turn_index: int,
        message: str,
        route_decision: RouteDecision,
        occurred_at: str,
        session_instance_id: str | None = None,
        run_attempt: int | None = None,
        generation: str | None = None,
        workspace: str | None = None,
    ) -> PersistedMessage:
        body = str(message).strip()
        if not body:
            raise ValueError("conversation turn requires a non-empty message")
        goal = _bounded(body)
        self.sessions.ensure_created(
            session_id=session_id,
            title="Conversation",
            created_at=occurred_at,
            session_instance_id=session_instance_id,
            run_attempt=run_attempt,
            generation=generation,
            workspace=workspace,
        )
        self.sessions.record_mode_changed(
            session_id=session_id,
            mode=route_decision.requested_mode.value,
            created_at=occurred_at,
        )
        persisted = self.sessions.append_message(
            session_id=session_id,
            message_id=f"{session_id}-user-{turn_index}",
            role="user",
            body=body,
            turn_index=turn_index,
            created_at=occurred_at,
            session_instance_id=session_instance_id,
            run_attempt=run_attempt,
            generation=generation,
        )
        self.sessions.record_route_decision(
            session_id=session_id,
            turn_index=turn_index,
            decision=route_decision.canonical_mapping(),
            created_at=occurred_at,
        )
        next_action = f"Execute turn {turn_index} via {route_decision.resolved_mode.value}"
        try:
            current = self.working.recover(session_id)
        except SessionStateError:
            self.working.initialize(
                session_id=session_id,
                primary_goal=goal,
                constraints=(
                    "Journal is event authority; CAS is content authority; projections are rebuildable views",
                ),
                decisions=(),
                completed_steps=(),
                pending_items=(f"Persist the response for turn {turn_index}",),
                next_action=next_action,
                source_frontier=self.journal.head_position,
                occurred_at=occurred_at,
            )
        else:
            if current.state.primary_goal != goal or current.state.next_action != next_action:
                self.working.update(
                    session_id=session_id,
                    expected_version=current.state.version,
                    changes=WorkingStateChanges(
                        primary_goal=goal,
                        pending_items=(f"Persist the response for turn {turn_index}",),
                        next_action=next_action,
                    ),
                    source_frontier=self.journal.head_position,
                    occurred_at=occurred_at,
                )
        return persisted

    def link_run(
        self,
        *,
        session_id: str,
        turn_index: int,
        run_id: str,
        occurred_at: str,
        session_instance_id: str | None = None,
        run_attempt: int | None = None,
        generation: str | None = None,
        workspace: str | None = None,
    ) -> None:
        self.sessions.link_run(
            session_id=session_id,
            run_id=run_id,
            turn_index=turn_index,
            created_at=occurred_at,
            session_instance_id=session_instance_id,
            run_attempt=run_attempt,
            generation=generation,
            workspace=workspace,
        )

    def complete_turn(
        self,
        *,
        session_id: str,
        turn_index: int,
        message: str,
        response: str,
        occurred_at: str,
        published: PublishedObjectReceipt | None = None,
        body_selector: str | None = None,
    ) -> PersistedMessage:
        message_body = str(message).strip()
        response_body = str(response).strip()
        if not message_body or not response_body:
            raise ValueError("completed conversation turn requires non-empty message and response")
        body_hash = hashlib.sha256(response_body.encode("utf-8")).hexdigest()
        current = self.working.recover(session_id)
        completion = f"Turn {turn_index} response persisted ({body_hash[:16]})"
        completed = tuple((*current.state.completed_steps, completion)[-512:])
        if current.state.next_action != "Await the next user request" or current.state.pending_items:
            self.working.update(
                session_id=session_id,
                expected_version=current.state.version,
                changes=WorkingStateChanges(
                    completed_steps=completed,
                    pending_items=(),
                    next_action="Await the next user request",
                ),
                source_frontier=self.journal.head_position,
                occurred_at=occurred_at,
            )
        try:
            current_summary = self.summaries.recover(session_id)
            confirmed = list(current_summary.content.confirmed)
        except SessionStateError:
            confirmed = []
        additions = (
            f"User turn {turn_index}: {_bounded(message_body, 1_800)}",
            f"Assistant turn {turn_index}: {_bounded(response_body, 3_900)}",
        )
        for item in additions:
            if item not in confirmed:
                confirmed.append(item)
        self.summaries.update(
            session_id=session_id,
            content=RollingSummaryContent(confirmed=tuple(confirmed[-24:])),
            source_message_range=(1, turn_index),
            source_frontier=self.journal.head_position,
            occurred_at=occurred_at,
        )
        # The assistant message is the final success marker for the session
        # turn. State and summary may be replayed/reconciled after a crash, but
        # recovery must not expose a successful pair until this append commits.
        if published is None:
            return self.sessions.append_message(
                session_id=session_id,
                message_id=f"{session_id}-assistant-{turn_index}",
                role="assistant",
                body=response_body,
                turn_index=turn_index,
                created_at=occurred_at,
            )
        return self.sessions.append_existing_message_ref(
            session_id=session_id,
            message_id=f"{session_id}-assistant-{turn_index}",
            role="assistant",
            body_hash=body_hash,
            turn_index=turn_index,
            created_at=occurred_at,
            published=published,
            body_selector=body_selector,
        )

    def fail_turn(
        self,
        *,
        session_id: str,
        turn_index: int,
        error_type: str,
        occurred_at: str,
    ) -> None:
        self.sessions.record_turn_failed(
            session_id=session_id,
            turn_index=turn_index,
            error_type=error_type,
            created_at=occurred_at,
        )
        try:
            current = self.working.recover(session_id)
        except SessionStateError:
            return
        next_action = f"Await explicit retry after {str(error_type)[:120]}"
        if current.state.next_action == next_action and not current.state.pending_items:
            return
        self.working.update(
            session_id=session_id,
            expected_version=current.state.version,
            changes=WorkingStateChanges(pending_items=(), next_action=next_action),
            source_frontier=self.journal.head_position,
            occurred_at=occurred_at,
        )


__all__ = ["ConversationLifecycle"]
