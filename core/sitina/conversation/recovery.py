from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sitina.conversation.lifecycle import ConversationLifecycle
from sitina.conversation.persistence import JournalSessionRepository, SessionPersistenceError


@dataclass(frozen=True)
class RecoverableTurn:
    session_id: str
    turn_index: int
    run_id: str
    user_message: str
    response: str
    terminal_event_id: str


class ConversationReconciler:
    """Completes session projection gaps from immutable successful-run facts.

    It never calls a provider. A repair is admitted only when a linked run has
    a verified successful terminal/evidence object (or the autonomous
    run-succeeded record) whose response hash matches the Journal commitment.
    """

    def __init__(self, journal: Any, cas: Any, key_provider: Any):
        self.journal = journal
        self.cas = cas
        self.keys = key_provider
        self.sessions = JournalSessionRepository(journal, cas, key_provider)

    def recoverable_turns(self, session_id: str) -> tuple[RecoverableTurn, ...]:
        recovered = self.sessions.recover(session_id)
        messages = list(recovered["messages"])
        users = {
            int(item["turn_index"]): str(item["body"])
            for item in messages
            if item["role"] == "user"
        }
        assistants = {
            int(item["turn_index"])
            for item in messages
            if item["role"] == "assistant"
        }
        links: dict[int, str] = {}
        for event in self.journal.iter_events(0):
            if event.stream_id != f"session/{session_id}" or event.event_type != "session.run-linked":
                continue
            links[int(event.payload["turn_index"])] = str(event.payload["run_id"])
        result = []
        for turn_index, user_message in sorted(users.items()):
            if turn_index in assistants or turn_index not in links:
                continue
            run_id = links[turn_index]
            response = self._successful_response(run_id)
            if response is None:
                continue
            body, terminal_event_id = response
            result.append(
                RecoverableTurn(session_id, turn_index, run_id, user_message, body, terminal_event_id)
            )
        return tuple(result)

    def reconcile(self, session_id: str, *, occurred_at: str) -> tuple[RecoverableTurn, ...]:
        turns = self.recoverable_turns(session_id)
        lifecycle = ConversationLifecycle(self.journal, self.cas, self.keys)
        for turn in turns:
            lifecycle.complete_turn(
                session_id=turn.session_id,
                turn_index=turn.turn_index,
                message=turn.user_message,
                response=turn.response,
                occurred_at=occurred_at,
            )
            self.sessions.record_turn_reconciled(
                session_id=turn.session_id,
                turn_index=turn.turn_index,
                run_id=turn.run_id,
                terminal_event_id=turn.terminal_event_id,
                created_at=occurred_at,
            )
        return turns

    def _successful_response(self, run_id: str) -> tuple[str, str] | None:
        events = tuple(
            item for item in self.journal.iter_events(0)
            if item.payload.get("run_id") == run_id
        )
        terminals = [
            item for item in events
            if item.event_type == "run.terminal" and item.payload.get("terminal_state") == "SUCCEEDED"
        ]
        if terminals:
            terminal = terminals[-1]
            evidence_ref = terminal.payload.get("evidence_package_ref")
            if not isinstance(evidence_ref, str) or not evidence_ref.startswith("cas:"):
                raise SessionPersistenceError("successful run terminal lacks a CAS evidence package")
            raw = self.cas.open_verified(self.cas.resolve_reference(evidence_ref))
            expected_evidence_hash = terminal.payload.get("evidence_package_hash")
            if expected_evidence_hash != hashlib.sha256(raw).hexdigest():
                raise SessionPersistenceError("run evidence package hash mismatch during session reconciliation")
            try:
                evidence = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise SessionPersistenceError("run evidence package is not valid JSON") from error
            if evidence.get("run_id") != run_id or evidence.get("expected_terminal") != "SUCCEEDED":
                raise SessionPersistenceError("run evidence package does not bind successful terminal state")
            response = self._evidence_response(evidence)
            expected_response_hash = terminal.payload.get("response_hash") or terminal.payload.get("user_response_hash")
            if not response or expected_response_hash != hashlib.sha256(response.encode()).hexdigest():
                raise SessionPersistenceError("run response hash mismatch during session reconciliation")
            return response, terminal.event_id

        succeeded = [item for item in events if item.event_type == "autonomous.run-succeeded"]
        if not succeeded:
            return None
        event = succeeded[-1]
        record_ref = event.payload.get("record_ref")
        if not isinstance(record_ref, str) or not record_ref.startswith("cas:"):
            raise SessionPersistenceError("autonomous success lacks a CAS record")
        raw = self.cas.open_verified(self.cas.resolve_reference(record_ref))
        if event.payload.get("record_hash") != hashlib.sha256(raw).hexdigest():
            raise SessionPersistenceError("autonomous success record hash mismatch")
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SessionPersistenceError("autonomous success record is not valid JSON") from error
        response = str(record.get("payload", {}).get("response") or "").strip()
        if record.get("run_id") != run_id or record.get("event") != "run_succeeded" or not response:
            raise SessionPersistenceError("autonomous success record is not bound to the linked run")
        return response, event.event_id

    @staticmethod
    def _evidence_response(evidence: dict[str, Any]) -> str:
        if evidence.get("schema") == "SITINA_TRUE_MULTI_AGENT_RUN_EVIDENCE_V1":
            return str(evidence.get("user_response") or "").strip()
        if evidence.get("schema") == "SITINA_FAST_CONVERSATION_RUN_EVIDENCE_V1":
            call = evidence.get("call")
            if isinstance(call, dict) and isinstance(call.get("value"), dict):
                return str(call["value"].get("answer") or "").strip()
        return ""


__all__ = ["ConversationReconciler", "RecoverableTurn"]
