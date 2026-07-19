from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef, PublishedObjectReceipt
from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes
from sitina.security.key_provider import InMemoryKeyProvider


class SessionPersistenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class PersistedMessage:
    session_id: str
    message_id: str
    role: str
    turn_index: int
    body_ref: str
    body_hash: str
    journal_position: int
    object_ref: ObjectRef


class JournalSessionRepository:
    """Journal lifecycle plus CAS-only message bodies; never writes Legacy JSON/SQLite."""

    TENANT = "sitina-conversation"

    def __init__(self, journal: LocalJournal, cas: LocalCAS, key_provider: InMemoryKeyProvider):
        self.journal = journal
        self.cas = cas
        self.keys = key_provider

    @staticmethod
    def _digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()

    def _events(self, session_id: str) -> tuple[EventEnvelope, ...]:
        stream_id = f"session/{session_id}"
        return tuple(item for item in self.journal.iter_events(0) if item.stream_id == stream_id)

    def _append(
        self,
        *,
        session_id: str,
        stage: str,
        event_type: str,
        payload: Mapping[str, Any],
        created_at: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        object_refs: Sequence[str] = (),
    ) -> EventEnvelope:
        stream_id = f"session/{session_id}"
        expected = self.journal._stream_heads.get(stream_id, 0)
        event_payload = dict(payload)
        digest = self._digest(
            {
                "session_id": session_id,
                "stage": stage,
                "event_type": event_type,
                "payload": event_payload,
            }
        )
        command = CommandEnvelope(
            "session-command-" + digest[:44],
            self.TENANT,
            stream_id,
            "session." + stage,
            "journal-session-repository",
            created_at,
            {"session_id": session_id, "event_hash": digest},
        )
        event = EventEnvelope(
            "session-event-" + digest[:46],
            event_type,
            self.TENANT,
            stream_id,
            0,
            0,
            created_at,
            event_payload,
            tuple(sorted(object_refs)),
        )
        receipt = self.journal.append(command, expected, [event], object_reference_proofs=proofs)
        return next(item for item in self.journal.iter_events(receipt.first_position - 1) if item.position == receipt.first_position)

    def ensure_created(self, *, session_id: str, title: str, created_at: str) -> EventEnvelope:
        existing = next((item for item in self._events(session_id) if item.event_type == "session.created"), None)
        if existing is not None:
            return existing
        return self._append(
            session_id=session_id,
            stage="create",
            event_type="session.created",
            payload={
                "schema": "SESSION_CREATED_V1",
                "event_type": "session.created",
                "session_id": session_id,
                "title": title,
                "created_at": created_at,
            },
            created_at=created_at,
        )

    def append_message(
        self,
        *,
        session_id: str,
        message_id: str,
        role: str,
        body: str,
        turn_index: int,
        created_at: str,
    ) -> PersistedMessage:
        if role not in {"user", "assistant", "system", "tool"} or not body:
            raise SessionPersistenceError("message role/body is invalid")
        existing = next(
            (
                item
                for item in self._events(session_id)
                if item.event_type == "session.message-appended" and item.payload.get("message_id") == message_id
            ),
            None,
        )
        if existing is not None:
            if (
                existing.payload.get("body_hash") != hashlib.sha256(body.encode()).hexdigest()
                or existing.payload.get("role") != role
                or int(existing.payload.get("turn_index", -1)) != turn_index
            ):
                raise SessionPersistenceError("message identity is bound to different content")
            reference = self._object_ref(existing.payload)
            self.cas.open_verified(reference)
            return PersistedMessage(
                session_id,
                message_id,
                role,
                turn_index,
                reference.reference_id,
                str(existing.payload["body_hash"]),
                existing.position,
                reference,
            )
        plaintext = body.encode("utf-8")
        encrypted = encrypt_object(plaintext, self.keys, tenant_id=self.TENANT, purpose="session-message")
        published = self.cas.publish_verified(encrypted)
        reference = published.object_ref
        body_hash = hashlib.sha256(plaintext).hexdigest()
        event = self._append(
            session_id=session_id,
            stage="append-message",
            event_type="session.message-appended",
            payload={
                "schema": "SESSION_MESSAGE_APPENDED_V1",
                "event_type": "session.message-appended",
                "session_id": session_id,
                "message_id": message_id,
                "role": role,
                "body_ref": reference.reference_id,
                "body_hash": body_hash,
                "body_tenant_id": reference.tenant_id,
                "body_plaintext_commitment": reference.plaintext_commitment,
                "body_commitment_key_id": reference.commitment_key_id,
                "turn_index": turn_index,
                "created_at": created_at,
            },
            created_at=created_at,
            proofs=(published,),
            object_refs=(reference.reference_id,),
        )
        return PersistedMessage(session_id, message_id, role, turn_index, reference.reference_id, body_hash, event.position, reference)

    def append_existing_message_ref(
        self,
        *,
        session_id: str,
        message_id: str,
        role: str,
        body_hash: str,
        turn_index: int,
        created_at: str,
        published: PublishedObjectReceipt,
        body_selector: str | None = None,
    ) -> PersistedMessage:
        existing = next(
            (
                item
                for item in self._events(session_id)
                if item.event_type == "session.message-appended" and item.payload.get("message_id") == message_id
            ),
            None,
        )
        if existing is not None:
            if (
                existing.payload.get("body_hash") != body_hash
                or existing.payload.get("role") != role
                or int(existing.payload.get("turn_index", -1)) != turn_index
            ):
                raise SessionPersistenceError("message identity is bound to different content")
            existing_reference = self._object_ref(existing.payload)
            self.cas.open_verified(existing_reference)
            return PersistedMessage(
                session_id,
                message_id,
                role,
                turn_index,
                existing_reference.reference_id,
                body_hash,
                existing.position,
                existing_reference,
            )
        reference = published.object_ref
        event = self._append(
            session_id=session_id,
            stage="append-message-ref",
            event_type="session.message-appended",
            payload={
                "schema": "SESSION_MESSAGE_APPENDED_V1",
                "event_type": "session.message-appended",
                "session_id": session_id,
                "message_id": message_id,
                "role": role,
                "body_ref": reference.reference_id,
                "body_hash": body_hash,
                "body_tenant_id": reference.tenant_id,
                "body_plaintext_commitment": reference.plaintext_commitment,
                "body_commitment_key_id": reference.commitment_key_id,
                "body_selector": body_selector,
                "turn_index": turn_index,
                "created_at": created_at,
            },
            created_at=created_at,
            proofs=(published,),
            object_refs=(reference.reference_id,),
        )
        return PersistedMessage(session_id, message_id, role, turn_index, reference.reference_id, body_hash, event.position, reference)

    def link_run(self, *, session_id: str, run_id: str, turn_index: int, created_at: str) -> EventEnvelope:
        existing = next(
            (
                item
                for item in self._events(session_id)
                if item.event_type == "session.run-linked"
                and item.payload.get("run_id") == run_id
                and int(item.payload.get("turn_index", -1)) == turn_index
            ),
            None,
        )
        if existing is not None:
            return existing
        return self._append(
            session_id=session_id,
            stage="link-run",
            event_type="session.run-linked",
            payload={
                "schema": "SESSION_RUN_LINKED_V1",
                "event_type": "session.run-linked",
                "session_id": session_id,
                "run_id": run_id,
                "turn_index": turn_index,
                "created_at": created_at,
            },
            created_at=created_at,
        )

    def record_turn_failed(self, *, session_id: str, turn_index: int, error_type: str, created_at: str) -> EventEnvelope:
        existing = next(
            (
                item
                for item in self._events(session_id)
                if item.event_type == "session.turn-failed"
                and int(item.payload.get("turn_index", -1)) == turn_index
                and item.payload.get("error_type") == error_type
            ),
            None,
        )
        if existing is not None:
            return existing
        return self._append(
            session_id=session_id,
            stage="turn-failed",
            event_type="session.turn-failed",
            payload={
                "schema": "SESSION_TURN_FAILED_V1",
                "event_type": "session.turn-failed",
                "session_id": session_id,
                "turn_index": turn_index,
                "error_type": error_type,
                "created_at": created_at,
            },
            created_at=created_at,
        )

    def record_turn_reconciled(
        self,
        *,
        session_id: str,
        turn_index: int,
        run_id: str,
        terminal_event_id: str,
        created_at: str,
    ) -> EventEnvelope:
        existing = next(
            (
                item
                for item in self._events(session_id)
                if item.event_type == "session.turn-reconciled"
                and int(item.payload.get("turn_index", -1)) == turn_index
            ),
            None,
        )
        if existing is not None:
            if (
                existing.payload.get("run_id") != run_id
                or existing.payload.get("terminal_event_id") != terminal_event_id
            ):
                raise SessionPersistenceError("session turn reconciliation is bound to different evidence")
            return existing
        return self._append(
            session_id=session_id,
            stage="turn-reconciled",
            event_type="session.turn-reconciled",
            payload={
                "schema": "SESSION_TURN_RECONCILED_V1",
                "event_type": "session.turn-reconciled",
                "session_id": session_id,
                "turn_index": turn_index,
                "run_id": run_id,
                "terminal_event_id": terminal_event_id,
                "automatic_provider_retry_performed": False,
                "created_at": created_at,
            },
            created_at=created_at,
        )

    def record_mode_changed(self, *, session_id: str, mode: str, created_at: str) -> EventEnvelope:
        normalized = str(mode).upper()
        if normalized not in {"AUTO", "FAST", "MULTI"}:
            raise SessionPersistenceError("session mode is invalid")
        prior = next(
            (item for item in reversed(self._events(session_id)) if item.event_type == "session.mode-changed"),
            None,
        )
        if prior is not None and prior.payload.get("mode") == normalized:
            return prior
        return self._append(
            session_id=session_id,
            stage="mode-change",
            event_type="session.mode-changed",
            payload={
                "schema": "SESSION_MODE_CHANGED_V1",
                "event_type": "session.mode-changed",
                "session_id": session_id,
                "mode": normalized,
                "created_at": created_at,
            },
            created_at=created_at,
        )

    def record_route_decision(
        self,
        *,
        session_id: str,
        turn_index: int,
        decision: Mapping[str, Any],
        created_at: str,
    ) -> EventEnvelope:
        normalized = dict(decision)
        existing = next(
            (
                item
                for item in self._events(session_id)
                if item.event_type == "session.route-decided"
                and int(item.payload.get("turn_index", -1)) == turn_index
            ),
            None,
        )
        if existing is not None:
            if existing.payload.get("decision") != normalized:
                raise SessionPersistenceError("session turn is bound to a different route decision")
            return existing
        return self._append(
            session_id=session_id,
            stage="route-decision",
            event_type="session.route-decided",
            payload={
                "schema": "SESSION_ROUTE_DECIDED_V1",
                "event_type": "session.route-decided",
                "session_id": session_id,
                "turn_index": turn_index,
                "decision": normalized,
                "created_at": created_at,
            },
            created_at=created_at,
        )

    def latest_session_id(self) -> str | None:
        created: set[str] = set()
        latest: tuple[int, str] | None = None
        for event in self.journal.iter_events(0):
            if event.event_type == "session.created":
                created.add(str(event.payload.get("session_id") or event.stream_id.removeprefix("session/")))
            if not event.stream_id.startswith("session/"):
                continue
            session_id = event.stream_id.removeprefix("session/")
            if session_id in created or event.event_type == "session.created":
                candidate = (event.position, session_id)
                if latest is None or candidate > latest:
                    latest = candidate
        return latest[1] if latest is not None else None

    @staticmethod
    def _object_ref(payload: Mapping[str, Any]) -> ObjectRef:
        reference = str(payload["body_ref"])
        if not reference.startswith("cas:"):
            raise SessionPersistenceError("message body has an unsupported reference")
        return ObjectRef(
            reference.removeprefix("cas:"),
            str(payload["body_tenant_id"]),
            str(payload["body_plaintext_commitment"]),
            str(payload["body_commitment_key_id"]),
        )

    def recover(self, session_id: str) -> dict[str, Any]:
        events = self._events(session_id)
        created = next((item for item in events if item.event_type == "session.created"), None)
        if created is None:
            raise SessionPersistenceError("session was not created in the Journal")
        messages = []
        failed_turns = []
        runs = []
        route_decisions = []
        mode = "AUTO"
        turn_index = 0
        for event in events:
            if event.event_type == "session.message-appended":
                reference = self._object_ref(event.payload)
                raw = self.cas.open_verified(reference)
                body = raw.decode("utf-8")
                selector = event.payload.get("body_selector")
                if selector:
                    import json

                    value = json.loads(body)
                    body = str(value[selector])
                if hashlib.sha256(body.encode()).hexdigest() != event.payload["body_hash"]:
                    raise SessionPersistenceError("session message body hash mismatch")
                messages.append(
                    {
                        "message_id": event.payload["message_id"],
                        "role": event.payload["role"],
                        "body": body,
                        "body_ref": reference.reference_id,
                        "turn_index": event.payload["turn_index"],
                        "source_position": event.position,
                        "source_event_id": event.event_id,
                        "schema_version": 1,
                    }
                )
                turn_index = max(turn_index, int(event.payload["turn_index"]))
            elif event.event_type == "session.turn-failed":
                failed_turns.append(int(event.payload["turn_index"]))
                turn_index = max(turn_index, int(event.payload["turn_index"]))
            elif event.event_type == "session.run-linked":
                run_id = str(event.payload["run_id"])
                if run_id not in runs:
                    runs.append(run_id)
                turn_index = max(turn_index, int(event.payload["turn_index"]))
            elif event.event_type == "session.mode-changed":
                mode = str(event.payload["mode"])
            elif event.event_type == "session.route-decided":
                route_decisions.append(
                    {
                        "turn_index": int(event.payload["turn_index"]),
                        "decision": dict(event.payload["decision"]),
                        "source_position": event.position,
                    }
                )
                turn_index = max(turn_index, int(event.payload["turn_index"]))
                mode = str(event.payload["decision"].get("requested_mode") or mode)
        by_turn: dict[int, dict[str, str]] = {}
        for message in messages:
            if message["role"] in {"user", "assistant"}:
                by_turn.setdefault(int(message["turn_index"]), {})[str(message["role"])] = str(message["body"])
        successful_turns = [
            {"turn_index": index, "user": pair["user"], "assistant": pair["assistant"]}
            for index, pair in sorted(by_turn.items())
            if "user" in pair and "assistant" in pair
        ]
        return {
            "session_id": session_id,
            "title": created.payload["title"],
            "mode": mode,
            "turn_index": turn_index,
            "messages": messages,
            "successful_turns": successful_turns,
            "failed_turns": failed_turns,
            "run_ids": runs,
            "route_decisions": route_decisions,
            "source_frontier": events[-1].position,
        }
