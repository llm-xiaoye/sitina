from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef, PublishedObjectReceipt
from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes, parse_canonical_json
from sitina.security.key_provider import InMemoryKeyProvider


Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$", min_length=1, max_length=255),
]
CASReference = Annotated[
    str,
    StringConstraints(pattern=r"^cas:[0-9a-f]{64}$", min_length=68, max_length=68),
]
HexDigest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=2_000)]
SummaryText = Annotated[str, StringConstraints(min_length=1, max_length=4_000)]


class SessionStateError(RuntimeError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class WorkingStateDecision(_StrictModel):
    decision: BoundedText
    evidence_refs: tuple[CASReference, ...] = Field(default=(), max_length=64)

    @field_validator("evidence_refs")
    @classmethod
    def _sorted_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("decision evidence_refs must be unique and sorted")
        return values


class WorkingState(_StrictModel):
    schema_id: str = Field(default="SITINA_SESSION_WORKING_STATE_V1", alias="schema", pattern=r"^SITINA_SESSION_WORKING_STATE_V1$")
    session_id: Identifier
    version: int = Field(ge=1)
    primary_goal: BoundedText
    constraints: tuple[BoundedText, ...] = Field(default=(), max_length=128)
    decisions: tuple[WorkingStateDecision, ...] = Field(default=(), max_length=128)
    completed_steps: tuple[BoundedText, ...] = Field(default=(), max_length=512)
    pending_items: tuple[BoundedText, ...] = Field(default=(), max_length=512)
    next_action: BoundedText
    source_frontier: int = Field(ge=0)
    previous_state_ref: CASReference | None = None


class WorkingStateChanges(_StrictModel):
    primary_goal: BoundedText | None = None
    constraints: tuple[BoundedText, ...] | None = Field(default=None, max_length=128)
    decisions: tuple[WorkingStateDecision, ...] | None = Field(default=None, max_length=128)
    completed_steps: tuple[BoundedText, ...] | None = Field(default=None, max_length=512)
    pending_items: tuple[BoundedText, ...] | None = Field(default=None, max_length=512)
    next_action: BoundedText | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> "WorkingStateChanges":
        if not self.model_fields_set:
            raise ValueError("working state delta must change at least one field")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("working state fields cannot be cleared to null")
        return self


class WorkingStateDelta(_StrictModel):
    schema_id: str = Field(default="SITINA_SESSION_WORKING_STATE_DELTA_V1", alias="schema", pattern=r"^SITINA_SESSION_WORKING_STATE_DELTA_V1$")
    session_id: Identifier
    from_version: int = Field(ge=1)
    to_version: int = Field(ge=2)
    previous_state_ref: CASReference
    source_frontier: int = Field(ge=0)
    changes: WorkingStateChanges

    @model_validator(mode="after")
    def _sequential(self) -> "WorkingStateDelta":
        if self.to_version != self.from_version + 1:
            raise ValueError("working state delta versions must be sequential")
        return self


class RollingSummaryContent(_StrictModel):
    schema_id: str = Field(default="SITINA_CONVERSATION_SUMMARY_CONTENT_V1", alias="schema", pattern=r"^SITINA_CONVERSATION_SUMMARY_CONTENT_V1$")
    confirmed: tuple[SummaryText, ...] = Field(default=(), max_length=256)
    inferred: tuple[SummaryText, ...] = Field(default=(), max_length=256)
    unresolved: tuple[SummaryText, ...] = Field(default=(), max_length=256)
    user_constraint: tuple[SummaryText, ...] = Field(default=(), max_length=256)
    system_decision: tuple[SummaryText, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def _has_content(self) -> "RollingSummaryContent":
        if not any((self.confirmed, self.inferred, self.unresolved, self.user_constraint, self.system_decision)):
            raise ValueError("rolling summary cannot be empty")
        return self


class RollingSummary(_StrictModel):
    schema_id: str = Field(default="SITINA_CONVERSATION_ROLLING_SUMMARY_V1", alias="schema", pattern=r"^SITINA_CONVERSATION_ROLLING_SUMMARY_V1$")
    session_id: Identifier
    summary_version: int = Field(ge=1)
    source_message_range: tuple[int, int]
    source_frontier: int = Field(ge=0)
    summary_ref: CASReference
    summary_hash: HexDigest
    previous_summary_ref: CASReference | None = None

    @model_validator(mode="after")
    def _valid_range(self) -> "RollingSummary":
        start, end = self.source_message_range
        if start < 1 or end < start:
            raise ValueError("rolling summary source message range is invalid")
        return self


@dataclass(frozen=True)
class WorkingStateSnapshot:
    state: WorkingState
    head_ref: str
    source_position: int


@dataclass(frozen=True)
class RollingSummarySnapshot:
    summary: RollingSummary
    content: RollingSummaryContent
    changed: bool
    source_position: int


class _SessionJournalCAS:
    TENANT = "sitina-conversation"

    def __init__(self, journal: LocalJournal, cas: LocalCAS, keys: InMemoryKeyProvider):
        self.journal = journal
        self.cas = cas
        self.keys = keys

    def _events(self, session_id: str) -> tuple[EventEnvelope, ...]:
        stream_id = f"session/{session_id}"
        return tuple(event for event in self.journal.iter_events(0) if event.stream_id == stream_id)

    @staticmethod
    def _digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()

    def _append(
        self,
        *,
        session_id: str,
        action: str,
        event_type: str,
        payload: Mapping[str, Any],
        occurred_at: str,
        proof: PublishedObjectReceipt,
    ) -> EventEnvelope:
        stream_id = f"session/{session_id}"
        digest = self._digest({"session_id": session_id, "action": action, "payload": dict(payload)})
        command = CommandEnvelope(
            "session-state-command-" + digest[:37],
            self.TENANT,
            stream_id,
            "session." + action,
            "journal-session-state-repository",
            occurred_at,
            {"session_id": session_id, "event_hash": digest},
        )
        event = EventEnvelope(
            "session-state-event-" + digest[:39],
            event_type,
            self.TENANT,
            stream_id,
            0,
            0,
            occurred_at,
            dict(payload),
            (proof.object_ref.reference_id,),
        )
        receipt = self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
            object_reference_proofs=(proof,),
        )
        return next(item for item in self.journal.iter_events(receipt.first_position - 1) if item.position == receipt.first_position)

    @staticmethod
    def _binding_payload(prefix: str, proof: PublishedObjectReceipt) -> dict[str, str]:
        reference = proof.object_ref
        return {
            f"{prefix}_ref": reference.reference_id,
            f"{prefix}_tenant_id": reference.tenant_id,
            f"{prefix}_plaintext_commitment": reference.plaintext_commitment,
            f"{prefix}_commitment_key_id": reference.commitment_key_id,
            f"{prefix}_profile": reference.profile,
        }

    @staticmethod
    def _object_ref(event: EventEnvelope, prefix: str) -> ObjectRef:
        payload = event.payload
        return ObjectRef(
            str(payload[f"{prefix}_ref"]).removeprefix("cas:"),
            str(payload[f"{prefix}_tenant_id"]),
            str(payload[f"{prefix}_plaintext_commitment"]),
            str(payload[f"{prefix}_commitment_key_id"]),
            str(payload[f"{prefix}_profile"]),
        )

    def _read_bound(self, event: EventEnvelope, prefix: str, expected_hash_field: str) -> tuple[ObjectRef, bytes]:
        reference = self._object_ref(event, prefix)
        raw = self.cas.open_verified(reference)
        if hashlib.sha256(raw).hexdigest() != event.payload[expected_hash_field]:
            raise SessionStateError(f"{prefix} CAS body hash mismatch")
        return reference, raw


class WorkingStateRepository(_SessionJournalCAS):
    def initialize(
        self,
        *,
        session_id: str,
        primary_goal: str,
        constraints: tuple[str, ...],
        decisions: tuple[WorkingStateDecision, ...],
        completed_steps: tuple[str, ...],
        pending_items: tuple[str, ...],
        next_action: str,
        source_frontier: int,
        occurred_at: str,
    ) -> WorkingStateSnapshot:
        if source_frontier > self.journal.head_position:
            raise SessionStateError("working state source frontier is beyond the verified Journal head")
        if any(event.event_type == "session.state-initialized" for event in self._events(session_id)):
            return self.recover(session_id)
        state = WorkingState(
            session_id=session_id,
            version=1,
            primary_goal=primary_goal,
            constraints=constraints,
            decisions=decisions,
            completed_steps=completed_steps,
            pending_items=pending_items,
            next_action=next_action,
            source_frontier=source_frontier,
            previous_state_ref=None,
        )
        raw = canonical_json_bytes(state.model_dump(mode="json", by_alias=True))
        proof = self.cas.publish_verified(
            encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="session-working-state-base")
        )
        state_hash = hashlib.sha256(raw).hexdigest()
        event = self._append(
            session_id=session_id,
            action="state-initialize",
            event_type="session.state-initialized",
            payload={
                "schema": "SITINA_SESSION_STATE_INITIALIZED_V1",
                "session_id": session_id,
                "version": 1,
                "state_hash": state_hash,
                "source_frontier": source_frontier,
                **self._binding_payload("state", proof),
            },
            occurred_at=occurred_at,
            proof=proof,
        )
        return WorkingStateSnapshot(state, proof.object_ref.reference_id, event.position)

    def update(
        self,
        *,
        session_id: str,
        expected_version: int,
        changes: WorkingStateChanges,
        source_frontier: int,
        occurred_at: str,
    ) -> WorkingStateSnapshot:
        if source_frontier > self.journal.head_position:
            raise SessionStateError("working state source frontier is beyond the verified Journal head")
        current = self.recover(session_id)
        if current.state.version != expected_version:
            raise SessionStateError("working state expected version conflict")
        changed_values = changes.model_dump(mode="json", exclude_unset=True)
        next_state = WorkingState.model_validate(
            {
                **current.state.model_dump(mode="json", by_alias=True),
                **changed_values,
                "version": expected_version + 1,
                "source_frontier": source_frontier,
                "previous_state_ref": current.head_ref,
            }
        )
        delta = WorkingStateDelta(
            session_id=session_id,
            from_version=expected_version,
            to_version=expected_version + 1,
            previous_state_ref=current.head_ref,
            source_frontier=source_frontier,
            changes=changes,
        )
        raw = canonical_json_bytes(delta.model_dump(mode="json", by_alias=True, exclude_none=True))
        proof = self.cas.publish_verified(
            encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="session-working-state-delta")
        )
        delta_hash = hashlib.sha256(raw).hexdigest()
        event = self._append(
            session_id=session_id,
            action="state-update",
            event_type="session.state-updated",
            payload={
                "schema": "SITINA_SESSION_STATE_UPDATED_V1",
                "session_id": session_id,
                "from_version": expected_version,
                "to_version": expected_version + 1,
                "previous_state_ref": current.head_ref,
                "delta_hash": delta_hash,
                "source_frontier": source_frontier,
                **self._binding_payload("delta", proof),
            },
            occurred_at=occurred_at,
            proof=proof,
        )
        return WorkingStateSnapshot(next_state, proof.object_ref.reference_id, event.position)

    def recover(self, session_id: str) -> WorkingStateSnapshot:
        events = [
            event
            for event in self._events(session_id)
            if event.event_type in {"session.state-initialized", "session.state-updated"}
        ]
        if not events or events[0].event_type != "session.state-initialized":
            raise SessionStateError("session has no initialized working state")
        base_ref, raw = self._read_bound(events[0], "state", "state_hash")
        value = parse_canonical_json(raw)
        state = WorkingState.model_validate(value)
        if state.session_id != session_id or state.version != 1:
            raise SessionStateError("working state base identity/version mismatch")
        head_ref = base_ref.reference_id
        source_position = events[0].position
        for event in events[1:]:
            delta_ref, raw = self._read_bound(event, "delta", "delta_hash")
            delta = WorkingStateDelta.model_validate(parse_canonical_json(raw))
            if (
                delta.session_id != session_id
                or delta.from_version != state.version
                or delta.previous_state_ref != head_ref
                or event.payload.get("previous_state_ref") != head_ref
            ):
                raise SessionStateError("working state delta chain is discontinuous")
            state = WorkingState.model_validate(
                {
                    **state.model_dump(mode="json", by_alias=True),
                    **delta.changes.model_dump(mode="json", exclude_unset=True),
                    "version": delta.to_version,
                    "source_frontier": delta.source_frontier,
                    "previous_state_ref": head_ref,
                }
            )
            head_ref = delta_ref.reference_id
            source_position = event.position
        return WorkingStateSnapshot(state, head_ref, source_position)


class RollingSummaryRepository(_SessionJournalCAS):
    def update(
        self,
        *,
        session_id: str,
        content: RollingSummaryContent,
        source_message_range: tuple[int, int],
        source_frontier: int,
        occurred_at: str,
    ) -> RollingSummarySnapshot:
        if source_frontier > self.journal.head_position:
            raise SessionStateError("rolling summary source frontier is beyond the verified Journal head")
        raw = canonical_json_bytes(content.model_dump(mode="json", by_alias=True))
        summary_hash = hashlib.sha256(raw).hexdigest()
        current = self._recover_optional(session_id)
        if current is not None and current.summary.summary_hash == summary_hash:
            return RollingSummarySnapshot(current.summary, current.content, False, current.source_position)
        if current is not None:
            if source_message_range[1] < current.summary.source_message_range[1] or source_frontier < current.summary.source_frontier:
                raise SessionStateError("rolling summary source coverage cannot regress")
        proof = self.cas.publish_verified(
            encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="conversation-rolling-summary")
        )
        summary = RollingSummary(
            session_id=session_id,
            summary_version=1 if current is None else current.summary.summary_version + 1,
            source_message_range=source_message_range,
            source_frontier=source_frontier,
            summary_ref=proof.object_ref.reference_id,
            summary_hash=summary_hash,
            previous_summary_ref=None if current is None else current.summary.summary_ref,
        )
        event = self._append(
            session_id=session_id,
            action="summary-update",
            event_type="session.summary-updated",
            payload={
                **summary.model_dump(mode="json", by_alias=True),
                **self._binding_payload("summary", proof),
            },
            occurred_at=occurred_at,
            proof=proof,
        )
        return RollingSummarySnapshot(summary, content, True, event.position)

    def _recover_optional(self, session_id: str) -> RollingSummarySnapshot | None:
        events = [event for event in self._events(session_id) if event.event_type == "session.summary-updated"]
        if not events:
            return None
        previous: RollingSummary | None = None
        content: RollingSummaryContent | None = None
        for index, event in enumerate(events, 1):
            summary = RollingSummary.model_validate(
                {
                    key: value
                    for key, value in event.payload.items()
                    if key
                    in {
                        "schema",
                        "session_id",
                        "summary_version",
                        "source_message_range",
                        "source_frontier",
                        "summary_ref",
                        "summary_hash",
                        "previous_summary_ref",
                    }
                }
            )
            if summary.session_id != session_id or summary.summary_version != index:
                raise SessionStateError("rolling summary chain identity/version mismatch")
            if previous is not None and summary.previous_summary_ref != previous.summary_ref:
                raise SessionStateError("rolling summary previous reference mismatch")
            reference, raw = self._read_bound(event, "summary", "summary_hash")
            if reference.reference_id != summary.summary_ref:
                raise SessionStateError("rolling summary event binds a different CAS object")
            content = RollingSummaryContent.model_validate(parse_canonical_json(raw))
            previous = summary
        assert previous is not None and content is not None
        return RollingSummarySnapshot(previous, content, True, events[-1].position)

    def recover(self, session_id: str) -> RollingSummarySnapshot:
        recovered = self._recover_optional(session_id)
        if recovered is None:
            raise SessionStateError("session has no rolling summary")
        return recovered
