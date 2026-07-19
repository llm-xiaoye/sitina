from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
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
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=4_000)]


class NativeBlackboardError(RuntimeError):
    pass


class NativeBlackboardConflict(NativeBlackboardError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class NativeBlackboardDocument(_StrictModel):
    document_id: Identifier
    task_id: Identifier
    author_agent_id: Identifier
    document_type: Literal[
        "claim",
        "evidence",
        "question",
        "conflict",
        "proposal",
        "decision",
        "gate_note",
        "lease_note",
        "arbitration_note",
        "risk_note",
        "test_note",
        "review_note",
        "backlog_candidate",
    ]
    content_summary: BoundedText
    artifact_refs: tuple[CASReference, ...] = Field(default=(), max_length=128)
    related_document_ids: tuple[Identifier, ...] = Field(default=(), max_length=128)
    version: int = Field(ge=1)

    @model_validator(mode="after")
    def _sets(self) -> "NativeBlackboardDocument":
        if tuple(sorted(set(self.artifact_refs))) != self.artifact_refs:
            raise ValueError("blackboard artifact refs must be unique and sorted")
        if tuple(sorted(set(self.related_document_ids))) != self.related_document_ids:
            raise ValueError("blackboard related ids must be unique and sorted")
        if self.document_id in self.related_document_ids:
            raise ValueError("blackboard document cannot relate to itself")
        return self


class BlackboardBaseSnapshotV1(_StrictModel):
    schema_id: Literal["SITINA_BLACKBOARD_BASE_SNAPSHOT_V1"] = Field(
        default="SITINA_BLACKBOARD_BASE_SNAPSHOT_V1",
        alias="schema",
    )
    run_id: Identifier
    base_version: int = Field(ge=0)
    documents: tuple[NativeBlackboardDocument, ...] = Field(default=(), max_length=10_000)
    source_frontier: int = Field(ge=0)
    previous_base_ref: CASReference | None
    independent_recovery_point: bool

    @model_validator(mode="after")
    def _documents_unique(self) -> "BlackboardBaseSnapshotV1":
        ids = [document.document_id for document in self.documents]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("blackboard base documents must be unique and sorted")
        if self.independent_recovery_point and self.previous_base_ref is not None:
            raise ValueError("independent blackboard base cannot depend on an older base")
        return self


class BlackboardPatchV1(_StrictModel):
    schema_id: Literal["SITINA_BLACKBOARD_PATCH_V1"] = Field(default="SITINA_BLACKBOARD_PATCH_V1", alias="schema")
    patch_id: Identifier
    run_id: Identifier
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=1)
    operation: Literal["add", "update", "remove"]
    document_id: Identifier
    expected_document_version: int | None = Field(default=None, ge=1)
    document: NativeBlackboardDocument | None
    source_frontier: int = Field(ge=0)

    @model_validator(mode="after")
    def _shape(self) -> "BlackboardPatchV1":
        if self.to_version != self.from_version + 1:
            raise ValueError("blackboard patch versions must be sequential")
        if self.operation == "add":
            if self.expected_document_version is not None or self.document is None or self.document.version != 1:
                raise ValueError("blackboard add patch requires a new version-one document")
        elif self.operation == "update":
            if self.expected_document_version is None or self.document is None:
                raise ValueError("blackboard update patch requires expected version and document")
            if self.document.version != self.expected_document_version + 1:
                raise ValueError("blackboard update document version is not sequential")
        elif self.document is not None or self.expected_document_version is None:
            raise ValueError("blackboard remove patch requires expected version and no document")
        if self.document is not None and self.document.document_id != self.document_id:
            raise ValueError("blackboard patch document identity differs")
        return self


@dataclass(frozen=True)
class NativeBlackboardSnapshot:
    run_id: str
    version: int
    documents: tuple[NativeBlackboardDocument, ...]
    base_ref: str
    base_raw_size: int
    patch_count: int
    delta_raw_size: int
    source_position: int


class NativeBlackboardRepository:
    TENANT = "sitina-blackboard"

    def __init__(
        self,
        journal: LocalJournal,
        cas: LocalCAS,
        keys: InMemoryKeyProvider,
        *,
        feature_activations: FeatureActivationRegistry | None = None,
        patch_limit: int = 50,
        delta_to_base_ratio: float = 0.5,
    ):
        if patch_limit < 1 or delta_to_base_ratio <= 0:
            raise ValueError("blackboard compaction thresholds are invalid")
        self.journal = journal
        self.cas = cas
        self.keys = keys
        self.feature_activations = feature_activations
        self.patch_limit = patch_limit
        self.delta_to_base_ratio = delta_to_base_ratio

    def _assert_write_enabled(self) -> FeatureActivationRegistry:
        if self.feature_activations is None:
            raise NativeBlackboardError("Blackboard native writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("journal_event_v2_write")
        return self.feature_activations

    def _events(self, run_id: str) -> tuple[EventEnvelope, ...]:
        return tuple(
            event
            for event in self.journal.iter_events(0)
            if event.stream_id == f"run/{run_id}" or event.payload.get("run_id") == run_id
        )

    def _run_tenant(self, run_id: str) -> str:
        events = self._events(run_id)
        if not events:
            raise NativeBlackboardError("native Blackboard requires a canonical run")
        return events[0].tenant_id

    def _append_object(
        self,
        *,
        run_id: str,
        action: str,
        event_type: str,
        payload: Mapping[str, Any],
        raw: bytes,
        purpose: str,
        occurred_at: str,
    ) -> tuple[EventEnvelope, ObjectRef]:
        tenant_id = self._run_tenant(run_id)
        published = self.cas.publish_verified(encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose=purpose))
        reference = published.object_ref
        full_payload = {
            **dict(payload),
            "object_ref": reference.reference_id,
            "object_hash": hashlib.sha256(raw).hexdigest(),
        }
        digest = hashlib.sha256(canonical_json_bytes(full_payload)).hexdigest()
        stream_id = f"run/{run_id}"
        command = CommandEnvelope(
            "blackboard-command-" + digest[:40],
            tenant_id,
            stream_id,
            "blackboard." + action,
            "native-blackboard-repository",
            occurred_at,
            {"run_id": run_id, "object_hash": full_payload["object_hash"]},
        )
        event = EventEnvelope(
            "blackboard-event-" + digest[:42],
            event_type,
            tenant_id,
            stream_id,
            0,
            0,
            occurred_at,
            full_payload,
            (reference.reference_id,),
        )
        receipt = self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
            object_reference_proofs=(published,),
        )
        committed = next(item for item in self.journal.iter_events(receipt.first_position - 1) if item.position == receipt.first_position)
        return committed, reference

    def initialize(self, *, run_id: str, occurred_at: str) -> NativeBlackboardSnapshot:
        activations = self._assert_write_enabled()
        if any(event.event_type == "blackboard.base-published" for event in self._events(run_id)):
            return self.recover(run_id)
        base = BlackboardBaseSnapshotV1(
            run_id=run_id,
            base_version=0,
            documents=(),
            source_frontier=self.journal.head_position,
            previous_base_ref=None,
            independent_recovery_point=True,
        )
        raw = canonical_json_bytes(base.model_dump(mode="json", by_alias=True))
        event, reference = self._append_object(
            run_id=run_id,
            action="base-publish",
            event_type="blackboard.base-published",
            payload={
                "schema": "SITINA_BLACKBOARD_BASE_PUBLISHED_V1",
                "run_id": run_id,
                "base_version": 0,
                "independent_recovery_point": True,
                "compaction_reason": "initialize",
            },
            raw=raw,
            purpose="blackboard-base",
            occurred_at=occurred_at,
        )
        activations.record_first_write("journal_event_v2_write", journal_position=event.position)
        return NativeBlackboardSnapshot(run_id, 0, (), reference.reference_id, len(raw), 0, 0, event.position)

    def recover(self, run_id: str) -> NativeBlackboardSnapshot:
        events = [event for event in self._events(run_id) if event.event_type in {"blackboard.base-published", "blackboard.patch-published"}]
        base_indexes = [index for index, event in enumerate(events) if event.event_type == "blackboard.base-published"]
        if not base_indexes:
            raise NativeBlackboardError("run has no native Blackboard base")
        start = base_indexes[-1]
        base_event = events[start]
        base_ref = self.cas.resolve_reference(str(base_event.payload["object_ref"]))
        base_raw = self.cas.open_verified(base_ref)
        if hashlib.sha256(base_raw).hexdigest() != base_event.payload.get("object_hash"):
            raise NativeBlackboardError("Blackboard base body hash mismatch")
        base = BlackboardBaseSnapshotV1.model_validate(parse_canonical_json(base_raw))
        if base.run_id != run_id or base.base_version != int(base_event.payload["base_version"]):
            raise NativeBlackboardError("Blackboard base publication identity mismatch")
        documents = {document.document_id: document for document in base.documents}
        version = base.base_version
        delta_bytes = 0
        patch_count = 0
        source_position = base_event.position
        for event in events[start + 1 :]:
            if event.event_type != "blackboard.patch-published":
                continue
            patch_ref = self.cas.resolve_reference(str(event.payload["object_ref"]))
            raw = self.cas.open_verified(patch_ref)
            if hashlib.sha256(raw).hexdigest() != event.payload.get("object_hash"):
                raise NativeBlackboardError("Blackboard patch body hash mismatch")
            patch = BlackboardPatchV1.model_validate(parse_canonical_json(raw))
            if patch.run_id != run_id or patch.from_version != version:
                raise NativeBlackboardError("Blackboard patch chain is discontinuous")
            self._apply(documents, patch)
            version = patch.to_version
            delta_bytes += len(raw)
            patch_count += 1
            source_position = event.position
        return NativeBlackboardSnapshot(
            run_id,
            version,
            tuple(documents[key] for key in sorted(documents)),
            base_ref.reference_id,
            len(base_raw),
            patch_count,
            delta_bytes,
            source_position,
        )

    @staticmethod
    def _apply(documents: dict[str, NativeBlackboardDocument], patch: BlackboardPatchV1) -> None:
        current = documents.get(patch.document_id)
        if patch.operation == "add":
            if current is not None:
                raise NativeBlackboardConflict("blackboard add collided with an existing document")
            assert patch.document is not None
            documents[patch.document_id] = patch.document
        elif patch.operation == "update":
            if current is None or current.version != patch.expected_document_version:
                raise NativeBlackboardConflict("blackboard update expected version conflict")
            assert patch.document is not None
            documents[patch.document_id] = patch.document
        else:
            if current is None or current.version != patch.expected_document_version:
                raise NativeBlackboardConflict("blackboard remove expected version conflict")
            del documents[patch.document_id]

    def apply_patch(self, patch: BlackboardPatchV1, *, occurred_at: str) -> NativeBlackboardSnapshot:
        activations = self._assert_write_enabled()
        current = self.recover(patch.run_id)
        if patch.from_version != current.version:
            raise NativeBlackboardConflict("blackboard partition version conflict")
        if patch.source_frontier > self.journal.head_position:
            raise NativeBlackboardError("blackboard patch source frontier is beyond Journal head")
        documents = {document.document_id: document for document in current.documents}
        self._apply(documents, patch)
        raw = canonical_json_bytes(patch.model_dump(mode="json", by_alias=True, exclude_none=True))
        event, _reference = self._append_object(
            run_id=patch.run_id,
            action="patch-publish",
            event_type="blackboard.patch-published",
            payload={
                "schema": "SITINA_BLACKBOARD_PATCH_PUBLISHED_V1",
                "run_id": patch.run_id,
                "patch_id": patch.patch_id,
                "from_version": patch.from_version,
                "to_version": patch.to_version,
                "operation": patch.operation,
                "document_id": patch.document_id,
            },
            raw=raw,
            purpose="blackboard-patch",
            occurred_at=occurred_at,
        )
        activations.record_first_write("journal_event_v2_write", journal_position=event.position)
        updated = self.recover(patch.run_id)
        ratio_limit = max(1, int(updated.base_raw_size * self.delta_to_base_ratio))
        if updated.patch_count >= self.patch_limit:
            return self.compact(run_id=patch.run_id, reason="patch-count", occurred_at=occurred_at)
        if updated.delta_raw_size > ratio_limit:
            return self.compact(run_id=patch.run_id, reason="delta-ratio", occurred_at=occurred_at)
        return updated

    def compact(
        self,
        *,
        run_id: str,
        reason: Literal["patch-count", "delta-ratio", "terminal", "pre-deletion"],
        occurred_at: str,
    ) -> NativeBlackboardSnapshot:
        activations = self._assert_write_enabled()
        current = self.recover(run_id)
        if reason == "terminal" and not any(event.event_type == "run.terminal" for event in self._events(run_id)):
            raise NativeBlackboardError("terminal Blackboard compaction requires run.terminal")
        independent = reason in {"terminal", "pre-deletion"}
        base = BlackboardBaseSnapshotV1(
            run_id=run_id,
            base_version=current.version,
            documents=current.documents,
            source_frontier=self.journal.head_position,
            previous_base_ref=None if independent else current.base_ref,
            independent_recovery_point=independent,
        )
        raw = canonical_json_bytes(base.model_dump(mode="json", by_alias=True))
        event, reference = self._append_object(
            run_id=run_id,
            action="base-compact",
            event_type="blackboard.base-published",
            payload={
                "schema": "SITINA_BLACKBOARD_BASE_PUBLISHED_V1",
                "run_id": run_id,
                "base_version": current.version,
                "independent_recovery_point": independent,
                "compaction_reason": reason,
                "superseded_base_ref": current.base_ref,
                "compacted_patch_count": current.patch_count,
            },
            raw=raw,
            purpose="blackboard-base",
            occurred_at=occurred_at,
        )
        activations.record_first_write("journal_event_v2_write", journal_position=event.position)
        return NativeBlackboardSnapshot(
            run_id,
            current.version,
            current.documents,
            reference.reference_id,
            len(raw),
            0,
            0,
            event.position,
        )


__all__ = [
    "BlackboardBaseSnapshotV1",
    "BlackboardPatchV1",
    "NativeBlackboardConflict",
    "NativeBlackboardDocument",
    "NativeBlackboardError",
    "NativeBlackboardRepository",
    "NativeBlackboardSnapshot",
]
