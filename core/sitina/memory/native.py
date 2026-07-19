from __future__ import annotations

import datetime as dt
import hashlib
import re
from typing import Annotated, Any, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef, PublishedObjectReceipt
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes, validate_timestamp
from sitina.security.key_provider import InMemoryKeyProvider


_MEMORY_ID = re.compile(r"^memory-[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_EPISODE_ID = re.compile(r"^episode-[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_CAS_REF = re.compile(r"^cas:[0-9a-f]{64}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")

MemoryId = Annotated[str, StringConstraints(pattern=_MEMORY_ID.pattern, min_length=8, max_length=127)]
EpisodeId = Annotated[str, StringConstraints(pattern=_EPISODE_ID.pattern, min_length=9, max_length=128)]
CASReference = Annotated[str, StringConstraints(pattern=_CAS_REF.pattern, min_length=68, max_length=68)]
HexDigest = Annotated[str, StringConstraints(pattern=_HASH.pattern, min_length=64, max_length=64)]
Principal = Annotated[str, StringConstraints(pattern=_PRINCIPAL.pattern, min_length=1, max_length=255)]


class MemoryError(RuntimeError):
    pass


class MemoryAccessDenied(MemoryError):
    pass


class MemoryStateError(MemoryError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class MemoryACL(_StrictModel):
    readers: tuple[Principal, ...] = Field(min_length=1, max_length=64)
    writers: tuple[Principal, ...] = Field(min_length=1, max_length=32)
    reviewers: tuple[Principal, ...] = Field(min_length=1, max_length=32)

    @field_validator("readers", "writers", "reviewers")
    @classmethod
    def _valid_principals(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("ACL principals must be unique and sorted")
        if any(not _PRINCIPAL.fullmatch(value) for value in values):
            raise ValueError("ACL contains an invalid principal")
        return values

    def require(self, principal: str, permission: Literal["read", "write", "review"]) -> None:
        if not _PRINCIPAL.fullmatch(principal):
            raise MemoryAccessDenied("invalid memory principal")
        allowed = {
            "read": self.readers,
            "write": self.writers,
            "review": self.reviewers,
        }[permission]
        if principal not in allowed:
            raise MemoryAccessDenied(f"principal is not authorized to {permission} this memory")


class MemoryDocument(_StrictModel):
    schema_id: Literal["SITINA_MEMORY_V1"] = Field(default="SITINA_MEMORY_V1", alias="schema")
    memory_id: MemoryId
    scope: Literal["agent_private", "run_shared", "project_shared", "user"]
    owner_id: Principal = Field(min_length=3)
    namespace: Principal = Field(min_length=3)
    content_ref: CASReference
    content_hash: HexDigest
    source_event_ids: tuple[Principal, ...] = Field(default=(), max_length=256)
    source_run_ids: tuple[Principal, ...] = Field(default=(), max_length=64)
    evidence_refs: tuple[CASReference, ...] = Field(default=(), max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    sensitivity: Literal["low", "moderate", "high", "restricted"]
    status: Literal["candidate", "accepted", "rejected", "superseded", "revoked", "expired"] = "candidate"
    valid_from: str
    expires_at: str | None = None
    retention_policy: Literal["until-superseded", "until-expired", "explicit-revocation", "legal-retention"]
    supersedes: tuple[MemoryId, ...] = Field(default=(), max_length=64)
    superseded_by: MemoryId | None = None
    acl: MemoryACL

    @field_validator("memory_id")
    @classmethod
    def _memory_id(cls, value: str) -> str:
        if not _MEMORY_ID.fullmatch(value):
            raise ValueError("invalid memory_id")
        return value

    @field_validator("content_ref")
    @classmethod
    def _content_ref(cls, value: str) -> str:
        if not _CAS_REF.fullmatch(value):
            raise ValueError("invalid content_ref")
        return value

    @field_validator("content_hash")
    @classmethod
    def _content_hash(cls, value: str) -> str:
        if not _HASH.fullmatch(value):
            raise ValueError("invalid content_hash")
        return value

    @field_validator("valid_from")
    @classmethod
    def _valid_from(cls, value: str) -> str:
        return validate_timestamp(value)

    @field_validator("expires_at")
    @classmethod
    def _expires_at(cls, value: str | None) -> str | None:
        return validate_timestamp(value) if value is not None else None

    @field_validator("source_event_ids", "source_run_ids", "supersedes")
    @classmethod
    def _unique_identifiers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("identifier collections must be unique and sorted")
        if any(not _PRINCIPAL.fullmatch(value) for value in values):
            raise ValueError("invalid identifier in memory metadata")
        return values

    @field_validator("evidence_refs")
    @classmethod
    def _evidence_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values or any(not _CAS_REF.fullmatch(value) for value in values):
            raise ValueError("evidence_refs must be unique sorted CAS references")
        return values

    @model_validator(mode="after")
    def _scope_and_lifecycle(self) -> "MemoryDocument":
        prefixes = {
            "agent_private": "agent/",
            "run_shared": "run/",
            "project_shared": "project/",
            "user": "user/",
        }
        if not self.owner_id.startswith(prefixes[self.scope]):
            raise ValueError("memory owner_id does not match its scope")
        if not self.namespace.startswith(self.owner_id + "/"):
            raise ValueError("memory namespace must be below owner_id")
        if self.expires_at is not None:
            valid_from = dt.datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
            expires_at = dt.datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if expires_at <= valid_from:
                raise ValueError("memory expiration must follow valid_from")
        if self.memory_id in self.supersedes:
            raise ValueError("memory cannot supersede itself")
        if self.superseded_by == self.memory_id:
            raise ValueError("memory cannot be superseded by itself")
        return self

    def journal_mapping(self) -> dict[str, Any]:
        """Return canonical-Journal metadata without body bytes or JSON floats."""
        value = self.model_dump(mode="json", by_alias=True)
        value.pop("confidence")
        value["confidence_millionths"] = int(round(self.confidence * 1_000_000))
        return value

    @classmethod
    def from_journal_mapping(cls, value: Mapping[str, Any]) -> "MemoryDocument":
        restored = dict(value)
        restored["confidence"] = int(restored.pop("confidence_millionths")) / 1_000_000
        return cls.model_validate(restored)


class EpisodeDocument(_StrictModel):
    schema_id: Literal["SITINA_EPISODE_V1"] = Field(default="SITINA_EPISODE_V1", alias="schema")
    episode_id: EpisodeId
    source_run_id: Principal
    goal_ref: CASReference
    action_event_range: tuple[int, int]
    terminal_evidence_ref: CASReference
    outcome: Literal["succeeded", "failed", "cancelled", "blocked"]
    failure_reason_code: Principal | None = Field(default=None, max_length=120)
    lesson_ref: CASReference
    source_frontier: int = Field(ge=1)

    @field_validator("episode_id")
    @classmethod
    def _episode_id(cls, value: str) -> str:
        if not _EPISODE_ID.fullmatch(value):
            raise ValueError("invalid episode_id")
        return value

    @field_validator("goal_ref", "terminal_evidence_ref", "lesson_ref")
    @classmethod
    def _cas_ref(cls, value: str) -> str:
        if not _CAS_REF.fullmatch(value):
            raise ValueError("episode references must be CAS references")
        return value

    @model_validator(mode="after")
    def _range_and_outcome(self) -> "EpisodeDocument":
        start, end = self.action_event_range
        if start < 1 or end < start or end > self.source_frontier:
            raise ValueError("episode action range is outside its source frontier")
        if self.outcome == "failed" and not self.failure_reason_code:
            raise ValueError("failed episode requires failure_reason_code")
        if self.outcome != "failed" and self.failure_reason_code is not None:
            raise ValueError("only failed episode may have failure_reason_code")
        return self


class MemoryRepository:
    TENANT = "sitina-memory"
    _TRANSITIONS = {
        "candidate": frozenset({"accepted", "rejected"}),
        "accepted": frozenset({"superseded", "revoked", "expired"}),
        "superseded": frozenset({"revoked", "expired"}),
        "rejected": frozenset(),
        "revoked": frozenset(),
        "expired": frozenset(),
    }

    def __init__(
        self,
        journal: LocalJournal,
        cas: LocalCAS,
        key_provider: InMemoryKeyProvider,
        *,
        feature_activations: FeatureActivationRegistry | None = None,
    ):
        self.journal = journal
        self.cas = cas
        self.keys = key_provider
        self.feature_activations = feature_activations

    def _assert_write_enabled(self) -> FeatureActivationRegistry:
        if self.feature_activations is None:
            raise MemoryStateError("Memory V1 writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("memory_v1_write")
        return self.feature_activations

    @staticmethod
    def _digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()

    def _stream_events(self, memory_id: str) -> tuple[EventEnvelope, ...]:
        stream_id = f"memory/{memory_id}"
        return tuple(event for event in self.journal.iter_events(0) if event.stream_id == stream_id)

    def _append(
        self,
        *,
        memory_id: str,
        action: str,
        payload: Mapping[str, Any],
        occurred_at: str,
        proofs: Sequence[PublishedObjectReceipt] = (),
        object_refs: Sequence[str] = (),
    ) -> EventEnvelope:
        stream_id = f"memory/{memory_id}"
        expected = self.journal._stream_heads.get(stream_id, 0)
        digest = self._digest({"memory_id": memory_id, "action": action, "payload": dict(payload)})
        command = CommandEnvelope(
            "memory-command-" + digest[:43],
            self.TENANT,
            stream_id,
            "memory." + action,
            "journal-memory-repository",
            occurred_at,
            {"memory_id": memory_id, "event_hash": digest},
        )
        event = EventEnvelope(
            "memory-event-" + digest[:45],
            "memory." + action,
            self.TENANT,
            stream_id,
            0,
            0,
            occurred_at,
            dict(payload),
            tuple(sorted(object_refs)),
        )
        receipt = self.journal.append(command, expected, [event], object_reference_proofs=proofs)
        return next(item for item in self.journal.iter_events(receipt.first_position - 1) if item.position == receipt.first_position)

    def create_candidate(
        self,
        *,
        memory_id: str,
        scope: Literal["agent_private", "run_shared", "project_shared", "user"],
        owner_id: str,
        namespace: str,
        content: str,
        source_event_ids: Sequence[str],
        source_run_ids: Sequence[str],
        evidence_refs: Sequence[str],
        confidence: float,
        sensitivity: Literal["low", "moderate", "high", "restricted"],
        valid_from: str,
        expires_at: str | None,
        retention_policy: Literal["until-superseded", "until-expired", "explicit-revocation", "legal-retention"],
        supersedes: Sequence[str],
        acl: MemoryACL,
        actor: str,
    ) -> MemoryDocument:
        activations = self._assert_write_enabled()
        acl.require(actor, "write")
        if not content or len(content.encode("utf-8")) > 256 * 1024:
            raise MemoryError("memory content must be between 1 byte and 256 KiB")
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        existing = self._stream_events(memory_id)
        if existing:
            document = self._reconstruct(existing)
            if document.content_hash != content_hash:
                raise MemoryStateError("memory identity is already bound to different content")
            return document

        encrypted = encrypt_object(content.encode("utf-8"), self.keys, tenant_id=self.TENANT, purpose="memory-content")
        published = self.cas.publish_verified(encrypted)
        document = MemoryDocument(
            memory_id=memory_id,
            scope=scope,
            owner_id=owner_id,
            namespace=namespace,
            content_ref=published.object_ref.reference_id,
            content_hash=content_hash,
            source_event_ids=tuple(sorted(set(source_event_ids))),
            source_run_ids=tuple(sorted(set(source_run_ids))),
            evidence_refs=tuple(sorted(set(evidence_refs))),
            confidence=confidence,
            sensitivity=sensitivity,
            status="candidate",
            valid_from=valid_from,
            expires_at=expires_at,
            retention_policy=retention_policy,
            supersedes=tuple(sorted(set(supersedes))),
            acl=acl,
        )
        event = self._append(
            memory_id=memory_id,
            action="candidate-created",
            payload={
                "schema": "SITINA_MEMORY_CANDIDATE_CREATED_V1",
                "memory": document.journal_mapping(),
                "content_tenant_id": published.object_ref.tenant_id,
                "content_plaintext_commitment": published.object_ref.plaintext_commitment,
                "content_commitment_key_id": published.object_ref.commitment_key_id,
                "content_profile": published.object_ref.profile,
                "actor": actor,
            },
            occurred_at=valid_from,
            proofs=(published,),
            object_refs=(published.object_ref.reference_id,),
        )
        activations.record_first_write("memory_v1_write", journal_position=event.position)
        return document

    def _reconstruct(self, events: Sequence[EventEnvelope]) -> MemoryDocument:
        if not events or events[0].event_type != "memory.candidate-created":
            raise MemoryStateError("memory stream has no candidate creation event")
        document = MemoryDocument.from_journal_mapping(events[0].payload["memory"])
        for event in events[1:]:
            status = str(event.payload.get("to_status", ""))
            if status not in self._TRANSITIONS.get(document.status, frozenset()):
                raise MemoryStateError("memory stream contains an invalid state transition")
            updates: dict[str, Any] = {"status": status}
            if status == "superseded":
                updates["superseded_by"] = str(event.payload["superseded_by"])
            document = document.model_copy(update=updates)
        return document

    def _raw_get(self, memory_id: str) -> MemoryDocument:
        events = self._stream_events(memory_id)
        if not events:
            raise KeyError(memory_id)
        return self._reconstruct(events)

    def get(self, memory_id: str, *, actor: str, include_content: bool = True) -> tuple[MemoryDocument, str | None]:
        document = self._raw_get(memory_id)
        document.acl.require(actor, "read")
        content: str | None = None
        if include_content:
            content = self.cas.open_verified(self._object_ref(document)).decode("utf-8")
            if hashlib.sha256(content.encode("utf-8")).hexdigest() != document.content_hash:
                raise MemoryStateError("memory content hash mismatch")
        return document, content

    def transition(
        self,
        memory_id: str,
        to_status: Literal["accepted", "rejected", "superseded", "revoked", "expired"],
        *,
        actor: str,
        occurred_at: str,
        reason_code: str,
        superseded_by: str | None = None,
    ) -> MemoryDocument:
        activations = self._assert_write_enabled()
        document = self._raw_get(memory_id)
        document.acl.require(actor, "review")
        if to_status == document.status:
            return document
        if to_status not in self._TRANSITIONS[document.status]:
            raise MemoryStateError(f"transition {document.status} -> {to_status} is forbidden")
        if not reason_code or len(reason_code) > 120 or not _PRINCIPAL.fullmatch(reason_code):
            raise MemoryStateError("invalid transition reason_code")
        if to_status == "superseded":
            if not superseded_by or not _MEMORY_ID.fullmatch(superseded_by):
                raise MemoryStateError("superseded transition requires superseded_by")
            replacement = self._raw_get(superseded_by)
            if replacement.status != "accepted" or memory_id not in replacement.supersedes:
                raise MemoryStateError("replacement must be accepted and declare the superseded memory")
        elif superseded_by is not None:
            raise MemoryStateError("superseded_by is only valid for a superseded transition")
        payload: dict[str, Any] = {
            "schema": "SITINA_MEMORY_STATE_CHANGED_V1",
            "memory_id": memory_id,
            "from_status": document.status,
            "to_status": to_status,
            "actor": actor,
            "reason_code": reason_code,
            "occurred_at": occurred_at,
        }
        if to_status in {"accepted", "revoked", "expired", "superseded"}:
            payload["content_ref"] = document.content_ref
        if superseded_by is not None:
            payload["superseded_by"] = superseded_by
        event = self._append(memory_id=memory_id, action=to_status, payload=payload, occurred_at=occurred_at)
        activations.record_first_write("memory_v1_write", journal_position=event.position)
        return self._raw_get(memory_id)

    def retrieve(
        self,
        *,
        actor: str,
        scope: str | None = None,
        owner_id: str | None = None,
        namespace_prefix: str | None = None,
        include_noncurrent: bool = False,
        at: str | None = None,
    ) -> tuple[MemoryDocument, ...]:
        now = dt.datetime.fromisoformat((at or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00"))
        stream_ids = sorted({event.stream_id for event in self.journal.iter_events(0) if event.stream_id.startswith("memory/memory-")})
        visible: list[MemoryDocument] = []
        for stream_id in stream_ids:
            document = self._raw_get(stream_id.removeprefix("memory/"))
            try:
                document.acl.require(actor, "read")
            except MemoryAccessDenied:
                continue
            if scope is not None and document.scope != scope:
                continue
            if owner_id is not None and document.owner_id != owner_id:
                continue
            if namespace_prefix is not None and not document.namespace.startswith(namespace_prefix):
                continue
            expired_by_time = document.expires_at is not None and dt.datetime.fromisoformat(document.expires_at.replace("Z", "+00:00")) <= now
            if not include_noncurrent and (document.status != "accepted" or expired_by_time):
                continue
            visible.append(document)
        return tuple(sorted(visible, key=lambda item: item.memory_id))

    def active_roots(self, *, at: str | None = None) -> tuple[dict[str, Any], ...]:
        now = dt.datetime.fromisoformat((at or dt.datetime.now(dt.timezone.utc).isoformat()).replace("Z", "+00:00"))
        stream_ids = sorted({event.stream_id for event in self.journal.iter_events(0) if event.stream_id.startswith("memory/memory-")})
        roots = []
        for stream_id in stream_ids:
            memory_id = stream_id.removeprefix("memory/")
            document = self._raw_get(memory_id)
            expired_by_time = document.expires_at is not None and dt.datetime.fromisoformat(document.expires_at.replace("Z", "+00:00")) <= now
            if document.status == "accepted" and not expired_by_time:
                last_event = self._stream_events(memory_id)[-1]
                roots.append(
                    {
                        "root_type": "memory",
                        "root_id": memory_id,
                        "object_ref": document.content_ref,
                        "source_position": last_event.position,
                        "source_event_id": last_event.event_id,
                        "schema_version": 1,
                    }
                )
        return tuple(roots)

    def _object_ref(self, document: MemoryDocument) -> ObjectRef:
        creation = self._stream_events(document.memory_id)[0]
        payload = creation.payload
        return ObjectRef(
            document.content_ref.removeprefix("cas:"),
            str(payload["content_tenant_id"]),
            str(payload["content_plaintext_commitment"]),
            str(payload["content_commitment_key_id"]),
            str(payload["content_profile"]),
        )


class EpisodeRepository:
    TENANT = "sitina-memory"

    def __init__(
        self,
        journal: LocalJournal,
        cas: LocalCAS,
        key_provider: InMemoryKeyProvider,
        *,
        feature_activations: FeatureActivationRegistry | None = None,
    ):
        self.journal = journal
        self.cas = cas
        self.keys = key_provider
        self.feature_activations = feature_activations

    def create(
        self,
        *,
        episode_id: str,
        source_run_id: str,
        goal_ref: ObjectRef,
        action_event_range: tuple[int, int],
        terminal_evidence_ref: ObjectRef,
        outcome: Literal["succeeded", "failed", "cancelled", "blocked"],
        failure_reason_code: str | None,
        lesson: str,
        occurred_at: str,
    ) -> EpisodeDocument:
        if self.feature_activations is None:
            raise MemoryStateError("Memory V1 writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("memory_v1_write")
        if not lesson or len(lesson.encode("utf-8")) > 64 * 1024:
            raise MemoryError("episode lesson must be between 1 byte and 64 KiB")
        source_frontier = self.journal.head_position
        goal_proof = self.cas.verify_existing(goal_ref)
        terminal_proof = self.cas.verify_existing(terminal_evidence_ref)
        lesson_encrypted = encrypt_object(lesson.encode("utf-8"), self.keys, tenant_id=self.TENANT, purpose="episode-lesson")
        lesson_proof = self.cas.publish_verified(lesson_encrypted)
        document = EpisodeDocument(
            episode_id=episode_id,
            source_run_id=source_run_id,
            goal_ref=goal_ref.reference_id,
            action_event_range=action_event_range,
            terminal_evidence_ref=terminal_evidence_ref.reference_id,
            outcome=outcome,
            failure_reason_code=failure_reason_code,
            lesson_ref=lesson_proof.object_ref.reference_id,
            source_frontier=source_frontier,
        )
        stream_id = f"episode/{episode_id}"
        durable_document = document.model_dump(mode="json", by_alias=True)
        digest = hashlib.sha256(canonical_json_bytes(durable_document)).hexdigest()
        command = CommandEnvelope(
            "episode-command-" + digest[:42],
            self.TENANT,
            stream_id,
            "memory.episode-create",
            "journal-memory-repository",
            occurred_at,
            {"episode_id": episode_id, "document_hash": digest},
        )
        event = EventEnvelope(
            "episode-event-" + digest[:44],
            "memory.episode-created",
            self.TENANT,
            stream_id,
            0,
            0,
            occurred_at,
            durable_document,
            tuple(sorted((goal_ref.reference_id, terminal_evidence_ref.reference_id, lesson_proof.object_ref.reference_id))),
        )
        proofs_by_reference = {
            proof.object_ref.reference_id: proof
            for proof in (goal_proof, terminal_proof, lesson_proof)
        }
        receipt = self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
            object_reference_proofs=tuple(proofs_by_reference.values()),
        )
        self.feature_activations.record_first_write("memory_v1_write", journal_position=receipt.last_position)
        return document
