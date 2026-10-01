from __future__ import annotations

import datetime as dt
import functools
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
_DECISION_ID = re.compile(r"^memory-decision-[A-Za-z0-9][A-Za-z0-9._:-]{0,180}$")

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


def _journal_mutation(method):
    """Serialize native memory mutations with the Journal's append mutex."""
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        mutex = getattr(self.journal, "_mutex", None)
        if mutex is None:
            raise MemoryStateError("native memory Journal mutation lock is unavailable")
        with mutex:
            return method(self, *args, **kwargs)
    return wrapped


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
    tier: Literal["working", "episodic", "long_term"] = "working"
    source_agent_ids: tuple[Principal, ...] = ()
    source_trust: Literal["untrusted", "derived", "verified", "authoritative"] = "untrusted"
    observed_at: str | None = None
    conflict_key: Principal | None = None
    quarantine_status: Literal["active", "quarantined"] = "active"
    content_trust: Literal["untrusted"] = "untrusted"

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

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str | None) -> str | None:
        return validate_timestamp(value) if value is not None else None

    @field_validator("source_event_ids", "source_run_ids", "source_agent_ids", "supersedes")
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
        if self.conflict_key is not None and not _PRINCIPAL.fullmatch(self.conflict_key):
            raise ValueError("invalid memory conflict_key")
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
    DECISION_STREAM = "memory/decisions"
    _TRANSITIONS = {
        "candidate": frozenset({"accepted", "rejected", "expired"}),
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

    def _decision_events(self) -> tuple[EventEnvelope, ...]:
        return tuple(
            event for event in self.journal.iter_events(0)
            if event.stream_id == self.DECISION_STREAM
        )

    def decision_projection(self) -> dict[str, Any]:
        """Reduce the single memory decision stream into authoritative overlays."""
        by_memory: dict[str, Mapping[str, Any]] = {}
        by_decision: dict[str, Mapping[str, Any]] = {}
        state_by_memory: dict[str, str] = {}
        for event in self._decision_events():
            payload = event.payload
            if not isinstance(payload, Mapping) or payload.get("schema") != "SITINA_MEMORY_DECISION_V1":
                raise MemoryStateError("memory decision stream contains an invalid schema")
            decision_id = str(payload.get("decision_id") or "")
            if not _DECISION_ID.fullmatch(decision_id):
                raise MemoryStateError("memory decision stream contains an invalid decision identity")
            decision_hash = str(payload.get("decision_hash") or "")
            expected_hash = hashlib.sha256(
                canonical_json_bytes({
                    "decision_id": decision_id,
                    "decision_kind": payload.get("decision_kind"),
                    "source_closure": payload.get("source_closure"),
                    "candidate_actions": payload.get("candidate_actions"),
                    "review_request_id": payload.get("review_request_id"),
                    "candidate_revisions": payload.get("candidate_revisions"),
                    "review_binding": payload.get("review_binding"),
                })
            ).hexdigest()
            if decision_hash != expected_hash:
                raise MemoryStateError("memory decision hash is invalid")
            if decision_id in by_decision:
                raise MemoryStateError("memory decision stream contains a duplicate decision")
            actions = payload.get("candidate_actions")
            if not isinstance(actions, list) or not actions:
                raise MemoryStateError("memory decision must contain candidate actions")
            by_decision[decision_id] = dict(payload)
            local_seen: set[str] = set()
            prior_state: dict[str, str] = {}
            for action in actions:
                if not isinstance(action, Mapping):
                    raise MemoryStateError("memory decision action is malformed")
                memory_id = str(action.get("memory_id") or "")
                if not _MEMORY_ID.fullmatch(memory_id) or memory_id in local_seen:
                    raise MemoryStateError("memory decision action identity is duplicated or invalid")
                if memory_id not in state_by_memory:
                    events = self._stream_events(memory_id)
                    if not events:
                        raise MemoryStateError("memory decision references an unknown candidate")
                    state_by_memory[memory_id] = self._reconstruct(events).status
                prior_state[memory_id] = state_by_memory[memory_id]
                expected_status = str(action.get("expected_status") or "")
                to_status = str(action.get("to_status") or "")
                if expected_status != prior_state[memory_id]:
                    raise MemoryStateError("memory decision lifecycle revision is stale")
                if to_status not in self._TRANSITIONS.get(expected_status, frozenset()):
                    raise MemoryStateError("memory decision lifecycle transition is invalid")
                local_seen.add(memory_id)
            for action in actions:
                memory_id = str(action.get("memory_id") or "")
                to_status = str(action.get("to_status") or "")
                if to_status == "superseded":
                    replacement_id = str(action.get("superseded_by") or "")
                    if not _MEMORY_ID.fullmatch(replacement_id):
                        raise MemoryStateError("memory decision superseded target is invalid")
                    if replacement_id not in state_by_memory:
                        replacement_events = self._stream_events(replacement_id)
                        if not replacement_events:
                            raise MemoryStateError("memory decision superseded target is unknown")
                        state_by_memory[replacement_id] = self._reconstruct(replacement_events).status
                    replacement_status = prior_state.get(replacement_id, state_by_memory.get(replacement_id))
                    if replacement_id in local_seen:
                        replacement_status = str(
                            next(item.get("to_status") for item in actions if item.get("memory_id") == replacement_id)
                        )
                    if replacement_status != "accepted":
                        raise MemoryStateError("memory decision superseded target is not accepted")
                    replacement = self._reconstruct(self._stream_events(replacement_id))
                    if memory_id not in replacement.supersedes:
                        raise MemoryStateError("memory decision superseded target is not bound to source")
                state_by_memory[memory_id] = to_status
                by_memory[memory_id] = dict(action)
        return {"by_memory": by_memory, "by_decision": by_decision}

    def _decision_for_memory(self, memory_id: str) -> Mapping[str, Any] | None:
        return self.decision_projection()["by_memory"].get(memory_id)

    def _decision_event_for_memory(self, memory_id: str) -> EventEnvelope | None:
        for event in reversed(self._decision_events()):
            actions = event.payload.get("candidate_actions") if isinstance(event.payload, Mapping) else None
            if isinstance(actions, list) and any(
                isinstance(action, Mapping) and action.get("memory_id") == memory_id for action in actions
            ):
                return event
        return None

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

    @_journal_mutation
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
        tier: Literal["working", "episodic", "long_term"] = "working",
        source_agent_ids: Sequence[str] = (),
        source_trust: Literal["untrusted", "derived", "verified", "authoritative"] = "untrusted",
        observed_at: str | None = None,
        conflict_key: str | None = None,
    ) -> MemoryDocument:
        activations = self._assert_write_enabled()
        acl.require(actor, "write")
        if not content or len(content.encode("utf-8")) > 256 * 1024:
            raise MemoryError("memory content must be between 1 byte and 256 KiB")
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        existing = self._stream_events(memory_id)
        if existing:
            document = self._reconstruct(existing)
            creation_payload = existing[0].payload if isinstance(existing[0].payload, Mapping) else {}
            creation_mapping = creation_payload.get("memory") if isinstance(creation_payload, Mapping) else None
            if not isinstance(creation_mapping, Mapping):
                raise MemoryStateError("memory candidate creation proof is malformed")
            created = MemoryDocument.from_journal_mapping(creation_mapping)
            requested_observed_at = observed_at or valid_from
            if (
                created.content_hash != content_hash
                or created.scope != scope
                or created.owner_id != owner_id
                or created.namespace != namespace
                or created.source_event_ids != tuple(sorted(set(source_event_ids)))
                or created.source_run_ids != tuple(sorted(set(source_run_ids)))
                or created.evidence_refs != tuple(sorted(set(evidence_refs)))
                or int(round(created.confidence * 1_000_000)) != int(round(confidence * 1_000_000))
                or created.sensitivity != sensitivity
                or created.valid_from != valid_from
                or created.expires_at != expires_at
                or created.retention_policy != retention_policy
                or created.supersedes != tuple(sorted(set(supersedes)))
                or created.acl != acl
                or created.tier != tier
                or created.source_agent_ids != tuple(sorted(set(source_agent_ids)))
                or created.source_trust != source_trust
                or created.observed_at != requested_observed_at
                or created.conflict_key != conflict_key
            ):
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
            tier=tier,
            source_agent_ids=tuple(sorted(set(source_agent_ids))),
            source_trust=source_trust,
            observed_at=observed_at or valid_from,
            conflict_key=conflict_key,
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

    @_journal_mutation
    def apply_memory_decision(
        self,
        *,
        decision_id: str,
        source_closure: Mapping[str, Any],
        candidate_actions: Sequence[Mapping[str, Any]],
        actor: str,
        occurred_at: str,
        decision_kind: str = "experience-review",
        review_request_id: str | None = None,
        candidate_revisions: Mapping[str, str] | None = None,
        review_binding: Mapping[str, Any] | None = None,
    ) -> tuple[MemoryDocument, ...]:
        """Commit one atomic accepted/supersede/disposition decision.

        Candidate creation may happen earlier, but all review outcomes that
        affect the current memory view are represented by this one stream
        event. A matching decision id and hash is an exact replay; a matching
        id with different closure/actions is a conflict.
        """
        activations = self._assert_write_enabled()
        if not _DECISION_ID.fullmatch(decision_id):
            raise MemoryStateError("invalid memory decision identity")
        if not isinstance(source_closure, Mapping) or not source_closure:
            raise MemoryStateError("memory decision requires a complete source closure")
        if not decision_kind or not _PRINCIPAL.fullmatch(decision_kind):
            raise MemoryStateError("invalid memory decision kind")
        if review_request_id is not None and not review_request_id:
            raise MemoryStateError("review request identity cannot be empty")
        revisions = {
            str(key): str(value)
            for key, value in (candidate_revisions or {}).items()
        }
        revision_payload = revisions or None
        actions = [dict(item) for item in candidate_actions]
        if not actions:
            raise MemoryStateError("memory decision requires candidate actions")
        existing = self.decision_projection()["by_decision"].get(decision_id)
        if existing is not None:
            replay_actions: list[dict[str, Any]] = []
            for action in actions:
                replay_action = {
                    "memory_id": str(action.get("memory_id") or ""),
                    "expected_status": str(action.get("expected_status") or ""),
                    "to_status": str(action.get("to_status") or ""),
                    "reason_code": str(action.get("reason_code") or ""),
                }
                if action.get("superseded_by") is not None:
                    replay_action["superseded_by"] = str(action.get("superseded_by"))
                replay_actions.append(replay_action)
            replay_hash = hashlib.sha256(canonical_json_bytes({
                "decision_id": decision_id,
                "decision_kind": decision_kind,
                    "source_closure": dict(source_closure),
                    "candidate_actions": replay_actions,
                    "review_request_id": review_request_id,
                    "candidate_revisions": revision_payload,
                    "review_binding": review_binding,
            })).hexdigest()
            if existing.get("decision_hash") != replay_hash:
                raise MemoryStateError("memory decision identity is bound to different content")
            return tuple(self._raw_get(str(item["memory_id"])) for item in replay_actions)
        if review_binding is not None:
            # Exact replay above must remain readable after the decision has
            # advanced the candidate state. A pre-dispatch binding is only a
            # gate for a new decision append.
            self.assert_review_binding(review_binding)
        expected_decision_head = self.journal._stream_heads.get(self.DECISION_STREAM, 0)
        normalized_actions: list[dict[str, Any]] = []
        seen: set[str] = set()
        planned: dict[str, str] = {}
        baseline: dict[str, tuple[int, str, tuple[str, ...], tuple[str, ...], str | None]] = {}
        for action in actions:
            memory_id = str(action.get("memory_id") or "")
            expected_status = str(action.get("expected_status") or "")
            to_status = str(action.get("to_status") or "")
            if not _MEMORY_ID.fullmatch(memory_id) or memory_id in seen:
                raise MemoryStateError("memory decision candidate identity is invalid or duplicated")
            document = self._raw_get(memory_id)
            if revisions and (memory_id not in revisions or not revisions[memory_id]):
                raise MemoryStateError("memory decision is missing the candidate review revision")
            baseline[memory_id] = (
                self.journal._stream_heads.get(f"memory/{memory_id}", 0),
                document.content_hash,
                document.source_event_ids,
                document.source_run_ids,
                document.conflict_key,
            )
            if document.status != expected_status:
                raise MemoryStateError("memory decision candidate revision is stale")
            if to_status not in self._TRANSITIONS.get(document.status, frozenset()):
                raise MemoryStateError(f"decision {document.status} -> {to_status} is forbidden")
            if document.status == "candidate" and to_status == "expired":
                if (decision_kind != "retention-expiry"
                        or document.retention_policy != "until-expired"
                        or document.expires_at is None
                        or dt.datetime.fromisoformat(document.expires_at.replace("Z", "+00:00"))
                        > dt.datetime.now(dt.timezone.utc)):
                    raise MemoryStateError("candidate expiry requires its elapsed retention policy")
            document.acl.require(actor, "review")
            reason = str(action.get("reason_code") or "")
            if not reason or not _PRINCIPAL.fullmatch(reason):
                raise MemoryStateError("memory decision reason_code is invalid")
            normalized = {
                "memory_id": memory_id,
                "expected_status": expected_status,
                "to_status": to_status,
                "reason_code": reason,
            }
            if to_status == "superseded":
                replacement = str(action.get("superseded_by") or "")
                if not _MEMORY_ID.fullmatch(replacement):
                    raise MemoryStateError("memory decision requires superseded_by")
                normalized["superseded_by"] = replacement
            elif action.get("superseded_by") is not None:
                raise MemoryStateError("superseded_by is only valid for superseded")
            seen.add(memory_id)
            planned[memory_id] = to_status
            normalized_actions.append(normalized)
        action_by_memory = {item["memory_id"]: item for item in normalized_actions}
        for action in normalized_actions:
            if action["to_status"] != "accepted":
                continue
            accepted_candidate = self._raw_get(action["memory_id"])
            for superseded_id in accepted_candidate.supersedes:
                replacement_action = action_by_memory.get(superseded_id)
                if (
                    replacement_action is None
                    or replacement_action.get("to_status") != "superseded"
                    or replacement_action.get("expected_status") != "accepted"
                    or replacement_action.get("superseded_by") != action["memory_id"]
                ):
                    raise MemoryStateError(
                        "accepted replacement must atomically dispose every currently bound superseded memory"
                    )
        for action in normalized_actions:
            if action["to_status"] != "superseded":
                continue
            replacement_id = str(action["superseded_by"])
            replacement = self._raw_get(replacement_id)
            if replacement_id not in baseline:
                baseline[replacement_id] = (
                    self.journal._stream_heads.get(f"memory/{replacement_id}", 0),
                    replacement.content_hash,
                    replacement.source_event_ids,
                    replacement.source_run_ids,
                    replacement.conflict_key,
                )
            replacement_status = planned.get(replacement_id, replacement.status)
            if replacement_status != "accepted" or action["memory_id"] not in replacement.supersedes:
                raise MemoryStateError("decision replacement is not an accepted candidate bound to supersedes")
        decision_hash = hashlib.sha256(canonical_json_bytes({
            "decision_id": decision_id,
            "decision_kind": decision_kind,
            "source_closure": dict(source_closure),
            "candidate_actions": normalized_actions,
            "review_request_id": review_request_id,
            "candidate_revisions": revision_payload,
            "review_binding": review_binding,
        })).hexdigest()
        if self.journal._stream_heads.get(self.DECISION_STREAM, 0) != expected_decision_head:
            raise MemoryStateError("memory decision raced with a committed decision")
        for memory_id, expected in baseline.items():
            current = self._raw_get(memory_id)
            observed = (
                self.journal._stream_heads.get(f"memory/{memory_id}", 0),
                current.content_hash,
                current.source_event_ids,
                current.source_run_ids,
                current.conflict_key,
            )
            if observed != expected:
                raise MemoryStateError("memory decision candidate/source revision is stale")
        payload = {
            "schema": "SITINA_MEMORY_DECISION_V1",
            "decision_id": decision_id,
            "decision_kind": decision_kind,
            "source_closure": dict(source_closure),
            "candidate_actions": normalized_actions,
            "decision_hash": decision_hash,
            "actor": actor,
            "review_request_id": review_request_id,
            "candidate_revisions": revision_payload,
            "review_binding": dict(review_binding) if review_binding is not None else None,
        }
        command = CommandEnvelope(
            "memory-decision-command-" + decision_hash[:39],
            self.TENANT,
            self.DECISION_STREAM,
            "memory.decision.commit",
            "journal-memory-repository",
            occurred_at,
            {"decision_id": decision_id, "decision_hash": decision_hash},
        )
        event = EventEnvelope(
            "memory-decision-event-" + decision_hash[:42],
            "memory.decision-committed",
            self.TENANT,
            self.DECISION_STREAM,
            0,
            0,
            occurred_at,
            payload,
            (),
        )
        try:
            receipt = self.journal.append(
                command,
                expected_decision_head,
                [event],
            )
        except Exception:
            committed = self.decision_projection()["by_decision"].get(decision_id)
            if committed is not None and committed.get("decision_hash") == decision_hash:
                return tuple(self._raw_get(item["memory_id"]) for item in normalized_actions)
            raise
        activations.record_first_write("memory_v1_write", journal_position=receipt.last_position)
        return tuple(self._raw_get(item["memory_id"]) for item in normalized_actions)

    def _reconstruct(self, events: Sequence[EventEnvelope]) -> MemoryDocument:
        if not events or events[0].event_type != "memory.candidate-created":
            raise MemoryStateError("memory stream has no candidate creation event")
        document = MemoryDocument.from_journal_mapping(events[0].payload["memory"])
        for event in events[1:]:
            if event.event_type == "memory.tier-promoted":
                from_tier = str(event.payload.get("from_tier", ""))
                to_tier = str(event.payload.get("to_tier", ""))
                allowed = {"working": "episodic", "episodic": "long_term"}
                if document.tier != from_tier or allowed.get(from_tier) != to_tier:
                    raise MemoryStateError("memory stream contains an invalid tier promotion")
                document = document.model_copy(update={"tier": to_tier})
                continue
            if event.event_type == "memory.quarantined":
                confidence = event.payload.get("confidence_millionths")
                if (
                    document.quarantine_status != "active"
                    or not isinstance(confidence, int)
                    or not 0 <= confidence <= 1_000_000
                ):
                    raise MemoryStateError("memory stream contains an invalid quarantine transition")
                document = document.model_copy(
                    update={"quarantine_status": "quarantined", "confidence": confidence / 1_000_000}
                )
                continue
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
        document = self._reconstruct(events)
        action = self._decision_for_memory(memory_id)
        if action is not None:
            status = str(action.get("to_status") or "")
            if status not in {"accepted", "rejected", "superseded", "revoked", "expired"}:
                raise MemoryStateError("memory decision contains an invalid target status")
            updates: dict[str, Any] = {"status": status}
            if status == "superseded":
                superseded_by = str(action.get("superseded_by") or "")
                if not _MEMORY_ID.fullmatch(superseded_by):
                    raise MemoryStateError("memory decision superseded target is invalid")
                updates["superseded_by"] = superseded_by
            document = document.model_copy(update=updates)
        return document

    def get(self, memory_id: str, *, actor: str, include_content: bool = True) -> tuple[MemoryDocument, str | None]:
        document = self._raw_get(memory_id)
        document.acl.require(actor, "read")
        content: str | None = None
        if include_content:
            content = self.cas.open_verified(self._object_ref(document)).decode("utf-8")
            if hashlib.sha256(content.encode("utf-8")).hexdigest() != document.content_hash:
                raise MemoryStateError("memory content hash mismatch")
        return document, content

    @_journal_mutation
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
        if self._decision_for_memory(memory_id) is not None:
            raise MemoryStateError("memory state is owned by the canonical decision stream")
        document = self._raw_get(memory_id)
        document.acl.require(actor, "review")
        if to_status == document.status:
            return document
        if to_status not in self._TRANSITIONS[document.status]:
            raise MemoryStateError(f"transition {document.status} -> {to_status} is forbidden")
        if document.status == "candidate" and to_status == "expired":
            raise MemoryStateError("candidate expiry requires a canonical retention decision")
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

    @_journal_mutation
    def promote(
        self,
        memory_id: str,
        *,
        to_tier: Literal["episodic", "long_term"],
        actor: str,
        occurred_at: str,
        reason_code: str,
    ) -> MemoryDocument:
        activations = self._assert_write_enabled()
        if self._decision_for_memory(memory_id) is not None:
            raise MemoryStateError("memory state is owned by the canonical decision stream")
        document = self._raw_get(memory_id)
        document.acl.require(actor, "review")
        if document.status != "accepted" or document.quarantine_status != "active":
            raise MemoryStateError("only accepted active memory can be promoted")
        allowed = {"working": "episodic", "episodic": "long_term"}
        if allowed.get(document.tier) != to_tier:
            raise MemoryStateError("memory tier promotion must be sequential")
        if not reason_code or not _PRINCIPAL.fullmatch(reason_code):
            raise MemoryStateError("invalid tier promotion reason")
        event = self._append(
            memory_id=memory_id,
            action="tier-promoted",
            payload={
                "schema": "SITINA_MEMORY_TIER_PROMOTED_V1",
                "memory_id": memory_id,
                "from_tier": document.tier,
                "to_tier": to_tier,
                "actor": actor,
                "reason_code": reason_code,
            },
            occurred_at=occurred_at,
        )
        activations.record_first_write("memory_v1_write", journal_position=event.position)
        return self._raw_get(memory_id)

    @_journal_mutation
    def quarantine(
        self,
        memory_id: str,
        *,
        actor: str,
        occurred_at: str,
        reason_code: str,
        confidence_millionths: int,
    ) -> MemoryDocument:
        activations = self._assert_write_enabled()
        if self._decision_for_memory(memory_id) is not None:
            raise MemoryStateError("memory state is owned by the canonical decision stream")
        document = self._raw_get(memory_id)
        document.acl.require(actor, "review")
        if document.quarantine_status != "active":
            return document
        if not reason_code or not _PRINCIPAL.fullmatch(reason_code):
            raise MemoryStateError("invalid quarantine reason")
        maximum = int(document.confidence * 1_000_000)
        if (
            not isinstance(confidence_millionths, int)
            or isinstance(confidence_millionths, bool)
            or not 0 <= confidence_millionths <= maximum
        ):
            raise MemoryStateError("quarantine confidence must be non-negative and cannot increase")
        event = self._append(
            memory_id=memory_id,
            action="quarantined",
            payload={
                "schema": "SITINA_MEMORY_QUARANTINED_V1",
                "memory_id": memory_id,
                "actor": actor,
                "reason_code": reason_code,
                "confidence_millionths": confidence_millionths,
                "content_ref": document.content_ref,
            },
            occurred_at=occurred_at,
        )
        activations.record_first_write("memory_v1_write", journal_position=event.position)
        return self._raw_get(memory_id)

    def retrieve(
        self,
        *,
        actor: str,
        scope: str | None = None,
        owner_id: str | None = None,
        namespace_prefix: str | None = None,
        tier: Literal["working", "episodic", "long_term"] | None = None,
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
            if tier is not None and document.tier != tier:
                continue
            expired_by_time = (
                document.retention_policy != "legal-retention"
                and document.expires_at is not None
                and dt.datetime.fromisoformat(document.expires_at.replace("Z", "+00:00")) <= now
            )
            if not include_noncurrent and (
                document.status != "accepted" or document.quarantine_status != "active" or expired_by_time
            ):
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
            expired_by_time = (
                document.retention_policy != "legal-retention"
                and document.expires_at is not None
                and dt.datetime.fromisoformat(document.expires_at.replace("Z", "+00:00")) <= now
            )
            if document.status == "accepted" and document.quarantine_status == "active" and not expired_by_time:
                last_event = self._decision_event_for_memory(memory_id) or self._stream_events(memory_id)[-1]
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

    def verify_provenance(self, memory_id: str) -> dict[str, Any]:
        document = self._raw_get(memory_id)
        document, content = self.get(memory_id, actor=document.acl.readers[0])
        if content is None or hashlib.sha256(content.encode("utf-8")).hexdigest() != document.content_hash:
            raise MemoryStateError("memory content provenance hash is invalid")
        journal_events = tuple(self.journal.iter_events(0))
        known_event_ids = {event.event_id for event in journal_events}
        known_run_ids = {
            str(run_id)
            for event in journal_events
            if isinstance(event.payload, Mapping)
            for run_id in (
                event.payload.get("run_id"),
                event.payload.get("run_instance_id"),
                event.payload.get("source_run_id"),
            )
            if run_id
        }
        orphan_events = sorted(set(document.source_event_ids) - known_event_ids)
        orphan_runs = sorted(set(document.source_run_ids) - known_run_ids)
        orphan_evidence = []
        for reference in document.evidence_refs:
            try:
                self.cas.verify_existing(self.cas.resolve_reference(reference))
            except Exception:  # collapse CAS errors without exposing local paths or content
                orphan_evidence.append(reference)
        if orphan_events or orphan_runs or orphan_evidence:
            raise MemoryStateError("memory provenance contains orphan references")
        return {
            "schema": "SITINA_MEMORY_PROVENANCE_VERIFIED_V1",
            "memory_id": memory_id,
            "content_hash": document.content_hash,
            "source_event_ids": list(document.source_event_ids),
            "source_run_ids": list(document.source_run_ids),
            "source_agent_ids": list(document.source_agent_ids),
            "source_trust": document.source_trust,
            "observed_at": document.observed_at,
            "evidence_refs": list(document.evidence_refs),
            "verified": True,
        }

    @_journal_mutation
    def capture_review_binding(self, memory_id: str) -> dict[str, Any]:
        """Capture the candidate and related native revisions before review dispatch."""
        document = self._raw_get(memory_id)
        related_ids = (memory_id, *document.supersedes)
        memories: dict[str, dict[str, Any]] = {}
        for related_id in related_ids:
            related = self._raw_get(str(related_id))
            memories[str(related_id)] = {
                "memory_id": str(related_id),
                "stream_version": len(self._stream_events(str(related_id))),
                "content_hash": related.content_hash,
                "status": related.status,
                "source_event_ids": list(related.source_event_ids),
                "source_run_ids": list(related.source_run_ids),
                "conflict_key": related.conflict_key,
                "supersedes": list(related.supersedes),
                "superseded_by": related.superseded_by,
            }
        return {
            "schema": "SITINA_MEMORY_REVIEW_BINDING_V1",
            "candidate_memory_id": str(memory_id),
            "memories": memories,
        }

    def assert_review_binding(self, binding: Mapping[str, Any]) -> None:
        """Fail closed when a reviewed candidate or related root changed."""
        if not isinstance(binding, Mapping) or binding.get("schema") != "SITINA_MEMORY_REVIEW_BINDING_V1":
            raise MemoryStateError("memory review binding is missing or malformed")
        memories = binding.get("memories")
        if not isinstance(memories, Mapping) or not memories:
            raise MemoryStateError("memory review binding has no native revisions")
        for memory_id, expected in memories.items():
            if not isinstance(expected, Mapping):
                raise MemoryStateError("memory review binding revision is malformed")
            current = self._raw_get(str(memory_id))
            observed = {
                "memory_id": str(memory_id),
                "stream_version": len(self._stream_events(str(memory_id))),
                "content_hash": current.content_hash,
                "status": current.status,
                "source_event_ids": list(current.source_event_ids),
                "source_run_ids": list(current.source_run_ids),
                "conflict_key": current.conflict_key,
                "supersedes": list(current.supersedes),
                "superseded_by": current.superseded_by,
            }
            if observed != dict(expected):
                raise MemoryStateError("memory review binding is stale")

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

    def _episode_events(self, episode_id: str) -> tuple[EventEnvelope, ...]:
        stream_id = f"episode/{episode_id}"
        return tuple(event for event in self.journal.iter_events(0) if event.stream_id == stream_id)

    @_journal_mutation
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
        obligation_id: str | None = None,
        processor_version: str | None = None,
        terminal_event_id: str | None = None,
        source_closure: Mapping[str, Any] | None = None,
        source_frontier: int | None = None,
    ) -> EpisodeDocument:
        if self.feature_activations is None:
            raise MemoryStateError("Memory V1 writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("memory_v1_write")
        if not lesson or len(lesson.encode("utf-8")) > 64 * 1024:
            raise MemoryError("episode lesson must be between 1 byte and 64 KiB")
        lesson_hash = hashlib.sha256(lesson.encode("utf-8")).hexdigest()
        if source_closure is not None and not isinstance(source_closure, Mapping):
            raise MemoryStateError("episode source closure must be a mapping")
        b6_identity = any(
            value is not None
            for value in (obligation_id, processor_version, terminal_event_id, source_closure, source_frontier)
        )
        if b6_identity and (
            not obligation_id
            or not processor_version
            or not terminal_event_id
            or source_closure is None
            or source_frontier is None
        ):
            raise MemoryStateError("B6 episode replay requires the complete terminal identity and source closure")
        closure_hash = (
            hashlib.sha256(canonical_json_bytes(dict(source_closure))).hexdigest()
            if source_closure is not None else None
        )
        existing_events = self._episode_events(episode_id)
        if existing_events:
            payload = existing_events[0].payload
            durable = payload.get("episode_document", payload)
            try:
                existing_document = EpisodeDocument.model_validate(durable)
            except Exception as error:
                raise MemoryStateError("existing episode document is malformed") from error
            existing_schema = str(payload.get("schema") or "SITINA_EPISODE_V1")
            if existing_schema == "SITINA_EPISODE_CREATED_V2":
                if not b6_identity:
                    raise MemoryStateError("B6 episode cannot be replayed through the legacy partial entry")
                if (
                    payload.get("obligation_id") != obligation_id
                    or payload.get("processor_version") != processor_version
                    or payload.get("terminal_event_id") != terminal_event_id
                    or payload.get("source_closure_hash") != closure_hash
                    or payload.get("lesson_hash") != lesson_hash
                    or int(existing_document.source_frontier) != int(source_frontier)
                    or tuple(existing_document.action_event_range) != tuple(action_event_range)
                    or existing_document.outcome != outcome
                    or existing_document.failure_reason_code != failure_reason_code
                ):
                    raise MemoryStateError("episode identity is bound to a different B6 request")
            elif b6_identity:
                raise MemoryStateError("legacy episode cannot be reinterpreted as a B6 episode")
            if existing_document.source_run_id != source_run_id or existing_document.goal_ref != goal_ref.reference_id:
                raise MemoryStateError("episode identity is bound to different source inputs")
            if existing_document.terminal_evidence_ref != terminal_evidence_ref.reference_id:
                raise MemoryStateError("episode identity is bound to different terminal evidence")
            return existing_document
        fixed_frontier = int(source_frontier) if source_frontier is not None else self.journal.head_position
        if fixed_frontier < 1 or fixed_frontier > self.journal.head_position:
            raise MemoryStateError("episode source frontier is not a committed Journal frontier")
        source_frontier = fixed_frontier
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
        if b6_identity:
            durable_payload = {
                **durable_document,
                "schema": "SITINA_EPISODE_CREATED_V2",
                "episode_document": durable_document,
                "obligation_id": obligation_id,
                "processor_version": processor_version,
                "terminal_event_id": terminal_event_id,
                "source_closure": dict(source_closure or {}),
                "source_closure_hash": closure_hash,
                "lesson_hash": lesson_hash,
            }
        else:
            durable_payload = durable_document
        digest = hashlib.sha256(canonical_json_bytes(durable_payload)).hexdigest()
        command = CommandEnvelope(
            "episode-command-" + digest[:42],
            self.TENANT,
            stream_id,
            "memory.episode-create",
            "journal-memory-repository",
            occurred_at,
            {"episode_id": episode_id, "document_hash": digest, **({"source_closure_hash": closure_hash} if b6_identity else {})},
        )
        event = EventEnvelope(
            "episode-event-" + digest[:44],
            "memory.episode-created",
            self.TENANT,
            stream_id,
            0,
            0,
            occurred_at,
            durable_payload,
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
