from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes, parse_canonical_json
from sitina.orchestrator.run_checkpoint_v2 import JournalRange, PublishedRunCheckpoint, RunCheckpointV2Repository
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


class ReferencedEvidenceError(RuntimeError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class RunEvidenceV2(_StrictModel):
    schema_id: Literal["SITINA_RUN_EVIDENCE_V2"] = Field(default="SITINA_RUN_EVIDENCE_V2", alias="schema")
    evidence_id: Identifier
    run_id: Identifier
    journal_range: JournalRange
    terminal_event_id: Identifier
    terminal_event_hash: HexDigest
    checkpoint_ref: CASReference
    input_refs: tuple[CASReference, ...] = Field(default=(), max_length=2_000)
    output_refs: tuple[CASReference, ...] = Field(default=(), max_length=2_000)
    tool_record_refs: tuple[CASReference, ...] = Field(default=(), max_length=2_000)
    provider_call_ids: tuple[Identifier, ...] = Field(default=(), max_length=2_000)
    evidence_policy_hash: HexDigest

    @field_validator("input_refs", "output_refs", "tool_record_refs", "provider_call_ids")
    @classmethod
    def _sets_are_sorted(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("evidence reference/identity arrays must be unique and sorted")
        return values

    @model_validator(mode="after")
    def _reference_classes_do_not_overlap(self) -> "RunEvidenceV2":
        classes = (set(self.input_refs), set(self.output_refs), set(self.tool_record_refs))
        if classes[0] & classes[1] or classes[0] & classes[2] or classes[1] & classes[2]:
            raise ValueError("one CAS ref cannot impersonate multiple evidence roles")
        return self


@dataclass(frozen=True)
class PublishedRunEvidence:
    document: RunEvidenceV2
    object_ref: ObjectRef
    source_position: int


class ReferencedEvidenceRepository:
    TENANT = "sitina-evidence"
    FORBIDDEN_BODY_FIELDS = frozenset(
        {
            "input",
            "input_payload",
            "output",
            "output_payload",
            "answer",
            "response",
            "prompt",
            "messages",
            "request_body",
            "response_body",
        }
    )

    def __init__(
        self,
        journal: LocalJournal,
        cas: LocalCAS,
        keys: InMemoryKeyProvider,
        *,
        feature_activations: FeatureActivationRegistry | None = None,
    ):
        self.journal = journal
        self.cas = cas
        self.keys = keys
        self.feature_activations = feature_activations

    def _assert_write_enabled(self) -> FeatureActivationRegistry:
        if self.feature_activations is None:
            raise ReferencedEvidenceError("Evidence V2 writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("evidence_v2_write")
        return self.feature_activations

    def _run_events(self, run_id: str, through_position: int | None = None) -> tuple[EventEnvelope, ...]:
        through = self.journal.head_position if through_position is None else through_position
        return tuple(
            event
            for event in self.journal.iter_events(0)
            if event.position <= through
            and (event.stream_id == f"run/{run_id}" or event.payload.get("run_id") == run_id)
        )

    @staticmethod
    def _object_ref(event: EventEnvelope) -> ObjectRef:
        payload = event.payload
        return ObjectRef(
            str(payload["evidence_ref"]).removeprefix("cas:"),
            str(payload["evidence_tenant_id"]),
            str(payload["evidence_plaintext_commitment"]),
            str(payload["evidence_commitment_key_id"]),
            str(payload["evidence_profile"]),
        )

    def create(
        self,
        *,
        run_id: str,
        checkpoint: PublishedRunCheckpoint,
        input_refs: tuple[str, ...],
        output_refs: tuple[str, ...],
        tool_record_refs: tuple[str, ...],
        provider_call_ids: tuple[str, ...],
        evidence_policy_hash: str,
        occurred_at: str,
    ) -> PublishedRunEvidence:
        activations = self._assert_write_enabled()
        RunCheckpointV2Repository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.feature_activations,
        ).verify(checkpoint)
        if checkpoint.document.run_id != run_id or checkpoint.document.checkpoint_kind != "terminal_compact":
            raise ReferencedEvidenceError("Evidence V2 requires this run's verified terminal compact checkpoint")
        run_events = self._run_events(run_id, checkpoint.document.journal_range.to_position)
        terminal = next((event for event in reversed(run_events) if event.event_type == "run.terminal"), None)
        if terminal is None or terminal.event_hash is None:
            raise ReferencedEvidenceError("Evidence V2 requires an authenticated terminal event")
        rooted_refs = {reference for event in run_events for reference in event.object_refs}
        classified = set(input_refs) | set(output_refs) | set(tool_record_refs)
        if not classified.issubset(rooted_refs):
            raise ReferencedEvidenceError("Evidence V2 may only classify CAS refs rooted by this run")
        identity_seed = {
            "run_id": run_id,
            "terminal_event_hash": terminal.event_hash,
            "checkpoint_ref": checkpoint.object_ref.reference_id,
            "input_refs": sorted(input_refs),
            "output_refs": sorted(output_refs),
            "tool_record_refs": sorted(tool_record_refs),
            "provider_call_ids": sorted(provider_call_ids),
            "evidence_policy_hash": evidence_policy_hash,
        }
        evidence_id = "evidence-v2-" + hashlib.sha256(canonical_json_bytes(identity_seed)).hexdigest()[:40]
        document = RunEvidenceV2(
            evidence_id=evidence_id,
            run_id=run_id,
            journal_range=checkpoint.document.journal_range,
            terminal_event_id=terminal.event_id,
            terminal_event_hash=terminal.event_hash,
            checkpoint_ref=checkpoint.object_ref.reference_id,
            input_refs=tuple(sorted(input_refs)),
            output_refs=tuple(sorted(output_refs)),
            tool_record_refs=tuple(sorted(tool_record_refs)),
            provider_call_ids=tuple(sorted(provider_call_ids)),
            evidence_policy_hash=evidence_policy_hash,
        )
        durable = document.model_dump(mode="json", by_alias=True)
        if self.FORBIDDEN_BODY_FIELDS & set(durable):
            raise ReferencedEvidenceError("Evidence V2 document contains duplicated body fields")
        raw = canonical_json_bytes(durable)
        published = self.cas.publish_verified(
            encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="run-evidence-v2")
        )
        reference = published.object_ref
        payload = {
            "schema": "SITINA_RUN_EVIDENCE_PUBLISHED_V2",
            "run_id": run_id,
            "evidence_id": evidence_id,
            "evidence_ref": reference.reference_id,
            "evidence_hash": hashlib.sha256(raw).hexdigest(),
            "evidence_tenant_id": reference.tenant_id,
            "evidence_plaintext_commitment": reference.plaintext_commitment,
            "evidence_commitment_key_id": reference.commitment_key_id,
            "evidence_profile": reference.profile,
            "checkpoint_ref": checkpoint.object_ref.reference_id,
            "terminal_event_id": terminal.event_id,
            "terminal_event_hash": terminal.event_hash,
        }
        digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        stream_id = f"run/{run_id}"
        tenant_id = run_events[0].tenant_id
        command = CommandEnvelope(
            "evidence-v2-command-" + digest[:39],
            tenant_id,
            stream_id,
            "run.evidence-v2-publish",
            "referenced-evidence-repository",
            occurred_at,
            {"run_id": run_id, "evidence_hash": payload["evidence_hash"]},
        )
        event = EventEnvelope(
            "evidence-v2-event-" + digest[:41],
            "run.evidence-published",
            tenant_id,
            stream_id,
            0,
            0,
            occurred_at,
            payload,
            (reference.reference_id,),
        )
        receipt = self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
            object_reference_proofs=(published,),
        )
        activations.record_first_write("evidence_v2_write", journal_position=receipt.last_position)
        return PublishedRunEvidence(document, reference, receipt.last_position)

    def open(self, event: EventEnvelope) -> PublishedRunEvidence:
        if event.event_type != "run.evidence-published":
            raise ReferencedEvidenceError("event is not an Evidence V2 publication")
        reference = self._object_ref(event)
        raw = self.cas.open_verified(reference)
        if hashlib.sha256(raw).hexdigest() != event.payload.get("evidence_hash"):
            raise ReferencedEvidenceError("Evidence V2 body hash mismatch")
        document = RunEvidenceV2.model_validate(parse_canonical_json(raw))
        if document.evidence_id != event.payload.get("evidence_id") or document.run_id != event.payload.get("run_id"):
            raise ReferencedEvidenceError("Evidence V2 publication identity mismatch")
        return PublishedRunEvidence(document, reference, event.position)

    def verify_replay(self, evidence: PublishedRunEvidence) -> dict[str, Any]:
        document = evidence.document
        events = self._run_events(document.run_id, document.journal_range.to_position)
        terminal = next((event for event in reversed(events) if event.event_type == "run.terminal"), None)
        if terminal is None or terminal.event_id != document.terminal_event_id or terminal.event_hash != document.terminal_event_hash:
            raise ReferencedEvidenceError("Evidence V2 terminal binding differs during replay")
        rooted = {reference for event in events for reference in event.object_refs}
        classified = set(document.input_refs) | set(document.output_refs) | set(document.tool_record_refs)
        if not classified.issubset(rooted):
            raise ReferencedEvidenceError("Evidence V2 replay has an unrooted classified reference")
        checkpoint_events = [
            event
            for event in self._run_events(document.run_id)
            if event.event_type == "run.checkpoint-published"
            and event.payload.get("checkpoint_ref") == document.checkpoint_ref
        ]
        if len(checkpoint_events) != 1:
            raise ReferencedEvidenceError("Evidence V2 checkpoint publication is missing or ambiguous")
        return {
            "status": "verified",
            "run_id": document.run_id,
            "evidence_id": document.evidence_id,
            "terminal_event_hash": document.terminal_event_hash,
            "checkpoint_ref": document.checkpoint_ref,
            "classified_ref_count": len(classified),
            "body_copy_count": 0,
        }


__all__ = [
    "PublishedRunEvidence",
    "ReferencedEvidenceError",
    "ReferencedEvidenceRepository",
    "RunEvidenceV2",
]
