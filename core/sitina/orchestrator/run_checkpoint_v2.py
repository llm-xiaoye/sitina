from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Mapping, Sequence

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
HexDigest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]


class RunCheckpointV2Error(RuntimeError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class JournalRange(_StrictModel):
    from_position: int = Field(ge=1)
    to_position: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> "JournalRange":
        if self.to_position < self.from_position:
            raise ValueError("checkpoint Journal range is reversed")
        return self


class RunCheckpointV2(_StrictModel):
    schema_id: Literal["SITINA_RUN_CHECKPOINT_V2"] = Field(default="SITINA_RUN_CHECKPOINT_V2", alias="schema")
    checkpoint_id: Identifier
    run_id: Identifier
    checkpoint_kind: Literal["incremental", "terminal_compact"]
    base_checkpoint_ref: CASReference | None
    journal_range: JournalRange
    new_cas_refs: tuple[CASReference, ...] = Field(max_length=6_000)
    blackboard_delta_ref: CASReference | None
    worktree_state_ref: CASReference | None
    frontier_commitment: HexDigest

    @model_validator(mode="after")
    def _shape(self) -> "RunCheckpointV2":
        if tuple(sorted(set(self.new_cas_refs))) != self.new_cas_refs:
            raise ValueError("checkpoint new_cas_refs must be unique and sorted")
        if self.checkpoint_kind == "terminal_compact" and self.base_checkpoint_ref is not None:
            raise ValueError("terminal compact checkpoint must be independently recoverable")
        if self.checkpoint_kind == "incremental" and self.base_checkpoint_ref in self.new_cas_refs:
            raise ValueError("base checkpoint is not a newly introduced run object")
        for reference in (self.blackboard_delta_ref, self.worktree_state_ref):
            if reference is not None and reference not in self.new_cas_refs:
                raise ValueError("checkpoint delta/state ref must be included in new_cas_refs")
        return self


@dataclass(frozen=True)
class PublishedRunCheckpoint:
    document: RunCheckpointV2
    object_ref: ObjectRef
    source_position: int
    raw_size: int


class RunCheckpointV2Repository:
    TENANT = "sitina-checkpoint"
    MAX_CHECKPOINT_BYTES = 512 * 1024
    _LIFECYCLE_EVENTS = frozenset(
        {
            "run.checkpoint-published",
            "run.checkpoint-chain-compacted",
            "run.evidence-published",
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
            raise RunCheckpointV2Error("Run Checkpoint V2 writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("checkpoint_v2_write")
        return self.feature_activations

    def _run_events(self, run_id: str, *, through_position: int | None = None) -> tuple[EventEnvelope, ...]:
        through = self.journal.head_position if through_position is None else through_position
        return tuple(
            event
            for event in self.journal.iter_events(0)
            if event.position <= through
            and (event.stream_id == f"run/{run_id}" or event.payload.get("run_id") == run_id)
        )

    def _checkpoint_events(self, run_id: str) -> tuple[EventEnvelope, ...]:
        return tuple(event for event in self._run_events(run_id) if event.event_type == "run.checkpoint-published")

    @staticmethod
    def _checkpoint_ref(event: EventEnvelope) -> ObjectRef:
        payload = event.payload
        return ObjectRef(
            str(payload["checkpoint_ref"]).removeprefix("cas:"),
            str(payload["checkpoint_tenant_id"]),
            str(payload["checkpoint_plaintext_commitment"]),
            str(payload["checkpoint_commitment_key_id"]),
            str(payload["checkpoint_profile"]),
        )

    def _open_event(self, event: EventEnvelope) -> PublishedRunCheckpoint:
        reference = self._checkpoint_ref(event)
        raw = self.cas.open_verified(reference)
        if len(raw) > self.MAX_CHECKPOINT_BYTES or hashlib.sha256(raw).hexdigest() != event.payload.get("checkpoint_hash"):
            raise RunCheckpointV2Error("Run Checkpoint V2 body is oversized or hash-invalid")
        document = RunCheckpointV2.model_validate(parse_canonical_json(raw))
        if document.checkpoint_id != event.payload.get("checkpoint_id") or document.run_id != event.payload.get("run_id"):
            raise RunCheckpointV2Error("Run Checkpoint V2 publication identity mismatch")
        return PublishedRunCheckpoint(document, reference, event.position, len(raw))

    def latest(self, run_id: str) -> PublishedRunCheckpoint | None:
        events = self._checkpoint_events(run_id)
        return self._open_event(events[-1]) if events else None

    def _semantic_refs(self, run_id: str, journal_range: JournalRange) -> tuple[str, ...]:
        refs = {
            reference
            for event in self._run_events(run_id, through_position=journal_range.to_position)
            if journal_range.from_position <= event.position <= journal_range.to_position
            and event.event_type not in self._LIFECYCLE_EVENTS
            for reference in event.object_refs
        }
        return tuple(sorted(refs))

    def _first_run_position(self, run_id: str, through_position: int) -> int:
        events = [
            event
            for event in self._run_events(run_id, through_position=through_position)
            if event.event_type not in self._LIFECYCLE_EVENTS
        ]
        if not events:
            raise RunCheckpointV2Error("cannot checkpoint a run with no canonical events")
        return events[0].position

    def create(
        self,
        *,
        run_id: str,
        through_position: int,
        occurred_at: str,
        blackboard_delta_ref: str | None = None,
        worktree_state_ref: str | None = None,
        terminal_compact: bool = False,
    ) -> PublishedRunCheckpoint:
        activations = self._assert_write_enabled()
        if through_position < 1 or through_position > self.journal.head_position:
            raise RunCheckpointV2Error("checkpoint frontier is outside the verified Journal")
        run_events = self._run_events(run_id, through_position=through_position)
        if not run_events:
            raise RunCheckpointV2Error("run has no canonical events at the checkpoint frontier")
        terminal_events = [event for event in run_events if event.event_type == "run.terminal"]
        if terminal_compact and not terminal_events:
            raise RunCheckpointV2Error("terminal compact checkpoint requires a committed run.terminal event")

        previous = self.latest(run_id)
        if terminal_compact:
            from_position = self._first_run_position(run_id, through_position)
            base_ref = None
            kind = "terminal_compact"
        else:
            from_position = (
                self._first_run_position(run_id, through_position)
                if previous is None
                else previous.document.journal_range.to_position + 1
            )
            base_ref = None if previous is None else previous.object_ref.reference_id
            kind = "incremental"
        if from_position > through_position:
            raise RunCheckpointV2Error("there are no new Journal positions for an incremental checkpoint")
        journal_range = JournalRange(from_position=from_position, to_position=through_position)
        refs = set(self._semantic_refs(run_id, journal_range))
        for reference in (blackboard_delta_ref, worktree_state_ref):
            if reference is not None and reference not in refs:
                raise RunCheckpointV2Error("checkpoint delta/state ref is not rooted by this run range")
        frontier = self.journal._position_hash.get(through_position)
        if frontier is None:
            raise RunCheckpointV2Error("checkpoint frontier has no canonical transaction commitment")
        identity_seed = {
            "run_id": run_id,
            "kind": kind,
            "base_checkpoint_ref": base_ref,
            "journal_range": journal_range.model_dump(mode="json"),
            "new_cas_refs": sorted(refs),
            "blackboard_delta_ref": blackboard_delta_ref,
            "worktree_state_ref": worktree_state_ref,
            "frontier_commitment": frontier,
        }
        checkpoint_id = "checkpoint-v2-" + hashlib.sha256(canonical_json_bytes(identity_seed)).hexdigest()[:40]
        document = RunCheckpointV2(
            checkpoint_id=checkpoint_id,
            run_id=run_id,
            checkpoint_kind=kind,
            base_checkpoint_ref=base_ref,
            journal_range=journal_range,
            new_cas_refs=tuple(sorted(refs)),
            blackboard_delta_ref=blackboard_delta_ref,
            worktree_state_ref=worktree_state_ref,
            frontier_commitment=frontier,
        )
        raw = canonical_json_bytes(document.model_dump(mode="json", by_alias=True))
        if len(raw) > self.MAX_CHECKPOINT_BYTES:
            raise RunCheckpointV2Error("Run Checkpoint V2 exceeds the 512 KiB limit")
        published = self.cas.publish_verified(
            encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="run-checkpoint-v2")
        )
        reference = published.object_ref
        payload = {
            "schema": "SITINA_RUN_CHECKPOINT_PUBLISHED_V2",
            "run_id": run_id,
            "checkpoint_id": checkpoint_id,
            "checkpoint_kind": kind,
            "checkpoint_ref": reference.reference_id,
            "checkpoint_hash": hashlib.sha256(raw).hexdigest(),
            "checkpoint_tenant_id": reference.tenant_id,
            "checkpoint_plaintext_commitment": reference.plaintext_commitment,
            "checkpoint_commitment_key_id": reference.commitment_key_id,
            "checkpoint_profile": reference.profile,
            "journal_from_position": from_position,
            "journal_to_position": through_position,
            "frontier_commitment": frontier,
        }
        digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        stream_id = f"run/{run_id}"
        tenant_id = run_events[0].tenant_id
        command = CommandEnvelope(
            "checkpoint-v2-command-" + digest[:37],
            tenant_id,
            stream_id,
            "run.checkpoint-v2-publish",
            "run-checkpoint-v2-repository",
            occurred_at,
            {"run_id": run_id, "checkpoint_hash": payload["checkpoint_hash"]},
        )
        event = EventEnvelope(
            "checkpoint-v2-event-" + digest[:39],
            "run.checkpoint-published",
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
        activations.record_first_write("checkpoint_v2_write", journal_position=receipt.last_position)
        return PublishedRunCheckpoint(document, reference, receipt.last_position, len(raw))

    def verify(self, checkpoint: PublishedRunCheckpoint) -> None:
        document = checkpoint.document
        if document.journal_range.to_position > self.journal.head_position:
            raise RunCheckpointV2Error("checkpoint is beyond the current Journal head")
        if self.journal._position_hash.get(document.journal_range.to_position) != document.frontier_commitment:
            raise RunCheckpointV2Error("checkpoint frontier commitment mismatch")
        expected_refs = self._semantic_refs(document.run_id, document.journal_range)
        if expected_refs != document.new_cas_refs:
            raise RunCheckpointV2Error("checkpoint refs differ from current-run Journal range")
        if document.checkpoint_kind == "terminal_compact":
            terminal = [
                event
                for event in self._run_events(document.run_id, through_position=document.journal_range.to_position)
                if event.event_type == "run.terminal"
            ]
            if not terminal:
                raise RunCheckpointV2Error("terminal compact checkpoint has no terminal fact")

    def restore_chain(self, run_id: str) -> tuple[PublishedRunCheckpoint, ...]:
        publications = {event.payload["checkpoint_ref"]: event for event in self._checkpoint_events(run_id)}
        latest = self.latest(run_id)
        if latest is None:
            raise RunCheckpointV2Error("run has no V2 checkpoint")
        if latest.document.checkpoint_kind == "terminal_compact":
            self.verify(latest)
            return (latest,)
        reversed_chain: list[PublishedRunCheckpoint] = []
        current = latest
        while True:
            self.verify(current)
            reversed_chain.append(current)
            base = current.document.base_checkpoint_ref
            if base is None:
                break
            try:
                current = self._open_event(publications[base])
            except KeyError as error:
                raise RunCheckpointV2Error("checkpoint base reference is unavailable") from error
        chain = tuple(reversed(reversed_chain))
        for left, right in zip(chain, chain[1:]):
            if left.document.journal_range.to_position + 1 != right.document.journal_range.from_position:
                raise RunCheckpointV2Error("checkpoint incremental ranges are discontinuous")
        return chain

    def compact_terminal(
        self,
        *,
        run_id: str,
        through_position: int,
        occurred_at: str,
    ) -> PublishedRunCheckpoint:
        prior_refs = tuple(event.payload["checkpoint_ref"] for event in self._checkpoint_events(run_id))
        terminal = self.create(
            run_id=run_id,
            through_position=through_position,
            occurred_at=occurred_at,
            terminal_compact=True,
        )
        self.verify(terminal)
        payload = {
            "schema": "SITINA_RUN_CHECKPOINT_CHAIN_COMPACTED_V1",
            "run_id": run_id,
            "terminal_checkpoint_ref": terminal.object_ref.reference_id,
            "released_checkpoint_root_refs": list(prior_refs),
            "history_objects_deleted": False,
        }
        digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        stream_id = f"run/{run_id}"
        run_events = self._run_events(run_id)
        tenant_id = run_events[0].tenant_id
        command = CommandEnvelope(
            "checkpoint-compact-command-" + digest[:35],
            tenant_id,
            stream_id,
            "run.checkpoint-chain-compact",
            "run-checkpoint-v2-repository",
            occurred_at,
            {"run_id": run_id, "terminal_checkpoint_ref": terminal.object_ref.reference_id},
        )
        event = EventEnvelope(
            "checkpoint-compact-event-" + digest[:37],
            "run.checkpoint-chain-compacted",
            tenant_id,
            stream_id,
            0,
            0,
            occurred_at,
            payload,
        )
        self.journal.append(command, self.journal._stream_heads.get(stream_id, 0), [event])
        return terminal


__all__ = [
    "JournalRange",
    "PublishedRunCheckpoint",
    "RunCheckpointV2",
    "RunCheckpointV2Error",
    "RunCheckpointV2Repository",
]
