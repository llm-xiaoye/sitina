from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

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


class AgentContextV2Error(RuntimeError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class AgentContextManifestV2(_StrictModel):
    schema_id: Literal["SITINA_AGENT_CONTEXT_MANIFEST_V2"] = Field(
        default="SITINA_AGENT_CONTEXT_MANIFEST_V2",
        alias="schema",
    )
    run_id: Identifier
    call_id: Identifier
    agent_id: Identifier
    prompt_template_ref: CASReference
    base_project_context_ref: CASReference | None
    conversation_state_ref: CASReference | None
    rolling_summary_ref: CASReference | None
    retrieved_memory_refs: tuple[CASReference, ...] = Field(default=(), max_length=256)
    blackboard_base_ref: CASReference | None
    delta_refs: tuple[CASReference, ...] = Field(default=(), max_length=512)
    renderer_version: Literal["context-renderer-v2"] = "context-renderer-v2"
    rendered_input_hash: HexDigest

    @field_validator("retrieved_memory_refs", "delta_refs")
    @classmethod
    def _unique_ordered_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("context reference arrays cannot contain duplicates")
        return values

    @property
    def component_refs(self) -> tuple[str, ...]:
        scalar = (
            self.prompt_template_ref,
            self.base_project_context_ref,
            self.conversation_state_ref,
            self.rolling_summary_ref,
            self.blackboard_base_ref,
        )
        return tuple(reference for reference in scalar if reference is not None) + self.retrieved_memory_refs + self.delta_refs


@dataclass(frozen=True)
class PublishedAgentContext:
    manifest: AgentContextManifestV2
    manifest_ref: ObjectRef
    rendered: bytes
    source_position: int


class AgentContextRendererV2:
    VERSION = "context-renderer-v2"

    def __init__(self, cas: LocalCAS):
        self.cas = cas

    def _open(self, reference: str) -> bytes:
        return self.cas.open_verified(self.cas.resolve_reference(reference))

    def render_refs(
        self,
        *,
        prompt_template_ref: str,
        base_project_context_ref: str | None,
        conversation_state_ref: str | None,
        rolling_summary_ref: str | None,
        retrieved_memory_refs: Sequence[str],
        blackboard_base_ref: str | None,
        delta_refs: Sequence[str],
    ) -> bytes:
        sections: list[tuple[str, str]] = [("prompt_template", prompt_template_ref)]
        for name, reference in (
            ("base_project_context", base_project_context_ref),
            ("conversation_state", conversation_state_ref),
            ("rolling_summary", rolling_summary_ref),
        ):
            if reference is not None:
                sections.append((name, reference))
        sections.extend((f"retrieved_memory:{index}", reference) for index, reference in enumerate(retrieved_memory_refs))
        if blackboard_base_ref is not None:
            sections.append(("blackboard_base", blackboard_base_ref))
        sections.extend((f"delta:{index}", reference) for index, reference in enumerate(delta_refs))
        rendered = bytearray()
        for name, reference in sections:
            body = self._open(reference)
            rendered.extend(f"[{name} bytes={len(body)} ref={reference}]\n".encode("utf-8"))
            rendered.extend(body)
            rendered.extend(b"\n")
        return bytes(rendered)

    def render_manifest(self, manifest: AgentContextManifestV2) -> bytes:
        return self.render_refs(
            prompt_template_ref=manifest.prompt_template_ref,
            base_project_context_ref=manifest.base_project_context_ref,
            conversation_state_ref=manifest.conversation_state_ref,
            rolling_summary_ref=manifest.rolling_summary_ref,
            retrieved_memory_refs=manifest.retrieved_memory_refs,
            blackboard_base_ref=manifest.blackboard_base_ref,
            delta_refs=manifest.delta_refs,
        )


class AgentContextManifestRepository:
    TENANT = "sitina-agent-context"

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
        self.renderer = AgentContextRendererV2(cas)

    def _assert_write_enabled(self) -> FeatureActivationRegistry:
        if self.feature_activations is None:
            raise AgentContextV2Error("Agent Context V2 writer has no verified Journal feature activation state")
        self.feature_activations.assert_write_enabled("agent_context_v2_write")
        return self.feature_activations

    def create(
        self,
        *,
        run_id: str,
        call_id: str,
        agent_id: str,
        prompt_template_ref: ObjectRef,
        base_project_context_ref: ObjectRef | None,
        conversation_state_ref: ObjectRef | None,
        rolling_summary_ref: ObjectRef | None,
        retrieved_memory_refs: Sequence[ObjectRef],
        blackboard_base_ref: ObjectRef | None,
        delta_refs: Sequence[ObjectRef],
        occurred_at: str,
        expected_rendered_input_hash: str | None = None,
    ) -> PublishedAgentContext:
        activations = self._assert_write_enabled()
        run_stream_id = f"run/{run_id}"
        # Context publications are an independently versioned child stream.
        # Provider execution can publish one or more manifests between two
        # authoritative run-stage appends; sharing the run stream would stale
        # the run command handler's optimistic stream version after every
        # successful Provider call.
        stream_id = f"run-context/{run_id}"
        run_events = tuple(
            event
            for event in self.journal.iter_events(0)
            if event.stream_id == run_stream_id or event.payload.get("run_id") == run_id
        )
        if not run_events:
            raise AgentContextV2Error("Agent Context manifest requires a canonical run")
        tenant_id = run_events[0].tenant_id
        ref = lambda value: value.reference_id if value is not None else None
        rendered = self.renderer.render_refs(
            prompt_template_ref=prompt_template_ref.reference_id,
            base_project_context_ref=ref(base_project_context_ref),
            conversation_state_ref=ref(conversation_state_ref),
            rolling_summary_ref=ref(rolling_summary_ref),
            retrieved_memory_refs=tuple(item.reference_id for item in retrieved_memory_refs),
            blackboard_base_ref=ref(blackboard_base_ref),
            delta_refs=tuple(item.reference_id for item in delta_refs),
        )
        rendered_hash = hashlib.sha256(rendered).hexdigest()
        if expected_rendered_input_hash is not None and expected_rendered_input_hash != rendered_hash:
            raise AgentContextV2Error("Agent Context reconstructed input hash differs before publication")
        manifest = AgentContextManifestV2(
            run_id=run_id,
            call_id=call_id,
            agent_id=agent_id,
            prompt_template_ref=prompt_template_ref.reference_id,
            base_project_context_ref=ref(base_project_context_ref),
            conversation_state_ref=ref(conversation_state_ref),
            rolling_summary_ref=ref(rolling_summary_ref),
            retrieved_memory_refs=tuple(item.reference_id for item in retrieved_memory_refs),
            blackboard_base_ref=ref(blackboard_base_ref),
            delta_refs=tuple(item.reference_id for item in delta_refs),
            rendered_input_hash=rendered_hash,
        )
        raw = canonical_json_bytes(manifest.model_dump(mode="json", by_alias=True))
        manifest_proof = self.cas.publish_verified(
            encrypt_object(raw, self.keys, tenant_id=self.TENANT, purpose="agent-context-manifest-v2")
        )
        components = (
            (prompt_template_ref,)
            + tuple(item for item in (base_project_context_ref, conversation_state_ref, rolling_summary_ref) if item is not None)
            + tuple(retrieved_memory_refs)
            + ((blackboard_base_ref,) if blackboard_base_ref is not None else ())
            + tuple(delta_refs)
        )
        proofs_by_ref = {item.reference_id: self.cas.verify_existing(item) for item in components}
        proofs_by_ref[manifest_proof.object_ref.reference_id] = manifest_proof
        payload = {
            "schema": "SITINA_AGENT_CONTEXT_MANIFEST_PUBLISHED_V2",
            "run_id": run_id,
            "call_id": call_id,
            "agent_id": agent_id,
            "manifest_ref": manifest_proof.object_ref.reference_id,
            "manifest_hash": hashlib.sha256(raw).hexdigest(),
            "renderer_version": manifest.renderer_version,
            "rendered_input_hash": rendered_hash,
            "component_ref_count": len(manifest.component_refs),
        }
        digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        command = CommandEnvelope(
            "agent-context-command-" + digest[:38],
            tenant_id,
            stream_id,
            "agent.context-manifest-v2-publish",
            "agent-context-manifest-repository",
            occurred_at,
            {"run_id": run_id, "call_id": call_id, "manifest_hash": payload["manifest_hash"]},
        )
        event = EventEnvelope(
            "agent-context-event-" + digest[:40],
            "agent.context-manifest-published",
            tenant_id,
            stream_id,
            0,
            0,
            occurred_at,
            payload,
            tuple(sorted(proofs_by_ref)),
        )
        receipt = self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
            object_reference_proofs=tuple(proofs_by_ref.values()),
        )
        activations.record_first_write("agent_context_v2_write", journal_position=receipt.last_position)
        return PublishedAgentContext(manifest, manifest_proof.object_ref, rendered, receipt.last_position)

    def open(self, event: EventEnvelope) -> PublishedAgentContext:
        if event.event_type != "agent.context-manifest-published":
            raise AgentContextV2Error("event is not an Agent Context V2 publication")
        manifest_ref = str(event.payload["manifest_ref"])
        reference = self.cas.resolve_reference(manifest_ref)
        raw = self.cas.open_verified(reference)
        if hashlib.sha256(raw).hexdigest() != event.payload.get("manifest_hash"):
            raise AgentContextV2Error("Agent Context manifest body hash mismatch")
        manifest = AgentContextManifestV2.model_validate(parse_canonical_json(raw))
        rendered = self.renderer.render_manifest(manifest)
        if hashlib.sha256(rendered).hexdigest() != manifest.rendered_input_hash:
            raise AgentContextV2Error("Agent Context reconstruction hash mismatch")
        return PublishedAgentContext(manifest, reference, rendered, event.position)


__all__ = [
    "AgentContextManifestRepository",
    "AgentContextManifestV2",
    "AgentContextRendererV2",
    "AgentContextV2Error",
    "PublishedAgentContext",
]
