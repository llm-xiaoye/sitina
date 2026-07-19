from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier
from sitina.security.key_provider import InMemoryKeyProvider, KeyPurpose


_HEX64 = re.compile(r"[0-9a-f]{64}")


class CoherentCutError(ValueError):
    pass


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


@dataclass(frozen=True)
class FrontierComponent:
    journal_id: str
    epoch: int
    shard: str
    position: int
    commitment: str
    key_id: str
    signature_hex: str

    def __post_init__(self) -> None:
        validate_identifier(self.journal_id, field="journal_id")
        validate_identifier(self.shard, field="shard")
        if self.epoch < 1 or self.position < 0:
            raise ValueError("frontier coordinates are invalid")
        _digest(self.commitment, "frontier commitment")
        if not re.fullmatch(r"[0-9a-f]{128}", self.signature_hex):
            raise ValueError("invalid frontier signature")

    def signed_mapping(self) -> dict[str, object]:
        return {
            "schema": "SIGNED_FRONTIER_COMPONENT_V1",
            "journal_id": self.journal_id,
            "epoch": self.epoch,
            "shard": self.shard,
            "position": self.position,
            "commitment": self.commitment,
        }

    @classmethod
    def sign(
        cls,
        provider: InMemoryKeyProvider,
        *,
        journal_id: str,
        epoch: int,
        shard: str,
        position: int,
        commitment: str,
    ) -> "FrontierComponent":
        unsigned = {
            "schema": "SIGNED_FRONTIER_COMPONENT_V1",
            "journal_id": journal_id,
            "epoch": epoch,
            "shard": shard,
            "position": position,
            "commitment": commitment,
        }
        key_id, signature = provider.sign(
            KeyPurpose.AUTHORITY_SIGNING,
            b"SITINA-FRONTIER-COMPONENT-V1\0" + canonical_json_bytes(unsigned),
        )
        return cls(journal_id, epoch, shard, position, commitment, key_id, signature.hex())

    def verify(self, provider: InMemoryKeyProvider) -> bool:
        return provider.verify(
            self.key_id,
            KeyPurpose.AUTHORITY_SIGNING,
            b"SITINA-FRONTIER-COMPONENT-V1\0" + canonical_json_bytes(self.signed_mapping()),
            bytes.fromhex(self.signature_hex),
        )

    def with_updates(self, **changes: object) -> "FrontierComponent":
        return dataclasses.replace(self, **changes)

    def mapping(self) -> dict[str, object]:
        return {**self.signed_mapping(), "key_id": self.key_id, "signature_hex": self.signature_hex}


@dataclass(frozen=True)
class SignedFrontierVectorV1:
    components: tuple[FrontierComponent, ...]
    profile: str = "BPLUS_OPT_V1_SINGLE_JOURNAL"

    @classmethod
    def from_components(cls, components: tuple[FrontierComponent, ...]) -> "SignedFrontierVectorV1":
        if len(components) != 1:
            raise ValueError("B+ OPT V1 requires exactly one frontier component")
        return cls(tuple(components))

    @property
    def component(self) -> FrontierComponent:
        return self.components[0]

    def mapping(self) -> dict[str, object]:
        return {"profile": self.profile, "components": [item.mapping() for item in self.components]}

    def semantic_mapping(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "components": [
                {**item.signed_mapping(), "key_id": item.key_id}
                for item in self.components
            ],
        }

    @property
    def frontier_hash(self) -> str:
        # The frontier identity commits to coordinates, commitment, and signing
        # key identity. The randomized signature envelope remains independently
        # verifiable but is not a semantic identity input.
        return domain_hash("SIGNED_FRONTIER_VECTOR", canonical_json_bytes(self.semantic_mapping()))


@dataclass(frozen=True)
class ObservationFrontier:
    vector: SignedFrontierVectorV1

    @property
    def frontier_hash(self) -> str:
        return domain_hash("OBSERVATION_FRONTIER", canonical_json_bytes(self.vector.semantic_mapping()))


@dataclass(frozen=True)
class DerivedFrontier:
    vector: SignedFrontierVectorV1

    @property
    def frontier_hash(self) -> str:
        return domain_hash("DERIVED_FRONTIER", canonical_json_bytes(self.vector.semantic_mapping()))


def _same_stream(*components: FrontierComponent) -> bool:
    coordinates = {(item.journal_id, item.epoch, item.shard) for item in components}
    return len(coordinates) == 1


@dataclass(frozen=True)
class CoherentCutProof:
    observation_frontier_hash: str
    derived_frontier_hash: str
    admitted_observations: tuple[tuple[str, int], ...]
    dispositions: tuple[tuple[str, int], ...]
    dependency_refs: tuple[str, ...]
    proof_hash: str

    @classmethod
    def build(
        cls,
        observation: ObservationFrontier,
        derived: DerivedFrontier,
        *,
        admitted_observations: Mapping[str, int],
        dispositions: Mapping[str, int],
        dependency_refs: tuple[str, ...],
    ) -> "CoherentCutProof":
        o, p = observation.vector.component, derived.vector.component
        if not _same_stream(o, p) or o.position > p.position:
            raise CoherentCutError("O and P do not form an ordered same-stream cut")
        admitted = tuple(sorted(admitted_observations.items()))
        disposed = tuple(sorted(dispositions.items()))
        disposition_map = dict(disposed)
        for observation_id, admitted_position in admitted:
            if admitted_position <= o.position:
                disposition = disposition_map.get(observation_id)
                if disposition is None or not admitted_position <= disposition <= p.position:
                    raise CoherentCutError("observation at or before O lacks a disposition by P")
        if tuple(sorted(set(dependency_refs))) != dependency_refs:
            raise CoherentCutError("dependency references must be unique and sorted")
        core = {
            "schema": "COHERENT_CUT_PROOF_V1",
            "observation_frontier_hash": observation.frontier_hash,
            "derived_frontier_hash": derived.frontier_hash,
            "admitted_observations": [[key, value] for key, value in admitted],
            "dispositions": [[key, value] for key, value in disposed],
            "dependency_refs": list(dependency_refs),
        }
        return cls(
            observation.frontier_hash,
            derived.frontier_hash,
            admitted,
            disposed,
            dependency_refs,
            domain_hash("COHERENT_CUT_PROOF", canonical_json_bytes(core)),
        )


@dataclass(frozen=True)
class TerminalRef:
    vector: SignedFrontierVectorV1
    event_id: str
    event_hash: str
    observation_frontier_hash: str
    derived_frontier_hash: str
    coherent_cut_proof_hash: str
    checkpoint_hash: str
    eligibility_manifest_hash: str
    outcome_refs: tuple[str, ...]
    terminal_hash: str

    @classmethod
    def build(
        cls,
        vector: SignedFrontierVectorV1,
        *,
        event_id: str,
        event_hash: str,
        observation: ObservationFrontier,
        derived: DerivedFrontier,
        coherent_cut_proof_hash: str,
        checkpoint_hash: str,
        eligibility_manifest_hash: str,
        outcome_refs: tuple[str, ...],
    ) -> "TerminalRef":
        t, o, p = vector.component, observation.vector.component, derived.vector.component
        if not _same_stream(o, p, t) or not o.position <= p.position < t.position:
            raise ValueError("terminal must satisfy O <= P < T in one Journal epoch/shard")
        validate_identifier(event_id, field="terminal event_id")
        for value, field in (
            (event_hash, "event hash"),
            (coherent_cut_proof_hash, "coherent cut proof hash"),
            (checkpoint_hash, "checkpoint hash"),
            (eligibility_manifest_hash, "eligibility manifest hash"),
        ):
            _digest(value, field)
        if not outcome_refs or tuple(sorted(set(outcome_refs))) != outcome_refs:
            raise ValueError("terminal outcome references must be non-empty, unique, and sorted")
        for reference in outcome_refs:
            _digest(reference, "outcome reference")
        core = {
            "schema": "TERMINAL_REF_V1",
            "vector": vector.semantic_mapping(),
            "event_id": event_id,
            "event_hash": event_hash,
            "observation_frontier_hash": observation.frontier_hash,
            "derived_frontier_hash": derived.frontier_hash,
            "coherent_cut_proof_hash": coherent_cut_proof_hash,
            "checkpoint_hash": checkpoint_hash,
            "eligibility_manifest_hash": eligibility_manifest_hash,
            "outcome_refs": list(outcome_refs),
        }
        return cls(
            vector,
            event_id,
            event_hash,
            observation.frontier_hash,
            derived.frontier_hash,
            coherent_cut_proof_hash,
            checkpoint_hash,
            eligibility_manifest_hash,
            outcome_refs,
            domain_hash("TERMINAL_REF", canonical_json_bytes(core)),
        )

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "TERMINAL_REF_V1",
            "vector": self.vector.mapping(),
            "event_id": self.event_id,
            "event_hash": self.event_hash,
            "observation_frontier_hash": self.observation_frontier_hash,
            "derived_frontier_hash": self.derived_frontier_hash,
            "coherent_cut_proof_hash": self.coherent_cut_proof_hash,
            "checkpoint_hash": self.checkpoint_hash,
            "eligibility_manifest_hash": self.eligibility_manifest_hash,
            "outcome_refs": list(self.outcome_refs),
        }

    def core_mapping(self) -> dict[str, object]:
        return {
            "schema": "TERMINAL_REF_V1",
            "vector": self.vector.semantic_mapping(),
            "event_id": self.event_id,
            "event_hash": self.event_hash,
            "observation_frontier_hash": self.observation_frontier_hash,
            "derived_frontier_hash": self.derived_frontier_hash,
            "coherent_cut_proof_hash": self.coherent_cut_proof_hash,
            "checkpoint_hash": self.checkpoint_hash,
            "eligibility_manifest_hash": self.eligibility_manifest_hash,
            "outcome_refs": list(self.outcome_refs),
        }
