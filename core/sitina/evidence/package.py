from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .frontier import DerivedFrontier, ObservationFrontier, TerminalRef


class EvidencePackageError(ValueError):
    pass


@dataclass(frozen=True)
class DependencyClosure:
    roots: tuple[str, ...]
    edges: tuple[tuple[str, tuple[str, ...]], ...]
    visited_identities: tuple[str, ...]
    root_set_hash: str
    edge_set_hash: str
    visited_set_hash: str

    @classmethod
    def build(cls, *, roots: tuple[str, ...], edges: Mapping[str, tuple[str, ...]]) -> "DependencyClosure":
        normalized_roots = tuple(sorted(set(roots)))
        if len(normalized_roots) != len(roots):
            raise EvidencePackageError("dependency roots must be unique")
        normalized_edges = tuple(
            (source, tuple(sorted(set(destinations))))
            for source, destinations in sorted(edges.items())
        )
        graph = dict(normalized_edges)
        pending = list(normalized_roots)
        visited: set[str] = set()
        while pending:
            identity = pending.pop()
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(graph.get(identity, ()))
        ordered_visited = tuple(sorted(visited))
        root_hash = domain_hash("DEPENDENCY_ROOT_SET", canonical_json_bytes(list(normalized_roots)))
        edge_hash = domain_hash("DEPENDENCY_EDGE_SET", canonical_json_bytes([[source, list(targets)] for source, targets in normalized_edges]))
        visited_hash = domain_hash("DEPENDENCY_VISITED_SET", canonical_json_bytes(list(ordered_visited)))
        return cls(normalized_roots, normalized_edges, ordered_visited, root_hash, edge_hash, visited_hash)

    def mapping(self) -> dict[str, object]:
        return {
            "roots": list(self.roots),
            "edges": [[source, list(targets)] for source, targets in self.edges],
            "visited_identities": list(self.visited_identities),
            "root_set_hash": self.root_set_hash,
            "edge_set_hash": self.edge_set_hash,
            "visited_set_hash": self.visited_set_hash,
        }


@dataclass(frozen=True)
class EvidencePackageCore:
    package_id: str
    run_id: str
    generation: int
    predecessor_core_hash: str | None
    observation: ObservationFrontier
    derived: DerivedFrontier
    terminal: TerminalRef
    terminal_source_frontier_hash: str
    dependency_closure: DependencyClosure
    object_commitments: tuple[str, ...]
    checkpoint_hash: str
    evidence_policy_hash: str
    material_inventory: Mapping[str, object]
    core_hash: str

    @classmethod
    def build(
        cls,
        *,
        package_id: str,
        run_id: str,
        generation: int,
        predecessor_core_hash: str | None,
        observation: ObservationFrontier,
        derived: DerivedFrontier,
        terminal: TerminalRef,
        terminal_source_frontier_hash: str,
        dependency_closure: DependencyClosure,
        object_commitments: tuple[str, ...],
        checkpoint_hash: str,
        evidence_policy_hash: str,
        material_inventory: Mapping[str, object],
    ) -> "EvidencePackageCore":
        validate_identifier(package_id, field="package_id")
        validate_identifier(run_id, field="run_id")
        if generation < 1 or (generation == 1) != (predecessor_core_hash is None):
            raise EvidencePackageError("generation/predecessor relationship is invalid")
        if tuple(sorted(set(object_commitments))) != object_commitments:
            raise EvidencePackageError("object commitments must be unique and sorted")
        provisional = cls(
            package_id, run_id, generation, predecessor_core_hash, observation, derived, terminal,
            terminal_source_frontier_hash, dependency_closure, object_commitments,
            checkpoint_hash, evidence_policy_hash, dict(material_inventory), "",
        )
        return replace(provisional, core_hash=domain_hash("EVIDENCE_PACKAGE_CORE", canonical_json_bytes(provisional.core_mapping())))

    def core_mapping(self) -> dict[str, object]:
        return {
            "schema": "EVIDENCE_PACKAGE_CORE_V1",
            "package_id": self.package_id,
            "run_id": self.run_id,
            "generation": self.generation,
            "predecessor_core_hash": self.predecessor_core_hash,
            "observation_frontier_hash": self.observation.frontier_hash,
            "derived_frontier_hash": self.derived.frontier_hash,
            "terminal": self.terminal.core_mapping(),
            "terminal_source_frontier_hash": self.terminal_source_frontier_hash,
            "dependency_closure": self.dependency_closure.mapping(),
            "object_commitments": list(self.object_commitments),
            "checkpoint_hash": self.checkpoint_hash,
            "evidence_policy_hash": self.evidence_policy_hash,
            "material_inventory": dict(self.material_inventory),
        }


@dataclass(frozen=True)
class EvidencePackageStream:
    package_id: str
    generations: tuple[EvidencePackageCore, ...] = ()
    accepted_assessments: Mapping[int, str] = None  # type: ignore[assignment]
    stream_version: int = 0

    def __post_init__(self) -> None:
        validate_identifier(self.package_id, field="package_id")
        if self.accepted_assessments is None:
            object.__setattr__(self, "accepted_assessments", {})

    def admit_generation(self, core: EvidencePackageCore, *, expected_generation: int) -> tuple["EvidencePackageStream", dict[str, object]]:
        if expected_generation != len(self.generations) or core.generation != len(self.generations) + 1:
            raise EvidencePackageError("generation CAS conflict")
        if core.package_id != self.package_id:
            raise EvidencePackageError("package identity changed")
        predecessor = self.generations[-1].core_hash if self.generations else None
        if core.predecessor_core_hash != predecessor:
            raise EvidencePackageError("generation predecessor does not match accepted head")
        event = {
            "schema": "EVIDENCE_PACKAGE_GENERATION_ADMITTED_V1",
            "package_id": self.package_id,
            "generation": core.generation,
            "core_hash": core.core_hash,
            "predecessor_core_hash": predecessor,
        }
        return replace(self, generations=(*self.generations, core), stream_version=self.stream_version + 1), event

    def accept_assessment(self, *, generation: int, assessment_hash: str, expected_stream_version: int) -> tuple["EvidencePackageStream", dict[str, object]]:
        if expected_stream_version != self.stream_version:
            raise EvidencePackageError("assessment stream CAS conflict")
        if not 1 <= generation <= len(self.generations) or generation in self.accepted_assessments:
            raise EvidencePackageError("assessment generation is not eligible")
        accepted = dict(self.accepted_assessments)
        accepted[generation] = assessment_hash
        event = {
            "schema": "EVIDENCE_ASSESSMENT_ACCEPTED_V1",
            "package_id": self.package_id,
            "generation": generation,
            "assessment_hash": assessment_hash,
        }
        return replace(self, accepted_assessments=accepted, stream_version=self.stream_version + 1), event
