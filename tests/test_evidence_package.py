from __future__ import annotations

import unittest

from sitina.evidence.package import DependencyClosure, EvidencePackageCore, EvidencePackageError, EvidencePackageStream
from tests.test_opt_v1 import vector
from sitina.evidence.frontier import DerivedFrontier, ObservationFrontier, TerminalRef


def core(generation: int = 1, predecessor: str | None = None, inventory: dict | None = None) -> EvidencePackageCore:
    o = ObservationFrontier(vector(5)); p = DerivedFrontier(vector(8))
    terminal = TerminalRef.build(vector(9), event_id="terminal-event-1", event_hash="a" * 64, observation=o, derived=p, coherent_cut_proof_hash="b" * 64, checkpoint_hash="c" * 64, eligibility_manifest_hash="d" * 64, outcome_refs=("e" * 64,))
    closure = DependencyClosure.build(roots=("run-1",), edges={"run-1": ("effect-1",), "effect-1": ("object-1",), "object-1": ()})
    return EvidencePackageCore.build(package_id="package-1", run_id="run-1", generation=generation, predecessor_core_hash=predecessor, observation=o, derived=p, terminal=terminal, terminal_source_frontier_hash="f" * 64, dependency_closure=closure, object_commitments=("1" * 64,), checkpoint_hash="c" * 64, evidence_policy_hash="2" * 64, material_inventory=inventory or {"events": 10, "objects": 1})


class EvidencePackageTests(unittest.TestCase):
    def test_core_hash_excludes_assessment_seal_artifact_and_self_hash(self) -> None:
        value = core()
        mapping = value.core_mapping()
        self.assertNotIn("assessment", mapping)
        self.assertNotIn("seal", mapping)
        self.assertNotIn("artifact", mapping)
        self.assertNotIn("core_hash", mapping)
        self.assertEqual(len(value.core_hash), 64)

    def test_remediation_is_new_generation_and_old_core_is_immutable(self) -> None:
        stream = EvidencePackageStream("package-1")
        first = core(); stream, _ = stream.admit_generation(first, expected_generation=0)
        second = core(2, first.core_hash, {"events": 11, "objects": 1})
        stream, _ = stream.admit_generation(second, expected_generation=1)
        self.assertEqual(stream.generations[0], first)
        self.assertNotEqual(first.core_hash, second.core_hash)
        with self.assertRaises(EvidencePackageError): stream.admit_generation(core(2, "0" * 64), expected_generation=2)

    def test_dependency_closure_hashes_roots_edges_and_visited_set(self) -> None:
        closure = core().dependency_closure
        self.assertEqual(closure.visited_identities, ("effect-1", "object-1", "run-1"))
        self.assertEqual(len({closure.root_set_hash, closure.edge_set_hash, closure.visited_set_hash}), 3)

    def test_stream_events_not_files_own_generation_and_accepted_assessment(self) -> None:
        stream = EvidencePackageStream("package-1")
        stream, event = stream.admit_generation(core(), expected_generation=0)
        self.assertEqual(event["schema"], "EVIDENCE_PACKAGE_GENERATION_ADMITTED_V1")
        stream, accepted = stream.accept_assessment(generation=1, assessment_hash="a" * 64, expected_stream_version=1)
        self.assertEqual(accepted["schema"], "EVIDENCE_ASSESSMENT_ACCEPTED_V1")
        self.assertEqual(stream.accepted_assessments[1], "a" * 64)


if __name__ == "__main__": unittest.main()
