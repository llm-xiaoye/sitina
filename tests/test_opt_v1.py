from __future__ import annotations

import unittest

from sitina.evidence.checkpoint import PreTerminalCheckpoint
from sitina.evidence.frontier import (
    CoherentCutError,
    CoherentCutProof,
    DerivedFrontier,
    FrontierComponent,
    ObservationFrontier,
    SignedFrontierVectorV1,
    TerminalRef,
)
from sitina.security.key_provider import InMemoryKeyProvider


def vector(position: int, commitment: str | None = None) -> SignedFrontierVectorV1:
    provider = InMemoryKeyProvider()
    component = FrontierComponent.sign(
        provider,
        journal_id="journal-1",
        epoch=1,
        shard="local",
        position=position,
        commitment=commitment or (f"{position:064x}"),
    )
    return SignedFrontierVectorV1.from_components((component,))


class OPTV1Tests(unittest.TestCase):
    def test_v1_rejects_zero_or_multiple_components(self) -> None:
        one = vector(1).component
        with self.assertRaises(ValueError): SignedFrontierVectorV1.from_components(())
        with self.assertRaises(ValueError): SignedFrontierVectorV1.from_components((one, one))

    def test_component_binds_journal_epoch_shard_position_commitment_and_signature(self) -> None:
        provider = InMemoryKeyProvider()
        component = FrontierComponent.sign(provider, journal_id="journal-1", epoch=1, shard="local", position=7, commitment="a" * 64)
        self.assertTrue(component.verify(provider))
        self.assertFalse(component.with_updates(position=8).verify(provider))
        self.assertEqual(SignedFrontierVectorV1.from_components((component,)).profile, "BPLUS_OPT_V1_SINGLE_JOURNAL")

    def test_every_observation_at_or_before_o_is_dispositioned_by_p(self) -> None:
        o = ObservationFrontier(vector(5))
        p = DerivedFrontier(vector(8))
        proof = CoherentCutProof.build(o, p, admitted_observations={"obs-1": 3, "obs-2": 5}, dispositions={"obs-1": 6, "obs-2": 8}, dependency_refs=("a" * 64,))
        self.assertEqual(len(proof.proof_hash), 64)
        with self.assertRaises(CoherentCutError):
            CoherentCutProof.build(o, p, admitted_observations={"obs-1": 5}, dispositions={}, dependency_refs=("a" * 64,))

    def test_checkpoint_and_terminal_bind_all_required_manifests(self) -> None:
        checkpoint = PreTerminalCheckpoint.build(
            run_id="run-1", task_graph={"version": 3}, blackboard={"version": 2}, protocols={"open": 0}, obligations={"required_open": 0}, effects={"exposure": 0}, eligibility={"blockers": 0}, object_manifest={"refs": ["cas:a"]}
        )
        o = ObservationFrontier(vector(5)); p = DerivedFrontier(vector(8))
        proof = CoherentCutProof.build(o, p, admitted_observations={}, dispositions={}, dependency_refs=("a" * 64,))
        terminal = TerminalRef.build(
            vector(9), event_id="terminal-event-1", event_hash="b" * 64, observation=o, derived=p,
            coherent_cut_proof_hash=proof.proof_hash, checkpoint_hash=checkpoint.checkpoint_hash,
            eligibility_manifest_hash=checkpoint.section_hashes["eligibility"], outcome_refs=("c" * 64,),
        )
        self.assertEqual(terminal.vector.component.position, 9)
        self.assertEqual(terminal.checkpoint_hash, checkpoint.checkpoint_hash)


if __name__ == "__main__": unittest.main()
