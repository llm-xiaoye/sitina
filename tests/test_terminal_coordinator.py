from __future__ import annotations

import unittest

from sitina.evidence.checkpoint import PreTerminalCheckpoint
from sitina.evidence.frontier import CoherentCutProof, DerivedFrontier, ObservationFrontier, TerminalRef
from sitina.evidence.terminal import EVIDENCE_BLOCKER_KINDS, TerminalBarrierSnapshot, TerminalCoordinator, TerminalCoordinatorError
from tests.test_opt_v1 import vector


def barrier(**changes: object) -> TerminalBarrierSnapshot:
    o = ObservationFrontier(vector(5)); p = DerivedFrontier(vector(8))
    proof = CoherentCutProof.build(o, p, admitted_observations={}, dispositions={}, dependency_refs=("a" * 64,))
    checkpoint = PreTerminalCheckpoint.build(run_id="run-1", task_graph={}, blackboard={}, protocols={}, obligations={}, effects={}, eligibility={}, object_manifest={})
    values = {
        "blocker_refs": {kind: () for kind in EVIDENCE_BLOCKER_KINDS}, "observation": o, "derived": p,
        "coherent_cut_proof_hash": proof.proof_hash, "checkpoint": checkpoint,
        "eligibility_manifest_hash": "b" * 64, "cancellation_ref": None,
        "failure_refs": (), "required_obligations_complete_ref": "c" * 64,
    }
    values.update(changes)
    return TerminalBarrierSnapshot(**values)


class TerminalCoordinatorTests(unittest.TestCase):
    def test_every_declared_blocker_prevents_p_and_terminal(self) -> None:
        for kind in EVIDENCE_BLOCKER_KINDS:
            with self.subTest(kind=kind):
                blockers = {item: () for item in EVIDENCE_BLOCKER_KINDS}; blockers[kind] = ("d" * 64,)
                coordinator = TerminalCoordinator("run-1").begin_closing()
                with self.assertRaises(TerminalCoordinatorError): coordinator.freeze_derived(barrier(blocker_refs=blockers))

    def test_mutation_after_p_is_rejected_except_evidence_recording(self) -> None:
        coordinator = TerminalCoordinator("run-1").begin_closing().freeze_derived(barrier())
        with self.assertRaises(TerminalCoordinatorError): coordinator.authorize_post_p_mutation("TASK_RESULT")
        coordinator.authorize_post_p_mutation("EVIDENCE_RECORD")

    def test_duplicate_terminal_command_returns_original_and_conflict_fails(self) -> None:
        coordinator = TerminalCoordinator("run-1").begin_closing().freeze_derived(barrier())
        coordinator, first = coordinator.commit_terminal(command_id="terminal-command-1", barrier=barrier())
        coordinator, duplicate = coordinator.commit_terminal(command_id="terminal-command-1", barrier=barrier())
        self.assertEqual(first, duplicate)
        with self.assertRaises(TerminalCoordinatorError): coordinator.commit_terminal(command_id="terminal-command-1", barrier=barrier(failure_refs=("e" * 64,), required_obligations_complete_ref=None))

    def test_outcome_priority_is_cancel_then_failure_then_success(self) -> None:
        cases = [
            (barrier(cancellation_ref="d" * 64, failure_refs=("e" * 64,)), "CANCELLED"),
            (barrier(failure_refs=("e" * 64,), required_obligations_complete_ref=None), "FAILED"),
            (barrier(), "SUCCEEDED"),
        ]
        for snapshot, expected in cases:
            coordinator = TerminalCoordinator("run-1").begin_closing().freeze_derived(snapshot)
            _, terminal = coordinator.commit_terminal(command_id=f"terminal-{expected.lower()}", barrier=snapshot)
            self.assertEqual(terminal.outcome, expected)


if __name__ == "__main__": unittest.main()
