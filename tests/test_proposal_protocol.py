from __future__ import annotations

import unittest

from sitina.protocols.proposals import ProposalError, ProposalRound, ProposalRoundState, ProposalState


class ProposalProtocolTests(unittest.TestCase):
    def round(self) -> ProposalRound:
        return ProposalRound.open(
            "round-1",
            generation=1,
            participants=("agent-a", "agent-b"),
            evaluators=("reviewer-1",),
            rubric_hash="11" * 32,
            policy_hash="22" * 32,
            deadline="2099-01-01T00:00:00Z",
            minimum_score=70,
            max_revisions=2,
        )[0]

    def test_selection_is_single_stream_cas_and_rejects_ineligible_proposals(self) -> None:
        round_ = self.round()
        round_, proposal, _ = round_.submit("proposal-1", "agent-a", "33" * 32)
        round_, _ = round_.evaluate("proposal-1", "reviewer-1", score=90, disposition="ACCEPT")
        selected, _ = round_.select("proposal-1", expected_version=round_.version)
        self.assertEqual(selected.state, ProposalRoundState.SELECTED)
        with self.assertRaises(ProposalError):
            selected.select("proposal-1", expected_version=selected.version)
        rejected = self.round()
        rejected, _, _ = rejected.submit("proposal-2", "agent-b", "44" * 32)
        rejected, _ = rejected.evaluate("proposal-2", "reviewer-1", score=90, disposition="REJECT")
        self.assertEqual(rejected.proposals[0].state, ProposalState.REJECTED)
        with self.assertRaises(ProposalError):
            rejected.select("proposal-2", expected_version=rejected.version)

    def test_needs_revision_requires_revision_within_bound(self) -> None:
        round_ = self.round()
        round_, _, _ = round_.submit("proposal-1", "agent-a", "33" * 32)
        round_, _ = round_.evaluate("proposal-1", "reviewer-1", score=50, disposition="NEEDS_REVISION")
        with self.assertRaises(ProposalError):
            round_.select("proposal-1", expected_version=round_.version)
        round_, revised, _ = round_.revise("proposal-1", "44" * 32)
        self.assertEqual(revised.revision, 2)
        self.assertEqual(revised.state, ProposalState.ACTIVE)

    def test_frozen_config_change_requires_new_generation(self) -> None:
        round_ = self.round()
        with self.assertRaises(ProposalError):
            round_.change_config(participants=("agent-a",), rubric_hash="55" * 32)
        next_round, event = round_.new_generation(
            participants=("agent-a",),
            evaluators=("reviewer-1",),
            rubric_hash="55" * 32,
            policy_hash="22" * 32,
            deadline="2099-02-01T00:00:00Z",
            minimum_score=80,
            max_revisions=1,
        )
        self.assertEqual(next_round.generation, 2)
        self.assertNotEqual(next_round.config_hash, round_.config_hash)
        self.assertEqual(event["schema"], "PROPOSAL_ROUND_GENERATION_OPENED_V1")

    def test_no_selection_next_action_is_whitelisted(self) -> None:
        round_ = self.round()
        for action in ("NEW_GENERATION", "ARBITRATION", "REWORK", "CANCEL"):
            terminal, event = round_.no_selection(action, expected_version=round_.version)
            self.assertEqual(terminal.state, ProposalRoundState.NO_SELECTION)
            self.assertEqual(event["next_action"], action)
        with self.assertRaises(ProposalError):
            round_.no_selection("SILENT_MAJORITY", expected_version=round_.version)


if __name__ == "__main__":
    unittest.main()
