from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import EventEnvelope
from sitina.projections.production import apply_production_event
from sitina.projections.schema import open_projection


class NegotiationProjectionTests(unittest.TestCase):
    def event(self, position: int, schema: str, payload: dict, *, run_id: str = "run-negotiation") -> EventEnvelope:
        return EventEnvelope(
            f"event-negotiation-{position}", schema.lower(), "tenant-1", "protocol/run-negotiation/proposal-1",
            position, position, "2026-07-16T00:00:00Z",
            {"schema": schema, "run_id": run_id, **payload},
        )

    def test_rebuild_materializes_rework_round_two_fresh_review_synthesis_and_selection(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        events = (
            self.event(1, "PROPOSAL_ROUND_OPENED_V1", {
                "round_id": "round-1", "generation": 1, "rubric_hash": "11" * 32,
                "policy_hash": "12" * 32, "config_hash": "13" * 32,
                "minimum_score": 70, "max_revisions": 2,
            }),
            self.event(2, "PROPOSAL_SUBMITTED_V1", {
                "round_id": "round-1", "generation": 1, "proposal_id": "proposal-1",
                "revision": 1, "participant_id": "agent-author", "body_ref": "21" * 32,
                "output_hash": "22" * 32, "input_snapshot_hash": "23" * 32,
            }),
            self.event(3, "PROPOSAL_EVALUATED_V1", {
                "round_id": "round-1", "generation": 1, "proposal_id": "proposal-1", "revision": 1,
                "evaluator_id": "agent-reviewer", "score": 55, "disposition": "NEEDS_REVISION",
            }),
            self.event(4, "REWORK_OPENED_V1", {
                "rework_id": "rework-1", "task_id": "proposal-revision-1", "failure_type": "REVIEW_REJECTED",
                "acceptance_criteria_hash": "31" * 32, "max_retries": 2,
            }),
            self.event(5, "REWORK_ROUND_STARTED_V1", {
                "rework_id": "rework-1", "round": 1, "attempt_id": "revision-attempt-1",
            }),
            self.event(6, "PROPOSAL_REVISED_V1", {
                "round_id": "round-1", "generation": 1, "proposal_id": "proposal-1", "revision": 2,
                "body_ref": "24" * 32, "parent_output_hash": "22" * 32,
                "new_output_hash": "25" * 32, "rework_id": "rework-1",
                "defect_resolution_hash": "32" * 32, "all_defects_addressed": True,
                "old_review_reused": False,
            }),
            self.event(7, "REWORK_SATISFIED_V1", {
                "rework_id": "rework-1", "round": 1, "result_ref": "24" * 32,
            }),
            self.event(8, "DEBATE_OPENED_V1", {
                "debate_id": "debate-1", "target_id": "round-1", "max_rounds": 2, "max_tokens": 1000,
            }),
            self.event(9, "DEBATE_RESPONSE_RECORDED_V1", {
                "debate_id": "debate-1", "response_id": "response-1", "claim_id": "claim-1",
                "target_claim_id": "claim-2", "actor_id": "agent-author", "round_number": 2,
                "token_count": 50, "body_ref": "41" * 32, "parent_output_hash": "25" * 32,
                "revision_output_hash": "42" * 32, "revision_call_id": "call-revision-2",
            }),
            self.event(10, "DEBATE_SYNTHESIS_SUBMITTED_V1", {
                "debate_id": "debate-1", "synthesis_candidate_hash": "43" * 32,
            }),
            self.event(11, "PROPOSAL_ROUND_GENERATION_OPENED_V1", {
                "round_id": "round-1", "generation": 2, "rubric_hash": "11" * 32,
                "policy_hash": "12" * 32, "config_hash": "14" * 32,
                "minimum_score": 70, "max_revisions": 2,
            }),
            self.event(12, "PROPOSAL_SUBMITTED_V1", {
                "round_id": "round-1", "generation": 2, "proposal_id": "proposal-1",
                "revision": 1, "participant_id": "agent-author", "body_ref": "44" * 32,
                "parent_output_hash": "25" * 32, "revision_output_hash": "42" * 32,
                "old_review_reused": False,
            }),
            self.event(13, "NEGOTIATION_FRESH_REVIEW_REQUESTED_V1", {
                "review_id": "fresh-review-1", "artifact_hash": "44" * 32,
                "artifact_author_id": "agent-author", "rubric_hash": "11" * 32,
                "reviewer_id": "agent-fresh-reviewer", "round_id": "round-1", "generation": 2,
            }),
            self.event(14, "NEGOTIATION_FRESH_REVIEW_SUBMITTED_V1", {
                "review_id": "fresh-review-1", "reviewer_id": "agent-fresh-reviewer",
                "effective_verdict": "approved", "response_ref": "45" * 32,
                "response_commitment": "46" * 32,
            }),
            self.event(15, "NEGOTIATION_FRESH_REVIEW_DISPOSITION_V1", {
                "review_id": "fresh-review-1", "disposition": "ACCEPT", "artifact_accepted": False,
            }),
            self.event(16, "PROPOSAL_EVALUATED_V1", {
                "round_id": "round-1", "generation": 2, "proposal_id": "proposal-1", "revision": 1,
                "evaluator_id": "agent-fresh-reviewer", "score": 90, "disposition": "ACCEPT",
            }),
            self.event(17, "DEBATE_SYNTHESIS_FINALIZED_V1", {
                "debate_id": "debate-1", "outcome": "CONSENSUS", "synthesis_hash": "47" * 32,
                "successor_obligation_id": None,
            }),
            self.event(18, "NEGOTIATION_SELECTION_DECIDED_V1", {
                "decision_id": "decision-select-1", "round_id": "round-1", "generation": 2,
                "decision": "SELECTED", "selected_proposal_id": "proposal-1",
                "latest_revision_hash": "42" * 32, "synthesis_candidate_hash": "43" * 32,
                "synthesis_hash": "47" * 32, "fresh_review_ids": ["fresh-review-1"],
                "fresh_review_hashes": ["48" * 32],
            }),
            self.event(19, "PROPOSAL_SELECTED_V1", {
                "round_id": "round-1", "generation": 2, "proposal_id": "proposal-1",
                "selected_output_hash": "42" * 32,
            }),
        )
        try:
            for event in events:
                apply_production_event(connection, event)
            self.assertEqual(
                connection.execute(
                    "SELECT current_generation,round_state,selected_proposal_id,selected_output_hash FROM proposal_rounds"
                ).fetchone(),
                (2, "SELECTED", "proposal-1", "42" * 32),
            )
            revisions = connection.execute(
                """SELECT generation,revision,parent_output_hash,output_hash,old_review_reused,score,disposition
                   FROM proposal_revisions ORDER BY generation,revision"""
            ).fetchall()
            self.assertEqual(revisions[-1], (2, 1, "25" * 32, "42" * 32, 0, 90, "ACCEPT"))
            self.assertEqual(
                connection.execute(
                    "SELECT rework_state,retry_count,current_result_ref FROM rework_runtime"
                ).fetchone(),
                ("SATISFIED", 1, "24" * 32),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT defect_resolution_hash,all_defects_addressed,round_state FROM rework_rounds"
                ).fetchone(),
                ("32" * 32, 1, "SATISFIED"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT debate_state,outcome,synthesis_hash FROM debate_runtime"
                ).fetchone(),
                ("TERMINAL", "CONSENSUS", "47" * 32),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT reviewer_id,verdict,disposition FROM review_runtime"
                ).fetchone(),
                ("agent-fresh-reviewer", "approved", "ACCEPT"),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT decision,selected_proposal_id,synthesis_hash,successor_obligation_id FROM negotiation_decisions"
                ).fetchone(),
                ("SELECTED", "proposal-1", "47" * 32, None),
            )
        finally:
            connection.close()

    def test_no_consensus_decision_retains_successor_obligation(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        event = self.event(1, "NEGOTIATION_NO_CONSENSUS_DECIDED_V1", {
            "decision_id": "decision-no-consensus-1", "round_id": "round-2", "generation": 2,
            "decision": "NO_CONSENSUS", "latest_revision_hashes": ["51" * 32, "52" * 32],
            "synthesis_candidate_hash": "53" * 32, "synthesis_hash": "54" * 32,
            "fresh_review_ids": ["fresh-review-a", "fresh-review-b"],
            "fresh_review_hashes": ["55" * 32, "56" * 32],
            "successor_obligation_id": "obligation-negotiation-successor",
        }, run_id="run-no-consensus")
        try:
            apply_production_event(connection, event)
            self.assertEqual(
                connection.execute(
                    "SELECT decision,successor_obligation_id FROM negotiation_decisions"
                ).fetchone(),
                ("NO_CONSENSUS", "obligation-negotiation-successor"),
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
