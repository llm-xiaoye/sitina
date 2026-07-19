from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import EventEnvelope
from sitina.projections.production import apply_production_event
from sitina.projections.schema import open_projection


class HandoffProjectionTests(unittest.TestCase):
    def event(self, position: int, schema: str, payload: dict) -> EventEnvelope:
        return EventEnvelope(
            f"event-handoff-{position}", schema.lower(), "tenant-1", "protocol/run-handoff/handoff-1",
            position, position, "2026-07-16T00:00:00Z",
            {"schema": schema, "run_id": "run-handoff", **payload},
        )

    def contract(self, generation: int, contract_hash: str, **changes: object) -> dict:
        value = {
            "handoff_id": "handoff-1",
            "generation": generation,
            "sender_id": "agent-sender",
            "receiver_id": "agent-receiver",
            "task_id": "task-handoff",
            "contract_hash": contract_hash,
            "contract_object_ref": "cas:" + contract_hash,
            "input_freeze_hash": ("31" if generation == 1 else "32") * 32,
            "output_schema_hash": "33" * 32,
            "max_generations": 3,
            "task_claim_ref": "34" * 32,
            "fencing_token": "35" * 32,
        }
        value.update(changes)
        return value

    def test_rebuild_materializes_rejected_generation_lineage_claim_execution_and_verification(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        first_hash = "11" * 32
        second_hash = "12" * 32
        generation_1_hash = "21" * 32
        generation_2_hash = "22" * 32
        events = (
            self.event(1, "HANDOFF_CONTRACT_FROZEN_V1", self.contract(1, first_hash)),
            self.event(2, "HANDOFF_OFFERED_V1", {
                "handoff_id": "handoff-1", "generation": 1, "generation_hash": generation_1_hash,
                "capability_hash": "23" * 32,
            }),
            self.event(3, "HANDOFF_REJECTED_V1", {
                "handoff_id": "handoff-1", "generation": 1, "generation_hash": generation_1_hash,
                "reason": "missing exact checks", "generation_permanently_closed": True,
            }),
            self.event(4, "HANDOFF_REJECTED_GENERATION_CLOSED_V1", {
                "handoff_id": "handoff-1", "closed_generation": 1,
                "generation_hash": generation_1_hash, "old_generation_reusable": False,
            }),
            self.event(5, "HANDOFF_CONTRACT_FROZEN_V1", self.contract(
                2, second_hash, previous_generation_hash=generation_1_hash,
                previous_generation_ref="cas:" + first_hash,
                previous_rejection_event_ref="event-handoff-3",
            )),
            self.event(6, "HANDOFF_RECEIVER_CAPABILITY_REVALIDATED_V1", {
                "handoff_id": "handoff-1", "generation": 2, "receiver_id": "agent-receiver",
                "capability_hash": "24" * 32, "result": "PASSED",
            }),
            self.event(7, "HANDOFF_GENERATION_OPENED_V2", {
                "handoff_id": "handoff-1", "generation": 2, "generation_hash": generation_2_hash,
                "capability_hash": "24" * 32, "prior_generation": 1,
                "prior_generation_hash": generation_1_hash, "prior_terminal_state": "REJECTED",
                "previous_generation_permanently_closed": True, "old_acceptance_reused": False,
                "reject_reason_resolution_hash": "25" * 32,
            }),
            self.event(8, "HANDOFF_ACCEPTED_V1", {
                "handoff_id": "handoff-1", "generation": 2, "receiver_id": "agent-receiver",
            }),
            self.event(9, "HANDOFF_CLAIM_PENDING_V1", {
                "handoff_id": "handoff-1", "generation": 2, "receiver_id": "agent-receiver",
                "task_claim_ref": "34" * 32, "reserved_fencing_token": "35" * 32,
            }),
            self.event(10, "HANDOFF_TASK_CLAIM_BOUND_V1", {
                "handoff_id": "handoff-1", "generation": 2, "task_attempt_id": "attempt-2",
                "claim_generation": 1, "lease_id": "lease-2", "fencing_token": "35" * 32,
            }),
            self.event(11, "HANDOFF_EXECUTION_STARTED_V1", {
                "handoff_id": "handoff-1", "generation": 2,
            }),
            self.event(12, "HANDOFF_RESULT_SUBMITTED_V1", {
                "handoff_id": "handoff-1", "generation": 2, "artifact_hash": "41" * 32,
                "schema_validation_evidence_hash": "42" * 32,
            }),
            self.event(13, "HANDOFF_VERIFIED_V1", {
                "handoff_id": "handoff-1", "generation": 2, "artifact_hash": "41" * 32,
                "verifier_id": "agent-verifier", "verification_evidence_hash": "43" * 32,
            }),
        )
        try:
            for event in events:
                apply_production_event(connection, event)
            runtime = connection.execute(
                """SELECT current_generation,handoff_state,receiver_id,current_task_attempt_id,
                          current_fencing_token,current_artifact_hash,verifier_id
                   FROM handoff_runtime WHERE run_id='run-handoff' AND handoff_id='handoff-1'"""
            ).fetchone()
            self.assertEqual(runtime, (
                2, "VERIFIED", "agent-receiver", "attempt-2", "35" * 32,
                "41" * 32, "agent-verifier",
            ))
            generations = connection.execute(
                """SELECT generation,generation_state,contract_hash,input_freeze_hash,accepted_by,
                          task_attempt_id,lease_id,artifact_hash,verifier_id
                   FROM handoff_generations WHERE run_id='run-handoff' ORDER BY generation"""
            ).fetchall()
            self.assertEqual(generations, [
                (1, "REJECTED", first_hash, "31" * 32, None, None, None, None, None),
                (2, "VERIFIED", second_hash, "32" * 32, "agent-receiver", "attempt-2", "lease-2", "41" * 32, "agent-verifier"),
            ])
            lineage = connection.execute(
                """SELECT generation,prior_generation,prior_generation_hash,prior_terminal_state,
                          previous_generation_permanently_closed,old_acceptance_reused
                   FROM handoff_generation_lineage WHERE run_id='run-handoff'"""
            ).fetchone()
            self.assertEqual(lineage, (2, 1, generation_1_hash, "REJECTED", 1, 0))
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
