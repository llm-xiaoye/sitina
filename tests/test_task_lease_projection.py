from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import EventEnvelope
from sitina.projections.production import apply_production_event
from sitina.projections.schema import open_projection


class TaskLeaseProjectionTests(unittest.TestCase):
    def event(self, position: int, schema: str, payload: dict) -> EventEnvelope:
        return EventEnvelope(
            f"event-task-lease-{position}", schema.lower(), "tenant-1", "task/task-lease",
            position, position, "2026-07-16T00:00:00Z",
            {"schema": schema, "run_id": "run-lease", **payload},
        )

    def test_rebuild_materializes_competition_expiry_reassignment_acceptance_and_stale_rejection(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        task_id = "task-lease"
        try:
            events = (
                self.event(1, "TASK_CREATED_V1", {"task_id": task_id, "specification_hash": "10" * 32}),
                self.event(2, "TASK_CLAIMED_V1", {
                    "task_id": task_id, "task_attempt_id": "attempt-a", "holder_agent_id": "agent-a",
                    "claim_generation": 1, "lease_id": "lease-a", "expires_at": "2026-07-16T00:01:00Z",
                    "fencing_token": "11" * 32, "state": "CLAIMED", "committed_stream_version": 2,
                }),
                self.event(3, "TASK_CLAIM_REJECTED_V1", {
                    "rejection_id": "rejection-b", "task_id": task_id, "rejected_holder_agent_id": "agent-b",
                    "reason_code": "TASK_STREAM_VERSION_CONFLICT", "expected_stream_version": 1,
                    "actual_stream_version": 2,
                }),
                self.event(4, "TASK_LEASE_RENEWED_V1", {
                    "task_id": task_id, "task_attempt_id": "attempt-a", "expires_at": "2026-07-16T00:02:00Z",
                    "committed_stream_version": 3,
                }),
                self.event(5, "TASK_LEASE_EXPIRED_V1", {
                    "task_id": task_id, "task_attempt_id": "attempt-a", "committed_stream_version": 4,
                }),
                self.event(6, "TASK_CLAIMED_V1", {
                    "task_id": task_id, "task_attempt_id": "attempt-b", "holder_agent_id": "agent-b",
                    "claim_generation": 2, "lease_id": "lease-b", "expires_at": "2026-07-16T00:03:00Z",
                    "fencing_token": "22" * 32, "state": "CLAIMED", "committed_stream_version": 5,
                }),
                self.event(7, "TASK_RESULT_SUBMITTED_V1", {
                    "task_id": task_id, "task_attempt_id": "attempt-b", "artifact_hash": "33" * 32,
                    "committed_stream_version": 6,
                }),
                self.event(8, "TASK_RESULT_ACCEPTED_V1", {
                    "task_id": task_id, "task_attempt_id": "attempt-b", "artifact_hash": "33" * 32,
                    "accepted_by": "acceptance-verifier", "committed_stream_version": 7,
                }),
                self.event(9, "TASK_STALE_FENCE_REJECTED_V1", {
                    "rejection_id": "stale-a", "task_id": task_id, "stale_attempt_id": "attempt-a",
                    "current_attempt_id": "attempt-b", "artifact_hash": "44" * 32,
                    "business_state_committed": False,
                }),
            )
            for event in events:
                apply_production_event(connection, event)
            runtime = connection.execute(
                """SELECT task_state,stream_version,active_attempt_id,claim_generation,accepted_artifact_hash
                   FROM task_runtime WHERE run_id='run-lease' AND task_id=?""",
                (task_id,),
            ).fetchone()
            self.assertEqual(runtime, ("COMPLETED", 7, None, 2, "33" * 32))
            attempts = connection.execute(
                """SELECT task_attempt_id,holder_agent_id,claim_generation,lease_id,attempt_state,
                          submitted_artifact_hash,accepted_by
                   FROM task_attempts WHERE run_id='run-lease' AND task_id=? ORDER BY claim_generation""",
                (task_id,),
            ).fetchall()
            self.assertEqual(attempts, [
                ("attempt-a", "agent-a", 1, "lease-a", "EXPIRED", None, None),
                ("attempt-b", "agent-b", 2, "lease-b", "ACCEPTED", "33" * 32, "acceptance-verifier"),
            ])
            self.assertEqual(connection.execute("SELECT count(*) FROM task_claim_rejections").fetchone()[0], 1)
            stale = connection.execute(
                "SELECT stale_attempt_id,current_attempt_id,artifact_hash,business_state_committed FROM task_stale_fence_rejections"
            ).fetchone()
            self.assertEqual(stale, ("attempt-a", "attempt-b", "44" * 32, 0))
        finally:
            connection.close()

    def test_rebuild_accepts_historical_multi_holder_claim_without_lease_id(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        try:
            apply_production_event(connection, self.event(1, "TASK_CLAIMED_V1", {
                "task_id": "legacy-blackboard-task",
                "task_attempt_id": "legacy-attempt-1",
                "holder_agent_ids": ["agent-gavel", "agent-forge"],
                "claim_generation": 1,
                "lease_expires_at": "2099-01-01T00:00:00Z",
                "fencing_token": "55" * 32,
                "fact_hash": "66" * 32,
                "state": "CLAIMED",
            }))
            attempt = connection.execute(
                """SELECT holder_agent_id,lease_id,expires_at,attempt_state
                   FROM task_attempts WHERE run_id='run-lease' AND task_id='legacy-blackboard-task'"""
            ).fetchone()
            self.assertEqual(attempt, (
                "legacy-multi-holder[agent-forge,agent-gavel]",
                "legacy-lease-" + ("66" * 20),
                "2099-01-01T00:00:00Z",
                "CLAIMED",
            ))
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
