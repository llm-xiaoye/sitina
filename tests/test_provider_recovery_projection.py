from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.journal.model import EventEnvelope
from sitina.projections.production import apply_production_event
from sitina.projections.schema import open_projection


class ProviderRecoveryProjectionTests(unittest.TestCase):
    def event(self, position: int, schema: str, payload: dict) -> EventEnvelope:
        return EventEnvelope(
            f"event-provider-recovery-{position}", schema.lower(), "tenant-1", "effect/run-provider/effect-1",
            position, position, "2026-07-16T00:00:00Z",
            {"schema": schema, "run_id": "run-provider", **payload},
        )

    def test_rebuild_materializes_all_four_paths_and_reassignment_summary(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        connection = open_projection(root / "projection.sqlite")
        try:
            events = (
                self.event(1, "CONTROLLED_PROVIDER_WORKER_LOSS_V1", {
                    "effect_id": "effect-pre", "effect_attempt_id": "attempt-pre", "agent_id": "agent-a",
                    "task_attempt_id": "task-attempt-a", "idempotency_identity": "idempotency-pre",
                    "invocation_started": False, "physical_send_count": 0,
                    "outcome_state": "CANCELLED_BEFORE_SEND", "settlement_state": "SETTLED",
                    "unresolved_transmission_exposure_count": 0, "usage_settled": True,
                }),
                self.event(2, "CONTROLLED_PROVIDER_WORKER_LOSS_V1", {
                    "effect_id": "effect-timeout", "effect_attempt_id": "attempt-timeout", "agent_id": "agent-a",
                    "task_attempt_id": "task-attempt-a", "idempotency_identity": "idempotency-timeout",
                    "invocation_started": True, "physical_send_count": 0,
                    "outcome_state": "OUTCOME_UNKNOWN", "settlement_state": "RECONCILING",
                    "unresolved_transmission_exposure_count": 1, "usage_settled": True,
                }),
                self.event(3, "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1", {
                    "effect_id": "effect-timeout", "effect_attempt_id": "attempt-timeout",
                    "state": {"outcome_state": "OUTCOME_UNKNOWN", "settlement_state": "SETTLED",
                              "settlement_basis": "POLICY_DISPOSITION", "unresolved_transmission_exposure_count": 1},
                }),
                self.event(4, "PROVIDER_EXPLICIT_REMOTE_FAILURE_OBSERVED_V1", {
                    "effect_id": "effect-failed", "effect_attempt_id": "attempt-failed", "agent_id": "agent-a",
                    "task_attempt_id": "task-attempt-a", "idempotency_identity": "idempotency-failed",
                    "physical_send_count": 1, "outcome_state": "FAILED_CONFIRMED", "settlement_state": "SETTLED",
                    "settlement_basis": "AUTHORITATIVE_REMOTE_OBSERVATION",
                    "unresolved_transmission_exposure_count": 0, "observation_id": "observation-failed",
                    "usage_settled": True,
                }),
                self.event(5, "PROVIDER_ACK_LOST_OUTCOME_UNKNOWN_V1", {
                    "effect_id": "effect-ack", "effect_attempt_id": "attempt-ack",
                    "outcome_state": "OUTCOME_UNKNOWN", "settlement_state": "RECONCILING",
                }),
                self.event(6, "EFFECT_RECONCILIATION_SETTLED_V1", {
                    "effect_id": "effect-ack", "effect_attempt_id": "attempt-ack", "ack_lost_reconciled": True,
                    "state": {"outcome_state": "SUCCEEDED", "settlement_state": "SETTLED",
                              "settlement_basis": "AUTHORITATIVE_REMOTE_OBSERVATION",
                              "unresolved_transmission_exposure_count": 0},
                }),
                self.event(7, "PROVIDER_RECOVERY_ACK_LOST_VERIFIED_V1", {
                    "effect_id": "effect-ack", "effect_attempt_id": "attempt-ack",
                }),
                self.event(8, "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1", {
                    "protocol_id": "provider-recovery-1", "task_id": "task-provider",
                    "pre_send_effect_id": "effect-pre", "timeout_effect_id": "effect-timeout",
                    "explicit_failure_effect_id": "effect-failed", "ack_lost_effect_id": "effect-ack",
                    "initial_decision_id": "decision-a", "reassignment_decision_id": "decision-b",
                    "prior_owner_id": "agent-a", "new_owner_id": "agent-b",
                    "prior_attempt_id": "task-attempt-a", "new_attempt_id": "task-attempt-b",
                    "terminal_blocking_exposure_count": 0, "unsettled_usage_count": 0,
                }),
            )
            for event in events:
                apply_production_event(connection, event)
            attempts = connection.execute(
                "SELECT path,outcome_state,settlement_state,physical_send_count FROM provider_recovery_attempts ORDER BY path"
            ).fetchall()
            self.assertEqual(len(attempts), 4)
            self.assertIn(("PRE_SEND_FAILURE", "CANCELLED_BEFORE_SEND", "SETTLED", 0), attempts)
            self.assertIn(("TIMEOUT_AFTER_INVOCATION_STARTED", "OUTCOME_UNKNOWN", "SETTLED", 0), attempts)
            self.assertIn(("EXPLICIT_REMOTE_FAILURE", "FAILED_CONFIRMED", "SETTLED", 1), attempts)
            self.assertIn(("ACK_LOST_AFTER_REMOTE_SUCCESS", "SUCCEEDED", "SETTLED", 1), attempts)
            self.assertEqual(
                connection.execute(
                    "SELECT recovery_state,initial_decision_id,reassignment_decision_id,terminal_blocking_exposure_count,unsettled_usage_count FROM provider_recovery_runtime"
                ).fetchone(),
                ("RECOVERED_AND_REASSIGNED", "decision-a", "decision-b", 0, 0),
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
