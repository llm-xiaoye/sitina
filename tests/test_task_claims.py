from __future__ import annotations

import unittest

from sitina.protocols.tasks import AttemptState, TaskAggregate, TaskProtocolError, TaskState


class TaskClaimTests(unittest.TestCase):
    def test_exactly_one_active_attempt_and_duplicate_claim_returns_original_fence(self) -> None:
        task = TaskAggregate("task-1", "11" * 32)
        task, attempt, _ = task.claim(claim_command_id="claim-1", lease_expires_at="2026-07-13T01:00:00Z")
        duplicate_task, duplicate, _ = task.claim(claim_command_id="claim-1", lease_expires_at="2026-07-13T01:00:00Z")
        self.assertEqual((duplicate_task, duplicate.fencing_token), (task, attempt.fencing_token))
        with self.assertRaises(TaskProtocolError): task.claim(claim_command_id="claim-2", lease_expires_at="2026-07-13T01:00:00Z")

    def test_old_fence_cannot_submit_after_expiry_and_reassignment(self) -> None:
        task = TaskAggregate("task-1", "11" * 32); task, first, _ = task.claim(claim_command_id="claim-1", lease_expires_at="2026-07-13T01:00:00Z")
        task, _ = task.expire(first.fencing_token); task, second, _ = task.claim(claim_command_id="claim-2", lease_expires_at="2026-07-13T02:00:00Z")
        self.assertNotEqual(first.fencing_token, second.fencing_token)
        with self.assertRaises(TaskProtocolError): task.submit(first.fencing_token, "22" * 32)

    def test_competing_claims_use_stream_cas_and_emit_stable_rejection(self) -> None:
        task = TaskAggregate("task-competition", "11" * 32)
        common_version = task.stream_version
        task, winner, granted = task.claim_or_reject(
            claim_command_id="claim-agent-a", lease_expires_at="2026-07-16T13:00:00Z",
            holder_agent_id="agent-a", expected_stream_version=common_version,
        )
        self.assertIsNotNone(winner)
        task_after_reject, loser, rejected = task.claim_or_reject(
            claim_command_id="claim-agent-b", lease_expires_at="2026-07-16T13:00:00Z",
            holder_agent_id="agent-b", expected_stream_version=common_version,
        )
        self.assertIsNone(loser)
        self.assertEqual(task_after_reject, task)
        self.assertEqual(granted["holder_agent_id"], "agent-a")
        self.assertEqual(rejected["reason_code"], "TASK_STREAM_VERSION_CONFLICT")
        self.assertFalse(rejected["task_stream_mutated"])

    def test_renew_requires_progress_evidence_and_expiry_permanently_revokes_fence(self) -> None:
        task = TaskAggregate("task-renew", "11" * 32)
        task, first, _ = task.claim(
            claim_command_id="claim-agent-a", lease_expires_at="2026-07-16T13:00:00Z",
            holder_agent_id="agent-a", expected_stream_version=task.stream_version,
        )
        with self.assertRaises(TaskProtocolError):
            task.renew(first.fencing_token, lease_expires_at="2026-07-16T13:01:00Z", progress_evidence_refs=())
        task, renewed = task.renew(
            first.fencing_token, lease_expires_at="2026-07-16T13:01:00Z",
            progress_evidence_refs=("21" * 32,),
        )
        self.assertEqual(renewed["progress_evidence_refs"], ["21" * 32])
        with self.assertRaises(TaskProtocolError):
            task.expire(first.fencing_token, observed_at="2026-07-16T13:00:59Z")
        task, expired = task.expire(first.fencing_token, observed_at="2026-07-16T13:01:00Z")
        self.assertTrue(expired["fencing_token_permanently_revoked"])
        self.assertEqual(task.attempts[-1].state, AttemptState.EXPIRED)

    def test_reassignment_changes_owner_attempt_generation_lease_and_fence(self) -> None:
        task = TaskAggregate("task-reassign", "11" * 32)
        task, first, _ = task.claim(
            claim_command_id="claim-agent-a", lease_expires_at="2026-07-16T13:00:00Z",
            holder_agent_id="agent-a", expected_stream_version=task.stream_version,
        )
        task, _ = task.expire(first.fencing_token, observed_at="2026-07-16T13:00:00Z")
        reassigned = task.reassignment_decided(
            prior_decision_id="decision-a", new_decision_id="decision-b",
            new_holder_agent_id="agent-b", reason_code="LEASE_EXPIRED",
        )
        task, second, _ = task.claim(
            claim_command_id="claim-agent-b", lease_expires_at="2026-07-16T14:00:00Z",
            holder_agent_id="agent-b", expected_stream_version=task.stream_version,
        )
        self.assertEqual(reassigned["new_agent_id"], "agent-b")
        self.assertNotEqual(first.task_attempt_id, second.task_attempt_id)
        self.assertNotEqual(first.claim_generation, second.claim_generation)
        self.assertNotEqual(first.lease_id, second.lease_id)
        self.assertNotEqual(first.fencing_token, second.fencing_token)

    def test_late_real_artifact_is_recorded_but_stale_outer_commit_is_rejected(self) -> None:
        task = TaskAggregate("task-late", "11" * 32)
        task, first, _ = task.claim(
            claim_command_id="claim-agent-a", lease_expires_at="2026-07-16T13:00:00Z",
            holder_agent_id="agent-a", expected_stream_version=task.stream_version,
        )
        task, _ = task.expire(first.fencing_token, observed_at="2026-07-16T13:00:00Z")
        task, second, _ = task.claim(
            claim_command_id="claim-agent-b", lease_expires_at="2026-07-16T14:00:00Z",
            holder_agent_id="agent-b", expected_stream_version=task.stream_version,
        )
        task, _ = task.submit(second.fencing_token, "22" * 32)
        task, accepted = task.accept(second.fencing_token, artifact_hash="22" * 32, policy_hash="33" * 32)
        unchanged, rejected = task.submit_or_reject(first.fencing_token, "44" * 32)
        self.assertEqual(unchanged, task)
        self.assertEqual(accepted["accepted_by"], "result-admission-verifier")
        self.assertFalse(accepted["agent_self_declared_complete"])
        self.assertFalse(rejected["business_state_committed"])
        self.assertEqual(rejected["artifact_hash"], "44" * 32)

    def test_attempt_failure_does_not_automatically_fail_task(self) -> None:
        task = TaskAggregate("task-1", "11" * 32); task, attempt, _ = task.claim(claim_command_id="claim-1", lease_expires_at="2026-07-13T01:00:00Z")
        task, event = task.fail_attempt(attempt.fencing_token, "fixture-error")
        self.assertEqual(task.state, TaskState.OPEN); self.assertEqual(event["task_state"], "OPEN")

    def test_acceptance_binds_exact_artifact_hash_and_policy(self) -> None:
        task = TaskAggregate("task-1", "11" * 32); task, attempt, _ = task.claim(claim_command_id="claim-1", lease_expires_at="2026-07-13T01:00:00Z")
        task, _ = task.submit(attempt.fencing_token, "22" * 32)
        with self.assertRaises(TaskProtocolError): task.accept(attempt.fencing_token, artifact_hash="33" * 32, policy_hash="44" * 32)
        task, event = task.accept(attempt.fencing_token, artifact_hash="22" * 32, policy_hash="44" * 32)
        self.assertEqual(task.state, TaskState.COMPLETED); self.assertEqual(event["artifact_hash"], "22" * 32)


if __name__ == "__main__": unittest.main()
