from __future__ import annotations

import unittest

from sitina.protocols.handoffs import Handoff, HandoffError, HandoffState
from sitina.protocols.tasks import TaskAggregate


class HandoffProtocolTests(unittest.TestCase):
    def handoff(self, *, high_risk: bool = False) -> Handoff:
        return Handoff.offer(
            "handoff-1", 1, "sender-1", "receiver-1", "task-1", "11" * 32,
            policy_hash="12" * 32, capability_hash="13" * 32,
            budget=100, deadline="2099-01-01T00:00:00Z", high_risk=high_risk,
            required_capabilities=("handoff-receive",),
            receiver_capabilities=("handoff-receive", "proposal"),
            input_freeze_hash="14" * 32, output_schema_hash="15" * 32,
        )[0]

    def next_generation(self, handoff: Handoff) -> tuple[Handoff, dict]:
        return handoff.new_generation(
            specification_hash="31" * 32, policy_hash="32" * 32,
            capability_hash="33" * 32, budget=50, deadline="2099-02-01T00:00:00Z",
            required_capabilities=("handoff-receive",),
            receiver_capabilities=("handoff-receive", "proposal"),
            input_freeze_hash="34" * 32, output_schema_hash="35" * 32,
            previous_generation_ref="cas:" + "36" * 32,
            previous_rejection_event_ref="event-rejection-1",
            reject_reason_resolution_hash="37" * 32,
        )

    def executing(self, handoff: Handoff) -> tuple[Handoff, TaskAggregate]:
        handoff, _ = handoff.accept("receiver-1")
        task, attempt, _ = TaskAggregate("task-1", "21" * 32).claim(
            claim_command_id="claim-1", lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id="receiver-1",
        )
        handoff, _ = handoff.mark_claim_pending(
            "receiver-1", task_claim_ref="22" * 32, fencing_token=attempt.fencing_token,
        )
        handoff, _ = handoff.bind_claim(task, attempt.fencing_token)
        handoff, _ = handoff.execute("receiver-1")
        return handoff, task

    def test_rejected_generation_never_reopens(self) -> None:
        handoff, _ = self.handoff().reject("receiver-1", "insufficient-context")
        self.assertEqual(handoff.state, HandoffState.REJECTED)
        with self.assertRaises(HandoffError):
            handoff.accept("receiver-1")

    def test_new_generation_revalidates_and_does_not_reuse_acceptance_or_claim(self) -> None:
        handoff, _ = self.handoff().reject("receiver-1", "missing acceptance checks")
        next_handoff, event = self.next_generation(handoff)
        self.assertEqual(next_handoff.generation, 2)
        self.assertEqual(next_handoff.state, HandoffState.OFFERED)
        self.assertIsNone(next_handoff.accepted_by)
        self.assertIsNone(next_handoff.fencing_token)
        self.assertEqual(event["schema"], "HANDOFF_GENERATION_OPENED_V2")
        self.assertTrue(event["previous_generation_permanently_closed"])
        self.assertFalse(event["old_acceptance_reused"])
        self.assertNotEqual(next_handoff.input_freeze_hash, handoff.input_freeze_hash)

    def test_execution_requires_acceptance_and_valid_task_claim(self) -> None:
        handoff = self.handoff()
        with self.assertRaises(HandoffError):
            handoff.execute("receiver-1")
        handoff, _ = handoff.accept("receiver-1")
        with self.assertRaises(HandoffError):
            handoff.execute("receiver-1")
        task, attempt, _ = TaskAggregate("task-1", "21" * 32).claim(
            claim_command_id="claim-1", lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id="receiver-1",
        )
        handoff, _ = handoff.mark_claim_pending(
            "receiver-1", task_claim_ref="22" * 32, fencing_token=attempt.fencing_token,
        )
        handoff, _ = handoff.bind_claim(task, attempt.fencing_token)
        executing, _ = handoff.execute("receiver-1")
        self.assertEqual(executing.state, HandoffState.EXECUTING)

    def test_high_risk_sender_or_receiver_cannot_self_verify(self) -> None:
        handoff, _ = self.executing(self.handoff(high_risk=True))
        handoff, _ = handoff.submit(
            "receiver-1", "31" * 32, output_schema_hash="15" * 32,
            schema_validation_evidence_hash="41" * 32,
        )
        for actor in ("sender-1", "receiver-1"):
            with self.assertRaises(HandoffError):
                handoff.verify(actor, accepted=True, verification_evidence_hash="42" * 32)
        verified, event = handoff.verify(
            "independent-verifier", accepted=True, verification_evidence_hash="42" * 32,
        )
        self.assertEqual(verified.state, HandoffState.VERIFIED)
        self.assertEqual(event["artifact_hash"], "31" * 32)
        self.assertTrue(event["output_hash_bound"])

    def test_clarification_closes_generation_before_generation_two(self) -> None:
        first, _ = self.handoff().clarify("receiver-1", "43" * 32)
        first, closed = first.close_for_new_generation("receiver-1", reason_ref="44" * 32)
        second, opened = self.next_generation(first)
        self.assertEqual(first.state, HandoffState.SUPERSEDED)
        self.assertTrue(closed["generation_permanently_closed"])
        self.assertEqual(second.generation, 2)
        self.assertEqual(opened["prior_terminal_state"], "SUPERSEDED")
        second, _ = self.executing(second)
        second, _ = second.submit(
            "receiver-1", "45" * 32, output_schema_hash="35" * 32,
            schema_validation_evidence_hash="46" * 32,
        )
        second, verified = second.verify(
            "independent-verifier", accepted=True, verification_evidence_hash="47" * 32,
        )
        self.assertEqual(second.state, HandoffState.VERIFIED)
        self.assertEqual(verified["generation"], 2)

    def test_verification_failure_enters_rework_and_generation_three_can_succeed(self) -> None:
        first, _ = self.handoff().reject("receiver-1", "missing acceptance checks")
        second, _ = self.next_generation(first)
        second, task = self.executing(second)
        second, _ = second.submit(
            "receiver-1", "51" * 32, output_schema_hash="35" * 32,
            schema_validation_evidence_hash="52" * 32,
        )
        second, rejected = second.verify(
            "independent-verifier", accepted=False, verification_evidence_hash="53" * 32,
        )
        self.assertEqual(second.state, HandoffState.REWORK)
        third, opened = second.new_generation(
            specification_hash="54" * 32, policy_hash="55" * 32, capability_hash="56" * 32,
            budget=40, deadline="2099-03-01T00:00:00Z",
            required_capabilities=("handoff-receive",), receiver_capabilities=("handoff-receive",),
            input_freeze_hash="57" * 32, output_schema_hash="58" * 32,
            previous_generation_ref="cas:" + "59" * 32,
            previous_rejection_event_ref="event-verification-rework-2",
            reject_reason_resolution_hash="60" * 32,
        )
        self.assertEqual(rejected["schema"], "HANDOFF_REWORK_REQUIRED_V1")
        self.assertEqual(third.generation, 3)
        self.assertFalse(opened["old_acceptance_reused"])
        self.assertEqual(len(third.closed_generation_hashes), 2)
        third, _ = self.executing(third)
        third, _ = third.submit(
            "receiver-1", "61" * 32, output_schema_hash="58" * 32,
            schema_validation_evidence_hash="62" * 32,
        )
        third, verified = third.verify(
            "independent-verifier", accepted=True, verification_evidence_hash="63" * 32,
        )
        self.assertEqual(third.state, HandoffState.VERIFIED)
        self.assertEqual(verified["generation"], 3)

    def test_generation_limit_and_capability_mismatch_fail_closed(self) -> None:
        with self.assertRaises(HandoffError):
            Handoff.offer(
                "handoff-capability", 1, "sender-1", "receiver-1", "task-1", "61" * 32,
                policy_hash="62" * 32, capability_hash="63" * 32, budget=10,
                deadline="2099-01-01T00:00:00Z", high_risk=False,
                required_capabilities=("handoff-receive",), receiver_capabilities=("proposal",),
            )
        first = Handoff.offer(
            "handoff-limit", 1, "sender-1", "receiver-1", "task-1", "64" * 32,
            policy_hash="65" * 32, capability_hash="66" * 32, budget=10,
            deadline="2099-01-01T00:00:00Z", high_risk=False, max_generations=1,
        )[0]
        first, _ = first.reject("receiver-1", "still incomplete")
        with self.assertRaises(HandoffError) as captured:
            self.next_generation(first)
        self.assertEqual(captured.exception.fact["schema"], "HANDOFF_GENERATION_LIMIT_REACHED_V1")

    def test_rebuild_restores_generation_two_submitted_state_without_skipping_transitions(self) -> None:
        first, offered = Handoff.offer(
            "handoff-1", 1, "sender-1", "receiver-1", "task-1", "11" * 32,
            policy_hash="12" * 32, capability_hash="13" * 32, budget=100,
            deadline="2099-01-01T00:00:00Z", high_risk=False,
            required_capabilities=("handoff-receive",), receiver_capabilities=("handoff-receive",),
            input_freeze_hash="14" * 32, output_schema_hash="15" * 32,
        )
        first, rejected = first.reject("receiver-1", "missing acceptance checks")
        second, opened = self.next_generation(first)
        second, accepted = second.accept("receiver-1")
        task, attempt, claimed = TaskAggregate("task-1", "21" * 32).claim(
            claim_command_id="claim-rebuild", lease_expires_at="2099-01-01T00:00:00Z",
            holder_agent_id="receiver-1",
        )
        second, pending = second.mark_claim_pending(
            "receiver-1", task_claim_ref="22" * 32, fencing_token=attempt.fencing_token,
        )
        second, bound = second.bind_claim(task, attempt.fencing_token)
        second, executing = second.execute("receiver-1")
        second, submitted = second.submit(
            "receiver-1", "23" * 32, output_schema_hash="35" * 32,
            schema_validation_evidence_hash="24" * 32,
        )
        rebuilt = Handoff.rebuild((
            offered, rejected, opened, accepted, pending, claimed, bound, executing, submitted,
        ))
        self.assertEqual(rebuilt.generation, 2)
        self.assertEqual(rebuilt.state, HandoffState.SUBMITTED)
        self.assertEqual(rebuilt.task_attempt_id, attempt.task_attempt_id)
        self.assertEqual(rebuilt.fencing_token, attempt.fencing_token)
        self.assertEqual(rebuilt.artifact_hash, "23" * 32)
        self.assertEqual(rebuilt.closed_generation_hashes, (first.generation_hash,))

    def test_restart_after_generation_two_acceptance_continues_without_reacceptance(self) -> None:
        first, offered = Handoff.offer(
            "handoff-restart", 1, "sender-1", "receiver-1", "task-restart", "71" * 32,
            policy_hash="72" * 32, capability_hash="73" * 32, budget=100,
            deadline="2099-01-01T00:00:00Z", high_risk=False,
            required_capabilities=("handoff-receive",), receiver_capabilities=("handoff-receive",),
            input_freeze_hash="74" * 32, output_schema_hash="75" * 32,
        )
        first, rejected = first.reject("receiver-1", "missing acceptance checks")
        second, opened = first.new_generation(
            specification_hash="76" * 32, policy_hash="77" * 32,
            capability_hash="78" * 32, budget=90, deadline="2099-02-01T00:00:00Z",
            required_capabilities=("handoff-receive",), receiver_capabilities=("handoff-receive",),
            input_freeze_hash="79" * 32, output_schema_hash="80" * 32,
            previous_generation_ref="cas:" + "81" * 32,
            previous_rejection_event_ref="event-restart-rejection-1",
            reject_reason_resolution_hash="82" * 32,
        )
        second, accepted = second.accept("receiver-1")

        restarted = Handoff.rebuild((offered, rejected, opened, accepted))
        self.assertEqual(restarted.generation, 2)
        self.assertEqual(restarted.state, HandoffState.ACCEPTED)
        self.assertEqual(restarted.accepted_by, "receiver-1")

        task, attempt, _ = TaskAggregate("task-restart", "83" * 32).claim(
            claim_command_id="claim-after-restart", lease_expires_at="2099-02-01T00:00:00Z",
            holder_agent_id="receiver-1",
        )
        restarted, _ = restarted.mark_claim_pending(
            "receiver-1", task_claim_ref="84" * 32, fencing_token=attempt.fencing_token,
        )
        restarted, _ = restarted.bind_claim(task, attempt.fencing_token)
        restarted, _ = restarted.execute("receiver-1")
        restarted, _ = restarted.submit(
            "receiver-1", "85" * 32, output_schema_hash="80" * 32,
            schema_validation_evidence_hash="86" * 32,
        )
        restarted, verified = restarted.verify(
            "independent-verifier", accepted=True, verification_evidence_hash="87" * 32,
        )
        self.assertEqual(restarted.state, HandoffState.VERIFIED)
        self.assertEqual(verified["generation"], 2)


if __name__ == "__main__":
    unittest.main()
