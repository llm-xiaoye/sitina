from __future__ import annotations

import unittest

from sitina.protocols.rework import FailureType, Rework, ReworkError, ReworkState


class ReworkProtocolTests(unittest.TestCase):
    def test_rounds_bind_failure_type_and_acceptance_criteria(self) -> None:
        rework, _ = Rework.open("rework-1", "task-1", FailureType.REVIEW_REJECTED, "11" * 32, max_retries=2)
        rework, event = rework.begin_round("attempt-1")
        self.assertEqual(event["failure_type"], FailureType.REVIEW_REJECTED.value)
        self.assertEqual(event["acceptance_criteria_hash"], "11" * 32)
        completed, _ = rework.complete_round("21" * 32, accepted=True)
        self.assertEqual(completed.state, ReworkState.SATISFIED)

    def test_retry_exhaustion_requires_successor(self) -> None:
        rework, _ = Rework.open("rework-1", "task-1", FailureType.TEST_FAILED, "11" * 32, max_retries=1)
        rework, _ = rework.begin_round("attempt-1")
        exhausted, event = rework.complete_round("21" * 32, accepted=False)
        self.assertEqual(exhausted.state, ReworkState.SUCCESSOR_REQUIRED)
        self.assertTrue(event["successor_obligation_id"].startswith("obligation-rework-"))
        with self.assertRaises(ReworkError):
            exhausted.begin_round("attempt-2")

    def test_simple_correction_routes_new_task_attempt_not_rework_protocol(self) -> None:
        route = Rework.route_failure(FailureType.SIMPLE_CORRECTION, multi_round_required=False)
        self.assertEqual(route, "NEW_TASK_ATTEMPT")


if __name__ == "__main__":
    unittest.main()
