from __future__ import annotations

import random
import unittest

from sitina.journal.model import FrontierRef
from sitina.scheduling.decisions import FILTER_ORDER
from sitina.scheduling.scheduler import Scheduler, TaskCandidate


def candidate(task_id, *, fail=None, score=10, aging=0):
    flags = {name: name != fail for name in FILTER_ORDER}
    return TaskCandidate(task_id, **flags, base_score=score, aging_score=aging, source_versions={"task": 1, "graph": 2})


class SchedulerDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.frontier = FrontierRef("journal-shadow-1", 1, "local", 10, "11" * 32)

    def test_filter_order_is_fixed_and_records_first_failure(self) -> None:
        decision = Scheduler().decide([candidate("task-1", fail="capability")], source_frontier=self.frontier, policy_hash="22" * 32)
        evaluation = decision.candidates[0]
        self.assertEqual(decision.filter_order, FILTER_ORDER)
        self.assertEqual(evaluation.first_failed_filter, "capability")
        self.assertEqual([name for name, _ in evaluation.filter_results], list(FILTER_ORDER))

    def test_aging_never_makes_ineligible_candidate_eligible(self) -> None:
        decision = Scheduler().decide([candidate("blocked", fail="eligibility", aging=1_000_000), candidate("ready", score=1)], source_frontier=self.frontier, policy_hash="22" * 32)
        self.assertEqual(decision.ordered_attempts, ("ready",))
        self.assertIsNone(next(item for item in decision.candidates if item.task_id == "blocked").final_score)

    def test_decision_binds_exact_frontier_versions_and_policy(self) -> None:
        decision = Scheduler().decide([candidate("task-1")], source_frontier=self.frontier, policy_hash="22" * 32)
        self.assertEqual(decision.source_frontier, self.frontier)
        self.assertEqual(decision.policy_hash, "22" * 32)
        self.assertEqual(decision.candidates[0].source_versions, {"task": 1, "graph": 2})
        self.assertEqual(len(decision.commitment), 64)

    def test_tie_breaker_is_stable_id_not_iteration_order(self) -> None:
        items = [candidate("task-b"), candidate("task-a"), candidate("task-c")]
        expected = Scheduler().decide(items, source_frontier=self.frontier, policy_hash="22" * 32)
        random.Random(7).shuffle(items)
        actual = Scheduler().decide(items, source_frontier=self.frontier, policy_hash="22" * 32)
        self.assertEqual(actual.ordered_attempts, ("task-a", "task-b", "task-c"))
        self.assertEqual(actual.decision_id, expected.decision_id)


if __name__ == "__main__": unittest.main()
