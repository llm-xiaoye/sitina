from __future__ import annotations

import unittest

from sitina.journal.model import FrontierRef
from sitina.scheduling.agents import AgentCandidate, AgentScheduler


class AgentSchedulingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.frontier = FrontierRef("journal-test", 1, "local", 10, "a" * 64)
        self.policy = "b" * 64

    def test_capability_and_runtime_filters_change_selected_agents(self) -> None:
        scheduler = AgentScheduler()
        candidates = (
            AgentCandidate("agent-a", "architect", ("proposal", "architecture"), source_versions={"registry": 1}),
            AgentCandidate("agent-b", "reviewer", ("proposal", "architecture"), load=4, source_versions={"registry": 1}),
            AgentCandidate("agent-c", "researcher", ("proposal",), source_versions={"registry": 1}),
        )
        first = scheduler.decide(
            "task-design", candidates, required_capabilities=("proposal", "architecture"), requested_slots=1,
            source_event_ids=("event-source",), source_frontier=self.frontier, candidate_tasks=("task-design",),
            policy_hash=self.policy, deadline="2026-07-20T00:00:00Z",
        )
        self.assertEqual(first.selected_attempts, ("agent-a",))
        changed = tuple(
            AgentCandidate(item.agent_id, item.role, item.capabilities, policy_allowed=item.agent_id != "agent-a", load=item.load)
            for item in candidates
        )
        second = scheduler.decide(
            "task-design", changed, required_capabilities=("proposal", "architecture"), requested_slots=1,
            source_event_ids=("event-source",), source_frontier=self.frontier, candidate_tasks=("task-design",),
            policy_hash=self.policy, deadline="2026-07-20T00:00:00Z",
        )
        self.assertEqual(second.selected_attempts, ("agent-b",))
        self.assertEqual(next(item for item in second.scorecards if item.agent_id == "agent-a").reason_code, "FILTERED_POLICY")

    def test_decision_records_complete_evidence_and_requested_dynamic_count(self) -> None:
        decision = AgentScheduler().decide(
            "task-propose",
            (
                AgentCandidate("agent-a", "architect", ("proposal",)),
                AgentCandidate("agent-b", "researcher", ("proposal",)),
                AgentCandidate("agent-c", "critic", ("review",)),
            ),
            required_capabilities=("proposal",), requested_slots=2, source_event_ids=("event-1", "event-2"),
            source_frontier=self.frontier, candidate_tasks=("task-propose", "task-review"),
            policy_hash=self.policy, deadline="2026-07-20T00:00:00Z",
        )
        value = decision.mapping()
        self.assertEqual(len(decision.selected_attempts), 2)
        self.assertEqual(value["source_event_ids"], ["event-1", "event-2"])
        self.assertEqual(value["filter_order"] if "filter_order" in value else value["eligibility_filters"][0], "eligibility")
        self.assertEqual(next(item for item in value["scorecards"] if item["agent_id"] == "agent-c")["first_failed_filter"], "capability")
        self.assertEqual(len(value["decision_commitment"]), 64)

    def test_capability_invalidation_recomputes_candidates_and_selects_a_new_agent(self) -> None:
        scheduler = AgentScheduler()
        initial = scheduler.decide(
            "task-reassignment",
            (
                AgentCandidate("agent-a", "executor", ("proposal", "deployment"), load=0),
                AgentCandidate("agent-b", "executor", ("proposal", "deployment"), load=1),
            ),
            required_capabilities=("proposal", "deployment"),
            requested_slots=1,
            source_event_ids=("event-task-created",),
            source_frontier=self.frontier,
            candidate_tasks=("task-reassignment",),
            policy_hash=self.policy,
            deadline="2026-07-20T00:00:00Z",
        )
        self.assertEqual(initial.selected_attempts, ("agent-a",))

        recomputed = scheduler.decide(
            "task-reassignment",
            (
                AgentCandidate("agent-a", "executor", ("proposal",), load=0),
                AgentCandidate("agent-b", "executor", ("proposal", "deployment"), load=1),
            ),
            required_capabilities=("proposal", "deployment"),
            requested_slots=1,
            source_event_ids=("event-capability-invalidated",),
            source_frontier=self.frontier,
            candidate_tasks=("task-reassignment",),
            policy_hash=self.policy,
            deadline="2026-07-20T00:00:00Z",
        )
        self.assertNotEqual(initial.decision_id, recomputed.decision_id)
        self.assertEqual(recomputed.source_event_ids, ("event-capability-invalidated",))
        self.assertEqual(recomputed.selected_attempts, ("agent-b",))
        self.assertEqual(
            next(item for item in recomputed.scorecards if item.agent_id == "agent-a").reason_code,
            "FILTERED_CAPABILITY",
        )

    def test_no_eligible_agent_is_an_explicit_fail_closed_decision(self) -> None:
        decision = AgentScheduler().decide(
            "task-reassignment",
            (
                AgentCandidate("agent-a", "executor", ("proposal",), eligible=False),
                AgentCandidate("agent-b", "executor", ("proposal",), lease_available=False),
            ),
            required_capabilities=("proposal",),
            requested_slots=1,
            source_event_ids=("event-prior-attempt-failed",),
            source_frontier=self.frontier,
            candidate_tasks=("task-reassignment",),
            policy_hash=self.policy,
            deadline="2026-07-20T00:00:00Z",
        )
        self.assertEqual(decision.reason_code, "NO_ELIGIBLE_AGENT")
        self.assertEqual(decision.selected_attempts, ())
        self.assertEqual(decision.source_event_ids, ("event-prior-attempt-failed",))
        self.assertTrue(all(not item.passed for item in decision.scorecards))


if __name__ == "__main__":
    unittest.main()
