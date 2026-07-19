from __future__ import annotations

import os
import unittest

from sitina.constants import SITINA_HOME
from sitina.orchestrator.acceptance_report import AcceptanceReportGenerator
from sitina.orchestrator.engine import SitinaEngine
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine
from sitina.storage import SitinaStore


class LiveCollaborationDepthTests(unittest.TestCase):
    """One real readonly run supplies evidence for the coupled depth protocol."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("SITINA_LIVE_TEST") != "1":
            raise unittest.SkipTest("SITINA_LIVE_TEST=1 not set")
        cls.home = SITINA_HOME
        cls.store = SitinaStore(cls.home)
        cls.store.init_db()
        cls.result = SitinaEngine(cls.home).run(
            "live-complex-readonly-fixture DeepSeek-only collaboration depth unittest",
            provider_mode="live",
        )
        cls.run_id = cls.result["run_id"]
        cls.timeline = RunLedger(cls.home, cls.store).timeline(cls.run_id)
        cls.replay = ReplayEngine(cls.home, cls.store).replay(cls.run_id, record=False)

    @classmethod
    def events(cls, event_type: str) -> list[dict]:
        return [event for event in cls.timeline if event["event_type"] == event_type]

    def test_live_two_proposer_competition(self) -> None:
        proposals = self.events("proposal_submitted")
        evaluators = self.events("proposal_evaluated")
        proposer_agents = {event["payload_json"].get("proposer_agent") for event in proposals}
        evaluator_agents = {event.get("agent_id") or event["payload_json"].get("reviewer_agent") for event in evaluators}
        self.assertGreaterEqual(len(proposer_agents), 2, proposer_agents)
        self.assertGreaterEqual(len(evaluator_agents), 2, evaluator_agents)
        self.assertEqual(len(self.events("proposal_selected")), 1)
        self.assertGreaterEqual(len(self.events("proposal_rejected")), 1)
        proposal_snapshots = [snap for snap in self.replay.agent_snapshots if snap.get("task_id") == "proposal"]
        self.assertGreaterEqual(len(proposal_snapshots), 2)
        self.assertTrue(all(snap.get("provider_mode") == "live" and snap.get("fallback_used") is False for snap in proposal_snapshots))
        self.assertEqual(len({snap.get("output_hash") for snap in proposal_snapshots}), len(proposal_snapshots))

    def test_live_multi_round_negotiation(self) -> None:
        opened = self.events("proposal_round_opened")
        debate = self.events("debate_round_opened")
        revisions = self.events("proposal_revision_created")
        self.assertEqual(len(opened), 1)
        self.assertGreaterEqual(len(debate), 1)
        self.assertGreaterEqual(len(revisions), 1)
        self.assertEqual(debate[0]["payload_json"].get("round"), 1)
        self.assertGreaterEqual(revisions[0]["payload_json"].get("revision_round", 0), 1)
        self.assertLessEqual(debate[0]["payload_json"].get("round", 0), debate[0]["payload_json"].get("max_rounds", 0))

    def test_live_proposal_revision(self) -> None:
        revisions = self.events("proposal_revision_created")
        reevaluations = self.events("proposal_revision_evaluated")
        self.assertGreaterEqual(len(revisions), 1)
        revision = revisions[0]["payload_json"]
        self.assertTrue(revision.get("revision_id"))
        self.assertTrue(revision.get("parent_proposal_id"))
        self.assertTrue(any(event["payload_json"].get("revision_id") == revision["revision_id"] for event in reevaluations))

    def test_live_cross_agent_debate(self) -> None:
        opened = self.events("debate_round_opened")
        responses = self.events("debate_response")
        closed = self.events("debate_round_closed")
        self.assertEqual(len(opened), 1)
        self.assertEqual(len(closed), 1)
        self.assertGreaterEqual(len({event.get("agent_id") for event in responses}), 2)
        self.assertTrue(all(event["payload_json"].get("source_agent") for event in responses))
        self.assertTrue(closed[0]["payload_json"].get("evaluation_ids"))

    def test_dynamic_dispatcher_selects_from_runtime_state(self) -> None:
        decisions = [event["payload_json"] for event in self.events("dispatch_decision")]
        dispatched = [item for item in decisions if item.get("status") == "dispatch"]
        self.assertGreaterEqual(len(dispatched), 5, decisions)
        self.assertGreaterEqual(len({item.get("task_id") for item in dispatched}), 5)
        self.assertEqual(decisions[-1].get("status"), "complete")
        self.assertTrue(all(item.get("decision_id") and item.get("state_snapshot_hash") for item in decisions))
        self.assertTrue(all(item.get("task_id") not in {entry.get("task_id") for entry in item.get("blocked_candidates", [])} for item in dispatched))

    def test_live_complex_readonly_long_flow(self) -> None:
        self.assertEqual(self.result.get("status"), "done", self.result)
        self.assertEqual(self.replay.status, "replay_ok", self.replay.model_dump())
        self.assertGreaterEqual(len({snap.get("agent_id") for snap in self.replay.agent_snapshots}), 5)
        self.assertGreaterEqual(len(self.events("checkpoint_created")), 1)
        self.assertGreaterEqual(len(self.replay.blackboard_summary.get("documents", [])), 1)
        self.assertEqual([event["event_type"] for event in self.timeline if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}], ["run_completed"])
        simulation = ReplayEngine(self.home, self.store).simulate(self.run_id, record=False)
        self.assertEqual(simulation.status, "replay_simulated")
        self.assertFalse(simulation.changed_real_files)
        report = AcceptanceReportGenerator(self.home).generate_acceptance_report(self.run_id)
        self.assertEqual(report["overall_status"], "passed", report)
        self.assertEqual(report["evidence"]["side_effect_count"], 0)
        self.assertEqual(report["evidence"]["secret_scan"]["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
