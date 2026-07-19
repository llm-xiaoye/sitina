from __future__ import annotations

import os
import unittest

from sitina.constants import SITINA_HOME
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.engine import SitinaEngine
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine


def require_live() -> None:
    if os.environ.get("SITINA_LIVE_TEST") != "1":
        raise unittest.SkipTest("SITINA_LIVE_TEST=1 not set")


class LiveTypedRetryReworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_live()
        cls.result = SitinaEngine(SITINA_HOME).run(
            "live-typed-rework-worker-fixture DeepSeek-only typed missing-evidence repair and re-evaluation unittest",
            provider_mode="live",
        )
        cls.run_id = cls.result["run_id"]
        cls.timeline = RunLedger(SITINA_HOME).timeline(cls.run_id)
        cls.replay = ReplayEngine(SITINA_HOME).replay(cls.run_id, record=False)

    def test_live_typed_retry_rework(self) -> None:
        self.assertEqual(self.result["status"], "done", self.result)
        self.assertEqual(self.replay.status, "replay_ok", self.replay.model_dump())
        self.assertTrue(any(item.get("failure_type") == "missing_evidence" and item.get("retryable") for item in self.replay.typed_failures))
        self.assertTrue(any(item.get("event_type") == "retry_scheduled" for item in self.replay.retry_state))
        self.assertTrue(self.replay.rework_edges)
        for task_id in ("rework_1_coder_rework", "rework_1_tester_rerun", "rework_1_reviewer_rerun"):
            self.assertEqual(self.replay.node_states.get(task_id), "completed")
        self.assertEqual(
            [event["event_type"] for event in self.timeline if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}],
            ["run_completed"],
        )
        self.assertTrue(all(snapshot.get("provider_mode") == "live" and snapshot.get("fallback_used") is False for snapshot in self.replay.agent_snapshots))


class LiveHandoffRejectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_live()
        cls.result = SitinaEngine(SITINA_HOME).run(
            "live-handoff-reject-fixture Plan a code change to core/sitina/runners/provider.py that requires source mutation before any approval or writable scope exists; receiver must assess supplied scope evidence",
            provider_mode="live",
        )
        cls.run_id = cls.result["run_id"]
        cls.timeline = RunLedger(SITINA_HOME).timeline(cls.run_id)
        cls.replay = ReplayEngine(SITINA_HOME).replay(cls.run_id, record=False)

    def test_live_handoff_reject(self) -> None:
        self.assertEqual(self.result["status"], "blocked", self.result)
        decisions = [event for event in self.timeline if event["event_type"] == "handoff_receiver_decision"]
        self.assertTrue(decisions)
        payload = decisions[-1]["payload_json"]
        self.assertEqual(payload["decision"]["decision"], "reject")
        self.assertEqual(payload["receiver_agent"], "planner")
        self.assertEqual(payload["provider_mode"], "live")
        self.assertEqual(payload["profile_name"], "deepseek")
        self.assertTrue(payload.get("input_hash") and payload.get("output_hash"))
        self.assertFalse(payload.get("fallback_used"))
        self.assertTrue(payload.get("provider_calls"))
        self.assertTrue(all(call.get("schema_validation_status") == "valid" for call in payload["provider_calls"]))
        receiver_snapshots = [item for item in self.replay.agent_snapshots if item.get("agent_id") == "planner" and item.get("task_id") == "planner"]
        self.assertTrue(receiver_snapshots)
        self.assertNotIn("handoff-reject-fixture", (receiver_snapshots[-1].get("input_payload") or {}).get("user_goal", ""))
        self.assertEqual(self.replay.status, "replay_ok", self.replay.model_dump())
        self.assertEqual(self.replay.node_states.get("planner"), "blocked")
        terminals = [event["event_type"] for event in self.timeline if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}]
        self.assertEqual(terminals, ["run_failed"])


class LiveLeaseArbitrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_live()
        engine = SitinaEngine(SITINA_HOME)
        cls.granted = engine.run(
            "live-lease-arbitration-worker-fixture DeepSeek-only grant decision from approved coder scope unittest",
            provider_mode="live",
        )
        cls.blocked = engine.run(
            "live-lease-arbitration-block-worker-fixture DeepSeek-only block decision because neither lease holder has approval scope unittest",
            provider_mode="live",
        )
        cls.granted_replay = ReplayEngine(SITINA_HOME).replay(cls.granted["run_id"], record=False)
        cls.blocked_replay = ReplayEngine(SITINA_HOME).replay(cls.blocked["run_id"], record=False)

    @staticmethod
    def decision(replay) -> str | None:
        decisions = [item for item in replay.arbitrations if item.get("event_type") == "arbitration_decision"]
        return decisions[-1].get("decision") if decisions else None

    def test_live_arbitration_conflict(self) -> None:
        self.assertEqual(self.granted["status"], "done", self.granted)
        self.assertEqual(self.blocked["status"], "blocked", self.blocked)
        self.assertEqual(self.decision(self.granted_replay), "grant_agent_a")
        self.assertEqual(self.decision(self.blocked_replay), "block")
        for replay in (self.granted_replay, self.blocked_replay):
            self.assertEqual(replay.status, "replay_ok", replay.model_dump())
            arbiter = [item for item in replay.agent_snapshots if item.get("agent_id") == "arbiter"]
            self.assertEqual(len(arbiter), 1)
            self.assertEqual(arbiter[0].get("provider_mode"), "live")
            self.assertEqual(arbiter[0].get("profile_name"), "deepseek")
            self.assertFalse(arbiter[0].get("fallback_used"))
            self.assertTrue(arbiter[0].get("input_hash") and arbiter[0].get("output_hash"))
            self.assertTrue(all(call.get("schema_validation_status") == "valid" for call in arbiter[0].get("provider_calls") or []))

    def test_live_lease_conflict(self) -> None:
        self.assertTrue(any(item.get("event_type") == "lease_conflict_detected" for item in self.granted_replay.leases))
        self.assertTrue(any(item.get("event_type") == "lease_holder_blocked" and item.get("holder_agent") == "maintenance_ops" for item in self.granted_replay.leases))
        self.assertEqual(self.granted_replay.node_states.get("lease_loser_maintenance_ops"), "blocked")
        self.assertTrue(any(item.get("event_type") == "lease_released" and item.get("holder_agent") == "coder" for item in self.granted_replay.leases))
        granted_events = RunLedger(SITINA_HOME).timeline(self.granted["run_id"])
        blocked_events = RunLedger(SITINA_HOME).timeline(self.blocked["run_id"])
        self.assertEqual([event["event_type"] for event in granted_events if event["event_type"] in {"run_completed", "run_failed"}], ["run_completed"])
        self.assertEqual([event["event_type"] for event in blocked_events if event["event_type"] in {"run_completed", "run_failed"}], ["run_failed"])


class LiveCheckpointResumeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_live()
        cls.engine = SitinaEngine(SITINA_HOME)
        cls.prepared = cls.engine.run(
            "live-checkpoint-resume-worker-fixture DeepSeek-only resume pending summary unittest",
            provider_mode="live",
        )
        cls.run_id = cls.prepared["run_id"]
        cls.before = RunLedger(SITINA_HOME).timeline(cls.run_id)
        cls.checkpoint = CheckpointManager(SITINA_HOME).latest_resumable(cls.run_id)
        cls.checkpoint_valid = bool(cls.checkpoint and CheckpointManager(SITINA_HOME).verify_for_resume(cls.checkpoint, cls.run_id)[0])
        cls.resumed = cls.engine.resume(cls.run_id)
        cls.after = RunLedger(SITINA_HOME).timeline(cls.run_id)
        cls.resumed_again = cls.engine.resume(cls.run_id)
        cls.after_second = RunLedger(SITINA_HOME).timeline(cls.run_id)
        cls.replay = ReplayEngine(SITINA_HOME).replay(cls.run_id, record=False)

    def test_live_checkpoint_resume_does_not_repeat_completed_provider_calls(self) -> None:
        self.assertEqual(self.prepared["status"], "paused", self.prepared)
        self.assertFalse(any(event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"} for event in self.before))
        self.assertIsNotNone(self.checkpoint)
        self.assertTrue(self.checkpoint_valid)
        self.assertEqual(self.resumed["status"], "ok", self.resumed)
        self.assertEqual(self.resumed["resumed_agent_calls"], 1)
        self.assertEqual(self.resumed["resumed_provider_calls"], 1)
        self.assertEqual(self.resumed["duplicate_provider_calls"], 0)
        completed = [event for event in self.after if event["event_type"] == "agent_completed"]
        self.assertEqual([event.get("agent_id") for event in completed].count("planner"), 1)
        self.assertEqual([event.get("agent_id") for event in completed].count("summary"), 1)
        call_ids = [call.get("provider_request_id") for event in completed for call in event["payload_json"].get("provider_calls") or []]
        self.assertEqual(len(call_ids), len(set(call_ids)))
        self.assertTrue(all(event["payload_json"].get("provider_mode") == "live" and event["payload_json"].get("fallback_used") is False for event in completed))
        terminals = [event["event_type"] for event in self.after if event["event_type"] in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}]
        self.assertEqual(terminals, ["run_completed"])
        self.assertEqual(self.resumed_again["status"], "ok", self.resumed_again)
        self.assertEqual(self.resumed_again["resumed_agent_calls"], 0)
        calls_after_second = [event for event in self.after_second if event["event_type"] == "agent_completed"]
        self.assertEqual(len(calls_after_second), len(completed))
        self.assertEqual(self.replay.status, "replay_ok", self.replay.model_dump())


if __name__ == "__main__":
    unittest.main()
