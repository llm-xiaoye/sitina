# Live Minimal Collaboration Test Fixture

"""
Live minimal collaboration fixture for Sitina v2.

This fixture tests the minimum viable live multi-agent collaboration loop:
1. Controller classify
2. At least 1 proposer agent submits a proposal
3. At least 1 evaluator agent evaluates the proposal
4. Selection chooses one proposal
5. Optional arbitration (lightweight)
6. Receiver handoff decision
7. Blackboard context injection
8. Ledger/audit write
9. Trace observable
10. Replay reconstructable
11. Replay simulate dry-run
12. Replay diff match
13. Terminal event
14. Secret scan 0
15. No real side effects
"""

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.constants import SITINA_HOME
from sitina.orchestrator.engine import SitinaEngine
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine
from sitina.guards.secrets import scan_paths_for_secrets
from sitina.storage import SitinaStore
from sitina.runners.provider import AnthropicCompatibleClient, ProviderCompletion, ProviderDeadlineExceeded


class LiveMinimalCollaborationTests(unittest.TestCase):
    """Tests for live minimal collaboration fixture."""

    _cached_live_result: dict | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.home = SITINA_HOME
        cls.store = SitinaStore(cls.home)
        cls.store.init_db()

    def _is_live_enabled(self) -> bool:
        """Check if live tests are enabled."""
        return os.environ.get("SITINA_LIVE_TEST") == "1"

    def _live_run(self) -> dict:
        """Run the live fixture once per test class to avoid repeated provider spend."""
        if not self._is_live_enabled():
            self.skipTest("SITINA_LIVE_TEST=1 not set")
        if self.__class__._cached_live_result is None:
            self.__class__._cached_live_result = SitinaEngine(self.home).run(
                "live-minimal-collaboration-fixture deepseek-only unittest validation",
                provider_mode="live",
            )
        return dict(self.__class__._cached_live_result)

    def test_live_minimal_collaboration_smoke(self) -> None:
        """Test live minimal collaboration smoke - basic round trip."""
        result = self._live_run()

        # Must have terminal event
        self.assertIn("status", result)
        self.assertEqual(result["status"], "done", result)
        self.assertEqual(result.get("verification_status"), "verified", result)

        run_id = result["run_id"]
        ledger = RunLedger(self.home, self.store)
        timeline = ledger.timeline(run_id)

        # Check for terminal event
        terminal_events = [
            e for e in timeline
            if e["event_type"] in {
                "run_completed", "run_failed", "run_blocked",
                "run_timeout", "run_cancelled", "run_interrupted"
            }
        ]
        self.assertGreater(len(terminal_events), 0, "No terminal event found")

    def test_live_minimal_collaboration_has_terminal_event(self) -> None:
        """Test that live run always has terminal event."""
        result = self._live_run()

        run_id = result["run_id"]
        ledger = RunLedger(self.home, self.store)
        timeline = ledger.timeline(run_id)

        terminal_events = [
            e for e in timeline
            if e["event_type"] in {
                "run_completed", "run_failed", "run_blocked",
                "run_timeout", "run_cancelled", "run_interrupted"
            }
        ]

        self.assertEqual(len(terminal_events), 1, f"Expected exactly 1 terminal event, got {len(terminal_events)}")
        terminal = terminal_events[0]
        self.assertIn("status", terminal)

    def test_live_minimal_collaboration_replay_ok(self) -> None:
        """Test that live run can be replayed."""
        result = self._live_run()

        run_id = result["run_id"]
        replay_engine = ReplayEngine(self.home, self.store)
        replay = replay_engine.replay(run_id, record=False)

        self.assertEqual(replay.status, "replay_ok", f"Replay failed: {replay.status}")

    def test_live_minimal_collaboration_simulate_dry_run(self) -> None:
        """Test that replay simulate is dry-run."""
        result = self._live_run()

        run_id = result["run_id"]
        replay_engine = ReplayEngine(self.home, self.store)

        # Simulate should be dry-run
        simulate = replay_engine.simulate(run_id, sandbox=str(self.home / "temp" / "live-minimal-test-sandbox"))
        simulate_result = simulate.model_dump()

        self.assertEqual(simulate_result.get("status"), "replay_simulated")
        self.assertFalse(simulate_result.get("changed_real_files", True))
        self.assertTrue(any(check.get("check") == "sandbox_execution" and check.get("status") == "ok" for check in simulate_result.get("checks", [])))

    def test_live_minimal_collaboration_agent_identity_isolated(self) -> None:
        """Test that different agents have isolated identities."""
        result = self._live_run()

        run_id = result["run_id"]
        replay_engine = ReplayEngine(self.home, self.store)
        replay = replay_engine.replay(run_id, record=False)

        # Check agent snapshots have different agent_ids
        agent_ids = {snap["agent_id"] for snap in replay.agent_snapshots}
        self.assertGreaterEqual(len(agent_ids), 2, "Expected at least 2 different agent IDs")

        # Check provider_mode is live
        provider_snaps = [snap for snap in replay.agent_snapshots if snap.get("provider_identity")]
        self.assertGreaterEqual(len(provider_snaps), 2, "Expected provider-backed agent snapshots")
        for snap in provider_snaps:
            self.assertEqual(snap["provider_identity"]["provider_mode"], "live")

    def test_live_minimal_collaboration_secret_scan_zero(self) -> None:
        """Test that live run does not persist secrets."""
        result = self._live_run()

        run_id = result["run_id"]

        # Scan artifacts, logs, outputs for secrets
        scan_paths = [
            self.home / "artifacts" / "command_outputs" / run_id,
            self.home / "logs",
            self.home / "outputs" / "reports",
        ]

        findings = []
        for path in scan_paths:
            if path.exists():
                result = scan_paths_for_secrets([str(path)])
                findings.extend(result.get("findings", []))

        # Should have 0 secret findings
        self.assertEqual(len(findings), 0, f"Found {len(findings)} secrets: {findings}")

    def test_live_minimal_collaboration_no_real_side_effect(self) -> None:
        """Test that live minimal does not execute real side effects."""
        result = self._live_run()

        run_id = result["run_id"]
        ledger = RunLedger(self.home, self.store)
        timeline = ledger.timeline(run_id)

        # Check no git_apply or real mutation events
        side_effect_events = [
            e for e in timeline
            if e.get("event_type") in {"git_apply", "patch_apply", "file_write"}
        ]

        self.assertEqual(len(side_effect_events), 0, "Live minimal should not execute real side effects")

    def test_live_minimal_collaboration_provider_identity_redacted(self) -> None:
        """Test that provider identity is redacted in outputs."""
        result = self._live_run()

        run_id = result["run_id"]
        replay_engine = ReplayEngine(self.home, self.store)
        replay = replay_engine.replay(run_id, record=False)

        # Check all agent snapshots have redacted provider identity
        provider_snaps = [snap for snap in replay.agent_snapshots if snap.get("provider_identity")]
        self.assertGreaterEqual(len(provider_snaps), 2, "Expected provider-backed agent snapshots")
        for snap in provider_snaps:
            provider_identity = snap["provider_identity"]
            self.assertEqual(provider_identity["redaction_status"], "redacted")
            self.assertNotIn("auth_token", str(provider_identity))
            self.assertNotIn("api_key", str(provider_identity).lower())

    def test_live_minimal_collaboration_timeout_terminal_event(self) -> None:
        """Test that timeout writes terminal event."""
        if not self._is_live_enabled():
            self.skipTest("SITINA_LIVE_TEST=1 not set")

        with patch.object(AnthropicCompatibleClient, "complete_with_metadata", side_effect=ProviderDeadlineExceeded("controlled deadline exceeded")):
            result = SitinaEngine(self.home).run("controlled live deadline failure fixture", provider_mode="live")
        self.assertEqual(result["status"], "timeout", result)
        timeline = RunLedger(self.home, self.store).timeline(result["run_id"])
        event_types = [event["event_type"] for event in timeline]
        self.assertIn("run_deadline_exceeded", event_types)
        self.assertEqual([event for event in event_types if event in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}], ["run_timeout"])
        self.assertEqual(ReplayEngine(self.home, self.store).replay(result["run_id"], record=False).status, "replay_ok")

    def test_live_minimal_collaboration_parse_failure_fail_closed(self) -> None:
        """Test that parse failure fails closed."""
        if not self._is_live_enabled():
            self.skipTest("SITINA_LIVE_TEST=1 not set")

        malformed = ProviderCompletion(
            text='{"not":"a schema-valid controller output"}',
            metadata={
                "provider_request_id": "controlled-live-parse-failure",
                "provider_call_started_at": "2026-07-10T00:00:00Z",
                "provider_call_completed_at": "2026-07-10T00:00:01Z",
                "fallback_used": False,
            },
        )
        with patch.object(AnthropicCompatibleClient, "complete_with_metadata", return_value=malformed):
            result = SitinaEngine(self.home).run("controlled live parse failure fixture", provider_mode="live")
        self.assertEqual(result["status"], "failed", result)
        timeline = RunLedger(self.home, self.store).timeline(result["run_id"])
        event_types = [event["event_type"] for event in timeline]
        self.assertIn("provider_parse_failed", event_types)
        self.assertIn("agent_schema_invalid", event_types)
        terminals = [event for event in event_types if event in {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted"}]
        self.assertEqual(len(terminals), 1)
        self.assertEqual(terminals[0], "run_failed")
        self.assertTrue(all((event.get("payload_json") or {}).get("fallback_used") is not True for event in timeline))
        self.assertEqual(ReplayEngine(self.home, self.store).replay(result["run_id"], record=False).status, "replay_ok")


if __name__ == "__main__":
    unittest.main()
