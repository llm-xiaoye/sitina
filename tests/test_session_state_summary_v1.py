from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from sitina.cas.local import LocalCAS
from sitina.cas.model import ObjectRef
from sitina.conversation.persistence import JournalSessionRepository
from sitina.conversation.lifecycle import ConversationLifecycle
from sitina.conversation.models import ChatMode, RouteDecision, RouteSource
from sitina.conversation.state import (
    RollingSummaryContent,
    RollingSummaryRepository,
    SessionStateError,
    WorkingStateChanges,
    WorkingStateDecision,
    WorkingStateRepository,
)
from sitina.journal.local import LocalJournal
from sitina.journal.model import parse_canonical_json
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class SessionStateAndSummaryV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.keys)
        self.cas = LocalCAS.open(self.home, self.keys)
        self.journal = LocalJournal.open(self.home, self.auth)
        sessions = JournalSessionRepository(self.journal, self.cas, self.keys)
        sessions.ensure_created(session_id="session-state-1", title="State", created_at="2026-07-18T00:00:00Z")
        sessions.append_message(
            session_id="session-state-1",
            message_id="message-state-1",
            role="user",
            body="Keep the goal and constraints durable.",
            turn_index=1,
            created_at="2026-07-18T00:00:01Z",
        )

    def tearDown(self) -> None:
        self.journal.close()

    @staticmethod
    def _ref(event, prefix: str) -> ObjectRef:
        return ObjectRef(
            str(event.payload[f"{prefix}_ref"]).removeprefix("cas:"),
            str(event.payload[f"{prefix}_tenant_id"]),
            str(event.payload[f"{prefix}_plaintext_commitment"]),
            str(event.payload[f"{prefix}_commitment_key_id"]),
            str(event.payload[f"{prefix}_profile"]),
        )

    def test_working_state_uses_base_plus_delta_and_rebuilds_after_restart(self) -> None:
        repository = WorkingStateRepository(self.journal, self.cas, self.keys)
        initial = repository.initialize(
            session_id="session-state-1",
            primary_goal="Repair storage without changing authority.",
            constraints=("Journal is authoritative.", "CAS stores bodies."),
            decisions=(WorkingStateDecision(decision="Use Base plus Delta.", evidence_refs=()),),
            completed_steps=("Persisted user message.",),
            pending_items=("Verify recovery.",),
            next_action="Write a state delta.",
            source_frontier=self.journal.head_position,
            occurred_at="2026-07-18T00:00:02Z",
        )
        self.assertEqual(initial.state.version, 1)
        updated = repository.update(
            session_id="session-state-1",
            expected_version=1,
            changes=WorkingStateChanges(
                completed_steps=("Persisted user message.", "Wrote a state delta."),
                pending_items=("Verify recovery.",),
                next_action="Reopen and recover.",
            ),
            source_frontier=self.journal.head_position,
            occurred_at="2026-07-18T00:00:03Z",
        )
        self.assertEqual(updated.state.version, 2)
        self.assertEqual(updated.state.primary_goal, initial.state.primary_goal)
        state_events = [event for event in self.journal.iter_events(0) if event.event_type.startswith("session.state-")]
        self.assertEqual([event.event_type for event in state_events], ["session.state-initialized", "session.state-updated"])
        self.assertNotIn("primary_goal", state_events[1].payload)
        delta_raw = self.cas.open_verified(self._ref(state_events[1], "delta"))
        delta = parse_canonical_json(delta_raw)
        self.assertNotIn("primary_goal", delta["changes"])
        self.assertNotIn("constraints", delta["changes"])
        self.assertLess(len(delta_raw), len(self.cas.open_verified(self._ref(state_events[0], "state"))))
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), 3)  # message + base + delta

        self.journal.close()
        self.journal = LocalJournal.open(self.home, self.auth)
        recovered = WorkingStateRepository(self.journal, LocalCAS.open(self.home, self.keys), self.keys).recover("session-state-1")
        self.assertEqual(recovered.state, updated.state)
        self.assertEqual(recovered.head_ref, updated.head_ref)
        with self.assertRaises(SessionStateError):
            WorkingStateRepository(self.journal, self.cas, self.keys).update(
                session_id="session-state-1",
                expected_version=1,
                changes=WorkingStateChanges(next_action="stale writer"),
                source_frontier=self.journal.head_position,
                occurred_at="2026-07-18T00:00:04Z",
            )

    def test_rolling_summary_is_typed_and_only_material_change_writes(self) -> None:
        repository = RollingSummaryRepository(self.journal, self.cas, self.keys)
        content = RollingSummaryContent(
            confirmed=("The user selected Journal authority.",),
            inferred=("Fast startup is important.",),
            unresolved=("Compression rollout is pending.",),
            user_constraint=("Do not write Production data.",),
            system_decision=("Use disposable test roots.",),
        )
        first = repository.update(
            session_id="session-state-1",
            content=content,
            source_message_range=(1, 1),
            source_frontier=self.journal.head_position,
            occurred_at="2026-07-18T00:01:00Z",
        )
        object_count = len(list((self.home / "cas/objects").rglob("*.obj")))
        head = self.journal.head_position
        unchanged = repository.update(
            session_id="session-state-1",
            content=content,
            source_message_range=(1, 1),
            source_frontier=self.journal.head_position,
            occurred_at="2026-07-18T00:01:01Z",
        )
        self.assertFalse(unchanged.changed)
        self.assertEqual(self.journal.head_position, head)
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), object_count)

        changed_content = content.model_copy(update={"confirmed": content.confirmed + ("Recovery succeeded.",)})
        second = repository.update(
            session_id="session-state-1",
            content=changed_content,
            source_message_range=(1, 2),
            source_frontier=self.journal.head_position,
            occurred_at="2026-07-18T00:01:02Z",
        )
        self.assertTrue(second.changed)
        self.assertEqual(second.summary.summary_version, 2)
        self.assertEqual(second.summary.previous_summary_ref, first.summary.summary_ref)
        events = [event for event in self.journal.iter_events(0) if event.event_type == "session.summary-updated"]
        self.assertEqual(len(events), 2)
        self.assertNotIn("confirmed", events[-1].payload)
        recovered = repository.recover("session-state-1")
        self.assertEqual(recovered.summary, second.summary)
        self.assertEqual(recovered.content, changed_content)

    def test_state_and_summary_models_reject_extra_or_empty_data(self) -> None:
        with self.assertRaises(ValidationError):
            WorkingStateChanges.model_validate({"next_action": "continue", "extra": True})
        with self.assertRaises(ValidationError):
            WorkingStateChanges.model_validate({})
        with self.assertRaises(ValidationError):
            RollingSummaryContent.model_validate({})
        with self.assertRaises(SessionStateError):
            WorkingStateRepository(self.journal, self.cas, self.keys).initialize(
                session_id="session-state-1",
                primary_goal="goal",
                constraints=(),
                decisions=(),
                completed_steps=(),
                pending_items=(),
                next_action="continue",
                source_frontier=self.journal.head_position + 1,
                occurred_at="2026-07-18T00:02:00Z",
            )

    def test_real_turn_lifecycle_persists_route_working_state_summary_and_messages(self) -> None:
        lifecycle = ConversationLifecycle(self.journal, self.cas, self.keys)
        route = RouteDecision(
            requested_mode=ChatMode.MULTI,
            resolved_mode=ChatMode.MULTI,
            source=RouteSource.USER_FORCED,
            reasons=("用户强制 MULTI",),
            policy_version="fixture-v1",
            input_hash="d" * 64,
            decision_path="USER_FORCED_MULTI",
        )
        lifecycle.start_turn(
            session_id="session-lifecycle",
            turn_index=1,
            message="validate persistence",
            route_decision=route,
            occurred_at="2026-07-18T00:00:00Z",
        )
        lifecycle.link_run(
            session_id="session-lifecycle",
            turn_index=1,
            run_id="multi-run-lifecycle",
            occurred_at="2026-07-18T00:00:01Z",
        )
        lifecycle.complete_turn(
            session_id="session-lifecycle",
            turn_index=1,
            message="validate persistence",
            response="persistence validated",
            occurred_at="2026-07-18T00:00:02Z",
        )
        recovered = JournalSessionRepository(self.journal, self.cas, self.keys).recover("session-lifecycle")
        self.assertEqual(recovered["mode"], "MULTI")
        self.assertEqual(recovered["successful_turns"][0]["assistant"], "persistence validated")
        working = WorkingStateRepository(self.journal, self.cas, self.keys).recover("session-lifecycle")
        self.assertEqual(working.state.next_action, "Await the next user request")
        summary = RollingSummaryRepository(self.journal, self.cas, self.keys).recover("session-lifecycle")
        self.assertIn("User turn 1: validate persistence", summary.content.confirmed)
        self.assertIn("Assistant turn 1: persistence validated", summary.content.confirmed)


if __name__ == "__main__":
    unittest.main()
