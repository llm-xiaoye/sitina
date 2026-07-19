from __future__ import annotations

import os
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.projections.coverage import MissingRequiredProjectionHandler
from sitina.projections.generations import ProjectionGenerationError, ProjectionGenerationPublisher, ProjectionGenerationReader
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers
from sitina.projections.runner import ProjectionRunner
from sitina.projections.schema import open_projection
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class ProjectionStableV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.provider = InMemoryKeyProvider()
        self.journal = LocalJournal.open(self.home, JournalAuthProvider(self.provider))

    def tearDown(self) -> None:
        self.journal.close()

    def _append(self, ordinal: int, event_type: str, stream_id: str, payload: dict) -> EventEnvelope:
        command = CommandEnvelope(
            f"projection-command-{ordinal}",
            "tenant-projection",
            stream_id,
            event_type,
            "projection-test",
            "2026-07-18T00:00:00Z",
            {"ordinal": ordinal},
        )
        event = EventEnvelope(
            f"projection-event-{ordinal}",
            event_type,
            "tenant-projection",
            stream_id,
            0,
            0,
            "2026-07-18T00:00:00Z",
            payload,
        )
        receipt = self.journal.append(command, self.journal._stream_heads.get(stream_id, 0), [event])
        return next(item for item in self.journal.iter_events(receipt.first_position - 1) if item.position == receipt.first_position)

    def _events(self) -> tuple[EventEnvelope, ...]:
        body_ref = "cas:" + "a" * 64
        events = (
            self._append(1, "session.created", "session/session-1", {
                "schema": "SESSION_CREATED_V1", "session_id": "session-1", "title": "Projection session",
                "created_at": "2026-07-18T00:00:00Z",
            }),
            self._append(2, "session.message-appended", "session/session-1", {
                "schema": "SESSION_MESSAGE_APPENDED_V1", "session_id": "session-1", "message_id": "message-1",
                "role": "user", "turn_index": 1, "body_ref": body_ref, "body_hash": "b" * 64,
                "created_at": "2026-07-18T00:00:00Z",
            }),
            self._append(3, "future.optional-observed", "future/optional-1", {
                "schema": "FUTURE_OPTIONAL_V9", "projection_requirement": "optional", "large_body": "not copied",
            }),
            self._append(4, "memory.candidate-created", "memory/memory-1", {
                "schema": "SITINA_MEMORY_CANDIDATE_CREATED_V1",
                "memory": {
                    "memory_id": "memory-1", "scope": "user", "owner_id": "user/test",
                    "namespace": "user/test/preferences", "status": "candidate", "content_ref": "cas:" + "c" * 64,
                    "expires_at": None,
                },
            }),
            self._append(5, "provider.health-observed", "provider-health/gpt", {
                "schema": "PROVIDER_HEALTH_OBSERVED_V1", "profile": "gpt", "status": "healthy",
                "checked_at": "2026-07-18T00:00:00Z", "next_check_at": None, "failure_count": 0,
                "last_error": None, "model": "fixture", "latency_ms": 10, "source": "test",
            }),
        )
        return events

    def test_pointer_verifies_authority_coverage_checksum_then_applies_exact_tail_in_overlay(self) -> None:
        events = self._events()
        root = self.home / "projections"
        building = root / "building" / "generation-1.sqlite"
        connection = open_projection(building)
        ProjectionRunner(connection, production_handlers()).apply_batch(events[:2])
        connection.close()
        pointer = ProjectionGenerationPublisher(root).publish(
            generation_id="generation-1",
            building_database=building,
            authority_checkpoint_commitment="d" * 64,
            journal_frontier=2,
            schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
            created_at="2026-07-18T00:01:00Z",
        )
        self.assertEqual(pointer["schema"], "PROJECTION_GENERATION_POINTER_V2")
        self.assertEqual(list((root / "building").glob("*.sqlite-*")), [])
        self.assertEqual(list((root / "current").glob("*.sqlite-*")), [])
        reader = ProjectionGenerationReader(root)
        with self.assertRaises(ProjectionGenerationError):
            reader.select(
                authority_checkpoint_commitments=("d" * 64,),
                schema_coverage_hashes=("0" * 64,),
            )
        applied = reader.select_with_tail(
            authority_checkpoint_commitments=("d" * 64,),
            schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
            current_journal_frontier=5,
            tail_events=events[2:],
            handlers=production_handlers(),
            max_tail_positions=10,
        )
        try:
            self.assertEqual(applied.applied_through, 5)
            self.assertEqual(applied.connection.execute("SELECT status FROM provider_health WHERE profile='gpt'").fetchone()[0], "healthy")
            self.assertEqual(applied.connection.execute("SELECT status FROM memory_items WHERE memory_id='memory-1'").fetchone()[0], "candidate")
            columns = {row[1] for row in applied.connection.execute("PRAGMA table_info(event_directory)")}
            self.assertEqual(columns, {"position", "event_id", "event_type", "stream_id", "run_id", "payload_hash", "source_segment"})
            self.assertIsNone(applied.connection.execute("SELECT name FROM sqlite_master WHERE name='business_events'").fetchone())
            self.assertEqual(applied.connection.execute("SELECT coverage_state FROM projection_schema_coverage WHERE schema_id='FUTURE_OPTIONAL_V9'").fetchone()[0], "DIRECTORY_ONLY")
        finally:
            applied.close()
        selected = reader.select(authority_checkpoint_commitments=("d" * 64,))
        self.assertEqual(list((root / "current").glob("*.sqlite-*")), [])
        base = open_projection(selected.database_path)
        try:
            self.assertEqual(base.execute("SELECT last_position FROM projection_offsets WHERE projection_name='kernel'").fetchone()[0], 2)
        finally:
            base.close()

    def test_missing_required_handler_rolls_back_and_sets_degraded(self) -> None:
        event = self._append(1, "future.required", "future/required-1", {
            "schema": "FUTURE_REQUIRED_V2", "projection_requirement": "required", "value": 1,
        })
        connection = open_projection(self.home / "required.sqlite")
        try:
            runner = ProjectionRunner(connection, production_handlers())
            with self.assertRaises(MissingRequiredProjectionHandler):
                runner.apply_batch((event,))
            self.assertEqual(connection.execute("SELECT state FROM projection_offsets WHERE projection_name='kernel'").fetchone()[0], "DEGRADED")
            self.assertEqual(connection.execute("SELECT count(*) FROM event_directory").fetchone()[0], 0)
            self.assertEqual(runner.offset, 0)
        finally:
            connection.close()

    def test_required_session_context_tool_and_evidence_events_have_query_handlers(self) -> None:
        reference = "cas:" + "a" * 64
        events = (
            self._append(1, "session.created", "session/session-1", {
                "schema": "SESSION_CREATED_V1", "session_id": "session-1", "title": "Visible",
            }),
            self._append(2, "session.message-appended", "session/session-1", {
                "schema": "SESSION_MESSAGE_APPENDED_V1", "session_id": "session-1", "message_id": "message-1",
                "role": "user", "turn_index": 1, "body_ref": reference, "body_hash": "b" * 64,
                "created_at": "2026-07-18T00:00:00Z",
            }),
            self._append(3, "session.run-linked", "session/session-1", {
                "schema": "SESSION_RUN_LINKED_V1", "session_id": "session-1", "run_id": "run-1", "turn_index": 1,
            }),
            self._append(4, "session.state-initialized", "session/session-1", {
                "schema": "SITINA_SESSION_STATE_INITIALIZED_V1", "session_id": "session-1", "version": 1,
                "state_ref": reference, "source_frontier": 3,
            }),
            self._append(5, "session.summary-updated", "session/session-1", {
                "schema": "SITINA_CONVERSATION_ROLLING_SUMMARY_V1", "session_id": "session-1", "summary_version": 1,
                "source_message_range": [1, 1], "source_frontier": 4, "summary_ref": reference, "summary_hash": "c" * 64,
                "previous_summary_ref": None,
            }),
            self._append(6, "agent.context-manifest-published", "run/run-1", {
                "schema": "SITINA_AGENT_CONTEXT_MANIFEST_PUBLISHED_V2", "run_id": "run-1", "call_id": "call-1",
                "agent_id": "agent-1", "manifest_ref": reference, "rendered_input_hash": "d" * 64,
            }),
            self._append(7, "tool.completed", "run/run-1", {
                "schema": "SITINA_TOOL_COMPLETED_V1", "run_id": "run-1", "tool_call_id": "tool-1",
                "terminal_status": "SUCCEEDED", "exit_code": 0, "result_manifest_ref": reference,
                "captured_bytes": 12, "dropped_bytes": 0, "truncated": False,
            }),
            self._append(8, "run.checkpoint-published", "run/run-1", {
                "schema": "SITINA_RUN_CHECKPOINT_PUBLISHED_V2", "run_id": "run-1", "checkpoint_id": "checkpoint-1",
                "checkpoint_kind": "incremental", "checkpoint_ref": reference, "journal_to_position": 7,
            }),
            self._append(9, "run.evidence-published", "run/run-1", {
                "schema": "SITINA_RUN_EVIDENCE_PUBLISHED_V2", "run_id": "run-1", "evidence_id": "evidence-1",
                "evidence_ref": reference, "checkpoint_ref": reference,
            }),
            self._append(10, "session.deleted", "session/session-1", {
                "schema": "SESSION_DELETED_V1", "session_id": "session-1",
            }),
        )
        connection = open_projection(self.home / "required-families.sqlite")
        try:
            ProjectionRunner(connection, production_handlers()).apply_batch(events)
            self.assertEqual(connection.execute("SELECT count(*) FROM session_messages").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM active_session_messages").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM active_session_runs").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT state_version FROM session_working_state").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT summary_version FROM session_summaries").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT status FROM agent_calls").fetchone()[0], "CONTEXT_READY")
            self.assertEqual(connection.execute("SELECT status FROM tool_calls").fetchone()[0], "SUCCEEDED")
            self.assertEqual(connection.execute("SELECT checkpoint_kind FROM run_checkpoints").fetchone()[0], "incremental")
            self.assertEqual(connection.execute("SELECT evidence_id FROM run_evidence").fetchone()[0], "evidence-1")
        finally:
            connection.close()

    def test_runtime_state_retains_recoverable_run_then_prunes_it_after_assistant_marker(self) -> None:
        reference = "cas:" + "a" * 64
        events = (
            self._append(1, "session.created", "session/session-1", {
                "schema": "SESSION_CREATED_V1", "session_id": "session-1", "title": "Runtime state",
                "created_at": "2026-07-18T00:00:00Z",
            }),
            self._append(2, "session.message-appended", "session/session-1", {
                "schema": "SESSION_MESSAGE_APPENDED_V1", "session_id": "session-1", "message_id": "user-1",
                "role": "user", "turn_index": 1, "body_ref": reference, "body_hash": "b" * 64,
                "created_at": "2026-07-18T00:00:00Z",
            }),
            self._append(3, "run.created", "run/run-1", {
                "schema": "FAST_CONVERSATION_RUN_OPENED_V1", "run_id": "run-1", "message_hash": "c" * 64,
                "session_id": "session-1", "turn_index": 1,
            }),
            self._append(4, "session.run-linked", "session/session-1", {
                "schema": "SESSION_RUN_LINKED_V1", "session_id": "session-1", "run_id": "run-1", "turn_index": 1,
            }),
            self._append(5, "protocol.provider.usage.recorded", "effect/run-1/effect-1", {
                "schema": "PROVIDER_USAGE_RECORDED_V1", "run_id": "run-1", "call_id": "call-1",
                "outcome": "SUCCEEDED", "physical_send_count": 1,
            }),
            self._append(6, "run.terminal", "run/run-1", {
                "schema": "RUN_TERMINAL_V1", "run_id": "run-1", "terminal_state": "SUCCEEDED",
            }),
        )
        path = self.home / "runtime-state.sqlite"
        connection = open_projection(path)
        try:
            ProjectionRunner(connection, production_handlers()).apply_batch(events)
            self.assertEqual(connection.execute("SELECT count(*) FROM runtime_state_events").fetchone()[0], 3)
            self.assertEqual(connection.execute("SELECT terminal_state FROM runtime_pending_runs").fetchone()[0], "SUCCEEDED")
            self.assertEqual(connection.execute("SELECT count(*) FROM runtime_pending_run_events").fetchone()[0], 4)
            assistant = self._append(7, "session.message-appended", "session/session-1", {
                "schema": "SESSION_MESSAGE_APPENDED_V1", "session_id": "session-1", "message_id": "assistant-1",
                "role": "assistant", "turn_index": 1, "body_ref": reference, "body_hash": "d" * 64,
                "created_at": "2026-07-18T00:00:01Z",
            })
            ProjectionRunner(connection, production_handlers()).apply_batch((assistant,))
            self.assertEqual(connection.execute("SELECT count(*) FROM runtime_pending_runs").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM runtime_pending_run_events").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM runtime_state_events").fetchone()[0], 4)
        finally:
            connection.close()

    def test_signed_projection_pointer_is_required_and_tamper_evident(self) -> None:
        events = self._events()[:2]
        root = self.home / "signed-projections"
        building = root / "building" / "generation-signed.sqlite"
        connection = open_projection(building)
        ProjectionRunner(connection, production_handlers()).apply_batch(events)
        connection.close()
        pointer = ProjectionGenerationPublisher(
            root,
            authority_key_provider=self.provider,
        ).publish(
            generation_id="generation-signed",
            building_database=building,
            authority_checkpoint_commitment="d" * 64,
            journal_frontier=2,
            schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
            created_at="2026-07-18T00:01:00Z",
        )
        self.assertIn("auth_key_id", pointer)
        self.assertIn("auth_tag", pointer)
        self.assertEqual(len(pointer["database_sha256"]), 64)
        reader = ProjectionGenerationReader(
            root,
            authority_key_provider=self.provider,
            require_signed_pointer=True,
        )
        self.assertEqual(
            reader.select(authority_checkpoint_commitments=("d" * 64,)).pointer,
            pointer,
        )
        pointer_path = root / "current-generation.json"
        tampered = json.loads(pointer_path.read_text(encoding="utf-8"))
        tampered["journal_frontier"] = 1
        pointer_path.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaises(ProjectionGenerationError):
            reader.select(authority_checkpoint_commitments=("d" * 64,))

    def test_runtime_state_reader_uses_signed_projection_and_tail_without_full_history_scan(self) -> None:
        events = self._events()
        root = self.home / "projections"
        building = root / "building" / "generation-runtime-state.sqlite"
        connection = open_projection(building)
        ProjectionRunner(connection, production_handlers()).apply_batch(events[:1])
        connection.close()
        pointer = ProjectionGenerationPublisher(
            root,
            authority_key_provider=self.provider,
        ).publish(
            generation_id="generation-runtime-state",
            building_database=building,
            authority_checkpoint_commitment="d" * 64,
            journal_frontier=1,
            schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
            created_at="2026-07-18T00:01:00Z",
        )
        report = SimpleNamespace(
            checkpoint_commitment="d" * 64,
            authority_state=SimpleNamespace(
                journal_id=self.journal.journal_id,
                epoch=self.journal.epoch,
                head_position=events[-1].position,
            ),
            active_tail_events=events[1:],
        )
        context = ProductionRuntimeContext(
            self.home,
            SimpleNamespace(environment_kind="PRODUCTION"),
            {},
            self.provider,  # type: ignore[arg-type]
            SimpleNamespace(fast_start_report=report, events=events[1:]),
            SimpleNamespace(enabled=False),
            SimpleNamespace(),  # type: ignore[arg-type]
        )
        with mock.patch.object(
            context,
            "_verified_history_events",
            side_effect=AssertionError("full history scan is forbidden"),
        ):
            reader = context.open_runtime_state_reader()
        self.assertEqual(reader.head_position, events[-1].position)
        self.assertEqual(reader.reader_generation, "signed-projection-v2+authenticated-active-tail")
        self.assertEqual(reader.projection_generation_id, pointer["generation_id"])
        self.assertEqual([event.position for event in reader.events], [1, 2, 4])


if __name__ == "__main__":
    unittest.main()
