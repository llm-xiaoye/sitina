from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sitina.journal.model import EventEnvelope
from sitina.orchestrator.bplus_production import BPlusProductionRuntimeError, ProductionRuntimeContext
from sitina.projections.coverage import MissingRequiredProjectionHandler
from sitina.projections.generations import ProjectionGenerationPublisher
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers
from sitina.projections.runner import ProjectionRunner
from sitina.projections.schema import open_projection


def _event(position: int, stream_version: int, event_type: str, payload: dict[str, object]) -> EventEnvelope:
    return EventEnvelope(
        f"event-{position}",
        event_type,
        "default",
        f"run/{payload['run_id']}",
        stream_version,
        position,
        f"2026-07-18T00:00:0{position}Z",
        payload,
        event_hash=f"{position:x}" * 64,
        journal_auth_key_id="fixture-key",
        journal_auth_tag=f"{position:x}" * 64,
    )


class ListProjectionFastStartTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        self.events = (
            _event(1, 1, "run.created", {"schema": "RUN_CREATED_V1", "run_id": "run-old", "goal_hash": "a" * 64, "agent_count": 2}),
            _event(2, 1, "run.created", {"schema": "RUN_CREATED_V1", "run_id": "run-still-active", "goal_hash": "b" * 64, "agent_count": 1}),
            _event(3, 2, "run.terminal", {"schema": "RUN_TERMINAL_V1", "run_id": "run-old", "status": "terminal"}),
            _event(4, 1, "run.created", {"schema": "RUN_CREATED_V1", "run_id": "run-tail", "goal_hash": "c" * 64, "agent_count": 3}),
        )
        root = self.home / "projections"
        building = root / "building" / "generation.sqlite"
        connection = open_projection(building)
        ProjectionRunner(connection, production_handlers()).apply_batch(self.events[:2])
        connection.close()
        ProjectionGenerationPublisher(root).publish(
            generation_id="generation-checkpoint",
            building_database=building,
            authority_checkpoint_commitment="d" * 64,
            journal_frontier=2,
            schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
            created_at="2026-07-18T00:01:00Z",
        )

    def _context(self) -> ProductionRuntimeContext:
        report = SimpleNamespace(
            checkpoint_commitment="d" * 64,
            authority_state=SimpleNamespace(head_position=4),
            active_tail_events=self.events[2:],
        )
        authority = SimpleNamespace(fast_start_report=report, events=self.events[2:])
        return ProductionRuntimeContext(
            self.home,
            None,  # type: ignore[arg-type]
            {},
            None,  # type: ignore[arg-type]
            authority,
            SimpleNamespace(enabled=False),
            SimpleNamespace(),  # type: ignore[arg-type]
        )

    def test_list_reads_verified_projection_and_exact_active_tail(self) -> None:
        runs = self._context().list_runs()
        self.assertEqual([item["run_id"] for item in runs], ["run-tail", "run-old", "run-still-active"])
        self.assertEqual(next(item for item in runs if item["run_id"] == "run-old")["phase"], "done")
        self.assertTrue(all(item["reader_generation"] == "projection-v2+active-tail" for item in runs))
        self.assertTrue(all(item["fallback_used"] is False for item in runs))

    def test_checkpoint_mismatch_fails_instead_of_returning_incomplete_tail(self) -> None:
        context = self._context()
        context.authority.fast_start_report.checkpoint_commitment = "e" * 64
        with self.assertRaisesRegex(BPlusProductionRuntimeError, "verified Projection"):
            context.list_runs()

    def test_historical_fast_run_created_upcasts_message_identity_and_single_agent(self) -> None:
        path = self.home / "fast-historical.sqlite"
        connection = open_projection(path)
        event = _event(
            1,
            1,
            "run.created",
            {
                "schema": "FAST_CONVERSATION_RUN_OPENED_V1",
                "run_id": "fast-historical",
                "message_hash": "e" * 64,
            },
        )
        ProjectionRunner(connection, production_handlers()).apply_batch((event,))
        row = connection.execute(
            "SELECT goal_hash,agent_count FROM bplus_runs WHERE run_id='fast-historical'"
        ).fetchone()
        connection.close()
        self.assertEqual(row, ("e" * 64, 1))

    def test_unknown_incomplete_run_created_fails_as_missing_required_compatibility(self) -> None:
        path = self.home / "unknown-incomplete.sqlite"
        connection = open_projection(path)
        event = _event(1, 1, "run.created", {"run_id": "unknown-incomplete"})
        with self.assertRaisesRegex(MissingRequiredProjectionHandler, "cannot supply"):
            ProjectionRunner(connection, production_handlers()).apply_batch((event,))
        connection.close()

    def test_historical_zero_agent_local_run_remains_projectable(self) -> None:
        path = self.home / "zero-agent-historical.sqlite"
        connection = open_projection(path)
        event = _event(
            1,
            1,
            "run.created",
            {"run_id": "zero-agent", "goal_hash": "f" * 64, "agent_count": 0},
        )
        ProjectionRunner(connection, production_handlers()).apply_batch((event,))
        row = connection.execute(
            "SELECT goal_hash,agent_count FROM bplus_runs WHERE run_id='zero-agent'"
        ).fetchone()
        connection.close()
        self.assertEqual(row, ("f" * 64, 0))


if __name__ == "__main__":
    unittest.main()
