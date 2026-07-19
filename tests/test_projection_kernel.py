from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.projections.rebuild import ProjectionGeneration, semantic_checksum
from sitina.projections.runner import ProjectionRunner
from sitina.projections.schema import ProjectionError, open_projection
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class ProjectionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        provider = InMemoryKeyProvider(); self.journal = LocalJournal.open(self.home, JournalAuthProvider(provider))
        self.events = []
        for index in range(2):
            command = CommandEnvelope(f"cmd-{index}", "tenant-1", "stream-1", "fixture.set", "actor-1", "2026-07-13T00:00:00Z", {"value": str(index)})
            event = EventEnvelope(f"event-{index}", "fixture.set", "tenant-1", "stream-1", 0, 0, "2026-07-13T00:00:00Z", {"value": str(index)})
            self.journal.append(command, index, [event]); self.events.extend(self.journal.iter_events(index))
        self.connection = open_projection(self.home / "projection.sqlite")

    def tearDown(self) -> None:
        self.connection.close(); self.journal.close(); shutil.rmtree(self.home)

    @staticmethod
    def handler(connection, event):
        connection.execute(
            "INSERT INTO fixture_values(stream_id,value) VALUES(?,?) ON CONFLICT(stream_id) DO UPDATE SET value=excluded.value",
            (event.stream_id, event.payload["value"]),
        )

    def test_handler_failure_rolls_back_rows_and_offset(self) -> None:
        failures = []
        def broken(connection, event):
            self.handler(connection, event)
            raise RuntimeError("handler failed")
        runner = ProjectionRunner(self.connection, {"fixture.set": broken}, record_failure=failures.append)
        with self.assertRaises(RuntimeError): runner.apply_batch(self.events[:1])
        self.assertEqual(runner.offset, 0)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM fixture_values").fetchone()[0], 0)
        self.assertTrue(failures[0]["blocking"])

    def test_projection_database_is_owner_only_at_creation(self) -> None:
        self.assertEqual(self.home.joinpath("projection.sqlite").stat().st_mode & 0o7777, 0o600)

    def test_in_memory_projection_does_not_create_or_chmod_a_filesystem_path(self) -> None:
        connection = open_projection(":memory:")
        try:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM projection_offsets").fetchone()[0],
                1,
            )
            self.assertFalse(Path(":memory:").exists())
        finally:
            connection.close()

    def test_gap_fails_and_catalog_stores_metadata_not_payload(self) -> None:
        runner = ProjectionRunner(self.connection, {"fixture.set": self.handler})
        with self.assertRaises(ProjectionError): runner.apply_batch(self.events[1:])
        runner.apply_batch(self.events)
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(event_catalog)")}
        self.assertNotIn("payload", columns)
        self.assertEqual(runner.offset, 2)

    def test_disposable_rebuild_is_semantically_equal_and_switches_generation(self) -> None:
        frontier = self.journal.query_command("cmd-1", CommandEnvelope("cmd-1", "tenant-1", "stream-1", "fixture.set", "actor-1", "2026-07-13T00:00:00Z", {"value": "1"}).command_request_hash).receipt.frontier
        root = self.home / "generations"
        first = ProjectionGeneration.build(root, self.journal, frontier, {"fixture.set": self.handler})
        second = ProjectionGeneration.build(root, self.journal, frontier, {"fixture.set": self.handler})
        self.assertEqual(first.semantic_checksum, second.semantic_checksum)
        pointer = second.switch(root)
        self.assertIn(second.generation_id, pointer.read_text())


if __name__ == "__main__": unittest.main()
