from __future__ import annotations

import dataclasses
import os
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sitina.cas.crypto import encrypt_object
from sitina.cas.gc import GCController
from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope, CommandStatus
from sitina.journal.local import CommandConflict, ExpectedStreamVersionConflict, LocalJournal, LocalJournalError, WriterPoisoned
from sitina.journal.model import EventEnvelope
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class LocalJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        self.provider = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.provider)
        self.gc_records = []
        self.gc = GCController(lambda event, payload: self.gc_records.append((event, payload)))
        self.journal = LocalJournal.open(self.home, self.auth, gc_controller=self.gc)

    def tearDown(self) -> None:
        try:
            self.journal.close()
        except Exception:
            pass
        shutil.rmtree(self.home)

    def command(self, command_id="cmd-1", payload=None):
        return CommandEnvelope(command_id, "tenant-1", "stream-1", "fixture.change", "actor-1", "2026-07-13T00:00:00Z", payload or {"x": 1})

    def event(self, event_id="event-1", refs=()):
        return EventEnvelope(event_id, "fixture.changed", "tenant-1", "stream-1", 0, 0, "2026-07-13T00:00:00Z", {"ok": True}, tuple(sorted(refs)))

    def test_append_continuity_idempotent_retry_and_conflict(self) -> None:
        command = self.command()
        first = self.journal.append(command, 0, [self.event()])
        self.assertEqual((first.first_position, first.last_position, first.last_stream_version), (1, 1, 1))
        self.assertEqual(self.journal.append(command, 0, [self.event()]), first)
        with self.assertRaises(CommandConflict):
            self.journal.append(self.command(payload={"x": 2}), 1, [self.event("event-2")])
        second = self.journal.append(self.command("cmd-2"), 1, [self.event("event-2")])
        self.assertEqual((second.first_position, second.last_stream_version), (2, 2))

    def test_expected_stream_version_and_single_stream_enforced(self) -> None:
        with self.assertRaises(ExpectedStreamVersionConflict):
            self.journal.append(self.command(), 2, [self.event()])
        wrong = dataclasses.replace(self.event(), stream_id="other-stream")
        with self.assertRaises(LocalJournalError):
            self.journal.append(self.command(), 0, [wrong])

    def test_object_before_event_exact_proof_and_gc_lease(self) -> None:
        cas = LocalCAS.open(self.home, self.provider)
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        receipt = cas.publish_verified(encrypted)
        reference = encrypted.reference.reference_id
        with self.assertRaises(LocalJournalError):
            self.journal.append(self.command(), 0, [self.event(refs=(reference,))])
        appended = self.journal.append(self.command(), 0, [self.event(refs=(reference,))], [receipt])
        self.assertEqual(appended.object_reference_manifest_hash, self.journal.query_command("cmd-1", self.command().command_request_hash).receipt.object_reference_manifest_hash)
        self.assertIn("gc.reference_root_committed", [record[0] for record in self.gc_records])

    def test_existing_root_proof_comes_only_from_verified_canonical_frame(self) -> None:
        cas = LocalCAS.open(self.home, self.provider)
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        published = cas.publish_verified(encrypted)
        first = self.journal.append(self.command(), 0, [self.event(refs=(encrypted.reference.reference_id,))], [published])
        proof = self.journal.lookup_existing_object_root_proof(encrypted.reference, first.frontier)
        second = self.journal.append(self.command("cmd-2"), 1, [self.event("event-2", (encrypted.reference.reference_id,))], [proof])
        self.assertEqual(second.last_position, 2)

    def test_query_unknown_and_conflict_are_canonical_states(self) -> None:
        command = self.command()
        self.assertEqual(self.journal.query_command(command.command_id, command.command_request_hash).status, CommandStatus.UNKNOWN)
        self.journal.append(command, 0, [self.event()])
        self.assertEqual(self.journal.query_command(command.command_id, command.command_request_hash).status, CommandStatus.COMMITTED)
        self.assertEqual(self.journal.query_command(command.command_id, "00" * 32).status, CommandStatus.CONFLICT)

    def test_expired_published_receipt_fails_before_frame_write(self) -> None:
        cas = LocalCAS.open(self.home, self.provider)
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        receipt = dataclasses.replace(cas.publish_verified(encrypted), expires_at="2000-01-01T00:00:00Z")
        with self.assertRaises(Exception):
            self.journal.append(self.command(), 0, [self.event(refs=(encrypted.reference.reference_id,))], [receipt])
        self.assertEqual(self.journal.head_position, 0)

    def test_concurrent_commands_are_serialized_into_one_gap_free_prefix(self) -> None:
        def submit(index):
            stream = f"stream-{index}"
            command = CommandEnvelope(f"parallel-cmd-{index}", "tenant-1", stream, "fixture.change", "actor-1", "2026-07-13T00:00:00Z", {"index": index})
            event = EventEnvelope(f"parallel-event-{index}", "fixture.changed", "tenant-1", stream, 0, 0, "2026-07-13T00:00:00Z", {})
            return self.journal.append(command, 0, [event])
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(submit, range(16)))
        self.assertEqual(sorted(receipt.last_position for receipt in receipts), list(range(1, 17)))
        self.assertEqual([event.position for event in self.journal.iter_events(0)], list(range(1, 17)))

    def test_rollover_publishes_owner_only_sparse_index(self) -> None:
        self.journal.append(self.command(), 0, [self.event()])
        sealed = self.journal.rollover()
        self.assertIsNotNone(sealed)
        indexes = list(self.home.joinpath("journal/indexes").glob("*.sidx"))
        self.assertEqual(len(indexes), 1)
        self.assertEqual(indexes[0].stat().st_mode & 0o7777, 0o600)


if __name__ == "__main__":
    unittest.main()
