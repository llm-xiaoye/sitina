from __future__ import annotations

import os
import shutil
import tempfile
import unittest
import errno
from unittest import mock
from pathlib import Path

from sitina.commands.model import CommandEnvelope, CommandStatus
from sitina.journal.local import LocalJournal, SimulatedCrash, WriterPoisoned
from sitina.journal.model import EventEnvelope
from sitina.journal.recovery import JournalRecoveryError
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class JournalCrashMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        self.provider = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.provider)

    def tearDown(self) -> None:
        shutil.rmtree(self.home)

    @staticmethod
    def command(command_id="cmd-1"):
        return CommandEnvelope(command_id, "tenant-1", "stream-1", "fixture.change", "actor-1", "2026-07-13T00:00:00Z", {"x": 1})

    @staticmethod
    def event(event_id="event-1"):
        return EventEnvelope(event_id, "fixture.changed", "tenant-1", "stream-1", 0, 0, "2026-07-13T00:00:00Z", {})

    def test_complete_unacknowledged_frame_is_adopted_and_lost_ack_is_idempotent(self) -> None:
        def fault(boundary, _journal):
            if boundary == "after_frame_fsync_before_ack":
                raise SimulatedCrash("lost ACK")
        first = LocalJournal.open(self.home, self.auth, fault_injector=fault)
        command = self.command()
        with self.assertRaises(SimulatedCrash):
            first.append(command, 0, [self.event()])
        with self.assertRaises(WriterPoisoned):
            first.append(self.command("cmd-2"), 0, [self.event("event-2")])
        first.close()
        recovered = LocalJournal.open(self.home, self.auth)
        result = recovered.query_command(command.command_id, command.command_request_hash)
        self.assertEqual(result.status, CommandStatus.COMMITTED)
        self.assertEqual(recovered.append(command, 0, [self.event()]), result.receipt)
        recovered.close()

    def test_incomplete_active_tail_is_truncated_but_media_corruption_is_not(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        receipt = journal.append(self.command(), 0, [self.event()])
        journal.close()
        active = self.home / "journal/active.seg"
        with active.open("ab") as handle:
            handle.write(b"SITB")
        recovered = LocalJournal.open(self.home, self.auth)
        self.assertEqual(recovered.head_position, receipt.last_position)
        recovered.close()
        raw = bytearray(active.read_bytes()); raw[30] ^= 1; active.write_bytes(raw)
        with self.assertRaises(JournalRecoveryError):
            LocalJournal.open(self.home, self.auth)

    def test_rollover_crash_boundaries_recover_to_sealed_segments_and_one_active(self) -> None:
        boundaries = (
            "rollover_after_group_sync", "rollover_after_footer_sync", "rollover_after_no_replace_publish",
            "rollover_after_directory_sync", "rollover_after_new_active_sync", "rollover_after_new_active_publish",
            "rollover_after_index_build",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                home = self.home / f"case-{index}"; home.mkdir(); (home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
                def fault(name, _journal, selected=boundary):
                    if name == selected:
                        raise SimulatedCrash(selected)
                journal = LocalJournal.open(home, self.auth, fault_injector=fault)
                journal.append(self.command(f"cmd-{index}"), 0, [self.event(f"event-{index}")])
                with self.assertRaises(SimulatedCrash):
                    journal.rollover()
                try: journal.close()
                except Exception: pass
                recovered = LocalJournal.open(home, self.auth)
                self.assertEqual(recovered.head_position, 1)
                self.assertLessEqual(len(list((home / "journal").glob("active.seg"))), 1)
                recovered.close()

    def test_eintr_and_short_write_are_retried_to_a_complete_frame(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        real_write = os.write
        calls = 0
        def flaky(fd, data):
            nonlocal calls
            if fd != journal._active_fd:
                return real_write(fd, data)
            calls += 1
            if calls == 1:
                raise InterruptedError()
            if calls == 2:
                return real_write(fd, data[: max(1, len(data) // 2)])
            return real_write(fd, data)
        with mock.patch("sitina.journal.local.os.write", side_effect=flaky):
            receipt = journal.append(self.command(), 0, [self.event()])
        self.assertEqual(receipt.last_position, 1)
        self.assertGreaterEqual(calls, 3)
        journal.close()

    def test_enospc_and_eio_poison_writer_until_fresh_recovery(self) -> None:
        for index, code in enumerate((errno.ENOSPC, errno.EIO)):
            with self.subTest(errno=code):
                home = self.home / f"io-{index}"; home.mkdir(); (home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
                journal = LocalJournal.open(home, self.auth)
                with mock.patch("sitina.journal.local.os.write", side_effect=OSError(code, "injected")):
                    with self.assertRaises(OSError): journal.append(self.command(f"cmd-io-{index}"), 0, [self.event(f"event-io-{index}")])
                with self.assertRaises(WriterPoisoned): journal.append(self.command("later"), 0, [self.event("later")])
                journal.close()
                recovered = LocalJournal.open(home, self.auth)
                self.assertEqual(recovered.head_position, 0)
                recovered.close()

    def test_unknown_fsync_result_poisons_then_recovery_adopts_complete_frame(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        real_fsync = os.fsync
        def uncertain(fd):
            if fd == journal._active_fd:
                raise OSError(errno.EIO, "unknown fsync result")
            return real_fsync(fd)
        command = self.command()
        with mock.patch("sitina.journal.local.os.fsync", side_effect=uncertain):
            with self.assertRaises(OSError): journal.append(command, 0, [self.event()])
        with self.assertRaises(WriterPoisoned): journal.append(self.command("later"), 0, [self.event("later")])
        journal.close()
        recovered = LocalJournal.open(self.home, self.auth)
        self.assertEqual(recovered.query_command(command.command_id, command.command_request_hash).status, CommandStatus.COMMITTED)
        recovered.close()

    def test_rollover_directory_sync_failure_requires_recovery(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        journal.append(self.command(), 0, [self.event()])
        with mock.patch.object(journal, "_sync_directory", side_effect=OSError(errno.EIO, "directory sync failed")):
            with self.assertRaises(OSError): journal.rollover()
        journal.close()
        recovered = LocalJournal.open(self.home, self.auth)
        self.assertEqual(recovered.head_position, 1)
        recovered.close()


if __name__ == "__main__":
    unittest.main()
