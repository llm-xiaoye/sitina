from __future__ import annotations

import os
import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.commands.gateway import CommandGateway, CommandPlan, RetryableNotAccepted
from sitina.commands.model import CommandEnvelope, CommandStatus
from sitina.commands.outcomes import CommandOutcomeResolver
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes
from sitina.projections.schema import open_projection
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class CommandOutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        self.journal = LocalJournal.open(self.home, JournalAuthProvider(InMemoryKeyProvider()))
        self.gateway = CommandGateway(self.journal)

    def tearDown(self) -> None:
        self.journal.close(); shutil.rmtree(self.home)

    @staticmethod
    def command(payload=None):
        return CommandEnvelope("cmd-1", "tenant-1", "stream-1", "fixture.change", "actor-1", "2026-07-13T00:00:00Z", payload or {"x": 1})

    @staticmethod
    def accepted(_command):
        return CommandPlan(events=(EventEnvelope("event-1", "fixture.changed", "tenant-1", "stream-1", 0, 0, "2026-07-13T00:00:00Z", {}),))

    def test_all_five_command_states(self) -> None:
        command = self.command()
        self.assertEqual(self.gateway.query(command.command_id, command.command_request_hash).status, CommandStatus.UNKNOWN)
        committed = self.gateway.submit(command, 0, self.accepted)
        self.assertEqual(committed.status, CommandStatus.COMMITTED)
        self.assertEqual(self.gateway.query(command.command_id, "00" * 32).status, CommandStatus.CONFLICT)

        home = self.home / "reject"; home.mkdir(); (home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        rejected_journal = LocalJournal.open(home, JournalAuthProvider(InMemoryKeyProvider()))
        rejected = CommandGateway(rejected_journal).submit(command, 0, lambda _: CommandPlan(rejection_reason="policy-deny"))
        self.assertEqual(rejected.status, CommandStatus.REJECTED)
        rejected_replay = CommandGateway(rejected_journal).submit(
            command, 0, lambda _: CommandPlan(rejection_reason="policy-deny")
        )
        self.assertEqual(rejected_replay.receipt, rejected.receipt)
        self.assertEqual(CommandGateway(rejected_journal).query(command.command_id, command.command_request_hash).status, CommandStatus.REJECTED)
        rejected_journal.close()

        home2 = self.home / "retry"; home2.mkdir(); (home2 / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        retry_journal = LocalJournal.open(home2, JournalAuthProvider(InMemoryKeyProvider()))
        def retry(_): raise RetryableNotAccepted("dependency unavailable before acceptance")
        retryable = CommandGateway(retry_journal).submit(command, 0, retry)
        self.assertEqual(retryable.status, CommandStatus.RETRYABLE_NOT_ACCEPTED)
        self.assertEqual(retry_journal.head_position, 0)
        retry_journal.close()

    def test_lost_ack_retry_rebuilds_projection_before_journal_replay(self) -> None:
        calls = []
        def planner(command): calls.append(command.command_id); return self.accepted(command)
        command = self.command()
        first = self.gateway.submit(command, 0, planner)
        second = self.gateway.submit(command, 0, planner)
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(calls, ["cmd-1", "cmd-1"])

    def test_sqlite_cache_miss_or_forged_row_cannot_override_canonical(self) -> None:
        cache = open_projection(self.home / "cache.sqlite")
        resolver = CommandOutcomeResolver(self.journal, cache)
        command = self.command()
        cache.execute("INSERT INTO command_outcomes VALUES(?,?,?,?,?,?)", (command.command_id, command.command_request_hash, "COMMITTED", "11" * 32, 1, 1))
        self.assertEqual(resolver.query(command.command_id, command.command_request_hash).status, CommandStatus.UNKNOWN)
        resolver.canonical_coverage_available = False
        self.assertEqual(resolver.query(command.command_id, command.command_request_hash).status, CommandStatus.UNKNOWN)
        cache.close()

    def test_same_id_different_hash_is_conflict_without_planner(self) -> None:
        command = self.command(); self.gateway.submit(command, 0, self.accepted)
        called = []
        result = self.gateway.submit(self.command({"x": 2}), 1, lambda _: called.append(True) or self.accepted(command))
        self.assertEqual(result.status, CommandStatus.CONFLICT)
        self.assertEqual(called, [True])

    def test_rejection_replay_uses_stable_event_identity(self) -> None:
        command = self.command()
        first = self.gateway.submit(command, 0, lambda _: CommandPlan(rejection_reason="stable-deny"))
        self.assertEqual(first.status, CommandStatus.REJECTED)
        events = tuple(self.journal.iter_events())
        self.assertEqual(len(events), 1)
        identity = hashlib.sha256(canonical_json_bytes({
            "command_id": command.command_id,
            "request_hash": command.command_request_hash,
            "reason_code": "stable-deny",
        })).hexdigest()
        self.assertEqual(events[0].event_id, "event-rejected-" + identity)
        second = self.gateway.submit(command, 0, lambda _: CommandPlan(rejection_reason="stable-deny"))
        self.assertEqual(second.receipt, first.receipt)
        self.assertEqual(tuple(self.journal.iter_events()), events)


if __name__ == "__main__": unittest.main()
