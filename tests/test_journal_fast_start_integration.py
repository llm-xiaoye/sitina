from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sitina.archive.production_backup import derive_verified_frontier
from sitina.commands.model import CommandEnvelope, CommandStatus
from sitina.journal.fast_start import (
    AuthorityClockGuard,
    AutomaticRolloverCoordinator,
    FastStartLoader,
    JournalEpochTransition,
    JournalFastStartMaintainer,
    RollbackAnchorStore,
    RolloverPolicy,
)
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.operations.phase6b import ProductionAuthorityReader
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from sitina.security.macos_keychain import MemoryKeychainBackend


class JournalFastStartIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.keys)
        self.anchor = RollbackAnchorStore(MemoryKeychainBackend(), journal_id="journal-shadow-1")

    @staticmethod
    def _event(event_id: str, event_type: str, stream_id: str, payload: dict) -> EventEnvelope:
        return EventEnvelope(
            event_id,
            event_type,
            "system",
            stream_id,
            0,
            0,
            "2026-07-18T00:00:00Z",
            payload,
        )

    def _authority_fixture(self):
        journal = LocalJournal.open(self.home, self.auth)
        prepared_payload = {
            "genesis_hash": "1" * 64,
            "snapshot_hash": "2" * 64,
            "fence_record_hash": "3" * 64,
            "cutover_command_id": "cutover-command-1",
            "cutover_request_hash": "9" * 64,
            "business_writer_count": 0,
            "migration_frontier_hash": "4" * 64,
        }
        prepared_command = CommandEnvelope(
            "prepare-command-1", "system", "authority/control", "authority.cutover.prepare",
            "operator", "2026-07-18T00:00:00Z", prepared_payload,
        )
        journal.append(
            prepared_command,
            0,
            [self._event("prepared-event-1", "authority.cutover.prepared", "authority/control", prepared_payload)],
        )
        committed_payload = {
            "command_id": "cutover-command-1",
            "request_hash": "9" * 64,
            "genesis_hash": "1" * 64,
            "snapshot_hash": "2" * 64,
            "migration_frontier_hash": "4" * 64,
            "outcome": "COMMITTED",
        }
        committed_command = CommandEnvelope(
            "cutover-command-1", "system", "authority/control", "authority.cutover.commit",
            "operator", "2026-07-18T00:00:00Z", committed_payload,
        )
        request_hash = "9" * 64
        journal.append(
            committed_command,
            1,
            [self._event("committed-event-1", "authority.cutover.committed", "authority/control", committed_payload)],
        )
        historical_command = CommandEnvelope(
            "historical-command-1", "system", "historical/stream-1", "historical.append",
            "operator", "2026-07-18T00:00:30Z", {"historical": True},
        )
        journal.append(
            historical_command,
            0,
            [self._event("historical-event-1", "historical.appended", "historical/stream-1", {"historical": True})],
        )
        maintainer = JournalFastStartMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="5" * 64,
        )
        maintainer.rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:01:00Z",
            verified_at="2026-07-18T00:01:00Z",
            authority_control_state_hash="6" * 64,
            active_format_capabilities_hash="7" * 64,
            fencing_state_hash="8" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
        )
        tail_command = CommandEnvelope(
            "tail-command-1", "system", "tail/stream-1", "tail.append", "operator",
            "2026-07-18T00:02:00Z", {"tail": True},
        )
        journal.append(
            tail_command,
            0,
            [self._event("tail-event-1", "tail.appended", "tail/stream-1", {"tail": True})],
        )
        journal.close()
        return committed_command, request_hash

    def test_production_authority_and_writer_reopen_use_checkpoint_plus_tail(self) -> None:
        committed_command, request_hash = self._authority_fixture()
        result = ProductionAuthorityReader.resolve(
            self.home,
            self.auth,
            journal_id="journal-shadow-1",
            epoch=1,
            command_id="cutover-command-1",
            request_hash=request_hash,
            genesis_hash="1" * 64,
            snapshot_hash="2" * 64,
            fence_record_hash="3" * 64,
            now=1_800_000_000,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        )
        self.assertEqual(result.read_mode, "FAST_START_CHECKPOINT_PLUS_ACTIVE_TAIL")
        self.assertEqual(result.journal_bytes_scanned, (self.home / "journal/active.seg").stat().st_size)
        self.assertTrue(result.resolution.authorizes_journal)
        self.assertIsNotNone(result.fast_start_report)

        reopened = LocalJournal.open(self.home, self.auth, fast_start_report=result.fast_start_report)
        self.assertFalse(reopened.history_complete_in_memory)
        self.assertEqual(reopened.head_position, 4)
        outcome = reopened.query_command(committed_command.command_id, committed_command.command_request_hash)
        self.assertEqual(outcome.status, CommandStatus.COMMITTED)
        command = CommandEnvelope(
            "authority-command-after-fast-start", "system", "authority/control", "authority.noop",
            "operator", "2026-07-18T00:03:00Z", {"noop": True},
        )
        receipt = reopened.append(
            command,
            2,
            [self._event("authority-event-after-fast-start", "authority.noop", "authority/control", {"noop": True})],
        )
        self.assertEqual(receipt.last_position, 5)
        self.assertEqual(len(tuple(reopened.iter_events_authoritative_slow())), 5)
        reopened.close()

    def test_backup_frontier_uses_authenticated_fast_start_head_not_materialized_event_count(self) -> None:
        _committed_command, request_hash = self._authority_fixture()
        result = ProductionAuthorityReader.resolve(
            self.home,
            self.auth,
            journal_id="journal-shadow-1",
            epoch=1,
            command_id="cutover-command-1",
            request_hash=request_hash,
            genesis_hash="1" * 64,
            snapshot_hash="2" * 64,
            fence_record_hash="3" * 64,
            now=1_800_000_000,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        )
        context = SimpleNamespace(
            home=self.home,
            authority=result,
            events=result.events,
            genesis=SimpleNamespace(journal_id="journal-shadow-1", epoch_root="epoch-1"),
        )
        self.assertLess(len(context.events), result.fast_start_report.authority_state.head_position)
        frontier = derive_verified_frontier(context)
        self.assertEqual(frontier.position, 4)
        self.assertEqual(frontier.commitment, result.fast_start_report.authority_state.last_transaction_hash)

    def test_automatic_rollover_runs_asynchronously_and_produces_certificate_checkpoint(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        maintainer = JournalFastStartMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="a" * 64,
        )
        coordinator = AutomaticRolloverCoordinator(
            maintainer,
            policy=RolloverPolicy(max_active_bytes=1, max_active_events=1, max_startup_scan_ms=10_000),
            checkpoint_context=lambda _reason: {
                "created_at": "2026-07-18T00:01:00Z",
                "verified_at": "2026-07-18T00:01:00Z",
                "authority_control_state_hash": "b" * 64,
                "active_format_capabilities_hash": "c" * 64,
                "fencing_state_hash": "d" * 64,
                "minimum_writer_version": "2",
                "rollback_floor_version": "2",
            },
        )
        journal.rollover_coordinator = coordinator
        command = CommandEnvelope(
            "auto-rollover-command", "system", "stream/auto", "fixture.auto", "operator",
            "2026-07-18T00:00:00Z", {"value": 1},
        )
        journal.append(command, 0, [self._event("auto-rollover-event", "fixture.auto", "stream/auto", {"value": 1})])
        coordinator.wait()
        self.assertEqual(coordinator.last_reason, "active-bytes")
        self.assertEqual(len(tuple((self.home / "journal/sealed").glob("*.seg"))), 1)
        self.assertEqual(len(tuple((self.home / "journal/certificates").glob("*.json"))), 1)
        self.assertEqual(len(tuple((self.home / "journal/checkpoints").glob("*.json"))), 1)
        journal.close()

    def test_close_never_releases_writer_lock_before_rollover_has_a_definite_outcome(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)

        class Coordinator:
            timeout = "not-called"

            def wait(self, timeout=5.0):
                self.timeout = timeout

        coordinator = Coordinator()
        journal.rollover_coordinator = coordinator
        journal.close()
        self.assertIsNone(coordinator.timeout)

    def test_dual_key_epoch_proofs_and_clock_rollback_are_fail_closed(self) -> None:
        auth = JournalAuthProvider(self.keys)
        rotation = auth.rotate(
            at_segment_boundary=True,
            epoch=1,
            previous_segment_commitment="a" * 64,
            effective_position=10,
            policy_hash="b" * 64,
        )
        self.assertTrue(auth.verify_rotation(rotation))
        self.assertFalse(auth.verify_rotation({**rotation, "effective_position": 11}))
        epoch = JournalEpochTransition.create(
            self.keys,
            journal_id="journal-shadow-1",
            old_epoch=1,
            previous_segment_commitment="c" * 64,
            effective_position=11,
            policy_hash="d" * 64,
        )
        self.assertTrue(JournalEpochTransition.verify(self.keys, epoch))
        self.assertEqual(epoch["new_epoch"], 2)

        clock = AuthorityClockGuard()
        self.assertIsNone(clock.observe(wall_utc="2026-07-18T12:00:00Z", monotonic_ns=100))
        anomaly = clock.observe(wall_utc="2026-07-18T11:00:00Z", monotonic_ns=200)
        self.assertEqual(anomaly["event_type"], "clock.anomaly-detected")
        self.assertFalse(anomaly["writer_permission_extended"])
        self.assertEqual(clock.conservative_wall_utc, "2026-07-18T12:00:00Z")


if __name__ == "__main__":
    unittest.main()
