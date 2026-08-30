from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.commands.model import CommandEnvelope
from sitina.cas.gc import SemanticRoot, SemanticRootIndex
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.journal.fast_start import (
    AuthorityIntegrityError,
    FastStartLoader,
    FullJournalVerifier,
    JournalFastStartMaintainer,
    MerkleBlockIndex,
    RollbackDetected,
    RollbackAnchorStore,
    RolloverPolicy,
)
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, event_replay_projection_hash
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from sitina.security.macos_keychain import MemoryKeychainBackend


class JournalFastStartV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.keys)
        self.keychain = MemoryKeychainBackend()
        self.anchor = RollbackAnchorStore(self.keychain, journal_id="journal-shadow-1")

    def _append(self, journal: LocalJournal, index: int) -> None:
        command = CommandEnvelope(
            f"cmd-{index}",
            "tenant-1",
            "stream-1",
            "fixture.change",
            "actor-1",
            "2026-07-18T00:00:00Z",
            {"index": index},
        )
        event = EventEnvelope(
            f"event-{index}",
            "fixture.changed",
            "tenant-1",
            "stream-1",
            0,
            0,
            "2026-07-18T00:00:00Z",
            {"index": index},
        )
        journal.append(command, index - 1, [event])

    def _sealed_fixture(self):
        journal = LocalJournal.open(self.home, self.auth)
        self._append(journal, 1)
        self._append(journal, 2)
        maintainer = JournalFastStartMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="a" * 64,
        )
        checkpoint = maintainer.rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:01:00Z",
            verified_at="2026-07-18T00:01:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
        )
        self._append(journal, 3)
        journal.close()
        segment = next((self.home / "journal/sealed").glob("*.seg"))
        return checkpoint, segment

    def test_fast_start_reads_metadata_and_active_tail_not_sealed_bytes(self) -> None:
        checkpoint, segment = self._sealed_fixture()
        reads: list[Path] = []
        fast = FastStartLoader(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            sealed_segment_read_observer=reads.append,
        ).load()
        full = FullJournalVerifier(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
        ).verify()
        self.assertEqual(fast.authority_state.head_position, 3)
        self.assertEqual(fast.authority_state, full.authority_state)
        self.assertEqual([event.position for event in full.verified_events], [1, 2, 3])
        self.assertEqual([event.position for event in fast.verified_events], [])
        self.assertEqual(fast.journal_events_verified, 1)
        self.assertEqual(fast.journal_bytes_scanned, (self.home / "journal/active.seg").stat().st_size)
        self.assertLess(fast.journal_bytes_scanned, segment.stat().st_size)
        self.assertEqual(reads, [])
        self.assertTrue(fast.fast_start_checkpoint_used)
        self.assertEqual(checkpoint["schema"], "SITINA_AUTHORITY_CHECKPOINT_V1")
        self.assertFalse(any("projection" in key.lower() for key in checkpoint))

    def test_fast_start_exact_replay_uses_checkpoint_projection(self) -> None:
        self._sealed_fixture()
        report = FastStartLoader(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        ).load()
        reopened = LocalJournal.open(self.home, self.auth, fast_start_report=report)
        try:
            command = CommandEnvelope(
                "cmd-1", "tenant-1", "stream-1", "fixture.change", "actor-1",
                "2026-07-18T00:00:00Z", {"index": 1},
            )
            event = EventEnvelope(
                "event-1", "fixture.changed", "tenant-1", "stream-1", 0, 0,
                "2026-07-18T00:00:00Z", {"index": 1},
            )
            replay = reopened.append(command, 0, (event,))
            self.assertEqual(replay.transaction_id, next(
                value["transaction_id"] for value in report.command_receipts if value["command_id"] == "cmd-1"
            ))
            with self.assertRaises(Exception):
                reopened.append(command, 0, (EventEnvelope(
                    "event-1", "fixture.changed", "tenant-1", "stream-1", 0, 0,
                    "2026-07-18T00:00:00Z", {"index": True},
                ),))
        finally:
            reopened.close()

    def test_second_rollover_carries_prior_projection_when_history_is_not_materialized(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        self._append(journal, 1)
        self._append(journal, 2)
        maintainer = JournalFastStartMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="a" * 64,
        )
        maintainer.rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:01:00Z",
            verified_at="2026-07-18T00:01:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
        )
        self._append(journal, 3)
        # Model a Fast Start writer whose sealed history is represented only
        # by the authenticated prior checkpoint projection.  The on-disk
        # segment still contains commands 1 and 2; they must not be replaced
        # with an empty projection during the next rollover.
        journal._events = [event for event in journal._events if event.event_id == "event-3"]
        second = maintainer.rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:02:00Z",
            verified_at="2026-07-18T00:02:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
        )
        command_index_path = self.home / "journal/indexes" / (
            "authority-command-idempotency-" + second["command_idempotency_index_commitment"] + ".json"
        )
        values = json.loads(command_index_path.read_text(encoding="utf-8"))["data"]
        self.assertEqual(values["cmd-1"]["event_projection"][0]["event_id"], "event-1")
        self.assertEqual(values["cmd-2"]["event_projection"][0]["event_id"], "event-2")
        self.assertEqual(values["cmd-3"]["event_projection"][0]["event_id"], "event-3")
        self.assertEqual(
            values["cmd-1"]["event_projection_hash"],
            event_replay_projection_hash(values["cmd-1"]["event_projection"]),
        )
        journal.close()

    def test_typed_semantic_roots_are_checkpoint_bound_and_tail_ready(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        self._append(journal, 1)
        semantic = SemanticRoot("active-session", "session-1", "cas:" + "e" * 64, 1, "event-1")
        maintainer = JournalFastStartMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="a" * 64,
        )
        checkpoint = maintainer.rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:01:00Z",
            verified_at="2026-07-18T00:01:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
            semantic_active_roots=(semantic.mapping(),),
        )
        journal.close()
        report = FastStartLoader(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        ).load()
        roots = SemanticRootIndex.from_fast_start(report)
        self.assertEqual(roots.roots, (semantic,))
        self.assertEqual(roots.commitment, report.semantic_active_roots_commitment)
        self.assertEqual(report.active_roots_index_commitment, checkpoint["active_roots_index_commitment"])

    def test_feature_activation_control_state_survives_checkpoint_fast_start(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        stream_id = "runtime/features/authority_checkpoint_v1_write"
        prepared = {
            "schema": "RUNTIME_FEATURE_PREPARED_V1",
            "feature": "authority_checkpoint_v1_write",
            "required_reader_capabilities": ["authority-checkpoint-v1"],
        }
        activated = {
            "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
            "feature": "authority_checkpoint_v1_write",
            "rollback_floor_version": 1,
        }
        journal.append(
            CommandEnvelope(
                "feature-prepare-command",
                "system",
                stream_id,
                "runtime.feature-prepare",
                "operator",
                "2026-07-18T00:00:00Z",
                prepared,
            ),
            0,
            [
                EventEnvelope(
                    "feature-prepare-event",
                    "runtime.feature-prepared",
                    "system",
                    stream_id,
                    0,
                    0,
                    "2026-07-18T00:00:00Z",
                    prepared,
                )
            ],
        )
        journal.append(
            CommandEnvelope(
                "feature-activate-command",
                "system",
                stream_id,
                "runtime.feature-activate",
                "operator",
                "2026-07-18T00:00:01Z",
                activated,
            ),
            1,
            [
                EventEnvelope(
                    "feature-activate-event",
                    "runtime.feature-activated",
                    "system",
                    stream_id,
                    0,
                    0,
                    "2026-07-18T00:00:01Z",
                    activated,
                )
            ],
        )
        JournalFastStartMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="a" * 64,
        ).rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:01:00Z",
            verified_at="2026-07-18T00:01:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="1",
            rollback_floor_version="1",
        )
        journal.close()
        report = FastStartLoader(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        ).load()
        self.assertEqual(
            [event.event_type for event in report.authority_control_events],
            ["runtime.feature-prepared", "runtime.feature-activated"],
        )
        state = FeatureActivationRegistry.from_journal_events(report.authority_control_events).state(
            "authority_checkpoint_v1_write"
        )
        self.assertIsNotNone(state)
        self.assertEqual(state.state, "ACTIVATED")

    def test_certificate_checkpoint_missing_segment_and_rollback_are_rejected(self) -> None:
        checkpoint, segment = self._sealed_fixture()
        certificate = next((self.home / "journal/certificates").glob("*.json"))
        original_certificate = certificate.read_text(encoding="utf-8")
        value = json.loads(original_certificate)
        value["event_count"] += 1
        certificate.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(AuthorityIntegrityError):
            FastStartLoader(
                self.home,
                journal_authenticator=self.auth,
                authority_key_provider=self.keys,
                rollback_anchor=self.anchor,
            ).load()
        certificate.write_text(original_certificate, encoding="utf-8")

        checkpoint_path = next((self.home / "journal/checkpoints").glob("*.json"))
        original_checkpoint = checkpoint_path.read_text(encoding="utf-8")
        changed = json.loads(original_checkpoint)
        changed["verified_through_position"] -= 1
        checkpoint_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(AuthorityIntegrityError):
            FastStartLoader(
                self.home,
                journal_authenticator=self.auth,
                authority_key_provider=self.keys,
                rollback_anchor=self.anchor,
            ).load()
        checkpoint_path.write_text(original_checkpoint, encoding="utf-8")

        missing = segment.with_suffix(".missing")
        segment.rename(missing)
        with self.assertRaises(AuthorityIntegrityError):
            FastStartLoader(
                self.home,
                journal_authenticator=self.auth,
                authority_key_provider=self.keys,
                rollback_anchor=self.anchor,
            ).load()
        missing.rename(segment)

        self.anchor.force_test_anchor(
            latest_epoch=1,
            latest_checkpoint_sequence=checkpoint["checkpoint_sequence"] + 1,
            latest_checkpoint_commitment="f" * 64,
            active_format_capabilities_hash="c" * 64,
        )
        with self.assertRaises(RollbackDetected):
            FastStartLoader(
                self.home,
                journal_authenticator=self.auth,
                authority_key_provider=self.keys,
                rollback_anchor=self.anchor,
            ).load()

    def test_merkle_block_proof_verifies_and_rejects_modified_block(self) -> None:
        _checkpoint, segment = self._sealed_fixture()
        index = MerkleBlockIndex.load(next((self.home / "journal/indexes").glob("*.merkle.json")))
        raw = segment.read_bytes()
        block_number = 0
        block = raw[: index.block_size]
        proof = index.proof(block_number)
        self.assertTrue(index.verify_block(block_number, block, proof))
        changed = bytes([block[0] ^ 1]) + block[1:]
        self.assertFalse(index.verify_block(block_number, changed, proof))

    def test_projection_corruption_cannot_block_authority_recovery(self) -> None:
        self._sealed_fixture()
        projection = self.home / "projections/current/damaged.sqlite"
        projection.parent.mkdir(parents=True)
        projection.write_bytes(b"not sqlite")
        report = FastStartLoader(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        ).load()
        self.assertEqual(report.authority_state.head_position, 3)

    def test_rollover_policy_covers_bytes_events_and_scan_latency(self) -> None:
        policy = RolloverPolicy(max_active_bytes=128 * 1024 * 1024, max_active_events=100_000, max_startup_scan_ms=500)
        self.assertEqual(policy.reason(active_bytes=128 * 1024 * 1024, active_events=1, startup_scan_ms=1), "active-bytes")
        self.assertEqual(policy.reason(active_bytes=1, active_events=100_000, startup_scan_ms=1), "active-events")
        self.assertEqual(policy.reason(active_bytes=1, active_events=1, startup_scan_ms=501), "startup-scan-latency")
        self.assertIsNone(policy.reason(active_bytes=1, active_events=1, startup_scan_ms=1))

    def test_checkpoint_indexes_stop_at_sealed_frontier_when_append_races_certificate(self) -> None:
        journal = LocalJournal.open(self.home, self.auth)
        self._append(journal, 1)
        outer = self

        class RacingMaintainer(JournalFastStartMaintainer):
            def _certificate(self, segment, active_journal, *, verified_at):
                outer._append(active_journal, 2)
                return super()._certificate(segment, active_journal, verified_at=verified_at)

        RacingMaintainer(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
            schema_registry_hash="a" * 64,
        ).rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:01:00Z",
            verified_at="2026-07-18T00:01:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
        )
        journal.close()
        fast = FastStartLoader(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
            rollback_anchor=self.anchor,
        ).load()
        full = FullJournalVerifier(
            self.home,
            journal_authenticator=self.auth,
            authority_key_provider=self.keys,
        ).verify()
        self.assertEqual(fast.verified_through_position, 1)
        self.assertEqual([event.position for event in fast.active_tail_events], [2])
        self.assertEqual(fast.authority_state, full.authority_state)


if __name__ == "__main__":
    unittest.main()
