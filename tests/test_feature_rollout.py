from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.compatibility.capabilities import FormatCapabilityRegistry
from sitina.compatibility.errors import FeatureGateError, StaleFencingToken
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.compatibility.rollout import JournalFeatureRollout
from sitina.journal.local import LocalJournal
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class JournalFeatureRolloutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("feature-rollout\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.journal = LocalJournal.open(self.home, JournalAuthProvider(self.keys))
        self.leases = CompatibilityLeaseRegistry(self.home)
        self.formats = FormatCapabilityRegistry.load(Path(__file__).resolve().parents[1] / "config/format_capabilities.json")

    def tearDown(self) -> None:
        self.journal.close()

    def _lease(self, process_id: str, capabilities: tuple[str, ...], *, token: int = 1) -> None:
        self.leases.register(
            RuntimeCompatibilityLease.build(
                process_id=process_id,
                binary_version="2.0.0",
                reader_capabilities=capabilities,
                writer_capabilities=capabilities,
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T01:00:00Z",
                fencing_token=token,
            )
        )

    def _rollout(self) -> JournalFeatureRollout:
        return JournalFeatureRollout(
            self.journal,
            self.leases,
            self.formats,
            process_id="writer",
            fencing_token=1,
            binary_version="2.0.0",
            actor="test-operator",
            goal_thread_id="goal-thread-1",
        )

    def test_prepare_activate_are_idempotent_journal_facts_with_format_rollback_semantics(self) -> None:
        self._lease("writer", ("authority-checkpoint-v1", "projection-v2"))
        rollout = self._rollout()
        prepared = rollout.prepare(
            "authority_checkpoint_v1_write",
            required_reader_capabilities=("authority-checkpoint-v1",),
            occurred_at="2026-07-18T00:00:01Z",
        )
        self.assertEqual(prepared.state, "PREPARED")
        activated = rollout.activate(
            "authority_checkpoint_v1_write",
            occurred_at="2026-07-18T00:00:02Z",
        )
        self.assertEqual(activated.state, "ACTIVATED")
        self.assertTrue(activated.rollback_safe_after_first_write)
        head = self.journal.head_position
        self.assertEqual(
            rollout.activate(
                "authority_checkpoint_v1_write",
                occurred_at="2026-07-18T00:00:03Z",
            ).activated_position,
            activated.activated_position,
        )
        self.assertEqual(self.journal.head_position, head)
        replayed = FeatureActivationRegistry.from_journal_events(self.journal.iter_events(0))
        self.assertTrue(replayed.state("authority_checkpoint_v1_write").rollback_safe_after_first_write)

    def test_incompatible_live_reader_blocks_prepare_before_journal_append(self) -> None:
        self._lease("writer", ("projection-v2",))
        self._lease("old-reader", ("authority-checkpoint-v1",))
        before = self.journal.head_position
        with self.assertRaises(FeatureGateError):
            self._rollout().prepare(
                "projection_v2_build",
                required_reader_capabilities=("projection-v2",),
                occurred_at="2026-07-18T00:00:01Z",
            )
        self.assertEqual(self.journal.head_position, before)

    def test_stale_writer_fence_cannot_prepare(self) -> None:
        self._lease("writer", ("projection-v2",), token=1)
        self.leases.release("writer", fencing_token=1)
        with self.assertRaises(StaleFencingToken):
            self._rollout().prepare(
                "projection_v2_build",
                required_reader_capabilities=("projection-v2",),
                occurred_at="2026-07-18T00:00:01Z",
            )


if __name__ == "__main__":
    unittest.main()
