from __future__ import annotations

import unittest

from sitina.cas.gc import GCController, GCFenceError, GCMarkFrontier, REQUIRED_CATALOGS
from sitina.journal.model import FrontierRef


def frontier(epoch=1):
    return GCMarkFrontier(
        FrontierRef("journal-1", 1, "local", 10, "11" * 32), epoch,
        {name: f"{name}-v1" for name in REQUIRED_CATALOGS}, "22" * 32, "33" * 32,
    )


class CASGCFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.records = []
        self.gc = GCController(lambda event, payload: self.records.append((event, payload)))

    def test_inflight_reference_lease_blocks_quarantine_until_frame_durable(self) -> None:
        lease = self.gc.with_reference_lease("cas:" + "aa" * 32)
        self.gc.mark(frontier(), [lease.reference_id])
        with self.assertRaises(GCFenceError):
            self.gc.quarantine(lease.reference_id)
        lease.commit(transaction_hash="44" * 32, position=11)
        with self.assertRaises(GCFenceError):
            self.gc.quarantine(lease.reference_id)

    def test_quarantining_blocks_new_reference_admission(self) -> None:
        reference = "cas:" + "bb" * 32
        self.gc.mark(frontier(), [reference])
        self.gc.quarantine(reference)
        with self.assertRaises(GCFenceError):
            self.gc.with_reference_lease(reference)

    def test_post_frontier_and_hold_read_backup_restore_rechecks_protect(self) -> None:
        refs = ["cas:" + value * 64 for value in ("a", "b", "c", "d", "e")]
        self.gc.mark(frontier(), refs)
        lease = self.gc.with_reference_lease(refs[0])
        lease.release()
        self.gc.add_hold(refs[1]); self.gc.add_read(refs[2]); self.gc.add_backup(refs[3]); self.gc.add_restore(refs[4])
        for reference in refs:
            with self.subTest(reference=reference), self.assertRaises(GCFenceError):
                self.gc.quarantine(reference)

    def test_incomplete_catalog_coverage_fails_before_mark(self) -> None:
        with self.assertRaises(GCFenceError):
            GCMarkFrontier(FrontierRef("journal-1", 1, "local", 1, "11" * 32), 1, {"journal": "v1"}, "22" * 32, "33" * 32)
        self.assertEqual(self.records, [])

    def test_restart_requires_journal_and_lease_reconciliation(self) -> None:
        controller = GCController(lambda *_args: None, reconciled=False)
        with self.assertRaises(GCFenceError):
            controller.with_reference_lease("cas:" + "aa" * 32)
        with self.assertRaises(GCFenceError):
            controller.reconcile(journal_verified=True, leases_reconciled=False)
        controller.reconcile(journal_verified=True, leases_reconciled=True)
        controller.with_reference_lease("cas:" + "aa" * 32).release()

    def test_control_transitions_are_journal_recorded(self) -> None:
        reference = "cas:" + "cc" * 32
        self.gc.mark(frontier(), [reference])
        self.gc.quarantine(reference)
        self.gc.sweep(reference)
        self.assertEqual([record[0] for record in self.records], ["gc.mark_frontier_frozen", "gc.object_quarantining", "gc.object_swept"])


if __name__ == "__main__":
    unittest.main()
