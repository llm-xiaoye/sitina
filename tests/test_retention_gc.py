from __future__ import annotations

import unittest

from sitina.cas.gc import GCController, GCFenceError, GCMarkFrontier, REQUIRED_CATALOGS
from sitina.journal.model import FrontierRef


def frontier(**changes: object) -> GCMarkFrontier:
    values={"journal_frontier":FrontierRef("journal-1",1,"local",10,"a"*64),"gc_epoch":2,"catalog_versions":{name:"v1" for name in REQUIRED_CATALOGS},"hold_snapshot_hash":"b"*64,"policy_hash":"c"*64,"signed_frontier_hash":"d"*64,"mark_started_position":11,"catalog_snapshot_hash":"e"*64}
    values.update(changes); return GCMarkFrontier(**values)


class RetentionGCTests(unittest.TestCase):
    def setUp(self) -> None: self.records=[]; self.gc=GCController(lambda e,p:self.records.append((e,p)))

    def test_fixed_frontier_epoch_catalog_and_hold_snapshot_are_in_commitment(self) -> None:
        cycle=self.gc.mark(frontier(),("object-1",))
        self.assertEqual(cycle.frontier.gc_epoch,2); self.assertEqual(cycle.frontier.mark_started_position,11)
        self.assertEqual(len(cycle.frontier.commitment),64)

    def test_required_index_unavailable_catalog_drift_or_hold_drift_invalidates(self) -> None:
        with self.assertRaises(GCFenceError): self.gc.mark(frontier(catalogs_readable=False),("object-1",))
        self.gc.mark(frontier(),("object-1",))
        with self.assertRaises(GCFenceError): self.gc.validate_frozen_snapshot(current_catalog_versions={**{name:"v1" for name in REQUIRED_CATALOGS},"cas":"v2"},current_hold_snapshot_hash="b"*64)

    def test_post_frontier_root_is_never_lost(self) -> None:
        self.gc.mark(frontier(),("object-1",)); lease=self.gc.with_reference_lease("object-1"); lease.commit(transaction_hash="f"*64,position=12)
        with self.assertRaises(GCFenceError): self.gc.propose_retention_operation("object-1",operation_id="retention-1",grace_elapsed=True,second_confirmation=True)

    def test_gc_only_proposes_dry_run_retention_operation_and_never_deletes(self) -> None:
        self.gc.mark(frontier(),("object-1",))
        proposal=self.gc.propose_retention_operation("object-1",operation_id="retention-1",grace_elapsed=True,second_confirmation=True)
        self.assertEqual(proposal["schema"],"GC_RETENTION_OPERATION_PROPOSED_V1")
        self.assertFalse(proposal["delete_authorized"]); self.assertFalse(proposal["physical_delete_executed"])


if __name__ == "__main__": unittest.main()
