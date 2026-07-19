from __future__ import annotations

import unittest

from sitina.archive.retention import ReplicaCopy, ReplicaPolicy, RetentionBlockers, evaluate_replica_set
from sitina.archive.retention_operations import OperationState, RetentionOperation, RetentionOperationError


def copies() -> tuple[ReplicaCopy, ...]:
    return (
        ReplicaCopy("copy-1", "fd-1", "r-1", "p-1", "admin-1", "key-1", 90, verified=True),
        ReplicaCopy("copy-2", "fd-2", "r-2", "p-2", "admin-2", "key-2", 95, verified=True),
        ReplicaCopy("copy-3", "fd-3", "r-1", "p-3", "admin-3", "key-3", 99, verified=True),
    )


class ReplicaEvictionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ReplicaPolicy(min_count=2, min_fault_domains=2, min_regions=2, min_providers=2, min_admin_domains=2, min_key_domains=2, max_verification_age=20)

    def test_replica_policy_checks_all_independent_dimensions(self) -> None:
        result = evaluate_replica_set(copies(), self.policy, now=100)
        self.assertTrue(result.compliant)
        for field in ("fault_domain", "region", "provider", "administrative_domain", "key_domain"):
            self.assertIn(field, result.dimension_counts)

    def test_eviction_after_set_must_remain_compliant_and_bundle_is_not_canonical_residency(self) -> None:
        self.assertTrue(evaluate_replica_set(copies()[1:], self.policy, now=100).compliant)
        self.assertFalse(evaluate_replica_set(copies()[2:], self.policy, now=100).compliant)
        bundle = ReplicaCopy("bundle-1", "fd-x", "r-x", "p-x", "a-x", "k-x", 100, verified=True, canonical_residency=False)
        self.assertFalse(evaluate_replica_set((bundle, *copies()[:1]), self.policy, now=100).compliant)

    def test_holds_incomplete_evidence_active_jobs_and_cross_refs_block(self) -> None:
        for blockers in (
            RetentionBlockers(legal_holds=("hold-1",)), RetentionBlockers(evidence_complete=False),
            RetentionBlockers(active_jobs=("job-1",)), RetentionBlockers(cross_run_refs=("run-2",)),
        ):
            with self.subTest(blockers=blockers): self.assertFalse(blockers.clear)

    def test_retention_operation_lifecycle_is_exact_and_dry_run_only(self) -> None:
        operation = RetentionOperation.propose("operation-1", kind="HOT_EVICTION", object_ids=("object-1",), copy_ids=("copy-1",), policy_snapshot_hash="a" * 64, catalog_snapshot_hash="b" * 64, frontier_hash="c" * 64, hold_snapshot_hash="d" * 64, approval_quorum=2, executor_id="dry-run-executor", deadline=200)
        operation = operation.assess(blockers=RetentionBlockers(), replica_compliant_after=True, current_catalog_hash="b" * 64, current_hold_hash="d" * 64)
        operation = operation.approve(("approver-1", "approver-2"), now=100)
        operation = operation.fence(fence="fence-1", current_catalog_hash="b" * 64, current_hold_hash="d" * 64)
        operation, receipt = operation.execute_dry_run(outcome="ACKNOWLEDGED")
        self.assertFalse(receipt["physical_delete_executed"])
        operation = operation.reconcile(evidence_hash="e" * 64, physical_absence_claimed=False)
        operation = operation.verify(verifier_id="verifier-1", dry_run_verified=True)
        operation = operation.complete()
        self.assertEqual(operation.state, OperationState.COMPLETED)
        self.assertFalse(operation.destructive_capability_present)

    def test_lost_ack_drift_new_hold_or_stale_approval_never_completes(self) -> None:
        base = RetentionOperation.propose("operation-2", kind="DELETE", object_ids=("object-1",), copy_ids=(), policy_snapshot_hash="a" * 64, catalog_snapshot_hash="b" * 64, frontier_hash="c" * 64, hold_snapshot_hash="d" * 64, approval_quorum=1, executor_id="dry-run-executor", deadline=101)
        assessed = base.assess(blockers=RetentionBlockers(), replica_compliant_after=True, current_catalog_hash="b" * 64, current_hold_hash="d" * 64)
        with self.assertRaises(RetentionOperationError): assessed.approve(("approver-1",), now=102)
        approved = assessed.approve(("approver-1",), now=100)
        with self.assertRaises(RetentionOperationError): approved.fence(fence="fence", current_catalog_hash="changed", current_hold_hash="d" * 64)
        fenced = approved.fence(fence="fence", current_catalog_hash="b" * 64, current_hold_hash="d" * 64)
        lost, _ = fenced.execute_dry_run(outcome="ACK_LOST")
        self.assertIn(lost.state, {OperationState.RECONCILING, OperationState.FAILED_UNKNOWN})
        with self.assertRaises(RetentionOperationError): lost.complete()


if __name__ == "__main__": unittest.main()
