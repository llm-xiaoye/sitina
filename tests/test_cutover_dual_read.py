from __future__ import annotations

import dataclasses, unittest

from sitina.legacy.compare import ComparisonDisposition, ComparisonProfile, FixedFrontierComparisonError, compare_cutover_fixed_frontier
from sitina.security.key_provider import InMemoryKeyProvider
from tests.test_opt_v1 import vector


class Reader:
    def __init__(self,value): self.value=value
    def read_run(self,run_id,frontier): return dict(self.value)


def semantic():
    return {"terminal_status":"SUCCEEDED","task_count":1,"protocol_count":2,"effect_accounting":{"open":0},"checkpoint_hashes":["a"*64],"audit_status":"PASSED","evidence_hashes":["b"*64],"secret_scan_status":"PASSED"}


class CutoverDualReadTests(unittest.TestCase):
    def test_signed_fixed_frontier_report_binds_generations_and_profile(self) -> None:
        report=compare_cutover_fixed_frontier("run-1",Reader(semantic()),Reader(semantic()),signed_frontier=vector(10),profile=ComparisonProfile.cutover_v1(),legacy_reader_generation="legacy-ro-v1",journal_reader_generation="journal-v1",catalog_snapshot_hash="c"*64,comparison_binary_hash="d"*64,provider=InMemoryKeyProvider())
        self.assertEqual(report.result.disposition,ComparisonDisposition.MATCH); self.assertFalse(report.verify(InMemoryKeyProvider()))
        # Verification uses provider key identity; a foreign ephemeral provider fails.
        provider=InMemoryKeyProvider(); report=compare_cutover_fixed_frontier("run-1",Reader(semantic()),Reader(semantic()),signed_frontier=vector(10),profile=ComparisonProfile.cutover_v1(),legacy_reader_generation="legacy-ro-v1",journal_reader_generation="journal-v1",catalog_snapshot_hash="c"*64,comparison_binary_hash="d"*64,provider=provider)
        self.assertTrue(report.verify(provider))

    def test_catalog_profile_or_frontier_drift_invalidates_report(self) -> None:
        provider=InMemoryKeyProvider(); profile=ComparisonProfile.cutover_v1(); frontier=vector(10)
        report=compare_cutover_fixed_frontier("run-1",Reader(semantic()),Reader(semantic()),signed_frontier=frontier,profile=profile,legacy_reader_generation="legacy",journal_reader_generation="journal",catalog_snapshot_hash="c"*64,comparison_binary_hash="d"*64,provider=provider)
        with self.assertRaises(FixedFrontierComparisonError): report.validate_current(signed_frontier_hash="0"*64,profile_hash=profile.profile_hash,catalog_snapshot_hash="c"*64)

    def test_unapproved_mismatch_blocks_cutover(self) -> None:
        changed=semantic(); changed["terminal_status"]="FAILED"
        report=compare_cutover_fixed_frontier("run-1",Reader(semantic()),Reader(changed),signed_frontier=vector(10),profile=ComparisonProfile.cutover_v1(),legacy_reader_generation="legacy",journal_reader_generation="journal",catalog_snapshot_hash="c"*64,comparison_binary_hash="d"*64,provider=InMemoryKeyProvider())
        self.assertEqual(report.result.disposition,ComparisonDisposition.BLOCKING_MISMATCH)


if __name__ == "__main__": unittest.main()
