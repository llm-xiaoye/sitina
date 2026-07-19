from __future__ import annotations

import dataclasses
import unittest

from sitina.authority.model import AuthorityControlFacts, AuthorityState, LegacyAuthorityFact
from sitina.authority.resolver import AuthorityResolver, AuthorityResolverError


def facts(**changes: object) -> AuthorityControlFacts:
    values = {
        "control_stream_readable": True, "signatures_valid": True, "continuity_verified": True,
        "conflicting_evidence": False, "same_identity_different_hash": False,
        "legacy": LegacyAuthorityFact(True, "a" * 64, "b" * 64), "cutover_absence_proven": True,
        "prepared": False, "command_id": None, "request_hash": None, "genesis_hash": None,
        "snapshot_hash": None, "outcome_status": "ABSENT", "outcome_verified": False,
        "outcome_command_id": None, "outcome_request_hash": None, "outcome_genesis_hash": None,
        "outcome_snapshot_hash": None, "input_frontier_hash": "c" * 64,
    }
    values.update(changes)
    return AuthorityControlFacts(**values)


class AuthorityResolverTests(unittest.TestCase):
    def setUp(self) -> None: self.resolver = AuthorityResolver("resolver-binary-hash", "resolver-profile-v1", ttl=10)

    def test_legacy_requires_verified_fact_and_cutover_absence(self) -> None:
        result = self.resolver.resolve(facts(), now=100)
        self.assertEqual(result.state, AuthorityState.LEGACY_WRITER_AUTHORIZED)
        self.assertTrue(result.authorizes_legacy); self.assertFalse(result.authorizes_journal)
        self.assertEqual(self.resolver.resolve(facts(cutover_absence_proven=False), now=100).writer_count, 0)

    def test_prepared_pending_or_ack_unknown_never_authorizes_a_writer(self) -> None:
        for status, expected in (("ABSENT", AuthorityState.CUTOVER_PREPARED_NO_WRITER), ("PENDING", AuthorityState.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER), ("UNKNOWN", AuthorityState.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER)):
            with self.subTest(status=status):
                result = self.resolver.resolve(facts(prepared=True, command_id="cutover-1", request_hash="d"*64, genesis_hash="e"*64, snapshot_hash="f"*64, outcome_status=status, cutover_absence_proven=False), now=100)
                self.assertEqual(result.state, expected); self.assertEqual(result.writer_count, 0)

    def test_exact_verified_committed_outcome_alone_authorizes_journal(self) -> None:
        base = facts(prepared=True, command_id="cutover-1", request_hash="d"*64, genesis_hash="e"*64, snapshot_hash="f"*64, outcome_status="COMMITTED", outcome_verified=True, outcome_command_id="cutover-1", outcome_request_hash="d"*64, outcome_genesis_hash="e"*64, outcome_snapshot_hash="f"*64, cutover_absence_proven=False)
        result = self.resolver.resolve(base, now=100)
        self.assertEqual(result.state, AuthorityState.JOURNAL_WRITER_AUTHORIZED); self.assertEqual(result.writer_count, 1)
        self.assertEqual(self.resolver.resolve(dataclasses.replace(base, outcome_request_hash="0"*64), now=100).writer_count, 0)

    def test_unreadable_corrupt_conflicting_or_uncertain_state_requires_recovery(self) -> None:
        for changes in ({"control_stream_readable":False},{"signatures_valid":False},{"continuity_verified":False},{"conflicting_evidence":True},{"same_identity_different_hash":True}):
            with self.subTest(changes=changes):
                result=self.resolver.resolve(facts(**changes),now=100)
                self.assertEqual(result.state,AuthorityState.RECOVERY_REQUIRED_NO_WRITER); self.assertEqual(result.writer_count,0)

    def test_stale_cached_resolution_cannot_open_writer(self) -> None:
        result=self.resolver.resolve(facts(),now=100)
        with self.assertRaises(AuthorityResolverError): result.assert_fresh(now=111)
        stale=self.resolver.resolve_cached(result,now=111)
        self.assertEqual(stale.state,AuthorityState.RECOVERY_REQUIRED_NO_WRITER)


if __name__ == "__main__": unittest.main()

