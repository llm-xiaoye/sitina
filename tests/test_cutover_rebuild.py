from __future__ import annotations

import unittest

from sitina.authority.model import AuthorityState
from sitina.legacy.cutover_verify import CutoverRecoverySimulator, ProjectionRebuilder, RebuildError


class CutoverRebuildTests(unittest.TestCase):
    def test_projection_rebuild_uses_only_journal_and_cas(self) -> None:
        events=({"position":1,"command_id":"c1","outcome":"OK","object_refs":["o1"]},{"position":2,"command_id":"c1","outcome":"OK","object_refs":[]})
        result=ProjectionRebuilder().rebuild(events,cas_objects={"o1":b"value"})
        self.assertEqual(result.positions,(1,2)); self.assertEqual(result.command_outcomes,{"c1":"OK"}); self.assertEqual(result.external_call_count,0)
        self.assertTrue(result.idempotency_preserved)

    def test_missing_cas_object_fails_closed(self) -> None:
        with self.assertRaises(RebuildError): ProjectionRebuilder().rebuild(({"position":1,"command_id":"c","outcome":"OK","object_refs":["missing"]},),cas_objects={})

    def test_lost_ack_recovers_same_command_or_no_writer_across_restart(self) -> None:
        simulator=CutoverRecoverySimulator("cutover-1","a"*64,"b"*64,"c"*64)
        unknown=simulator.submit(crash_window="AFTER_SUBMISSION_BEFORE_COMMIT")
        self.assertEqual(unknown.state,AuthorityState.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER)
        self.assertEqual(simulator.restart().recover("cutover-1","a"*64).state,AuthorityState.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER)
        committed=CutoverRecoverySimulator("cutover-2","d"*64,"e"*64,"f"*64).submit(crash_window="AFTER_COMMIT_BEFORE_ACK")
        self.assertEqual(committed.state,AuthorityState.JOURNAL_WRITER_AUTHORIZED)

    def test_same_command_different_hash_never_recovers(self) -> None:
        simulator=CutoverRecoverySimulator("cutover-1","a"*64,"b"*64,"c"*64); simulator.submit(crash_window="AFTER_SUBMISSION_BEFORE_COMMIT")
        self.assertEqual(simulator.recover("cutover-1","0"*64).state,AuthorityState.RECOVERY_REQUIRED_NO_WRITER)


if __name__ == "__main__": unittest.main()
