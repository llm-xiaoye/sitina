from __future__ import annotations

import unittest

from sitina.protocols.merge import MergeError, MergeOperation, MergeOperationKind, MergeProtocol, MergeState


class MergeProtocolTests(unittest.TestCase):
    def test_only_schema_declared_safe_operation_kinds_merge(self) -> None:
        merge, _ = MergeProtocol.open("merge-1", "document-1", 3, "11" * 32, allowed_kinds=(MergeOperationKind.APPEND_ONLY,))
        merge, _ = merge.propose("proposal-1", (MergeOperation("/notes", MergeOperationKind.APPEND_ONLY, "21" * 32),))
        merge, _ = merge.validate("proposal-1", schema_valid=True, evidence_ref="31" * 32)
        merged, _ = merge.merge("proposal-1")
        self.assertEqual(merged.state, MergeState.MERGED)
        unsafe, _ = MergeProtocol.open("merge-2", "document-1", 3, "11" * 32, allowed_kinds=(MergeOperationKind.APPEND_ONLY,))
        with self.assertRaises(MergeError):
            unsafe.propose("proposal-2", (MergeOperation("/value", MergeOperationKind.COMMUTATIVE, "22" * 32),))

    def test_different_json_paths_do_not_automatically_authorize_merge(self) -> None:
        merge, _ = MergeProtocol.open("merge-1", "document-1", 3, "11" * 32, allowed_kinds=(MergeOperationKind.APPEND_ONLY,))
        with self.assertRaises(MergeError):
            merge.propose("proposal-1", (MergeOperation("/a", MergeOperationKind.UNDECLARED, "21" * 32), MergeOperation("/b", MergeOperationKind.UNDECLARED, "22" * 32)))

    def test_failed_merge_routes_arbitration_obligation(self) -> None:
        merge, _ = MergeProtocol.open("merge-1", "document-1", 3, "11" * 32, allowed_kinds=(MergeOperationKind.APPEND_ONLY,))
        failed, event = merge.fail("schema-conflict")
        self.assertEqual(failed.state, MergeState.ESCALATED)
        self.assertTrue(event["arbitration_obligation_id"].startswith("obligation-arbitration-"))


if __name__ == "__main__":
    unittest.main()
