from __future__ import annotations

import unittest

from sitina.evidence.supplements import SupplementAssessment, SupplementBody, SupplementError, SupplementRecord, SupplementStream
from sitina.security.key_provider import InMemoryKeyProvider
from tests.test_evidence_seal import passed_assessment


def record(provider: InMemoryKeyProvider, previous: str | None = None, conclusion: str = "PASSED") -> SupplementRecord:
    body = SupplementBody(base_seal_hash="a" * 64, previous_record_hash=previous, coverage_frontier_hash="b" * 64, late_facts=("c" * 64,), dependency_refs=("d" * 64,), proposed_audit_conclusion=conclusion)
    assessment = SupplementAssessment(body_hash=body.body_hash, status="PASSED", verifier_id="verifier-1", policy_hash="e" * 64)
    handle = provider.issue_evidence_sealer_capability("evidence-sealer")
    return SupplementRecord.sign(body, assessment, provider, handle)


class EvidenceSupplementTests(unittest.TestCase):
    def test_hash_layers_exclude_self_and_bind_base_previous(self) -> None:
        provider = InMemoryKeyProvider(); item = record(provider)
        self.assertNotIn("supplement_body_hash", item.body.mapping())
        self.assertNotIn("supplement_record_hash", item.record_mapping())
        self.assertTrue(item.verify(provider))

    def test_stream_cas_and_previous_hash_prevent_forks(self) -> None:
        provider = InMemoryKeyProvider(); stream = SupplementStream("package-1", "a" * 64)
        first = record(provider); stream, _ = stream.accept(first, expected_version=0)
        second = record(provider, first.record_hash)
        with self.assertRaises(SupplementError): stream.accept(second, expected_version=0)
        stream, _ = stream.accept(second, expected_version=1)
        with self.assertRaises(SupplementError): stream.accept(record(provider, first.record_hash), expected_version=2)

    def test_late_contradiction_changes_current_audit_not_original_bytes(self) -> None:
        provider = InMemoryKeyProvider(); stream = SupplementStream("package-1", "a" * 64, original_terminal_hash="f" * 64, original_assessment_hash=passed_assessment().assessment_hash)
        original = (stream.base_seal_hash, stream.original_terminal_hash, stream.original_assessment_hash)
        stream, _ = stream.accept(record(provider, conclusion="CONTRADICTED"), expected_version=0)
        self.assertEqual(stream.current_audit, "CONTRADICTED")
        self.assertEqual((stream.base_seal_hash, stream.original_terminal_hash, stream.original_assessment_hash), original)


if __name__ == "__main__": unittest.main()
