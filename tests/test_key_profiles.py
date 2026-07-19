from __future__ import annotations

import unittest

from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider, KeyProviderError, KeyPurpose


class KeyProfileTests(unittest.TestCase):
    def test_runtime_writer_capability_is_journal_auth_current_only(self) -> None:
        provider = InMemoryKeyProvider()
        capability = provider.runtime_journal_capability
        provider.current_descriptor(KeyPurpose.JOURNAL_AUTH, capability)
        with self.assertRaises(KeyProviderError):
            provider.current_descriptor(KeyPurpose.EVIDENCE_SIGNING, capability)
        with self.assertRaises(KeyProviderError):
            provider.current_descriptor(KeyPurpose.AUTHORITY_SIGNING, capability)

    def test_environment_and_namespace_key_ids_do_not_cross_resolve(self) -> None:
        left = InMemoryKeyProvider(environment="test", namespace="a")
        right = InMemoryKeyProvider(environment="test", namespace="b")
        key_id = left.current_descriptor(KeyPurpose.CAS_KEK).key_id
        with self.assertRaises(KeyProviderError):
            right.symmetric_for_id(key_id, KeyPurpose.CAS_KEK)

    def test_journal_auth_rotation_retains_history_and_fails_after_destruction(self) -> None:
        provider = InMemoryKeyProvider()
        auth = JournalAuthProvider(provider)
        key_id, tag = auth.authenticate("journal-1", 1, "11" * 32)
        transition = auth.rotate(at_segment_boundary=True, epoch=1, previous_segment_commitment="22" * 32, effective_position=2, policy_hash="33" * 32)
        self.assertNotEqual(transition["old_key_id"], transition["new_key_id"])
        self.assertTrue(auth.verify("journal-1", 1, key_id, "11" * 32, tag))
        provider.destroy(KeyPurpose.JOURNAL_AUTH, 1)
        self.assertFalse(auth.verify("journal-1", 1, key_id, "11" * 32, tag))

    def test_rotation_between_segment_boundaries_is_rejected(self) -> None:
        with self.assertRaises(KeyProviderError):
            JournalAuthProvider(InMemoryKeyProvider()).rotate(at_segment_boundary=False, epoch=1, previous_segment_commitment="00" * 32, effective_position=1, policy_hash="11" * 32)

    def test_evidence_and_authority_signatures_are_purpose_isolated(self) -> None:
        provider = InMemoryKeyProvider()
        key_id, signature = provider.sign(KeyPurpose.EVIDENCE_SIGNING, b"evidence")
        self.assertTrue(provider.verify(key_id, KeyPurpose.EVIDENCE_SIGNING, b"evidence", signature))
        with self.assertRaises(KeyProviderError):
            provider.verify(key_id, KeyPurpose.AUTHORITY_SIGNING, b"evidence", signature)


if __name__ == "__main__":
    unittest.main()
