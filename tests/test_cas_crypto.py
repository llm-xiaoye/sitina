from __future__ import annotations

import unittest
from dataclasses import replace

from sitina.cas.crypto import decrypt_object, encrypt_object, rewrap_object
from sitina.cas.model import CASError
from sitina.security.key_provider import InMemoryKeyProvider, KeyPurpose


class CASCryptoTests(unittest.TestCase):
    def test_round_trip_uses_random_object_keys_and_stable_tenant_commitment(self) -> None:
        provider = InMemoryKeyProvider()
        left = encrypt_object(b"secret payload", provider, tenant_id="tenant-1")
        right = encrypt_object(b"secret payload", provider, tenant_id="tenant-1")
        self.assertEqual(decrypt_object(left, provider), b"secret payload")
        self.assertNotEqual(left.reference.object_id, right.reference.object_id)
        self.assertEqual(left.reference.plaintext_commitment, right.reference.plaintext_commitment)
        self.assertNotIn(b"secret payload", left.object_bytes())

    def test_tampering_and_wrong_provider_fail_closed(self) -> None:
        provider = InMemoryKeyProvider()
        encrypted = encrypt_object(b"payload", provider, tenant_id="tenant-1")
        damaged = replace(encrypted, ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]))
        with self.assertRaises(CASError):
            decrypt_object(damaged, provider)
        with self.assertRaises(CASError):
            decrypt_object(encrypted, InMemoryKeyProvider(namespace="other"))

    def test_rewrap_changes_only_envelope_and_preserves_object_bytes(self) -> None:
        provider = InMemoryKeyProvider()
        encrypted = encrypt_object(b"payload", provider, tenant_id="tenant-1")
        raw = encrypted.object_bytes()
        provider.rotate(KeyPurpose.CAS_KEK)
        rewrapped = rewrap_object(encrypted, provider)
        self.assertEqual(rewrapped.object_bytes(), raw)
        self.assertEqual(rewrapped.reference, encrypted.reference)
        self.assertNotEqual(rewrapped.envelope.envelope_id, encrypted.envelope.envelope_id)
        self.assertEqual(decrypt_object(rewrapped, provider), b"payload")

    def test_crypto_erasure_attestation_and_decrypt_failure(self) -> None:
        provider = InMemoryKeyProvider()
        encrypted = encrypt_object(b"payload", provider, tenant_id="tenant-1")
        attestation = provider.destroy(KeyPurpose.CAS_KEK, 1)
        self.assertTrue(attestation["destroyed"])
        with self.assertRaises(CASError):
            decrypt_object(encrypted, provider)


if __name__ == "__main__":
    unittest.main()
