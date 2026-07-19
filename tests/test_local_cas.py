from __future__ import annotations

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import CASCollision, LocalCAS
from sitina.cas.model import CASError, ExistingDurableObjectRootProof, PublishedObjectReceipt
from sitina.security.key_provider import InMemoryKeyProvider


class LocalCASTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        self.provider = InMemoryKeyProvider()
        self.cas = LocalCAS.open(self.home, self.provider)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.home)

    def test_verified_no_replace_publication_and_open(self) -> None:
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        receipt = self.cas.publish_verified(encrypted)
        receipt.assert_valid(encrypted.reference.reference_id)
        self.assertEqual(self.cas.open_verified(encrypted.reference), b"payload")
        self.assertIn("NO_REPLACE", receipt.durability_profile)

    def test_new_commitment_and_object_directories_are_owner_only(self) -> None:
        publication = self.cas.publish_plaintext(
            b"owner-only-layout",
            tenant_id="tenant-1",
            purpose_class="test",
        )
        commitment_path = self.cas._commitment_path(publication.commitment_index_key)
        object_path = self.cas._object_path(publication.receipt.object_ref.object_id)
        self.assertEqual(commitment_path.parent.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(object_path.parent.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(commitment_path.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(object_path.stat().st_mode & 0o7777, 0o600)

    def test_exact_existing_is_idempotent_under_concurrency(self) -> None:
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        with ThreadPoolExecutor(max_workers=4) as pool:
            receipts = list(pool.map(lambda _: self.cas.publish_verified(encrypted), range(8)))
        self.assertEqual({item.object_ref for item in receipts}, {encrypted.reference})
        self.assertEqual(self.cas.open_verified(encrypted.reference), b"payload")

    def test_identity_collision_is_an_incident(self) -> None:
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        target = self.cas._object_path(encrypted.reference.object_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"different")
        with self.assertRaises(CASCollision):
            self.cas.publish_verified(encrypted)
        self.assertEqual(len(list((self.cas.root / "collisions").glob("*.json"))), 1)

    def test_missing_and_symlink_objects_fail_closed(self) -> None:
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        with self.assertRaises(CASError):
            self.cas.open_verified(encrypted.reference)
        target = self.cas._object_path(encrypted.reference.object_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(self.home / ".sitina-bplus-disposable-v1")
        with self.assertRaises(CASError):
            self.cas.open_verified(encrypted.reference)

    def test_receipt_and_existing_root_proof_cannot_be_constructed_by_callers(self) -> None:
        encrypted = encrypt_object(b"payload", self.provider, tenant_id="tenant-1")
        with self.assertRaises(CASError):
            PublishedObjectReceipt(encrypted.reference, "x", "0" * 64, "0" * 64, "x", "x", "x", True, True)
        with self.assertRaises(CASError):
            ExistingDurableObjectRootProof(encrypted.reference, "journal-1", "0" * 64, 1, 1, "0" * 64)
        self.assertFalse(hasattr(self.cas, "lookup_existing_object_root_proof"))


if __name__ == "__main__":
    unittest.main()
