from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.cas.crypto import encrypt_object, rewrap_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import CASError
from sitina.cas.packs import MetadataPackReader, MetadataPackWriter, PackError, PackWriteDisabled
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.security.key_provider import InMemoryKeyProvider, KeyPurpose


def _activated_alias_packs(home: Path) -> FeatureActivationRegistry:
    leases = CompatibilityLeaseRegistry(home)
    leases.register(
        RuntimeCompatibilityLease.build(
            process_id="alias-pack-test",
            binary_version="2.0.0",
            reader_capabilities=("alias-pack-v1",),
            writer_capabilities=("alias-pack-v1",),
            started_at="2026-07-18T00:00:00Z",
            lease_expires_at="2026-07-18T02:00:00Z",
            fencing_token=1,
        )
    )
    activations = FeatureActivationRegistry()
    activations.prepare(
        "alias_pack_v1_write",
        required_reader_capabilities=("alias-pack-v1",),
        leases=leases,
        now="2026-07-18T00:01:00Z",
        journal_position=1,
        journal_control_event={
            "schema": "RUNTIME_FEATURE_PREPARED_V1",
            "event_type": "runtime.feature-prepared",
            "feature": "alias_pack_v1_write",
        },
    )
    activations.activate(
        "alias_pack_v1_write",
        rollback_floor_version=2,
        journal_position=2,
        journal_control_event={
            "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
            "event_type": "runtime.feature-activated",
            "feature": "alias_pack_v1_write",
        },
    )
    return activations


class CASMetadataPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.activations = _activated_alias_packs(self.home)

    def test_pack_is_copy_only_and_reader_falls_back_after_loose_metadata_removal(self) -> None:
        cas = LocalCAS.open(self.home, self.keys, feature_activations=self.activations)
        publication = cas.publish_plaintext(
            b"metadata pack dual-read body",
            tenant_id="tenant-pack",
            purpose_class="text",
            compression="none",
        )
        reference = publication.receipt.object_ref
        result = cas.pack_metadata(reference)
        self.assertFalse(result["loose_metadata_deleted"])

        alias_path = cas.root / "aliases" / f"{reference.object_id}.json"
        envelope_id = result["envelope_id"]
        envelope_path = cas._envelope_path(envelope_id)
        self.assertTrue(alias_path.is_file())
        self.assertTrue(envelope_path.is_file())
        alias_path.unlink()
        envelope_path.unlink()
        self.assertEqual(cas.open_verified(reference), b"metadata pack dual-read body")

    def test_key_rotation_packs_latest_alias_without_changing_object_bytes(self) -> None:
        cas = LocalCAS.open(self.home, self.keys, feature_activations=self.activations)
        encrypted = encrypt_object(b"rewrap through pack", self.keys, tenant_id="tenant-pack", purpose="text")
        receipt = cas.publish_verified(encrypted)
        object_bytes = cas._object_path(receipt.object_ref.object_id).read_bytes()
        cas.pack_metadata(receipt.object_ref)

        self.keys.rotate(KeyPurpose.CAS_KEK)
        rewrapped = rewrap_object(encrypted, self.keys)
        cas.publish_rewrapped_envelope(rewrapped)
        cas.pack_metadata(receipt.object_ref)
        self.assertEqual(cas._object_path(receipt.object_ref.object_id).read_bytes(), object_bytes)

        alias_path = cas.root / "aliases" / f"{receipt.object_ref.object_id}.json"
        alias_path.unlink()
        for path in (cas.root / "envelopes").rglob("*.json"):
            path.unlink()
        packed_alias = MetadataPackReader(self.home, kind="alias").get(receipt.object_ref.object_id)
        self.assertEqual(packed_alias["envelope_id"], rewrapped.envelope.envelope_id)
        self.assertEqual(cas.open_verified(receipt.object_ref), b"rewrap through pack")

    def test_write_gate_and_sealed_pack_are_fail_closed(self) -> None:
        unactivated = LocalCAS.open(self.home, self.keys)
        publication = unactivated.publish_plaintext(
            b"gate body", tenant_id="tenant-pack", purpose_class="text", compression="none"
        )
        with self.assertRaises(CASError):
            unactivated.pack_metadata(publication.receipt.object_ref)
        self.assertFalse(any((self.home / "cas/packs").glob("*.dat")))

        writer = MetadataPackWriter(
            self.home,
            kind="alias",
            write_enabled=True,
            feature_activations=self.activations,
        )
        writer.append("alias-one", {"schema": "fixture", "value": 1})
        writer.seal()
        with self.assertRaises(PackWriteDisabled):
            writer.append("alias-two", {"schema": "fixture", "value": 2})

        with writer.pack_path.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaises(PackError):
            MetadataPackReader(self.home, kind="alias").get("missing")


if __name__ == "__main__":
    unittest.main()
