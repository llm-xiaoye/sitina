from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path

from sitina.cas.crypto import decrypt_object, encrypt_object
from sitina.cas.local import LocalCAS
from sitina.cas.model import CASError
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.journal.model import parse_canonical_json
from sitina.security.key_provider import InMemoryKeyProvider


class CASCompressionAndDedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        leases = CompatibilityLeaseRegistry(self.home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="cas-zstd-test",
                binary_version="2.0.0",
                reader_capabilities=("cas-zstd",),
                writer_capabilities=("cas-zstd",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T02:00:00Z",
                fencing_token=1,
            )
        )
        self.activations = FeatureActivationRegistry()
        self.activations.prepare(
            "cas_zstd_write",
            required_reader_capabilities=("cas-zstd",),
            leases=leases,
            now="2026-07-18T00:01:00Z",
            journal_position=1,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "event_type": "runtime.feature-prepared",
                "feature": "cas_zstd_write",
            },
        )
        self.activations.activate(
            "cas_zstd_write",
            rollback_floor_version=2,
            journal_position=2,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "event_type": "runtime.feature-activated",
                "feature": "cas_zstd_write",
            },
        )

    @staticmethod
    def _header(cas: LocalCAS, object_id: str):
        raw = cas._object_path(object_id).read_bytes()
        length = int.from_bytes(raw[:4], "big")
        return parse_canonical_json(raw[4 : 4 + length]), raw

    def test_new_reader_dual_reads_none_single_zstd_and_chunked_zstd(self) -> None:
        cas = LocalCAS.open(self.home, self.keys, feature_activations=self.activations)
        legacy = cas.publish_plaintext(b"legacy body", tenant_id="tenant-a", purpose_class="text", compression="none")
        medium_body = ("Sitina compression correctness. " * 600).encode()
        medium = cas.publish_plaintext(medium_body, tenant_id="tenant-a", purpose_class="text", compression="auto")
        large_body = (b"0123456789abcdef" * 80_000) + b"tail"
        large = cas.publish_plaintext(large_body, tenant_id="tenant-a", purpose_class="large-text", compression="auto")

        legacy_header, _ = self._header(cas, legacy.receipt.object_ref.object_id)
        medium_header, medium_raw = self._header(cas, medium.receipt.object_ref.object_id)
        large_header, _ = self._header(cas, large.receipt.object_ref.object_id)
        self.assertEqual(legacy_header["schema"], "SITINA_CAS_CORE_HEADER_V1")
        self.assertEqual(legacy_header["compression"], "none")
        self.assertEqual(medium_header["schema"], "SITINA_CAS_CORE_HEADER_V2")
        self.assertEqual(medium_header["compression"], "zstd")
        self.assertEqual(medium_header["compression_level"], 3)
        self.assertEqual(medium_header["compression_mode"], "single")
        self.assertLess(len(medium_raw), len(medium_body))
        self.assertEqual(large_header["compression_mode"], "chunked")
        self.assertGreater(large_header["compression_chunk_count"], 1)
        self.assertEqual(cas.open_verified(legacy.receipt.object_ref), b"legacy body")
        self.assertEqual(cas.open_verified(medium.receipt.object_ref), medium_body)
        self.assertEqual(cas.open_verified(large.receipt.object_ref), large_body)

    def test_default_old_write_and_media_skip_do_not_require_zstd_activation(self) -> None:
        old_write = LocalCAS.open(self.home, self.keys)
        body = b"x" * 4_000
        unactivated = old_write.publish_plaintext(body, tenant_id="tenant-old", purpose_class="text", compression="auto")
        self.assertEqual(unactivated.compression_profile, "none")
        header, _ = self._header(old_write, unactivated.receipt.object_ref.object_id)
        self.assertEqual(header["compression"], "none")
        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        with self.assertRaises(CASError):
            old_write.publish_plaintext(body, tenant_id="tenant-old", purpose_class="explicit", compression="zstd")
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)

        active = LocalCAS.open(self.home, self.keys, feature_activations=self.activations)
        media = active.publish_plaintext(
            b"\x89PNG\r\n\x1a\n" + b"x" * 8_000,
            tenant_id="tenant-media",
            purpose_class="image",
            compression="auto",
            media_type="image/png",
        )
        self.assertEqual(media.compression_profile, "none")

    def test_dedup_scope_includes_tenant_purpose_compression_and_crypto_profile(self) -> None:
        cas = LocalCAS.open(self.home, self.keys, feature_activations=self.activations)
        body = b"same canonical body " * 200
        first = cas.publish_plaintext(body, tenant_id="tenant-a", purpose_class="memory", compression="auto")
        again = cas.publish_plaintext(body, tenant_id="tenant-a", purpose_class="memory", compression="auto")
        other_tenant = cas.publish_plaintext(body, tenant_id="tenant-b", purpose_class="memory", compression="auto")
        other_purpose = cas.publish_plaintext(body, tenant_id="tenant-a", purpose_class="evidence", compression="auto")
        other_compression = cas.publish_plaintext(body, tenant_id="tenant-a", purpose_class="memory", compression="none")
        self.assertFalse(first.reused)
        self.assertTrue(again.reused)
        self.assertEqual(first.receipt.object_ref, again.receipt.object_ref)
        identities = {
            first.receipt.object_ref.object_id,
            other_tenant.receipt.object_ref.object_id,
            other_purpose.receipt.object_ref.object_id,
            other_compression.receipt.object_ref.object_id,
        }
        self.assertEqual(len(identities), 4)
        for publication in (first, again, other_tenant, other_purpose, other_compression):
            self.assertEqual(cas.open_verified(publication.receipt.object_ref), body)

    def test_concurrent_publish_converges_on_one_indexed_object(self) -> None:
        cas = LocalCAS.open(self.home, self.keys, feature_activations=self.activations)
        body = b"concurrent deterministic body " * 300
        barrier = threading.Barrier(8)
        results = []
        errors = []

        def publish() -> None:
            try:
                barrier.wait()
                results.append(
                    cas.publish_plaintext(body, tenant_id="tenant-concurrent", purpose_class="text", compression="auto")
                )
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        threads = [threading.Thread(target=publish) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len({item.receipt.object_ref.object_id for item in results}), 1)
        self.assertEqual(sum(not item.reused for item in results), 1)
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), 1)

    def test_reconcile_rebuilds_index_and_reports_duplicate_ciphertexts_without_deleting(self) -> None:
        cas = LocalCAS.open(self.home, self.keys)
        body = b"orphaned publication body"
        first = cas.publish_verified(encrypt_object(body, self.keys, tenant_id="tenant-reconcile", purpose="text"))
        second = cas.publish_verified(encrypt_object(body, self.keys, tenant_id="tenant-reconcile", purpose="text"))
        self.assertNotEqual(first.object_ref.object_id, second.object_ref.object_id)
        report = cas.reconcile_commitment_index()
        self.assertEqual(report["indexed"], 1)
        self.assertEqual(report["objects_deleted"], 0)
        self.assertEqual(sum(len(value) for value in report["duplicate_candidates"].values()), 1)
        reused = cas.publish_plaintext(body, tenant_id="tenant-reconcile", purpose_class="text", compression="none")
        self.assertTrue(reused.reused)
        self.assertIn(reused.receipt.object_ref.object_id, {first.object_ref.object_id, second.object_ref.object_id})
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), 2)

    def test_low_level_zstd_round_trip_preserves_plaintext_commitment(self) -> None:
        body = b"commitment input " * 500
        encrypted = encrypt_object(body, self.keys, tenant_id="tenant-a", purpose="fixture", compression="zstd")
        self.assertEqual(decrypt_object(encrypted, self.keys), body)
        self.assertTrue(
            self.keys.verify_commitment(
                encrypted.reference.commitment_key_id,
                encrypted.reference.tenant_id,
                body,
                encrypted.reference.plaintext_commitment,
            )
        )

    def test_read_only_cas_view_reads_without_layout_writes_and_rejects_publish(self) -> None:
        writer = LocalCAS.open(self.home, self.keys)
        published = writer.publish_plaintext(
            b"read-only fixture", tenant_id="tenant-reader", purpose_class="text", compression="none"
        )
        before = {
            path.relative_to(self.home).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in self.home.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        reader = LocalCAS.open_read_only(self.home, self.keys)
        self.assertEqual(reader.open_verified(published.receipt.object_ref), b"read-only fixture")
        with self.assertRaisesRegex(CASError, "read-only"):
            reader.publish_plaintext(
                b"forbidden", tenant_id="tenant-reader", purpose_class="text", compression="none"
            )
        after = {
            path.relative_to(self.home).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in self.home.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
