from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from sitina.cas.crypto import encrypt_object
from sitina.cas.gc import (
    ContentLifecycleResolver,
    DestructionAttestation,
    GCController,
    GCFenceError,
    SemanticGCDryRunPlanner,
    SemanticRoot,
    SemanticRootIndex,
)
from sitina.cas.lifecycle import CASStagingCoordinator
from sitina.cas.local import LocalCAS
from sitina.journal.model import parse_canonical_json
from sitina.journal.model import canonical_json_bytes
from sitina.security.key_provider import InMemoryKeyProvider


class CASLifecycleAndSemanticGCTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.cas = LocalCAS.open(self.home, self.keys)

    def test_staging_reconcile_never_cleans_unverified_and_recovers_rooted_publish(self) -> None:
        coordinator = CASStagingCoordinator(self.cas)
        encrypted = encrypt_object(b"durable staging body", self.keys, tenant_id="tenant-stage", purpose="message")
        coordinator.stage("stage-operation", encrypted, created_at="2026-07-16T00:00:00Z")
        report = coordinator.reconcile(
            is_journal_rooted=lambda _ref: None,
            journal_references=(),
            semantic_roots=(),
            now="2026-07-18T00:00:00Z",
            staging_grace_seconds=1,
        )
        self.assertEqual(report["unverified_staging_never_auto_cleaned"], ["stage-operation"])
        self.assertTrue(coordinator._object_path("stage-operation").is_file())

        coordinator.validate("stage-operation")
        report = coordinator.reconcile(
            is_journal_rooted=lambda _ref: None,
            journal_references=(),
            semantic_roots=(),
            now="2026-07-18T00:00:00Z",
            staging_grace_seconds=1,
        )
        self.assertEqual(report["expired_validated_staging"], ["stage-operation"])
        coordinator.publish("stage-operation")
        reference = encrypted.reference.reference_id
        report = coordinator.reconcile(
            is_journal_rooted=lambda value: {"transaction_hash": "a" * 64, "position": 12} if value == reference else None,
            journal_references=(reference,),
            semantic_roots=(reference,),
            now="2026-07-18T00:00:00Z",
            repair=True,
        )
        self.assertEqual(report["recovered_operations"], ["stage-operation"])
        self.assertEqual(coordinator.load("stage-operation").state, "RELEASED")
        self.assertFalse(coordinator._object_path("stage-operation").exists())
        self.assertEqual(self.cas.open_verified(encrypted.reference), b"durable staging body")

    def test_quarantine_promotes_only_sanitized_bytes_and_restart_orphans_are_attested(self) -> None:
        quarantine_id = self.cas.publish_quarantine(b"unsafe raw", classification="external-text")
        self.assertEqual(self.cas.open_quarantine(quarantine_id, classification="external-text"), b"unsafe raw")
        publication = self.cas.promote_quarantine(
            quarantine_id,
            classification="external-text",
            sanitized_plaintext=b"safe normalized",
            tenant_id="tenant-quarantine",
            purpose_class="sanitized-text",
            compression="none",
        )
        self.assertEqual(self.cas.open_verified(publication.receipt.object_ref), b"safe normalized")
        metadata = parse_canonical_json(
            (self.cas.root / "quarantine" / f"{quarantine_id}.meta.json").read_bytes()
        )
        self.assertEqual(metadata["state"], "DESTROYED_WITH_ATTESTATION")
        self.assertFalse((self.cas.root / "quarantine" / f"{quarantine_id}.q").exists())

        orphan_id = self.cas.publish_quarantine(b"restart loses process key", classification="binary")
        reopened = LocalCAS.open(self.home, self.keys)
        dry_run = reopened.reconcile_quarantine(dry_run=True)
        self.assertEqual(dry_run["restart_unrecoverable"], [orphan_id])
        self.assertTrue((reopened.root / "quarantine" / f"{orphan_id}.q").is_file())
        executed = reopened.reconcile_quarantine(dry_run=False)
        self.assertTrue(executed["planned_actions"])
        self.assertFalse((reopened.root / "quarantine" / f"{orphan_id}.q").exists())
        orphan_meta = parse_canonical_json(
            (reopened.root / "quarantine" / f"{orphan_id}.meta.json").read_bytes()
        )
        self.assertEqual(orphan_meta["state"], "DESTROYED_WITH_ATTESTATION")

    def test_checkpoint_plus_tail_semantic_roots_protect_and_history_alone_does_not(self) -> None:
        refs = []
        for index in range(6):
            publication = self.cas.publish_plaintext(
                f"gc-body-{index}".encode(),
                tenant_id="tenant-gc",
                purpose_class=f"gc-{index}",
                compression="none",
            )
            reference = publication.receipt.object_ref.reference_id
            refs.append(reference)
            os.utime(self.cas._object_path(publication.receipt.object_ref.object_id), (1, 1))

        checkpoint_root = SemanticRoot("session", "session-checkpoint", refs[0], 3, "event-checkpoint")
        checkpoint_index = SemanticRootIndex((checkpoint_root,), checkpoint_position=5)
        roots = SemanticRootIndex.from_checkpoint(
            [checkpoint_root.mapping()],
            active_roots_index_commitment=checkpoint_index.commitment,
            checkpoint_position=5,
        )
        with self.assertRaises(GCFenceError):
            SemanticRootIndex.from_checkpoint(
                [checkpoint_root.mapping()],
                active_roots_index_commitment="0" * 64,
                checkpoint_position=5,
            )

        roots.apply_tail(
            (
                {"position": 6, "event_id": "e6", "event_type": "session.deleted", "payload": {"session_id": "session-checkpoint", "trash_lease_id": "trash-1", "object_refs": [refs[0]]}},
                {"position": 7, "event_id": "e7", "event_type": "memory.accepted", "payload": {"memory_id": "memory-1", "content_ref": refs[1]}},
                {"position": 8, "event_id": "e8", "event_type": "backup.activated", "payload": {"backup_id": "backup-1", "object_refs": [refs[2]]}},
                {"position": 9, "event_id": "e9", "event_type": "legal-retention.activated", "payload": {"hold_id": "hold-1", "object_refs": [refs[3]]}},
                {"position": 10, "event_id": "e10", "event_type": "gc.reference_lease_acquired", "payload": {"lease_id": "lease-1", "reference_id": refs[4]}},
                {"position": 11, "event_id": "history", "event_type": "tool.completed", "payload": {"object_ref": refs[5]}},
            )
        )
        plan = SemanticGCDryRunPlanner(self.cas).plan(
            roots,
            historical_references=refs,
            now_epoch_seconds=2_000_000_000,
            grace_seconds=0,
        )
        retained = {item["object_ref"]: item for item in plan["retained"]}
        self.assertEqual(set(retained), set(refs[:5]))
        self.assertEqual({item["object_ref"] for item in plan["candidates"]}, {refs[5]})
        self.assertTrue(next(item for item in plan["candidates"] if item["object_ref"] == refs[5])["appears_in_journal_history"])
        self.assertFalse(plan["physical_delete_executed"])
        self.assertTrue(self.cas._object_path(refs[5].removeprefix("cas:")).is_file())

        controller = GCController(lambda *_args: None)
        controller.set_semantic_roots(roots)
        self.assertTrue(controller._protected(refs[0]))

        roots.apply_tail(
            (
                {"position": 12, "event_type": "trash.lease-released", "payload": {"trash_lease_id": "trash-1"}},
                {"position": 13, "event_type": "memory.revoked", "payload": {"memory_id": "memory-1"}},
                {"position": 14, "event_type": "backup.retired", "payload": {"backup_id": "backup-1"}},
                {"position": 15, "event_type": "legal-retention.released", "payload": {"hold_id": "hold-1"}},
                {"position": 16, "event_type": "gc.reference_lease_released", "payload": {"lease_id": "lease-1"}},
            )
        )
        released_plan = SemanticGCDryRunPlanner(self.cas).plan(
            roots,
            historical_references=refs,
            now_epoch_seconds=2_000_000_000,
            grace_seconds=0,
        )
        self.assertEqual({item["object_ref"] for item in released_plan["candidates"]}, set(refs))
        self.assertTrue(all(item["appears_in_journal_history"] for item in released_plan["candidates"]))

        roots.apply_tail(
            (
                {
                    "position": 17,
                    "event_id": "run-checkpoint",
                    "event_type": "run.checkpoint-published",
                    "object_refs": [refs[5]],
                    "payload": {"run_id": "run-1", "checkpoint_ref": refs[5]},
                },
            )
        )
        self.assertEqual(roots.root_types_for(refs[5]), ("active-run",))
        roots.apply_tail(
            (
                {
                    "position": 18,
                    "event_id": "run-compact",
                    "event_type": "run.checkpoint-chain-compacted",
                    "payload": {"run_id": "run-1", "released_checkpoint_root_refs": [refs[5]]},
                },
            )
        )
        self.assertEqual(roots.root_types_for(refs[5]), ())

    def test_content_lifecycle_distinguishes_roots_purge_shred_and_unattested_loss(self) -> None:
        publications = [
            self.cas.publish_plaintext(
                f"lifecycle-{index}".encode(),
                tenant_id="tenant-lifecycle",
                purpose_class=f"lifecycle-{index}",
                compression="none",
            )
            for index in range(5)
        ]
        refs = [publication.receipt.object_ref.reference_id for publication in publications]
        roots = SemanticRootIndex(
            (
                SemanticRoot("trash", "trash-1", refs[1], 1, "event-1"),
                SemanticRoot("backup", "backup-1", refs[2], 2, "event-2"),
            ),
            checkpoint_position=2,
        )
        resolver = ContentLifecycleResolver(self.cas, roots)
        self.assertEqual(resolver.status(refs[0])["state"], "AVAILABLE")
        self.assertEqual(resolver.status(refs[1])["state"], "TRASH_HELD")
        self.assertEqual(resolver.status(refs[2])["state"], "BACKUP_HELD")

        purged = DestructionAttestation(
            refs[3], "PHYSICAL_DELETE", 30, "c" * 64, "2026-07-18T00:00:00Z", "verified GC sweep"
        ).mapping()
        purged_path = self.cas.root / "destruction-attestations" / f"{purged['attestation_id']}.json"
        self.cas._publish_bytes(canonical_json_bytes(purged), purged_path)
        self.cas._object_path(publications[3].receipt.object_ref.object_id).unlink()
        status = resolver.status(refs[3])
        self.assertEqual(status["state"], "PURGED")
        self.assertFalse(status["classified_as_corruption"])

        shredded = DestructionAttestation(
            refs[4], "CRYPTO_SHRED", 31, "d" * 64, "2026-07-18T00:01:00Z", "verified envelope destruction"
        ).mapping()
        shredded_path = self.cas.root / "destruction-attestations" / f"{shredded['attestation_id']}.json"
        self.cas._publish_bytes(canonical_json_bytes(shredded), shredded_path)
        self.assertEqual(resolver.status(refs[4])["state"], "CRYPTO_SHREDDED")

        missing = "cas:" + "f" * 64
        self.assertEqual(resolver.status(missing)["state"], "MISSING_UNATTESTED")


if __name__ == "__main__":
    unittest.main()
