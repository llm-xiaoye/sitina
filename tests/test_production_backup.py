from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sitina.archive.production_backup import (
    FrozenProductionPrefix,
    ProductionBackupBuilder,
    ProductionBackupContended,
    ProductionBackupError,
    ProductionBackupManifest,
    ProductionRestoreDrill,
    ProductionSnapshotMetadata,
    _RestoredAuthorityReadView,
    _validate_checkpoint_recovery,
    _validate_evidence_recovery,
    _validate_memory_recovery,
    _validate_session_recovery,
)
from sitina.journal.model import FrontierRef
from sitina.legacy.fence import (
    LegacyWriteDenied,
    authorized_production_permission_hardening,
)


class ProductionBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.root / ".sitina-bplus-disposable-v1").write_text("production-backup-tests\n")
        self.home = self.root / "production"
        (self.home / "journal").mkdir(parents=True)
        (self.home / "journal/writer.lock").write_bytes(b"")
        (self.home / "journal/writer.lock.generation.json").write_bytes(b"generation-before\n")
        (self.home / "journal/active.seg").write_bytes(b"journal-authority")
        object_path = self.home / "cas/objects/aa/object.obj"
        object_path.parent.mkdir(parents=True)
        object_path.write_bytes(b"encrypted-object")
        (self.home / "cas/envelopes").mkdir(parents=True)
        (self.home / "cas/aliases").mkdir(parents=True)
        staging_path = self.home / "cas/staging/object.stage"
        staging_path.parent.mkdir(parents=True)
        os.link(object_path, staging_path)
        (self.home / "state/bplus-production-genesis").mkdir(parents=True)
        (self.home / "state/.legacy-control").mkdir(parents=True)
        (self.home / "state/bplus-production-genesis/genesis.json").write_text(
            json.dumps({"root_path_hash": "1" * 64}) + "\n"
        )
        fence_core = {"state": "FROZEN_NO_WRITER"}
        fence_hash = "sha256:" + hashlib.sha256(
            json.dumps(fence_core, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        (self.home / "state/.legacy-control/frozen.json").write_text(
            json.dumps({**fence_core, "record_hash": fence_hash}) + "\n"
        )
        for relative in (
            "config/context_policy.json",
            "config/conversation_router.json",
            "config/cutover_contracts.bplus_v1.json",
            "config/evidence_policy.bplus_v1.json",
            "config/feature_flags.json",
            "config/format_capabilities.json",
            "config/legacy_fact_classification.json",
            "config/parallel_policy.yaml",
            "config/retry_policy.yaml",
            "config/sitina.yaml",
            "config/true_multi_agent_agents.json",
            "config/true_multi_agent_policy.json",
        ):
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n")
        self.staging = self.root / "staging"
        self.staging.mkdir()
        self.restore_parent = self.root / "restore-parent"
        self.restore_parent.mkdir()
        (self.restore_parent / ".sitina-bplus-disposable-v1").write_text("restore-parent\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    @staticmethod
    def metadata() -> ProductionSnapshotMetadata:
        return ProductionSnapshotMetadata(
            "goal-thread",
            FrontierRef("journal-1", 1, "local", 1, "a" * 64),
            1,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            "e" * 64,
            {"schema": "TEST_KEYCHAIN_PUBLIC_INVENTORY_V1", "secret_values_included": False},
        )

    def build(self, *, builder: ProductionBackupBuilder | None = None, backup_id: str = "backup-1"):
        return (builder or ProductionBackupBuilder()).build(
            backup_id,
            source_home=self.home,
            destination=self.home / "backups" / backup_id,
            staging_parent=self.staging,
            metadata_provider=self.metadata,
        )

    def test_frozen_prefix_backup_and_restore_preserve_hardlinks_without_lock_metadata_mutation(self) -> None:
        generation_before = (self.home / "journal/writer.lock.generation.json").read_bytes()
        manifest = self.build()
        self.assertEqual((self.home / "journal/writer.lock.generation.json").read_bytes(), generation_before)
        loaded = ProductionBackupManifest.load(manifest.backup_root)
        self.assertNotIn("journal/writer.lock", {item.path for item in loaded.files})
        object_copy = loaded.backup_root / "payload/cas/objects/aa/object.obj"
        stage_copy = loaded.backup_root / "payload/cas/staging/object.stage"
        self.assertTrue(os.path.samefile(object_copy, stage_copy))
        self.assertTrue(all(int(item.mode, 8) == 0o600 for item in loaded.files))
        self.assertEqual(
            (loaded.backup_root / "payload/config/context_policy.json").stat().st_mode & 0o7777,
            0o600,
        )
        report = ProductionRestoreDrill().restore(
            loaded,
            target=self.restore_parent / "restore-1",
            semantic_validator=lambda _root, _manifest: {"verified": True, "writer_activated": False},
        )
        self.assertTrue(report["verified"])
        self.assertFalse(report["writer_activated"])
        self.assertTrue(
            os.path.samefile(
                self.restore_parent / "restore-1/cas/objects/aa/object.obj",
                self.restore_parent / "restore-1/cas/staging/object.stage",
            )
        )
        self.assertEqual(
            (self.restore_parent / "restore-1/config/context_policy.json").stat().st_mode & 0o7777,
            0o600,
        )
        self.assertEqual(
            (self.restore_parent / "restore-1/.sitina-bplus-disposable-v1").stat().st_mode & 0o7777,
            0o600,
        )

    def test_writer_contention_fails_before_backup_publication(self) -> None:
        descriptor = os.open(self.home / "journal/writer.lock", os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(ProductionBackupContended):
                self.build(backup_id="backup-contended")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertFalse((self.home / "backups/backup-contended").exists())

    def test_same_process_authority_mutation_is_detected_before_publish(self) -> None:
        def fault(point: str) -> None:
            if point == "after_copy":
                (self.home / "config/feature_flags.json").write_text('{"changed":true}\n')

        with self.assertRaisesRegex(ProductionBackupError, "inventory changed"):
            self.build(builder=ProductionBackupBuilder(fault_injector=fault), backup_id="backup-mutated")
        self.assertFalse((self.home / "backups/backup-mutated").exists())

    def test_symlinked_authority_file_is_rejected(self) -> None:
        target = self.home / "outside"
        target.write_bytes(b"outside")
        os.symlink(target, self.home / "cas/aliases/bad-link")
        with self.assertRaisesRegex(ProductionBackupError, "authority file"):
            self.build(backup_id="backup-symlink")

    def test_payload_tampering_fails_restore_before_semantic_validation(self) -> None:
        manifest = self.build(backup_id="backup-tamper")
        path = manifest.backup_root / "payload/journal/active.seg"
        path.write_bytes(b"tampered")
        called = False

        def validator(_root: Path, _manifest: ProductionBackupManifest):
            nonlocal called
            called = True
            return {"verified": True, "writer_activated": False}

        with self.assertRaises(ProductionBackupError):
            ProductionRestoreDrill().restore(
                manifest,
                target=self.restore_parent / "tampered",
                semantic_validator=validator,
            )
        self.assertFalse(called)

    def test_permission_hardening_capability_is_lock_goal_manifest_and_root_bound(self) -> None:
        with FrozenProductionPrefix.acquire(self.home) as frozen:
            with authorized_production_permission_hardening(
                frozen,
                roots=(self.home / "journal", self.home / "cas"),
                manifest_sha256="a" * 64,
                goal_thread_id="goal-thread",
            ):
                os.chmod(self.home / "journal/active.seg", 0o600)
            with self.assertRaises(LegacyWriteDenied):
                with authorized_production_permission_hardening(
                    frozen,
                    roots=(self.home / "config",),
                    manifest_sha256="a" * 64,
                    goal_thread_id="goal-thread",
                ):
                    pass
            with self.assertRaises(LegacyWriteDenied):
                with authorized_production_permission_hardening(
                    frozen,
                    roots=(self.home / "journal",),
                    manifest_sha256="not-a-hash",
                    goal_thread_id="goal-thread",
                ):
                    pass

    def test_empty_native_recovery_domains_are_proved_by_full_journal_scan(self) -> None:
        view = _RestoredAuthorityReadView((), journal_id="journal-1", epoch=1)
        provider = object()
        self.assertTrue(
            _validate_checkpoint_recovery(view, object(), genesis_hash="a" * 64)[
                "checkpoint_state_reconstructed"
            ]
        )
        self.assertTrue(_validate_session_recovery(view, object(), provider)["session_state_reconstructed"])
        self.assertTrue(_validate_memory_recovery(view, object(), provider)["memory_state_reconstructed"])
        self.assertTrue(_validate_evidence_recovery(view, object(), provider)["evidence_state_reconstructed"])

    def test_legacy_evidence_recovery_verifies_body_hash_and_terminal_binding(self) -> None:
        raw = json.dumps(
            {"schema": "SITINA_TEST_EVIDENCE_V1", "run_id": "run-1"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        reference = "cas:" + hashlib.sha256(raw).hexdigest()

        class FakeCAS:
            def __init__(self, value: bytes):
                self.value = value

            @staticmethod
            def resolve_reference(reference_id: str) -> str:
                return reference_id

            def open_verified(self, _reference: object) -> bytes:
                return self.value

        sealed = SimpleNamespace(
            position=1,
            stream_id="run/run-1",
            event_type="protocol.run.evidence.package.sealed",
            payload={
                "run_id": "run-1",
                "evidence_package_ref": reference,
                "evidence_package_hash": hashlib.sha256(raw).hexdigest(),
            },
            object_refs=(reference,),
            event_hash="a" * 64,
        )
        terminal = SimpleNamespace(
            position=2,
            stream_id="run/run-1",
            event_type="run.terminal",
            payload={"run_id": "run-1"},
            object_refs=(),
            event_hash="b" * 64,
        )
        view = _RestoredAuthorityReadView((sealed, terminal), journal_id="journal-1", epoch=1)
        report = _validate_evidence_recovery(view, FakeCAS(raw), object())
        self.assertEqual(report["terminal_with_cas_evidence_count"], 1)
        self.assertEqual(report["evidence_unique_object_count"], 1)
        with self.assertRaisesRegex(ProductionBackupError, "plaintext hash"):
            _validate_evidence_recovery(view, FakeCAS(raw + b"tampered"), object())


if __name__ == "__main__":
    unittest.main()
