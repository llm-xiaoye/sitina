from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sitina.authority.model import AuthorityState
from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.journal.local import CommandConflict, LocalJournal
from sitina.legacy.coverage import CanonicalLegacyBackupBuilder, FrozenSnapshotBuilder, LegacyCoverageBuilder
from sitina.legacy.fence import LegacyWriteGate
from sitina.legacy.migration_control import ProductionMigrationPublisher
from sitina.legacy.production_genesis import ProductionGenesisBuilder
from sitina.operations.phase6b import (
    PHASE6B_OPERATION_IDS,
    AuthorityControlStream,
    Phase6BManifestError,
    Phase6BManifestVerifier,
)
from sitina.orchestrator.bplus_production import BPlusProductionRuntime, ProductionRuntimeContext
from sitina.orchestrator.engine import SitinaEngine
from sitina.security.key_provider import JournalAuthProvider, KeyPurpose
from sitina.security.macos_keychain import MacOSKeychainProvider, MemoryKeychainBackend, SecurityFrameworkKeychainBackend


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class Phase6AProductionToolingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"]).resolve(strict=True)
        self.sim = self.home / f"phase6b-production-simulation-{self._testMethodName}"
        self.snapshot_root = self.home / f"phase6b-snapshot-{self._testMethodName}"
        self.migration_root = self.home / f"phase6b-migration-{self._testMethodName}"
        self.backup_root = self.home / f"phase6b-backup-{self._testMethodName}"
        self.control_root = self.home / f"phase6b-control-{self._testMethodName}"
        self.sim.mkdir()
        (self.sim / ".sitina-bplus-disposable-v1").write_text("controlled-production-simulation\n", encoding="utf-8")
        for relative in ("state", "data", "logs/events", "logs/audit", "artifacts", "outputs", "memory"):
            (self.sim / relative).mkdir(parents=True, exist_ok=True)
        self.now = int(time.time())
        self.readiness = {
            "schema": "BPLUS_CUTOVER_TOOLING_READY_R1_V1",
            "status": "CUTOVER_TOOLING_READY",
            "authority": False,
            "maintenance_authorized": False,
            "cutover_authorized": False,
            "predicates": {"fixture_production_tooling_complete": True, "production_sentinels_unchanged": True},
        }
        self.readiness["readiness_sha256"] = hashlib.sha256(canonical(self.readiness)).hexdigest()
        self.manifest = self._signed_manifest()
        self.capability = Phase6BManifestVerifier.verify_mapping(
            self.manifest, readiness_report=self.readiness, now=self.now, allow_simulation=True
        )

    def _signed_manifest(self) -> dict[str, object]:
        code_path = self.home / "core/sitina/journal/local.py"
        source_hash = hashlib.sha256(code_path.read_bytes()).hexdigest()
        self.control_root.mkdir(exist_ok=True)
        source_core = {
            "schema": "CONTENT_MANIFEST_V1",
            "root": str(self.home),
            "scope": "PHASE6A_R1_MINIMAL_TEST_SOURCE",
            "excluded_roots": [],
            "excluded_patterns": [],
            "previous_manifest_hash": "sha256:" + "0" * 64,
            "entries": [{
                "path": code_path.relative_to(self.home).as_posix(),
                "size": code_path.stat().st_size,
                "mode": oct(code_path.stat().st_mode & 0o7777),
                "sha256": source_hash,
            }],
        }
        source_manifest_hash = hashlib.sha256(canonical(source_core)).hexdigest()
        source_manifest_path = self.control_root / "source-content-manifest.json"
        source_manifest_path.write_text(
            json.dumps({**source_core, "manifest_sha256": source_manifest_hash}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        prerequisite_artifacts = {}
        for name in ("effect_drain", "monitoring_transfer", "key_profile"):
            path = self.control_root / f"{name}.json"
            path.write_text(json.dumps({"schema": "PHASE6A_R1_TEST_PREREQUISITE_V1", "name": name}, sort_keys=True) + "\n", encoding="utf-8")
            prerequisite_artifacts[name] = {
                "path": str(path),
                "physical_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        genesis_values = {
            "installation_id": "sitina-production-sim",
            "journal_id": "journal-production-sim",
            "epoch_root": "epoch-production-sim-1",
            "key_namespace": "sitina-production-sim-v1",
            "intended_snapshot_hash": "a" * 64,
            "format_profile_hash": "1" * 64,
            "operator_id": "phase6b-executor",
            "verifier_id": "phase6b-read-only-verifier",
        }
        expected_genesis = ProductionGenesisBuilder(self.sim).derive_manifest_artifact(
            genesis_values, environment_kind="CONTROLLED_PRODUCTION_SIMULATION"
        )
        genesis_values["genesis_hash"] = expected_genesis.genesis_hash
        migration_contract_hash = hashlib.sha256(
            b"SITINA-BPLUS-V1\0MIGRATION_CONTRACT\0"
            + canonical({"snapshot_hash": "a" * 64, "format_profile_hash": "1" * 64})
        ).hexdigest()
        cutover_body = {
            "schema": "AUTHORITY_CUTOVER_REQUEST_V1",
            "snapshot_hash": "a" * 64,
            "genesis_hash": expected_genesis.genesis_hash,
            "migration_contract_hash": migration_contract_hash,
            "effect_drain_hash": prerequisite_artifacts["effect_drain"]["physical_sha256"],
            "monitoring_transfer_hash": prerequisite_artifacts["monitoring_transfer"]["physical_sha256"],
            "source_manifest_sha256": source_manifest_hash,
            "readiness_sha256": self.readiness["readiness_sha256"],
            "key_profile_hash": prerequisite_artifacts["key_profile"]["physical_sha256"],
            "operator_authorization_hash": "05621d9bd89ee19fb80ec44f84b770a88808345639068d261a3aec126d916601",
        }
        core: dict[str, object] = {
            "schema": "PHASE6B_MAINTENANCE_MANIFEST_V1",
            "environment_kind": "CONTROLLED_PRODUCTION_SIMULATION",
            "goal_thread_id": "019f5c6b-3083-7860-b45b-c8b487c4e3ab",
            "owner_principal": "user-standing-owner-authorization-v1",
            "standing_owner_authorization_hash": "sha256:05621d9bd89ee19fb80ec44f84b770a88808345639068d261a3aec126d916601",
            "approval_derivation": "AUTOMATIC_FROM_STANDING_OWNER_AUTHORIZATION_V1",
            "phase6a_readiness_sha256": self.readiness["readiness_sha256"],
            "source_manifest_sha256": source_manifest_hash,
            "source_manifest_path": str(source_manifest_path),
            "window": {"starts_at": self.now - 10, "ends_at": self.now + 3600, "expires_at": self.now + 3000},
            "roots": {
                "production_home": str(self.sim),
                "snapshot_root": str(self.snapshot_root),
                "migration_root": str(self.migration_root),
                "backup_root": str(self.backup_root),
                "control_root": str(self.control_root),
            },
            "authorized_operations": list(PHASE6B_OPERATION_IDS),
            "code_identities": {str(code_path): source_hash},
            "production_genesis": genesis_values,
            "cutover_command": {
                "command_id": "cutover-production-sim-v1",
                "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now)),
                "request_body": cutover_body,
            },
            "cutover_verified_command": {
                "command_id": "cutover-verified-production-sim-v1",
                "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now + 1)),
                "required_predicates": ["rebuild", "dual_read", "legacy_zero_write", "backup_restore", "mock_only"],
                "required_report_hashes": ["rebuild", "dual_read", "evidence"],
            },
            "operator_quorum": [
                {"principal_id": "user-standing-owner-authorization-v1", "role": "OWNER_PRINCIPAL", "human_identity_claimed": False},
                {"principal_id": "phase6b-read-only-verifier", "role": "INDEPENDENT_TECHNICAL_VERIFIER", "human_identity_claimed": False},
                {"principal_id": "phase6b-executor", "role": "EXECUTION_PRINCIPAL", "human_identity_claimed": False},
            ],
            "prerequisites": {"source_coverage": True, "restore_drill": True, "effect_drain": True, "monitoring_transfer": True},
            "prerequisite_artifacts": prerequisite_artifacts,
            "stop_conditions": ["ANY_IDENTITY_DRIFT", "ANY_UNKNOWN_OUTCOME", "ANY_UNEXPLAINED_OMISSION"],
        }
        core["cutover_command"]["request_hash"] = hashlib.sha256(  # type: ignore[index]
            b"SITINA-BPLUS-V1\0CUTOVER_COMMAND_REQUEST\0" + canonical(cutover_body)
        ).hexdigest()
        private = Ed25519PrivateKey.generate()
        signed = canonical(core)
        report = dict(core)
        report["technical_verifier_public_key_hex"] = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        report["technical_verifier_signature_hex"] = private.sign(signed).hex()
        report["signed_body_sha256"] = hashlib.sha256(signed).hexdigest()
        report["manifest_sha256"] = hashlib.sha256(canonical(report)).hexdigest()
        return report

    def _genesis_and_provider(self):
        builder = ProductionGenesisBuilder(self.sim)
        genesis = builder.build_authorized(self.capability, now=self.now)
        genesis = builder.verify_independent(genesis, verifier_id="phase6b-read-only-verifier")
        builder.persist_authorized(genesis, self.capability, now=self.now)
        backend = MemoryKeychainBackend()
        provider = MacOSKeychainProvider(
            environment="production-simulation", namespace=genesis.key_namespace, backend=backend
        )
        return genesis, backend, provider

    def test_manifest_is_signed_time_bounded_drift_checked_and_not_human_fabricated(self) -> None:
        self.assertEqual(self.capability.environment_kind, "CONTROLLED_PRODUCTION_SIMULATION")
        self.assertEqual(set(self.capability.authorized_operations), set(PHASE6B_OPERATION_IDS))
        self.assertFalse(any(item["human_identity_claimed"] for item in self.manifest["operator_quorum"]))  # type: ignore[index]
        tampered = json.loads(json.dumps(self.manifest))
        tampered["roots"]["production_home"] = str(self.home / "different")
        with self.assertRaises(Phase6BManifestError):
            Phase6BManifestVerifier.verify_mapping(tampered, readiness_report=self.readiness, now=self.now, allow_simulation=True)
        with self.assertRaises(Phase6BManifestError):
            Phase6BManifestVerifier.verify_mapping(self.manifest, readiness_report=self.readiness, now=self.now + 4000, allow_simulation=True)

    def test_production_genesis_is_manifest_bound_independently_verified_and_idempotent(self) -> None:
        genesis, _, _ = self._genesis_and_provider()
        self.assertEqual(genesis.environment_kind, "CONTROLLED_PRODUCTION_SIMULATION")
        self.assertTrue(genesis.independently_verified)
        self.assertFalse(genesis.authority)
        self.assertNotIn("fixture", genesis.genesis_id)
        again = ProductionGenesisBuilder(self.sim).persist_authorized(genesis, self.capability, now=self.now)
        self.assertEqual(again.genesis_hash, genesis.genesis_hash)

    def test_persistent_key_provider_reopens_without_exposing_secret_material(self) -> None:
        genesis, backend, provider = self._genesis_and_provider()
        auth1 = JournalAuthProvider(provider)
        key_id, tag = auth1.authenticate(genesis.journal_id, 1, "2" * 64)
        reopened = MacOSKeychainProvider(
            environment="production-simulation", namespace=genesis.key_namespace, backend=backend
        )
        self.assertTrue(JournalAuthProvider(reopened).verify(genesis.journal_id, 1, key_id, "2" * 64, tag))
        self.assertNotIn(tag.encode(), canonical(backend.public_inventory()))
        self.assertNotEqual(
            provider.current_descriptor(KeyPurpose.JOURNAL_AUTH).key_id,
            provider.current_descriptor(KeyPurpose.CAS_KEK).key_id,
        )

    def test_actual_macos_keychain_transport_uses_framework_and_no_secret_argv(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        launcher = (source_root / "bin/sitina").read_text(encoding="utf-8")
        self.assertIn("export PYTHONDONTWRITEBYTECODE=1", launcher)
        environment = dict(os.environ)
        environment.pop("SITINA_CONTROL_PLANE_READONLY", None)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        environment["SITINA_HOME"] = str(self.sim)
        environment["PYTHONPATH"] = str(source_root / "core")
        bootstrap = subprocess.run(
            [sys.executable, "-c", "import sys, sitina.cli; assert sys.dont_write_bytecode; print('BYTECODE_FREE_BOOTSTRAP_OK')"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual((bootstrap.returncode, bootstrap.stdout.strip()), (0, "BYTECODE_FREE_BOOTSTRAP_OK"))
        path = self.home / "phase6a-r1-ephemeral.keychain-db"
        backend = SecurityFrameworkKeychainBackend(
            keychain_path=str(path), create=True, keychain_password=b"phase6a-r1-ephemeral-only"
        )
        try:
            provider = MacOSKeychainProvider(
                environment="production-simulation", namespace="phase6a-r1-keychain-test", backend=backend
            )
            authenticator = JournalAuthProvider(provider)
            key_id, tag = authenticator.authenticate("journal-keychain-r1", 1, "7" * 64)
            reopened = MacOSKeychainProvider(
                environment="production-simulation", namespace="phase6a-r1-keychain-test", backend=backend
            )
            self.assertTrue(JournalAuthProvider(reopened).verify("journal-keychain-r1", 1, key_id, "7" * 64, tag))
            inventory = backend.public_inventory()
            self.assertFalse(inventory["secret_values_included"])
            self.assertFalse(inventory["secret_argv_transport"])
        finally:
            backend.delete_private_keychain()
            backend.close()

    def test_production_fence_and_journal_cas_require_exact_capability(self) -> None:
        genesis, _, provider = self._genesis_and_provider()
        status = LegacyWriteGate(self.sim).freeze_authorized("snapshot-production-sim-v1", self.capability, now=self.now)
        self.assertEqual(status.state, "FROZEN_NO_WRITER")
        with self.assertRaises(Exception):
            LocalJournal.open(self.sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1, namespace_kind="production_simulation")
        journal = LocalJournal.open(
            self.sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        cas = LocalCAS.open(
            self.sim, provider, namespace_kind="production_simulation",
            operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        receipt = cas.publish_verified(encrypt_object(b"phase6b-simulation", provider, tenant_id="system"))
        self.assertEqual(cas.open_verified(receipt.object_ref), b"phase6b-simulation")
        with patch("sitina.journal.local.time.time", return_value=self.now + 4000):
            with self.assertRaises(Exception):
                AuthorityControlStream(journal, self.capability, genesis, now=self.now).record_genesis_and_prepare(
                    migration_frontier_hash="c" * 64,
                    fence_record_hash=LegacyWriteGate(self.sim).status().record_hash,
                )
        with patch("sitina.cas.local.time.time", return_value=self.now + 4000):
            with self.assertRaises(Exception):
                cas.publish_verified(encrypt_object(b"expired-capability", provider, tenant_id="system"))
        journal.close()

    def test_cutover_lost_ack_recovers_same_command_and_resolves_journal_only(self) -> None:
        genesis, backend, provider = self._genesis_and_provider()
        LegacyWriteGate(self.sim).freeze_authorized("snapshot-production-sim-v1", self.capability, now=self.now)
        crashed = {"done": False, "fsync_count": 0}
        def fault(boundary: str, _journal: LocalJournal) -> None:
            if boundary == "after_frame_fsync_before_ack":
                crashed["fsync_count"] += 1
            if boundary == "after_frame_fsync_before_ack" and crashed["fsync_count"] == 2 and not crashed["done"]:
                crashed["done"] = True
                raise RuntimeError("simulated-lost-ack")
        journal = LocalJournal.open(
            self.sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", operational_capability=self.capability,
            genesis_hash=genesis.genesis_hash, fault_injector=fault,
        )
        stream = AuthorityControlStream(journal, self.capability, genesis, now=self.now)
        stream.record_genesis_and_prepare(migration_frontier_hash="c" * 64, fence_record_hash=LegacyWriteGate(self.sim).status().record_hash)
        with self.assertRaises(RuntimeError):
            stream.submit_cutover()
        journal.close()
        reopened_provider = MacOSKeychainProvider(environment="production-simulation", namespace=genesis.key_namespace, backend=backend)
        recovered_journal = LocalJournal.open(
            self.sim, JournalAuthProvider(reopened_provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        recovered = AuthorityControlStream(recovered_journal, self.capability, genesis, now=self.now + 60)
        result = recovered.recover_cutover()
        self.assertEqual(result.status.value, "COMMITTED")
        resolution = recovered.resolve_authority(now=self.now)
        self.assertEqual(resolution.state, AuthorityState.JOURNAL_WRITER_AUTHORIZED)
        self.assertEqual(resolution.writer_count, 1)
        with self.assertRaises(CommandConflict):
            recovered.submit_cutover(request_body={"different": True})
        recovered_journal.close()

    def test_cutover_verified_is_committed_once_and_bound_to_all_predicates(self) -> None:
        genesis, _, provider = self._genesis_and_provider()
        LegacyWriteGate(self.sim).freeze_authorized("snapshot-production-sim-v1", self.capability, now=self.now)
        journal = LocalJournal.open(
            self.sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        stream = AuthorityControlStream(journal, self.capability, genesis, now=self.now)
        stream.record_genesis_and_prepare(migration_frontier_hash="c" * 64, fence_record_hash=LegacyWriteGate(self.sim).status().record_hash)
        stream.submit_cutover()
        predicates = {"rebuild": True, "dual_read": True, "legacy_zero_write": True, "backup_restore": True, "mock_only": True}
        first = stream.submit_cutover_verified(
            command_id="cutover-verified-production-sim-v1", predicates=predicates,
            report_hashes={"rebuild": "3" * 64, "dual_read": "4" * 64, "evidence": "5" * 64},
        )
        second = stream.submit_cutover_verified(
            command_id="cutover-verified-production-sim-v1", predicates=predicates,
            report_hashes={"rebuild": "3" * 64, "dual_read": "4" * 64, "evidence": "5" * 64},
        )
        self.assertEqual(first.transaction_hash, second.transaction_hash)
        proof = stream.verify_committed_cutover_verified("cutover-verified-production-sim-v1")
        self.assertTrue(proof["verified"])
        journal.close()

    def test_legacy_coverage_is_complete_chunked_and_preserves_incomplete_lines(self) -> None:
        snapshot = self.home / "legacy-rehearsal-snapshot"
        (snapshot / "data").mkdir(parents=True)
        (snapshot / "logs/events").mkdir(parents=True)
        (snapshot / "artifacts/runs").mkdir(parents=True)
        with sqlite3.connect(snapshot / "data/sitina.db") as connection:
            connection.execute("CREATE TABLE runs(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            connection.executemany("INSERT INTO runs(payload) VALUES(?)", [("one",), ("two",)])
        (snapshot / "logs/events/legacy.jsonl").write_bytes(b'{"event_id":"a"}\nnot-json\n')
        (snapshot / "artifacts/runs/result.txt").write_text("legacy-result\n", encoding="utf-8")
        coverage = LegacyCoverageBuilder(snapshot, chunk_rows=1, chunk_lines=1).build()
        self.assertEqual(coverage.source_coverage_percent, 100)
        self.assertEqual(coverage.unexplained_omission_count, 0)
        self.assertGreater(coverage.legacy_incomplete_with_reason_count, 0)
        self.assertEqual(coverage.sqlite_tables["runs"].row_count, 2)
        self.assertTrue(all(item.disposition for item in coverage.files))

    def test_frozen_snapshot_backup_hold_and_isolated_restore_are_exact(self) -> None:
        with sqlite3.connect(self.sim / "data/sitina.db") as connection:
            connection.execute("CREATE TABLE facts(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("INSERT INTO facts(value) VALUES('preserved')")
        (self.sim / "logs/events/legacy.jsonl").write_text('{"event_id":"one"}\n', encoding="utf-8")
        LegacyWriteGate(self.sim).freeze_authorized("snapshot-production-sim-v1", self.capability, now=self.now)
        snapshot = FrozenSnapshotBuilder().build(self.sim, self.snapshot_root, self.capability, now=self.now)
        self.assertEqual((snapshot.sqlite_integrity, snapshot.source_file_count), ("ok", snapshot.copied_file_count))
        backup = CanonicalLegacyBackupBuilder().build(snapshot, self.backup_root, self.capability, now=self.now)
        self.assertGreater(backup.file_count, 0)
        proof = CanonicalLegacyBackupBuilder().verify_restore(
            backup, self.control_root / "restore-drill", self.capability, now=self.now
        )
        self.assertTrue(proof["verified"])
        self.assertFalse(proof["writer_activated"])

    def test_migration_publisher_roots_every_source_and_restarts_idempotently(self) -> None:
        snapshot = self.snapshot_root
        (snapshot / "data").mkdir(parents=True)
        (snapshot / "logs/events").mkdir(parents=True)
        with sqlite3.connect(snapshot / "data/sitina.db") as connection:
            connection.execute("CREATE TABLE facts(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            connection.executemany("INSERT INTO facts(value) VALUES(?)", [("a",), ("b",)])
        (snapshot / "logs/events/legacy.jsonl").write_text('{"event_id":"one"}\n', encoding="utf-8")
        coverage = LegacyCoverageBuilder(snapshot, chunk_rows=1, chunk_lines=1).build()
        workspace = self.migration_root
        workspace.mkdir()
        (workspace / ".sitina-bplus-migration-workspace-v1").write_text("phase6b-migration\n", encoding="utf-8")
        genesis, _, provider = self._genesis_and_provider()
        LegacyWriteGate(self.sim).freeze_authorized("snapshot-production-sim-v1", self.capability, now=self.now)
        journal = LocalJournal.open(
            self.sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        cas = LocalCAS.open(
            self.sim, provider, namespace_kind="production_simulation",
            operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        publisher = ProductionMigrationPublisher(snapshot, workspace, coverage, cas, journal, self.capability, now=self.now, chunk_bytes=1024, batch_size=1)
        first = publisher.publish()
        second = ProductionMigrationPublisher(snapshot, workspace, coverage, cas, journal, self.capability, now=self.now + 60, chunk_bytes=1024, batch_size=1).publish()
        self.assertEqual(first.control_transaction_hash, second.control_transaction_hash)
        self.assertEqual((first.published_file_count, first.unresolved_omission_count), (coverage.source_file_count, 0))
        self.assertFalse(first.business_authority or first.cutover_authority)
        journal.close()

    def test_journal_first_runtime_survives_restart_and_projection_rebuild(self) -> None:
        with sqlite3.connect(self.sim / "data/sitina.db") as connection:
            connection.executescript(
                "CREATE TABLE runs(run_id TEXT PRIMARY KEY,phase TEXT,risk_level TEXT,verification_status TEXT,updated_at TEXT,state_json TEXT);"
                "CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,run_id TEXT,trace_id TEXT,event_type TEXT,payload_json TEXT);"
            )
            legacy_state = {"run_id": "legacy-run-r1", "phase": "done", "risk_level": "low", "verification_status": "verified"}
            connection.execute(
                "INSERT INTO runs VALUES(?,?,?,?,?,?)",
                ("legacy-run-r1", "done", "low", "verified", "2026-07-13T00:00:00Z", json.dumps(legacy_state)),
            )
            connection.execute(
                "INSERT INTO events(ts,run_id,trace_id,event_type,payload_json) VALUES(?,?,?,?,?)",
                ("2026-07-13T00:00:00Z", "legacy-run-r1", "legacy-trace", "run_ledger", json.dumps({"event_type": "run_completed", "status": "ok"})),
            )
        genesis, backend, provider = self._genesis_and_provider()
        LegacyWriteGate(self.sim).freeze_authorized("snapshot-production-sim-v1", self.capability, now=self.now)
        FrozenSnapshotBuilder().build(self.sim, self.snapshot_root, self.capability, now=self.now)
        journal = LocalJournal.open(
            self.sim, JournalAuthProvider(provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", operational_capability=self.capability, genesis_hash=genesis.genesis_hash,
        )
        stream = AuthorityControlStream(journal, self.capability, genesis, now=self.now)
        stream.record_genesis_and_prepare(migration_frontier_hash="c" * 64, fence_record_hash=LegacyWriteGate(self.sim).status().record_hash)
        stream.submit_cutover()
        resolution = stream.resolve_authority(now=self.now)
        runtime = BPlusProductionRuntime(self.sim, journal, resolution, now=self.now)
        result = runtime.create_canary_run("bounded dynamic task", agents=("agent-a", "agent-b", "reviewer-c"))
        before = runtime.rebuild_projection(disposable=True)
        run_id = result["run_id"]
        journal.close()
        reopened_provider = MacOSKeychainProvider(environment="production-simulation", namespace=genesis.key_namespace, backend=backend)
        reopened_journal = LocalJournal.open(
            self.sim, JournalAuthProvider(reopened_provider), journal_id=genesis.journal_id, epoch=1,
            namespace_kind="production_simulation", authority_resolution=resolution, genesis_hash=genesis.genesis_hash,
        )
        reopened = BPlusProductionRuntime(self.sim, reopened_journal, resolution, now=self.now)
        self.assertEqual(reopened.show_run(run_id)["status"], "terminal")
        after = reopened.rebuild_projection(disposable=True)
        self.assertEqual(before.semantic_checksum, after.semantic_checksum)
        reopened_journal.close()

        durable = ProductionRuntimeContext.load(
            self.sim, now=self.now + 4000, keychain_backend=backend, allow_simulation=True
        )
        self.assertEqual(durable.authority.resolution.state, AuthorityState.JOURNAL_WRITER_AUTHORIZED)
        self.assertTrue(any(item["run_id"] == "legacy-run-r1" for item in durable.list_runs()))
        self.assertEqual(durable.show_run("legacy-run-r1")["reader_generation"], "legacy-frozen-snapshot-v1")
        routed = SitinaEngine(self.sim, bplus_keychain_backend=backend).run("deployed route", provider_mode="mock")
        self.assertEqual(
            (routed["writer"], routed["routing_generation"]),
            ("journal", "bplus-production-journal-cas-v1"),
        )
        self.assertEqual(routed["provider_call_count"], 0)
        self.assertEqual(routed["legacy_read_count"], 0)
        self.assertEqual(routed["legacy_write_count"], 0)
        self.assertEqual(len(routed["object_refs"]), 3)
        reread = ProductionRuntimeContext.load(
            self.sim, keychain_backend=backend, allow_simulation=True
        )
        self.assertEqual(reread.show_run(routed["run_id"])["status"], "terminal")
        replay = reread.replay_run(routed["run_id"])
        self.assertEqual(replay["status"], "replay_ok")
        self.assertEqual(replay["cas_reference_count"], 3)
        self.assertEqual(replay["cas_read_count"], 3)
        self.assertEqual(replay["external_call_count"], 0)

    def test_operator_cli_executes_controlled_cutover_and_commits_cutover_verified(self) -> None:
        with sqlite3.connect(self.sim / "data/sitina.db") as connection:
            connection.executescript(
                "CREATE TABLE runs(run_id TEXT PRIMARY KEY,phase TEXT,risk_level TEXT,verification_status TEXT,updated_at TEXT,state_json TEXT);"
                "CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,run_id TEXT,trace_id TEXT,event_type TEXT,payload_json TEXT);"
            )
            state = {"run_id": "legacy-operator-run", "phase": "done", "risk_level": "low", "verification_status": "verified"}
            connection.execute(
                "INSERT INTO runs VALUES(?,?,?,?,?,?)",
                ("legacy-operator-run", "done", "low", "verified", "2026-07-13T00:00:00Z", json.dumps(state)),
            )
        self.control_root.mkdir(exist_ok=True)
        manifest_path = self.control_root / "maintenance-manifest.json"
        readiness_path = self.control_root / "readiness.json"
        manifest_path.write_text(json.dumps(self.manifest, sort_keys=True) + "\n", encoding="utf-8")
        readiness_path.write_text(json.dumps(self.readiness, sort_keys=True) + "\n", encoding="utf-8")
        environment = dict(os.environ)
        environment.pop("SITINA_CONTROL_PLANE_READONLY", None)
        environment["SITINA_HOME"] = str(self.sim)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "scripts/cutover-phase6b.py"),
                "--manifest", str(manifest_path),
                "--readiness", str(readiness_path),
                "--expected-manifest-sha256", str(self.manifest["manifest_sha256"]),
                "--expected-readiness-sha256", str(self.readiness["readiness_sha256"]),
                "--allow-simulation",
                "--memory-keychain",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(report["status"], "CUTOVER_VERIFIED")
        self.assertEqual(report["authority_state"], "JOURNAL_WRITER_AUTHORIZED")
        self.assertTrue(report["cutover_verified"]["verified"])
        self.assertFalse(report["legacy_writer_activated_after_fence"])
        self.assertEqual(LegacyWriteGate(self.sim).status().state, "FROZEN_NO_WRITER")


if __name__ == "__main__":
    unittest.main()
