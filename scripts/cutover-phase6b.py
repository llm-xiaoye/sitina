#!/usr/bin/env python3
"""Hash-pinned, fail-closed Sitina B+ Phase 6B cutover operator."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "core"))

from sitina.authority.model import AuthorityState  # noqa: E402
from sitina.cas.local import LocalCAS  # noqa: E402
from sitina.journal.local import LocalJournal  # noqa: E402
from sitina.journal.model import FrontierRef, canonical_json_bytes  # noqa: E402
from sitina.legacy.coverage import (  # noqa: E402
    CanonicalLegacyBackupBuilder,
    CanonicalLegacyBackupResult,
    FrozenSnapshotBuilder,
    FrozenSnapshotResult,
    LegacyCoverageBuilder,
    _hash_regular,
)
from sitina.legacy.fence import LegacyWriteGate  # noqa: E402
from sitina.legacy.migration_control import ProductionMigrationPublisher  # noqa: E402
from sitina.legacy.production_genesis import ProductionGenesisBuilder  # noqa: E402
from sitina.operations.phase6b import AuthorityControlStream, Phase6BManifestVerifier  # noqa: E402
from sitina.orchestrator.bplus_production import BPlusProductionRuntime, ProductionRuntimeContext  # noqa: E402
from sitina.projections.production import production_handlers  # noqa: E402
from sitina.projections.rebuild import ProjectionGeneration  # noqa: E402
from sitina.security.key_provider import JournalAuthProvider, KeyPurpose  # noqa: E402
from sitina.security.macos_keychain import MacOSKeychainProvider, MemoryKeychainBackend  # noqa: E402
from sitina.storage import LegacySnapshotStore  # noqa: E402


class CutoverOperatorError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CutoverOperatorError(f"required control artifact is unavailable: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CutoverOperatorError(f"control artifact is not an object: {path}")
    return value


def _persist_exact(path: Path, value: Mapping[str, object]) -> Path:
    raw = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != raw:
            raise CutoverOperatorError(f"existing control artifact has different bytes: {path}")
        return path
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def _rehydrate_snapshot(path: Path, capability: object) -> FrozenSnapshotResult:
    value = _load(path / "frozen-snapshot-manifest.json")
    claimed = str(value.pop("manifest_sha256", ""))
    if claimed != hashlib.sha256(_canonical(value)).hexdigest():
        raise CutoverOperatorError("existing frozen snapshot manifest hash is invalid")
    if (
        value.get("phase6b_manifest_sha256") != capability.manifest_sha256
        or value.get("intended_snapshot_hash") != capability.production_genesis["intended_snapshot_hash"]
        or value.get("destination") != str(path)
        or value.get("sqlite_integrity") != "ok"
        or value.get("source_closure_verified") is not True
    ):
        raise CutoverOperatorError("existing frozen snapshot differs from the Maintenance Manifest")
    entries = tuple(value.get("entries", ()))
    if len(entries) != int(value.get("copied_file_count", -1)):
        raise CutoverOperatorError("existing frozen snapshot count is invalid")
    for item in entries:
        candidate = path / str(item["path"])
        digest, metadata = _hash_regular(candidate)
        if digest != item["copied_sha256"] or metadata.st_size != int(item["size"]):
            raise CutoverOperatorError(f"existing frozen snapshot file differs: {item['path']}")
    return FrozenSnapshotResult(
        str(value["snapshot_id"]), str(value["source_root"]), str(value["destination"]),
        int(value["source_file_count"]), int(value["copied_file_count"]), str(value["sqlite_integrity"]),
        entries, claimed,
    )


def _rehydrate_backup(path: Path, snapshot: FrozenSnapshotResult) -> CanonicalLegacyBackupResult:
    value = _load(path / "backup-manifest.json")
    claimed = str(value.pop("manifest_sha256", ""))
    if claimed != hashlib.sha256(_canonical(value)).hexdigest():
        raise CutoverOperatorError("existing canonical backup manifest hash is invalid")
    if value.get("source_snapshot_manifest_sha256") != snapshot.manifest_sha256 or value.get("destination") != str(path):
        raise CutoverOperatorError("existing canonical backup differs from the frozen snapshot")
    files = tuple(value.get("files", ()))
    if len(files) != int(value.get("file_count", -1)):
        raise CutoverOperatorError("existing canonical backup count is invalid")
    for item in files:
        candidate = path / str(item["path"])
        digest, metadata = _hash_regular(candidate)
        if digest != item["sha256"] or metadata.st_size != int(item["size"]):
            raise CutoverOperatorError(f"existing canonical backup file differs: {item['path']}")
    return CanonicalLegacyBackupResult(
        str(value["backup_id"]), str(value["source_snapshot_manifest_sha256"]), str(value["destination"]),
        int(value["file_count"]), files, str(value["hold_sha256"]), claimed,
    )


def _projection(journal: LocalJournal, root: Path) -> ProjectionGeneration:
    if journal.head_position < 1:
        raise CutoverOperatorError("Projection rebuild cannot use an empty Journal")
    frontier = FrontierRef(
        journal.journal_id,
        journal.epoch,
        "local",
        journal.head_position,
        journal._position_hash[journal.head_position],
    )
    return ProjectionGeneration.build(root, journal, frontier, production_handlers())


def _report_hash(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(dict(value))).hexdigest()


def execute(
    manifest_path: Path,
    readiness_path: Path,
    *,
    expected_manifest_sha256: str,
    expected_readiness_sha256: str,
    allow_simulation: bool,
    memory_keychain: bool,
    now: int | None = None,
) -> dict[str, object]:
    moment = int(time.time()) if now is None else int(now)
    manifest = _load(manifest_path)
    readiness = _load(readiness_path)
    if manifest.get("manifest_sha256") != expected_manifest_sha256:
        raise CutoverOperatorError("Maintenance Manifest does not match the operator-pinned hash")
    if readiness.get("readiness_sha256") != expected_readiness_sha256:
        raise CutoverOperatorError("CutoverToolingReady does not match the operator-pinned hash")
    capability = Phase6BManifestVerifier.verify_mapping(
        manifest,
        readiness_report=readiness,
        now=moment,
        allow_simulation=allow_simulation,
    )
    if capability.environment_kind == "PRODUCTION" and os.environ.get("SITINA_CONTROL_PLANE_READONLY") == "1":
        raise CutoverOperatorError("Production execution requires the installed Legacy mutation audit hook")
    if memory_keychain and capability.environment_kind != "CONTROLLED_PRODUCTION_SIMULATION":
        raise CutoverOperatorError("memory Keychain backend is prohibited for Production")
    capability.control_root.mkdir(parents=True, exist_ok=True)
    lock_path = capability.control_root / f"phase6b-{capability.manifest_sha256[:24]}.execution.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise CutoverOperatorError("another Phase 6B executor holds the exact operation lock") from error

        snapshot_id = str(capability.production_genesis.get("snapshot_id") or (
            "snapshot-" + str(capability.production_genesis["intended_snapshot_hash"])[:32]
        ))
        capability.assert_operation("INITIALIZE_PRODUCTION_KEY_NAMESPACE", capability.production_home, now=int(time.time()))
        backend = MemoryKeychainBackend() if memory_keychain else None
        provider = MacOSKeychainProvider(
            environment="production" if capability.environment_kind == "PRODUCTION" else "production-simulation",
            namespace=str(capability.production_genesis["key_namespace"]),
            backend=backend,
        )
        for purpose in KeyPurpose:
            provider.current_descriptor(purpose)
        key_inventory = provider.public_inventory()
        if key_inventory.get("secret_values_included") is not False:
            raise CutoverOperatorError("Production key provider public inventory exposed secret material")
        key_inventory_hash = _report_hash(key_inventory)
        fence = LegacyWriteGate(capability.production_home).freeze_authorized(snapshot_id, capability, now=int(time.time()))
        if fence.state != "FROZEN_NO_WRITER" or fence.snapshot_destination != str(capability.snapshot_root):
            raise CutoverOperatorError("Legacy writer fence did not commit the exact snapshot destination")

        snapshot = (
            _rehydrate_snapshot(capability.snapshot_root, capability)
            if capability.snapshot_root.exists()
            else FrozenSnapshotBuilder().build(
                capability.production_home, capability.snapshot_root, capability, now=int(time.time())
            )
        )
        coverage = LegacyCoverageBuilder(capability.snapshot_root).build()
        if coverage.source_coverage_percent != 100 or coverage.unexplained_omission_count != 0:
            raise CutoverOperatorError("frozen Legacy Source Coverage is incomplete")

        backup = (
            _rehydrate_backup(capability.backup_root, snapshot)
            if capability.backup_root.exists()
            else CanonicalLegacyBackupBuilder().build(snapshot, capability.backup_root, capability, now=int(time.time()))
        )
        restore_root = capability.control_root / f"phase6b-{capability.manifest_sha256[:24]}-restore-drill"
        restore_proof_path = capability.control_root / f"phase6b-{capability.manifest_sha256[:24]}-restore-proof.json"
        if restore_proof_path.exists():
            restore_proof = _load(restore_proof_path)
            claimed = str(restore_proof.get("report_sha256", ""))
            body = {key: value for key, value in restore_proof.items() if key != "report_sha256"}
            if claimed != hashlib.sha256(_canonical(body)).hexdigest() or restore_proof.get("verified") is not True:
                raise CutoverOperatorError("persisted restore proof is invalid")
        else:
            if restore_root.exists():
                raise CutoverOperatorError("restore drill directory exists without a committed proof")
            restore_proof = CanonicalLegacyBackupBuilder().verify_restore(
                backup, restore_root, capability, now=int(time.time())
            )
            if restore_proof.get("verified") is not True:
                raise CutoverOperatorError("canonical backup restore drill failed")
            _persist_exact(restore_proof_path, restore_proof)

        genesis_builder = ProductionGenesisBuilder(capability.production_home)
        if (capability.production_home / "state/bplus-production-genesis/genesis.json").exists():
            genesis = genesis_builder.load_persisted()
            if genesis.genesis_hash != capability.production_genesis["genesis_hash"]:
                raise CutoverOperatorError("persisted Production Genesis differs from the Maintenance Manifest")
        else:
            verifier = next(
                str(item["principal_id"]) for item in manifest["operator_quorum"]
                if item["role"] == "INDEPENDENT_TECHNICAL_VERIFIER"
            )
            genesis = genesis_builder.verify_independent(
                genesis_builder.build_authorized(capability, now=int(time.time())), verifier_id=verifier
            )
            genesis_builder.persist_authorized(genesis, capability, now=int(time.time()))

        if provider.namespace != genesis.key_namespace:
            raise CutoverOperatorError("initialized Keychain namespace differs from persisted Genesis")
        namespace = "production" if capability.environment_kind == "PRODUCTION" else "production_simulation"
        journal = LocalJournal.open(
            capability.production_home,
            JournalAuthProvider(provider),
            journal_id=genesis.journal_id,
            epoch=int(genesis.epoch_root.rsplit("-", 1)[1]),
            namespace_kind=namespace,
            operational_capability=capability,
            genesis_hash=genesis.genesis_hash,
        )
        try:
            cas = LocalCAS.open(
                capability.production_home,
                provider,
                namespace_kind=namespace,
                operational_capability=capability,
                genesis_hash=genesis.genesis_hash,
            )
            capability.migration_root.mkdir(parents=True, exist_ok=True)
            marker = capability.migration_root / ".sitina-bplus-migration-workspace-v1"
            _persist_exact(marker, {"schema": "SITINA_BPLUS_MIGRATION_WORKSPACE_V1", "manifest_sha256": capability.manifest_sha256})
            migration = ProductionMigrationPublisher(
                capability.snapshot_root,
                capability.migration_root,
                coverage,
                cas,
                journal,
                capability,
                now=int(time.time()),
            ).publish()
            if migration.unresolved_omission_count != 0:
                raise CutoverOperatorError("migration control reported an unexplained omission")

            control = AuthorityControlStream(journal, capability, genesis, now=int(time.time()))
            control.record_genesis_and_prepare(
                migration_frontier_hash=migration.migration_frontier_hash,
                fence_record_hash=fence.record_hash,
            )
            prepared = control.resolve_authority(now=int(time.time()))
            if prepared.state is not AuthorityState.CUTOVER_PREPARED_NO_WRITER:
                raise CutoverOperatorError("authority did not enter the prepared no-writer state")
            pre_rebuild = _projection(
                journal,
                capability.control_root / f"phase6b-{capability.manifest_sha256[:24]}-precutover-rebuilds",
            )
            reverified = Phase6BManifestVerifier.verify_mapping(
                manifest,
                readiness_report=readiness,
                now=int(time.time()),
                allow_simulation=allow_simulation,
            )
            if reverified.manifest_sha256 != capability.manifest_sha256:
                raise CutoverOperatorError("Maintenance Manifest identity changed before Cutover submission")
            try:
                control.submit_cutover()
            except BaseException:
                journal.close()
                journal = LocalJournal.open(
                    capability.production_home,
                    JournalAuthProvider(provider),
                    journal_id=genesis.journal_id,
                    epoch=int(genesis.epoch_root.rsplit("-", 1)[1]),
                    namespace_kind=namespace,
                    operational_capability=capability,
                    genesis_hash=genesis.genesis_hash,
                )
                control = AuthorityControlStream(journal, capability, genesis, now=int(time.time()))
                recovered = control.recover_cutover()
                if recovered.status.value != "COMMITTED":
                    raise CutoverOperatorError("stable Cutover Command outcome is not committed")
            resolution = control.resolve_authority(now=int(time.time()))
            if resolution.state is not AuthorityState.JOURNAL_WRITER_AUTHORIZED:
                raise CutoverOperatorError("committed Cutover did not resolve unique Journal authority")

            runtime = BPlusProductionRuntime(capability.production_home, journal, resolution, now=int(time.time()))
            canary = runtime.create_canary_run(
                "Phase 6B journal-first mock canary",
                agents=("phase6b-controller", "phase6b-planner", "phase6b-independent-reviewer"),
                command_id="phase6b-mock-canary-" + capability.manifest_sha256[:32],
                occurred_at=str(capability.cutover_verified_command["occurred_at"]),
            )
            post_rebuild = runtime.rebuild_projection(disposable=True)
            legacy_reader = LegacySnapshotStore(
                capability.snapshot_root, intended_snapshot_hash=genesis.intended_snapshot_hash
            )
            legacy_run_count = len(legacy_reader.list_runs(limit=None))
            dual_read = {
                "schema": "PHASE6B_FIXED_FRONTIER_DUAL_READ_V1",
                "legacy_run_count": legacy_run_count,
                "bplus_canary_run_id": canary["run_id"],
                "bplus_canary_status": runtime.show_run(str(canary["run_id"]))["status"],
                "legacy_writer_activated": False,
                "verified": True,
            }
            dual_read_hash = _report_hash(dual_read)
            evidence_core = {
                "schema": "PHASE6B_PRE_CUTOVER_VERIFIED_EVIDENCE_V1",
                "manifest_sha256": capability.manifest_sha256,
                "snapshot_manifest_sha256": snapshot.manifest_sha256,
                "backup_manifest_sha256": backup.manifest_sha256,
                "restore_report_sha256": restore_proof["report_sha256"],
                "coverage_hash": coverage.coverage_hash,
                "migration_transaction_hash": migration.control_transaction_hash,
                "precutover_rebuild_checksum": pre_rebuild.semantic_checksum,
                "postcutover_rebuild_checksum": post_rebuild.semantic_checksum,
                "dual_read_report_sha256": dual_read_hash,
                "canary_transaction_hash": canary["transaction_hash"],
                "effect_capability_ceiling": "MOCK_ONLY",
            }
            evidence_hash = _report_hash(evidence_core)
            available_predicates = {
                "source_coverage": coverage.source_coverage_percent == 100 and coverage.unexplained_omission_count == 0,
                "backup_restore": restore_proof.get("verified") is True,
                "prepared_no_writer": prepared.writer_count == 0,
                "cutover_committed": resolution.authorizes_journal and resolution.writer_count == 1,
                "journal_first": canary.get("status") == "terminal",
                "legacy_zero_write": LegacyWriteGate(capability.production_home).status().state == "FROZEN_NO_WRITER",
                "dual_read": dual_read["verified"] is True,
                "rebuild": bool(pre_rebuild.semantic_checksum and post_rebuild.semantic_checksum),
                "mock_only": True,
                "key_health": bool(key_inventory.get("secret_values_included") is False),
            }
            available_reports = {
                "snapshot": snapshot.manifest_sha256,
                "backup": backup.manifest_sha256,
                "restore": str(restore_proof["report_sha256"]),
                "coverage": coverage.coverage_hash,
                "migration": migration.control_transaction_hash,
                "precutover_rebuild": pre_rebuild.semantic_checksum,
                "postcutover_rebuild": post_rebuild.semantic_checksum,
                "dual_read": dual_read_hash,
                "rebuild": post_rebuild.semantic_checksum,
                "evidence": evidence_hash,
                "key_inventory": key_inventory_hash,
            }
            required_predicates = [str(item) for item in capability.cutover_verified_command["required_predicates"]]
            required_reports = [str(item) for item in capability.cutover_verified_command["required_report_hashes"]]
            if any(name not in available_predicates for name in required_predicates):
                raise CutoverOperatorError("CutoverVerified contract names an unsupported predicate")
            if any(name not in available_reports for name in required_reports):
                raise CutoverOperatorError("CutoverVerified contract names an unsupported report hash")
            predicates = {name: available_predicates[name] for name in required_predicates}
            report_hashes = {name: available_reports[name] for name in required_reports}
            control.submit_cutover_verified(
                command_id=str(capability.cutover_verified_command["command_id"]),
                predicates=predicates,
                report_hashes=report_hashes,
            )
            proof = control.verify_committed_cutover_verified(str(capability.cutover_verified_command["command_id"]))
            if proof.get("verified") is not True:
                raise CutoverOperatorError("CutoverVerified committed fact cannot be independently verified")
            final_frontier = journal.head_position
        finally:
            journal.close()

        durable = ProductionRuntimeContext.load(
            capability.production_home,
            now=int(time.time()),
            keychain_backend=backend,
            allow_simulation=allow_simulation,
        )
        durable_cutover_verified = durable.cutover_verified()
        if durable_cutover_verified.get("verified") is not True:
            raise CutoverOperatorError("durable CutoverVerified reread failed")
        report_core = {
            "schema": "SITINA_BPLUS_PHASE6B_CUTOVER_REPORT_V1",
            "status": "CUTOVER_VERIFIED",
            "manifest_sha256": capability.manifest_sha256,
            "readiness_sha256": capability.readiness_sha256,
            "production_home": str(capability.production_home),
            "snapshot_manifest_sha256": snapshot.manifest_sha256,
            "backup_manifest_sha256": backup.manifest_sha256,
            "restore_report_sha256": restore_proof["report_sha256"],
            "coverage_hash": coverage.coverage_hash,
            "source_file_count": coverage.source_file_count,
            "unexplained_omission_count": coverage.unexplained_omission_count,
            "migration_frontier_hash": migration.migration_frontier_hash,
            "authority_state": durable.authority.resolution.state.value,
            "cutover_verified": durable_cutover_verified,
            "final_journal_position": final_frontier,
            "canary": canary,
            "dual_read": dual_read,
            "precutover_rebuild_checksum": pre_rebuild.semantic_checksum,
            "postcutover_rebuild_checksum": post_rebuild.semantic_checksum,
            "effect_capability_ceiling": "MOCK_ONLY",
            "key_inventory_sha256": key_inventory_hash,
            "key_provider_profile": key_inventory.get("provider_profile", key_inventory.get("schema")),
            "legacy_writer_activated_after_fence": False,
            "business_writer_count": durable.authority.resolution.writer_count,
        }
        report = {**report_core, "report_sha256": _report_hash(report_core)}
        report_path = capability.control_root / f"sitina-bplus-phase6b-cutover-{capability.manifest_sha256[:24]}.json"
        _persist_exact(report_path, report)
        return {**report, "report_path": str(report_path)}
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cutover-phase6b.py")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--readiness", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-readiness-sha256", required=True)
    parser.add_argument("--allow-simulation", action="store_true")
    parser.add_argument("--memory-keychain", action="store_true", help="controlled simulation only")
    parser.add_argument("--admit-only", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.admit_only:
        manifest = _load(arguments.manifest)
        readiness = _load(arguments.readiness)
        if manifest.get("manifest_sha256") != arguments.expected_manifest_sha256:
            raise CutoverOperatorError("Maintenance Manifest does not match the pinned hash")
        if readiness.get("readiness_sha256") != arguments.expected_readiness_sha256:
            raise CutoverOperatorError("CutoverToolingReady does not match the pinned hash")
        capability = Phase6BManifestVerifier.verify_mapping(
            manifest, readiness_report=readiness, allow_simulation=arguments.allow_simulation
        )
        print(json.dumps({
            "status": "ADMITTED_READ_ONLY",
            "manifest_sha256": capability.manifest_sha256,
            "environment_kind": capability.environment_kind,
            "production_home": str(capability.production_home),
            "authority": False,
            "production_mutated": False,
        }, sort_keys=True))
        return 0
    report = execute(
        arguments.manifest,
        arguments.readiness,
        expected_manifest_sha256=arguments.expected_manifest_sha256,
        expected_readiness_sha256=arguments.expected_readiness_sha256,
        allow_simulation=arguments.allow_simulation,
        memory_keychain=arguments.memory_keychain,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
