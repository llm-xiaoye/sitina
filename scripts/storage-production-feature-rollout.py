#!/usr/bin/env python3
"""Prepare, activate, checkpoint, and verify the required Storage V2 writers.

The Production mode is deliberately coupled to a byte-exact prior simulation,
source manifest, raw Production Sentinel, verified restore receipt, and backup
frontier.  Evidence is written outside the target installation.
"""

from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

from sitina.archive.production_backup import (
    ProductionBackupManifest,
    derive_verified_frontier,
    load_restored_genesis,
)
from sitina.compatibility.capabilities import FormatCapabilityRegistry
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.compatibility.rollout import JournalFeatureRollout
from sitina.journal.fast_start import FullJournalVerifier, RollbackAnchorStore
from sitina.journal.model import FrontierRef, canonical_json_bytes
from sitina.legacy.fence import LegacyWriteGate, authorized_compatibility_rollout
from sitina.operations.phase6b import ProductionAuthorityReader
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.projections.generations import ProjectionGenerationPublisher, ProjectionGenerationReader
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers
from sitina.projections.rebuild import ProjectionGeneration
from sitina.security.key_provider import JournalAuthProvider
from sitina.security.macos_keychain import (
    IsolatedOverlayKeychainBackend,
    MacOSKeychainProvider,
    MemoryKeychainBackend,
)
from sitina.storage import DisabledLegacyStore, LegacyRuntimePolicy


PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
FEATURES = (
    ("agent_context_v2_write", ("agent-context-v2",)),
    ("memory_v1_write", ("memory-v1",)),
    ("cas_zstd_write", ("cas-zstd",)),
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        raw = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short feature-rollout evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _validate_source_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "CONTENT_MANIFEST_V1" or Path(str(value.get("root"))) != PRODUCTION_HOME:
        raise RuntimeError("source manifest identity is invalid")
    unsigned = {key: item for key, item in value.items() if key != "manifest_sha256"}
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != value.get("manifest_sha256"):
        raise RuntimeError("source manifest commitment is invalid")
    for item in value.get("entries", ()):
        target = PRODUCTION_HOME / str(item["path"])
        if target.is_symlink() or not target.is_file():
            raise RuntimeError("source manifest entry is unavailable")
        if target.stat().st_size != int(item["size"]) or _sha256(target) != item["sha256"]:
            raise RuntimeError("source changed after its exact simulation manifest")
    return value


def _validate_sentinel(path: Path, goal_thread_id: str) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "SITINA_STORAGE_PRODUCTION_SENTINEL_V1":
        raise RuntimeError("before Sentinel schema is invalid")
    if value.get("goal_thread_id") != goal_thread_id:
        raise RuntimeError("before Sentinel and rollout Goal identities differ")
    unsigned = {key: item for key, item in value.items() if key != "report_sha256"}
    expected = hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if value.get("report_sha256") != expected:
        raise RuntimeError("before Sentinel commitment is invalid")
    return value


def _restore_semantic(value: dict[str, object]) -> dict[str, object]:
    candidate: Any = value
    for _ in range(4):
        semantic = candidate.get("semantic") if isinstance(candidate, dict) else None
        if isinstance(semantic, dict):
            return semantic
        candidate = candidate.get("restore") if isinstance(candidate, dict) else None
    raise RuntimeError("restore prerequisite has no semantic verification")


def _validate_restore(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    semantic = _restore_semantic(value)
    if semantic.get("verified") is not True or semantic.get("full_replay_verified") is not True:
        raise RuntimeError("restore prerequisite lacks independent full replay verification")
    for domain in ("checkpoint_recovery", "session_recovery", "memory_recovery", "evidence_recovery"):
        item = semantic.get(domain)
        if not isinstance(item, dict) or not any(
            key.endswith("_state_reconstructed") and result is True for key, result in item.items()
        ):
            raise RuntimeError(f"restore prerequisite lacks {domain}")
    return value


def _seed_simulation_anchor(
    home: Path,
    provider: MacOSKeychainProvider,
    backend: MemoryKeychainBackend,
    journal_id: str,
) -> None:
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(provider),
        authority_key_provider=provider,
    ).verify()
    checkpoint_path = sorted((home / "journal/checkpoints").glob("checkpoint-*.json"))[-1]
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    activations = FeatureActivationRegistry.from_journal_events(full.verified_events)
    RollbackAnchorStore(backend, journal_id=journal_id).update(
        latest_epoch=int(checkpoint["epoch"]),
        latest_checkpoint_sequence=int(checkpoint["checkpoint_sequence"]),
        latest_checkpoint_commitment=full.checkpoint_commitment,
        active_format_capabilities_hash=activations.active_capabilities_hash,
    )


def _restored_loader(
    home: Path,
    manifest: ProductionBackupManifest,
) -> tuple[Callable[[], ProductionRuntimeContext], IsolatedOverlayKeychainBackend, MemoryKeychainBackend]:
    if (
        home == PRODUCTION_HOME
        or not (home / ".sitina-bplus-disposable-v1").is_file()
        or not (home / ".sitina-clean-acceptance-v1").is_file()
    ):
        raise RuntimeError("simulation requires disposable and clean-acceptance markers")
    genesis = load_restored_genesis(home, manifest)
    source_provider = MacOSKeychainProvider(environment="production", namespace=genesis.key_namespace)
    overlay = IsolatedOverlayKeychainBackend(source_provider.backend, isolated_services=(RollbackAnchorStore.SERVICE,))
    provider = MacOSKeychainProvider(environment="production", namespace=genesis.key_namespace, backend=overlay)
    anchor_backend = MemoryKeychainBackend()
    _seed_simulation_anchor(home, provider, anchor_backend, genesis.journal_id)

    def load() -> ProductionRuntimeContext:
        fence = LegacyWriteGate(home).read_verified_record()
        if fence is None or fence.get("state") != "FROZEN_NO_WRITER":
            raise RuntimeError("restored simulation has no verified no-writer fence")
        epoch = int(genesis.epoch_root.rsplit("-", 1)[1])
        authority = ProductionAuthorityReader.resolve(
            home,
            JournalAuthProvider(provider),
            journal_id=genesis.journal_id,
            epoch=epoch,
            command_id=str(fence["cutover_command_id"]),
            request_hash=str(fence["cutover_request_hash"]),
            genesis_hash=genesis.genesis_hash,
            snapshot_hash=genesis.intended_snapshot_hash,
            fence_record_hash=str(fence["record_hash"]),
            now=int(time.time()),
            authority_key_provider=provider,
            rollback_anchor=RollbackAnchorStore(anchor_backend, journal_id=genesis.journal_id),
        )
        policy = LegacyRuntimePolicy.load(home)
        if not policy.fully_disabled:
            raise RuntimeError("restored simulation requires fully disabled Legacy reads")
        return ProductionRuntimeContext(
            home,
            genesis,
            dict(fence),
            provider,
            authority,
            DisabledLegacyStore(policy),
            policy,
            _restored_simulation_namespace=True,
            _rollback_anchor_backend=anchor_backend,
        )

    return load, overlay, anchor_backend


def _production_loader(home: Path) -> Callable[[], ProductionRuntimeContext]:
    if home != PRODUCTION_HOME:
        raise RuntimeError("Production rollout root is not the fixed installation")
    return lambda: ProductionRuntimeContext.load(home)


def _checkpoint_document(home: Path) -> tuple[dict[str, object], Path]:
    paths = sorted((home / "journal/checkpoints").glob("checkpoint-*.json"))
    if not paths:
        raise RuntimeError("Authority Checkpoint is unavailable")
    return json.loads(paths[-1].read_text(encoding="utf-8")), paths[-1]


def _key_preflight(context: ProductionRuntimeContext) -> dict[str, object]:
    accounts = (
        "journal-auth:v1",
        "cas-kek:v1",
        "cas-commitment:v1",
        "authority-signing:v1",
        "evidence-signing:v1",
    )
    for account in accounts:
        material = context.provider.backend.get(context.provider.service, account)
        if material is None or len(material) != 32:
            raise RuntimeError("required protected Keychain material is absent or invalid")
    return {"service": context.provider.service, "required_accounts_present": list(accounts), "secret_values_included": False}


def _sidecars(home: Path) -> list[str]:
    found: list[str] = []
    for name in ("current", "building"):
        for path in sorted((home / "projections" / name).glob("*.sqlite-*")):
            found.append(path.relative_to(home).as_posix())
    return found


def _expected_run_rows(events: tuple[Any, ...], limit: int) -> list[tuple[str, str]]:
    created: dict[str, Any] = {}
    terminal: dict[str, int] = {}
    for event in events:
        run_id = event.payload.get("run_id")
        if not isinstance(run_id, str):
            continue
        if event.event_type == "run.created":
            created[run_id] = event
        elif event.event_type == "run.terminal":
            terminal[run_id] = event.position
    ordered = sorted(created, key=lambda item: terminal.get(item, created[item].position), reverse=True)[:limit]
    return [(run_id, "done" if run_id in terminal else "active") for run_id in ordered]


def _rollout(
    *,
    mode: str,
    home: Path,
    load_context: Callable[[], ProductionRuntimeContext],
    goal_thread_id: str,
    expected_initial: FrontierRef,
) -> dict[str, object]:
    context = load_context()
    initial = derive_verified_frontier(context)
    if initial != expected_initial:
        raise RuntimeError("rollout starting frontier differs from the verified backup")
    initial_fast = context.authority.fast_start_report
    if initial_fast is None or not initial_fast.fast_start_checkpoint_used:
        raise RuntimeError("writer rollout requires the already-activated Fast Start read path")
    formats = FormatCapabilityRegistry.load(home / "config/format_capabilities.json")
    key_preflight = _key_preflight(context)
    started = dt.datetime.now(dt.timezone.utc)
    process_id = f"storage-feature-rollout-{mode}-{os.getpid()}"
    capabilities = tuple(sorted({item for _feature, required in FEATURES for item in required}))
    lease = RuntimeCompatibilityLease.build(
        process_id=process_id,
        binary_version="2.0.0",
        reader_capabilities=capabilities,
        writer_capabilities=capabilities,
        started_at=started.isoformat().replace("+00:00", "Z"),
        lease_expires_at=(started + dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        fencing_token=1,
    )
    receipts: list[dict[str, object]] = []
    journal = context.open_writer()
    try:
        coordinator = journal.rollover_coordinator
        if coordinator is None:
            raise RuntimeError("Fast Start writer has no checkpoint coordinator")
        with authorized_compatibility_rollout(journal, goal_thread_id=goal_thread_id, process_id=process_id):
            leases = CompatibilityLeaseRegistry(home)
            leases.register(lease)
            try:
                rollout = JournalFeatureRollout(
                    journal,
                    leases,
                    formats,
                    process_id=process_id,
                    fencing_token=lease.fencing_token,
                    binary_version=lease.binary_version,
                    actor="storage-production-closure-operator",
                    goal_thread_id=goal_thread_id,
                )
                for feature, required in FEATURES:
                    receipts.append(
                        rollout.prepare(feature, required_reader_capabilities=required, occurred_at=_utc_now()).mapping()
                    )
                prepared = FeatureActivationRegistry.from_journal_events(journal.iter_events(0))
                if any(prepared.state(feature) is None or prepared.state(feature).state != "PREPARED" for feature, _ in FEATURES):
                    raise RuntimeError("prepared feature state did not replay")
                for feature, _required in FEATURES:
                    receipts.append(rollout.activate(feature, occurred_at=_utc_now()).mapping())
                activated = FeatureActivationRegistry.from_journal_events(journal.iter_events(0))
                if any(
                    activated.state(feature) is None
                    or activated.state(feature).state != "ACTIVATED"
                    or activated.state(feature).rollback_floor_version != 2
                    for feature, _ in FEATURES
                ):
                    raise RuntimeError("activated feature state or rollback floor did not replay")
                checkpoint_values = dict(coordinator.checkpoint_context("storage-v2-feature-rollout"))
                checkpoint = coordinator.maintainer.rollover_and_checkpoint(journal, **checkpoint_values)
            finally:
                leases.release(process_id, fencing_token=lease.fencing_token)
    finally:
        journal.close()

    fast_context = load_context()
    fast = fast_context.authority.fast_start_report
    if fast is None or not fast.fast_start_checkpoint_used or fast.active_tail_event_count != 0:
        raise RuntimeError("post-rollout Fast Start did not use a fully sealed checkpoint")
    full_started = time.monotonic()
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(fast_context.provider),
        authority_key_provider=fast_context.provider,
    ).verify()
    full_seconds = time.monotonic() - full_started
    if full.authority_state != fast.authority_state:
        raise RuntimeError("post-rollout Fast Start differs from independent full replay")
    full_features = FeatureActivationRegistry.from_journal_events(full.verified_events)
    fast_features = FeatureActivationRegistry.from_journal_events(
        tuple(fast.authority_control_events) + tuple(fast.active_tail_events)
    )
    for feature, _required in FEATURES:
        full_item = full_features.state(feature)
        fast_item = fast_features.state(feature)
        if full_item is None or fast_item is None or full_item != fast_item or full_item.state != "ACTIVATED":
            raise RuntimeError("Fast Start omitted or changed an activated writer feature")
    if full_features.active_capabilities_hash != fast_features.active_capabilities_hash:
        raise RuntimeError("Fast Start feature commitment differs from full replay")
    checkpoint_on_disk, checkpoint_path = _checkpoint_document(home)
    if checkpoint_on_disk != checkpoint:
        raise RuntimeError("published checkpoint differs from the writer receipt")
    if checkpoint_on_disk.get("rollback_floor_version") != "2" or checkpoint_on_disk.get("minimum_writer_version") != "2":
        raise RuntimeError("Authority Checkpoint did not raise the writer rollback floor")
    anchor_backend = fast_context._rollback_anchor_backend or fast_context.provider.backend
    anchor = RollbackAnchorStore(anchor_backend, journal_id=fast.authority_state.journal_id).read()
    if anchor is None or anchor.get("active_format_capabilities_hash") != full_features.active_capabilities_hash:
        raise RuntimeError("rollback anchor did not bind the active format capability hash")

    frontier = FrontierRef(
        fast.authority_state.journal_id,
        fast.authority_state.epoch,
        "local",
        fast.authority_state.head_position,
        fast.authority_state.last_transaction_hash,
    )

    class FullReadView:
        def iter_events(self, after_position: int = 0):
            return iter(event for event in full.verified_events if event.position > after_position)

    projection_started = time.monotonic()
    generation = ProjectionGeneration.build(home / "projections/building", FullReadView(), frontier, production_handlers())
    pointer = ProjectionGenerationPublisher(
        home / "projections",
        feature_activations=full_features,
        authority_key_provider=fast_context.provider,
    ).publish(
        generation_id=generation.generation_id,
        building_database=generation.database_path,
        authority_checkpoint_commitment=fast.checkpoint_commitment,
        journal_frontier=frontier.position,
        schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
        created_at=_utc_now(),
    )
    projection_seconds = time.monotonic() - projection_started
    selected = ProjectionGenerationReader(home / "projections").select(
        authority_checkpoint_commitments=(fast.checkpoint_commitment,),
        schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
    )
    if selected.pointer != pointer:
        raise RuntimeError("new Projection V2 generation is not exactly selectable")
    sidecars = _sidecars(home)
    if sidecars:
        raise RuntimeError("Projection V2 publish left SQLite sidecars in mutable generation directories")
    final_context = load_context()
    rows = final_context.list_runs(limit=50)
    actual = [(str(row["run_id"]), str(row["phase"])) for row in rows]
    expected = _expected_run_rows(tuple(full.verified_events), 50)
    if actual != expected:
        raise RuntimeError("Projection V2 state differs from independent full replay")
    replay = final_context.replay_run(actual[0][0]) if actual else {"status": "no_runs"}
    if actual and replay.get("status") != "replay_ok":
        raise RuntimeError("explicit post-rollout authoritative replay failed")
    return {
        "mode": mode,
        "home": str(home),
        "initial_frontier": initial.__dict__,
        "activated_frontier": frontier.__dict__,
        "appended_event_count": frontier.position - initial.position,
        "feature_receipts": receipts,
        "active_capabilities_hash": full_features.active_capabilities_hash,
        "rollback_plan": {
            "pre_first_write_backup_id": "bound-by-top-level-evidence",
            "rollback_floor_version": 2,
            "rollback_safe_after_first_write": False,
            "bulk_data_rewrite_performed": False,
            "reader_support_prevalidated": True,
        },
        "checkpoint": {
            "path": checkpoint_path.relative_to(home).as_posix(),
            "commitment": fast.checkpoint_commitment,
            "sequence": int(checkpoint_on_disk["checkpoint_sequence"]),
            "verified_through_position": fast.verified_through_position,
            "rollback_floor_version": int(checkpoint_on_disk["rollback_floor_version"]),
            "minimum_writer_version": int(checkpoint_on_disk["minimum_writer_version"]),
            "sealed_segment_count": fast.sealed_segment_count,
            "active_tail_event_count": fast.active_tail_event_count,
            "journal_bytes_scanned": fast.journal_bytes_scanned,
            "journal_events_verified": fast.journal_events_verified,
        },
        "projection": pointer,
        "projection_sidecars": sidecars,
        "fast_start_equals_full_replay": True,
        "projection_equals_full_replay": True,
        "explicit_replay": replay,
        "writer_count": 1,
        "legacy_read_count": 0,
        "external_effect_count": 0,
        "credentials_copied": False,
        "key_material_preflight": key_preflight,
        "timings_seconds": {
            "full_replay": full_seconds,
            "projection_build_publish": projection_seconds,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Activate the minimal required Sitina Storage V2 writer set.")
    parser.add_argument("--mode", choices=("simulate", "production"), required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--before-sentinel", type=Path, required=True)
    parser.add_argument("--restore-evidence", type=Path, required=True)
    parser.add_argument("--simulation-evidence", type=Path)
    parser.add_argument("--goal-thread-id", required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    evidence_output = args.evidence_output.expanduser().resolve(strict=False)
    if evidence_output == home or home in evidence_output.parents:
        raise RuntimeError("feature-rollout evidence must be outside the activated home")
    backup = ProductionBackupManifest.load(args.backup_root.expanduser().resolve(strict=True))
    if backup.metadata.goal_thread_id != args.goal_thread_id:
        raise RuntimeError("backup and rollout Goal identities differ")
    source_path = args.source_manifest.expanduser().resolve(strict=True)
    sentinel_path = args.before_sentinel.expanduser().resolve(strict=True)
    restore_path = args.restore_evidence.expanduser().resolve(strict=True)
    source = _validate_source_manifest(source_path)
    sentinel = _validate_sentinel(sentinel_path, args.goal_thread_id)
    _validate_restore(restore_path)
    overlay = None
    anchor_backend = None
    if args.mode == "simulate":
        load_context, overlay, anchor_backend = _restored_loader(home, backup)
    else:
        if args.simulation_evidence is None:
            raise RuntimeError("Production rollout requires exact successful simulation evidence")
        simulation_path = args.simulation_evidence.expanduser().resolve(strict=True)
        simulation = json.loads(simulation_path.read_text(encoding="utf-8"))
        exact = (
            simulation.get("status") == "PASSED"
            and simulation.get("goal_thread_id") == args.goal_thread_id
            and simulation.get("backup_id") == backup.backup_id
            and simulation.get("backup_manifest_hash") == backup.manifest_hash
            and simulation.get("source_manifest_sha256") == source.get("manifest_sha256")
            and simulation.get("source_manifest_file_sha256") == _sha256(source_path)
            and simulation.get("before_sentinel_file_sha256") == _sha256(sentinel_path)
            and simulation.get("before_sentinel_report_sha256") == sentinel.get("report_sha256")
            and simulation.get("restore_evidence_file_sha256") == _sha256(restore_path)
            and simulation.get("rollout", {}).get("mode") == "simulate"
            and simulation.get("rollout", {}).get("initial_frontier") == backup.metadata.frontier.__dict__
            and simulation.get("feature_set") == [feature for feature, _ in FEATURES]
        )
        if not exact:
            raise RuntimeError("Production prerequisites differ from the exact successful simulation")
        load_context = _production_loader(home)
        if derive_verified_frontier(load_context()) != backup.metadata.frontier:
            raise RuntimeError("Production Journal frontier changed after the pre-rollout backup")
    rollout = _rollout(
        mode=args.mode,
        home=home,
        load_context=load_context,
        goal_thread_id=args.goal_thread_id,
        expected_initial=backup.metadata.frontier,
    )
    evidence: dict[str, object] = {
        "schema": "SITINA_STORAGE_V2_WRITER_FEATURE_ROLLOUT_V1",
        "status": "PASSED",
        "goal_thread_id": args.goal_thread_id,
        "feature_set": [feature for feature, _ in FEATURES],
        "backup_id": backup.backup_id,
        "backup_manifest_hash": backup.manifest_hash,
        "backup_manifest_file_sha256": _sha256(backup.backup_root / "backup-manifest.json"),
        "source_manifest_sha256": source["manifest_sha256"],
        "source_manifest_file_sha256": _sha256(source_path),
        "before_sentinel_report_sha256": sentinel["report_sha256"],
        "before_sentinel_file_sha256": _sha256(sentinel_path),
        "restore_evidence_file_sha256": _sha256(restore_path),
        "rollout": rollout,
        "simulation_overlay": overlay.public_inventory() if overlay is not None else None,
        "simulation_anchor_item_count": anchor_backend.public_inventory()["item_count"] if anchor_backend is not None else None,
        "production_rollback_anchor_advanced": args.mode == "production",
        "credentials_copied": False,
        "external_effect_count": 0,
        "completed_at": _utc_now(),
    }
    _atomic_json(evidence_output, evidence)
    print(json.dumps(evidence, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "FAILED_CLOSED",
                    "error_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise
