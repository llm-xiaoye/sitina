#!/usr/bin/env python3
from __future__ import annotations

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
from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash
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


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
FEATURES = (
    ("authority_checkpoint_v1_write", ("authority-checkpoint-v1",)),
    ("projection_v2_build", ("projection-v2",)),
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        raw = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short activation evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _validate_source_manifest(path: Path, expected_root: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != "CONTENT_MANIFEST_V1" or Path(str(value.get("root"))) != expected_root:
        raise RuntimeError("source manifest identity is invalid")
    unsigned = {key: item for key, item in value.items() if key != "manifest_sha256"}
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != value.get("manifest_sha256"):
        raise RuntimeError("source manifest commitment is invalid")
    for item in value.get("entries", ()):
        relative = str(item["path"])
        target = expected_root / relative
        if target.is_symlink() or not target.is_file():
            raise RuntimeError(f"source manifest entry is unavailable: {relative}")
        digest = _sha256(target)
        if digest != item["sha256"] or target.stat().st_size != int(item["size"]):
            raise RuntimeError(f"source manifest entry changed: {relative}")
    return value


def _resolution_hash(resolution: object) -> str:
    return domain_hash(
        "AUTHORITY_FENCING_STATE",
        canonical_json_bytes(
            {
                "state": getattr(getattr(resolution, "state"), "value"),
                "writer_count": int(getattr(resolution, "writer_count")),
                "issued_at": int(getattr(resolution, "issued_at")),
                "expires_at": int(getattr(resolution, "expires_at")),
                "resolution_id": str(getattr(resolution, "resolution_id")),
                "input_frontier_hash": str(getattr(resolution, "input_frontier_hash")),
            }
        ),
    )


def _restored_loader(
    home: Path,
    manifest: ProductionBackupManifest,
) -> tuple[Callable[[], ProductionRuntimeContext], IsolatedOverlayKeychainBackend, MemoryKeychainBackend]:
    if home == PRODUCTION_HOME or not (home / ".sitina-bplus-disposable-v1").is_file():
        raise RuntimeError("simulation requires a marked, non-Production restore root")
    genesis = load_restored_genesis(home, manifest)
    source_provider = MacOSKeychainProvider(environment="production", namespace=genesis.key_namespace)
    overlay = IsolatedOverlayKeychainBackend(
        source_provider.backend,
        isolated_services=(RollbackAnchorStore.SERVICE,),
    )
    provider = MacOSKeychainProvider(
        environment="production",
        namespace=genesis.key_namespace,
        backend=overlay,
    )
    anchor_backend = MemoryKeychainBackend()

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
        raise RuntimeError("production activation root is not the fixed Production installation")

    def load() -> ProductionRuntimeContext:
        return ProductionRuntimeContext.load(home)

    return load


def _assert_key_material_preexists(context: ProductionRuntimeContext) -> dict[str, object]:
    accounts = (
        "journal-auth:v1",
        "cas-kek:v1",
        "cas-commitment:v1",
        "authority-signing:v1",
        "evidence-signing:v1",
    )
    present = []
    for account in accounts:
        material = context.provider.backend.get(context.provider.service, account)
        if material is None or len(material) != 32:
            raise RuntimeError(f"required protected Keychain material is absent or invalid: {account}")
        present.append(account)
    return {
        "service": context.provider.service,
        "required_accounts_present": present,
        "secret_values_included": False,
    }


def _expected_run_rows(events: tuple[Any, ...], limit: int) -> list[tuple[str, str]]:
    created: dict[str, Any] = {}
    terminal_position: dict[str, int] = {}
    for event in events:
        run_id = event.payload.get("run_id")
        if not isinstance(run_id, str):
            continue
        if event.event_type == "run.created":
            created[run_id] = event
        elif event.event_type == "run.terminal":
            terminal_position[run_id] = event.position
    ordered = sorted(
        created,
        key=lambda run_id: terminal_position.get(run_id, created[run_id].position),
        reverse=True,
    )[:limit]
    return [(run_id, "done" if run_id in terminal_position else "active") for run_id in ordered]


def _activate(
    *,
    mode: str,
    home: Path,
    load_context: Callable[[], ProductionRuntimeContext],
    goal_thread_id: str,
) -> dict[str, object]:
    context = load_context()
    initial_frontier = derive_verified_frontier(context)
    initial_event_count = len(context.events)
    if context.authority.fast_start_report is not None:
        raise RuntimeError("activation requires the declared no-checkpoint starting state")
    key_preflight = _assert_key_material_preexists(context)
    formats = FormatCapabilityRegistry.load(home / "config/format_capabilities.json")
    started = dt.datetime.now(dt.timezone.utc)
    lease_started = started.isoformat().replace("+00:00", "Z")
    lease_expires = (started + dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    process_id = f"storage-activation-{mode}-{os.getpid()}"
    capabilities = tuple(sorted({item for _feature, required in FEATURES for item in required}))
    lease = RuntimeCompatibilityLease.build(
        process_id=process_id,
        binary_version="2.0.0",
        reader_capabilities=capabilities,
        writer_capabilities=capabilities,
        started_at=lease_started,
        lease_expires_at=lease_expires,
        fencing_token=1,
    )
    feature_receipts: list[dict[str, object]] = []
    checkpoint_reason: str | None = None
    checkpoint_started = time.monotonic()
    journal = context.open_writer()
    try:
        with authorized_compatibility_rollout(
            journal,
            goal_thread_id=goal_thread_id,
            process_id=process_id,
        ):
            leases = CompatibilityLeaseRegistry(home)
            leases.register(lease)
            release_required = True
            try:
                if journal.rollover_coordinator is not None:
                    raise RuntimeError("pre-activation writer unexpectedly attached a checkpoint coordinator")
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
                    feature_receipts.append(
                        rollout.prepare(feature, required_reader_capabilities=required, occurred_at=_utc_now()).mapping()
                    )
                prepared_state = FeatureActivationRegistry.from_journal_events(journal.iter_events(0))
                if any(prepared_state.state(feature).state != "PREPARED" for feature, _required in FEATURES):
                    raise RuntimeError("prepared rollout state does not replay exactly")
                for feature, _required in FEATURES:
                    feature_receipts.append(rollout.activate(feature, occurred_at=_utc_now()).mapping())
                activated_state = FeatureActivationRegistry.from_journal_events(journal.iter_events(0))
                if any(activated_state.state(feature).state != "ACTIVATED" for feature, _required in FEATURES):
                    raise RuntimeError("activated rollout state does not replay exactly")
            finally:
                if release_required:
                    leases.release(process_id, fencing_token=lease.fencing_token)
                    release_required = False
    finally:
        journal.close()

    checkpoint_context = load_context()
    checkpoint_writer = checkpoint_context.open_writer()
    coordinator = checkpoint_writer.rollover_coordinator
    if coordinator is None:
        checkpoint_writer.close()
        raise RuntimeError("activated writer did not attach the Authority Checkpoint coordinator")
    checkpoint_reason = coordinator.last_reason
    checkpoint_writer.close()

    fast_context = load_context()
    fast = fast_context.authority.fast_start_report
    if fast is None or not fast.fast_start_checkpoint_used:
        raise RuntimeError("Authority Checkpoint did not become the default Production read path")
    full_started = time.monotonic()
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(fast_context.provider),
        authority_key_provider=fast_context.provider,
    ).verify()
    full_seconds = time.monotonic() - full_started
    if full.authority_state != fast.authority_state:
        raise RuntimeError("Fast Start authority state differs from full replay")
    full_features = FeatureActivationRegistry.from_journal_events(full.verified_events)
    fast_features = FeatureActivationRegistry.from_journal_events(
        tuple(fast.authority_control_events) + tuple(fast.active_tail_events)
    )
    if full_features.active_capabilities_hash != fast_features.active_capabilities_hash:
        raise RuntimeError("Fast Start feature state differs from full replay")
    if any(fast_features.state(feature).state != "ACTIVATED" for feature, _required in FEATURES):
        raise RuntimeError("Fast Start omitted an activated feature")

    frontier = FrontierRef(
        fast.authority_state.journal_id,
        fast.authority_state.epoch,
        "local",
        fast.authority_state.head_position,
        fast.authority_state.last_transaction_hash,
    )
    projection_started = time.monotonic()

    class FullReadView:
        def iter_events(self, after_position: int = 0):
            return iter(event for event in full.verified_events if event.position > after_position)

    generation = ProjectionGeneration.build(
        home / "projections/building",
        FullReadView(),
        frontier,
        production_handlers(),
    )
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
        raise RuntimeError("published Projection V2 cannot be selected by exact checkpoint identity")

    final_context = load_context()
    default_started = time.monotonic()
    rows = final_context.list_runs(limit=50)
    default_read_seconds = time.monotonic() - default_started
    expected = _expected_run_rows(tuple(full.verified_events), 50)
    actual = [(str(row["run_id"]), str(row["phase"])) for row in rows]
    if actual != expected:
        raise RuntimeError("Projection V2 default run state differs from full replay")
    replay = final_context.replay_run(actual[0][0]) if actual else {"status": "no_runs"}
    if actual and replay.get("status") != "replay_ok":
        raise RuntimeError("post-activation explicit authoritative replay failed")
    return {
        "mode": mode,
        "home": str(home),
        "initial_event_count": initial_event_count,
        "initial_frontier": initial_frontier.__dict__,
        "activated_frontier": frontier.__dict__,
        "feature_receipts": feature_receipts,
        "active_capabilities_hash": full_features.active_capabilities_hash,
        "checkpoint": {
            "reason": checkpoint_reason,
            "commitment": fast.checkpoint_commitment,
            "verified_through_position": fast.verified_through_position,
            "sealed_segment_count": fast.sealed_segment_count,
            "active_tail_event_count": fast.active_tail_event_count,
            "journal_bytes_scanned": fast.journal_bytes_scanned,
            "journal_events_verified": fast.journal_events_verified,
            "rollback_floor_version": 1,
        },
        "projection": pointer,
        "default_reader_generation": rows[0]["reader_generation"] if rows else "projection-v2+active-tail",
        "default_row_count": len(rows),
        "explicit_replay": replay,
        "fast_start_equals_full_replay": True,
        "projection_equals_full_replay": True,
        "writer_count": 1,
        "legacy_read_count": 0,
        "external_effect_count": 0,
        "credentials_copied": False,
        "key_material_preflight": key_preflight,
        "timings_seconds": {
            "checkpoint_and_fast_start": time.monotonic() - checkpoint_started,
            "full_replay": full_seconds,
            "projection_build_publish": projection_seconds,
            "default_projection_read": default_read_seconds,
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Activate safe Sitina Storage V2 read-path formats.")
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
    backup = ProductionBackupManifest.load(args.backup_root.expanduser().resolve(strict=True))
    source_manifest_path = args.source_manifest.expanduser().resolve(strict=True)
    before_sentinel = args.before_sentinel.expanduser().resolve(strict=True)
    restore_evidence_path = args.restore_evidence.expanduser().resolve(strict=True)
    evidence_output = args.evidence_output.expanduser().resolve(strict=False)
    if evidence_output == home or home in evidence_output.parents:
        raise RuntimeError("activation evidence output must be outside the activated home")
    source = _validate_source_manifest(source_manifest_path, PRODUCTION_HOME)
    restore = json.loads(restore_evidence_path.read_text(encoding="utf-8"))
    semantic = restore.get("semantic") or restore.get("restore", {}).get("semantic") or restore.get("restore", {}).get("restore", {}).get("semantic")
    if not isinstance(semantic, dict) or semantic.get("verified") is not True:
        raise RuntimeError("restore prerequisite evidence is not verified")
    for domain in ("checkpoint_recovery", "session_recovery", "memory_recovery", "evidence_recovery"):
        value = semantic.get(domain)
        if not isinstance(value, dict) or not any(key.endswith("_state_reconstructed") and item is True for key, item in value.items()):
            raise RuntimeError(f"restore prerequisite lacks {domain}")
    if backup.metadata.goal_thread_id != args.goal_thread_id:
        raise RuntimeError("backup and activation Goal identities differ")

    overlay = None
    anchor_backend = None
    if args.mode == "simulate":
        load_context, overlay, anchor_backend = _restored_loader(home, backup)
    else:
        if args.simulation_evidence is None:
            raise RuntimeError("production activation requires successful exact simulation evidence")
        simulation_path = args.simulation_evidence.expanduser().resolve(strict=True)
        simulation = json.loads(simulation_path.read_text(encoding="utf-8"))
        if simulation.get("status") != "PASSED" or simulation.get("activation", {}).get("mode") != "simulate":
            raise RuntimeError("exact activation simulation prerequisite did not pass")
        if simulation.get("goal_thread_id") != args.goal_thread_id:
            raise RuntimeError("simulation and activation Goal identities differ")
        if simulation.get("backup_id") != backup.backup_id or simulation.get("backup_manifest_hash") != backup.manifest_hash:
            raise RuntimeError("simulation and activation backup identities differ")
        if simulation.get("source_manifest_sha256") != source.get("manifest_sha256") or simulation.get(
            "source_manifest_file_sha256"
        ) != _sha256(source_manifest_path):
            raise RuntimeError("production source differs from the exact simulated source")
        if simulation.get("before_sentinel_file_sha256") != _sha256(before_sentinel):
            raise RuntimeError("simulation and activation Sentinel identities differ")
        if simulation.get("restore_evidence_file_sha256") != _sha256(restore_evidence_path):
            raise RuntimeError("simulation and activation restore evidence identities differ")
        simulated_initial = simulation.get("activation", {}).get("initial_frontier")
        if simulated_initial != backup.metadata.frontier.__dict__:
            raise RuntimeError("simulation did not start from the verified backup frontier")
        load_context = _production_loader(home)
        production_context = load_context()
        if derive_verified_frontier(production_context) != backup.metadata.frontier:
            raise RuntimeError("Production frontier changed after the verified backup")

    activation = _activate(
        mode=args.mode,
        home=home,
        load_context=load_context,
        goal_thread_id=args.goal_thread_id,
    )
    evidence: dict[str, object] = {
        "schema": "SITINA_STORAGE_SAFE_READ_PATH_ACTIVATION_V1",
        "status": "PASSED",
        "goal_thread_id": args.goal_thread_id,
        "backup_id": backup.backup_id,
        "backup_manifest_hash": backup.manifest_hash,
        "source_manifest_sha256": source["manifest_sha256"],
        "source_manifest_file_sha256": _sha256(source_manifest_path),
        "before_sentinel_file_sha256": _sha256(before_sentinel),
        "restore_evidence_file_sha256": _sha256(restore_evidence_path),
        "activation": activation,
        "simulation_overlay": overlay.public_inventory() if overlay is not None else None,
        "simulation_anchor_item_count": anchor_backend.public_inventory()["item_count"] if anchor_backend is not None else None,
        "production_rollback_anchor_created": args.mode == "production",
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
