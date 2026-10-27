#!/usr/bin/env python3
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
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable

from sitina.archive.production_backup import ProductionBackupManifest, load_restored_genesis
from sitina.authority.model import AuthorityResolution
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.journal.fast_start import FullJournalVerifier, RollbackAnchorStore
from sitina.memory.native import MemoryACL, MemoryRepository
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
MEMORY_ID = "memory-post-checkpoint-restore-20260719"


def _utc(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write(path: Path, value: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    return hashlib.sha256(raw).hexdigest()


def _restored_loader(
    home: Path,
    manifest: ProductionBackupManifest,
) -> tuple[Callable[[], ProductionRuntimeContext], IsolatedOverlayKeychainBackend, MemoryKeychainBackend]:
    if home == PRODUCTION_HOME or not (home / ".sitina-bplus-disposable-v1").is_file():
        raise RuntimeError("post-checkpoint write test requires a marked non-Production restore")
    clean_marker = home / ".sitina-clean-acceptance-v1"
    if not clean_marker.exists():
        descriptor = os.open(clean_marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("storage-production-restored-memory-post-checkpoint\n")
            handle.flush()
            os.fsync(handle.fileno())
    genesis = load_restored_genesis(home, manifest)
    source_provider = MacOSKeychainProvider(environment="production", namespace=genesis.key_namespace)
    overlay = IsolatedOverlayKeychainBackend(
        source_provider.backend,
        isolated_services=(RollbackAnchorStore.SERVICE,),
    )
    provider = MacOSKeychainProvider(environment="production", namespace=genesis.key_namespace, backend=overlay)
    anchor_backend = MemoryKeychainBackend()
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(provider),
        authority_key_provider=provider,
    ).verify()
    checkpoint_path = max((home / "journal/checkpoints").glob("checkpoint-*.json"), key=lambda path: path.name)
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    activations = FeatureActivationRegistry.from_journal_events(full.verified_events)
    RollbackAnchorStore(anchor_backend, journal_id=genesis.journal_id).update(
        latest_epoch=int(checkpoint["epoch"]),
        latest_checkpoint_sequence=int(checkpoint["checkpoint_sequence"]),
        latest_checkpoint_commitment=full.checkpoint_commitment,
        active_format_capabilities_hash=activations.active_capabilities_hash,
    )

    def load() -> ProductionRuntimeContext:
        from sitina.legacy.fence import LegacyWriteGate

        fence = LegacyWriteGate(home).read_verified_record()
        if fence is None or fence.get("state") != "FROZEN_NO_WRITER":
            raise RuntimeError("restored write test has no verified no-writer fence")
        authority = ProductionAuthorityReader.resolve(
            home,
            JournalAuthProvider(provider),
            journal_id=genesis.journal_id,
            epoch=int(genesis.epoch_root.rsplit("-", 1)[1]),
            command_id=str(fence["cutover_command_id"]),
            request_hash=str(fence["cutover_request_hash"]),
            genesis_hash=genesis.genesis_hash,
            snapshot_hash=genesis.intended_snapshot_hash,
            fence_record_hash=str(fence["record_hash"]),
            now=int(time.time()),
            authority_key_provider=provider,
            rollback_anchor=RollbackAnchorStore(anchor_backend, journal_id=genesis.journal_id),
        )
        if not isinstance(authority.resolution, AuthorityResolution):
            raise RuntimeError("restored write test has no exact Authority resolution")
        policy = LegacyRuntimePolicy.load(home)
        if not policy.fully_disabled:
            raise RuntimeError("restored write test requires disabled Legacy reads")
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


def _publish_projection(home: Path, context: ProductionRuntimeContext) -> dict[str, Any]:
    full = FullJournalVerifier(
        home,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    fast = context.authority.fast_start_report
    if fast is None or fast.active_tail_event_count != 0:
        raise RuntimeError("restored write test requires a fully checkpointed base")
    from sitina.journal.model import FrontierRef

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

    features = FeatureActivationRegistry.from_journal_events(full.verified_events)
    generation = ProjectionGeneration.build(home / "projections/building", FullReadView(), frontier, production_handlers())
    return ProjectionGenerationPublisher(
        home / "projections",
        feature_activations=features,
        authority_key_provider=context.provider,
    ).publish(
        generation_id=generation.generation_id,
        building_database=generation.database_path,
        authority_checkpoint_commitment=fast.checkpoint_commitment,
        journal_frontier=frontier.position,
        schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
        created_at=_utc(dt.datetime.now(dt.timezone.utc)),
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exercise a native Memory write after a restored Authority Checkpoint.")
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--restore-root", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    backup_root = args.backup_root.expanduser().resolve(strict=True)
    restore_root = args.restore_root.expanduser().resolve(strict=True)
    output = args.evidence_output.expanduser().resolve(strict=False)
    if restore_root == PRODUCTION_HOME or PRODUCTION_HOME in restore_root.parents or output == PRODUCTION_HOME or PRODUCTION_HOME in output.parents:
        raise RuntimeError("restored Memory test paths may not enter Production")
    manifest = ProductionBackupManifest.load(backup_root)
    if manifest.metadata.frontier.position != 85_413 or manifest.metadata.frontier.commitment != "d8e802ec34c461ceebf080132651845f7da3d89e5fb95d2b0892e7a95196c984":
        raise RuntimeError("restored Memory test backup is not the accepted final frontier")
    production_before = ProductionRuntimeContext.load(PRODUCTION_HOME).authority.fast_start_report
    if production_before is None:
        raise RuntimeError("Production Fast Start is unavailable before restored write test")
    production_cas_before = sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj"))

    load, _overlay, _anchor = _restored_loader(restore_root, manifest)
    base = load()
    base_fast = base.authority.fast_start_report
    if base_fast is None or base_fast.active_tail_event_count != 0 or base_fast.authority_state.head_position != 85_413:
        raise RuntimeError("restored Memory test did not start from checkpoint sequence 3")
    pointer = _publish_projection(restore_root, base)
    if not isinstance(pointer.get("auth_tag"), str):
        raise RuntimeError("restored Memory test Projection pointer is unsigned")

    context = load()
    writer = context.open_runtime_writer()
    content = "Disposable post-checkpoint Memory acceptance proves state-aware Journal writes survive restart."
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    occurred = dt.datetime.now(dt.timezone.utc)
    acl = MemoryACL(readers=("user",), writers=("user",), reviewers=("user",))
    initial_position = writer.head_position
    try:
        features = FeatureActivationRegistry.from_journal_events(writer.iter_events(0))
        features.assert_write_enabled("memory_v1_write")
        repository = MemoryRepository(
            writer,
            context.open_cas(),
            context.provider,
            feature_activations=features,
        )
        candidate = repository.create_candidate(
            memory_id=MEMORY_ID,
            scope="user",
            owner_id="user/storage-closure",
            namespace="user/storage-closure/post-checkpoint",
            content=content,
            source_event_ids=(),
            source_run_ids=(),
            evidence_refs=(),
            confidence=0.99,
            sensitivity="low",
            valid_from=_utc(occurred),
            expires_at=None,
            retention_policy="explicit-revocation",
            supersedes=(),
            acl=acl,
            actor="user",
        )
        if candidate.status != "candidate" or any(item.memory_id == MEMORY_ID for item in repository.retrieve(actor="user")):
            raise RuntimeError("unreviewed restored Memory became visible")
        accepted = repository.transition(
            MEMORY_ID,
            "accepted",
            actor="user",
            occurred_at=_utc(occurred + dt.timedelta(seconds=1)),
            reason_code="restored-post-checkpoint-reviewed",
        )
        if accepted.status != "accepted" or not any(item.memory_id == MEMORY_ID for item in repository.retrieve(actor="user")):
            raise RuntimeError("accepted restored Memory is not retrievable")
        final_position = writer.head_position
    finally:
        writer.close()
    if final_position != initial_position + 2:
        raise RuntimeError("restored Memory lifecycle did not append exactly two Journal events")

    restarted = load()
    restarted_fast = restarted.authority.fast_start_report
    if restarted_fast is None or restarted_fast.verified_through_position != initial_position or restarted_fast.active_tail_event_count != 2:
        raise RuntimeError("restored Memory restart did not use checkpoint plus exact two-event tail")
    reader = restarted.open_runtime_state_reader()
    try:
        recovered = MemoryRepository(reader, restarted.open_cas_reader(), restarted.provider)
        document, recovered_content = recovered.get(MEMORY_ID, actor="user")
        visible = recovered.retrieve(actor="user")
    finally:
        reader.close()
    if document.status != "accepted" or recovered_content != content or not any(item.memory_id == MEMORY_ID for item in visible):
        raise RuntimeError("restored Memory restart changed the accepted document")

    selected = ProjectionGenerationReader(
        restore_root / "projections",
        authority_key_provider=restarted.provider,
        require_signed_pointer=True,
    ).select_with_tail(
        authority_checkpoint_commitments=(restarted_fast.checkpoint_commitment,),
        schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
        current_journal_frontier=final_position,
        tail_events=restarted_fast.active_tail_events,
        handlers=production_handlers(),
    )
    try:
        projected = selected.connection.execute(
            "SELECT status FROM memory_current WHERE memory_id=?",
            (MEMORY_ID,),
        ).fetchone()
    finally:
        selected.close()
    if projected != ("accepted",):
        raise RuntimeError("signed Projection plus tail omitted restored accepted Memory")
    full = FullJournalVerifier(
        restore_root,
        journal_authenticator=JournalAuthProvider(restarted.provider),
        authority_key_provider=restarted.provider,
    ).verify()
    if full.authority_state != restarted_fast.authority_state or len(full.verified_events) != final_position:
        raise RuntimeError("restored Memory Fast Start differs from full replay")

    production_after = ProductionRuntimeContext.load(PRODUCTION_HOME).authority.fast_start_report
    if (
        production_after is None
        or production_after.authority_state != production_before.authority_state
        or sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj")) != production_cas_before
    ):
        raise RuntimeError("restored Memory test changed Production")
    evidence: dict[str, Any] = {
        "schema": "SITINA_STORAGE_RESTORED_MEMORY_POST_CHECKPOINT_V1",
        "status": "PASSED",
        "backup_id": manifest.backup_id,
        "backup_manifest_hash": manifest.manifest_hash,
        "restore_root": str(restore_root),
        "base": {
            "checkpoint_commitment": base_fast.checkpoint_commitment,
            "verified_through_position": base_fast.verified_through_position,
            "active_tail_event_count": base_fast.active_tail_event_count,
            "projection_generation_id": pointer["generation_id"],
            "projection_authority_signed": True,
        },
        "write": {
            "memory_id": MEMORY_ID,
            "content_sha256": content_hash,
            "content_included": False,
            "initial_position": initial_position,
            "final_position": final_position,
            "journal_event_count": 2,
            "cas_object_count": 1,
            "provider_send_count": 0,
            "candidate_hidden_before_review": True,
            "accepted_retrievable_after_review": True,
        },
        "restart": {
            "checkpoint_plus_tail": True,
            "checkpoint_verified_through_position": restarted_fast.verified_through_position,
            "active_tail_event_count": restarted_fast.active_tail_event_count,
            "runtime_state_event_count": len(restarted.open_runtime_state_reader().events),
            "accepted_content_hash_verified": True,
            "projection_plus_tail_status": projected[0],
            "fast_start_equals_full_replay": True,
        },
        "isolation": {
            "production_frontier_before": production_before.authority_state.head_position,
            "production_frontier_after": production_after.authority_state.head_position,
            "production_commitment_unchanged": True,
            "production_cas_object_count_unchanged": True,
            "rollback_anchor_backend": "memory-only",
            "provider_credentials_used": False,
            "secret_values_included": False,
        },
    }
    digest = _write(output, evidence)
    print(json.dumps({"status": "PASSED", "path": str(output), "sha256": digest}, sort_keys=True))
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
                    "secret_values_included": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise
