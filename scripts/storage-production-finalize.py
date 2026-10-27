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
from typing import Any, Mapping
from unittest import mock

from sitina.archive.production_backup import ProductionBackupManifest
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.conversation.runtime import ConversationRuntime
from sitina.journal.fast_start import FullJournalVerifier
from sitina.journal.model import FrontierRef
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.projections.generations import ProjectionGenerationPublisher, ProjectionGenerationReader
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers
from sitina.projections.rebuild import ProjectionGeneration, semantic_checksum
from sitina.security.key_provider import JournalAuthProvider


PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
GOAL_THREAD_ID = "019f7643-f34d-7911-9bd6-82722c165f2e"
ROLLBACK_BACKUP_ID = "storage-closure-final-20260719T003146Z"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = json.dumps(dict(value), sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    return hashlib.sha256(raw).hexdigest()


def _latest_checkpoint(home: Path) -> tuple[dict[str, Any], Path]:
    values = []
    for path in (home / "journal/checkpoints").glob("checkpoint-*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        values.append((int(value["checkpoint_sequence"]), value, path))
    if not values:
        raise RuntimeError("Production has no Authority Checkpoint")
    _sequence, value, path = max(values, key=lambda item: item[0])
    return value, path


def _runtime_state_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        "runtime_state_event_count": int(connection.execute("SELECT count(*) FROM runtime_state_events").fetchone()[0]),
        "pending_run_count": int(connection.execute("SELECT count(*) FROM runtime_pending_runs").fetchone()[0]),
        "pending_run_event_count": int(connection.execute("SELECT count(*) FROM runtime_pending_run_events").fetchone()[0]),
        "session_count": int(connection.execute("SELECT count(*) FROM sessions WHERE status='ACTIVE'").fetchone()[0]),
        "session_message_count": int(connection.execute("SELECT count(*) FROM active_session_messages").fetchone()[0]),
        "accepted_memory_count": int(connection.execute("SELECT count(*) FROM memory_current WHERE status='accepted'").fetchone()[0]),
        "rejected_memory_count": int(connection.execute("SELECT count(*) FROM memory_current WHERE status='rejected'").fetchone()[0]),
    }


def _validate_runtime_state_counts(counts: Mapping[str, int]) -> int:
    """Validate final closure state without freezing an old session frontier."""

    required = {
        "runtime_state_event_count",
        "pending_run_count",
        "pending_run_event_count",
        "session_count",
        "session_message_count",
        "accepted_memory_count",
        "rejected_memory_count",
    }
    if set(counts) != required:
        raise RuntimeError("final checkpoint Projection runtime-state fields are incomplete")
    message_count = int(counts["session_message_count"])
    if (
        int(counts["runtime_state_event_count"]) < 47
        or int(counts["pending_run_count"]) != 0
        or int(counts["pending_run_event_count"]) != 0
        or int(counts["session_count"]) != 1
        or message_count < 10
        or message_count % 2
        or int(counts["accepted_memory_count"]) != 1
        or int(counts["rejected_memory_count"]) != 1
    ):
        raise RuntimeError(f"final checkpoint Projection has unexpected session/memory state: {dict(counts)}")
    return message_count // 2


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seal the exact Production frontier and publish its signed Projection.")
    parser.add_argument("evidence_output", type=Path)
    parser.add_argument("--rollback-backup-id", default=ROLLBACK_BACKUP_ID)
    return parser.parse_args()


def _unsafe_modes(paths: list[Path]) -> list[str]:
    unsafe: list[str] = []
    for path in paths:
        if not path.exists():
            continue
        expected = 0o700 if path.is_dir() else 0o600
        if path.lstat().st_mode & 0o7777 != expected:
            unsafe.append(path.relative_to(PRODUCTION_HOME).as_posix())
    return sorted(unsafe)


def main() -> int:
    args = _arguments()
    output = args.evidence_output.expanduser().resolve(strict=False)
    if output == PRODUCTION_HOME or PRODUCTION_HOME in output.parents:
        raise RuntimeError("finalization evidence must be outside Production")

    initial = ProductionRuntimeContext.load(PRODUCTION_HOME)
    initial_fast = initial.authority.fast_start_report
    if initial_fast is None or not initial_fast.fast_start_checkpoint_used:
        raise RuntimeError("finalization requires verified Fast Start")
    initial_checkpoint, initial_checkpoint_path = _latest_checkpoint(PRODUCTION_HOME)
    initial_frontier = initial_fast.authority_state.head_position
    initial_commitment = initial_fast.authority_state.last_transaction_hash
    initial_tail = initial_fast.active_tail_event_count
    initial_cas_objects = sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj"))
    rollback = ProductionBackupManifest.load(PRODUCTION_HOME / "backups" / args.rollback_backup_id)
    if (
        rollback.metadata.frontier.position > initial_frontier
        or rollback.body_mapping().get("credentials_copied") is not False
    ):
        raise RuntimeError("rollback backup is unsafe or newer than the finalization frontier")
    checkpoint_performed = False

    if initial_tail:
        journal = initial.open_writer()
        try:
            coordinator = journal.rollover_coordinator
            if coordinator is None:
                raise RuntimeError("Production writer has no Authority Checkpoint coordinator")
            checkpoint_values = dict(coordinator.checkpoint_context("storage-production-final-closure"))
            checkpoint_receipt = coordinator.maintainer.rollover_and_checkpoint(journal, **checkpoint_values)
            checkpoint_performed = True
        finally:
            journal.close()
    else:
        checkpoint_receipt = initial_checkpoint

    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    fast = context.authority.fast_start_report
    if fast is None or not fast.fast_start_checkpoint_used or fast.active_tail_event_count != 0:
        raise RuntimeError("final Authority Checkpoint did not fully seal the Production frontier")
    if fast.authority_state.head_position != initial_frontier or fast.authority_state.last_transaction_hash != initial_commitment:
        raise RuntimeError("Authority Checkpoint changed the logical Journal frontier")
    checkpoint, checkpoint_path = _latest_checkpoint(PRODUCTION_HOME)
    if int(checkpoint["checkpoint_sequence"]) < int(initial_checkpoint["checkpoint_sequence"]):
        raise RuntimeError("Authority Checkpoint sequence regressed")
    if int(checkpoint["verified_through_position"]) != initial_frontier:
        raise RuntimeError("final Authority Checkpoint does not cover the exact Journal frontier")
    if checkpoint_performed and checkpoint != checkpoint_receipt:
        raise RuntimeError("published Authority Checkpoint differs from its writer receipt")

    full_started = time.monotonic()
    full = FullJournalVerifier(
        PRODUCTION_HOME,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    full_seconds = time.monotonic() - full_started
    if full.authority_state != fast.authority_state or len(full.verified_events) != initial_frontier:
        raise RuntimeError("final Fast Start differs from independent full replay")
    features = FeatureActivationRegistry.from_journal_events(full.verified_events)
    for feature in ("projection_v2_build", "agent_context_v2_write", "memory_v1_write", "cas_zstd_write"):
        state = features.state(feature)
        if state is None or state.state != "ACTIVATED":
            raise RuntimeError(f"required feature is not active at final frontier: {feature}")

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
    generation = ProjectionGeneration.build(
        PRODUCTION_HOME / "projections/building",
        FullReadView(),
        frontier,
        production_handlers(),
    )
    pointer = ProjectionGenerationPublisher(
        PRODUCTION_HOME / "projections",
        feature_activations=features,
        authority_key_provider=context.provider,
    ).publish(
        generation_id=generation.generation_id,
        building_database=generation.database_path,
        authority_checkpoint_commitment=fast.checkpoint_commitment,
        journal_frontier=frontier.position,
        schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
        created_at=_utc_now(),
    )
    projection_seconds = time.monotonic() - projection_started
    if not isinstance(pointer.get("auth_key_id"), str) or not isinstance(pointer.get("auth_tag"), str):
        raise RuntimeError("final Projection pointer is not Authority signed")
    selected = ProjectionGenerationReader(
        PRODUCTION_HOME / "projections",
        authority_key_provider=context.provider,
        require_signed_pointer=True,
    ).select(
        authority_checkpoint_commitments=(fast.checkpoint_commitment,),
        schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
    )
    connection = sqlite3.connect(selected.database_path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        counts = _runtime_state_counts(connection)
        selected_checksum = semantic_checksum(connection)
    finally:
        connection.close()
    if selected.pointer != pointer or selected_checksum != pointer["semantic_checksum"]:
        raise RuntimeError("final signed Projection is not exactly selectable")
    expected_turn_index = _validate_runtime_state_counts(counts)

    restarted = ProductionRuntimeContext.load(PRODUCTION_HOME)
    with mock.patch(
        "sitina.orchestrator.bplus_production.FullJournalVerifier.verify",
        side_effect=AssertionError("ordinary final runtime state read attempted full history replay"),
    ):
        state_reader = restarted.open_runtime_state_reader()
        session = ConversationRuntime(PRODUCTION_HOME).resume_or_create_session()
    if (
        state_reader.head_position != initial_frontier
        or len(state_reader.events) != counts["runtime_state_event_count"]
        or session.turn_index != expected_turn_index
        or len(session.history) != expected_turn_index
        or session.last_failed_message is not None
        or len(session.accepted_memories) != 1
    ):
        raise RuntimeError("final signed Projection restart did not recover exact session/memory state")

    current_database = PRODUCTION_HOME / str(pointer["database_path"])
    newest_segment = max((PRODUCTION_HOME / "journal/sealed").glob("*.seg"), key=lambda path: path.name)
    new_paths = [
        PRODUCTION_HOME / "journal",
        PRODUCTION_HOME / "journal/sealed",
        PRODUCTION_HOME / "journal/checkpoints",
        PRODUCTION_HOME / "journal/indexes",
        PRODUCTION_HOME / "journal/active.seg",
        newest_segment,
        checkpoint_path,
        PRODUCTION_HOME / "projections",
        PRODUCTION_HOME / "projections/current",
        PRODUCTION_HOME / "projections/previous",
        PRODUCTION_HOME / "projections/building",
        PRODUCTION_HOME / "projections/current-generation.json",
        PRODUCTION_HOME / "projections/previous-generation.json",
        current_database,
    ]
    unsafe = _unsafe_modes(new_paths)
    sidecars = [
        path.relative_to(PRODUCTION_HOME).as_posix()
        for name in ("current", "previous", "building")
        for path in (PRODUCTION_HOME / "projections" / name).glob("*.sqlite-*")
    ]
    if unsafe or sidecars:
        raise RuntimeError("final Journal/Projection publication regressed permissions or retained sidecars")
    final_context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    final_fast = final_context.authority.fast_start_report
    if (
        final_fast is None
        or final_fast.authority_state.head_position != initial_frontier
        or final_fast.authority_state.last_transaction_hash != initial_commitment
        or sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj")) != initial_cas_objects
    ):
        raise RuntimeError("final Projection publication mutated Journal or CAS authority")

    evidence: dict[str, Any] = {
        "schema": "SITINA_STORAGE_PRODUCTION_FINAL_CHECKPOINT_PROJECTION_V1",
        "status": "PASSED",
        "goal_thread_id": GOAL_THREAD_ID,
        "authority": {
            "frontier_position": initial_frontier,
            "frontier_commitment": initial_commitment,
            "initial_checkpoint_sequence": int(initial_checkpoint["checkpoint_sequence"]),
            "initial_checkpoint_path": initial_checkpoint_path.relative_to(PRODUCTION_HOME).as_posix(),
            "initial_active_tail_event_count": initial_tail,
            "final_checkpoint_sequence": int(checkpoint["checkpoint_sequence"]),
            "final_checkpoint_path": checkpoint_path.relative_to(PRODUCTION_HOME).as_posix(),
            "final_checkpoint_commitment": fast.checkpoint_commitment,
            "verified_through_position": fast.verified_through_position,
            "final_active_tail_event_count": fast.active_tail_event_count,
            "checkpoint_performed": checkpoint_performed,
            "logical_event_append_count": 0,
            "cas_mutation_count": 0,
            "fast_start_equals_full_replay": True,
        },
        "projection": {
            "generation_id": pointer["generation_id"],
            "journal_frontier": pointer["journal_frontier"],
            "semantic_checksum": pointer["semantic_checksum"],
            "database_sha256": pointer["database_sha256"],
            "schema_coverage_hash": pointer["schema_coverage_hash"],
            "authority_signed": True,
            "signature_value_included": False,
            "runtime_state": counts,
            "sqlite_sidecars": sidecars,
        },
        "restart": {
            "reader_generation": state_reader.reader_generation,
            "projection_generation_id": state_reader.projection_generation_id,
            "runtime_state_event_count": len(state_reader.events),
            "full_history_scan_attempt_count": 0,
            "provider_send_count": 0,
            "session_turn_index": session.turn_index,
            "successful_turn_count": len(session.history),
            "accepted_memory_count": len(session.accepted_memories),
        },
        "permissions": {
            "status": "ok",
            "checked_new_or_rotated_paths": len(new_paths),
            "unsafe_paths": unsafe,
            "directory_mode": "0700",
            "file_mode": "0600",
        },
        "rollback_plan": {
            "backup_id": rollback.backup_id,
            "backup_manifest_hash": rollback.manifest_hash,
            "backup_frontier_position": rollback.metadata.frontier.position,
            "restore_replaces_checkpoint_layout": True,
            "projection_disposition": "discard_and_rebuild_from_restored_authority",
            "credentials_copied": False,
        },
        "timings_seconds": {
            "full_replay": round(full_seconds, 6),
            "projection_build_publish": round(projection_seconds, 6),
        },
        "message_or_memory_bodies_included": False,
        "provider_secret_values_included": False,
    }
    digest = _atomic_json(output, evidence)
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
