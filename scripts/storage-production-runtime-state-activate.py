#!/usr/bin/env python3
"""Simulate, publish, and verify the signed runtime-state Projection read path."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.conversation.runtime import ConversationRuntime
from sitina.journal.fast_start import FullJournalVerifier
from sitina.journal.model import FrontierRef, canonical_json_bytes
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.projections.generations import ProjectionGenerationPublisher, ProjectionGenerationReader
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers
from sitina.projections.rebuild import ProjectionGeneration, semantic_checksum
from sitina.projections.runner import ProjectionRunner
from sitina.projections.schema import open_projection
from sitina.security.key_provider import JournalAuthProvider


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
GOAL_THREAD_ID = "019f7643-f34d-7911-9bd6-82722c165f2e"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(dict(value), ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short runtime-state activation evidence write")
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
    return _sha(raw)


def _checkpoint(home: Path, verified_through: int) -> tuple[dict[str, Any], Path]:
    matching = []
    for path in sorted((home / "journal/checkpoints").glob("checkpoint-*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if int(value["verified_through_position"]) == verified_through:
            matching.append((value, path))
    if len(matching) != 1:
        raise RuntimeError("verified Fast Start checkpoint is unavailable or ambiguous")
    return matching[0]


def _state_rows(connection: sqlite3.Connection) -> tuple[tuple[Any, ...], ...]:
    columns = (
        "position,event_id,event_type,tenant_id,stream_id,stream_version,occurred_at,payload_json,"
        "object_refs_json,schema_major,event_hash,journal_auth_key_id,journal_auth_tag"
    )
    rows = list(connection.execute(f"SELECT {columns} FROM runtime_state_events"))
    rows.extend(connection.execute(f"SELECT {columns} FROM runtime_pending_run_events"))
    return tuple(sorted(set(rows), key=lambda row: int(row[0])))


def _sidecars(home: Path) -> list[str]:
    return sorted(
        path.relative_to(home).as_posix()
        for name in ("current", "previous", "building")
        for path in (home / "projections" / name).glob("*.sqlite-*")
        if path.is_file()
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: storage-production-runtime-state-activate.py EVIDENCE_OUTPUT")
    output = Path(sys.argv[1]).expanduser().resolve(strict=False)
    if output == PRODUCTION_HOME or PRODUCTION_HOME in output.parents:
        raise RuntimeError("runtime-state activation evidence must be outside Production")
    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    fast = context.authority.fast_start_report
    if fast is None or not fast.fast_start_checkpoint_used:
        raise RuntimeError("runtime-state activation requires verified Fast Start")
    initial_frontier = fast.authority_state.head_position
    initial_commitment = fast.authority_state.last_transaction_hash
    initial_cas_objects = sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj"))
    full_started = time.monotonic()
    full = FullJournalVerifier(
        PRODUCTION_HOME,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    full_seconds = time.monotonic() - full_started
    if full.authority_state != fast.authority_state:
        raise RuntimeError("Fast Start authority differs from independent full replay")
    checkpoint, checkpoint_path = _checkpoint(PRODUCTION_HOME, fast.verified_through_position)
    checkpoint_frontier = FrontierRef(
        full.authority_state.journal_id,
        full.authority_state.epoch,
        "local",
        fast.verified_through_position,
        str(checkpoint["last_transaction_hash"]),
    )
    base_events = tuple(event for event in full.verified_events if event.position <= checkpoint_frontier.position)
    tail_events = tuple(event for event in full.verified_events if event.position > checkpoint_frontier.position)
    if tail_events != tuple(fast.active_tail_events):
        raise RuntimeError("full replay suffix differs from authenticated Fast Start active tail")

    output.parent.mkdir(parents=True, exist_ok=True)
    simulation_started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="sitina-runtime-state-simulation-", dir=output.parent) as temporary:
        simulation_path = Path(temporary) / "simulation.sqlite"
        simulation = open_projection(simulation_path)
        try:
            ProjectionRunner(simulation, production_handlers()).apply_batch(base_events)
            base_state_rows = _state_rows(simulation)
            ProjectionRunner(simulation, production_handlers()).apply_batch(tail_events)
            expected_rows = _state_rows(simulation)
            expected_checksum = semantic_checksum(simulation)
            expected_pending_runs = int(
                simulation.execute("SELECT count(*) FROM runtime_pending_runs").fetchone()[0]
            )
        finally:
            simulation.close()
    simulation_seconds = time.monotonic() - simulation_started
    if expected_pending_runs != 0:
        raise RuntimeError("current Production frontier contains an unreconciled runtime run")

    old_pointer = json.loads((PRODUCTION_HOME / "projections/current-generation.json").read_text(encoding="utf-8"))
    build_started = time.monotonic()

    class CheckpointReadView:
        def iter_events(self, after_position: int = 0):
            return iter(event for event in base_events if event.position > after_position)

    generation = ProjectionGeneration.build(
        PRODUCTION_HOME / "projections/building",
        CheckpointReadView(),
        checkpoint_frontier,
        production_handlers(),
    )
    build_seconds = time.monotonic() - build_started
    features = FeatureActivationRegistry.from_journal_events(full.verified_events)
    features.assert_write_enabled("projection_v2_build")
    pointer = ProjectionGenerationPublisher(
        PRODUCTION_HOME / "projections",
        feature_activations=features,
        authority_key_provider=context.provider,
    ).publish(
        generation_id=generation.generation_id,
        building_database=generation.database_path,
        authority_checkpoint_commitment=fast.checkpoint_commitment,
        journal_frontier=checkpoint_frontier.position,
        schema_coverage_hash=PRODUCTION_SCHEMA_COVERAGE.commitment,
        created_at=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    if not isinstance(pointer.get("auth_key_id"), str) or not isinstance(pointer.get("auth_tag"), str):
        raise RuntimeError("published runtime-state Projection pointer is not authority-signed")
    selected = ProjectionGenerationReader(
        PRODUCTION_HOME / "projections",
        authority_key_provider=context.provider,
        require_signed_pointer=True,
    ).select_with_tail(
        authority_checkpoint_commitments=(fast.checkpoint_commitment,),
        schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
        current_journal_frontier=initial_frontier,
        tail_events=fast.active_tail_events,
        handlers=production_handlers(),
    )
    try:
        actual_rows = _state_rows(selected.connection)
        actual_checksum = semantic_checksum(selected.connection)
        pending_runs = int(selected.connection.execute("SELECT count(*) FROM runtime_pending_runs").fetchone()[0])
    finally:
        selected.close()
    if actual_rows != expected_rows or pending_runs != 0:
        raise RuntimeError("published signed Projection + tail differs from independent full-replay simulation")
    if _sidecars(PRODUCTION_HOME):
        raise RuntimeError("runtime-state Projection publication left mutable SQLite sidecars")

    restarted = ProductionRuntimeContext.load(PRODUCTION_HOME)
    state_started = time.monotonic()
    with mock.patch(
        "sitina.orchestrator.bplus_production.FullJournalVerifier.verify",
        side_effect=AssertionError("ordinary runtime state read attempted full history replay"),
    ):
        state_reader = restarted.open_runtime_state_reader()
    state_seconds = time.monotonic() - state_started
    projected_hashes = tuple(event.event_hash for event in state_reader.events)
    expected_hashes = tuple(str(row[10]) for row in expected_rows)
    if projected_hashes != expected_hashes or state_reader.head_position != initial_frontier:
        raise RuntimeError("authenticated runtime state reader differs from simulated exact event set")
    resume_started = time.monotonic()
    with mock.patch(
        "sitina.orchestrator.bplus_production.FullJournalVerifier.verify",
        side_effect=AssertionError("ordinary Conversation restart attempted full history replay"),
    ):
        session = ConversationRuntime(PRODUCTION_HOME).resume_or_create_session()
    resume_seconds = time.monotonic() - resume_started
    if session.turn_index != 5 or len(session.history) != 5 or session.last_failed_message is not None:
        raise RuntimeError("signed runtime-state restart did not recover the exact five-turn Production session")
    if len(session.accepted_memories) != 1:
        raise RuntimeError("signed runtime-state restart did not recover the exact accepted Memory set")
    final = ProductionRuntimeContext.load(PRODUCTION_HOME).authority.fast_start_report
    if (
        final is None
        or final.authority_state.head_position != initial_frontier
        or final.authority_state.last_transaction_hash != initial_commitment
        or sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj")) != initial_cas_objects
    ):
        raise RuntimeError("derived runtime-state activation mutated Journal or CAS authority")
    previous_pointer = json.loads((PRODUCTION_HOME / "projections/previous-generation.json").read_text(encoding="utf-8"))
    evidence: dict[str, Any] = {
        "schema": "SITINA_STORAGE_PRODUCTION_RUNTIME_STATE_PROJECTION_ACTIVATION_V1",
        "status": "PASSED",
        "goal_thread_id": GOAL_THREAD_ID,
        "production_home": str(PRODUCTION_HOME),
        "authority": {
            "frontier_position": initial_frontier,
            "frontier_commitment": initial_commitment,
            "checkpoint_commitment": fast.checkpoint_commitment,
            "checkpoint_path": checkpoint_path.relative_to(PRODUCTION_HOME).as_posix(),
            "checkpoint_verified_through_position": checkpoint_frontier.position,
            "active_tail_event_count": len(tail_events),
            "fast_start_equals_full_replay": True,
            "journal_mutation_count": 0,
            "cas_mutation_count": 0,
        },
        "simulation": {
            "base_event_count": len(base_events),
            "tail_event_count": len(tail_events),
            "base_runtime_state_event_count": len(base_state_rows),
            "final_runtime_state_event_count": len(expected_rows),
            "pending_run_count": expected_pending_runs,
            "full_projection_semantic_checksum": expected_checksum,
            "published_overlay_semantic_checksum": actual_checksum,
            "exact_match_after_publish": True,
        },
        "projection": {
            "generation_id": pointer["generation_id"],
            "journal_frontier": pointer["journal_frontier"],
            "semantic_checksum": pointer["semantic_checksum"],
            "database_sha256": pointer["database_sha256"],
            "schema_coverage_hash": pointer["schema_coverage_hash"],
            "authority_signed": True,
            "signature_key_id": pointer["auth_key_id"],
            "signature_value_included": False,
            "runtime_state_projection_schema": "SITINA_RUNTIME_STATE_PROJECTION_V1",
            "previous_generation_id": previous_pointer["generation_id"],
            "previous_generation_authority_signed": isinstance(previous_pointer.get("auth_tag"), str),
            "rollback_is_pointer_rotation": True,
            "sqlite_sidecars": [],
        },
        "runtime_restart": {
            "reader_generation": state_reader.reader_generation,
            "projection_generation_id": state_reader.projection_generation_id,
            "runtime_state_event_count": len(state_reader.events),
            "full_history_scan_attempt_count": 0,
            "provider_send_count": 0,
            "session_turn_index": session.turn_index,
            "successful_turn_count": len(session.history),
            "accepted_memory_count": len(session.accepted_memories),
        },
        "timings_seconds": {
            "full_replay_acceptance_only": round(full_seconds, 6),
            "independent_simulation": round(simulation_seconds, 6),
            "checkpoint_generation_build": round(build_seconds, 6),
            "ordinary_runtime_state_open": round(state_seconds, 6),
            "ordinary_conversation_resume": round(resume_seconds, 6),
        },
        "message_or_memory_bodies_included": False,
        "provider_secret_values_included": False,
    }
    digest = _atomic_json(output, evidence)
    print(json.dumps({"status": "PASSED", "path": str(output), "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
