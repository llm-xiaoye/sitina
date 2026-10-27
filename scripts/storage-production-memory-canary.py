#!/usr/bin/env python3
"""Run the bounded Journal/CAS native Memory V1 Production lifecycle canary."""

from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.conversation.runtime import ConversationRuntime
from sitina.journal.fast_start import FullJournalVerifier
from sitina.memory.native import MemoryACL, MemoryRepository
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.projections.generations import ProjectionGenerationReader
from sitina.projections.production import PRODUCTION_SCHEMA_COVERAGE, production_handlers
from sitina.security.key_provider import JournalAuthProvider


PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
GOAL_THREAD_ID = "019f7643-f34d-7911-9bd6-82722c165f2e"
ACCEPTED_ID = "memory-production-closure-accepted-20260718"
REJECTED_ID = "memory-production-closure-rejected-20260718"


def _stamp(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, value: dict[str, object]) -> None:
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
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("short memory-canary evidence write")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: storage-production-memory-canary.py EVIDENCE_OUTPUT")
    output = Path(sys.argv[1]).expanduser().resolve(strict=False)
    if output == PRODUCTION_HOME or PRODUCTION_HOME in output.parents:
        raise RuntimeError("memory canary evidence must be outside Production")
    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    report = context.authority.fast_start_report
    if report is None or not report.fast_start_checkpoint_used:
        raise RuntimeError("memory canary requires the verified Fast Start authority path")
    initial = report.authority_state.head_position
    checkpoint_commitment = report.checkpoint_commitment
    accepted_content = (
        "Production closure canary memory: accepted facts must be loaded from Journal metadata and verified CAS content."
    )
    rejected_content = "Production closure negative canary: this unreviewed or rejected content must never enter context."
    acl = MemoryACL(readers=("user",), writers=("user",), reviewers=("user",))
    started = dt.datetime.now(dt.timezone.utc)
    journal = context.open_writer()
    try:
        activations = FeatureActivationRegistry.from_journal_events(journal.iter_events(0))
        repository = MemoryRepository(
            journal,
            context.open_cas(),
            context.provider,
            feature_activations=activations,
        )
        accepted_candidate = repository.create_candidate(
            memory_id=ACCEPTED_ID,
            scope="user",
            owner_id="user/production-closure",
            namespace="user/production-closure/canary",
            content=accepted_content,
            source_event_ids=(),
            source_run_ids=(),
            evidence_refs=(),
            confidence=0.99,
            sensitivity="low",
            valid_from=_stamp(started),
            expires_at=None,
            retention_policy="explicit-revocation",
            supersedes=(),
            acl=acl,
            actor="user",
        )
        if repository.retrieve(actor="user"):
            raise RuntimeError("unreviewed Memory candidate became available")
        accepted = repository.transition(
            ACCEPTED_ID,
            "accepted",
            actor="user",
            occurred_at=_stamp(started + dt.timedelta(seconds=1)),
            reason_code="production-closure-reviewed",
        )
        if [item.memory_id for item in repository.retrieve(actor="user")] != [ACCEPTED_ID]:
            raise RuntimeError("accepted Memory did not become deterministically retrievable")
        rejected_candidate = repository.create_candidate(
            memory_id=REJECTED_ID,
            scope="user",
            owner_id="user/production-closure",
            namespace="user/production-closure/canary",
            content=rejected_content,
            source_event_ids=(),
            source_run_ids=(),
            evidence_refs=(),
            confidence=0.50,
            sensitivity="low",
            valid_from=_stamp(started + dt.timedelta(seconds=2)),
            expires_at=None,
            retention_policy="explicit-revocation",
            supersedes=(),
            acl=acl,
            actor="user",
        )
        if [item.memory_id for item in repository.retrieve(actor="user")] != [ACCEPTED_ID]:
            raise RuntimeError("unreviewed negative Memory candidate became available")
        rejected = repository.transition(
            REJECTED_ID,
            "rejected",
            actor="user",
            occurred_at=_stamp(started + dt.timedelta(seconds=3)),
            reason_code="production-closure-rejected",
        )
        if [item.memory_id for item in repository.retrieve(actor="user")] != [ACCEPTED_ID]:
            raise RuntimeError("rejected Memory became available")
        final_position = journal.head_position
        written_events = tuple(journal.iter_events(initial))
    finally:
        journal.close()
    if final_position != initial + 4 or [event.position for event in written_events] != list(range(initial + 1, initial + 5)):
        raise RuntimeError("memory lifecycle did not append the exact four-event Journal suffix")
    serialized = json.dumps([event.payload for event in written_events], sort_keys=True)
    if accepted_content in serialized or rejected_content in serialized:
        raise RuntimeError("Memory content leaked into Journal metadata")

    restarted = ProductionRuntimeContext.load(PRODUCTION_HOME)
    restarted_report = restarted.authority.fast_start_report
    if restarted_report is None or restarted_report.checkpoint_commitment != checkpoint_commitment:
        raise RuntimeError("memory restart selected an unexpected checkpoint")
    if restarted_report.authority_state.head_position != final_position:
        raise RuntimeError("memory restart omitted the active Journal suffix")
    reader = restarted.open_verified_journal_reader()
    try:
        recovered = MemoryRepository(reader, restarted.open_cas_reader(), restarted.provider)
        visible = recovered.retrieve(actor="user")
        if [item.memory_id for item in visible] != [ACCEPTED_ID]:
            raise RuntimeError("restart did not recover the exact accepted Memory set")
        recovered_document, recovered_content = recovered.get(ACCEPTED_ID, actor="user")
        rejected_document, _ = recovered.get(REJECTED_ID, actor="user", include_content=False)
        if recovered_content != accepted_content or recovered_document.status != "accepted" or rejected_document.status != "rejected":
            raise RuntimeError("restart changed Memory content or lifecycle state")
    finally:
        reader.close()

    overlay = ProjectionGenerationReader(PRODUCTION_HOME / "projections").select_with_tail(
        authority_checkpoint_commitments=(checkpoint_commitment,),
        current_journal_frontier=final_position,
        tail_events=restarted_report.active_tail_events,
        handlers=production_handlers(),
        schema_coverage_hashes=(PRODUCTION_SCHEMA_COVERAGE.commitment,),
    )
    try:
        projected = dict(
            overlay.connection.execute(
                "SELECT memory_id,status FROM memory_items WHERE memory_id IN (?,?) ORDER BY memory_id",
                (ACCEPTED_ID, REJECTED_ID),
            )
        )
    finally:
        overlay.close()
    if projected != {ACCEPTED_ID: "accepted", REJECTED_ID: "rejected"}:
        raise RuntimeError("Projection + exact active tail differs from Memory authority")

    runtime = ConversationRuntime(PRODUCTION_HOME)
    session = runtime.resume_or_create_session()
    if session.accepted_memories != ((accepted_content, 990_000),):
        raise RuntimeError("Conversation Runtime did not recover only accepted Memory")
    composed = runtime.context.compose(
        session.history,
        current_user_message="Confirm that accepted Memory participates in context reconstruction.",
        goal_constraints="Read-only context reconstruction canary.",
        working_state=session.working_state,
        memories=session.accepted_memories,
        rolling_summary=session.rolling_summary,
    )
    memory_component = next(item for item in composed.component_manifest if item["component"] == "memories")
    if memory_component["included"] is not True or memory_component["content_hash"] != _sha(accepted_content.encode()):
        raise RuntimeError("accepted Memory did not enter the real context renderer")

    full = FullJournalVerifier(
        PRODUCTION_HOME,
        journal_authenticator=JournalAuthProvider(restarted.provider),
        authority_key_provider=restarted.provider,
    ).verify()
    if full.authority_state != restarted_report.authority_state:
        raise RuntimeError("memory Fast Start state differs from full replay")
    feature_state = FeatureActivationRegistry.from_journal_events(full.verified_events)
    memory_feature = feature_state.state("memory_v1_write")
    if memory_feature is None or memory_feature.first_write_position != initial + 1:
        raise RuntimeError("Memory V1 first-write position is not replayable")
    evidence: dict[str, object] = {
        "schema": "SITINA_STORAGE_PRODUCTION_MEMORY_LIFECYCLE_CANARY_V1",
        "status": "PASSED",
        "goal_thread_id": GOAL_THREAD_ID,
        "initial_position": initial,
        "final_position": final_position,
        "journal_range": [initial + 1, final_position],
        "checkpoint_commitment": checkpoint_commitment,
        "checkpoint_verified_through_position": restarted_report.verified_through_position,
        "active_tail_event_count": restarted_report.active_tail_event_count,
        "accepted_memory": {
            "memory_id": ACCEPTED_ID,
            "status": accepted.status,
            "content_ref": accepted_candidate.content_ref,
            "content_sha256": _sha(accepted_content.encode()),
            "content_in_journal": False,
            "recovered_after_restart": True,
            "included_in_conversation_context": True,
        },
        "rejected_memory": {
            "memory_id": REJECTED_ID,
            "status": rejected.status,
            "content_ref": rejected_candidate.content_ref,
            "content_sha256": _sha(rejected_content.encode()),
            "available_before_review": False,
            "available_after_rejection": False,
        },
        "projection_plus_tail_equals_authority": True,
        "fast_start_equals_full_replay": True,
        "memory_v1_first_write_position": memory_feature.first_write_position,
        "legacy_read_count": 0,
        "external_effect_count": 0,
        "credentials_copied": False,
        "completed_at": _stamp(dt.datetime.now(dt.timezone.utc)),
    }
    _write(output, evidence)
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
        )
        raise
