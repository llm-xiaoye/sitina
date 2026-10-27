#!/usr/bin/env python3
"""Benchmark the 85k-event Production read path and disposable write paths."""

from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping

PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
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
                raise OSError("short Production benchmark evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    return _sha(raw)


def _elapsed_ms(operation: Callable[[], Any]) -> tuple[float, Any]:
    started = time.perf_counter_ns()
    result = operation()
    return (time.perf_counter_ns() - started) / 1_000_000, result


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires samples")
    coordinate = (len(ordered) - 1) * quantile
    lower = math.floor(coordinate)
    upper = math.ceil(coordinate)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (coordinate - lower)


def _series(samples: list[float], *, memory: list[dict[str, int]] | None = None) -> dict[str, Any]:
    return {
        "sample_count": len(samples),
        "median_ms": round(statistics.median(samples), 6),
        "p95_ms": round(_percentile(samples, 0.95), 6),
        "p99_ms": round(_percentile(samples, 0.99), 6),
        "minimum_ms": round(min(samples), 6),
        "maximum_ms": round(max(samples), 6),
        "raw_ms": [round(value, 6) for value in samples],
        "peak_memory": {
            "python_tracemalloc_bytes": max((item["python_tracemalloc_bytes"] for item in memory or ()), default=0),
            "process_max_rss_native_units": max((item["process_max_rss_native_units"] for item in memory or ()), default=0),
            "process_max_rss_platform": sys.platform,
        },
    }


def _worker_result(operation: Callable[[], tuple[list[float], dict[str, Any]]]) -> int:
    samples, metadata = operation()
    print(
        json.dumps(
            {
                "samples_ms": samples,
                "metadata": metadata,
                "memory": {
                    "python_tracemalloc_bytes": 0,
                    "process_max_rss_native_units": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
                },
            },
            sort_keys=True,
        )
    )
    return 0


def _context_load_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    elapsed, context = _elapsed_ms(lambda: ProductionRuntimeContext.load(PRODUCTION_HOME))
    report = context.authority.fast_start_report
    return [elapsed], {
        "frontier": report.authority_state.head_position,
        "frontier_commitment": report.authority_state.last_transaction_hash,
        "checkpoint_commitment": report.checkpoint_commitment,
        "checkpoint_verified_through_position": report.verified_through_position,
        "active_tail_event_count": report.active_tail_event_count,
        "fast_start_checkpoint_used": report.fast_start_checkpoint_used,
        "journal_bytes_scanned": report.journal_bytes_scanned,
        "journal_events_verified": report.journal_events_verified,
    }


def _warm_fast_start_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    samples = []
    context = None
    for _ in range(30):
        elapsed, context = _elapsed_ms(lambda: ProductionRuntimeContext.load(PRODUCTION_HOME))
        samples.append(elapsed)
    assert context is not None
    report = context.authority.fast_start_report
    return samples, {
        "frontier": report.authority_state.head_position,
        "fast_start_checkpoint_used": report.fast_start_checkpoint_used,
        "journal_bytes_scanned": report.journal_bytes_scanned,
        "journal_events_verified": report.journal_events_verified,
    }


def _runtime_state_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    samples = []
    reader = None
    for _ in range(30):
        elapsed, reader = _elapsed_ms(context.open_runtime_state_reader)
        samples.append(elapsed)
        reader.close()
    assert reader is not None
    return samples, {
        "frontier": reader.head_position,
        "state_event_count": len(reader.events),
        "reader_generation": reader.reader_generation,
        "projection_generation_id": reader.projection_generation_id,
    }


def _conversation_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.conversation.runtime import ConversationRuntime

    elapsed, pair = _elapsed_ms(
        lambda: (
            (runtime := ConversationRuntime(PRODUCTION_HOME)),
            runtime.resume_or_create_session(),
        )
    )
    _runtime, session = pair
    return [elapsed], {
        "session_id_hash": _sha(session.session_id.encode()),
        "turn_index": session.turn_index,
        "successful_turn_count": len(session.history),
        "accepted_memory_count": len(session.accepted_memories),
    }


def _context_compose_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.conversation.runtime import ConversationRuntime

    runtime = ConversationRuntime(PRODUCTION_HOME)
    session = runtime.resume_or_create_session()
    samples = []
    snapshot = None
    for _ in range(100):
        elapsed, snapshot = _elapsed_ms(
            lambda: runtime.context.compose(
                session.history,
                current_user_message="Read-only Production context reconstruction benchmark.",
                goal_constraints="Preserve Journal/CAS authority and do not execute tools.",
                working_state=session.working_state,
                memories=session.accepted_memories,
                rolling_summary=session.rolling_summary,
            )
        )
        samples.append(elapsed)
    assert snapshot is not None
    return samples, {
        "context_hash": snapshot.context_hash,
        "turn_count": snapshot.turn_count,
        "char_count": snapshot.char_count,
        "component_count": len(snapshot.component_manifest),
    }


def _full_replay_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.journal.fast_start import FullJournalVerifier
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext
    from sitina.security.key_provider import JournalAuthProvider

    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    elapsed, report = _elapsed_ms(
        lambda: FullJournalVerifier(
            PRODUCTION_HOME,
            journal_authenticator=JournalAuthProvider(context.provider),
            authority_key_provider=context.provider,
        ).verify()
    )
    return [elapsed], {
        "frontier": report.authority_state.head_position,
        "event_count": report.journal_events_verified,
        "bytes_scanned": report.journal_bytes_scanned,
        "commitment": report.authority_state.last_transaction_hash,
    }


def _projection_rebuild_worker(workspace: Path) -> tuple[list[float], dict[str, Any]]:
    from sitina.journal.fast_start import FullJournalVerifier
    from sitina.journal.model import FrontierRef
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext
    from sitina.projections.production import production_handlers
    from sitina.projections.rebuild import ProjectionGeneration
    from sitina.security.key_provider import JournalAuthProvider

    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    full = FullJournalVerifier(
        PRODUCTION_HOME,
        journal_authenticator=JournalAuthProvider(context.provider),
        authority_key_provider=context.provider,
    ).verify()
    frontier = FrontierRef(
        full.authority_state.journal_id,
        full.authority_state.epoch,
        "local",
        full.authority_state.head_position,
        full.authority_state.last_transaction_hash,
    )

    class FullReadView:
        def iter_events(self, after_position: int = 0):
            return iter(event for event in full.verified_events if event.position > after_position)

    with tempfile.TemporaryDirectory(prefix="sitina-projection-benchmark-", dir=workspace) as temporary:
        elapsed, generation = _elapsed_ms(
            lambda: ProjectionGeneration.build(
                Path(temporary),
                FullReadView(),
                frontier,
                production_handlers(),
            )
        )
        size = generation.database_path.stat().st_size
        checksum = generation.semantic_checksum
    return [elapsed], {
        "frontier": frontier.position,
        "event_count": len(full.verified_events),
        "database_bytes": size,
        "semantic_checksum": checksum,
        "production_projection_mutation_count": 0,
    }


def _cas_read_worker() -> tuple[list[float], dict[str, Any]]:
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    context = ProductionRuntimeContext.load(PRODUCTION_HOME)
    state = context.open_runtime_state_reader()
    references = sorted({reference for event in state.events for reference in event.object_refs})
    if not references:
        raise RuntimeError("runtime state has no CAS references to benchmark")
    samples = []
    verified = []
    for index in range(100):
        reference = references[index % len(references)]
        elapsed, result = _elapsed_ms(lambda reference=reference: context._verify_cas_reference(reference))
        samples.append(elapsed)
        verified.append(str(result["plaintext_sha256"]))
    return samples, {
        "unique_reference_count": len(references),
        "sampled_plaintext_hash_set_commitment": _sha("".join(sorted(set(verified))).encode()),
        "all_ciphertext_and_plaintext_commitments_verified": True,
    }


def _journal_append_worker(workspace: Path) -> tuple[list[float], dict[str, Any]]:
    from sitina.commands.model import CommandEnvelope
    from sitina.journal.local import LocalJournal
    from sitina.journal.model import EventEnvelope
    from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider

    with tempfile.TemporaryDirectory(prefix="sitina-journal-append-benchmark-", dir=workspace) as temporary:
        home = Path(temporary)
        (home / ".sitina-bplus-disposable-v1").write_text("benchmark\n", encoding="utf-8")
        provider = InMemoryKeyProvider()
        journal = LocalJournal.open(home, JournalAuthProvider(provider), journal_id="journal-benchmark")
        samples = []
        try:
            for ordinal in range(1, 101):
                occurred_at = (dt.datetime(2026, 7, 18, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=ordinal)).isoformat().replace("+00:00", "Z")
                stream_id = "run/benchmark"
                command = CommandEnvelope(
                    f"benchmark-command-{ordinal}",
                    "benchmark",
                    stream_id,
                    "benchmark.append",
                    "benchmark",
                    occurred_at,
                    {"ordinal": ordinal},
                )
                event = EventEnvelope(
                    f"benchmark-event-{ordinal}",
                    "benchmark.observed",
                    "benchmark",
                    stream_id,
                    0,
                    0,
                    occurred_at,
                    {"schema": "BENCHMARK_OPTIONAL_V1", "projection_requirement": "optional", "ordinal": ordinal},
                )
                elapsed, _receipt = _elapsed_ms(
                    lambda command=command, event=event: journal.append(
                        command,
                        journal._stream_heads.get(stream_id, 0),
                        (event,),
                    )
                )
                samples.append(elapsed)
            head = journal.head_position
            active_bytes = (home / "journal/active.seg").stat().st_size
        finally:
            journal.close()
    return samples, {"event_count": head, "active_segment_bytes": active_bytes, "disposable_only": True}


def _cas_publish_worker(workspace: Path) -> tuple[list[float], dict[str, Any]]:
    from sitina.cas.local import LocalCAS
    from sitina.security.key_provider import InMemoryKeyProvider

    with tempfile.TemporaryDirectory(prefix="sitina-cas-publish-benchmark-", dir=workspace) as temporary:
        home = Path(temporary)
        (home / ".sitina-bplus-disposable-v1").write_text("benchmark\n", encoding="utf-8")
        cas = LocalCAS.open(home, InMemoryKeyProvider())
        samples = []
        object_ids = []
        for ordinal in range(100):
            body = (f"Production CAS disposable benchmark {ordinal:04d}." + "x" * 4096).encode()
            elapsed, publication = _elapsed_ms(
                lambda body=body, ordinal=ordinal: cas.publish_plaintext(
                    body,
                    tenant_id="benchmark",
                    purpose_class=f"sample-{ordinal}",
                    compression="none",
                    media_type="application/octet-stream",
                )
            )
            samples.append(elapsed)
            object_ids.append(publication.receipt.object_ref.object_id)
    return samples, {
        "object_count": len(object_ids),
        "unique_object_count": len(set(object_ids)),
        "disposable_only": True,
    }


WORKERS: dict[str, Callable[[Path], tuple[list[float], dict[str, Any]]]] = {
    "context-load": lambda _workspace: _context_load_worker(),
    "warm-fast-start": lambda _workspace: _warm_fast_start_worker(),
    "runtime-state": lambda _workspace: _runtime_state_worker(),
    "conversation": lambda _workspace: _conversation_worker(),
    "context-compose": lambda _workspace: _context_compose_worker(),
    "full-replay": lambda _workspace: _full_replay_worker(),
    "projection-rebuild": _projection_rebuild_worker,
    "cas-read": lambda _workspace: _cas_read_worker(),
    "journal-append": _journal_append_worker,
    "cas-publish": _cas_publish_worker,
}


def _invoke_worker(name: str, workspace: Path) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(PRODUCTION_HOME / "core")
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", name, "--workspace", str(workspace)],
        cwd=PRODUCTION_HOME,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--workspace", type=Path, default=Path((_SITINA_ACCOUNT_HOME + '/Desktop/sitina/.benchmark-tmp')))
    parser.add_argument("--worker", choices=tuple(WORKERS))
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve(strict=False)
    workspace.mkdir(parents=True, exist_ok=True)
    if workspace == PRODUCTION_HOME or PRODUCTION_HOME in workspace.parents or workspace in PRODUCTION_HOME.parents:
        raise RuntimeError("benchmark workspace must be disjoint from Production")
    if args.worker:
        return _worker_result(lambda: WORKERS[args.worker](workspace))
    if args.output is None:
        raise SystemExit("benchmark output is required")
    output = args.output.expanduser().resolve(strict=False)
    if output == PRODUCTION_HOME or PRODUCTION_HOME in output.parents:
        raise RuntimeError("benchmark evidence must be outside Production")

    initial_pointer_sha = _sha((PRODUCTION_HOME / "projections/current-generation.json").read_bytes())
    initial_cas_count = sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj"))
    plan = {
        "cold_start": ("context-load", 7),
        "warm_fast_start": ("warm-fast-start", 1),
        "runtime_state_open": ("runtime-state", 1),
        "conversation_resume": ("conversation", 10),
        "full_authoritative_replay": ("full-replay", 3),
        "projection_rebuild_85k": ("projection-rebuild", 3),
        "context_reconstruction": ("context-compose", 1),
        "cas_verified_read": ("cas-read", 1),
        "journal_durable_append_disposable": ("journal-append", 1),
        "cas_atomic_publish_disposable": ("cas-publish", 1),
    }
    results: dict[str, Any] = {}
    for label, (worker, repeats) in plan.items():
        samples: list[float] = []
        memory: list[dict[str, int]] = []
        metadata: list[dict[str, Any]] = []
        for _ in range(repeats):
            value = _invoke_worker(worker, workspace)
            samples.extend(float(item) for item in value["samples_ms"])
            memory.append({key: int(item) for key, item in value["memory"].items()})
            metadata.append(dict(value["metadata"]))
        results[label] = {**_series(samples, memory=memory), "worker_metadata": metadata}

    baseline = results["cold_start"]["worker_metadata"][0]
    if not all(
        item["frontier"] == baseline["frontier"]
        and item["frontier_commitment"] == baseline["frontier_commitment"]
        and item["checkpoint_commitment"] == baseline["checkpoint_commitment"]
        for item in results["cold_start"]["worker_metadata"]
    ):
        raise RuntimeError("cold-start workers observed different Production authority")
    from sitina.orchestrator.bplus_production import ProductionRuntimeContext

    final = ProductionRuntimeContext.load(PRODUCTION_HOME).authority.fast_start_report
    if (
        final is None
        or final.authority_state.head_position != int(baseline["frontier"])
        or final.authority_state.last_transaction_hash != baseline["frontier_commitment"]
        or final.checkpoint_commitment != baseline["checkpoint_commitment"]
        or _sha((PRODUCTION_HOME / "projections/current-generation.json").read_bytes()) != initial_pointer_sha
        or sum(1 for _ in (PRODUCTION_HOME / "cas/objects").glob("*/*.obj")) != initial_cas_count
    ):
        raise RuntimeError("read-only Production benchmark changed authority or derived generation state")
    evidence: dict[str, Any] = {
        "schema": "SITINA_STORAGE_PRODUCTION_85K_BENCHMARK_V1",
        "status": "PASSED",
        "goal_thread_id": GOAL_THREAD_ID,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "production_home": str(PRODUCTION_HOME),
        "production_event_count": int(baseline["frontier"]),
        "approximately_85000_events": 80_000 <= int(baseline["frontier"]) <= 95_000,
        "checkpoint_commitment": baseline["checkpoint_commitment"],
        "checkpoint_verified_through_position": int(baseline["checkpoint_verified_through_position"]),
        "active_tail_event_count": int(baseline["active_tail_event_count"]),
        "results": results,
        "production_journal_mutation_count": 0,
        "production_cas_mutation_count": 0,
        "production_projection_mutation_count": 0,
        "provider_send_count": 0,
        "raw_results_included": True,
        "latency_instrumentation": "perf_counter_ns_without_allocation_tracing",
        "memory_instrumentation": "per_worker_process_max_rss",
        "secret_values_included": False,
        "message_or_memory_bodies_included": False,
    }
    digest = _atomic_json(output, evidence)
    print(json.dumps({"status": "PASSED", "path": str(output), "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
