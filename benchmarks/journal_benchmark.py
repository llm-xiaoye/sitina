#!/usr/bin/env python3
"""Unqualified fixture-only Journal benchmark; never publishes supported SLOs."""

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
import platform
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile_value))))
    return ordered[index]


def run_case(test_root: Path, *, payload_bytes: int, command_count: int) -> dict:
    home = Path(tempfile.mkdtemp(prefix="phase1-benchmark-", dir=test_root))
    (home / ".sitina-bplus-disposable-v1").write_text("benchmark-fixture\n", encoding="utf-8")
    provider = InMemoryKeyProvider(environment="test", namespace=f"benchmark-{payload_bytes}")
    journal = LocalJournal.open(home, JournalAuthProvider(provider))
    durations: list[float] = []
    try:
        payload = "x" * payload_bytes
        started = time.perf_counter()
        for index in range(command_count):
            command = CommandEnvelope(
                f"benchmark-command-{index}", "tenant-benchmark", "stream-benchmark", "benchmark.append",
                "benchmark-actor", "2026-07-13T00:00:00Z", {"payload": payload, "index": index},
            )
            event = EventEnvelope(
                f"benchmark-event-{index}", "benchmark.appended", "tenant-benchmark", "stream-benchmark",
                0, 0, "2026-07-13T00:00:00Z", {"payload": payload, "index": index},
            )
            before = time.perf_counter_ns()
            journal.append(command, index, [event])
            durations.append((time.perf_counter_ns() - before) / 1_000_000)
        elapsed = time.perf_counter() - started
        size = (home / "journal/active.seg").stat().st_size
        return {
            "payload_bytes": payload_bytes, "command_count": command_count, "elapsed_seconds": round(elapsed, 6),
            "commands_per_second_observed": round(command_count / elapsed, 3), "segment_bytes": size,
            "append_latency_ms": {
                "min": round(min(durations), 6), "median": round(statistics.median(durations), 6),
                "p95": round(percentile(durations, 0.95), 6), "max": round(max(durations), 6),
            },
            "head_position": journal.head_position,
        }
    finally:
        journal.close()
        shutil.rmtree(home)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--test-root", type=Path, default=Path((_SITINA_ACCOUNT_HOME + '/Desktop/sitina/bplus-test-homes')))
    parser.add_argument("--count", type=int, default=100)
    arguments = parser.parse_args(argv)
    arguments.test_root.mkdir(parents=True, exist_ok=True)
    cases = [run_case(arguments.test_root, payload_bytes=size, command_count=arguments.count) for size in (64, 4096)]
    stat = os.statvfs(arguments.test_root)
    core = {
        "schema": "SITINA_PHASE1_JOURNAL_BENCHMARK_V1",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "MEASURED_NOT_YET_QUALIFIED", "qualification_status": "NOT_YET_QUALIFIED",
        "supported_capacity_claimed": False, "goal_thread_id": "019f5c6b-3083-7860-b45b-c8b487c4e3ab",
        "phase1_manifest_hash": "sha256:8e96dd7a3e4d83190e968b99c8877c4467e6eb39bb2783a00fa9fc6ebf6c72df",
        "profiles": {
            "durability": "MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1",
            "powerloss": "MACOS_APFS_FULLFSYNC_POWERLOSS_QUALIFIED_V1:NOT_YET_QUALIFIED",
            "frame": "SITINA_LOCAL_FRAME_V1", "position": "LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1",
        },
        "environment": {
            "python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "filesystem_path": str(arguments.test_root), "filesystem_block_size": stat.f_bsize,
            "filesystem_type": "LOCAL_FILESYSTEM_TYPE_NOT_ASSERTED_BY_STDLIB",
        },
        "cases": cases,
        "limitations": [
            "Fixture-only microbenchmark; not a Production capacity or latency claim.",
            "No hardware power-loss injection or F_FULLFSYNC qualification was performed.",
            "Thresholds remain unset until an explicit capacity qualification review.",
        ],
    }
    core["report_sha256"] = hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    fd = os.open(arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(core, handle, ensure_ascii=False, sort_keys=True, indent=2); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
    print(json.dumps({"path": str(arguments.output), "report_sha256": core["report_sha256"], "status": core["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
