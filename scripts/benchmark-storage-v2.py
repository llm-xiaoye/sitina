#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
import time
from pathlib import Path

from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.journal.fast_start import (
    FastStartLoader,
    FullJournalVerifier,
    JournalFastStartMaintainer,
    RollbackAnchorStore,
)
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from sitina.security.macos_keychain import MemoryKeychainBackend


PRODUCTION = Path("/Users/moss/SitinaHub")


def allocated(path: Path) -> int:
    stat = path.stat()
    return int(getattr(stat, "st_blocks", 0)) * 512 or stat.st_size


def append(journal: LocalJournal, ordinal: int, payload: dict[str, object]) -> None:
    stream_id = "run/run-benchmark"
    occurred_at = f"2026-07-18T00:{ordinal // 60:02d}:{ordinal % 60:02d}Z"
    command = CommandEnvelope(
        f"benchmark-command-{ordinal}", "benchmark", stream_id, "benchmark.append", "benchmark", occurred_at,
        {"ordinal": ordinal},
    )
    event = EventEnvelope(
        f"benchmark-event-{ordinal}", "benchmark.observed", "benchmark", stream_id, 0, 0, occurred_at, payload,
    )
    journal.append(command, journal._stream_heads.get(stream_id, 0), (event,))


def duration_ms(operation, *, repeats: int = 3) -> tuple[float, object]:
    measurements: list[float] = []
    result = None
    for _ in range(repeats):
        started = time.perf_counter_ns()
        result = operation()
        measurements.append((time.perf_counter_ns() - started) / 1_000_000)
    return min(measurements), result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the storage V2 benchmark in a disposable fixture.")
    parser.add_argument("--workspace", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    workspace = args.workspace.expanduser().resolve(strict=True)
    if workspace == PRODUCTION or PRODUCTION in workspace.parents or workspace in PRODUCTION.parents:
        raise SystemExit("benchmark workspace must be disjoint from Production")

    with tempfile.TemporaryDirectory(prefix="sitina-storage-v2-benchmark-", dir=workspace) as temporary:
        home = Path(temporary)
        (home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        keys = InMemoryKeyProvider()
        auth = JournalAuthProvider(keys)
        backend = MemoryKeychainBackend()
        anchor = RollbackAnchorStore(backend, journal_id="journal-benchmark")
        journal = LocalJournal.open(home, auth, journal_id="journal-benchmark")
        payloads: list[dict[str, object]] = []
        padding = "compressible projection payload " * 256
        for ordinal in range(1, 281):
            payload = {
                "schema": "BENCHMARK_OPTIONAL_V1",
                "projection_requirement": "optional",
                "run_id": "run-benchmark",
                "ordinal": ordinal,
                "padding": padding,
            }
            payloads.append(payload)
            append(journal, ordinal, payload)
        JournalFastStartMaintainer(
            home,
            journal_authenticator=auth,
            authority_key_provider=keys,
            rollback_anchor=anchor,
            schema_registry_hash="a" * 64,
        ).rollover_and_checkpoint(
            journal,
            created_at="2026-07-18T00:05:00Z",
            verified_at="2026-07-18T00:05:00Z",
            authority_control_state_hash="b" * 64,
            active_format_capabilities_hash="c" * 64,
            fencing_state_hash="d" * 64,
            minimum_writer_version="2",
            rollback_floor_version="2",
        )
        for ordinal in range(281, 301):
            payload = {
                "schema": "BENCHMARK_OPTIONAL_V1",
                "projection_requirement": "optional",
                "run_id": "run-benchmark",
                "ordinal": ordinal,
                "padding": padding,
            }
            payloads.append(payload)
            append(journal, ordinal, payload)
        journal.close()

        fast_ms, fast = duration_ms(
            lambda: FastStartLoader(
                home,
                journal_authenticator=auth,
                authority_key_provider=keys,
                rollback_anchor=anchor,
            ).load()
        )
        full_ms, full = duration_ms(
            lambda: FullJournalVerifier(
                home, journal_authenticator=auth, authority_key_provider=keys
            ).verify()
        )

        legacy_db = home / "legacy-payload-projection.sqlite"
        connection = sqlite3.connect(legacy_db)
        connection.execute("CREATE TABLE events(position INTEGER PRIMARY KEY,payload_json TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO events VALUES(?,?)",
            ((index, json.dumps(payload, sort_keys=True, separators=(",", ":"))) for index, payload in enumerate(payloads, 1)),
        )
        connection.commit()
        connection.execute("VACUUM")
        connection.close()

        directory_db = home / "event-directory-projection.sqlite"
        connection = sqlite3.connect(directory_db)
        connection.execute(
            "CREATE TABLE event_directory(position INTEGER PRIMARY KEY,event_id TEXT NOT NULL,event_type TEXT NOT NULL,"
            "stream_id TEXT NOT NULL,run_id TEXT,payload_hash TEXT NOT NULL,source_segment TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO event_directory VALUES(?,?,?,?,?,?,?)",
            (
                (
                    index,
                    f"benchmark-event-{index}",
                    "benchmark.observed",
                    "run/run-benchmark",
                    "run-benchmark",
                    hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
                    "sealed" if index <= 280 else "active",
                )
                for index, payload in enumerate(payloads, 1)
            ),
        )
        connection.commit()
        connection.execute("VACUUM")
        connection.close()

        leases = CompatibilityLeaseRegistry(home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="benchmark",
                binary_version="2.0.0",
                reader_capabilities=("cas-zstd",),
                writer_capabilities=("cas-zstd",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T01:00:00Z",
                fencing_token=1,
            )
        )
        activations = FeatureActivationRegistry()
        activations.prepare(
            "cas_zstd_write",
            required_reader_capabilities=("cas-zstd",),
            leases=leases,
            now="2026-07-18T00:01:00Z",
            journal_position=1,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "event_type": "runtime.feature-prepared",
                "feature": "cas_zstd_write",
            },
        )
        activations.activate(
            "cas_zstd_write",
            rollback_floor_version=2,
            journal_position=2,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "event_type": "runtime.feature-activated",
                "feature": "cas_zstd_write",
            },
        )
        cas = LocalCAS.open(home, keys, feature_activations=activations)
        body = ("Sitina CAS compression benchmark. " * 16_384).encode()
        none = cas.publish_plaintext(
            body, tenant_id="benchmark", purpose_class="none", compression="none", media_type="text/plain"
        )
        zstd = cas.publish_plaintext(
            body, tenant_id="benchmark", purpose_class="zstd", compression="zstd", media_type="text/plain"
        )
        reused = cas.publish_plaintext(
            body, tenant_id="benchmark", purpose_class="zstd", compression="zstd", media_type="text/plain"
        )
        none_bytes = allocated(cas._object_path(none.receipt.object_ref.object_id))
        zstd_bytes = allocated(cas._object_path(zstd.receipt.object_ref.object_id))
        legacy_projection_bytes = allocated(legacy_db)
        directory_projection_bytes = allocated(directory_db)
        report = {
            "schema": "SITINA_STORAGE_V2_FIXTURE_BENCHMARK_V1",
            "fixture_only": True,
            "production_data_read": False,
            "production_data_written": False,
            "event_count": len(payloads),
            "sealed_event_count": 280,
            "active_tail_event_count": 20,
            "startup": {
                "before_full_verify_ms_min_3": round(full_ms, 3),
                "after_fast_start_ms_min_3": round(fast_ms, 3),
                "before_bytes_scanned": full.journal_bytes_scanned,
                "after_bytes_scanned": fast.journal_bytes_scanned,
                "byte_scan_reduction_ratio": round(1 - fast.journal_bytes_scanned / full.journal_bytes_scanned, 6),
                "authority_state_equal": fast.authority_state == full.authority_state,
            },
            "projection": {
                "before_full_payload_allocated_bytes": legacy_projection_bytes,
                "after_event_directory_allocated_bytes": directory_projection_bytes,
                "allocated_byte_reduction_ratio": round(1 - directory_projection_bytes / legacy_projection_bytes, 6),
            },
            "cas": {
                "logical_plaintext_bytes": len(body),
                "before_none_allocated_bytes": none_bytes,
                "after_zstd_allocated_bytes": zstd_bytes,
                "allocated_byte_reduction_ratio": round(1 - zstd_bytes / none_bytes, 6),
                "second_identical_publish_reused": reused.reused,
                "same_tenant_purpose_object_id_equal": reused.receipt.object_ref.object_id == zstd.receipt.object_ref.object_id,
            },
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
