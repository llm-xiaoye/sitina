from __future__ import annotations

import json
import datetime as dt
import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.journal.locks import WriterLock
from sitina.legacy.fence import (
    LegacyFenceBusy,
    LegacyWriteDenied,
    LegacyWriteGate,
    authorized_compatibility_rollout,
    build_fence_coverage,
)
from sitina.legacy.model import (
    AuthorityResolution,
    AuthorityResolver,
    LegacyAuthorityStage,
    LegacySourceKind,
    LegacySourceRecord,
)
from sitina.legacy.readonly import LegacySQLiteReader
from sitina.storage import SitinaStore
from sitina.utils import write_json


class LegacyCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"]).resolve(strict=True)

    def test_authority_types_never_derive_writer_from_stage(self) -> None:
        self.assertFalse(hasattr(LegacyAuthorityStage.CUTOVER_PREPARED_NO_WRITER, "authoritative_writer"))
        self.assertIsNone(AuthorityResolution.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER.writer)
        self.assertEqual(AuthorityResolution.LEGACY_WRITER_AUTHORIZED.writer, "legacy")
        self.assertEqual(AuthorityResolution.JOURNAL_WRITER_AUTHORIZED.writer, "journal")
        resolver = AuthorityResolver()
        self.assertEqual(
            resolver.resolve(legacy_fence_verified=False, production_genesis_verified=False, cutover_outcome=None),
            AuthorityResolution.LEGACY_WRITER_AUTHORIZED,
        )
        self.assertEqual(
            resolver.resolve(legacy_fence_verified=True, production_genesis_verified=True, cutover_outcome=None),
            AuthorityResolution.CUTOVER_PREPARED_NO_WRITER,
        )
        self.assertEqual(
            resolver.resolve(legacy_fence_verified=True, production_genesis_verified=True, cutover_outcome="UNKNOWN"),
            AuthorityResolution.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER,
        )
        self.assertEqual(
            resolver.resolve(legacy_fence_verified=True, production_genesis_verified=True, cutover_outcome="COMMITTED"),
            AuthorityResolution.JOURNAL_WRITER_AUTHORIZED,
        )

    def test_legacy_source_record_requires_provenance_and_valid_hash(self) -> None:
        record = LegacySourceRecord(
            kind=LegacySourceKind.SQLITE_TABLE,
            source_ref="data/sitina.db#events:42",
            content_hash="sha256:" + "0" * 64,
            observed_at="2026-07-13T00:00:00Z",
        )
        self.assertTrue(record.source_ref.endswith("events:42"))
        with self.assertRaises(ValueError):
            LegacySourceRecord(
                kind=LegacySourceKind.SQLITE_TABLE,
                source_ref="",
                content_hash="not-a-hash",
                observed_at="unknown",
            )

    def test_readonly_sqlite_adapter_never_creates_or_mutates(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.home / "temp") as temporary:
            root = Path(temporary)
            database = root / "legacy.db"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
                connection.executemany("INSERT INTO events(payload) VALUES (?)", [("one",), ("two",)])
            before = {path.name: (path.stat().st_size, path.stat().st_mtime_ns) for path in root.iterdir()}
            with LegacySQLiteReader.open(database) as reader:
                self.assertEqual(reader.table_names(), ["events"])
                self.assertEqual(reader.table_count("events"), 2)
                self.assertEqual(reader.table_max_integer_key("events", "id"), 2)
                self.assertEqual([row["payload"] for row in reader.iter_table_rows("events", key_column="id")], ["one", "two"])
                with self.assertRaises(sqlite3.OperationalError):
                    reader.connection.execute("INSERT INTO events(payload) VALUES ('forbidden')")
                with self.assertRaises(ValueError):
                    list(reader.iter_table_rows("events; DROP TABLE events", key_column="id"))
            after = {path.name: (path.stat().st_size, path.stat().st_mtime_ns) for path in root.iterdir()}
            self.assertEqual(before, after)
            missing = root / "missing.db"
            with self.assertRaises(FileNotFoundError):
                LegacySQLiteReader.open(missing)
            self.assertFalse(missing.exists())

    def test_independent_snapshot_is_required_for_immutable_mode(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.home / "temp") as temporary:
            root = Path(temporary)
            live = root / "live.db"
            with sqlite3.connect(live) as connection:
                connection.execute("CREATE TABLE t(id INTEGER PRIMARY KEY)")
            with self.assertRaises(ValueError):
                LegacySQLiteReader.open(live, immutable=True)
            snapshot = root / "snapshot.db"
            with sqlite3.connect(live) as source, sqlite3.connect(snapshot) as target:
                source.backup(target)
            with LegacySQLiteReader.open_snapshot(snapshot) as reader:
                self.assertEqual(reader.table_names(), ["t"])

    def test_fixture_fence_blocks_top_level_and_low_level_writes_but_allows_readonly(self) -> None:
        gate = LegacyWriteGate(self.home)
        gate.unfreeze_fixture_if_present()
        SitinaStore(self.home).init_db()
        self.assertEqual(gate.status().state, "LEGACY_ACTIVE")
        gate.assert_writes_allowed()
        frozen = gate.freeze("snapshot_phase0_fixture", fixture_authorization=True)
        self.assertEqual(frozen.state, "FROZEN_NO_WRITER")
        try:
            with self.assertRaises(LegacyWriteDenied):
                gate.assert_writes_allowed()
            with self.assertRaises(LegacyWriteDenied):
                SitinaStore(self.home).append_jsonl(self.home / "logs/events/forbidden.jsonl", {"x": 1})
            with LegacySQLiteReader.open(self.home / "data/sitina.db") as reader:
                self.assertIn("runs", reader.table_names())
        finally:
            gate.unfreeze_fixture()
        self.assertEqual(gate.status().state, "LEGACY_ACTIVE")

    def test_kernel_coordination_lock_prevents_freeze_with_live_writer(self) -> None:
        gate = LegacyWriteGate(self.home)
        gate.unfreeze_fixture_if_present()
        script = (
            "from pathlib import Path\n"
            "import os,sys\n"
            "from sitina.legacy.fence import LegacyWriteGate\n"
            "g=LegacyWriteGate(Path(os.environ['SITINA_HOME']))\n"
            "g.acquire_process_writer_lease()\n"
            "print('READY', flush=True)\n"
            "sys.stdin.readline()\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", script],
            cwd=self.home,
            env=dict(os.environ),
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "READY")
            with self.assertRaises(LegacyFenceBusy):
                gate.freeze("snapshot_busy", fixture_authorization=True)
        finally:
            assert child.stdin is not None
            child.stdin.write("release\n")
            child.stdin.flush()
            stdout, stderr = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, stdout + stderr)
        frozen = gate.freeze("snapshot_after_drain", fixture_authorization=True)
        try:
            self.assertEqual(frozen.state, "FROZEN_NO_WRITER")
        finally:
            gate.unfreeze_fixture()

    def test_frozen_guard_covers_direct_filesystem_sqlite_and_registered_sinks(self) -> None:
        gate = LegacyWriteGate(self.home)
        gate.unfreeze_fixture_if_present()
        SitinaStore(self.home).init_db()
        gate.freeze("snapshot_bypass_matrix", fixture_authorization=True)
        try:
            with self.assertRaises(LegacyWriteDenied):
                write_json(self.home / "state/direct-bypass.json", {"forbidden": True})
            with self.assertRaises(LegacyWriteDenied):
                (self.home / "artifacts/direct-bypass.txt").write_text("forbidden", encoding="utf-8")
            with self.assertRaises(LegacyWriteDenied):
                sqlite3.connect(self.home / "data/sitina.db")
            with self.assertRaises(LegacyWriteDenied):
                subprocess.run([sys.executable, "-c", "print('forbidden')"], check=False)
        finally:
            gate.unfreeze_fixture()
        inventory = json.loads(Path("/Users/moss/Desktop/sitina/output/sitina-bplus-write-sink-inventory-phase-minus1-final.json").read_text(encoding="utf-8"))
        coverage = build_fence_coverage(inventory)
        self.assertEqual(coverage["summary"]["blocker_count"], 0, coverage)
        self.assertEqual(coverage["summary"]["entry_count"], inventory["summary"]["entry_count"])
        self.assertGreater(coverage["summary"]["guarded_count"], 0)

    def test_compatibility_rollout_scope_requires_live_journal_lock_and_exact_hashed_identity(self) -> None:
        gate = LegacyWriteGate(self.home)
        gate.unfreeze_fixture_if_present()
        journal_root = self.home / "journal"
        journal_root.mkdir(parents=True, exist_ok=True)
        writer_lock = WriterLock.acquire(journal_root / "writer.lock", "compatibility-test-journal", 1)
        journal = SimpleNamespace(home=self.home, root=journal_root, writer_lock=writer_lock)
        process_id = "compatibility-rollout-test-" + uuid.uuid4().hex
        started = dt.datetime.now(dt.timezone.utc)

        def build_lease(identity: str) -> RuntimeCompatibilityLease:
            return RuntimeCompatibilityLease.build(
                process_id=identity,
                binary_version="test",
                reader_capabilities=("projection-v2",),
                writer_capabilities=("projection-v2",),
                started_at=started.isoformat().replace("+00:00", "Z"),
                lease_expires_at=(started + dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                fencing_token=1,
            )

        gate.freeze("compatibility-rollout-scope", fixture_authorization=True)
        try:
            with authorized_compatibility_rollout(
                journal,
                goal_thread_id="goal-thread",
                process_id=process_id,
            ):
                registry = CompatibilityLeaseRegistry(self.home)
                lease = build_lease(process_id)
                registry.register(lease)
                with self.assertRaises(LegacyWriteDenied):
                    (self.home / "runtime/forbidden.json").write_text("forbidden\n", encoding="utf-8")
                with self.assertRaises(LegacyWriteDenied):
                    registry.register(build_lease("different-process"))
                registry.release(process_id, fencing_token=lease.fencing_token)
            name = hashlib.sha256(process_id.encode("utf-8")).hexdigest()
            with self.assertRaises(LegacyWriteDenied):
                (self.home / f"runtime/compatibility-leases/{name}.lease.json").write_text(
                    "forbidden\n", encoding="utf-8"
                )
            writer_lock.close()
            with self.assertRaises(LegacyWriteDenied):
                with authorized_compatibility_rollout(
                    journal,
                    goal_thread_id="goal-thread",
                    process_id=process_id,
                ):
                    pass
        finally:
            if not writer_lock._closed:
                writer_lock.close()
            gate.unfreeze_fixture()

    def test_cli_exposes_status_and_observational_inventory_only(self) -> None:
        launcher = self.home / "bin/sitina"
        status = subprocess.run(
            [str(launcher), "legacy", "status"],
            cwd=self.home,
            env=dict(os.environ),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
        payload = json.loads(status.stdout)
        self.assertEqual(payload["state"], "LEGACY_ACTIVE")
        help_result = subprocess.run([str(launcher), "legacy", "--help"], cwd=self.home, env=dict(os.environ), capture_output=True, text=True, timeout=30)
        self.assertNotIn("freeze", help_result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
