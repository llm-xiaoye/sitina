from __future__ import annotations

import json
import hashlib
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.legacy.retirement import LegacyRuntimePolicy
from sitina.utils import ensure_dir, iso_now, redact_text, stable_json


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_version (id, version) VALUES (1, 1);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  phase TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  verification_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  state_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  run_id TEXT,
  trace_id TEXT,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  run_id TEXT,
  trace_id TEXT,
  agent TEXT,
  operation TEXT NOT NULL,
  input_hash TEXT,
  output_hash TEXT,
  artifact_hash TEXT,
  risk_scan_id TEXT,
  approval_id TEXT,
  exit_status TEXT,
  duration_ms INTEGER,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_hash TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  turn_id TEXT NOT NULL,
  producing_agent TEXT NOT NULL,
  command_fingerprint TEXT NOT NULL,
  artifact_path TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  risk_scan_id TEXT NOT NULL,
  risk_scan_hash TEXT NOT NULL,
  scope_hash TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_scans (
  risk_scan_id TEXT PRIMARY KEY,
  risk_scan_hash TEXT NOT NULL,
  run_id TEXT,
  risk_level TEXT NOT NULL,
  action TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_candidates (
  candidate_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS obsidian_cache (
  path TEXT PRIMARY KEY,
  mtime REAL NOT NULL,
  content_hash TEXT NOT NULL,
  title TEXT,
  excerpt TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS obsidian_line_cache (
  path TEXT NOT NULL,
  line INTEGER NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (path, line)
);

CREATE TABLE IF NOT EXISTS provider_health (
  profile TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  next_check_at TEXT,
  failure_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  model TEXT,
  latency_ms INTEGER
);
"""


class SitinaStore:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.db_path = home / "data" / "sitina.db"
        self.events_dir = home / "logs" / "events"
        self.audit_dir = home / "logs" / "audit"
        self.runs_dir = home / "logs" / "runs"

    def connect(self) -> sqlite3.Connection:
        policy = LegacyRuntimePolicy.load(self.home)
        if policy.protected_environment and not policy.write_enabled:
            policy.deny_write("SitinaStore.connect")
        ensure_dir(self.db_path.parent)
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def connect_authorized(self, resolution: object, *, now: int, writer: str) -> sqlite3.Connection:
        """Open a fixture writer only when the current resolution names it."""
        from sitina.authority.model import AuthorityResolution

        if not isinstance(resolution, AuthorityResolution):
            raise PermissionError("store writer requires AuthorityResolution")
        resolution.assert_fresh(now=now)
        allowed = (writer == "legacy" and resolution.authorizes_legacy) or (writer == "journal" and resolution.authorizes_journal)
        if not allowed or resolution.writer_count != 1:
            raise PermissionError("AuthorityResolution does not authorize this store writer")
        return self.connect()

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def append_jsonl(self, path: Path, row: dict[str, Any]) -> None:
        policy = LegacyRuntimePolicy.load(self.home)
        if policy.protected_environment and not policy.active_business_jsonl_enabled:
            policy.deny_write(f"SitinaStore.append_jsonl:{path}")
        ensure_dir(path.parent)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def record_event(self, event_type: str, payload: dict[str, Any], run_id: str | None = None, trace_id: str | None = None) -> str:
        ts = iso_now()
        row = {"ts": ts, "run_id": run_id, "trace_id": trace_id, "event_type": event_type, "payload": payload}
        path = self.events_dir / f"{ts[:10]}.jsonl"
        self.append_jsonl(path, row)
        if run_id:
            self.append_jsonl(self.runs_dir / f"{run_id}.jsonl", row)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events (ts, run_id, trace_id, event_type, payload_json) VALUES (?, ?, ?, ?, ?)",
                (ts, run_id, trace_id, event_type, stable_json(payload)),
            )
        return ts

    def record_audit(self, operation: str, payload: dict[str, Any], run_id: str | None = None, trace_id: str | None = None, **fields: Any) -> None:
        ts = iso_now()
        clean_payload = json.loads(redact_text(json.dumps(payload, ensure_ascii=False)))
        row = {"ts": ts, "run_id": run_id, "trace_id": trace_id, "operation": operation, "payload": clean_payload, **fields}
        self.append_jsonl(self.audit_dir / f"{ts[:10]}.jsonl", row)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                (ts, run_id, trace_id, agent, operation, input_hash, output_hash, artifact_hash,
                 risk_scan_id, approval_id, exit_status, duration_ms, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    run_id,
                    trace_id,
                    fields.get("agent"),
                    operation,
                    fields.get("input_hash"),
                    fields.get("output_hash"),
                    fields.get("artifact_hash"),
                    fields.get("risk_scan_id"),
                    fields.get("approval_id"),
                    fields.get("exit_status"),
                    fields.get("duration_ms"),
                    stable_json(clean_payload),
                ),
            )

    def upsert_run_state(self, state: dict[str, Any]) -> None:
        now = iso_now()
        run_id = state["run_id"]
        with self.connect() as conn:
            existing = conn.execute("SELECT created_at FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            created = existing[0] if existing else now
            conn.execute(
                """
                INSERT INTO runs (run_id, phase, risk_level, verification_status, created_at, updated_at, state_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                  phase=excluded.phase,
                  risk_level=excluded.risk_level,
                  verification_status=excluded.verification_status,
                  updated_at=excluded.updated_at,
                  state_json=excluded.state_json
                """,
                (
                    run_id,
                    state["phase"],
                    state["risk_level"],
                    state["verification_status"],
                    created,
                    now,
                    stable_json(state),
                ),
            )

    def insert_risk_scan(self, scan: dict[str, Any], run_id: str | None = None) -> None:
        ensure_dir(self.home / "artifacts" / "risk_scans")
        (self.home / "artifacts" / "risk_scans" / f"{scan['risk_scan_id']}.json").write_text(
            json.dumps(scan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO risk_scans
                (risk_scan_id, risk_scan_hash, run_id, risk_level, action, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan["risk_scan_id"],
                    scan["risk_scan_hash"],
                    run_id,
                    scan["risk_level"],
                    scan["action"],
                    scan["created_at"],
                    stable_json(scan),
                ),
            )

    def insert_approval(self, approval: dict[str, Any]) -> None:
        ensure_dir(self.home / "artifacts" / "approvals")
        (self.home / "artifacts" / "approvals" / f"{approval['approval_id']}.json").write_text(
            json.dumps(approval, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO approvals
                (approval_id, run_id, risk_scan_id, risk_scan_hash, scope_hash, plan_hash, action, expires_at, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval["approval_id"],
                    approval["run_id"],
                    approval["risk_scan_id"],
                    approval["risk_scan_hash"],
                    approval["scope_hash"],
                    approval["plan_hash"],
                    approval["action"],
                    approval["expires_at"],
                    approval["created_at"],
                    stable_json(approval),
                ),
            )

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT payload_json FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def insert_artifact(self, artifact: dict[str, Any]) -> None:
        ensure_dir(self.home / "artifacts" / "evidence")
        self.append_jsonl(self.home / "artifacts" / "evidence" / "artifact_registry.jsonl", artifact)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts
                (artifact_hash, run_id, turn_id, producing_agent, command_fingerprint, artifact_path, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact["artifact_hash"],
                    artifact["run_id"],
                    artifact["turn_id"],
                    artifact["producing_agent"],
                    artifact["producing_command_fingerprint"],
                    artifact["artifact_path"],
                    artifact["created_at"],
                ),
            )

    def get_artifact(self, artifact_hash: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT run_id, turn_id, producing_agent, command_fingerprint, artifact_path, created_at FROM artifacts WHERE artifact_hash = ?",
                (artifact_hash,),
            ).fetchone()
        if not row:
            return None
        return {
            "artifact_hash": artifact_hash,
            "run_id": row[0],
            "turn_id": row[1],
            "producing_agent": row[2],
            "producing_command_fingerprint": row[3],
            "artifact_path": row[4],
            "created_at": row[5],
        }

    def list_runs(self, *, limit: int | None = 50) -> list[dict[str, Any]]:
        if limit is not None and limit < 0:
            raise ValueError("run list limit must be non-negative or None")
        query = "SELECT run_id, phase, risk_level, verification_status, updated_at FROM runs ORDER BY updated_at DESC"
        params: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "run_id": r[0],
                "phase": r[1],
                "risk_level": r[2],
                "verification_status": r[3],
                "updated_at": r[4],
            }
            for r in rows
        ]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT state_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def insert_memory_candidate(self, candidate: dict[str, Any]) -> bool:
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO memory_candidates
                (candidate_id, run_id, status, payload_json, created_at, reviewed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate["candidate_id"],
                    candidate["run_id"],
                    candidate.get("status", "pending"),
                    stable_json(candidate["payload"]),
                    candidate["created_at"],
                    candidate.get("reviewed_at"),
                ),
            )
            return cursor.rowcount > 0

    def list_memory_candidates(self, status: str | None = "pending", *, limit: int = 50) -> list[dict[str, Any]]:
        query = "SELECT candidate_id, run_id, status, payload_json, created_at, reviewed_at FROM memory_candidates"
        params: list[Any] = []
        if status and status != "all":
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._memory_candidate_from_row(row) for row in rows]

    def get_memory_candidate(self, candidate_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT candidate_id, run_id, status, payload_json, created_at, reviewed_at
                FROM memory_candidates WHERE candidate_id = ?
                """,
                (candidate_id,),
            ).fetchone()
        return self._memory_candidate_from_row(row) if row else None

    def update_memory_candidate_status(
        self,
        candidate_id: str,
        status: str,
        reviewed_at: str,
        payload_updates: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_memory_candidate(candidate_id)
        if not current:
            return None
        payload = dict(current.get("payload", {}))
        payload.update(payload_updates or {})
        payload["status"] = status
        payload["reviewed_at"] = reviewed_at
        with self.connect() as conn:
            conn.execute(
                "UPDATE memory_candidates SET status = ?, reviewed_at = ?, payload_json = ? WHERE candidate_id = ?",
                (status, reviewed_at, stable_json(payload), candidate_id),
            )
        return self.get_memory_candidate(candidate_id)

    def _memory_candidate_from_row(self, row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "candidate_id": row[0],
            "run_id": row[1],
            "status": row[2],
            "payload": json.loads(row[3]),
            "created_at": row[4],
            "reviewed_at": row[5],
        }

    def get_provider_health(self, profile: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT profile, status, checked_at, next_check_at, failure_count, last_error, model, latency_ms
                FROM provider_health WHERE profile = ?
                """,
                (profile,),
            ).fetchone()
        if not row:
            return None
        return {
            "profile": row[0],
            "status": row[1],
            "checked_at": row[2],
            "next_check_at": row[3],
            "failure_count": row[4],
            "last_error": row[5],
            "model": row[6],
            "latency_ms": row[7],
        }

    def list_provider_health(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT profile, status, checked_at, next_check_at, failure_count, last_error, model, latency_ms
                FROM provider_health ORDER BY profile
                """
            ).fetchall()
        return [
            {
                "profile": row[0],
                "status": row[1],
                "checked_at": row[2],
                "next_check_at": row[3],
                "failure_count": row[4],
                "last_error": row[5],
                "model": row[6],
                "latency_ms": row[7],
            }
            for row in rows
        ]

    def upsert_provider_health(self, row: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO provider_health
                (profile, status, checked_at, next_check_at, failure_count, last_error, model, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile) DO UPDATE SET
                  status=excluded.status,
                  checked_at=excluded.checked_at,
                  next_check_at=excluded.next_check_at,
                  failure_count=excluded.failure_count,
                  last_error=excluded.last_error,
                  model=excluded.model,
                  latency_ms=excluded.latency_ms
                """,
                (
                    row["profile"],
                    row["status"],
                    row["checked_at"],
                    row.get("next_check_at"),
                    int(row.get("failure_count", 0)),
                    row.get("last_error"),
                    row.get("model"),
                    row.get("latency_ms"),
                ),
            )


class LegacySnapshotStore:
    """Strictly read-only compatibility reader for the frozen Legacy source."""

    enabled = True
    reader_generation = "legacy-frozen-snapshot-v1"

    def __init__(self, snapshot_root: Path, *, intended_snapshot_hash: str):
        self.home = Path(snapshot_root).expanduser().resolve(strict=True)
        self.db_path = self.home / "data/sitina.db"
        self.manifest_path = self.home / "frozen-snapshot-manifest.json"
        if self.manifest_path.is_symlink() or not self.manifest_path.is_file():
            raise ValueError("frozen Legacy snapshot manifest is unavailable")
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            claimed = str(manifest.pop("manifest_sha256"))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("frozen Legacy snapshot manifest is malformed") from error
        actual = hashlib.sha256(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if claimed != actual or manifest.get("schema") != "FROZEN_COHERENT_SNAPSHOT_V1":
            raise ValueError("frozen Legacy snapshot manifest hash is invalid")
        if manifest.get("destination") != str(self.home):
            raise ValueError("frozen Legacy snapshot manifest belongs to another root")
        if manifest.get("intended_snapshot_hash") != intended_snapshot_hash:
            raise ValueError("frozen Legacy snapshot intent differs from Production Genesis")
        if not self.db_path.is_file() or self.db_path.is_symlink():
            raise ValueError("frozen Legacy SQLite database is unavailable")
        if any(self.db_path.with_name(self.db_path.name + suffix).exists() for suffix in ("-wal", "-shm")):
            raise ValueError("frozen Legacy SQLite database has mutable WAL sidecars")
        self.manifest = manifest
        self.manifest_sha256 = claimed
        self.intended_snapshot_hash = intended_snapshot_hash

    def connect(self) -> sqlite3.Connection:
        encoded = urllib.parse.quote(str(self.db_path), safe="/")
        connection = sqlite3.connect(f"file:{encoded}?mode=ro&immutable=1", uri=True, timeout=30)
        connection.execute("PRAGMA query_only=ON")
        return connection

    def list_runs(self, *, limit: int | None = 50) -> list[dict[str, Any]]:
        if limit is not None and limit < 0:
            raise ValueError("run list limit must be non-negative or None")
        query = "SELECT run_id, phase, risk_level, verification_status, updated_at FROM runs ORDER BY updated_at DESC"
        parameters: tuple[int, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            parameters = (limit,)
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            {
                "run_id": row[0], "phase": row[1], "risk_level": row[2],
                "verification_status": row[3], "updated_at": row[4],
                "reader_generation": "legacy-frozen-snapshot-v1",
                "as_of_snapshot_manifest_sha256": self.manifest_sha256,
            }
            for row in rows
        ]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT state_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        if not isinstance(value, dict):
            raise ValueError("frozen Legacy run state is not an object")
        return {
            **value,
            "reader_generation": "legacy-frozen-snapshot-v1",
            "as_of_snapshot_manifest_sha256": self.manifest_sha256,
        }

    def timeline(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id,ts,trace_id,payload_json FROM events "
                "WHERE run_id=? AND event_type='run_ledger' ORDER BY id ASC",
                (run_id,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row_id, timestamp, trace_id, payload_json in rows:
            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                continue
            result.append({
                **payload,
                "_event_row_id": row_id,
                "_recorded_ts": timestamp,
                "_trace_id": trace_id,
                "_reader_generation": "legacy-frozen-snapshot-v1",
            })
        return result
