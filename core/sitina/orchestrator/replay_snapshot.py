"""Integrity-chained replay snapshots stored separately for each run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.orchestrator.revision import CodeRevisionResolver
from sitina.utils import iso_now, new_id, read_json, sha256_text, stable_json, write_json


class ReplaySnapshotManager:
    SCHEMA_VERSION = "1.0"
    REQUIRED_HASH_FIELDS = {
        "snapshot_hash",
        "previous_snapshot_hash",
        "event_range_hash",
        "code_revision",
        "created_at",
    }

    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.root = home / "artifacts" / "replay_snapshots"

    def append(self, run_id: str, timeline: list[dict[str, Any]], replay_result: dict[str, Any]) -> dict[str, Any]:
        current = self.verify(run_id, timeline)
        if current["status"] in {"failed", "legacy_unverified"}:
            return current
        snapshots = self._chain_files(run_id)
        sequence = len(snapshots) + 1
        previous_hash = None
        if snapshots:
            previous = read_json(snapshots[-1], default={}) or {}
            previous_hash = previous.get("snapshot_hash")
        event_rows = [int(event.get("_event_row_id", 0)) for event in timeline if int(event.get("_event_row_id", 0)) > 0]
        replay_payload = {key: value for key, value in replay_result.items() if key != "snapshot_integrity"}
        body = {
            "snapshot_schema_version": self.SCHEMA_VERSION,
            "snapshot_id": "replay_snapshot_" + new_id(),
            "run_id": run_id,
            "sequence": sequence,
            "previous_snapshot_hash": previous_hash,
            "event_start_row_id": min(event_rows) if event_rows else None,
            "event_end_row_id": max(event_rows) if event_rows else None,
            "event_count": len(timeline),
            "event_range_hash": self.event_range_hash(timeline),
            "replay_result_hash": sha256_text(stable_json(replay_payload)),
            "code_revision": CodeRevisionResolver(self.home).for_run(run_id),
            "created_at": iso_now(),
        }
        document = body | {"snapshot_hash": sha256_text(stable_json(body))}
        path = self.run_directory(run_id) / f"{sequence:06d}.json"
        write_json(path, document)
        return self.verify(run_id, timeline)

    def verify(self, run_id: str, timeline: list[dict[str, Any]]) -> dict[str, Any]:
        chain_files = self._chain_files(run_id)
        legacy_files = self._legacy_files(run_id)
        if not chain_files and not legacy_files:
            return {"status": "not_recorded", "snapshot_count": 0, "errors": [], "latest_snapshot_hash": None}
        documents: list[tuple[Path, dict[str, Any]]] = []
        for path in chain_files + legacy_files:
            value = read_json(path, default=None)
            if not isinstance(value, dict):
                return self._failed([f"invalid replay snapshot JSON: {path.name}"], len(chain_files) + len(legacy_files))
            documents.append((path, value))
        if any(not self.REQUIRED_HASH_FIELDS <= set(value) for _path, value in documents):
            if chain_files:
                return self._failed(["mixed or incomplete replay snapshot hash format"], len(documents))
            return {
                "status": "legacy_unverified",
                "snapshot_count": len(documents),
                "errors": [],
                "latest_snapshot_hash": None,
                "legacy_files": [path.name for path, _value in documents],
            }

        errors: list[str] = []
        previous_hash: str | None = None
        for expected_sequence, (path, document) in enumerate(documents, start=1):
            sequence = document.get("sequence")
            if sequence != expected_sequence or path.parent == self.run_directory(run_id) and path.name != f"{expected_sequence:06d}.json":
                errors.append(f"replay snapshot order mismatch: {path.name}")
            if document.get("run_id") != run_id:
                errors.append(f"replay snapshot run_id mismatch: {path.name}")
            if document.get("previous_snapshot_hash") != previous_hash:
                errors.append(f"replay snapshot previous hash mismatch: {path.name}")
            claimed_hash = document.get("snapshot_hash")
            body = {key: value for key, value in document.items() if key != "snapshot_hash"}
            if claimed_hash != sha256_text(stable_json(body)):
                errors.append(f"replay snapshot hash mismatch: {path.name}")
            range_events = self._event_range(timeline, document)
            if len(range_events) != document.get("event_count"):
                errors.append(f"replay snapshot event range missing: {path.name}")
            elif self.event_range_hash(range_events) != document.get("event_range_hash"):
                errors.append(f"replay snapshot event range hash mismatch: {path.name}")
            previous_hash = str(claimed_hash) if isinstance(claimed_hash, str) else None
        if errors:
            return self._failed(errors, len(documents))
        return {
            "status": "passed",
            "snapshot_count": len(documents),
            "errors": [],
            "latest_snapshot_hash": previous_hash,
        }

    def hashes(self, run_id: str) -> list[str]:
        values: list[str] = []
        for path in self._chain_files(run_id):
            document = read_json(path, default={}) or {}
            if isinstance(document.get("snapshot_hash"), str):
                values.append(str(document["snapshot_hash"]))
        return values

    def run_directory(self, run_id: str) -> Path:
        return self.root / run_id

    @staticmethod
    def event_range_hash(events: list[dict[str, Any]]) -> str:
        return sha256_text(stable_json(events))

    @staticmethod
    def _event_range(timeline: list[dict[str, Any]], document: dict[str, Any]) -> list[dict[str, Any]]:
        start = document.get("event_start_row_id")
        end = document.get("event_end_row_id")
        if not isinstance(start, int) or not isinstance(end, int):
            return []
        return [
            event
            for event in timeline
            if isinstance(event.get("_event_row_id"), int) and start <= int(event["_event_row_id"]) <= end
        ]

    def _chain_files(self, run_id: str) -> list[Path]:
        directory = self.run_directory(run_id)
        return sorted(directory.glob("*.json")) if directory.exists() else []

    def _legacy_files(self, run_id: str) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(path for path in self.root.glob(f"{run_id}*.json") if path.is_file())

    @staticmethod
    def _failed(errors: list[str], count: int) -> dict[str, Any]:
        return {"status": "failed", "snapshot_count": count, "errors": errors, "latest_snapshot_hash": None}
