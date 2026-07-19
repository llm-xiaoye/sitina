from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from sitina.journal.model import parse_canonical_json


class StorageMetricsError(RuntimeError):
    pass


def _field(value: object, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


class StorageMetricsCollector:
    """Point-in-time metrics snapshot. Collection has no Journal writer dependency."""

    def __init__(self, home: str | Path):
        self.home = Path(home).resolve(strict=True)

    @staticmethod
    def _regular_files(root: Path) -> tuple[Path, ...]:
        if not root.exists():
            return ()
        values: list[Path] = []
        for path in root.rglob("*"):
            if path.is_symlink():
                raise StorageMetricsError(f"diagnostic inventory rejects symlink: {path}")
            if path.is_file():
                values.append(path)
        return tuple(sorted(values))

    @staticmethod
    def _allocated(path: Path) -> int:
        metadata = path.stat()
        return int(getattr(metadata, "st_blocks", 0)) * 512 or metadata.st_size

    def _cas(self) -> dict[str, Any]:
        root = self.home / "cas"
        objects = self._regular_files(root / "objects")
        logical = 0
        for path in objects:
            raw = path.read_bytes()
            if len(raw) < 4:
                raise StorageMetricsError("CAS metric inventory found a truncated object")
            header_length = int.from_bytes(raw[:4], "big")
            header = parse_canonical_json(raw[4 : 4 + header_length])
            logical += int(header["plaintext_length"])
        allocated = sum(self._allocated(path) for path in self._regular_files(root))
        return {
            "cas_object_count": len(objects),
            "cas_logical_bytes": logical,
            "cas_allocated_bytes": allocated,
            "cas_dedup_ratio": round(logical / allocated, 6) if allocated else 1.0,
            "cas_dedup_ratio_definition": "logical_plaintext_bytes/total_cas_allocated_bytes",
            "cas_staging_count": len(tuple((root / "staging").glob("*.stage"))) if (root / "staging").is_dir() else 0,
            "cas_quarantine_count": len(tuple((root / "quarantine").glob("*.q"))) if (root / "quarantine").is_dir() else 0,
        }

    def _projection(self, journal_frontier: int) -> dict[str, Any]:
        root = self.home / "projections"
        pointer_path = root / "current-generation.json"
        pointer: dict[str, Any] = {}
        if pointer_path.is_file() and not pointer_path.is_symlink():
            try:
                pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pointer = {}
        frontier = int(pointer.get("journal_frontier", 0))
        generation_files = tuple(
            path
            for name in ("current", "previous", "building")
            for path in self._regular_files(root / name)
            if path.suffix == ".sqlite"
        )
        return {
            "projection_frontier": frontier,
            "projection_lag": max(0, journal_frontier - frontier),
            "projection_generation_count": len(generation_files),
            "projection_disk_bytes": sum(self._allocated(path) for path in generation_files),
            "projection_pointer_schema": pointer.get("schema"),
        }

    @staticmethod
    def _memory(events: Iterable[object]) -> dict[str, Any]:
        counts = {
            "candidate": 0,
            "accepted": 0,
            "expired": 0,
            "conflict": 0,
            "retrieval": 0,
            "retrieval_hit": 0,
            "episode_reuse": 0,
        }
        for event in events:
            event_type = str(_field(event, "event_type", ""))
            payload = _field(event, "payload", {})
            payload = payload if isinstance(payload, Mapping) else {}
            if event_type == "memory.candidate-created":
                counts["candidate"] += 1
            elif event_type == "memory.accepted":
                counts["accepted"] += 1
            elif event_type == "memory.expired":
                counts["expired"] += 1
            elif event_type in {"memory.conflict", "memory.transition-conflict"}:
                counts["conflict"] += 1
            elif event_type == "memory.retrieval":
                counts["retrieval"] += 1
                if int(payload.get("result_count", 0)) > 0:
                    counts["retrieval_hit"] += 1
            elif event_type in {"memory.episode-reused", "episode.reused"}:
                counts["episode_reuse"] += 1
        candidates = counts["candidate"]
        retrievals = counts["retrieval"]
        return {
            "memory_candidate_count": candidates,
            "memory_acceptance_rate": round(counts["accepted"] / candidates, 6) if candidates else 0.0,
            "memory_expired_rate": round(counts["expired"] / candidates, 6) if candidates else 0.0,
            "memory_conflict_rate": round(counts["conflict"] / candidates, 6) if candidates else 0.0,
            "memory_retrieval_hit_rate": round(counts["retrieval_hit"] / retrievals, 6) if retrievals else 0.0,
            "episode_reuse_rate": round(counts["episode_reuse"] / retrievals, 6) if retrievals else 0.0,
        }

    def collect(
        self,
        *,
        startup_duration_ms: int,
        journal_frontier: int,
        fast_start_report: object | None = None,
        memory_events: Iterable[object] = (),
        gc_dry_run_plan: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if startup_duration_ms < 0 or journal_frontier < 0:
            raise StorageMetricsError("startup duration and Journal frontier must be non-negative")
        report = fast_start_report or {}
        sealed = self._regular_files(self.home / "journal" / "sealed")
        control_events = _field(report, "authority_control_events", _field(report, "control_events", ())) or ()
        tail_events = _field(report, "active_tail_events", _field(report, "tail_events", ())) or ()
        checkpoint_used = bool(
            _field(
                report,
                "fast_start_checkpoint_used",
                _field(report, "checkpoint_used", _field(report, "checkpoint_sequence", 0)),
            )
        )
        snapshot = {
            "schema": "SITINA_STORAGE_METRICS_SNAPSHOT_V1",
            "read_only": True,
            "journal_events_appended": 0,
            "startup_duration_ms": startup_duration_ms,
            "journal_bytes_scanned": int(_field(report, "journal_bytes_scanned", 0)),
            "journal_events_verified": int(_field(report, "journal_events_verified", len(control_events) + len(tail_events))),
            "fast_start_checkpoint_used": checkpoint_used,
            "active_tail_event_count": int(_field(report, "active_tail_event_count", len(tail_events))),
            "sealed_segment_count": len([path for path in sealed if path.suffix in {".seg", ".journal"}]),
            **self._projection(journal_frontier),
            **self._cas(),
            "gc_candidate_count": len((gc_dry_run_plan or {}).get("candidates", [])),
            **self._memory(memory_events),
        }
        return snapshot


__all__ = ["StorageMetricsCollector", "StorageMetricsError"]
