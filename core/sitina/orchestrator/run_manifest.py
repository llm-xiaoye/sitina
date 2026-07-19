"""Immutable completion manifests for current and legacy runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from sitina.constants import SITINA_HOME
from sitina.orchestrator.accounting import ProviderAccounting
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine
from sitina.orchestrator.revision import CodeRevisionResolver
from sitina.orchestrator.terminal import terminal_summary
from sitina.storage import SitinaStore
from sitina.utils import file_sha256, iso_now, new_id, sha256_text, stable_json, write_json


class RunManifestManager:
    SCHEMA_VERSION = "1.0"

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.ledger = RunLedger(home, self.store)

    def path(self, run_id: str) -> Path:
        return self.home / "artifacts" / "runs" / run_id / "manifest.json"

    def create(self, run_id: str, *, legacy_generated: bool = False) -> dict[str, Any]:
        timeline = self.ledger.timeline(run_id)
        if not timeline:
            raise ValueError(f"run not found: {run_id}")
        replay = ReplayEngine(self.home, self.store).replay(run_id, record=False)
        revision = CodeRevisionResolver(self.home).for_run(run_id)
        accounting = ProviderAccounting(self.home, self.store).for_run(run_id, timeline=timeline, replay=replay)
        terminal = terminal_summary(timeline)
        associated = self._associated_files(run_id, timeline)
        file_hashes = {relative: file_sha256(self.home / relative) for relative in associated}
        with self.store.connect() as conn:
            audit_count = int(conn.execute("SELECT COUNT(*) FROM audit_log WHERE run_id = ?", (run_id,)).fetchone()[0])
        run_started = next((event for event in timeline if event.get("event_type") == "run_started"), {})
        start_payload = run_started.get("payload_json") or {}
        body = {
            "manifest_id": "run_manifest_" + new_id(),
            "manifest_schema_version": self.SCHEMA_VERSION,
            "run_id": run_id,
            **revision,
            "provider_mode": start_payload.get("provider_mode") or self._one_or_many(snapshot.get("provider_mode") for snapshot in replay.agent_snapshots),
            "profiles": sorted({str((snapshot.get("provider_identity") or {}).get("profile_name")) for snapshot in replay.agent_snapshots if (snapshot.get("provider_identity") or {}).get("profile_name")}),
            "models": sorted({str((snapshot.get("provider_identity") or {}).get("model")) for snapshot in replay.agent_snapshots if (snapshot.get("provider_identity") or {}).get("model")}),
            "agent_ids": sorted({str(snapshot.get("agent_id")) for snapshot in replay.agent_snapshots if snapshot.get("agent_id")}),
            "event_count": len(timeline),
            "event_row_end": max((int(event.get("_event_row_id") or 0) for event in timeline), default=0),
            "audit_count": audit_count,
            "provider_call_count": accounting["http_attempts"],
            "logical_agent_calls": accounting["logical_agent_calls"],
            "proposal_ids": sorted({str(item.get("proposal_id")) for item in replay.proposals.get("submitted", []) if item.get("proposal_id")}),
            "evaluation_ids": sorted({str(item.get("evaluation_id")) for item in replay.proposals.get("evaluations", []) if item.get("evaluation_id")}),
            "handoff_ids": sorted({str(item.get("handoff_id")) for item in replay.handoff_chain if item.get("handoff_id")}),
            "arbitration_ids": sorted({str(item.get("arbitration_id")) for item in replay.arbitrations if item.get("arbitration_id")}),
            "lease_ids": sorted({str(item.get("lease_id")) for item in replay.leases if item.get("lease_id")}),
            "checkpoint_ids": [str(item.get("checkpoint_id")) for item in CheckpointManager(self.home).list(run_id) if item.get("checkpoint_id")],
            "terminal_event": {
                "event_type": terminal.get("type"),
                "normalized_terminal": terminal.get("normalized_terminal"),
                "legacy_blocked_terminal": terminal.get("legacy_blocked_terminal"),
                "status": terminal.get("status"),
                "reason_hash": sha256_text(str(terminal.get("reason") or "")),
            },
            "associated_files": associated,
            "file_hashes": file_hashes,
            "controlled_fixture": accounting["controlled_fixture"],
            "real_provider_called": accounting["real_provider_called"],
            "excluded_from_live_usage_totals": accounting["excluded_from_live_usage_totals"],
            "legacy_generated": legacy_generated or bool(revision.get("legacy_unversioned")),
            "created_at": run_started.get("timestamp") or run_started.get("_recorded_ts"),
            "completed_at": next((event.get("timestamp") or event.get("_recorded_ts") for event in timeline if event.get("event_type") in self._terminal_types()), None),
            "manifest_created_at": iso_now(),
        }
        document = body | {"file_hash": sha256_text(stable_json(body))}
        version_path = self.path(run_id).parent / "manifests" / f"{body['manifest_id']}.json"
        write_json(version_path, document)
        write_json(self.path(run_id), document)
        return document

    def ensure(self, run_id: str) -> dict[str, Any]:
        path = self.path(run_id)
        if path.exists():
            from sitina.utils import read_json

            document = read_json(path, default=None)
            if isinstance(document, dict):
                return document
        return self.create(run_id, legacy_generated=True)

    def verify(self, manifest_or_path: dict[str, Any] | Path | str) -> tuple[bool, list[str]]:
        from sitina.utils import read_json

        if isinstance(manifest_or_path, dict):
            manifest = manifest_or_path
        else:
            manifest = read_json(Path(manifest_or_path), default=None)
        if not isinstance(manifest, dict):
            return False, ["manifest missing or invalid"]
        errors: list[str] = []
        claimed = manifest.get("file_hash")
        body = {key: value for key, value in manifest.items() if key != "file_hash"}
        if claimed != sha256_text(stable_json(body)):
            errors.append("manifest file_hash mismatch")
        for relative in manifest.get("associated_files", []):
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                errors.append("manifest contains unsafe associated path")
                continue
            path = self.home / relative
            expected = (manifest.get("file_hashes") or {}).get(relative)
            if not path.is_file():
                errors.append(f"associated file missing: {relative}")
            elif expected != file_sha256(path):
                errors.append(f"associated file hash mismatch: {relative}")
        return not errors, errors

    def _associated_files(self, run_id: str, timeline: list[dict[str, Any]]) -> list[str]:
        candidates: set[Path] = set()
        task_graph = self.home / "artifacts" / "task_graphs" / f"{run_id}.json"
        if task_graph.is_file():
            candidates.add(task_graph)
        blackboard = self.home / "state" / "blackboard_runs" / f"{run_id}.json"
        if blackboard.is_file():
            candidates.add(blackboard)
        replay_directory = self.home / "artifacts" / "replay_snapshots" / run_id
        if replay_directory.exists():
            candidates.update(path for path in replay_directory.glob("*.json") if path.is_file())
        for item in CheckpointManager(self.home).list(run_id):
            checkpoint_id = item.get("checkpoint_id")
            if checkpoint_id:
                path = CheckpointManager(self.home).path(str(checkpoint_id))
                if path.is_file():
                    candidates.add(path)
        parse_dir = self.home / "artifacts" / "provider_parse_failures" / run_id
        if parse_dir.exists():
            candidates.update(path for path in parse_dir.rglob("*") if path.is_file())
        readonly_dir = self.home / "artifacts" / "readonly_analysis" / run_id
        if readonly_dir.exists():
            candidates.update(path for path in readonly_dir.rglob("*") if path.is_file())
        for event in timeline:
            for value in event.get("artifacts") or []:
                path = Path(str(value))
                if path.is_file():
                    candidates.add(path)
        return sorted(filter(None, (self._safe_relative(path) for path in candidates)))

    def _safe_relative(self, path: Path) -> str | None:
        try:
            relative = path.resolve().relative_to(self.home.resolve())
        except ValueError:
            return None
        lowered = relative.as_posix().lower()
        if lowered.startswith(("profiles/", "data/", "logs/")) or lowered.endswith(".env"):
            return None
        return relative.as_posix()

    @staticmethod
    def _one_or_many(values: Iterable[Any]) -> Any:
        unique = sorted({str(value) for value in values if value})
        return unique[0] if len(unique) == 1 else unique

    @staticmethod
    def _terminal_types() -> set[str]:
        return {"run_completed", "run_blocked", "run_failed", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}
