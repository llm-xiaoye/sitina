"""Integrity-checked checkpoints for interruption, cancellation, and resume."""

from __future__ import annotations

import fcntl
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay_snapshot import ReplaySnapshotManager
from sitina.utils import compute_agent_input_hash, ensure_dir, iso_now, new_id, read_json, sha256_text, stable_json, write_json


class CheckpointManager:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.directory = home / "artifacts" / "checkpoints"
        self.index_path = self.directory / "index.json"

    def create(
        self,
        *,
        run_id: str,
        stage: str,
        completed_agent_calls: list[dict[str, Any]] | None = None,
        pending_agent_calls: list[dict[str, Any] | str] | None = None,
        proposal_ids: list[str] | None = None,
        evaluation_ids: list[str] | None = None,
        selected_proposal_id: str | None = None,
        resumable: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ensure_dir(self.directory)
        checkpoint_id = "checkpoint_" + new_id()
        task_graph_path = self.home / "artifacts" / "task_graphs" / f"{run_id}.json"
        task_graph_hash = sha256_text(task_graph_path.read_text(encoding="utf-8")) if task_graph_path.exists() else None
        payload = {
            "checkpoint_id": checkpoint_id,
            "run_id": run_id,
            "stage": stage,
            "completed_agent_calls": completed_agent_calls or [],
            "pending_agent_calls": pending_agent_calls or [],
            "proposal_ids": proposal_ids or [],
            "evaluation_ids": evaluation_ids or [],
            "selected_proposal_id": selected_proposal_id,
            "blackboard_version": self._blackboard_version(run_id),
            "task_graph_hash": task_graph_hash,
            "replay_snapshot_hashes": self._snapshot_hashes(run_id),
            "provider_call_identities": self._provider_calls(completed_agent_calls or []),
            "created_at": iso_now(),
            "resumable": resumable,
            "extra": extra or {},
        }
        checkpoint_hash = sha256_text(stable_json(payload))
        document = payload | {"checkpoint_hash": checkpoint_hash}
        write_json(self.path(checkpoint_id), document)
        with self._index_lock():
            index = read_json(self.index_path, default={}) or {}
            index.setdefault("checkpoints", []).append({"checkpoint_id": checkpoint_id, "run_id": run_id, "stage": stage, "created_at": document["created_at"], "resumable": resumable})
            write_json(self.index_path, index)
        RunLedger(self.home).record(
            "checkpoint_created",
            run_id=run_id,
            status="ok",
            reason=f"checkpoint saved after {stage}",
            artifacts=[str(self.path(checkpoint_id))],
            payload={"checkpoint_id": checkpoint_id, "stage": stage, "checkpoint_hash": checkpoint_hash, "resumable": resumable},
        )
        return document

    def path(self, checkpoint_id: str) -> Path:
        return self.directory / f"{checkpoint_id}.json"

    def list(self, run_id: str) -> list[dict[str, Any]]:
        index = read_json(self.index_path, default={}) or {}
        return [item for item in index.get("checkpoints", []) if item.get("run_id") == run_id]

    def show(self, checkpoint_id: str) -> dict[str, Any] | None:
        document = read_json(self.path(checkpoint_id), default=None)
        return document if isinstance(document, dict) else None

    def latest(self, run_id: str) -> dict[str, Any] | None:
        items = self.list(run_id)
        return self.show(str(items[-1]["checkpoint_id"])) if items else None

    def latest_resumable(self, run_id: str) -> dict[str, Any] | None:
        for item in reversed(self.list(run_id)):
            checkpoint = self.show(str(item["checkpoint_id"]))
            if checkpoint and checkpoint.get("resumable") and checkpoint.get("pending_agent_calls"):
                return checkpoint
        return None

    def verify(self, checkpoint: dict[str, Any]) -> tuple[bool, str]:
        claimed_hash = checkpoint.get("checkpoint_hash")
        body = {key: value for key, value in checkpoint.items() if key != "checkpoint_hash"}
        if not isinstance(claimed_hash, str) or claimed_hash != sha256_text(stable_json(body)):
            return False, "checkpoint hash mismatch"
        return True, "checkpoint integrity verified"

    def verify_for_resume(self, checkpoint: dict[str, Any], run_id: str) -> tuple[bool, str]:
        valid, reason = self.verify(checkpoint)
        if not valid:
            return valid, reason
        if checkpoint.get("run_id") != run_id:
            return False, "checkpoint run_id mismatch"
        if not checkpoint.get("resumable"):
            return False, "checkpoint is not resumable"

        task_graph_path = self.home / "artifacts" / "task_graphs" / f"{run_id}.json"
        expected_graph_hash = checkpoint.get("task_graph_hash")
        if not expected_graph_hash or not task_graph_path.exists():
            return False, "resumable checkpoint is missing its task graph"
        current_graph_hash = sha256_text(task_graph_path.read_text(encoding="utf-8"))
        if current_graph_hash != expected_graph_hash:
            return False, "checkpoint task graph hash mismatch"

        current_snapshot_hashes = set(self._snapshot_hashes(run_id))
        checkpoint_snapshot_hashes = checkpoint.get("replay_snapshot_hashes")
        if not isinstance(checkpoint_snapshot_hashes, list) or not set(checkpoint_snapshot_hashes).issubset(current_snapshot_hashes):
            return False, "checkpoint replay snapshot hash mismatch"

        pending = checkpoint.get("pending_agent_calls")
        if not isinstance(pending, list) or not pending:
            return False, "checkpoint has no pending agent calls"
        pending_call_ids: set[str] = set()
        for call in pending:
            if not isinstance(call, dict):
                return False, "legacy pending agent call cannot be resumed"
            call_id = call.get("call_id")
            agent_id = call.get("agent_id")
            input_payload = call.get("input_payload")
            if not isinstance(call_id, str) or not call_id or not isinstance(agent_id, str) or not agent_id:
                return False, "pending agent call is missing call_id or agent_id"
            if call_id in pending_call_ids:
                return False, "checkpoint contains duplicate pending call_id"
            pending_call_ids.add(call_id)
            if not isinstance(input_payload, dict) or call.get("input_hash") != compute_agent_input_hash(input_payload):
                return False, f"pending agent call input hash mismatch: {call_id}"
            if call.get("provider_mode") not in {"mock", "live"}:
                return False, f"pending agent call provider mode is invalid: {call_id}"

        completed = checkpoint.get("completed_agent_calls")
        if not isinstance(completed, list):
            return False, "checkpoint completed agent calls are invalid"
        completed_call_ids = {
            str(call.get("call_id"))
            for call in completed
            if isinstance(call, dict) and call.get("call_id")
        }
        if pending_call_ids & completed_call_ids:
            return False, "checkpoint call_id is both completed and pending"

        provider_call_ids = self._provider_calls(completed)
        if len(provider_call_ids) != len(set(provider_call_ids)):
            return False, "checkpoint contains duplicate provider request identities"
        if checkpoint.get("provider_call_identities") != provider_call_ids:
            return False, "checkpoint provider call identities mismatch"
        return True, "checkpoint resume context verified"

    def _blackboard_version(self, run_id: str) -> int:
        from sitina.orchestrator.blackboard import Blackboard

        partition_version = Blackboard(self.home).partition_version(run_id)
        if partition_version:
            return partition_version
        path = self.home / "state" / "blackboard.json"
        doc = read_json(path, default={}) or {}
        documents = doc.get("documents", []) if isinstance(doc, dict) else []
        return sum(1 for item in documents if isinstance(item, dict) and item.get("run_id") == run_id)

    def _snapshot_hashes(self, run_id: str) -> list[str]:
        timeline = RunLedger(self.home).timeline(run_id)
        replay_hashes = ReplaySnapshotManager(self.home).hashes(run_id)
        agent_hashes = [str((event.get("payload_json") or {}).get("output_hash")) for event in timeline if event.get("event_type") == "agent_completed" and (event.get("payload_json") or {}).get("output_hash")]
        return replay_hashes + agent_hashes

    def _provider_calls(self, calls: list[dict[str, Any]]) -> list[str]:
        identities: list[str] = []
        for call in calls:
            if not isinstance(call, dict):
                continue
            nested = call.get("provider_calls")
            provider_calls = nested if isinstance(nested, list) else [call]
            for provider_call in provider_calls:
                if isinstance(provider_call, dict) and provider_call.get("provider_request_id"):
                    identities.append(str(provider_call["provider_request_id"]))
        return identities

    @contextmanager
    def _index_lock(self):
        lock_path = self.directory / ".index.lock"
        ensure_dir(lock_path.parent)
        with lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
