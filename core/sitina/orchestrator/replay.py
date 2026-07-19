from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay_snapshot import ReplaySnapshotManager
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import canonicalize_agent_input, ensure_dir, file_sha256, sha256_text, stable_json


ReplayStatus = Literal["replay_ok", "replay_incomplete", "replay_inconsistent", "run_not_found"]


class SideEffectDescriptor(StrictModel):
    descriptor_id: str
    run_id: str
    effect_type: str
    status: str
    summary: dict[str, Any] = Field(default_factory=dict)


class ReplayResult(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    status: ReplayStatus
    event_count: int
    task_graph_summary: dict[str, Any] = Field(default_factory=dict)
    node_states: dict[str, str] = Field(default_factory=dict)
    gates: dict[str, dict[str, Any]] = Field(default_factory=dict)
    handoff_chain: list[dict[str, Any]] = Field(default_factory=list)
    rework_edges: list[dict[str, Any]] = Field(default_factory=list)
    rework_nodes: list[dict[str, Any]] = Field(default_factory=list)
    rework_lifecycle: list[dict[str, Any]] = Field(default_factory=list)
    typed_failures: list[dict[str, Any]] = Field(default_factory=list)
    retry_state: list[dict[str, Any]] = Field(default_factory=list)
    reviewer_merges: list[dict[str, Any]] = Field(default_factory=list)
    parallel_groups: list[dict[str, Any]] = Field(default_factory=list)
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    patch_state: dict[str, Any] = Field(default_factory=dict)
    memory_outcome: dict[str, Any] = Field(default_factory=dict)
    team_selection: dict[str, Any] = Field(default_factory=dict)
    proposals: dict[str, Any] = Field(default_factory=dict)
    blackboard_summary: dict[str, Any] = Field(default_factory=dict)
    collaboration_phases: list[dict[str, Any]] = Field(default_factory=list)
    agent_snapshots: list[dict[str, Any]] = Field(default_factory=list)
    autonomy: dict[str, Any] = Field(default_factory=dict)
    leases: list[dict[str, Any]] = Field(default_factory=list)
    arbitrations: list[dict[str, Any]] = Field(default_factory=list)
    side_effects: list[SideEffectDescriptor] = Field(default_factory=list)
    missing_events: list[str] = Field(default_factory=list)
    inconsistent_events: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    snapshot_integrity: dict[str, Any] = Field(default_factory=dict)


class ReplaySimulationResult(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    status: Literal["replay_simulated", "replay_simulation_failed", "blocked"]
    mode: Literal["dry_run", "sandbox"] = "dry_run"
    sandbox_path: str | None = None
    checks: list[dict[str, Any]] = Field(default_factory=list)
    blocked_reason: str | None = None
    replay_status: ReplayStatus
    changed_real_files: bool = False


class ReplayEngine:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def simulate(self, run_id: str, *, sandbox: str | None = None, record: bool = True) -> ReplaySimulationResult:
        replay = self.replay(run_id, record=False)
        sandbox_path: Path | None = None
        mode: Literal["dry_run", "sandbox"] = "dry_run"
        checks: list[dict[str, Any]] = []
        if sandbox:
            sandbox_path = Path(sandbox).expanduser().resolve(strict=False)
            ok, reason = self._validate_sandbox(sandbox_path)
            if not ok:
                result = ReplaySimulationResult(
                    run_id=run_id,
                    status="blocked",
                    replay_status=replay.status,
                    blocked_reason=reason,
                    checks=[{"check": "sandbox_scope", "status": "blocked", "reason": reason}],
                )
                if record:
                    self._record_simulation(result)
                return result
            ensure_dir(sandbox_path)
            mode = "sandbox"
            checks.append({"check": "sandbox_scope", "status": "ok", "sandbox_path": str(sandbox_path)})
        checks.extend({"check": "replay_consistency", "status": replay.status, "missing_events": replay.missing_events, "inconsistent_events": replay.inconsistent_events} for _ in [0])
        checks.extend(self._agent_snapshot_checks(replay))
        checks.extend(self._simulation_side_effect_checks(replay, sandbox_path))
        failed = any(item.get("status") in {"failed", "blocked"} for item in checks) or replay.status == "replay_inconsistent"
        result = ReplaySimulationResult(
            run_id=run_id,
            status="replay_simulation_failed" if failed else "replay_simulated",
            mode=mode,
            sandbox_path=str(sandbox_path) if sandbox_path else None,
            checks=checks,
            replay_status=replay.status,
            changed_real_files=False,
        )
        if record:
            self._record_simulation(result)
        return result

    def _validate_sandbox(self, sandbox: Path) -> tuple[bool, str | None]:
        managed_roots = [
            (self.home / "artifacts").resolve(strict=False),
            (self.home / "temp").resolve(strict=False),
        ]
        for root in managed_roots:
            try:
                sandbox.relative_to(root)
                return True, None
            except ValueError:
                continue
        return False, "replay simulate sandbox must be inside Sitina managed artifacts/ or temp/"

    def _simulation_side_effect_checks(self, replay: ReplayResult, sandbox_path: Path | None) -> list[dict[str, Any]]:
        checks: list[dict[str, Any]] = []
        descriptor_ids = {
            item.summary.get("descriptor_id")
            for item in replay.side_effects
            if item.summary.get("descriptor_id")
        }
        for effect in replay.side_effects:
            summary = effect.summary
            effect_type = str(summary.get("effect_type") or effect.effect_type)
            if effect_type in {"file_write", "git_apply", "maintenance", "memory_accept", "memory_reject", "approval_mutation", "external_command"}:
                if effect_type in {"file_write", "git_apply", "maintenance"} and effect.status == "executed":
                    missing = []
                    if not summary.get("reviewer_decision_id") and effect_type in {"file_write", "git_apply", "maintenance"}:
                        missing.append("reviewer_decision_id")
                    if not summary.get("approval_id") and effect_type in {"file_write", "git_apply", "maintenance"}:
                        missing.append("approval_id")
                    if not summary.get("verifier_id") and effect_type in {"file_write", "git_apply"}:
                        missing.append("verifier_id")
                    checks.append({"check": "descriptor_execution_gates", "descriptor_id": effect.descriptor_id, "effect_type": effect_type, "status": "failed" if missing else "ok", "missing": missing})
                if effect_type == "git_apply":
                    checks.extend(self._check_patch_hash(summary))
            if effect.effect_type in {"git_patch_apply", "git_apply"}:
                checks.extend(self._check_patch_hash(summary))
            if effect.effect_type in {"approved_coder_complete", "evidence_verified"} and not descriptor_ids:
                checks.append({"check": "legacy_side_effect_descriptor", "status": "ok", "reason": "legacy approved coder flow recorded before descriptor requirement; verified by approval/test/review gates"})
        if sandbox_path:
            checks.append({"check": "sandbox_execution", "status": "ok", "reason": "simulation did not execute real provider/MCP/file/git side effects"})
        else:
            checks.append({"check": "dry_run_execution", "status": "ok", "reason": "dry-run only; no side effects replayed"})
        return checks

    def _agent_snapshot_checks(self, replay: ReplayResult) -> list[dict[str, Any]]:
        if not replay.agent_snapshots:
            if any(item.get("event_type") == "run_backlog_link_blocked" for item in replay.autonomy.get("run_links", [])):
                return [{"check": "agent_snapshot_consistency", "status": "ok", "reason": "expected early-block backlog gate run has no agent snapshots"}]
            return [{"check": "agent_snapshot_consistency", "status": "blocked", "reason": "no agent input/output snapshots found"}]
        missing = [
            item
            for item in replay.agent_snapshots
            if item.get("status") == "completed" and (not item.get("started") or not item.get("input_hash") or not item.get("output_hash"))
        ]
        mismatched = [
            item
            for item in replay.agent_snapshots
            if item.get("input_payload") and item.get("input_snapshot_hash_verified") is False
        ]
        return [
            {
                "check": "agent_snapshot_consistency",
                "status": "failed" if missing or mismatched else "ok",
                "agent_call_count": len(replay.agent_snapshots),
                "missing": missing[:5],
                "mismatched": [{"task_id": item.get("task_id"), "agent_id": item.get("agent_id")} for item in mismatched[:5]],
            }
        ]

    def _check_patch_hash(self, summary: dict[str, Any]) -> list[dict[str, Any]]:
        patch_path = summary.get("patch_path")
        expected = summary.get("patch_hash")
        if not patch_path or not expected:
            return []
        path = Path(str(patch_path))
        actual = file_sha256(path) if path.exists() and path.is_file() else None
        return [
            {
                "check": "patch_hash",
                "patch_path": str(path),
                "expected": expected,
                "actual": actual,
                "status": "ok" if actual == expected else "failed",
            }
        ]

    def _record_simulation(self, result: ReplaySimulationResult) -> None:
        event_type = "replay_simulation_blocked" if result.status == "blocked" else "replay_simulation_completed"
        RunLedger(self.home, self.store).record(
            event_type,
            run_id=result.run_id,
            status="blocked" if result.status == "blocked" else ("failed" if result.status == "replay_simulation_failed" else "ok"),
            reason=result.blocked_reason or result.status,
            payload=result.model_dump(),
        )

    def replay(self, run_id: str, *, record: bool = True) -> ReplayResult:
        timeline = RunLedger(self.home, self.store).timeline(run_id)
        if not timeline:
            return ReplayResult(
                run_id=run_id,
                status="run_not_found",
                event_count=0,
                missing_events=["run_ledger"],
                limitations=self._limitations(),
            )
        timeline = sorted(timeline, key=lambda item: (item.get("_event_row_id", 0), item.get("timestamp", "")))
        snapshot_manager = ReplaySnapshotManager(self.home)
        snapshot_integrity = snapshot_manager.verify(run_id, timeline)
        missing = self._missing_required_events(timeline)
        inconsistent: list[str] = []
        if snapshot_integrity.get("status") == "failed":
            inconsistent.extend(str(error) for error in snapshot_integrity.get("errors") or [])
        node_states: dict[str, str] = {}
        terminal_nodes: set[str] = set()
        gates: dict[str, dict[str, Any]] = {}
        handoffs: list[dict[str, Any]] = []
        rework_edges: list[dict[str, Any]] = []
        rework_nodes: list[dict[str, Any]] = []
        rework_lifecycle: list[dict[str, Any]] = []
        typed_failures: list[dict[str, Any]] = []
        retry_state: list[dict[str, Any]] = []
        reviewer_merges: list[dict[str, Any]] = []
        parallel_groups: list[dict[str, Any]] = []
        approvals: list[dict[str, Any]] = []
        patch_state: dict[str, Any] = {}
        memory_outcome: dict[str, Any] = {}
        team_selection: dict[str, Any] = {}
        proposals: dict[str, Any] = {"rounds": [], "submitted": [], "evaluations": [], "selected": [], "rejected": [], "blocked": []}
        blackboard_docs: list[dict[str, Any]] = []
        collaboration_phases: list[dict[str, Any]] = []
        agent_snapshots: list[dict[str, Any]] = []
        open_agent_calls: dict[tuple[str, str], list[dict[str, Any]]] = {}
        autonomy: dict[str, Any] = {"goals": [], "backlog": [], "run_links": []}
        leases: list[dict[str, Any]] = []
        arbitrations: list[dict[str, Any]] = []
        side_effects: list[SideEffectDescriptor] = []
        graph_summary: dict[str, Any] = {}
        last_patch_hash: str | None = None
        terminal_run_completed = False
        selected_proposal_ids: set[str] = set()

        for event in timeline:
            event_type = event.get("event_type")
            task_id = str(event.get("task_id") or "main")
            payload = self._safe_payload(event.get("payload_json") or {})
            if event_type == "task_graph_created":
                graph_summary = self._graph_summary(payload)
                for node in payload.get("nodes", []):
                    if isinstance(node, dict):
                        node_states[str(node.get("task_id"))] = str(node.get("status", "pending"))
            elif event_type == "task_graph_node_status":
                node_status = str(payload.get("status", event.get("status", "unknown")))
                if task_id in terminal_nodes and node_status == "running":
                    inconsistent.append(f"node {task_id} returned to running after terminal status")
                if node_status in {"completed", "blocked", "failed", "skipped"}:
                    terminal_nodes.add(task_id)
                node_states[task_id] = node_status
                if payload.get("node_type") in {"coder", "worktree_prepare", "patch_hash_verify", "patch_apply"} or payload.get("patch_hash"):
                    patch_state[task_id] = self._patch_descriptor(payload)
                    if payload.get("patch_hash"):
                        if task_id == "patch_hash_verify" and last_patch_hash and payload.get("patch_hash") != last_patch_hash:
                            inconsistent.append("patch_hash_verify does not match latest patch hash")
                        if task_id in {"coder", "parallel_reviewer_group", "multi_reviewer_merge", "approval"}:
                            last_patch_hash = payload.get("patch_hash")
                if payload.get("node_type") == "side_effect" and node_status == "completed" and not payload.get("side_effect_descriptor_ids"):
                    inconsistent.append(f"side-effect node {task_id} completed without descriptor")
            elif event_type in {"gate_required", "gate_passed", "gate_blocked"}:
                gates[task_id] = {"event_type": event_type, "status": event.get("status"), "reason": event.get("reason"), "payload": payload}
            elif event_type == "agent_handoff":
                handoffs.append(self._handoff_descriptor(payload))
            elif event_type in {"handoff_accepted", "handoff_rejected"}:
                handoffs.append(self._handoff_descriptor(payload) | {"event_type": event_type, "reviewer": event.get("agent_id"), "reason": event.get("reason")})
            elif event_type == "agent_team_candidate_selected":
                team_selection = payload
            elif event_type == "rework_edge_created":
                rework_edges.append(payload)
            elif event_type == "rework_node_created":
                rework_nodes.append(payload)
                if payload.get("task_id"):
                    node_states[str(payload.get("task_id"))] = str(payload.get("status", "pending"))
            elif event_type in {"rework_requested", "rework_dispatched", "rework_started", "rework_completed", "rework_failed", "rework_retry_exhausted"}:
                rework_lifecycle.append({"event_type": event_type, **payload})
            elif event_type == "typed_failure_recorded":
                typed_failures.append(payload)
            elif event_type in {"retry_scheduled", "retry_exhausted"}:
                retry_state.append({"event_type": event_type, "task_id": task_id, **payload})
            elif event_type == "reviewer_decision":
                reviewer_merges.append(payload)
            elif event_type in {"parallel_group_started", "parallel_group_completed"}:
                parallel_groups.append({"event_type": event_type, **payload})
            elif event_type == "memory_checked":
                memory_outcome = {"event_type": event_type, "status": event.get("status"), "reason": event.get("reason"), **payload}
            elif isinstance(event_type, str) and event_type.startswith("proposal_"):
                self._collect_proposal_event(proposals, event_type, payload)
                if event_type == "proposal_selected" and payload.get("selected_proposal_id"):
                    selected_proposal_ids.add(str(payload.get("selected_proposal_id")))
            elif event_type == "task_graph_patch_applied":
                graph_summary["proposal_round_id"] = payload.get("proposal_round_id")
                graph_summary["selected_proposal_id"] = payload.get("selected_proposal_id")
                if payload.get("selected_proposal_id") and payload.get("selected_proposal_id") not in selected_proposal_ids:
                    inconsistent.append("task graph patch applied from unselected proposal")
            elif event_type == "blackboard_document_recorded":
                blackboard_docs.append(payload)
            elif event_type in {"blackboard_doc_created", "blackboard_doc_updated"}:
                blackboard_docs.append(payload)
            elif event_type == "collaboration_phase":
                collaboration_phases.append(payload)
            elif event_type == "agent_started":
                agent_id = str(event.get("agent_id") or payload.get("agent") or "unknown")
                key = (task_id, agent_id)
                open_agent_calls.setdefault(key, []).append(
                    {
                        "task_id": task_id,
                        "agent_id": agent_id,
                        "input_hash": payload.get("input_hash"),
                        "raw_input_hash": payload.get("raw_input_hash"),
                        "safe_input_hash": payload.get("safe_input_hash"),
                        "provider_mode": payload.get("provider_mode"),
                        "profile_name": payload.get("profile_name"),
                        "model": payload.get("model"),
                        "provider_identity": payload.get("provider_identity"),
                        "provider_calls": payload.get("provider_calls") or [],
                        "fallback_used": payload.get("fallback_used"),
                        "call_id": payload.get("call_id"),
                        "input_payload": payload.get("input_payload"),
                        "input_hash_semantics": payload.get("input_hash_semantics"),
                    }
                )
            elif event_type in {"agent_completed", "agent_blocked"}:
                agent_id = str(event.get("agent_id") or payload.get("agent") or "unknown")
                key = (task_id, agent_id)
                started = open_agent_calls.get(key, [])
                start = started.pop(0) if started else {}
                snapshot = {
                    "task_id": task_id,
                    "agent_id": agent_id,
                    "status": "completed" if event_type == "agent_completed" else "blocked",
                    "input_hash": payload.get("input_hash") or start.get("input_hash"),
                    "raw_input_hash": payload.get("raw_input_hash") or start.get("raw_input_hash"),
                    "safe_input_hash": payload.get("safe_input_hash") or start.get("safe_input_hash"),
                    "output_hash": payload.get("output_hash"),
                    "provider_mode": payload.get("provider_mode") or start.get("provider_mode"),
                    "profile_name": payload.get("profile_name") or start.get("profile_name"),
                    "model": payload.get("model") or start.get("model"),
                    "provider_identity": payload.get("provider_identity") or start.get("provider_identity"),
                    "provider_calls": payload.get("provider_calls") or start.get("provider_calls") or [],
                    "fallback_used": payload.get("fallback_used") if payload.get("fallback_used") is not None else start.get("fallback_used"),
                    "call_id": payload.get("call_id") or start.get("call_id"),
                    "started": bool(start),
                    "input_payload": start.get("input_payload"),
                    "input_hash_semantics": start.get("input_hash_semantics") or "sha256(stable_json(redacted_input_payload))",
                }
                expected_input_hash = snapshot.get("safe_input_hash") or snapshot.get("input_hash")
                if snapshot.get("input_payload") and expected_input_hash:
                    actual_input_hash = sha256_text(stable_json(snapshot["input_payload"]))
                    if actual_input_hash != expected_input_hash:
                        inconsistent.append(f"agent {agent_id} input snapshot hash mismatch")
                    snapshot["input_snapshot_hash_verified"] = actual_input_hash == expected_input_hash
                if event_type == "agent_completed" and not snapshot["output_hash"]:
                    inconsistent.append(f"agent {agent_id} completed without output_hash")
                if not snapshot["started"]:
                    inconsistent.append(f"agent {agent_id} completed without matching start event")
                agent_snapshots.append(snapshot)
            elif event_type in {"long_term_goal_created", "long_term_goal_updated", "project_plan_updated"}:
                autonomy.setdefault("goals", []).append({"event_type": event_type, **payload})
            elif event_type in {"backlog_candidate_created", "backlog_item_updated"}:
                autonomy.setdefault("backlog", []).append({"event_type": event_type, **payload})
            elif event_type == "run_backlog_linked":
                autonomy.setdefault("run_links", []).append(payload)
            elif event_type == "run_backlog_link_blocked":
                autonomy.setdefault("run_links", []).append({"event_type": event_type, **payload})
            elif event_type in {"lease_requested", "lease_granted", "lease_denied", "lease_released", "lease_conflict_detected", "lease_holder_blocked"}:
                leases.append({"event_type": event_type, **payload})
            elif event_type in {"arbitration_node_created", "arbitration_decision"}:
                arbitrations.append({"event_type": event_type, **payload})
                if event_type == "arbitration_node_created" and payload.get("node_type") == "arbitration" and payload.get("task_id"):
                    node_states[str(payload.get("task_id"))] = str(payload.get("status", event.get("status", "blocked")))
            elif event_type in {"side_effect_descriptor_created", "side_effect_reviewed", "side_effect_verified", "side_effect_approved", "side_effect_executed", "side_effect_blocked"}:
                side_effects.append(self._side_effect(run_id, event_type, str(event.get("status") or payload.get("status", "unknown")), payload))
            elif event_type in {"tool_invocation", "tool_blocked"}:
                side_effects.append(self._side_effect(run_id, "mcp_tool_invocation", str(event.get("status")), payload))
            elif event_type == "run_completed":
                patch_state.setdefault("run_completed", payload)
                terminal_run_completed = True
            elif event_type in {"run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}:
                patch_state.setdefault(str(event_type), payload)

        for event in self._safe_event_rows(run_id):
            event_type = event["event_type"]
            payload = event["payload"]
            if event_type in {"memory_no_candidate", "memory_candidates_created", "memory_candidates_duplicate", "memory_agent_warning"}:
                memory_outcome = {"event_type": event_type, **self._safe_payload(payload)}
            elif event_type in {"approved_coder_complete", "evidence_verified"}:
                side_effects.append(self._side_effect(run_id, event_type, str(payload.get("status", "ok")), self._safe_payload(payload)))

        for audit in self._safe_audit_rows(run_id):
            op = audit["operation"]
            payload = audit["payload"]
            if op.startswith("git_patch") or op == "git_worktree_prepare":
                summary = self._safe_payload(payload)
                if op == "git_patch_approval":
                    approvals.append(summary)
                if op == "git_patch_apply":
                    patch_state.setdefault("git_patch_apply", summary)
                side_effects.append(self._side_effect(run_id, op, str(audit.get("exit_status") or summary.get("status", "unknown")), summary))
            elif op.startswith("mcp_"):
                side_effects.append(self._side_effect(run_id, op, str(audit.get("exit_status") or "unknown"), self._safe_payload(payload)))

        early_backlog_blocked = any(item.get("event_type") == "run_backlog_link_blocked" for item in autonomy.get("run_links", []))
        if not memory_outcome and not early_backlog_blocked:
            missing.append("memory_outcome")
        inconsistent.extend(self._snapshot_inconsistencies(run_id, node_states, terminal_run_completed))
        status: ReplayStatus = "replay_ok"
        if inconsistent:
            status = "replay_inconsistent"
        elif missing:
            status = "replay_incomplete"
        result = ReplayResult(
            run_id=run_id,
            status=status,
            event_count=len(timeline),
            task_graph_summary=graph_summary,
            node_states=node_states,
            gates=gates,
            handoff_chain=handoffs,
            rework_edges=rework_edges,
            rework_nodes=rework_nodes,
            rework_lifecycle=rework_lifecycle,
            typed_failures=typed_failures,
            retry_state=retry_state,
            reviewer_merges=reviewer_merges,
            parallel_groups=parallel_groups,
            approvals=approvals,
            patch_state=patch_state,
            memory_outcome=memory_outcome,
            team_selection=team_selection,
            proposals=proposals,
            blackboard_summary={"documents": blackboard_docs, "count": len(blackboard_docs)},
            collaboration_phases=collaboration_phases,
            agent_snapshots=agent_snapshots,
            autonomy=autonomy,
            leases=leases,
            arbitrations=arbitrations,
            side_effects=side_effects,
            missing_events=sorted(set(missing)),
            inconsistent_events=inconsistent,
            limitations=self._limitations(),
            snapshot_integrity=snapshot_integrity,
        )
        if record:
            if result.status != "replay_inconsistent":
                result.snapshot_integrity = snapshot_manager.append(run_id, timeline, result.model_dump())
                if result.snapshot_integrity.get("status") == "failed":
                    result.status = "replay_inconsistent"
                    result.inconsistent_events.extend(str(error) for error in result.snapshot_integrity.get("errors") or [])
            RunLedger(self.home, self.store).record(
                "replay_snapshot_built",
                run_id=run_id,
                task_type=graph_summary.get("task_type", "chat"),
                status="ok" if result.status == "replay_ok" else "warning",
                reason=result.status,
                payload={
                    "status": result.status,
                    "node_count": len(result.node_states),
                    "blackboard_count": result.blackboard_summary.get("count", 0),
                    "snapshot_integrity": result.snapshot_integrity,
                },
            )
            if result.status == "replay_inconsistent":
                RunLedger(self.home, self.store).record(
                    "replay_inconsistent",
                    run_id=run_id,
                    task_type=graph_summary.get("task_type", "chat"),
                    status="failed",
                    reason="; ".join(result.inconsistent_events[:3]) or "replay inconsistent",
                    payload={"inconsistent_events": result.inconsistent_events},
                )
            RunLedger(self.home, self.store).record(
                "replay_completed",
                run_id=run_id,
                task_type=graph_summary.get("task_type", "chat"),
                status="ok" if result.status == "replay_ok" else ("failed" if result.status == "replay_inconsistent" else "warning"),
                reason=result.status,
                payload={"status": result.status, "missing_events": result.missing_events, "inconsistent_events": result.inconsistent_events},
            )
        return result

    def _missing_required_events(self, timeline: list[dict[str, Any]]) -> list[str]:
        event_types = {event.get("event_type") for event in timeline}
        if "run_backlog_link_blocked" in event_types:
            missing = [event_type for event_type in ("run_started", "run_backlog_link_blocked") if event_type not in event_types]
            if not event_types.intersection({"run_blocked", "run_failed"}):
                missing.append("terminal_run_event")
            return missing
        early_terminal_events = {"run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}
        if event_types.intersection(early_terminal_events):
            return ["run_started"] if "run_started" not in event_types else []
        required = ["run_started", "task_graph_created"]
        if "worker_chain_precondition" not in event_types:
            required.append("controller_decision")
        missing = [event_type for event_type in required if event_type not in event_types]
        terminal_events = {"run_completed", "run_failed", "run_blocked", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}
        if not event_types.intersection(terminal_events):
            missing.append("terminal_run_event")
        return missing

    def _graph_summary(self, payload: dict[str, Any]) -> dict[str, Any]:
        nodes = payload.get("nodes", [])
        return {
            "run_id": payload.get("run_id"),
            "task_type": payload.get("task_type"),
            "node_count": len(nodes) if isinstance(nodes, list) else 0,
            "mandatory_nodes": [node.get("task_id") for node in nodes if isinstance(node, dict) and node.get("mandatory", True)],
            "dependencies": {node.get("task_id"): node.get("depends_on", []) for node in nodes if isinstance(node, dict)},
        }

    def _handoff_descriptor(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "handoff_id": payload.get("handoff_id"),
            "from_agent": payload.get("from_agent"),
            "to_agent": payload.get("to_agent"),
            "task_id": payload.get("task_id"),
            "task_type": payload.get("task_type"),
            "status": payload.get("status"),
            "input_refs": payload.get("input_refs", payload.get("required_inputs", [])),
            "artifact_hashes": payload.get("artifact_hashes", {}),
            "required_gates": payload.get("required_gates", payload.get("gate_requirements", [])),
            "gate_requirements": payload.get("gate_requirements", []),
            "provided_artifacts": payload.get("provided_artifacts", []),
            "scope_lease_ids": payload.get("scope_lease_ids", []),
            "side_effect_descriptor_ids": payload.get("side_effect_descriptor_ids", []),
        }

    def _patch_descriptor(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": payload.get("status"),
            "patch_id": payload.get("patch_id"),
            "patch_hash": payload.get("patch_hash"),
            "target_repo": payload.get("target_repo"),
            "artifact_refs": payload.get("artifact_refs", []),
        }

    def _collect_proposal_event(self, proposals: dict[str, list[dict[str, Any]]], event_type: str, payload: dict[str, Any]) -> None:
        mapping = {
            "proposal_round_opened": "rounds",
            "proposal_round_started": "rounds",
            "proposal_round_closed": "rounds",
            "proposal_submitted": "submitted",
            "proposal_evaluated": "evaluations",
            "proposal_selected": "selected",
            "proposal_rejected": "rejected",
            "proposal_blocked": "blocked",
        }
        bucket = mapping.get(event_type, "other")
        if event_type == "proposal_round_closed":
            rounds = proposals.setdefault("rounds", [])
            round_id = payload.get("proposal_round_id")
            replaced = False
            for idx, existing in enumerate(rounds):
                if existing.get("proposal_round_id") == round_id:
                    rounds[idx] = payload
                    replaced = True
                    break
            if not replaced:
                rounds.append(payload)
            return
        proposals.setdefault(bucket, []).append(payload)

    def _side_effect(self, run_id: str, effect_type: str, status: str, payload: dict[str, Any]) -> SideEffectDescriptor:
        summary = {
            key: value
            for key, value in payload.items()
            if key
            in {
                "server",
                "tool",
                "tool_type",
                "status",
                "reason",
                "artifact_hash",
                "artifact_path",
                "target",
                "target_repo",
                "repo",
                "patch_id",
                "patch_hash",
                "patch_path",
                "reviewer_decision",
                "approval_id",
                "approval_artifact",
                "review_artifact",
                "merge_artifact",
                "changed_files",
                "before_hashes",
                "after_hashes",
                "descriptor_id",
                "effect_type",
                "target_refs",
                "scope_hash",
                "required_gates",
                "reviewer_decision_id",
                "verifier_id",
                "lease_id",
            }
        }
        descriptor_id = str(summary.get("descriptor_id") or ("se_" + sha256_text(stable_json({"effect_type": effect_type, "payload": summary})).split(":", 1)[1][:16]))
        return SideEffectDescriptor(descriptor_id=descriptor_id, run_id=run_id, effect_type=effect_type, status=status, summary=summary)

    def _snapshot_inconsistencies(self, run_id: str, node_states: dict[str, str], terminal_run_event: bool) -> list[str]:
        from sitina.orchestrator.task_graph import TaskGraphRuntime

        graph = TaskGraphRuntime(self.home, self.store).load(run_id)
        if not graph:
            return []
        out: list[str] = []
        snapshot_nodes = {node.task_id: node.status for node in graph.nodes}
        if set(snapshot_nodes) != set(node_states):
            out.append("snapshot_mismatch: task graph node set differs from ledger replay")
        for task_id, snapshot_status in snapshot_nodes.items():
            replay_status = node_states.get(task_id)
            if replay_status and replay_status != snapshot_status:
                out.append(f"snapshot_mismatch: node {task_id} ledger={replay_status} snapshot={snapshot_status}")
        if terminal_run_event:
            missing = [node.task_id for node in graph.nodes if node.mandatory and node.status != "completed"]
            if missing and any(event_status == "completed" for event_status in node_states.values()):
                out.append("mandatory node(s) incomplete at terminal event: " + ", ".join(missing))
        return out

    def _safe_payload(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        return canonicalize_agent_input(payload)

    def _safe_event_rows(self, run_id: str) -> list[dict[str, Any]]:
        self.store.init_db()
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, payload_json
                FROM events
                WHERE run_id = ? AND event_type != 'run_ledger'
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for event_type, payload_json in rows:
            try:
                out.append({"event_type": event_type, "payload": self._safe_payload(json.loads(payload_json))})
            except json.JSONDecodeError:
                continue
        return out

    def _safe_audit_rows(self, run_id: str) -> list[dict[str, Any]]:
        self.store.init_db()
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT operation, exit_status, payload_json
                FROM audit_log
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for operation, exit_status, payload_json in rows:
            try:
                payload = self._safe_payload(json.loads(payload_json))
            except json.JSONDecodeError:
                payload = {}
            out.append({"operation": operation, "exit_status": exit_status, "payload": payload})
        return out

    def _limitations(self) -> list[str]:
        return [
            "Replay reconstructs state from ledger/events/audit and artifacts metadata only.",
            "Replay never re-executes provider calls, MCP tools, file writes, memory acceptance, or git apply.",
            "Replay side-effect descriptors intentionally omit sensitive raw content.",
        ]
