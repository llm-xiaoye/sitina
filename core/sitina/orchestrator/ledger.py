from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import iso_now, new_id, redact_text, sha256_text, stable_json


LEDGER_EVENT_TYPES = {
    "collaboration_phase",
    "readonly_analysis_inventory_created",
    "dispatch_decision",
    "dispatcher_decision_created",
    "dispatcher_agent_selected",
    "dispatcher_no_eligible_agent",
    "proposal_revision_created",
    "proposal_revision_evaluated",
    "debate_round_opened",
    "debate_response",
    "debate_round_closed",
    "long_term_goal_created",
    "long_term_goal_updated",
    "long_term_goal_agent_suggested",
    "project_plan_updated",
    "backlog_candidate_created",
    "backlog_item_updated",
    "run_backlog_linked",
    "run_backlog_link_blocked",
    "replay_simulation_completed",
    "replay_simulation_blocked",
    "agent_capability_registered",
    "agent_team_candidate_selected",
    "run_started",
    "task_graph_created",
    "worker_chain_precondition",
    "task_graph_edge_added",
    "task_graph_edge_superseded",
    "task_graph_patch_applied",
    "task_graph_node_status",
    "rework_edge_created",
    "rework_node_created",
    "rework_requested",
    "rework_dispatched",
    "rework_started",
    "rework_completed",
    "rework_failed",
    "rework_retry_exhausted",
    "typed_failure_recorded",
    "side_effect_recorded",
    "side_effect_descriptor_created",
    "side_effect_reviewed",
    "side_effect_verified",
    "side_effect_approved",
    "side_effect_executed",
    "side_effect_blocked",
    "proposal_round_opened",
    "proposal_round_started",
    "proposal_submitted",
    "proposal_evaluated",
    "proposal_evaluation_evidence_insufficient",
    "proposal_selected",
    "proposal_rejected",
    "proposal_blocked",
    "proposal_round_closed",
    "blackboard_doc_created",
    "blackboard_doc_updated",
    "blackboard_version_conflict",
    "blackboard_document_recorded",
    "lease_requested",
    "lease_granted",
    "lease_denied",
    "lease_released",
    "lease_conflict_detected",
    "lease_holder_blocked",
    "arbitration_node_created",
    "arbitration_decision",
    "replay_snapshot_built",
    "replay_inconsistent",
    "replay_completed",
    "controller_decision",
    "policy_execution_plan",
    "agent_handoff",
    "handoff_receiver_decision",
    "handoff_accepted",
    "handoff_rejected",
    "agent_started",
    "agent_completed",
    "agent_call_started",
    "agent_call_terminal",
    "agent_skipped",
    "agent_blocked",
    "tool_invocation",
    "tool_blocked",
    "gate_required",
    "gate_passed",
    "gate_blocked",
    "retry_scheduled",
    "retry_exhausted",
    "reviewer_decision",
    "parallel_group_started",
    "parallel_group_completed",
    "summary_created",
    "memory_checked",
    "run_completed",
    "run_failed",
    "run_blocked",
    "run_timeout",
    "run_cancelled",
    "run_interrupted",
    "run_paused",
    "provider_connect_timeout",
    "provider_read_timeout",
    "run_deadline_exceeded",
    "provider_auth_failed",
    "provider_permission_denied",
    "provider_rate_limited",
    "provider_retry_scheduled",
    "provider_retry_denied",
    "provider_http_attempt_started",
    "provider_http_attempt_completed",
    "provider_http_attempt_failed",
    "provider_parse_failed",
    "agent_schema_invalid",
    "provider_profile_missing",
    "provider_failed",
    "checkpoint_created",
    "checkpoint_failed",
    "checkpoint_resumed",
}


class LedgerEvent(StrictModel):
    schema_version: str = "1.0"
    event_id: str
    run_id: str
    task_id: str
    task_type: str
    agent_id: str | None = None
    actor: str = "system"
    event_type: str
    timestamp: str
    redaction_status: Literal["none", "redacted", "blocked"] = "none"
    status: Literal["ok", "blocked", "failed", "skipped", "warning", "pending"]
    reason: str
    artifacts: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    payload_json: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_ledger_event(self) -> "LedgerEvent":
        if str(self.schema_version).split(".", 1)[0] != "1":
            raise ValueError("ledger schema_version major must be 1")
        if self.event_type not in LEDGER_EVENT_TYPES:
            raise ValueError(f"unknown ledger event_type: {self.event_type}")
        if self.status in {"blocked", "failed"} and not self.reason:
            raise ValueError("blocked/failed ledger event requires reason")
        return self


class RunLedger:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def record(
        self,
        event_type: str,
        *,
        run_id: str,
        task_id: str = "main",
        task_type: str = "chat",
        agent_id: str | None = None,
        status: Literal["ok", "blocked", "failed", "skipped", "warning", "pending"] = "ok",
        reason: str = "recorded",
        artifacts: list[str] | None = None,
        related_event_ids: list[str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> LedgerEvent:
        raw_payload = payload or {}
        clean_payload = self._redacted_payload(raw_payload)
        redaction_status: Literal["none", "redacted", "blocked"] = "redacted" if stable_json(clean_payload) != stable_json(raw_payload) else "none"
        event = LedgerEvent(
            event_id="ledger_" + new_id(),
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent_id,
            actor=agent_id or "system",
            event_type=event_type,
            timestamp=iso_now(),
            redaction_status=redaction_status,
            status=status,
            reason=reason,
            artifacts=artifacts or [],
            related_event_ids=related_event_ids or [],
            payload_json=clean_payload,
        )
        row = event.model_dump()
        self.store.record_event("run_ledger", row, run_id=run_id, trace_id=f"{run_id}:ledger:{event.event_id}")
        self.store.record_audit(
            "run_ledger",
            row,
            run_id=run_id,
            trace_id=f"{run_id}:ledger:{event.event_id}",
            agent=agent_id,
            exit_status=status,
            output_hash=sha256_text(stable_json(row)),
        )
        return event

    def timeline(self, run_id: str) -> list[dict[str, Any]]:
        self.store.init_db()
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, ts, trace_id, payload_json
                FROM events
                WHERE run_id = ? AND event_type = 'run_ledger'
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row_id, ts, trace_id, payload_json in rows:
            payload = json.loads(payload_json)
            payload["_event_row_id"] = row_id
            payload["_recorded_ts"] = ts
            payload["_trace_id"] = trace_id
            events.append(payload)
        return events

    def trace_summary(self, run_id: str) -> dict[str, Any]:
        from sitina.orchestrator.replay import ReplayEngine
        from sitina.orchestrator.task_graph import TaskGraphRuntime

        timeline = self.timeline(run_id)
        blocked = [item for item in timeline if item.get("status") in {"blocked", "failed"}]
        skipped = [item for item in timeline if item.get("event_type") == "agent_skipped"]
        graph = TaskGraphRuntime(self.home, self.store).load(run_id)
        replay = ReplayEngine(self.home, self.store).replay(run_id, record=False)
        return {
            "status": "ok",
            "run_id": run_id,
            "event_count": len(timeline),
            "timeline": timeline,
            "blocked_events": blocked,
            "skipped_agents": skipped,
            "task_graph": graph.model_dump() if graph else None,
            "replay": {
                "status": replay.status,
                "missing_events": replay.missing_events,
                "inconsistent_events": replay.inconsistent_events,
                "node_states": replay.node_states,
            },
        }

    def _redacted_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        redacted = redact_text(text)
        return json.loads(redacted)
