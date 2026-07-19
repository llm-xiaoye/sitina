from __future__ import annotations

import json
import hashlib
import sqlite3

from sitina.journal.model import EventEnvelope, canonical_json_bytes

from .coverage import (
    MissingRequiredProjectionHandler,
    ProjectionCoverageEntry,
    ProjectionRequirement,
    ProjectionSchemaCoverage,
)


PRODUCTION_HANDLED_SCHEMA_IDS = frozenset(
    {
        "BLACKBOARD_AUTO_REBASE_AUTHORIZED_V1", "BLACKBOARD_CONFLICT_RESOLVED_V1",
        "BLACKBOARD_DOCUMENT_CREATED_V1", "BLACKBOARD_DOCUMENT_READ_V1", "BLACKBOARD_MERGE_DECISION_V1",
        "BLACKBOARD_MERGE_PROPOSAL_SUBMITTED_V1", "BLACKBOARD_MERGE_REVIEWED_V1",
        "BLACKBOARD_PATCH_COMMITTED_V1", "BLACKBOARD_PATCH_CONFLICT_V1", "CHECKPOINT_MANIFEST_PUBLISHED_V1",
        "CHECKPOINT_PROCESS_RECONSTRUCTED_V1", "CHECKPOINT_RESUME_COMPLETED_V1",
        "CHECKPOINT_RESUME_MATRIX_COMPLETED_V1", "CHECKPOINT_RUNTIME_STOPPED_V1",
        "CONTROLLED_PROVIDER_WORKER_LOSS_V1", "DEBATE_OPENED_V1", "DEBATE_RESPONSE_RECORDED_V1",
        "DEBATE_SYNTHESIS_FINALIZED_V1", "DEBATE_SYNTHESIS_SUBMITTED_V1", "EFFECT_RECONCILIATION_SETTLED_V1",
        "HANDOFF_ACCEPTED_V1", "HANDOFF_CLAIM_PENDING_V1", "HANDOFF_CONTRACT_FROZEN_V1",
        "HANDOFF_EXECUTION_STARTED_V1", "HANDOFF_GENERATION_CLOSED_V1", "HANDOFF_GENERATION_LIMIT_REACHED_V1",
        "HANDOFF_GENERATION_OPENED_V1", "HANDOFF_GENERATION_OPENED_V2", "HANDOFF_OFFERED_V1",
        "HANDOFF_RECEIVER_CAPABILITY_REVALIDATED_V1", "HANDOFF_REJECTED_GENERATION_CLOSED_V1",
        "HANDOFF_REJECTED_V1", "HANDOFF_RESULT_SUBMITTED_V1", "HANDOFF_REWORK_REQUIRED_V1",
        "HANDOFF_TASK_CLAIM_BOUND_V1", "HANDOFF_VERIFIED_V1", "NEGOTIATION_FRESH_REVIEW_DISPOSITION_V1",
        "NEGOTIATION_FRESH_REVIEW_REQUESTED_V1", "NEGOTIATION_FRESH_REVIEW_SUBMITTED_V1",
        "NEGOTIATION_NO_CONSENSUS_DECIDED_V1", "NEGOTIATION_PROPOSAL_REVISION_SUBMITTED_V1",
        "NEGOTIATION_ROUND_OPENED_V1", "NEGOTIATION_SELECTION_DECIDED_V1", "PROPOSAL_EVALUATED_V1",
        "PROPOSAL_REVISED_V1", "PROPOSAL_ROUND_GENERATION_OPENED_V1", "PROPOSAL_ROUND_NO_SELECTION_V1",
        "PROPOSAL_ROUND_OPENED_V1", "PROPOSAL_SELECTED_V1", "PROPOSAL_SUBMITTED_V1",
        "PROVIDER_ACK_LOST_OUTCOME_UNKNOWN_V1", "PROVIDER_EXPLICIT_REMOTE_FAILURE_OBSERVED_V1",
        "PROVIDER_HEALTH_OBSERVED_V1", "PROVIDER_RECOVERY_ACK_LOST_VERIFIED_V1",
        "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1", "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1",
        "REVIEW_DISPOSITION_RECORDED_V1", "REVIEW_REQUESTED_V1", "REVIEW_RESPONSE_RECORDED_V1",
        "RUNTIME_FEATURE_ACTIVATED_V1", "RUNTIME_FEATURE_PREPARED_V1",
        "REWORK_OPENED_V1", "REWORK_RETRY_EXHAUSTED_V1", "REWORK_ROUND_FAILED_V1", "REWORK_ROUND_STARTED_V1",
        "REWORK_SATISFIED_V1", "RUN_CREATED_V1", "RUN_TERMINAL_V1", "SESSION_CREATED_V1",
        "SESSION_DELETED_V1", "SESSION_DELETION_PREPARED_V1", "SESSION_MESSAGE_APPENDED_V1",
        "SESSION_RESTORED_V1", "SESSION_RUN_LINKED_V1", "SESSION_TURN_FAILED_V1",
        "SITINA_AGENT_CONTEXT_MANIFEST_PUBLISHED_V2", "SITINA_RUN_CHECKPOINT_CHAIN_COMPACTED_V1",
        "SITINA_RUN_CHECKPOINT_PUBLISHED_V2", "SITINA_RUN_EVIDENCE_PUBLISHED_V2",
        "SITINA_SESSION_STATE_INITIALIZED_V1", "SITINA_SESSION_STATE_UPDATED_V1",
        "SITINA_CONVERSATION_ROLLING_SUMMARY_V1", "SITINA_TOOL_COMPLETED_V1",
        "TRASH_LEASE_RELEASED_V1",
        "SITINA_EPISODE_V1", "SITINA_MEMORY_CANDIDATE_CREATED_V1", "SITINA_MEMORY_STATE_CHANGED_V1",
        "TASK_ATTEMPT_FAILED_V1", "TASK_CLAIMED_V1", "TASK_CLAIM_EXPIRED_V1", "TASK_CLAIM_REJECTED_V1",
        "TASK_CREATED_V1", "TASK_LEASE_EXPIRED_V1", "TASK_LEASE_RELEASED_V1", "TASK_LEASE_RENEWED_V1",
        "TASK_RESULT_ACCEPTED_V1", "TASK_RESULT_SUBMITTED_V1", "TASK_STALE_FENCE_REJECTED_V1",
    }
)

PRODUCTION_SCHEMA_COVERAGE = ProjectionSchemaCoverage(
    ProjectionCoverageEntry(schema_id, ProjectionRequirement.REQUIRED, "production-v1")
    for schema_id in PRODUCTION_HANDLED_SCHEMA_IDS
)


def _run_created_projection_fields(payload: dict[str, object]) -> tuple[str, int]:
    """Normalize compatible historical run-open shapes without inventing data."""

    goal_hash = payload.get("goal_hash")
    agent_count = payload.get("agent_count")
    if isinstance(goal_hash, str) and len(goal_hash) == 64 and isinstance(agent_count, int) and agent_count >= 0:
        return goal_hash, agent_count
    if payload.get("schema") == "FAST_CONVERSATION_RUN_OPENED_V1":
        message_hash = payload.get("message_hash")
        if isinstance(message_hash, str) and len(message_hash) == 64:
            # FAST is a single logical agent and its exact user-message hash is
            # the run goal identity in this historical schema.
            return message_hash, 1
    raise MissingRequiredProjectionHandler(
        f"run.created schema cannot supply goal_hash/agent_count: {payload.get('schema', 'UNSCHEMATIZED_EVENT_V1')}"
    )


def _insert_exact_runtime_event(
    connection: sqlite3.Connection,
    table: str,
    event: EventEnvelope,
    *,
    run_id: str | None = None,
) -> None:
    """Keep authenticated, body-free event envelopes in a rebuildable state view."""

    if table not in {"runtime_state_events", "runtime_pending_run_events"}:
        raise ValueError("unsupported runtime state Projection table")
    columns = (
        "position,event_id,event_type,tenant_id,stream_id,stream_version,occurred_at,payload_json,"
        "object_refs_json,schema_major,event_hash,journal_auth_key_id,journal_auth_tag"
    )
    values: tuple[object, ...] = (
        event.position,
        event.event_id,
        event.event_type,
        event.tenant_id,
        event.stream_id,
        event.stream_version,
        event.occurred_at,
        canonical_json_bytes(dict(event.payload)).decode("utf-8"),
        canonical_json_bytes(list(event.object_refs)).decode("utf-8"),
        event.schema_major,
        event.event_hash,
        event.journal_auth_key_id,
        event.journal_auth_tag,
    )
    if table == "runtime_pending_run_events":
        columns = "position,run_id," + columns.removeprefix("position,")
        values = (event.position, str(run_id), *values[1:])
    placeholders = ",".join("?" for _ in values)
    connection.execute(f"INSERT OR REPLACE INTO {table}({columns}) VALUES({placeholders})", values)


def _apply_runtime_state_event(connection: sqlite3.Connection, event: EventEnvelope) -> None:
    """Project exact current runtime state plus only runs that may need recovery.

    Session and Memory envelopes are retained because their CAS-bound chains
    reconstruct current state.  Run envelopes are retained only while a run
    is open or a successful linked turn lacks its assistant success marker.
    """

    payload = dict(event.payload)
    if event.stream_id.startswith(("session/", "memory/")):
        _insert_exact_runtime_event(connection, "runtime_state_events", event)

    run_id_value = payload.get("run_id")
    run_id = str(run_id_value) if isinstance(run_id_value, str) else None
    if event.event_type == "run.created" and run_id is not None:
        connection.execute(
            "INSERT OR REPLACE INTO runtime_pending_runs(run_id,session_id,turn_index,terminal_state,created_position,last_position) "
            "VALUES(?,NULL,NULL,NULL,?,?)",
            (run_id, event.position, event.position),
        )
    if run_id is not None and connection.execute(
        "SELECT 1 FROM runtime_pending_runs WHERE run_id=?", (run_id,)
    ).fetchone() is not None:
        _insert_exact_runtime_event(
            connection,
            "runtime_pending_run_events",
            event,
            run_id=run_id,
        )
        connection.execute(
            "UPDATE runtime_pending_runs SET last_position=? WHERE run_id=?",
            (event.position, run_id),
        )

    if event.event_type == "session.run-linked" and run_id is not None:
        connection.execute(
            "UPDATE runtime_pending_runs SET session_id=?,turn_index=?,last_position=? WHERE run_id=?",
            (str(payload["session_id"]), int(payload["turn_index"]), event.position, run_id),
        )
    elif event.event_type == "run.terminal" and run_id is not None:
        terminal_state = str(payload.get("terminal_state") or "")
        connection.execute(
            "UPDATE runtime_pending_runs SET terminal_state=?,last_position=? WHERE run_id=?",
            (terminal_state, event.position, run_id),
        )
        row = connection.execute(
            "SELECT session_id FROM runtime_pending_runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if terminal_state != "SUCCEEDED" or row is None or row[0] is None:
            connection.execute("DELETE FROM runtime_pending_run_events WHERE run_id=?", (run_id,))
            connection.execute("DELETE FROM runtime_pending_runs WHERE run_id=?", (run_id,))

    completed_session: str | None = None
    completed_turn: int | None = None
    if event.event_type == "session.message-appended" and payload.get("role") == "assistant":
        completed_session = str(payload["session_id"])
        completed_turn = int(payload["turn_index"])
    elif event.event_type == "session.turn-reconciled":
        completed_session = str(payload["session_id"])
        completed_turn = int(payload["turn_index"])
    if completed_session is not None and completed_turn is not None:
        completed_runs = [
            str(row[0])
            for row in connection.execute(
                "SELECT run_id FROM runtime_pending_runs WHERE session_id=? AND turn_index=?",
                (completed_session, completed_turn),
            )
        ]
        for completed_run in completed_runs:
            connection.execute("DELETE FROM runtime_pending_run_events WHERE run_id=?", (completed_run,))
            connection.execute("DELETE FROM runtime_pending_runs WHERE run_id=?", (completed_run,))


def apply_production_event(
    connection: sqlite3.Connection,
    event: EventEnvelope,
    *,
    coverage: ProjectionSchemaCoverage = PRODUCTION_SCHEMA_COVERAGE,
) -> None:
    payload = dict(event.payload)
    coverage_entry = coverage.assert_projectable(payload)
    schema_id = str(payload.get("schema", "UNSCHEMATIZED_EVENT_V1"))
    try:
        schema_version = int(schema_id.rsplit("_V", 1)[1])
    except (IndexError, ValueError):
        schema_version = 0
    run_id = payload.get("run_id")
    connection.execute(
        "INSERT INTO event_directory(position,event_id,event_type,stream_id,run_id,payload_hash,source_segment) VALUES(?,?,?,?,?,?,?)",
        (
            event.position,
            event.event_id,
            event.event_type,
            event.stream_id,
            str(run_id) if run_id is not None else None,
            hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
            str(getattr(event, "source_segment", "active")),
        ),
    )
    connection.execute(
        "INSERT OR REPLACE INTO projection_schema_coverage(schema_id,requirement,handler_id,coverage_state) VALUES(?,?,?,?)",
        (
            coverage_entry.schema_id,
            coverage_entry.requirement.value,
            coverage_entry.handler_id,
            coverage_entry.state,
        ),
    )
    connection.execute(
        "INSERT OR REPLACE INTO projection_metadata(key,value) VALUES('schema_coverage_hash',?)",
        (coverage.commitment,),
    )
    connection.execute(
        "INSERT OR REPLACE INTO projection_metadata(key,value) VALUES('runtime_state_projection_schema','SITINA_RUNTIME_STATE_PROJECTION_V1')"
    )
    _apply_runtime_state_event(connection, event)
    if event.event_type == "session.created":
        connection.execute(
            "INSERT INTO sessions(session_id,title,status,created_position,last_position,deleted_position,source_position,source_event_id,schema_version) "
            "VALUES(?,?,'ACTIVE',?,?,NULL,?,?,?) ON CONFLICT(session_id) DO UPDATE SET title=excluded.title,status='ACTIVE',"
            "last_position=excluded.last_position,deleted_position=NULL,source_position=excluded.source_position,"
            "source_event_id=excluded.source_event_id,schema_version=excluded.schema_version",
            (
                str(payload["session_id"]), str(payload["title"]), event.position, event.position,
                event.position, event.event_id, schema_version,
            ),
        )
    elif event.event_type == "session.message-appended":
        connection.execute(
            "INSERT OR IGNORE INTO sessions(session_id,title,status,created_position,last_position,deleted_position,source_position,source_event_id,schema_version) "
            "VALUES(?,?,'ACTIVE',?,?,NULL,?,?,?)",
            (
                str(payload["session_id"]), "Untitled", event.position, event.position,
                event.position, event.event_id, schema_version,
            ),
        )
        connection.execute(
            "INSERT INTO session_messages(message_id,session_id,role,turn_index,body_ref,body_hash,created_at,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(message_id) DO UPDATE SET body_ref=excluded.body_ref,body_hash=excluded.body_hash,"
            "source_position=excluded.source_position,source_event_id=excluded.source_event_id,schema_version=excluded.schema_version",
            (
                str(payload["message_id"]), str(payload["session_id"]), str(payload["role"]),
                int(payload["turn_index"]), str(payload["body_ref"]), str(payload["body_hash"]),
                str(payload["created_at"]), event.position, event.event_id, schema_version,
            ),
        )
        connection.execute(
            "INSERT OR REPLACE INTO session_object_refs(session_id,object_ref,ref_kind,source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?)",
            (str(payload["session_id"]), str(payload["body_ref"]), "message-body", event.position, event.event_id, schema_version),
        )
        connection.execute("UPDATE sessions SET last_position=? WHERE session_id=?", (event.position, str(payload["session_id"])))
    elif event.event_type == "session.deleted":
        connection.execute(
            "UPDATE sessions SET status='DELETED',last_position=?,deleted_position=?,source_position=?,source_event_id=?,schema_version=? WHERE session_id=?",
            (event.position, event.position, event.position, event.event_id, schema_version, str(payload["session_id"])),
        )
    elif event.event_type == "session.restored":
        connection.execute(
            "UPDATE sessions SET status='ACTIVE',last_position=?,deleted_position=NULL,source_position=?,source_event_id=?,schema_version=? WHERE session_id=?",
            (event.position, event.position, event.event_id, schema_version, str(payload["session_id"])),
        )
    elif event.event_type == "session.run-linked":
        connection.execute(
            "INSERT OR REPLACE INTO session_runs(session_id,run_id,turn_index,source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?)",
            (str(payload["session_id"]), str(payload["run_id"]), int(payload["turn_index"]), event.position, event.event_id, schema_version),
        )
    elif event.event_type in {"session.state-initialized", "session.state-updated"}:
        state_ref = str(payload.get("state_ref") or payload.get("delta_ref"))
        version = int(payload.get("version") or payload.get("to_version"))
        connection.execute(
            "INSERT INTO session_working_state(session_id,state_ref,state_kind,state_version,source_frontier,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET state_ref=excluded.state_ref,state_kind=excluded.state_kind,"
            "state_version=excluded.state_version,source_frontier=excluded.source_frontier,source_position=excluded.source_position,"
            "source_event_id=excluded.source_event_id,schema_version=excluded.schema_version",
            (
                str(payload["session_id"]), state_ref,
                "BASE" if event.event_type == "session.state-initialized" else "DELTA",
                version, int(payload["source_frontier"]), event.position, event.event_id, schema_version,
            ),
        )
        connection.execute(
            "INSERT OR REPLACE INTO session_object_refs(session_id,object_ref,ref_kind,source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?)",
            (str(payload["session_id"]), state_ref, "working-state", event.position, event.event_id, schema_version),
        )
    elif event.event_type == "session.summary-updated":
        connection.execute(
            "INSERT OR REPLACE INTO session_summaries(session_id,summary_version,summary_ref,summary_hash,source_message_start,source_message_end,"
            "source_frontier,source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                str(payload["session_id"]), int(payload["summary_version"]), str(payload["summary_ref"]),
                str(payload["summary_hash"]), int(payload["source_message_range"][0]), int(payload["source_message_range"][1]),
                int(payload["source_frontier"]), event.position, event.event_id, schema_version,
            ),
        )
        connection.execute(
            "INSERT OR REPLACE INTO session_object_refs(session_id,object_ref,ref_kind,source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?)",
            (str(payload["session_id"]), str(payload["summary_ref"]), "rolling-summary", event.position, event.event_id, schema_version),
        )
    elif event.event_type == "agent.context-manifest-published":
        connection.execute(
            "INSERT OR REPLACE INTO agent_calls(call_id,run_id,agent_id,status,context_manifest_ref,rendered_input_hash,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,'CONTEXT_READY',?,?,?,?,?)",
            (
                str(payload["call_id"]), str(payload["run_id"]), str(payload["agent_id"]), str(payload["manifest_ref"]),
                str(payload["rendered_input_hash"]), event.position, event.event_id, schema_version,
            ),
        )
    elif event.event_type == "tool.completed":
        connection.execute(
            "INSERT OR REPLACE INTO tool_calls(tool_call_id,run_id,status,exit_code,result_manifest_ref,captured_bytes,dropped_bytes,truncated,"
            "source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(payload["tool_call_id"]), str(payload["run_id"]), str(payload["terminal_status"]), payload.get("exit_code"),
                str(payload["result_manifest_ref"]), int(payload["captured_bytes"]), int(payload["dropped_bytes"]),
                int(bool(payload["truncated"])), event.position, event.event_id, schema_version,
            ),
        )
    elif event.event_type == "run.checkpoint-published":
        connection.execute(
            "INSERT OR REPLACE INTO run_checkpoints(checkpoint_id,run_id,checkpoint_kind,checkpoint_ref,frontier_position,"
            "source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?,?,?)",
            (
                str(payload["checkpoint_id"]), str(payload["run_id"]), str(payload["checkpoint_kind"]),
                str(payload["checkpoint_ref"]), int(payload["journal_to_position"]), event.position, event.event_id, schema_version,
            ),
        )
    elif event.event_type == "run.evidence-published":
        connection.execute(
            "INSERT OR REPLACE INTO run_evidence(evidence_id,run_id,evidence_ref,checkpoint_ref,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                str(payload["evidence_id"]), str(payload["run_id"]), str(payload["evidence_ref"]),
                str(payload["checkpoint_ref"]), event.position, event.event_id, schema_version,
            ),
        )
    elif event.event_type == "memory.candidate-created":
        memory = dict(payload["memory"])
        connection.execute(
            "INSERT INTO memory_items(memory_id,scope,owner_id,namespace,status,content_ref,expires_at,created_position,last_position,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(memory_id) DO UPDATE SET status=excluded.status,last_position=excluded.last_position,"
            "source_position=excluded.source_position,source_event_id=excluded.source_event_id,schema_version=excluded.schema_version",
            (
                str(memory["memory_id"]), str(memory["scope"]), str(memory["owner_id"]), str(memory["namespace"]),
                str(memory["status"]), str(memory["content_ref"]), memory.get("expires_at"), event.position, event.position,
                event.position, event.event_id, schema_version,
            ),
        )
        connection.execute(
            "INSERT OR REPLACE INTO memory_current(memory_id,scope,owner_id,namespace,status,content_ref,expires_at,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                str(memory["memory_id"]), str(memory["scope"]), str(memory["owner_id"]), str(memory["namespace"]),
                str(memory["status"]), str(memory["content_ref"]), memory.get("expires_at"), event.position, event.event_id, schema_version,
            ),
        )
        for superseded in memory.get("supersedes", ()):
            connection.execute(
                "INSERT OR REPLACE INTO memory_relations(memory_id,related_memory_id,relation,source_position,source_event_id,schema_version) VALUES(?,?,?,?,?,?)",
                (str(memory["memory_id"]), str(superseded), "SUPERSEDES", event.position, event.event_id, schema_version),
            )
    elif event.event_type.startswith("memory.") and payload.get("memory_id") is not None and payload.get("to_status") is not None:
        connection.execute(
            "UPDATE memory_items SET status=?,last_position=? WHERE memory_id=?",
            (str(payload["to_status"]), event.position, str(payload["memory_id"])),
        )
        connection.execute(
            "UPDATE memory_current SET status=?,source_position=?,source_event_id=?,schema_version=? WHERE memory_id=?",
            (str(payload["to_status"]), event.position, event.event_id, schema_version, str(payload["memory_id"])),
        )
    elif event.event_type == "memory.episode-created":
        action_range = payload["action_event_range"]
        connection.execute(
            "INSERT OR REPLACE INTO memory_episodes(episode_id,source_run_id,goal_ref,action_start_position,action_end_position,"
            "terminal_evidence_ref,lesson_ref,outcome,failure_reason_code,source_frontier,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(payload["episode_id"]), str(payload["source_run_id"]), str(payload["goal_ref"]),
                int(action_range[0]), int(action_range[1]), str(payload["terminal_evidence_ref"]),
                str(payload["lesson_ref"]), str(payload["outcome"]), payload.get("failure_reason_code"),
                int(payload["source_frontier"]), event.position, event.event_id, schema_version,
            ),
        )
    elif event.event_type == "provider.health-observed":
        connection.execute(
            "INSERT INTO provider_health(profile,status,checked_at,next_check_at,failure_count,last_error,model,latency_ms,source,source_position,source_event_id,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(profile) DO UPDATE SET status=excluded.status,checked_at=excluded.checked_at,"
            "next_check_at=excluded.next_check_at,failure_count=excluded.failure_count,last_error=excluded.last_error,model=excluded.model,"
            "latency_ms=excluded.latency_ms,source=excluded.source,source_position=excluded.source_position,"
            "source_event_id=excluded.source_event_id,schema_version=excluded.schema_version",
            (
                str(payload["profile"]), str(payload["status"]), str(payload["checked_at"]), payload.get("next_check_at"),
                int(payload["failure_count"]), payload.get("last_error"), payload.get("model"), payload.get("latency_ms"),
                str(payload["source"]), event.position, event.event_id, schema_version,
            ),
        )
    if event.event_type == "run.created":
        goal_hash, agent_count = _run_created_projection_fields(payload)
        connection.execute(
            "INSERT INTO bplus_runs(run_id,status,goal_hash,agent_count,created_position,terminal_position) VALUES(?,?,?,?,?,NULL)",
            (str(payload["run_id"]), "active", goal_hash, agent_count, event.position),
        )
    elif event.event_type == "run.terminal":
        connection.execute(
            "UPDATE bplus_runs SET status='terminal',terminal_position=? WHERE run_id=?",
            (event.position, str(payload["run_id"])),
        )
    schema = str(payload.get("schema", ""))
    projection_run_id = str(run_id)
    if schema in {"PROPOSAL_ROUND_OPENED_V1", "PROPOSAL_ROUND_GENERATION_OPENED_V1"}:
        round_id = str(payload["round_id"])
        generation = int(payload["generation"])
        connection.execute(
            """
            INSERT INTO proposal_rounds(
              run_id,round_id,current_generation,round_state,rubric_hash,policy_hash,config_hash,
              minimum_score,max_revisions,selected_proposal_id,selected_output_hash,opened_position,last_position
            ) VALUES(?,?,?,'OPEN',?,?,?,?,?,NULL,NULL,?,?)
            ON CONFLICT(run_id,round_id) DO UPDATE SET
              current_generation=excluded.current_generation,round_state='OPEN',rubric_hash=excluded.rubric_hash,
              policy_hash=excluded.policy_hash,config_hash=excluded.config_hash,
              minimum_score=excluded.minimum_score,max_revisions=excluded.max_revisions,
              selected_proposal_id=NULL,selected_output_hash=NULL,last_position=excluded.last_position
            """,
            (
                projection_run_id, round_id, generation, payload.get("rubric_hash"),
                payload.get("policy_hash"), payload.get("config_hash"), payload.get("minimum_score"),
                payload.get("max_revisions"), event.position, event.position,
            ),
        )
    elif schema == "PROPOSAL_SUBMITTED_V1":
        round_id = str(payload["round_id"])
        generation = int(payload["generation"])
        proposal_id = str(payload["proposal_id"])
        revision = int(payload.get("revision", 1))
        body_ref = str(payload["body_ref"])
        output_hash = str(payload.get("revision_output_hash", payload.get("output_hash", body_ref)))
        connection.execute(
            """
            INSERT INTO proposal_revisions(
              run_id,round_id,generation,proposal_id,revision,participant_id,body_ref,parent_output_hash,
              output_hash,input_snapshot_hash,review_id,review_output_hash,old_review_reused,revision_state,
              score,evaluator_id,disposition,source_position,last_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',NULL,NULL,NULL,?,?)
            ON CONFLICT(run_id,round_id,generation,proposal_id,revision) DO UPDATE SET
              participant_id=excluded.participant_id,body_ref=excluded.body_ref,
              parent_output_hash=excluded.parent_output_hash,output_hash=excluded.output_hash,
              input_snapshot_hash=excluded.input_snapshot_hash,old_review_reused=excluded.old_review_reused,
              revision_state='ACTIVE',last_position=excluded.last_position
            """,
            (
                projection_run_id, round_id, generation, proposal_id, revision,
                payload.get("participant_id"), body_ref, payload.get("parent_output_hash"), output_hash,
                payload.get("input_snapshot_hash"), payload.get("review_id"),
                payload.get("review_output_hash"), int(bool(payload.get("old_review_reused", False))),
                event.position, event.position,
            ),
        )
        connection.execute(
            "UPDATE proposal_rounds SET current_generation=?,last_position=? WHERE run_id=? AND round_id=?",
            (generation, event.position, projection_run_id, round_id),
        )
    elif schema in {"PROPOSAL_REVISED_V1", "NEGOTIATION_PROPOSAL_REVISION_SUBMITTED_V1"}:
        round_id = str(payload["round_id"])
        generation = int(payload.get("generation", 1))
        proposal_id = str(payload["proposal_id"])
        revision = int(payload.get("revision", 2))
        parent_output_hash = payload.get("parent_output_hash", payload.get("parent_proposal_hash"))
        output_hash = str(payload.get("revision_output_hash", payload.get("new_output_hash", payload.get("new_artifact_hash", payload.get("body_ref")))))
        body_ref = str(payload.get("body_ref", payload.get("revision_output_ref", output_hash))).removeprefix("cas:")
        previous = connection.execute(
            """SELECT participant_id,input_snapshot_hash FROM proposal_revisions
               WHERE run_id=? AND round_id=? AND proposal_id=? ORDER BY generation DESC,revision DESC LIMIT 1""",
            (projection_run_id, round_id, proposal_id),
        ).fetchone()
        participant_id = payload.get("revision_author_id") or (previous[0] if previous else None)
        input_snapshot_hash = payload.get("input_snapshot_hash") or (previous[1] if previous else None)
        connection.execute(
            """
            INSERT INTO proposal_revisions(
              run_id,round_id,generation,proposal_id,revision,participant_id,body_ref,parent_output_hash,
              output_hash,input_snapshot_hash,review_id,review_output_hash,old_review_reused,revision_state,
              score,evaluator_id,disposition,source_position,last_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'ACTIVE',NULL,NULL,NULL,?,?)
            ON CONFLICT(run_id,round_id,generation,proposal_id,revision) DO UPDATE SET
              participant_id=excluded.participant_id,body_ref=excluded.body_ref,
              parent_output_hash=excluded.parent_output_hash,output_hash=excluded.output_hash,
              old_review_reused=excluded.old_review_reused,last_position=excluded.last_position
            """,
            (
                projection_run_id, round_id, generation, proposal_id, revision, participant_id,
                body_ref, parent_output_hash, output_hash, input_snapshot_hash, payload.get("review_id"),
                payload.get("review_output_hash"), int(bool(payload.get("old_review_reused", False))),
                event.position, event.position,
            ),
        )
        rework_id = payload.get("rework_id")
        if rework_id is not None:
            connection.execute(
                """UPDATE rework_rounds SET defect_resolution_hash=?,all_defects_addressed=?
                   WHERE run_id=? AND rework_id=? AND round_number=(
                     SELECT MAX(round_number) FROM rework_rounds WHERE run_id=? AND rework_id=?
                   )""",
                (
                    payload.get("defect_resolution_hash"), int(bool(payload.get("all_defects_addressed"))),
                    projection_run_id, str(rework_id), projection_run_id, str(rework_id),
                ),
            )
    elif schema == "PROPOSAL_EVALUATED_V1":
        connection.execute(
            """
            UPDATE proposal_revisions SET revision_state=?,score=?,evaluator_id=?,disposition=?,last_position=?
            WHERE run_id=? AND round_id=? AND generation=? AND proposal_id=? AND revision=?
            """,
            (
                {"ACCEPT": "ACTIVE", "NEEDS_REVISION": "NEEDS_REVISION", "REJECT": "REJECTED"}.get(
                    str(payload["disposition"]), str(payload["disposition"])
                ),
                int(payload["score"]), payload.get("evaluator_id"), str(payload["disposition"]),
                event.position, projection_run_id, str(payload["round_id"]), int(payload["generation"]),
                str(payload["proposal_id"]), int(payload.get("revision", 1)),
            ),
        )
        connection.execute(
            "UPDATE proposal_rounds SET last_position=? WHERE run_id=? AND round_id=?",
            (event.position, projection_run_id, str(payload["round_id"])),
        )
    elif schema == "PROPOSAL_SELECTED_V1":
        connection.execute(
            """UPDATE proposal_rounds SET round_state='SELECTED',current_generation=?,selected_proposal_id=?,
                 selected_output_hash=?,last_position=? WHERE run_id=? AND round_id=?""",
            (
                int(payload["generation"]), str(payload["proposal_id"]), payload.get("selected_output_hash"),
                event.position, projection_run_id, str(payload["round_id"]),
            ),
        )
    elif schema == "PROPOSAL_ROUND_NO_SELECTION_V1":
        connection.execute(
            """UPDATE proposal_rounds SET round_state='NO_SELECTION',current_generation=?,last_position=?
               WHERE run_id=? AND round_id=?""",
            (int(payload["generation"]), event.position, projection_run_id, str(payload["round_id"])),
        )
    elif schema in {"REVIEW_REQUESTED_V1", "NEGOTIATION_FRESH_REVIEW_REQUESTED_V1"}:
        connection.execute(
            """
            INSERT INTO review_runtime(
              run_id,review_id,artifact_hash,artifact_author_id,rubric_hash,reviewer_id,verdict,
              response_ref,response_commitment,disposition,artifact_accepted,requested_position,last_position
            ) VALUES(?,?,?,?,?,?,NULL,NULL,NULL,NULL,0,?,?)
            ON CONFLICT(run_id,review_id) DO UPDATE SET artifact_hash=excluded.artifact_hash,
              artifact_author_id=excluded.artifact_author_id,rubric_hash=excluded.rubric_hash,
              reviewer_id=excluded.reviewer_id,last_position=excluded.last_position
            """,
            (
                projection_run_id, str(payload["review_id"]), str(payload["artifact_hash"]),
                payload.get("artifact_author_id"), payload.get("rubric_hash"), payload.get("reviewer_id"),
                event.position, event.position,
            ),
        )
    elif schema in {"REVIEW_RESPONSE_RECORDED_V1", "NEGOTIATION_FRESH_REVIEW_SUBMITTED_V1"}:
        connection.execute(
            """UPDATE review_runtime SET reviewer_id=?,verdict=?,response_ref=?,response_commitment=?,last_position=?
               WHERE run_id=? AND review_id=?""",
            (
                payload.get("reviewer_id"), payload.get("effective_verdict", payload.get("verdict")),
                payload.get("response_ref", payload.get("fresh_review_output_ref")),
                payload.get("response_commitment"), event.position, projection_run_id, str(payload["review_id"]),
            ),
        )
    elif schema in {"REVIEW_DISPOSITION_RECORDED_V1", "NEGOTIATION_FRESH_REVIEW_DISPOSITION_V1"}:
        connection.execute(
            """UPDATE review_runtime SET disposition=?,artifact_accepted=?,last_position=?
               WHERE run_id=? AND review_id=?""",
            (
                payload.get("disposition"), int(bool(payload.get("artifact_accepted", False))),
                event.position, projection_run_id, str(payload["review_id"]),
            ),
        )
    elif schema in {"DEBATE_OPENED_V1", "NEGOTIATION_ROUND_OPENED_V1"} and payload.get("debate_id") is not None:
        connection.execute(
            """
            INSERT INTO debate_runtime(
              run_id,debate_id,target_id,debate_state,max_rounds,max_tokens,outcome,synthesis_hash,
              successor_obligation_id,opened_position,last_position
            ) VALUES(?,?,?,'OPEN',?,?,NULL,NULL,NULL,?,?)
            ON CONFLICT(run_id,debate_id) DO UPDATE SET debate_state='OPEN',max_rounds=excluded.max_rounds,
              max_tokens=excluded.max_tokens,last_position=excluded.last_position
            """,
            (
                projection_run_id, str(payload["debate_id"]), str(payload.get("target_id", payload.get("round_id"))),
                int(payload.get("max_rounds", 2)), int(payload.get("max_tokens", payload.get("token_budget", 1))),
                event.position, event.position,
            ),
        )
    elif schema == "DEBATE_RESPONSE_RECORDED_V1":
        connection.execute(
            """
            INSERT OR REPLACE INTO debate_responses(
              run_id,debate_id,response_id,claim_id,target_claim_id,actor_id,round_number,token_count,
              body_ref,parent_output_hash,revision_output_hash,revision_call_id,source_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["debate_id"]), str(payload["response_id"]),
                str(payload["claim_id"]), str(payload["target_claim_id"]), payload.get("actor_id"),
                int(payload["round_number"]), int(payload["token_count"]), str(payload["body_ref"]),
                payload.get("parent_output_hash"), payload.get("revision_output_hash"),
                payload.get("revision_call_id"), event.position,
            ),
        )
        connection.execute(
            "UPDATE debate_runtime SET debate_state='RESPONSES_RECORDED',last_position=? WHERE run_id=? AND debate_id=?",
            (event.position, projection_run_id, str(payload["debate_id"])),
        )
    elif schema == "DEBATE_SYNTHESIS_SUBMITTED_V1":
        connection.execute(
            """UPDATE debate_runtime SET debate_state='SYNTHESIS_SUBMITTED',synthesis_hash=?,last_position=?
               WHERE run_id=? AND debate_id=?""",
            (
                payload.get("synthesis_candidate_hash"), event.position,
                projection_run_id, str(payload["debate_id"]),
            ),
        )
    elif schema == "DEBATE_SYNTHESIS_FINALIZED_V1":
        connection.execute(
            """UPDATE debate_runtime SET debate_state='TERMINAL',outcome=?,synthesis_hash=?,
                 successor_obligation_id=?,last_position=? WHERE run_id=? AND debate_id=?""",
            (
                str(payload["outcome"]), payload.get("synthesis_hash"), payload.get("successor_obligation_id"),
                event.position, projection_run_id, str(payload["debate_id"]),
            ),
        )
    elif schema in {"NEGOTIATION_SELECTION_DECIDED_V1", "NEGOTIATION_NO_CONSENSUS_DECIDED_V1"}:
        latest = payload.get("latest_revision_hashes")
        if not isinstance(latest, list):
            selected = payload.get("latest_revision_hash")
            latest = [selected] if selected is not None else []
        connection.execute(
            """
            INSERT OR REPLACE INTO negotiation_decisions(
              run_id,decision_id,round_id,generation,decision,selected_proposal_id,
              latest_revision_hashes_json,synthesis_candidate_hash,synthesis_hash,
              fresh_review_ids_json,fresh_review_hashes_json,successor_obligation_id,source_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["decision_id"]), str(payload["round_id"]),
                int(payload["generation"]), str(payload["decision"]), payload.get("selected_proposal_id"),
                json.dumps(latest, sort_keys=True, separators=(",", ":")),
                str(payload["synthesis_candidate_hash"]), str(payload["synthesis_hash"]),
                json.dumps(payload.get("fresh_review_ids", []), sort_keys=True, separators=(",", ":")),
                json.dumps(payload.get("fresh_review_hashes", []), sort_keys=True, separators=(",", ":")),
                payload.get("successor_obligation_id"), event.position,
            ),
        )
    elif schema == "REWORK_OPENED_V1":
        connection.execute(
            """
            INSERT OR REPLACE INTO rework_runtime(
              run_id,rework_id,task_id,rework_state,failure_type,acceptance_criteria_hash,max_retries,
              retry_count,current_result_ref,successor_obligation_id,opened_position,last_position
            ) VALUES(?,?,?,'OPEN',?,?,?,0,NULL,NULL,?,?)
            """,
            (
                projection_run_id, str(payload["rework_id"]), str(payload["task_id"]),
                str(payload["failure_type"]), str(payload["acceptance_criteria_hash"]),
                int(payload["max_retries"]), event.position, event.position,
            ),
        )
    elif schema == "REWORK_ROUND_STARTED_V1":
        connection.execute(
            """
            INSERT OR REPLACE INTO rework_rounds(
              run_id,rework_id,round_number,attempt_id,round_state,result_ref,defect_resolution_hash,
              all_defects_addressed,started_position,terminal_position
            ) VALUES(?,?,?,?,'ACTIVE',NULL,NULL,NULL,?,NULL)
            """,
            (
                projection_run_id, str(payload["rework_id"]), int(payload["round"]),
                payload.get("attempt_id"), event.position,
            ),
        )
        connection.execute(
            """UPDATE rework_runtime SET rework_state='ROUND_ACTIVE',retry_count=?,last_position=?
               WHERE run_id=? AND rework_id=?""",
            (int(payload["round"]), event.position, projection_run_id, str(payload["rework_id"])),
        )
    elif schema in {"REWORK_SATISFIED_V1", "REWORK_ROUND_FAILED_V1", "REWORK_RETRY_EXHAUSTED_V1"}:
        state = {
            "REWORK_SATISFIED_V1": "SATISFIED",
            "REWORK_ROUND_FAILED_V1": "OPEN",
            "REWORK_RETRY_EXHAUSTED_V1": "SUCCESSOR_REQUIRED",
        }[schema]
        round_number = int(payload.get("round", payload.get("retry_count", 1)))
        connection.execute(
            """UPDATE rework_rounds SET round_state=?,result_ref=?,terminal_position=?
               WHERE run_id=? AND rework_id=? AND round_number=?""",
            (
                state, payload.get("result_ref"), event.position, projection_run_id,
                str(payload["rework_id"]), round_number,
            ),
        )
        connection.execute(
            """UPDATE rework_runtime SET rework_state=?,retry_count=?,current_result_ref=?,
                 successor_obligation_id=?,last_position=? WHERE run_id=? AND rework_id=?""",
            (
                state, round_number, payload.get("result_ref"), payload.get("successor_obligation_id"),
                event.position, projection_run_id, str(payload["rework_id"]),
            ),
        )
    elif schema == "BLACKBOARD_DOCUMENT_CREATED_V1":
        connection.execute(
            """
            INSERT INTO blackboard_documents(
              document_id,run_id,namespace,schema_id,schema_version,current_version,current_hash,
              classification,writer_policy_hash,merge_policy_hash,created_position,last_position,last_writer_id,object_ref
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)
            """,
            (
                str(payload["document_id"]), projection_run_id, str(payload["namespace"]),
                str(payload.get("schema_id", "sitina.blackboard.document")), int(payload.get("schema_version", 1)),
                int(payload.get("current_version", payload.get("version", 0))),
                str(payload.get("current_hash", payload.get("document_hash"))), str(payload["classification"]),
                str(payload.get("writer_policy_hash", payload.get("policy_hash", "0" * 64))),
                str(payload.get("merge_policy_hash", payload.get("policy_hash", "0" * 64))),
                event.position, event.position,
            ),
        )
        connection.execute(
            """
            INSERT INTO blackboard_versions(
              run_id,document_id,version,document_hash,base_version,base_hash,patch_ref,patch_hash,
              writer_agent_id,writer_fence,resolution_conflict_id,source_position
            ) VALUES(?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?)
            """,
            (
                projection_run_id, str(payload["document_id"]),
                int(payload.get("current_version", payload.get("version", 0))),
                str(payload.get("current_hash", payload.get("document_hash"))), event.position,
            ),
        )
    elif schema == "BLACKBOARD_DOCUMENT_READ_V1":
        connection.execute(
            """
            INSERT INTO blackboard_reads(read_id,document_id,run_id,reader_agent_id,read_version,read_hash,source_position)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                str(payload["read_id"]), str(payload["document_id"]), projection_run_id,
                str(payload["reader_agent_id"]), int(payload["read_version"]), str(payload["read_hash"]), event.position,
            ),
        )
    elif schema == "BLACKBOARD_PATCH_CONFLICT_V1":
        conflict_id = str(payload.get("conflict_id", f"legacy-blackboard-conflict-{event.position}"))
        connection.execute(
            """
            INSERT INTO blackboard_conflicts(
              conflict_id,document_id,run_id,conflict_state,attempted_base_version,attempted_base_hash,
              canonical_version,canonical_hash,attempted_patch_hash,merge_id,review_id,decision_id,
              resolved_version,resolved_hash,opened_position,resolved_position
            ) VALUES(?,?,?,'OPEN',?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,?,NULL)
            """,
            (
                conflict_id, str(payload["document_id"]), projection_run_id,
                int(payload["attempted_base_version"]), str(payload["attempted_base_hash"]),
                int(payload["canonical_version"]), str(payload["canonical_hash"]),
                str(payload.get("patch_hash", payload.get("fact_hash", "0" * 64))), event.position,
            ),
        )
    elif schema == "BLACKBOARD_MERGE_PROPOSAL_SUBMITTED_V1":
        connection.execute(
            "UPDATE blackboard_conflicts SET conflict_state='MERGE_PROPOSED',merge_id=? WHERE run_id=? AND conflict_id=?",
            (str(payload["merge_id"]), projection_run_id, str(payload["conflict_id"])),
        )
    elif schema == "BLACKBOARD_MERGE_REVIEWED_V1":
        connection.execute(
            "UPDATE blackboard_conflicts SET conflict_state='REVIEWED',review_id=? WHERE run_id=? AND conflict_id=?",
            (str(payload["review_id"]), projection_run_id, str(payload["conflict_id"])),
        )
    elif schema in {"BLACKBOARD_MERGE_DECISION_V1", "BLACKBOARD_AUTO_REBASE_AUTHORIZED_V1"}:
        connection.execute(
            "UPDATE blackboard_conflicts SET decision_id=? WHERE run_id=? AND conflict_id=?",
            (str(payload["decision_id"]), projection_run_id, str(payload["conflict_id"])),
        )
    elif schema == "BLACKBOARD_CONFLICT_RESOLVED_V1":
        conflict_id = payload.get("conflict_id")
        if conflict_id is None:
            row = connection.execute(
                """
                SELECT conflict_id FROM blackboard_conflicts
                WHERE run_id=? AND document_id=? AND conflict_state!='RESOLVED'
                ORDER BY opened_position DESC LIMIT 1
                """,
                (projection_run_id, str(payload["document_id"])),
            ).fetchone()
            conflict_id = row[0] if row is not None else f"legacy-blackboard-conflict-resolution-{event.position}"
        resolved_hash = payload.get("resolved_hash")
        if resolved_hash is None:
            row = connection.execute(
                "SELECT current_hash FROM blackboard_documents WHERE run_id=? AND document_id=?",
                (projection_run_id, str(payload["document_id"])),
            ).fetchone()
            resolved_hash = row[0] if row is not None else str(payload.get("fact_hash", "0" * 64))
        connection.execute(
            """
            UPDATE blackboard_conflicts
            SET conflict_state='RESOLVED',decision_id=?,resolved_version=?,resolved_hash=?,resolved_position=?
            WHERE run_id=? AND conflict_id=?
            """,
            (
                str(payload.get("decision_id", payload.get("fact_hash", f"legacy-decision-{event.position}"))),
                int(payload["resolved_version"]), str(resolved_hash), event.position,
                projection_run_id, str(conflict_id),
            ),
        )
    elif schema == "BLACKBOARD_PATCH_COMMITTED_V1":
        document_id = str(payload["document_id"])
        committed_version = int(payload["committed_version"])
        committed_hash = str(payload["committed_hash"])
        connection.execute(
            """
            INSERT INTO blackboard_versions(
              run_id,document_id,version,document_hash,base_version,base_hash,patch_ref,patch_hash,
              writer_agent_id,writer_fence,resolution_conflict_id,source_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, document_id, committed_version, committed_hash,
                int(payload["base_version"]), str(payload["base_hash"]), payload.get("patch_ref"),
                str(payload.get("patch_hash", payload.get("fact_hash", payload.get("patch_commitment", "0" * 64)))),
                str(payload.get("writer_agent_id", payload.get("actor_id"))),
                str(payload.get("writer_fence", payload.get("fencing_token"))),
                payload.get("resolution_conflict_id"), event.position,
            ),
        )
        connection.execute(
            """
            UPDATE blackboard_documents
            SET current_version=?,current_hash=?,last_position=?,last_writer_id=?,object_ref=?
            WHERE run_id=? AND document_id=?
            """,
            (
                committed_version, committed_hash, event.position,
                str(payload.get("writer_agent_id", payload.get("actor_id"))), payload.get("patch_ref"),
                projection_run_id, document_id,
            ),
        )
    elif schema == "TASK_CREATED_V1" and payload.get("task_id") is not None:
        connection.execute(
            """
            INSERT OR IGNORE INTO task_runtime(
              run_id,task_id,specification_hash,task_state,stream_version,active_attempt_id,
              holder_agent_id,claim_generation,lease_id,expires_at,fencing_token,
              accepted_artifact_hash,created_position,last_position
            ) VALUES(?,?,?,'OPEN',1,NULL,NULL,0,NULL,NULL,NULL,NULL,?,?)
            """,
            (projection_run_id, str(payload["task_id"]), payload.get("specification_hash"), event.position, event.position),
        )
    elif schema == "TASK_CLAIMED_V1" and payload.get("task_id") is not None:
        task_id = str(payload["task_id"])
        attempt_id = str(payload.get("task_attempt_id", payload.get("attempt_id")))
        holder = payload.get("holder_agent_id")
        if not isinstance(holder, str) or not holder:
            legacy_holders = payload.get("holder_agent_ids")
            if isinstance(legacy_holders, list) and legacy_holders and all(
                isinstance(value, str) and value for value in legacy_holders
            ):
                holder = "legacy-multi-holder[" + ",".join(sorted(set(legacy_holders))) + "]"
            else:
                holder = "legacy-holder[" + str(payload.get("actor_id", "unknown")) + "]"
        holder_agent_id = holder
        claim_generation = int(payload["claim_generation"])
        lease = payload.get("lease_id")
        if not isinstance(lease, str) or not lease:
            lease = "legacy-lease-" + str(payload.get("fact_hash", event.event_hash))[:40]
        lease_id = lease
        expires_at = str(payload.get("expires_at", payload.get("lease_expires_at")))
        fencing_token = str(payload["fencing_token"])
        stream_version = int(payload.get("committed_stream_version", payload.get("expected_stream_version", 1) + 1))
        connection.execute(
            """
            INSERT OR IGNORE INTO task_runtime(
              run_id,task_id,specification_hash,task_state,stream_version,active_attempt_id,
              holder_agent_id,claim_generation,lease_id,expires_at,fencing_token,
              accepted_artifact_hash,created_position,last_position
            ) VALUES(?,?,NULL,'OPEN',1,NULL,NULL,0,NULL,NULL,NULL,NULL,?,?)
            """,
            (projection_run_id, task_id, event.position, event.position),
        )
        connection.execute(
            """
            INSERT INTO task_attempts(
              run_id,task_id,task_attempt_id,holder_agent_id,claim_generation,lease_id,expires_at,
              fencing_token,attempt_state,submitted_artifact_hash,accepted_by,claim_position,terminal_position
            ) VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,?,NULL)
            """,
            (
                projection_run_id, task_id, attempt_id, holder_agent_id, claim_generation, lease_id,
                expires_at, fencing_token, str(payload.get("state", "CLAIMED")), event.position,
            ),
        )
        connection.execute(
            """
            UPDATE task_runtime SET task_state='OPEN',stream_version=?,active_attempt_id=?,holder_agent_id=?,
              claim_generation=?,lease_id=?,expires_at=?,fencing_token=?,last_position=?
            WHERE run_id=? AND task_id=?
            """,
            (
                stream_version, attempt_id, holder_agent_id, claim_generation, lease_id, expires_at,
                fencing_token, event.position, projection_run_id, task_id,
            ),
        )
    elif schema == "TASK_CLAIM_REJECTED_V1" and payload.get("task_id") is not None:
        connection.execute(
            """
            INSERT INTO task_claim_rejections(
              run_id,rejection_id,task_id,rejected_holder_agent_id,reason_code,
              expected_stream_version,actual_stream_version,source_position
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["rejection_id"]), str(payload["task_id"]),
                str(payload["rejected_holder_agent_id"]), str(payload["reason_code"]),
                int(payload["expected_stream_version"]), int(payload["actual_stream_version"]), event.position,
            ),
        )
    elif schema == "TASK_LEASE_RENEWED_V1" and payload.get("task_id") is not None:
        connection.execute(
            """UPDATE task_attempts SET expires_at=?
               WHERE run_id=? AND task_id=? AND task_attempt_id=?""",
            (
                str(payload["expires_at"]), projection_run_id, str(payload["task_id"]),
                str(payload.get("task_attempt_id", payload.get("attempt_id"))),
            ),
        )
        connection.execute(
            """UPDATE task_runtime SET stream_version=?,expires_at=?,last_position=?
               WHERE run_id=? AND task_id=?""",
            (
                int(payload["committed_stream_version"]), str(payload["expires_at"]), event.position,
                projection_run_id, str(payload["task_id"]),
            ),
        )
    elif schema in {"TASK_LEASE_EXPIRED_V1", "TASK_CLAIM_EXPIRED_V1", "TASK_LEASE_RELEASED_V1", "TASK_ATTEMPT_FAILED_V1"} and payload.get("task_id") is not None:
        state = {
            "TASK_LEASE_EXPIRED_V1": "EXPIRED",
            "TASK_CLAIM_EXPIRED_V1": "EXPIRED",
            "TASK_LEASE_RELEASED_V1": "RELEASED",
            "TASK_ATTEMPT_FAILED_V1": "FAILED",
        }[schema]
        attempt_id = str(payload.get("task_attempt_id", payload.get("attempt_id")))
        connection.execute(
            """UPDATE task_attempts SET attempt_state=?,terminal_position=?
               WHERE run_id=? AND task_id=? AND task_attempt_id=?""",
            (state, event.position, projection_run_id, str(payload["task_id"]), attempt_id),
        )
        connection.execute(
            """UPDATE task_runtime SET stream_version=?,active_attempt_id=NULL,holder_agent_id=NULL,
                 lease_id=NULL,expires_at=NULL,fencing_token=NULL,last_position=?
               WHERE run_id=? AND task_id=?""",
            (
                int(payload.get("committed_stream_version", 0)), event.position,
                projection_run_id, str(payload["task_id"]),
            ),
        )
    elif schema == "TASK_RESULT_SUBMITTED_V1" and payload.get("task_id") is not None:
        attempt_id = str(payload.get("task_attempt_id", payload.get("attempt_id")))
        connection.execute(
            """UPDATE task_attempts SET attempt_state='SUBMITTED',submitted_artifact_hash=?
               WHERE run_id=? AND task_id=? AND task_attempt_id=?""",
            (str(payload["artifact_hash"]), projection_run_id, str(payload["task_id"]), attempt_id),
        )
        connection.execute(
            """UPDATE task_runtime SET stream_version=?,last_position=? WHERE run_id=? AND task_id=?""",
            (
                int(payload.get("committed_stream_version", 0)), event.position,
                projection_run_id, str(payload["task_id"]),
            ),
        )
    elif schema == "TASK_RESULT_ACCEPTED_V1" and payload.get("task_id") is not None:
        attempt_id = str(payload.get("task_attempt_id", payload.get("attempt_id")))
        connection.execute(
            """UPDATE task_attempts SET attempt_state='ACCEPTED',accepted_by=?,terminal_position=?
               WHERE run_id=? AND task_id=? AND task_attempt_id=?""",
            (
                str(payload.get("accepted_by", payload.get("actor_id", "acceptance-authority"))), event.position,
                projection_run_id, str(payload["task_id"]), attempt_id,
            ),
        )
        connection.execute(
            """
            UPDATE task_runtime SET task_state='COMPLETED',stream_version=?,active_attempt_id=NULL,
              holder_agent_id=NULL,lease_id=NULL,expires_at=NULL,fencing_token=NULL,
              accepted_artifact_hash=?,last_position=? WHERE run_id=? AND task_id=?
            """,
            (
                int(payload.get("committed_stream_version", 0)), str(payload["artifact_hash"]), event.position,
                projection_run_id, str(payload["task_id"]),
            ),
        )
    elif schema == "CONTROLLED_PROVIDER_WORKER_LOSS_V1" and payload.get("effect_id") is not None:
        connection.execute(
            """
            INSERT OR REPLACE INTO provider_recovery_attempts(
              run_id,effect_id,effect_attempt_id,path,agent_id,task_attempt_id,idempotency_identity,
              physical_send_count,outcome_state,settlement_state,settlement_basis,
              unresolved_exposure_count,observation_id,usage_settled,retry_count,fallback_count,
              source_position,last_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["effect_id"]), str(payload["effect_attempt_id"]),
                "TIMEOUT_AFTER_INVOCATION_STARTED" if bool(payload.get("invocation_started")) else "PRE_SEND_FAILURE",
                payload.get("agent_id"), payload.get("task_attempt_id"), payload.get("idempotency_identity"),
                int(payload.get("physical_send_count", 0)), str(payload.get("outcome_state", "NOT_SENT")),
                str(payload.get("settlement_state", "OPEN")), payload.get("settlement_basis"),
                int(payload.get("unresolved_transmission_exposure_count", 0)),
                int(bool(payload.get("usage_settled", False))), int(payload.get("http_retry_count", 0)),
                0, event.position, event.position,
            ),
        )
    elif schema == "PROVIDER_EXPLICIT_REMOTE_FAILURE_OBSERVED_V1" and payload.get("effect_id") is not None:
        connection.execute(
            """
            INSERT OR REPLACE INTO provider_recovery_attempts(
              run_id,effect_id,effect_attempt_id,path,agent_id,task_attempt_id,idempotency_identity,
              physical_send_count,outcome_state,settlement_state,settlement_basis,
              unresolved_exposure_count,observation_id,usage_settled,retry_count,fallback_count,
              source_position,last_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["effect_id"]), str(payload["effect_attempt_id"]),
                "EXPLICIT_REMOTE_FAILURE", payload.get("agent_id"), payload.get("task_attempt_id"),
                payload.get("idempotency_identity"), int(payload.get("physical_send_count", 0)),
                str(payload.get("outcome_state", "FAILED_CONFIRMED")),
                str(payload.get("settlement_state", "SETTLED")), payload.get("settlement_basis"),
                int(payload.get("unresolved_transmission_exposure_count", 0)), payload.get("observation_id"),
                int(bool(payload.get("usage_settled", False))), int(payload.get("http_retry_count", 0)),
                0, event.position, event.position,
            ),
        )
    elif schema == "PROVIDER_ACK_LOST_OUTCOME_UNKNOWN_V1" and payload.get("effect_id") is not None:
        connection.execute(
            """
            INSERT OR REPLACE INTO provider_recovery_attempts(
              run_id,effect_id,effect_attempt_id,path,agent_id,task_attempt_id,idempotency_identity,
              physical_send_count,outcome_state,settlement_state,settlement_basis,
              unresolved_exposure_count,observation_id,usage_settled,retry_count,fallback_count,
              source_position,last_position
            ) VALUES(?,?,?,'ACK_LOST_AFTER_REMOTE_SUCCESS',?,NULL,NULL,1,?,?,NULL,1,NULL,0,0,0,?,?)
            """,
            (
                projection_run_id, str(payload["effect_id"]), str(payload["effect_attempt_id"]),
                payload.get("agent_id", payload.get("actor_id")),
                str(payload.get("outcome_state", "OUTCOME_UNKNOWN")),
                str(payload.get("settlement_state", "RECONCILING")), event.position, event.position,
            ),
        )
    elif schema == "EFFECT_RECONCILIATION_SETTLED_V1" and payload.get("effect_id") is not None:
        state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
        connection.execute(
            """
            UPDATE provider_recovery_attempts SET
              outcome_state=COALESCE(?,outcome_state),settlement_state=COALESCE(?,settlement_state),
              settlement_basis=COALESCE(?,settlement_basis),unresolved_exposure_count=COALESCE(?,unresolved_exposure_count),
              usage_settled=1,last_position=?
            WHERE run_id=? AND effect_id=? AND effect_attempt_id=?
            """,
            (
                state.get("outcome_state"), state.get("settlement_state"), state.get("settlement_basis"),
                state.get("unresolved_transmission_exposure_count"), event.position, projection_run_id,
                str(payload["effect_id"]), str(payload["effect_attempt_id"]),
            ),
        )
    elif schema == "PROVIDER_UNKNOWN_POLICY_DISPOSITION_V1" and payload.get("effect_id") is not None:
        state = payload.get("state") if isinstance(payload.get("state"), dict) else {}
        connection.execute(
            """
            UPDATE provider_recovery_attempts SET outcome_state=?,settlement_state=?,settlement_basis=?,
              unresolved_exposure_count=?,usage_settled=1,last_position=?
            WHERE run_id=? AND effect_id=? AND effect_attempt_id=?
            """,
            (
                str(state.get("outcome_state", "OUTCOME_UNKNOWN")),
                str(state.get("settlement_state", "SETTLED")),
                str(state.get("settlement_basis", "POLICY_DISPOSITION")),
                int(state.get("unresolved_transmission_exposure_count", 1)), event.position,
                projection_run_id, str(payload["effect_id"]), str(payload["effect_attempt_id"]),
            ),
        )
    elif schema == "PROVIDER_RECOVERY_ACK_LOST_VERIFIED_V1" and payload.get("effect_id") is not None:
        connection.execute(
            """UPDATE provider_recovery_attempts SET outcome_state='SUCCEEDED',settlement_state='SETTLED',
                 settlement_basis='AUTHORITATIVE_REMOTE_OBSERVATION',unresolved_exposure_count=0,
                 usage_settled=1,last_position=?
               WHERE run_id=? AND effect_id=? AND effect_attempt_id=?""",
            (event.position, projection_run_id, str(payload["effect_id"]), str(payload["effect_attempt_id"])),
        )
    elif schema == "PROVIDER_RECOVERY_MATRIX_COMPLETED_V1" and payload.get("protocol_id") is not None:
        connection.execute(
            """
            INSERT OR REPLACE INTO provider_recovery_runtime(
              run_id,protocol_id,task_id,recovery_state,pre_send_effect_id,timeout_effect_id,
              explicit_failure_effect_id,ack_lost_effect_id,initial_decision_id,reassignment_decision_id,
              prior_owner_id,new_owner_id,prior_attempt_id,new_attempt_id,
              terminal_blocking_exposure_count,unsettled_usage_count,completed_position
            ) VALUES(?,?,?,'RECOVERED_AND_REASSIGNED',?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["protocol_id"]), str(payload["task_id"]),
                str(payload["pre_send_effect_id"]), str(payload["timeout_effect_id"]),
                str(payload["explicit_failure_effect_id"]), str(payload["ack_lost_effect_id"]),
                str(payload["initial_decision_id"]), str(payload["reassignment_decision_id"]),
                str(payload["prior_owner_id"]), str(payload["new_owner_id"]),
                str(payload["prior_attempt_id"]), str(payload["new_attempt_id"]),
                int(payload.get("terminal_blocking_exposure_count", 0)),
                int(payload.get("unsettled_usage_count", 0)), event.position,
            ),
        )
    elif schema == "TASK_STALE_FENCE_REJECTED_V1" and payload.get("task_id") is not None:
        connection.execute(
            """
            INSERT INTO task_stale_fence_rejections(
              run_id,rejection_id,task_id,stale_attempt_id,current_attempt_id,artifact_hash,
              business_state_committed,source_position
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                projection_run_id, str(payload["rejection_id"]), str(payload["task_id"]),
                payload.get("stale_attempt_id"), payload.get("current_attempt_id"),
                str(payload["artifact_hash"]), int(bool(payload.get("business_state_committed"))), event.position,
            ),
        )
    elif schema == "HANDOFF_CONTRACT_FROZEN_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        contract_hash = str(payload["contract_hash"])
        input_freeze_hash = str(payload.get("input_freeze_hash", contract_hash))
        output_schema_hash = str(payload.get("output_schema_hash", contract_hash))
        max_generations = int(payload.get("max_generations", 3))
        connection.execute(
            """
            INSERT OR REPLACE INTO handoff_generations(
              run_id,handoff_id,generation,generation_hash,generation_state,sender_id,receiver_id,task_id,
              contract_hash,contract_object_ref,previous_generation_hash,previous_generation_ref,
              previous_rejection_event_ref,reject_reason_resolution_hash,input_freeze_hash,output_schema_hash,
              capability_hash,max_generations,accepted_by,task_claim_ref,task_attempt_id,claim_generation,
              lease_id,fencing_token,artifact_hash,schema_validation_evidence_hash,verifier_id,
              verification_evidence_hash,opened_position,closed_position
            ) VALUES(?,?,?,NULL,'FROZEN',?,?,?,?,?,?,?,?,NULL,?,?,NULL,?,NULL,?,NULL,NULL,NULL,?,NULL,NULL,NULL,NULL,?,NULL)
            """,
            (
                projection_run_id, handoff_id, generation, payload.get("sender_id", payload.get("from_agent")),
                payload.get("receiver_id", payload.get("to_agent")), payload.get("task_id"), contract_hash,
                payload.get("contract_object_ref"), payload.get("previous_generation_hash"),
                payload.get("previous_generation_ref"), payload.get("previous_rejection_event_ref"),
                input_freeze_hash, output_schema_hash, max_generations, payload.get("task_claim_ref"),
                payload.get("fencing_token"), event.position,
            ),
        )
        connection.execute(
            """
            INSERT INTO handoff_runtime(
              run_id,handoff_id,current_generation,handoff_state,sender_id,receiver_id,task_id,max_generations,
              current_contract_hash,input_freeze_hash,output_schema_hash,current_task_attempt_id,
              current_fencing_token,current_artifact_hash,verifier_id,created_position,last_position
            ) VALUES(?,?,?,'FROZEN',?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,?)
            ON CONFLICT(run_id,handoff_id) DO UPDATE SET
              current_generation=excluded.current_generation,handoff_state='FROZEN',sender_id=excluded.sender_id,
              receiver_id=excluded.receiver_id,task_id=excluded.task_id,max_generations=excluded.max_generations,
              current_contract_hash=excluded.current_contract_hash,input_freeze_hash=excluded.input_freeze_hash,
              output_schema_hash=excluded.output_schema_hash,current_task_attempt_id=NULL,
              current_fencing_token=NULL,current_artifact_hash=NULL,verifier_id=NULL,last_position=excluded.last_position
            """,
            (
                projection_run_id, handoff_id, generation, payload.get("sender_id", payload.get("from_agent")),
                payload.get("receiver_id", payload.get("to_agent")), payload.get("task_id"), max_generations,
                contract_hash, input_freeze_hash, output_schema_hash, event.position, event.position,
            ),
        )
    elif schema == "HANDOFF_OFFERED_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_hash=?,generation_state='OFFERED',capability_hash=?
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                payload.get("generation_hash"), payload.get("capability_hash"), projection_run_id,
                handoff_id, generation,
            ),
        )
        connection.execute(
            """UPDATE handoff_runtime SET handoff_state='OFFERED',last_position=?
               WHERE run_id=? AND handoff_id=?""",
            (event.position, projection_run_id, handoff_id),
        )
    elif schema == "HANDOFF_REJECTED_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_state='REJECTED',closed_position=?
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (event.position, projection_run_id, handoff_id, generation),
        )
        connection.execute(
            "UPDATE handoff_runtime SET handoff_state='REJECTED',last_position=? WHERE run_id=? AND handoff_id=?",
            (event.position, projection_run_id, handoff_id),
        )
    elif schema in {"HANDOFF_GENERATION_CLOSED_V1", "HANDOFF_REJECTED_GENERATION_CLOSED_V1"} and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload.get("generation", payload.get("closed_generation")))
        state = "SUPERSEDED" if schema == "HANDOFF_GENERATION_CLOSED_V1" else "REJECTED"
        connection.execute(
            """UPDATE handoff_generations SET generation_state=?,closed_position=COALESCE(closed_position,?)
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (state, event.position, projection_run_id, handoff_id, generation),
        )
        connection.execute(
            "UPDATE handoff_runtime SET handoff_state=?,last_position=? WHERE run_id=? AND handoff_id=?",
            (state, event.position, projection_run_id, handoff_id),
        )
    elif schema == "HANDOFF_RECEIVER_CAPABILITY_REVALIDATED_V1" and payload.get("handoff_id") is not None:
        connection.execute(
            """UPDATE handoff_generations SET capability_hash=?
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                payload.get("capability_hash"), projection_run_id, str(payload["handoff_id"]),
                int(payload["generation"]),
            ),
        )
    elif schema in {"HANDOFF_GENERATION_OPENED_V1", "HANDOFF_GENERATION_OPENED_V2"} and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_hash=?,generation_state='OFFERED',capability_hash=?,
                 previous_generation_hash=COALESCE(previous_generation_hash,?),
                 reject_reason_resolution_hash=COALESCE(reject_reason_resolution_hash,?)
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                payload.get("generation_hash"), payload.get("capability_hash"),
                payload.get("previous_generation_hash", payload.get("prior_generation_hash")),
                payload.get("reject_reason_resolution_hash"), projection_run_id, handoff_id, generation,
            ),
        )
        prior_generation = payload.get("prior_generation")
        prior_hash = payload.get("prior_generation_hash")
        if prior_generation is not None and prior_hash is not None:
            connection.execute(
                """
                INSERT OR REPLACE INTO handoff_generation_lineage(
                  run_id,handoff_id,generation,prior_generation,prior_generation_hash,prior_terminal_state,
                  previous_generation_permanently_closed,old_acceptance_reused,source_position
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    projection_run_id, handoff_id, generation, int(prior_generation), str(prior_hash),
                    str(payload.get("prior_terminal_state", "REJECTED")),
                    int(bool(payload.get("previous_generation_permanently_closed", True))),
                    int(bool(payload.get("old_acceptance_reused", False))), event.position,
                ),
            )
        connection.execute(
            """UPDATE handoff_runtime SET current_generation=?,handoff_state='OFFERED',last_position=?
               WHERE run_id=? AND handoff_id=?""",
            (generation, event.position, projection_run_id, handoff_id),
        )
    elif schema == "HANDOFF_ACCEPTED_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        accepted_by = payload.get("receiver_id")
        connection.execute(
            """UPDATE handoff_generations SET generation_state='ACCEPTED',accepted_by=?
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (accepted_by, projection_run_id, handoff_id, generation),
        )
        connection.execute(
            "UPDATE handoff_runtime SET handoff_state='ACCEPTED',last_position=? WHERE run_id=? AND handoff_id=?",
            (event.position, projection_run_id, handoff_id),
        )
    elif schema == "HANDOFF_CLAIM_PENDING_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_state='CLAIM_PENDING',task_claim_ref=?,fencing_token=?
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                payload.get("task_claim_ref"), payload.get("reserved_fencing_token"), projection_run_id,
                handoff_id, generation,
            ),
        )
        connection.execute(
            """UPDATE handoff_runtime SET handoff_state='CLAIM_PENDING',current_fencing_token=?,last_position=?
               WHERE run_id=? AND handoff_id=?""",
            (payload.get("reserved_fencing_token"), event.position, projection_run_id, handoff_id),
        )
    elif schema == "HANDOFF_TASK_CLAIM_BOUND_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_state='CLAIMED',task_attempt_id=?,claim_generation=?,
                 lease_id=?,fencing_token=? WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                payload.get("task_attempt_id"), payload.get("claim_generation"), payload.get("lease_id"),
                payload.get("fencing_token"), projection_run_id, handoff_id, generation,
            ),
        )
        connection.execute(
            """UPDATE handoff_runtime SET handoff_state='CLAIMED',current_task_attempt_id=?,
                 current_fencing_token=?,last_position=? WHERE run_id=? AND handoff_id=?""",
            (
                payload.get("task_attempt_id"), payload.get("fencing_token"), event.position,
                projection_run_id, handoff_id,
            ),
        )
    elif schema == "HANDOFF_EXECUTION_STARTED_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            "UPDATE handoff_generations SET generation_state='EXECUTING' WHERE run_id=? AND handoff_id=? AND generation=?",
            (projection_run_id, handoff_id, generation),
        )
        connection.execute(
            "UPDATE handoff_runtime SET handoff_state='EXECUTING',last_position=? WHERE run_id=? AND handoff_id=?",
            (event.position, projection_run_id, handoff_id),
        )
    elif schema == "HANDOFF_RESULT_SUBMITTED_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_state='SUBMITTED',artifact_hash=?,
                 schema_validation_evidence_hash=? WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                payload.get("artifact_hash"), payload.get("schema_validation_evidence_hash"),
                projection_run_id, handoff_id, generation,
            ),
        )
        connection.execute(
            """UPDATE handoff_runtime SET handoff_state='SUBMITTED',current_artifact_hash=?,last_position=?
               WHERE run_id=? AND handoff_id=?""",
            (payload.get("artifact_hash"), event.position, projection_run_id, handoff_id),
        )
    elif schema in {"HANDOFF_VERIFIED_V1", "HANDOFF_REWORK_REQUIRED_V1"} and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        state = "VERIFIED" if schema == "HANDOFF_VERIFIED_V1" else "REWORK"
        connection.execute(
            """UPDATE handoff_generations SET generation_state=?,verifier_id=?,verification_evidence_hash=?,
                 closed_position=CASE WHEN ?='VERIFIED' THEN ? ELSE closed_position END
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (
                state, payload.get("verifier_id"), payload.get("verification_evidence_hash"), state,
                event.position, projection_run_id, handoff_id, generation,
            ),
        )
        connection.execute(
            """UPDATE handoff_runtime SET handoff_state=?,verifier_id=?,current_artifact_hash=?,last_position=?
               WHERE run_id=? AND handoff_id=?""",
            (
                state, payload.get("verifier_id"), payload.get("artifact_hash"), event.position,
                projection_run_id, handoff_id,
            ),
        )
    elif schema == "HANDOFF_GENERATION_LIMIT_REACHED_V1" and payload.get("handoff_id") is not None:
        handoff_id = str(payload["handoff_id"])
        generation = int(payload["generation"])
        connection.execute(
            """UPDATE handoff_generations SET generation_state='FAILED_GENERATION_LIMIT',closed_position=?
               WHERE run_id=? AND handoff_id=? AND generation=?""",
            (event.position, projection_run_id, handoff_id, generation),
        )
        connection.execute(
            """UPDATE handoff_runtime SET handoff_state='FAILED_GENERATION_LIMIT',last_position=?
               WHERE run_id=? AND handoff_id=?""",
            (event.position, projection_run_id, handoff_id),
        )
    elif schema == "CHECKPOINT_MANIFEST_PUBLISHED_V1":
        connection.execute(
            """
            INSERT INTO checkpoint_resume_runtime(
              run_id,checkpoint_id,frontier_kind,checkpoint_state,validated_through_position,
              checkpoint_position,manifest_ref,manifest_hash,old_process_pid,new_process_pid,
              pre_restart_head,post_restart_head,pending_command_id,provider_send_count_before,
              provider_send_count_after,duplicate_provider_send_count,restored_protocol_state,
              restored_lease_id,restored_fencing_token_hash,restored_blackboard_version,
              restored_blackboard_hash,resume_event_id,frontier_terminal_event_id,opened_position,
              completed_position
            ) VALUES(?,?,?,'MANIFEST_PUBLISHED',?,?,?,?,?,NULL,NULL,NULL,?,?,NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,NULL)
            ON CONFLICT(run_id,checkpoint_id) DO UPDATE SET
              frontier_kind=excluded.frontier_kind,checkpoint_state='MANIFEST_PUBLISHED',
              validated_through_position=excluded.validated_through_position,
              checkpoint_position=excluded.checkpoint_position,manifest_ref=excluded.manifest_ref,
              manifest_hash=excluded.manifest_hash,old_process_pid=excluded.old_process_pid,
              pending_command_id=excluded.pending_command_id,
              provider_send_count_before=excluded.provider_send_count_before
            """,
            (
                projection_run_id,
                str(payload["checkpoint_id"]),
                str(payload["frontier_kind"]),
                int(payload["validated_through_position"]),
                event.position,
                str(payload["manifest_ref"]),
                str(payload["manifest_hash"]),
                int(payload["old_process_pid"]),
                str(payload["pending_command_id"]),
                int(payload.get("provider_send_count_before", 0)),
                event.position,
            ),
        )
    elif schema == "CHECKPOINT_RUNTIME_STOPPED_V1":
        connection.execute(
            """UPDATE checkpoint_resume_runtime SET checkpoint_state='RUNTIME_STOPPED',
                 old_process_pid=?,pre_restart_head=? WHERE run_id=? AND checkpoint_id=?""",
            (
                int(payload["old_process_pid"]),
                event.position,
                projection_run_id,
                str(payload["checkpoint_id"]),
            ),
        )
    elif schema == "CHECKPOINT_PROCESS_RECONSTRUCTED_V1":
        connection.execute(
            """UPDATE checkpoint_resume_runtime SET checkpoint_state='PROCESS_RECONSTRUCTED',
                 new_process_pid=?,pending_command_id=?,restored_protocol_state=?,restored_lease_id=?,
                 restored_fencing_token_hash=?,restored_blackboard_version=?,restored_blackboard_hash=?
               WHERE run_id=? AND checkpoint_id=?""",
            (
                int(payload["new_process_pid"]),
                str(payload["pending_command_id"]),
                payload.get("restored_protocol_state"),
                payload.get("restored_lease_id"),
                payload.get("restored_fencing_token_hash"),
                payload.get("restored_blackboard_version"),
                payload.get("restored_blackboard_hash"),
                projection_run_id,
                str(payload["checkpoint_id"]),
            ),
        )
    elif schema == "CHECKPOINT_RESUME_COMPLETED_V1":
        connection.execute(
            """UPDATE checkpoint_resume_runtime SET checkpoint_state='RESUMED_AND_CONTINUED',
                 new_process_pid=?,pre_restart_head=?,post_restart_head=?,pending_command_id=?,
                 provider_send_count_before=?,provider_send_count_after=?,duplicate_provider_send_count=?,
                 restored_protocol_state=?,restored_lease_id=?,restored_fencing_token_hash=?,
                 restored_blackboard_version=?,restored_blackboard_hash=?,resume_event_id=?,
                 frontier_terminal_event_id=?,completed_position=?
               WHERE run_id=? AND checkpoint_id=?""",
            (
                int(payload["new_process_pid"]),
                int(payload["pre_restart_head"]),
                int(payload["post_restart_head"]),
                str(payload["pending_command_id"]),
                int(payload["provider_send_count_before"]),
                int(payload["provider_send_count_after"]),
                int(payload["duplicate_provider_send_count"]),
                payload.get("restored_protocol_state"),
                payload.get("restored_lease_id"),
                payload.get("restored_fencing_token_hash"),
                payload.get("restored_blackboard_version"),
                payload.get("restored_blackboard_hash"),
                payload.get("resume_event_id"),
                payload.get("frontier_terminal_event_id"),
                event.position,
                projection_run_id,
                str(payload["checkpoint_id"]),
            ),
        )
    elif schema == "CHECKPOINT_RESUME_MATRIX_COMPLETED_V1":
        connection.execute(
            """
            INSERT INTO checkpoint_resume_matrix(
              run_id,checkpoint_count,frontier_kinds_json,checkpoint_ids_json,old_process_pid,
              new_process_pids_json,distinct_process_boundaries,provider_send_count_before,
              provider_send_count_after,duplicate_provider_send_count,same_pending_command_ids,
              journal_identity_preserved,projection_used_for_resume,process_cache_used_for_resume,
              legacy_reads,acceptance_reads,completed_position
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id) DO UPDATE SET
              checkpoint_count=excluded.checkpoint_count,frontier_kinds_json=excluded.frontier_kinds_json,
              checkpoint_ids_json=excluded.checkpoint_ids_json,old_process_pid=excluded.old_process_pid,
              new_process_pids_json=excluded.new_process_pids_json,
              distinct_process_boundaries=excluded.distinct_process_boundaries,
              provider_send_count_before=excluded.provider_send_count_before,
              provider_send_count_after=excluded.provider_send_count_after,
              duplicate_provider_send_count=excluded.duplicate_provider_send_count,
              same_pending_command_ids=excluded.same_pending_command_ids,
              journal_identity_preserved=excluded.journal_identity_preserved,
              projection_used_for_resume=excluded.projection_used_for_resume,
              process_cache_used_for_resume=excluded.process_cache_used_for_resume,
              legacy_reads=excluded.legacy_reads,acceptance_reads=excluded.acceptance_reads,
              completed_position=excluded.completed_position
            """,
            (
                projection_run_id,
                int(payload["checkpoint_count"]),
                json.dumps(payload["frontier_kinds"], sort_keys=True, separators=(",", ":")),
                json.dumps(payload["checkpoint_ids"], sort_keys=True, separators=(",", ":")),
                int(payload["old_process_pid"]),
                json.dumps(payload["new_process_pids"], sort_keys=True, separators=(",", ":")),
                int(bool(payload["distinct_process_boundaries"])),
                int(payload["provider_send_count_before"]),
                int(payload["provider_send_count_after"]),
                int(payload["duplicate_provider_send_count"]),
                int(bool(payload["same_pending_command_ids"])),
                int(bool(payload["journal_identity_preserved"])),
                int(bool(payload["projection_used_for_resume"])),
                int(bool(payload["process_cache_used_for_resume"])),
                int(payload["legacy_reads"]),
                int(payload["acceptance_reads"]),
                event.position,
            ),
        )


def production_handlers() -> dict[str, object]:
    return {"*": apply_production_event}
