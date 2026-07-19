from __future__ import annotations

import os
import sqlite3
from pathlib import Path


class ProjectionError(RuntimeError):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS event_catalog(
  position INTEGER PRIMARY KEY,
  event_hash TEXT NOT NULL UNIQUE,
  stream_id TEXT NOT NULL,
  stream_version INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  segment_id TEXT NOT NULL,
  frame_offset INTEGER NOT NULL,
  UNIQUE(stream_id, stream_version)
);
CREATE TABLE IF NOT EXISTS stream_heads(
  stream_id TEXT PRIMARY KEY,
  last_stream_version INTEGER NOT NULL,
  last_position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS command_outcomes(
  command_id TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  transaction_hash TEXT,
  first_position INTEGER,
  last_position INTEGER
);
CREATE TABLE IF NOT EXISTS projection_offsets(
  projection_name TEXT PRIMARY KEY,
  last_position INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('RUNNING','DEGRADED','FAILED','BLOCKED','INCOMPATIBLE'))
);
CREATE TABLE IF NOT EXISTS projection_metadata(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projection_schema_coverage(
  schema_id TEXT PRIMARY KEY,
  requirement TEXT NOT NULL CHECK(requirement IN ('REQUIRED','OPTIONAL')),
  handler_id TEXT,
  coverage_state TEXT NOT NULL CHECK(coverage_state IN ('HANDLED','DIRECTORY_ONLY','MISSING_REQUIRED'))
);
CREATE TABLE IF NOT EXISTS fixture_values(
  stream_id TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dispatch_outbox(
  decision_id TEXT NOT NULL,
  attempt_index INTEGER NOT NULL,
  task_id TEXT NOT NULL,
  claim_command_id TEXT NOT NULL,
  candidate_state TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(decision_id, attempt_index)
);
CREATE TABLE IF NOT EXISTS durable_timer_candidates(
  timer_id TEXT PRIMARY KEY,
  deadline_utc TEXT NOT NULL,
  target_command_id TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  candidate_state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS terminal_eligibility_counts(
  run_id TEXT NOT NULL,
  blocker_kind TEXT NOT NULL,
  blocker_count INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, blocker_kind)
);
CREATE TABLE IF NOT EXISTS protocol_registry(
  protocol_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  protocol_kind TEXT NOT NULL,
  protocol_state TEXT NOT NULL,
  created_position INTEGER NOT NULL,
  terminal_position INTEGER
);
CREATE TABLE IF NOT EXISTS obligation_registry(
  obligation_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  protocol_id TEXT,
  obligation_state TEXT NOT NULL,
  required_for_run_terminal INTEGER NOT NULL,
  created_position INTEGER NOT NULL,
  terminal_position INTEGER
);
CREATE TABLE IF NOT EXISTS event_directory(
  position INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  stream_id TEXT NOT NULL,
  run_id TEXT,
  payload_hash TEXT NOT NULL,
  source_segment TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_state_events(
  position INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  stream_id TEXT NOT NULL,
  stream_version INTEGER NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  object_refs_json TEXT NOT NULL,
  schema_major INTEGER NOT NULL,
  event_hash TEXT,
  journal_auth_key_id TEXT,
  journal_auth_tag TEXT
);
CREATE TABLE IF NOT EXISTS runtime_pending_runs(
  run_id TEXT PRIMARY KEY,
  session_id TEXT,
  turn_index INTEGER,
  terminal_state TEXT,
  created_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_pending_run_events(
  position INTEGER PRIMARY KEY,
  run_id TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  stream_id TEXT NOT NULL,
  stream_version INTEGER NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  object_refs_json TEXT NOT NULL,
  schema_major INTEGER NOT NULL,
  event_hash TEXT,
  journal_auth_key_id TEXT,
  journal_auth_tag TEXT
);
CREATE INDEX IF NOT EXISTS runtime_pending_run_events_run ON runtime_pending_run_events(run_id,position);
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','DELETED')),
  created_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  deleted_position INTEGER,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_messages(
  message_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL,
  turn_index INTEGER NOT NULL,
  body_ref TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS session_messages_session_turn ON session_messages(session_id,turn_index);
CREATE TABLE IF NOT EXISTS session_runs(
  session_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  turn_index INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(session_id,run_id)
);
CREATE TABLE IF NOT EXISTS session_object_refs(
  session_id TEXT NOT NULL,
  object_ref TEXT NOT NULL,
  ref_kind TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(session_id,object_ref,ref_kind)
);
CREATE TABLE IF NOT EXISTS session_working_state(
  session_id TEXT PRIMARY KEY,
  state_ref TEXT NOT NULL,
  state_kind TEXT NOT NULL CHECK(state_kind IN ('BASE','DELTA')),
  state_version INTEGER NOT NULL,
  source_frontier INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_summaries(
  session_id TEXT NOT NULL,
  summary_version INTEGER NOT NULL,
  summary_ref TEXT NOT NULL,
  summary_hash TEXT NOT NULL,
  source_message_start INTEGER NOT NULL,
  source_message_end INTEGER NOT NULL,
  source_frontier INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(session_id,summary_version)
);
CREATE VIEW IF NOT EXISTS active_session_messages AS
  SELECT m.* FROM session_messages m JOIN sessions s ON s.session_id=m.session_id WHERE s.status='ACTIVE';
CREATE VIEW IF NOT EXISTS active_session_runs AS
  SELECT r.* FROM session_runs r JOIN sessions s ON s.session_id=r.session_id WHERE s.status='ACTIVE';
CREATE TABLE IF NOT EXISTS memory_items(
  memory_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  status TEXT NOT NULL,
  content_ref TEXT NOT NULL,
  expires_at TEXT,
  created_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_current(
  memory_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  status TEXT NOT NULL,
  content_ref TEXT NOT NULL,
  expires_at TEXT,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memory_relations(
  memory_id TEXT NOT NULL,
  related_memory_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(memory_id,related_memory_id,relation)
);
CREATE TABLE IF NOT EXISTS memory_episodes(
  episode_id TEXT PRIMARY KEY,
  source_run_id TEXT NOT NULL,
  goal_ref TEXT NOT NULL,
  action_start_position INTEGER NOT NULL,
  action_end_position INTEGER NOT NULL,
  terminal_evidence_ref TEXT NOT NULL,
  lesson_ref TEXT NOT NULL,
  outcome TEXT NOT NULL,
  failure_reason_code TEXT,
  source_frontier INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE VIEW IF NOT EXISTS episodes AS SELECT * FROM memory_episodes;
CREATE TABLE IF NOT EXISTS provider_health(
  profile TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  next_check_at TEXT,
  failure_count INTEGER NOT NULL,
  last_error TEXT,
  model TEXT,
  latency_ms INTEGER,
  source TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE VIEW IF NOT EXISTS provider_health_current AS SELECT * FROM provider_health;
CREATE TABLE IF NOT EXISTS agent_calls(
  call_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  status TEXT NOT NULL,
  context_manifest_ref TEXT,
  rendered_input_hash TEXT,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_status_transitions(
  call_id TEXT NOT NULL,
  status TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(call_id,source_position)
);
CREATE TABLE IF NOT EXISTS tool_calls(
  tool_call_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  exit_code INTEGER,
  result_manifest_ref TEXT NOT NULL,
  captured_bytes INTEGER NOT NULL,
  dropped_bytes INTEGER NOT NULL,
  truncated INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS competition_scores(
  run_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  score REAL NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(run_id,subject_id,source_position)
);
CREATE TABLE IF NOT EXISTS token_usage(
  run_id TEXT NOT NULL,
  call_id TEXT,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  PRIMARY KEY(run_id,source_position)
);
CREATE TABLE IF NOT EXISTS run_checkpoints(
  checkpoint_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  checkpoint_kind TEXT NOT NULL,
  checkpoint_ref TEXT NOT NULL,
  frontier_position INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS run_evidence(
  evidence_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  evidence_ref TEXT NOT NULL,
  checkpoint_ref TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  source_event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bplus_runs(
  run_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  goal_hash TEXT NOT NULL,
  agent_count INTEGER NOT NULL,
  created_position INTEGER NOT NULL,
  terminal_position INTEGER
);
CREATE TABLE IF NOT EXISTS blackboard_documents(
  run_id TEXT NOT NULL,
  document_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  schema_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  current_version INTEGER NOT NULL,
  current_hash TEXT NOT NULL,
  classification TEXT NOT NULL,
  writer_policy_hash TEXT NOT NULL,
  merge_policy_hash TEXT NOT NULL,
  created_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  last_writer_id TEXT,
  object_ref TEXT,
  PRIMARY KEY(run_id, document_id)
);
CREATE TABLE IF NOT EXISTS blackboard_versions(
  run_id TEXT NOT NULL,
  document_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  document_hash TEXT NOT NULL,
  base_version INTEGER,
  base_hash TEXT,
  patch_ref TEXT,
  patch_hash TEXT,
  writer_agent_id TEXT,
  writer_fence TEXT,
  resolution_conflict_id TEXT,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, document_id, version)
);
CREATE TABLE IF NOT EXISTS blackboard_reads(
  run_id TEXT NOT NULL,
  read_id TEXT NOT NULL,
  document_id TEXT NOT NULL,
  reader_agent_id TEXT NOT NULL,
  read_version INTEGER NOT NULL,
  read_hash TEXT NOT NULL,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, read_id)
);
CREATE TABLE IF NOT EXISTS blackboard_conflicts(
  run_id TEXT NOT NULL,
  conflict_id TEXT NOT NULL,
  document_id TEXT NOT NULL,
  conflict_state TEXT NOT NULL,
  attempted_base_version INTEGER NOT NULL,
  attempted_base_hash TEXT NOT NULL,
  canonical_version INTEGER NOT NULL,
  canonical_hash TEXT NOT NULL,
  attempted_patch_hash TEXT NOT NULL,
  merge_id TEXT,
  review_id TEXT,
  decision_id TEXT,
  resolved_version INTEGER,
  resolved_hash TEXT,
  opened_position INTEGER NOT NULL,
  resolved_position INTEGER,
  PRIMARY KEY(run_id, conflict_id)
);
CREATE TABLE IF NOT EXISTS task_runtime(
  run_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  specification_hash TEXT,
  task_state TEXT NOT NULL,
  stream_version INTEGER NOT NULL,
  active_attempt_id TEXT,
  holder_agent_id TEXT,
  claim_generation INTEGER NOT NULL,
  lease_id TEXT,
  expires_at TEXT,
  fencing_token TEXT,
  accepted_artifact_hash TEXT,
  created_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, task_id)
);
CREATE TABLE IF NOT EXISTS task_attempts(
  run_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  task_attempt_id TEXT NOT NULL,
  holder_agent_id TEXT NOT NULL,
  claim_generation INTEGER NOT NULL,
  lease_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  fencing_token TEXT NOT NULL,
  attempt_state TEXT NOT NULL,
  submitted_artifact_hash TEXT,
  accepted_by TEXT,
  claim_position INTEGER NOT NULL,
  terminal_position INTEGER,
  PRIMARY KEY(run_id, task_id, task_attempt_id)
);
CREATE TABLE IF NOT EXISTS task_claim_rejections(
  run_id TEXT NOT NULL,
  rejection_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  rejected_holder_agent_id TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  expected_stream_version INTEGER NOT NULL,
  actual_stream_version INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, rejection_id)
);
CREATE TABLE IF NOT EXISTS task_stale_fence_rejections(
  run_id TEXT NOT NULL,
  rejection_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  stale_attempt_id TEXT,
  current_attempt_id TEXT,
  artifact_hash TEXT NOT NULL,
  business_state_committed INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, rejection_id)
);
CREATE TABLE IF NOT EXISTS handoff_runtime(
  run_id TEXT NOT NULL,
  handoff_id TEXT NOT NULL,
  current_generation INTEGER NOT NULL,
  handoff_state TEXT NOT NULL,
  sender_id TEXT,
  receiver_id TEXT,
  task_id TEXT,
  max_generations INTEGER NOT NULL,
  current_contract_hash TEXT,
  input_freeze_hash TEXT,
  output_schema_hash TEXT,
  current_task_attempt_id TEXT,
  current_fencing_token TEXT,
  current_artifact_hash TEXT,
  verifier_id TEXT,
  created_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, handoff_id)
);
CREATE TABLE IF NOT EXISTS handoff_generations(
  run_id TEXT NOT NULL,
  handoff_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  generation_hash TEXT,
  generation_state TEXT NOT NULL,
  sender_id TEXT,
  receiver_id TEXT,
  task_id TEXT,
  contract_hash TEXT,
  contract_object_ref TEXT,
  previous_generation_hash TEXT,
  previous_generation_ref TEXT,
  previous_rejection_event_ref TEXT,
  reject_reason_resolution_hash TEXT,
  input_freeze_hash TEXT,
  output_schema_hash TEXT,
  capability_hash TEXT,
  max_generations INTEGER NOT NULL,
  accepted_by TEXT,
  task_claim_ref TEXT,
  task_attempt_id TEXT,
  claim_generation INTEGER,
  lease_id TEXT,
  fencing_token TEXT,
  artifact_hash TEXT,
  schema_validation_evidence_hash TEXT,
  verifier_id TEXT,
  verification_evidence_hash TEXT,
  opened_position INTEGER NOT NULL,
  closed_position INTEGER,
  PRIMARY KEY(run_id, handoff_id, generation)
);
CREATE TABLE IF NOT EXISTS handoff_generation_lineage(
  run_id TEXT NOT NULL,
  handoff_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  prior_generation INTEGER NOT NULL,
  prior_generation_hash TEXT NOT NULL,
  prior_terminal_state TEXT NOT NULL,
  previous_generation_permanently_closed INTEGER NOT NULL,
  old_acceptance_reused INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, handoff_id, generation)
);
CREATE TABLE IF NOT EXISTS proposal_rounds(
  run_id TEXT NOT NULL,
  round_id TEXT NOT NULL,
  current_generation INTEGER NOT NULL,
  round_state TEXT NOT NULL,
  rubric_hash TEXT,
  policy_hash TEXT,
  config_hash TEXT,
  minimum_score INTEGER,
  max_revisions INTEGER,
  selected_proposal_id TEXT,
  selected_output_hash TEXT,
  opened_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, round_id)
);
CREATE TABLE IF NOT EXISTS proposal_revisions(
  run_id TEXT NOT NULL,
  round_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  proposal_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  participant_id TEXT,
  body_ref TEXT NOT NULL,
  parent_output_hash TEXT,
  output_hash TEXT,
  input_snapshot_hash TEXT,
  review_id TEXT,
  review_output_hash TEXT,
  old_review_reused INTEGER NOT NULL,
  revision_state TEXT NOT NULL,
  score INTEGER,
  evaluator_id TEXT,
  disposition TEXT,
  source_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, round_id, generation, proposal_id, revision)
);
CREATE TABLE IF NOT EXISTS review_runtime(
  run_id TEXT NOT NULL,
  review_id TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  artifact_author_id TEXT,
  rubric_hash TEXT,
  reviewer_id TEXT,
  verdict TEXT,
  response_ref TEXT,
  response_commitment TEXT,
  disposition TEXT,
  artifact_accepted INTEGER NOT NULL,
  requested_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, review_id)
);
CREATE TABLE IF NOT EXISTS debate_runtime(
  run_id TEXT NOT NULL,
  debate_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  debate_state TEXT NOT NULL,
  max_rounds INTEGER NOT NULL,
  max_tokens INTEGER NOT NULL,
  outcome TEXT,
  synthesis_hash TEXT,
  successor_obligation_id TEXT,
  opened_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, debate_id)
);
CREATE TABLE IF NOT EXISTS debate_responses(
  run_id TEXT NOT NULL,
  debate_id TEXT NOT NULL,
  response_id TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  target_claim_id TEXT NOT NULL,
  actor_id TEXT,
  round_number INTEGER NOT NULL,
  token_count INTEGER NOT NULL,
  body_ref TEXT NOT NULL,
  parent_output_hash TEXT,
  revision_output_hash TEXT,
  revision_call_id TEXT,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, debate_id, response_id)
);
CREATE TABLE IF NOT EXISTS negotiation_decisions(
  run_id TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  round_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  decision TEXT NOT NULL,
  selected_proposal_id TEXT,
  latest_revision_hashes_json TEXT NOT NULL,
  synthesis_candidate_hash TEXT NOT NULL,
  synthesis_hash TEXT NOT NULL,
  fresh_review_ids_json TEXT NOT NULL,
  fresh_review_hashes_json TEXT NOT NULL,
  successor_obligation_id TEXT,
  source_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, decision_id)
);
CREATE TABLE IF NOT EXISTS rework_runtime(
  run_id TEXT NOT NULL,
  rework_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  rework_state TEXT NOT NULL,
  failure_type TEXT NOT NULL,
  acceptance_criteria_hash TEXT NOT NULL,
  max_retries INTEGER NOT NULL,
  retry_count INTEGER NOT NULL,
  current_result_ref TEXT,
  successor_obligation_id TEXT,
  opened_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, rework_id)
);
CREATE TABLE IF NOT EXISTS rework_rounds(
  run_id TEXT NOT NULL,
  rework_id TEXT NOT NULL,
  round_number INTEGER NOT NULL,
  attempt_id TEXT,
  round_state TEXT NOT NULL,
  result_ref TEXT,
  defect_resolution_hash TEXT,
  all_defects_addressed INTEGER,
  started_position INTEGER NOT NULL,
  terminal_position INTEGER,
  PRIMARY KEY(run_id, rework_id, round_number)
);
CREATE TABLE IF NOT EXISTS provider_recovery_attempts(
  run_id TEXT NOT NULL,
  effect_id TEXT NOT NULL,
  effect_attempt_id TEXT NOT NULL,
  path TEXT NOT NULL,
  agent_id TEXT,
  task_attempt_id TEXT,
  idempotency_identity TEXT,
  physical_send_count INTEGER NOT NULL,
  outcome_state TEXT NOT NULL,
  settlement_state TEXT NOT NULL,
  settlement_basis TEXT,
  unresolved_exposure_count INTEGER NOT NULL,
  observation_id TEXT,
  usage_settled INTEGER NOT NULL,
  retry_count INTEGER NOT NULL,
  fallback_count INTEGER NOT NULL,
  source_position INTEGER NOT NULL,
  last_position INTEGER NOT NULL,
  PRIMARY KEY(run_id, effect_id, effect_attempt_id)
);
CREATE TABLE IF NOT EXISTS provider_recovery_runtime(
  run_id TEXT NOT NULL PRIMARY KEY,
  protocol_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  recovery_state TEXT NOT NULL,
  pre_send_effect_id TEXT NOT NULL,
  timeout_effect_id TEXT NOT NULL,
  explicit_failure_effect_id TEXT NOT NULL,
  ack_lost_effect_id TEXT NOT NULL,
  initial_decision_id TEXT NOT NULL,
  reassignment_decision_id TEXT NOT NULL,
  prior_owner_id TEXT NOT NULL,
  new_owner_id TEXT NOT NULL,
  prior_attempt_id TEXT NOT NULL,
  new_attempt_id TEXT NOT NULL,
  terminal_blocking_exposure_count INTEGER NOT NULL,
  unsettled_usage_count INTEGER NOT NULL,
  completed_position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoint_resume_runtime(
  run_id TEXT NOT NULL,
  checkpoint_id TEXT NOT NULL,
  frontier_kind TEXT NOT NULL,
  checkpoint_state TEXT NOT NULL,
  validated_through_position INTEGER NOT NULL,
  checkpoint_position INTEGER,
  manifest_ref TEXT,
  manifest_hash TEXT NOT NULL,
  old_process_pid INTEGER,
  new_process_pid INTEGER,
  pre_restart_head INTEGER,
  post_restart_head INTEGER,
  pending_command_id TEXT,
  provider_send_count_before INTEGER NOT NULL,
  provider_send_count_after INTEGER,
  duplicate_provider_send_count INTEGER NOT NULL,
  restored_protocol_state TEXT,
  restored_lease_id TEXT,
  restored_fencing_token_hash TEXT,
  restored_blackboard_version INTEGER,
  restored_blackboard_hash TEXT,
  resume_event_id TEXT,
  frontier_terminal_event_id TEXT,
  opened_position INTEGER NOT NULL,
  completed_position INTEGER,
  PRIMARY KEY(run_id, checkpoint_id)
);
CREATE TABLE IF NOT EXISTS checkpoint_resume_matrix(
  run_id TEXT PRIMARY KEY,
  checkpoint_count INTEGER NOT NULL,
  frontier_kinds_json TEXT NOT NULL,
  checkpoint_ids_json TEXT NOT NULL,
  old_process_pid INTEGER NOT NULL,
  new_process_pids_json TEXT NOT NULL,
  distinct_process_boundaries INTEGER NOT NULL,
  provider_send_count_before INTEGER NOT NULL,
  provider_send_count_after INTEGER NOT NULL,
  duplicate_provider_send_count INTEGER NOT NULL,
  same_pending_command_ids INTEGER NOT NULL,
  journal_identity_preserved INTEGER NOT NULL,
  projection_used_for_resume INTEGER NOT NULL,
  process_cache_used_for_resume INTEGER NOT NULL,
  legacy_reads INTEGER NOT NULL,
  acceptance_reads INTEGER NOT NULL,
  completed_position INTEGER NOT NULL
);
"""


def open_projection(path: str | os.PathLike[str]) -> sqlite3.Connection:
    raw_path = os.fspath(path)
    in_memory = raw_path == ":memory:"
    candidate = Path(raw_path)
    if not in_memory:
        if candidate.is_symlink():
            raise ProjectionError("projection path may not be a symlink")
        candidate.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(raw_path, isolation_level=None, timeout=5.0)
    if not in_memory:
        os.chmod(candidate, 0o600, follow_symlinks=False)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.executescript(SCHEMA)
    connection.execute(
        "INSERT OR IGNORE INTO projection_offsets(projection_name,last_position,state) VALUES('kernel',0,'RUNNING')"
    )
    return connection
