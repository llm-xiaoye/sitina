#!/usr/bin/env python3
"""Fail-closed validator for the current Step 7 CANARY_READY contract.

This gate is intentionally read-only.  It verifies a candidate and its bound
evidence against the current repository and deployment, but never creates,
copies, quarantines, deletes, deploys, promotes, or enables anything.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


CANDIDATE_SCHEMA = "SITINA_STEP7_REVIEW_CANDIDATE_V1"
READY_MARKER = "SITINA_STEP7_CANARY_READY_V1"
SUMMARY_MARKER = "SITINA_STEP7_GATE_JSON:"
ENTRY_CANDIDATE_SCHEMA = "SITINA_STEP7_ENTRY_REVIEW_CANDIDATE_V1"
ENTRY_CANDIDATE_SHA256 = "acb33c0cde566339a194d850bd83d6bbebc9679b301a1b5246555772ef93fc56"
STEP7_BASE_COMMIT = "45a36be780413f561cf1f8f0d4b8ec80dd3f9416"
STEP7_CHANGED_FILES = (
    "scripts/step7_readiness_gate.py",
    "scripts/test-bplus.py",
    "tests/foundation/activation_gate_runner.py",
    "tests/foundation/registration_gate_runner.py",
    "tests/foundation/test_step7_readiness_gate.py",
    "tests/test_suites.json",
)
APPROVED_PYTHON_PATH = (
    "/Users/moss/Desktop/sitina/bplus-test-runtime/"
    "cpython-3.12.13-lock-dbc3f95b77ed/bin/python"
)
STEP7_AUTHORITY_PATH = (
    "/Users/moss/.codex/attachments/"
    "198f270e-7042-4d01-aac5-ff595095d657/pasted-text-1.txt"
)
STEP7_AUTHORITY_SHA256 = (
    "685f93ec678a2590cf621336b559cf5e3cedc73701f1aefed3f01db5f28fea3c"
)
STEP56_ACCEPT_SCHEMA = "SITINA_STEP56_INDEPENDENT_ACCEPTANCE_V2"
STEP56_SOURCE_SESSION_PATH = (
    "/Users/moss/.codex/sessions/2026/07/20/"
    "rollout-2026-07-20T14-42-51-019f810d-78fe-75d2-8efd-d43fccbd82d7.jsonl"
)
STEP56_SOURCE_SESSION_ID = "019f810d-78fe-75d2-8efd-d43fccbd82d7"
STEP56_SOURCE_SESSION_PREFIX_LINE_COUNT = 11564
STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH = 21938163
STEP56_SOURCE_SESSION_PREFIX_SHA256 = (
    "790b71ffa8a3b2a43ce54b3c77304d7eea3c5f6ed02a3e7d83f8500a5e7b20c2"
)
STEP56_SOURCE_SESSION_META_RAW_SHA256 = (
    "108a46acefdec456c54872ac4cf02a63133a954ceb1f82fbf4d642a13846360e"
)
STEP7_SOURCE_THREAD_ID = "019f810d-78fe-75d2-8efd-d43fccbd82d7"
STEP7_DELEGATED_SOURCE_SESSION = {
    "path": STEP56_SOURCE_SESSION_PATH,
    "session_id": STEP7_SOURCE_THREAD_ID,
    "id": STEP7_SOURCE_THREAD_ID,
    "originator": "codex_work_desktop",
    "source": "vscode",
    "thread_source": "user",
    "model_provider": "openai",
    "meta_raw_sha256": STEP56_SOURCE_SESSION_META_RAW_SHA256,
}
STEP56_ACCEPT_RECORDS = {
    "amsg_019fa247-a1e1-7581-ae28-ff20ebfbe76f": {
        "artifact_id": "STEP56_ACCEPT_IDENTITY_CAPABILITY",
        "line_number": 11560,
        "raw_record_sha256": "2bc4e3de850c7548ae9ca5b3f1e1f4206e7ed6d530c583f5496294a48e2162e9",
        "author": "/root/identity_review_current",
        "content_sha256": "8b1beb8d286455530989d2c3fed65193b2784fd377614571e95717027ca4695f",
        "payload_sha256": "87aecc7a92aebe4dda09ffb5d7e2b7fdf9c92bbf933cb78809ab9d8145256e13",
    },
    "amsg_019fa247-a1e1-7581-ae28-ff30de295084": {
        "artifact_id": "STEP56_ACCEPT_STEP5_SENTINEL_RUNNER",
        "line_number": 11562,
        "raw_record_sha256": "0f9ce1d00a0d3f72a23a75a6132b1d35dac147a760bf008bb9be27504b147a58",
        "author": "/root/step5_control_review",
        "content_sha256": "835376a57c4111a8255983fc329ac9169f20fe6c1ae4e811a2f4803efb9a7346",
        "payload_sha256": "f30fb14cbdb332d138ed143596d3d31406d92e04fafde943eee54d8d71089448",
    },
    "amsg_019fa247-a1e1-7581-ae28-ff462b6887f6": {
        "artifact_id": "STEP56_ACCEPT_TEST_ENVIRONMENT_REGISTRATION",
        "line_number": 11564,
        "raw_record_sha256": "e6eedb7e0e7c345567bb446656d85197dd239d8bebfa319ef45ff496fe1a1f5b",
        "author": "/root/test_gate_review_current",
        "content_sha256": "e81e5585c849493aed7a733a955a9b9ad1e0910b7a85c3750909f40f55998147",
        "payload_sha256": "79c2c7fa83af859480eba9ca9eb24f26dae56175343521b303b33d3b85cbb363",
    },
}
POLICY_RELATIVE_PATH = "config/true_multi_agent_policy.json"
TEST_REGISTRY_RELATIVE_PATH = "tests/test_suites.json"
TEST_RESULT_SCHEMA = "BPLUS_TEST_RESULT_V1"
ACTIVATION_RESULT_SCHEMA = "SITINA_EXECUTION_ACTIVATION_GATE_RESULT_V1"
REGISTRATION_RESULT_SCHEMA = "SITINA_REGISTERED_TEST_GATE_RESULT_V1"
DEPENDENCY_RESULT_SCHEMA = "SITINA_BPLUS_DEPENDENCY_GATE_V1"
AUTONOMOUS_AUDIT_SCHEMA = "SITINA_AUTONOMOUS_RUN_EVENT_V1"
REAL_REVIEW_RECEIPT_SCHEMA = "SITINA_STEP7_REAL_REVIEW_CAPTURE_RECEIPT_V1"
CODEX_CAPTURE_ANCHOR_SCHEMA = "SITINA_CODEX_APPEND_ONLY_CAPTURE_ANCHOR_V1"
CODEX_USER_AUTHORIZATION_SCHEMA = "SITINA_CODEX_USER_AUTHORIZATION_RECEIPT_V1"
AUDIT_CAPTURE_ANCHOR_MARKER = "SITINA_STEP7_AUDIT_CAPTURE_ANCHOR_V1"
PREIMAGE_CAPTURE_ANCHOR_MARKER = "SITINA_STEP7_PREIMAGE_CAPTURE_ANCHOR_V1"
DEPLOYMENT_AUTHORIZATION_MARKER = "SITINA_STEP7_DEPLOYMENT_AUTHORIZATION_V2"
CODEX_SESSION_ROOT = Path("/Users/moss/.codex/sessions")
SENTINEL_SAMPLE_SCHEMA = "SITINA_STEP7_PRODUCTION_SENTINEL_SAMPLE_V1"
ROLLBACK_MANIFEST_SCHEMA = "SITINA_STEP7_BACKUP_MANIFEST_V3"
ROLLBACK_RESULT_SCHEMA = "SITINA_STEP7_ROLLBACK_VERIFICATION_V3"
DEPLOYMENT_PACKET_SCHEMA = "SITINA_STEP7_DEPLOYMENT_APPROVAL_PACKET_V3"
BACKUP_ROLLBACK_PLAN_SCHEMA = "SITINA_STEP7_BACKUP_AND_ROLLBACK_PLAN_V3"
DEPLOYMENT_REQUEST_CANDIDATE_SCHEMA = (
    "SITINA_STEP7_DEPLOYMENT_REQUEST_REVIEW_CANDIDATE_V2"
)
DEPLOYMENT_REQUEST_EVIDENCE_SCHEMA = (
    "SITINA_STEP7_DEPLOYMENT_REQUEST_REVIEW_EVIDENCE_V1"
)
DEPLOYMENT_AUTHORIZATION_CONTRACT_SCHEMA = (
    "SITINA_STEP7_EXACT_AUTHORIZATION_CONTRACT_V1"
)
REVOKED_DEPLOYMENT_APPROVAL_IDS = {
    "SITINA_STEP7_DEPLOY_82650BC_3F_20260727T073056Z",
    "SITINA_STEP7_DEPLOY_CC6E72A0_6F_20260727T094143Z",
    "SITINA_STEP7_DEPLOY_CBBD2E1_6F_20260727T113530Z",
}
CLEANUP_CANDIDATE_SCHEMA = "SITINA_CLEANUP_CANDIDATE_STEP7_DRAFT_V1"
CLEANUP_LEDGER_SCHEMA = "SITINA_CLEANUP_LEDGER_STEP7_DRAFT_V1"
OFFICIAL_GOAL_ID = "019f5c6b-3083-7860-b45b-c8b487c4e3ab"
BASE_SENTINEL_SCHEMA = "PRODUCTION_SENTINEL_V2"
MUTABLE_SENTINEL_SCHEMA = "PRODUCTION_MUTABLE_SENTINEL_V3"
EXECUTION_MANIFEST_SCHEMA = "EXECUTION_MANIFEST_V1"
EXPECTED_PRODUCTION_GUARD_PROFILE = "APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1"
BASE_SENTINEL_PATH = (
    "/Users/moss/Desktop/sitina/output/sitina-bplus-production-sentinel-initial.json"
)
BASE_SENTINEL_PHYSICAL_SHA256 = (
    "8add59df8b6b3c50666cc90bdc1001a804143295ff18cc97e5227193f2f1d07e"
)
BASE_SENTINEL_REPORT_SHA256 = (
    "92a477de47958ad3e616a99a2a031b0752252d4093f101198494855cd9ef4eab"
)
MUTABLE_SENTINEL_PATH = (
    "/Users/moss/Desktop/sitina/output/"
    "sitina-bplus-production-mutable-sentinel-phase-minus1-baseline.json"
)
MUTABLE_SENTINEL_PHYSICAL_SHA256 = (
    "965fc0dda5f523170013e53e07514a3de5c2f2bfe164ff7a9a50cd15f5620f1a"
)
MUTABLE_SENTINEL_REPORT_SHA256 = (
    "e77130eb077f3e554c277bc6585012f639bf70fbce792baa59f0a333f9dbb52a"
)
EXECUTION_MANIFEST_PATH = (
    "/Users/moss/Desktop/sitina/output/"
    "sitina-bplus-execution-manifest-v1-phase-minus1.json"
)
EXECUTION_MANIFEST_PHYSICAL_SHA256 = (
    "41eeb0055857e40c5e1297d60771282ca52ec1806783d242e813c37899248aa8"
)
EXECUTION_MANIFEST_CANONICAL_SHA256 = (
    "ba8ea81e30fdf121a7a615dbfc918cb2bf35b50083102e08de10d51c8bc9ac47"
)
HISTORICAL_SKIP_REASON = (
    "historical Phase -1 acceptance is evaluated only by its manifest-bound suite"
)
CLEANUP_CANDIDATE_FIELDS = {
    "schema",
    "candidate_name",
    "created_at_utc",
    "draft",
    "verdict",
    "authority",
    "source_snapshot",
    "scope",
    "evidence_sources",
    "inventory_method",
    "objects",
    "old_operations",
    "coverage_summary",
    "review_state",
    "step8_step9_not_entered",
}
CLEANUP_LEDGER_FIELDS = {
    "schema",
    "ledger_name",
    "created_at_utc",
    "draft",
    "verdict",
    "approved_action_count",
    "completed_approved_action_count",
    "new_actions_performed_during_step7",
    "unapproved_actions_performed",
    "permanent_deletion",
    "candidate_binding",
    "step56_entry_binding",
    "action_boundary",
    "historical_recoverable_quarantine",
    "preexisting_risks",
    "entries",
    "entry_totals",
    "real_sitina_review",
    "review_state",
    "step8_step9_not_entered",
}
CLEANUP_LEDGER_ENTRY_FIELDS = {
    "candidate_id",
    "category",
    "recommendation",
    "approval_status",
    "actual_action",
    "current_disposition",
    "new_action_authorized",
}
REAL_REVIEW_CANDIDATE_FIELDS = {
    "run_id",
    "provider_mode",
    "profile",
    "model",
    "review_stage",
    "terminal_state",
    "started_at_utc",
    "ended_at_utc",
    "provider_calls",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "verdict",
    "input_sha256",
    "output_sha256",
    "tool_call_count",
    "tool_call_types",
    "tool_permissions",
    "file_changes",
    "external_changes",
    "denied_tool_calls",
    "unique_files_changed",
    "input",
    "audit",
    "receipt",
}
REAL_REVIEW_RECEIPT_FIELDS = {
    "schema",
    "review_stage",
    "run_id",
    "created_at_utc",
    "input",
    "audit",
    "event_count",
    "first_event",
    "last_event",
    "event_chain_sha256",
    "provider_request_ids",
    "usage",
    "boundary",
    "capture_anchor",
}
CODEX_RECORD_REFERENCE_FIELDS = {
    "schema",
    "session_path",
    "line_number",
    "record_id",
    "raw_record_sha256",
    "content_sha256",
    "marker",
    "author",
}
DEPLOYMENT_PACKET_FIELDS = {
    "schema",
    "approval_id",
    "created_at_utc",
    "source_binding",
    "deployment_binding",
    "preimage_capture",
    "exact_file_operations",
    "backup_and_rollback_plan",
    "backup_and_rollback_plan_sha256",
    "authorization_contract",
    "forbidden_boundaries",
    "requires_exact_user_authorization",
    "self_authorizes_execution",
    "deployment_executed_at_creation",
}
BACKUP_ROLLBACK_PLAN_FIELDS = {
    "schema",
    "approval_id",
    "status",
    "source_binding",
    "deployment_binding",
    "exact_file_operations_sha256",
    "backup_root",
    "backup_manifest_path",
    "rollback_quarantine_root",
    "recovery_verification_path",
    "objects",
    "execution_sequence",
    "failure_policy",
    "forbidden_boundaries",
}
BACKUP_ROLLBACK_OBJECT_FIELDS = {
    "index",
    "relative_path",
    "operation",
    "target_path",
    "preimage_sha256",
    "target_sha256",
    "preimage_backup_path",
    "rollback_quarantine_path",
    "rollback_action",
    "recovery_verification",
}
DEPLOYMENT_REQUEST_CANDIDATE_FIELDS = {
    "schema",
    "candidate_id",
    "created_at_utc",
    "status",
    "approval_id",
    "source_binding",
    "deployment_binding",
    "approval_packet",
    "authorization_contract",
    "exact_file_operation_count",
    "exact_file_operations_sha256",
    "rollback_plan_sha256",
    "review_summary",
    "evidence_bundle",
    "authorized",
    "deployment_executed",
    "forbidden_boundaries",
}
DEPLOYMENT_REQUEST_EVIDENCE_FIELDS = {
    "schema",
    "created_at_utc",
    "source",
    "approval_id",
    "approval_packet",
    "authorization_contract",
    "exact_file_operations_sha256",
    "rollback_plan_sha256",
    "review_summary",
    "evidence",
}
DEPLOYMENT_REQUEST_EVIDENCE_CATEGORIES = {
    "authority",
    "entry_candidate",
    "step56_accepts",
    "gates",
    "real_sitina_reviews",
    "static_integrity",
    "excluded_attempts",
    "revocation",
    "changed_source",
}
DEPLOYMENT_REQUEST_SUPPORTING_EVIDENCE_FIELDS = {
    "static_integrity",
    "excluded_attempts",
    "revocation",
}
DEPLOYMENT_AUTHORIZATION_CONTRACT_FIELDS = {
    "schema",
    "marker",
    "source_thread_id",
    "required_payload_fields",
    "requires_user_record",
    "delegated_wrapper_required",
    "delegated_wrapper_source_thread_required",
    "delegated_source_session",
    "self_authorizes_execution",
}
DEPLOYMENT_AUTHORIZATION_PAYLOAD_FIELDS = (
    "approval_id",
    "approval_packet_sha256",
    "exact_file_operation_count",
    "exact_file_operations_sha256",
    "rollback_plan_sha256",
    "review_candidate_sha256",
    "source_head",
    "source_tree",
    "deployment_root",
)
BACKUP_ROLLBACK_FORBIDDEN_FIELDS = (
    "permanent_delete_allowed",
    "unlink_or_rmtree_allowed",
    "overwrite_existing_backup_allowed",
    "overwrite_existing_quarantine_allowed",
    "symlink_or_nonregular_object_allowed",
    "unlisted_path_mutation_allowed",
    "production_data_mutation_allowed",
    "baseline_install_or_promotion_allowed",
    "production_canary_allowed",
    "step8_allowed",
    "step9_allowed",
    "execution_switch_change_allowed",
    "external_mutation_allowed",
    "packet_plan_or_candidate_mutation_after_authorization_allowed",
    "backup_cleanup_after_failure_allowed",
)
BACKUP_ROLLBACK_EXECUTION_SEQUENCE = (
    "VERIFY_IMMUTABLE_ARTIFACTS_AND_USER_AUTHORIZATION",
    "VERIFY_HEAD_TREE_CLEAN_SWITCHES_AND_SENTINELS",
    "RECAPTURE_PREIMAGES_AND_COMPARE_PACKET",
    "CREATE_UNIQUE_BACKUP_ROOT_EXCLUSIVE_NOFOLLOW",
    "COPY_AND_VERIFY_REPLACE_PREIMAGES",
    "WRITE_AND_VERIFY_BACKUP_MANIFEST_EXCLUSIVE",
    "RUN_DISPOSABLE_RESTORE_REAPPLY_REHEARSAL",
    "APPLY_OPERATIONS_IN_PACKET_ORDER",
    "VERIFY_POSTIMAGES",
    "RUN_AUTHORIZED_DEPLOYED_STEP7_GATES",
    "WRITE_EXECUTION_OR_RECOVERY_RESULT",
)
BACKUP_ROLLBACK_FAILURE_POLICY = {
    "preapply_failure": "STOP_WITHOUT_DEPLOYMENT_MUTATION",
    "postapply_failure": "ROLLBACK_APPLIED_OPERATIONS_IN_REVERSE_ORDER",
    "replace_restore": "RESTORE_VERIFIED_PREIMAGE_ATOMIC_REPLACE",
    "create_restore": "MOVE_CREATED_TARGET_TO_QUARANTINE_ATOMIC_RENAME",
    "permanent_delete": "FORBIDDEN",
    "unknown_target": "STOP_FOR_MANUAL_RECOVERY",
    "verify_recovery_result": "REQUIRED",
    "retain_backups_and_quarantine": "REQUIRED",
}
ROLLBACK_OPERATION_FIELDS = {
    "relative_path",
    "operation",
    "source_path",
    "target_path",
    "target_sha256",
    "target_size",
    "target_mode",
    "preimage_exists",
    "preimage_sha256",
    "preimage_size",
    "preimage_mode",
}
ROLLBACK_MANIFEST_FIELDS = {
    "schema",
    "source_head",
    "source_tree",
    "deployment_root",
    "approval_id",
    "approval_packet_sha256",
    "exact_file_operations_sha256",
    "rollback_plan_sha256",
    "review_candidate_sha256",
    "backup_root",
    "backup_manifest_path",
    "backup_root_created_exclusively",
    "backup_root_reused",
    "backup_root_mode",
    "backup_root_parent_components_safe",
    "verified_before_deployment",
    "deployment_mutated",
    "mismatch_count",
    "entries",
}
ROLLBACK_RECOVERY_FIELDS = {
    "schema",
    "manifest",
    "approval_packet",
    "review_candidate",
    "rollback_plan_sha256",
    "authorization_raw_record_sha256",
    "source_head",
    "source_tree",
    "deployment_root",
    "method",
    "deployment_mutated",
    "verified",
    "mismatch_count",
    "delete_operation_count",
    "backups_retained",
    "quarantines_retained",
    "manual_recovery_required",
    "entries",
}
CLEANUP_OBJECT_IDS = (
    *(f"STEP7-OLD-DATA-{index:03d}" for index in range(1, 11)),
    "STEP7-OLD-CODE-001",
    *(f"STEP7-OLD-OPS-{index:03d}" for index in range(1, 10)),
)
CLEANUP_ACTION_SEMANTICS_SHA256 = (
    "9d8955b7e516769224d7c33807fcf341a9c2fcb76aa8ee5eb22bbf5c2623ccd2"
)
TEST_RESULT_FIELDS = {
    "schema",
    "stage",
    "suite",
    "selectors",
    "mode",
    "command",
    "child_cwd",
    "duration_seconds",
    "test_count",
    "skipped_count",
    "activation_gate",
    "registration_gate",
    "dependency_gate",
    "warning_count",
    "warning_lines",
    "stdout_sha256",
    "timed_out",
    "return_code",
    "external_attempt_count",
    "production_attempt_count",
    "production_attempt_records",
    "production_attempt_log_sha256",
    "production_guard_profile",
    "production_sentinel_before",
    "production_sentinel_after",
    "production_mutable_sentinel_before",
    "production_mutable_sentinel_after",
    "production_sentinel_unchanged",
    "production_sentinel_baseline",
    "production_mutable_sentinel_baseline",
    "execution_manifest_hash",
}
DEPENDENCY_RESULT_FIELDS = {
    "schema",
    "accepted",
    "dependencies_match",
    "expected_lock_sha256",
    "expected_python_version",
    "historical_manifest_binding_match",
    "historical_manifest_dependency_lock_sha256",
    "installed_locked_versions",
    "lock_path",
    "lock_sha256",
    "locked_distribution_count",
    "locked_versions",
    "manifest_binding_match",
    "missing",
    "python_executable",
    "python_match",
    "python_version",
    "version_mismatches",
}
STRICT_COMMON_FIELDS = {
    "schema",
    "policy",
    "accepted",
    "selector_counts",
    "collected_test_ids",
    "collected_test_ids_sha256",
    "started_test_ids",
    "started_test_ids_sha256",
    "collection_errors",
    "collection_complete",
    "execution_complete",
    "collected_test_count",
    "executed_test_count",
    "passed",
    "failures",
    "errors",
    "skipped",
    "expected_failures",
    "unexpected_successes",
    "missing_test_ids",
    "unexpected_test_ids",
    "failure_details",
    "error_details",
    "skip_details",
    "expected_failure_details",
    "unexpected_success_details",
}
REGISTRATION_EXTRA_FIELDS = {
    "selector_count",
    "skip_allowlist_match",
    "expected_skip_details",
}
AUDIT_EVENT_FIELDS = {
    "run_started": {
        "event",
        "run_id",
        "schema",
        "selected_agents",
        "selected_skills",
        "task",
        "timestamp",
        "tool_count",
    },
    "provider_call_intended": {
        "event",
        "max_tokens",
        "messages",
        "run_id",
        "schema",
        "system_prompt",
        "timestamp",
        "tools",
        "turn",
    },
    "model_turn_completed": {
        "event",
        "metadata",
        "run_id",
        "schema",
        "stop_reason",
        "text",
        "timestamp",
        "tool_calls",
        "turn",
    },
    "tool_call_intended": {
        "argument_summary",
        "call_id",
        "event",
        "name",
        "permission",
        "run_id",
        "schema",
        "timestamp",
    },
    "tool_completed": {
        "argument_summary",
        "call_id",
        "event",
        "permission",
        "result_summary",
        "run_id",
        "schema",
        "timestamp",
    },
    "run_succeeded": {"event", "response", "run_id", "schema", "timestamp"},
}
MODEL_METADATA_FIELDS = {
    "connect_timeout_seconds",
    "duration_ms",
    "fallback_used",
    "input_hash",
    "model",
    "output_hash",
    "profile_name",
    "protocol",
    "protocol_fallback_used",
    "provider_call_completed_at",
    "provider_call_started_at",
    "provider_mode",
    "provider_request_id",
    "read_timeout_seconds",
    "redaction_status",
    "request_timeout_seconds",
    "token_usage",
    "tool_call_count",
}
SWITCHES = (
    "tool_calls_allowed",
    "external_mutation_allowed",
    "execution_bridge_enabled",
    "execution_handoff_bypass_enabled",
)
REQUIRED_GATES = (
    "minimal_negative_contract",
    "identity_sentinel_directed",
    "execution_activation",
    "step7_readiness_gate",
    "unit_fast",
    "integration_isolated",
    "all_registered_unique",
)
MINIMUM_GATE_COUNTS = {
    "minimal_negative_contract": 8,
    "identity_sentinel_directed": 56,
    "execution_activation": 60,
    "step7_readiness_gate": 1,
    "unit_fast": 208,
    "integration_isolated": 200,
    "all_registered_unique": 980,
}
DIRECTED_STAGE_SELECTORS = {
    "minimal_negative_contract": (
        "tests/foundation/test_dependency_lock_gate.py",
        "tests/foundation/test_registration_gate_runner.py",
    ),
    "identity_sentinel_directed": (
        "tests/foundation/test_sentinel_content_addressed.py",
        "tests/test_execution_bridge.py",
        "tests/test_execution_bridge_integration.py",
        "tests/test_execution_sandbox.py",
    ),
}
STAGE_SUITE_KEYS = {
    "minimal_negative_contract": "unit_fast",
    "identity_sentinel_directed": "unit_fast",
    "execution_activation": "execution_activation_gate",
    "step7_readiness_gate": "step7_readiness_gate",
    "unit_fast": "unit_fast",
    "integration_isolated": "integration_isolated",
    "all_registered_unique": "all_registered_unique",
}
HISTORICAL_SKIP_IDS = (
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_default_suites_pass_with_zero_external_or_production_access",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_legacy_baseline_reproducible_with_semantics_preserved",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_manifest_promotion_and_pinned_profile",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_plan_inventory_and_incident_recovery_gates",
    "tests.foundation.test_phase_minus1_acceptance.PhaseMinus1AcceptanceTests."
    "test_source_only_manifest_is_current_and_excludes_runtime",
)
FORBIDDEN_ACTION_FIELDS = (
    "production_canary_run",
    "execution_switch_enabled",
    "production_data_modified",
    "production_data_deleted",
    "baseline_installed_or_promoted",
    "quarantine_or_trash_cleared",
    "unique_or_latest_backup_deleted",
    "reachable_evidence_deleted",
    "historical_baseline_deleted",
    "git_history_rewritten",
    "push_merge_publish_or_external_change",
    "destructive_git_recovery_used",
    "gate_weakened_assertion_removed_or_skip_added",
    "step8_entered",
    "step9_entered",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _load_json_lines(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                raise ValueError(f"blank JSONL record at line {line_number}")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"non-object JSONL record at line {line_number}")
            records.append(value)
    if not records:
        raise ValueError("empty JSONL audit")
    return records


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_value_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _audit_event_chain_sha256(records: Sequence[Mapping[str, Any]]) -> str:
    previous = bytes(32)
    for record in records:
        encoded = json.dumps(
            dict(record),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        previous = hashlib.sha256(previous + encoded).digest()
    return previous.hex()


def _openai_wire_messages(
    system_prompt: Any,
    messages: Any,
) -> list[dict[str, Any]] | None:
    if not isinstance(system_prompt, str) or not isinstance(messages, list):
        return None
    converted: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt}
    ]
    for raw in messages:
        if not isinstance(raw, Mapping):
            return None
        role = str(raw.get("role") or "")
        if role in {"user", "assistant"}:
            item: dict[str, Any] = {
                "role": role,
                "content": str(raw.get("content") or ""),
            }
            if role == "assistant" and raw.get("tool_calls"):
                calls = raw.get("tool_calls")
                if not isinstance(calls, list):
                    return None
                item["tool_calls"] = []
                for call in calls:
                    if not isinstance(call, Mapping):
                        return None
                    arguments = call.get("arguments") or {}
                    if not isinstance(arguments, Mapping):
                        return None
                    item["tool_calls"].append(
                        {
                            "id": str(call.get("id") or ""),
                            "type": "function",
                            "function": {
                                "name": str(call.get("name") or ""),
                                "arguments": json.dumps(
                                    dict(arguments),
                                    ensure_ascii=False,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                            },
                        }
                    )
            converted.append(item)
        elif role == "tool":
            converted.append(
                {
                    "role": "tool",
                    "tool_call_id": str(raw.get("tool_call_id") or ""),
                    "content": str(raw.get("content") or ""),
                }
            )
        else:
            return None
    return converted


def _verify_codex_capture_anchor(
    anchor: Any,
    *,
    marker: str,
    expected_payload: Mapping[str, Any],
    anchor_root: Path,
    errors: list[str],
    label: str,
) -> None:
    if not isinstance(anchor, Mapping) or set(anchor) != CODEX_RECORD_REFERENCE_FIELDS:
        errors.append(f"{label} append-only anchor schema mismatch")
        return
    if (
        anchor.get("schema") != CODEX_CAPTURE_ANCHOR_SCHEMA
        or anchor.get("marker") != marker
        or not _integer(anchor.get("line_number"))
        or anchor.get("line_number") <= 0
        or not _valid_sha256(anchor.get("raw_record_sha256"))
        or not _valid_sha256(anchor.get("content_sha256"))
        or not isinstance(anchor.get("record_id"), str)
        or not anchor.get("record_id")
        or not isinstance(anchor.get("author"), str)
        or not anchor.get("author")
    ):
        errors.append(f"{label} append-only anchor binding mismatch")
        return
    session_path = _safe_regular_file(
        anchor.get("session_path"),
        errors,
        f"{label} append-only session",
    )
    try:
        resolved_root = anchor_root.expanduser().resolve(strict=True)
        if (
            session_path is None
            or not session_path.is_relative_to(resolved_root)
            or session_path.suffix != ".jsonl"
        ):
            raise ValueError("anchor session is outside the fixed session root")
        raw_lines = session_path.read_bytes().splitlines(keepends=True)
        meta = json.loads(raw_lines[0])
        raw = raw_lines[int(anchor["line_number"]) - 1]
        record = json.loads(raw)
    except (
        IndexError,
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        errors.append(f"{label} append-only anchor record cannot be read")
        return
    payload = record.get("payload") if isinstance(record, Mapping) else None
    meta_payload = meta.get("payload") if isinstance(meta, Mapping) else None
    content = payload.get("content") if isinstance(payload, Mapping) else None
    text = (
        content[0].get("text")
        if isinstance(content, list)
        and content
        and isinstance(content[0], Mapping)
        else None
    )
    expected_text = marker + " " + json.dumps(
        dict(expected_payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    production_session_root = resolved_root == CODEX_SESSION_ROOT.resolve(strict=True)
    session_identity_valid = (
        isinstance(meta_payload, Mapping)
        and meta.get("type") == "session_meta"
        and meta_payload.get("originator") == "Codex Desktop"
        and meta_payload.get("source") == "vscode"
        and meta_payload.get("thread_source") == "subagent"
        and meta_payload.get("model_provider") == "openai"
        and isinstance(meta_payload.get("session_id"), str)
        and isinstance(meta_payload.get("id"), str)
    )
    if production_session_root:
        session_identity_valid = bool(
            session_identity_valid
            and session_path.name.startswith("rollout-")
            and (
                str(meta_payload.get("session_id")) in session_path.name
                or str(meta_payload.get("id")) in session_path.name
            )
        )
    independent_audit = marker == AUDIT_CAPTURE_ANCHOR_MARKER
    if independent_audit:
        author = anchor.get("author")
        expected_text = (
            "Message Type: FINAL_ANSWER\n"
            "Task name: /root\n"
            f"Sender: {author}\n"
            "Payload:\n"
            + expected_text
        )
        record_identity_valid = (
            isinstance(payload, Mapping)
            and payload.get("type") == "agent_message"
            and payload.get("author") == author
            and payload.get("recipient") == "/root"
            and isinstance(author, str)
            and author.startswith("/root/step7_")
            and author != "/root"
        )
    else:
        record_identity_valid = (
            isinstance(payload, Mapping)
            and payload.get("type") == "message"
            and payload.get("role") == "assistant"
            and payload.get("phase") == "commentary"
            and anchor.get("author") == "/root"
        )
    if (
        hashlib.sha256(raw).hexdigest() != anchor.get("raw_record_sha256")
        or not session_identity_valid
        or record.get("type") != "response_item"
        or not isinstance(payload, Mapping)
        or payload.get("id") != anchor.get("record_id")
        or not record_identity_valid
        or text != expected_text
        or _sha256_text(text) != anchor.get("content_sha256")
    ):
        errors.append(f"{label} append-only anchor content mismatch")


def _verify_user_authorization(
    receipt: Any,
    *,
    expected_payload: Mapping[str, Any],
    anchor_root: Path,
    errors: list[str],
) -> None:
    """Require exact user-authored approval bound to the packet's physical bytes."""

    label = "deployment user authorization"
    if not isinstance(receipt, Mapping) or set(receipt) != CODEX_RECORD_REFERENCE_FIELDS:
        errors.append(f"{label} receipt schema mismatch")
        return
    if (
        receipt.get("schema") != CODEX_USER_AUTHORIZATION_SCHEMA
        or receipt.get("marker") != DEPLOYMENT_AUTHORIZATION_MARKER
        or receipt.get("author") != "user"
        or not _integer(receipt.get("line_number"))
        or receipt.get("line_number") <= 0
        or not isinstance(receipt.get("record_id"), str)
        or not receipt.get("record_id")
        or not _valid_sha256(receipt.get("raw_record_sha256"))
        or not _valid_sha256(receipt.get("content_sha256"))
    ):
        errors.append(f"{label} receipt binding mismatch")
        return
    session_path = _safe_regular_file(
        receipt.get("session_path"), errors, f"{label} session"
    )
    try:
        resolved_root = anchor_root.expanduser().resolve(strict=True)
        if (
            session_path is None
            or not session_path.is_relative_to(resolved_root)
            or session_path.suffix != ".jsonl"
        ):
            raise ValueError("authorization session is outside fixed session root")
        raw_lines = session_path.read_bytes().splitlines(keepends=True)
        meta = json.loads(raw_lines[0])
        raw = raw_lines[int(receipt["line_number"]) - 1]
        record = json.loads(raw)
    except (
        IndexError,
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        errors.append(f"{label} record cannot be read")
        return
    meta_payload = meta.get("payload") if isinstance(meta, Mapping) else None
    payload = record.get("payload") if isinstance(record, Mapping) else None
    content = payload.get("content") if isinstance(payload, Mapping) else None
    expected_text = DEPLOYMENT_AUTHORIZATION_MARKER + " " + json.dumps(
        dict(expected_payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    texts = (
        [
            item.get("text")
            for item in content
            if isinstance(item, Mapping)
            and item.get("type") == "input_text"
            and isinstance(item.get("text"), str)
        ]
        if isinstance(content, list)
        else []
    )
    authorization_text = texts[0] if len(texts) == 1 else None
    delegated = (
        re.fullmatch(
            r"<codex_delegation>\s*"
            r"<source_thread_id>([^<]+)</source_thread_id>\s*"
            r"<input>([\s\S]*)</input>\s*"
            r"</codex_delegation>",
            authorization_text,
        )
        if isinstance(authorization_text, str)
        else None
    )
    authorization_matches = (
        delegated is not None
        and delegated.group(1) == STEP7_SOURCE_THREAD_ID
        and delegated.group(2) == expected_text
    )
    production_session_root = resolved_root == CODEX_SESSION_ROOT.resolve(strict=True)
    session_identity_valid = (
        isinstance(meta_payload, Mapping)
        and meta.get("type") == "session_meta"
        and meta_payload.get("originator") == "Codex Desktop"
        and meta_payload.get("source") == "vscode"
        and meta_payload.get("thread_source") == "subagent"
        and meta_payload.get("model_provider") == "openai"
        and isinstance(meta_payload.get("session_id"), str)
        and isinstance(meta_payload.get("id"), str)
    )
    if production_session_root:
        session_identity_valid = bool(
            session_identity_valid
            and session_path.name.startswith("rollout-")
            and (
                str(meta_payload.get("session_id")) in session_path.name
                or str(meta_payload.get("id")) in session_path.name
            )
        )
    if (
        hashlib.sha256(raw).hexdigest() != receipt.get("raw_record_sha256")
        or not session_identity_valid
        or record.get("type") != "response_item"
        or not isinstance(payload, Mapping)
        or payload.get("type") != "message"
        or payload.get("id") != receipt.get("record_id")
        or payload.get("role") != "user"
        or not authorization_matches
        or not isinstance(authorization_text, str)
        or _sha256_text(authorization_text) != receipt.get("content_sha256")
    ):
        errors.append(f"{label} content mismatch")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_sha256(value: Any, *, prefixed: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    expected_length = 71 if prefixed else 64
    if len(value) != expected_length:
        return False
    if prefixed:
        if not value.startswith("sha256:"):
            return False
        value = value[7:]
    return all(character in "0123456789abcdef" for character in value)


def _valid_iso8601(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _iso_datetime(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _safe_regular_file(path_value: Any, errors: list[str], label: str) -> Path | None:
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        errors.append(f"{label} path must be absolute")
        return None
    path = Path(path_value)
    try:
        metadata = path.lstat()
    except OSError:
        errors.append(f"{label} file missing: {path}")
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        errors.append(f"{label} must be a regular non-symlink file: {path}")
        return None
    return path


def _verify_nofollow_descendant(
    path: Path,
    *,
    trusted_root: Path,
    leaf_kind: str,
    errors: list[str],
    label: str,
) -> bool:
    """Reject lexical escape and symlinks/non-directories in every component."""

    if (
        not path.is_absolute()
        or not trusted_root.is_absolute()
        or not path.is_relative_to(trusted_root)
    ):
        errors.append(f"{label} escapes its trusted root")
        return False
    relative = path.relative_to(trusted_root)
    components = [trusted_root]
    current = trusted_root
    for part in relative.parts:
        current /= part
        components.append(current)
    valid = True
    for index, component in enumerate(components):
        try:
            metadata = component.lstat()
        except OSError:
            errors.append(f"{label} component is missing: {component}")
            valid = False
            continue
        is_leaf = index == len(components) - 1
        expected_regular = is_leaf and leaf_kind == "file"
        expected_directory = not expected_regular
        if stat.S_ISLNK(metadata.st_mode):
            errors.append(f"{label} component is a symlink: {component}")
            valid = False
        elif expected_regular and not stat.S_ISREG(metadata.st_mode):
            errors.append(f"{label} leaf is not a regular file: {component}")
            valid = False
        elif expected_directory and not stat.S_ISDIR(metadata.st_mode):
            errors.append(f"{label} component is not a directory: {component}")
            valid = False
    return valid


def _verify_file_reference(
    value: Any,
    errors: list[str],
    label: str,
    *,
    require_json_object: bool = True,
) -> tuple[Path | None, dict[str, Any] | None]:
    if not isinstance(value, Mapping):
        errors.append(f"{label} reference must be an object")
        return None, None
    path = _safe_regular_file(value.get("path"), errors, label)
    expected = value.get("sha256")
    if not _valid_sha256(expected):
        errors.append(f"{label} reference requires a SHA-256")
    if path is None:
        return None, None
    actual = _sha256(path)
    if actual != expected:
        errors.append(f"{label} SHA-256 mismatch")
    if not require_json_object:
        return path, None
    try:
        document = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{label} is not a JSON object: {type(exc).__name__}")
        document = None
    return path, document


def _git(source_root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments],
        cwd=source_root,
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()


def _tracked_files(source_root: Path) -> list[str]:
    raw = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=source_root,
        stderr=subprocess.DEVNULL,
    )
    return [item.decode("utf-8") for item in raw.split(b"\0") if item]


def _verify_source_state(
    candidate: Mapping[str, Any],
    source_root: Path,
    enforce_step7_boundary: bool,
    errors: list[str],
) -> dict[str, Any]:
    source = candidate.get("source")
    if not isinstance(source, Mapping):
        errors.append("source state is missing")
        return {}
    try:
        head = _git(source_root, "rev-parse", "HEAD^{commit}")
        tree = _git(source_root, "rev-parse", "HEAD^{tree}")
        status = _git(source_root, "status", "--porcelain=v1", "--untracked-files=all")
    except (OSError, subprocess.CalledProcessError):
        errors.append("source root is not a readable Git worktree")
        return {}
    if source.get("root") != str(source_root):
        errors.append("candidate source root mismatch")
    if source.get("head") != head:
        errors.append("candidate source HEAD mismatch")
    if source.get("tree") != tree:
        errors.append("candidate source tree mismatch")
    if source.get("worktree_clean") is not True or status:
        errors.append("source worktree is not clean")
    changed_files = source.get("changed_files")
    if not isinstance(changed_files, list) or not changed_files:
        errors.append("candidate must list Step7 changed files")
    elif any(
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        for relative in changed_files
    ) or len(set(changed_files)) != len(changed_files):
        errors.append("candidate Step7 changed files are unsafe or duplicated")
    if enforce_step7_boundary:
        try:
            committed_changed_files = _git(
                source_root,
                "diff",
                "--name-only",
                f"{STEP7_BASE_COMMIT}..{head}",
                "--",
            ).splitlines()
            diff_check = subprocess.run(
                ["git", "diff", "--check", f"{STEP7_BASE_COMMIT}..{head}", "--"],
                cwd=source_root,
                capture_output=True,
                text=True,
                check=False,
            )
        except (OSError, subprocess.CalledProcessError):
            errors.append("unable to derive the committed Step7 boundary")
        else:
            if (
                committed_changed_files != list(STEP7_CHANGED_FILES)
                or changed_files != committed_changed_files
            ):
                errors.append("candidate Step7 changed files do not match the committed diff")
            if diff_check.returncode != 0:
                errors.append("committed Step7 diff fails git diff --check")
    return {"head": head, "tree": tree, "worktree_clean": not bool(status)}


def _verify_source_deployment(
    source_root: Path,
    deployment_root: Path,
    candidate: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    declared = candidate.get("source_deployment")
    if not isinstance(declared, Mapping):
        errors.append("source_deployment evidence is missing")
        return {}
    if declared.get("source_root") != str(source_root):
        errors.append("source_deployment source root mismatch")
    if declared.get("deployment_root") != str(deployment_root):
        errors.append("source_deployment deployment root mismatch")
    try:
        relative_paths = _tracked_files(source_root)
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        errors.append("unable to enumerate tracked source files")
        return {}
    missing: list[str] = []
    content_mismatches: list[str] = []
    mode_mismatches: list[str] = []
    unsafe: list[str] = []
    for relative in relative_paths:
        source = source_root / relative
        deployment = deployment_root / relative
        try:
            source_stat = source.lstat()
            deployment_stat = deployment.lstat()
        except OSError:
            missing.append(relative)
            continue
        if (
            stat.S_ISLNK(source_stat.st_mode)
            or stat.S_ISLNK(deployment_stat.st_mode)
            or not stat.S_ISREG(source_stat.st_mode)
            or not stat.S_ISREG(deployment_stat.st_mode)
        ):
            unsafe.append(relative)
            continue
        if source_stat.st_size != deployment_stat.st_size or _sha256(source) != _sha256(deployment):
            content_mismatches.append(relative)
        if stat.S_IMODE(source_stat.st_mode) != stat.S_IMODE(deployment_stat.st_mode):
            mode_mismatches.append(relative)
    if missing:
        errors.append(f"deployment missing {len(missing)} tracked files")
    if content_mismatches:
        errors.append(f"source/deployment content mismatch for {len(content_mismatches)} files")
    if mode_mismatches:
        errors.append(f"source/deployment mode mismatch for {len(mode_mismatches)} files")
    if unsafe:
        errors.append(f"source/deployment contains {len(unsafe)} unsafe tracked paths")
    if declared.get("tracked_file_count") != len(relative_paths):
        errors.append("declared tracked-file count mismatch")
    if declared.get("exact_match_count") != len(relative_paths):
        errors.append("declared exact-match count mismatch")
    return {
        "tracked_file_count": len(relative_paths),
        "exact_match_count": len(relative_paths)
        - len(set(missing + content_mismatches + mode_mismatches + unsafe)),
        "missing": missing,
        "content_mismatches": content_mismatches,
        "mode_mismatches": mode_mismatches,
        "unsafe": unsafe,
    }


def _verify_step56_source_session(
    source_session: Path,
    errors: list[str],
) -> list[bytes]:
    """Verify the immutable prefix through the last formal ACCEPT record.

    The source task remains active, so bytes appended after the accepted prefix
    are intentionally outside this contract.
    """

    if not source_session.is_file() or source_session.is_symlink():
        errors.append("formal Step5/6 source session is missing or unsafe")
        return []
    try:
        with source_session.open("rb") as handle:
            prefix = handle.read(STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH)
        raw_lines = prefix.splitlines(keepends=True)
        meta = json.loads(raw_lines[0])
    except (OSError, IndexError, UnicodeError, json.JSONDecodeError):
        errors.append("formal Step5/6 source session prefix cannot be read")
        return []
    meta_payload = meta.get("payload") if isinstance(meta, Mapping) else None
    if (
        len(prefix) != STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH
        or hashlib.sha256(prefix).hexdigest()
        != STEP56_SOURCE_SESSION_PREFIX_SHA256
        or len(raw_lines) != STEP56_SOURCE_SESSION_PREFIX_LINE_COUNT
        or not raw_lines[-1].endswith(b"\n")
    ):
        errors.append("formal Step5/6 source session prefix has changed")
        return []
    if (
        hashlib.sha256(raw_lines[0]).hexdigest()
        != STEP56_SOURCE_SESSION_META_RAW_SHA256
        or meta.get("type") != "session_meta"
        or not isinstance(meta_payload, Mapping)
        or meta_payload.get("id") != STEP56_SOURCE_SESSION_ID
        or meta_payload.get("session_id") != STEP56_SOURCE_SESSION_ID
        or meta_payload.get("originator") != "codex_work_desktop"
        or meta_payload.get("source") != "vscode"
        or meta_payload.get("thread_source") != "user"
        or meta_payload.get("model_provider") != "openai"
    ):
        errors.append("formal Step5/6 source session metadata mismatch")
        return []
    return raw_lines


def _verify_entry_candidate(
    candidate: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any] | None:
    reference = candidate.get("step56_entry_candidate")
    _, entry = _verify_file_reference(reference, errors, "Step5/6 entry candidate")
    if isinstance(reference, Mapping) and reference.get("sha256") != ENTRY_CANDIDATE_SHA256:
        errors.append("Step5/6 entry candidate is not the authorized physical artifact")
    if entry is None:
        return None
    if entry.get("schema") != ENTRY_CANDIDATE_SCHEMA:
        errors.append("Step5/6 entry candidate schema mismatch")
    if entry.get("verdict") != "READY_FOR_INDEPENDENT_STEP7_ENTRY_REVIEW":
        errors.append("Step5/6 entry candidate is not review-ready")
    if entry.get("scope_completed") != "Sitina Step 5/6 closure":
        errors.append("Step5/6 formal-closure scope is missing")
    if entry.get("step7_entered") is not False:
        errors.append("Step5/6 entry evidence incorrectly entered Step7")
    if candidate.get("step5_step6_formally_accepted") is not True:
        errors.append("candidate does not attest formal Step5/6 acceptance")
    source = entry.get("source")
    expected_head = source.get("final_commit") if isinstance(source, Mapping) else None
    expected_tree = source.get("final_tree") if isinstance(source, Mapping) else None
    if expected_head != "45a36be780413f561cf1f8f0d4b8ec80dd3f9416":
        errors.append("Step5/6 entry candidate final HEAD mismatch")
    if expected_tree != "d815f49be0ab9129e41acbd664a5b476da8e8c57":
        errors.append("Step5/6 entry candidate final tree mismatch")
    declared_reviews = entry.get("independent_subagent_final_reviews")
    if not isinstance(declared_reviews, Mapping) or len(declared_reviews) != 3:
        errors.append("Step5/6 entry candidate lacks three declared independent reviews")
    elif set(declared_reviews.values()) != {"PASS_NO_BLOCKER"}:
        errors.append("Step5/6 entry candidate has a non-accepting independent review")

    raw_accepts = candidate.get("step56_independent_accepts")
    if not isinstance(raw_accepts, list) or len(raw_accepts) != len(
        STEP56_ACCEPT_RECORDS
    ):
        errors.append("candidate must bind exactly three Step5/6 independent ACCEPT artifacts")
        return entry

    source_session = Path(STEP56_SOURCE_SESSION_PATH)
    raw_lines = _verify_step56_source_session(source_session, errors)
    if not raw_lines:
        return entry
    expected_ids = set(STEP56_ACCEPT_RECORDS)
    observed_ids: list[str] = []
    for index, raw_reference in enumerate(raw_accepts):
        _, document = _verify_file_reference(
            raw_reference,
            errors,
            f"Step5/6 independent ACCEPT {index}",
        )
        if document is None:
            continue
        if document.get("schema") != STEP56_ACCEPT_SCHEMA:
            errors.append(f"Step5/6 independent ACCEPT {index} schema mismatch")
        if set(document) != {
            "schema",
            "artifact_id",
            "source_session",
            "source_record",
            "decision",
            "candidate_binding",
        }:
            errors.append(f"Step5/6 independent ACCEPT {index} field set mismatch")
        session = document.get("source_session")
        if not isinstance(session, Mapping) or (
            set(session)
            != {
                "path",
                "session_id",
                "session_meta_raw_sha256",
                "accepted_prefix",
            }
            or session.get("path") != STEP56_SOURCE_SESSION_PATH
            or session.get("session_id") != STEP56_SOURCE_SESSION_ID
            or session.get("session_meta_raw_sha256")
            != STEP56_SOURCE_SESSION_META_RAW_SHA256
            or session.get("accepted_prefix")
            != {
                "line_count": STEP56_SOURCE_SESSION_PREFIX_LINE_COUNT,
                "byte_length": STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH,
                "sha256": STEP56_SOURCE_SESSION_PREFIX_SHA256,
            }
        ):
            errors.append(f"Step5/6 independent ACCEPT {index} source-session mismatch")
        record_claim = document.get("source_record")
        if not isinstance(record_claim, Mapping) or set(record_claim) != {
            "line_number",
            "raw_record_sha256",
            "type",
            "payload_type",
            "id",
            "timestamp",
            "author",
            "recipient",
            "content_utf8_bytes",
            "content_sha256",
            "payload_utf8_bytes",
            "payload_sha256",
        }:
            errors.append(f"Step5/6 independent ACCEPT {index} record field set mismatch")
        record_id = (
            record_claim.get("id") if isinstance(record_claim, Mapping) else None
        )
        observed_ids.append(record_id if isinstance(record_id, str) else "")
        expected = STEP56_ACCEPT_RECORDS.get(record_id)
        if expected is None:
            errors.append(f"Step5/6 independent ACCEPT {index} record identity mismatch")
            continue
        if document.get("artifact_id") != expected["artifact_id"]:
            errors.append(f"Step5/6 independent ACCEPT {index} artifact identity mismatch")
        line_number = expected["line_number"]
        if line_number > len(raw_lines):
            errors.append(f"Step5/6 independent ACCEPT {index} source record missing")
            continue
        raw_record = raw_lines[line_number - 1]
        if hashlib.sha256(raw_record).hexdigest() != expected["raw_record_sha256"]:
            errors.append(f"Step5/6 independent ACCEPT {index} raw record hash mismatch")
            continue
        try:
            source_record = json.loads(raw_record)
        except (UnicodeError, json.JSONDecodeError):
            errors.append(f"Step5/6 independent ACCEPT {index} source record is invalid")
            continue
        payload = source_record.get("payload")
        content_items = payload.get("content") if isinstance(payload, Mapping) else None
        content_item = (
            content_items[0]
            if isinstance(content_items, list)
            and len(content_items) == 1
            and isinstance(content_items[0], Mapping)
            else None
        )
        content = content_item.get("text") if isinstance(content_item, Mapping) else None
        prefix = (
            "Message Type: FINAL_ANSWER\n"
            "Task name: /root\n"
            f"Sender: {expected['author']}\n"
            "Payload:\n"
        )
        message_payload = (
            content[len(prefix) :]
            if isinstance(content, str) and content.startswith(prefix)
            else None
        )
        exact_record_fields = {
            "line_number": line_number,
            "raw_record_sha256": expected["raw_record_sha256"],
            "type": "response_item",
            "payload_type": "agent_message",
            "id": record_id,
            "timestamp": source_record.get("timestamp"),
            "author": expected["author"],
            "recipient": "/root",
            "content_utf8_bytes": (
                len(content.encode("utf-8")) if isinstance(content, str) else None
            ),
            "content_sha256": expected["content_sha256"],
            "payload_utf8_bytes": (
                len(message_payload.encode("utf-8"))
                if isinstance(message_payload, str)
                else None
            ),
            "payload_sha256": expected["payload_sha256"],
        }
        if not isinstance(record_claim, Mapping) or any(
            record_claim.get(field) != value
            for field, value in exact_record_fields.items()
        ):
            errors.append(f"Step5/6 independent ACCEPT {index} record fields mismatch")
        if (
            source_record.get("type") != "response_item"
            or not isinstance(payload, Mapping)
            or payload.get("type") != "agent_message"
            or payload.get("id") != record_id
            or payload.get("author") != expected["author"]
            or payload.get("recipient") != "/root"
            or not isinstance(content_item, Mapping)
            or content_item.get("type") != "input_text"
            or not isinstance(content, str)
            or _sha256_text(content) != expected["content_sha256"]
            or not isinstance(message_payload, str)
            or _sha256_text(message_payload) != expected["payload_sha256"]
        ):
            errors.append(f"Step5/6 independent ACCEPT {index} source message mismatch")
        elif (
            not message_payload.startswith("`ACCEPT_STEP7_ENTRY`")
            or ENTRY_CANDIDATE_SHA256 not in message_payload
            or expected_head not in message_payload
            or expected_tree not in message_payload
        ):
            errors.append(f"Step5/6 independent ACCEPT {index} decision content mismatch")
        decision = document.get("decision")
        if not isinstance(decision, Mapping) or (
            set(decision)
            != {
                "marker",
                "accepted_scope",
                "step8_authorized",
                "step9_authorized",
                "production_canary_authorized",
                "execution_switch_change_authorized",
                "baseline_change_authorized",
                "production_mutation_authorized",
            }
            or decision.get("marker") != "ACCEPT_STEP7_ENTRY"
            or decision.get("accepted_scope")
            != "STEP7_DESIGN_AND_LOCAL_IMPLEMENTATION_ONLY"
            or any(
                decision.get(field) is not False
                for field in (
                    "step8_authorized",
                    "step9_authorized",
                    "production_canary_authorized",
                    "execution_switch_change_authorized",
                    "baseline_change_authorized",
                    "production_mutation_authorized",
                )
            )
        ):
            errors.append(f"Step5/6 independent ACCEPT {index} authority boundary mismatch")
        binding = document.get("candidate_binding")
        if not isinstance(binding, Mapping) or (
            set(binding)
            != {
                "path",
                "physical_sha256",
                "schema",
                "candidate_id",
                "head",
                "tree",
            }
            or binding.get("path")
            != "/Users/moss/Desktop/sitina/output/"
            "sitina-step7-entry-review-candidate-step56-45a36be.json"
            or binding.get("physical_sha256") != ENTRY_CANDIDATE_SHA256
            or binding.get("schema") != ENTRY_CANDIDATE_SCHEMA
            or binding.get("candidate_id") != entry.get("candidate_id")
            or binding.get("head") != expected_head
            or binding.get("tree") != expected_tree
        ):
            errors.append(f"Step5/6 independent ACCEPT {index} candidate binding mismatch")
    if set(observed_ids) != expected_ids or len(set(observed_ids)) != len(expected_ids):
        errors.append("Step5/6 independent ACCEPT record set is incomplete or duplicated")
    return entry


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _selector_module(selector: str) -> str:
    return selector[:-3].replace("/", ".") if selector.endswith(".py") else selector


def _locked_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([a-z0-9][a-z0-9-]*)==([^\s]+)\s*\\?$", line)
        if match:
            versions[match.group(1)] = match.group(2)
    if not versions:
        raise ValueError("dependency lock contains no pinned distributions")
    return versions


def _strict_gate_counts(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "collected": result.get("collected_test_count"),
        "executed": result.get("executed_test_count"),
        "passed": result.get("passed"),
        "failed": result.get("failures"),
        "errors": result.get("errors"),
        "skipped": result.get("skipped"),
        "xfail": result.get("expected_failures"),
        "xpass": result.get("unexpected_successes"),
    }


def _recompute_deployment_collection(
    deployment_root: Path,
    registry_path: Path,
    stage: str,
    selectors: Sequence[str],
) -> dict[str, Any]:
    """Collect the deployed tests without executing them or writing bytecode."""

    if stage == "all_registered_unique":
        program = (
            "import json,sys;"
            "from pathlib import Path;"
            "from tests.foundation.registration_gate_runner "
            "import load_registration_suite;"
            "x=load_registration_suite(Path(sys.argv[1]));"
            "print(json.dumps({'selector_counts':x.selector_counts,"
            "'collected_test_ids':list(x.collected_test_ids),"
            "'collection_errors':list(x.collection_errors)},"
            "sort_keys=True,separators=(',',':')))"
        )
        command = [APPROVED_PYTHON_PATH, "-c", program, str(registry_path)]
    else:
        program = (
            "import json,sys;"
            "from tests.foundation.activation_gate_runner import load_gate_suite;"
            "x=load_gate_suite(json.loads(sys.argv[1]));"
            "print(json.dumps({'selector_counts':x.selector_counts,"
            "'collected_test_ids':list(x.collected_test_ids),"
            "'collection_errors':list(x.collection_errors)},"
            "sort_keys=True,separators=(',',':')))"
        )
        command = [
            APPROVED_PYTHON_PATH,
            "-c",
            program,
            json.dumps(list(selectors), ensure_ascii=False, separators=(",", ":")),
        ]
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        cwd=deployment_root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=True,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError("collection subprocess returned an ambiguous result")
    value = json.loads(lines[0])
    if not isinstance(value, dict) or set(value) != {
        "selector_counts",
        "collected_test_ids",
        "collection_errors",
    }:
        raise ValueError("collection subprocess returned a malformed result")
    return value


def _verify_gates(
    candidate: Mapping[str, Any],
    deployment_root: Path,
    sentinel: Mapping[str, Any],
    errors: list[str],
    test_only_collection_snapshots: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    raw_gates = candidate.get("gates")
    if not isinstance(raw_gates, list) or len(raw_gates) != len(REQUIRED_GATES):
        errors.append("gate evidence array does not contain the exact required gate set")
        return {}
    if any(not isinstance(item, Mapping) for item in raw_gates):
        errors.append("gate evidence contains a malformed item")
        return {}
    stage_names = [item.get("stage") for item in raw_gates]
    if any(not isinstance(stage, str) for stage in stage_names):
        errors.append("gate evidence contains a malformed stage")
        return {}
    if len(set(stage_names)) != len(stage_names):
        errors.append("gate evidence contains a duplicate stage")
    gates = {str(item.get("stage")): item for item in raw_gates}
    if set(gates) != set(REQUIRED_GATES):
        errors.append("required gate set is incomplete or contains unknown stages")
    registry_path = deployment_root / TEST_REGISTRY_RELATIVE_PATH
    try:
        registry = _load_json(registry_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        errors.append("unable to read the versioned test registry")
        return {}
    suites = registry.get("suites")
    if registry.get("schema") != "BPLUS_TEST_SUITES_V1" or not isinstance(
        suites, Mapping
    ):
        errors.append("versioned test registry schema mismatch")
        return {}
    approved_python = registry.get("approved_python")
    dependency_lock = registry.get("dependency_lock_sha256")
    test_home_root = registry.get("test_home_root")
    production_home = registry.get("production_home")
    if (
        approved_python != APPROVED_PYTHON_PATH
        or not _valid_sha256(dependency_lock)
        or not isinstance(test_home_root, str)
        or production_home != sentinel.get("production_home")
    ):
        errors.append("versioned test registry execution binding mismatch")
    lock_path = deployment_root / "requirements-bplus.lock"
    python_version_path = deployment_root / ".python-version"
    locked_versions: dict[str, str] = {}
    try:
        if (
            not lock_path.is_file()
            or lock_path.is_symlink()
            or _sha256(lock_path) != dependency_lock
            or python_version_path.is_symlink()
            or python_version_path.read_text(encoding="utf-8").strip() != "3.12.13"
        ):
            errors.append("versioned dependency lock or Python version mismatch")
        locked_versions = _locked_versions(lock_path)
        python_version = subprocess.check_output(
            [APPROVED_PYTHON_PATH, "-c", "import sys; print(sys.version.split()[0])"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if python_version != "3.12.13":
            errors.append("approved Python runtime version mismatch")
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.CalledProcessError,
    ):
        errors.append("unable to verify dependency lock and Python version")

    registered_selectors: list[str] = []
    for suite_value in suites.values():
        if not isinstance(suite_value, Mapping):
            errors.append("versioned test registry contains a malformed suite")
            continue
        for selector in suite_value.get("selectors", []):
            if isinstance(selector, str) and selector not in registered_selectors:
                registered_selectors.append(selector)
    expected_skip_details = [
        {"test_id": test_id, "reason": HISTORICAL_SKIP_REASON}
        for test_id in HISTORICAL_SKIP_IDS
    ]
    summaries: dict[str, Any] = {}
    evidence_identities: list[tuple[Any, Any]] = []
    for stage in REQUIRED_GATES:
        gate = gates.get(stage)
        if not isinstance(gate, Mapping):
            continue
        for field in (
            "collected",
            "executed",
            "passed",
            "failed",
            "errors",
            "skipped",
            "xfail",
            "xpass",
            "warnings",
            "external_attempts",
            "production_attempts",
        ):
            if not _integer(gate.get(field)):
                errors.append(f"{stage} has invalid {field}")
        if gate.get("collection_complete") is not True or gate.get("execution_complete") is not True:
            errors.append(f"{stage} is incomplete")
        if gate.get("execution_root") != str(deployment_root):
            errors.append(f"{stage} did not execute from the deployment root")
        if gate.get("control_override_used") is not False or gate.get("live_override_used") is not False:
            errors.append(f"{stage} used an override")
        if all(_integer(gate.get(field)) for field in ("collected", "executed", "passed", "skipped")):
            if gate["collected"] != gate["executed"]:
                errors.append(f"{stage} did not execute every collected test")
            if gate["executed"] < MINIMUM_GATE_COUNTS[stage]:
                errors.append(f"{stage} count fell below its acceptance floor")
            if gate["passed"] + gate["skipped"] != gate["executed"]:
                errors.append(f"{stage} pass/skip accounting is inconsistent")
        for field in (
            "failed",
            "errors",
            "xfail",
            "xpass",
            "warnings",
            "external_attempts",
            "production_attempts",
        ):
            if gate.get(field) != 0:
                errors.append(f"{stage} has non-zero {field}")
        skip_ids = gate.get("skip_ids")
        if stage == "all_registered_unique":
            if gate.get("skipped") != len(HISTORICAL_SKIP_IDS):
                errors.append("registered aggregate does not contain exactly five skips")
            if tuple(skip_ids or ()) != HISTORICAL_SKIP_IDS:
                errors.append("registered aggregate skip allowlist mismatch")
            if gate.get("skip_allowlist_match") is not True:
                errors.append("registered aggregate did not confirm the skip allowlist")
            if gate.get("discovered_test_files") != gate.get("registered_unique_selectors"):
                errors.append("registered aggregate discovery/registration mismatch")
        elif gate.get("skipped") != 0 or skip_ids not in (None, []):
            errors.append(f"{stage} contains an unexpected skip")
        evidence_reference = gate.get("evidence")
        evidence_identities.append(
            (
                evidence_reference.get("path")
                if isinstance(evidence_reference, Mapping)
                else None,
                evidence_reference.get("sha256")
                if isinstance(evidence_reference, Mapping)
                else None,
            )
        )
        _, evidence = _verify_file_reference(
            evidence_reference, errors, f"{stage} evidence"
        )
        if evidence is None:
            continue
        expected_suite = STAGE_SUITE_KEYS[stage]
        suite_config = suites.get(expected_suite)
        configured_selectors = (
            suite_config.get("selectors")
            if isinstance(suite_config, Mapping)
            else None
        )
        if stage in DIRECTED_STAGE_SELECTORS:
            expected_selectors = list(DIRECTED_STAGE_SELECTORS[stage])
        elif stage == "all_registered_unique":
            expected_selectors = registered_selectors
        else:
            expected_selectors = (
                configured_selectors
                if isinstance(configured_selectors, list)
                else None
            )
        if isinstance(approved_python, str) and isinstance(
            expected_selectors, list
        ):
            if stage == "all_registered_unique":
                expected_command = [
                    approved_python,
                    "-m",
                    "tests.foundation.registration_gate_runner",
                    "--registry",
                    str(registry_path),
                ]
            else:
                expected_command = [
                    approved_python,
                    "-m",
                    "tests.foundation.activation_gate_runner",
                    *expected_selectors,
                ]
        else:
            expected_command = None
        if evidence.get("schema") != TEST_RESULT_SCHEMA:
            errors.append(f"{stage} evidence schema mismatch")
        if set(evidence) != TEST_RESULT_FIELDS:
            errors.append(f"{stage} evidence field set mismatch")
        if evidence.get("stage") != stage:
            errors.append(f"{stage} evidence stage mismatch")
        if evidence.get("suite") != expected_suite:
            errors.append(f"{stage} evidence suite mismatch")
        if evidence.get("selectors") != expected_selectors:
            errors.append(f"{stage} evidence selector list mismatch")
        if evidence.get("command") != expected_command:
            errors.append(f"{stage} evidence command mismatch")
        if (
            evidence.get("mode") != "tests"
            or evidence.get("return_code") != 0
            or evidence.get("timed_out") is not False
            or not isinstance(evidence.get("duration_seconds"), (int, float))
            or isinstance(evidence.get("duration_seconds"), bool)
            or evidence.get("duration_seconds") < 0
            or not _valid_sha256(evidence.get("stdout_sha256"))
        ):
            errors.append(f"{stage} evidence did not complete successfully")
        child_cwd = evidence.get("child_cwd")
        if (
            not isinstance(child_cwd, str)
            or not isinstance(test_home_root, str)
            or not Path(child_cwd).is_relative_to(Path(test_home_root))
            or child_cwd == production_home
        ):
            errors.append(f"{stage} evidence child home is not isolated")
        if (
            evidence.get("warning_count") != gate.get("warnings")
            or evidence.get("warning_lines") != []
            or evidence.get("external_attempt_count") != gate.get("external_attempts")
            or evidence.get("production_attempt_count")
            != gate.get("production_attempts")
            or evidence.get("production_attempt_records") != []
            or evidence.get("production_attempt_log_sha256")
            != hashlib.sha256(b"").hexdigest()
            or evidence.get("production_guard_profile")
            != EXPECTED_PRODUCTION_GUARD_PROFILE
        ):
            errors.append(f"{stage} evidence attempt/warning binding mismatch")
        if (
            evidence.get("production_sentinel_baseline") != sentinel.get("base_path")
            or evidence.get("production_sentinel_before")
            != sentinel.get("base_report")
            or evidence.get("production_sentinel_after")
            != sentinel.get("base_report")
            or evidence.get("production_mutable_sentinel_baseline")
            != sentinel.get("mutable_path")
            or evidence.get("production_mutable_sentinel_before")
            != sentinel.get("mutable_report")
            or evidence.get("production_mutable_sentinel_after")
            != sentinel.get("mutable_report")
            or evidence.get("production_sentinel_unchanged") is not True
            or evidence.get("execution_manifest_hash") != sentinel.get("manifest_hash")
        ):
            errors.append(f"{stage} evidence sentinel/manifest binding mismatch")
        dependency = evidence.get("dependency_gate")
        if not isinstance(dependency, Mapping) or (
            set(dependency) != DEPENDENCY_RESULT_FIELDS
            or dependency.get("schema") != DEPENDENCY_RESULT_SCHEMA
            or dependency.get("accepted") is not True
            or dependency.get("dependencies_match") is not True
            or dependency.get("expected_lock_sha256") != dependency_lock
            or dependency.get("lock_sha256") != dependency_lock
            or dependency.get("lock_path") != str(lock_path)
            or dependency.get("python_executable") != approved_python
            or dependency.get("expected_python_version") != "3.12.13"
            or dependency.get("python_version") != "3.12.13"
            or dependency.get("python_match") is not True
            or dependency.get("manifest_binding_match") is not True
            or dependency.get("missing") != []
            or dependency.get("version_mismatches") != []
            or dependency.get("locked_versions") != locked_versions
            or dependency.get("installed_locked_versions") != locked_versions
            or dependency.get("locked_distribution_count")
            != len(locked_versions)
        ):
            errors.append(f"{stage} evidence dependency binding mismatch")

        strict_result = (
            evidence.get("registration_gate")
            if stage == "all_registered_unique"
            else evidence.get("activation_gate")
        )
        strict_schema = (
            REGISTRATION_RESULT_SCHEMA
            if stage == "all_registered_unique"
            else ACTIVATION_RESULT_SCHEMA
        )
        strict_policy = (
            "EXACT_HISTORICAL_SKIP_ALLOWLIST_V1"
            if stage == "all_registered_unique"
            else "ZERO_NONPASS_AND_COMPLETE_V1"
        )
        if not isinstance(strict_result, Mapping) or (
            set(strict_result)
            != (
                STRICT_COMMON_FIELDS | REGISTRATION_EXTRA_FIELDS
                if stage == "all_registered_unique"
                else STRICT_COMMON_FIELDS
            )
            or strict_result.get("schema") != strict_schema
            or strict_result.get("policy") != strict_policy
            or strict_result.get("accepted") is not True
            or strict_result.get("collection_complete") is not True
            or strict_result.get("execution_complete") is not True
        ):
            errors.append(f"{stage} strict result schema or completion mismatch")
            continue
        if stage == "all_registered_unique":
            if evidence.get("activation_gate") is not None:
                errors.append("registered evidence unexpectedly contains activation result")
        elif evidence.get("registration_gate") is not None:
            errors.append(f"{stage} evidence unexpectedly contains registration result")
        derived_counts = _strict_gate_counts(strict_result)
        if any(gate.get(field) != value for field, value in derived_counts.items()):
            errors.append(f"{stage} candidate/evidence count mismatch")
        if (
            evidence.get("test_count") != strict_result.get("executed_test_count")
            or evidence.get("skipped_count") != strict_result.get("skipped")
        ):
            errors.append(f"{stage} outer/inner test count mismatch")
        detail_fields = (
            "collection_errors",
            "failure_details",
            "error_details",
            "expected_failure_details",
            "unexpected_success_details",
            "missing_test_ids",
            "unexpected_test_ids",
        )
        if any(strict_result.get(field) != [] for field in detail_fields):
            errors.append(f"{stage} strict result contains non-pass details")
        selector_counts = strict_result.get("selector_counts")
        if (
            not isinstance(selector_counts, Mapping)
            or set(selector_counts) != set(expected_selectors or [])
            or any(
                not _integer(value) or value <= 0
                for value in selector_counts.values()
            )
            or sum(selector_counts.values()) != strict_result.get("collected_test_count")
        ):
            errors.append(f"{stage} strict result selector accounting mismatch")
        collected_ids = strict_result.get("collected_test_ids")
        started_ids = strict_result.get("started_test_ids")
        if (
            not isinstance(collected_ids, list)
            or not collected_ids
            or any(not isinstance(test_id, str) or not test_id for test_id in collected_ids)
            or len(collected_ids) != len(set(collected_ids))
            or started_ids != collected_ids
            or len(collected_ids) != strict_result.get("collected_test_count")
            or strict_result.get("collected_test_ids_sha256")
            != _json_value_sha256(collected_ids)
            or strict_result.get("started_test_ids_sha256")
            != _json_value_sha256(started_ids)
        ):
            errors.append(f"{stage} strict result exact test-ID closure mismatch")
        try:
            recomputed = (
                dict(test_only_collection_snapshots[stage])
                if test_only_collection_snapshots is not None
                else _recompute_deployment_collection(
                    deployment_root,
                    registry_path,
                    stage,
                    expected_selectors or [],
                )
            )
        except (
            KeyError,
            OSError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
        ):
            errors.append(f"{stage} deployed test collection could not be recomputed")
            recomputed = {}
        if (
            recomputed.get("collection_errors") != []
            or recomputed.get("selector_counts") != selector_counts
            or recomputed.get("collected_test_ids") != collected_ids
            or _json_value_sha256(recomputed.get("collected_test_ids"))
            != strict_result.get("collected_test_ids_sha256")
        ):
            errors.append(f"{stage} evidence differs from deployed test collection")
        if stage == "all_registered_unique":
            if (
                strict_result.get("selector_count") != len(expected_selectors or [])
                or strict_result.get("skip_allowlist_match") is not True
                or strict_result.get("skip_details") != expected_skip_details
                or strict_result.get("expected_skip_details") != expected_skip_details
                or gate.get("discovered_test_files") != len(expected_selectors or [])
                or gate.get("registered_unique_selectors")
                != len(expected_selectors or [])
            ):
                errors.append("registered aggregate exact registration binding mismatch")
        elif strict_result.get("skip_details") != []:
            errors.append(f"{stage} strict result contains unexpected skips")
        summaries[stage] = {
            field: gate.get(field)
            for field in (
                "collected",
                "executed",
                "passed",
                "failed",
                "errors",
                "skipped",
                "xfail",
                "xpass",
                "warnings",
            )
        }
    if len(set(evidence_identities)) != len(REQUIRED_GATES):
        errors.append("gate evidence references are not seven unique artifacts")
    return summaries


def _verify_review(
    value: Any,
    source_state: Mapping[str, Any],
    source_root: Path,
    deployment_root: Path,
    expected_stage: str,
    required_reference_identities: set[tuple[str, str]],
    errors: list[str],
    label: str,
    anchor_root: Path,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{label} is missing")
        return {}
    if set(value) != REAL_REVIEW_CANDIDATE_FIELDS:
        errors.append(f"{label} candidate field set mismatch")
    if value.get("review_stage") != expected_stage:
        errors.append(f"{label} review stage mismatch")
    input_path, review_input = _verify_file_reference(
        value.get("input"),
        errors,
        f"{label} input",
    )
    required_files = (
        review_input.get("required_files")
        if isinstance(review_input, Mapping)
        else None
    )
    input_reference_identities: list[tuple[str, str]] = []
    if not isinstance(review_input, Mapping) or (
        set(review_input)
        != {"schema", "review_stage", "source", "required_files", "rules"}
        or review_input.get("schema") != "SITINA_STEP7_REAL_REVIEW_INPUT_V1"
        or review_input.get("review_stage") != expected_stage
        or review_input.get("source")
        != {"head": source_state.get("head"), "tree": source_state.get("tree")}
        or not isinstance(required_files, list)
        or not required_files
        or review_input.get("rules")
        != {
            "read_only_tools_only": True,
            "all_required_files_must_be_read": True,
            "terminal_verdict": "PASS",
            "step8_step9_forbidden": True,
        }
    ):
        errors.append(f"{label} input schema or source binding mismatch")
        required_files = []
    for index, reference in enumerate(required_files):
        if not isinstance(reference, Mapping) or (
            set(reference) != {"path", "sha256", "media_type", "purpose"}
            or reference.get("media_type") not in ("json", "jsonl", "text")
            or not isinstance(reference.get("purpose"), str)
            or not reference.get("purpose")
        ):
            errors.append(f"{label} input required file {index} is malformed")
            continue
        _verify_file_reference(
            reference,
            errors,
            f"{label} input required file {index}",
            require_json_object=reference.get("media_type") == "json",
        )
        input_reference_identities.append(
            (str(reference.get("path")), str(reference.get("sha256")))
        )
    if (
        len(input_reference_identities) != len(set(input_reference_identities))
        or set(input_reference_identities) != required_reference_identities
    ):
        errors.append(f"{label} input required-file closure mismatch")
    audit_path, _ = _verify_file_reference(
        value.get("audit"),
        errors,
        f"{label} audit",
        require_json_object=False,
    )
    if audit_path is None:
        return {}
    receipt_path, receipt = _verify_file_reference(
        value.get("receipt"),
        errors,
        f"{label} capture receipt",
    )
    try:
        records = _load_json_lines(audit_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{label} audit is not valid JSONL: {type(exc).__name__}")
        return {}
    run_ids = {record.get("run_id") for record in records}
    if len(run_ids) != 1 or not all(
        isinstance(run_id, str) and run_id for run_id in run_ids
    ):
        errors.append(f"{label} audit run ID set is invalid")
        return {}
    run_id = next(iter(run_ids))
    for record in records:
        if (
            record.get("schema") != AUTONOMOUS_AUDIT_SCHEMA
            or not _valid_iso8601(record.get("timestamp"))
        ):
            errors.append(f"{label} audit contains an invalid event")
    events = [record.get("event") for record in records]
    counts = Counter(events)
    allowed_events = {
        "run_started",
        "provider_call_intended",
        "model_turn_completed",
        "tool_call_intended",
        "tool_completed",
        "run_succeeded",
    }
    if any(event not in allowed_events for event in events):
        errors.append(f"{label} audit contains a non-read or unsupported event")
    for record in records:
        expected_fields = AUDIT_EVENT_FIELDS.get(str(record.get("event")))
        if expected_fields is None or set(record) != expected_fields:
            errors.append(f"{label} audit event field set mismatch")
    if (
        events[0] != "run_started"
        or events[-1] != "run_succeeded"
        or counts["run_started"] != 1
        or counts["run_succeeded"] != 1
        or any(
            counts[event]
            for event in (
                "run_failed",
                "run_turn_cap_reached",
                "provider_call_failed",
                "run_stuck",
            )
        )
    ):
        errors.append(f"{label} audit terminal event sequence is invalid")
    started = records[0]
    terminal = records[-1]
    timestamps_valid = all(
        _valid_iso8601(record.get("timestamp")) for record in records
    )
    if timestamps_valid:
        started_time = _iso_datetime(started["timestamp"])
        terminal_time = _iso_datetime(terminal["timestamp"])
        if started_time >= terminal_time or any(
            not (started_time <= _iso_datetime(record["timestamp"]) <= terminal_time)
            for record in records
        ):
            errors.append(f"{label} audit event timestamps escape the run interval")
    if input_path is not None and str(input_path) not in str(started.get("task", "")):
        errors.append(f"{label} audit task does not bind its input artifact")

    provider_intended = [
        record for record in records if record.get("event") == "provider_call_intended"
    ]
    model_turns = [
        record for record in records if record.get("event") == "model_turn_completed"
    ]
    intended_turns = [record.get("turn") for record in provider_intended]
    completed_turns = [record.get("turn") for record in model_turns]
    expected_turns = list(range(1, len(model_turns) + 1))
    if (
        not model_turns
        or intended_turns != expected_turns
        or completed_turns != expected_turns
    ):
        errors.append(f"{label} audit provider/model turn closure mismatch")
    record_positions = {id(record): index for index, record in enumerate(records)}
    for intended, completed in zip(provider_intended, model_turns):
        if (
            record_positions[id(intended)] >= record_positions[id(completed)]
            or (
                timestamps_valid
                and _iso_datetime(intended["timestamp"])
                > _iso_datetime(completed["timestamp"])
            )
        ):
            errors.append(f"{label} audit provider/model event topology mismatch")

    usage_fields = (
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    )
    usage = {field: 0 for field in usage_fields}
    provider_request_ids: list[str] = []
    model_call_ids: list[str] = []
    model_read_paths: list[str] = []
    for turn_index, turn in enumerate(model_turns):
        intended = (
            provider_intended[turn_index]
            if turn_index < len(provider_intended)
            else {}
        )
        wire_messages = _openai_wire_messages(
            intended.get("system_prompt"),
            intended.get("messages"),
        )
        expected_input_hash = (
            "sha256:"
            + _canonical_sha256(
                {
                    "system": None,
                    "messages": wire_messages,
                }
            )
        )
        metadata = turn.get("metadata")
        turn_usage = (
            metadata.get("token_usage") if isinstance(metadata, Mapping) else None
        )
        if not isinstance(metadata, Mapping) or (
            set(metadata) != MODEL_METADATA_FIELDS
            or metadata.get("provider_mode") != "live"
            or metadata.get("profile_name") != "deepseek"
            or metadata.get("model") != "deepseek-v4-pro"
            or metadata.get("protocol") != "openai_chat_completions"
            or metadata.get("fallback_used") is not False
            or metadata.get("protocol_fallback_used") is not False
            or wire_messages is None
            or metadata.get("input_hash") != expected_input_hash
            or not _valid_sha256(metadata.get("output_hash"), prefixed=True)
        ):
            errors.append(f"{label} audit provider metadata mismatch")
        if isinstance(metadata, Mapping) and isinstance(turn.get("text"), str) and (
            metadata.get("output_hash")
            != f"sha256:{_sha256_text(turn.get('text'))}"
        ):
            errors.append(f"{label} audit model output hash mismatch")
        if not isinstance(turn_usage, Mapping) or any(
            not _integer(turn_usage.get(field)) for field in usage_fields
        ) or set(turn_usage) != set(usage_fields):
            errors.append(f"{label} audit token usage is invalid")
        else:
            if turn_usage["total_tokens"] != (
                turn_usage["input_tokens"] + turn_usage["output_tokens"]
            ):
                errors.append(f"{label} audit per-turn token accounting mismatch")
            for field in usage_fields:
                usage[field] += turn_usage[field]
        request_id = (
            metadata.get("provider_request_id")
            if isinstance(metadata, Mapping)
            else None
        )
        provider_request_ids.append(request_id if isinstance(request_id, str) else "")
        tool_calls = turn.get("tool_calls")
        if not isinstance(tool_calls, list):
            errors.append(f"{label} audit model turn tool calls are invalid")
            continue
        if isinstance(metadata, Mapping) and metadata.get("tool_call_count") != len(
            tool_calls
        ):
            errors.append(f"{label} audit model/tool count mismatch")
        for call in tool_calls:
            if (
                not isinstance(call, Mapping)
                or set(call) != {"arguments", "id", "name"}
                or call.get("name") != "sitina_read_file"
                or not isinstance(call.get("id"), str)
                or not isinstance(call.get("arguments"), Mapping)
                or not isinstance(call["arguments"].get("path"), str)
                or not Path(call["arguments"]["path"]).is_absolute()
            ):
                errors.append(f"{label} audit used a non-read or malformed tool call")
            else:
                model_call_ids.append(call["id"])
                raw_path = call["arguments"]["path"]
                verified_read_path = _safe_regular_file(
                    raw_path, errors, f"{label} audit read"
                )
                if verified_read_path is not None:
                    resolved_read_path = verified_read_path.resolve(strict=True)
                    allowed_roots = (
                        source_root.resolve(strict=True),
                        deployment_root.resolve(strict=True),
                        Path("/Users/moss/Desktop/sitina/output").resolve(strict=True),
                    )
                    fixed_allowed_paths = {
                        Path(STEP56_SOURCE_SESSION_PATH).resolve(strict=True),
                        Path(
                            "/Users/moss/.codex/attachments/"
                            "198f270e-7042-4d01-aac5-ff595095d657/pasted-text-1.txt"
                        ).resolve(strict=True),
                        *(
                            {input_path.resolve(strict=True)}
                            if input_path is not None
                            else set()
                        ),
                        *{
                            Path(path).resolve(strict=True)
                            for path, _digest in input_reference_identities
                        },
                    }
                    if resolved_read_path not in fixed_allowed_paths and not any(
                        resolved_read_path.is_relative_to(root)
                        for root in allowed_roots
                    ):
                        errors.append(
                            f"{label} audit read outside the allowed evidence roots"
                        )
                model_read_paths.append(raw_path)
    if (
        any(not request_id for request_id in provider_request_ids)
        or len(set(provider_request_ids)) != len(provider_request_ids)
    ):
        errors.append(f"{label} audit provider request IDs are missing or duplicated")

    intended_calls = [
        record for record in records if record.get("event") == "tool_call_intended"
    ]
    completed_calls = [
        record for record in records if record.get("event") == "tool_completed"
    ]
    intended_ids = [record.get("call_id") for record in intended_calls]
    completed_ids = [record.get("call_id") for record in completed_calls]
    if (
        not model_call_ids
        or len(model_call_ids) != len(set(model_call_ids))
        or Counter(model_call_ids) != Counter(intended_ids)
        or Counter(model_call_ids) != Counter(completed_ids)
    ):
        errors.append(f"{label} audit tool event closure mismatch")
    expected_read_paths = (
        [str(input_path), *(path for path, _digest in input_reference_identities)]
        if input_path is not None
        else []
    )
    if model_read_paths != expected_read_paths:
        errors.append(f"{label} audit did not read the exact bound input file set")
    model_call_positions: dict[str, int] = {}
    for turn in model_turns:
        for call in turn.get("tool_calls", []):
            if isinstance(call, Mapping) and isinstance(call.get("id"), str):
                model_call_positions[call["id"]] = record_positions[id(turn)]
    intended_by_id = {
        record.get("call_id"): record
        for record in intended_calls
        if isinstance(record.get("call_id"), str)
    }
    completed_by_id = {
        record.get("call_id"): record
        for record in completed_calls
        if isinstance(record.get("call_id"), str)
    }
    for call_id, model_position in model_call_positions.items():
        intended = intended_by_id.get(call_id)
        completed = completed_by_id.get(call_id)
        if intended is None or completed is None:
            continue
        if not (
            model_position < record_positions[id(intended)] < record_positions[id(completed)]
        ) or (
            timestamps_valid
            and _iso_datetime(intended["timestamp"])
            > _iso_datetime(completed["timestamp"])
        ):
            errors.append(f"{label} audit tool event topology mismatch")
    for turn_number in range(1, len(model_turns)):
        previous_call_ids = [
            call.get("id")
            for call in model_turns[turn_number - 1].get("tool_calls", [])
            if isinstance(call, Mapping)
        ]
        next_provider_position = record_positions[id(provider_intended[turn_number])]
        if any(
            call_id in completed_by_id
            and record_positions[id(completed_by_id[call_id])] >= next_provider_position
            for call_id in previous_call_ids
        ):
            errors.append(f"{label} audit next provider turn preceded tool completion")
    for record in intended_calls:
        summary = record.get("argument_summary")
        if (
            record.get("name") != "sitina_read_file"
            or record.get("permission") != "read"
            or not isinstance(summary, Mapping)
            or set(summary)
            != {
                "argument_bytes_after_redaction",
                "argument_hash",
                "argument_keys",
                "normalized_tool_name",
                "redacted_paths",
                "schema",
            }
            or summary.get("schema") != "SITINA_TOOL_ARGUMENT_SUMMARY_V1"
            or summary.get("normalized_tool_name") != "sitina.sitina_read_file"
        ):
            errors.append(f"{label} audit intended a non-read tool")
    for record in completed_calls:
        result = record.get("result_summary")
        if (
            record.get("permission") != "read"
            or not isinstance(result, Mapping)
            or set(result)
            != {
                "duration_ms",
                "error",
                "normalized_tool_name",
                "permission_decision",
                "result_bytes_after_redaction",
                "result_redacted_paths",
                "result_ref",
                "schema",
                "status",
            }
            or result.get("schema") != "SITINA_TOOL_RESULT_SUMMARY_V1"
            or result.get("normalized_tool_name") != "sitina.sitina_read_file"
            or result.get("permission_decision") != "allowed"
            or result.get("status") != "ok"
            or result.get("error") is not None
            or not _valid_sha256(result.get("result_ref"), prefixed=True)
        ):
            errors.append(f"{label} audit contains a failed or denied read")

    response = terminal.get("response")
    last_turn = model_turns[-1] if model_turns else {}
    if (
        not isinstance(response, str)
        or last_turn.get("text") != response
        or last_turn.get("stop_reason") != "stop"
        or last_turn.get("tool_calls") != []
    ):
        errors.append(f"{label} audit final model response binding mismatch")
    try:
        review_result = json.loads(response) if isinstance(response, str) else None
    except json.JSONDecodeError:
        review_result = None
    if not isinstance(review_result, Mapping) or (
        set(review_result)
        != {
            "schema",
            "review_stage",
            "source_head",
            "source_tree",
            "verdict",
            "blockers",
            "step8_step9_not_entered",
            "files_read",
        }
        or review_result.get("schema") != "SITINA_STEP7_REAL_REVIEW_RESULT_V1"
        or review_result.get("review_stage") != value.get("review_stage")
        or review_result.get("source_head") != source_state.get("head")
        or review_result.get("source_tree") != source_state.get("tree")
        or review_result.get("verdict") != "PASS"
        or review_result.get("blockers") != []
        or review_result.get("step8_step9_not_entered") is not True
        or not isinstance(review_result.get("files_read"), list)
        or review_result.get("files_read")
        != list(dict.fromkeys(model_read_paths))
    ):
        errors.append(f"{label} audit has no bound terminal PASS verdict")

    derived = {
        "run_id": run_id,
        "provider_mode": "live",
        "profile": "deepseek",
        "model": "deepseek-v4-pro",
        "terminal_state": "run_succeeded",
        "started_at_utc": started.get("timestamp"),
        "ended_at_utc": terminal.get("timestamp"),
        "provider_calls": len(model_turns),
        **usage,
        "verdict": (
            review_result.get("verdict")
            if isinstance(review_result, Mapping)
            else None
        ),
        "input_sha256": _sha256(input_path) if input_path is not None else None,
        "output_sha256": _sha256_text(response) if isinstance(response, str) else None,
        "tool_call_count": len(model_call_ids),
        "tool_call_types": ["sitina_read_file"],
        "tool_permissions": ["read"],
        "file_changes": 0,
        "external_changes": 0,
        "denied_tool_calls": 0,
        "unique_files_changed": 0,
    }
    if any(value.get(field) != expected for field, expected in derived.items()):
        errors.append(f"{label} candidate/audit derived fields mismatch")
    if usage["input_tokens"] <= 0 or usage["output_tokens"] <= 0 or usage[
        "total_tokens"
    ] <= 0:
        errors.append(f"{label} audit has zero token usage")
    expected_receipt_usage = {field: usage[field] for field in usage_fields}
    receipt_anchor_payload = {
        "review_stage": expected_stage,
        "run_id": run_id,
        "input_sha256": _sha256(input_path) if input_path is not None else None,
        "audit_sha256": _sha256(audit_path),
        "event_chain_sha256": _audit_event_chain_sha256(records),
        "provider_request_ids": provider_request_ids,
        "usage": expected_receipt_usage,
    }
    if not isinstance(receipt, Mapping) or (
        set(receipt) != REAL_REVIEW_RECEIPT_FIELDS
        or receipt.get("schema") != REAL_REVIEW_RECEIPT_SCHEMA
        or receipt.get("review_stage") != expected_stage
        or receipt.get("run_id") != run_id
        or not _valid_iso8601(receipt.get("created_at_utc"))
        or receipt.get("input")
        != {
            "path": str(input_path) if input_path is not None else None,
            "sha256": _sha256(input_path) if input_path is not None else None,
        }
        or receipt.get("audit")
        != {
            "path": str(audit_path),
            "sha256": _sha256(audit_path),
            "format": "jsonl",
        }
        or receipt.get("event_count") != len(records)
        or receipt.get("first_event") != events[0]
        or receipt.get("last_event") != events[-1]
        or receipt.get("event_chain_sha256")
        != _audit_event_chain_sha256(records)
        or receipt.get("provider_request_ids") != provider_request_ids
        or receipt.get("usage") != expected_receipt_usage
        or receipt.get("boundary")
        != "PRE_DEPLOYMENT_READ_ONLY_REVIEW_CAPTURE_V1"
        or receipt_path is None
    ):
        errors.append(f"{label} capture receipt binding mismatch")
    else:
        _verify_codex_capture_anchor(
            receipt.get("capture_anchor"),
            marker=AUDIT_CAPTURE_ANCHOR_MARKER,
            expected_payload=receipt_anchor_payload,
            anchor_root=anchor_root,
            errors=errors,
            label=f"{label} capture receipt",
        )
    return derived


def _verify_cleanup(
    candidate: Mapping[str, Any],
    source_state: Mapping[str, Any],
    source_root: Path,
    deployment_root: Path,
    errors: list[str],
    anchor_root: Path,
) -> dict[str, Any]:
    cleanup = candidate.get("cleanup")
    if not isinstance(cleanup, Mapping):
        errors.append("cleanup closure is missing")
        return {}
    cleanup_required_references = {
        (
            str(reference.get("path")),
            str(reference.get("sha256")),
        )
        for reference in (cleanup.get("candidate"), cleanup.get("ledger"))
        if isinstance(reference, Mapping)
    }
    _, cleanup_candidate = _verify_file_reference(
        cleanup.get("candidate"), errors, "cleanup candidate"
    )
    _, ledger = _verify_file_reference(cleanup.get("ledger"), errors, "cleanup ledger")
    candidate_path = (
        cleanup.get("candidate", {}).get("path")
        if isinstance(cleanup.get("candidate"), Mapping)
        else None
    )
    candidate_sha = (
        cleanup.get("candidate", {}).get("sha256")
        if isinstance(cleanup.get("candidate"), Mapping)
        else None
    )
    candidate_items: list[Mapping[str, Any]] = []
    if not isinstance(cleanup_candidate, Mapping) or (
        set(cleanup_candidate) != CLEANUP_CANDIDATE_FIELDS
        or cleanup_candidate.get("schema") != CLEANUP_CANDIDATE_SCHEMA
        or cleanup_candidate.get("candidate_name") != "STEP7_CLEANUP_CANDIDATE"
        or cleanup_candidate.get("draft") is not True
        or cleanup_candidate.get("verdict")
        != "DRAFT_PENDING_MAIN_REVIEW_AND_REAL_SITINA_REVIEW"
        or cleanup_candidate.get("step8_step9_not_entered") is not True
    ):
        errors.append("cleanup candidate schema mismatch")
    else:
        authority = cleanup_candidate.get("authority")
        if not isinstance(authority, Mapping) or (
            authority.get("step7_definition") != "CANARY_READY"
            or authority.get("definition_path") != STEP7_AUTHORITY_PATH
            or authority.get("definition_physical_sha256")
            != STEP7_AUTHORITY_SHA256
            or authority.get("phase6b_step7_mixed_in") is not False
        ):
            errors.append("cleanup candidate authority binding mismatch")
        scope = cleanup_candidate.get("scope")
        absent = (
            scope.get("forbidden_actions_confirmed_absent")
            if isinstance(scope, Mapping)
            else None
        )
        if (
            not isinstance(scope, Mapping)
            or scope.get("categories") != ["old_data", "old_code", "old_operations"]
            or not isinstance(absent, Mapping)
            or not absent
            or any(value is not False for value in absent.values())
        ):
            errors.append("cleanup candidate action boundary mismatch")
        objects = cleanup_candidate.get("objects")
        old_operations = cleanup_candidate.get("old_operations")
        operation_items = (
            old_operations.get("items")
            if isinstance(old_operations, Mapping)
            else None
        )
        scheduler = (
            old_operations.get("launchd_cron_read_only_inventory")
            if isinstance(old_operations, Mapping)
            else None
        )
        if (
            not isinstance(objects, list)
            or not isinstance(operation_items, list)
            or not isinstance(scheduler, Mapping)
            or len(objects) != 11
            or len(operation_items) != 8
        ):
            errors.append("cleanup candidate object inventory shape mismatch")
        else:
            raw_items = [*objects, *operation_items, scheduler]
            if not all(isinstance(item, Mapping) for item in raw_items):
                errors.append("cleanup candidate contains a malformed object")
            else:
                candidate_items = list(raw_items)
                candidate_ids = [item.get("candidate_id") for item in candidate_items]
                if (
                    tuple(candidate_ids) != CLEANUP_OBJECT_IDS
                    or len(set(candidate_ids)) != len(CLEANUP_OBJECT_IDS)
                ):
                    errors.append("cleanup candidate exact object set mismatch")
                for index, item in enumerate(candidate_items):
                    if (
                        item.get("candidate_id") != CLEANUP_OBJECT_IDS[index]
                        or item.get("category")
                        not in ("old_data", "old_code", "old_operations")
                        or item.get("recommended_action")
                        not in (
                            "KEEP",
                            "REVIEW",
                            "QUARANTINE",
                            "REMOVE_CODE",
                            "APPROVAL_REQUIRED",
                        )
                        or not isinstance(item.get("approval_status"), str)
                        or not isinstance(item.get("actual_action"), str)
                    ):
                        errors.append(
                            f"cleanup candidate object {index} contract mismatch"
                        )
                action_projection = [
                    {
                        field: item.get(field)
                        for field in (
                            "candidate_id",
                            "category",
                            "recommended_action",
                            "approval_status",
                            "actual_action",
                        )
                    }
                    for item in candidate_items
                ]
                if (
                    _json_value_sha256(action_projection)
                    != CLEANUP_ACTION_SEMANTICS_SHA256
                ):
                    errors.append(
                        "cleanup candidate action semantics differ from the "
                        "accepted zero-action inventory"
                    )
        coverage = cleanup_candidate.get("coverage_summary")
        if not isinstance(coverage, Mapping) or (
            coverage.get("old_data_candidate_count") != 10
            or coverage.get("old_code_candidate_count") != 1
            or coverage.get("old_operation_candidate_count") != 9
            or coverage.get("new_actions_executed_by_this_draft") != 0
            or coverage.get("historical_recoverable_quarantine_files") != 62
        ):
            errors.append("cleanup candidate coverage summary mismatch")
        evidence_sources = cleanup_candidate.get("evidence_sources")
        if not isinstance(evidence_sources, list) or len(evidence_sources) != 10:
            errors.append("cleanup candidate evidence-source set mismatch")
        else:
            evidence_identities: list[tuple[str, str]] = []
            for index, reference in enumerate(evidence_sources):
                if not isinstance(reference, Mapping) or (
                    not isinstance(reference.get("path"), str)
                    or not _valid_sha256(reference.get("physical_sha256"))
                ):
                    errors.append(
                        f"cleanup candidate evidence source {index} is malformed"
                    )
                    continue
                source_path = _safe_regular_file(
                    reference["path"],
                    errors,
                    f"cleanup candidate evidence source {index}",
                )
                evidence_identities.append(
                    (reference["path"], reference["physical_sha256"])
                )
                if source_path is None or _sha256(source_path) != reference.get(
                    "physical_sha256"
                ):
                    errors.append(
                        f"cleanup candidate evidence source {index} SHA-256 mismatch"
                    )
                if "schema" in reference:
                    try:
                        source_document = _load_json(source_path) if source_path else None
                    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                        source_document = None
                    if (
                        not isinstance(source_document, Mapping)
                        or source_document.get("schema") != reference.get("schema")
                    ):
                        errors.append(
                            f"cleanup candidate evidence source {index} schema mismatch"
                        )
            if len(evidence_identities) != len(set(evidence_identities)):
                errors.append("cleanup candidate evidence sources are duplicated")
    if not isinstance(ledger, Mapping) or (
        set(ledger) != CLEANUP_LEDGER_FIELDS
        or ledger.get("schema") != CLEANUP_LEDGER_SCHEMA
        or ledger.get("ledger_name") != "STEP7_CLEANUP_LEDGER"
        or ledger.get("draft") is not True
        or ledger.get("verdict")
        != "DRAFT_PENDING_MAIN_REVIEW_AND_REAL_SITINA_REVIEW"
        or ledger.get("step8_step9_not_entered") is not True
    ):
        errors.append("cleanup ledger schema mismatch")
    else:
        approved = ledger.get("approved_action_count")
        completed = ledger.get("completed_approved_action_count")
        if (
            not _integer(approved)
            or not _integer(completed)
            or approved != 0
            or completed != 0
        ):
            errors.append("approved cleanup actions are not exactly the empty set")
        if ledger.get("new_actions_performed_during_step7") != 0:
            errors.append("Step7 performed a new cleanup action")
        if ledger.get("permanent_deletion") is not False:
            errors.append("cleanup ledger records permanent deletion")
        if ledger.get("unapproved_actions_performed") != 0:
            errors.append("cleanup ledger records an unapproved action")
        candidate_binding = ledger.get("candidate_binding")
        if not isinstance(candidate_binding, Mapping) or (
            set(candidate_binding)
            != {"path", "physical_sha256", "schema", "binding_rule"}
            or candidate_binding.get("path") != candidate_path
            or candidate_binding.get("physical_sha256") != candidate_sha
            or candidate_binding.get("schema") != CLEANUP_CANDIDATE_SCHEMA
        ):
            errors.append("cleanup ledger/candidate physical binding mismatch")
        entry_binding = ledger.get("step56_entry_binding")
        if not isinstance(entry_binding, Mapping) or (
            entry_binding.get("path")
            != "/Users/moss/Desktop/sitina/output/"
            "sitina-step7-entry-review-candidate-step56-45a36be.json"
            or entry_binding.get("physical_sha256") != ENTRY_CANDIDATE_SHA256
        ):
            errors.append("cleanup ledger Step5/6 entry binding mismatch")
        action_boundary = ledger.get("action_boundary")
        if not isinstance(action_boundary, Mapping) or any(
            value != 0
            for key, value in action_boundary.items()
            if key != "purpose"
        ):
            errors.append("cleanup ledger action boundary is not zero")
        entries = ledger.get("entries")
        if not isinstance(entries, list) or len(entries) != len(CLEANUP_OBJECT_IDS):
            errors.append("cleanup ledger exact entry set mismatch")
        else:
            candidate_by_id = {
                str(item.get("candidate_id")): item for item in candidate_items
            }
            entry_ids = [
                item.get("candidate_id")
                for item in entries
                if isinstance(item, Mapping)
            ]
            if tuple(entry_ids) != CLEANUP_OBJECT_IDS:
                errors.append("cleanup ledger exact entry order or identity mismatch")
            for index, entry in enumerate(entries):
                source_item = (
                    candidate_by_id.get(str(entry.get("candidate_id")))
                    if isinstance(entry, Mapping)
                    else None
                )
                if not isinstance(entry, Mapping) or (
                    set(entry) != CLEANUP_LEDGER_ENTRY_FIELDS
                    or entry.get("new_action_authorized") is not False
                    or source_item is None
                    or entry.get("category") != source_item.get("category")
                    or entry.get("recommendation")
                    != source_item.get("recommended_action")
                    or entry.get("approval_status")
                    != source_item.get("approval_status")
                    or entry.get("actual_action") != source_item.get("actual_action")
                ):
                    errors.append(f"cleanup ledger entry {index} closure mismatch")
        totals = ledger.get("entry_totals")
        coverage = (
            cleanup_candidate.get("coverage_summary")
            if isinstance(cleanup_candidate, Mapping)
            else None
        )
        if not isinstance(totals, Mapping) or (
            totals.get("total") != len(CLEANUP_OBJECT_IDS)
            or totals.get("by_category")
            != {"old_data": 10, "old_code": 1, "old_operations": 9}
            or not isinstance(coverage, Mapping)
            or totals.get("by_recommendation") != coverage.get("recommended_actions")
            or totals.get("entries_with_new_action_authorized") != 0
            or totals.get("entries_with_new_action_executed") != 0
        ):
            errors.append("cleanup ledger aggregate closure mismatch")
        internal_review = ledger.get("real_sitina_review")
        if not isinstance(internal_review, Mapping) or (
            internal_review.get("status") != "PENDING"
            or internal_review.get("verdict") is not None
            or internal_review.get("claimed_as_pass") is not False
            or internal_review.get("input_tokens") != 0
            or internal_review.get("output_tokens") != 0
            or internal_review.get("total_tokens") != 0
            or internal_review.get("tool_call_types") != []
            or internal_review.get("file_changes") != 0
            or internal_review.get("external_changes") != 0
        ):
            errors.append("cleanup ledger draft review state mismatch")
    return _verify_review(
        cleanup.get("real_sitina_review"),
        source_state,
        source_root,
        deployment_root,
        "CLEANUP_CLOSURE",
        cleanup_required_references,
        errors,
        "cleanup Sitina review",
        anchor_root,
    )


def _verify_switches(
    candidate: Mapping[str, Any],
    source_root: Path,
    deployment_root: Path,
    errors: list[str],
) -> None:
    declared = candidate.get("execution_switches")
    if not isinstance(declared, Mapping):
        errors.append("execution-switch evidence is missing")
        return
    source_policy = source_root / POLICY_RELATIVE_PATH
    deployment_policy = deployment_root / POLICY_RELATIVE_PATH
    try:
        if source_policy.is_symlink() or deployment_policy.is_symlink():
            raise ValueError("policy file is a symlink")
        source = _load_json(source_policy)
        deployment = _load_json(deployment_policy)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        errors.append("unable to read source/deployment execution policy")
        return
    if _sha256(source_policy) != _sha256(deployment_policy):
        errors.append("source/deployment execution policy differs")
    for field in SWITCHES:
        if declared.get(field) is not False or source.get(field) is not False or deployment.get(field) is not False:
            errors.append(f"execution switch is not false: {field}")


def _internal_report_hash(document: Mapping[str, Any]) -> str:
    value = dict(document)
    value.pop("report_sha256", None)
    return _canonical_sha256(value)


def _verify_sentinel(
    candidate: Mapping[str, Any],
    deployment_root: Path,
    errors: list[str],
) -> dict[str, Any]:
    sentinel = candidate.get("production_sentinel")
    if not isinstance(sentinel, Mapping):
        errors.append("production sentinel evidence is missing")
        return {}
    if sentinel.get("goal_id") != OFFICIAL_GOAL_ID:
        errors.append("production sentinel Goal binding mismatch")
    base_ref = sentinel.get("base_baseline")
    mutable_ref = sentinel.get("mutable_baseline")
    manifest_ref = sentinel.get("execution_manifest")
    _, base = _verify_file_reference(base_ref, errors, "production base baseline")
    _, mutable = _verify_file_reference(
        mutable_ref, errors, "production mutable baseline"
    )
    _, manifest = _verify_file_reference(
        manifest_ref, errors, "production execution manifest"
    )
    fixed_references = (
        (base_ref, BASE_SENTINEL_PATH, BASE_SENTINEL_PHYSICAL_SHA256, "base"),
        (
            mutable_ref,
            MUTABLE_SENTINEL_PATH,
            MUTABLE_SENTINEL_PHYSICAL_SHA256,
            "mutable",
        ),
        (
            manifest_ref,
            EXECUTION_MANIFEST_PATH,
            EXECUTION_MANIFEST_PHYSICAL_SHA256,
            "manifest",
        ),
    )
    for reference, path, digest, label in fixed_references:
        if not isinstance(reference, Mapping) or (
            reference.get("path") != path or reference.get("sha256") != digest
        ):
            errors.append(f"production {label} artifact is not the fixed baseline")
    if base is not None and (
        base.get("schema") != BASE_SENTINEL_SCHEMA
        or base.get("goal_thread_id") != OFFICIAL_GOAL_ID
        or base.get("production_home") != "/Users/moss/SitinaHub"
        or base.get("observation_mode")
        != "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2"
        or base.get("report_sha256") != BASE_SENTINEL_REPORT_SHA256
        or _internal_report_hash(base) != BASE_SENTINEL_REPORT_SHA256
    ):
        errors.append("production base baseline content binding mismatch")
    if mutable is not None and (
        mutable.get("schema") != MUTABLE_SENTINEL_SCHEMA
        or mutable.get("goal_thread_id") != OFFICIAL_GOAL_ID
        or mutable.get("production_home") != "/Users/moss/SitinaHub"
        or mutable.get("observation_mode")
        != "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2"
        or mutable.get("report_sha256") != MUTABLE_SENTINEL_REPORT_SHA256
        or mutable.get("base_v1_report_sha256") != BASE_SENTINEL_REPORT_SHA256
        or _internal_report_hash(mutable) != MUTABLE_SENTINEL_REPORT_SHA256
    ):
        errors.append("production mutable baseline content binding mismatch")
    manifest_hash = (
        f"sha256:{_canonical_sha256(manifest)}" if manifest is not None else None
    )
    manifest_hashes = (
        manifest.get("hashes") if isinstance(manifest, Mapping) else None
    )
    manifest_goal = (
        manifest.get("goal") if isinstance(manifest, Mapping) else None
    )
    manifest_roots = (
        manifest.get("roots") if isinstance(manifest, Mapping) else None
    )
    if manifest is not None and (
        manifest.get("schema") != EXECUTION_MANIFEST_SCHEMA
        or not isinstance(manifest_goal, Mapping)
        or manifest_goal.get("thread_id") != OFFICIAL_GOAL_ID
        or not isinstance(manifest_roots, Mapping)
        or manifest_roots.get("production_home") != "/Users/moss/SitinaHub"
        or not isinstance(manifest_hashes, Mapping)
        or manifest_hashes.get("production_sentinel_hash")
        != f"sha256:{BASE_SENTINEL_REPORT_SHA256}"
        or manifest_hashes.get("production_mutable_sentinel_hash")
        != f"sha256:{MUTABLE_SENTINEL_REPORT_SHA256}"
        or manifest_hash != f"sha256:{EXECUTION_MANIFEST_CANONICAL_SHA256}"
    ):
        errors.append("production execution manifest content binding mismatch")

    samples = sentinel.get("samples")
    observed_stages: list[str] = []
    observed_times: dict[str, dt.datetime] = {}
    if not isinstance(samples, list) or len(samples) != 2:
        errors.append("production sentinel requires exactly two sample artifacts")
    else:
        for index, sample_ref in enumerate(samples):
            _, sample = _verify_file_reference(
                sample_ref, errors, f"production sentinel sample {index}"
            )
            if sample is None:
                continue
            stage = sample.get("sample")
            observed_stages.append(stage if isinstance(stage, str) else "")
            if isinstance(stage, str) and _valid_iso8601(sample.get("observed_at_utc")):
                observed_times[stage] = _iso_datetime(sample["observed_at_utc"])
            sample_base = sample.get("base")
            sample_mutable = sample.get("mutable")
            sample_manifest = sample.get("manifest")
            if (
                sample.get("schema") != SENTINEL_SAMPLE_SCHEMA
                or stage not in ("before", "after")
                or sample.get("goal_id") != OFFICIAL_GOAL_ID
                or sample.get("production_home") != "/Users/moss/SitinaHub"
                or not _valid_iso8601(sample.get("observed_at_utc"))
                or sample.get("production_attempts") != 0
                or sample_base
                != {
                    "baseline_path": BASE_SENTINEL_PATH,
                    "baseline_physical_sha256": BASE_SENTINEL_PHYSICAL_SHA256,
                    "report_sha256": BASE_SENTINEL_REPORT_SHA256,
                }
                or sample_mutable
                != {
                    "baseline_path": MUTABLE_SENTINEL_PATH,
                    "baseline_physical_sha256": MUTABLE_SENTINEL_PHYSICAL_SHA256,
                    "report_sha256": MUTABLE_SENTINEL_REPORT_SHA256,
                }
                or sample_manifest
                != {
                    "path": EXECUTION_MANIFEST_PATH,
                    "physical_sha256": EXECUTION_MANIFEST_PHYSICAL_SHA256,
                    "canonical_sha256": EXECUTION_MANIFEST_CANONICAL_SHA256,
                }
            ):
                errors.append(f"production sentinel sample {index} binding mismatch")
    if set(observed_stages) != {"before", "after"} or len(
        set(observed_stages)
    ) != 2:
        errors.append("production sentinel sample stages are incomplete or duplicated")
    elif (
        set(observed_times) != {"before", "after"}
        or observed_times["before"] >= observed_times["after"]
    ):
        errors.append("production sentinel sample time order is invalid")
    if sentinel.get("production_attempts") != 0:
        errors.append("production sentinel evidence records a production attempt")
    return {
        "goal_id": OFFICIAL_GOAL_ID,
        "production_home": "/Users/moss/SitinaHub",
        "base_path": BASE_SENTINEL_PATH,
        "base_report": BASE_SENTINEL_REPORT_SHA256,
        "mutable_path": MUTABLE_SENTINEL_PATH,
        "mutable_report": MUTABLE_SENTINEL_REPORT_SHA256,
        "manifest_hash": f"sha256:{EXECUTION_MANIFEST_CANONICAL_SHA256}",
    }


def _verify_backup_and_rollback_plan(
    plan: Any,
    *,
    approval_id: Any,
    packet_operations: Sequence[Any],
    source_root: Path,
    deployment_root: Path,
    source_state: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    """Verify the packet-embedded, hash-addressed recovery boundary."""

    label = "backup and rollback plan"
    if not isinstance(plan, Mapping) or set(plan) != BACKUP_ROLLBACK_PLAN_FIELDS:
        errors.append(f"{label} schema mismatch")
        return {}
    operations_sha256 = _json_value_sha256(packet_operations)
    forbidden = plan.get("forbidden_boundaries")
    if (
        plan.get("schema") != BACKUP_ROLLBACK_PLAN_SCHEMA
        or plan.get("approval_id") != approval_id
        or plan.get("status") != "PLANNED_NOT_EXECUTED"
        or plan.get("source_binding")
        != {
            "root": str(source_root),
            "head": source_state.get("head"),
            "tree": source_state.get("tree"),
        }
        or plan.get("deployment_binding") != {"root": str(deployment_root)}
        or plan.get("exact_file_operations_sha256") != operations_sha256
        or plan.get("execution_sequence")
        != list(BACKUP_ROLLBACK_EXECUTION_SEQUENCE)
        or plan.get("failure_policy") != BACKUP_ROLLBACK_FAILURE_POLICY
        or not isinstance(forbidden, Mapping)
        or set(forbidden) != set(BACKUP_ROLLBACK_FORBIDDEN_FIELDS)
        or any(forbidden.get(field) is not False for field in forbidden)
    ):
        errors.append(f"{label} binding mismatch")
    if (
        not isinstance(approval_id, str)
        or re.fullmatch(r"[A-Z0-9_]+", approval_id) is None
    ):
        errors.append(f"{label} approval ID is unsafe")
        return {}
    allowed_parent = source_root.parent / "output"
    expected_root = allowed_parent / f"sitina-step7-deploy-v3-{approval_id}"
    root_value = plan.get("backup_root")
    if not isinstance(root_value, Mapping) or root_value != {
        "path": str(expected_root),
        "allowed_parent": str(allowed_parent),
        "allowed_parent_must_exist_before_authorized_execution": True,
        "allowed_parent_creation_allowed": False,
        "allowed_parent_required_type": "DIRECTORY_NO_SYMLINK",
        "allowed_parent_ancestor_safety_required": True,
        "derived_from_approval_id": True,
        "must_not_exist_before_authorized_execution": True,
        "create_mode": "0o700",
        "create_semantics": "EXCLUSIVE_NOFOLLOW",
        "reuse_allowed": False,
    }:
        errors.append(f"{label} unique backup root mismatch")
    _verify_nofollow_descendant(
        allowed_parent,
        trusted_root=source_root.parent,
        leaf_kind="directory",
        errors=errors,
        label=f"{label} allowed parent",
    )
    expected_manifest = expected_root / "backup-manifest.json"
    expected_quarantine = expected_root / "quarantine" / "created"
    expected_recovery = expected_root / "recovery-verification.json"
    if plan.get("backup_manifest_path") != str(expected_manifest):
        errors.append(f"{label} manifest path mismatch")
    if plan.get("rollback_quarantine_root") != str(expected_quarantine):
        errors.append(f"{label} quarantine root mismatch")
    if plan.get("recovery_verification_path") != str(expected_recovery):
        errors.append(f"{label} recovery-verification path mismatch")
    raw_objects = plan.get("objects")
    if not isinstance(raw_objects, list) or len(raw_objects) != len(packet_operations):
        errors.append(f"{label} object count mismatch")
        raw_objects = []
    objects: dict[str, Mapping[str, Any]] = {}
    seen_artifact_paths: set[str] = set()
    for index, (operation, plan_object) in enumerate(
        zip(packet_operations, raw_objects)
    ):
        if not isinstance(operation, Mapping) or not isinstance(plan_object, Mapping):
            errors.append(f"{label} object {index} is malformed")
            continue
        relative = operation.get("relative_path")
        if not isinstance(relative, str):
            errors.append(f"{label} object {index} path mismatch")
            continue
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != relative
        ):
            errors.append(f"{label} object {index} relative path is unsafe")
            continue
        kind = operation.get("operation")
        backup_path = (
            str(expected_root / "preimages" / f"{relative}.preimage")
            if kind == "REPLACE"
            else None
        )
        quarantine_path = (
            str(expected_quarantine / relative) if kind == "CREATE" else None
        )
        recovery_verification = (
            {
                "restored_sha256": operation.get("preimage_sha256"),
                "reapplied_sha256": operation.get("target_sha256"),
            }
            if kind == "REPLACE"
            else {
                "target_absent_after_quarantine": True,
                "quarantined_sha256": operation.get("target_sha256"),
                "reapplied_sha256": operation.get("target_sha256"),
            }
        )
        expected_object = {
            "index": index,
            "relative_path": relative,
            "operation": kind,
            "target_path": operation.get("target_path"),
            "preimage_sha256": operation.get("preimage_sha256"),
            "target_sha256": operation.get("target_sha256"),
            "preimage_backup_path": backup_path,
            "rollback_quarantine_path": quarantine_path,
            "rollback_action": (
                "RESTORE_VERIFIED_PREIMAGE"
                if kind == "REPLACE"
                else "QUARANTINE_CREATED_TARGET"
            ),
            "recovery_verification": recovery_verification,
        }
        if (
            kind not in ("REPLACE", "CREATE")
            or set(plan_object) != BACKUP_ROLLBACK_OBJECT_FIELDS
            or dict(plan_object) != expected_object
        ):
            errors.append(f"{label} object {index} operation binding mismatch")
        artifact_path = backup_path or quarantine_path
        if artifact_path is not None:
            if artifact_path in seen_artifact_paths:
                errors.append(f"{label} object {index} artifact path is duplicated")
            seen_artifact_paths.add(artifact_path)
        objects[relative] = plan_object
    if len(objects) != len(raw_objects):
        errors.append(f"{label} object paths are duplicated")
    return {
        "sha256": _json_value_sha256(plan),
        "backup_root": str(expected_root),
        "manifest_path": str(expected_manifest),
        "quarantine_root": str(expected_quarantine),
        "recovery_path": str(expected_recovery),
        "objects": objects,
        "forbidden_boundaries": dict(forbidden)
        if isinstance(forbidden, Mapping)
        else {},
    }


def _verify_rollback_and_bound_evidence(
    candidate: Mapping[str, Any],
    source_root: Path,
    deployment_root: Path,
    source_state: Mapping[str, Any],
    errors: list[str],
    anchor_root: Path,
) -> None:
    rollback = candidate.get("rollback_proof")
    if not isinstance(rollback, Mapping) or set(rollback) != {
        "approval_packet",
        "deployment_request_candidate",
        "authorization_receipt",
        "manifest",
        "recovery_result",
    }:
        errors.append("verified rollback proof is missing")
        return
    packet_path, packet = _verify_file_reference(
        rollback.get("approval_packet"), errors, "rollback approval packet"
    )
    request_candidate_path, request_candidate = _verify_file_reference(
        rollback.get("deployment_request_candidate"),
        errors,
        "deployment request review candidate",
    )
    manifest_path, manifest = _verify_file_reference(
        rollback.get("manifest"), errors, "rollback manifest"
    )
    recovery_path, recovery = _verify_file_reference(
        rollback.get("recovery_result"), errors, "rollback recovery result"
    )
    changed_files = candidate.get("source", {}).get("changed_files")
    expected_paths = set(changed_files) if isinstance(changed_files, list) else set()
    packet_operations = (
        packet.get("exact_file_operations") if isinstance(packet, Mapping) else None
    )
    packet_plan = (
        packet.get("backup_and_rollback_plan")
        if isinstance(packet, Mapping)
        else None
    )
    authorization_contract = (
        packet.get("authorization_contract")
        if isinstance(packet, Mapping)
        else None
    )
    packet_forbidden = (
        packet.get("forbidden_boundaries")
        if isinstance(packet, Mapping)
        else None
    )
    if not isinstance(packet, Mapping) or (
        set(packet) != DEPLOYMENT_PACKET_FIELDS
        or packet.get("schema") != DEPLOYMENT_PACKET_SCHEMA
        or packet.get("approval_id") in REVOKED_DEPLOYMENT_APPROVAL_IDS
        or not isinstance(packet.get("approval_id"), str)
        or not packet.get("approval_id")
        or not _valid_iso8601(packet.get("created_at_utc"))
        or packet.get("source_binding")
        != {
            "head": source_state.get("head"),
            "tree": source_state.get("tree"),
        }
        or packet.get("deployment_binding")
        != {"root": str(deployment_root)}
        or not isinstance(packet_operations, list)
        or not isinstance(packet_plan, Mapping)
        or packet.get("backup_and_rollback_plan_sha256")
        != _json_value_sha256(packet_plan)
        or not isinstance(authorization_contract, Mapping)
        or set(authorization_contract)
        != DEPLOYMENT_AUTHORIZATION_CONTRACT_FIELDS
        or authorization_contract
        != {
            "schema": DEPLOYMENT_AUTHORIZATION_CONTRACT_SCHEMA,
            "marker": DEPLOYMENT_AUTHORIZATION_MARKER,
            "source_thread_id": STEP7_SOURCE_THREAD_ID,
            "required_payload_fields": list(
                DEPLOYMENT_AUTHORIZATION_PAYLOAD_FIELDS
            ),
            "requires_user_record": True,
            "delegated_wrapper_required": True,
            "delegated_wrapper_source_thread_required": True,
            "delegated_source_session": STEP7_DELEGATED_SOURCE_SESSION,
            "self_authorizes_execution": False,
        }
        or not isinstance(packet_forbidden, Mapping)
        or set(packet_forbidden) != set(BACKUP_ROLLBACK_FORBIDDEN_FIELDS)
        or any(packet_forbidden.get(field) is not False for field in packet_forbidden)
        or packet.get("requires_exact_user_authorization") is not True
        or packet.get("self_authorizes_execution") is not False
        or packet.get("deployment_executed_at_creation") is not False
    ):
        errors.append("rollback approval packet schema or binding mismatch")
        packet_operations = []
    plan_verification = _verify_backup_and_rollback_plan(
        packet_plan,
        approval_id=packet.get("approval_id")
        if isinstance(packet, Mapping)
        else None,
        packet_operations=packet_operations,
        source_root=source_root,
        deployment_root=deployment_root,
        source_state=source_state,
        errors=errors,
    )
    if (
        isinstance(packet_forbidden, Mapping)
        and plan_verification.get("forbidden_boundaries") != dict(packet_forbidden)
    ):
        errors.append("approval packet and rollback plan forbidden boundaries differ")
    operations_sha256 = _json_value_sha256(packet_operations)
    plan_sha256 = plan_verification.get("sha256")
    request_evidence_path, request_evidence = _verify_file_reference(
        request_candidate.get("evidence_bundle")
        if isinstance(request_candidate, Mapping)
        else None,
        errors,
        "deployment request review evidence bundle",
    )
    evidence_categories = (
        request_evidence.get("evidence")
        if isinstance(request_evidence, Mapping)
        else None
    )
    review_summary = {
        "formal_step56_accept_count": 3,
        "gate_count": 7,
        "real_sitina_review_count": 2,
        "changed_source_count": len(expected_paths),
        "deployment_operation_count": len(packet_operations),
        "replace_count": sum(
            operation.get("operation") == "REPLACE"
            for operation in packet_operations
            if isinstance(operation, Mapping)
        ),
        "create_count": sum(
            operation.get("operation") == "CREATE"
            for operation in packet_operations
            if isinstance(operation, Mapping)
        ),
        "deployment_pending": True,
        "step8_step9_not_entered": True,
    }
    if not isinstance(request_evidence, Mapping) or (
        set(request_evidence) != DEPLOYMENT_REQUEST_EVIDENCE_FIELDS
        or request_evidence.get("schema") != DEPLOYMENT_REQUEST_EVIDENCE_SCHEMA
        or not _valid_iso8601(request_evidence.get("created_at_utc"))
        or request_evidence.get("source")
        != {
            "root": str(source_root),
            "head": source_state.get("head"),
            "tree": source_state.get("tree"),
        }
        or request_evidence.get("approval_id")
        != (
            packet.get("approval_id")
            if isinstance(packet, Mapping)
            else None
        )
        or request_evidence.get("approval_packet")
        != (
            {"path": str(packet_path), "sha256": _sha256(packet_path)}
            if packet_path is not None
            else None
        )
        or request_evidence.get("authorization_contract")
        != authorization_contract
        or request_evidence.get("exact_file_operations_sha256")
        != operations_sha256
        or request_evidence.get("rollback_plan_sha256") != plan_sha256
        or request_evidence.get("review_summary") != review_summary
        or not isinstance(evidence_categories, Mapping)
        or set(evidence_categories) != DEPLOYMENT_REQUEST_EVIDENCE_CATEGORIES
    ):
        errors.append("deployment request review evidence bundle mismatch")
        evidence_categories = {}
    supporting_evidence = candidate.get(
        "deployment_request_supporting_evidence"
    )
    cleanup_value = candidate.get("cleanup")
    cleanup_review_value = (
        cleanup_value.get("real_sitina_review")
        if isinstance(cleanup_value, Mapping)
        else None
    )
    full_review_value = candidate.get("real_sitina_review")
    changed_source_references = [
        {
            "path": str(source_root / relative),
            "sha256": _sha256(source_root / relative),
        }
        for relative in changed_files
        if isinstance(relative, str)
        and (source_root / relative).is_file()
        and not (source_root / relative).is_symlink()
    ] if isinstance(changed_files, list) else []
    expected_evidence_categories = {
        "authority": {
            "path": STEP7_AUTHORITY_PATH,
            "sha256": STEP7_AUTHORITY_SHA256,
        },
        "entry_candidate": candidate.get("step56_entry_candidate"),
        "step56_accepts": candidate.get("step56_independent_accepts"),
        "gates": [
            gate.get("evidence")
            for gate in candidate.get("gates", [])
            if isinstance(gate, Mapping)
        ],
        "real_sitina_reviews": [
            cleanup_review_value.get("receipt")
            if isinstance(cleanup_review_value, Mapping)
            else None,
            full_review_value.get("receipt")
            if isinstance(full_review_value, Mapping)
            else None,
        ],
        "static_integrity": (
            supporting_evidence.get("static_integrity")
            if isinstance(supporting_evidence, Mapping)
            else None
        ),
        "excluded_attempts": (
            supporting_evidence.get("excluded_attempts")
            if isinstance(supporting_evidence, Mapping)
            else None
        ),
        "revocation": (
            supporting_evidence.get("revocation")
            if isinstance(supporting_evidence, Mapping)
            else None
        ),
        "changed_source": changed_source_references,
    }
    supporting_documents: dict[str, Any] = {}
    if isinstance(supporting_evidence, Mapping):
        for category in DEPLOYMENT_REQUEST_SUPPORTING_EVIDENCE_FIELDS:
            _, document = _verify_file_reference(
                supporting_evidence.get(category),
                errors,
                f"deployment request supporting evidence {category}",
            )
            supporting_documents[category] = document
    static_integrity = supporting_documents.get("static_integrity")
    static_source = (
        static_integrity.get("source")
        if isinstance(static_integrity, Mapping)
        else None
    )
    static_deployment = (
        static_integrity.get("deployment")
        if isinstance(static_integrity, Mapping)
        else None
    )
    static_forbidden = (
        static_integrity.get("forbidden_actions")
        if isinstance(static_integrity, Mapping)
        else None
    )
    static_switches = (
        static_integrity.get("execution_switches")
        if isinstance(static_integrity, Mapping)
        else None
    )
    static_gates = (
        static_integrity.get("gates")
        if isinstance(static_integrity, Mapping)
        else None
    )
    static_gate_identities = [
        {"path": item.get("path"), "sha256": item.get("sha256")}
        for item in static_gates
        if isinstance(item, Mapping)
    ] if isinstance(static_gates, list) else []
    expected_static_forbidden = {
        "baseline_install_or_promotion": False,
        "deployment": False,
        "production_canary": False,
        "production_data_mutation": False,
        "step8_entered": False,
        "step9_entered": False,
    }
    if not isinstance(static_integrity, Mapping) or (
        static_integrity.get("schema")
        != "SITINA_STEP7_SOURCE_BOUNDARY_STATIC_INTEGRITY_V2"
        or not isinstance(static_source, Mapping)
        or static_source.get("root") != str(source_root)
        or static_source.get("head") != source_state.get("head")
        or static_source.get("tree") != source_state.get("tree")
        or static_source.get("worktree_clean") is not True
        or static_source.get("changed_files_from_step7_base") != changed_files
        or not isinstance(static_deployment, Mapping)
        or static_deployment.get("root") != str(deployment_root)
        or static_deployment.get("operation_count") != len(packet_operations)
        or static_deployment.get("replace_count") != review_summary["replace_count"]
        or static_deployment.get("create_count") != review_summary["create_count"]
        or static_deployment.get("deployment_performed") is not False
        or static_deployment.get("mismatch_paths") != changed_files
        or static_deployment.get("exact_operations") != packet_operations
        or not isinstance(static_switches, Mapping)
        or static_switches.get("all_false") is not True
        or static_forbidden != expected_static_forbidden
        or static_integrity.get("formal_step56_accepts")
        != candidate.get("step56_independent_accepts")
        or not isinstance(static_gates, list)
        or static_gate_identities
        != expected_evidence_categories["gates"]
        or static_integrity.get("revocation")
        != (
            supporting_evidence.get("revocation")
            if isinstance(supporting_evidence, Mapping)
            else None
        )
    ):
        errors.append("deployment request static-integrity evidence mismatch")
    excluded_attempts = supporting_documents.get("excluded_attempts")
    excluded_items = (
        excluded_attempts.get("attempts")
        if isinstance(excluded_attempts, Mapping)
        else None
    )
    if not isinstance(excluded_attempts, Mapping) or (
        excluded_attempts.get("schema") != "SITINA_STEP7_EXCLUDED_ATTEMPTS_V2"
        or excluded_attempts.get("source")
        != {
            "head": source_state.get("head"),
            "tree": source_state.get("tree"),
        }
        or excluded_attempts.get("all_counted_as_pass") is not False
        or not isinstance(excluded_items, list)
        or not excluded_items
        or any(
            not isinstance(item, Mapping)
            or item.get("counted_as_pass") is not False
            for item in excluded_items
        )
    ):
        errors.append("deployment request excluded-attempt evidence mismatch")
    revocation = supporting_documents.get("revocation")
    revoked_candidate = (
        revocation.get("revoked_candidate")
        if isinstance(revocation, Mapping)
        else None
    )
    revoked_packet = (
        revocation.get("revoked_packet")
        if isinstance(revocation, Mapping)
        else None
    )
    if not isinstance(revocation, Mapping) or (
        revocation.get("schema")
        != "SITINA_STEP7_DEPLOYMENT_PACKET_REVOCATION_V1"
        or revocation.get("source_thread_id") != STEP7_SOURCE_THREAD_ID
        or revocation.get("decision") != "REJECT_DEPLOY_REQUEST"
        or revocation.get("revoked_approval_id")
        != "SITINA_STEP7_DEPLOY_CBBD2E1_6F_20260727T113530Z"
        or not isinstance(revoked_candidate, Mapping)
        or revoked_candidate.get("sha256")
        != "0fb40ec5563ce4236979b268a13b935e1c9e6db39d36a1b9746da9ba931f5590"
        or not isinstance(revoked_packet, Mapping)
        or revoked_packet.get("sha256")
        != "5ca184ac9231e00e140f7e2f7b9d6ba13ada8aa53e08a3dbf851402d86434f29"
        or any(
            revocation.get(field) is not False
            for field in (
                "may_execute",
                "may_request_authorization",
                "may_reuse_candidate_sha256",
                "may_reuse_packet_sha256",
                "deployment_performed",
                "production_canary_run",
                "production_data_modified",
                "baseline_modified",
                "step8_step9_entered",
            )
        )
    ):
        errors.append("deployment request revocation evidence mismatch")
    if not isinstance(supporting_evidence, Mapping) or (
        set(supporting_evidence)
        != DEPLOYMENT_REQUEST_SUPPORTING_EVIDENCE_FIELDS
        or evidence_categories != expected_evidence_categories
    ):
        errors.append(
            "deployment request review evidence category identities mismatch"
        )
        evidence_categories = {}
    evidence_references: list[Any] = []
    if isinstance(evidence_categories, Mapping):
        for category in (
            "authority",
            "entry_candidate",
            "static_integrity",
            "excluded_attempts",
            "revocation",
        ):
            evidence_references.append(evidence_categories.get(category))
        for category, expected_count in (
            ("step56_accepts", 3),
            ("gates", 7),
            ("real_sitina_reviews", 2),
            ("changed_source", len(expected_paths)),
        ):
            values = evidence_categories.get(category)
            if not isinstance(values, list) or len(values) != expected_count:
                errors.append(
                    f"deployment request review evidence {category} count mismatch"
                )
                continue
            evidence_references.extend(values)
    observed_bundle_references: list[tuple[str, str]] = []
    for index, reference in enumerate(evidence_references):
        path, _ = _verify_file_reference(
            reference,
            errors,
            f"deployment request review evidence {index}",
            require_json_object=(
                isinstance(reference, Mapping)
                and str(reference.get("path", "")).endswith(".json")
            ),
        )
        if path is not None and isinstance(reference, Mapping):
            observed_bundle_references.append(
                (str(path), str(reference.get("sha256")))
            )
    if len(observed_bundle_references) != len(set(observed_bundle_references)):
        errors.append("deployment request review evidence contains duplicates")
    expected_request_candidate = {
        "schema": DEPLOYMENT_REQUEST_CANDIDATE_SCHEMA,
        "candidate_id": (
            f"{packet.get('approval_id')}_REVIEW_CANDIDATE"
            if isinstance(packet, Mapping)
            else None
        ),
        "created_at_utc": request_candidate.get("created_at_utc")
        if isinstance(request_candidate, Mapping)
        else None,
        "status": "AWAITING_EXACT_USER_AUTHORIZATION",
        "approval_id": packet.get("approval_id")
        if isinstance(packet, Mapping)
        else None,
        "source_binding": {
            "root": str(source_root),
            "head": source_state.get("head"),
            "tree": source_state.get("tree"),
        },
        "deployment_binding": {"root": str(deployment_root)},
        "approval_packet": (
            {"path": str(packet_path), "sha256": _sha256(packet_path)}
            if packet_path is not None
            else None
        ),
        "authorization_contract": (
            dict(authorization_contract)
            if isinstance(authorization_contract, Mapping)
            else {}
        ),
        "exact_file_operation_count": len(packet_operations),
        "exact_file_operations_sha256": operations_sha256,
        "rollback_plan_sha256": plan_sha256,
        "review_summary": review_summary,
        "evidence_bundle": (
            {
                "path": str(request_evidence_path),
                "sha256": _sha256(request_evidence_path),
            }
            if request_evidence_path is not None
            else None
        ),
        "authorized": False,
        "deployment_executed": False,
        "forbidden_boundaries": dict(packet_forbidden)
        if isinstance(packet_forbidden, Mapping)
        else {},
    }
    if (
        not isinstance(request_candidate, Mapping)
        or set(request_candidate) != DEPLOYMENT_REQUEST_CANDIDATE_FIELDS
        or not _valid_iso8601(request_candidate.get("created_at_utc"))
        or dict(request_candidate) != expected_request_candidate
    ):
        errors.append("deployment request review candidate schema or binding mismatch")
    if (
        packet_path is not None
        and request_candidate_path is not None
        and isinstance(packet, Mapping)
    ):
        _verify_user_authorization(
            rollback.get("authorization_receipt"),
            expected_payload={
                "approval_id": packet.get("approval_id"),
                "approval_packet_sha256": _sha256(packet_path),
                "exact_file_operation_count": len(packet_operations),
                "exact_file_operations_sha256": operations_sha256,
                "rollback_plan_sha256": plan_sha256,
                "review_candidate_sha256": _sha256(request_candidate_path),
                "source_head": source_state.get("head"),
                "source_tree": source_state.get("tree"),
                "deployment_root": str(deployment_root),
            },
            anchor_root=anchor_root,
            errors=errors,
        )
    packet_paths = [
        operation.get("relative_path")
        for operation in packet_operations
        if isinstance(operation, Mapping)
    ]
    if (
        len(packet_paths) != len(set(packet_paths))
        or set(packet_paths) != expected_paths
        or len(packet_paths) != len(packet_operations)
    ):
        errors.append("rollback approval packet object set mismatch")
    preimage_capture = (
        packet.get("preimage_capture") if isinstance(packet, Mapping) else None
    )
    capture_entries = (
        preimage_capture.get("entries")
        if isinstance(preimage_capture, Mapping)
        else None
    )
    backup_root_preflight = (
        preimage_capture.get("backup_root_preflight")
        if isinstance(preimage_capture, Mapping)
        else None
    )
    if not isinstance(preimage_capture, Mapping) or (
        set(preimage_capture)
        != {
            "schema",
            "captured_at_utc",
            "deployment_root",
            "deployment_mutated",
            "entries",
            "backup_root_preflight",
            "capture_anchor",
        }
        or preimage_capture.get("schema")
        != "SITINA_STEP7_DEPLOYMENT_PREIMAGE_CAPTURE_V2"
        or not _valid_iso8601(preimage_capture.get("captured_at_utc"))
        or preimage_capture.get("deployment_root") != str(deployment_root)
        or preimage_capture.get("deployment_mutated") is not False
        or not isinstance(capture_entries, list)
        or not isinstance(backup_root_preflight, Mapping)
        or set(backup_root_preflight)
        != {
            "checked_at_utc",
            "path",
            "allowed_parent",
            "allowed_parent_existed",
            "allowed_parent_is_directory",
            "allowed_parent_is_symlink",
            "allowed_parent_creation_allowed",
            "allowed_parent_ancestor_safety_verified",
            "existed",
            "reuse_allowed",
            "ancestor_safety_verified",
            "symlink_component_count",
        }
        or not _valid_iso8601(backup_root_preflight.get("checked_at_utc"))
        or backup_root_preflight.get("path")
        != plan_verification.get("backup_root")
        or backup_root_preflight.get("allowed_parent")
        != str(source_root.parent / "output")
        or backup_root_preflight.get("allowed_parent_existed") is not True
        or backup_root_preflight.get("allowed_parent_is_directory") is not True
        or backup_root_preflight.get("allowed_parent_is_symlink") is not False
        or backup_root_preflight.get("allowed_parent_creation_allowed") is not False
        or backup_root_preflight.get("allowed_parent_ancestor_safety_verified")
        is not True
        or backup_root_preflight.get("existed") is not False
        or backup_root_preflight.get("reuse_allowed") is not False
        or backup_root_preflight.get("ancestor_safety_verified") is not True
        or backup_root_preflight.get("symlink_component_count") != 0
    ):
        errors.append("rollback approval packet preimage capture mismatch")
        capture_entries = []
    capture_by_path: dict[str, Mapping[str, Any]] = {}
    for index, capture in enumerate(capture_entries):
        if not isinstance(capture, Mapping) or (
            set(capture)
            != {
                "relative_path",
                "target_path",
                "exists",
                "sha256",
                "size",
                "mode",
            }
            or capture.get("relative_path") not in expected_paths
        ):
            errors.append(f"rollback preimage capture entry {index} mismatch")
            continue
        capture_by_path[str(capture["relative_path"])] = capture
    if set(capture_by_path) != expected_paths:
        errors.append("rollback preimage capture object set mismatch")
    if isinstance(preimage_capture, Mapping):
        _verify_codex_capture_anchor(
            preimage_capture.get("capture_anchor"),
            marker=PREIMAGE_CAPTURE_ANCHOR_MARKER,
            expected_payload={
                "approval_id": packet.get("approval_id")
                if isinstance(packet, Mapping)
                else None,
                "source_head": source_state.get("head"),
                "source_tree": source_state.get("tree"),
                "deployment_root": str(deployment_root),
                "entries": capture_entries,
                "backup_root_preflight": backup_root_preflight,
            },
            anchor_root=anchor_root,
            errors=errors,
            label="rollback preimage capture",
        )
    packet_by_path = {
        str(operation.get("relative_path")): operation
        for operation in packet_operations
        if isinstance(operation, Mapping)
        and isinstance(operation.get("relative_path"), str)
    }
    manifest_entries = manifest.get("entries") if isinstance(manifest, Mapping) else None
    if not isinstance(manifest, Mapping) or (
        set(manifest) != ROLLBACK_MANIFEST_FIELDS
        or manifest.get("schema") != ROLLBACK_MANIFEST_SCHEMA
        or manifest.get("source_head") != source_state.get("head")
        or manifest.get("source_tree") != source_state.get("tree")
        or manifest.get("deployment_root") != str(deployment_root)
        or not isinstance(manifest.get("approval_id"), str)
        or not manifest.get("approval_id")
        or manifest.get("approval_id") in REVOKED_DEPLOYMENT_APPROVAL_IDS
        or packet is None
        or manifest.get("approval_id") != packet.get("approval_id")
        or not _valid_sha256(manifest.get("approval_packet_sha256"))
        or packet_path is None
        or manifest.get("approval_packet_sha256") != _sha256(packet_path)
        or manifest.get("exact_file_operations_sha256") != operations_sha256
        or manifest.get("rollback_plan_sha256") != plan_sha256
        or request_candidate_path is None
        or manifest.get("review_candidate_sha256")
        != _sha256(request_candidate_path)
        or manifest.get("backup_root") != plan_verification.get("backup_root")
        or manifest.get("backup_manifest_path") != str(manifest_path)
        or manifest.get("backup_manifest_path")
        != plan_verification.get("manifest_path")
        or manifest.get("backup_root_created_exclusively") is not True
        or manifest.get("backup_root_reused") is not False
        or manifest.get("backup_root_mode") != "0o700"
        or manifest.get("backup_root_parent_components_safe") is not True
        or manifest.get("verified_before_deployment") is not True
        or manifest.get("deployment_mutated") is not False
        or manifest.get("mismatch_count") != 0
        or not isinstance(manifest_entries, list)
    ):
        errors.append("rollback manifest schema or binding mismatch")
        manifest_entries = []
    trusted_backup_parent = source_root.parent / "output"
    if manifest_path is not None:
        _verify_nofollow_descendant(
            manifest_path,
            trusted_root=trusted_backup_parent,
            leaf_kind="file",
            errors=errors,
            label="rollback backup manifest",
        )
    backup_root_path = Path(str(plan_verification.get("backup_root", "")))
    if backup_root_path.is_absolute():
        _verify_nofollow_descendant(
            backup_root_path,
            trusted_root=trusted_backup_parent,
            leaf_kind="directory",
            errors=errors,
            label="rollback backup root",
        )
        try:
            if oct(stat.S_IMODE(backup_root_path.lstat().st_mode)) != "0o700":
                errors.append("rollback backup root mode mismatch")
        except OSError:
            pass
    relative_paths = [
        entry.get("relative_path")
        for entry in manifest_entries
        if isinstance(entry, Mapping)
    ]
    if (
        len(relative_paths) != len(set(relative_paths))
        or set(relative_paths) != expected_paths
        or len(relative_paths) != len(manifest_entries)
    ):
        errors.append("rollback manifest object set mismatch")
    manifest_by_path: dict[str, Mapping[str, Any]] = {}
    for index, entry in enumerate(manifest_entries):
        if not isinstance(entry, Mapping):
            errors.append(f"rollback manifest entry {index} is malformed")
            continue
        relative = entry.get("relative_path")
        if set(entry) != ROLLBACK_OPERATION_FIELDS | {
            "backup",
            "rollback_quarantine_path",
        }:
            errors.append(f"rollback manifest entry {index} field set mismatch")
        if not isinstance(relative, str) or relative not in expected_paths:
            errors.append(f"rollback manifest entry {index} path mismatch")
            continue
        manifest_by_path[relative] = entry
        source_path = source_root / relative
        deployment_path = deployment_root / relative
        source_file = _safe_regular_file(
            str(source_path), errors, f"rollback target source {relative}"
        )
        deployment_file = _safe_regular_file(
            str(deployment_path), errors, f"rollback active target {relative}"
        )
        operation = entry.get("operation")
        if operation not in ("REPLACE", "CREATE"):
            errors.append(f"rollback manifest entry {relative} operation mismatch")
        if (
            entry.get("source_path") != str(source_path)
            or entry.get("target_path") != str(deployment_path)
        ):
            errors.append(f"rollback manifest entry {relative} target binding mismatch")
        packet_operation = packet_by_path.get(relative)
        plan_object = plan_verification.get("objects", {}).get(relative)
        capture_entry = capture_by_path.get(relative)
        if not isinstance(packet_operation, Mapping) or (
            set(packet_operation) != ROLLBACK_OPERATION_FIELDS
            or any(
                packet_operation.get(field) != entry.get(field)
                for field in ROLLBACK_OPERATION_FIELDS
            )
        ):
            errors.append(f"rollback manifest entry {relative} packet mismatch")
        expected_capture = {
            "relative_path": relative,
            "target_path": str(deployment_path),
            "exists": entry.get("preimage_exists"),
            "sha256": entry.get("preimage_sha256"),
            "size": entry.get("preimage_size"),
            "mode": entry.get("preimage_mode"),
        }
        if capture_entry != expected_capture:
            errors.append(f"rollback preimage capture {relative} manifest mismatch")
        if not isinstance(plan_object, Mapping) or (
            plan_object.get("operation") != operation
            or plan_object.get("target_path") != entry.get("target_path")
            or plan_object.get("preimage_sha256") != entry.get("preimage_sha256")
            or plan_object.get("target_sha256") != entry.get("target_sha256")
            or plan_object.get("rollback_quarantine_path")
            != entry.get("rollback_quarantine_path")
        ):
            errors.append(f"rollback manifest entry {relative} plan mismatch")
        if source_file is not None:
            source_stat = source_file.stat()
            if (
                entry.get("target_sha256") != _sha256(source_file)
                or entry.get("target_size") != source_stat.st_size
                or entry.get("target_mode")
                != oct(stat.S_IMODE(source_stat.st_mode))
            ):
                errors.append(f"rollback manifest entry {relative} target metadata mismatch")
        if deployment_file is not None and source_file is not None and (
            _sha256(deployment_file) != _sha256(source_file)
            or deployment_file.stat().st_size != source_file.stat().st_size
            or stat.S_IMODE(deployment_file.stat().st_mode)
            != stat.S_IMODE(source_file.stat().st_mode)
        ):
            errors.append(f"rollback active target {relative} does not match source")
        backup_ref = entry.get("backup")
        if operation == "REPLACE":
            backup_path, _ = _verify_file_reference(
                backup_ref,
                errors,
                f"rollback preimage backup {relative}",
                require_json_object=False,
            )
            if (
                entry.get("preimage_exists") is not True
                or not _valid_sha256(entry.get("preimage_sha256"))
                or not _integer(entry.get("preimage_size"))
                or not isinstance(entry.get("preimage_mode"), str)
                or backup_path is None
                or not isinstance(plan_object, Mapping)
                or str(backup_path)
                != plan_object.get("preimage_backup_path")
                or entry.get("rollback_quarantine_path") is not None
            ):
                errors.append(f"rollback replace preimage {relative} is incomplete")
            elif (
                _sha256(backup_path) != entry.get("preimage_sha256")
                or backup_path.stat().st_size != entry.get("preimage_size")
                or oct(stat.S_IMODE(backup_path.stat().st_mode))
                != entry.get("preimage_mode")
            ):
                errors.append(f"rollback preimage backup {relative} metadata mismatch")
            if backup_path is not None:
                _verify_nofollow_descendant(
                    backup_path,
                    trusted_root=trusted_backup_parent,
                    leaf_kind="file",
                    errors=errors,
                    label=f"rollback preimage backup {relative}",
                )
        elif operation == "CREATE" and (
            entry.get("preimage_exists") is not False
            or entry.get("preimage_sha256") is not None
            or entry.get("preimage_size") is not None
            or entry.get("preimage_mode") is not None
            or backup_ref is not None
            or not isinstance(plan_object, Mapping)
            or entry.get("rollback_quarantine_path")
            != plan_object.get("rollback_quarantine_path")
            or plan_object.get("rollback_action")
            != "QUARANTINE_CREATED_TARGET"
        ):
            errors.append(f"rollback create preimage {relative} must be absent")

    recovery_entries = recovery.get("entries") if isinstance(recovery, Mapping) else None
    if not isinstance(recovery, Mapping) or (
        set(recovery) != ROLLBACK_RECOVERY_FIELDS
        or recovery.get("schema") != ROLLBACK_RESULT_SCHEMA
        or manifest_path is None
        or recovery.get("manifest")
        != {"path": str(manifest_path), "sha256": _sha256(manifest_path)}
        or packet_path is None
        or recovery.get("approval_packet")
        != {"path": str(packet_path), "sha256": _sha256(packet_path)}
        or request_candidate_path is None
        or recovery.get("review_candidate")
        != {
            "path": str(request_candidate_path),
            "sha256": _sha256(request_candidate_path),
        }
        or recovery.get("rollback_plan_sha256") != plan_sha256
        or not isinstance(rollback.get("authorization_receipt"), Mapping)
        or recovery.get("authorization_raw_record_sha256")
        != rollback.get("authorization_receipt", {}).get("raw_record_sha256")
        or recovery.get("source_head") != source_state.get("head")
        or recovery.get("source_tree") != source_state.get("tree")
        or recovery.get("deployment_root") != str(deployment_root)
        or recovery.get("method") != "DISPOSABLE_ISOLATED_RESTORE_REHEARSAL_V1"
        or recovery.get("deployment_mutated") is not False
        or recovery.get("verified") is not True
        or recovery.get("mismatch_count") != 0
        or recovery.get("delete_operation_count") != 0
        or recovery.get("backups_retained") is not True
        or recovery.get("quarantines_retained") is not True
        or recovery.get("manual_recovery_required") is not False
        or recovery_path is None
        or str(recovery_path) != plan_verification.get("recovery_path")
        or not isinstance(recovery_entries, list)
    ):
        errors.append("rollback recovery-result schema or binding mismatch")
        recovery_entries = []
    if recovery_path is not None:
        _verify_nofollow_descendant(
            recovery_path,
            trusted_root=trusted_backup_parent,
            leaf_kind="file",
            errors=errors,
            label="rollback recovery result",
        )
    recovery_paths = [
        entry.get("relative_path")
        for entry in recovery_entries
        if isinstance(entry, Mapping)
    ]
    if (
        len(recovery_paths) != len(set(recovery_paths))
        or set(recovery_paths) != expected_paths
        or len(recovery_paths) != len(recovery_entries)
    ):
        errors.append("rollback recovery-result object set mismatch")
    for index, result in enumerate(recovery_entries):
        if not isinstance(result, Mapping):
            errors.append(f"rollback recovery entry {index} is malformed")
            continue
        relative = result.get("relative_path")
        if set(result) != {
            "relative_path",
            "operation",
            "restored",
            "reapplied",
            "restored_artifact",
            "reapplied_artifact",
            "quarantined_artifact",
            "quarantine_move",
        }:
            errors.append(f"rollback recovery entry {index} field set mismatch")
        source_entry = manifest_by_path.get(relative)
        if source_entry is None:
            errors.append(f"rollback recovery entry {index} has no manifest object")
            continue
        operation = source_entry.get("operation")
        expected_restored = (
            {
                "exists": True,
                "sha256": source_entry.get("preimage_sha256"),
                "size": source_entry.get("preimage_size"),
                "mode": source_entry.get("preimage_mode"),
            }
            if operation == "REPLACE"
            else {"exists": False, "sha256": None, "size": None, "mode": None}
        )
        expected_reapplied = {
            "exists": True,
            "sha256": source_entry.get("target_sha256"),
            "size": source_entry.get("target_size"),
            "mode": source_entry.get("target_mode"),
        }
        restored_artifact = result.get("restored_artifact")
        reapplied_artifact = result.get("reapplied_artifact")
        quarantined_artifact = result.get("quarantined_artifact")
        quarantine_move = result.get("quarantine_move")
        if (
            result.get("operation") != operation
            or result.get("restored") != expected_restored
            or result.get("reapplied") != expected_reapplied
        ):
            errors.append(f"rollback recovery entry {relative} result mismatch")
        if operation == "REPLACE":
            restored_path, _ = _verify_file_reference(
                restored_artifact,
                errors,
                f"rollback restored snapshot {relative}",
                require_json_object=False,
            )
            if restored_path is None or (
                _sha256(restored_path) != source_entry.get("preimage_sha256")
                or restored_path.stat().st_size != source_entry.get("preimage_size")
                or oct(stat.S_IMODE(restored_path.stat().st_mode))
                != source_entry.get("preimage_mode")
            ):
                errors.append(f"rollback restored snapshot {relative} mismatch")
            if quarantined_artifact is not None:
                errors.append(
                    f"rollback replace entry {relative} has a quarantine snapshot"
                )
            if quarantine_move is not None:
                errors.append(
                    f"rollback replace entry {relative} has quarantine move evidence"
                )
        elif restored_artifact is not None:
            errors.append(f"rollback create entry {relative} has a restored snapshot")
        elif operation == "CREATE":
            quarantine_path, _ = _verify_file_reference(
                quarantined_artifact,
                errors,
                f"rollback quarantine snapshot {relative}",
                require_json_object=False,
            )
            plan_object = plan_verification.get("objects", {}).get(relative)
            if (
                quarantine_path is None
                or not isinstance(plan_object, Mapping)
                or str(quarantine_path)
                != plan_object.get("rollback_quarantine_path")
                or _sha256(quarantine_path) != source_entry.get("target_sha256")
                or quarantine_path.stat().st_size != source_entry.get("target_size")
                or oct(stat.S_IMODE(quarantine_path.stat().st_mode))
                != source_entry.get("target_mode")
            ):
                errors.append(f"rollback quarantine snapshot {relative} mismatch")
            if quarantine_path is not None:
                _verify_nofollow_descendant(
                    quarantine_path,
                    trusted_root=trusted_backup_parent,
                    leaf_kind="file",
                    errors=errors,
                    label=f"rollback quarantine snapshot {relative}",
                )
                quarantine_stat = quarantine_path.stat()
                expected_rehearsal_source = (
                    Path(str(plan_verification.get("backup_root", "")))
                    / "rehearsal"
                    / "created"
                    / relative
                )
                if quarantine_move != {
                    "method": "ATOMIC_RENAME_SAME_FILESYSTEM",
                    "source_path": str(expected_rehearsal_source),
                    "destination_path": str(quarantine_path),
                    "source_device": quarantine_stat.st_dev,
                    "source_inode": quarantine_stat.st_ino,
                    "destination_device": quarantine_stat.st_dev,
                    "destination_inode": quarantine_stat.st_ino,
                    "inode_preserved": True,
                    "source_absent_after_move": True,
                    "delete_operation_count": 0,
                } or expected_rehearsal_source.exists():
                    errors.append(
                        f"rollback quarantine move evidence {relative} mismatch"
                    )
        reapplied_path, _ = _verify_file_reference(
            reapplied_artifact,
            errors,
            f"rollback reapplied snapshot {relative}",
            require_json_object=False,
        )
        if reapplied_path is None or (
            _sha256(reapplied_path) != source_entry.get("target_sha256")
            or reapplied_path.stat().st_size != source_entry.get("target_size")
            or oct(stat.S_IMODE(reapplied_path.stat().st_mode))
            != source_entry.get("target_mode")
        ):
            errors.append(f"rollback reapplied snapshot {relative} mismatch")
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("candidate has no bound evidence list")
    else:
        observed_references: list[tuple[Any, Any]] = []
        for index, reference in enumerate(evidence):
            evidence_format = (
                reference.get("format") if isinstance(reference, Mapping) else None
            )
            if evidence_format not in (None, "json", "jsonl", "text"):
                errors.append(f"bound evidence {index} format mismatch")
            _verify_file_reference(
                reference,
                errors,
                f"bound evidence {index}",
                require_json_object=evidence_format not in ("jsonl", "text"),
            )
            observed_references.append(
                (
                    reference.get("path") if isinstance(reference, Mapping) else None,
                    reference.get("sha256")
                    if isinstance(reference, Mapping)
                    else None,
                )
            )
        if len(set(observed_references)) != len(observed_references):
            errors.append("candidate bound evidence list contains duplicate references")
        required_references: list[Any] = [
            candidate.get("step56_entry_candidate"),
            *(candidate.get("step56_independent_accepts") or []),
            *[
                gate.get("evidence")
                for gate in candidate.get("gates", [])
                if isinstance(gate, Mapping)
            ],
        ]
        cleanup = candidate.get("cleanup")
        if isinstance(cleanup, Mapping):
            required_references.extend(
                (cleanup.get("candidate"), cleanup.get("ledger"))
            )
            cleanup_review = cleanup.get("real_sitina_review")
            if isinstance(cleanup_review, Mapping):
                required_references.extend(
                    (
                        cleanup_review.get("input"),
                        cleanup_review.get("audit"),
                        cleanup_review.get("receipt"),
                    )
                )
        review = candidate.get("real_sitina_review")
        if isinstance(review, Mapping):
            required_references.extend(
                (review.get("input"), review.get("audit"), review.get("receipt"))
            )
        sentinel = candidate.get("production_sentinel")
        if isinstance(sentinel, Mapping):
            required_references.extend(
                (
                    sentinel.get("base_baseline"),
                    sentinel.get("mutable_baseline"),
                    sentinel.get("execution_manifest"),
                    *(sentinel.get("samples") or []),
                )
            )
        required_references.extend(
            (
                rollback.get("approval_packet"),
                rollback.get("deployment_request_candidate"),
                rollback.get("manifest"),
                rollback.get("recovery_result"),
            )
        )
        if isinstance(request_candidate, Mapping):
            required_references.append(request_candidate.get("evidence_bundle"))
        required_references.extend(evidence_references)
        required_identities = {
            (reference.get("path"), reference.get("sha256"))
            for reference in required_references
            if isinstance(reference, Mapping)
        }
        if not required_identities.issubset(set(observed_references)):
            errors.append("candidate bound evidence list omits a required JSON artifact")


def _verify_boundaries(candidate: Mapping[str, Any], errors: list[str]) -> None:
    forbidden = candidate.get("forbidden_actions")
    if not isinstance(forbidden, Mapping):
        errors.append("forbidden-action ledger is missing")
    else:
        for field in FORBIDDEN_ACTION_FIELDS:
            if forbidden.get(field) is not False:
                errors.append(f"forbidden action is present or unconfirmed: {field}")
    if candidate.get("authorization_to_enter_step8") is not False:
        errors.append("candidate improperly grants Step8 admission")
    risks = candidate.get("remaining_risks")
    if not isinstance(risks, list):
        errors.append("remaining risks must be explicitly listed")
    pending = candidate.get("pending_production_actions")
    if not isinstance(pending, list) or not pending:
        errors.append("pending production actions are missing")
    elif not all(
        isinstance(item, Mapping)
        and item.get("approval_required") is True
        and item.get("status") == "NOT_AUTHORIZED"
        for item in pending
    ):
        errors.append("pending production actions are not all approval-bound and unauthorized")


def validate_step7_candidate(
    candidate: Mapping[str, Any],
    *,
    source_root: Path,
    deployment_root: Path,
    _test_only_disable_committed_boundary: bool = False,
    _test_only_collection_snapshots: Mapping[
        str, Mapping[str, Any]
    ] | None = None,
    _test_only_anchor_root: Path | None = None,
) -> dict[str, Any]:
    """Return a machine-readable, fail-closed Step7 validation summary."""

    errors: list[str] = []
    source_root = source_root.expanduser().resolve(strict=True)
    deployment_root = deployment_root.expanduser().resolve(strict=True)
    anchor_root = (
        _test_only_anchor_root
        if _test_only_anchor_root is not None
        else CODEX_SESSION_ROOT
    )
    if candidate.get("schema") != CANDIDATE_SCHEMA:
        errors.append("candidate schema mismatch")
    if candidate.get("marker") != READY_MARKER:
        errors.append("candidate marker mismatch")
    _verify_entry_candidate(candidate, errors)
    source_state = _verify_source_state(
        candidate,
        source_root,
        not _test_only_disable_committed_boundary,
        errors,
    )
    source_deployment = _verify_source_deployment(
        source_root, deployment_root, candidate, errors
    )
    _verify_switches(candidate, source_root, deployment_root, errors)
    sentinel = _verify_sentinel(candidate, deployment_root, errors)
    gates = _verify_gates(
        candidate,
        deployment_root,
        sentinel,
        errors,
        _test_only_collection_snapshots,
    )
    cleanup_review = _verify_cleanup(
        candidate,
        source_state,
        source_root,
        deployment_root,
        errors,
        anchor_root,
    )
    full_review_references: list[Any] = [
        candidate.get("step56_entry_candidate"),
        *(candidate.get("step56_independent_accepts") or []),
        *[
            gate.get("evidence")
            for gate in candidate.get("gates", [])
            if isinstance(gate, Mapping)
        ],
    ]
    cleanup = candidate.get("cleanup")
    if isinstance(cleanup, Mapping):
        full_review_references.extend((cleanup.get("candidate"), cleanup.get("ledger")))
        cleanup_review_value = cleanup.get("real_sitina_review")
        if isinstance(cleanup_review_value, Mapping):
            full_review_references.extend(
                (
                    cleanup_review_value.get("input"),
                    cleanup_review_value.get("audit"),
                    cleanup_review_value.get("receipt"),
                )
            )
    sentinel_value = candidate.get("production_sentinel")
    if isinstance(sentinel_value, Mapping):
        full_review_references.extend(
            (
                sentinel_value.get("base_baseline"),
                sentinel_value.get("mutable_baseline"),
                sentinel_value.get("execution_manifest"),
                *(sentinel_value.get("samples") or []),
            )
        )
    rollback_value = candidate.get("rollback_proof")
    if isinstance(rollback_value, Mapping):
        full_review_references.extend(
            (
                rollback_value.get("approval_packet"),
            )
        )
    supporting_evidence = candidate.get(
        "deployment_request_supporting_evidence"
    )
    if isinstance(supporting_evidence, Mapping):
        full_review_references.extend(supporting_evidence.values())
    source_value = candidate.get("source")
    if isinstance(source_value, Mapping):
        for relative in source_value.get("changed_files", []):
            if isinstance(relative, str):
                path = source_root / relative
                if path.is_file() and not path.is_symlink():
                    full_review_references.append(
                        {"path": str(path), "sha256": _sha256(path)}
                    )
    full_review_references.append(
        {"path": STEP7_AUTHORITY_PATH, "sha256": STEP7_AUTHORITY_SHA256}
    )
    full_review_required_identities = {
        (str(reference.get("path")), str(reference.get("sha256")))
        for reference in full_review_references
        if isinstance(reference, Mapping)
    }
    step7_review = _verify_review(
        candidate.get("real_sitina_review"),
        source_state,
        source_root,
        deployment_root,
        "STEP7_FULL_REVIEW",
        full_review_required_identities,
        errors,
        "Step7 Sitina review",
        anchor_root,
    )
    if (
        cleanup_review.get("run_id") is not None
        and cleanup_review.get("run_id") == step7_review.get("run_id")
    ):
        errors.append("cleanup and full Step7 reviews are not independent runs")
    _verify_rollback_and_bound_evidence(
        candidate,
        source_root,
        deployment_root,
        source_state,
        errors,
        anchor_root,
    )
    _verify_boundaries(candidate, errors)
    return {
        "schema": "SITINA_STEP7_GATE_RESULT_V1",
        "marker": READY_MARKER,
        "accepted": not errors,
        "error_count": len(errors),
        "errors": errors,
        "source": source_state,
        "source_deployment": source_deployment,
        "gates": gates,
        "execution_switches_false": not any(
            error.startswith("execution switch") for error in errors
        ),
        "step8_admission_granted": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--deployment-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        candidate = _load_json(arguments.candidate.expanduser().resolve(strict=True))
        summary = validate_step7_candidate(
            candidate,
            source_root=arguments.source_root,
            deployment_root=arguments.deployment_root,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        summary = {
            "schema": "SITINA_STEP7_GATE_RESULT_V1",
            "marker": READY_MARKER,
            "accepted": False,
            "error_count": 1,
            "errors": [f"gate input rejected: {type(exc).__name__}"],
            "step8_admission_granted": False,
        }
    print(SUMMARY_MARKER + json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
