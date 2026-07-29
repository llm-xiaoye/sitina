from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import runpy
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts import step7_readiness_gate as step7_gate
from scripts.step7_readiness_gate import (
    BACKUP_ROLLBACK_EXECUTION_SEQUENCE,
    BACKUP_ROLLBACK_FAILURE_POLICY,
    BACKUP_ROLLBACK_FORBIDDEN_FIELDS,
    BACKUP_ROLLBACK_PLAN_SCHEMA,
    ACTIVATION_RESULT_SCHEMA,
    APPROVED_PYTHON_PATH,
    BASE_SENTINEL_PATH,
    BASE_SENTINEL_PHYSICAL_SHA256,
    BASE_SENTINEL_REPORT_SHA256,
    CANDIDATE_SCHEMA,
    CODEX_SOURCE_USER_AUTHORIZATION_REFERENCE_FIELDS,
    CODEX_SOURCE_USER_AUTHORIZATION_SCHEMA,
    CODEX_USER_AUTHORIZATION_SCHEMA,
    DEPENDENCY_RESULT_SCHEMA,
    DEPLOYMENT_PACKET_SCHEMA,
    DEPLOYMENT_AUTHORIZATION_CONTRACT_SCHEMA,
    DEPLOYMENT_AUTHORIZATION_MARKER,
    DEPLOYMENT_AUTHORIZATION_PAYLOAD_FIELDS,
    DEPLOYMENT_AUTHORIZATION_TWO_HOP_STRUCTURE,
    DEPLOYMENT_DELEGATION_MARKER,
    DEPLOYMENT_DELEGATION_SOURCE_BINDING_FIELDS,
    DEPLOYMENT_REQUEST_CANDIDATE_SCHEMA,
    DEPLOYMENT_REQUEST_EVIDENCE_SCHEMA,
    DIRECTED_STAGE_SELECTORS,
    ENTRY_CANDIDATE_SHA256,
    EXECUTION_MANIFEST_CANONICAL_SHA256,
    EXECUTION_MANIFEST_PATH,
    EXECUTION_MANIFEST_PHYSICAL_SHA256,
    EXPECTED_PRODUCTION_GUARD_PROFILE,
    FORBIDDEN_ACTION_FIELDS,
    HISTORICAL_SKIP_IDS,
    HISTORICAL_SKIP_REASON,
    MUTABLE_SENTINEL_PATH,
    MUTABLE_SENTINEL_PHYSICAL_SHA256,
    MUTABLE_SENTINEL_REPORT_SHA256,
    OFFICIAL_GOAL_ID,
    READY_MARKER,
    REGISTRATION_RESULT_SCHEMA,
    REQUIRED_GATES,
    ROLLBACK_MANIFEST_SCHEMA,
    ROLLBACK_RESULT_SCHEMA,
    SENTINEL_SAMPLE_SCHEMA,
    STAGE_SUITE_KEYS,
    STEP56_ACCEPT_RECORDS,
    STEP56_ACCEPT_SCHEMA,
    STEP56_SOURCE_SESSION_ID,
    STEP56_SOURCE_SESSION_META_RAW_SHA256,
    STEP56_SOURCE_SESSION_PATH,
    STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH,
    STEP56_SOURCE_SESSION_PREFIX_LINE_COUNT,
    STEP56_SOURCE_SESSION_PREFIX_SHA256,
    STEP7_DELEGATED_SOURCE_SESSION,
    STEP7_SOURCE_THREAD_ID,
    SOURCE_UI_TRANSPORT_NORMALIZATION_CONTRACT,
    SOURCE_UI_TRANSPORT_NORMALIZATION_SCHEMA,
    TEST_RESULT_SCHEMA,
    _openai_wire_messages,
    _json_value_sha256,
    _normalize_source_authorization_transport,
    _step7_v4_atomic_replace,
    _step7_v4_checkpoint,
    _step7_v4_close_test_capability,
    _step7_v4_copy_exclusive,
    _step7_v4_dir_identity,
    _step7_v4_intent,
    _step7_v4_issue_test_capability,
    _step7_v4_production_gate_contract,
    _step7_v4_recovered_checkpoint,
    _step7_v4_rename_noreplace,
    _step7_v4_rollback_intent,
    _verify_backup_and_rollback_plan,
    _verify_step56_source_session,
    execute_step7_v4,
    recover_step7_v4_execution,
    step7_v4_failure_injection_steps,
    validate_step7_candidate,
)


ENTRY_CANDIDATE = Path(
    "/Users/moss/Desktop/sitina/output/"
    "sitina-step7-entry-review-candidate-step56-45a36be.json"
)
DEPLOYED_CONTENT_ROOT = Path(__file__).resolve().parents[2]
_BOUND_SOURCE_ROOT = os.environ.get("SITINA_STEP7_SOURCE_ROOT")
if _BOUND_SOURCE_ROOT is None:
    REPOSITORY_ROOT = DEPLOYED_CONTENT_ROOT
else:
    _source_root = Path(_BOUND_SOURCE_ROOT)
    if (
        not _source_root.is_absolute()
        or _source_root.resolve(strict=True) != _source_root
    ):
        raise RuntimeError(
            "SITINA_STEP7_SOURCE_ROOT must be an absolute canonical path"
        )
    _git_top_level = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=_source_root,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).strip()
    if Path(_git_top_level).resolve(strict=True) != _source_root:
        raise RuntimeError(
            "SITINA_STEP7_SOURCE_ROOT is not the bound git top-level"
        )
    REPOSITORY_ROOT = _source_root


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Step7ReadinessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._step7_v4_capabilities: dict[str, object] = {}
        if not ENTRY_CANDIDATE.is_file():
            self.fail(f"missing authoritative entry candidate: {ENTRY_CANDIDATE}")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.deployment = self.root / "deployment"
        self.output = self.root / "output"
        for path in (self.source, self.deployment, self.output):
            path.mkdir()
        self.anchor_root = self.output / "codex-sessions"
        self.anchor_root.mkdir()
        self.anchor_session = self.anchor_root / "fixture-session.jsonl"
        self.anchor_session.write_text(
            json.dumps(
                {
                    "timestamp": "2026-07-27T00:00:00.000Z",
                    "type": "session_meta",
                    "payload": {
                        "session_id": "fixture-session",
                        "id": "fixture-session",
                        "originator": "Codex Desktop",
                        "source": "vscode",
                        "thread_source": "subagent",
                        "model_provider": "openai",
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.source_authorization_session = (
            self.anchor_root / "fixture-source-session.jsonl"
        )
        self.source_authorization_session.write_text(
            json.dumps(
                {
                    "timestamp": "2026-07-27T00:00:00.000Z",
                    "type": "session_meta",
                    "payload": {
                        "session_id": STEP7_SOURCE_THREAD_ID,
                        "id": STEP7_SOURCE_THREAD_ID,
                        "originator": "codex_work_desktop",
                        "source": "vscode",
                        "thread_source": "user",
                        "model_provider": "openai",
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        policy = {
            "schema": "SITINA_TRUE_MULTI_AGENT_POLICY_V1",
            "tool_calls_allowed": False,
            "external_mutation_allowed": False,
            "execution_bridge_enabled": False,
            "execution_handoff_bypass_enabled": False,
        }
        (self.source / "config").mkdir()
        (self.source / "config/true_multi_agent_policy.json").write_text(
            json.dumps(policy, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (self.source / "tests").mkdir()
        (self.source / "core/sitina/security").mkdir(parents=True)
        shutil.copy2(
            REPOSITORY_ROOT / "core/sitina/security/redaction.py",
            self.source / "core/sitina/security/redaction.py",
        )
        shutil.copy2(
            REPOSITORY_ROOT / "tests/test_suites.json",
            self.source / "tests/test_suites.json",
        )
        shutil.copy2(
            REPOSITORY_ROOT / "requirements-bplus.lock",
            self.source / "requirements-bplus.lock",
        )
        (self.source / ".python-version").write_text("3.12.13\n", encoding="utf-8")
        (self.source / "tracked.txt").write_text("Step7 tracked source\n", encoding="utf-8")
        shutil.copytree(self.source, self.deployment, dirs_exist_ok=True)
        (self.source / "created.txt").write_text(
            "Step7 newly created source\n",
            encoding="utf-8",
        )
        self._git("init", "-q")
        self._git("config", "user.email", "step7-tests@example.invalid")
        self._git("config", "user.name", "Step7 Tests")
        self._git("add", ".")
        self._git("commit", "-qm", "fixture")

        cleanup_source = Path(
            "/Users/moss/Desktop/sitina/output/"
            "sitina-cleanup-candidate-step7-20260727.json"
        )
        ledger_source = Path(
            "/Users/moss/Desktop/sitina/output/"
            "sitina-cleanup-ledger-step7-20260727.json"
        )
        cleanup_candidate = json.loads(cleanup_source.read_text(encoding="utf-8"))
        for index, reference in enumerate(cleanup_candidate["evidence_sources"]):
            local_source = self.output / f"cleanup-source-{index}.json"
            source_document = (
                {"schema": reference["schema"], "fixture": True}
                if "schema" in reference
                else {"fixture": True}
            )
            local_source.write_text(
                json.dumps(source_document, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            reference["path"] = str(local_source.resolve())
            reference["physical_sha256"] = sha256(local_source)
        self.cleanup_candidate = self._json_file(
            "cleanup-candidate.json", cleanup_candidate
        )
        self.cleanup_ledger = self.output / "cleanup-ledger.json"
        cleanup_ledger = json.loads(ledger_source.read_text(encoding="utf-8"))
        cleanup_ledger["candidate_binding"]["path"] = str(
            self.cleanup_candidate.resolve()
        )
        cleanup_ledger["candidate_binding"]["physical_sha256"] = sha256(
            self.cleanup_candidate
        )
        self.cleanup_ledger.write_text(
            json.dumps(cleanup_ledger, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.general_evidence = self._json_file(
            "general-evidence.json",
            {"schema": "SITINA_STEP7_TEST_EVIDENCE_V1", "accepted": True},
        )
        self.cleanup_review_input = self._json_file(
            "cleanup-review-input.json",
            {
                "schema": "SITINA_STEP7_REAL_REVIEW_INPUT_V1",
                "scope": "strict cleanup closure test fixture",
            },
        )
        self.review_input = self._json_file(
            "review-input.json",
            {
                "schema": "SITINA_STEP7_REAL_REVIEW_INPUT_V1",
                "scope": "strict full Step7 test fixture",
            },
        )
        self.cleanup_audit = self.output / "cleanup-review.jsonl"
        self.cleanup_audit.write_text("", encoding="utf-8")
        self.audit = self.output / "review.jsonl"
        self.audit.write_text("", encoding="utf-8")
        self.sentinel_samples = [
            self._json_file(
                f"sentinel-{sample}.json",
                self._sentinel_sample(sample, second),
            )
            for second, sample in enumerate(("before", "after"))
        ]
        self.gate_evidence: dict[str, Path] = {
            stage: self._json_file(
                f"{stage}.json",
                self._gate_evidence_document(stage),
            )
            for stage in REQUIRED_GATES
        }
        self.step56_accepts = self._step56_accept_artifacts()
        self.rollback_exclusions_stub = self._json_file(
            "rollback-exclusions.json",
            {
                "schema": "SITINA_STEP7_EXCLUDED_ATTEMPTS_V2",
                "source": {
                    "head": self._git("rev-parse", "HEAD^{commit}"),
                    "tree": self._git("rev-parse", "HEAD^{tree}"),
                },
                "all_counted_as_pass": False,
                "attempts": [
                    {
                        "kind": "SUPERSEDED_FIXTURE_ATTEMPT",
                        "counted_as_pass": False,
                    }
                ],
            },
        )
        self.rollback_revocation_stub = self._json_file(
            "rollback-revocation.json",
            {
                "schema": "SITINA_STEP7_DEPLOYMENT_PACKET_REVOCATION_V1",
                "source_thread_id": (
                    "019f810d-78fe-75d2-8efd-d43fccbd82d7"
                ),
                "decision": "REJECT_DEPLOY_REQUEST",
                "revoked_approval_id": (
                    "SITINA_STEP7_DEPLOY_62ACDF0_6F_20260727T145000Z"
                ),
                "revoked_candidate": {
                    "sha256": (
                        "6d2f5c8884ac4e4556af19a56a6de72"
                        "cbac59db421f1cac6888d7e5fcc8ccd5e"
                    )
                },
                "revoked_packet": {
                    "sha256": (
                        "b08466b7ef37f6e96c507548c70f56b8"
                        "3b628bb32c99ab8525067d884db5d556"
                    )
                },
                "may_execute": False,
                "may_request_authorization": False,
                "may_reuse_candidate_sha256": False,
                "may_reuse_packet_sha256": False,
                "deployment_performed": False,
                "production_canary_run": False,
                "production_data_modified": False,
                "baseline_modified": False,
                "step8_step9_entered": False,
            },
        )
        source_head = self._git("rev-parse", "HEAD^{commit}")
        source_short = source_head[:7]
        self.rollback_artifact_version = "20260724T000000Z"
        self.rollback_approval_id = (
            "SITINA_STEP7_DEPLOY_"
            f"{source_short.upper()}_6F_{self.rollback_artifact_version}"
        )
        self.rollback_root = (
            self.output.resolve()
            / f"sitina-step7-deploy-v4-{self.rollback_approval_id}"
        )
        self.rehearsal_quarantine_root = (
            self.rollback_root / "rehearsal" / "quarantine" / "created"
        )
        self.rollback_quarantine_root = (
            self.rollback_root / "quarantine" / "created"
        )
        self.rollback_backup = (
            self.rollback_root / "preimages" / "tracked.txt.preimage"
        )
        self.rollback_restored_snapshot = self.output / "tracked.txt.restored-snapshot"
        shutil.copy2(
            self.deployment / "tracked.txt",
            self.rollback_restored_snapshot,
        )
        self.rollback_reapplied_snapshot = self.output / "tracked.txt.reapplied-snapshot"
        shutil.copy2(self.source / "tracked.txt", self.rollback_reapplied_snapshot)
        self.rollback_created_reapplied_snapshot = (
            self.output / "created.txt.reapplied-snapshot"
        )
        shutil.copy2(
            self.source / "created.txt",
            self.rollback_created_reapplied_snapshot,
        )
        self.rollback_packet = self._json_file(
            "rollback-approval-packet.json",
            self._rollback_packet_document(),
        )
        packet_document = json.loads(
            self.rollback_packet.read_text(encoding="utf-8")
        )
        source_tree = self._git("rev-parse", "HEAD^{tree}")
        self.formal_executor = (
            self.output
            / (
                f"step7-{source_short}-authorized-execution-"
                f"{self.rollback_artifact_version}.py"
            )
        )
        formal_executor_binding = {
            "schema": "SITINA_STEP7_FORMAL_EXECUTOR_RUNTIME_BINDING_V1",
            "approved_python": APPROVED_PYTHON_PATH,
            "pycache_prefix": step7_gate.STEP7_PYCACHE_PREFIX,
            "git": {
                "path": step7_gate.GIT_EXECUTABLE_PATH,
                "sha256": step7_gate.GIT_EXECUTABLE_SHA256,
            },
            "approval_id": self.rollback_approval_id,
            "run_id": f"{self.rollback_approval_id}_EXECUTION",
            "source_root": str(self.source.resolve()),
            "source_head": source_head,
            "source_tree": source_tree,
            "deployment_root": str(self.deployment.resolve()),
            "allowed_backup_parent": str(self.output.resolve()),
            "backup_root": str(self.rollback_root),
            "packet": self._reference(self.rollback_packet),
            "candidate_path": str(
                self.output.resolve()
                / "rollback-deployment-request-candidate.json"
            ),
            "evidence_path": str(
                self.output.resolve() / "rollback-request-evidence.json"
            ),
            "static_integrity_path": str(self.general_evidence.resolve()),
            "operations_path": str(
                self.output.resolve()
                / f"sitina-step7-deployment-operations-{source_short}.json"
            ),
            "operations_sha256": _json_value_sha256(
                packet_document["exact_file_operations"]
            ),
            "plan_sha256": packet_document[
                "backup_and_rollback_plan_sha256"
            ],
            "authorization_receipt_path": str(
                self.output.resolve()
                / (
                    f"sitina-step7-authorization-receipt-{source_short}-"
                    f"{self.rollback_artifact_version}.json"
                )
            ),
            "execution_specification_path": str(
                self.output.resolve()
                / (
                    f"sitina-step7-authorized-execution-spec-{source_short}-"
                    f"{self.rollback_artifact_version}.json"
                )
            ),
            "gate_path": str(self.source.resolve() / "tracked.txt"),
            "source_dependencies": [
                self._reference(self.source / "tracked.txt"),
                self._reference(self.source / "created.txt"),
            ],
        }
        self.formal_executor_binding = formal_executor_binding
        self.formal_executor.write_text(
            step7_gate._step7_formal_executor_source(
                formal_executor_binding
            ),
            encoding="utf-8",
        )
        self.general_evidence.write_text(
            json.dumps(
                self._static_integrity_document(),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self._finalize_review_inputs_and_audits()
        self.rollback_request_evidence = self._json_file(
            "rollback-request-evidence.json",
            self._rollback_request_evidence_document(),
        )
        self.rollback_review_candidate = self._json_file(
            "rollback-deployment-request-candidate.json",
            self._rollback_review_candidate_document(),
        )
        self.rollback_authorization = self._user_authorization(
            self.rollback_packet,
            json.loads(self.rollback_packet.read_text(encoding="utf-8")),
        )
        self.rollback_root.mkdir(mode=0o700)
        self.rollback_backup.parent.mkdir()
        shutil.copy2(self.deployment / "tracked.txt", self.rollback_backup)
        shutil.copy2(
            self.source / "created.txt",
            self.deployment / "created.txt",
        )
        rehearsal_source = (
            self.rollback_root / "rehearsal" / "created" / "created.txt"
        )
        rehearsal_source.parent.mkdir(parents=True)
        shutil.copy2(self.source / "created.txt", rehearsal_source)
        self.rehearsal_quarantine_created = (
            self.rehearsal_quarantine_root / "created.txt"
        )
        self.rehearsal_quarantine_created.parent.mkdir(parents=True)
        self.rehearsal_quarantine_move = _step7_v4_rename_noreplace(
            rehearsal_source,
            self.rehearsal_quarantine_created,
        )
        self.rollback_quarantine_created = (
            self.rollback_quarantine_root / "created.txt"
        )
        self.rollback_quarantine_created.parent.mkdir(parents=True)
        self.assertFalse(self.rollback_quarantine_created.exists())
        self.rollback_manifest = self.rollback_root / "backup-manifest.json"
        self.rollback_manifest.write_text(
            json.dumps(self._rollback_manifest_document(), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.rollback_recovery = self.rollback_root / "recovery-verification.json"
        self.rollback_recovery.write_text(
            json.dumps(self._rollback_recovery_document(), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.candidate = self._valid_candidate()
        self.collection_snapshots = {}
        for stage, path in self.gate_evidence.items():
            evidence = json.loads(path.read_text(encoding="utf-8"))
            strict = (
                evidence["registration_gate"]
                if stage == "all_registered_unique"
                else evidence["activation_gate"]
            )
            self.collection_snapshots[stage] = {
                "selector_counts": copy.deepcopy(strict["selector_counts"]),
                "collected_test_ids": list(strict["collected_test_ids"]),
                "collection_errors": [],
            }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", *arguments],
            cwd=self.source,
            text=True,
        ).strip()

    def _json_file(self, name: str, value: dict[str, object]) -> Path:
        path = self.output / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _reference(path: Path) -> dict[str, str]:
        return {"path": str(path.resolve()), "sha256": sha256(path)}

    def _failed_preapply_revocation_document(self) -> dict[str, object]:
        old_root = Path(step7_gate.FAILED_PREAPPLY_REVOCATION_BACKUP_ROOT)
        inventory = []
        for path in (old_root, *sorted(old_root.rglob("*"))):
            metadata = path.lstat()
            inventory.append(
                {
                    "path": str(path),
                    "type": "DIRECTORY",
                    "mode": oct(stat.S_IMODE(metadata.st_mode)),
                    "size": metadata.st_size,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "sha256": None,
                }
            )
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPOSITORY_ROOT,
            text=True,
        ).strip()
        tree = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=REPOSITORY_ROOT,
            text=True,
        ).strip()
        references = step7_gate.FAILED_PREAPPLY_REVOCATION_REFERENCES
        return {
            "schema": step7_gate.FAILED_PREAPPLY_REVOCATION_SCHEMA,
            "revoked_at_utc": "2026-07-28T04:18:14.461Z",
            "source_thread_id": STEP7_SOURCE_THREAD_ID,
            "decision": "FAILED_PREAPPLY_REVOKE_AND_REBUILD",
            "physical_classification": (
                "DEPLOYMENT_PREAPPLY_WITH_BACKUP_LAYOUT_RESIDUE"
            ),
            "revoked_approval_id": (
                step7_gate.FAILED_PREAPPLY_REVOCATION_APPROVAL_ID
            ),
            "revoked_source": {
                "root": str(REPOSITORY_ROOT),
                **step7_gate.FAILED_PREAPPLY_REVOCATION_SOURCE,
            },
            "revoked_artifacts": {
                "prior_revocation": {
                    "path": (
                        "/Users/moss/Desktop/sitina/output/"
                        "sitina-step7-deployment-packet-revocation-"
                        "8c3582c-20260728T041814Z.json"
                    ),
                    "sha256": (
                        "f3bb029aa1ff05e239931806d2084a846"
                        "5ea7a3ab6bde438341f8d93d6d2b467"
                    ),
                },
                "authorization_request": {
                    **references["revoked_authorization_request"],
                    "canonical_logical_length": 666,
                    "canonical_logical_sha256": (
                        "ed93132cd51e4efd992cab8aabc422ce9"
                        "ed795949ae79050bc3e6da3e1fc4da5"
                    ),
                },
                "authorization_receipt": {
                    "path": (
                        "/Users/moss/Desktop/sitina/output/"
                        "sitina-step7-authorization-receipt-8c3582c.json"
                    ),
                    "sha256": (
                        "b1e9eab9a9e8a2e9bd4ed623fdbdc969"
                        "e9d3829affcce028eeb8ef0459a228cc"
                    ),
                    "canonical_sha256": (
                        "52e6dec96b2a7d7bfbb006244b2209dd3"
                        "2f7005c46bb3c5157f6089546b79a3f"
                    ),
                    "source_raw_record_sha256": (
                        "740880047a8e02de44802b11748a3055f"
                        "0106d5d7c1fa9b2fe192712ee74af05"
                    ),
                    "wrapper_raw_record_sha256": (
                        "3afbfda470474b8e0def88925b461211b"
                        "ca774c5e66f14e3c28fab9d41eab240"
                    ),
                },
                "packet": copy.deepcopy(references["revoked_packet"]),
                "review_candidate": copy.deepcopy(
                    references["revoked_candidate"]
                ),
                "evidence_bundle": copy.deepcopy(
                    references["revoked_evidence"]
                ),
                "execution_specification": copy.deepcopy(
                    references["revoked_execution_specification"]
                ),
            },
            "failed_execution_record": {
                "session_path": (
                    step7_gate.FAILED_PREAPPLY_REVOCATION_SESSION
                ),
                "line_number": 11732,
                "raw_record_sha256": (
                    "64e5a86c318443888cfff3cbca66aa1d3"
                    "dd887a33cea9acd18b72b37a0b305fe"
                ),
                "status": "MANUAL_RECOVERY_REQUIRED",
                "failure_step": (
                    "[Errno 2] No such file or directory: 'scripts'"
                ),
                "delete_operation_count": 0,
                "unlink_operation_count": 0,
                "rmtree_operation_count": 0,
            },
            "backup_residue": {
                "root": str(old_root),
                "inventory": inventory,
                "directory_count": 9,
                "file_count": 0,
                "symlink_count": 0,
                "checkpoint_file_count": 0,
                "manifest_exists": False,
                "must_be_retained": True,
                "reuse_allowed": False,
                "cleanup_authorized": False,
            },
            "deployment_effects": {
                "deployment_target_change_count": 0,
                "production_data_change_count": 0,
                "baseline_change_count": 0,
                "canary_run_count": 0,
                "execution_switch_change_count": 0,
                "step8_step9_entered": False,
            },
            "recovery": {
                "reason": (
                    "NO_MANIFEST_NO_INTENT_NO_COMMIT_NO_DEPLOYMENT_MUTATION"
                ),
                "deployment_rollback_required": False,
                "deployment_rollback_permitted": False,
                "manual_backup_cleanup_requires_new_exact_authorization": True,
            },
            "reuse_policy": {
                "may_execute": False,
                "may_retry": False,
                "may_reuse_packet": False,
                "may_reuse_candidate": False,
                "may_reuse_evidence": False,
                "may_reuse_operations_sha256": False,
                "may_reuse_plan_sha256": False,
                "may_reuse_gate_results": False,
                "may_reuse_real_sitina_reviews": False,
                "may_reuse_authorization_request": False,
                "may_reuse_authorization_receipt": False,
                "may_reuse_source_user_record": False,
                "may_reuse_delegation_wrapper": False,
                "may_reuse_execution_specification": False,
                "may_reuse_backup_root": False,
            },
            "successor_fix": {
                "source_root": str(REPOSITORY_ROOT),
                "head": head,
                "tree": tree,
                "scope": (
                    "CREATE_NESTED_PREIMAGE_PARENT_DIRECTORIES_NOFOLLOW"
                ),
            },
            "step8_step9_not_entered": True,
        }

    def _capture_anchor(
        self,
        marker: str,
        payload: dict[str, object],
        *,
        independent_reviewer: bool = False,
    ) -> dict[str, object]:
        existing = self.anchor_session.read_bytes().splitlines(keepends=True)
        line_number = len(existing) + 1
        record_id = f"msg-fixture-{line_number}"
        text = marker + " " + json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        author = "/root/step7_fixture_independent_review"
        if independent_reviewer:
            text = (
                "Message Type: FINAL_ANSWER\n"
                "Task name: /root\n"
                f"Sender: {author}\n"
                "Payload:\n"
                + text
            )
            record_payload = {
                "type": "agent_message",
                "id": record_id,
                "author": author,
                "recipient": "/root",
                "content": [{"type": "input_text", "text": text}],
            }
        else:
            author = "/root"
            record_payload = {
                "type": "message",
                "id": record_id,
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
                "phase": "commentary",
            }
        record = {
            "timestamp": f"2026-07-27T00:00:{line_number:02d}.000Z",
            "type": "response_item",
            "payload": record_payload,
        }
        raw = (
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with self.anchor_session.open("ab") as handle:
            handle.write(raw)
        return {
            "schema": "SITINA_CODEX_APPEND_ONLY_CAPTURE_ANCHOR_V1",
            "session_path": str(self.anchor_session.resolve()),
            "line_number": line_number,
            "record_id": record_id,
            "raw_record_sha256": hashlib.sha256(raw).hexdigest(),
            "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "marker": marker,
            "author": author,
        }

    def _user_authorization(
        self,
        packet_path: Path,
        packet: dict[str, object],
        *,
        payload_override: dict[str, object] | None = None,
        delegated: bool = True,
        source_thread_id: str = STEP7_SOURCE_THREAD_ID,
        input_suffix: str = "",
        source_text_prefix: str = "",
        source_text_suffix: str = "",
        self_delegated: bool = False,
        source_role: str = "user",
        binding_override: dict[str, object] | None = None,
        source_timestamp: str = "2026-07-27T00:01:00.000Z",
    ) -> dict[str, object]:
        payload = payload_override or {
            "approval_id": packet["approval_id"],
            "approval_packet_sha256": sha256(packet_path),
            "exact_file_operation_count": len(packet["exact_file_operations"]),
            "exact_file_operations_sha256": _json_value_sha256(
                packet["exact_file_operations"]
            ),
            "rollback_plan_sha256": packet[
                "backup_and_rollback_plan_sha256"
            ],
            "review_candidate_sha256": sha256(
                self.rollback_review_candidate
            ),
            "source_head": packet["source_binding"]["head"],
            "source_tree": packet["source_binding"]["tree"],
            "deployment_root": packet["deployment_binding"]["root"],
        }
        marker = DEPLOYMENT_AUTHORIZATION_MARKER
        exact_authorization = marker + " " + json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        source_text = (
            source_text_prefix + exact_authorization + source_text_suffix
        )
        source_existing = self.source_authorization_session.read_bytes().splitlines(
            keepends=True
        )
        source_line_number = len(source_existing) + 1
        source_record_id = f"msg-source-fixture-{source_line_number}"
        source_record = {
            "timestamp": source_timestamp,
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": source_record_id,
                "role": source_role,
                "content": [{"type": "input_text", "text": source_text}],
            },
        }
        source_raw = (
            json.dumps(
                source_record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with self.source_authorization_session.open("ab") as handle:
            handle.write(source_raw)
        canonical_source_text = _normalize_source_authorization_transport(
            source_text
        )
        if canonical_source_text is None:
            canonical_source_text = source_text
        source_text_bytes = source_text.encode("utf-8")
        canonical_source_text_bytes = canonical_source_text.encode("utf-8")
        transport_mode = (
            "IDENTITY"
            if canonical_source_text == source_text
            else "REMOVE_ONE_TERMINAL_LF"
        )
        source_reference = {
            "schema": CODEX_SOURCE_USER_AUTHORIZATION_SCHEMA,
            "session_path": str(self.source_authorization_session.resolve()),
            "line_number": source_line_number,
            "record_id": source_record_id,
            "raw_record_sha256": hashlib.sha256(source_raw).hexdigest(),
            "actual_content_sha256": hashlib.sha256(
                source_text_bytes
            ).hexdigest(),
            "actual_content_length": len(source_text_bytes),
            "canonical_logical_sha256": hashlib.sha256(
                canonical_source_text_bytes
            ).hexdigest(),
            "canonical_logical_length": len(canonical_source_text_bytes),
            "transport_normalization_mode": transport_mode,
            "transport_removed_suffix_hex": (
                "" if transport_mode == "IDENTITY" else "0a"
            ),
            "transport_removed_byte_count": (
                0 if transport_mode == "IDENTITY" else 1
            ),
            "marker": marker,
            "author": "user",
        }
        source_meta_raw = self.source_authorization_session.read_bytes().splitlines(
            keepends=True
        )[0]
        source_binding = {
            "approval_id": packet["approval_id"],
            "source_thread_id": STEP7_SOURCE_THREAD_ID,
            "source_session_path": source_reference["session_path"],
            "source_session_meta_raw_sha256": hashlib.sha256(
                source_meta_raw
            ).hexdigest(),
            "source_line_number": source_reference["line_number"],
            "source_record_id": source_reference["record_id"],
            "source_raw_record_sha256": source_reference[
                "raw_record_sha256"
            ],
            "source_actual_content_sha256": source_reference[
                "actual_content_sha256"
            ],
            "source_actual_content_length": source_reference[
                "actual_content_length"
            ],
            "source_canonical_logical_sha256": source_reference[
                "canonical_logical_sha256"
            ],
            "source_canonical_logical_length": source_reference[
                "canonical_logical_length"
            ],
            "source_transport_normalization_schema": (
                SOURCE_UI_TRANSPORT_NORMALIZATION_SCHEMA
            ),
            "source_transport_normalization_mode": source_reference[
                "transport_normalization_mode"
            ],
            "source_transport_removed_suffix_hex": source_reference[
                "transport_removed_suffix_hex"
            ],
            "source_transport_removed_byte_count": source_reference[
                "transport_removed_byte_count"
            ],
        }
        if binding_override is not None:
            source_binding.update(binding_override)
        delegation_input = DEPLOYMENT_DELEGATION_MARKER + " " + json.dumps(
            source_binding,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        wrapper_session = (
            self.source_authorization_session
            if self_delegated
            else self.anchor_session
        )
        existing = wrapper_session.read_bytes().splitlines(keepends=True)
        line_number = len(existing) + 1
        record_id = f"msg-delegation-fixture-{line_number}"
        text = (
            "<codex_delegation>\n"
            f"  <source_thread_id>{source_thread_id}</source_thread_id>\n"
            f"  <input>{delegation_input}{input_suffix}</input>\n"
            "</codex_delegation>"
            if delegated
            else exact_authorization
        )
        record = {
            "timestamp": f"2026-07-27T00:02:{line_number:02d}.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": record_id,
                "role": "user",
                "content": [{"type": "input_text", "text": text}],
            },
        }
        raw = (
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with wrapper_session.open("ab") as handle:
            handle.write(raw)
        return {
            "schema": CODEX_USER_AUTHORIZATION_SCHEMA,
            "session_path": str(wrapper_session.resolve()),
            "line_number": line_number,
            "record_id": record_id,
            "raw_record_sha256": hashlib.sha256(raw).hexdigest(),
            "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "marker": DEPLOYMENT_DELEGATION_MARKER,
            "author": "user",
            "source_authorization": source_reference,
        }

    @staticmethod
    def _fixture_counts() -> dict[str, int]:
        return {
            "minimal_negative_contract": 8,
            "identity_sentinel_directed": 56,
            "execution_activation": 60,
            "step7_readiness_gate": 32,
            "unit_fast": 232,
            "integration_isolated": 200,
            "all_registered_unique": 985,
        }

    def _registry_and_selectors(
        self,
    ) -> tuple[dict[str, object], dict[str, list[str]], list[str]]:
        registry = json.loads(
            (self.source / "tests/test_suites.json").read_text(encoding="utf-8")
        )
        suites = registry["suites"]
        suite_selectors = {
            name: list(value["selectors"]) for name, value in suites.items()
        }
        registered: list[str] = []
        for value in suites.values():
            for selector in value.get("selectors", []):
                if selector not in registered:
                    registered.append(selector)
        return registry, suite_selectors, registered

    def _sentinel_sample(self, sample: str, second: int) -> dict[str, object]:
        return {
            "schema": SENTINEL_SAMPLE_SCHEMA,
            "sample": sample,
            "goal_id": OFFICIAL_GOAL_ID,
            "production_home": "/Users/moss/SitinaHub",
            "observed_at_utc": f"2026-07-27T00:10:0{second}Z",
            "production_attempts": 0,
            "base": {
                "baseline_path": BASE_SENTINEL_PATH,
                "baseline_physical_sha256": BASE_SENTINEL_PHYSICAL_SHA256,
                "report_sha256": BASE_SENTINEL_REPORT_SHA256,
            },
            "mutable": {
                "baseline_path": MUTABLE_SENTINEL_PATH,
                "baseline_physical_sha256": MUTABLE_SENTINEL_PHYSICAL_SHA256,
                "report_sha256": MUTABLE_SENTINEL_REPORT_SHA256,
            },
            "manifest": {
                "path": EXECUTION_MANIFEST_PATH,
                "physical_sha256": EXECUTION_MANIFEST_PHYSICAL_SHA256,
                "canonical_sha256": EXECUTION_MANIFEST_CANONICAL_SHA256,
            },
        }

    def _gate_evidence_document(self, stage: str) -> dict[str, object]:
        registry, suite_selectors, registered = self._registry_and_selectors()
        suite = STAGE_SUITE_KEYS[stage]
        if stage in DIRECTED_STAGE_SELECTORS:
            selectors = list(DIRECTED_STAGE_SELECTORS[stage])
        elif stage == "all_registered_unique":
            selectors = registered
        else:
            selectors = suite_selectors[suite]
        approved_python = registry["approved_python"]
        if stage == "all_registered_unique":
            command = [
                approved_python,
                "-m",
                "tests.foundation.registration_gate_runner",
                "--registry",
                str(self.deployment.resolve() / "tests/test_suites.json"),
            ]
        else:
            command = [
                approved_python,
                "-m",
                "tests.foundation.activation_gate_runner",
                *selectors,
            ]
        collected = self._fixture_counts()[stage]
        skipped = len(HISTORICAL_SKIP_IDS) if stage == "all_registered_unique" else 0
        quotient, remainder = divmod(collected, len(selectors))
        selector_counts = {
            selector: quotient + (1 if index < remainder else 0)
            for index, selector in enumerate(selectors)
        }
        collected_test_ids = [
            f"fixture.{stage}.test_{index:04d}" for index in range(collected)
        ]
        collected_test_ids_sha256 = hashlib.sha256(
            json.dumps(
                collected_test_ids,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        strict = {
            "schema": (
                REGISTRATION_RESULT_SCHEMA
                if stage == "all_registered_unique"
                else ACTIVATION_RESULT_SCHEMA
            ),
            "policy": (
                "EXACT_HISTORICAL_SKIP_ALLOWLIST_V1"
                if stage == "all_registered_unique"
                else "ZERO_NONPASS_AND_COMPLETE_V1"
            ),
            "accepted": True,
            "collected_test_count": collected,
            "executed_test_count": collected,
            "passed": collected - skipped,
            "failures": 0,
            "errors": 0,
            "skipped": skipped,
            "expected_failures": 0,
            "unexpected_successes": 0,
            "collection_complete": True,
            "execution_complete": True,
            "collection_errors": [],
            "failure_details": [],
            "error_details": [],
            "expected_failure_details": [],
            "unexpected_success_details": [],
            "missing_test_ids": [],
            "unexpected_test_ids": [],
            "selector_counts": selector_counts,
            "collected_test_ids": collected_test_ids,
            "collected_test_ids_sha256": collected_test_ids_sha256,
            "started_test_ids": collected_test_ids,
            "started_test_ids_sha256": collected_test_ids_sha256,
            "skip_details": [],
        }
        if stage == "all_registered_unique":
            skip_details = [
                {"test_id": test_id, "reason": HISTORICAL_SKIP_REASON}
                for test_id in HISTORICAL_SKIP_IDS
            ]
            strict.update(
                {
                    "selector_count": len(selectors),
                    "skip_allowlist_match": True,
                    "skip_details": skip_details,
                    "expected_skip_details": skip_details,
                }
            )
        dependency_lock = registry["dependency_lock_sha256"]
        locked_versions = {}
        for line in (
            self.deployment / "requirements-bplus.lock"
        ).read_text(encoding="utf-8").splitlines():
            if "==" in line and not line.startswith("#") and line[0].isalnum():
                name, version = line.split("==", 1)
                locked_versions[name] = version.split()[0]
        dependency = {
            "schema": DEPENDENCY_RESULT_SCHEMA,
            "accepted": True,
            "dependencies_match": True,
            "expected_lock_sha256": dependency_lock,
            "lock_sha256": dependency_lock,
            "lock_path": str(self.deployment.resolve() / "requirements-bplus.lock"),
            "python_executable": approved_python,
            "expected_python_version": "3.12.13",
            "historical_manifest_binding_match": False,
            "historical_manifest_dependency_lock_sha256": "0" * 64,
            "python_version": "3.12.13",
            "python_match": True,
            "manifest_binding_match": True,
            "missing": [],
            "version_mismatches": [],
            "locked_versions": locked_versions,
            "installed_locked_versions": locked_versions,
            "locked_distribution_count": len(locked_versions),
        }
        return {
            "schema": TEST_RESULT_SCHEMA,
            "stage": stage,
            "suite": suite,
            "selectors": selectors,
            "command": command,
            "mode": "tests",
            "return_code": 0,
            "timed_out": False,
            "duration_seconds": 0.01,
            "stdout_sha256": "a" * 64,
            "child_cwd": f"{registry['test_home_root']}/step7-fixture-{stage}",
            "child_home_cleanup_succeeded": True,
            "child_home_cleanup_error": None,
            "warning_count": 0,
            "warning_lines": [],
            "external_attempt_count": 0,
            "production_attempt_count": 0,
            "production_attempt_records": [],
            "production_attempt_log_sha256": hashlib.sha256(b"").hexdigest(),
            "readonly_attempt_count": 0,
            "readonly_attempt_records": [],
            "readonly_attempt_log_sha256": hashlib.sha256(b"").hexdigest(),
            "capture_only": False,
            "production_guard_profile": EXPECTED_PRODUCTION_GUARD_PROFILE,
            "production_sentinel_baseline": BASE_SENTINEL_PATH,
            "production_sentinel_before": BASE_SENTINEL_REPORT_SHA256,
            "production_sentinel_after": BASE_SENTINEL_REPORT_SHA256,
            "production_mutable_sentinel_baseline": MUTABLE_SENTINEL_PATH,
            "production_mutable_sentinel_before": MUTABLE_SENTINEL_REPORT_SHA256,
            "production_mutable_sentinel_after": MUTABLE_SENTINEL_REPORT_SHA256,
            "production_sentinel_unchanged": True,
            "execution_manifest_hash": (
                f"sha256:{EXECUTION_MANIFEST_CANONICAL_SHA256}"
            ),
            "dependency_gate": dependency,
            "test_count": collected,
            "skipped_count": skipped,
            "activation_gate": None if stage == "all_registered_unique" else strict,
            "registration_gate": strict if stage == "all_registered_unique" else None,
        }

    def _rollback_plan_document(
        self,
        operations: list[dict[str, object]],
        *,
        source_head: str,
        source_tree: str,
        deployment_root: str,
    ) -> dict[str, object]:
        forbidden = {
            field: False for field in BACKUP_ROLLBACK_FORBIDDEN_FIELDS
        }
        objects: list[dict[str, object]] = []
        for index, operation in enumerate(operations):
            relative = str(operation["relative_path"])
            kind = str(operation["operation"])
            backup_path = (
                str(self.rollback_root / "preimages" / f"{relative}.preimage")
                if kind == "REPLACE"
                else None
            )
            rehearsal_quarantine_path = (
                str(self.rehearsal_quarantine_root / relative)
                if kind == "CREATE"
                else None
            )
            rollback_quarantine_path = (
                str(self.rollback_quarantine_root / relative)
                if kind == "CREATE"
                else None
            )
            objects.append(
                {
                    "index": index,
                    "relative_path": relative,
                    "operation": kind,
                    "target_path": operation["target_path"],
                    "preimage_sha256": operation["preimage_sha256"],
                    "target_sha256": operation["target_sha256"],
                    "preimage_backup_path": backup_path,
                    "rehearsal_quarantine_path": rehearsal_quarantine_path,
                    "rollback_quarantine_path": rollback_quarantine_path,
                    "rollback_action": (
                        "RESTORE_VERIFIED_PREIMAGE"
                        if kind == "REPLACE"
                        else "QUARANTINE_CREATED_TARGET"
                    ),
                    "recovery_verification": (
                        {
                            "restored_sha256": operation["preimage_sha256"],
                            "reapplied_sha256": operation["target_sha256"],
                        }
                        if kind == "REPLACE"
                        else {
                            "target_absent_after_quarantine": True,
                            "quarantined_sha256": operation["target_sha256"],
                            "reapplied_sha256": operation["target_sha256"],
                        }
                    ),
                }
            )
        return {
            "schema": BACKUP_ROLLBACK_PLAN_SCHEMA,
            "approval_id": self.rollback_approval_id,
            "status": "PLANNED_NOT_EXECUTED",
            "source_binding": {
                "root": str(self.source.resolve()),
                "head": source_head,
                "tree": source_tree,
            },
            "deployment_binding": {"root": deployment_root},
            "exact_file_operations_sha256": _json_value_sha256(operations),
            "backup_root": {
                "path": str(self.rollback_root),
                "allowed_parent": str(self.output.resolve()),
                "allowed_parent_must_exist_before_authorized_execution": True,
                "allowed_parent_creation_allowed": False,
                "allowed_parent_required_type": "DIRECTORY_NO_SYMLINK",
                "allowed_parent_ancestor_safety_required": True,
                "derived_from_approval_id": True,
                "must_not_exist_before_authorized_execution": True,
                "create_mode": "0o700",
                "create_semantics": "EXCLUSIVE_NOFOLLOW",
                "reuse_allowed": False,
            },
            "backup_manifest_path": str(
                self.rollback_root / "backup-manifest.json"
            ),
            "rehearsal_quarantine_root": str(
                self.rehearsal_quarantine_root
            ),
            "rollback_quarantine_root": str(self.rollback_quarantine_root),
            "rehearsal_result_path": str(
                self.rollback_root / "rehearsal-result.json"
            ),
            "execution_result_path": str(
                self.rollback_root / "execution-result.json"
            ),
            "recovery_result_path": str(
                self.rollback_root / "recovery-result.json"
            ),
            "recovery_verification_path": str(
                self.rollback_root / "recovery-verification.json"
            ),
            "objects": objects,
            "execution_sequence": list(BACKUP_ROLLBACK_EXECUTION_SEQUENCE),
            "failure_policy": copy.deepcopy(BACKUP_ROLLBACK_FAILURE_POLICY),
            "forbidden_boundaries": forbidden,
        }

    def _rollback_manifest_document(self) -> dict[str, object]:
        target = self.source.resolve() / "tracked.txt"
        target_stat = target.stat()
        created = self.source.resolve() / "created.txt"
        created_stat = created.stat()
        backup_stat = self.rollback_backup.stat()
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        plan_sha256 = packet["backup_and_rollback_plan_sha256"]
        return {
            "schema": ROLLBACK_MANIFEST_SCHEMA,
            "source_head": self._git("rev-parse", "HEAD^{commit}"),
            "source_tree": self._git("rev-parse", "HEAD^{tree}"),
            "deployment_root": str(self.deployment.resolve()),
            "approval_id": self.rollback_approval_id,
            "approval_packet_sha256": sha256(self.rollback_packet),
            "exact_file_operations_sha256": _json_value_sha256(
                packet["exact_file_operations"]
            ),
            "rollback_plan_sha256": plan_sha256,
            "review_candidate_sha256": sha256(
                self.rollback_review_candidate
            ),
            "backup_root": str(self.rollback_root),
            "backup_manifest_path": str(
                self.rollback_root / "backup-manifest.json"
            ),
            "backup_root_created_exclusively": True,
            "backup_root_reused": False,
            "backup_root_mode": "0o700",
            "backup_root_parent_components_safe": True,
            "verified_before_deployment": True,
            "deployment_mutated": False,
            "mismatch_count": 0,
            "entries": [
                {
                    "relative_path": "tracked.txt",
                    "operation": "REPLACE",
                    "source_path": str(target),
                    "target_path": str(self.deployment.resolve() / "tracked.txt"),
                    "target_sha256": sha256(target),
                    "target_size": target_stat.st_size,
                    "target_mode": oct(stat.S_IMODE(target_stat.st_mode)),
                    "preimage_exists": True,
                    "preimage_sha256": sha256(self.rollback_backup),
                    "preimage_size": backup_stat.st_size,
                    "preimage_mode": oct(stat.S_IMODE(backup_stat.st_mode)),
                    "backup": self._reference(self.rollback_backup),
                    "rehearsal_quarantine_path": None,
                    "rollback_quarantine_path": None,
                },
                {
                    "relative_path": "created.txt",
                    "operation": "CREATE",
                    "source_path": str(created),
                    "target_path": str(
                        self.deployment.resolve() / "created.txt"
                    ),
                    "target_sha256": sha256(created),
                    "target_size": created_stat.st_size,
                    "target_mode": oct(stat.S_IMODE(created_stat.st_mode)),
                    "preimage_exists": False,
                    "preimage_sha256": None,
                    "preimage_size": None,
                    "preimage_mode": None,
                    "backup": None,
                    "rehearsal_quarantine_path": str(
                        self.rehearsal_quarantine_created
                    ),
                    "rollback_quarantine_path": str(
                        self.rollback_quarantine_created
                    ),
                },
            ],
        }

    def _rollback_packet_document(self) -> dict[str, object]:
        target = self.source.resolve() / "tracked.txt"
        target_stat = target.stat()
        preimage = self.deployment.resolve() / "tracked.txt"
        preimage_stat = preimage.stat()
        created = self.source.resolve() / "created.txt"
        created_stat = created.stat()
        source_head = self._git("rev-parse", "HEAD^{commit}")
        source_tree = self._git("rev-parse", "HEAD^{tree}")
        deployment_root = str(self.deployment.resolve())
        approval_id = self.rollback_approval_id
        backup_root_preflight = {
            "checked_at_utc": "2026-07-27T00:00:00Z",
            "path": str(self.rollback_root),
            "allowed_parent": str(self.output.resolve()),
            "allowed_parent_existed": True,
            "allowed_parent_is_directory": True,
            "allowed_parent_is_symlink": False,
            "allowed_parent_creation_allowed": False,
            "allowed_parent_ancestor_safety_verified": True,
            "existed": False,
            "reuse_allowed": False,
            "ancestor_safety_verified": True,
            "symlink_component_count": 0,
        }
        capture_entries = [
            {
                "relative_path": "tracked.txt",
                "target_path": str(self.deployment.resolve() / "tracked.txt"),
                "exists": True,
                "sha256": sha256(preimage),
                "size": preimage_stat.st_size,
                "mode": oct(stat.S_IMODE(preimage_stat.st_mode)),
            },
            {
                "relative_path": "created.txt",
                "target_path": str(self.deployment.resolve() / "created.txt"),
                "exists": False,
                "sha256": None,
                "size": None,
                "mode": None,
            },
        ]
        capture_anchor = self._capture_anchor(
            "SITINA_STEP7_PREIMAGE_CAPTURE_ANCHOR_V1",
            {
                "approval_id": approval_id,
                "source_head": source_head,
                "source_tree": source_tree,
                "deployment_root": deployment_root,
                "entries": capture_entries,
                "backup_root_preflight": backup_root_preflight,
            },
        )
        operations = [
            {
                "relative_path": "tracked.txt",
                "operation": "REPLACE",
                "source_path": str(target),
                "target_path": str(self.deployment.resolve() / "tracked.txt"),
                "target_sha256": sha256(target),
                "target_size": target_stat.st_size,
                "target_mode": oct(stat.S_IMODE(target_stat.st_mode)),
                "preimage_exists": True,
                "preimage_sha256": sha256(preimage),
                "preimage_size": preimage_stat.st_size,
                "preimage_mode": oct(stat.S_IMODE(preimage_stat.st_mode)),
            },
            {
                "relative_path": "created.txt",
                "operation": "CREATE",
                "source_path": str(created),
                "target_path": str(
                    self.deployment.resolve() / "created.txt"
                ),
                "target_sha256": sha256(created),
                "target_size": created_stat.st_size,
                "target_mode": oct(stat.S_IMODE(created_stat.st_mode)),
                "preimage_exists": False,
                "preimage_sha256": None,
                "preimage_size": None,
                "preimage_mode": None,
            },
        ]
        plan = self._rollback_plan_document(
            operations,
            source_head=source_head,
            source_tree=source_tree,
            deployment_root=deployment_root,
        )
        forbidden = {
            field: False for field in BACKUP_ROLLBACK_FORBIDDEN_FIELDS
        }
        return {
            "schema": DEPLOYMENT_PACKET_SCHEMA,
            "approval_id": approval_id,
            "created_at_utc": "2026-07-27T00:00:00Z",
            "source_binding": {
                "head": source_head,
                "tree": source_tree,
            },
            "deployment_binding": {"root": deployment_root},
            "preimage_capture": {
                "schema": "SITINA_STEP7_DEPLOYMENT_PREIMAGE_CAPTURE_V2",
                "captured_at_utc": "2026-07-27T00:00:00Z",
                "deployment_root": deployment_root,
                "deployment_mutated": False,
                "entries": capture_entries,
                "backup_root_preflight": backup_root_preflight,
                "capture_anchor": capture_anchor,
            },
            "exact_file_operations": operations,
            "backup_and_rollback_plan": plan,
            "backup_and_rollback_plan_sha256": _json_value_sha256(plan),
            "authorization_contract": {
                "schema": DEPLOYMENT_AUTHORIZATION_CONTRACT_SCHEMA,
                "marker": DEPLOYMENT_AUTHORIZATION_MARKER,
                "delegation_marker": DEPLOYMENT_DELEGATION_MARKER,
                "source_thread_id": (
                    "019f810d-78fe-75d2-8efd-d43fccbd82d7"
                ),
                "required_payload_fields": list(
                    DEPLOYMENT_AUTHORIZATION_PAYLOAD_FIELDS
                ),
                "requires_user_record": True,
                "delegated_wrapper_required": True,
                "delegated_wrapper_source_thread_required": True,
                "delegated_source_session": STEP7_DELEGATED_SOURCE_SESSION,
                "delegation_source_binding_fields": list(
                    DEPLOYMENT_DELEGATION_SOURCE_BINDING_FIELDS
                ),
                "two_hop_structure": DEPLOYMENT_AUTHORIZATION_TWO_HOP_STRUCTURE,
                "source_ui_transport_normalization": (
                    SOURCE_UI_TRANSPORT_NORMALIZATION_CONTRACT
                ),
                "self_authorizes_execution": False,
            },
            "forbidden_boundaries": forbidden,
            "requires_exact_user_authorization": True,
            "self_authorizes_execution": False,
            "deployment_executed_at_creation": False,
        }

    def _rollback_request_evidence_document(self) -> dict[str, object]:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        summary = {
            "formal_step56_accept_count": 3,
            "gate_count": 7,
            "real_sitina_review_count": 2,
            "changed_source_count": 2,
            "deployment_operation_count": 2,
            "replace_count": 1,
            "create_count": 1,
            "deployment_pending": True,
            "step8_step9_not_entered": True,
        }
        return {
            "schema": DEPLOYMENT_REQUEST_EVIDENCE_SCHEMA,
            "created_at_utc": "2026-07-27T00:00:00Z",
            "source": {
                "root": str(self.source.resolve()),
                "head": packet["source_binding"]["head"],
                "tree": packet["source_binding"]["tree"],
            },
            "approval_id": self.rollback_approval_id,
            "approval_packet": self._reference(self.rollback_packet),
            "authorization_contract": copy.deepcopy(
                packet["authorization_contract"]
            ),
            "exact_file_operations_sha256": _json_value_sha256(
                packet["exact_file_operations"]
            ),
            "rollback_plan_sha256": packet[
                "backup_and_rollback_plan_sha256"
            ],
            "review_summary": summary,
            "evidence": {
                "authority": {
                    "path": (
                        "/Users/moss/.codex/attachments/"
                        "198f270e-7042-4d01-aac5-ff595095d657/"
                        "pasted-text-1.txt"
                    ),
                    "sha256": "685f93ec678a2590cf621336b559cf5e3cedc73701f1aefed3f01db5f28fea3c",
                },
                "entry_candidate": {
                    "path": str(ENTRY_CANDIDATE),
                    "sha256": ENTRY_CANDIDATE_SHA256,
                },
                "step56_accepts": [
                    self._reference(path) for path in self.step56_accepts
                ],
                "gates": [
                    self._reference(self.gate_evidence[stage])
                    for stage in REQUIRED_GATES
                ],
                "real_sitina_reviews": [
                    self._reference(self.cleanup_receipt),
                    self._reference(self.review_receipt),
                ],
                "static_integrity": self._reference(self.general_evidence),
                "excluded_attempts": self._reference(
                    self.rollback_exclusions_stub
                ),
                "revocation": self._reference(
                    self.rollback_revocation_stub
                ),
                "changed_source": [
                    self._reference(self.source / "tracked.txt"),
                    self._reference(self.source / "created.txt"),
                ],
            },
        }

    def _static_integrity_document(self) -> dict[str, object]:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        changed_files = ["tracked.txt", "created.txt"]
        gate_references = [
            {
                "path": str(self.gate_evidence[stage].resolve()),
                "sha256": sha256(self.gate_evidence[stage]),
            }
            for stage in REQUIRED_GATES
        ]
        return {
            "schema": "SITINA_STEP7_SOURCE_BOUNDARY_STATIC_INTEGRITY_V2",
            "source": {
                "root": str(self.source.resolve()),
                "head": self._git("rev-parse", "HEAD^{commit}"),
                "tree": self._git("rev-parse", "HEAD^{tree}"),
                "worktree_clean": True,
                "changed_files_from_step7_base": changed_files,
            },
            "deployment": {
                "root": str(self.deployment.resolve()),
                "operation_count": 2,
                "replace_count": 1,
                "create_count": 1,
                "deployment_performed": False,
                "mismatch_paths": changed_files,
                "exact_operations": packet["exact_file_operations"],
            },
            "execution_switches": {"all_false": True},
            "forbidden_actions": {
                "baseline_install_or_promotion": False,
                "deployment": False,
                "production_canary": False,
                "production_data_mutation": False,
                "step8_entered": False,
                "step9_entered": False,
            },
            "formal_step56_accepts": [
                self._reference(path) for path in self.step56_accepts
            ],
            "gates": gate_references,
            "revocation": self._reference(self.rollback_revocation_stub),
            "formal_executor": {
                "schema": "SITINA_STEP7_FORMAL_EXECUTOR_BINDING_V1",
                "executor": self._reference(self.formal_executor),
                "launch_command": [
                    APPROVED_PYTHON_PATH,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={step7_gate.STEP7_PYCACHE_PREFIX}",
                    str(self.formal_executor.resolve()),
                ],
                "binding": copy.deepcopy(
                    self.formal_executor_binding
                ),
                "self_contained": True,
                "fully_bound_before_authorization": True,
                "dynamic_template": None,
                "source_dependencies": [
                    self._reference(self.source / "tracked.txt"),
                    self._reference(self.source / "created.txt"),
                ],
                "forbidden_runtime_parameters": [
                    "FAILURE_INJECTION",
                    "CALLER_GATE_CALLBACK",
                    "TEST_CAPABILITY",
                    "VARIABLE_SOURCE_ROOT",
                    "VARIABLE_DEPLOYMENT_ROOT",
                    "VARIABLE_BACKUP_ROOT",
                ],
            },
        }

    def _rollback_review_candidate_document(self) -> dict[str, object]:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        summary = json.loads(
            self.rollback_request_evidence.read_text(encoding="utf-8")
        )["review_summary"]
        return {
            "schema": DEPLOYMENT_REQUEST_CANDIDATE_SCHEMA,
            "candidate_id": (
                f"{self.rollback_approval_id}_REVIEW_CANDIDATE"
            ),
            "created_at_utc": "2026-07-27T00:00:00Z",
            "status": "AWAITING_EXACT_USER_AUTHORIZATION",
            "approval_id": self.rollback_approval_id,
            "source_binding": {
                "root": str(self.source.resolve()),
                "head": packet["source_binding"]["head"],
                "tree": packet["source_binding"]["tree"],
            },
            "deployment_binding": {
                "root": packet["deployment_binding"]["root"]
            },
            "approval_packet": self._reference(self.rollback_packet),
            "authorization_contract": copy.deepcopy(
                packet["authorization_contract"]
            ),
            "exact_file_operation_count": len(
                packet["exact_file_operations"]
            ),
            "exact_file_operations_sha256": _json_value_sha256(
                packet["exact_file_operations"]
            ),
            "rollback_plan_sha256": packet[
                "backup_and_rollback_plan_sha256"
            ],
            "review_summary": summary,
            "evidence_bundle": self._reference(
                self.rollback_request_evidence
            ),
            "authorized": False,
            "deployment_executed": False,
            "forbidden_boundaries": copy.deepcopy(
                packet["forbidden_boundaries"]
            ),
        }

    def _rollback_recovery_document(self) -> dict[str, object]:
        manifest = json.loads(self.rollback_manifest.read_text(encoding="utf-8"))
        entry = manifest["entries"][0]
        created_entry = manifest["entries"][1]
        quarantine_stat = self.rehearsal_quarantine_created.stat()
        rehearsal_source = (
            self.rollback_root / "rehearsal" / "created" / "created.txt"
        )
        return {
            "schema": ROLLBACK_RESULT_SCHEMA,
            "manifest": self._reference(self.rollback_manifest),
            "approval_packet": self._reference(self.rollback_packet),
            "review_candidate": self._reference(
                self.rollback_review_candidate
            ),
            "rollback_plan_sha256": manifest["rollback_plan_sha256"],
            "authorization_raw_record_sha256": self.rollback_authorization[
                "raw_record_sha256"
            ],
            "source_head": manifest["source_head"],
            "source_tree": manifest["source_tree"],
            "deployment_root": str(self.deployment.resolve()),
            "method": "DISPOSABLE_ISOLATED_RESTORE_REHEARSAL_V4",
            "deployment_mutated": False,
            "verified": True,
            "mismatch_count": 0,
            "delete_operation_count": 0,
            "backups_retained": True,
            "quarantines_retained": True,
            "manual_recovery_required": False,
            "entries": [
                {
                    "relative_path": "tracked.txt",
                    "operation": "REPLACE",
                    "restored": {
                        "exists": True,
                        "sha256": entry["preimage_sha256"],
                        "size": entry["preimage_size"],
                        "mode": entry["preimage_mode"],
                    },
                    "reapplied": {
                        "exists": True,
                        "sha256": entry["target_sha256"],
                        "size": entry["target_size"],
                        "mode": entry["target_mode"],
                    },
                    "restored_artifact": self._reference(
                        self.rollback_restored_snapshot
                    ),
                    "reapplied_artifact": self._reference(
                        self.rollback_reapplied_snapshot
                    ),
                    "rehearsal_quarantined_artifact": None,
                    "rehearsal_quarantine_move": None,
                    "live_rollback_quarantine_preflight": None,
                },
                {
                    "relative_path": "created.txt",
                    "operation": "CREATE",
                    "restored": {
                        "exists": False,
                        "sha256": None,
                        "size": None,
                        "mode": None,
                    },
                    "reapplied": {
                        "exists": True,
                        "sha256": created_entry["target_sha256"],
                        "size": created_entry["target_size"],
                        "mode": created_entry["target_mode"],
                    },
                    "restored_artifact": None,
                    "reapplied_artifact": self._reference(
                        self.rollback_created_reapplied_snapshot
                    ),
                    "rehearsal_quarantined_artifact": self._reference(
                        self.rehearsal_quarantine_created
                    ),
                    "rehearsal_quarantine_move": self.rehearsal_quarantine_move,
                    "live_rollback_quarantine_preflight": {
                        "path": str(self.rollback_quarantine_created),
                        "existed": False,
                        "overwrite_allowed": False,
                        "exclusive_no_replace_required": True,
                        "nofollow_required": True,
                        "method": (
                            "ATOMIC_RENAME_NOREPLACE_NOFOLLOW_SAME_FILESYSTEM"
                        ),
                    },
                },
            ],
        }

    def _step56_accept_artifacts(self) -> list[Path]:
        source_session = Path(STEP56_SOURCE_SESSION_PATH)
        self.assertTrue(source_session.is_file())
        prefix_errors: list[str] = []
        raw_lines = _verify_step56_source_session(source_session, prefix_errors)
        self.assertEqual(prefix_errors, [])
        paths: list[Path] = []
        for record_id, expected in STEP56_ACCEPT_RECORDS.items():
            raw_record = raw_lines[expected["line_number"] - 1]
            source_record = json.loads(raw_record)
            content = source_record["payload"]["content"][0]["text"]
            prefix = (
                "Message Type: FINAL_ANSWER\n"
                "Task name: /root\n"
                f"Sender: {expected['author']}\n"
                "Payload:\n"
            )
            self.assertTrue(content.startswith(prefix))
            message_payload = content[len(prefix) :]
            artifact = {
                "schema": STEP56_ACCEPT_SCHEMA,
                "artifact_id": expected["artifact_id"],
                "source_session": {
                    "path": STEP56_SOURCE_SESSION_PATH,
                    "session_id": STEP56_SOURCE_SESSION_ID,
                    "session_meta_raw_sha256": (
                        STEP56_SOURCE_SESSION_META_RAW_SHA256
                    ),
                    "accepted_prefix": {
                        "line_count": STEP56_SOURCE_SESSION_PREFIX_LINE_COUNT,
                        "byte_length": STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH,
                        "sha256": STEP56_SOURCE_SESSION_PREFIX_SHA256,
                    },
                },
                "source_record": {
                    "line_number": expected["line_number"],
                    "raw_record_sha256": expected["raw_record_sha256"],
                    "type": "response_item",
                    "payload_type": "agent_message",
                    "id": record_id,
                    "timestamp": source_record["timestamp"],
                    "author": expected["author"],
                    "recipient": "/root",
                    "content_utf8_bytes": len(content.encode("utf-8")),
                    "content_sha256": expected["content_sha256"],
                    "payload_utf8_bytes": len(message_payload.encode("utf-8")),
                    "payload_sha256": expected["payload_sha256"],
                },
                "decision": {
                    "marker": "ACCEPT_STEP7_ENTRY",
                    "accepted_scope": "STEP7_DESIGN_AND_LOCAL_IMPLEMENTATION_ONLY",
                    "step8_authorized": False,
                    "step9_authorized": False,
                    "production_canary_authorized": False,
                    "execution_switch_change_authorized": False,
                    "baseline_change_authorized": False,
                    "production_mutation_authorized": False,
                },
                "candidate_binding": {
                    "path": str(ENTRY_CANDIDATE),
                    "physical_sha256": ENTRY_CANDIDATE_SHA256,
                    "schema": "SITINA_STEP7_ENTRY_REVIEW_CANDIDATE_V1",
                    "candidate_id": "SITINA_STEP56_45A36BE_STEP7_ENTRY_REVIEW_CANDIDATE",
                    "head": "45a36be780413f561cf1f8f0d4b8ec80dd3f9416",
                    "tree": "d815f49be0ab9129e41acbd664a5b476da8e8c57",
                },
            }
            paths.append(
                self._json_file(
                    f"step56-accept-{expected['artifact_id'].lower()}.json",
                    artifact,
                )
            )
        return paths

    def _review_required_file(
        self,
        path: Path,
        media_type: str,
        purpose: str,
    ) -> dict[str, object]:
        return {
            "path": str(path.resolve()),
            "sha256": sha256(path),
            "media_type": media_type,
            "purpose": purpose,
        }

    def _projected_review_required_file(
        self,
        source: Path,
        *,
        source_media_type: str,
        purpose: str,
        safe_root: Path,
        review_stage: str,
    ) -> dict[str, object]:
        projection_root = safe_root / "projections"
        projection_root.mkdir(mode=0o700, exist_ok=True)
        source_head = self._git("rev-parse", "HEAD^{commit}")
        source_tree = self._git("rev-parse", "HEAD^{tree}")
        projection_text = (
            step7_gate._step7_provider_visible_projection_text(
                source.resolve(),
                source_media_type=source_media_type,
                purpose=purpose,
                source_root=self.source.resolve(),
                review_stage=review_stage,
                source_head=source_head,
                source_tree=source_tree,
            )
        )
        projection = projection_root / (
            f"{len(tuple(projection_root.iterdir())):02d}-projection.txt"
        )
        projection.write_text(projection_text, encoding="utf-8")
        return {
            "path": str(projection.resolve()),
            "sha256": sha256(projection),
            "size": projection.stat().st_size,
            "media_type": "text",
            "purpose": purpose,
            "source_path": str(source.resolve()),
            "source_sha256": sha256(source),
            "source_size": source.stat().st_size,
            "source_media_type": source_media_type,
            "projection_schema": (
                step7_gate.PROVIDER_VISIBLE_PROJECTION_SCHEMA
            ),
        }

    def _review_input_document(
        self,
        review_stage: str,
        required_files: list[dict[str, object]],
        *,
        schema: str = "SITINA_STEP7_REAL_REVIEW_INPUT_V1",
    ) -> dict[str, object]:
        return {
            "schema": schema,
            "review_stage": review_stage,
            "source": {
                "head": self._git("rev-parse", "HEAD^{commit}"),
                "tree": self._git("rev-parse", "HEAD^{tree}"),
            },
            "required_files": required_files,
            "rules": {
                "read_only_tools_only": True,
                "all_required_files_must_be_read": True,
                "terminal_verdict": "PASS",
                "step8_step9_forbidden": True,
            },
        }

    def _provider_visible_review_files(
        self,
        required_files: list[dict[str, object]],
        *,
        review_stage: str,
        input_path: Path,
    ) -> tuple[list[dict[str, object]], str]:
        redact = step7_gate._step7_projection_redaction_function(
            self.source.resolve()
        )
        provider_files: list[dict[str, object]] = []
        projected = False
        for reference in required_files:
            path = Path(str(reference["path"]))
            text = path.read_text(encoding="utf-8")
            if step7_gate._step7_projection_boundary_identity(
                text,
                redact=redact,
            ):
                provider_files.append(reference)
                continue
            projected = True
            provider_files.append(
                self._projected_review_required_file(
                    path,
                    source_media_type=str(reference["media_type"]),
                    purpose=str(reference["purpose"]),
                    safe_root=input_path.parent,
                    review_stage=review_stage,
                )
            )
        return (
            provider_files,
            (
                "SITINA_STEP7_REAL_REVIEW_INPUT_V2"
                if projected
                else "SITINA_STEP7_REAL_REVIEW_INPUT_V1"
            ),
        )

    def _finalize_review_inputs_and_audits(self) -> None:
        cleanup_files = [
            self._review_required_file(
                self.cleanup_candidate, "json", "cleanup candidate"
            ),
            self._review_required_file(
                self.cleanup_ledger, "json", "cleanup ledger"
            ),
        ]
        cleanup_files, cleanup_schema = self._provider_visible_review_files(
            cleanup_files,
            review_stage="CLEANUP_CLOSURE",
            input_path=self.cleanup_review_input,
        )
        self.cleanup_review_input.write_text(
            json.dumps(
                self._review_input_document(
                    "CLEANUP_CLOSURE",
                    cleanup_files,
                    schema=cleanup_schema,
                ),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.cleanup_audit.write_text(
            self._audit_jsonl(
                "CLEANUP_CLOSURE",
                self.cleanup_review_input,
                "agent-run-step7-cleanup-fixture",
            ),
            encoding="utf-8",
        )
        self.cleanup_receipt = self._audit_receipt_file(
            "cleanup-review-receipt.json",
            "CLEANUP_CLOSURE",
            self.cleanup_review_input,
            self.cleanup_audit,
            "agent-run-step7-cleanup-fixture",
        )
        full_files = [
            self._review_required_file(
                ENTRY_CANDIDATE, "json", "Step5/6 entry candidate"
            ),
            *[
                self._review_required_file(path, "json", "formal Step5/6 ACCEPT")
                for path in self.step56_accepts
            ],
            *[
                self._review_required_file(path, "json", "strict gate evidence")
                for path in self.gate_evidence.values()
            ],
            self._review_required_file(
                self.cleanup_candidate, "json", "cleanup candidate"
            ),
            self._review_required_file(
                self.cleanup_ledger, "json", "cleanup ledger"
            ),
            self._review_required_file(
                self.cleanup_review_input, "json", "cleanup review input"
            ),
            self._review_required_file(
                self.cleanup_audit, "jsonl", "cleanup review audit"
            ),
            self._review_required_file(
                self.cleanup_receipt, "json", "cleanup review capture receipt"
            ),
            self._review_required_file(
                Path(BASE_SENTINEL_PATH), "json", "base production sentinel"
            ),
            self._review_required_file(
                Path(MUTABLE_SENTINEL_PATH), "json", "mutable production sentinel"
            ),
            self._review_required_file(
                Path(EXECUTION_MANIFEST_PATH), "json", "execution manifest"
            ),
            *[
                self._review_required_file(path, "json", "Step7 sentinel sample")
                for path in self.sentinel_samples
            ],
            self._review_required_file(
                self.rollback_packet, "json", "deployment approval packet"
            ),
            self._review_required_file(
                self.rollback_exclusions_stub,
                "json",
                "deployment request exclusions",
            ),
            self._review_required_file(
                self.rollback_revocation_stub,
                "json",
                "deployment request revocation",
            ),
            self._review_required_file(
                self.general_evidence,
                "json",
                "deployment request static integrity",
            ),
            self._review_required_file(
                self.formal_executor,
                "text",
                "hash-bound self-contained formal executor",
            ),
            self._review_required_file(
                self.source / "tracked.txt", "text", "Step7 changed source"
            ),
            self._review_required_file(
                self.source / "created.txt", "text", "Step7 created source"
            ),
            self._review_required_file(
                Path(
                    "/Users/moss/.codex/attachments/"
                    "198f270e-7042-4d01-aac5-ff595095d657/pasted-text-1.txt"
                ),
                "text",
                "current Step7 authority",
            ),
        ]
        full_files, full_schema = self._provider_visible_review_files(
            full_files,
            review_stage="STEP7_FULL_REVIEW",
            input_path=self.review_input,
        )
        self.review_input.write_text(
            json.dumps(
                self._review_input_document(
                    "STEP7_FULL_REVIEW",
                    full_files,
                    schema=full_schema,
                ),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.audit.write_text(
            self._audit_jsonl(
                "STEP7_FULL_REVIEW",
                self.review_input,
                "agent-run-step7-full-fixture",
            ),
            encoding="utf-8",
        )
        self.review_receipt = self._audit_receipt_file(
            "review-receipt.json",
            "STEP7_FULL_REVIEW",
            self.review_input,
            self.audit,
            "agent-run-step7-full-fixture",
        )

    def _review(
        self,
        review_stage: str,
        input_path: Path,
        audit_path: Path,
        receipt_path: Path,
        run_id: str,
    ) -> dict[str, object]:
        response = self._review_response(review_stage, input_path)
        review_input = json.loads(input_path.read_text(encoding="utf-8"))
        tool_call_count = 1 + len(review_input["required_files"])
        return {
            "run_id": run_id,
            "provider_mode": "live",
            "profile": "deepseek",
            "model": "deepseek-v4-pro",
            "review_stage": review_stage,
            "terminal_state": "run_succeeded",
            "started_at_utc": "2026-07-27T00:00:00Z",
            "ended_at_utc": "2026-07-27T00:00:07Z",
            "provider_calls": 2,
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "verdict": "PASS",
            "input_sha256": sha256(input_path),
            "output_sha256": hashlib.sha256(response.encode("utf-8")).hexdigest(),
            "tool_call_count": tool_call_count,
            "tool_call_types": ["sitina_read_file"],
            "tool_permissions": ["read"],
            "file_changes": 0,
            "external_changes": 0,
            "denied_tool_calls": 0,
            "unique_files_changed": 0,
            "input": self._reference(input_path),
            "audit": {**self._reference(audit_path), "format": "jsonl"},
            "receipt": self._reference(receipt_path),
        }

    def _audit_receipt_file(
        self,
        name: str,
        review_stage: str,
        input_path: Path,
        audit_path: Path,
        run_id: str,
    ) -> Path:
        records = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        previous = bytes(32)
        for record in records:
            encoded = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            previous = hashlib.sha256(previous + encoded).digest()
        provider_request_ids: list[str] = []
        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        }
        for record in records:
            if record.get("event") != "model_turn_completed":
                continue
            metadata = record["metadata"]
            provider_request_ids.append(metadata["provider_request_id"])
            for field in usage:
                usage[field] += metadata["token_usage"][field]
        event_chain = previous.hex()
        anchor_payload = {
            "review_stage": review_stage,
            "run_id": run_id,
            "input_sha256": sha256(input_path),
            "audit_sha256": sha256(audit_path),
            "event_chain_sha256": event_chain,
            "provider_request_ids": provider_request_ids,
            "usage": usage,
        }
        capture_anchor = self._capture_anchor(
            "SITINA_STEP7_AUDIT_CAPTURE_ANCHOR_V1",
            anchor_payload,
            independent_reviewer=True,
        )
        return self._json_file(
            name,
            {
                "schema": "SITINA_STEP7_REAL_REVIEW_CAPTURE_RECEIPT_V1",
                "review_stage": review_stage,
                "run_id": run_id,
                "created_at_utc": "2026-07-27T00:00:08Z",
                "input": self._reference(input_path),
                "audit": {**self._reference(audit_path), "format": "jsonl"},
                "event_count": len(records),
                "first_event": records[0]["event"],
                "last_event": records[-1]["event"],
                "event_chain_sha256": event_chain,
                "provider_request_ids": provider_request_ids,
                "usage": usage,
                "boundary": "PRE_DEPLOYMENT_READ_ONLY_REVIEW_CAPTURE_V1",
                "capture_anchor": capture_anchor,
            },
        )

    def _review_response(self, review_stage: str, input_path: Path) -> str:
        review_input = json.loads(input_path.read_text(encoding="utf-8"))
        files_read = [
            str(input_path.resolve()),
            *(str(reference["path"]) for reference in review_input["required_files"]),
        ]
        result = {
                "schema": (
                    "SITINA_STEP7_REAL_REVIEW_RESULT_V2"
                    if review_input["schema"]
                    == "SITINA_STEP7_REAL_REVIEW_INPUT_V2"
                    else "SITINA_STEP7_REAL_REVIEW_RESULT_V1"
                ),
                "review_stage": review_stage,
                "source_head": self._git("rev-parse", "HEAD^{commit}"),
                "source_tree": self._git("rev-parse", "HEAD^{tree}"),
                "verdict": "PASS",
                "blockers": [],
                "step8_step9_not_entered": True,
                "files_read": files_read,
            }
        if review_input["schema"] == "SITINA_STEP7_REAL_REVIEW_INPUT_V2":
            result["source_file_closure"] = [
                {
                    "path": reference.get("source_path", reference["path"]),
                    "sha256": reference.get(
                        "source_sha256", reference["sha256"]
                    ),
                }
                for reference in review_input["required_files"]
            ]
        return json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _audit_jsonl(
        self,
        review_stage: str,
        input_path: Path,
        run_id: str,
    ) -> str:
        schema = "SITINA_AUTONOMOUS_RUN_EVENT_V1"
        review_input = json.loads(input_path.read_text(encoding="utf-8"))
        read_paths = [
            str(input_path.resolve()),
            *(str(reference["path"]) for reference in review_input["required_files"]),
        ]
        calls = [
            {
                "id": f"call-{review_stage.lower()}-read-{index}",
                "name": "sitina_read_file",
                "arguments": {"path": path},
            }
            for index, path in enumerate(read_paths, start=1)
        ]
        response = self._review_response(review_stage, input_path)
        system_prompt = "Read-only Step7 reviewer."
        first_messages = [
            {"role": "user", "content": f"Read {input_path.resolve()}"}
        ]

        def tool_message(call: dict[str, object]) -> dict[str, object]:
            result = Path(str(call["arguments"]["path"])).read_text(
                encoding="utf-8", errors="replace"
            )
            return {
                "role": "tool",
                "name": "sitina_read_file",
                "tool_call_id": call["id"],
                "is_error": False,
                "content": json.dumps(
                    {
                        "can_grant_permissions": False,
                        "can_override_instructions": False,
                        "redacted_paths": [],
                        "result": result,
                        "schema": "SITINA_UNTRUSTED_TOOL_DATA_V1",
                        "source": "tool",
                        "status": "ok",
                        "tool": "sitina_read_file",
                        "trust": "untrusted-data",
                    },
                    sort_keys=True,
                ),
            }

        def argument_summary(call: dict[str, object]) -> dict[str, object]:
            encoded = json.dumps(
                call["arguments"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return {
                "schema": "SITINA_TOOL_ARGUMENT_SUMMARY_V1",
                "normalized_tool_name": "sitina.sitina_read_file",
                "argument_bytes_after_redaction": len(encoded),
                "argument_hash": hashlib.sha256(encoded).hexdigest(),
                "argument_keys": ["path"],
                "redacted_paths": [],
            }

        def result_summary(call: dict[str, object]) -> dict[str, object]:
            result = Path(str(call["arguments"]["path"])).read_text(
                encoding="utf-8", errors="replace"
            )
            encoded = json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return {
                "schema": "SITINA_TOOL_RESULT_SUMMARY_V1",
                "normalized_tool_name": "sitina.sitina_read_file",
                "permission_decision": "allowed",
                "status": "ok",
                "error": None,
                "result_ref": f"sha256:{hashlib.sha256(encoded).hexdigest()}",
                "duration_ms": 1,
                "result_bytes_after_redaction": len(encoded),
                "result_redacted_paths": [],
            }

        second_messages = [
            *first_messages,
            {"role": "assistant", "content": "", "tool_calls": calls},
            *(tool_message(call) for call in calls),
        ]

        def provider_input_hash(messages: list[dict[str, str]]) -> str:
            wire_messages = _openai_wire_messages(system_prompt, messages)
            self.assertIsNotNone(wire_messages)
            body = {"system": None, "messages": wire_messages}
            return "sha256:" + hashlib.sha256(
                json.dumps(
                    body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()

        records = [
            {
                "schema": schema,
                "event": "run_started",
                "run_id": run_id,
                "timestamp": "2026-07-27T00:00:00Z",
                "task": f"Read {input_path.resolve()} and return the required JSON.",
                "selected_agents": [],
                "selected_skills": [],
                "tool_count": 8,
            },
            {
                "schema": schema,
                "event": "provider_call_intended",
                "run_id": run_id,
                "timestamp": "2026-07-27T00:00:01Z",
                "turn": 1,
                "max_tokens": 1000,
                "messages": first_messages,
                "system_prompt": system_prompt,
                "tools": [{"name": "sitina_read_file"}],
            },
            {
                "schema": schema,
                "event": "model_turn_completed",
                "run_id": run_id,
                "timestamp": "2026-07-27T00:00:02Z",
                "turn": 1,
                "metadata": {
                    "provider_mode": "live",
                    "profile_name": "deepseek",
                    "model": "deepseek-v4-pro",
                    "fallback_used": False,
                    "protocol_fallback_used": False,
                    "provider_request_id": f"provider-{review_stage.lower()}-1",
                    "input_hash": provider_input_hash(first_messages),
                    "output_hash": (
                        "sha256:"
                        + hashlib.sha256(b"").hexdigest()
                    ),
                    "tool_call_count": len(calls),
                    "token_usage": {
                        "input_tokens": 50,
                        "output_tokens": 10,
                        "total_tokens": 60,
                        "cache_read_tokens": 0,
                        "cache_write_tokens": 0,
                    },
                    "connect_timeout_seconds": "10.0",
                    "duration_ms": 1,
                    "protocol": "openai_chat_completions",
                    "provider_call_completed_at": "2026-07-27T00:00:02Z",
                    "provider_call_started_at": "2026-07-27T00:00:01Z",
                    "read_timeout_seconds": "120.0",
                    "redaction_status": "redacted",
                    "request_timeout_seconds": "120.0",
                },
                "stop_reason": "tool_calls",
                "text": "",
                "tool_calls": calls,
            },
            *[
                {
                    "schema": schema,
                    "event": "tool_call_intended",
                    "run_id": run_id,
                    "timestamp": "2026-07-27T00:00:03Z",
                    "call_id": call["id"],
                    "name": "sitina_read_file",
                    "permission": "read",
                    "argument_summary": argument_summary(call),
                }
                for call in calls
            ],
            *[
                {
                    "schema": schema,
                    "event": "tool_completed",
                    "run_id": run_id,
                    "timestamp": "2026-07-27T00:00:04Z",
                    "call_id": call["id"],
                    "permission": "read",
                    "argument_summary": argument_summary(call),
                    "result_summary": result_summary(call),
                }
                for call in calls
            ],
            {
                "schema": schema,
                "event": "provider_call_intended",
                "run_id": run_id,
                "timestamp": "2026-07-27T00:00:05Z",
                "turn": 2,
                "max_tokens": 1000,
                "messages": second_messages,
                "system_prompt": system_prompt,
                "tools": [{"name": "sitina_read_file"}],
            },
            {
                "schema": schema,
                "event": "model_turn_completed",
                "run_id": run_id,
                "timestamp": "2026-07-27T00:00:06Z",
                "turn": 2,
                "metadata": {
                    "provider_mode": "live",
                    "profile_name": "deepseek",
                    "model": "deepseek-v4-pro",
                    "fallback_used": False,
                    "protocol_fallback_used": False,
                    "provider_request_id": f"provider-{review_stage.lower()}-2",
                    "input_hash": provider_input_hash(second_messages),
                    "output_hash": (
                        "sha256:"
                        + hashlib.sha256(response.encode("utf-8")).hexdigest()
                    ),
                    "tool_call_count": 0,
                    "token_usage": {
                        "input_tokens": 50,
                        "output_tokens": 10,
                        "total_tokens": 60,
                        "cache_read_tokens": 0,
                        "cache_write_tokens": 0,
                    },
                    "connect_timeout_seconds": "10.0",
                    "duration_ms": 1,
                    "protocol": "openai_chat_completions",
                    "provider_call_completed_at": "2026-07-27T00:00:06Z",
                    "provider_call_started_at": "2026-07-27T00:00:05Z",
                    "read_timeout_seconds": "120.0",
                    "redaction_status": "redacted",
                    "request_timeout_seconds": "120.0",
                },
                "stop_reason": "stop",
                "text": response,
                "tool_calls": [],
            },
            {
                "schema": schema,
                "event": "run_succeeded",
                "run_id": run_id,
                "timestamp": "2026-07-27T00:00:07Z",
                "response": response,
            },
        ]
        return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)

    def _valid_candidate(self) -> dict[str, object]:
        counts = self._fixture_counts()
        _, _, registered_selectors = self._registry_and_selectors()
        projection_evidence = [
            {
                "path": reference["path"],
                "sha256": reference["sha256"],
                "format": "text",
            }
            for input_path in (self.cleanup_review_input, self.review_input)
            for reference in json.loads(
                input_path.read_text(encoding="utf-8")
            )["required_files"]
            if set(reference)
            == step7_gate.PROVIDER_VISIBLE_PROJECTION_REFERENCE_FIELDS
        ]
        gates: list[dict[str, object]] = []
        for stage in REQUIRED_GATES:
            skipped = 5 if stage == "all_registered_unique" else 0
            gate: dict[str, object] = {
                "stage": stage,
                "collected": counts[stage],
                "executed": counts[stage],
                "passed": counts[stage] - skipped,
                "failed": 0,
                "errors": 0,
                "skipped": skipped,
                "xfail": 0,
                "xpass": 0,
                "warnings": 0,
                "external_attempts": 0,
                "production_attempts": 0,
                "collection_complete": True,
                "execution_complete": True,
                "execution_root": str(self.deployment.resolve()),
                "control_override_used": False,
                "live_override_used": False,
                "skip_ids": list(HISTORICAL_SKIP_IDS) if skipped else [],
                "evidence": self._reference(self.gate_evidence[stage]),
            }
            if stage == "all_registered_unique":
                gate.update(
                    {
                        "skip_allowlist_match": True,
                        "discovered_test_files": len(registered_selectors),
                        "registered_unique_selectors": len(registered_selectors),
                    }
                )
            gates.append(gate)
        bound_evidence = [
            {
                "path": (
                    "/Users/moss/.codex/attachments/"
                    "198f270e-7042-4d01-aac5-ff595095d657/"
                    "pasted-text-1.txt"
                ),
                "sha256": (
                    "685f93ec678a2590cf621336b559cf5e3cedc73701f1aefed3f01db5f28fea3c"
                ),
                "format": "text",
            },
            {"path": str(ENTRY_CANDIDATE), "sha256": ENTRY_CANDIDATE_SHA256},
            *(self._reference(path) for path in self.step56_accepts),
            *(self._reference(path) for path in self.gate_evidence.values()),
            self._reference(self.cleanup_candidate),
            self._reference(self.cleanup_ledger),
            self._reference(self.cleanup_review_input),
            {**self._reference(self.cleanup_audit), "format": "jsonl"},
            self._reference(self.cleanup_receipt),
            self._reference(self.review_input),
            {**self._reference(self.audit), "format": "jsonl"},
            self._reference(self.review_receipt),
            {"path": BASE_SENTINEL_PATH, "sha256": BASE_SENTINEL_PHYSICAL_SHA256},
            {
                "path": MUTABLE_SENTINEL_PATH,
                "sha256": MUTABLE_SENTINEL_PHYSICAL_SHA256,
            },
            {
                "path": EXECUTION_MANIFEST_PATH,
                "sha256": EXECUTION_MANIFEST_PHYSICAL_SHA256,
            },
            *(self._reference(path) for path in self.sentinel_samples),
            self._reference(self.rollback_packet),
            self._reference(self.rollback_request_evidence),
            self._reference(self.rollback_review_candidate),
            self._reference(self.rollback_manifest),
            self._reference(self.rollback_recovery),
            self._reference(self.rollback_exclusions_stub),
            self._reference(self.rollback_revocation_stub),
            {**self._reference(self.source / "tracked.txt"), "format": "text"},
            {**self._reference(self.source / "created.txt"), "format": "text"},
            self._reference(self.general_evidence),
            {**self._reference(self.formal_executor), "format": "text"},
            *projection_evidence,
        ]
        return {
            "schema": CANDIDATE_SCHEMA,
            "marker": READY_MARKER,
            "step5_step6_formally_accepted": True,
            "step56_entry_candidate": {
                "path": str(ENTRY_CANDIDATE),
                "sha256": ENTRY_CANDIDATE_SHA256,
            },
            "step56_independent_accepts": [
                self._reference(path) for path in self.step56_accepts
            ],
            "source": {
                "root": str(self.source.resolve()),
                "head": self._git("rev-parse", "HEAD^{commit}"),
                "tree": self._git("rev-parse", "HEAD^{tree}"),
                "worktree_clean": True,
                "changed_files": ["tracked.txt", "created.txt"],
            },
            "gates": gates,
            "cleanup": {
                "candidate": self._reference(self.cleanup_candidate),
                "ledger": self._reference(self.cleanup_ledger),
                "real_sitina_review": self._review(
                    "CLEANUP_CLOSURE",
                    self.cleanup_review_input,
                    self.cleanup_audit,
                    self.cleanup_receipt,
                    "agent-run-step7-cleanup-fixture",
                ),
            },
            "real_sitina_review": self._review(
                "STEP7_FULL_REVIEW",
                self.review_input,
                self.audit,
                self.review_receipt,
                "agent-run-step7-full-fixture",
            ),
            "source_deployment": {
                "source_root": str(self.source.resolve()),
                "deployment_root": str(self.deployment.resolve()),
                "tracked_file_count": len(self._git("ls-files").splitlines()),
                "exact_match_count": len(self._git("ls-files").splitlines()),
            },
            "execution_switches": {
                "tool_calls_allowed": False,
                "external_mutation_allowed": False,
                "execution_bridge_enabled": False,
                "execution_handoff_bypass_enabled": False,
            },
            "production_sentinel": {
                "goal_id": OFFICIAL_GOAL_ID,
                "base_baseline": {
                    "path": BASE_SENTINEL_PATH,
                    "sha256": BASE_SENTINEL_PHYSICAL_SHA256,
                },
                "mutable_baseline": {
                    "path": MUTABLE_SENTINEL_PATH,
                    "sha256": MUTABLE_SENTINEL_PHYSICAL_SHA256,
                },
                "execution_manifest": {
                    "path": EXECUTION_MANIFEST_PATH,
                    "sha256": EXECUTION_MANIFEST_PHYSICAL_SHA256,
                },
                "samples": [
                    self._reference(path) for path in self.sentinel_samples
                ],
                "production_attempts": 0,
            },
            "rollback_proof": {
                "approval_packet": self._reference(self.rollback_packet),
                "deployment_request_candidate": self._reference(
                    self.rollback_review_candidate
                ),
                "authorization_receipt": copy.deepcopy(
                    self.rollback_authorization
                ),
                "manifest": self._reference(self.rollback_manifest),
                "recovery_result": self._reference(self.rollback_recovery),
            },
            "deployment_request_supporting_evidence": {
                "static_integrity": self._reference(self.general_evidence),
                "excluded_attempts": self._reference(
                    self.rollback_exclusions_stub
                ),
                "revocation": self._reference(
                    self.rollback_revocation_stub
                ),
            },
            "evidence": bound_evidence,
            "remaining_risks": [],
            "pending_production_actions": [
                {
                    "action": "STEP8_CONTROLLED_CANARY",
                    "approval_required": True,
                    "status": "NOT_AUTHORIZED",
                }
            ],
            "forbidden_actions": {
                field: False for field in FORBIDDEN_ACTION_FIELDS
            },
            "authorization_to_enter_step8": False,
        }

    def _step7_v4_execution_spec(self) -> dict[str, object]:
        capability = _step7_v4_issue_test_capability()
        self.addCleanup(shutil.rmtree, capability.scope_root, True)
        self.addCleanup(_step7_v4_close_test_capability, capability)
        root = capability.scope_root
        source = capability.source_root
        deployment = capability.deployment_root
        output = capability.output_root
        (source / "replace.txt").write_text("new replace\n", encoding="utf-8")
        (source / "create.txt").write_text("new create\n", encoding="utf-8")
        (deployment / "replace.txt").write_text("old replace\n", encoding="utf-8")
        sentinel = deployment / "sentinel.txt"
        sentinel.write_text("stable sentinel\n", encoding="utf-8")
        sentinel_stat = sentinel.stat()
        backup_root = output / "step7-v4-run"
        operations: list[dict[str, object]] = []
        for relative, kind in (("replace.txt", "REPLACE"), ("create.txt", "CREATE")):
            source_path, target_path = source / relative, deployment / relative
            source_stat = source_path.stat()
            operations.append(
                {
                    "relative_path": relative,
                    "operation": kind,
                    "source_path": str(source_path),
                    "target_path": str(target_path),
                    "target_sha256": sha256(source_path),
                    "target_size": source_stat.st_size,
                    "target_mode": oct(stat.S_IMODE(source_stat.st_mode)),
                    "preimage_exists": kind == "REPLACE",
                    "preimage_sha256": sha256(target_path) if kind == "REPLACE" else None,
                    "preimage_size": target_path.stat().st_size if kind == "REPLACE" else None,
                    "preimage_mode": (
                        oct(stat.S_IMODE(target_path.stat().st_mode))
                        if kind == "REPLACE"
                        else None
                    ),
                    "preimage_backup_path": (
                        str(backup_root / "preimages" / f"{relative}.preimage")
                        if kind == "REPLACE"
                        else None
                    ),
                    "rehearsal_quarantine_path": (
                        str(backup_root / "rehearsal/quarantine/created" / relative)
                        if kind == "CREATE"
                        else None
                    ),
                    "rollback_quarantine_path": (
                        str(backup_root / "quarantine/created" / relative)
                        if kind == "CREATE"
                        else None
                    ),
                }
            )
        sentinels = [
            {
                "path": str(sentinel),
                "sha256": sha256(sentinel),
                "size": sentinel_stat.st_size,
                "mode": oct(stat.S_IMODE(sentinel_stat.st_mode)),
                "type": "REGULAR_FILE",
            }
        ]
        forbidden = {
            field: False for field in BACKUP_ROLLBACK_FORBIDDEN_FIELDS
        }
        gate_contract = {
            "schema": "SITINA_STEP7_TEST_ONLY_GATE_CONTRACT_V1",
            "runner_mode": "EXPLICIT_TEST_ONLY_CALLBACK",
        }
        specification: dict[str, object] = {
            "run_id": f"step7-v4-{root.name}",
            "packet_sha256": "a" * 64,
            "plan_sha256": "b" * 64,
            "candidate_sha256": "c" * 64,
            "authorization_receipt_sha256": "d" * 64,
            "authorization_source_sha256": "e" * 64,
            "authorization_wrapper_sha256": "f" * 64,
            "source_head": "1" * 40,
            "source_tree": "2" * 40,
            "source_root": str(source),
            "deployment_root": str(deployment),
            "session_root": str(capability.session_root),
            "allowed_backup_parent": str(output),
            "backup_root": str(backup_root),
            "sentinels": sentinels,
            "sentinels_sha256": _json_value_sha256(sentinels),
            "operations": operations,
            "operations_sha256": _json_value_sha256(
                [
                    {
                        field: operation.get(field)
                        for field in {
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
                    }
                    for operation in operations
                ]
            ),
            "forbidden_boundaries": forbidden,
            "forbidden_boundaries_sha256": _json_value_sha256(forbidden),
            "gate_contract": gate_contract,
            "gate_contract_sha256": _json_value_sha256(gate_contract),
        }
        self._step7_v4_capabilities[str(specification["run_id"])] = capability
        return specification

    def _step7_v4_capability(self, spec: dict[str, object]) -> object:
        return self._step7_v4_capabilities[str(spec["run_id"])]

    def _assert_step7_v4_checkpoint_closure(
        self,
        result: dict[str, object],
    ) -> None:
        references = result["checkpoint_references"]
        self.assertEqual(
            result["checkpoint_references_sha256"],
            _json_value_sha256(references),
        )
        canonical_set = sorted(
            references,
            key=lambda item: (
                item["kind"],
                item["index"],
                item["reference"]["path"],
                item["reference"]["sha256"],
            ),
        )
        self.assertEqual(
            result["checkpoint_reference_set_sha256"],
            _json_value_sha256(canonical_set),
        )
        for item in references:
            reference = item["reference"]
            self.assertEqual(
                reference["sha256"], sha256(Path(reference["path"]))
            )
        closure = result["checkpoint_closure"]
        self.assertEqual(
            [item["relative_path"] for item in closure],
            sorted(item["relative_path"] for item in closure),
        )
        self.assertEqual(
            result["checkpoint_closure_sha256"],
            _json_value_sha256(closure),
        )
        for item in closure:
            reference = item["reference"]
            self.assertEqual(
                reference["sha256"], sha256(Path(reference["path"]))
            )

    def _step7_v4_tree_snapshot(self, root: Path) -> dict[str, object]:
        snapshot: dict[str, object] = {}
        for path in sorted(
            [root, *root.rglob("*")],
            key=lambda item: str(item),
        ):
            metadata = path.lstat()
            relative = "." if path == root else path.relative_to(root).as_posix()
            if path.is_symlink():
                value: object = {
                    "type": "SYMLINK",
                    "target": str(path.readlink()),
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            elif path.is_file():
                value = {
                    "type": "REGULAR_FILE",
                    "sha256": sha256(path),
                    "size": metadata.st_size,
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            else:
                value = {
                    "type": "DIRECTORY",
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            snapshot[relative] = value
        return snapshot

    def _append_step7_v4_operation(
        self,
        spec: dict[str, object],
        relative: str,
        kind: str,
    ) -> None:
        source_root = Path(str(spec["source_root"]))
        deployment_root = Path(str(spec["deployment_root"]))
        backup_root = Path(str(spec["backup_root"]))
        source = source_root / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"new {relative}\n", encoding="utf-8")
        target = deployment_root / relative
        if kind == "REPLACE":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"old {relative}\n", encoding="utf-8")
        source_stat = source.stat()
        operation = {
            "relative_path": relative,
            "operation": kind,
            "source_path": str(source),
            "target_path": str(target),
            "target_sha256": sha256(source),
            "target_size": source_stat.st_size,
            "target_mode": oct(stat.S_IMODE(source_stat.st_mode)),
            "preimage_exists": kind == "REPLACE",
            "preimage_sha256": sha256(target) if kind == "REPLACE" else None,
            "preimage_size": target.stat().st_size if kind == "REPLACE" else None,
            "preimage_mode": (
                oct(stat.S_IMODE(target.stat().st_mode))
                if kind == "REPLACE"
                else None
            ),
            "preimage_backup_path": (
                str(backup_root / "preimages" / f"{relative}.preimage")
                if kind == "REPLACE"
                else None
            ),
            "rehearsal_quarantine_path": (
                str(backup_root / "rehearsal/quarantine/created" / relative)
                if kind == "CREATE"
                else None
            ),
            "rollback_quarantine_path": (
                str(backup_root / "quarantine/created" / relative)
                if kind == "CREATE"
                else None
            ),
        }
        spec["operations"].append(operation)
        core_fields = {
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
        spec["operations_sha256"] = _json_value_sha256(
            [
                {field: item.get(field) for field in core_fields}
                for item in spec["operations"]
            ]
        )

    def _step7_v4_exact_six_operation_spec(
        self,
    ) -> dict[str, object]:
        spec = self._step7_v4_execution_spec()
        source_root = Path(str(spec["source_root"]))
        deployment_root = Path(str(spec["deployment_root"]))
        for path in (
            source_root / "replace.txt",
            source_root / "create.txt",
            deployment_root / "replace.txt",
        ):
            path.unlink()
        spec["operations"] = []
        for relative, kind in (
            ("scripts/step7_readiness_gate.py", "CREATE"),
            ("scripts/test-bplus.py", "REPLACE"),
            (
                "tests/foundation/activation_gate_runner.py",
                "REPLACE",
            ),
            (
                "tests/foundation/registration_gate_runner.py",
                "REPLACE",
            ),
            (
                "tests/foundation/test_step7_readiness_gate.py",
                "CREATE",
            ),
            ("tests/test_suites.json", "REPLACE"),
        ):
            self._append_step7_v4_operation(spec, relative, kind)
        return spec

    def test_v4_executor_dry_run_then_real_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            backup_root = Path(str(spec["backup_root"]))
            deployment = Path(str(spec["deployment_root"]))
            dry_run = execute_step7_v4(
                spec,
                dry_run=True,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(dry_run["status"], "DRY_RUN_VERIFIED")
            self.assertFalse(backup_root.exists())
            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=lambda _: {"accepted": True, "gate": "temporary"},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(result["status"], "EXECUTED", result)
            self.assertEqual(
                (deployment / "replace.txt").read_text(encoding="utf-8"),
                "new replace\n",
            )
            created = deployment / "create.txt"
            self.assertEqual(created.read_text(encoding="utf-8"), "new create\n")
            self.assertNotEqual(
                created.stat().st_ino,
                (Path(str(spec["source_root"])) / "create.txt").stat().st_ino,
            )
            rehearsal = Path(str(spec["operations"][1]["rehearsal_quarantine_path"]))
            live = Path(str(spec["operations"][1]["rollback_quarantine_path"]))
            self.assertTrue(rehearsal.is_file())
            self.assertFalse(live.exists())
            self.assertTrue((backup_root / "backup-manifest.json").is_file())
            self.assertTrue((backup_root / "execution-result.json").is_file())
            self.assertTrue(
                (backup_root / "recovery-verification.json").is_file()
            )
            manifest_document = json.loads(
                (backup_root / "backup-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                manifest_document["schema"],
                "SITINA_STEP7_EXECUTION_MANIFEST_V1",
            )
            self.assertNotEqual(
                manifest_document["schema"], ROLLBACK_MANIFEST_SCHEMA
            )
            self.assertEqual(
                manifest_document["gate_contract"], spec["gate_contract"]
            )
            self.assertEqual(result["sentinels"], spec["sentinels"])
            self.assertEqual(result["gate_contract"], spec["gate_contract"])
            self.assertEqual(result["applied_indices"], [0, 1])
            self.assertEqual(result["reverse_recovery_indices"], [])
            self.assertEqual(
                [
                    (item["kind"], item["index"])
                    for item in result["checkpoint_references"]
                ],
                [
                    ("INTENT", 0),
                    ("INTENT", 1),
                    ("COMMIT", 0),
                    ("COMMIT", 1),
                ],
            )
            self._assert_step7_v4_checkpoint_closure(result)
            self.assertEqual(
                result["manifest"]["sha256"],
                sha256(backup_root / "backup-manifest.json"),
            )
            self.assertEqual(
                result["rehearsal_result"]["sha256"],
                sha256(backup_root / "rehearsal-result.json"),
            )
            self.assertEqual(
                result["recovery_verification"]["sha256"],
                sha256(backup_root / "recovery-verification.json"),
            )
            for field in (
                "delete_operation_count",
                "unlink_operation_count",
                "rmtree_operation_count",
            ):
                self.assertEqual(result[field], 0)

    def test_v4_exact_six_path_topology_executes_without_false_inventory_drift(
        self,
    ) -> None:
        spec = self._step7_v4_exact_six_operation_spec()
        capability = self._step7_v4_capability(spec)
        deployment = Path(str(spec["deployment_root"]))
        output = Path(str(spec["allowed_backup_parent"]))
        self.assertEqual(deployment.stat().st_dev, output.stat().st_dev)
        dry_run = execute_step7_v4(
            spec,
            dry_run=True,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(dry_run["status"], "DRY_RUN_VERIFIED", dry_run)
        result = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(result["status"], "EXECUTED", result)
        self.assertEqual(result["applied_indices"], list(range(6)))
        for operation in spec["operations"]:
            self.assertEqual(
                sha256(Path(str(operation["target_path"]))),
                operation["target_sha256"],
            )

    def test_v4_exact_six_path_quarantine_parents_are_prebound(
        self,
    ) -> None:
        spec = self._step7_v4_exact_six_operation_spec()
        result = execute_step7_v4(
            spec,
            dry_run=False,
            fail_at="AFTER_REHEARSAL_RESULT_BEFORE_FIRST_INTENT",
            gate_callback=lambda _: {"accepted": True},
            _test_capability=self._step7_v4_capability(spec),
        )
        self.assertEqual(
            result["status"],
            "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION",
            result,
        )
        manifest_path = (
            Path(str(spec["backup_root"])) / "backup-manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        bindings = manifest["quarantine_parent_identities"]
        self.assertEqual(
            set(bindings),
            {
                "scripts/step7_readiness_gate.py",
                "tests/foundation/test_step7_readiness_gate.py",
            },
        )
        for binding in bindings.values():
            self.assertEqual(
                set(binding),
                {
                    "rehearsal_source_parent",
                    "rehearsal_quarantine_parent",
                    "rollback_quarantine_parent",
                },
            )
            for identity in binding.values():
                parent = Path(identity["path"])
                metadata = parent.lstat()
                self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                self.assertFalse(parent.is_symlink())
                self.assertEqual(metadata.st_dev, identity["device"])
                self.assertEqual(metadata.st_ino, identity["inode"])

    def test_v4_exact_six_path_nested_create_failures_recover_exact_preimage(
        self,
    ) -> None:
        for index in (0, 4):
            with self.subTest(index=index):
                spec = self._step7_v4_exact_six_operation_spec()
                capability = self._step7_v4_capability(spec)
                deployment = Path(str(spec["deployment_root"]))
                before = self._step7_v4_tree_snapshot(deployment)
                result = execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at=f"AFTER_APPLY:{index}",
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
                self.assertEqual(
                    result["status"],
                    "RECOVERED_AFTER_FAILURE",
                    result,
                )
                self.assertEqual(
                    self._step7_v4_tree_snapshot(deployment),
                    before,
                )
                failed_create = spec["operations"][index]
                self.assertFalse(
                    Path(str(failed_create["target_path"])).exists()
                )
                self.assertTrue(
                    Path(
                        str(
                            failed_create[
                                "rollback_quarantine_path"
                            ]
                        )
                    ).is_file()
                )
                repeated = recover_step7_v4_execution(
                    spec,
                    run_id=str(spec["run_id"]),
                    _test_capability=capability,
                )
                self.assertEqual(repeated, result)
                self.assertEqual(
                    self._step7_v4_tree_snapshot(deployment),
                    before,
                )

    def test_v4_executor_captures_nested_replace_preimage(self) -> None:
        spec = self._step7_v4_execution_spec()
        self._append_step7_v4_operation(
            spec,
            "nested/replace.txt",
            "REPLACE",
        )
        result = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=self._step7_v4_capability(spec),
        )
        self.assertEqual(result["status"], "EXECUTED", result)
        nested = spec["operations"][-1]
        backup = Path(str(nested["preimage_backup_path"]))
        self.assertTrue(backup.is_file())
        self.assertEqual(
            sha256(backup),
            nested["preimage_sha256"],
        )

    def test_v4_nested_preimage_copy_failure_is_preapply_and_not_reusable(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        self._append_step7_v4_operation(
            spec,
            "nested/replace.txt",
            "REPLACE",
        )
        deployment = Path(str(spec["deployment_root"]))
        backup_root = Path(str(spec["backup_root"]))
        before = self._step7_v4_tree_snapshot(deployment)
        original_copy = step7_gate._step7_v4_copy_exclusive

        def fail_nested_preimage(
            source: Path,
            destination: Path,
            **kwargs: object,
        ) -> None:
            if (
                "preimages" in destination.parts
                and "nested" in destination.parts
            ):
                raise OSError("injected nested preimage copy failure")
            original_copy(source, destination, **kwargs)

        with mock.patch.object(
            step7_gate,
            "_step7_v4_copy_exclusive",
            side_effect=fail_nested_preimage,
        ):
            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
        self.assertEqual(result["status"], "MANUAL_RECOVERY_REQUIRED", result)
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment),
            before,
        )
        self.assertTrue((backup_root / "preimages/nested").is_dir())
        for relative in (
            "backup-manifest.json",
            "rehearsal-result.json",
            "execution-result.json",
            "recovery-result.json",
            "checkpoints/intent-0000.json",
        ):
            self.assertFalse((backup_root / relative).exists(), relative)
        repeated = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=self._step7_v4_capability(spec),
        )
        self.assertEqual(
            repeated["status"],
            "MANUAL_RECOVERY_REQUIRED",
            repeated,
        )
        self.assertIn("preoccupied", repeated["failure_step"])
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment),
            before,
        )

    def test_v4_all_replace_rehearsals_are_disposable_and_physically_bound(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        for index in range(2, 5):
            self._append_step7_v4_operation(
                spec, f"replace-{index}.txt", "REPLACE"
            )
        deployment = Path(str(spec["deployment_root"]))
        before = self._step7_v4_tree_snapshot(deployment)
        observed: dict[str, object] = {}
        original_verify = step7_gate._step7_v4_verify_bound_inputs

        def observe_preapply(
            specification: object,
            operations: object,
        ) -> None:
            observed["deployment"] = self._step7_v4_tree_snapshot(
                deployment
            )
            original_verify(specification, operations)

        with mock.patch.object(
            step7_gate,
            "_step7_v4_verify_bound_inputs",
            side_effect=observe_preapply,
        ):
            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
        self.assertEqual(result["status"], "EXECUTED", result)
        self.assertEqual(observed["deployment"], before)
        backup_root = Path(str(spec["backup_root"]))
        rehearsal = json.loads(
            (backup_root / "rehearsal-result.json").read_text(
                encoding="utf-8"
            )
        )
        replace_entries = [
            entry
            for entry in rehearsal["entries"]
            if entry["operation"] == "REPLACE"
        ]
        self.assertEqual(len(replace_entries), 4)
        for entry in replace_entries:
            for field, tuple_field in (
                ("restored_artifact", "restored_tuple"),
                ("reapplied_artifact", "reapplied_tuple"),
            ):
                reference = entry[field]
                path = Path(reference["path"])
                self.assertTrue(path.is_relative_to(backup_root))
                self.assertEqual(reference["sha256"], sha256(path))
                self.assertEqual(
                    step7_gate._step7_v4_file_tuple(path),
                    entry[tuple_field],
                )
            checkpoint = (
                backup_root
                / "checkpoints"
                / f"rehearsal-{entry['index']:04d}-replace.json"
            )
            self.assertEqual(
                json.loads(checkpoint.read_text(encoding="utf-8"))[
                    "entry_sha256"
                ],
                _json_value_sha256(entry),
            )

    def test_v4_production_rejects_every_non_none_failure_injection(
        self,
    ) -> None:
        for fail_at in ([], set(), "ANY"):
            with self.subTest(api="execute", fail_at=repr(fail_at)):
                with self.assertRaisesRegex(
                    ValueError, "production executor forbids"
                ):
                    execute_step7_v4(
                        {},
                        dry_run=True,
                        fail_at=fail_at,
                    )
            with self.subTest(api="recover", fail_at=repr(fail_at)):
                with self.assertRaisesRegex(
                    ValueError, "production recovery forbids"
                ):
                    recover_step7_v4_execution(
                        {},
                        run_id="unused",
                        fail_at=fail_at,
                    )

    def test_v4_production_run_id_is_exactly_approval_execution_id(
        self,
    ) -> None:
        packet = {"approval_id": "SITINA_STEP7_DEPLOY_EXACT"}
        step7_gate._step7_v4_require_production_run_id(
            {"run_id": "SITINA_STEP7_DEPLOY_EXACT_EXECUTION"},
            packet,
        )
        for run_id in (
            "SITINA_STEP7_DEPLOY_EXACT",
            "SITINA_STEP7_DEPLOY_OTHER_EXECUTION",
            "SITINA_STEP7_DEPLOY_EXACT_EXECUTION_EXTRA",
        ):
            with self.subTest(run_id=run_id), self.assertRaisesRegex(
                ValueError, "run_id must equal approval_id"
            ):
                step7_gate._step7_v4_require_production_run_id(
                    {"run_id": run_id}, packet
                )

    def test_v4_superseded_4de067a_approval_is_mechanically_revoked(
        self,
    ) -> None:
        approval_id = "SITINA_STEP7_DEPLOY_4DE067A_6F_20260728T173000Z"
        self.assertIn(
            approval_id,
            step7_gate.REVOKED_DEPLOYMENT_APPROVAL_IDS,
        )
        with self.assertRaisesRegex(
            ValueError,
            "production approval_id is revoked",
        ):
            step7_gate._step7_v4_require_production_run_id(
                {"run_id": f"{approval_id}_EXECUTION"},
                {"approval_id": approval_id},
            )

    def test_v4_superseded_c327e63_approval_is_mechanically_revoked(
        self,
    ) -> None:
        approval_id = "SITINA_STEP7_DEPLOY_C327E63_6F_20260729T053000Z"
        self.assertIn(
            approval_id,
            step7_gate.REVOKED_DEPLOYMENT_APPROVAL_IDS,
        )
        with self.assertRaisesRegex(
            ValueError,
            "production approval_id is revoked",
        ):
            step7_gate._step7_v4_require_production_run_id(
                {"run_id": f"{approval_id}_EXECUTION"},
                {"approval_id": approval_id},
            )

    def test_v4_superseded_a5650d1_approval_is_mechanically_revoked(
        self,
    ) -> None:
        approval_id = "SITINA_STEP7_DEPLOY_A5650D1_6F_20260729T070000Z"
        self.assertIn(
            approval_id,
            step7_gate.REVOKED_DEPLOYMENT_APPROVAL_IDS,
        )
        with self.assertRaisesRegex(
            ValueError,
            "production approval_id is revoked",
        ):
            step7_gate._step7_v4_require_production_run_id(
                {"run_id": f"{approval_id}_EXECUTION"},
                {"approval_id": approval_id},
            )

    def test_v4_superseded_f2deec0_approvals_are_mechanically_revoked(
        self,
    ) -> None:
        approval_ids = (
            "SITINA_STEP7_DEPLOY_F2DEEC0_6F_20260729T073500Z",
            "SITINA_STEP7_DEPLOY_F2DEEC0_6F_20260729T083000Z",
        )
        for approval_id in approval_ids:
            with self.subTest(approval_id=approval_id):
                self.assertIn(
                    approval_id,
                    step7_gate.REVOKED_DEPLOYMENT_APPROVAL_IDS,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "production approval_id is revoked",
                ):
                    step7_gate._step7_v4_require_production_run_id(
                        {"run_id": f"{approval_id}_EXECUTION"},
                        {"approval_id": approval_id},
                    )

    def test_v4_manifest_is_reloaded_exactly_before_rehearsal_or_apply(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        deployment = Path(str(spec["deployment_root"]))
        before = self._step7_v4_tree_snapshot(deployment)
        original_load = step7_gate._step7_v4_load_manifest

        def tamper_then_load(
            specification: object,
            **kwargs: object,
        ) -> object:
            if kwargs.get("expected_manifest") is not None:
                path = (
                    Path(str(spec["backup_root"]))
                    / "backup-manifest.json"
                )
                document = json.loads(path.read_text(encoding="utf-8"))
                document["status"] = "TAMPERED"
                path.write_text(
                    json.dumps(document, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            return original_load(specification, **kwargs)

        with mock.patch.object(
            step7_gate,
            "_step7_v4_load_manifest",
            side_effect=tamper_then_load,
        ):
            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
        self.assertEqual(
            result["status"],
            "MANUAL_RECOVERY_REQUIRED",
            result,
        )
        self.assertIn(
            "manifest binding mismatch", result["recovery_error"]
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment), before
        )
        self.assertFalse(
            (
                Path(str(spec["backup_root"]))
                / "checkpoints"
                / "intent-0000.json"
            ).exists()
        )

    def test_v4_missing_recovery_verification_blocks_first_intent(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        deployment = Path(str(spec["deployment_root"]))
        before = self._step7_v4_tree_snapshot(deployment)
        original_load = step7_gate._step7_v4_load_rehearsal

        def remove_then_load(*args: object, **kwargs: object) -> object:
            verification = (
                Path(str(spec["backup_root"]))
                / "recovery-verification.json"
            )
            if verification.exists():
                verification.unlink()
            return original_load(*args, **kwargs)

        with mock.patch.object(
            step7_gate,
            "_step7_v4_load_rehearsal",
            side_effect=remove_then_load,
        ):
            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
        self.assertEqual(
            result["status"],
            "MANUAL_RECOVERY_REQUIRED",
            result,
        )
        self.assertIn(
            "recovery-verification.json", result["recovery_error"]
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment), before
        )
        self.assertFalse(
            (
                Path(str(spec["backup_root"]))
                / "checkpoints"
                / "intent-0000.json"
            ).exists()
        )

    def test_v4_intent_and_commit_are_reloaded_before_later_mutation(
        self,
    ) -> None:
        for checkpoint_name, untouched_relative in (
            ("intent-0000.json", "replace.txt"),
            ("commit-0000.json", "create.txt"),
        ):
            with self.subTest(checkpoint=checkpoint_name):
                spec = self._step7_v4_execution_spec()
                deployment = Path(str(spec["deployment_root"]))
                original_load = step7_gate._step7_v4_load_json

                def drift_checkpoint(path: Path) -> dict[str, object]:
                    document = original_load(path)
                    if path.name == checkpoint_name:
                        document = dict(document)
                        document["run_id"] = "tampered"
                    return document

                with mock.patch.object(
                    step7_gate,
                    "_step7_v4_load_json",
                    side_effect=drift_checkpoint,
                ):
                    result = execute_step7_v4(
                        spec,
                        dry_run=False,
                        gate_callback=lambda _: {"accepted": True},
                        _test_capability=self._step7_v4_capability(spec),
                    )
                self.assertNotEqual(result["status"], "EXECUTED", result)
                if checkpoint_name.startswith("intent"):
                    self.assertEqual(
                        (deployment / untouched_relative).read_text(
                            encoding="utf-8"
                        ),
                        "old replace\n",
                    )
                else:
                    self.assertFalse(
                        (deployment / untouched_relative).exists()
                    )
                    self.assertFalse(
                        (
                            Path(str(spec["backup_root"]))
                            / "checkpoints"
                            / "intent-0001.json"
                        ).exists()
                    )

    def test_v4_recovery_verification_entry_closure_fails_closed(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        executed = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(executed["status"], "EXECUTED", executed)
        backup_root = Path(str(spec["backup_root"]))
        manifest_path = backup_root / "backup-manifest.json"
        _, manifest = step7_gate._step7_v4_load_manifest(
            spec, run_id=str(spec["run_id"])
        )
        verification_path = backup_root / "recovery-verification.json"
        rehearsal_path = backup_root / "rehearsal-result.json"
        verification_original = verification_path.read_bytes()
        rehearsal_original = rehearsal_path.read_bytes()

        def missing(entries: list[object]) -> list[object]:
            return entries[:-1]

        def duplicated(entries: list[object]) -> list[object]:
            return [*entries, copy.deepcopy(entries[-1])]

        def reordered(entries: list[object]) -> list[object]:
            return list(reversed(entries))

        def extra(entries: list[object]) -> list[object]:
            value = copy.deepcopy(entries[-1])
            value["index"] = 999
            value["relative_path"] = "extra"
            return [*entries, value]

        for name, mutate in (
            ("missing", missing),
            ("duplicated", duplicated),
            ("reordered", reordered),
            ("extra", extra),
        ):
            with self.subTest(name=name):
                verification = json.loads(
                    verification_original.decode("utf-8")
                )
                verification["entries"] = mutate(
                    verification["entries"]
                )
                verification["entries_sha256"] = _json_value_sha256(
                    verification["entries"]
                )
                verification_path.write_bytes(
                    step7_gate._step7_v4_json_payload(verification)
                )
                rehearsal = json.loads(
                    rehearsal_original.decode("utf-8")
                )
                rehearsal["recovery_verification"] = {
                    "path": str(verification_path),
                    "sha256": sha256(verification_path),
                }
                rehearsal_path.write_bytes(
                    step7_gate._step7_v4_json_payload(rehearsal)
                )
                with self.assertRaisesRegex(
                    ValueError, "recovery verification"
                ):
                    step7_gate._step7_v4_load_rehearsal(
                        backup_root,
                        manifest,
                        manifest["binding"],
                        manifest_path,
                    )
                verification_path.write_bytes(verification_original)
                rehearsal_path.write_bytes(rehearsal_original)

    def test_v4_rehearsal_artifact_closure_rejects_extra_leaf(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        executed = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=self._step7_v4_capability(spec),
        )
        self.assertEqual(executed["status"], "EXECUTED", executed)
        backup_root = Path(str(spec["backup_root"]))
        manifest_path = backup_root / "backup-manifest.json"
        _, manifest = step7_gate._step7_v4_load_manifest(
            spec, run_id=str(spec["run_id"])
        )
        (backup_root / "rehearsal/unexpected.txt").write_text(
            "unexpected\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValueError, "artifact closure mismatch"
        ):
            step7_gate._step7_v4_load_rehearsal(
                backup_root,
                manifest,
                manifest["binding"],
                manifest_path,
            )

    def test_v4_recovery_after_success_is_read_only_and_idempotent(self) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        executed = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True, "gate": "success"},
            _test_capability=capability,
        )
        self.assertEqual(executed["status"], "EXECUTED", executed)
        scope = capability.scope_root
        before = self._step7_v4_tree_snapshot(scope)
        first = recover_step7_v4_execution(
            spec,
            run_id=str(spec["run_id"]),
            _test_capability=capability,
        )
        self.assertEqual(
            first["status"], "ALREADY_EXECUTED_NO_RECOVERY", first
        )
        self.assertEqual(first["side_effect_count"], 0)
        self.assertEqual(
            self._step7_v4_tree_snapshot(scope),
            before,
        )
        second = recover_step7_v4_execution(
            spec,
            run_id=str(spec["run_id"]),
            _test_capability=capability,
        )
        self.assertEqual(second, first)
        self.assertEqual(
            self._step7_v4_tree_snapshot(scope),
            before,
        )
        backup_root = Path(str(spec["backup_root"]))
        self.assertFalse((backup_root / "recovery-result.json").exists())
        self.assertFalse(
            (backup_root / "checkpoints/rollback-intent.json").exists()
        )
        self.assertFalse(
            any(
                path.name.startswith("recovered-")
                for path in (backup_root / "checkpoints").iterdir()
            )
        )
        self._assert_step7_v4_checkpoint_closure(first)
        with self.assertRaisesRegex(ValueError, "terminal result"):
            _step7_v4_checkpoint(
                backup_root,
                "failure",
                {
                    "run_id": spec["run_id"],
                    "error_type": "Forbidden",
                    "error": "must not publish after success",
                },
            )

    def test_v4_success_checkpoint_closure_tamper_is_read_only_rejected(
        self,
    ) -> None:
        for mutation in (
            "omit_result_reference",
            "reorder_result_references",
            "delete_commit",
            "tamper_commit",
            "extra_failure",
            "extra_rollback_intent",
            "extra_recovered",
        ):
            with self.subTest(mutation=mutation):
                spec = self._step7_v4_execution_spec()
                capability = self._step7_v4_capability(spec)
                executed = execute_step7_v4(
                    spec,
                    dry_run=False,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
                self.assertEqual(executed["status"], "EXECUTED")
                backup_root = Path(str(spec["backup_root"]))
                result_path = backup_root / "execution-result.json"
                checkpoint_root = backup_root / "checkpoints"
                if mutation in {
                    "omit_result_reference",
                    "reorder_result_references",
                }:
                    result = json.loads(
                        result_path.read_text(encoding="utf-8")
                    )
                    references = result["checkpoint_references"]
                    if mutation == "omit_result_reference":
                        references.pop()
                    else:
                        references.reverse()
                    result["checkpoint_references_sha256"] = (
                        _json_value_sha256(references)
                    )
                    canonical_set = sorted(
                        references,
                        key=lambda item: (
                            item["kind"],
                            item["index"],
                            item["reference"]["path"],
                            item["reference"]["sha256"],
                        ),
                    )
                    result["checkpoint_reference_set_sha256"] = (
                        _json_value_sha256(canonical_set)
                    )
                    result_path.write_text(
                        json.dumps(result, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                elif mutation in {"delete_commit", "tamper_commit"}:
                    commit = checkpoint_root / "commit-0001.json"
                    if mutation == "delete_commit":
                        commit.unlink()
                    else:
                        value = json.loads(
                            commit.read_text(encoding="utf-8")
                        )
                        value["operation"] = "TAMPERED"
                        commit.write_text(
                            json.dumps(value, sort_keys=True) + "\n",
                            encoding="utf-8",
                        )
                else:
                    manifest_path = backup_root / "backup-manifest.json"
                    manifest = json.loads(
                        manifest_path.read_text(encoding="utf-8")
                    )
                    binding = manifest["binding"]
                    if mutation == "extra_failure":
                        name = "failure.json"
                        value = {
                            "run_id": spec["run_id"],
                            "error_type": "InjectedExternalCheckpoint",
                            "error": "phase-inappropriate after success",
                        }
                    elif mutation == "extra_rollback_intent":
                        name = "rollback-intent.json"
                        value = _step7_v4_rollback_intent(
                            binding,
                            manifest_path,
                            intent_indices=[0, 1],
                            commit_indices=[0, 1],
                            applied_indices=[0, 1],
                        )
                    else:
                        name = "recovered-0001-create.json"
                        value = _step7_v4_recovered_checkpoint(
                            binding,
                            1,
                            spec["operations"][1],
                        )
                    (checkpoint_root / name).write_text(
                        json.dumps(value, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                deployment = Path(str(spec["deployment_root"]))
                deployment_before = self._step7_v4_tree_snapshot(
                    deployment
                )
                checkpoints_before = self._step7_v4_tree_snapshot(
                    checkpoint_root
                )
                rejected = recover_step7_v4_execution(
                    spec,
                    run_id=str(spec["run_id"]),
                    _test_capability=capability,
                )
                self.assertEqual(
                    rejected["status"], "MANUAL_RECOVERY_REQUIRED"
                )
                self.assertEqual(
                    self._step7_v4_tree_snapshot(deployment),
                    deployment_before,
                )
                self.assertEqual(
                    self._step7_v4_tree_snapshot(checkpoint_root),
                    checkpoints_before,
                )
                self.assertFalse(
                    (backup_root / "recovery-result.json").exists()
                )

    def test_v4_preterminal_checkpoint_injection_is_structured(self) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        backup_root = Path(str(spec["backup_root"]))
        checkpoint_root = backup_root / "checkpoints"
        deployment = Path(str(spec["deployment_root"]))
        rejection_snapshot: dict[str, object] = {}
        original_phase_check = (
            step7_gate._step7_v4_require_phase_checkpoint_closure
        )

        def observe_phase_rejection(**arguments: object) -> None:
            try:
                original_phase_check(**arguments)
            except ValueError:
                rejection_snapshot["deployment"] = (
                    self._step7_v4_tree_snapshot(deployment)
                )
                rejection_snapshot["checkpoints"] = (
                    self._step7_v4_tree_snapshot(checkpoint_root)
                )
                raise

        def inject_failure(_: object) -> dict[str, object]:
            (checkpoint_root / "failure.json").write_text(
                json.dumps(
                    {
                        "run_id": spec["run_id"],
                        "error_type": "InjectedPreterminalFailure",
                        "error": "must not be overwritten",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return {"accepted": True}

        with mock.patch.object(
            step7_gate,
            "_step7_v4_require_phase_checkpoint_closure",
            side_effect=observe_phase_rejection,
        ):
            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=inject_failure,
                _test_capability=capability,
            )
        self.assertEqual(result["status"], "MANUAL_RECOVERY_REQUIRED")
        self.assertIn("checkpoint phase closure", result["failure_step"])
        self.assertIn("checkpoint conflicts", result["checkpoint_error"])
        for field in (
            "delete_operation_count",
            "unlink_operation_count",
            "rmtree_operation_count",
        ):
            self.assertEqual(result[field], 0)
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment),
            rejection_snapshot["deployment"],
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(checkpoint_root),
            rejection_snapshot["checkpoints"],
        )
        self.assertFalse((backup_root / "recovery-result.json").exists())
        self.assertFalse(
            (checkpoint_root / "rollback-intent.json").exists()
        )
        self.assertFalse(
            any(
                path.name.startswith("recovered-")
                for path in checkpoint_root.iterdir()
            )
        )

    def test_v4_preterminal_rollback_intent_enters_controlled_recovery(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        backup_root = Path(str(spec["backup_root"]))

        def inject_rollback_intent(_: object) -> dict[str, object]:
            manifest_path = backup_root / "backup-manifest.json"
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            value = _step7_v4_rollback_intent(
                manifest["binding"],
                manifest_path,
                intent_indices=[0, 1],
                commit_indices=[0, 1],
                applied_indices=[0, 1],
            )
            (
                backup_root / "checkpoints/rollback-intent.json"
            ).write_text(
                json.dumps(value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return {"accepted": True}

        result = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=inject_rollback_intent,
            _test_capability=capability,
        )
        self.assertEqual(
            result["status"], "RECOVERED_AFTER_FAILURE", result
        )
        self.assertEqual(result["reverse_recovery_indices"], [1, 0])
        deployment = Path(str(spec["deployment_root"]))
        self.assertEqual(
            (deployment / "replace.txt").read_text(encoding="utf-8"),
            "old replace\n",
        )
        self.assertFalse((deployment / "create.txt").exists())

    def test_v4_executor_partial_failure_resumes_from_disk_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            first = execute_step7_v4(
                spec,
                dry_run=False,
                fail_at={"WRITE_SUCCESS_RESULT", "ROLLBACK_REPLACE"},
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(first["status"], "MANUAL_RECOVERY_REQUIRED", first)
            resumed = recover_step7_v4_execution(
                spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
            )
            self.assertEqual(resumed["status"], "RECOVERED_AFTER_FAILURE", resumed)
            self.assertEqual(resumed["applied_indices"], [0, 1])
            self.assertEqual(resumed["reverse_recovery_indices"], [1, 0])
            self.assertEqual(
                resumed["recovered_checkpoints_sha256"],
                _json_value_sha256(resumed["recovered_checkpoints"]),
            )
            self.assertEqual(
                [
                    (item["kind"], item["index"])
                    for item in resumed["checkpoint_references"]
                    if item["kind"] == "RECOVERED"
                ],
                [("RECOVERED", 1), ("RECOVERED", 0)],
            )
            self._assert_step7_v4_checkpoint_closure(resumed)
            for item in resumed["recovered_checkpoints"]:
                reference = item["reference"]
                self.assertEqual(
                    reference["sha256"], sha256(Path(reference["path"]))
                )
            deployment = Path(str(spec["deployment_root"]))
            self.assertEqual(
                (deployment / "replace.txt").read_text(encoding="utf-8"),
                "old replace\n",
            )
            self.assertFalse((deployment / "create.txt").exists())
            self.assertTrue(
                Path(str(spec["operations"][1]["rollback_quarantine_path"])).is_file()
            )
            repeated = recover_step7_v4_execution(
                spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
            )
            self.assertEqual(repeated, resumed)
            wrong = recover_step7_v4_execution(
                spec, run_id="different-run", _test_capability=self._step7_v4_capability(spec)
            )
            self.assertEqual(wrong["status"], "MANUAL_RECOVERY_REQUIRED")

    def test_v4_recovery_audits_later_checkpoint_before_any_rollback(self) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        stopped = execute_step7_v4(
            spec,
            dry_run=False,
            fail_at={"WRITE_SUCCESS_RESULT", "ROLLBACK_CREATE"},
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(stopped["status"], "MANUAL_RECOVERY_REQUIRED")
        backup_root = Path(str(spec["backup_root"]))
        checkpoint = backup_root / "checkpoints/commit-0000.json"
        tampered = json.loads(checkpoint.read_text(encoding="utf-8"))
        tampered["operation"] = "TAMPERED_LATER_REPLACE"
        checkpoint.write_text(
            json.dumps(tampered, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        deployment = Path(str(spec["deployment_root"]))
        before = self._step7_v4_tree_snapshot(deployment)
        live = Path(
            str(spec["operations"][1]["rollback_quarantine_path"])
        )
        self.assertFalse(live.exists())
        rejected = recover_step7_v4_execution(
            spec,
            run_id=str(spec["run_id"]),
            _test_capability=capability,
        )
        self.assertEqual(rejected["status"], "MANUAL_RECOVERY_REQUIRED")
        self.assertIn("commit checkpoint 0", rejected["recovery_error"])
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment),
            before,
        )
        self.assertFalse(live.exists())
        self.assertFalse(
            any(
                path.name.startswith("recovered-")
                for path in (backup_root / "checkpoints").iterdir()
            )
        )

    def test_v4_rollback_intent_recovers_mutation_checkpoint_crash(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        stopped = execute_step7_v4(
            spec,
            dry_run=False,
            fail_at={
                "WRITE_SUCCESS_RESULT",
                "AFTER_RECOVERY_MUTATION_BEFORE_CHECKPOINT:1",
            },
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(stopped["status"], "MANUAL_RECOVERY_REQUIRED")
        backup_root = Path(str(spec["backup_root"]))
        self.assertTrue(
            (backup_root / "checkpoints/rollback-intent.json").is_file()
        )
        self.assertFalse(
            (
                backup_root
                / "checkpoints/recovered-0001-create.json"
            ).exists()
        )
        resumed = recover_step7_v4_execution(
            spec,
            run_id=str(spec["run_id"]),
            _test_capability=capability,
        )
        self.assertEqual(resumed["status"], "RECOVERED_AFTER_FAILURE")
        self.assertEqual(resumed["reverse_recovery_indices"], [1, 0])
        self._assert_step7_v4_checkpoint_closure(resumed)
        with self.assertRaisesRegex(ValueError, "terminal result"):
            _step7_v4_checkpoint(
                backup_root,
                "failure",
                {
                    "run_id": spec["run_id"],
                    "error_type": "Forbidden",
                    "error": "must not publish after recovery",
                },
            )

    def test_v4_recovery_rejects_recovered_state_without_rollback_intent(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        stopped = execute_step7_v4(
            spec,
            dry_run=False,
            fail_at={"WRITE_SUCCESS_RESULT", "WRITE_ROLLBACK_INTENT"},
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(stopped["status"], "MANUAL_RECOVERY_REQUIRED")
        backup_root = Path(str(spec["backup_root"]))
        self.assertFalse(
            (backup_root / "checkpoints/rollback-intent.json").exists()
        )
        replace = spec["operations"][0]
        shutil.copy2(
            Path(str(replace["preimage_backup_path"])),
            Path(str(replace["target_path"])),
        )
        create = spec["operations"][1]
        Path(str(create["target_path"])).rename(
            Path(str(create["rollback_quarantine_path"]))
        )
        deployment = Path(str(spec["deployment_root"]))
        before = self._step7_v4_tree_snapshot(deployment)
        rejected = recover_step7_v4_execution(
            spec,
            run_id=str(spec["run_id"]),
            _test_capability=capability,
        )
        self.assertEqual(rejected["status"], "MANUAL_RECOVERY_REQUIRED")
        self.assertIn(
            "without rollback intent", rejected["recovery_error"]
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment),
            before,
        )

    def test_v4_recovered_checkpoint_phase_rejects_late_extra_intent(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        recovered = execute_step7_v4(
            spec,
            dry_run=False,
            fail_at="AFTER_APPLY:0",
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(
            recovered["status"], "RECOVERED_AFTER_FAILURE", recovered
        )
        backup_root = Path(str(spec["backup_root"]))
        manifest = json.loads(
            (backup_root / "backup-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        late_intent = _step7_v4_intent(
            manifest["binding"],
            1,
            spec["operations"][1],
        )
        (backup_root / "checkpoints/intent-0001.json").write_text(
            json.dumps(late_intent, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        deployment = Path(str(spec["deployment_root"]))
        deployment_before = self._step7_v4_tree_snapshot(deployment)
        checkpoints_before = self._step7_v4_tree_snapshot(
            backup_root / "checkpoints"
        )
        rejected = recover_step7_v4_execution(
            spec,
            run_id=str(spec["run_id"]),
            _test_capability=capability,
        )
        self.assertEqual(
            rejected["status"], "MANUAL_RECOVERY_REQUIRED", rejected
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(deployment),
            deployment_before,
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(
                backup_root / "checkpoints"
            ),
            checkpoints_before,
        )

    def test_v4_executor_failure_injection_covers_every_side_effect(self) -> None:
        recovery_steps = {
            "WRITE_ROLLBACK_INTENT",
            "AFTER_ROLLBACK_INTENT",
            "ROLLBACK_CREATE",
            "ROLLBACK_REPLACE",
            "WRITE_RECOVERY_RESULT",
        }
        with tempfile.TemporaryDirectory() as directory:
            template = self._step7_v4_execution_spec()
            self._append_step7_v4_operation(template, "replace-2.txt", "REPLACE")
            self._append_step7_v4_operation(template, "create-2.txt", "CREATE")
            steps = step7_v4_failure_injection_steps(template["operations"])
        self.assertEqual(len(steps), len(set(steps)))
        for index in range(4):
            self.assertIn(f"AFTER_INTENT:{index}", steps)
            self.assertIn(f"AFTER_MUTATION_BEFORE_COMMIT:{index}", steps)
            self.assertIn(f"AFTER_APPLY:{index}", steps)
        self.assertIn("RUN_CREATE_REHEARSAL:1", steps)
        self.assertIn("RUN_CREATE_REHEARSAL:3", steps)
        self.assertNotIn("RUN_CREATE_REHEARSAL:0", steps)
        self.assertNotIn("RUN_CREATE_REHEARSAL:2", steps)
        self.assertIn("RUN_REPLACE_REHEARSAL:0", steps)
        self.assertIn("RUN_REPLACE_REHEARSAL:2", steps)
        self.assertNotIn("RUN_REPLACE_REHEARSAL:1", steps)
        self.assertNotIn("RUN_REPLACE_REHEARSAL:3", steps)
        for step in steps:
            with self.subTest(step=step), tempfile.TemporaryDirectory() as directory:
                spec = self._step7_v4_execution_spec()
                self._append_step7_v4_operation(
                    spec, "replace-2.txt", "REPLACE"
                )
                self._append_step7_v4_operation(
                    spec, "create-2.txt", "CREATE"
                )
                fail_at: object = (
                    {"WRITE_SUCCESS_RESULT", step}
                    if (
                        step in recovery_steps
                        or step.startswith(
                            "AFTER_RECOVERY_MUTATION_BEFORE_CHECKPOINT:"
                        )
                    )
                    else step
                )
                result = execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at=fail_at,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=self._step7_v4_capability(spec),
                )
                self.assertNotEqual(result["status"], "EXECUTED", result)
                for field in ("delete_operation_count", "unlink_operation_count", "rmtree_operation_count"):
                    self.assertEqual(result.get(field), 0)

    def test_v4_executor_rejects_drift_and_symlink_after_dry_run(self) -> None:
        for mutation in (
            "preimage",
            "preimage_mode",
            "sentinel",
            "create_symlink",
            "broken_symlink",
            "derived_artifact",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                spec = self._step7_v4_execution_spec()
                execute_step7_v4(
                    spec,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=self._step7_v4_capability(spec),
                )
                deployment = Path(str(spec["deployment_root"]))
                if mutation == "preimage":
                    (deployment / "replace.txt").write_text("drift\n", encoding="utf-8")
                elif mutation == "preimage_mode":
                    (deployment / "replace.txt").chmod(0o600)
                elif mutation == "sentinel":
                    (deployment / "sentinel.txt").write_text("drift\n", encoding="utf-8")
                elif mutation == "create_symlink":
                    (deployment / "create.txt").symlink_to(deployment / "replace.txt")
                elif mutation == "broken_symlink":
                    (deployment / "create.txt").symlink_to(deployment / "missing")
                else:
                    spec["operations"][1]["rollback_quarantine_path"] = str(
                        Path(str(spec["backup_root"]))
                        / "quarantine/created/drift.txt"
                    )
                with self.assertRaises(ValueError):
                    execute_step7_v4(
                        spec,
                        dry_run=False,
                        gate_callback=lambda _: {"accepted": True},
                        _test_capability=self._step7_v4_capability(spec),
                    )
                self.assertFalse(Path(str(spec["backup_root"])).exists())

    def test_v4_atomic_noreplace_preserves_preoccupied_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            source, destination = root / "source", root / "destination"
            source.write_text("source\n", encoding="utf-8")
            destination.write_text("occupied\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                _step7_v4_rename_noreplace(source, destination)
            self.assertEqual(source.read_text(encoding="utf-8"), "source\n")
            self.assertEqual(destination.read_text(encoding="utf-8"), "occupied\n")

    def test_v4_recovery_result_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            result = execute_step7_v4(
                spec,
                dry_run=False,
                fail_at="WRITE_SUCCESS_RESULT",
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(result["status"], "RECOVERED_AFTER_FAILURE")
            result_path = Path(str(spec["backup_root"])) / "recovery-result.json"
            tampered = json.loads(result_path.read_text(encoding="utf-8"))
            tampered["delete_operation_count"] = 1
            result_path.write_text(
                json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8"
            )
            rejected = recover_step7_v4_execution(
                spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
            )
            self.assertEqual(rejected["status"], "MANUAL_RECOVERY_REQUIRED")

    def test_v4_recovered_checkpoint_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            result = execute_step7_v4(
                spec,
                dry_run=False,
                fail_at="WRITE_SUCCESS_RESULT",
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(result["status"], "RECOVERED_AFTER_FAILURE")
            checkpoint = (
                Path(str(spec["backup_root"]))
                / "checkpoints/recovered-0000-replace.json"
            )
            value = json.loads(checkpoint.read_text(encoding="utf-8"))
            value["action"] = "TAMPERED"
            checkpoint.write_text(
                json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
            )
            rejected = recover_step7_v4_execution(
                spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
            )
            self.assertEqual(rejected["status"], "MANUAL_RECOVERY_REQUIRED")

    def test_v4_executor_same_byte_symlink_artifacts_are_rejected(self) -> None:
        for artifact in ("manifest", "checkpoint", "recovery_result"):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as directory:
                spec = self._step7_v4_execution_spec()
                failure = (
                    "AFTER_INTENT:0"
                    if artifact == "manifest"
                    else "AFTER_MUTATION_BEFORE_COMMIT:0"
                    if artifact == "checkpoint"
                    else "WRITE_SUCCESS_RESULT"
                )
                execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at=failure,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=self._step7_v4_capability(spec),
                )
                backup_root = Path(str(spec["backup_root"]))
                path = (
                    backup_root / "backup-manifest.json"
                    if artifact == "manifest"
                    else backup_root
                    / "checkpoints/recovered-0000-replace.json"
                    if artifact == "checkpoint"
                    else backup_root / "recovery-result.json"
                )
                backing = path.with_name(f"{path.name}.same-bytes")
                shutil.copy2(path, backing)
                path.unlink()
                path.symlink_to(backing)
                rejected = recover_step7_v4_execution(
                    spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
                )
                self.assertEqual(
                    rejected["status"], "MANUAL_RECOVERY_REQUIRED", rejected
                )

    def test_v3_runtime_manifest_and_recovery_result_are_rejected(self) -> None:
        for artifact in ("manifest", "recovery_result"):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as directory:
                spec = self._step7_v4_execution_spec()
                failure = (
                    "AFTER_INTENT:0"
                    if artifact == "manifest"
                    else "WRITE_SUCCESS_RESULT"
                )
                execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at=failure,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=self._step7_v4_capability(spec),
                )
                path = Path(str(spec["backup_root"])) / (
                    "backup-manifest.json"
                    if artifact == "manifest"
                    else "recovery-result.json"
                )
                value = json.loads(path.read_text(encoding="utf-8"))
                value["schema"] = (
                    "SITINA_STEP7_BACKUP_MANIFEST_V3"
                    if artifact == "manifest"
                    else "SITINA_STEP7_ROLLBACK_VERIFICATION_V3"
                )
                path.write_text(
                    json.dumps(value, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                rejected = recover_step7_v4_execution(
                    spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
                )
                self.assertEqual(
                    rejected["status"], "MANUAL_RECOVERY_REQUIRED", rejected
                )

    def test_v4_recovery_requires_this_run_applied_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            stopped = execute_step7_v4(
                spec,
                dry_run=False,
                fail_at="AFTER_APPLY:0",
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(stopped["status"], "RECOVERED_AFTER_FAILURE", stopped)
            deployment = Path(str(spec["deployment_root"]))
            (deployment / "create.txt").write_text(
                "new create\n", encoding="utf-8"
            )
            result_path = Path(str(spec["backup_root"])) / "recovery-result.json"
            result_path.rename(result_path.with_suffix(".prior"))
            rejected = recover_step7_v4_execution(
                spec, run_id=str(spec["run_id"]), _test_capability=self._step7_v4_capability(spec)
            )
            self.assertEqual(rejected["status"], "MANUAL_RECOVERY_REQUIRED")
            self.assertIn("strict apply intent", rejected["recovery_error"])

    def test_v4_deployed_gate_rejection_and_mutation_are_rolled_back(self) -> None:
        for behavior in ("reject", "mutate"):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as directory:
                spec = self._step7_v4_execution_spec()

                def gate(_: object) -> dict[str, object]:
                    if behavior == "mutate":
                        deployment = Path(str(spec["deployment_root"]))
                        (deployment / "sentinel.txt").write_text(
                            "sentinel drift\n", encoding="utf-8"
                        )
                        return {"accepted": True}
                    attempt_path = (
                        Path(str(spec["backup_root"]))
                        / "official-gates"
                        / "activation.json"
                    )
                    attempt_path.write_text(
                        json.dumps(
                            {
                                "schema": (
                                    "SITINA_STEP7_OFFICIAL_GATE_"
                                    "ATTEMPT_V2"
                                ),
                                "name": "activation",
                                "return_code": 1,
                            },
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    return {"accepted": False}

                result = execute_step7_v4(
                    spec,
                    dry_run=False,
                    gate_callback=gate,
                    _test_capability=self._step7_v4_capability(spec),
                )
                expected = (
                    "MANUAL_RECOVERY_REQUIRED"
                    if behavior == "mutate"
                    else "RECOVERED_AFTER_FAILURE"
                )
                self.assertEqual(result["status"], expected, result)
                deployment = Path(str(spec["deployment_root"]))
                if behavior == "mutate":
                    self.assertEqual(
                        (deployment / "replace.txt").read_text(
                            encoding="utf-8"
                        ),
                        "new replace\n",
                    )
                    self.assertTrue((deployment / "create.txt").is_file())
                    self.assertIn(
                        "undeclared deployment-tree mutation",
                        result["recovery_error"],
                    )
                else:
                    self.assertEqual(
                        (deployment / "replace.txt").read_text(
                            encoding="utf-8"
                        ),
                        "old replace\n",
                    )
                    self.assertFalse((deployment / "create.txt").exists())
                    attempts = result[
                        "official_gate_attempt_references"
                    ]
                    self.assertEqual(len(attempts), 1)
                    self.assertEqual(
                        attempts[0]["path"],
                        str(
                            Path(str(spec["backup_root"]))
                            / "official-gates"
                            / "activation.json"
                        ),
                    )
                    self.assertEqual(
                        result[
                            "official_gate_attempt_"
                            "reference_set_sha256"
                        ],
                        _json_value_sha256(attempts),
                    )
                    for path in (
                        Path(str(spec["backup_root"]))
                        / "checkpoints"
                        / "failure.json",
                        Path(str(spec["backup_root"]))
                        / "checkpoints"
                        / "rollback-intent.json",
                    ):
                        document = json.loads(
                            path.read_text(encoding="utf-8")
                        )
                        self.assertEqual(
                            document[
                                "official_gate_attempt_references"
                            ],
                            attempts,
                        )
                        self.assertEqual(
                            document[
                                "official_gate_attempt_"
                                "reference_set_sha256"
                            ],
                            _json_value_sha256(attempts),
                        )

    def test_v4_executor_defaults_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            capability = self._step7_v4_capability(spec)
            with self.assertRaisesRegex(ValueError, "callback is required"):
                execute_step7_v4(
                    spec,
                    dry_run=True,
                    _test_capability=capability,
                )
            with self.assertRaisesRegex(ValueError, "production"):
                execute_step7_v4(
                    spec,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                )
            with self.assertRaisesRegex(ValueError, "production"):
                execute_step7_v4(spec, dry_run=True)
            empty_sentinels = copy.deepcopy(spec)
            empty_sentinels["sentinels"] = []
            empty_sentinels["sentinels_sha256"] = _json_value_sha256([])
            with self.assertRaisesRegex(ValueError, "sentinel"):
                execute_step7_v4(
                    empty_sentinels,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
            noncanonical = copy.deepcopy(spec)
            noncanonical["source_root"] = (
                str(Path(str(spec["source_root"])) / ".." / "source")
            )
            with self.assertRaisesRegex(ValueError, "canonical"):
                execute_step7_v4(
                    noncanonical,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )

    def test_v4_test_capability_is_opaque_scoped_and_revocable(self) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        with self.assertRaises(TypeError):
            json.dumps(capability)
        with self.assertRaises(TypeError):
            _step7_v4_issue_test_capability(Path("/private/tmp"))
        with self.assertRaisesRegex(ValueError, "issued scoped capability"):
            execute_step7_v4(
                spec,
                dry_run=True,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=object(),
            )
        original_source_root = capability.source_root
        object.__setattr__(
            capability,
            "_source_root",
            Path("/Users/moss/Desktop/sitina/source-worktree"),
        )
        try:
            with self.assertRaisesRegex(ValueError, "root binding drift"):
                execute_step7_v4(
                    spec,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
        finally:
            object.__setattr__(
                capability,
                "_source_root",
                original_source_root,
            )

        other = self._step7_v4_execution_spec()
        with self.assertRaisesRegex(ValueError, "exactly match"):
            execute_step7_v4(
                spec,
                dry_run=True,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(other),
            )

        _step7_v4_close_test_capability(capability)
        with self.assertRaisesRegex(ValueError, "unknown or expired"):
            execute_step7_v4(
                spec,
                dry_run=True,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=capability,
            )

    def test_v4_test_capability_ignores_environment_selected_temp_roots(
        self,
    ) -> None:
        with mock.patch.dict(
            "os.environ",
            {"TMPDIR": "/Users/moss/Desktop/sitina"},
        ), mock.patch.object(
            tempfile,
            "tempdir",
            "/Users/moss/Desktop/sitina",
        ):
            spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        self.assertTrue(
            capability.scope_root.is_relative_to(Path("/private/tmp"))
        )
        verified = execute_step7_v4(
            spec,
            dry_run=True,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=capability,
        )
        self.assertEqual(verified["status"], "DRY_RUN_VERIFIED")

    def test_v4_test_roots_reject_real_relatives_before_preflight(self) -> None:
        real_roots = (
            Path("/Users/moss/Desktop/sitina/source-worktree"),
            Path("/Users/moss/SitinaHub"),
            Path("/Users/moss/Desktop/sitina/output"),
            Path("/Users/moss/.codex/sessions"),
        )
        fields = (
            "source_root",
            "deployment_root",
            "allowed_backup_parent",
            "session_root",
        )
        for field, real_root in zip(fields, real_roots, strict=True):
            for replacement in (
                real_root,
                real_root.parent,
                real_root / "forbidden-child",
            ):
                with self.subTest(field=field, replacement=replacement):
                    spec = self._step7_v4_execution_spec()
                    spec[field] = str(replacement)
                    with mock.patch.object(
                        step7_gate,
                        "_step7_v4_preflight",
                        side_effect=AssertionError("preflight was reached"),
                    ), self.assertRaisesRegex(ValueError, "real Sitina root"):
                        execute_step7_v4(
                            spec,
                            dry_run=True,
                            gate_callback=lambda _: {"accepted": True},
                            _test_capability=self._step7_v4_capability(spec),
                        )
                    self.assertFalse(Path(str(spec["backup_root"])).exists())

    def test_v4_test_roots_are_pairwise_isolated_before_preflight(self) -> None:
        for field, peer in (
            ("source_root", "deployment_root"),
            ("deployment_root", "session_root"),
            ("session_root", "allowed_backup_parent"),
        ):
            with self.subTest(field=field, peer=peer):
                spec = self._step7_v4_execution_spec()
                spec[field] = str(spec[peer])
                with mock.patch.object(
                    step7_gate,
                    "_step7_v4_preflight",
                    side_effect=AssertionError("preflight was reached"),
                ), self.assertRaisesRegex(ValueError, "pairwise isolated"):
                    execute_step7_v4(
                        spec,
                        dry_run=True,
                        gate_callback=lambda _: {"accepted": True},
                        _test_capability=self._step7_v4_capability(spec),
                    )

    def test_v4_test_capability_rejects_scope_identity_replacement(self) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        moved = capability.scope_root.with_name(
            f"{capability.scope_root.name}-moved"
        )
        capability.scope_root.rename(moved)
        capability.scope_root.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(ValueError, "scope_root identity drift"):
                execute_step7_v4(
                    spec,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
        finally:
            capability.scope_root.rmdir()
            moved.rename(capability.scope_root)

    def test_v4_test_capability_rejects_child_identity_replacement(self) -> None:
        spec = self._step7_v4_execution_spec()
        capability = self._step7_v4_capability(spec)
        moved = capability.source_root.with_name("source-moved")
        capability.source_root.rename(moved)
        capability.source_root.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(ValueError, "source_root identity drift"):
                execute_step7_v4(
                    spec,
                    dry_run=True,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
        finally:
            capability.source_root.rmdir()
            moved.rename(capability.source_root)

    def test_v4_preapply_and_manifestless_residue_states_are_distinct(self) -> None:
        for failure, expected in (
            ("CREATE_BACKUP_ROOT", "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION"),
            ("CREATE_BACKUP_LAYOUT", "MANUAL_RECOVERY_REQUIRED"),
            ("RUN_CREATE_REHEARSAL", "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION"),
            ("RUN_CREATE_REHEARSAL:1", "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION"),
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                spec = self._step7_v4_execution_spec()
                result = execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at=failure,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=self._step7_v4_capability(spec),
                )
                self.assertEqual(result["status"], expected, result)
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            Path(str(spec["backup_root"])).mkdir()
            occupied = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(
                occupied["status"], "MANUAL_RECOVERY_REQUIRED", occupied
            )

    def test_v4_preapply_failure_terminals_are_classified_and_idempotent(
        self,
    ) -> None:
        steps = (
            "RUN_REPLACE_REHEARSAL",
            "RUN_CREATE_REHEARSAL",
            "RUN_REPLACE_REHEARSAL:0",
            "RUN_CREATE_REHEARSAL:1",
            "RUN_REPLACE_REHEARSAL:2",
            "RUN_CREATE_REHEARSAL:3",
            "WRITE_RECOVERY_VERIFICATION",
            "AFTER_RECOVERY_VERIFICATION_BEFORE_REHEARSAL_RESULT",
            "AFTER_REHEARSAL_RESULT_BEFORE_FIRST_INTENT",
        )
        for step in steps:
            with self.subTest(step=step):
                spec = self._step7_v4_execution_spec()
                self._append_step7_v4_operation(
                    spec, "replace-2.txt", "REPLACE"
                )
                self._append_step7_v4_operation(
                    spec, "create-2.txt", "CREATE"
                )
                capability = self._step7_v4_capability(spec)
                deployment = Path(str(spec["deployment_root"]))
                before = self._step7_v4_tree_snapshot(deployment)
                first = execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at=step,
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
                expected_classification = (
                    "COMPLETE_REHEARSAL_PREAPPLY"
                    if step
                    == "AFTER_REHEARSAL_RESULT_BEFORE_FIRST_INTENT"
                    else "PARTIAL_REHEARSAL_RESIDUE"
                )
                self.assertEqual(
                    first["status"],
                    "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION",
                    first,
                )
                self.assertEqual(
                    first["classification"], expected_classification
                )
                self.assertNotIn("failure_step", first)
                self.assertNotIn("recovery_error", first)
                self.assertEqual(
                    first["artifact_closure_sha256"],
                    _json_value_sha256(first["artifact_closure"]),
                )
                self._assert_step7_v4_checkpoint_closure(first)
                self.assertEqual(
                    self._step7_v4_tree_snapshot(deployment), before
                )
                second = recover_step7_v4_execution(
                    spec,
                    run_id=str(spec["run_id"]),
                    _test_capability=capability,
                )
                third = recover_step7_v4_execution(
                    spec,
                    run_id=str(spec["run_id"]),
                    _test_capability=capability,
                )
                self.assertEqual(second, first)
                self.assertEqual(third, first)

    def test_v4_create_move_evidence_rejects_each_field_drift(
        self,
    ) -> None:
        spec = self._step7_v4_execution_spec()
        executed = execute_step7_v4(
            spec,
            dry_run=False,
            gate_callback=lambda _: {"accepted": True},
            _test_capability=self._step7_v4_capability(spec),
        )
        self.assertEqual(executed["status"], "EXECUTED", executed)
        backup_root = Path(str(spec["backup_root"]))
        manifest_path = backup_root / "backup-manifest.json"
        _, manifest = step7_gate._step7_v4_load_manifest(
            spec, run_id=str(spec["run_id"])
        )
        rehearsal_path = backup_root / "rehearsal-result.json"
        original = rehearsal_path.read_bytes()
        create_entry = json.loads(original)["entries"][1]
        move_fields = tuple(create_entry["move"])
        for field in move_fields:
            with self.subTest(field=field):
                document = json.loads(original)
                move = document["entries"][1]["move"]
                if isinstance(move[field], bool):
                    move[field] = not move[field]
                elif isinstance(move[field], int):
                    move[field] += 1
                else:
                    move[field] = f"{move[field]}-tampered"
                rehearsal_path.write_bytes(
                    step7_gate._step7_v4_json_payload(document)
                )
                with self.assertRaisesRegex(
                    ValueError, "rehearsal entry 1 physical binding mismatch"
                ):
                    step7_gate._step7_v4_load_rehearsal(
                        backup_root,
                        manifest,
                        manifest["binding"],
                        manifest_path,
                    )
                rehearsal_path.write_bytes(original)
        document = json.loads(original)
        del document["entries"][1]["move"][move_fields[0]]
        rehearsal_path.write_bytes(
            step7_gate._step7_v4_json_payload(document)
        )
        with self.assertRaisesRegex(
            ValueError, "rehearsal entry 1 physical binding mismatch"
        ):
            step7_gate._step7_v4_load_rehearsal(
                backup_root,
                manifest,
                manifest["binding"],
                manifest_path,
            )

    def test_v4_missing_rehearsal_requires_exact_clean_preapply_state(
        self,
    ) -> None:
        clean_spec = self._step7_v4_execution_spec()
        clean_capability = self._step7_v4_capability(clean_spec)
        clean = execute_step7_v4(
            clean_spec,
            dry_run=False,
            fail_at="RUN_CREATE_REHEARSAL",
            gate_callback=lambda _: {"accepted": True},
            _test_capability=clean_capability,
        )
        self.assertEqual(
            clean["status"],
            "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION",
            clean,
        )
        clean_scope_before = self._step7_v4_tree_snapshot(
            clean_capability.scope_root
        )
        repeated = recover_step7_v4_execution(
            clean_spec,
            run_id=str(clean_spec["run_id"]),
            _test_capability=clean_capability,
        )
        self.assertEqual(
            repeated["status"],
            "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION",
            repeated,
        )
        self.assertEqual(
            self._step7_v4_tree_snapshot(clean_capability.scope_root),
            clean_scope_before,
        )

        for mutation in (
            "intent",
            "deployment",
            "terminal_result",
            "failure_checkpoint",
            "rehearsal_checkpoint",
            "source_drift",
            "backup_drift",
            "orphan_rehearsal_artifact",
        ):
            with self.subTest(mutation=mutation):
                spec = self._step7_v4_execution_spec()
                capability = self._step7_v4_capability(spec)
                stopped = execute_step7_v4(
                    spec,
                    dry_run=False,
                    fail_at="RUN_CREATE_REHEARSAL",
                    gate_callback=lambda _: {"accepted": True},
                    _test_capability=capability,
                )
                self.assertEqual(
                    stopped["status"],
                    "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION",
                    stopped,
                )
                backup_root = Path(str(spec["backup_root"]))
                manifest_path = backup_root / "backup-manifest.json"
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
                if mutation == "intent":
                    value = _step7_v4_intent(
                        manifest["binding"],
                        0,
                        spec["operations"][0],
                    )
                    (
                        backup_root / "checkpoints/intent-0000.json"
                    ).write_text(
                        json.dumps(value, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                elif mutation == "deployment":
                    replace = spec["operations"][0]
                    shutil.copy2(
                        Path(str(replace["source_path"])),
                        Path(str(replace["target_path"])),
                    )
                elif mutation == "terminal_result":
                    (backup_root / "execution-result.json").write_text(
                        "{}\n",
                        encoding="utf-8",
                    )
                elif mutation == "failure_checkpoint":
                    (backup_root / "checkpoints/failure.json").write_text(
                        json.dumps(
                            {
                                "run_id": spec["run_id"],
                                "error_type": "TestFailure",
                                "error": "preapply residue",
                            },
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                elif mutation == "rehearsal_checkpoint":
                    (
                        backup_root
                        / "checkpoints/rehearsal-0001-create.json"
                    ).write_text(
                        json.dumps(
                            {
                                "run_id": spec["run_id"],
                                "relative_path": "create.txt",
                                "move": {},
                            },
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                elif mutation == "source_drift":
                    Path(
                        str(spec["operations"][0]["source_path"])
                    ).write_text("source drift\n", encoding="utf-8")
                elif mutation == "backup_drift":
                    Path(
                        str(
                            spec["operations"][0][
                                "preimage_backup_path"
                            ]
                        )
                    ).write_text("backup drift\n", encoding="utf-8")
                else:
                    orphan = (
                        backup_root
                        / "rehearsal"
                        / "created"
                        / "create.txt"
                    )
                    orphan.write_text(
                        "orphan rehearsal\n", encoding="utf-8"
                    )
                scope_before = self._step7_v4_tree_snapshot(
                    capability.scope_root
                )
                rejected = recover_step7_v4_execution(
                    spec,
                    run_id=str(spec["run_id"]),
                    _test_capability=capability,
                )
                self.assertEqual(
                    rejected["status"], "MANUAL_RECOVERY_REQUIRED"
                )
                self.assertIsInstance(
                    rejected.get("recovery_error"), str
                )
                self.assertTrue(rejected["recovery_error"])
                self.assertEqual(
                    self._step7_v4_tree_snapshot(
                        capability.scope_root
                    ),
                    scope_before,
                )

    def test_v4_intent_covers_interruption_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            result = execute_step7_v4(
                spec,
                dry_run=False,
                fail_at="AFTER_MUTATION_BEFORE_COMMIT:0",
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(result["status"], "RECOVERED_AFTER_FAILURE", result)
            backup_root = Path(str(spec["backup_root"]))
            self.assertTrue(
                (backup_root / "checkpoints/intent-0000.json").is_file()
            )
            self.assertFalse(
                (backup_root / "checkpoints/commit-0000.json").exists()
            )
            deployment = Path(str(spec["deployment_root"]))
            self.assertEqual(
                (deployment / "replace.txt").read_text(encoding="utf-8"),
                "old replace\n",
            )
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()
            preapply = execute_step7_v4(
                spec,
                dry_run=False,
                fail_at="AFTER_INTENT:0",
                gate_callback=lambda _: {"accepted": True},
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(
                preapply["status"],
                "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION",
                preapply,
            )

    def test_v4_gate_unlisted_tree_mutation_requires_manual_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = self._step7_v4_execution_spec()

            def gate(_: object) -> dict[str, object]:
                deployment = Path(str(spec["deployment_root"]))
                (deployment / "unlisted.txt").write_text(
                    "forbidden\n", encoding="utf-8"
                )
                return {"accepted": True}

            result = execute_step7_v4(
                spec,
                dry_run=False,
                gate_callback=gate,
                _test_capability=self._step7_v4_capability(spec),
            )
            self.assertEqual(result["status"], "MANUAL_RECOVERY_REQUIRED", result)
            self.assertTrue(
                (
                    Path(str(spec["deployment_root"])) / "unlisted.txt"
                ).is_file()
            )

    def test_v4_dirfd_parent_identity_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.txt"
            source.write_text("source\n", encoding="utf-8")
            parent = root / "target"
            parent.mkdir()
            identity = _step7_v4_dir_identity(parent)
            original = root / "target-original"
            parent.rename(original)
            parent.mkdir()
            with self.assertRaisesRegex(ValueError, "parent identity drift"):
                _step7_v4_copy_exclusive(
                    source,
                    parent / "created.txt",
                    expected_parent_identity=identity,
                )
            self.assertFalse((parent / "created.txt").exists())

    def test_v4_rename_rejects_symlink_parent_dirfd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_parent = root / "real"
            real_parent.mkdir()
            source = real_parent / "source.txt"
            source.write_text("source\n", encoding="utf-8")
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(OSError):
                _step7_v4_rename_noreplace(
                    linked_parent / "source.txt",
                    real_parent / "destination.txt",
                )

    def test_v4_copy_and_replace_reject_symlink_source_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_source = root / "real-source.txt"
            real_source.write_text("same bytes\n", encoding="utf-8")
            linked_source = root / "linked-source.txt"
            linked_source.symlink_to(real_source)
            copy_destination = root / "copy.txt"
            replace_destination = root / "replace.txt"
            replace_destination.write_text("preimage\n", encoding="utf-8")
            with self.assertRaises(OSError):
                _step7_v4_copy_exclusive(linked_source, copy_destination)
            with self.assertRaises(OSError):
                _step7_v4_atomic_replace(
                    linked_source, replace_destination
                )
            self.assertFalse(copy_destination.exists())
            self.assertEqual(
                replace_destination.read_text(encoding="utf-8"),
                "preimage\n",
            )

    def test_v4_packet_plan_schema_rejects_v3(self) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        packet["schema"] = "SITINA_STEP7_DEPLOYMENT_APPROVAL_PACKET_V3"
        packet["backup_and_rollback_plan"]["schema"] = (
            "SITINA_STEP7_BACKUP_AND_ROLLBACK_PLAN_V3"
        )
        errors: list[str] = []
        _verify_backup_and_rollback_plan(
            packet["backup_and_rollback_plan"],
            approval_id=packet["approval_id"],
            packet_operations=packet["exact_file_operations"],
            source_root=self.source.resolve(),
            deployment_root=self.deployment.resolve(),
            source_state={
                "head": packet["source_binding"]["head"],
                "tree": packet["source_binding"]["tree"],
            },
            errors=errors,
        )
        self.assertTrue(any("binding mismatch" in error for error in errors))

    @staticmethod
    def _official_source_binding(root: Path) -> dict[str, object]:
        return {
            "root": str(root.resolve()),
            "head": "a" * 40,
            "tree": "b" * 40,
            "clean": True,
            "diff_check_clean": True,
            "physical_worktree": {
                "tracked_file_count": 1,
                "tree_entries_sha256": "c" * 64,
            },
        }

    def _write_official_gate_fixture(
        self,
        tree: Path,
        *,
        test_home_root: Path,
        label: str,
    ) -> dict[str, object]:
        (tree / "scripts").mkdir(parents=True)
        (tree / "tests/foundation").mkdir(parents=True)
        (tree / "config").mkdir(parents=True)
        (tree / "scripts/test-bplus.py").write_text(
            f"{label} test runner\n",
            encoding="utf-8",
        )
        (tree / "tests/foundation/activation_gate_runner.py").write_text(
            f"{label} activation\n",
            encoding="utf-8",
        )
        (
            tree / "tests/foundation/registration_gate_runner.py"
        ).write_text(
            f"{label} registration\n",
            encoding="utf-8",
        )
        shutil.copy2(
            REPOSITORY_ROOT / "requirements-bplus.lock",
            tree / "requirements-bplus.lock",
        )
        policy = {
            "schema": "SITINA_TRUE_MULTI_AGENT_POLICY_V1",
            **{field: False for field in step7_gate.SWITCHES},
        }
        (tree / "config/true_multi_agent_policy.json").write_text(
            json.dumps(policy, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        registry = {
            "schema": "BPLUS_TEST_SUITES_V1",
            "approved_python": APPROVED_PYTHON_PATH,
            "dependency_lock_sha256": sha256(
                tree / "requirements-bplus.lock"
            ),
            "test_home_root": str(test_home_root),
            "historical_skip_allowlist": [
                {
                    "test_id": test_id,
                    "reason": HISTORICAL_SKIP_REASON,
                }
                for test_id in HISTORICAL_SKIP_IDS
            ],
            "suites": {
                "execution_activation_gate": {
                    "selectors": [
                        "tests/test_execution_bridge.py"
                    ],
                    "timeout_seconds": 60,
                },
                "all_registered_unique": {
                    "selectors": [],
                    "timeout_seconds": 120,
                },
            },
        }
        (tree / "tests/test_suites.json").write_text(
            json.dumps(registry, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return registry

    def _official_capture(
        self,
        name: str,
        *,
        contract: dict[str, object],
        deployment: Path,
    ) -> tuple[dict[str, object], dict[str, object]]:
        stage = (
            "execution_activation"
            if name == "activation"
            else "all_registered_unique"
        )
        capture = copy.deepcopy(self._gate_evidence_document(stage))
        strict_field = (
            "activation_gate"
            if name == "activation"
            else "registration_gate"
        )
        strict = capture[strict_field]
        assert isinstance(strict, dict)
        selectors = list(
            contract[
                "activation_selectors"
                if name == "activation"
                else "registered_selectors"
            ]
        )
        collected = strict["collected_test_count"]
        quotient, remainder = divmod(collected, len(selectors))
        strict["selector_counts"] = {
            selector: quotient + (1 if index < remainder else 0)
            for index, selector in enumerate(selectors)
        }
        if name == "registration":
            strict["selector_count"] = len(selectors)
        capture_contract = contract["capture_suites"][name]
        capture["stage"] = capture_contract["stage"]
        capture["suite"] = capture_contract["suite"]
        capture["selectors"] = selectors
        capture["command"] = (
            [
                APPROVED_PYTHON_PATH,
                "-m",
                "tests.foundation.activation_gate_runner",
                *selectors,
            ]
            if name == "activation"
            else [
                APPROVED_PYTHON_PATH,
                "-m",
                "tests.foundation.registration_gate_runner",
                "--registry",
                contract["registry"]["path"],
            ]
        )
        capture["child_cwd"] = str(
            Path(contract["test_home_root"])
            / f"official-{name}-already-cleaned"
        )
        capture["capture_only"] = True
        locked_versions = step7_gate._locked_versions(
            deployment / "requirements-bplus.lock"
        )
        dependency = capture["dependency_gate"]
        dependency.update(
            {
                "expected_lock_sha256": contract[
                    "dependency_lock_sha256"
                ],
                "lock_sha256": contract["dependency_lock_sha256"],
                "lock_path": str(
                    deployment / "requirements-bplus.lock"
                ),
                "locked_versions": locked_versions,
                "installed_locked_versions": locked_versions,
                "locked_distribution_count": len(locked_versions),
            }
        )
        return capture, strict

    def test_v4_production_gate_contract_binds_physical_runner_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deployment = Path(directory).resolve()
            test_home_root = deployment / "test-homes"
            test_home_root.mkdir()
            self._write_official_gate_fixture(
                deployment,
                test_home_root=test_home_root,
                label="deployment",
            )
            source_binding = self._official_source_binding(deployment)
            first = _step7_v4_production_gate_contract(
                deployment,
                source_binding=source_binding,
            )
            test_runner = deployment / "scripts/test-bplus.py"
            activation = (
                deployment
                / "tests/foundation/activation_gate_runner.py"
            )
            self.assertEqual(
                first["test_runner"]["sha256"], sha256(test_runner)
            )
            self.assertEqual(
                first["source_root"], str(deployment)
            )
            self.assertEqual(
                first["runner_mode"],
                (
                    "GUARDED_DISPOSABLE_HOME_CAPTURE_ONLY_"
                    "NO_GLOBAL_EVIDENCE_V2"
                ),
            )
            self.assertEqual(
                first["activation_runner"]["sha256"], sha256(activation)
            )
            activation.write_text("changed\n", encoding="utf-8")
            second = _step7_v4_production_gate_contract(
                deployment,
                source_binding=source_binding,
            )
            self.assertNotEqual(
                first["activation_runner"]["sha256"],
                second["activation_runner"]["sha256"],
            )

    def test_v4_production_gate_contract_closes_physical_source_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            test_home_root = root / "test-homes"
            test_home_root.mkdir()
            self._write_official_gate_fixture(
                source,
                test_home_root=test_home_root,
                label="source",
            )
            subprocess.run(
                [step7_gate.GIT_EXECUTABLE_PATH, "init", "-q"],
                cwd=source,
                env=step7_gate._step7_git_environment(),
                check=True,
            )
            subprocess.run(
                [
                    step7_gate.GIT_EXECUTABLE_PATH,
                    "config",
                    "user.email",
                    "step7-tests@example.invalid",
                ],
                cwd=source,
                env=step7_gate._step7_git_environment(),
                check=True,
            )
            subprocess.run(
                [
                    step7_gate.GIT_EXECUTABLE_PATH,
                    "config",
                    "user.name",
                    "Step7 Tests",
                ],
                cwd=source,
                env=step7_gate._step7_git_environment(),
                check=True,
            )
            subprocess.run(
                [step7_gate.GIT_EXECUTABLE_PATH, "add", "."],
                cwd=source,
                env=step7_gate._step7_git_environment(),
                check=True,
            )
            subprocess.run(
                [
                    step7_gate.GIT_EXECUTABLE_PATH,
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=source,
                env=step7_gate._step7_git_environment(),
                check=True,
            )
            source_binding = step7_gate._step7_v4_git_state(source)
            contract = _step7_v4_production_gate_contract(source)
            self.assertEqual(contract["source_binding"], source_binding)
            self.assertEqual(
                set(contract["source_binding"]),
                {
                    "root",
                    "head",
                    "tree",
                    "clean",
                    "diff_check_clean",
                    "physical_worktree",
                },
            )

            for mutation in (
                lambda value: value.pop("physical_worktree"),
                lambda value: value["physical_worktree"].__setitem__(
                    "tracked_file_count", 0
                ),
                lambda value: value["physical_worktree"].__setitem__(
                    "tree_entries_sha256", "0" * 63
                ),
                lambda value: value["physical_worktree"].__setitem__(
                    "unexpected", True
                ),
            ):
                with self.subTest(mutation=mutation):
                    changed = copy.deepcopy(source_binding)
                    mutation(changed)
                    with self.assertRaisesRegex(
                        ValueError,
                        "official gate source binding is invalid",
                    ):
                        _step7_v4_production_gate_contract(
                            source,
                            source_binding=changed,
                        )

    def test_v4_production_gate_contract_binds_postimage_to_deployment_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            deployment = root / "deployment"
            test_home_root = root / "test-homes"
            test_home_root.mkdir()
            self._write_official_gate_fixture(
                source,
                test_home_root=test_home_root,
                label="source",
            )
            self._write_official_gate_fixture(
                deployment,
                test_home_root=test_home_root,
                label="deployment",
            )
            source_binding = self._official_source_binding(source)
            contract = _step7_v4_production_gate_contract(
                deployment,
                content_root=source,
                source_root=source,
                source_binding=source_binding,
            )
            self.assertEqual(contract["source_root"], str(source))
            self.assertEqual(
                contract["environment"],
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONPYCACHEPREFIX": (
                        step7_gate.STEP7_PYCACHE_PREFIX
                    ),
                    "SITINA_STEP7_OFFICIAL_GATE_CAPTURE": "1",
                    "SITINA_STEP7_SOURCE_ROOT": str(source),
                    "SITINA_STEP7_CAPTURE_READONLY_ROOTS_JSON": (
                        json.dumps(
                            contract["readonly_roots"],
                            separators=(",", ":"),
                        )
                    ),
                },
            )
            self.assertEqual(
                contract["test_runner"]["path"],
                str(deployment / "scripts/test-bplus.py"),
            )
            self.assertEqual(
                contract["test_runner"]["sha256"],
                sha256(source / "scripts/test-bplus.py"),
            )
            self.assertEqual(
                contract["activation_runner"]["path"],
                str(
                    deployment
                    / "tests/foundation/activation_gate_runner.py"
                ),
            )
            self.assertEqual(
                contract["activation_runner"]["sha256"],
                sha256(source / "tests/foundation/activation_gate_runner.py"),
            )
            self.assertNotEqual(
                contract["activation_runner"]["sha256"],
                sha256(
                    deployment
                    / "tests/foundation/activation_gate_runner.py"
                ),
            )
            self.assertFalse((deployment / ".git").exists())

    def test_v4_official_gate_uses_guarded_capture_only_runner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            deployment = root / "deployment"
            test_home_root = root / "test-homes"
            test_home_root.mkdir()
            self._write_official_gate_fixture(
                source,
                test_home_root=test_home_root,
                label="postimage",
            )
            shutil.copytree(source, deployment)
            source_binding = self._official_source_binding(source)
            contract = _step7_v4_production_gate_contract(
                deployment,
                content_root=source,
                source_root=source,
                source_binding=source_binding,
            )
            activation_capture, activation = self._official_capture(
                "activation",
                contract=contract,
                deployment=deployment,
            )
            registration_capture, registration = self._official_capture(
                "registration",
                contract=contract,
                deployment=deployment,
            )
            completed = (
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=(
                        "SITINA_ACTIVATION_GATE_JSON:"
                        + json.dumps(activation, sort_keys=True)
                        + "\n"
                        + "SITINA_BPLUS_CAPTURE_JSON:"
                        + json.dumps(
                            activation_capture,
                            sort_keys=True,
                        )
                        + "\n"
                    ),
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=(
                        "SITINA_REGISTRATION_GATE_JSON:"
                        + json.dumps(registration, sort_keys=True)
                        + "\n"
                        + "SITINA_BPLUS_CAPTURE_JSON:"
                        + json.dumps(
                            registration_capture,
                            sort_keys=True,
                        )
                        + "\n"
                    ),
                    stderr="",
                ),
            )
            backup_root = root / "backup"
            gate_evidence_root = backup_root / "official-gates"
            gate_evidence_root.mkdir(parents=True)
            gate_evidence = {
                "root": str(gate_evidence_root),
                "identity": step7_gate._step7_v4_dir_identity(
                    gate_evidence_root
                ),
            }
            with (
                mock.patch.object(
                    step7_gate,
                    "_step7_v4_git_state",
                    return_value=source_binding,
                ),
                mock.patch.object(
                    step7_gate,
                    "_step7_v4_control_inventory_outside_backup",
                    return_value={},
                ),
                mock.patch.object(
                    step7_gate.subprocess,
                    "run",
                    side_effect=completed,
                ) as run,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "deployment inventory drift",
                ):
                    step7_gate._step7_v4_run_official_gates(
                        deployment,
                        contract,
                        gate_evidence=gate_evidence,
                        expected_inventory={},
                    )
                self.assertEqual(run.call_count, 0)
                result = step7_gate._step7_v4_run_official_gates(
                    deployment,
                    contract,
                    gate_evidence=gate_evidence,
                    expected_inventory=step7_gate._step7_v4_inventory(
                        deployment
                    ),
                )
            self.assertEqual(
                result["schema"],
                "SITINA_STEP7_OFFICIAL_GATE_CAPTURE_V2",
            )
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                command = call.args[0]
                self.assertEqual(
                    command[1],
                    str(deployment / "scripts/test-bplus.py"),
                )
                self.assertIn("--capture-only", command)
                self.assertEqual(
                    call.kwargs["env"][
                        "SITINA_STEP7_OFFICIAL_GATE_CAPTURE"
                    ],
                    "1",
                )
                self.assertEqual(
                    call.kwargs["env"]["SITINA_STEP7_SOURCE_ROOT"],
                    str(source),
                )
                self.assertNotIn("PYTHONPATH", call.kwargs["env"])
            self.assertEqual(
                set(step7_gate._step7_v4_inventory(gate_evidence_root)),
                {
                    "activation.json",
                    "registration.json",
                    "manifest.json",
                },
            )
            manifest_reference = result["evidence_manifest"]
            self.assertEqual(
                manifest_reference["path"],
                str(gate_evidence_root / "manifest.json"),
            )
            self.assertEqual(
                contract["test_home_root_identity"],
                step7_gate._step7_v4_dir_identity(test_home_root),
            )
            self.assertEqual(
                step7_gate._step7_v4_inventory(test_home_root),
                {},
            )
            step7_gate._step7_v4_validate_official_gate_result(
                backup_root,
                result,
                gate_contract=contract,
            )
            manifest_path = gate_evidence_root / "manifest.json"
            tampered_manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            tampered_manifest["contract_sha256"] = "0" * 64
            manifest_path.write_text(
                json.dumps(tampered_manifest, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "success evidence binding mismatch",
            ):
                step7_gate._step7_v4_validate_official_gate_result(
                    backup_root,
                    result,
                    gate_contract=contract,
                )
            drift_root = root / "drift-backup" / "official-gates"
            drift_root.mkdir(parents=True)
            drift_evidence = {
                "root": str(drift_root),
                "identity": step7_gate._step7_v4_dir_identity(
                    drift_root
                ),
            }

            def leave_test_home_residue(
                *_args: object,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                (test_home_root / "unexpected-residue").write_text(
                    "drift\n",
                    encoding="utf-8",
                )
                return completed[0]

            with (
                mock.patch.object(
                    step7_gate,
                    "_step7_v4_git_state",
                    return_value=source_binding,
                ),
                mock.patch.object(
                    step7_gate,
                    "_step7_v4_control_inventory_outside_backup",
                    return_value={},
                ),
                mock.patch.object(
                    step7_gate.subprocess,
                    "run",
                    side_effect=leave_test_home_residue,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "test home root post-run drift",
                ),
            ):
                step7_gate._step7_v4_run_official_gates(
                    deployment,
                    contract,
                    gate_evidence=drift_evidence,
                    expected_inventory=step7_gate._step7_v4_inventory(
                        deployment
                    ),
                )
            (test_home_root / "unexpected-residue").unlink()

    def test_v4_capture_only_publish_and_marker_contracts(self) -> None:
        namespace = runpy.run_path(
            str(REPOSITORY_ROOT / "scripts/test-bplus.py"),
            run_name="step7_capture_publish_probe",
        )
        publish = namespace["_publish_result"]
        marker = namespace["CAPTURE_MARKER"]
        self.assertEqual(marker, "SITINA_BPLUS_CAPTURE_JSON:")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "aggregate.json"
            suite_root = root / "suites"
            result = {
                "schema": "BPLUS_TEST_RESULT_V2",
                "capture_only": True,
            }
            publish(
                result_path=result_path,
                suite_result_root=suite_root,
                suite="execution_activation_gate",
                result=result,
                capture_only=True,
            )
            self.assertFalse(result_path.exists())
            self.assertFalse(suite_root.exists())
            publish(
                result_path=result_path,
                suite_result_root=suite_root,
                suite="execution_activation_gate",
                result=result,
                capture_only=False,
            )
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")),
                result,
            )
            self.assertEqual(
                json.loads(
                    (
                        suite_root
                        / "execution_activation_gate.json"
                    ).read_text(encoding="utf-8")
                ),
                result,
            )
        payload = {"accepted": True}
        encoded = json.dumps(payload, sort_keys=True)
        self.assertEqual(
            step7_gate._step7_v4_parse_capture_marker(
                f"SITINA_BPLUS_CAPTURE_JSON:{encoded}\n",
                "SITINA_BPLUS_CAPTURE_JSON:",
            ),
            [payload],
        )
        self.assertEqual(
            len(
                step7_gate._step7_v4_parse_capture_marker(
                    (
                        f"SITINA_BPLUS_CAPTURE_JSON:{encoded}\n"
                        f"SITINA_BPLUS_CAPTURE_JSON:{encoded}\n"
                    ),
                    "SITINA_BPLUS_CAPTURE_JSON:",
                )
            ),
            2,
        )
        self.assertEqual(
            step7_gate._step7_v4_parse_capture_marker(
                "SITINA_BPLUS_CAPTURE_JSON:{bad json}\n",
                "SITINA_BPLUS_CAPTURE_JSON:",
            ),
            [],
        )
        for suffix in ("{bad json}", "[]"):
            with self.subTest(invalid_suffix=suffix):
                self.assertEqual(
                    step7_gate._step7_v4_parse_capture_marker(
                        (
                            f"SITINA_BPLUS_CAPTURE_JSON:{encoded}\n"
                            f"SITINA_BPLUS_CAPTURE_JSON:{suffix}\n"
                        ),
                        "SITINA_BPLUS_CAPTURE_JSON:",
                    ),
                    [],
                )
        for marker in (
            "SITINA_ACTIVATION_GATE_JSON:",
            "SITINA_REGISTRATION_GATE_JSON:",
        ):
            for suffix in ("{bad json}", "[]"):
                with self.subTest(
                    strict_marker=marker,
                    invalid_suffix=suffix,
                ):
                    self.assertEqual(
                        step7_gate._step7_v4_parse_capture_marker(
                            (
                                f"{marker}{encoded}\n"
                                f"{marker}{suffix}\n"
                            ),
                            marker,
                        ),
                        [],
                    )

    def test_v4_capture_readonly_guard_directly_denies_mutation(
        self,
    ) -> None:
        namespace = runpy.run_path(
            str(REPOSITORY_ROOT / "scripts/test-bplus.py"),
            run_name="step7_readonly_guard_probe",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            readonly_root = root / "readonly"
            guard_root = root / "guard"
            readonly_root.mkdir()
            guard_root.mkdir()
            target = readonly_root / "bound.txt"
            target.write_text("before\n", encoding="utf-8")
            (guard_root / "sitecustomize.py").write_text(
                namespace["NETWORK_GUARD"],
                encoding="utf-8",
            )
            readonly_log = root / "readonly-attempts.jsonl"
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(guard_root),
                "SITINA_EXTERNAL_ATTEMPT_LOG": str(
                    root / "external.jsonl"
                ),
                "SITINA_PRODUCTION_ATTEMPT_LOG": str(
                    root / "production.jsonl"
                ),
                "SITINA_READONLY_ATTEMPT_LOG": str(readonly_log),
                "SITINA_READONLY_ROOTS_JSON": json.dumps(
                    [str(readonly_root)],
                    separators=(",", ":"),
                ),
                "SITINA_PRODUCTION_HOME": str(
                    root / "unrelated-production"
                ),
            }
            completed = subprocess.run(
                [
                    APPROVED_PYTHON_PATH,
                    "-c",
                    (
                        "from pathlib import Path; "
                        f"Path({str(target)!r}).write_text("
                        "'after\\n', encoding='utf-8')"
                    ),
                ],
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "read-only-root mutation",
                completed.stderr,
            )
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "before\n",
            )
            records = readonly_log.read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(len(records), 1)

    def test_v4_disposable_cleanup_runs_after_child_setup_exception(
        self,
    ) -> None:
        namespace = runpy.run_path(
            str(REPOSITORY_ROOT / "scripts/test-bplus.py"),
            run_name="step7_cleanup_probe",
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "child-home"
            home.mkdir()

            class DisposableProbe:
                path = home

                def cleanup(self) -> None:
                    shutil.rmtree(self.path)

            with self.assertRaisesRegex(
                RuntimeError,
                "injected child setup failure",
            ):
                namespace["_execute_with_disposable_cleanup"](
                    DisposableProbe(),
                    lambda: (_ for _ in ()).throw(
                        RuntimeError(
                            "injected child setup failure"
                        )
                    ),
                )
            self.assertFalse(home.exists())

    def test_v4_nested_python_bytecode_is_redirected_to_disposable_home(
        self,
    ) -> None:
        runner_source = (
            REPOSITORY_ROOT / "scripts/test-bplus.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '"PYTHONPYCACHEPREFIX": str(home / ".pycache")',
            runner_source,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            core = root / "core"
            package = core / "nested_probe"
            disposable = root / "disposable"
            package.mkdir(parents=True)
            disposable.mkdir()
            (package / "__init__.py").write_text(
                "VALUE = 7\n",
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "PYTHONPATH": str(core),
                "PYTHONPYCACHEPREFIX": str(
                    disposable / ".pycache"
                ),
            }
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            completed = subprocess.run(
                [
                    APPROVED_PYTHON_PATH,
                    "-c",
                    (
                        "import nested_probe; "
                        "assert nested_probe.VALUE == 7"
                    ),
                ],
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertFalse((package / "__pycache__").exists())
            self.assertTrue(
                any(
                    path.suffix == ".pyc"
                    for path in (
                        disposable / ".pycache"
                    ).rglob("*.pyc")
                )
            )

    def test_v6_failed_official_gate_revocation_is_exact_and_fail_closed(
        self,
    ) -> None:
        source_root = REPOSITORY_ROOT
        deployment_root = Path("/Users/moss/SitinaHub")
        source_state = {
            "head": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=source_root,
                text=True,
            ).strip(),
            "tree": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=source_root,
                text=True,
            ).strip(),
        }
        artifacts = copy.deepcopy(
            step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_ARTIFACTS
        )
        recovery_artifacts = copy.deepcopy(
            step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_RECOVERY_ARTIFACTS
        )
        recovery = {
            "artifacts": recovery_artifacts,
            "status": "RECOVERED_AFTER_FAILURE",
            "backup_root_retained": True,
            "backup_root_mode": "0o700",
            "deployment_inventory_before_sha256": (
                "b77e4098d675474bed191f7693716b9e5c6740254b51ec7aac49f29eafede112"
            ),
            "deployment_inventory_after_sha256": (
                "b77e4098d675474bed191f7693716b9e5c6740254b51ec7aac49f29eafede112"
            ),
            "applied_indices": [0, 1, 2, 3, 4, 5],
            "reverse_recovery_indices": [5, 4, 3, 2, 1, 0],
            "checkpoint_references_sha256": (
                "2a848e9e8a7c00ad5f4c48c9f7d402de68d684f0872831c1b8496c6f6c4d5e29"
            ),
            "checkpoint_reference_set_sha256": (
                "92faece6f4712ee8f77a30eabbd962c0a62878c72774e3c1244b5ff24f08bfd0"
            ),
            "checkpoint_closure_sha256": (
                "15b7c8d6469b3c42b708e3bdb367f17e3162ef5a5ac63d9a37076ef113fdb917"
            ),
            "delete_operation_count": 0,
            "unlink_operation_count": 0,
            "rmtree_operation_count": 0,
        }
        reuse_fields = {
            "may_execute",
            "may_request_authorization",
            "may_reuse_approval_id",
            "may_reuse_run_id",
            "may_reuse_packet",
            "may_reuse_candidate",
            "may_reuse_evidence",
            "may_reuse_gate_results",
            "may_reuse_real_sitina_reviews",
            "may_reuse_authorization_request",
            "may_reuse_source_record",
            "may_reuse_wrapper_record",
            "may_reuse_authorization_receipt",
            "may_reuse_execution_specification",
            "may_reuse_operations_sha256",
            "may_reuse_plan_sha256",
            "may_reuse_backup_root",
            "may_reuse_manifest",
            "may_reuse_recovery_artifacts",
        }
        revocation = {
            "schema": step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_SCHEMA,
            "revoked_at_utc": "2026-07-28T11:30:00Z",
            "source_thread_id": STEP7_SOURCE_THREAD_ID,
            "decision": (
                "REJECT_DEPLOY_REQUEST_REVOKE_CONSUMED_AUTHORIZATION"
            ),
            "physical_classification": (
                "AUTHORIZED_POSTAPPLY_OFFICIAL_GATE_FAILURE_"
                "FULL_RECOVERY_RETAINED_BACKUP_ROOT"
            ),
            "revoked_approval_id": (
                step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_APPROVAL_ID
            ),
            "revoked_run_id": (
                step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_RUN_ID
            ),
            "revoked_source": {
                "root": str(source_root),
                **step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_SOURCE,
            },
            "revoked_artifacts": artifacts,
            "authorization_chain": {
                "source_record": {
                    "session_path": (
                        "/Users/moss/.codex/sessions/2026/07/20/"
                        "rollout-2026-07-20T14-42-51-"
                        "019f810d-78fe-75d2-8efd-d43fccbd82d7.jsonl"
                    ),
                    "line_number": 14699,
                    "record_id": (
                        "msg_019fa833-1028-7543-b2ec-ba058c1a29e6"
                    ),
                    "raw_record_sha256": (
                        "86ed6d9c3d4175aac140a5a067548323"
                        "ca969dffc395fbcdaadbc883594c2fed"
                    ),
                    "actual_content_sha256": (
                        "e493cdcfd66188d8997e0d2d0b0925cf"
                        "a60a933b3153eae0c216010787372a98"
                    ),
                    "actual_content_length": 667,
                    "canonical_logical_sha256": (
                        "7344060e8e65a0ff33a06399dbef2b7c"
                        "6143cb292a7891edc431a71a60f8d47b"
                    ),
                    "canonical_logical_length": 666,
                    "normalization_mode": "REMOVE_ONE_TERMINAL_LF",
                },
                "wrapper_record": {
                    "session_path": (
                        "/Users/moss/.codex/sessions/2026/07/27/"
                        "rollout-2026-07-27T01-36-47-"
                        "019fa24a-5147-7001-9788-2af4521d1ea7.jsonl"
                    ),
                    "line_number": 14808,
                    "record_id": (
                        "msg_019fa83a-05be-7430-924e-96b2f61aaaa6"
                    ),
                    "raw_record_sha256": (
                        "26b66dd55e18274982b080ded7af216ff"
                        "17e0cb17bf5564e16098106815e4ce7"
                    ),
                    "content_sha256": (
                        "ff12a9347a4b8f73505decb1fea9b4e7"
                        "77609e5ab6d5e2d90d0ccd8668b263d3"
                    ),
                },
                "receipt_physical_sha256": (
                    artifacts["authorization_receipt"]["sha256"]
                ),
                "receipt_canonical_sha256": (
                    artifacts["authorization_receipt"][
                        "canonical_sha256"
                    ]
                ),
                "consumed": True,
                "reusable": False,
            },
            "execution_attempt": {
                "run_id": (
                    step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_RUN_ID
                ),
                "backup_root": (
                    step7_gate.FAILED_OFFICIAL_GATE_REVOCATION_BACKUP_ROOT
                ),
                "old_gate_contract_sha256": (
                    "00e7ea70251e517408bcbc615a95a6ee8"
                    "9353912e0b1bc4a2d38f2b2b3dbb0bf"
                ),
                "applied_indices": [0, 1, 2, 3, 4, 5],
                "committed_indices": [0, 1, 2, 3, 4, 5],
                "failure_phase": "DEPLOYED_OFFICIAL_ACTIVATION_GATE",
                "failure_error": (
                    "official activation gate did not return one PASS "
                    "summary"
                ),
                "failure_checkpoint_sha256": (
                    recovery_artifacts["failure_checkpoint"]["sha256"]
                ),
                "formal_attempt_capture_persisted": False,
                "terminal_status": "RECOVERED_AFTER_FAILURE",
                "counted_as_pass": False,
            },
            "gate_failure": {
                "accepted": False,
                "counted_as_pass": False,
                "formal_attempt_capture_persisted": False,
                "diagnostic_classification": "EXPLORATORY_EXCLUDED",
                "collected": 144,
                "executed": 144,
                "passed": 133,
                "failures": 2,
                "errors": 24,
                "skipped": 0,
                "xfail": 0,
                "xpass": 0,
                "root_causes": [
                    "MISSING_CONTROLLED_PYTHONPATH_FOR_DEPLOYED_CORE",
                    "DEPLOYMENT_COPY_HAS_NO_GIT_METADATA",
                ],
                "diagnostic_artifacts": {
                    name: artifacts[name]
                    for name in (
                        "diagnostic_stdout",
                        "diagnostic_stderr",
                        "diagnostic_exit",
                        "diagnostic_root_record",
                    )
                },
            },
            "recovery": recovery,
            "deployment_effects": {
                "transient_applied_operation_count": 6,
                "terminal_deployment_change_count": 0,
                "production_data_change_count": 0,
                "baseline_change_count": 0,
                "canary_run_count": 0,
                "execution_switch_change_count": 0,
                "external_change_count": 0,
                "backup_root_created": True,
                "backup_root_retained": True,
                "permanent_delete_count": 0,
                "step8_step9_entered": False,
            },
            "production_state": {
                "deployment_root": str(deployment_root),
                "deployment_inventory_sha256": (
                    recovery["deployment_inventory_after_sha256"]
                ),
                "sentinels": step7_gate._step7_v4_production_sentinels(),
                "source_switches": {
                    field: False for field in step7_gate.SWITCHES
                },
                "deployment_switches": {
                    field: False for field in step7_gate.SWITCHES
                },
            },
            "reuse_policy": {
                field: False for field in reuse_fields
            },
            "successor_requirement": {
                "source_root": str(source_root),
                "head": source_state["head"],
                "tree": source_state["tree"],
                "scope": (
                    "OFFICIAL_DEPLOYED_GATE_CAPTURE_AND_"
                    "RECOVERY_CLOSURE_V2"
                ),
                "required_fixes": [
                    "GUARDED_CAPTURE_ONLY_TEST_RUNNER",
                    "DEPLOYMENT_WITHOUT_GIT_USES_BOUND_SOURCE_IDENTITY",
                    "CONTROLLED_PYTHONPATH_AND_DISPOSABLE_HOME",
                    "READONLY_SOURCE_DEPLOYMENT_AND_CONTROL_ROOTS",
                    "MANIFEST_BOUND_OFFICIAL_GATE_ATTEMPT_EVIDENCE",
                    "SUCCESS_AND_RECOVERY_DEREFERENCE_ATTEMPT_CLOSURE",
                    "MALFORMED_OR_DUPLICATE_MARKERS_FAIL_CLOSED",
                    "PROCESS_GROUP_TIMEOUT_AND_DISPOSABLE_HOME_CLEANUP",
                    "TEST_HOME_ROOT_IDENTITY_AND_INVENTORY_STABILITY",
                ],
            },
            "step8_step9_not_entered": True,
        }
        manifest_inventory = json.loads(
            Path(
                recovery_artifacts["manifest"]["path"]
            ).read_text(encoding="utf-8")
        )["deployment_inventory_before"]
        packet_document = json.loads(
            Path(artifacts["packet"]["path"]).read_text(
                encoding="utf-8"
            )
        )
        preimage_tuples = {
            operation["target_path"]: {
                "exists": (
                    operation["operation"] == "REPLACE"
                ),
                "type": (
                    "REGULAR_FILE"
                    if operation["operation"] == "REPLACE"
                    else None
                ),
                "sha256": operation["preimage_sha256"],
                "size": operation["preimage_size"],
                "mode": operation["preimage_mode"],
            }
            for operation in packet_document["exact_file_operations"]
        }
        original_inventory = step7_gate._step7_v4_inventory
        original_file_tuple = step7_gate._step7_v4_file_tuple
        original_load_json = step7_gate._load_json

        def isolated_inventory(root: Path) -> dict[str, object]:
            if Path(root) == deployment_root:
                return copy.deepcopy(manifest_inventory)
            return original_inventory(root)

        def isolated_file_tuple(path: Path) -> dict[str, object]:
            value = preimage_tuples.get(str(path))
            if value is not None:
                return copy.deepcopy(value)
            return original_file_tuple(path)

        def isolated_load_json(path: Path) -> object:
            if Path(path) in {
                source_root / "config/true_multi_agent_policy.json",
                deployment_root
                / "config/true_multi_agent_policy.json",
            }:
                return {
                    field: False for field in step7_gate.SWITCHES
                }
            return original_load_json(path)

        mutations = {
            "approval": ("revoked_approval_id", "WRONG"),
            "source record": (
                "authorization_chain.source_record.raw_record_sha256",
                "0" * 64,
            ),
            "gate counts": ("gate_failure.errors", 23),
            "recovery": (
                "recovery.checkpoint_closure_sha256",
                "0" * 64,
            ),
            "production": (
                "production_state.deployment_inventory_sha256",
                "0" * 64,
            ),
            "reuse": ("reuse_policy.may_execute", True),
        }
        with (
            mock.patch.object(
                step7_gate,
                "_step7_v4_inventory",
                side_effect=isolated_inventory,
            ),
            mock.patch.object(
                step7_gate,
                "_step7_v4_file_tuple",
                side_effect=isolated_file_tuple,
            ),
            mock.patch.object(
                step7_gate,
                "_load_json",
                side_effect=isolated_load_json,
            ),
        ):
            self.assertTrue(
                step7_gate._failed_official_gate_revocation_is_valid(
                    revocation,
                    source_root=source_root,
                    deployment_root=deployment_root,
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                )
            )
            for label, (path, value) in mutations.items():
                with self.subTest(label=label):
                    malformed = copy.deepcopy(revocation)
                    target = malformed
                    parts = path.split(".")
                    for part in parts[:-1]:
                        target = target[part]
                    target[parts[-1]] = value
                    self.assertFalse(
                        step7_gate._failed_official_gate_revocation_is_valid(
                            malformed,
                            source_root=source_root,
                            deployment_root=deployment_root,
                            source_state=source_state,
                            anchor_root=Path(
                                "/Users/moss/.codex/sessions"
                            ),
                        )
                    )

    def test_v7_ca61797_revocation_is_exact_physical_and_fail_closed(
        self,
    ) -> None:
        path = Path(
            "/Users/moss/Desktop/sitina/output/"
            "sitina-step7-deployment-packet-revocation-"
            "ca61797-v7-20260728T151500Z.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        source_state = {
            "head": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=REPOSITORY_ROOT,
                text=True,
            ).strip(),
            "tree": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=REPOSITORY_ROOT,
                text=True,
            ).strip(),
        }

        def validate(value: dict[str, object]) -> bool:
            return step7_gate._failed_ca61797_revocation_v7_is_valid(
                value,
                source_root=REPOSITORY_ROOT,
                deployment_root=Path("/Users/moss/SitinaHub"),
                source_state=source_state,
                anchor_root=Path("/Users/moss/.codex/sessions"),
            )

        self.assertTrue(validate(document))
        original_file_tuple = step7_gate._step7_v4_file_tuple
        original_inventory = step7_gate._step7_v4_inventory

        def reject_live_target(path: Path) -> dict[str, object]:
            if Path(path).is_relative_to(Path("/Users/moss/SitinaHub")):
                raise AssertionError("V7 historical validation read live target")
            return original_file_tuple(path)

        def reject_live_inventory(path: Path) -> dict[str, object]:
            if Path(path) == Path("/Users/moss/SitinaHub"):
                raise AssertionError(
                    "V7 historical validation read live inventory"
                )
            return original_inventory(path)

        with (
            mock.patch.object(
                step7_gate,
                "_step7_v4_file_tuple",
                side_effect=reject_live_target,
            ),
            mock.patch.object(
                step7_gate,
                "_step7_v4_inventory",
                side_effect=reject_live_inventory,
            ),
        ):
            self.assertTrue(validate(document))

        mutations = (
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value.__setitem__("schema", "WRONG"),
            lambda value: value.__setitem__(
                "historical_revocation_snapshot_mode", "PREIMAGE"
            ),
            lambda value: value["revoked_artifacts"]["packet"].__setitem__(
                "sha256", "0" * 64
            ),
            lambda value: value["authorization_chain"][
                "source_record"
            ].__setitem__("raw_record_sha256", "0" * 64),
            lambda value: value["active_session_prefix_anchor"][
                "accepted_prefix"
            ].__setitem__("sha256", "0" * 64),
            lambda value: value["executor_dependency_closure"].__setitem__(
                "fully_bound_before_execution", True
            ),
            lambda value: value["gate_failure"].__setitem__("failed", 1),
            lambda value: value["recovery"].__setitem__(
                "checkpoint_closure_sha256", "0" * 64
            ),
            lambda value: value["recovery"].__setitem__(
                "delete_operation_count", 1
            ),
            lambda value: value["reuse_policy"].__setitem__(
                "may_reuse_executor", True
            ),
            lambda value: value["successor_requirement"].__setitem__(
                "tree", "0" * 40
            ),
            lambda value: value.__setitem__(
                "step8_step9_not_entered", False
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(document)
                mutation(changed)
                self.assertFalse(validate(changed))

        fresh_body_semantic_mutations = (
            lambda value: value["execution_attempt"].__setitem__(
                "registration_run", True
            ),
            lambda value: value["execution_attempt"].__setitem__(
                "terminal_status", "EXECUTED"
            ),
            lambda value: value["gate_failure"].__setitem__(
                "failure_ids", []
            ),
            lambda value: value["recovery"].__setitem__(
                "status", "EXECUTED"
            ),
            lambda value: value["production_state"]["source_switches"].__setitem__(
                "tool_calls_allowed", True
            ),
            lambda value: value["deployment_effects"].__setitem__(
                "external_change_count", 1
            ),
            lambda value: value["reuse_policy"].__setitem__(
                "may_execute", True
            ),
            lambda value: value["executor_dependency_closure"].update(
                {
                    "launcher": copy.deepcopy(
                        value["executor_dependency_closure"][
                            "dynamic_template"
                        ]
                    ),
                    "dynamic_template": copy.deepcopy(
                        value["executor_dependency_closure"]["launcher"]
                    ),
                }
            ),
            lambda value: value["revoked_artifacts"].__setitem__(
                "authorization_request",
                copy.deepcopy(
                    value["revoked_artifacts"]["prior_exclusions"]
                ),
            ),
            lambda value: value["recovery"]["artifacts"].update(
                {
                    "rehearsal_result": copy.deepcopy(
                        value["recovery"]["artifacts"][
                            "recovery_verification"
                        ]
                    ),
                    "recovery_verification": copy.deepcopy(
                        value["recovery"]["artifacts"]["rehearsal_result"]
                    ),
                }
            ),
            lambda value: value["recovery"]["artifacts"].__setitem__(
                "failure_checkpoint",
                copy.deepcopy(
                    value["recovery"]["artifacts"]["rollback_intent"]
                ),
            ),
        )
        for mutation in fresh_body_semantic_mutations:
            with self.subTest(fresh_body_semantic_mutation=mutation):
                changed = copy.deepcopy(document)
                mutation(changed)
                changed_body = copy.deepcopy(changed)
                changed_body.pop("successor_requirement")
                with mock.patch.object(
                    step7_gate,
                    "CA61797_REVOCATION_BODY_SHA256",
                    _json_value_sha256(changed_body),
                ):
                    self.assertFalse(validate(changed))

    def test_v7_active_prefix_allows_tail_append_and_rejects_prefix_drift(
        self,
    ) -> None:
        original = Path(step7_gate.CA61797_REVOCATION_ACTIVE_SESSION)
        prefix_size = step7_gate.CA61797_REVOCATION_ACTIVE_PREFIX[
            "byte_length"
        ]
        with original.open("rb") as handle:
            prefix = handle.read(prefix_size)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = root / "active.jsonl"
            tail = (
                json.dumps(
                    {
                        "timestamp": "2026-07-28T16:00:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "id": "tail-only",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "append only",
                                }
                            ],
                        },
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            fixture.write_bytes(prefix + tail)
            anchor = {
                "session_path": str(fixture),
                "session_id": (
                    step7_gate.CA61797_REVOCATION_ACTIVE_SESSION_ID
                ),
                "session_meta_raw_sha256": (
                    step7_gate.CA61797_REVOCATION_ACTIVE_SESSION_META_SHA256
                ),
                "accepted_prefix": copy.deepcopy(
                    step7_gate.CA61797_REVOCATION_ACTIVE_PREFIX
                ),
                "tail_append_allowed": True,
            }
            with mock.patch.object(
                step7_gate,
                "CA61797_REVOCATION_ACTIVE_SESSION",
                str(fixture),
            ):
                accepted, _ = (
                    step7_gate._ca61797_active_session_prefix_is_valid(
                        anchor,
                        anchor_root=root,
                    )
                )
                self.assertTrue(accepted)
                fixture.write_bytes(prefix + tail.replace(b"append", b"change"))
                accepted, _ = (
                    step7_gate._ca61797_active_session_prefix_is_valid(
                        anchor,
                        anchor_root=root,
                    )
                )
                self.assertTrue(accepted)
                changed_prefix = bytearray(prefix)
                changed_prefix[1024] ^= 1
                fixture.write_bytes(bytes(changed_prefix) + tail)
                accepted, _ = (
                    step7_gate._ca61797_active_session_prefix_is_valid(
                        anchor,
                        anchor_root=root,
                    )
                )
                self.assertFalse(accepted)

    def test_v4_guarded_capture_rejects_boundary_and_dependency_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            deployment = root / "deployment"
            test_home_root = root / "test-homes"
            test_home_root.mkdir()
            self._write_official_gate_fixture(
                source,
                test_home_root=test_home_root,
                label="postimage",
            )
            shutil.copytree(source, deployment)
            source_binding = self._official_source_binding(source)
            contract = _step7_v4_production_gate_contract(
                deployment,
                content_root=source,
                source_root=source,
                source_binding=source_binding,
            )
            capture, strict = self._official_capture(
                "activation",
                contract=contract,
                deployment=deployment,
            )
            step7_gate._step7_v4_validate_official_capture(
                name="activation",
                capture=capture,
                strict=strict,
                deployment_root=deployment,
                contract=contract,
            )
            mutations = {
                "network attempt": (
                    "external_attempt_count",
                    1,
                ),
                "production sentinel": (
                    "production_sentinel_after",
                    "0" * 64,
                ),
                "uncleaned child home": (
                    "child_cwd",
                    str(deployment),
                ),
                "capture mode": (
                    "capture_only",
                    False,
                ),
                "warning": (
                    "warning_count",
                    1,
                ),
            }
            for label, (field, value) in mutations.items():
                with self.subTest(label=label):
                    malformed = copy.deepcopy(capture)
                    malformed[field] = value
                    with self.assertRaisesRegex(
                        ValueError,
                        "guarded capture mismatch",
                    ):
                        step7_gate._step7_v4_validate_official_capture(
                            name="activation",
                            capture=malformed,
                            strict=strict,
                            deployment_root=deployment,
                            contract=contract,
                        )
            malformed = copy.deepcopy(capture)
            malformed["dependency_gate"]["lock_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                ValueError,
                "guarded capture mismatch",
            ):
                step7_gate._step7_v4_validate_official_capture(
                    name="activation",
                    capture=malformed,
                    strict=strict,
                    deployment_root=deployment,
                    contract=contract,
                )

    def test_deployed_import_root_is_independent_of_bound_git_root(
        self,
    ) -> None:
        imported_gate = Path(step7_gate.__file__).resolve()
        self.assertTrue(
            imported_gate.is_relative_to(DEPLOYED_CONTENT_ROOT),
            imported_gate,
        )
        self.assertEqual(
            REPOSITORY_ROOT,
            Path(
                os.environ.get(
                    "SITINA_STEP7_SOURCE_ROOT",
                    str(DEPLOYED_CONTENT_ROOT),
                )
            ).resolve(strict=True),
        )

    def _validate(self, candidate: dict[str, object] | None = None) -> dict[str, object]:
        return validate_step7_candidate(
            candidate or self.candidate,
            source_root=self.source,
            deployment_root=self.deployment,
            _test_only_disable_committed_boundary=True,
            _test_only_collection_snapshots=self.collection_snapshots,
            _test_only_anchor_root=self.anchor_root,
        )

    def _refresh_bound_reference(
        self,
        candidate: dict[str, object],
        path: Path,
    ) -> dict[str, str]:
        reference = self._reference(path)
        for index, existing in enumerate(candidate["evidence"]):
            if existing["path"] == reference["path"]:
                candidate["evidence"][index] = copy.deepcopy(reference)
        return reference

    def assertRejected(
        self,
        candidate: dict[str, object],
        fragment: str,
    ) -> None:
        result = self._validate(candidate)
        self.assertFalse(result["accepted"])
        self.assertTrue(
            any(fragment in error for error in result["errors"]),
            result["errors"],
        )

    def test_valid_candidate_is_accepted_without_granting_step8(self) -> None:
        compile(
            self.formal_executor.read_text(encoding="utf-8"),
            str(self.formal_executor),
            "exec",
        )
        result = self._validate()
        self.assertTrue(result["accepted"], result["errors"])
        self.assertEqual(result["error_count"], 0)
        self.assertFalse(result["step8_admission_granted"])
        self.assertEqual(result["marker"], READY_MARKER)

    def test_formal_executor_is_required_in_candidate_and_full_review(
        self,
    ) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"] = [
            reference
            for reference in candidate["evidence"]
            if reference["path"] != str(self.formal_executor.resolve())
        ]
        self.assertRejected(
            candidate,
            "candidate bound evidence list omits a required JSON artifact",
        )

        input_original = self.review_input.read_text(encoding="utf-8")
        audit_original = self.audit.read_text(encoding="utf-8")
        receipt_original = self.review_receipt.read_text(encoding="utf-8")
        original_document = json.loads(input_original)
        required_identities = {
            (reference["path"], reference["sha256"])
            for reference in original_document["required_files"]
        }
        original_document["required_files"] = [
            reference
            for reference in original_document["required_files"]
            if reference["path"] != str(self.formal_executor.resolve())
        ]
        try:
            self.review_input.write_text(
                json.dumps(original_document, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.audit.write_text(
                self._audit_jsonl(
                    "STEP7_FULL_REVIEW",
                    self.review_input,
                    "agent-run-step7-full-fixture",
                ),
                encoding="utf-8",
            )
            self.review_receipt = self._audit_receipt_file(
                "review-receipt.json",
                "STEP7_FULL_REVIEW",
                self.review_input,
                self.audit,
                "agent-run-step7-full-fixture",
            )
            errors: list[str] = []
            step7_gate._verify_review(
                self._review(
                    "STEP7_FULL_REVIEW",
                    self.review_input,
                    self.audit,
                    self.review_receipt,
                    "agent-run-step7-full-fixture",
                ),
                {
                    "head": self._git("rev-parse", "HEAD^{commit}"),
                    "tree": self._git("rev-parse", "HEAD^{tree}"),
                },
                self.source.resolve(),
                self.deployment.resolve(),
                "STEP7_FULL_REVIEW",
                required_identities,
                errors,
                "Step7 Sitina review",
                self.anchor_root.resolve(),
            )
            self.assertTrue(
                any(
                    "input required-file closure mismatch" in error
                    for error in errors
                ),
                errors,
            )
        finally:
            self.review_input.write_text(input_original, encoding="utf-8")
            self.audit.write_text(audit_original, encoding="utf-8")
            self.review_receipt.write_text(
                receipt_original,
                encoding="utf-8",
            )

    def test_full_review_projection_is_required_in_bound_evidence(self) -> None:
        review_input = json.loads(
            self.review_input.read_text(encoding="utf-8")
        )
        projected = next(
            reference
            for reference in review_input["required_files"]
            if set(reference)
            == step7_gate.PROVIDER_VISIBLE_PROJECTION_REFERENCE_FIELDS
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"] = [
            reference
            for reference in candidate["evidence"]
            if (
                reference["path"],
                reference["sha256"],
            )
            != (projected["path"], projected["sha256"])
        ]
        self.assertRejected(
            candidate,
            "candidate bound evidence list omits a required JSON artifact",
        )

    def test_cleanup_projection_is_required_in_bound_evidence(self) -> None:
        review_input = json.loads(
            self.cleanup_review_input.read_text(encoding="utf-8")
        )
        projected = next(
            reference
            for reference in review_input["required_files"]
            if set(reference)
            == step7_gate.PROVIDER_VISIBLE_PROJECTION_REFERENCE_FIELDS
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"] = [
            reference
            for reference in candidate["evidence"]
            if (
                reference["path"],
                reference["sha256"],
            )
            != (projected["path"], projected["sha256"])
        ]
        self.assertRejected(
            candidate,
            "candidate bound evidence list omits a required JSON artifact",
        )

    def test_review_operations_json_value_accepts_array_and_fails_closed(
        self,
    ) -> None:
        operations = self.output / "review-operations.json"
        operations.write_text(
            json.dumps(
                [
                    {
                        "operation": "REPLACE",
                        "relative_path": "scripts/step7_readiness_gate.py",
                    }
                ],
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        entry = self._review_required_file(
            operations,
            "json_value",
            "exact deployment operations",
        )
        errors: list[str] = []
        identity = step7_gate._verify_review_required_file(
            entry,
            errors,
            "Step7 Sitina review input required file operations",
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            (
                identity["formal_path"],
                identity["formal_sha256"],
                identity["provider_path"],
            ),
            (
                str(operations.resolve()),
                sha256(operations),
                str(operations.resolve()),
            ),
        )

        operations.write_text("{invalid", encoding="utf-8")
        invalid_entry = self._review_required_file(
            operations,
            "json_value",
            "exact deployment operations",
        )
        errors = []
        step7_gate._verify_review_required_file(
            invalid_entry,
            errors,
            "Step7 Sitina review input required file operations",
        )
        self.assertTrue(
            any("is not valid JSON: JSONDecodeError" in error for error in errors),
            errors,
        )

        operations.write_text("[1, 2, 3]\n", encoding="utf-8")
        object_entry = self._review_required_file(
            operations,
            "json",
            "exact deployment operations",
        )
        errors = []
        step7_gate._verify_review_required_file(
            object_entry,
            errors,
            "Step7 Sitina review input required file operations",
        )
        self.assertTrue(
            any("is not a JSON object: ValueError" in error for error in errors),
            errors,
        )

    def test_provider_visible_projection_binds_original_identity_and_is_safe(
        self,
    ) -> None:
        safe_root = self.output / "provider-visible-positive"
        safe_root.mkdir()
        source = self.output / "provider-visible-source.json"
        source.write_text(
            json.dumps(
                {
                    "schema": "SITINA_TEST_PROVIDER_VISIBLE_SOURCE_V1",
                    "credential_note": "Bearer secret-token-value",
                    "accepted": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        purpose = "provider-visible projection contract fixture"
        reference = self._projected_review_required_file(
            source,
            source_media_type="json",
            purpose=purpose,
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        projection = Path(str(reference["path"]))
        errors: list[str] = []
        identity = step7_gate._verify_review_required_file(
            reference,
            errors,
            "Step7 provider-visible required file",
            source_root=self.source.resolve(),
            projection_root=(safe_root / "projections").resolve(),
            review_stage="STEP7_FULL_REVIEW",
            source_head=self._git("rev-parse", "HEAD^{commit}"),
            source_tree=self._git("rev-parse", "HEAD^{tree}"),
            allow_projection=True,
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            (
                identity["formal_path"],
                identity["formal_sha256"],
                identity["provider_path"],
            ),
            (
                str(source.resolve()),
                sha256(source),
                str(projection.resolve()),
            ),
        )
        redact = step7_gate._step7_projection_redaction_function(
            self.source.resolve()
        )
        projection_text = projection.read_text(encoding="utf-8")
        for boundary in ("handoff", "log"):
            sanitized = redact(
                projection_text,
                boundary=boundary,
                allowlist=(),
            )
            self.assertEqual(sanitized.redacted_paths, ())
            self.assertEqual(sanitized.value, projection_text)
        self.assertNotIn("secret-token-value", projection_text)

    def test_provider_visible_projection_fails_closed_on_each_binding_drift(
        self,
    ) -> None:
        safe_root = self.output / "provider-visible-negative"
        safe_root.mkdir()
        source = self.output / "projection-drift-source.txt"
        original_source = "api_key=secret-token-value\nStep7 evidence\n"
        source.write_text(original_source, encoding="utf-8")
        purpose = "provider-visible projection drift fixture"
        reference = self._projected_review_required_file(
            source,
            source_media_type="text",
            purpose=purpose,
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        projection = Path(str(reference["path"]))
        original_projection = projection.read_text(encoding="utf-8")

        def verify(mutated: dict[str, object]) -> list[str]:
            errors: list[str] = []
            step7_gate._verify_review_required_file(
                mutated,
                errors,
                "Step7 provider-visible required file",
                source_root=self.source.resolve(),
                projection_root=(safe_root / "projections").resolve(),
                review_stage="STEP7_FULL_REVIEW",
                source_head=self._git("rev-parse", "HEAD^{commit}"),
                source_tree=self._git("rev-parse", "HEAD^{tree}"),
                allow_projection=True,
            )
            return errors

        mutations = (
            ("source_sha256", "0" * 64),
            ("source_size", source.stat().st_size + 1),
            ("source_media_type", "json"),
            ("projection_schema", "SITINA_WRONG_PROJECTION_V1"),
            ("size", projection.stat().st_size + 1),
            ("purpose", purpose + " changed"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                mutated = dict(reference)
                mutated[field] = value
                errors = verify(mutated)
                self.assertTrue(errors, field)

        source.write_text(original_source + "drift\n", encoding="utf-8")
        errors = verify(reference)
        self.assertTrue(
            any("projection closure mismatch" in error for error in errors),
            errors,
        )
        source.write_text(original_source, encoding="utf-8")

        projection.write_text(
            original_projection.replace("Step7 evidence", "forged evidence"),
            encoding="utf-8",
        )
        forged_reference = dict(reference)
        forged_reference["sha256"] = sha256(projection)
        forged_reference["size"] = projection.stat().st_size
        errors = verify(forged_reference)
        self.assertTrue(
            any("projection closure mismatch" in error for error in errors),
            errors,
        )

    def test_review_v2_mixed_projection_binds_provider_and_source_closures(
        self,
    ) -> None:
        safe_root = self.output / "mixed-provider-review"
        safe_root.mkdir()
        direct = safe_root / "direct.txt"
        direct.write_text("plain Step7 evidence\n", encoding="utf-8")
        sensitive = safe_root / "sensitive.txt"
        sensitive.write_text(
            "api_key=secret-token-value\ncomplete Step7 evidence\n",
            encoding="utf-8",
        )
        projected = self._projected_review_required_file(
            sensitive,
            source_media_type="text",
            purpose="sensitive formal evidence",
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        required_files = [
            self._review_required_file(
                direct,
                "text",
                "direct provider-visible evidence",
            ),
            projected,
        ]
        review_input = safe_root / "input.json"
        review_input.write_text(
            json.dumps(
                self._review_input_document(
                    "STEP7_FULL_REVIEW",
                    required_files,
                    schema="SITINA_STEP7_REAL_REVIEW_INPUT_V2",
                ),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        audit = safe_root / "audit.jsonl"
        audit.write_text(
            self._audit_jsonl(
                "STEP7_FULL_REVIEW",
                review_input,
                "agent-run-step7-mixed-projection-fixture",
            ),
            encoding="utf-8",
        )
        receipt = self._audit_receipt_file(
            "mixed-projection-review-receipt.json",
            "STEP7_FULL_REVIEW",
            review_input,
            audit,
            "agent-run-step7-mixed-projection-fixture",
        )
        errors: list[str] = []
        step7_gate._verify_review(
            self._review(
                "STEP7_FULL_REVIEW",
                review_input,
                audit,
                receipt,
                "agent-run-step7-mixed-projection-fixture",
            ),
            {
                "head": self._git("rev-parse", "HEAD^{commit}"),
                "tree": self._git("rev-parse", "HEAD^{tree}"),
            },
            self.source.resolve(),
            self.deployment.resolve(),
            "STEP7_FULL_REVIEW",
            {
                (str(direct.resolve()), sha256(direct)),
                (str(sensitive.resolve()), sha256(sensitive)),
            },
            errors,
            "Step7 Sitina review",
            self.anchor_root.resolve(),
        )
        self.assertEqual(errors, [])
        result = json.loads(
            json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])[
                "response"
            ]
        )
        self.assertEqual(
            result["files_read"],
            [
                str(review_input.resolve()),
                str(direct.resolve()),
                str(projected["path"]),
            ],
        )
        self.assertEqual(
            result["source_file_closure"],
            [
                {"path": str(direct.resolve()), "sha256": sha256(direct)},
                {
                    "path": str(sensitive.resolve()),
                    "sha256": sha256(sensitive),
                },
            ],
        )
        original_records = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
        ]
        closure = copy.deepcopy(result["source_file_closure"])
        variants = {
            "missing": closure[:-1],
            "extra": [*closure, copy.deepcopy(closure[0])],
            "reordered": list(reversed(closure)),
            "path": [
                {**closure[0], "path": closure[0]["path"] + ".drift"},
                closure[1],
            ],
            "sha": [
                closure[0],
                {**closure[1], "sha256": "0" * 64},
            ],
        }
        for index, (name, mutated_closure) in enumerate(variants.items()):
            with self.subTest(source_closure=name):
                records = copy.deepcopy(original_records)
                mutated_result = copy.deepcopy(result)
                mutated_result["source_file_closure"] = mutated_closure
                response = json.dumps(
                    mutated_result,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                final_turn = next(
                    record
                    for record in reversed(records)
                    if record["event"] == "model_turn_completed"
                )
                final_turn["text"] = response
                final_turn["metadata"]["output_hash"] = (
                    "sha256:"
                    + hashlib.sha256(response.encode("utf-8")).hexdigest()
                )
                records[-1]["response"] = response
                audit.write_text(
                    "".join(
                        json.dumps(record, sort_keys=True) + "\n"
                        for record in records
                    ),
                    encoding="utf-8",
                )
                mutated_receipt = self._audit_receipt_file(
                    f"mixed-projection-closure-{index}-receipt.json",
                    "STEP7_FULL_REVIEW",
                    review_input,
                    audit,
                    "agent-run-step7-mixed-projection-fixture",
                )
                review = self._review(
                    "STEP7_FULL_REVIEW",
                    review_input,
                    audit,
                    mutated_receipt,
                    "agent-run-step7-mixed-projection-fixture",
                )
                review["output_sha256"] = hashlib.sha256(
                    response.encode("utf-8")
                ).hexdigest()
                errors = []
                step7_gate._verify_review(
                    review,
                    {
                        "head": self._git("rev-parse", "HEAD^{commit}"),
                        "tree": self._git("rev-parse", "HEAD^{tree}"),
                    },
                    self.source.resolve(),
                    self.deployment.resolve(),
                    "STEP7_FULL_REVIEW",
                    {
                        (str(direct.resolve()), sha256(direct)),
                        (str(sensitive.resolve()), sha256(sensitive)),
                    },
                    errors,
                    "Step7 Sitina review",
                    self.anchor_root.resolve(),
                )
                self.assertTrue(
                    any(
                        "no bound terminal PASS verdict" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_redaction_prone_direct_and_v1_projection_fail_closed(self) -> None:
        safe_root = self.output / "projection-version-negative"
        safe_root.mkdir()
        source = safe_root / "sensitive.txt"
        source.write_text("api_key=secret-token-value\n", encoding="utf-8")
        direct = self._review_required_file(
            source,
            "text",
            "redaction-prone direct fixture",
        )
        errors: list[str] = []
        step7_gate._verify_review_required_file(
            direct,
            errors,
            "Step7 direct required file",
            source_root=self.source.resolve(),
        )
        self.assertTrue(
            any("not boundary identity" in error for error in errors),
            errors,
        )

        projected = self._projected_review_required_file(
            source,
            source_media_type="text",
            purpose="redaction-prone projected fixture",
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        errors = []
        step7_gate._verify_review_required_file(
            projected,
            errors,
            "Step7 V1 projected required file",
            source_root=self.source.resolve(),
            projection_root=(safe_root / "projections").resolve(),
            review_stage="STEP7_FULL_REVIEW",
            source_head=self._git("rev-parse", "HEAD^{commit}"),
            source_tree=self._git("rev-parse", "HEAD^{tree}"),
            allow_projection=False,
        )
        self.assertTrue(
            any("projection binding mismatch" in error for error in errors),
            errors,
        )
        with mock.patch.object(
            step7_gate,
            "_step7_projection_redaction_function",
            side_effect=RuntimeError("redactor unavailable"),
        ):
            errors = []
            step7_gate._verify_review_required_file(
                direct,
                errors,
                "Step7 exception-safe direct required file",
                source_root=self.source.resolve(),
            )
        self.assertTrue(
            any("redaction source is unsafe: RuntimeError" in error for error in errors),
            errors,
        )

    def test_projection_transport_preserves_redacted_value_json_envelope(self) -> None:
        safe_root = self.output / "projection-tool-envelope-transport"
        safe_root.mkdir()
        source = safe_root / "redacted-quote-boundaries.txt"
        source.write_text(
            'phase_token=phase-minus1"\napi_key=secret-token-value"\n',
            encoding="utf-8",
        )
        projection = step7_gate._step7_provider_visible_projection_text(
            source.resolve(),
            source_media_type="text",
            purpose="serialized tool-envelope quote regression",
            source_root=self.source.resolve(),
            review_stage="STEP7_FULL_REVIEW",
            source_head=self._git("rev-parse", "HEAD^{commit}"),
            source_tree=self._git("rev-parse", "HEAD^{tree}"),
        )
        raw_header, payload = projection.split("\n", 1)
        header = json.loads(raw_header)
        self.assertEqual(
            header["transform"]["algorithm"],
            step7_gate.PROVIDER_VISIBLE_PROJECTION_ALGORITHM,
        )
        self.assertEqual(
            header["transform"][
                "tool_envelope_value_neutralization_count"
            ],
            2,
        )
        self.assertIn('phase_token=<redacted> "', payload)
        self.assertIn('api_key=<redacted> "', payload)
        self.assertNotIn("phase-minus1", payload)
        self.assertNotIn("secret-token-value", payload)

        redact = step7_gate._step7_projection_redaction_function(
            self.source.resolve()
        )
        envelope = json.dumps(
            {
                "schema": "SITINA_UNTRUSTED_TOOL_DATA_V1",
                "source": "tool",
                "trust": "untrusted-data",
                "can_grant_permissions": False,
                "can_override_instructions": False,
                "status": "ok",
                "tool": "sitina_read_file",
                "result": projection,
                "redacted_paths": [],
            },
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        for boundary in ("handoff", "log"):
            observed = redact(envelope, boundary=boundary, allowlist=())
            self.assertEqual(observed.redacted_paths, ())
            self.assertEqual(observed.value, envelope)
            self.assertEqual(json.loads(observed.value)["result"], projection)

        self.assertFalse(
            step7_gate._step7_projection_boundary_identity(
                'phase_token=<redacted>"',
                redact=redact,
            )
        )

    def test_projection_transport_value_spacer_removal_fails_closed(self) -> None:
        safe_root = self.output / "projection-tool-envelope-negative"
        safe_root.mkdir()
        source = safe_root / "redacted-quote-boundary.txt"
        source.write_text(
            'api_key=secret-token-value"\n',
            encoding="utf-8",
        )
        reference = self._projected_review_required_file(
            source,
            source_media_type="text",
            purpose="serialized tool-envelope negative regression",
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        projection = Path(str(reference["path"]))
        text = projection.read_text(encoding="utf-8")
        self.assertIn('api_key=<redacted> "', text)
        projection.write_text(
            text.replace('api_key=<redacted> "', 'api_key=<redacted>"'),
            encoding="utf-8",
        )
        mutated = dict(reference)
        mutated["sha256"] = sha256(projection)
        mutated["size"] = projection.stat().st_size
        errors: list[str] = []
        step7_gate._verify_review_required_file(
            mutated,
            errors,
            "Step7 quote-spacer mutated projection",
            source_root=self.source.resolve(),
            projection_root=(safe_root / "projections").resolve(),
            review_stage="STEP7_FULL_REVIEW",
            source_head=self._git("rev-parse", "HEAD^{commit}"),
            source_tree=self._git("rev-parse", "HEAD^{tree}"),
            allow_projection=True,
        )
        self.assertTrue(
            any("projection closure mismatch" in error for error in errors),
            errors,
        )

    def test_projection_wrong_root_and_symlink_fail_closed(self) -> None:
        safe_root = self.output / "projection-path-negative"
        safe_root.mkdir()
        source = safe_root / "sensitive.txt"
        source.write_text("api_key=secret-token-value\n", encoding="utf-8")
        reference = self._projected_review_required_file(
            source,
            source_media_type="text",
            purpose="projection path safety fixture",
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        projection = Path(str(reference["path"]))

        def verify(value: dict[str, object]) -> list[str]:
            errors: list[str] = []
            step7_gate._verify_review_required_file(
                value,
                errors,
                "Step7 path-safe projected required file",
                source_root=self.source.resolve(),
                projection_root=(safe_root / "projections").resolve(),
                review_stage="STEP7_FULL_REVIEW",
                source_head=self._git("rev-parse", "HEAD^{commit}"),
                source_tree=self._git("rev-parse", "HEAD^{tree}"),
                allow_projection=True,
            )
            return errors

        other_root = safe_root / "other"
        other_root.mkdir()
        outside = other_root / "projection.txt"
        shutil.copy2(projection, outside)
        outside_reference = dict(reference)
        outside_reference["path"] = str(outside.resolve())
        outside_reference["sha256"] = sha256(outside)
        outside_reference["size"] = outside.stat().st_size
        self.assertTrue(
            any("projection root mismatch" in error for error in verify(outside_reference))
        )

        link = safe_root / "projections" / "symlink.txt"
        link.symlink_to(projection)
        symlink_reference = dict(reference)
        symlink_reference["path"] = str(link)
        self.assertTrue(
            any(
                "regular non-symlink" in error
                for error in verify(symlink_reference)
            )
        )

    def test_projection_and_direct_validation_use_one_stable_capture(self) -> None:
        safe_root = self.output / "projection-single-capture"
        safe_root.mkdir()
        source = safe_root / "sensitive.txt"
        source.write_text("api_key=secret-token-value\n", encoding="utf-8")
        projected = self._projected_review_required_file(
            source,
            source_media_type="text",
            purpose="single-capture projection fixture",
            safe_root=safe_root,
            review_stage="STEP7_FULL_REVIEW",
        )
        real_capture = step7_gate._step7_provider_visible_source_text
        with mock.patch.object(
            step7_gate,
            "_step7_provider_visible_source_text",
            wraps=real_capture,
        ) as capture:
            errors: list[str] = []
            step7_gate._verify_review_required_file(
                projected,
                errors,
                "Step7 single-capture projected required file",
                source_root=self.source.resolve(),
                projection_root=(safe_root / "projections").resolve(),
                review_stage="STEP7_FULL_REVIEW",
                source_head=self._git("rev-parse", "HEAD^{commit}"),
                source_tree=self._git("rev-parse", "HEAD^{tree}"),
                allow_projection=True,
            )
        self.assertEqual(errors, [])
        self.assertEqual(capture.call_count, 1)

        direct_source = safe_root / "direct.txt"
        direct_source.write_text("plain Step7 evidence\n", encoding="utf-8")
        direct = self._review_required_file(
            direct_source,
            "text",
            "single-capture direct fixture",
        )
        with mock.patch.object(
            step7_gate,
            "_step7_provider_visible_source_text",
            wraps=real_capture,
        ) as capture:
            errors = []
            step7_gate._verify_review_required_file(
                direct,
                errors,
                "Step7 single-capture direct required file",
                source_root=self.source.resolve(),
            )
        self.assertEqual(errors, [])
        self.assertEqual(capture.call_count, 1)

    def test_projection_redactor_load_uses_nofollow_source_snapshot(self) -> None:
        source_root = (self.output / "redactor-race-source").resolve()
        module_path = source_root / "core/sitina/security/redaction.py"
        module_path.parent.mkdir(parents=True)
        shutil.copy2(
            REPOSITORY_ROOT / "core/sitina/security/redaction.py",
            module_path,
        )
        external = self.output / "swapped-external-redaction.py"
        external.write_text(
            "def redact_boundary_value(value, *, boundary, allowlist=()):\n"
            "    raise RuntimeError('SWAPPED_EXTERNAL')\n",
            encoding="utf-8",
        )
        real_read = step7_gate._step7_v4_read_regular

        def capture_then_swap(path: Path) -> tuple[bytes, os.stat_result]:
            raw, metadata = real_read(path)
            if path == module_path:
                path.unlink()
                path.symlink_to(external)
            return raw, metadata

        with mock.patch.object(
            step7_gate,
            "_step7_v4_read_regular",
            side_effect=capture_then_swap,
        ):
            redact = step7_gate._step7_projection_redaction_function(
                source_root
            )
        result = redact(
            "api_key=secret-token-value",
            boundary="handoff",
            allowlist=(),
        )
        self.assertTrue(module_path.is_symlink())
        self.assertNotEqual(result.value, "SWAPPED_EXTERNAL")
        self.assertTrue(result.redacted_paths)

        unsafe_root = (self.output / "redactor-preexisting-symlink").resolve()
        unsafe_module = unsafe_root / "core/sitina/security/redaction.py"
        unsafe_module.parent.mkdir(parents=True)
        unsafe_module.symlink_to(external)
        with self.assertRaises((OSError, ValueError)):
            step7_gate._step7_projection_redaction_function(unsafe_root)

    def test_projection_missing_or_symlink_root_fails_closed(self) -> None:
        safe_root = self.output / "projection-root-negative"
        safe_root.mkdir()
        source = safe_root / "sensitive.txt"
        source.write_text("api_key=secret-token-value\n", encoding="utf-8")
        source_head = self._git("rev-parse", "HEAD^{commit}")
        source_tree = self._git("rev-parse", "HEAD^{tree}")
        projection_text = step7_gate._step7_provider_visible_projection_text(
            source.resolve(),
            source_media_type="text",
            purpose="projection root safety fixture",
            source_root=self.source.resolve(),
            review_stage="STEP7_FULL_REVIEW",
            source_head=source_head,
            source_tree=source_tree,
        )
        physical_root = safe_root / "physical-projections"
        physical_root.mkdir()
        projection = physical_root / "projection.txt"
        projection.write_text(projection_text, encoding="utf-8")
        reference = {
            "path": str(projection.resolve()),
            "sha256": sha256(projection),
            "size": projection.stat().st_size,
            "media_type": "text",
            "purpose": "projection root safety fixture",
            "source_path": str(source.resolve()),
            "source_sha256": sha256(source),
            "source_size": source.stat().st_size,
            "source_media_type": "text",
            "projection_schema": (
                step7_gate.PROVIDER_VISIBLE_PROJECTION_SCHEMA
            ),
        }

        for expected_root in (
            safe_root / "missing-projections",
            safe_root / "projections",
        ):
            if expected_root.name == "projections":
                expected_root.symlink_to(physical_root, target_is_directory=True)
            with self.subTest(root=expected_root.name):
                errors: list[str] = []
                step7_gate._verify_review_required_file(
                    reference,
                    errors,
                    "Step7 root-safe projected required file",
                    source_root=self.source.resolve(),
                    projection_root=expected_root,
                    review_stage="STEP7_FULL_REVIEW",
                    source_head=source_head,
                    source_tree=source_tree,
                    allow_projection=True,
                )
                self.assertTrue(
                    any("projection root is unsafe" in error for error in errors),
                    errors,
                )

    def test_review_v2_exact_33_12_21_provider_closure_counts(self) -> None:
        safe_root = self.output / "projection-exact-counts"
        safe_root.mkdir()
        references: list[dict[str, object]] = []
        for index in range(12):
            direct = safe_root / f"direct-{index}.txt"
            direct.write_text(
                f"plain Step7 evidence item {index}\n",
                encoding="utf-8",
            )
            references.append(
                self._review_required_file(
                    direct,
                    "text",
                    f"direct evidence item {index}",
                )
            )
        for index in range(21):
            sensitive = safe_root / f"sensitive-{index}.txt"
            sensitive.write_text(
                f"api_key=secret-value-{index}\nStep7 evidence\n",
                encoding="utf-8",
            )
            references.append(
                self._projected_review_required_file(
                    sensitive,
                    source_media_type="text",
                    purpose=f"projected evidence item {index}",
                    safe_root=safe_root,
                    review_stage="STEP7_FULL_REVIEW",
                )
            )
        bindings: list[dict[str, object]] = []
        errors: list[str] = []
        for index, reference in enumerate(references):
            binding = step7_gate._verify_review_required_file(
                reference,
                errors,
                f"Step7 exact-count required file {index}",
                source_root=self.source.resolve(),
                projection_root=(safe_root / "projections").resolve(),
                review_stage="STEP7_FULL_REVIEW",
                source_head=self._git("rev-parse", "HEAD^{commit}"),
                source_tree=self._git("rev-parse", "HEAD^{tree}"),
                allow_projection=True,
            )
            self.assertIsNotNone(binding)
            bindings.append(binding)
        self.assertEqual(errors, [])
        formal = {
            (binding["formal_path"], binding["formal_sha256"])
            for binding in bindings
        }
        provider = {
            (binding["provider_path"], binding["provider_sha256"])
            for binding in bindings
        }
        self.assertEqual(len(bindings), 33)
        self.assertEqual(len(formal), 33)
        self.assertEqual(len(provider), 33)
        self.assertEqual(
            sum(binding["projected"] is False for binding in bindings),
            12,
        )
        self.assertEqual(
            sum(binding["projected"] is True for binding in bindings),
            21,
        )
        self.assertEqual(1 + len(provider), 34)

    def test_same_path_fresh_hash_noop_executor_is_rejected(self) -> None:
        executor_original = self.formal_executor.read_text(encoding="utf-8")
        static_original = self.general_evidence.read_text(encoding="utf-8")
        bundle_original = self.rollback_request_evidence.read_text(
            encoding="utf-8"
        )
        request_original = self.rollback_review_candidate.read_text(
            encoding="utf-8"
        )
        try:
            self.formal_executor.write_text(
                "#!/usr/bin/env python3\n"
                "def main() -> int:\n"
                "    return 0\n",
                encoding="utf-8",
            )
            static_document = json.loads(static_original)
            static_document["formal_executor"]["executor"] = self._reference(
                self.formal_executor
            )
            self.general_evidence.write_text(
                json.dumps(static_document, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            bundle = json.loads(bundle_original)
            bundle["evidence"]["static_integrity"] = self._reference(
                self.general_evidence
            )
            self.rollback_request_evidence.write_text(
                json.dumps(bundle, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            request = json.loads(request_original)
            request["evidence_bundle"] = self._reference(
                self.rollback_request_evidence
            )
            self.rollback_review_candidate.write_text(
                json.dumps(request, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["deployment_request_supporting_evidence"][
                "static_integrity"
            ] = self._reference(self.general_evidence)
            self._refresh_bound_reference(candidate, self.formal_executor)
            self._refresh_bound_reference(candidate, self.general_evidence)
            self._refresh_bound_reference(
                candidate,
                self.rollback_request_evidence,
            )
            candidate["rollback_proof"]["deployment_request_candidate"] = (
                self._refresh_bound_reference(
                    candidate,
                    self.rollback_review_candidate,
                )
            )
            self.assertRejected(
                candidate,
                "deployment request formal executor binding mismatch",
            )
        finally:
            self.formal_executor.write_text(
                executor_original,
                encoding="utf-8",
            )
            self.general_evidence.write_text(
                static_original,
                encoding="utf-8",
            )
            self.rollback_request_evidence.write_text(
                bundle_original,
                encoding="utf-8",
            )
            self.rollback_review_candidate.write_text(
                request_original,
                encoding="utf-8",
            )

    def test_formal_executor_requires_bound_isolated_python_before_imports(
        self,
    ) -> None:
        shadow = self.formal_executor.parent / "hashlib.py"
        marker = self.formal_executor.parent / "shadow-imported.txt"
        symlink = self.formal_executor.parent / "executor-symlink.py"
        shadow.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n",
            encoding="utf-8",
        )
        try:
            ordinary = subprocess.run(
                [APPROVED_PYTHON_PATH, str(self.formal_executor.resolve())],
                cwd=self.formal_executor.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(ordinary.returncode, 0)
            self.assertFalse(marker.exists())
            isolated = subprocess.run(
                [
                    APPROVED_PYTHON_PATH,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={step7_gate.STEP7_PYCACHE_PREFIX}",
                    str(self.formal_executor.resolve()),
                ],
                cwd=self.formal_executor.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(isolated.returncode, 0)
            self.assertFalse(marker.exists())
            symlink.symlink_to(self.formal_executor.resolve())
            symlink_launch = subprocess.run(
                [
                    APPROVED_PYTHON_PATH,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={step7_gate.STEP7_PYCACHE_PREFIX}",
                    str(symlink),
                ],
                cwd=self.formal_executor.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(symlink_launch.returncode, 0)
            self.assertIn(
                "exact non-symlink launch path",
                symlink_launch.stderr,
            )
        finally:
            shadow.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            symlink.unlink(missing_ok=True)

    def test_formal_executor_receipt_contract_keeps_inline_receipt_and_fails_closed(
        self,
    ) -> None:
        source = self.formal_executor.read_text(encoding="utf-8")
        receipt_load = source.index(
            "receipt, _, receipt_sha256 = read_json(receipt_path)"
        )
        receipt_verification = source.index(
            "    verify_authorization_receipt_contract(\n"
            "        specification,",
            receipt_load,
        )
        execution = source.index(
            "gate.execute_step7_v4(specification, dry_run=False)"
        )
        self.assertLess(receipt_load, receipt_verification)
        self.assertLess(receipt_verification, execution)
        self.assertIn(
            'specification.get("authorization_receipt_file", {}).get("path")',
            source,
        )
        self.assertNotIn(
            'specification.get("authorization_receipt", {}).get("path")',
            source,
        )
        parsed = ast.parse(source, filename=str(self.formal_executor))
        selected = [
            node
            for node in parsed.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            or (
                isinstance(node, ast.FunctionDef)
                and node.name
                in {
                    "value_sha256",
                    "require",
                    "verify_authorization_receipt_contract",
                }
            )
        ]
        namespace: dict[str, object] = {}
        exec(
            compile(
                ast.Module(body=selected, type_ignores=[]),
                str(self.formal_executor),
                "exec",
            ),
            namespace,
        )
        verify = namespace["verify_authorization_receipt_contract"]
        receipt_path = Path(
            self.formal_executor_binding["authorization_receipt_path"]
        )
        receipt = {
            "schema": "SITINA_CODEX_USER_AUTHORIZATION_RECEIPT_V3",
            "author": "user",
            "marker": DEPLOYMENT_DELEGATION_MARKER,
        }
        physical_sha256 = "1" * 64
        specification = {
            "authorization_receipt": copy.deepcopy(receipt),
            "authorization_receipt_file": {
                "path": str(receipt_path),
                "sha256": physical_sha256,
            },
            "authorization_receipt_sha256": _json_value_sha256(receipt),
        }

        verify(
            specification,
            receipt,
            receipt_path,
            physical_sha256,
        )

        old_contradictory_specification = copy.deepcopy(specification)
        old_contradictory_specification["authorization_receipt"] = (
            old_contradictory_specification.pop("authorization_receipt_file")
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "authorization receipt file binding drift",
        ):
            verify(
                old_contradictory_specification,
                receipt,
                receipt_path,
                physical_sha256,
            )

        tampered_specifications = []
        tampered_file_path = copy.deepcopy(specification)
        tampered_file_path["authorization_receipt_file"]["path"] += ".drift"
        tampered_specifications.append(
            (tampered_file_path, "authorization receipt file binding drift")
        )
        tampered_file_sha = copy.deepcopy(specification)
        tampered_file_sha["authorization_receipt_file"]["sha256"] = "2" * 64
        tampered_specifications.append(
            (tampered_file_sha, "authorization receipt file binding drift")
        )
        tampered_inline = copy.deepcopy(specification)
        tampered_inline["authorization_receipt"]["author"] = "assistant"
        tampered_specifications.append(
            (tampered_inline, "authorization receipt inline binding drift")
        )
        tampered_canonical = copy.deepcopy(specification)
        tampered_canonical["authorization_receipt_sha256"] = "3" * 64
        tampered_specifications.append(
            (
                tampered_canonical,
                "authorization receipt canonical binding drift",
            )
        )
        for tampered, error in tampered_specifications:
            with self.subTest(error=error), self.assertRaisesRegex(
                RuntimeError,
                error,
            ):
                verify(
                    tampered,
                    receipt,
                    receipt_path,
                    physical_sha256,
                )

    def test_v4_production_receipt_file_is_exact_and_fails_closed(
        self,
    ) -> None:
        receipt = {
            "schema": "SITINA_CODEX_USER_AUTHORIZATION_RECEIPT_V3",
            "author": "user",
            "marker": DEPLOYMENT_DELEGATION_MARKER,
        }
        source_head = "a" * 40
        artifact_version = "20260724T000000Z"
        approval_id = (
            f"SITINA_STEP7_DEPLOY_AAAAAAA_6F_{artifact_version}"
        )
        receipt_path = (
            self.output
            / (
                "sitina-step7-authorization-receipt-aaaaaaa-"
                f"{artifact_version}.json"
            )
        ).resolve()
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        reference = self._reference(receipt_path)
        binding = {
            "allowed_backup_parent": str(self.output.resolve()),
            "source_head": source_head,
            "approval_id": approval_id,
            "authorization_receipt_path": str(receipt_path),
            "authorization_receipt_sha256": _json_value_sha256(receipt),
        }
        specification = {
            "authorization_receipt": copy.deepcopy(receipt),
            "authorization_receipt_file": reference,
        }
        self.assertEqual(
            step7_gate._step7_v4_verify_authorization_receipt_file(
                specification,
                binding,
            ),
            receipt,
        )

        malformed_cases = (
            {},
            {
                "authorization_receipt_file": {
                    "path": str(receipt_path),
                },
            },
        )
        for malformed in malformed_cases:
            with self.subTest(malformed=malformed), self.assertRaisesRegex(
                ValueError,
                "authorization receipt file reference is malformed",
            ):
                step7_gate._step7_v4_verify_authorization_receipt_file(
                    malformed,
                    binding,
                )

        wrong_path = copy.deepcopy(specification)
        wrong_path["authorization_receipt_file"]["path"] += ".drift"
        with self.assertRaisesRegex(
            ValueError,
            "authorization receipt file path mismatch",
        ):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                wrong_path,
                binding,
            )

        unversioned_path = copy.deepcopy(specification)
        unversioned_path["authorization_receipt_file"]["path"] = str(
            self.output.resolve()
            / "sitina-step7-authorization-receipt-aaaaaaa.json"
        )
        with self.assertRaisesRegex(
            ValueError,
            "authorization receipt file path mismatch",
        ):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                unversioned_path,
                binding,
            )

        wrong_approval = copy.deepcopy(binding)
        wrong_approval["approval_id"] = (
            "SITINA_STEP7_DEPLOY_BBBBBBB_6F_20260724T000000Z"
        )
        with self.assertRaisesRegex(
            ValueError,
            "authorization receipt file path mismatch",
        ):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                specification,
                wrong_approval,
            )

        wrong_physical_sha = copy.deepcopy(specification)
        wrong_physical_sha["authorization_receipt_file"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(
            ValueError,
            "authorization receipt file reference SHA-256 mismatch",
        ):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                wrong_physical_sha,
                binding,
            )

        wrong_inline = copy.deepcopy(specification)
        wrong_inline["authorization_receipt"]["author"] = "assistant"
        with self.assertRaisesRegex(
            ValueError,
            "authorization receipt inline binding mismatch",
        ):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                wrong_inline,
                binding,
            )

        wrong_canonical_binding = copy.deepcopy(binding)
        wrong_canonical_binding["authorization_receipt_sha256"] = "c" * 64
        with self.assertRaisesRegex(
            ValueError,
            "authorization receipt canonical binding mismatch",
        ):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                specification,
                wrong_canonical_binding,
            )

        symlink_target = self.output / "receipt-symlink-target.json"
        receipt_path.replace(symlink_target)
        receipt_path.symlink_to(symlink_target)
        symlink_specification = copy.deepcopy(specification)
        symlink_specification["authorization_receipt_file"]["sha256"] = (
            sha256(symlink_target)
        )
        with self.assertRaises((OSError, ValueError)):
            step7_gate._step7_v4_verify_authorization_receipt_file(
                symlink_specification,
                binding,
            )

    def test_formal_executor_artifact_version_binds_approval_and_source(
        self,
    ) -> None:
        source_head = self.formal_executor_binding["source_head"]
        approval_id = self.formal_executor_binding["approval_id"]
        expected_version = self.rollback_artifact_version
        self.assertEqual(
            step7_gate._step7_approval_artifact_version(
                approval_id,
                source_head,
            ),
            expected_version,
        )
        self.assertEqual(
            self.formal_executor.name,
            (
                f"step7-{source_head[:7]}-authorized-execution-"
                f"{expected_version}.py"
            ),
        )
        self.assertTrue(
            self.formal_executor_binding[
                "authorization_receipt_path"
            ].endswith(
                f"-{source_head[:7]}-{expected_version}.json"
            )
        )
        self.assertTrue(
            self.formal_executor_binding[
                "execution_specification_path"
            ].endswith(
                f"-{source_head[:7]}-{expected_version}.json"
            )
        )
        invalid = (
            ("SITINA_STEP7_DEPLOY_TEST_FIXTURE", source_head),
            (
                "SITINA_STEP7_DEPLOY_BBBBBBB_6F_20260724T000000Z",
                source_head,
            ),
            (approval_id, "b" * 40),
            (
                f"SITINA_STEP7_DEPLOY_{source_head[:7].upper()}_6F_"
                "20260724T000000",
                source_head,
            ),
        )
        for candidate_approval, candidate_head in invalid:
            with self.subTest(
                approval_id=candidate_approval,
                source_head=candidate_head,
            ):
                self.assertIsNone(
                    step7_gate._step7_approval_artifact_version(
                        candidate_approval,
                        candidate_head,
                    )
                )

    def test_formal_executor_rejects_path_shadowed_git(self) -> None:
        fake_bin = self.output / "fake-bin"
        fake_bin.mkdir()
        marker = fake_bin / "fake-git-executed.txt"
        fake_git = fake_bin / "git"
        fake_git.write_text(
            "#!/bin/sh\n"
            f"printf executed > {str(marker)!r}\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        operations_path = Path(
            self.formal_executor_binding["operations_path"]
        )
        packet = json.loads(
            self.rollback_packet.read_text(encoding="utf-8")
        )
        operations_path.write_text(
            json.dumps(
                packet["exact_file_operations"],
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            environment = dict(os.environ)
            environment["PATH"] = (
                str(fake_bin) + os.pathsep + environment.get("PATH", "")
            )
            completed = subprocess.run(
                [
                    APPROVED_PYTHON_PATH,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={step7_gate.STEP7_PYCACHE_PREFIX}",
                    str(self.formal_executor.resolve()),
                ],
                cwd=self.formal_executor.parent,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertIn(
                Path(
                    self.formal_executor_binding[
                        "execution_specification_path"
                    ]
                ).name,
                completed.stderr,
            )
        finally:
            operations_path.unlink(missing_ok=True)
            fake_git.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
            fake_bin.rmdir()

    def test_git_attestation_disables_local_fsmonitor_hook(self) -> None:
        local_config = self.source / ".git" / "config"
        config_original = local_config.read_bytes()
        expected_head = self._git("rev-parse", "HEAD^{commit}")
        hook = self.output / "malicious-fsmonitor.sh"
        marker = self.output / "fsmonitor-executed.txt"
        hook.write_text(
            "#!/bin/sh\n"
            f"printf executed > {str(marker)!r}\n"
            "exit 0\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        try:
            subprocess.run(
                [
                    step7_gate.GIT_EXECUTABLE_PATH,
                    "config",
                    "--local",
                    "core.fsmonitor",
                    str(hook),
                ],
                cwd=self.source,
                env=step7_gate._step7_git_environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            state = step7_gate._step7_v4_git_state(self.source)
            self.assertEqual(state["head"], expected_head)
            self.assertFalse(marker.exists())
            result = self._validate()
            self.assertTrue(result["accepted"], result["errors"])
            self.assertFalse(marker.exists())
            subprocess.run(
                [
                    step7_gate.GIT_EXECUTABLE_PATH,
                    "config",
                    "--local",
                    "filter.pwn.clean",
                    str(hook),
                ],
                cwd=self.source,
                env=step7_gate._step7_git_environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            attributes = self.source / ".gitattributes"
            attributes.write_text(
                "tracked.txt filter=pwn\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "untracked source file",
            ):
                step7_gate._step7_v4_git_state(self.source)
            self.assertFalse(marker.exists())
            attributes.unlink()
            info_attributes = self.source / ".git" / "info" / "attributes"
            info_attributes.write_text(
                "tracked.txt filter=pwn\n",
                encoding="utf-8",
            )
            state = step7_gate._step7_v4_git_state(self.source)
            self.assertEqual(state["head"], expected_head)
            self.assertFalse(marker.exists())
            result = self._validate()
            self.assertTrue(result["accepted"], result["errors"])
            self.assertFalse(marker.exists())
        finally:
            local_config.write_bytes(config_original)
            (self.source / ".gitattributes").unlink(missing_ok=True)
            (self.source / ".git" / "info" / "attributes").unlink(
                missing_ok=True
            )
            hook.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)

    def test_wrong_schema_or_marker_is_rejected(self) -> None:
        for field, value, fragment in (
            ("schema", "OLD_STEP7", "schema"),
            ("marker", "SITINA_STEP8_CANARY", "marker"),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate[field] = value
                self.assertRejected(candidate, fragment)

    def test_wrong_entry_candidate_hash_or_formal_status_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["step56_entry_candidate"]["sha256"] = "0" * 64
        self.assertRejected(candidate, "Step5/6 entry candidate")
        candidate = copy.deepcopy(self.candidate)
        candidate["step5_step6_formally_accepted"] = False
        self.assertRejected(candidate, "formal Step5/6")

    def test_stale_head_or_tree_is_rejected(self) -> None:
        for field, fragment in (("head", "HEAD"), ("tree", "tree")):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["source"][field] = "0" * 40
                self.assertRejected(candidate, fragment)

    def test_dirty_worktree_is_rejected(self) -> None:
        (self.source / "tracked.txt").write_text("dirty\n", encoding="utf-8")
        self.assertRejected(self.candidate, "not clean")

    def test_hardlinked_tracked_source_is_rejected(self) -> None:
        alias = self.output / "tracked-hardlink-alias.txt"
        os.link(self.source / "tracked.txt", alias)
        try:
            self.assertRejected(self.candidate, "not clean")
        finally:
            alias.unlink()

    def test_incomplete_or_unknown_gate_set_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"].pop()
        self.assertRejected(candidate, "gate evidence")
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"].append(copy.deepcopy(candidate["gates"][0]))
        candidate["gates"][-1]["stage"] = "old_phase6b_step7"
        self.assertRejected(candidate, "gate set")

    def test_each_nonpass_gate_category_is_rejected(self) -> None:
        for field in ("failed", "errors", "xfail", "xpass", "warnings"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                gate = candidate["gates"][0]
                gate[field] = 1
                gate["passed"] -= 1
                self.assertRejected(candidate, field)

    def test_incomplete_or_under_count_gate_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"][2]["executed"] -= 1
        self.assertRejected(candidate, "execute every collected")
        candidate = copy.deepcopy(self.candidate)
        candidate["gates"][4].update(
            {"collected": 207, "executed": 207, "passed": 207}
        )
        self.assertRejected(candidate, "acceptance floor")

    def test_skip_allowlist_must_match_exactly(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        aggregate = candidate["gates"][-1]
        aggregate["skip_ids"] = aggregate["skip_ids"][:-1] + ["replacement.skip"]
        self.assertRejected(candidate, "skip allowlist mismatch")

    def test_unexpected_skip_outside_registered_aggregate_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        gate = candidate["gates"][0]
        gate["skipped"] = 1
        gate["passed"] -= 1
        gate["skip_ids"] = ["unexpected.skip"]
        self.assertRejected(candidate, "unexpected skip")

    def test_control_or_live_override_is_rejected(self) -> None:
        for field in ("control_override_used", "live_override_used"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["gates"][0][field] = True
                self.assertRejected(candidate, "used an override")

    def test_non_live_wrong_model_or_missing_verdict_review_is_rejected(self) -> None:
        for field, value, fragment in (
            ("provider_mode", "mock", "derived fields"),
            ("model", "substitute-model", "derived fields"),
            ("verdict", None, "derived fields"),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["real_sitina_review"][field] = value
                self.assertRejected(candidate, fragment)

    def test_zero_or_inconsistent_review_usage_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["total_tokens"] = 0
        self.assertRejected(candidate, "derived fields")
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["total_tokens"] = 100
        self.assertRejected(candidate, "derived fields")

    def test_non_read_tool_or_review_mutation_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["tool_call_types"] = ["read", "write"]
        self.assertRejected(candidate, "derived fields")
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["file_changes"] = 1
        self.assertRejected(candidate, "derived fields")
        candidate = copy.deepcopy(self.candidate)
        candidate["real_sitina_review"]["external_changes"] = 1
        self.assertRejected(candidate, "derived fields")

    def test_sentinel_drift_wrong_goal_or_production_attempt_is_rejected(self) -> None:
        sample_path = self.sentinel_samples[0]
        original = sample_path.read_text(encoding="utf-8")
        try:
            sample = json.loads(original)
            sample["base"]["report_sha256"] = "3" * 64
            sample_path.write_text(
                json.dumps(sample, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["production_sentinel"]["samples"][0] = (
                self._refresh_bound_reference(candidate, sample_path)
            )
            self.assertRejected(candidate, "sample 0 binding")
        finally:
            sample_path.write_text(original, encoding="utf-8")
        candidate = copy.deepcopy(self.candidate)
        candidate["production_sentinel"]["goal_id"] = ""
        self.assertRejected(candidate, "Goal binding")
        candidate = copy.deepcopy(self.candidate)
        candidate["production_sentinel"]["production_attempts"] = 1
        self.assertRejected(candidate, "production attempt")

    def test_each_execution_switch_must_remain_false(self) -> None:
        for field in self.candidate["execution_switches"]:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["execution_switches"][field] = True
                self.assertRejected(candidate, field)

    def test_missing_deployment_file_is_rejected(self) -> None:
        (self.deployment / "tracked.txt").unlink()
        self.assertRejected(self.candidate, "missing")

    def test_source_deployment_content_mismatch_is_rejected(self) -> None:
        (self.deployment / "tracked.txt").write_text("different\n", encoding="utf-8")
        self.assertRejected(self.candidate, "content mismatch")

    def test_source_deployment_mode_mismatch_is_rejected(self) -> None:
        deployment_file = self.deployment / "tracked.txt"
        deployment_file.chmod(stat.S_IMODE(deployment_file.stat().st_mode) ^ stat.S_IXUSR)
        self.assertRejected(self.candidate, "mode mismatch")

    def test_source_deployment_symlink_is_rejected(self) -> None:
        deployment_file = self.deployment / "tracked.txt"
        deployment_file.unlink()
        deployment_file.symlink_to(self.deployment / "config/true_multi_agent_policy.json")
        self.assertRejected(self.candidate, "unsafe tracked")

    def test_incomplete_unapproved_or_destructive_cleanup_is_rejected(self) -> None:
        for field, value, fragment in (
            ("completed_approved_action_count", 1, "exactly the empty set"),
            ("new_actions_performed_during_step7", 1, "new cleanup action"),
            ("unapproved_actions_performed", 1, "unapproved action"),
            ("permanent_deletion", True, "permanent deletion"),
        ):
            with self.subTest(field=field):
                original = self.cleanup_ledger.read_text(encoding="utf-8")
                try:
                    ledger = json.loads(original)
                    ledger[field] = value
                    self.cleanup_ledger.write_text(
                        json.dumps(ledger, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    candidate = copy.deepcopy(self.candidate)
                    candidate["cleanup"]["ledger"] = self._reference(
                        self.cleanup_ledger
                    )
                    self.assertRejected(candidate, fragment)
                finally:
                    self.cleanup_ledger.write_text(original, encoding="utf-8")

    def test_cleanup_requires_its_own_real_sitina_review(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["cleanup"]["real_sitina_review"]["verdict"] = "FAIL"
        self.assertRejected(candidate, "cleanup Sitina review")

    def test_cleanup_ledger_hash_mismatch_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["cleanup"]["ledger"]["sha256"] = "0" * 64
        self.assertRejected(candidate, "cleanup ledger SHA-256")

    def test_cleanup_candidate_and_ledger_require_exact_twenty_object_closure(
        self,
    ) -> None:
        original = self.cleanup_ledger.read_text(encoding="utf-8")
        try:
            ledger = json.loads(original)
            ledger["entries"][0]["recommendation"] = "KEEP"
            self.cleanup_ledger.write_text(
                json.dumps(ledger, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["cleanup"]["ledger"] = self._reference(self.cleanup_ledger)
            self.assertRejected(candidate, "entry 0 closure")
        finally:
            self.cleanup_ledger.write_text(original, encoding="utf-8")

    def test_cleanup_action_semantics_cannot_be_synchronously_rewritten(
        self,
    ) -> None:
        candidate_original = self.cleanup_candidate.read_text(encoding="utf-8")
        ledger_original = self.cleanup_ledger.read_text(encoding="utf-8")
        try:
            cleanup_candidate = json.loads(candidate_original)
            cleanup_candidate["objects"][0].update(
                {
                    "approval_status": "EXACT_DELETION_APPROVAL_GRANTED",
                    "actual_action": "PERMANENT_DELETION_EXECUTED_BY_STEP7",
                }
            )
            self.cleanup_candidate.write_text(
                json.dumps(cleanup_candidate, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            ledger = json.loads(ledger_original)
            ledger["entries"][0].update(
                {
                    "approval_status": "EXACT_DELETION_APPROVAL_GRANTED",
                    "actual_action": "PERMANENT_DELETION_EXECUTED_BY_STEP7",
                }
            )
            ledger["candidate_binding"]["physical_sha256"] = sha256(
                self.cleanup_candidate
            )
            self.cleanup_ledger.write_text(
                json.dumps(ledger, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["cleanup"]["candidate"] = self._reference(
                self.cleanup_candidate
            )
            candidate["cleanup"]["ledger"] = self._reference(self.cleanup_ledger)
            self.assertRejected(candidate, "action semantics")
        finally:
            self.cleanup_candidate.write_text(
                candidate_original, encoding="utf-8"
            )
            self.cleanup_ledger.write_text(ledger_original, encoding="utf-8")

    def test_rollback_proof_and_artifact_hash_are_required(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"] = None
        self.assertRejected(candidate, "rollback proof")
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["manifest"]["sha256"] = "0" * 64
        self.assertRejected(candidate, "rollback manifest")

    def test_bound_evidence_must_be_regular_and_hash_verified(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"][0]["sha256"] = "0" * 64
        self.assertRejected(candidate, "bound evidence")
        link = self.output / "evidence-link.json"
        link.symlink_to(self.general_evidence)
        candidate = copy.deepcopy(self.candidate)
        candidate["evidence"] = [{"path": str(link), "sha256": sha256(link)}]
        self.assertRejected(candidate, "regular non-symlink")

    def test_every_forbidden_action_and_step8_admission_is_rejected(self) -> None:
        for field in FORBIDDEN_ACTION_FIELDS:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.candidate)
                candidate["forbidden_actions"][field] = True
                self.assertRejected(candidate, field)
        candidate = copy.deepcopy(self.candidate)
        candidate["authorization_to_enter_step8"] = True
        self.assertRejected(candidate, "Step8 admission")

    def test_pending_production_actions_remain_unauthorized(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["pending_production_actions"] = []
        self.assertRejected(candidate, "pending production actions")
        candidate = copy.deepcopy(self.candidate)
        candidate["pending_production_actions"][0]["status"] = "AUTHORIZED"
        self.assertRejected(candidate, "approval-bound and unauthorized")

    def test_each_gate_evidence_document_must_reject_empty_object_with_fresh_hash(
        self,
    ) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        for gate in self.candidate["gates"]:
            stage = gate["stage"]
            path = self.gate_evidence[stage]
            original = path.read_text(encoding="utf-8")
            try:
                path.write_text("{}\n", encoding="utf-8")
                candidate = copy.deepcopy(self.candidate)
                candidate_gate = next(
                    item for item in candidate["gates"] if item["stage"] == stage
                )
                candidate_gate["evidence"] = self._refresh_bound_reference(
                    candidate, path
                )
                result = self._validate(candidate)
                self.assertFalse(
                    result["accepted"],
                    f"{stage} accepted empty evidence with a refreshed SHA-256",
                )
            finally:
                path.write_text(original, encoding="utf-8")

    def test_gate_ids_and_counts_are_recomputed_from_deployed_collection(self) -> None:
        stage = "minimal_negative_contract"
        path = self.gate_evidence[stage]
        original = path.read_text(encoding="utf-8")
        try:
            evidence = json.loads(original)
            strict = evidence["activation_gate"]
            fabricated_ids = [f"fabricated.test_{index:04d}" for index in range(999)]
            selector_names = list(strict["selector_counts"])
            strict["selector_counts"] = {
                selector_names[0]: 998,
                selector_names[1]: 1,
            }
            strict["collected_test_ids"] = fabricated_ids
            strict["started_test_ids"] = list(fabricated_ids)
            strict["collected_test_ids_sha256"] = hashlib.sha256(
                json.dumps(
                    fabricated_ids,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            strict["started_test_ids_sha256"] = strict[
                "collected_test_ids_sha256"
            ]
            strict["collected_test_count"] = 999
            strict["executed_test_count"] = 999
            strict["passed"] = 999
            evidence["test_count"] = 999
            path.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
            candidate = copy.deepcopy(self.candidate)
            candidate_gate = next(
                item for item in candidate["gates"] if item["stage"] == stage
            )
            candidate_gate.update(
                {
                    "collected": 999,
                    "executed": 999,
                    "passed": 999,
                    "evidence": self._refresh_bound_reference(candidate, path),
                }
            )
            self.assertRejected(candidate, "deployed test collection")
        finally:
            path.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_unrelated_bytes_with_fresh_hash(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            self.audit.write_text(
                "unrelated bytes that are not a Sitina audit\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            candidate["cleanup"]["real_sitina_review"]["audit"] = self._reference(
                self.audit
            )
            result = self._validate(candidate)
            self.assertFalse(
                result["accepted"],
                "unrelated review bytes were accepted after refreshing their SHA-256",
            )
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_non_success_terminal_event(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            records[-1]["event"] = "run_failed"
            records[-1].pop("response")
            records[-1]["error"] = "fixture terminal failure"
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "terminal event sequence")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_usage_is_derived_not_trusted_from_candidate(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            first_turn = next(
                record
                for record in records
                if record["event"] == "model_turn_completed"
            )
            usage = first_turn["metadata"]["token_usage"]
            usage["input_tokens"] += 1
            usage["total_tokens"] += 1
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "candidate/audit derived fields mismatch")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_and_receipt_cannot_bypass_append_only_anchor(
        self,
    ) -> None:
        audit_original = self.audit.read_text(encoding="utf-8")
        receipt_original = self.review_receipt.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in audit_original.splitlines()]
            turns = [
                record
                for record in records
                if record["event"] == "model_turn_completed"
            ]
            turns[0]["metadata"]["token_usage"].update(
                {"input_tokens": 9000, "output_tokens": 700, "total_tokens": 9700}
            )
            turns[1]["metadata"]["token_usage"].update(
                {"input_tokens": 1003, "output_tokens": 703, "total_tokens": 1706}
            )
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            previous = bytes(32)
            for record in records:
                encoded = json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                previous = hashlib.sha256(previous + encoded).digest()
            receipt = json.loads(receipt_original)
            receipt["audit"] = {
                **self._reference(self.audit),
                "format": "jsonl",
            }
            receipt["event_chain_sha256"] = previous.hex()
            receipt["usage"] = {
                "input_tokens": 10003,
                "output_tokens": 1403,
                "total_tokens": 11406,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
            }
            receipt["capture_anchor"] = self._capture_anchor(
                "SITINA_STEP7_AUDIT_CAPTURE_ANCHOR_V1",
                {
                    "review_stage": receipt["review_stage"],
                    "run_id": receipt["run_id"],
                    "input_sha256": receipt["input"]["sha256"],
                    "audit_sha256": receipt["audit"]["sha256"],
                    "event_chain_sha256": receipt["event_chain_sha256"],
                    "provider_request_ids": receipt["provider_request_ids"],
                    "usage": receipt["usage"],
                },
            )
            self.review_receipt.write_text(
                json.dumps(receipt, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            review = candidate["real_sitina_review"]
            review.update(receipt["usage"])
            review["audit"] = {
                **self._reference(self.audit),
                "format": "jsonl",
            }
            review["receipt"] = self._reference(self.review_receipt)
            self._refresh_bound_reference(candidate, self.audit)
            self._refresh_bound_reference(candidate, self.review_receipt)
            self.assertRejected(candidate, "append-only anchor")
        finally:
            self.audit.write_text(audit_original, encoding="utf-8")
            self.review_receipt.write_text(receipt_original, encoding="utf-8")

    def test_review_audit_rejects_non_read_tool_even_when_events_close(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            model_turn = next(
                record
                for record in records
                if record["event"] == "model_turn_completed"
                and record["tool_calls"]
            )
            model_turn["tool_calls"][0]["name"] = "sitina_write_file"
            intended = next(
                record for record in records if record["event"] == "tool_call_intended"
            )
            intended["name"] = "sitina_write_file"
            intended["permission"] = "write"
            intended["argument_summary"]["normalized_tool_name"] = (
                "sitina.sitina_write_file"
            )
            completed = next(
                record for record in records if record["event"] == "tool_completed"
            )
            completed["permission"] = "write"
            completed["result_summary"]["normalized_tool_name"] = (
                "sitina.sitina_write_file"
            )
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "non-read")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_provider_redaction_status_drift(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            model_turn = next(
                record
                for record in records
                if record["event"] == "model_turn_completed"
            )
            model_turn["metadata"]["redaction_status"] = "unverified"
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "provider metadata mismatch")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_denied_or_failed_read(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            completed = next(
                record for record in records if record["event"] == "tool_completed"
            )
            completed["result_summary"].update(
                {
                    "permission_decision": "denied",
                    "status": "error",
                    "error": "fixture denial",
                }
            )
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "failed or denied read")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_redacted_read_argument(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            intended = next(
                record for record in records if record["event"] == "tool_call_intended"
            )
            intended["argument_summary"]["redacted_paths"] = ["$.path"]
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "redacted tool")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_redacted_read_result(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            completed = next(
                record for record in records if record["event"] == "tool_completed"
            )
            completed["result_summary"]["result_redacted_paths"] = ["$"]
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "redacted read")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_completed_argument_summary_drift(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            completed = next(
                record for record in records if record["event"] == "tool_completed"
            )
            completed["argument_summary"]["redacted_paths"] = ["$.path"]
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "failed or denied read")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_result_summary_identity_drift(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            completed = next(
                record for record in records if record["event"] == "tool_completed"
            )
            completed["result_summary"]["result_ref"] = f"sha256:{'a' * 64}"
            completed["result_summary"]["result_bytes_after_redaction"] += 1
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "failed or denied read")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_missing_provider_assistant_transcript(
        self,
    ) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            provider = next(
                record
                for record in records
                if record["event"] == "provider_call_intended"
                and any(
                    message.get("role") == "tool"
                    for message in record["messages"]
                )
            )
            provider["messages"] = [
                message
                for message in provider["messages"]
                if message.get("role") != "assistant"
            ]
            model_turn = next(
                record
                for record in records
                if record["event"] == "model_turn_completed"
                and record["turn"] == provider["turn"]
            )
            model_turn["metadata"]["input_hash"] = (
                "sha256:"
                + step7_gate._canonical_sha256(
                    {
                        "system": None,
                        "messages": step7_gate._openai_wire_messages(
                            provider["system_prompt"],
                            provider["messages"],
                        ),
                    }
                )
            )
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "assistant/tool transcript mismatch")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_provider_tool_result_byte_drift(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        try:
            records = [json.loads(line) for line in original.splitlines()]
            provider = next(
                record
                for record in records
                if record["event"] == "provider_call_intended"
                and any(
                    message.get("role") == "tool"
                    for message in record["messages"]
                )
            )
            tool_message = next(
                message
                for message in provider["messages"]
                if message.get("role") == "tool"
            )
            envelope = json.loads(tool_message["content"])
            envelope["result"] += " "
            tool_message["content"] = json.dumps(envelope, sort_keys=True)
            model_turn = next(
                record
                for record in records
                if record["event"] == "model_turn_completed"
                and record["turn"] == provider["turn"]
            )
            model_turn["metadata"]["input_hash"] = (
                "sha256:"
                + step7_gate._canonical_sha256(
                    {
                        "system": None,
                        "messages": step7_gate._openai_wire_messages(
                            provider["system_prompt"],
                            provider["messages"],
                        ),
                    }
                )
            )
            self.audit.write_text(
                "".join(
                    json.dumps(record, sort_keys=True) + "\n" for record in records
                ),
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["real_sitina_review"]["audit"] = self._reference(self.audit)
            self.assertRejected(candidate, "differs from physical evidence")
        finally:
            self.audit.write_text(original, encoding="utf-8")

    def test_review_audit_rejects_provider_tool_message_identity_drift(
        self,
    ) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.audit.read_text(encoding="utf-8")
        for mutation in ("wrong_role", "wrong_call_id", "non_object"):
            with self.subTest(mutation=mutation):
                try:
                    records = [json.loads(line) for line in original.splitlines()]
                    provider = next(
                        record
                        for record in records
                        if record["event"] == "provider_call_intended"
                        and any(
                            message.get("role") == "tool"
                            for message in record["messages"]
                        )
                    )
                    index = next(
                        index
                        for index, message in enumerate(provider["messages"])
                        if message.get("role") == "tool"
                    )
                    if mutation == "wrong_role":
                        provider["messages"][index]["role"] = "user"
                    elif mutation == "wrong_call_id":
                        provider["messages"][index]["tool_call_id"] = "wrong-call"
                    else:
                        provider["messages"][index] = []
                    wire_messages = step7_gate._openai_wire_messages(
                        provider["system_prompt"],
                        provider["messages"],
                    )
                    if wire_messages is not None:
                        model_turn = next(
                            record
                            for record in records
                            if record["event"] == "model_turn_completed"
                            and record["turn"] == provider["turn"]
                        )
                        model_turn["metadata"]["input_hash"] = (
                            "sha256:"
                            + step7_gate._canonical_sha256(
                                {"system": None, "messages": wire_messages}
                            )
                        )
                    self.audit.write_text(
                        "".join(
                            json.dumps(record, sort_keys=True) + "\n"
                            for record in records
                        ),
                        encoding="utf-8",
                    )
                    candidate = copy.deepcopy(self.candidate)
                    candidate["real_sitina_review"]["audit"] = self._reference(
                        self.audit
                    )
                    self.assertRejected(
                        candidate, "malformed or redacted tool result"
                    )
                finally:
                    self.audit.write_text(original, encoding="utf-8")

    def test_gate_schema_stage_and_counts_are_bound_to_candidate(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        stage = "step7_readiness_gate"
        path = self.gate_evidence[stage]
        original = path.read_text(encoding="utf-8")
        mutations = (
            ("schema", lambda document: document.update(schema="WRONG_SCHEMA")),
            ("stage", lambda document: document.update(stage="wrong_stage")),
            (
                "count",
                lambda document: document["activation_gate"].update(
                    passed=document["activation_gate"]["passed"] - 1
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                try:
                    document = json.loads(original)
                    mutate(document)
                    path.write_text(
                        json.dumps(document, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    candidate = copy.deepcopy(self.candidate)
                    gate = next(
                        item
                        for item in candidate["gates"]
                        if item["stage"] == stage
                    )
                    gate["evidence"] = self._refresh_bound_reference(candidate, path)
                    self.assertFalse(self._validate(candidate)["accepted"])
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_registered_skip_ids_and_reasons_are_evidence_bound(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        path = self.gate_evidence["all_registered_unique"]
        original = path.read_text(encoding="utf-8")
        try:
            document = json.loads(original)
            document["registration_gate"]["skip_details"][0]["reason"] = (
                "arbitrary replacement reason"
            )
            path.write_text(
                json.dumps(document, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            gate = next(
                item
                for item in candidate["gates"]
                if item["stage"] == "all_registered_unique"
            )
            gate["evidence"] = self._refresh_bound_reference(candidate, path)
            self.assertRejected(candidate, "exact registration binding")
        finally:
            path.write_text(original, encoding="utf-8")

    def test_sentinel_rejects_arbitrary_equal_hashes_and_goal(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        originals = [
            path.read_text(encoding="utf-8") for path in self.sentinel_samples
        ]
        try:
            for index, path in enumerate(self.sentinel_samples):
                sample = json.loads(originals[index])
                sample["goal_id"] = "arbitrary-goal-not-bound-to-baseline"
                sample["base"]["report_sha256"] = "e" * 64
                sample["mutable"]["report_sha256"] = "f" * 64
                path.write_text(
                    json.dumps(sample, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            candidate = copy.deepcopy(self.candidate)
            candidate["production_sentinel"]["goal_id"] = (
                "arbitrary-goal-not-bound-to-baseline"
            )
            candidate["production_sentinel"]["samples"] = [
                self._refresh_bound_reference(candidate, path)
                for path in self.sentinel_samples
            ]
            result = self._validate(candidate)
            self.assertFalse(
                result["accepted"],
                "arbitrary equal sentinel strings and an arbitrary Goal were accepted",
            )
        finally:
            for path, original in zip(self.sentinel_samples, originals):
                path.write_text(original, encoding="utf-8")

    def test_rollback_rejects_empty_artifact_with_verified_boolean_and_fresh_hash(
        self,
    ) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.rollback_manifest.read_text(encoding="utf-8")
        try:
            self.rollback_manifest.write_text("{}\n", encoding="utf-8")
            candidate = copy.deepcopy(self.candidate)
            manifest_ref = self._refresh_bound_reference(
                candidate, self.rollback_manifest
            )
            candidate["rollback_proof"] = {
                "verified": True,
                "approval_packet": self._reference(self.rollback_packet),
                "manifest": manifest_ref,
                "recovery_result": self._reference(self.rollback_recovery),
            }
            result = self._validate(candidate)
            self.assertFalse(
                result["accepted"],
                "verified:true plus an empty rollback artifact was accepted",
            )
        finally:
            self.rollback_manifest.write_text(original, encoding="utf-8")

    def test_rollback_preimage_backup_bytes_are_physically_verified(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        backup_original = self.rollback_backup.read_bytes()
        manifest_original = self.rollback_manifest.read_text(encoding="utf-8")
        recovery_original = self.rollback_recovery.read_text(encoding="utf-8")
        try:
            self.rollback_backup.write_bytes(backup_original + b"tampered")
            manifest = json.loads(manifest_original)
            manifest["entries"][0]["backup"] = self._reference(self.rollback_backup)
            self.rollback_manifest.write_text(
                json.dumps(manifest, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            recovery = json.loads(recovery_original)
            recovery["manifest"] = self._reference(self.rollback_manifest)
            self.rollback_recovery.write_text(
                json.dumps(recovery, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["rollback_proof"]["manifest"] = (
                self._refresh_bound_reference(candidate, self.rollback_manifest)
            )
            candidate["rollback_proof"]["recovery_result"] = (
                self._refresh_bound_reference(candidate, self.rollback_recovery)
            )
            self.assertRejected(candidate, "preimage backup tracked.txt metadata mismatch")
        finally:
            self.rollback_backup.write_bytes(backup_original)
            self.rollback_manifest.write_text(manifest_original, encoding="utf-8")
            self.rollback_recovery.write_text(recovery_original, encoding="utf-8")

    def test_rollback_synchronous_packet_rewrite_requires_exact_user_authorization(
        self,
    ) -> None:
        packet_original = self.rollback_packet.read_text(encoding="utf-8")
        manifest_original = self.rollback_manifest.read_text(encoding="utf-8")
        recovery_original = self.rollback_recovery.read_text(encoding="utf-8")
        try:
            packet = json.loads(packet_original)
            packet["created_at_utc"] = "2026-07-27T00:00:01Z"
            capture = packet["preimage_capture"]
            capture["capture_anchor"] = self._capture_anchor(
                "SITINA_STEP7_PREIMAGE_CAPTURE_ANCHOR_V1",
                {
                    "approval_id": packet["approval_id"],
                    "source_head": packet["source_binding"]["head"],
                    "source_tree": packet["source_binding"]["tree"],
                    "deployment_root": packet["deployment_binding"]["root"],
                    "entries": capture["entries"],
                },
            )
            self.rollback_packet.write_text(
                json.dumps(packet, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest = json.loads(manifest_original)
            manifest["approval_packet_sha256"] = sha256(self.rollback_packet)
            self.rollback_manifest.write_text(
                json.dumps(manifest, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            recovery = json.loads(recovery_original)
            recovery["manifest"] = self._reference(self.rollback_manifest)
            self.rollback_recovery.write_text(
                json.dumps(recovery, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["rollback_proof"]["approval_packet"] = (
                self._refresh_bound_reference(candidate, self.rollback_packet)
            )
            candidate["rollback_proof"]["manifest"] = (
                self._refresh_bound_reference(candidate, self.rollback_manifest)
            )
            candidate["rollback_proof"]["recovery_result"] = (
                self._refresh_bound_reference(candidate, self.rollback_recovery)
            )
            self.assertRejected(candidate, "deployment user authorization")
        finally:
            self.rollback_packet.write_text(packet_original, encoding="utf-8")
            self.rollback_manifest.write_text(manifest_original, encoding="utf-8")
            self.rollback_recovery.write_text(recovery_original, encoding="utf-8")

    def test_rollback_rejects_missing_or_assistant_authored_authorization(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = None
        self.assertRejected(candidate, "deployment user authorization")

        candidate = copy.deepcopy(self.candidate)
        authorization = candidate["rollback_proof"]["authorization_receipt"]
        authorization["author"] = "/root"
        self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_accepts_exact_delegation_wrapper(self) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        evidence = json.loads(
            self.rollback_request_evidence.read_text(encoding="utf-8")
        )
        review_candidate = json.loads(
            self.rollback_review_candidate.read_text(encoding="utf-8")
        )
        contract = packet["authorization_contract"]
        self.assertIs(contract["delegated_wrapper_required"], True)
        self.assertEqual(
            contract["delegation_marker"],
            DEPLOYMENT_DELEGATION_MARKER,
        )
        self.assertEqual(
            contract["delegated_source_session"],
            STEP7_DELEGATED_SOURCE_SESSION,
        )
        self.assertEqual(
            contract["delegation_source_binding_fields"],
            list(DEPLOYMENT_DELEGATION_SOURCE_BINDING_FIELDS),
        )
        self.assertEqual(
            contract["two_hop_structure"],
            DEPLOYMENT_AUTHORIZATION_TWO_HOP_STRUCTURE,
        )
        self.assertEqual(
            contract["source_ui_transport_normalization"],
            SOURCE_UI_TRANSPORT_NORMALIZATION_CONTRACT,
        )
        self.assertIn("source_authorization", self.rollback_authorization)
        self.assertEqual(
            set(self.rollback_authorization["source_authorization"]),
            CODEX_SOURCE_USER_AUTHORIZATION_REFERENCE_FIELDS,
        )
        self.assertEqual(
            self.rollback_authorization["source_authorization"][
                "transport_normalization_mode"
            ],
            "IDENTITY",
        )
        self.assertEqual(
            self.rollback_authorization["source_authorization"][
                "transport_removed_suffix_hex"
            ],
            "",
        )
        self.assertEqual(evidence["authorization_contract"], contract)
        self.assertEqual(review_candidate["authorization_contract"], contract)
        result = self._validate(copy.deepcopy(self.candidate))
        self.assertTrue(result["accepted"], result["errors"])

    def test_deployment_authorization_accepts_one_terminal_source_lf(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            source_text_suffix="\n",
        )
        source_reference = receipt["source_authorization"]
        self.assertEqual(
            source_reference["actual_content_length"],
            source_reference["canonical_logical_length"] + 1,
        )
        self.assertNotEqual(
            source_reference["actual_content_sha256"],
            source_reference["canonical_logical_sha256"],
        )
        self.assertEqual(
            source_reference["transport_normalization_mode"],
            "REMOVE_ONE_TERMINAL_LF",
        )
        self.assertEqual(
            source_reference["transport_removed_suffix_hex"],
            "0a",
        )
        self.assertEqual(
            source_reference["transport_removed_byte_count"],
            1,
        )
        wrapper_lines = self.anchor_session.read_bytes().splitlines(
            keepends=True
        )
        wrapper_record = json.loads(
            wrapper_lines[receipt["line_number"] - 1]
        )
        wrapper_text = wrapper_record["payload"]["content"][0]["text"]
        delegation_input = wrapper_text.split("<input>", 1)[1].split(
            "</input>",
            1,
        )[0]
        source_binding = json.loads(
            delegation_input.removeprefix(
                DEPLOYMENT_DELEGATION_MARKER + " "
            )
        )
        self.assertEqual(
            source_binding["source_actual_content_sha256"],
            source_reference["actual_content_sha256"],
        )
        self.assertEqual(
            source_binding["source_actual_content_length"],
            source_reference["actual_content_length"],
        )
        self.assertEqual(
            source_binding["source_canonical_logical_sha256"],
            source_reference["canonical_logical_sha256"],
        )
        self.assertEqual(
            source_binding["source_canonical_logical_length"],
            source_reference["canonical_logical_length"],
        )
        self.assertEqual(
            source_binding["source_transport_normalization_schema"],
            SOURCE_UI_TRANSPORT_NORMALIZATION_SCHEMA,
        )
        self.assertEqual(
            source_binding["source_transport_normalization_mode"],
            source_reference["transport_normalization_mode"],
        )
        self.assertEqual(
            source_binding["source_transport_removed_suffix_hex"],
            source_reference["transport_removed_suffix_hex"],
        )
        self.assertEqual(
            source_binding["source_transport_removed_byte_count"],
            source_reference["transport_removed_byte_count"],
        )
        recovery_original = self.rollback_recovery.read_text(encoding="utf-8")
        try:
            recovery = json.loads(recovery_original)
            recovery["authorization_raw_record_sha256"] = receipt[
                "raw_record_sha256"
            ]
            self.rollback_recovery.write_text(
                json.dumps(recovery, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["rollback_proof"]["authorization_receipt"] = receipt
            candidate["rollback_proof"]["recovery_result"] = (
                self._refresh_bound_reference(
                    candidate,
                    self.rollback_recovery,
                )
            )
            result = self._validate(candidate)
            self.assertTrue(result["accepted"], result["errors"])
        finally:
            self.rollback_recovery.write_text(
                recovery_original,
                encoding="utf-8",
            )

    def test_deployment_authorization_rejects_legacy_direct_user_text(self) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            delegated=False,
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_rejects_other_delegation_source_thread(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            source_thread_id="019f0000-0000-0000-0000-000000000000",
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_rejects_one_extra_input_byte(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            input_suffix="x",
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_rejects_wrapper_only(self) -> None:
        receipt = copy.deepcopy(self.rollback_authorization)
        receipt.pop("source_authorization")
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_rejects_source_agent_record(self) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            source_role="assistant",
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization source")

    def test_deployment_authorization_rejects_source_session_self_delegation(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            self_delegated=True,
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_rejects_missing_source_record(self) -> None:
        receipt = copy.deepcopy(self.rollback_authorization)
        receipt["source_authorization"]["session_path"] = str(
            self.anchor_root / "missing-source-session.jsonl"
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization source")

    def test_deployment_authorization_rejects_each_source_reference_drift(
        self,
    ) -> None:
        mutations = {
            "session_path": str(self.anchor_session.resolve()),
            "line_number": 999,
            "record_id": "wrong-source-record",
            "raw_record_sha256": "0" * 64,
            "actual_content_sha256": "0" * 64,
            "actual_content_length": 0,
            "canonical_logical_sha256": "0" * 64,
            "canonical_logical_length": 0,
            "transport_normalization_mode": "REMOVE_ONE_TERMINAL_LF",
            "transport_removed_suffix_hex": "0a",
            "transport_removed_byte_count": 1,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.rollback_authorization)
                receipt["source_authorization"][field] = value
                candidate = copy.deepcopy(self.candidate)
                candidate["rollback_proof"]["authorization_receipt"] = receipt
                self.assertRejected(
                    candidate,
                    "deployment user authorization source",
                )

    def test_deployment_authorization_rejects_disallowed_transport_suffixes(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        invalid_transports = (
            ("", "\r"),
            ("", "\r\n"),
            ("", "\n\n"),
            ("", " "),
            (" ", ""),
            ("\t", ""),
            ("", "\u00a0"),
            ("", "x"),
        )
        for prefix, suffix in invalid_transports:
            with self.subTest(prefix=repr(prefix), suffix=repr(suffix)):
                receipt = self._user_authorization(
                    self.rollback_packet,
                    packet,
                    source_text_prefix=prefix,
                    source_text_suffix=suffix,
                )
                candidate = copy.deepcopy(self.candidate)
                candidate["rollback_proof"]["authorization_receipt"] = receipt
                self.assertRejected(
                    candidate,
                    "deployment user authorization",
                )

    def test_deployment_authorization_rejects_extra_source_content_item(
        self,
    ) -> None:
        receipt = copy.deepcopy(self.rollback_authorization)
        source_reference = receipt["source_authorization"]
        source_lines = self.source_authorization_session.read_bytes().splitlines(
            keepends=True
        )
        source_index = source_reference["line_number"] - 1
        source_record = json.loads(source_lines[source_index])
        source_record["payload"]["content"].append(
            {"type": "input_text", "text": "unbound-extra-content"}
        )
        source_raw = (
            json.dumps(
                source_record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        source_lines[source_index] = source_raw
        self.source_authorization_session.write_bytes(b"".join(source_lines))
        source_reference["raw_record_sha256"] = hashlib.sha256(source_raw).hexdigest()
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(
            candidate,
            "deployment user authorization source content mismatch",
        )

    def test_deployment_authorization_rejects_wrong_source_binding(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        for field in DEPLOYMENT_DELEGATION_SOURCE_BINDING_FIELDS:
            with self.subTest(field=field):
                receipt = self._user_authorization(
                    self.rollback_packet,
                    packet,
                    binding_override={field: "wrong"},
                )
                candidate = copy.deepcopy(self.candidate)
                candidate["rollback_proof"]["authorization_receipt"] = receipt
                self.assertRejected(candidate, "deployment user authorization")

    def test_deployment_authorization_rejects_source_after_delegation(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        receipt = self._user_authorization(
            self.rollback_packet,
            packet,
            source_timestamp="2026-07-27T00:03:00.000Z",
        )
        candidate = copy.deepcopy(self.candidate)
        candidate["rollback_proof"]["authorization_receipt"] = receipt
        self.assertRejected(candidate, "deployment user authorization")

    def test_rollback_restore_result_cannot_drift_from_manifest(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        original = self.rollback_recovery.read_text(encoding="utf-8")
        try:
            recovery = json.loads(original)
            recovery["entries"][0]["restored"]["sha256"] = "f" * 64
            self.rollback_recovery.write_text(
                json.dumps(recovery, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["rollback_proof"]["recovery_result"] = (
                self._refresh_bound_reference(candidate, self.rollback_recovery)
            )
            self.assertRejected(candidate, "result mismatch")
        finally:
            self.rollback_recovery.write_text(original, encoding="utf-8")

    def test_backup_plan_rejects_arbitrary_root_or_preimage_backup_path(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        for mutation in ("root", "preimage"):
            plan = copy.deepcopy(packet["backup_and_rollback_plan"])
            if mutation == "root":
                plan["backup_root"]["path"] = str(self.output / "arbitrary")
            else:
                plan["objects"][0]["preimage_backup_path"] = str(
                    self.output / "unbound.preimage"
                )
            errors: list[str] = []
            _verify_backup_and_rollback_plan(
                plan,
                approval_id=packet["approval_id"],
                packet_operations=packet["exact_file_operations"],
                source_root=self.source.resolve(),
                deployment_root=self.deployment.resolve(),
                source_state={
                    "head": packet["source_binding"]["head"],
                    "tree": packet["source_binding"]["tree"],
                },
                errors=errors,
            )
            self.assertTrue(
                any("backup and rollback plan" in error for error in errors),
                (mutation, errors),
            )

    def test_backup_plan_create_rollback_must_quarantine_not_delete(self) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        target = self.source.resolve() / "new-step7-file.py"
        operation = {
            "relative_path": "new-step7-file.py",
            "operation": "CREATE",
            "source_path": str(target),
            "target_path": str(self.deployment.resolve() / "new-step7-file.py"),
            "target_sha256": "a" * 64,
            "target_size": 1,
            "target_mode": "0o644",
            "preimage_exists": False,
            "preimage_sha256": None,
            "preimage_size": None,
            "preimage_mode": None,
        }
        plan = self._rollback_plan_document(
            [operation],
            source_head=packet["source_binding"]["head"],
            source_tree=packet["source_binding"]["tree"],
            deployment_root=packet["deployment_binding"]["root"],
        )
        plan["objects"][0]["rollback_action"] = "DELETE_CREATED_TARGET"
        errors: list[str] = []
        _verify_backup_and_rollback_plan(
            plan,
            approval_id=packet["approval_id"],
            packet_operations=[operation],
            source_root=self.source.resolve(),
            deployment_root=self.deployment.resolve(),
            source_state={
                "head": packet["source_binding"]["head"],
                "tree": packet["source_binding"]["tree"],
            },
            errors=errors,
        )
        self.assertIn(
            "backup and rollback plan object 0 operation binding mismatch",
            errors,
        )

    def test_backup_plan_requires_existing_safe_parent_and_forbids_creation(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        plan = packet["backup_and_rollback_plan"]
        self.assertEqual(len(plan["execution_sequence"]), 16)
        self.assertEqual(
            plan["execution_sequence"][4],
            "CREATE_UNIQUE_BACKUP_ROOT_EXCLUSIVE_NOFOLLOW",
        )
        self.assertEqual(
            plan["backup_root"],
            {
                "path": str(self.rollback_root),
                "allowed_parent": str(self.output.resolve()),
                "allowed_parent_must_exist_before_authorized_execution": True,
                "allowed_parent_creation_allowed": False,
                "allowed_parent_required_type": "DIRECTORY_NO_SYMLINK",
                "allowed_parent_ancestor_safety_required": True,
                "derived_from_approval_id": True,
                "must_not_exist_before_authorized_execution": True,
                "create_mode": "0o700",
                "create_semantics": "EXCLUSIVE_NOFOLLOW",
                "reuse_allowed": False,
            },
        )
        for mutation in ("parent_creation", "parent_exists", "sequence"):
            mutated = copy.deepcopy(plan)
            if mutation == "parent_creation":
                mutated["backup_root"][
                    "allowed_parent_creation_allowed"
                ] = True
            elif mutation == "parent_exists":
                mutated["backup_root"][
                    "allowed_parent_must_exist_before_authorized_execution"
                ] = False
            else:
                mutated["execution_sequence"][4] = (
                    "CREATE_ALLOWED_PARENT_IF_ABSENT_AND_UNIQUE_BACKUP_ROOT_"
                    "EXCLUSIVE_NOFOLLOW"
                )
            errors: list[str] = []
            _verify_backup_and_rollback_plan(
                mutated,
                approval_id=packet["approval_id"],
                packet_operations=packet["exact_file_operations"],
                source_root=self.source.resolve(),
                deployment_root=self.deployment.resolve(),
                source_state={
                    "head": packet["source_binding"]["head"],
                    "tree": packet["source_binding"]["tree"],
                },
                errors=errors,
            )
            self.assertTrue(
                any("backup and rollback plan" in error for error in errors),
                (mutation, errors),
            )

    def test_replace_backup_parent_symlink_is_rejected(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        preimages = self.rollback_backup.parent
        original = self.rollback_root / "preimages-original"
        outside = self.output / "outside-preimages"
        outside.mkdir()
        shutil.copy2(self.rollback_backup, outside / self.rollback_backup.name)
        preimages.rename(original)
        preimages.symlink_to(outside, target_is_directory=True)
        try:
            self.assertRejected(
                copy.deepcopy(self.candidate),
                "rollback preimage backup tracked.txt component is a symlink",
            )
        finally:
            preimages.unlink()
            original.rename(preimages)

    def test_create_quarantine_parent_symlink_is_rejected(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        quarantine = self.rehearsal_quarantine_root
        original = self.rollback_root / "rehearsal-quarantine-created-original"
        outside = self.output / "outside-quarantine"
        outside.mkdir()
        shutil.copy2(
            self.rehearsal_quarantine_created,
            outside / self.rehearsal_quarantine_created.name,
        )
        quarantine.rename(original)
        quarantine.symlink_to(outside, target_is_directory=True)
        try:
            self.assertRejected(
                copy.deepcopy(self.candidate),
                (
                    "rollback rehearsal quarantine snapshot created.txt "
                    "component is a symlink"
                ),
            )
        finally:
            quarantine.unlink()
            original.rename(quarantine)

    def test_live_create_quarantine_must_remain_unoccupied(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        shutil.copy2(
            self.source / "created.txt",
            self.rollback_quarantine_created,
        )
        try:
            self.assertRejected(
                copy.deepcopy(self.candidate),
                "live rollback quarantine created.txt must be absent",
            )
        finally:
            self.rollback_quarantine_created.unlink()

    def test_rehearsal_and_live_quarantine_paths_cannot_alias(self) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        plan = copy.deepcopy(packet["backup_and_rollback_plan"])
        create_object = next(
            item for item in plan["objects"] if item["operation"] == "CREATE"
        )
        create_object["rehearsal_quarantine_path"] = create_object[
            "rollback_quarantine_path"
        ]
        errors: list[str] = []
        _verify_backup_and_rollback_plan(
            plan,
            approval_id=packet["approval_id"],
            packet_operations=packet["exact_file_operations"],
            source_root=self.source.resolve(),
            deployment_root=self.deployment.resolve(),
            source_state={
                "head": packet["source_binding"]["head"],
                "tree": packet["source_binding"]["tree"],
            },
            errors=errors,
        )
        self.assertTrue(
            any("operation binding mismatch" in error for error in errors),
            errors,
        )

    def test_preimage_capture_requires_safe_existing_parent_and_unused_root(
        self,
    ) -> None:
        packet_original = self.rollback_packet.read_text(encoding="utf-8")
        try:
            for field, unsafe_value in (
                ("allowed_parent_existed", False),
                ("allowed_parent_is_directory", False),
                ("allowed_parent_is_symlink", True),
                ("allowed_parent_creation_allowed", True),
                ("allowed_parent_ancestor_safety_verified", False),
                ("existed", True),
            ):
                with self.subTest(field=field):
                    packet = json.loads(packet_original)
                    capture = packet["preimage_capture"]
                    capture["backup_root_preflight"][field] = unsafe_value
                    capture["capture_anchor"] = self._capture_anchor(
                        "SITINA_STEP7_PREIMAGE_CAPTURE_ANCHOR_V1",
                        {
                            "approval_id": packet["approval_id"],
                            "source_head": packet["source_binding"]["head"],
                            "source_tree": packet["source_binding"]["tree"],
                            "deployment_root": packet["deployment_binding"][
                                "root"
                            ],
                            "entries": capture["entries"],
                            "backup_root_preflight": capture[
                                "backup_root_preflight"
                            ],
                        },
                    )
                    self.rollback_packet.write_text(
                        json.dumps(packet, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    candidate = copy.deepcopy(self.candidate)
                    candidate["rollback_proof"]["approval_packet"] = (
                        self._refresh_bound_reference(
                            candidate,
                            self.rollback_packet,
                        )
                    )
                    self.assertRejected(
                        candidate,
                        "rollback approval packet preimage capture mismatch",
                    )
        finally:
            self.rollback_packet.write_text(packet_original, encoding="utf-8")

    def test_exact_authorization_binds_plan_and_review_candidate_hashes(
        self,
    ) -> None:
        packet = json.loads(self.rollback_packet.read_text(encoding="utf-8"))
        exact_payload = {
            "approval_id": packet["approval_id"],
            "approval_packet_sha256": sha256(self.rollback_packet),
            "exact_file_operation_count": len(packet["exact_file_operations"]),
            "exact_file_operations_sha256": _json_value_sha256(
                packet["exact_file_operations"]
            ),
            "rollback_plan_sha256": packet[
                "backup_and_rollback_plan_sha256"
            ],
            "review_candidate_sha256": sha256(
                self.rollback_review_candidate
            ),
            "source_head": packet["source_binding"]["head"],
            "source_tree": packet["source_binding"]["tree"],
            "deployment_root": packet["deployment_binding"]["root"],
        }
        for omitted in ("rollback_plan_sha256", "review_candidate_sha256"):
            incomplete = dict(exact_payload)
            incomplete.pop(omitted)
            receipt = self._user_authorization(
                self.rollback_packet,
                packet,
                payload_override=incomplete,
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["rollback_proof"]["authorization_receipt"] = receipt
            self.assertRejected(candidate, "deployment user authorization")

    def test_review_candidate_hash_binds_complete_evidence_bundle(self) -> None:
        candidate = copy.deepcopy(self.candidate)
        original = self.rollback_review_candidate.read_text(encoding="utf-8")
        try:
            request = json.loads(original)
            request["evidence_bundle"]["sha256"] = "0" * 64
            self.rollback_review_candidate.write_text(
                json.dumps(request, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate["rollback_proof"]["deployment_request_candidate"] = (
                self._refresh_bound_reference(
                    candidate,
                    self.rollback_review_candidate,
                )
            )
            self.assertRejected(
                candidate,
                "deployment request review evidence bundle",
            )
        finally:
            self.rollback_review_candidate.write_text(
                original,
                encoding="utf-8",
            )

    def test_evidence_bundle_rejects_fresh_sha_semantic_substitution_for_each_category(
        self,
    ) -> None:
        bundle_original = self.rollback_request_evidence.read_text(
            encoding="utf-8"
        )
        request_original = self.rollback_review_candidate.read_text(
            encoding="utf-8"
        )
        unrelated = self._json_file(
            "unrelated-but-valid-evidence.json",
            {"schema": "UNRELATED_VALID_JSON_V1", "accepted": True},
        )
        replacement = self._reference(unrelated)
        categories = (
            "authority",
            "entry_candidate",
            "step56_accepts",
            "gates",
            "real_sitina_reviews",
            "static_integrity",
            "excluded_attempts",
            "revocation",
            "changed_source",
        )
        try:
            for category in categories:
                bundle = json.loads(bundle_original)
                current = bundle["evidence"][category]
                if isinstance(current, list):
                    current[0] = replacement
                else:
                    bundle["evidence"][category] = replacement
                self.rollback_request_evidence.write_text(
                    json.dumps(bundle, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                request = json.loads(request_original)
                request["evidence_bundle"] = self._reference(
                    self.rollback_request_evidence
                )
                self.rollback_review_candidate.write_text(
                    json.dumps(request, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                candidate = copy.deepcopy(self.candidate)
                self._refresh_bound_reference(
                    candidate,
                    self.rollback_request_evidence,
                )
                candidate["rollback_proof"]["deployment_request_candidate"] = (
                    self._refresh_bound_reference(
                        candidate,
                        self.rollback_review_candidate,
                    )
                )
                self.assertRejected(
                    candidate,
                    "deployment request review evidence category identities mismatch",
                )
        finally:
            self.rollback_request_evidence.write_text(
                bundle_original,
                encoding="utf-8",
            )
            self.rollback_review_candidate.write_text(
                request_original,
                encoding="utf-8",
            )

    def test_supporting_evidence_rejects_synchronized_but_unrelated_documents(
        self,
    ) -> None:
        bundle_original = self.rollback_request_evidence.read_text(
            encoding="utf-8"
        )
        request_original = self.rollback_review_candidate.read_text(
            encoding="utf-8"
        )
        replacements = {
            category: self._json_file(
                f"unrelated-{category}.json",
                {
                    "schema": f"UNRELATED_{category.upper()}_V1",
                    "accepted": True,
                },
            )
            for category in (
                "static_integrity",
                "excluded_attempts",
                "revocation",
            )
        }
        expected_errors = {
            "static_integrity": (
                "deployment request static-integrity evidence mismatch"
            ),
            "excluded_attempts": (
                "deployment request excluded-attempt evidence mismatch"
            ),
            "revocation": "deployment request revocation evidence mismatch",
        }
        try:
            for category, replacement_path in replacements.items():
                replacement = self._reference(replacement_path)
                bundle = json.loads(bundle_original)
                bundle["evidence"][category] = replacement
                self.rollback_request_evidence.write_text(
                    json.dumps(bundle, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                request = json.loads(request_original)
                request["evidence_bundle"] = self._reference(
                    self.rollback_request_evidence
                )
                self.rollback_review_candidate.write_text(
                    json.dumps(request, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                candidate = copy.deepcopy(self.candidate)
                old_reference = candidate[
                    "deployment_request_supporting_evidence"
                ][category]
                candidate["deployment_request_supporting_evidence"][
                    category
                ] = replacement
                for index, existing in enumerate(candidate["evidence"]):
                    if existing["path"] == old_reference["path"]:
                        candidate["evidence"][index] = replacement
                self._refresh_bound_reference(
                    candidate,
                    self.rollback_request_evidence,
                )
                candidate["rollback_proof"]["deployment_request_candidate"] = (
                    self._refresh_bound_reference(
                        candidate,
                        self.rollback_review_candidate,
                    )
                )
                self.assertRejected(
                    candidate,
                    expected_errors[category],
                )
        finally:
            self.rollback_request_evidence.write_text(
                bundle_original,
                encoding="utf-8",
            )
            self.rollback_review_candidate.write_text(
                request_original,
                encoding="utf-8",
            )

    def test_failed_preapply_revocation_v3_is_physically_bound(self) -> None:
        document = self._failed_preapply_revocation_document()
        source_state = {
            "head": document["successor_fix"]["head"],
            "tree": document["successor_fix"]["tree"],
        }
        self.assertTrue(
            step7_gate._failed_preapply_revocation_is_valid(
                document,
                source_root=REPOSITORY_ROOT,
                deployment_root=Path("/Users/moss/SitinaHub"),
                source_state=source_state,
                anchor_root=Path("/Users/moss/.codex/sessions"),
                live_target_expectation="NONE",
            )
        )

    def test_failed_preapply_revocation_v3_historical_mode_does_not_read_live_targets(
        self,
    ) -> None:
        document = self._failed_preapply_revocation_document()
        source_state = {
            "head": document["successor_fix"]["head"],
            "tree": document["successor_fix"]["tree"],
        }
        deployment_root = Path("/Users/moss/SitinaHub")
        targets = {
            Path(operation["target_path"])
            for operation in json.loads(
                Path(
                    step7_gate.FAILED_PREAPPLY_REVOCATION_REFERENCES[
                        "revoked_packet"
                    ]["path"]
                ).read_text(encoding="utf-8")
            )["exact_file_operations"]
        }
        original_lstat = Path.lstat

        def reject_live_target_read(path: Path) -> os.stat_result:
            if path in targets:
                raise AssertionError("historical validation read a live target")
            return original_lstat(path)

        with mock.patch.object(Path, "lstat", reject_live_target_read):
            self.assertTrue(
                step7_gate._failed_preapply_revocation_is_valid(
                    document,
                    source_root=REPOSITORY_ROOT,
                    deployment_root=deployment_root,
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                    live_target_expectation="NONE",
                )
            )
            self.assertFalse(
                step7_gate._failed_preapply_revocation_is_valid(
                    document,
                    source_root=REPOSITORY_ROOT,
                    deployment_root=deployment_root,
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                    live_target_expectation="UNKNOWN",
                )
            )
            with self.assertRaises(AssertionError):
                step7_gate._failed_preapply_revocation_is_valid(
                    document,
                    source_root=REPOSITORY_ROOT,
                    deployment_root=deployment_root,
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                    live_target_expectation="PREIMAGE",
                )

    def test_failed_preapply_revocation_v3_drift_fails_closed(self) -> None:
        mutations = (
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value.__setitem__("schema", "WRONG"),
            lambda value: value.__setitem__("decision", "REJECT_DEPLOY_REQUEST"),
            lambda value: value.__setitem__(
                "revoked_approval_id", "SITINA_STEP7_DEPLOY_WRONG"
            ),
            lambda value: value["revoked_source"].__setitem__("head", "0" * 40),
            lambda value: value["successor_fix"].__setitem__("tree", "0" * 40),
            lambda value: value["revoked_artifacts"]["packet"].__setitem__(
                "sha256", "0" * 64
            ),
            lambda value: value["revoked_artifacts"][
                "authorization_receipt"
            ].__setitem__("source_raw_record_sha256", "0" * 64),
            lambda value: value["failed_execution_record"].__setitem__(
                "line_number", 11731
            ),
            lambda value: value["backup_residue"]["inventory"][0].__setitem__(
                "inode", -1
            ),
            lambda value: value["backup_residue"].__setitem__(
                "directory_count", 8
            ),
            lambda value: value["deployment_effects"].__setitem__(
                "deployment_target_change_count", 1
            ),
            lambda value: value["recovery"].__setitem__(
                "deployment_rollback_permitted", True
            ),
            lambda value: value["reuse_policy"].__setitem__(
                "may_reuse_packet", True
            ),
            lambda value: value.__setitem__(
                "step8_step9_not_entered", False
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = self._failed_preapply_revocation_document()
                source_state = {
                    "head": document["successor_fix"]["head"],
                    "tree": document["successor_fix"]["tree"],
                }
                mutate(document)
                self.assertFalse(
                    step7_gate._failed_preapply_revocation_is_valid(
                        document,
                        source_root=REPOSITORY_ROOT,
                        deployment_root=Path("/Users/moss/SitinaHub"),
                        source_state=source_state,
                        anchor_root=Path("/Users/moss/.codex/sessions"),
                    )
                )

    def test_failed_preapply_revocation_v3_rejects_preimage_drift(self) -> None:
        document = self._failed_preapply_revocation_document()
        source_state = {
            "head": document["successor_fix"]["head"],
            "tree": document["successor_fix"]["tree"],
        }
        original_sha256 = step7_gate._sha256

        def drift_one_preimage(path: Path) -> str:
            if path == Path("/Users/moss/SitinaHub/scripts/test-bplus.py"):
                return "0" * 64
            return original_sha256(path)

        with mock.patch.object(
            step7_gate,
            "_sha256",
            side_effect=drift_one_preimage,
        ):
            self.assertFalse(
                step7_gate._failed_preapply_revocation_is_valid(
                    document,
                    source_root=REPOSITORY_ROOT,
                    deployment_root=Path("/Users/moss/SitinaHub"),
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                )
            )

    def test_rejected_topology_revocation_v5_is_bound_and_fail_closed(
        self,
    ) -> None:
        source_state = {
            "head": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=REPOSITORY_ROOT,
                text=True,
            ).strip(),
            "tree": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=REPOSITORY_ROOT,
                text=True,
            ).strip(),
        }
        reuse_fields = {
            "may_execute",
            "may_request_authorization",
            "may_reuse_approval_id",
            "may_reuse_packet",
            "may_reuse_candidate",
            "may_reuse_evidence",
            "may_reuse_gate_results",
            "may_reuse_real_sitina_reviews",
            "may_reuse_authorization_request",
            "may_reuse_63671f9_authorization",
            "may_reuse_operations_sha256",
            "may_reuse_plan_sha256",
        }
        document = {
            "schema": step7_gate.REJECTED_TOPOLOGY_REVOCATION_SCHEMA,
            "revoked_at_utc": "2026-07-28T10:00:00Z",
            "source_thread_id": step7_gate.STEP7_SOURCE_THREAD_ID,
            "decision": "REJECT_DEPLOY_REQUEST_REVOKE_AND_REBUILD",
            "physical_classification": (
                "ISOLATED_DYNAMIC_COUNTEREXAMPLE_NO_PRODUCTION_MUTATION"
            ),
            "revoked_approval_id": (
                step7_gate.REJECTED_TOPOLOGY_REVOCATION_APPROVAL_ID
            ),
            "revoked_source": {
                "root": str(REPOSITORY_ROOT),
                **step7_gate.REJECTED_TOPOLOGY_REVOCATION_SOURCE,
            },
            "revoked_artifacts": copy.deepcopy(
                step7_gate.REJECTED_TOPOLOGY_REVOCATION_ARTIFACTS
            ),
            "dynamic_counterexample": {
                "python_version": "3.12.13",
                "filesystem": "APFS_SAME_DEVICE",
                "operation_order": [
                    "scripts/step7_readiness_gate.py",
                    "scripts/test-bplus.py",
                    "tests/foundation/activation_gate_runner.py",
                    "tests/foundation/registration_gate_runner.py",
                    "tests/foundation/test_step7_readiness_gate.py",
                    "tests/test_suites.json",
                ],
                "dry_run_status": "DRY_RUN_VERIFIED",
                "failure_after_operation_index": 0,
                "failure_before_operation_index": 1,
                "execution_error": (
                    "deployment inventory drift immediately before apply"
                ),
                "recovery_status": "MANUAL_RECOVERY_REQUIRED",
                "recovery_error": (
                    "[Errno 2] No such file or directory: 'scripts'"
                ),
                "counted_as_pass": False,
            },
            "deployment_effects": {
                "production_deployment_change_count": 0,
                "production_data_change_count": 0,
                "baseline_change_count": 0,
                "canary_run_count": 0,
                "execution_switch_change_count": 0,
                "external_change_count": 0,
                "backup_root_created": False,
                "step8_step9_entered": False,
            },
            "reuse_policy": {
                field: False for field in reuse_fields
            },
            "successor_requirement": {
                "source_root": str(REPOSITORY_ROOT),
                "head": source_state["head"],
                "tree": source_state["tree"],
                "scope": (
                    "NESTED_CREATE_INVENTORY_AND_"
                    "QUARANTINE_PARENT_CLOSURE_V1"
                ),
                "required_fixes": [
                    "DIRECTORY_INVENTORY_IGNORES_VOLATILE_ST_SIZE_ONLY",
                    (
                        "CREATE_PARENT_DIRECTORY_TYPE_MODE_AND_"
                        "PATH_DRIFT_STILL_DETECTED"
                    ),
                    (
                        "PRECREATE_ALL_REHEARSAL_AND_"
                        "ROLLBACK_QUARANTINE_PARENTS"
                    ),
                    (
                        "BIND_QUARANTINE_PARENT_PATH_DEVICE_"
                        "AND_INODE_IN_MANIFEST"
                    ),
                    (
                        "VERIFY_QUARANTINE_PARENT_BINDINGS_"
                        "BEFORE_FIRST_INTENT_AND_RECOVERY"
                    ),
                    (
                        "EXACT_SIX_OPERATION_SAME_DEVICE_"
                        "SUCCESS_AND_RECOVERY_REGRESSIONS"
                    ),
                ],
            },
            "step8_step9_not_entered": True,
        }
        validate = lambda value: (
            step7_gate._rejected_topology_revocation_is_valid(
                value,
                source_root=REPOSITORY_ROOT,
                deployment_root=Path("/Users/moss/SitinaHub"),
                source_state=source_state,
                anchor_root=Path("/Users/moss/.codex/sessions"),
            )
        )
        self.assertTrue(validate(document))
        for mutation in (
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value["revoked_artifacts"]["packet"].__setitem__(
                "sha256", "0" * 64
            ),
            lambda value: value["dynamic_counterexample"].__setitem__(
                "failure_after_operation_index", 1
            ),
            lambda value: value["deployment_effects"].__setitem__(
                "production_deployment_change_count", 1
            ),
            lambda value: value["reuse_policy"].__setitem__(
                "may_reuse_63671f9_authorization", True
            ),
            lambda value: value["successor_requirement"].__setitem__(
                "tree", "0" * 40
            ),
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(document)
                mutation(changed)
                self.assertFalse(validate(changed))

    def test_interrupted_prebackup_revocation_v4_is_bound_and_fail_closed(
        self,
    ) -> None:
        source_state = {
            "head": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{commit}"],
                cwd=REPOSITORY_ROOT,
                text=True,
            ).strip(),
            "tree": subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=REPOSITORY_ROOT,
                text=True,
            ).strip(),
        }
        packet = json.loads(
            Path(
                step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_ARTIFACTS[
                    "packet"
                ]["path"]
            ).read_text(encoding="utf-8")
        )
        target_preimages = []
        for operation in packet["exact_file_operations"]:
            target_preimages.append(
                {
                    "relative_path": operation["relative_path"],
                    "operation": operation["operation"],
                    "target_path": operation["target_path"],
                    **step7_gate._step7_v4_expected_tuple(
                        operation, postimage=False
                    ),
                }
            )
        policy_sha256 = (
            "8bcdd4f05d16c05fa71ecca2c503da8428c3476b873659a7b38024b144b35470"
        )
        sentinels = [
            {"path": path, "sha256": digest}
            for path, digest in (
                (
                    step7_gate.BASE_SENTINEL_PATH,
                    step7_gate.BASE_SENTINEL_PHYSICAL_SHA256,
                ),
                (
                    step7_gate.MUTABLE_SENTINEL_PATH,
                    step7_gate.MUTABLE_SENTINEL_PHYSICAL_SHA256,
                ),
                (
                    step7_gate.EXECUTION_MANIFEST_PATH,
                    step7_gate.EXECUTION_MANIFEST_PHYSICAL_SHA256,
                ),
            )
        ]
        records = [
            (12741, "DRY_RUN_VERIFIED", "4f5e33346e95fd6ed2c629e136357a493593292bef934edd5817dec0181a6dc9"),
            (12758, "FORMAL_EXECUTE_COMMAND", "491374fd779e867b41e96cdbe055f53f92e7b5a2eeb3315de88edcb3c1445d76"),
            (12759, "FORMAL_EXECUTE_ASYNC_START", "2dfc484ce1f1d2b8cdce94e687f0281cad7b53cfbc4e3a39b20d9fb826124854"),
            (12764, "FORMAL_SEMANTICS_BLOCKER", "714efe5b50a3171f2679ca354fcca2132aaf1014bc21ed069442eb0ee13cade2"),
            (12769, "OPERATOR_INTERRUPT", "458fc3b7a2c51b8d069eaa68832d0fa8d61d9028da894d147f50f6b869d53c64"),
            (12770, "EXIT_130_KEYBOARD_INTERRUPT", "8242fc84b125e48f60d27b53f034e53544220f042860efc37d81c7830fd8c31d"),
            (12775, "POST_ABORT_PHYSICAL_VERIFICATION", "09c685073d5c3436c769ebab0aeefc229606e22218329c7bcb12171c87c535f4"),
        ]
        preparation = {
            name: copy.deepcopy(
                step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_ARTIFACTS[
                    name
                ]
            )
            for name in (
                "authorization_receipt",
                "execution_specification",
                "executor",
                "executor_bytecode",
            )
        }
        reuse_fields = {
            "may_execute",
            "may_retry",
            "may_reuse_packet",
            "may_reuse_candidate",
            "may_reuse_evidence",
            "may_reuse_gate_results",
            "may_reuse_real_sitina_reviews",
            "may_reuse_authorization_request",
            "may_reuse_source_user_record",
            "may_reuse_delegation_wrapper",
            "may_reuse_authorization_receipt",
            "may_reuse_execution_specification",
            "may_reuse_executor",
            "may_reuse_run_id",
            "may_reuse_operations_sha256",
            "may_reuse_plan_sha256",
            "may_reuse_backup_root",
        }
        document = {
            "schema": step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_SCHEMA,
            "revoked_at_utc": "2026-07-28T07:40:00Z",
            "source_thread_id": step7_gate.STEP7_SOURCE_THREAD_ID,
            "decision": "REVOKE_CONSUMED_AUTHORIZATION_AND_REBUILD",
            "physical_classification": (
                "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION_NO_BACKUP_ROOT"
            ),
            "revoked_approval_id": (
                step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_APPROVAL_ID
            ),
            "revoked_source": {
                "root": str(REPOSITORY_ROOT),
                **step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_SOURCE,
            },
            "revoked_artifacts": copy.deepcopy(
                step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_ARTIFACTS
            ),
            "authorization_chain": {
                "source_user_record": {
                    "session_path": (
                        "/Users/moss/.codex/sessions/2026/07/20/"
                        "rollout-2026-07-20T14-42-51-"
                        "019f810d-78fe-75d2-8efd-d43fccbd82d7.jsonl"
                    ),
                    "session_id": step7_gate.STEP7_SOURCE_THREAD_ID,
                    "session_meta_raw_sha256": (
                        "108a46acefdec456c54872ac4cf02a63133a954ceb1f82fbf4d642a13846360e"
                    ),
                    "line_number": 14191,
                    "record_id": "msg_019fa791-d688-7ae1-8b2c-f98bf7a0ee0b",
                    "raw_record_sha256": (
                        "c209761fc6341d942016da06c570ede7a762922f3dfc445b4e32daedaaf38a0a"
                    ),
                    "actual_content_sha256": (
                        "a91e11541291e5272845d084059d64190d213c36a94cfcb5c4a3b47d0b55e73d"
                    ),
                    "actual_content_length": 667,
                    "canonical_logical_sha256": (
                        "554fe6899d86ec16f4709d72f42d0c18c90c195ac3723dc4633bd8c2f5d939bd"
                    ),
                    "canonical_logical_length": 666,
                    "transport_normalization_mode": "REMOVE_ONE_TERMINAL_LF",
                    "transport_removed_suffix_hex": "0a",
                    "transport_removed_byte_count": 1,
                },
                "delegation_wrapper": {
                    "session_path": (
                        step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_SESSION
                    ),
                    "line_number": 12661,
                    "record_id": "msg_019fa792-b4e4-7060-b656-b982f27fe866",
                    "raw_record_sha256": (
                        "2bea2ec4d6d3199748d17cf96c503c402c2cb515017aade35dd07691dbea94ae"
                    ),
                    "content_sha256": (
                        "097dba308c294ce5bc1a8fdfc94cbc49ef67e5229304f9d2b8904c3c50f97239"
                    ),
                    "content_length": 1232,
                    "source_thread_id": step7_gate.STEP7_SOURCE_THREAD_ID,
                },
            },
            "execution_attempt": {
                "session_path": (
                    step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_SESSION
                ),
                "run_id": (
                    step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_RUN_ID
                ),
                "records": [
                    {
                        "line_number": line,
                        "kind": kind,
                        "raw_record_sha256": raw_sha256,
                    }
                    for line, kind, raw_sha256 in records
                ],
                "terminal_verdict_present": False,
                "exit_code": 130,
                "failure_class": (
                    "OPERATOR_ABORT_AFTER_FORMAL_SEMANTICS_BLOCKER"
                ),
                "gate_result_count": 0,
            },
            "stop_phase": {
                "phase": (
                    "READ_ONLY_DEPLOYMENT_TREE_INVENTORY_BEFORE_BACKUP_ROOT"
                ),
                "stack": [
                    "executor.main",
                    "execute_step7_v4",
                    "_step7_v4_inventory",
                    "_step7_v4_file_tuple",
                    "_step7_v4_open_dir_nofollow",
                    "os.open",
                ],
                "first_authorized_write": "CREATE_BACKUP_ROOT",
                "backup_root_creation_reached": False,
            },
            "post_abort_physical_state": {
                "backup_root": {
                    "path": (
                        step7_gate
                        .INTERRUPTED_PREBACKUP_REVOCATION_BACKUP_ROOT
                    ),
                    "exists": False,
                    "is_symlink": False,
                },
                "target_preimages": target_preimages,
                "source_head": (
                    step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_SOURCE[
                        "head"
                    ]
                ),
                "source_tree": (
                    step7_gate.INTERRUPTED_PREBACKUP_REVOCATION_SOURCE[
                        "tree"
                    ]
                ),
                "source_clean_at_abort": True,
                "source_policy": {
                    "path": str(
                        REPOSITORY_ROOT
                        / step7_gate.POLICY_RELATIVE_PATH
                    ),
                    "sha256": policy_sha256,
                },
                "deployment_policy": {
                    "path": (
                        "/Users/moss/SitinaHub/"
                        f"{step7_gate.POLICY_RELATIVE_PATH}"
                    ),
                    "sha256": policy_sha256,
                },
                "execution_switches": {
                    field: False for field in step7_gate.SWITCHES
                },
                "sentinels": sentinels,
            },
            "deployment_effects": {
                "formal_execution_effect_count": 0,
                "deployment_target_change_count": 0,
                "production_data_change_count": 0,
                "baseline_change_count": 0,
                "canary_run_count": 0,
                "execution_switch_change_count": 0,
                "external_change_count": 0,
                "step8_step9_entered": False,
            },
            "preparation_artifacts": {
                "artifact_count": 4,
                "artifacts": preparation,
            },
            "formal_semantics_blockers": [
                "REPLACE_DISPOSABLE_RESTORE_REAPPLY_REHEARSAL_MISSING",
                "PRODUCTION_FAILURE_INJECTION_NOT_AUTHORITY_BOUND",
                "PRODUCTION_RUN_ID_NOT_UNIQUELY_DERIVED",
                "EXECUTION_MANIFEST_NOT_RELOADED_BEFORE_REHEARSAL_OR_APPLY",
                "RECOVERY_VERIFICATION_ARTIFACT_NOT_EMITTED_OR_BOUND",
            ],
            "recovery": {
                "invoked": False,
                "required": False,
                "permitted": False,
                "reason": (
                    "NO_BACKUP_ROOT_NO_MANIFEST_NO_INTENT_"
                    "NO_DEPLOYMENT_MUTATION"
                ),
                "cleanup_required": False,
            },
            "exclusion": {
                "counted_as_pass": False,
                "terminal_verdict_present": False,
                "exit_code": 130,
                "failure_class": (
                    "OPERATOR_ABORT_AFTER_FORMAL_SEMANTICS_BLOCKER"
                ),
                "physical_classification": (
                    "PREAPPLY_ABORTED_NO_DEPLOYMENT_MUTATION_NO_BACKUP_ROOT"
                ),
                "gate_result_count": 0,
                "deployment_file_change_count": 0,
                "external_change_count": 0,
                "recovery_invoked": False,
            },
            "reuse_policy": {
                field: False for field in reuse_fields
            },
            "successor_requirement": {
                "source_root": str(REPOSITORY_ROOT),
                "head": source_state["head"],
                "tree": source_state["tree"],
                "scope": "FORMAL_STEP7_EXECUTION_SEMANTICS_CLOSURE_V1",
                "required_fixes": [
                    "DISPOSABLE_REPLACE_RESTORE_REAPPLY_REHEARSAL",
                    "PRODUCTION_FAILURE_INJECTION_FORBIDDEN",
                    "APPROVAL_DERIVED_PRODUCTION_RUN_ID",
                    "MANIFEST_PHYSICAL_READBACK_BEFORE_REHEARSAL",
                    "PREAPPLY_RECOVERY_VERIFICATION_ARTIFACT_CLOSURE",
                    "LIFECYCLE_CHECKPOINT_PHYSICAL_READBACK_BEFORE_MUTATION",
                    (
                        "REHEARSAL_AND_RECOVERY_VERIFICATION_"
                        "READBACK_BEFORE_FIRST_INTENT"
                    ),
                ],
            },
            "step8_step9_not_entered": True,
        }
        validate = lambda value: (
            step7_gate._interrupted_prebackup_revocation_is_valid(
                value,
                source_root=REPOSITORY_ROOT,
                deployment_root=Path("/Users/moss/SitinaHub"),
                source_state=source_state,
                anchor_root=Path("/Users/moss/.codex/sessions"),
                live_target_expectation="NONE",
            )
        )
        self.assertTrue(validate(document))
        original_file_tuple = step7_gate._step7_v4_file_tuple
        live_targets = {
            Path(operation["target_path"])
            for operation in packet["exact_file_operations"]
        }

        def reject_live_target_tuple(path: Path) -> dict[str, object]:
            if path in live_targets:
                raise AssertionError("historical validation read a live target")
            return original_file_tuple(path)

        with mock.patch.object(
            step7_gate,
            "_step7_v4_file_tuple",
            side_effect=reject_live_target_tuple,
        ):
            self.assertTrue(
                step7_gate._interrupted_prebackup_revocation_is_valid(
                    document,
                    source_root=REPOSITORY_ROOT,
                    deployment_root=Path("/Users/moss/SitinaHub"),
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                    live_target_expectation="NONE",
                )
            )
            with self.assertRaises(AssertionError):
                step7_gate._interrupted_prebackup_revocation_is_valid(
                    document,
                    source_root=REPOSITORY_ROOT,
                    deployment_root=Path("/Users/moss/SitinaHub"),
                    source_state=source_state,
                    anchor_root=Path("/Users/moss/.codex/sessions"),
                    live_target_expectation="PREIMAGE",
                )
        mutations = (
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value.__setitem__("schema", "WRONG"),
            lambda value: value["revoked_artifacts"]["packet"].__setitem__(
                "sha256", "0" * 64
            ),
            lambda value: value["authorization_chain"][
                "source_user_record"
            ].__setitem__("raw_record_sha256", "0" * 64),
            lambda value: value["execution_attempt"]["records"][0].__setitem__(
                "line_number", 12740
            ),
            lambda value: value["stop_phase"].__setitem__(
                "backup_root_creation_reached", True
            ),
            lambda value: value["post_abort_physical_state"][
                "target_preimages"
            ][0].__setitem__("exists", True),
            lambda value: value["post_abort_physical_state"][
                "target_preimages"
            ][1].__setitem__("sha256", "0" * 64),
            lambda value: value["deployment_effects"].__setitem__(
                "deployment_target_change_count", 1
            ),
            lambda value: value["formal_semantics_blockers"].pop(),
            lambda value: value["recovery"].__setitem__("invoked", True),
            lambda value: value["reuse_policy"].__setitem__(
                "may_reuse_packet", True
            ),
            lambda value: value["successor_requirement"].__setitem__(
                "tree", "0" * 40
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(document)
                mutate(changed)
                self.assertFalse(validate(changed))

    def test_supporting_evidence_malformed_shapes_fail_closed(self) -> None:
        bundle_original = self.rollback_request_evidence.read_text(
            encoding="utf-8"
        )
        request_original = self.rollback_review_candidate.read_text(
            encoding="utf-8"
        )
        dynamic_executor = self.output / "step7-dynamic-executor.py"
        dynamic_executor.write_text(
            "#!/usr/bin/env python3\n"
            "template = 'step7-5aef88e-authorized-execution.py'\n"
            "exec(compile(template, template, 'exec'))\n",
            encoding="utf-8",
        )
        noop_executor = self.output / "step7-noop-executor.py"
        noop_executor.write_text(
            "#!/usr/bin/env python3\n"
            "def main() -> int:\n"
            "    return 0\n",
            encoding="utf-8",
        )
        cases = (
            (
                "static_integrity",
                self.general_evidence,
                lambda document: document.__setitem__("gates", None),
                "deployment request static-integrity evidence mismatch",
            ),
            (
                "revocation",
                self.rollback_revocation_stub,
                lambda document: document.__setitem__(
                    "revoked_candidate", []
                ),
                "deployment request revocation evidence mismatch",
            ),
            (
                "revocation",
                self.rollback_revocation_stub,
                lambda document: document.__setitem__(
                    "revoked_packet", None
                ),
                "deployment request revocation evidence mismatch",
            ),
            (
                "static_integrity",
                self.general_evidence,
                lambda document: document.__setitem__(
                    "forbidden_actions", {}
                ),
                "deployment request static-integrity evidence mismatch",
            ),
            (
                "static_integrity",
                self.general_evidence,
                lambda document: document["formal_executor"].__setitem__(
                    "self_contained", False
                ),
                "deployment request formal executor binding mismatch",
            ),
            (
                "static_integrity",
                self.general_evidence,
                lambda document: document["formal_executor"].__setitem__(
                    "dynamic_template",
                    {
                        "path": "step7-5aef88e-authorized-execution.py",
                        "sha256": "0" * 64,
                    },
                ),
                "deployment request formal executor binding mismatch",
            ),
            (
                "static_integrity",
                self.general_evidence,
                lambda document: document["formal_executor"].__setitem__(
                    "executor", self._reference(dynamic_executor)
                ),
                "deployment request formal executor binding mismatch",
            ),
            (
                "static_integrity",
                self.general_evidence,
                lambda document: document["formal_executor"].__setitem__(
                    "executor", self._reference(noop_executor)
                ),
                "deployment request formal executor binding mismatch",
            ),
        )
        originals = {
            path: path.read_text(encoding="utf-8")
            for _, path, _, _ in cases
        }
        try:
            for category, path, mutate, expected_error in cases:
                document = json.loads(originals[path])
                mutate(document)
                path.write_text(
                    json.dumps(document, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                replacement = self._reference(path)
                bundle = json.loads(bundle_original)
                bundle["evidence"][category] = replacement
                self.rollback_request_evidence.write_text(
                    json.dumps(bundle, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                request = json.loads(request_original)
                request["evidence_bundle"] = self._reference(
                    self.rollback_request_evidence
                )
                self.rollback_review_candidate.write_text(
                    json.dumps(request, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                candidate = copy.deepcopy(self.candidate)
                candidate["deployment_request_supporting_evidence"][
                    category
                ] = replacement
                for index, existing in enumerate(candidate["evidence"]):
                    if existing["path"] == str(path):
                        candidate["evidence"][index] = replacement
                self._refresh_bound_reference(
                    candidate,
                    self.rollback_request_evidence,
                )
                candidate["rollback_proof"]["deployment_request_candidate"] = (
                    self._refresh_bound_reference(
                        candidate,
                        self.rollback_review_candidate,
                    )
                )
                self.assertRejected(candidate, expected_error)
                path.write_text(originals[path], encoding="utf-8")
        finally:
            for path, original in originals.items():
                path.write_text(original, encoding="utf-8")
            self.rollback_request_evidence.write_text(
                bundle_original,
                encoding="utf-8",
            )
            self.rollback_review_candidate.write_text(
                request_original,
                encoding="utf-8",
            )

    def test_step56_accepts_cannot_be_missing_duplicated_or_tampered(self) -> None:
        baseline = self._validate()
        self.assertTrue(baseline["accepted"], baseline["errors"])
        accepts = self.candidate["step56_independent_accepts"]

        candidate = copy.deepcopy(self.candidate)
        candidate.pop("step56_independent_accepts")
        self.assertFalse(self._validate(candidate)["accepted"])

        candidate = copy.deepcopy(self.candidate)
        candidate["step56_independent_accepts"] = [
            copy.deepcopy(accepts[0]),
            copy.deepcopy(accepts[0]),
            copy.deepcopy(accepts[2]),
        ]
        self.assertFalse(self._validate(candidate)["accepted"])

        accept_path = Path(accepts[0]["path"])
        original = accept_path.read_text(encoding="utf-8")
        try:
            document = json.loads(original)
            document["decision"]["marker"] = "REJECT_STEP7_ENTRY"
            accept_path.write_text(
                json.dumps(document, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            candidate = copy.deepcopy(self.candidate)
            candidate["step56_independent_accepts"][0] = (
                self._refresh_bound_reference(candidate, accept_path)
            )
            result = self._validate(candidate)
            self.assertFalse(
                result["accepted"],
                "a tampered formal Step5/6 acceptance was accepted with a fresh SHA-256",
            )
        finally:
            accept_path.write_text(original, encoding="utf-8")

    def test_step56_active_session_allows_tail_append_after_accepted_prefix(
        self,
    ) -> None:
        source = Path(STEP56_SOURCE_SESSION_PATH)
        prefix = source.read_bytes()[:STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH]
        fixture = self.output / "step56-session-with-legal-tail.jsonl"
        fixture.write_bytes(
            prefix
            + b'{"type":"event_msg","payload":{"type":"legal_tail_append"}}\n'
        )
        errors: list[str] = []
        raw_lines = _verify_step56_source_session(fixture, errors)
        self.assertEqual(errors, [])
        self.assertEqual(
            len(raw_lines),
            STEP56_SOURCE_SESSION_PREFIX_LINE_COUNT,
        )

    def test_step56_active_session_rejects_target_record_change(self) -> None:
        source = Path(STEP56_SOURCE_SESSION_PATH)
        prefix = bytearray(
            source.read_bytes()[:STEP56_SOURCE_SESSION_PREFIX_BYTE_LENGTH]
        )
        # The expected digest is not stored in the record, so mutate a byte in
        # the exact target record ID while keeping the surrounding JSON valid.
        needle = b"amsg_019fa247-a1e1-7581-ae28-ff462b6887f6"
        offset = prefix.rfind(needle)
        self.assertGreater(offset, 0)
        prefix[offset + len(needle) - 1] = ord("7")
        fixture = self.output / "step56-session-with-tampered-accept.jsonl"
        fixture.write_bytes(prefix)
        errors: list[str] = []
        self.assertEqual(_verify_step56_source_session(fixture, errors), [])
        self.assertIn(
            "formal Step5/6 source session prefix has changed",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
