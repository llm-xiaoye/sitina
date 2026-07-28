from __future__ import annotations

import copy
import hashlib
import json
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
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


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
        self.rollback_approval_id = "SITINA_STEP7_DEPLOY_TEST_FIXTURE"
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
            "warning_count": 0,
            "warning_lines": [],
            "external_attempt_count": 0,
            "production_attempt_count": 0,
            "production_attempt_records": [],
            "production_attempt_log_sha256": hashlib.sha256(b"").hexdigest(),
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

    def _review_input_document(
        self,
        review_stage: str,
        required_files: list[dict[str, object]],
    ) -> dict[str, object]:
        return {
            "schema": "SITINA_STEP7_REAL_REVIEW_INPUT_V1",
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

    def _finalize_review_inputs_and_audits(self) -> None:
        cleanup_files = [
            self._review_required_file(
                self.cleanup_candidate, "json", "cleanup candidate"
            ),
            self._review_required_file(
                self.cleanup_ledger, "json", "cleanup ledger"
            ),
        ]
        self.cleanup_review_input.write_text(
            json.dumps(
                self._review_input_document("CLEANUP_CLOSURE", cleanup_files),
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
        self.review_input.write_text(
            json.dumps(
                self._review_input_document("STEP7_FULL_REVIEW", full_files),
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
        return json.dumps(
            {
                "schema": "SITINA_STEP7_REAL_REVIEW_RESULT_V1",
                "review_stage": review_stage,
                "source_head": self._git("rev-parse", "HEAD^{commit}"),
                "source_tree": self._git("rev-parse", "HEAD^{tree}"),
                "verdict": "PASS",
                "blockers": [],
                "step8_step9_not_entered": True,
                "files_read": files_read,
            },
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
        second_messages = [{"role": "user", "content": "Return the verdict."}]

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
                    "argument_summary": {
                        "schema": "SITINA_TOOL_ARGUMENT_SUMMARY_V1",
                        "normalized_tool_name": "sitina.sitina_read_file",
                        "argument_bytes_after_redaction": len(
                            json.dumps(call["arguments"]).encode("utf-8")
                        ),
                        "argument_hash": hashlib.sha256(
                            json.dumps(
                                call["arguments"], sort_keys=True
                            ).encode("utf-8")
                        ).hexdigest(),
                        "argument_keys": ["path"],
                        "redacted_paths": [],
                    },
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
                    "argument_summary": {
                        "schema": "SITINA_TOOL_ARGUMENT_SUMMARY_V1",
                        "normalized_tool_name": "sitina.sitina_read_file",
                        "argument_bytes_after_redaction": len(
                            json.dumps(call["arguments"]).encode("utf-8")
                        ),
                        "argument_hash": hashlib.sha256(
                            json.dumps(
                                call["arguments"], sort_keys=True
                            ).encode("utf-8")
                        ).hexdigest(),
                        "argument_keys": ["path"],
                        "redacted_paths": [],
                    },
                    "result_summary": {
                        "schema": "SITINA_TOOL_RESULT_SUMMARY_V1",
                        "normalized_tool_name": "sitina.sitina_read_file",
                        "permission_decision": "allowed",
                        "status": "ok",
                        "error": None,
                        "result_ref": f"sha256:{'3' * 64}",
                        "duration_ms": 1,
                        "result_bytes_after_redaction": 1,
                        "result_redacted_paths": [],
                    },
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
            for field in (
                "delete_operation_count",
                "unlink_operation_count",
                "rmtree_operation_count",
            ):
                self.assertEqual(result[field], 0)

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
                self.assertIn(
                    "missing rehearsal-result",
                    rejected["recovery_error"],
                )
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

    def test_v4_production_gate_contract_binds_physical_runner_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deployment = Path(directory).resolve()
            foundation = deployment / "tests/foundation"
            foundation.mkdir(parents=True)
            activation = foundation / "activation_gate_runner.py"
            registration = foundation / "registration_gate_runner.py"
            activation.write_text("activation\n", encoding="utf-8")
            registration.write_text("registration\n", encoding="utf-8")
            registry = {
                "schema": "BPLUS_TEST_SUITES_V1",
                "approved_python": (
                    "/Users/moss/Desktop/sitina/bplus-test-runtime/"
                    "cpython-3.12.13-lock-dbc3f95b77ed/bin/python"
                ),
                "historical_skip_allowlist": [
                    {"test_id": test_id, "reason": HISTORICAL_SKIP_REASON}
                    for test_id in HISTORICAL_SKIP_IDS
                ],
                "suites": {
                    "execution_activation_gate": {
                        "selectors": ["tests/test_execution_bridge.py"]
                    }
                },
            }
            registry_path = deployment / "tests/test_suites.json"
            registry_path.write_text(
                json.dumps(registry, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            first = _step7_v4_production_gate_contract(deployment)
            self.assertEqual(
                first["activation_runner"]["sha256"], sha256(activation)
            )
            activation.write_text("changed\n", encoding="utf-8")
            second = _step7_v4_production_gate_contract(deployment)
            self.assertNotEqual(
                first["activation_runner"]["sha256"],
                second["activation_runner"]["sha256"],
            )

    def test_v4_production_gate_contract_binds_postimage_to_deployment_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            deployment = root / "deployment"
            for tree in (source, deployment):
                (tree / "tests/foundation").mkdir(parents=True)
                (tree / "tests/foundation/activation_gate_runner.py").write_text(
                    f"{tree.name}-activation\n", encoding="utf-8"
                )
                (tree / "tests/foundation/registration_gate_runner.py").write_text(
                    f"{tree.name}-registration\n", encoding="utf-8"
                )
                registry = {
                    "schema": "BPLUS_TEST_SUITES_V1",
                    "approved_python": APPROVED_PYTHON_PATH,
                    "historical_skip_allowlist": [
                        {"test_id": test_id, "reason": HISTORICAL_SKIP_REASON}
                        for test_id in HISTORICAL_SKIP_IDS
                    ],
                    "suites": {
                        "execution_activation_gate": {
                            "selectors": ["tests/test_execution_bridge.py"]
                        }
                    },
                }
                (tree / "tests/test_suites.json").write_text(
                    json.dumps(registry, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            contract = _step7_v4_production_gate_contract(
                deployment, content_root=source
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
            if existing["path"] == str(path):
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
        result = self._validate()
        self.assertTrue(result["accepted"], result["errors"])
        self.assertEqual(result["error_count"], 0)
        self.assertFalse(result["step8_admission_granted"])
        self.assertEqual(result["marker"], READY_MARKER)

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

    def test_supporting_evidence_malformed_shapes_fail_closed(self) -> None:
        bundle_original = self.rollback_request_evidence.read_text(
            encoding="utf-8"
        )
        request_original = self.rollback_review_candidate.read_text(
            encoding="utf-8"
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
