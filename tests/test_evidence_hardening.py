from __future__ import annotations

import tempfile
import unittest
import hashlib
import json
import importlib.util
import runpy
import sqlite3
import shutil
from unittest.mock import patch
from pathlib import Path

from sitina.orchestrator.accounting import ProviderAccounting
from sitina.orchestrator.acceptance_report import AcceptanceReportGenerator
from sitina.orchestrator.audit_verify import AuditVerifier
from sitina.orchestrator.baseline import BaselineManager
from sitina.orchestrator.blackboard import Blackboard, BlackboardVersionConflict
from sitina.orchestrator.cli_evidence import CLI_CHECKS, CliEvidenceRecorder
from sitina.orchestrator.collaboration import CollaborationRuntime
from sitina.orchestrator.evidence_bundle import EvidenceBundleManager
from sitina.guards.secrets import scan_json_for_secrets, scan_paths_for_secrets, scan_sqlite_for_secrets, scan_text_for_secrets
from sitina.security.profile_exception import evaluate_deepseek_direct_storage_exception
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.maintenance import MaintenanceOps
from sitina.orchestrator.replay import ReplayEngine, ReplayResult
from sitina.orchestrator.replay_snapshot import ReplaySnapshotManager
from sitina.orchestrator.revision import CodeRevisionResolver, REVISION_FIELDS
from sitina.orchestrator.run_manifest import RunManifestManager
from sitina.orchestrator.reporting import ReportPersistence, report_exit_code
from sitina.orchestrator.retry import RetryDecision, RetryPolicy
from sitina.orchestrator.task_graph import TaskGraph, TaskGraphNode, TaskGraphRuntime
from sitina.orchestrator.terminal import terminal_summary
from sitina.orchestrator.timeout_support import ensure_terminal_event
from sitina.storage import SitinaStore
from sitina.utils import file_sha256, iso_now, sha256_text, stable_json, write_json


class EvidenceHardeningTests(unittest.TestCase):
    def _home(self, root: str) -> Path:
        home = Path(root)
        (home / "core" / "sitina").mkdir(parents=True)
        (home / "core" / "sitina" / "fixture.py").write_text("VALUE = 1\n", encoding="utf-8")
        (home / "config").mkdir(parents=True)
        (home / "config" / "sitina.yaml").write_text("{}\n", encoding="utf-8")
        (home / "config" / "roles.env").write_text('export SITINA_ROLE_DEFAULT_PROFILE="deepseek"\n', encoding="utf-8")
        SitinaStore(home).init_db()
        return home

    def _record_terminal_run(self, home: Path, run_id: str, *, revision: bool = True) -> None:
        store = SitinaStore(home)
        store.init_db()
        payload = {"provider_mode": "mock"}
        if revision:
            current = CodeRevisionResolver(home).current()
            payload.update({field: current[field] for field in REVISION_FIELDS})
            payload["code_file_count"] = current["code_file_count"]
            payload["revision_hash_method"] = current["revision_hash_method"]
        ledger = RunLedger(home, store)
        ledger.record("run_started", run_id=run_id, reason="test run started", payload=payload)
        ledger.record("run_blocked", run_id=run_id, status="blocked", reason="controlled test block")

    def test_run_records_code_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._record_terminal_run(home, "run_revision")
            revision = CodeRevisionResolver(home).for_run("run_revision")
            self.assertEqual(revision["code_revision_type"], "deterministic_code_hash")
            self.assertTrue(str(revision["code_revision"]).startswith("sha256:"))
            self.assertFalse(revision["legacy_unversioned"])

    def test_code_revision_changes_with_controlled_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            before = CodeRevisionResolver(home).current()["code_revision"]
            (home / "core" / "sitina" / "fixture.py").write_text("VALUE = 2\n", encoding="utf-8")
            after = CodeRevisionResolver(home).current()["code_revision"]
            self.assertNotEqual(before, after)

    def test_secret_files_are_excluded_from_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            before = CodeRevisionResolver(home).current()["code_revision"]
            (home / "profiles").mkdir()
            (home / "profiles" / "deepseek.env").write_text("API_KEY=fake-value-not-read\n", encoding="utf-8")
            after = CodeRevisionResolver(home).current()["code_revision"]
            self.assertEqual(before, after)

    def test_legacy_run_marked_unversioned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._record_terminal_run(home, "run_legacy", revision=False)
            revision = CodeRevisionResolver(home).for_run("run_legacy")
            self.assertTrue(revision["legacy_unversioned"])
            self.assertEqual(revision["code_revision"], "legacy_unversioned")

    def test_run_manifest_contains_all_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_manifest"
            self._record_terminal_run(home, run_id)
            evidence = home / "artifacts" / "provider_parse_failures" / run_id / "controller-0.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"redaction_status":"redacted"}\n', encoding="utf-8")
            manifest = RunManifestManager(home).create(run_id)
            self.assertTrue(RunManifestManager(home).path(run_id).is_file())
            self.assertIn("artifacts/provider_parse_failures/run_manifest/controller-0.json", manifest["associated_files"])
            self.assertTrue(manifest["file_hash"].startswith("sha256:"))
            self.assertEqual(manifest["terminal_event"]["event_type"], "run_blocked")
            self.assertTrue(RunManifestManager(home).verify(manifest)[0])

    def test_manifest_hash_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_manifest_tamper"
            self._record_terminal_run(home, run_id)
            evidence = home / "artifacts" / "provider_parse_failures" / run_id / "controller-0.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"status":"before"}\n', encoding="utf-8")
            manifest = RunManifestManager(home).create(run_id)
            evidence.write_text('{"status":"after"}\n', encoding="utf-8")
            ok, errors = RunManifestManager(home).verify(manifest)
            self.assertFalse(ok)
            self.assertTrue(any("hash mismatch" in item for item in errors))

    def test_report_distinguishes_logical_calls_and_http_attempts(self) -> None:
        accounting = self._accounting_fixture()
        self.assertEqual(accounting["logical_agent_calls"], 2)
        self.assertEqual(accounting["successful_agent_calls"], 1)
        self.assertEqual(accounting["failed_agent_calls"], 1)
        self.assertEqual(accounting["http_attempts"], 3)
        self.assertEqual(accounting["retry_attempts"], 1)

    def test_report_tokens_include_first_and_all_attempts(self) -> None:
        accounting = self._accounting_fixture()
        self.assertEqual(accounting["first_attempt_total_tokens"], 22)
        self.assertEqual(accounting["all_attempt_total_tokens"], 35)
        self.assertGreater(accounting["all_attempt_total_tokens"], accounting["first_attempt_total_tokens"])

    def test_report_duration_includes_wall_clock_and_sum(self) -> None:
        accounting = self._accounting_fixture()
        self.assertEqual(accounting["sum_first_attempt_duration_ms"], 120)
        self.assertEqual(accounting["sum_all_attempt_duration_ms"], 190)
        self.assertEqual(accounting["run_wall_clock_duration_ms"], 1000)

    def test_controlled_fixture_excluded_from_live_usage(self) -> None:
        accounting = self._accounting_fixture(controlled=True)
        self.assertTrue(accounting["controlled_fixture"])
        self.assertFalse(accounting["real_provider_called"])
        self.assertTrue(accounting["excluded_from_live_usage_totals"])

    def test_blocked_run_uses_run_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            store = SitinaStore(home)
            store.init_db()
            ledger = RunLedger(home, store)
            ledger.record("run_started", run_id="run_blocked", reason="started")
            ensure_terminal_event(ledger, "run_blocked", "chat", "blocked", "policy blocked")
            self.assertEqual(terminal_summary(ledger.timeline("run_blocked"))["type"], "run_blocked")

    def test_parse_failure_uses_run_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            store = SitinaStore(home)
            store.init_db()
            ledger = RunLedger(home, store)
            ledger.record("run_started", run_id="run_failed", reason="started")
            ensure_terminal_event(ledger, "run_failed", "chat", "failed", "parser failed")
            self.assertEqual(terminal_summary(ledger.timeline("run_failed"))["type"], "run_failed")

    def test_timeout_uses_run_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            store = SitinaStore(home)
            store.init_db()
            ledger = RunLedger(home, store)
            ledger.record("run_started", run_id="run_timeout", reason="started")
            ensure_terminal_event(ledger, "run_timeout", "chat", "timeout", "deadline")
            self.assertEqual(terminal_summary(ledger.timeline("run_timeout"))["type"], "run_timeout")

    def test_terminal_event_is_unique(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            store = SitinaStore(home)
            store.init_db()
            ledger = RunLedger(home, store)
            ledger.record("run_started", run_id="run_unique", reason="started")
            ensure_terminal_event(ledger, "run_unique", "chat", "blocked", "first")
            ensure_terminal_event(ledger, "run_unique", "chat", "failed", "second")
            self.assertEqual(terminal_summary(ledger.timeline("run_unique"))["count"], 1)

    def test_legacy_blocked_terminal_normalized(self) -> None:
        summary = terminal_summary([{"event_type": "run_failed", "status": "blocked", "reason": "legacy"}])
        self.assertTrue(summary["legacy_blocked_terminal"])
        self.assertEqual(summary["normalized_terminal"], "run_blocked")

    def test_secret_scan_reads_sqlite_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "fixture.db"
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE events (payload_json TEXT)")
                conn.execute("INSERT INTO events (payload_json) VALUES (?)", (json.dumps({"authorization": "Bearer unitsecret1234567890"}),))
            result = scan_sqlite_for_secrets(db)
            self.assertGreaterEqual(result["count"], 1)
            self.assertTrue(all(item["table"] == "events" for item in result["findings"]))

    def test_secret_scan_recursively_walks_json(self) -> None:
        nested = {"outer": json.dumps({"headers": {"authorization": "Bearer nestedsecret123456"}})}
        findings = scan_json_for_secrets(nested)
        self.assertTrue(any("$decoded" in item.field_path for item in findings))

    def test_secret_scan_known_patterns_no_false_negative(self) -> None:
        samples = (
            "API_KEY=unitsecret1234567890",
            "Authorization: Bearer bearerunit123456789",
            "password=unitpassword123456",
            "-----BEGIN PRIVATE KEY-----",
            "SITINA_AUTH_TOKEN=unittoken123456789",
            "sk-unitkey123456789012345",
        )
        for sample in samples:
            with self.subTest(sample=sample.split("=", 1)[0]):
                self.assertTrue(scan_text_for_secrets(sample))

    def test_secret_scan_placeholders_no_false_positive(self) -> None:
        samples = (
            "API_KEY=${SITINA_API_KEY}",
            "api_key=YOUR_API_KEY",
            "authorization=Bearer <redacted>",
            "token_budget=4096",
            "token_hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "provider_request_id=provider_1234567890abcdef",
            "decision_id=dispatch_20260719T171435638629Z",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(scan_text_for_secrets(sample), [])
        self.assertEqual(scan_json_for_secrets({"write_authorization": "not_granted"}), [])

    def test_secret_scan_keeps_internal_equals_in_opaque_tokens(self) -> None:
        internal_equals = "AbCdEf12GhIj=KlMnOp34QrSt"
        named_secret = "API_KEY=unitsecret1234567890"
        opaque = "opaque=AbCdEfGhIjKlMnOpQrStUvWx123456"
        padded = "base64=AbCdEfGhIjKlMnOpQrStUvWx1234=="
        self.assertTrue(
            any(item.pattern_type == "high_entropy_token" for item in scan_text_for_secrets(internal_equals))
        )
        self.assertTrue(scan_text_for_secrets(named_secret))
        self.assertTrue(scan_text_for_secrets(opaque))
        self.assertTrue(scan_text_for_secrets(padded))

    def test_secret_scan_never_outputs_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret_value = "sk-neveroutput123456789012345"
            path = Path(tmp) / "nested.json"
            path.write_text(json.dumps({"api_key": secret_value}), encoding="utf-8")
            result = scan_paths_for_secrets([path])
            self.assertGreaterEqual(result["count"], 1)
            self.assertNotIn(secret_value, json.dumps(result, sort_keys=True))

    def test_secret_scan_skips_generated_bytecode_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "__pycache__"
            cache.mkdir()
            (cache / "fixture.cpython-312.pyc").write_bytes(b"API_KEY=generatedfixture123456")
            result = scan_paths_for_secrets([Path(tmp)])
            self.assertEqual(result["count"], 0)
            self.assertEqual(result["scanned_files"], 0)
            self.assertEqual(result["skipped_files"], 1)

    def test_security_audit_reviews_only_its_exact_safe_source_enum(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/storage-production-security-audit.py"
        spec = importlib.util.spec_from_file_location("storage_production_security_audit_test", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module.DEFAULT_EVIDENCE_ROOT = root
            path = root / "storage-production-security-audit-final.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": "SITINA_STORAGE_PRODUCTION_SECURITY_AUDIT_V1",
                        "secret_values_included": False,
                    }
                ),
                encoding="utf-8",
            )
            controlled = {
                "findings": [
                    {
                        "path": str(path),
                        "field_path": "$.provider_profiles.profiles[0].secret_source",
                        "pattern_type": "sensitive_field",
                    }
                ]
            }
            self.assertEqual(module._review_artifact_patterns(controlled)["status"], "reviewed")
            controlled["findings"][0]["field_path"] = "$.unrelated.secret_source"
            self.assertEqual(module._review_artifact_patterns(controlled)["status"], "unresolved")

    @staticmethod
    def _direct_profile_audit() -> dict[str, object]:
        return {
            "status": "failed",
            "plaintext_secret_count": 1,
            "secret_values_included": False,
            "profiles": [
                {
                    "profile": "deepseek",
                    "status": "failed",
                    "secret_source": "unsafe_or_missing",
                    "reference_scheme": None,
                    "reference_error": None,
                    "findings": ["PLAINTEXT_PROVIDER_SECRET", "PROVIDER_SECRET_REFERENCE_MISSING"],
                    "secret_value_included": False,
                },
                {
                    "profile": "gpt",
                    "status": "ok",
                    "secret_source": "keychain_reference",
                    "reference_scheme": "keychain",
                    "reference_error": None,
                    "findings": [],
                    "secret_value_included": False,
                },
            ],
        }

    def test_deepseek_direct_storage_exception_requires_explicit_user_acceptance(self) -> None:
        audit = self._direct_profile_audit()
        self.assertEqual(
            evaluate_deepseek_direct_storage_exception(audit, user_accepted=False)["status"],
            "not_requested",
        )
        accepted = evaluate_deepseek_direct_storage_exception(audit, user_accepted=True)
        self.assertEqual(accepted["status"], "accepted")
        self.assertTrue(accepted["exact_exception_shape_verified"])
        self.assertFalse(accepted["credential_value_included"])
        self.assertFalse(accepted["credential_modified"])

    def test_deepseek_direct_storage_exception_rejects_any_additional_profile_failure(self) -> None:
        audit = self._direct_profile_audit()
        audit["profiles"][1]["status"] = "failed"
        audit["profiles"][1]["secret_source"] = "unsafe_or_missing"
        self.assertEqual(
            evaluate_deepseek_direct_storage_exception(audit, user_accepted=True)["status"],
            "rejected",
        )

    def test_exact_literal_scanner_detects_chunk_boundary_and_nested_profile_path(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/storage-production-security-audit.py"
        spec = importlib.util.spec_from_file_location("storage_production_security_exact_test", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        literal = b"boundary-secret-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "backup" / "profiles"
            nested.mkdir(parents=True)
            path = nested / "archived.env"
            path.write_bytes(b"12345" + literal + b"67890")
            count, size, digest = module._scan_regular_file_literals(path, (literal,), chunk_size=7)
            self.assertEqual(count, 1)
            self.assertEqual(size, path.stat().st_size)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            result = module._scan_file_literals([root], (literal,))
            self.assertEqual(result["exact_provider_literal_hit_count"], 1)
            self.assertEqual(result["unsafe_path_count"], 0)

    def test_exact_literal_scanner_does_not_follow_symlinks(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/storage-production-security-audit.py"
        spec = importlib.util.spec_from_file_location("storage_production_security_symlink_test", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_text("controlled-secret-value", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(target)
            result = module._scan_file_literals([link], (b"controlled-secret-value",))
            self.assertEqual(result["scanned_files"], 0)
            self.assertEqual(result["unsafe_path_count"], 1)

    def test_backup_mode_review_accepts_only_exact_or_owner_only_tightening(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/storage-production-security-audit.py"
        spec = importlib.util.spec_from_file_location("storage_production_security_mode_test", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            module._backup_mode_disposition(actual=0o600, recorded=0o600),
            "exact",
        )
        self.assertEqual(
            module._backup_mode_disposition(actual=0o600, recorded=0o644),
            "owner_only_tightening",
        )
        self.assertEqual(
            module._backup_mode_disposition(actual=0o644, recorded=0o600),
            "invalid",
        )
        self.assertEqual(
            module._backup_mode_disposition(actual=0o640, recorded=0o644),
            "invalid",
        )

    def test_external_only_permission_scope_needs_no_production_capability(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/storage-production-permission-harden.py"
        module = runpy.run_path(script)
        with module["_permission_authorization"](
            object(),
            home_roots=(),
            manifest_sha256="a" * 64,
            goal_thread_id="goal-thread",
        ):
            pass

    def test_source_manifest_excludes_derived_sentinel_evidence(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/storage-source-manifest.py"
        module = runpy.run_path(script)
        root = Path("/controlled/source")
        self.assertTrue(
            module["_excluded"](
                root / "docs/storage-production-closure/sentinel-after.json",
                root,
            )
        )
        self.assertFalse(
            module["_excluded"](
                root / "docs/storage-production-closure/FINAL_REPORT.md",
                root,
            )
        )

    def test_cli_evidence_missing_command_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recorder = CliEvidenceRecorder(Path(tmp))
            for command in CLI_CHECKS[:-1]:
                recorder.record("run_cli", command, 0, {"status": "ok"})
            summary = recorder.summary("run_cli")
            self.assertEqual(summary["cli_checks_expected"], 12)
            self.assertEqual(summary["cli_checks_executed"], 11)
            self.assertEqual(summary["status"], "incomplete")

    def test_cli_evidence_all_commands_pass_and_hashes_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recorder = CliEvidenceRecorder(Path(tmp))
            for command in CLI_CHECKS:
                recorder.record("run_cli", command, 0, {"overall_status": "passed"})
            summary = recorder.summary("run_cli")
            self.assertEqual(summary["cli_checks_passed"], 12)
            self.assertEqual(summary["status"], "passed")
            self.assertTrue(all(item["evidence_hash_valid"] for item in summary["checks"]))

    def test_blocked_cli_report_is_protocol_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recorder = CliEvidenceRecorder(Path(tmp))
            evidence = recorder.record("run_cli", "report_acceptance", 2, {"overall_status": "blocked"})
            self.assertTrue(evidence["protocol_ok"])

    def test_report_exit_codes_match_status(self) -> None:
        self.assertEqual({status: report_exit_code(status) for status in ("passed", "failed", "blocked", "incomplete", "stale")}, {"passed": 0, "failed": 1, "blocked": 2, "incomplete": 3, "stale": 4})

    def test_report_contains_schema_version_and_revision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            report = ReportPersistence(home).persist(
                {
                    "report_type": "acceptance",
                    "generated_at": "2026-07-10T00:00:00Z",
                    "run_id": "run_report",
                    "overall_status": "passed",
                    "code_revision": {"code_revision": "sha256:controlled", "config_hash": "sha256:config"},
                }
            )
            self.assertEqual(report["report_schema_version"], "1.0")
            self.assertEqual(report["code_revision_value"], "sha256:controlled")
            self.assertTrue(Path(report["report_path"]).is_file())
            self.assertTrue(ReportPersistence.verify(report))

    def test_report_v1_default_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            store = SitinaStore(home)
            store.init_db()
            generator = AcceptanceReportGenerator(home)
            first = generator.generate_v1_report()
            count_after_first = store.connect().execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            second = generator.generate_v1_report()
            count_after_second = store.connect().execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            self.assertEqual(count_after_first, count_after_second)
            self.assertEqual(first["baseline_id"], second["baseline_id"])
            self.assertEqual(first["run_ids"], second["run_ids"])

    def test_report_v1_refresh_is_retired(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            SitinaStore(home).init_db()
            generator = AcceptanceReportGenerator(home)
            with self.assertRaisesRegex(RuntimeError, "Legacy baseline refresh was retired"):
                generator.generate_v1_report(refresh_baseline=True)

    def test_stale_baseline_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            current = CodeRevisionResolver(home).current()
            stale = dict(current) | {"code_revision": "sha256:stale"}
            BaselineManager(home).save(revision=stale, records=self._baseline_records(), secret_scan={"total_findings": 0})
            self.assertIsNone(BaselineManager(home).current(current))

    def test_dispatcher_decision_event_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            graph = self._dispatch_graph("run_dispatch_explicit")
            decision = CollaborationRuntime(home).dispatch_next(run_id=graph.run_id, task_graph=graph)
            events = RunLedger(home).timeline(graph.run_id)
            self.assertEqual(decision.selected_task, "planner")
            self.assertIn("dispatcher_decision_created", {event["event_type"] for event in events})
            self.assertIn("dispatcher_agent_selected", {event["event_type"] for event in events})

    def test_dispatcher_records_state_snapshot_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            graph = self._dispatch_graph("run_dispatch_hash")
            decision = CollaborationRuntime(home).dispatch_next(run_id=graph.run_id, task_graph=graph)
            self.assertTrue(decision.state_snapshot_hash.startswith("sha256:"))
            self.assertTrue(decision.task_graph_hash.startswith("sha256:"))
            for field in (
                "decision_id",
                "round_id",
                "candidate_agents",
                "eligible_agents",
                "blocked_agents",
                "selected_agent",
                "selected_task",
                "reason_code",
                "reason_summary",
                "decision_source",
                "created_at",
            ):
                self.assertIn(field, decision.model_dump())

    def test_dispatcher_excludes_blocked_agents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            graph = self._dispatch_graph("run_dispatch_blocked")
            graph.nodes.append(
                self._dispatch_node(
                    graph.run_id,
                    "blocked_coder",
                    "coder",
                    "coder",
                    status="blocked",
                    mandatory=False,
                    blocked_reason="controlled block",
                )
            )
            decision = CollaborationRuntime(home).dispatch_next(run_id=graph.run_id, task_graph=graph)
            self.assertEqual(decision.selected_agent, "planner")
            self.assertNotIn("coder", decision.eligible_agents)
            self.assertTrue(any(item["agent_id"] == "coder" for item in decision.blocked_agents))

    def test_dispatcher_does_not_repeat_completed_agents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            graph = self._dispatch_graph("run_dispatch_completed")
            decision = CollaborationRuntime(home).dispatch_next(run_id=graph.run_id, task_graph=graph)
            self.assertEqual(decision.selected_agent, "planner")
            self.assertNotIn("controller", decision.candidate_agents)
            self.assertNotEqual(decision.selected_task, "controller")

    def test_dispatcher_state_changes_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_dispatch_route"
            rework = self._dispatch_node(run_id, "rework_1_planner", "planner_rework", "planner")
            arbitration = self._dispatch_node(run_id, "conflict_arbitration", "arbitration", "arbiter", depends_on=[rework.task_id])
            graph = TaskGraph(run_id=run_id, task_type="code_change", nodes=[rework, arbitration], created_at=iso_now())
            runtime = CollaborationRuntime(home)
            first = runtime.dispatch_next(run_id=run_id, task_graph=graph)
            self.assertEqual(first.selected_agent, "planner")
            self.assertEqual(first.reason_code, "rework_ready")
            graph.nodes[0].status = "completed"
            second = runtime.dispatch_next(run_id=run_id, task_graph=graph)
            self.assertEqual(second.selected_agent, "arbiter")
            self.assertEqual(second.reason_code, "conflict_requires_arbitration")
            self.assertNotEqual(first.state_snapshot_hash, second.state_snapshot_hash)

    def test_report_does_not_count_handoff_as_dispatch_decision(self) -> None:
        explicit = {"event_type": "dispatcher_decision_created", "payload_json": {"decision_id": "decision_1"}}
        timeline = [
            {"event_type": "agent_handoff", "payload_json": {"handoff_id": "handoff_1"}},
            {"event_type": "dispatch_decision", "payload_json": {"decision_id": "legacy_1"}},
            explicit,
        ]
        summary = AcceptanceReportGenerator._dispatcher_summary(timeline)
        self.assertEqual(summary["decision_count"], 1)
        self.assertEqual(summary["decisions"], [explicit["payload_json"]])
        self.assertTrue(summary["task_graph_constrained_dynamic_dispatch"])
        self.assertFalse(summary["fully_open_dynamic_dispatch"])

    def test_typed_rework_has_explicit_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_typed_rework"
            graph = self._completed_rework(home, run_id)
            event_types = [
                event["event_type"]
                for event in RunLedger(home).timeline(run_id)
                if event["event_type"] in {"rework_requested", "rework_dispatched", "rework_started", "rework_completed", "rework_failed", "rework_retry_exhausted"}
            ]
            self.assertEqual(event_types, ["rework_requested", "rework_dispatched", "rework_started", "rework_completed"])
            lifecycle = [event["payload_json"] for event in RunLedger(home).timeline(run_id) if event["event_type"] in set(event_types)]
            self.assertEqual(len({item["rework_id"] for item in lifecycle}), 1)
            for item in lifecycle:
                for field in ("source_evaluation_id", "failure_type", "target_agent", "parent_task_id", "retry_index", "max_retries", "input_hash", "output_hash", "terminal_status"):
                    self.assertIn(field, item)
            self.assertEqual(lifecycle[0]["failure_type"], "missing_evidence")
            self.assertEqual(lifecycle[-1]["terminal_status"], "completed")
            for task_id in ("rework_1_coder_rework", "rework_1_tester_rerun", "rework_1_reviewer_rerun"):
                self.assertEqual(graph.node_map[task_id].status, "completed")

    def test_rework_retry_exhausted_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_rework_exhausted"
            source = self._dispatch_node(run_id, "tester", "tester", "tester", status="blocked", blocked_reason="missing evidence")
            graph = TaskGraph(run_id=run_id, task_type="code_change", nodes=[source], created_at=iso_now())
            TaskGraphRuntime(home).save(graph)
            decision = RetryDecision(
                failure_type="missing_evidence",
                status="blocked",
                action="return_to_coder",
                attempt=3,
                max_attempts=2,
                rerun_gates=["tester", "reviewer"],
                escalation="needs_replan",
                reason="missing evidence retry exhausted",
            )
            RetryPolicy(home).materialize_rework_edge(graph, decision, from_task_id="tester", failure_id="evaluation_missing_1")
            events = [event for event in RunLedger(home).timeline(run_id) if event["event_type"].startswith("rework_")]
            lifecycle = [event for event in events if event["event_type"] in {"rework_requested", "rework_retry_exhausted"}]
            self.assertEqual([event["event_type"] for event in lifecycle], ["rework_requested", "rework_retry_exhausted"])
            self.assertEqual(lifecycle[0]["payload_json"]["rework_id"], lifecycle[1]["payload_json"]["rework_id"])
            self.assertEqual(lifecycle[1]["payload_json"]["terminal_status"], "retry_exhausted")

    def test_rework_replay_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_rework_replay"
            self._completed_rework(home, run_id)
            replay = ReplayEngine(home).replay(run_id, record=False)
            self.assertEqual(
                [item["event_type"] for item in replay.rework_lifecycle],
                ["rework_requested", "rework_dispatched", "rework_started", "rework_completed"],
            )
            self.assertEqual(len({item["rework_id"] for item in replay.rework_lifecycle}), 1)
            summary = AcceptanceReportGenerator._rework_summary(replay)
            self.assertEqual(summary["rework_count"], 1)
            self.assertEqual(summary["terminal_counts"]["rework_completed"], 1)

    def test_blackboard_run_partition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            board = Blackboard(home)
            first = board.record_document(
                run_id="run_partition_a",
                task_id="main",
                author_agent="planner",
                doc_type="claim",
                content_summary="run A isolated claim",
                expected_version=0,
            )
            second = board.record_document(
                run_id="run_partition_b",
                task_id="main",
                author_agent="reviewer",
                doc_type="evidence",
                content_summary="run B isolated evidence",
                expected_version=0,
            )
            self.assertTrue(board.run_path("run_partition_a").is_file())
            self.assertTrue(board.run_path("run_partition_b").is_file())
            self.assertEqual([item["doc_id"] for item in board.documents("run_partition_a")], [first.doc_id])
            self.assertEqual([item["doc_id"] for item in board.documents("run_partition_b")], [second.doc_id])
            self.assertEqual(board.partition_version("run_partition_a"), 1)

            board.path.parent.mkdir(parents=True, exist_ok=True)
            board.path.write_text(
                json.dumps({"documents": [{"doc_id": "legacy_doc", "run_id": "run_partition_a", "doc_type": "claim", "content_summary": "legacy read"}]}),
                encoding="utf-8",
            )
            self.assertEqual({item["doc_id"] for item in board.documents("run_partition_a")}, {first.doc_id, "legacy_doc"})
            replay = ReplayEngine(home).replay("run_partition_a", record=False)
            self.assertTrue(any(item.get("doc_id") == first.doc_id for item in replay.blackboard_summary["documents"]))

    def test_blackboard_version_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            board = Blackboard(home)
            created = board.record_document(
                run_id="run_blackboard_cas",
                task_id="main",
                author_agent="planner",
                doc_type="claim",
                content_summary="version one",
                expected_version=0,
            )
            updated = board.update_document(
                run_id="run_blackboard_cas",
                doc_id=created.doc_id,
                author_agent="reviewer",
                expected_version=1,
                content_summary="version two",
            )
            self.assertEqual(updated.version, 2)
            with self.assertRaises(BlackboardVersionConflict):
                board.update_document(
                    run_id="run_blackboard_cas",
                    doc_id=created.doc_id,
                    author_agent="critic",
                    expected_version=1,
                    content_summary="stale update",
                )
            stored = next(item for item in board.documents("run_blackboard_cas") if item["doc_id"] == created.doc_id)
            self.assertEqual(stored["version"], 2)
            conflicts = [event for event in RunLedger(home).timeline("run_blackboard_cas") if event["event_type"] == "blackboard_version_conflict"]
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0]["payload_json"]["expected_version"], 1)
            self.assertEqual(conflicts[0]["payload_json"]["actual_version"], 2)

    def test_prune_defaults_to_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_prune_dry"
            self._old_run(home, run_id)
            self._fake_evidence_bundle(home, run_id)
            maintenance = MaintenanceOps(home)
            result = maintenance.prune(older_than_days=30)
            self.assertEqual(result["mode"], "dry_run")
            self.assertTrue(result["dry_run"])
            self.assertFalse(result["permanent_delete"])
            self.assertFalse(result["vacuum_performed"])
            self.assertFalse(maintenance.archive_registry_path.exists())
            self.assertIsNotNone(SitinaStore(home).get_run(run_id))

            archived = maintenance.prune(older_than_days=30, dry_run=False, archive=True)
            self.assertEqual(archived["mode"], "archive")
            self.assertEqual(archived["archived_count"], 1)
            self.assertEqual(archived["deleted_run_count"], 0)
            self.assertIsNotNone(SitinaStore(home).get_run(run_id))
            registry = json.loads(maintenance.archive_registry_path.read_text(encoding="utf-8"))
            self.assertIn(run_id, registry["archived_runs"])

    def test_baseline_runs_cannot_be_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_baseline_protected"
            self._old_run(home, run_id)
            self._fake_evidence_bundle(home, run_id)
            revision = CodeRevisionResolver(home).current()
            BaselineManager(home).save(
                revision=revision,
                records={"protected_fixture": {"status": "passed", "run_id": run_id}},
                secret_scan={"total_findings": 0},
            )
            maintenance = MaintenanceOps(home)
            result = maintenance.prune(older_than_days=30, dry_run=False, archive=True)
            candidate = next(item for item in result["candidates"] if item["run_id"] == run_id)
            self.assertIn("baseline_run", candidate["protections"])
            self.assertFalse(candidate["archive_eligible"])
            self.assertEqual(result["archived_count"], 0)
            registry = json.loads(maintenance.archive_registry_path.read_text(encoding="utf-8"))
            self.assertNotIn(run_id, registry["archived_runs"])
            self.assertIsNotNone(SitinaStore(home).get_run(run_id))

    def test_export_evidence_bundle_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as portable_tmp:
            home = self._home(tmp)
            run_id = "run_bundle_verify"
            self._record_terminal_run(home, run_id)
            RunManifestManager(home).create(run_id)
            exported = EvidenceBundleManager(home).export(run_id)
            self.assertEqual(exported["status"], "passed", exported)
            portable = Path(portable_tmp) / "portable_bundle"
            shutil.copytree(exported["bundle_path"], portable)
            verified = EvidenceBundleManager(home).verify(portable)
            self.assertEqual(verified["status"], "passed", verified)
            self.assertEqual(verified["secret_findings"], 0)
            manifest = json.loads((portable / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(all(not Path(item["path"]).is_absolute() for item in manifest["files"]))
            self.assertNotIn(str(home), json.dumps([json.loads(path.read_text(encoding="utf-8")) for path in portable.glob("*.json")]))

    def test_evidence_bundle_tamper_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_bundle_tamper"
            self._record_terminal_run(home, run_id)
            exported = EvidenceBundleManager(home).export(run_id)
            self.assertEqual(exported["status"], "passed", exported)
            bundle = Path(exported["bundle_path"])
            trace = bundle / "trace.json"
            trace.write_text(trace.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            verified = EvidenceBundleManager(home).verify(bundle)
            self.assertEqual(verified["status"], "failed")
            self.assertTrue(any("hash mismatch" in error for error in verified["errors"]))

    def test_audit_verify_detects_orphan_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_audit_orphan"
            self._record_terminal_run(home, run_id)
            RunManifestManager(home).create(run_id)
            before = AuditVerifier(home).verify(run_id)
            self.assertEqual(before["status"], "passed", before)
            SitinaStore(home).record_audit(
                "run_ledger",
                {"event_type": "synthetic_orphan"},
                run_id=run_id,
                trace_id=f"{run_id}:ledger:orphan",
                exit_status="ok",
            )
            after = AuditVerifier(home).verify(run_id)
            self.assertEqual(after["status"], "failed")
            self.assertFalse(after["checks"]["no_orphan_ledger_audit"])

    def test_replay_snapshot_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_replay_hash_chain"
            self._record_terminal_run(home, run_id)
            engine = ReplayEngine(home)
            first = engine.replay(run_id, record=True)
            self.assertEqual(first.snapshot_integrity["status"], "passed")
            second = engine.replay(run_id, record=True)
            self.assertEqual(second.snapshot_integrity["snapshot_count"], 2)
            directory = ReplaySnapshotManager(home).run_directory(run_id)
            first_path = directory / "000001.json"
            second_path = directory / "000002.json"
            first_doc = json.loads(first_path.read_text(encoding="utf-8"))
            second_doc = json.loads(second_path.read_text(encoding="utf-8"))
            self.assertEqual(second_doc["previous_snapshot_hash"], first_doc["snapshot_hash"])
            for field in ("snapshot_hash", "previous_snapshot_hash", "event_range_hash", "code_revision", "created_at"):
                self.assertIn(field, second_doc)

            original_second = second_path.read_text(encoding="utf-8")
            second_doc["created_at"] = "tampered"
            second_path.write_text(json.dumps(second_doc), encoding="utf-8")
            tampered = engine.replay(run_id, record=False)
            self.assertEqual(tampered.status, "replay_inconsistent")
            self.assertEqual(tampered.snapshot_integrity["status"], "failed")
            second_path.write_text(original_second, encoding="utf-8")

            original_first = first_path.read_text(encoding="utf-8")
            first_path.unlink()
            self.assertEqual(ReplaySnapshotManager(home).verify(run_id, RunLedger(home).timeline(run_id))["status"], "failed")
            first_path.write_text(original_first, encoding="utf-8")

            temporary = directory / "swap.json"
            first_path.rename(temporary)
            second_path.rename(first_path)
            temporary.rename(second_path)
            self.assertEqual(ReplaySnapshotManager(home).verify(run_id, RunLedger(home).timeline(run_id))["status"], "failed")

            legacy_run = "run_legacy_snapshot"
            self._record_terminal_run(home, legacy_run)
            legacy_path = ReplaySnapshotManager(home).root / f"{legacy_run}-old.json"
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            legacy_path.write_text('{"run_id":"run_legacy_snapshot","status":"replay_ok"}\n', encoding="utf-8")
            legacy = ReplayEngine(home).replay(legacy_run, record=False)
            self.assertEqual(legacy.snapshot_integrity["status"], "legacy_unverified")

    @staticmethod
    def _baseline_records() -> dict[str, dict[str, str | int]]:
        names = (
            "code_change_fixture",
            "handoff_reject_fixture",
            "arbitration_ask_user_fixture",
            "lease_conflict_fixture",
            "high_risk_full_gate_fixture",
            "side_effect_descriptor_fixture",
        )
        return {
            name: {
                "status": "passed",
                "run_id": f"run_{index}",
                "terminal": "run_blocked" if "reject" in name or "ask_user" in name else "run_completed",
                "replay": "replay_ok",
                "simulate": "replay_simulated",
                "diff": "match",
                "secret_scan": 0,
            }
            for index, name in enumerate(names)
        }

    @classmethod
    def _dispatch_graph(cls, run_id: str) -> TaskGraph:
        controller = cls._dispatch_node(run_id, "controller", "controller", "controller", status="completed")
        planner = cls._dispatch_node(run_id, "planner", "planner", "planner", depends_on=["controller"])
        return TaskGraph(run_id=run_id, task_type="code_change", nodes=[controller, planner], created_at=iso_now())

    @staticmethod
    def _dispatch_node(
        run_id: str,
        task_id: str,
        node_type: str,
        owner_agent: str,
        *,
        status: str = "pending",
        depends_on: list[str] | None = None,
        mandatory: bool = True,
        blocked_reason: str | None = None,
    ) -> TaskGraphNode:
        return TaskGraphNode(
            task_id=task_id,
            run_id=run_id,
            task_type="code_change",
            node_type=node_type,
            owner_agent=owner_agent,
            status=status,
            depends_on=depends_on or [],
            mandatory=mandatory,
            blocked_reason=blocked_reason,
            created_at=iso_now(),
        )

    @classmethod
    def _completed_rework(cls, home: Path, run_id: str) -> TaskGraph:
        ledger = RunLedger(home)
        ledger.record("run_started", run_id=run_id, task_type="code_change", reason="typed rework test started")
        source = cls._dispatch_node(run_id, "tester", "tester", "tester", status="blocked", blocked_reason="missing evidence")
        graph = TaskGraph(run_id=run_id, task_type="code_change", nodes=[source], created_at=iso_now())
        runtime = TaskGraphRuntime(home)
        runtime.save(graph)
        decision = RetryDecision(
            failure_type="missing_evidence",
            status="retry",
            action="return_to_coder",
            attempt=1,
            max_attempts=2,
            rerun_gates=["tester", "reviewer"],
            escalation="needs_replan",
            reason="missing evidence requires controlled rework",
        )
        graph = RetryPolicy(home).materialize_rework_edge(
            graph,
            decision,
            from_task_id="tester",
            approved_scope_hash="sha256:controlled-scope",
            failure_id="evaluation_missing_1",
        )
        for task_id in ("rework_1_coder_rework", "rework_1_tester_rerun", "rework_1_reviewer_rerun"):
            graph = runtime.transition(graph, task_id, "running", reason=f"{task_id} started")
            graph = runtime.transition(graph, task_id, "completed", reason=f"{task_id} completed", patch_hash="sha256:controlled-output")
        ledger.record("run_completed", run_id=run_id, task_type="code_change", reason="typed rework test completed")
        return graph

    @staticmethod
    def _old_run(home: Path, run_id: str) -> None:
        store = SitinaStore(home)
        store.upsert_run_state(
            {
                "run_id": run_id,
                "phase": "done",
                "risk_level": "low",
                "verification_status": "verified",
            }
        )
        with store.connect() as conn:
            conn.execute("UPDATE runs SET created_at = ?, updated_at = ? WHERE run_id = ?", ("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z", run_id))

    @staticmethod
    def _fake_evidence_bundle(home: Path, run_id: str) -> Path:
        directory = home / "outputs" / "evidence" / "bundles" / run_id / "bundle_fixture"
        payload = directory / "payload.json"
        write_json(payload, {"run_id": run_id, "status": "passed"})
        body = {
            "bundle_id": "bundle_fixture",
            "bundle_schema_version": "1.0",
            "run_id": run_id,
            "created_at": iso_now(),
            "code_revision": {"code_revision": "sha256:fixture"},
            "files": [{"path": "payload.json", "hash": file_sha256(payload)}],
        }
        write_json(directory / "manifest.json", body | {"evidence_hash": sha256_text(stable_json(body))})
        return directory

    def _accounting_fixture(self, *, controlled: bool = False) -> dict:
        timeline = [
            {
                "event_type": "run_started",
                "timestamp": "2026-07-10T00:00:00Z",
                "payload_json": {"controlled_fixture": controlled, "controlled_fixture_type": "timeout" if controlled else None},
            },
            {"event_type": "agent_started", "task_id": "one", "agent_id": "planner", "payload_json": {"provider_mode": "live"}},
            {"event_type": "agent_completed", "task_id": "one", "agent_id": "planner", "payload_json": {"provider_mode": "live"}},
            {"event_type": "agent_started", "task_id": "two", "agent_id": "reviewer", "payload_json": {"provider_mode": "live"}},
            {"event_type": "agent_blocked", "task_id": "two", "agent_id": "reviewer", "payload_json": {"provider_mode": "live"}},
            {"event_type": "run_completed", "timestamp": "2026-07-10T00:00:01Z", "payload_json": {}},
        ]
        calls_one = [
            {"attempt": 1, "duration_ms": 70, "token_usage": {"input_tokens": 8, "output_tokens": 4, "total_tokens": 12}},
            {"attempt": 2, "duration_ms": 70, "token_usage": {"input_tokens": 9, "output_tokens": 4, "total_tokens": 13}},
        ]
        calls_two = [{"attempt": 1, "duration_ms": 50, "token_usage": {"input_tokens": 6, "output_tokens": 4, "total_tokens": 10}}]
        replay = ReplayResult(
            run_id="run_accounting",
            status="replay_ok",
            event_count=len(timeline),
            agent_snapshots=[
                {"task_id": "one", "agent_id": "planner", "provider_mode": "live", "provider_calls": calls_one},
                {"task_id": "two", "agent_id": "reviewer", "provider_mode": "live", "provider_calls": calls_two},
            ],
        )
        return ProviderAccounting(Path("/tmp/unused-accounting-home")).for_run("run_accounting", timeline=timeline, replay=replay)


if __name__ == "__main__":
    unittest.main()
