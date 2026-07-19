from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.orchestrator.acceptance_report import AcceptanceReportGenerator
from sitina.orchestrator.audit_verify import AuditVerifier
from sitina.orchestrator.cli_evidence import CLI_CHECKS, CliEvidenceRecorder
from sitina.orchestrator.collaboration import CollaborationRuntime
from sitina.orchestrator.engine import SitinaEngine
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.proposals import ProposalBid, ProposalManager
from sitina.orchestrator.reporting import ReportPersistence, report_exit_code
from sitina.orchestrator.revision import CodeRevisionResolver, REVISION_FIELDS
from sitina.orchestrator.run_manifest import RunManifestManager
from sitina.storage import SitinaStore
from sitina.utils import sha256_text, stable_json


class LiveAuditAcceptanceContractTests(unittest.TestCase):
    def _home(self, root: str) -> Path:
        home = Path(root)
        (home / "core" / "sitina").mkdir(parents=True)
        (home / "core" / "sitina" / "fixture.py").write_text("VALUE = 1\n", encoding="utf-8")
        (home / "config").mkdir(parents=True)
        (home / "config" / "sitina.yaml").write_text("{}\n", encoding="utf-8")
        (home / "config" / "roles.env").write_text('export SITINA_ROLE_DEFAULT_PROFILE="deepseek"\n', encoding="utf-8")
        source_policy = Path(__file__).resolve().parents[1] / "config" / "proposal_policy.yaml"
        shutil.copy2(source_policy, home / "config" / "proposal_policy.yaml")
        SitinaStore(home).init_db()
        return home

    def _start_run(self, home: Path, run_id: str, *, provider_mode: str = "live", controlled: bool = False) -> None:
        revision = CodeRevisionResolver(home).current()
        payload = {
            "provider_mode": provider_mode,
            "controlled_fixture": controlled,
            "controlled_fixture_type": "test" if controlled else None,
        }
        payload.update({field: revision[field] for field in REVISION_FIELDS})
        payload["code_file_count"] = revision["code_file_count"]
        payload["revision_hash_method"] = revision["revision_hash_method"]
        ledger = RunLedger(home)
        ledger.record("run_started", run_id=run_id, task_type="code_change", reason="test run started", payload=payload)
        ledger.record(
            "task_graph_created",
            run_id=run_id,
            task_type="code_change",
            reason="test graph",
            payload={"run_id": run_id, "task_type": "code_change", "nodes": []},
        )
        ledger.record(
            "controller_decision",
            run_id=run_id,
            task_type="code_change",
            agent_id="controller",
            reason="test controller decision",
            payload={"decision": "continue"},
        )

    def _seed_call(
        self,
        home: Path,
        run_id: str,
        logical_id: str,
        *,
        agent: str = "planner",
        task_id: str = "proposal",
        provider_mode: str = "live",
        call_origin: str = "collaboration",
        terminal_status: str = "completed",
        attempt_outcomes: tuple[str, ...] = ("completed",),
        terminal_logical_id: str | None = None,
    ) -> None:
        store = SitinaStore(home)
        ledger = RunLedger(home, store)
        input_hash = sha256_text(stable_json({"logical_id": logical_id, "agent": agent}))
        context = {"call_origin": call_origin}
        if call_origin == "handoff_receiver":
            context["handoff_id"] = "handoff_test"
        start_payload = {
            "agent_call_audit_schema_version": "1.0",
            "logical_call_id": logical_id,
            "phase": "started",
            "agent_id": agent,
            "role": agent,
            "task_id": task_id,
            "task_type": "code_change",
            "provider_mode": provider_mode,
            "profile_name": "deepseek" if provider_mode == "live" else None,
            "model": None,
            "input_hash": input_hash,
            "fallback_used": False if provider_mode == "live" else None,
            "context": context,
        }
        ledger.record(
            "agent_call_started",
            run_id=run_id,
            task_id=task_id,
            task_type="code_change",
            agent_id=agent,
            reason="logical call started",
            payload=start_payload,
        )
        store.record_audit(
            "agent_call_started",
            start_payload,
            run_id=run_id,
            trace_id=f"{run_id}:agent_call:{logical_id}:started",
            agent=agent,
            input_hash=input_hash,
            exit_status="started",
        )
        calls = []
        for index, outcome in enumerate(attempt_outcomes, start=1):
            attempt_id = f"attempt_{logical_id}_{index}"
            attempt_base = {
                "attempt_id": attempt_id,
                "logical_call_id": logical_id,
                "attempt": index,
                "provider_mode": provider_mode,
                "profile_name": "deepseek",
                "model": "deepseek-chat",
                "provider_call_started_at": f"2026-07-13T00:00:0{index}Z",
                "fallback_used": False,
            }
            ledger.record(
                "provider_http_attempt_started",
                run_id=run_id,
                task_id=task_id,
                task_type="code_change",
                agent_id=agent,
                reason="attempt started",
                payload=attempt_base,
            )
            terminal_attempt = dict(attempt_base) | {
                "provider_call_completed_at": f"2026-07-13T00:00:1{index}Z",
                "duration_ms": 10,
            }
            if outcome == "completed":
                terminal_attempt |= {
                    "provider_request_id": f"request_{logical_id}_{index}",
                    "token_usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
                }
                event_type = "provider_http_attempt_completed"
                status = "ok"
            else:
                terminal_attempt["error_type"] = "provider_rate_limited"
                event_type = "provider_http_attempt_failed"
                status = "failed"
            ledger.record(
                event_type,
                run_id=run_id,
                task_id=task_id,
                task_type="code_change",
                agent_id=agent,
                status=status,
                reason=f"attempt {outcome}",
                payload=terminal_attempt,
            )
            calls.append(terminal_attempt)
        terminal_id = terminal_logical_id or logical_id
        output_hash = sha256_text(stable_json({"logical_id": terminal_id, "status": terminal_status}))
        terminal_payload = {
            "agent_call_audit_schema_version": "1.0",
            "logical_call_id": terminal_id,
            "phase": "terminal",
            "terminal_status": terminal_status,
            "agent_id": agent,
            "role": agent,
            "task_id": task_id,
            "task_type": "code_change",
            "provider_mode": provider_mode,
            "profile_name": "deepseek" if provider_mode == "live" else None,
            "model": "deepseek-chat" if provider_mode == "live" else None,
            "input_hash": input_hash,
            "output_hash": output_hash if terminal_status == "completed" else None,
            "provider_request_ids": [call["provider_request_id"] for call in calls if call.get("provider_request_id")],
            "attempt_ids": [call["attempt_id"] for call in calls],
            "http_attempt_count": len(calls),
            "duration_ms": 20,
            "schema_validation_status": "valid" if terminal_status == "completed" else "not_completed",
            "fallback_used": False if provider_mode == "live" else None,
            "context": context,
        }
        ledger.record(
            "agent_call_terminal",
            run_id=run_id,
            task_id=task_id,
            task_type="code_change",
            agent_id=agent,
            status="ok" if terminal_status == "completed" else "failed",
            reason=f"logical call {terminal_status}",
            payload=terminal_payload,
        )
        store.record_audit(
            "agent_call_terminal",
            terminal_payload,
            run_id=run_id,
            trace_id=f"{run_id}:agent_call:{terminal_id}:terminal",
            agent=agent,
            input_hash=input_hash,
            output_hash=terminal_payload["output_hash"],
            exit_status=terminal_status,
            duration_ms=20,
        )

    def _finish_run(self, home: Path, run_id: str, *, terminal: str = "run_completed") -> None:
        status = "ok" if terminal == "run_completed" else "failed"
        RunLedger(home).record(
            terminal,
            run_id=run_id,
            task_type="code_change",
            status=status,
            reason="test terminal",
        )
        RunManifestManager(home).create(run_id)

    def _live_report(self, home: Path, run_id: str) -> dict:
        revision = CodeRevisionResolver(home).for_run(run_id)
        provider_call = {
            "schema_validation_status": "valid",
            "fallback_used": False,
            "provider_request_id": "request_report_1",
        }
        return {
            "overall_status": "passed",
            "run_id": run_id,
            "code_revision": revision,
            "provider_accounting": {"real_provider_called": True, "controlled_fixture": False},
            "replay": {"status": "replay_ok", "snapshot_integrity": {"status": "passed"}},
            "provider": {
                "provider_mode": ["live"],
                "profile_name": ["deepseek"],
                "model": ["deepseek-chat"],
                "all_deepseek": True,
                "fallback_used": False,
                "provider_call_count": 2,
            },
            "terminal_event": {"count": 1, "type": "run_completed", "normalized_terminal": "run_completed", "status": "ok"},
            "simulate": {"status": "replay_simulated"},
            "diff": {"status": "match"},
            "secret_scan": {"total_findings": 0, "status": "ok"},
            "changed_real_files": False,
            "agent_identities": [
                {"agent_id": "controller", "provider_calls": [provider_call]},
                {"agent_id": "planner", "provider_calls": [provider_call]},
            ],
            "lease": [],
            "arbitration": [],
            "retry_rework": {"retry_state": [], "rework_nodes": {}},
            "checkpoint_resume": {"integrity_ok": True},
            "read_write_contract": {"contract_consistent": True},
        }

    def _passed_run(self, home: Path, run_id: str = "run_passed") -> dict:
        self._start_run(home, run_id)
        self._seed_call(home, run_id, "logical_passed")
        self._finish_run(home, run_id)
        return AuditVerifier(home).verify_evidence(run_id)

    def _record_cli_protocol(self, home: Path, run_id: str) -> None:
        recorder = CliEvidenceRecorder(home)
        for command in CLI_CHECKS:
            output = {"overall_status": "passed"} if command.startswith("report_") else {"status": "ok"}
            recorder.record(run_id, command, 0, output)

    def test_01_handoff_receiver_has_high_level_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_handoff")
            self._seed_call(home, "run_handoff", "logical_handoff", call_origin="handoff_receiver")
            self._finish_run(home, "run_handoff")
            result = AuditVerifier(home).verify("run_handoff")
            self.assertEqual(result["status"], "passed", result)
            self.assertEqual(result["agent_call_relationships"][0]["call_origin"], "handoff_receiver")

    def test_02_all_live_call_origins_use_unified_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_origins")
            for index, origin in enumerate(("engine", "collaboration", "handoff_receiver", "arbitration"), start=1):
                self._seed_call(home, "run_origins", f"logical_{index}", task_id=f"task_{index}", call_origin=origin)
            self._finish_run(home, "run_origins")
            result = AuditVerifier(home).verify("run_origins")
            self.assertEqual(result["counts"]["high_level_agent_call_starts"], 4)
            self.assertEqual(result["counts"]["high_level_agent_call_terminals"], 4)
            self.assertEqual({item["call_origin"] for item in result["agent_call_relationships"]}, {"engine", "collaboration", "handoff_receiver", "arbitration"})

    def test_03_each_logical_call_has_one_start_and_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_one_to_one")
            self._seed_call(home, "run_one_to_one", "logical_one")
            self._finish_run(home, "run_one_to_one")
            checks = AuditVerifier(home).verify("run_one_to_one")["checks"]
            self.assertTrue(checks["high_level_start_terminal_one_to_one"])

    def test_04_retry_keeps_one_logical_call_with_multiple_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_retry")
            self._seed_call(home, "run_retry", "logical_retry", attempt_outcomes=("failed", "completed"))
            self._finish_run(home, "run_retry")
            result = AuditVerifier(home).verify("run_retry")
            self.assertEqual(result["counts"]["high_level_agent_call_starts"], 1)
            self.assertEqual(result["counts"]["provider_attempt_terminals"], 2)
            self.assertTrue(result["checks"]["retry_does_not_inflate_logical_calls"])

    def test_05_provider_attempt_requires_logical_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_orphan_attempt")
            self._seed_call(home, "run_orphan_attempt", "logical_valid")
            ledger = RunLedger(home)
            payload = {"attempt_id": "attempt_orphan", "logical_call_id": "logical_orphan", "provider_mode": "live"}
            ledger.record("provider_http_attempt_started", run_id="run_orphan_attempt", agent_id="planner", task_id="proposal", task_type="code_change", payload=payload)
            ledger.record("provider_http_attempt_failed", run_id="run_orphan_attempt", agent_id="planner", task_id="proposal", task_type="code_change", status="failed", reason="orphan", payload=payload)
            self._finish_run(home, "run_orphan_attempt")
            result = AuditVerifier(home).verify("run_orphan_attempt")
            self.assertFalse(result["checks"]["provider_attempts_require_logical_call"])

    def test_06_completed_call_requires_successful_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_no_success")
            self._seed_call(home, "run_no_success", "logical_no_success", attempt_outcomes=("failed",))
            self._finish_run(home, "run_no_success")
            result = AuditVerifier(home).verify("run_no_success")
            self.assertFalse(result["checks"]["completed_calls_have_successful_attempt"])

    def test_07_failed_call_has_one_failed_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_failed_call")
            self._seed_call(home, "run_failed_call", "logical_failed", terminal_status="failed", attempt_outcomes=("failed",))
            self._finish_run(home, "run_failed_call", terminal="run_failed")
            result = AuditVerifier(home).verify("run_failed_call")
            self.assertTrue(result["checks"]["high_level_start_terminal_one_to_one"])
            self.assertEqual(result["agent_call_relationships"][0]["terminal_status"], "failed")

    def test_08_mock_calls_are_excluded_from_live_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_mock", provider_mode="mock")
            self._seed_call(home, "run_mock", "logical_mock", provider_mode="mock", attempt_outcomes=())
            self._finish_run(home, "run_mock")
            result = AuditVerifier(home).verify("run_mock")
            self.assertEqual(result["status"], "passed", result)
            self.assertEqual(result["counts"]["high_level_agent_call_starts"], 0)

    def test_09_duplicate_logical_terminal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_duplicate_terminal")
            self._seed_call(home, "run_duplicate_terminal", "logical_duplicate")
            row = next(item for item in AuditVerifier(home)._audit_rows("run_duplicate_terminal") if item["operation"] == "agent_call_terminal")
            SitinaStore(home).record_audit("agent_call_terminal", row["payload"], run_id="run_duplicate_terminal", agent="planner", exit_status="completed")
            self._finish_run(home, "run_duplicate_terminal")
            result = AuditVerifier(home).verify("run_duplicate_terminal")
            self.assertFalse(result["checks"]["no_duplicate_logical_terminal"])

    def test_10_relationships_not_equal_counts_determine_consistency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_equal_counts_wrong_ids")
            self._seed_call(home, "run_equal_counts_wrong_ids", "logical_start", terminal_logical_id="logical_terminal")
            self._finish_run(home, "run_equal_counts_wrong_ids")
            result = AuditVerifier(home).verify("run_equal_counts_wrong_ids")
            self.assertEqual(result["counts"]["high_level_agent_call_starts"], result["counts"]["high_level_agent_call_terminals"])
            self.assertFalse(result["checks"]["provider_call_count_consistent"])

    def test_11_acceptance_fails_when_audit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_accept_audit_fail")
            self._seed_call(home, "run_accept_audit_fail", "logical_start", terminal_logical_id="logical_other")
            self._finish_run(home, "run_accept_audit_fail")
            audit = AuditVerifier(home).verify_evidence("run_accept_audit_fail")
            report = AcceptanceReportGenerator(home).generate_acceptance_report("run_accept_audit_fail", live_report=self._live_report(home, "run_accept_audit_fail"), audit_result=audit)
            self.assertEqual(report["overall_status"], "failed")
            self.assertFalse(report["audit_verify"]["passed"])

    def test_12_acceptance_is_incomplete_when_audit_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            audit = AuditVerifier(home).verify_evidence("run_missing")
            report = AcceptanceReportGenerator(home).generate_acceptance_report("run_missing", live_report=self._live_report(home, "run_missing"), audit_result=audit)
            self.assertEqual(report["overall_status"], "incomplete")

    def test_13_acceptance_rejects_audit_run_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            audit = self._passed_run(home, "run_audit_source")
            report = AcceptanceReportGenerator(home).generate_acceptance_report("run_other", live_report=self._live_report(home, "run_audit_source"), audit_result=audit)
            self.assertEqual(report["overall_status"], "failed")
            self.assertFalse(report["audit_verify"]["passed"])

    def test_14_acceptance_rejects_audit_revision_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            audit = self._passed_run(home, "run_revision_mismatch")
            audit["code_revision"] = dict(audit["code_revision"]) | {"code_revision": "sha256:wrong"}
            report = AcceptanceReportGenerator(home).generate_acceptance_report("run_revision_mismatch", live_report=self._live_report(home, "run_revision_mismatch"), audit_result=audit)
            self.assertEqual(report["overall_status"], "failed")
            self.assertFalse(report["audit_verify"]["evidence_valid"])

    def test_15_cli_protocol_pass_does_not_override_domain_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_cli_no_override")
            self._seed_call(home, "run_cli_no_override", "logical_start", terminal_logical_id="logical_other")
            self._finish_run(home, "run_cli_no_override")
            self._record_cli_protocol(home, "run_cli_no_override")
            audit = AuditVerifier(home).verify_evidence("run_cli_no_override")
            report = AcceptanceReportGenerator(home).generate_acceptance_report("run_cli_no_override", live_report=self._live_report(home, "run_cli_no_override"), enforce_cli_protocol=True, audit_result=audit)
            self.assertEqual(report["cli_execution_protocol"]["status"], "passed")
            self.assertEqual(report["domain_acceptance"]["status"], "failed")
            self.assertEqual(report["overall_status"], "failed")

    def test_16_failed_acceptance_has_nonzero_exit_code(self) -> None:
        self.assertNotEqual(report_exit_code("failed"), 0)

    def test_17_readonly_contract_has_no_touched_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            contract = CollaborationRuntime(home)._minimal_live_contract("live-minimal-collaboration-fixture")
            self.assertEqual(contract["write_paths"], [])
            self.assertEqual(contract["touched_files"], [])
            self.assertEqual(contract["required_side_effects"], [])

    def test_18_read_and_write_paths_are_separate_fields(self) -> None:
        bid = ProposalBid(read_paths=["/read"], write_paths=["/write"], touched_files=["/write/file"])
        self.assertEqual(bid.read_paths, ["/read"])
        self.assertEqual(bid.write_paths, ["/write"])
        self.assertEqual(bid.touched_files, ["/write/file"])

    def test_19_empty_writable_scope_rejects_write_intent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            manager = ProposalManager(home)
            round_ = manager.open_round(run_id="run_contract_reject", task_id="main", task_type="code_change", participants=["planner", "critic"])
            proposal = manager.submit(
                round_,
                proposer_agent="planner",
                proposal_type="task_graph",
                summary="write intent",
                risk_level="low",
                bid={"write_paths": ["/write"], "writable_scope": [], "touched_files": ["/write/file"]},
                execution_contract={"source_mutation_allowed": False, "writable_scope": []},
            )
            self.assertEqual(proposal.status, "blocked")
            self.assertIn("no-side-effect contract", proposal.blocked_reason)

    def test_20_regular_code_change_contract_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            manager = ProposalManager(home)
            round_ = manager.open_round(run_id="run_regular", task_id="main", task_type="code_change", participants=["planner", "critic"])
            proposal = manager.submit(
                round_,
                proposer_agent="planner",
                proposal_type="task_graph",
                summary="regular write plan",
                risk_level="low",
                bid={"write_paths": ["/write"], "writable_scope": ["/write"], "touched_files": ["/write/file"]},
            )
            self.assertEqual(proposal.status, "submitted")

    def test_21_critic_rejects_contract_write_intent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            manager = ProposalManager(home)
            round_ = manager.open_round(run_id="run_critic_contract", task_id="main", task_type="code_change", participants=["planner", "critic"])
            proposal = manager.submit(
                round_,
                proposer_agent="planner",
                proposal_type="task_graph",
                summary="write intent",
                risk_level="low",
                bid={"write_paths": ["/write"]},
                execution_contract={"source_mutation_allowed": False, "writable_scope": []},
            )
            payload = {"extensions": {"proposal_evaluation": {"decision": "support", "score": 90, "reason": "support"}}, "claims": []}
            evaluation = CollaborationRuntime(home)._evaluation_from_agent_output(manager, round_, proposal, "critic", payload)
            self.assertEqual(evaluation.decision, "block")

    def test_22_run_output_distinguishes_command_and_domain_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_output_status", provider_mode="mock")
            RunLedger(home).record("run_blocked", run_id="run_output_status", status="blocked", reason="policy block")
            result = SitinaEngine(home)._finalize_autonomy_run({"run_id": "run_output_status", "phase": "blocked", "status": "blocked", "reason": "policy block"})
            self.assertEqual(result["command_status"], "executed")
            self.assertEqual(result["run_status"], "run_blocked")
            self.assertEqual(result["terminal_type"], "run_blocked")

    def test_23_blocked_run_is_not_domain_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            self._start_run(home, "run_blocked_domain", provider_mode="mock")
            RunLedger(home).record("run_blocked", run_id="run_blocked_domain", status="blocked", reason="policy block")
            result = SitinaEngine(home)._finalize_autonomy_run({"run_id": "run_blocked_domain", "phase": "blocked", "status": "blocked"})
            self.assertFalse(result["domain_success"])

    def test_24_acceptance_uses_domain_outcome_not_command_exit(self) -> None:
        self.assertEqual(report_exit_code("passed"), 0)
        self.assertNotEqual(report_exit_code("blocked"), 0)

    def test_25_cli_protocol_and_domain_acceptance_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            audit = self._passed_run(home, "run_cli_separate")
            report = AcceptanceReportGenerator(home).generate_acceptance_report("run_cli_separate", live_report=self._live_report(home, "run_cli_separate"), enforce_cli_protocol=True, audit_result=audit)
            self.assertEqual(report["domain_acceptance"]["status"], "passed", report)
            self.assertEqual(report["cli_execution_protocol"]["status"], "incomplete")
            self.assertEqual(report["overall_status"], "incomplete")

    def test_26_formal_report_name_contains_timestamp_and_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            report = {"run_id": "run_filename", "generated_at": "2026-07-13T12:34:56Z", "overall_status": "passed", "code_revision": {"code_revision": "sha256:test"}}
            path = ReportPersistence(home).persist_formal_acceptance(report)
            self.assertRegex(path.name, r"^Sitina_deepseek_live_minimal_acceptance_\d{8}-\d{6}_run_filename\.md$")

    def test_27_formal_report_never_overwrites_same_second(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            report = {"run_id": "run_no_overwrite", "generated_at": "2026-07-13T12:34:56Z", "overall_status": "passed", "code_revision": {"code_revision": "sha256:test"}}
            first = ReportPersistence(home).persist_formal_acceptance(report)
            second = ReportPersistence(home).persist_formal_acceptance(report)
            self.assertNotEqual(first, second)
            self.assertTrue(first.is_file())
            self.assertTrue(second.is_file())

    def test_28_formal_report_filename_and_payload_run_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home(tmp)
            run_id = "run_payload_match"
            report = {"run_id": run_id, "generated_at": "2026-07-13T12:34:56Z", "overall_status": "passed", "code_revision": {"code_revision": "sha256:test"}}
            path = ReportPersistence(home).persist_formal_acceptance(report)
            self.assertIn(f"_{run_id}.md", path.name)
            self.assertIn(f"run_id: `{run_id}`", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
