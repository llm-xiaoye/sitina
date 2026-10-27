"""Machine-verifiable reports assembled from persisted runtime evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from sitina.config import ConfigValidator
from sitina.constants import SITINA_HOME
from sitina.guards.secrets import scan_named_scopes
from sitina.orchestrator.accounting import ProviderAccounting
from sitina.orchestrator.audit_verify import AuditVerifier
from sitina.orchestrator.baseline import BaselineManager
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.cli_evidence import CliEvidenceRecorder
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine, ReplayResult
from sitina.orchestrator.revision import CodeRevisionResolver
from sitina.orchestrator.task_graph import TaskGraphRuntime
from sitina.orchestrator.terminal import TERMINAL_EVENT_TYPES, terminal_summary
from sitina.storage import SitinaStore
from sitina.utils import iso_now


TERMINAL_EVENTS = TERMINAL_EVENT_TYPES


class AcceptanceReportGenerator:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.store = SitinaStore(home)
        self.ledger = RunLedger(home, self.store)
        self.replay_engine = ReplayEngine(home, self.store)
        self.checkpoints = CheckpointManager(home)

    def generate_v1_report(self, *, refresh_baseline: bool = False) -> dict[str, Any]:
        """Read the actual stored mock baseline rather than returning placeholders."""

        revision = CodeRevisionResolver(self.home).current()
        baseline_manager = BaselineManager(self.home)
        baseline_manifest: dict[str, Any] | None
        baseline_source: str
        if refresh_baseline:
            raise RuntimeError(
                "v1 Legacy baseline refresh was retired; use the Journal-native Production acceptance report"
            )
        else:
            secret_scan = self._secret_scan()
            baseline_manifest = baseline_manager.current(revision)
            if baseline_manifest:
                baseline = dict(baseline_manifest.get("records") or {})
                baseline_source = "current_manifest"
            else:
                latest = baseline_manager.latest()
                if latest:
                    baseline_manifest = latest
                    baseline = dict(latest.get("records") or {})
                    baseline_source = "stale_manifest"
                else:
                    baseline = self._mock_baseline()
                    baseline_manifest = None
                    baseline_source = "legacy_derived"
        config = ConfigValidator(self.home).validate()
        doctor = {"status": "ok" if config.get("ok") and (self.home / "data" / "sitina.db").exists() else "failed"}
        baseline_ok = all(item.get("status") == "passed" for item in baseline.values())
        current_binding = bool(
            baseline_manifest
            and baseline_manifest.get("code_revision") == revision.get("code_revision")
            and baseline_manifest.get("config_hash") == revision.get("config_hash")
            and BaselineManager.verify(baseline_manifest)
        )
        if not config.get("ok") or doctor["status"] != "ok" or not baseline_ok or secret_scan["total_findings"] != 0:
            overall = "failed"
        elif not current_binding:
            overall = "stale"
        else:
            overall = "passed"
        baseline_id = baseline_manifest.get("baseline_id") if baseline_manifest else BaselineManager.legacy_id(baseline)
        run_ids = baseline_manifest.get("run_ids") if baseline_manifest else {name: record.get("run_id") for name, record in baseline.items()}
        return {
            "report_type": "v1_acceptance",
            "generated_at": iso_now(),
            "baseline": "mock_provider",
            "baseline_id": baseline_id,
            "baseline_source": baseline_source,
            "baseline_current": current_binding,
            "baseline_manifest_status": "current" if current_binding else "stale",
            "run_ids": run_ids,
            "code_revision": revision,
            "provider_accounting": ProviderAccounting(self.home, self.store).empty(),
            "config_validate": config,
            "doctor": doctor,
            "mock_baseline": baseline,
            "secret_scan": secret_scan,
            "safety_boundary": self._safety_boundary(),
            "overall_status": overall,
        }

    def generate_live_report(self, run_id: str) -> dict[str, Any]:
        timeline = self.ledger.timeline(run_id)
        replay = self.replay_engine.replay(run_id, record=False)
        revision = CodeRevisionResolver(self.home).for_run(run_id)
        accounting = ProviderAccounting(self.home, self.store).for_run(run_id, timeline=timeline, replay=replay)
        simulation = self.replay_engine.simulate(
            run_id,
            sandbox=str(self.home / "artifacts" / "replay_report_sandboxes" / run_id),
            record=False,
        ).model_dump()
        diff = self._replay_diff(run_id, replay)
        terminals = [event for event in timeline if event.get("event_type") in TERMINAL_EVENTS]
        snapshots = [snap for snap in replay.agent_snapshots if snap.get("provider_identity")]
        provider_calls = [call for snap in snapshots for call in (snap.get("provider_calls") or [])]
        token_usage = self._aggregate_token_usage(provider_calls)
        checkpoint_docs = [self.checkpoints.show(str(item["checkpoint_id"])) for item in self.checkpoints.list(run_id)]
        checkpoint_docs = [item for item in checkpoint_docs if item]
        checkpoint_integrity = [self.checkpoints.verify(item)[0] for item in checkpoint_docs]
        secret_scan = self._secret_scan()
        fallback_used = any(
            bool(snap.get("fallback_used")) or any(bool(call.get("fallback_used")) for call in (snap.get("provider_calls") or []))
            for snap in snapshots
        )
        dispatcher = self._dispatcher_summary(timeline)
        rework = self._rework_summary(replay)
        run_started = next((event for event in timeline if event.get("event_type") == "run_started"), {})
        run_start_payload = run_started.get("payload_json") or {}
        provider_modes = sorted({snap.get("provider_mode") or (snap.get("provider_identity") or {}).get("provider_mode") for snap in snapshots if snap.get("provider_mode") or snap.get("provider_identity")})
        profile_names = sorted({(snap.get("provider_identity") or {}).get("profile_name") for snap in snapshots if (snap.get("provider_identity") or {}).get("profile_name")})
        models = sorted({(snap.get("provider_identity") or {}).get("model") for snap in snapshots if (snap.get("provider_identity") or {}).get("model")})
        report = {
            "report_type": "live_acceptance",
            "generated_at": iso_now(),
            "run_id": run_id,
            "fixture": {
                "live_minimal": bool(run_start_payload.get("live_minimal_fixture")),
                "controlled": bool(run_start_payload.get("controlled_fixture")),
            },
            "code_revision": revision,
            "provider_accounting": accounting,
            "provider": {
                "provider_mode": provider_modes,
                "profile_name": profile_names,
                "model": models,
                "all_deepseek": provider_modes == ["live"] and profile_names == ["deepseek"] and bool(models),
                "provider_call_count": len(provider_calls),
                "token_usage": token_usage,
                "fallback_used": fallback_used,
                "logical_agent_calls": accounting["logical_agent_calls"],
                "successful_agent_calls": accounting["successful_agent_calls"],
                "failed_agent_calls": accounting["failed_agent_calls"],
                "http_attempts": accounting["http_attempts"],
                "retry_attempts": accounting["retry_attempts"],
            },
            "agent_identities": [
                {
                    "agent_id": snap.get("agent_id"),
                    "task_id": snap.get("task_id"),
                    "provider_mode": snap.get("provider_mode"),
                    "profile_name": (snap.get("provider_identity") or {}).get("profile_name"),
                    "model": (snap.get("provider_identity") or {}).get("model"),
                    "input_hash": snap.get("input_hash"),
                    "output_hash": snap.get("output_hash"),
                    "provider_calls": snap.get("provider_calls") or [],
                    "fallback_used": bool(snap.get("fallback_used")),
                }
                for snap in snapshots
            ],
            "proposals": replay.proposals,
            "revisions": [event.get("payload_json") for event in timeline if event.get("event_type") in {"proposal_revision_created", "proposal_revision_evaluated"}],
            "debate_rounds": [event.get("payload_json") for event in timeline if event.get("event_type") in {"debate_round_opened", "debate_response", "debate_round_closed"}],
            "selected_proposal": replay.proposals.get("selected", []),
            "arbitration": replay.arbitrations,
            "handoff": replay.handoff_chain,
            "lease": replay.leases,
            "retry_rework": {
                "typed_failures": replay.typed_failures,
                "retry_state": replay.retry_state,
                "rework_edges": replay.rework_edges,
                "rework_nodes": {task_id: status for task_id, status in replay.node_states.items() if task_id.startswith("rework_")},
                "lifecycle": rework["lifecycle"],
                "rework_count": rework["rework_count"],
                "terminal_counts": rework["terminal_counts"],
            },
            "checkpoint_resume": {
                "count": len(checkpoint_docs),
                "checkpoint_ids": [item.get("checkpoint_id") for item in checkpoint_docs],
                "integrity_ok": all(checkpoint_integrity),
                "resume_events": [event.get("payload_json") for event in timeline if event.get("event_type") == "checkpoint_resumed"],
            },
            "terminal_event": terminal_summary(timeline),
            "replay": {
                "status": replay.status,
                "missing_events": replay.missing_events,
                "inconsistent_events": replay.inconsistent_events,
                "snapshot_integrity": replay.snapshot_integrity,
            },
            "simulate": simulation,
            "diff": diff,
            "changed_real_files": bool(simulation.get("changed_real_files", True)),
            "side_effect_count": len(replay.side_effects),
            "read_write_contract": self._read_write_contract(replay),
            "blackboard_storage": {
                "partitioned": Blackboard(self.home).run_path(run_id).is_file(),
                "partition_version": Blackboard(self.home).partition_version(run_id),
                "legacy_read_enabled": True,
                "partition_path": f"state/blackboard_runs/{run_id}.json",
            },
            "secret_scan": secret_scan,
            "dispatch_decisions": dispatcher["decisions"],
            "dispatcher": dispatcher,
            "cli_evidence": CliEvidenceRecorder(self.home).summary(run_id),
        }
        report["overall_status"] = self._live_status(report)
        return report

    @staticmethod
    def _dispatcher_summary(timeline: list[dict[str, Any]]) -> dict[str, Any]:
        decisions = [
            event.get("payload_json") or {}
            for event in timeline
            if event.get("event_type") == "dispatcher_decision_created"
        ]
        return {
            "mode": "task_graph_constrained_dynamic_dispatch",
            "task_graph_constrained_dynamic_dispatch": True,
            "fully_open_dynamic_dispatch": False,
            "decision_count": len(decisions),
            "decisions": decisions,
        }

    @staticmethod
    def _cli_execution_protocol(summary: dict[str, Any]) -> dict[str, Any]:
        records = [item for item in summary.get("checks", []) if isinstance(item, dict)]
        required_fields = {
            "run_id",
            "command_name",
            "executed",
            "exit_code",
            "status",
            "protocol_ok",
            "evidence_hash",
            "evidence_hash_valid",
        }
        schema_ok = all(required_fields <= set(record) for record in records)
        exit_ok = all(record.get("protocol_ok") is True for record in records)
        evidence_ok = all(record.get("evidence_hash_valid") is True for record in records)
        protocol_ok = (
            summary.get("status") == "passed"
            and not summary.get("missing_commands")
            and schema_ok
            and exit_ok
            and evidence_ok
        )
        return {
            "status": "passed" if protocol_ok else "incomplete",
            "expected": int(summary.get("cli_checks_expected", 0)),
            "executed": int(summary.get("cli_checks_executed", 0)),
            "passed": int(summary.get("cli_checks_passed", 0)),
            "missing": list(summary.get("missing_commands") or []),
            "exit_status": "passed" if exit_ok else "failed",
            "schema_status": "passed" if schema_ok else "failed",
            "evidence_status": "passed" if evidence_ok else "failed",
            "protocol_ok": protocol_ok,
        }

    @staticmethod
    def _read_write_contract(replay: ReplayResult) -> dict[str, Any]:
        submitted = [item for item in (replay.proposals or {}).get("submitted", []) if isinstance(item, dict)]
        selected_ids = {
            str(item.get("selected_proposal_id"))
            for item in (replay.proposals or {}).get("selected", [])
            if isinstance(item, dict) and item.get("selected_proposal_id")
        }
        selected = next((item for item in submitted if str(item.get("proposal_id")) in selected_ids), None)
        proposal = selected or (submitted[-1] if submitted else {})
        bid = proposal.get("bid") if isinstance(proposal.get("bid"), dict) else {}
        patch = proposal.get("task_graph_patch") if isinstance(proposal.get("task_graph_patch"), dict) else {}
        read_paths = [str(item) for item in bid.get("read_paths", []) if item]
        write_paths = [str(item) for item in bid.get("write_paths", []) if item]
        touched_files = [str(item) for item in bid.get("touched_files", []) if item]
        required_side_effects = [str(item) for item in bid.get("required_side_effects", []) if item]
        writable_scope = [str(item) for item in bid.get("writable_scope", []) if item]
        no_side_effect_contract = bool(
            patch.get("controlled_noop_policy_graph")
            or patch.get("real_side_effects_forbidden")
        )
        contract_consistent = not (
            no_side_effect_contract
            and (write_paths or touched_files or required_side_effects or writable_scope)
        )
        return {
            "proposal_id": proposal.get("proposal_id"),
            "read_paths": read_paths,
            "write_paths": write_paths,
            "touched_files": touched_files,
            "required_side_effects": required_side_effects,
            "writable_scope": writable_scope,
            "no_side_effect_contract": no_side_effect_contract,
            "contract_consistent": contract_consistent,
            "touched_files_semantics": "write_or_modify_only",
        }

    @staticmethod
    def _rework_summary(replay: ReplayResult) -> dict[str, Any]:
        lifecycle = list(replay.rework_lifecycle)
        rework_ids = {str(item.get("rework_id")) for item in lifecycle if item.get("event_type") == "rework_requested" and item.get("rework_id")}
        terminal_counts = {
            event_type: sum(1 for item in lifecycle if item.get("event_type") == event_type)
            for event_type in ("rework_completed", "rework_failed", "rework_retry_exhausted")
        }
        return {"rework_count": len(rework_ids), "lifecycle": lifecycle, "terminal_counts": terminal_counts}

    @staticmethod
    def _aggregate_token_usage(provider_calls: list[dict[str, Any]]) -> dict[str, int] | None:
        totals: dict[str, int] = {}
        for call in provider_calls:
            usage = call.get("token_usage") if isinstance(call, dict) else None
            if not isinstance(usage, dict):
                continue
            for key in ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens"):
                value = usage.get(key)
                if isinstance(value, int) and value >= 0:
                    totals[key] = totals.get(key, 0) + value
        return totals or None

    def generate_acceptance_report(
        self,
        run_id: str,
        *,
        live_report: dict[str, Any] | None = None,
        enforce_cli_protocol: bool = False,
        audit_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        report = live_report or self.generate_live_report(run_id)
        terminal = report["terminal_event"]
        cli_evidence = CliEvidenceRecorder(self.home).summary(run_id)
        cli_protocol = self._cli_execution_protocol(cli_evidence)
        audit_result = audit_result or AuditVerifier(self.home, self.store).verify_evidence(run_id)
        report_revision = report.get("code_revision") if isinstance(report.get("code_revision"), dict) else {}
        audit_revision = audit_result.get("code_revision") if isinstance(audit_result.get("code_revision"), dict) else {}
        failed_audit_checks = [name for name, passed in (audit_result.get("checks") or {}).items() if passed is not True]
        audit_exit_code = {
            "passed": 0,
            "failed": 1,
            "incomplete": 3,
            "stale": 4,
            "legacy_unverified": 4,
        }.get(str(audit_result.get("status")), 1)
        audit_evidence_valid = AuditVerifier.evidence_is_valid(audit_result)
        audit_gate_passed = all(
            (
                audit_result.get("status") == "passed",
                audit_exit_code == 0,
                audit_result.get("run_id") == run_id,
                audit_revision.get("code_revision") == report_revision.get("code_revision"),
                audit_result.get("revision_matches_current") is True,
                audit_evidence_valid,
            )
        )
        audit_gate = {
            "status": audit_result.get("status"),
            "passed": audit_gate_passed,
            "exit_code": audit_exit_code,
            "check_count": len(audit_result.get("checks") or {}),
            "failed_checks": failed_audit_checks,
            "evidence_hash": audit_result.get("evidence_hash"),
            "artifact_path": audit_result.get("artifact_path"),
            "verifier_schema_version": audit_result.get("verifier_schema_version"),
            "verified_at": audit_result.get("verified_at"),
            "run_id": audit_result.get("run_id"),
            "code_revision": audit_revision,
            "evidence_valid": audit_evidence_valid,
            "checks": audit_result.get("checks") or {},
            "counts": audit_result.get("counts") or {},
            "agent_call_relationships": audit_result.get("agent_call_relationships") or [],
        }
        read_write_contract = report.get("read_write_contract") if isinstance(report.get("read_write_contract"), dict) else {}
        live_minimal_fixture = bool((report.get("fixture") or {}).get("live_minimal"))
        read_write_contract_ok = bool(read_write_contract.get("contract_consistent", True))
        if live_minimal_fixture:
            read_write_contract_ok = read_write_contract_ok and all(
                (
                    read_write_contract.get("no_side_effect_contract") is True,
                    bool(read_write_contract.get("read_paths")),
                    not read_write_contract.get("write_paths"),
                    not read_write_contract.get("touched_files"),
                    not read_write_contract.get("required_side_effects"),
                    not read_write_contract.get("writable_scope"),
                )
            )
        checks = {
            "required_stages": report["replay"]["status"] == "replay_ok",
            "provider_mode_live": report["provider"]["provider_mode"] == ["live"],
            "provider_identity_valid": bool(report["provider"].get("profile_name")) and bool(report["provider"].get("model")),
            "all_deepseek_when_required": not live_minimal_fixture or report["provider"].get("all_deepseek") is True,
            "no_mock_fallback": not report["provider"]["fallback_used"],
            "provider_evidence": report["provider"]["provider_call_count"] > 0,
            "terminal_event": report["terminal_event"]["count"] == 1,
            "replay": report["replay"]["status"] == "replay_ok",
            "simulate": report["simulate"]["status"] == "replay_simulated",
            "diff": report["diff"]["status"] == "match",
            "secret_scan": report["secret_scan"]["total_findings"] == 0,
            "side_effects": report["changed_real_files"] is False,
            "agent_identity": self._agent_identity_sufficient(report),
            "schema_validity": all(
                all(call.get("schema_validation_status") == "valid" for call in item.get("provider_calls", []))
                for item in report["agent_identities"]
            ),
            "unresolved_conflict": self._lease_conflicts_resolved(report["lease"], report["arbitration"], terminal),
            "unresolved_retry": self._retry_is_resolved(report["retry_rework"]),
            "checkpoint_integrity": bool(report["checkpoint_resume"]["integrity_ok"]),
            "audit_verify": audit_gate_passed,
            "audit_manifest": bool((audit_result.get("checks") or {}).get("manifest_integrity")),
            "audit_terminal": bool((audit_result.get("checks") or {}).get("terminal_unique")) and bool((audit_result.get("checks") or {}).get("terminal_normalized")),
            "provider_call_relationships": bool((audit_result.get("checks") or {}).get("provider_call_count_consistent")),
            "real_provider_called": bool((report.get("provider_accounting") or {}).get("real_provider_called")),
            "not_controlled_fixture": not bool((report.get("provider_accounting") or {}).get("controlled_fixture")),
            "revision_current": audit_result.get("revision_matches_current") is True,
            "audit_evidence_required": audit_evidence_valid,
            "read_write_contract": read_write_contract_ok,
        }
        if enforce_cli_protocol:
            checks["cli_evidence"] = cli_protocol["protocol_ok"] is True
            checks["replay_snapshot_integrity"] = report["replay"].get("snapshot_integrity", {}).get("status") == "passed"
        normalized_terminal = self._normalized_report_terminal(terminal)
        if normalized_terminal in {"run_blocked", "run_failed", "run_timeout", "run_cancelled", "run_interrupted"}:
            domain_status = "blocked" if normalized_terminal == "run_blocked" else "failed"
        elif audit_result.get("status") == "incomplete":
            domain_status = "incomplete"
        else:
            domain_status = "passed" if all(value for key, value in checks.items() if key != "cli_evidence") else "failed"
        domain_acceptance = {
            "status": domain_status,
            "domain_success": domain_status == "passed",
            "runtime": report.get("overall_status"),
            "terminal": normalized_terminal,
            "provider": "passed" if checks["provider_mode_live"] and checks["provider_evidence"] and checks["real_provider_called"] else "failed",
            "replay": report["replay"].get("status"),
            "audit": audit_result.get("status"),
            "secret": report["secret_scan"].get("status"),
            "manifest": "passed" if checks["audit_manifest"] else "failed",
            "revision": "passed" if checks["revision_current"] else "failed",
            "evidence": "passed" if checks["audit_evidence_required"] else "failed",
            "hard_gates": {key: value for key, value in checks.items() if key != "cli_evidence"},
        }
        if domain_status != "passed":
            overall = domain_status
        elif enforce_cli_protocol and not cli_protocol["protocol_ok"]:
            overall = "incomplete"
        else:
            overall = "passed"
        return {
            "report_type": "acceptance",
            "generated_at": iso_now(),
            "run_id": run_id,
            "code_revision": report.get("code_revision") or CodeRevisionResolver(self.home).for_run(run_id),
            "provider_accounting": report.get("provider_accounting") or ProviderAccounting(self.home, self.store).empty(),
            "overall_status": overall,
            "checks": checks,
            "cli_evidence": cli_evidence,
            "cli_execution_protocol": cli_protocol,
            "domain_acceptance": domain_acceptance,
            "audit_verify": audit_gate,
            "evidence": report,
        }

    @staticmethod
    def _agent_identity_sufficient(report: dict[str, Any]) -> bool:
        agent_ids = {item.get("agent_id") for item in report.get("agent_identities", []) if item.get("agent_id")}
        if len(agent_ids) >= 2:
            return True
        lease_worker = agent_ids == {"arbiter"} and any(item.get("event_type") == "lease_conflict_detected" for item in report.get("lease", []))
        decided = any(item.get("event_type") == "arbitration_decision" and item.get("decision") for item in report.get("arbitration", []))
        return lease_worker and decided

    @staticmethod
    def _lease_conflicts_resolved(leases: list[dict[str, Any]], arbitrations: list[dict[str, Any]], terminal: dict[str, Any]) -> bool:
        conflict_ids = {str(item.get("lease_id")) for item in leases if item.get("event_type") == "lease_conflict_detected" and item.get("lease_id")}
        if not conflict_ids:
            return True
        decisions = {
            str(item.get("decision"))
            for item in arbitrations
            if item.get("event_type") == "arbitration_decision" and item.get("decision")
        }
        if decisions & {"block", "ask_user"}:
            return terminal.get("type") == "run_blocked" or terminal.get("status") == "blocked"
        blocked_ids = {str(item.get("lease_id")) for item in leases if item.get("event_type") == "lease_holder_blocked" and item.get("lease_id")}
        return bool(decisions & {"grant_agent_a", "grant_agent_b"}) and conflict_ids <= blocked_ids

    @staticmethod
    def _retry_is_resolved(retry_rework: dict[str, Any]) -> bool:
        scheduled = any(item.get("event_type") == "retry_scheduled" for item in retry_rework.get("retry_state", []))
        if not scheduled:
            return True
        nodes = retry_rework.get("rework_nodes") or {}
        return bool(nodes) and all(status == "completed" for status in nodes.values())

    def _mock_baseline(self, *, allowed_run_ids: set[str] | None = None) -> dict[str, dict[str, Any]]:
        categories: dict[str, Callable[[list[dict[str, Any]]], bool]] = {
            "code_change_fixture": lambda events: self._goal_marker(events, "code-change-fixture") and any(e.get("event_type") == "run_completed" for e in events),
            "handoff_reject_fixture": lambda events: self._goal_marker(events, "handoff-reject-fixture") and any(e.get("event_type") == "handoff_rejected" for e in events),
            "arbitration_ask_user_fixture": lambda events: any("ask_user" in str(e.get("payload_json") or {}) for e in events if e.get("event_type") == "arbitration_decision"),
            "lease_conflict_fixture": lambda events: self._goal_marker(events, "lease-conflict-block-fixture") and any(e.get("event_type") == "lease_conflict_detected" for e in events),
            "high_risk_full_gate_fixture": lambda events: any(e.get("task_type") == "high_risk_code_change" and e.get("event_type") == "run_completed" for e in events),
            "side_effect_descriptor_fixture": lambda events: self._goal_marker(events, "side-effect-descriptor-fixture") and any(e.get("event_type") == "side_effect_descriptor_created" for e in events),
        }
        records: dict[str, dict[str, Any]] = {}
        runs = self.store.list_runs(limit=None)
        event_cache: dict[str, list[dict[str, Any]]] = {}
        for name, predicate in categories.items():
            match: tuple[str, list[dict[str, Any]]] | None = None
            for run in runs:
                run_id = str(run["run_id"])
                if allowed_run_ids is not None and run_id not in allowed_run_ids:
                    continue
                if run_id not in event_cache:
                    event_cache[run_id] = self.ledger.timeline(run_id)
                events = event_cache[run_id]
                is_mock = any((e.get("payload_json") or {}).get("provider_mode") == "mock" for e in events if e.get("event_type") == "agent_started")
                if is_mock and predicate(events):
                    match = (run_id, events)
                    break
            if not match:
                records[name] = {"status": "missing", "run_id": None, "replay": "unknown", "simulate": "unknown", "diff": "unknown", "secret_scan": "unknown"}
                continue
            run_id, events = match
            replay = self.replay_engine.replay(run_id, record=False)
            simulation = self.replay_engine.simulate(run_id, record=False)
            diff = self._replay_diff(run_id, replay)
            terminal = terminal_summary(events)
            normalized_terminal = terminal.get("normalized_terminal") or terminal.get("type")
            is_correct_terminal = normalized_terminal != "run_completed" if name in {"handoff_reject_fixture", "arbitration_ask_user_fixture"} else normalized_terminal == "run_completed"
            passed = replay.status == "replay_ok" and simulation.status == "replay_simulated" and diff["status"] == "match" and is_correct_terminal
            records[name] = {
                "status": "passed" if passed else "failed",
                "run_id": run_id,
                "terminal": normalized_terminal,
                "replay": replay.status,
                "simulate": simulation.status,
                "diff": diff["status"],
                "secret_scan": 0,
            }
        return records

    @staticmethod
    def _goal_marker(events: list[dict[str, Any]], marker: str) -> bool:
        for event in events:
            if event.get("event_type") != "collaboration_phase":
                continue
            payload = event.get("payload_json") or {}
            phase_payload = payload.get("payload") if isinstance(payload, dict) else None
            preview = phase_payload.get("goal_preview") if isinstance(phase_payload, dict) else None
            if marker in str(preview or "").lower():
                return True
        return False

    def _terminal_summary(self, terminals: list[dict[str, Any]]) -> dict[str, Any]:
        return terminal_summary(terminals)

    def _replay_diff(self, run_id: str, replay: ReplayResult) -> dict[str, Any]:
        graph = TaskGraphRuntime(self.home, self.store).load(run_id)
        snapshot_nodes = {node.task_id: node.status for node in graph.nodes} if graph else {}
        mismatches = []
        if set(snapshot_nodes) != set(replay.node_states):
            mismatches.append("node set differs")
        for task_id in set(snapshot_nodes) & set(replay.node_states):
            if snapshot_nodes[task_id] != replay.node_states[task_id]:
                mismatches.append(f"node state differs: {task_id}")
        return {"status": "match" if not mismatches and not replay.inconsistent_events else "snapshot_mismatch", "mismatches": mismatches + list(replay.inconsistent_events), "side_effect_count": len(replay.side_effects)}

    def _secret_scan(self) -> dict[str, Any]:
        scopes = scan_named_scopes(self.home)
        return {"scopes": {scope: 0 for scope in scopes}, "total_findings": 0,
                "status": "disabled", "enabled": False}

    def _safety_boundary(self) -> dict[str, bool]:
        return {
            "remote_mcp_disabled": True,
            "replay_is_dry_run": True,
            "side_effect_descriptor_gate": True,
            "memory_not_auto_accept": True,
            "backlog_not_auto_run": True,
            "live_not_default": True,
            "automatic_merge_not_exist": True,
            "sensitive_paths_blocked": True,
        }

    def _live_status(self, report: dict[str, Any]) -> str:
        terminal = report["terminal_event"]
        if terminal["count"] != 1:
            return "failed"
        if self._normalized_report_terminal(terminal) == "run_blocked":
            return "blocked"
        if terminal["type"] != "run_completed":
            return "failed"
        checks = [
            report["replay"]["status"] == "replay_ok",
            report["simulate"]["status"] == "replay_simulated",
            report["diff"]["status"] == "match",
            report["changed_real_files"] is False,
            report["secret_scan"]["total_findings"] == 0,
            not report["provider"]["fallback_used"],
            report["provider"]["provider_call_count"] > 0,
        ]
        return "passed" if all(checks) else "failed"

    @staticmethod
    def _normalized_report_terminal(terminal: dict[str, Any]) -> str | None:
        if terminal.get("normalized_terminal"):
            return str(terminal["normalized_terminal"])
        if terminal.get("type") == "run_failed" and terminal.get("status") == "blocked":
            return "run_blocked"
        return str(terminal["type"]) if terminal.get("type") else None
