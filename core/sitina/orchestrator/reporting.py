"""Report envelope persistence and process exit semantics."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.utils import iso_now, new_id, sha256_text, stable_json, write_json


REPORT_STATUS_EXIT_CODES = {"passed": 0, "failed": 1, "blocked": 2, "incomplete": 3, "stale": 4}


def report_exit_code(status: str) -> int:
    return REPORT_STATUS_EXIT_CODES.get(str(status), 1)


class ReportPersistence:
    SCHEMA_VERSION = "1.0"

    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.directory = home / "outputs" / "reports" / "acceptance"

    def persist(self, report: dict[str, Any]) -> dict[str, Any]:
        generated_at = str(report.get("generated_at") or iso_now())
        try:
            generated = dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError:
            generated = dt.datetime.now(dt.timezone.utc)
        valid_until = (generated + dt.timedelta(days=30)).isoformat().replace("+00:00", "Z")
        revision = report.get("code_revision") if isinstance(report.get("code_revision"), dict) else {}
        run_ids = report.get("run_ids")
        if not isinstance(run_ids, list):
            run_ids = [report["run_id"]] if report.get("run_id") else [value.get("run_id") for value in (report.get("mock_baseline") or {}).values() if isinstance(value, dict) and value.get("run_id")]
        body = dict(report) | {
            "report_id": str(report.get("report_id") or ("report_" + new_id())),
            "report_schema_version": self.SCHEMA_VERSION,
            "generated_at": generated_at,
            "valid_until": valid_until,
            "code_revision_value": revision.get("code_revision") or report.get("code_revision_value"),
            "config_hash": revision.get("config_hash") or report.get("config_hash"),
            "baseline_id": report.get("baseline_id"),
            "run_ids": sorted({str(value) for value in run_ids if value}),
        }
        document = body | {"file_hash": sha256_text(stable_json(body))}
        path = self.directory / f"{document['report_id']}.json"
        write_json(path, document)
        return document | {"report_path": str(path)}

    def persist_formal_acceptance(self, report: dict[str, Any]) -> Path:
        run_id = str(report.get("run_id") or "").strip()
        if not run_id:
            raise ValueError("formal acceptance report requires run_id")
        generated_at = str(report.get("generated_at") or iso_now())
        try:
            generated = dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError:
            generated = dt.datetime.now(dt.timezone.utc)
        revision = report.get("code_revision") if isinstance(report.get("code_revision"), dict) else {}
        audit = report.get("audit_verify") if isinstance(report.get("audit_verify"), dict) else {}
        cli_protocol = report.get("cli_execution_protocol") if isinstance(report.get("cli_execution_protocol"), dict) else {}
        domain = report.get("domain_acceptance") if isinstance(report.get("domain_acceptance"), dict) else {}
        evidence = report.get("evidence") if isinstance(report.get("evidence"), dict) else {}
        contract = evidence.get("read_write_contract") if isinstance(evidence.get("read_write_contract"), dict) else {}
        formal_context = report.get("formal_context") if isinstance(report.get("formal_context"), dict) else {}
        relationships = audit.get("agent_call_relationships") if isinstance(audit.get("agent_call_relationships"), list) else []
        lines = [
            "# Sitina DeepSeek Live Minimal Acceptance",
            "",
            "## 1. Summary",
            "",
            f"- run_id: `{run_id}`",
            f"- generated_at: `{generated_at}`",
            f"- code_revision: `{revision.get('code_revision')}`",
            f"- overall_status: `{report.get('overall_status')}`",
            "",
            "## 2. Previous Gap And Read-Only Assurance",
            "",
            f"- previous_run_id: `{formal_context.get('previous_run_id', '20260713-065041-ecac')}`",
            f"- previous_gap: `{formal_context.get('previous_gap', 'provider_call_count_consistent=false')}`",
            f"- previous_evidence_read_only: `{formal_context.get('previous_evidence_read_only', True)}`",
            "",
            "## 3. Modifications",
            "",
            f"- modified_files: `{formal_context.get('modified_files', [])}`",
            "",
            "## 4. Unified Agent Audit",
            "",
            "| logical_call_id | agent | origin | starts | terminals | HTTP attempts | terminal |",
            "|---|---|---|---:|---:|---:|---|",
            *[
                f"| {item.get('logical_call_id')} | {item.get('agent_id')} | {item.get('call_origin')} | {item.get('start_count')} | {item.get('terminal_count')} | {item.get('http_attempts')} | {item.get('terminal_status')} |"
                for item in relationships
                if isinstance(item, dict)
            ],
            "",
            "## 5. Acceptance Audit Hard Gate",
            "",
            f"- audit_status: `{audit.get('status')}`",
            f"- audit_exit_code: `{audit.get('exit_code')}`",
            f"- audit_evidence_hash: `{audit.get('evidence_hash')}`",
            f"- domain_acceptance: `{domain.get('status')}`",
            "",
            "## 6. Read/Write Contract",
            "",
            f"- read_paths: `{contract.get('read_paths', [])}`",
            f"- write_paths: `{contract.get('write_paths', [])}`",
            f"- touched_files: `{contract.get('touched_files', [])}`",
            f"- required_side_effects: `{contract.get('required_side_effects', [])}`",
            f"- writable_scope: `{contract.get('writable_scope', [])}`",
            f"- contract_consistent: `{contract.get('contract_consistent')}`",
            "",
            "## 7. CLI Semantics",
            "",
            f"- cli_execution_protocol: `{cli_protocol.get('status')}`",
            f"- protocol_ok: `{cli_protocol.get('protocol_ok')}`",
            f"- domain_acceptance: `{domain.get('status')}`",
            "",
            "## 8. Tests",
            "",
            f"- targeted_tests: `{formal_context.get('targeted_tests')}`",
            f"- full_unittest: `{formal_context.get('full_unittest')}`",
            "",
            "## 9. Live Evidence",
            "",
            f"- provider: `{(evidence.get('provider') or {}).get('profile_name')}`",
            f"- model: `{(evidence.get('provider') or {}).get('model')}`",
            f"- logical_calls: `{(report.get('provider_accounting') or {}).get('logical_agent_calls')}`",
            f"- http_attempts: `{(report.get('provider_accounting') or {}).get('http_attempts')}`",
            f"- terminal: `{(evidence.get('terminal_event') or {}).get('normalized_terminal')}`",
            "",
            "## 10. Audit, Replay, Secret, And Evidence",
            "",
            f"- replay: `{(evidence.get('replay') or {}).get('status')}`",
            f"- simulate: `{(evidence.get('simulate') or {}).get('status')}`",
            f"- secret_findings: `{(evidence.get('secret_scan') or {}).get('total_findings')}`",
            f"- evidence_bundle: `{formal_context.get('evidence_bundle')}`",
            f"- evidence_verify: `{formal_context.get('evidence_verify')}`",
            "",
            "## 11. Remaining Limits",
            "",
            "- task_graph_constrained_dynamic_dispatch=true",
            "- fully_open_dynamic_dispatch=false",
            f"- remaining_limits: `{formal_context.get('remaining_limits', ['not fully open autonomy'])}`",
            "",
        ]
        directory = self.home / "outputs" / "reports"
        directory.mkdir(parents=True, exist_ok=True)
        for offset in range(86400):
            timestamp = (generated + dt.timedelta(seconds=offset)).strftime("%Y%m%d-%H%M%S")
            path = directory / f"Sitina_deepseek_live_minimal_acceptance_{timestamp}_{run_id}.md"
            try:
                with path.open("x", encoding="utf-8") as handle:
                    handle.write("\n".join(lines))
                return path
            except FileExistsError:
                continue
        raise FileExistsError("could not allocate a unique formal acceptance report filename")

    @staticmethod
    def verify(report: dict[str, Any]) -> bool:
        claimed = report.get("file_hash")
        body = {key: value for key, value in report.items() if key not in {"file_hash", "report_path"}}
        return claimed == sha256_text(stable_json(body))
