"""Machine-readable evidence for the twelve-command acceptance protocol."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.utils import canonicalize_agent_input, iso_now, new_id, read_json, sha256_text, stable_json, write_json


CLI_CHECKS = (
    "trace",
    "replay",
    "replay_simulate",
    "replay_diff",
    "proposals_list",
    "handoff_list",
    "arbitration_list",
    "lease_list",
    "blackboard_show",
    "checkpoint_list",
    "report_live",
    "report_acceptance",
)


class CliEvidenceRecorder:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.directory = home / "outputs" / "evidence" / "cli_checks"

    def record(self, run_id: str, command_name: str, exit_code: int, output: Any) -> dict[str, Any]:
        if command_name not in CLI_CHECKS:
            raise ValueError(f"unknown CLI evidence command: {command_name}")
        safe_output = canonicalize_agent_input(output) if isinstance(output, dict) else {"output_type": type(output).__name__}
        status = str(safe_output.get("overall_status") or safe_output.get("status") or ("passed" if exit_code == 0 else "failed"))
        expected_exit = self._expected_exit(command_name, status)
        directory = self.directory / run_id
        for _ in range(1024):
            cli_check_id = "cli_check_" + new_id()
            path = directory / f"{cli_check_id}.json"
            if not path.exists():
                break
        else:
            raise FileExistsError("could not allocate a unique CLI evidence id")
        body = {
            "cli_check_id": cli_check_id,
            "run_id": run_id,
            "command_name": command_name,
            "executed": True,
            "exit_code": int(exit_code),
            "status": status,
            "protocol_ok": int(exit_code) == expected_exit,
            "output_hash": sha256_text(stable_json(safe_output)),
            "checked_at": iso_now(),
        }
        evidence = body | {"evidence_hash": sha256_text(stable_json(body))}
        write_json(path, evidence)
        return evidence

    def records(self, run_id: str) -> list[dict[str, Any]]:
        directory = self.directory / run_id
        if not directory.exists():
            return []
        records: list[dict[str, Any]] = []
        for path in sorted(directory.glob("*.json")):
            value = read_json(path, default=None)
            if not isinstance(value, dict):
                continue
            claimed = value.get("evidence_hash")
            body = {key: item for key, item in value.items() if key != "evidence_hash"}
            value["evidence_hash_valid"] = claimed == sha256_text(stable_json(body))
            records.append(value)
        return records

    def summary(self, run_id: str) -> dict[str, Any]:
        latest: dict[str, dict[str, Any]] = {}
        for record in self.records(run_id):
            command = str(record.get("command_name") or "")
            if command not in CLI_CHECKS:
                continue
            current = latest.get(command)
            if current is None or str(record.get("checked_at") or "") >= str(current.get("checked_at") or ""):
                latest[command] = record
        missing = [command for command in CLI_CHECKS if command not in latest]
        passed = [
            command
            for command, record in latest.items()
            if record.get("executed") is True and record.get("protocol_ok") is True and record.get("evidence_hash_valid") is True
        ]
        return {
            "cli_checks_expected": len(CLI_CHECKS),
            "cli_checks_executed": len(latest),
            "cli_checks_passed": len(passed),
            "missing_commands": missing,
            "checks": [latest[command] for command in CLI_CHECKS if command in latest],
            "status": "passed" if len(passed) == len(CLI_CHECKS) else "incomplete",
        }

    @staticmethod
    def command_for_args(args: Any) -> tuple[str, str] | None:
        command = getattr(args, "command", None)
        if command == "trace":
            return "trace", str(args.run_id)
        if command == "replay":
            values = list(getattr(args, "run_id", []) or [])
            if len(values) == 2 and values[0] == "simulate":
                return "replay_simulate", str(values[1])
            if len(values) == 2 and values[0] == "diff":
                return "replay_diff", str(values[1])
            if len(values) == 1:
                return "replay", str(values[0])
        subcommands = {
            ("proposals", "proposals_cmd", "list"): "proposals_list",
            ("handoff", "handoff_cmd", "list"): "handoff_list",
            ("arbitration", "arbitration_cmd", "list"): "arbitration_list",
            ("lease", "lease_cmd", "list"): "lease_list",
            ("blackboard", "blackboard_cmd", "show"): "blackboard_show",
            ("checkpoint", "checkpoint_cmd", "list"): "checkpoint_list",
            ("report", "report_cmd", "live"): "report_live",
            ("report", "report_cmd", "acceptance"): "report_acceptance",
        }
        for (top, attr, subcommand), name in subcommands.items():
            if command == top and getattr(args, attr, None) == subcommand:
                return name, str(args.run_id)
        return None

    @staticmethod
    def _expected_exit(command_name: str, status: str) -> int:
        if command_name.startswith("report_"):
            return {"passed": 0, "failed": 1, "blocked": 2, "incomplete": 3, "stale": 4}.get(status, 1)
        return 0
