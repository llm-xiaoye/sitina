from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sitina.constants import ACTION_ORDER, RISK_ORDER, SITINA_HOME
from sitina.schemas.models import RiskMatch, RiskScanResult
from sitina.utils import iso_now, load_json_yaml, new_id, sha256_text, stable_json


class RiskScanner:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.config_path = home / "config" / "permissions.yaml"
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        if not self.config_path.exists():
            return []
        data = load_json_yaml(self.config_path)
        return data.get("risk_rules", [])

    def scan(
        self,
        operation: str,
        target: str | None = None,
        command: str | None = None,
        tool_type: str | None = None,
        allowed_roots: list[str] | None = None,
    ) -> RiskScanResult:
        matches: list[RiskMatch] = []
        for rule in self.rules:
            if not self._operation_matches(rule, operation):
                continue
            if not self._rule_matches(rule, target=target, command=command, tool_type=tool_type):
                continue
            matches.append(
                RiskMatch(
                    rule_id=rule["id"],
                    risk_level=rule["risk_level"],
                    action=rule["action"],
                    reason=rule.get("reason", rule["id"]),
                )
            )

        matches.extend(self._path_escape_matches(operation, target, allowed_roots))

        risk_level = "low"
        action = "allow"
        for match in matches:
            if RISK_ORDER[match.risk_level] > RISK_ORDER[risk_level]:
                risk_level = match.risk_level
            if ACTION_ORDER[match.action] > ACTION_ORDER[action]:
                action = match.action

        payload = {
            "operation": operation,
            "target": target,
            "command": command,
            "tool_type": tool_type,
            "risk_level": risk_level,
            "action": action,
            "matches": [m.model_dump() for m in matches],
        }
        risk_scan_hash = sha256_text(stable_json(payload))
        return RiskScanResult(
            risk_scan_id="risk_" + new_id(),
            operation=operation,
            target=target,
            command=command,
            risk_level=risk_level,
            action=action,
            approval_required=action == "approval",
            matches=matches,
            risk_scan_hash=risk_scan_hash,
            created_at=iso_now(),
        )

    def _operation_matches(self, rule: dict[str, Any], operation: str) -> bool:
        operations = rule.get("operations", ["*"])
        return "*" in operations or operation in operations

    def _rule_matches(self, rule: dict[str, Any], target: str | None, command: str | None, tool_type: str | None) -> bool:
        path_patterns = rule.get("path_patterns", [])
        command_patterns = rule.get("command_patterns", [])
        tool_types = rule.get("tool_types", [])

        if path_patterns:
            if not target:
                return False
            normalized = str(Path(target).expanduser())
            if not any(re.search(pattern, normalized) for pattern in path_patterns):
                return False

        if command_patterns:
            if not command:
                return False
            if not any(re.search(pattern, command) for pattern in command_patterns):
                return False

        if tool_types:
            if tool_type not in tool_types:
                return False

        if not path_patterns and not command_patterns and not tool_types:
            return True
        return True

    def _path_escape_matches(self, operation: str, target: str | None, allowed_roots: list[str] | None) -> list[RiskMatch]:
        if operation not in {"write", "overwrite", "delete", "move", "restore", "rollback", "prune", "doctor_fix"}:
            return []
        if not target:
            return []
        matches: list[RiskMatch] = []
        raw = Path(target).expanduser()
        if ".." in raw.parts:
            matches.append(
                RiskMatch(rule_id="path_dotdot_escape", risk_level="critical", action="block", reason=".. path escape is forbidden")
            )
        if allowed_roots:
            resolved = raw.resolve(strict=False)
            roots = [Path(root).expanduser().resolve(strict=False) for root in allowed_roots]
            if not any(str(resolved).startswith(str(root) + "/") or resolved == root for root in roots):
                matches.append(
                    RiskMatch(rule_id="write_outside_allowed_roots", risk_level="high", action="approval", reason="target is outside approved roots")
                )
        try:
            if raw.exists() and raw.is_symlink():
                resolved = raw.resolve(strict=True)
                roots = [Path(root).expanduser().resolve(strict=False) for root in allowed_roots or [self.home]]
                if not any(str(resolved).startswith(str(root) + "/") or resolved == root for root in roots):
                    matches.append(
                        RiskMatch(rule_id="symlink_escape", risk_level="critical", action="block", reason="symlink escapes allowed root")
                    )
        except OSError:
            matches.append(RiskMatch(rule_id="symlink_resolution_error", risk_level="critical", action="block", reason="symlink resolution failed"))
        return matches
