from __future__ import annotations

from pathlib import Path
from typing import Any

from sitina.constants import AGENTS, SITINA_HOME
from sitina.utils import load_json_yaml, sha256_text, stable_json


class WorkflowPolicy:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.path = home / "config" / "workflows.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}
        self.default = self.config.get("workflows", {}).get("default_implementation", {})

    @property
    def max_turns(self) -> int:
        return int(self.default.get("max_turns", 16))

    @property
    def max_rework_rounds(self) -> int:
        return int(self.default.get("max_rework_rounds", 2))

    def validate(self) -> list[str]:
        errors: list[str] = []
        workflow = self.default
        if not workflow:
            return ["default_implementation workflow missing"]
        if int(workflow.get("max_turns", 0)) <= 0:
            errors.append("max_turns must be positive")
        for step in workflow.get("steps", []):
            if step not in AGENTS:
                errors.append(f"workflow step is not registered agent: {step}")
        loop = workflow.get("loop_detection", {})
        if loop.get("enabled") and not loop.get("keys"):
            errors.append("loop_detection.enabled requires keys")
        return errors

    def loop_key(self, diff_hash: str | None, repeated_decision: str | None) -> str:
        return sha256_text(stable_json({"diff_hash": diff_hash, "repeated_decision": repeated_decision}))

    def detect_loop(self, history: list[dict[str, Any]]) -> bool:
        seen: set[str] = set()
        for item in history:
            key = self.loop_key(item.get("diff_hash"), item.get("repeated_decision"))
            if key in seen:
                return True
            seen.add(key)
        return False
