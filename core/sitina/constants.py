from __future__ import annotations

import os
from pathlib import Path


SITINA_HOME = Path(os.environ.get("SITINA_HOME", "/Users/moss/SitinaHub")).expanduser()

AGENTS = (
    "controller",
    "planner",
    "architect",
    "coder",
    "tester",
    "reviewer",
    "security",
    "critic",
    "arbiter",
    "researcher",
    "memory",
    "summary",
)

PHASES = (
    "created",
    "planning",
    "awaiting_approval",
    "coding",
    "testing",
    "reviewing",
    "controller_decision",
    "summarizing",
    "done",
    "blocked",
    "timeout",
    "cancelled",
    "interrupted",
    "failed",
)

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ACTION_ORDER = {"allow": 0, "approval": 1, "block": 2}

REQUIRED_DIRS = (
    "bin",
    "core/sitina/orchestrator",
    "core/sitina/guards",
    "core/sitina/schemas",
    "core/sitina/runners",
    "core/sitina/storage",
    "core/sitina/evals",
    "config/mcp",
    "profiles",
    "schemas",
    "prompts/agents",
    "data/migrations",
    "state/locks",
    "memory/projects",
    "logs/conversations",
    "logs/runs",
    "logs/events",
    "logs/audit",
    "artifacts/patches",
    "artifacts/command_outputs",
    "artifacts/approvals",
    "artifacts/risk_scans",
    "artifacts/evidence",
    "artifacts/exports",
    "outputs/reports",
    "backups",
)

SECRET_ENV_FRAGMENTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "API_KEY",
    "AUTH",
    "CREDENTIAL",
    "SSH",
)
