"""Compatibility interfaces for the removed sensitive-content scanner.

No text, field, file, or database is classified as a secret by these adapters.
Reports explicitly say disabled; they are not evidence that a scan was passed.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class SecretFinding:
    scope: str
    path: str
    field_path: str
    pattern_type: str
    table: str | None = None
    row_id: str | None = None

    @property
    def field(self) -> str:
        return self.field_path

    @property
    def pattern(self) -> str:
        return self.pattern_type

    def safe_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "path": self.path, "table": self.table,
                "row_id": self.row_id, "field_path": self.field_path,
                "pattern_type": self.pattern_type, "count": 1}


def scan_text_for_secrets(text: str, *, path: str = "<text>", scope: str = "text",
                          field_path: str = "<text>", table: str | None = None,
                          row_id: str | None = None) -> list[SecretFinding]:
    return []


def scan_json_for_secrets(value: Any, *, path: str = "<json>", scope: str = "json",
                          field_path: str = "$", table: str | None = None,
                          row_id: str | None = None, _depth: int = 0) -> list[SecretFinding]:
    return []


def _disabled_summary(**counts: int) -> dict[str, Any]:
    return {"status": "disabled", "enabled": False, "count": 0,
            "findings": [], **counts}


def scan_paths_for_secrets(paths: Iterable[Path | str], *, scope: str = "files") -> dict[str, Any]:
    return _disabled_summary(scanned_files=0, skipped_files=0)


def scan_sqlite_for_secrets(db_path: Path | str, *, scope: str = "sqlite") -> dict[str, Any]:
    return _disabled_summary(scanned_files=0, skipped_files=0, scanned_rows=0)


def secret_scan_scopes(home: Path) -> dict[str, list[Path]]:
    """Retain report section identities without traversing their contents."""
    return {
        "ledger": [home / "logs" / "runs"],
        "audit": [home / "logs" / "audit"],
        "blackboard": [home / "state" / "blackboard.json", home / "state" / "blackboard_runs"],
        "trace": [home / "logs" / "events", home / "logs" / "runs"],
        "replay": [home / "artifacts" / "replay_snapshots", home / "logs" / "runs"],
        "checkpoints": [home / "artifacts" / "checkpoints"],
        "artifacts": [home / "artifacts"],
        "provider_error_artifacts": [home / "artifacts" / "provider_parse_failures"],
        "outputs/reports": [home / "outputs" / "reports"],
        "evidence_bundles": [home / "outputs" / "evidence"],
        "docs": [home / "docs"],
    }


def scan_named_scopes(home: Path) -> dict[str, dict[str, Any]]:
    return {**{name: _disabled_summary(scanned_files=0, skipped_files=0)
               for name in secret_scan_scopes(home)},
            "sqlite": _disabled_summary(scanned_files=0, skipped_files=0, scanned_rows=0)}
