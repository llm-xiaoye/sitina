"""Deterministic code and configuration revision evidence."""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any, Iterable

from sitina import __version__
from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.utils import file_sha256, sha256_text, stable_json


REVISION_FIELDS = (
    "code_revision_type",
    "code_revision",
    "code_dirty",
    "config_hash",
    "roles_hash",
    "policy_hash",
    "python_version",
    "sitina_version",
)


class CodeRevisionResolver:
    """Bind a run to code without ever reading profile or credential files."""

    def __init__(self, home: Path = SITINA_HOME):
        self.home = home

    def current(self) -> dict[str, Any]:
        code_hash, code_file_count = self._controlled_code_hash()
        git = self._git_revision(code_hash)
        return {
            **git,
            "config_hash": self._hash_files(self._config_files()),
            "roles_hash": self._hash_files([self.home / "config" / "roles.env"]),
            "policy_hash": self._hash_files(self._policy_files()),
            "python_version": platform.python_version(),
            "sitina_version": __version__,
            "code_file_count": code_file_count,
            "revision_hash_method": "sha256(stable_json(relative_path,file_sha256))",
        }

    def for_run(self, run_id: str) -> dict[str, Any]:
        for event in RunLedger(self.home).timeline(run_id):
            if event.get("event_type") != "run_started":
                continue
            payload = event.get("payload_json") or {}
            if all(field in payload for field in REVISION_FIELDS):
                return {field: payload.get(field) for field in REVISION_FIELDS} | {
                    "code_file_count": payload.get("code_file_count"),
                    "revision_hash_method": payload.get("revision_hash_method"),
                    "legacy_unversioned": False,
                }
        return {
            "code_revision_type": "legacy_unversioned",
            "code_revision": "legacy_unversioned",
            "code_dirty": False,
            "config_hash": "legacy_unversioned",
            "roles_hash": "legacy_unversioned",
            "policy_hash": "legacy_unversioned",
            "python_version": None,
            "sitina_version": None,
            "code_file_count": None,
            "revision_hash_method": None,
            "legacy_unversioned": True,
        }

    def _git_revision(self, code_hash: str) -> dict[str, Any]:
        if not (self.home / ".git").exists():
            return {
                "code_revision_type": "deterministic_code_hash",
                "code_revision": code_hash,
                "code_dirty": False,
            }
        try:
            head = subprocess.run(
                ["git", "-C", str(self.home), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            ).stdout.strip()
            dirty = bool(
                subprocess.run(
                    ["git", "-C", str(self.home), "status", "--porcelain", "--untracked-files=no"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                ).stdout.strip()
            )
        except (OSError, subprocess.SubprocessError):
            return {
                "code_revision_type": "deterministic_code_hash",
                "code_revision": code_hash,
                "code_dirty": False,
            }
        if not dirty:
            return {"code_revision_type": "git_commit", "code_revision": head, "code_dirty": False}
        return {
            "code_revision_type": "git_dirty_tree_hash",
            "code_revision": sha256_text(stable_json({"git_head": head, "controlled_tree_hash": code_hash})),
            "code_dirty": True,
        }

    def _controlled_code_hash(self) -> tuple[str, int]:
        files: list[Path] = []
        roots = (
            (self.home / "core" / "sitina", "*.py"),
            (self.home / "schemas", "*.json"),
            (self.home / "prompts", "*.md"),
        )
        for root, pattern in roots:
            if root.exists():
                files.extend(path for path in root.rglob(pattern) if path.is_file() and "__pycache__" not in path.parts)
        entrypoint = self.home / "bin" / "sitina"
        if entrypoint.is_file():
            files.append(entrypoint)
        return self._hash_files(files), len(set(files))

    def _config_files(self) -> list[Path]:
        root = self.home / "config"
        if not root.exists():
            return []
        return [
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in {".json", ".yaml", ".yml"}
        ]

    def _policy_files(self) -> list[Path]:
        names = (
            "agent_capabilities.yaml",
            "agent_ownership.yaml",
            "parallel_policy.yaml",
            "permissions.yaml",
            "proposal_policy.yaml",
            "retry_policy.yaml",
            "reviewers.yaml",
            "workflow_policy.yaml",
            "workflows.yaml",
        )
        return [self.home / "config" / name for name in names]

    def _hash_files(self, paths: Iterable[Path]) -> str:
        entries: list[dict[str, str]] = []
        for path in sorted(set(paths), key=lambda item: str(item)):
            if not path.is_file():
                continue
            try:
                relative = path.resolve().relative_to(self.home.resolve()).as_posix()
            except ValueError:
                continue
            if self._excluded(relative):
                continue
            digest = file_sha256(path)
            if digest:
                entries.append({"path": relative, "hash": digest})
        return sha256_text(stable_json(entries))

    @staticmethod
    def _excluded(relative: str) -> bool:
        lowered = relative.lower()
        return (
            lowered.startswith("profiles/")
            or lowered.endswith(".env") and lowered != "config/roles.env"
            or "/__pycache__/" in lowered
            or lowered.endswith(".pyc")
            or lowered.startswith(("data/", "logs/", "artifacts/", "outputs/", "state/"))
        )
