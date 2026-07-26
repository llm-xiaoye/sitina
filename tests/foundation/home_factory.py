"""Disposable Sitina homes and read-only production sentinels."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sitina.runtime.execution_contract import ProductionHomeGuard


MARKER = ".sitina-bplus-disposable-v1"
MUTABLE_ROOTS = ("data", "logs", "state", "artifacts", "outputs", "memory", "backups", "temp")
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
    "outputs/generated",
    "backups",
    "temp",
    "Downloads",
)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _copy_source_tree(source: Path, destination: Path, *, safe_env_names: set[str]) -> None:
    if source.is_symlink():
        raise RuntimeError(f"source tree is a symlink: {source}")
    for directory, directory_names, file_names in os.walk(source, followlinks=False):
        current = Path(directory)
        relative = current.relative_to(source)
        for name in list(directory_names):
            candidate = current / name
            if candidate.is_symlink():
                raise RuntimeError(f"source directory symlink rejected: {candidate}")
            if name == "__pycache__" or name.startswith("."):
                directory_names.remove(name)
        target_directory = destination / relative
        target_directory.mkdir(parents=True, exist_ok=True)
        for name in file_names:
            path = current / name
            if path.is_symlink():
                raise RuntimeError(f"source file symlink rejected: {path}")
            if name == ".DS_Store" or "__pycache__" in path.parts:
                continue
            if path.suffix == ".env" and name not in safe_env_names:
                continue
            target = target_directory / name
            shutil.copy2(path, target, follow_symlinks=False)


def _sanitize_mcp_config(home: Path) -> None:
    path = home / "config/mcp/servers.yaml"
    if not path.exists():
        return
    value = json.loads(path.read_text(encoding="utf-8"))
    for definition in value.get("servers", {}).values():
        if "allowed_roots" in definition:
            definition["allowed_roots"] = [str(home)]
        environment = definition.get("env")
        if isinstance(environment, dict) and "SITINA_ALLOWED_ROOTS" in environment:
            environment["SITINA_ALLOWED_ROOTS"] = "${SITINA_ROOT}"
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _create_test_profiles(home: Path) -> None:
    profiles = home / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    for name in ("deepseek", "gpt", "minimax", "qwen"):
        path = profiles / f"{name}.env"
        path.write_text(
            "\n".join(
                (
                    "ANTHROPIC_BASE_URL=https://example.invalid/v1",
                    f"ANTHROPIC_AUTH_TOKEN_REF=keychain://com.sitina.fixture/{name}",
                    f"ANTHROPIC_MODEL={name}-fixture-model",
                    "",
                )
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)


def _seed_legacy_fixture(home: Path) -> None:
    root = home / "fixtures/legacy"
    root.mkdir(parents=True, exist_ok=True)
    database = root / "sitina.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE fixture_events(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        connection.execute("INSERT INTO fixture_events(payload) VALUES (?)", ('{"fixture":true}',))
    (root / "events.jsonl").write_text('{"fixture":true,"event_id":"legacy-fixture-1"}\n', encoding="utf-8")
    (root / "state.json").write_text('{"fixture":true,"state":"created"}\n', encoding="utf-8")


def _seed_compatibility_documents(source_root: Path, home: Path) -> None:
    readme = source_root / "README.md"
    if readme.is_symlink() or not readme.is_file():
        raise RuntimeError(f"source README must be a regular file: {readme}")
    shutil.copy2(readme, home / "README.md", follow_symlinks=False)
    (home / "outputs/reports/Sitina_v1_final_acceptance_report.md").write_text(
        "# Disposable legacy acceptance-report fixture\n\n"
        "This source-independent fixture records mock/local validation only. "
        "No live-provider result is asserted.\n",
        encoding="utf-8",
    )


@dataclass
class DisposableHome:
    path: Path
    root: Path
    marker_nonce: str

    def cleanup(self) -> None:
        candidate = self.path.resolve(strict=True)
        root = self.root.resolve(strict=True)
        if not _inside(candidate, root) or candidate == root:
            raise RuntimeError(f"cleanup target outside disposable root: {candidate}")
        marker = candidate / MARKER
        if marker.is_symlink() or not marker.is_file():
            raise RuntimeError(f"disposable marker missing: {candidate}")
        if marker.read_text(encoding="utf-8").strip() != self.marker_nonce:
            raise RuntimeError(f"disposable marker mismatch: {candidate}")
        for path in candidate.rglob("*"):
            if path.is_symlink():
                path.unlink()
        shutil.rmtree(candidate)

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, _type, _value, _traceback) -> None:
        self.cleanup()


class DisposableHomeFactory:
    def __init__(self, source_root: Path, production_home: Path, test_root: Path):
        self.source_root = source_root.resolve(strict=True)
        self.production_home = production_home.resolve(strict=True)
        self.test_root = ProductionHomeGuard(self.production_home).assert_test_home_isolated(test_root)

    def create(self, prefix: str = "sitina-bplus-") -> DisposableHome:
        self.test_root.mkdir(parents=True, exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=self.test_root)).resolve(strict=True)
        ProductionHomeGuard(self.production_home).assert_test_home_isolated(path)
        nonce = uuid.uuid4().hex
        (path / MARKER).write_text(nonce + "\n", encoding="utf-8")
        manifest_path = self.source_root / "tests/fixtures/sitina_home_template/fixture-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        safe_env = set(manifest["safe_config_env_files"])
        for relative in manifest["copy_roots"]:
            source = self.source_root / relative
            if source.exists():
                _copy_source_tree(source, path / relative, safe_env_names=safe_env)
        for relative in (*MUTABLE_ROOTS, *REQUIRED_DIRS):
            (path / relative).mkdir(parents=True, exist_ok=True)
        _sanitize_mcp_config(path)
        _create_test_profiles(path)
        _seed_compatibility_documents(self.source_root, path)
        (path / "memory/global_memory.md").write_text("# Disposable test memory\n", encoding="utf-8")
        (path / "memory/user_preferences.json").write_text("{}\n", encoding="utf-8")
        _seed_legacy_fixture(path)
        return DisposableHome(path=path, root=self.test_root, marker_nonce=nonce)


def _file_record(home: Path, path: Path) -> dict[str, Any]:
    before = path.lstat()
    relative = path.relative_to(home).as_posix()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        return {"path": relative, "kind": "non_regular", "mode": oct(before.st_mode & 0o7777)}
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    after = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after):
        raise RuntimeError(f"production file changed during sentinel capture: {relative}")
    # V2: content-addressed record. Hash only relpath + size + permission bits +
    # content sha256. Volatile filesystem identity (mtime_ns / inode / device) is
    # deliberately excluded so a content-preserving rewrite (atomic rename,
    # restore, re-seal) does not cause spurious drift; real tampering still shows
    # as a content/size/mode change or an added/removed entry. The identity()
    # recheck above guards only against a file changing *during* capture and is
    # not part of the hash.
    return {
        "path": relative,
        "size": before.st_size,
        "mode": oct(before.st_mode & 0o7777),
        "sha256": digest.hexdigest(),
    }


def _paths_under(root: Path, predicate=lambda path: True) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        (path for path in root.rglob("*") if (path.is_file() or path.is_symlink()) and predicate(path)),
        key=lambda path: path.as_posix(),
    )


def _sentinel_category(home: Path, name: str, paths: Iterable[Path]) -> dict[str, Any]:
    entries = [_file_record(home, path) for path in sorted(set(paths), key=lambda path: path.as_posix())]
    merkle = hashlib.sha256()
    for entry in entries:
        merkle.update(json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
        merkle.update(b"\n")
    return {
        "name": name,
        "entry_count": len(entries),
        "total_bytes": sum(int(entry.get("size", 0)) for entry in entries),
        "merkle_profile": "SORTED_CANONICAL_JSON_LEAVES_SHA256_V1",
        "merkle_root_sha256": merkle.hexdigest(),
        "entries": entries,
    }


def capture_production_sentinel(production_home: Path, goal_thread_id: str) -> dict[str, Any]:
    home = production_home.resolve(strict=True)
    exact_db = [home / "data/sitina.db", home / "data/sitina.db-wal", home / "data/sitina.db-shm"]
    exact_db = [path for path in exact_db if path.exists()]
    event_jsonl = _paths_under(home / "logs/events", lambda path: path.suffix == ".jsonl")
    audit_jsonl = _paths_under(home / "logs/audit", lambda path: path.suffix == ".jsonl")
    state_files = _paths_under(home / "state")
    artifact_files = _paths_under(home / "artifacts")
    output_files = _paths_under(home / "outputs")
    log_files = _paths_under(home / "logs")
    combined = state_files + artifact_files + output_files + log_files
    selected = lambda word: sorted({path for path in combined if word in path.as_posix().lower()}, key=lambda path: path.as_posix())
    categories = [
        _sentinel_category(home, "sqlite_exact", exact_db),
        _sentinel_category(home, "legacy_event_jsonl", event_jsonl),
        _sentinel_category(home, "legacy_audit_jsonl", audit_jsonl),
        _sentinel_category(home, "state_root", state_files),
        _sentinel_category(
            home,
            "checkpoint_material",
            [path for path in state_files + artifact_files if "checkpoint" in path.as_posix().lower()],
        ),
        _sentinel_category(home, "manifest_material", [path for path in state_files + artifact_files if "manifest" in path.name.lower()]),
        _sentinel_category(home, "replay_material", selected("replay")),
        _sentinel_category(home, "blackboard_material", selected("blackboard")),
        _sentinel_category(home, "evidence_material", selected("evidence")),
        _sentinel_category(home, "artifact_root", artifact_files),
    ]
    core = {
        "schema": "PRODUCTION_SENTINEL_V2",
        "goal_thread_id": goal_thread_id,
        "production_home": str(home),
        "observation_mode": "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2",
        "hash_algorithm": "sha256",
        "categories": categories,
    }
    digest = hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**core, "report_sha256": digest}


def capture_production_mutable_sentinel(production_home: Path, goal_thread_id: str) -> dict[str, Any]:
    """Cover every mutable Production root without re-hashing base categories twice."""

    home = production_home.resolve(strict=True)
    base = capture_production_sentinel(home, goal_thread_id)
    exact_db = {home / "data/sitina.db", home / "data/sitina.db-wal", home / "data/sitina.db-shm"}
    event_jsonl = set(_paths_under(home / "logs/events", lambda path: path.suffix == ".jsonl"))
    audit_jsonl = set(_paths_under(home / "logs/audit", lambda path: path.suffix == ".jsonl"))
    data_other = [path for path in _paths_under(home / "data") if path not in exact_db]
    logs_other = [path for path in _paths_under(home / "logs") if path not in event_jsonl and path not in audit_jsonl]
    extension_categories = [
        _sentinel_category(home, "data_other", data_other),
        _sentinel_category(home, "logs_other", logs_other),
        _sentinel_category(home, "output_root", _paths_under(home / "outputs")),
        _sentinel_category(home, "memory_root", _paths_under(home / "memory")),
        _sentinel_category(home, "backups_root", _paths_under(home / "backups")),
        _sentinel_category(home, "temp_root", _paths_under(home / "temp")),
    ]
    core = {
        "schema": "PRODUCTION_MUTABLE_SENTINEL_V3",
        "goal_thread_id": goal_thread_id,
        "production_home": str(home),
        "observation_mode": "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2",
        "hash_algorithm": "sha256",
        # Retained for compatibility with the manifest-bound active V3 baseline.
        "base_v1_report_sha256": base["report_sha256"],
        "categories": [*base["categories"], *extension_categories],
    }
    digest = hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**core, "report_sha256": digest}
