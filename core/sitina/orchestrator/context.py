from __future__ import annotations

import html
import hashlib
import os
import secrets
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.conversation.context import ContextPolicy
from sitina.legacy.retirement import LegacyRuntimePolicy
from sitina.storage import SitinaStore
from sitina.utils import load_json_yaml, read_json


class ContextBuilder:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.store = SitinaStore(home)

    def wrap_untrusted(self, text: str, *, source_type: str, trust_level: str = "untrusted") -> str:
        nonce = secrets.token_hex(4)
        escaped = html.escape(text, quote=False)
        return (
            f'<<UNTRUSTED_SOURCE nonce="{nonce}" source_type="{source_type}" '
            f'trust_level="{trust_level}" trusted_as_instruction="false">>\n'
            f"{escaped}\n"
            f'<<END_UNTRUSTED_SOURCE nonce="{nonce}">>'
        )

    def build_default_context(self, run_state: dict[str, Any]) -> dict[str, Any]:
        policy = ContextPolicy.load(self.home)
        legacy_policy = LegacyRuntimePolicy.load(self.home)
        legacy_memory_path = self.home / "memory" / "global_memory.md"
        if legacy_policy.protected_environment and legacy_policy.fully_disabled:
            memory = ""
            memory_authority = "canonical-journal-cas-memory-v1"
        else:
            memory = legacy_memory_path.read_text(encoding="utf-8") if legacy_memory_path.exists() else ""
            memory_authority = "legacy-markdown-fixture"
        active = read_json(self.home / "state" / "active_conversation.json", default={})
        blackboard = read_json(self.home / "state" / "blackboard.json", default={})
        return {
            "priority_order": ["source_code", "project_docs", "obsidian", "official_web", "general_web"],
            "context_policy_source": "config/context_policy.json",
            "context_policy_hash": policy.policy_hash,
            "max_recent_turns": policy.max_recent_turns,
            "memory": memory,
            "memory_authority": memory_authority,
            "active_conversation": active,
            "blackboard": blackboard,
            "run_state": run_state,
        }

    def configured_obsidian_roots(self) -> list[str]:
        roots: list[str] = []
        env_roots = os.environ.get("SITINA_OBSIDIAN_VAULTS")
        if env_roots:
            roots.extend(item.strip() for item in env_roots.split(",") if item.strip())
        config_path = self.home / "config" / "sitina.yaml"
        if config_path.exists():
            try:
                config = load_json_yaml(config_path)
                vaults = config.get("context", {}).get("obsidian", {}).get("vaults", [])
            except Exception:
                vaults = []
            for item in vaults:
                if isinstance(item, str):
                    roots.append(item)
                elif isinstance(item, dict) and item.get("enabled", True) and item.get("path"):
                    roots.append(str(item["path"]))
        out: list[str] = []
        for root in roots:
            expanded = str(Path(root).expanduser())
            if expanded not in out:
                out.append(expanded)
        return out

    def index_obsidian(self, roots: list[str] | None = None, *, incremental: bool = True) -> dict[str, Any]:
        self.store.init_db()
        roots = roots if roots is not None else self.configured_obsidian_roots()
        indexed = 0
        skipped = 0
        deleted = 0
        errors: list[dict[str, str]] = []
        seen_paths: set[str] = set()
        for root in roots:
            base = Path(root).expanduser()
            if not base.exists():
                errors.append({"root": str(base), "error": "vault path missing"})
                continue
            for path in base.rglob("*.md"):
                seen_paths.add(str(path))
                try:
                    stat = path.stat()
                    cached = self._cached_obsidian_file(path)
                    if incremental and cached and float(cached["mtime"]) == stat.st_mtime:
                        skipped += 1
                        continue
                    text = path.read_text(encoding="utf-8")
                    self._cache_obsidian_file(path, text)
                    indexed += 1
                except UnicodeDecodeError:
                    errors.append({"path": str(path), "error": "not utf-8"})
                except OSError as exc:
                    errors.append({"path": str(path), "error": str(exc)})
        deleted = self._delete_stale_obsidian_rows(roots, seen_paths)
        return {"status": "ok", "roots": roots, "indexed": indexed, "skipped": skipped, "deleted": deleted, "errors": errors}

    def retrieve_obsidian(self, query: str, roots: list[str] | None = None) -> list[dict[str, Any]]:
        roots = roots if roots is not None else self.configured_obsidian_roots()
        self.index_obsidian(roots, incremental=True)
        results: list[dict[str, Any]] = []
        needle = query.lower()
        if not needle:
            return results
        like = f"%{needle}%"
        root_paths = [Path(root).expanduser().resolve(strict=False) for root in roots]
        max_results = self._obsidian_max_results()
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT path, line, content, updated_at
                FROM obsidian_line_cache
                WHERE lower(content) LIKE ?
                ORDER BY path, line
                LIMIT 1000
                """,
                (like,),
            ).fetchall()
        for path, line, content, updated_at in rows:
            if root_paths:
                resolved = Path(path).expanduser().resolve(strict=False)
                if not any(str(resolved).startswith(str(root) + "/") or resolved == root for root in root_paths):
                    continue
            results.append(
                {
                    "path": path,
                    "line": line,
                    "line_start": line,
                    "line_end": line,
                    "citation": f"{path}:{line}",
                    "updated_at": updated_at,
                    "excerpt": self.wrap_untrusted(content, source_type="obsidian", trust_level="local_note"),
                }
            )
            if len(results) >= max_results:
                break
        return results

    def _cache_obsidian_file(self, path: Path, text: str) -> None:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        title = next((line.strip("# ").strip() for line in text.splitlines() if line.strip().startswith("#")), path.stem)
        excerpt = text[:500]
        with self.store.connect() as conn:
            conn.execute(
                """
                INSERT INTO obsidian_cache (path, mtime, content_hash, title, excerpt, updated_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(path) DO UPDATE SET
                  mtime=excluded.mtime,
                  content_hash=excluded.content_hash,
                  title=excluded.title,
                  excerpt=excluded.excerpt,
                  updated_at=excluded.updated_at
                """,
                (str(path), path.stat().st_mtime, digest, title, excerpt),
            )
            conn.execute("DELETE FROM obsidian_line_cache WHERE path = ?", (str(path),))
            conn.executemany(
                """
                INSERT INTO obsidian_line_cache (path, line, content, content_hash, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                """,
                [(str(path), idx, line, digest) for idx, line in enumerate(text.splitlines(), start=1)],
            )

    def _cached_obsidian_file(self, path: Path) -> dict[str, Any] | None:
        with self.store.connect() as conn:
            row = conn.execute("SELECT mtime, content_hash FROM obsidian_cache WHERE path = ?", (str(path),)).fetchone()
        if not row:
            return None
        return {"mtime": row[0], "content_hash": row[1]}

    def _obsidian_max_results(self) -> int:
        config_path = self.home / "config" / "sitina.yaml"
        if not config_path.exists():
            return 10
        try:
            config = load_json_yaml(config_path)
            return int(config.get("context", {}).get("obsidian", {}).get("max_results", 10))
        except Exception:
            return 10

    def _delete_stale_obsidian_rows(self, roots: list[str], seen_paths: set[str]) -> int:
        if not roots:
            return 0
        root_paths = [Path(root).expanduser().resolve(strict=False) for root in roots]
        seen_resolved = {str(Path(path).expanduser().resolve(strict=False)) for path in seen_paths}
        with self.store.connect() as conn:
            rows = conn.execute("SELECT path FROM obsidian_cache").fetchall()
            stale = []
            for (raw_path,) in rows:
                path = Path(raw_path).expanduser().resolve(strict=False)
                in_scope = any(str(path).startswith(str(root) + "/") or path == root for root in root_paths)
                if in_scope and raw_path not in seen_paths and str(path) not in seen_resolved:
                    stale.append(raw_path)
            for path in stale:
                conn.execute("DELETE FROM obsidian_cache WHERE path = ?", (path,))
                conn.execute("DELETE FROM obsidian_line_cache WHERE path = ?", (path,))
        return len(stale)
