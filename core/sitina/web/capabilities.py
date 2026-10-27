from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, ContextManager, Iterable, Mapping
from urllib.parse import urljoin, urlsplit
import hashlib
import http.client
import json
import os
import signal
import ssl
import subprocess
import threading
import zipfile

from sitina.execution import ExecutionPolicy, task_environment
from sitina.execution_network import TaskNetworkGateway
from sitina.extensions.authority import ExtensionAuthorityError
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.spec import load_skill


from sitina.extensions.skill_sources import PublicSkillSourceFetcher


class SkillsService:
    """Web adapter over the existing shared extension Journal and immutable store.

    The HTTP caller authenticates its local user and passes user_initiated=True
    for mutations.  Public fetching must be supplied by the task network gateway;
    this adapter never opens a socket or invokes an unconfined downloader.
    """

    def __init__(
        self,
        manager: ExtensionManager,
        *,
        public_source_fetcher: Callable[[str, str], ContextManager[Path]] | None = None,
        available_tools: Iterable[str] | None = None,
    ):
        self.manager = manager
        self.public_source_fetcher = public_source_fetcher
        self.available_tools = None if available_tools is None else frozenset(available_tools)
        self._mutation_lock = threading.Lock()

    @property
    def authority(self):
        return self.manager.shared_authority

    def list_skills(self) -> dict[str, Any]:
        authority = self.authority
        projection = authority.load_projection()
        candidates: dict[str, list[dict[str, Any]]] = {}
        origins: dict[str, str] = {}
        recent: dict[str, str] = {}
        removed: set[str] = set()
        operations: dict[str, dict[str, Any]] = {}
        for event in authority._journal_events():
            if event.event_type == "extension.skill-management-requested":
                original = event.payload["management_request"]
                operations[str(original["request_id"])] = {
                    "request_id": original["request_id"], "state": "PENDING",
                    "action": original["action"], "name": original.get("name"),
                }
            elif event.event_type == "extension.skill-management-committed":
                payload = event.payload
                candidate_id = str(payload["candidate_id"])
                recent[str(payload["name"])] = candidate_id
                if payload["result"].get("action") == "delete":
                    removed.add(str(payload["name"]))
                elif str(payload["result"].get("action", "")).startswith("install"):
                    removed.discard(str(payload["name"]))
                if payload.get("source"):
                    origins[candidate_id] = str(payload["source"])
                operations[str(payload["result"]["request_id"])] = dict(payload["result"])
            elif event.event_type == "extension.skill-management-failed":
                result = event.payload["result"]
                operations[str(result["request_id"])] = dict(result)
        for value in projection["candidates"].values():
            if value.get("kind") == "skill":
                candidates.setdefault(str(value["name"]), []).append(dict(value))
        skills: list[dict[str, Any]] = []
        for name, versions in sorted(candidates.items()):
            if name in removed:
                continue
            versions.sort(key=lambda value: int(value["stream_version"]), reverse=True)
            default = dict(projection["defaults"].get("skill:" + name) or {})
            publication = projection["publications"].get(default.get("publication_id"), {})
            active_id = str(default.get("candidate_id") or publication.get("published", {}).get("candidate_id") or "")
            selected_id = active_id or recent.get(name) or str(versions[0]["candidate_id"])
            selected = next((value for value in versions if value["candidate_id"] == selected_id), versions[0])
            row: dict[str, Any] = {
                "name": name, "installed": True, "enabled": default.get("state") == "ACTIVE",
                "candidate_id": selected["candidate_id"], "version": selected["version"],
                "source": origins.get(str(selected["candidate_id"])) or selected.get("provenance", {}).get("source"),
                "description": "", "availability": "AVAILABLE", "unavailable_reason": None,
                "required_tools": [], "missing_tools": [], "tools_observed": self.available_tools is not None,
                "instructions": "", "versions": [], "management_allowed": True,
            }
            for version in versions:
                candidate_id = str(version["candidate_id"])
                row["versions"].append({
                    "candidate_id": candidate_id, "version": str(version["version"]),
                    "active": candidate_id == active_id, "install_id": version["install_id"],
                    "source": origins.get(candidate_id) or version.get("provenance", {}).get("source"),
                })
            try:
                snapshot = authority.build_execution_snapshot(str(selected["candidate_id"]))
                skill = load_skill(snapshot.root / "SKILL.md")
                row.update({
                    "description": skill.description, "instructions": skill.body,
                    "required_tools": list(skill.required_tools),
                    "allowed_tools": list(skill.allowed_tools),
                    "installation_path": str(snapshot.root),
                    "missing_tools": sorted(set(skill.required_tools) - self.available_tools)
                    if self.available_tools is not None else [],
                })
            except (OSError, ValueError, RuntimeError) as error:
                row.update({"availability": "UNAVAILABLE", "unavailable_reason": str(error)})
            skills.append(row)
        return {
            "skills": skills, "operations": list(operations.values())[-20:],
            "scope": "global", "existing_tasks_keep_pinned_versions": True,
            "installation_root": str(self.manager.root),
        }

    def inspect_source(self, request: Mapping[str, Any]) -> dict[str, Any]:
        source, request_id = request.get("source"), request.get("request_id")
        if (not isinstance(source, str) or len(source) > 4096 or not isinstance(request_id, str)
                or not request_id or len(request_id) > 160):
            raise ExtensionAuthorityError("来源或请求标识无效。")
        if self.public_source_fetcher is None or not hasattr(self.public_source_fetcher, "inspect"):
            raise ExtensionAuthorityError("公开来源识别暂不可用。")
        return self.public_source_fetcher.inspect(source, request_id)

    def mutate(self, request: Mapping[str, Any], *, user_initiated: bool = False) -> dict[str, Any]:
        # One adapter instance avoids concurrent UI installs, while the authority
        # supplies cross-process root locking and durable request replay.
        with self._mutation_lock:
            return self.manager.manage_skill(
                request, user_initiated=user_initiated, source_resolver=self._resolve_source,
            )

    @contextmanager
    def _resolve_source(self, source: str, action: str, request_id: str):
        if action == "install_public":
            url = urlsplit(source[4:] if source.startswith("git+") else source)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None or url.password is not None or url.fragment:
                raise ExtensionAuthorityError("公开来源必须是无登录信息的 HTTP(S) 地址。")
            if self.public_source_fetcher is None:
                raise ExtensionAuthorityError("受控公开下载出口尚不可用；未发出下载请求。")
            # The injected gateway must validate DNS, destination, redirects and
            # Git upload-pack protocol before returning an isolated local source.
            with self.public_source_fetcher(source, request_id) as path:
                with self._local_source(Path(path)) as root:
                    yield root
            return
        path = Path(source).expanduser()
        if not path.is_absolute():
            raise ExtensionAuthorityError("本地技能来源必须使用绝对路径。")
        with self._local_source(path) as root:
            yield root

    @contextmanager
    def _local_source(self, path: Path):
        if path.is_symlink():
            raise ExtensionAuthorityError("技能来源入口不能是符号链接；请使用实际目录。")
        path = path.resolve(strict=True)
        if path.is_dir():
            load_skill(path / "SKILL.md", metadata_only=True)
            yield path
            return
        if path.name == "SKILL.md" and path.is_file():
            load_skill(path, metadata_only=True)
            yield path.parent
            return
        if not path.is_file() or not zipfile.is_zipfile(path):
            raise ExtensionAuthorityError("技能来源必须是目录、SKILL.md 或 ZIP 技能包。")
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 10000 or sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
                raise ExtensionAuthorityError("技能包展开范围过大，请先解压到本地目录再安装。")
            if any(entry.flag_bits & 1 for entry in entries):
                raise ExtensionAuthorityError("不支持加密技能包。")
        with TemporaryDirectory(prefix="sitina-skill-import-") as scratch:
            root = Path(scratch).resolve(strict=True)
            ExtensionManager._safe_extract_zip(path, root)
            if (root / "SKILL.md").is_file():
                skill_root = root
            else:
                matches = list(root.glob("*/SKILL.md"))
                if len(matches) != 1:
                    raise ExtensionAuthorityError("技能包必须恰好包含一个技能根目录。")
                skill_root = matches[0].parent
            load_skill(skill_root / "SKILL.md", metadata_only=True)
            yield skill_root
