from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, unquote, urljoin, urlsplit
import hashlib
import http.client
import json
import base64
import os
import re
import signal
import ssl
import stat
import subprocess
import zipfile

from sitina.execution import ExecutionPolicy, task_environment
from sitina.execution_network import TaskNetworkGateway
from .authority import ExtensionAuthorityError
from .manager import ExtensionManager
from .spec import load_skill


class GitHubAnonymousRateLimitError(ExtensionAuthorityError):
    """Public metadata quota was exhausted; no credential fallback is allowed."""


@dataclass(frozen=True)
class PinnedGitHubSkillSource:
    archive_url: str
    commit: str
    subdirectory: tuple[str, ...]


def parse_pinned_github_source(source: str) -> PinnedGitHubSkillSource | None:
    """Recognize a public GitHub directory with an explicit immutable commit."""
    parsed = urlsplit(source)
    parts = parsed.path.strip('/').split('/')
    if parsed.hostname != 'github.com' or len(parts) < 3 or parts[2] != 'tree':
        return None
    if (parsed.scheme != 'https' or parsed.netloc.lower() != 'github.com'
            or parsed.query or parsed.fragment or len(parts) < 5):
        raise ExtensionAuthorityError('GitHub 技能目录必须使用无登录信息的 HTTPS 固定提交地址。')
    owner, repository, _tree, commit, *raw_directory = parts
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+', owner)
            or not re.fullmatch(r'[A-Za-z0-9_.-]+', repository)
            or owner in {'.', '..'} or repository in {'.', '..'}
            or not re.fullmatch(r'[0-9a-fA-F]{40}', commit)):
        raise ExtensionAuthorityError('GitHub 技能目录必须固定完整的 40 位 commit，不接受移动分支。')
    directory = tuple(unquote(part, errors='strict') for part in raw_directory)
    if any(not part or part in {'.', '..'} or '/' in part or '\\' in part
           or '\x00' in part or part == '.git' for part in directory):
        raise ExtensionAuthorityError('GitHub 技能子目录必须是仓库内的普通相对路径。')
    commit = commit.lower()
    return PinnedGitHubSkillSource(
        archive_url=f'https://github.com/{owner}/{repository}/archive/{commit}.zip',
        commit=commit, subdirectory=directory,
    )


def _archive_members(archive):
    entries = archive.infolist()
    if len(entries) > 10000 or sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
        raise ExtensionAuthorityError('公开技能仓库展开范围过大。')
    members, roots = {}, set()
    for entry in entries:
        parts = entry.filename.rstrip('/').split('/')
        if (entry.flag_bits & 1 or any(p in {'', '.', '..', '.git'} for p in parts)
                or '\\' in entry.filename or '\x00' in entry.filename):
            raise ExtensionAuthorityError('技能归档包含加密或不安全路径。')
        roots.add(parts[0])
        if len(parts) == 1:
            if not entry.is_dir():
                raise ExtensionAuthorityError('技能归档缺少普通仓库根目录。')
            continue
        relative = '/'.join(parts[1:])
        if relative in members:
            raise ExtensionAuthorityError('技能归档包含重复路径。')
        members[relative] = entry
    if len(roots) != 1:
        raise ExtensionAuthorityError('技能归档必须恰好包含一个仓库根。')
    return members


def materialize_pinned_skill_archive(
    archive_path: Path, scratch: Path, source: PinnedGitHubSkillSource,
) -> Path:
    """Select one explicit Skill directory without treating siblings as its resources."""
    if not zipfile.is_zipfile(archive_path):
        raise ExtensionAuthorityError('固定提交下载没有返回 ZIP 仓库归档。')
    with zipfile.ZipFile(archive_path) as archive:
        members = _archive_members(archive)
        prefix = '/'.join(source.subdirectory)
        for n in range(1, len(source.subdirectory) + 1):
            ancestor = members.get('/'.join(source.subdirectory[:n]))
            if ancestor is not None and (not ancestor.is_dir()
                    or stat.S_IFMT(ancestor.external_attr >> 16) not in {0, stat.S_IFDIR}):
                raise ExtensionAuthorityError('技能目录的祖先不能是文件或符号链接。')
        selected_entries = [(path[len(prefix) + 1:], entry) for path, entry in members.items()
                            if path.startswith(prefix + '/')]
        if any(stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG, stat.S_IFDIR}
               for _, entry in selected_entries):
            raise ExtensionAuthorityError('选定技能目录包含符号链接或特殊文件。')
        files = [(path, entry) for path, entry in selected_entries if not entry.is_dir()]
        if not files or len(files) > 200 or sum(e.file_size for _, e in files) > 32 * 1024 * 1024:
            raise ExtensionAuthorityError('技能目录为空或超过下载范围。')
        if any(stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG}
               for _, entry in files):
            raise ExtensionAuthorityError('选定技能目录包含符号链接或特殊文件。')
        selected = scratch / 'selected-archive'
        selected.mkdir()
        for relative, entry in files:
            target = selected / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(archive.read(entry))
            target.chmod(0o755 if (entry.external_attr >> 16) & 0o111 else 0o644)
    load_skill(selected / 'SKILL.md', metadata_only=True)
    return selected

class PublicSkillSourceFetcher:
    """Anonymous sources go through one task gateway and isolated storage.

    The downloader connects only to the gateway's loopback listener.  Git runs
    inside the native process sandbox with that same listener as its sole
    network destination; user Git configuration and credential helpers are not
    inherited.  A source is Git when it ends in .git or uses git+https://.
    """

    def __init__(self, root: Path, *, git_executable: Path = Path("/usr/bin/git")):
        self.root = Path(root).expanduser().resolve(strict=False)
        self.git_executable = Path(git_executable)

    def _public_file(self, url: str, scratch: Path, request_id: str) -> Path:
        scratch.mkdir()
        decisions = []
        gateway = TaskNetworkGateway(
            scratch / "gateway", "skill-source-" + hashlib.sha256(request_id.encode()).hexdigest()[:32],
            public_read=True, public_git=False, allowed_urls=(url,), audit=decisions.append,
        )
        try:
            gateway.start()
            return self._download(url, scratch, gateway, validate_skill=False)
        except Exception as error:
            rejected = [row.get("reason") for row in decisions if row.get("event") == "request_rejected"]
            if rejected:
                raise ExtensionAuthorityError("公开下载被网络边界拒绝：" + str(rejected[-1])) from error
            raise
        finally:
            gateway.close()

    def inspect(self, source: str, request_id: str) -> dict:
        """Resolve a public source without installing it or trusting its instructions."""
        parsed = urlsplit(source)
        if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment):
            raise ExtensionAuthorityError("请使用无登录信息和查询参数的公开 HTTPS 来源。")
        parts = parsed.path.strip("/").split("/")
        if parsed.netloc != "github.com":
            return {"kind": "source", "choices": [{"name": "安装此来源", "source": source}]}
        if len(parts) < 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) or p in {".", ".."} for p in parts[:2]):
            raise ExtensionAuthorityError("GitHub 仓库地址不完整。")
        owner, repo = parts[:2]
        repo = repo.removesuffix(".git")
        if len(parts) == 2:
            ref, relative, kind = "HEAD", "", "repository"
        elif len(parts) >= 5 and parts[2] in {"tree", "blob"}:
            ref, relative, kind = unquote(parts[3]), "/".join(parts[4:]), parts[2]
        else:
            raise ExtensionAuthorityError("请提供仓库、技能目录或 marketplace.json 地址。")
        segments = [unquote(p) for p in relative.split("/")] if relative else []
        if any(p in {"", ".", ".."} or "/" in p or "\\" in p or "\x00" in p for p in segments):
            raise ExtensionAuthorityError("GitHub 来源路径不安全。")
        self.root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix="inspect-", dir=self.root) as name:
            scratch = Path(name)
            commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref, safe='')}"
            try:
                commit_file = self._public_file(commit_url, scratch / "commit", request_id + "-commit")
            except GitHubAnonymousRateLimitError:
                return self._inspect_archive(owner, repo, ref, segments, kind, scratch, request_id)
            commit_value = json.loads(commit_file.read_text())
            commit = commit_value.get("sha") if isinstance(commit_value, dict) else None
            if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ExtensionAuthorityError("GitHub 未返回可固定的提交版本。")
            prefix = f"https://github.com/{owner}/{repo}/tree/{commit}/"
            files = None
            if kind == "tree":
                return {"kind": "skill", "commit": commit, "choices": [
                    {"name": segments[-1], "source": prefix + "/".join(segments)}]}
            if kind == "repository":
                tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit}?recursive=1"
                tree_file = self._public_file(tree_url, scratch / "tree", request_id + "-tree")
                if tree_file.stat().st_size > 4 * 1024 * 1024:
                    raise ExtensionAuthorityError("仓库目录清单过大，请提供具体技能目录地址。")
                tree = json.loads(tree_file.read_text())
                if (not isinstance(tree, dict) or tree.get("truncated") is not False
                        or not isinstance(tree.get("tree"), list) or len(tree["tree"]) > 10000):
                    raise ExtensionAuthorityError("仓库目录清单不完整，请提供具体技能目录地址。")
                files = set()
                for entry in tree["tree"]:
                    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                        raise ExtensionAuthorityError("GitHub 目录成员格式错误。")
                    path = entry["path"]
                    if (any(p in {"", ".", "..", ".git"} for p in path.split("/"))
                            or "\\" in path or "\x00" in path):
                        raise ExtensionAuthorityError("仓库目录清单包含不安全路径。")
                    if entry.get("type") == "blob" and entry.get("mode") in {"100644", "100755"}:
                        files.add(path)
                if ".claude-plugin/marketplace.json" in files:
                    segments = [".claude-plugin", "marketplace.json"]
                else:
                    skill_files = sorted(path for path in files if path.split("/")[-1] == "SKILL.md")
                    if not skill_files:
                        raise ExtensionAuthorityError("仓库可以访问，但未找到可安装的 SKILL.md 或技能市场清单。")
                    if len(skill_files) > 500:
                        raise ExtensionAuthorityError("仓库包含过多技能，请提供具体技能目录地址。")
                    choices = []
                    for path in skill_files:
                        directory = path.rsplit("/", 1)[0] if "/" in path else ""
                        choices.append({
                            "name": directory.split("/")[-1] if directory else repo,
                            "group": directory or "仓库根目录",
                            "source": (prefix + quote(directory, safe="/") if directory else
                                       f"https://github.com/{owner}/{repo}/archive/{commit}.zip"),
                        })
                    return {"kind": "repository", "name": repo, "commit": commit, "choices": choices}
            if segments[-1] == "SKILL.md":
                if len(segments) < 2:
                    return {"kind": "source", "commit": commit, "choices": [
                        {"name": repo, "source": f"https://github.com/{owner}/{repo}/archive/{commit}.zip"}]}
                return {"kind": "skill", "commit": commit, "choices": [
                    {"name": segments[-2], "source": prefix + "/".join(segments[:-1])}]}
            if segments[-1] != "marketplace.json":
                raise ExtensionAuthorityError("该文件不是技能说明或 marketplace.json。")
            manifest_url = f"https://api.github.com/repos/{owner}/{repo}/contents/" + "/".join(segments) + "?ref=" + commit
            manifest_file = self._public_file(manifest_url, scratch / "manifest", request_id + "-manifest")
            if manifest_file.stat().st_size > 1024 * 1024:
                raise ExtensionAuthorityError("技能清单超过 1 MiB。")
            manifest = json.loads(self._github_content(json.loads(manifest_file.read_text())))
            plugins = manifest.get("plugins") if isinstance(manifest, dict) else None
            if not isinstance(plugins, list) or len(plugins) > 200:
                raise ExtensionAuthorityError("技能市场清单缺少有效 plugins 列表。")
            if files is None:
                files = self._repository_files(owner, repo, commit, scratch, request_id)
            choices, unsupported = self._marketplace_skill_choices(manifest, files, prefix)
            return {"kind": "marketplace", "name": str(manifest.get("name", repo)), "commit": commit,
                    "choices": choices, "unsupported": unsupported}

    def _repository_files(self, owner, repo, commit, scratch, request_id):
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit}?recursive=1"
        path = self._public_file(url, scratch / "marketplace-tree", request_id + "-marketplace-tree")
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ExtensionAuthorityError("仓库目录清单过大，请提供具体技能目录地址。")
        value = json.loads(path.read_text())
        if (not isinstance(value, dict) or value.get("truncated") is not False
                or not isinstance(value.get("tree"), list) or len(value["tree"]) > 10000):
            raise ExtensionAuthorityError("仓库目录清单不完整，请提供具体技能目录地址。")
        files = set()
        for entry in value["tree"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise ExtensionAuthorityError("GitHub 目录成员格式错误。")
            path = entry["path"]
            self._safe_skill_relative_path(path)
            if entry.get("type") == "blob" and entry.get("mode") in {"100644", "100755"}:
                files.add(path)
        return files

    @staticmethod
    def _safe_skill_relative_path(value):
        if not isinstance(value, str):
            raise ExtensionAuthorityError("技能路径必须是字符串。")
        path = value.removeprefix("./").rstrip("/")
        if path in {"", "."}:
            return ""
        if (any(part in {"", ".", "..", ".git"} for part in path.split("/"))
                or any(char in path for char in (chr(92), "?", "#", "%", chr(0), ":"))):
            raise ExtensionAuthorityError("技能清单包含越界或不支持的路径。")
        return path

    @staticmethod
    def _discover_plugin_skills(files, source_root):
        prefix = source_root + "/" if source_root else ""
        if prefix + "SKILL.md" in files:
            return [source_root]
        for relative_root in ("skills/", ".agents/skills/", ".claude/skills/"):
            skill_prefix = prefix + relative_root
            paths = sorted(path.rsplit("/", 1)[0] for path in files
                           if path.startswith(skill_prefix) and path.endswith("/SKILL.md")
                           and not {"tests", "test", "fixtures", "oracles"}.intersection(
                               path[len(skill_prefix):].split("/")[:-1]))
            if paths:
                return paths
        return []

    @classmethod
    def _marketplace_skill_choices(cls, manifest, files, prefix):
        choices, unsupported, seen = [], [], set()
        for plugin in manifest["plugins"]:
            if not isinstance(plugin, dict):
                raise ExtensionAuthorityError("技能清单中的插件格式不正确。")
            group = str(plugin.get("name", "未命名插件"))
            source = plugin.get("source")
            try:
                root = cls._safe_skill_relative_path(source)
            except ExtensionAuthorityError:
                unsupported.append(group)
                continue
            paths = plugin.get("skills")
            if paths is None:
                directories = cls._discover_plugin_skills(files, root)
            elif isinstance(paths, list):
                directories = []
                for path in paths:
                    relative = cls._safe_skill_relative_path(path)
                    directory = "/".join(part for part in (root, relative) if part)
                    if directory.endswith("/SKILL.md"):
                        directory = directory.rsplit("/", 1)[0]
                    elif directory == "SKILL.md":
                        directory = ""
                    if (directory + "/" if directory else "") + "SKILL.md" not in files:
                        raise ExtensionAuthorityError("清单指定的技能目录中没有普通 SKILL.md。")
                    directories.append(directory)
            else:
                raise ExtensionAuthorityError("技能清单的 skills 必须是目录列表。")
            if not directories:
                unsupported.append(group)
                continue
            for directory in directories:
                if directory in seen:
                    continue
                if len(choices) >= 500:
                    raise ExtensionAuthorityError("技能清单包含过多条目。")
                seen.add(directory)
                choices.append({"name": directory.rsplit("/", 1)[-1] or group, "group": group,
                                "source": prefix + quote(directory, safe="/") if directory else
                                          prefix.split("/tree/", 1)[0] + "/archive/" +
                                          prefix.split("/tree/", 1)[1].rstrip("/") + ".zip"})
        return choices, unsupported

    def _inspect_archive(self, owner, repo, ref, segments, kind, scratch, request_id):
        if kind == "blob" and segments[-1] not in {"SKILL.md", "marketplace.json"}:
            raise ExtensionAuthorityError("该文件不是技能说明或 marketplace.json。")
        archive_path = self._public_file(
            f"https://codeload.github.com/{owner}/{repo}/zip/{quote(ref, safe='')}",
            scratch / "archive", request_id + "-archive")
        with zipfile.ZipFile(archive_path) as archive:
            commit = archive.comment.decode("ascii", errors="strict")
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ExtensionAuthorityError("GitHub 归档未提供可固定的完整提交身份。")
            if re.fullmatch(r"[0-9a-fA-F]{40}", ref) and commit != ref.lower():
                raise ExtensionAuthorityError("GitHub 归档提交身份与请求版本不一致。")
            members = _archive_members(archive)
        files = {path for path, entry in members.items()
                 if not entry.is_dir() and stat.S_IFMT(entry.external_attr >> 16) in {0, stat.S_IFREG}}
        prefix = f"https://github.com/{owner}/{repo}/tree/{commit}/"
        relative = "/".join(segments)
        if kind == "tree" or (segments and segments[-1] == "SKILL.md"):
            directory = relative if kind == "tree" else "/".join(segments[:-1])
            skill_path = directory + "/SKILL.md" if directory else "SKILL.md"
            if skill_path not in files:
                raise ExtensionAuthorityError("指定目录不存在可安装的 SKILL.md。")
            return {"kind": "skill", "commit": commit, "choices": [{
                "name": directory.split("/")[-1] if directory else repo,
                "source": prefix + quote(directory, safe="/") if directory else
                          f"https://github.com/{owner}/{repo}/archive/{commit}.zip"}]}
        manifest_path = relative if kind == "blob" else ".claude-plugin/marketplace.json"
        if manifest_path in files:
            if members[manifest_path].file_size > 1024 * 1024:
                raise ExtensionAuthorityError("技能清单超过 1 MiB。")
            with zipfile.ZipFile(archive_path) as archive:
                raw = archive.read(members[manifest_path])
            manifest = json.loads(raw)
            if (not isinstance(manifest, dict) or not isinstance(manifest.get("plugins"), list)
                    or len(manifest["plugins"]) > 200):
                raise ExtensionAuthorityError("技能市场清单缺少有效 plugins 列表。")
            choices, unsupported = self._marketplace_skill_choices(manifest, files, prefix)
            return {"kind": "marketplace", "name": str(manifest.get("name", repo)),
                    "commit": commit, "choices": choices, "unsupported": unsupported}
        paths = sorted(p for p in files if p.split("/")[-1] == "SKILL.md")
        if not paths or len(paths) > 500:
            raise ExtensionAuthorityError("仓库未提供有限范围内可安装的 SKILL.md。")
        choices = []
        for path in paths:
            directory = path.rsplit("/", 1)[0] if "/" in path else ""
            choices.append({"name": directory.split("/")[-1] if directory else repo,
                            "group": directory or "仓库根目录",
                            "source": prefix + quote(directory, safe="/") if directory else
                            f"https://github.com/{owner}/{repo}/archive/{commit}.zip"})
        return {"kind": "repository", "name": repo, "commit": commit, "choices": choices}

    @staticmethod
    def _github_content(value: dict) -> bytes:
        if (not isinstance(value, dict) or value.get("encoding") != "base64"
                or not isinstance(value.get("content"), str) or len(value["content"]) > 12 * 1024 * 1024):
            raise ExtensionAuthorityError("GitHub 文件内容格式或大小不受支持。")
        try:
            content = base64.b64decode(value["content"].replace("\n", ""), validate=True)
        except ValueError as error:
            raise ExtensionAuthorityError("GitHub 文件编码无效。") from error
        sha = value.get("sha")
        actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if not isinstance(sha, str) or sha != actual:
            raise ExtensionAuthorityError("GitHub 文件内容与固定 blob 身份不一致。")
        return content

    def _github_directory(self, source: str, pinned: PinnedGitHubSkillSource, scratch: Path, request_id: str) -> Path:
        """Fetch only the selected directory; metadata failure must not widen it."""
        return self._github_directory_blobs(source, pinned, scratch, request_id)

    def _github_archive(self, source: str, pinned: PinnedGitHubSkillSource, scratch: Path, request_id: str) -> Path:
        owner, repo = urlsplit(source).path.strip("/").split("/")[:2]
        archive = self._public_file(f"https://codeload.github.com/{owner}/{repo}/zip/{pinned.commit}",
                                    scratch / "archive", request_id + "-archive")
        with zipfile.ZipFile(archive) as opened:
            if opened.comment.decode("ascii", errors="strict") != pinned.commit:
                raise ExtensionAuthorityError("GitHub 归档提交身份与所选版本不一致。")
        return materialize_pinned_skill_archive(archive, scratch, pinned)

    def _github_directory_blobs(self, source: str, pinned: PinnedGitHubSkillSource, scratch: Path, request_id: str) -> Path:
        owner, repo = urlsplit(source).path.strip("/").split("/")[:2]
        base = f"https://api.github.com/repos/{owner}/{repo}"
        tree_file = self._public_file(base + "/git/trees/" + pinned.commit + "?recursive=1",
                                      scratch / "tree", request_id + "-tree")
        tree = json.loads(tree_file.read_text())
        if not isinstance(tree, dict) or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
            raise ExtensionAuthorityError("GitHub 目录清单不完整。")
        prefix = "/".join(pinned.subdirectory) + "/"
        entries = []
        for entry in tree["tree"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise ExtensionAuthorityError("GitHub 目录成员格式错误。")
            if not entry["path"].startswith(prefix):
                continue
            relative = entry["path"][len(prefix):]
            if any(p in {"", ".", "..", ".git"} for p in relative.split("/")) or "\\" in relative or "\x00" in relative:
                raise ExtensionAuthorityError("技能目录包含越界路径。")
            if entry.get("type") == "tree":
                continue
            if (entry.get("type") != "blob" or entry.get("mode") not in {"100644", "100755"}
                    or not isinstance(entry.get("sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", entry["sha"])
                    or type(entry.get("size")) is not int or entry["size"] < 0):
                raise ExtensionAuthorityError("技能目录包含符号链接、子模块或未知文件类型。")
            entries.append((relative, entry))
        if not entries or len(entries) > 200 or sum(e["size"] for _, e in entries) > 32 * 1024 * 1024:
            raise ExtensionAuthorityError("技能目录为空或超过下载范围。")
        destination = scratch / "selected"
        destination.mkdir()
        for ordinal, (relative, entry) in enumerate(entries):
            # One API metadata request fixes membership and Git blob identities.
            # Fetch the selected bytes from the same immutable commit without
            # spending one API request per file or downloading sibling Skills.
            blob_url = (f"https://raw.githubusercontent.com/{owner}/{repo}/{pinned.commit}/"
                        + quote(entry["path"], safe="/"))
            document = self._public_file(blob_url,
                                         scratch / ("blob-" + str(ordinal)), request_id + "-blob-" + str(ordinal))
            content = document.read_bytes()
            actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            if actual != entry["sha"] or len(content) != entry["size"]:
                raise ExtensionAuthorityError("技能文件与固定目录清单不一致。")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(content)
            target.chmod(0o755 if entry["mode"] == "100755" else 0o644)
        load_skill(destination / "SKILL.md")
        return destination

    @contextmanager
    def __call__(self, source: str, request_id: str):
        git_source = source.startswith("git+")
        url = source[4:] if git_source else source
        parsed = urlsplit(url)
        git_source = git_source or parsed.path.rstrip("/").endswith(".git")
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise ExtensionAuthorityError("公开来源必须是无登录信息的 HTTP(S) 地址。")
        if git_source and (parsed.scheme != "https" or parsed.query):
            raise ExtensionAuthorityError("公开 Git 来源必须使用无查询参数的 HTTPS 仓库地址。")
        pinned = parse_pinned_github_source(url)
        if pinned is not None:
            git_source = False
        download_url = pinned.archive_url if pinned is not None else url
        self.root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix="source-", dir=self.root) as name:
            scratch = Path(name).resolve(strict=True)
            if pinned is not None:
                yield self._github_directory(url, pinned, scratch, request_id)
                return
            task_id = "skill-public-" + hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:32]
            gateway = TaskNetworkGateway(
                scratch / "gateway", task_id, public_read=not git_source, public_git=git_source,
                allowed_urls=() if git_source else (download_url,), git_urls=(url,) if git_source else (),
            )
            try:
                gateway.start()
                if git_source:
                    destination = self._clone(url, scratch, gateway)
                else:
                    destination = self._download(download_url, scratch, gateway)
                    if pinned is not None:
                        destination = materialize_pinned_skill_archive(destination, scratch, pinned)
                yield destination
            finally:
                gateway.close()

    @staticmethod
    def _download(url: str, scratch: Path, gateway: TaskNetworkGateway, *, validate_skill: bool = True) -> Path:
        destination = scratch / "source.download"
        # Redirects are requested again through the same inspected gateway.
        # No ProxyHandler, ambient proxy bypass, cookies or authorization headers
        # participate in this client.
        for _redirect in range(6):
            parsed = urlsplit(url)
            if parsed.scheme == "https":
                context = ssl.create_default_context(cafile=str(gateway.read_paths[0]))
                connection = http.client.HTTPSConnection("127.0.0.1", gateway.port,
                                                         timeout=30, context=context)
                connection.set_tunnel(parsed.hostname, parsed.port or 443)
                target = parsed.path or "/"
                if parsed.query:
                    target += "?" + parsed.query
            else:
                connection = http.client.HTTPConnection("127.0.0.1", gateway.port, timeout=30)
                target = url
            try:
                connection.request("GET", target, headers={"Accept": "application/zip, text/plain, */*",
                                                          "User-Agent": "Sitina-Skills/1"})
                response = connection.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location:
                        raise ExtensionAuthorityError("公开来源重定向缺少目标。")
                    redirected = urljoin(url, location)
                    next_url = urlsplit(redirected)
                    if (next_url.scheme not in {"http", "https"} or not next_url.hostname
                            or next_url.username is not None or next_url.password is not None or next_url.fragment):
                        raise ExtensionAuthorityError("公开来源重定向不符合匿名 HTTP(S) 规则。")
                    url = redirected
                    continue
                if response.status != 200:
                    if (parsed.hostname == "api.github.com" and response.status in {403, 429}
                            and response.getheader("X-RateLimit-Remaining") == "0"):
                        raise GitHubAnonymousRateLimitError(
                            "GitHub 匿名下载额度已用尽，请等待额度恢复后重试；本次未完成安装。"
                            "这不表示仓库链接失效，也不会改用账号凭据。")
                    raise ExtensionAuthorityError("受控公开下载返回 HTTP " + str(response.status) + "。")
                maximum = 32 * 1024 * 1024
                total = 0
                with destination.open("xb") as output:
                    while True:
                        chunk = response.read(min(65536, maximum - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > maximum:
                            raise ExtensionAuthorityError("公开技能包超过 32 MiB；请下载后使用本地安装。")
                        output.write(chunk)
                if not validate_skill or zipfile.is_zipfile(destination):
                    return destination
                markdown = destination.with_name("SKILL.md")
                destination.rename(markdown)
                load_skill(markdown, metadata_only=True)
                return markdown
            except TimeoutError as error:
                raise ExtensionAuthorityError("公开来源下载超时；尚未完成安装，请检查网络后重新提交。") from error
            finally:
                connection.close()
        raise ExtensionAuthorityError("公开来源重定向次数过多。")

    def _clone(self, url: str, scratch: Path, gateway: TaskNetworkGateway) -> Path:
        if not self.git_executable.is_absolute() or not self.git_executable.is_file():
            raise ExtensionAuthorityError("原生 Git 不可用；未尝试其他下载入口。")
        checkout = scratch / "checkout"
        environment = task_environment(scratch / "runtime", workspace=scratch, gateway=gateway.environment())
        policy = ExecutionPolicy(gateway.task_id, read_roots=(self.git_executable,), write_roots=(scratch,))
        profile = policy.sandbox_profile(runtime_roots=(scratch / "runtime",),
                                         gateway_port=gateway.port, trust_paths=gateway.read_paths)
        argv = ["/usr/bin/sandbox-exec", "-p", profile, str(self.git_executable),
                "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false",
                "clone", "--no-tags", "--", url, str(checkout)]
        log_path = scratch / "git-output.log"
        with log_path.open("xb") as log:
            child = subprocess.Popen(argv, cwd=scratch, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=log, start_new_session=True)
            try:
                code = child.wait(timeout=90)
            except subprocess.TimeoutExpired as error:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                raise ExtensionAuthorityError("受控 Git 下载超时；未重试。") from error
        if code != 0:
            with log_path.open("rb") as log:
                detail = log.read(8192).decode("utf-8", errors="replace")
            raise ExtensionAuthorityError("受控 Git 下载失败（exit " + str(code) + "）：" + detail)
        load_skill(checkout / "SKILL.md", metadata_only=True)
        return checkout

