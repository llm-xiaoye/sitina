"""Independent acceptance boundary for Code Mode v1.

This module deliberately does not import or consume the Legacy B+ foundation
or activation gates.  Code Mode is accepted from a frozen candidate identity,
an independently supplied review decision, and run-bound execution evidence.
The module is intentionally side-effect free: callers decide where to persist
an evidence package, while this gate only verifies content-addressed inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from sitina.orchestrator.production_identity import (
    DEFAULT_IDENTITY_ROOTS,
    DEFAULT_RUNTIME_EXCLUDED_ROOTS,
    production_identity_digest,
)
from sitina.journal.model import payload_self_hash


SCHEMA = "CODE_EXECUTION_ACCEPTANCE_V1"
PROFILE_SCHEMA = "CODE_MODE_PROFILE_V1"
EVIDENCE_SCHEMA = "CODE_MODE_EVIDENCE_V1"
LEGACY_STATUS = "LEGACY_BPLUS_BLOCKED"
CODE_MODE_READY = "CODE_MODE_READY"
CODE_MODE_BLOCKED = "CODE_MODE_BLOCKED"
CANARY_PASSED = "CODE_MODE_CANARY_PASSED"
RELEASE_ACCEPTED = "CODE_MODE_RELEASE_ACCEPTED"

_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_DEFAULT_CANDIDATE_SOURCE_ROOTS = (
    "core",
    "config",
    "scripts",
    "tests",
    "bin",
    "schemas",
    "prompts/agents",
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "package.json",
    "package-lock.json",
)
_DEFAULT_CANDIDATE_EXCLUDED_ROOTS = (
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".superpowers",
    "artifacts",
    "review-evidence",
    "journal",
    "cas",
    "state",
    "runtime",
    "cache",
    "logs",
    "output",
    "backups",
    "reports",
    "evidence",
    "canary",
    "manifests",
    "control-plane",
    "activations",
    "foundations",
    "genesis",
    "handoff",
    "ledgers",
    "frozen-hooks",
    "tokens",
    "venv",
    ".venv",
    ".canary-homes",
)
_ALL_ALLOWED_INVENTORY_SCOPE = "<workspace-all-allowed>"
_CANDIDATE_RUNTIME_MARKERS = frozenset({".sitina-code-mode-v1"})
WORKTREE_DIGEST_SCHEMA = "CODE_MODE_WORKTREE_DIGEST_V1"

_DEFAULT_IDENTITY_PATHS = (
    "config/conversation_router.json",
    "config/true_multi_agent_policy.json",
    "config/code_mode_profile.json",
    "config/permissions.yaml",
    "core/sitina/conversation/router.py",
    "core/sitina/conversation/runtime.py",
    "core/sitina/orchestrator/true_multi_agent.py",
    "core/sitina/orchestrator/true_multi_agent_runtime.py",
    "core/sitina/orchestrator/execution_bridge.py",
    "core/sitina/orchestrator/execution_verification.py",
    "core/sitina/extensions/runtime.py",
    "core/sitina/extensions/tools.py",
    "core/sitina/runners/tool_executor.py",
    "core/sitina/orchestrator/code_mode_gate.py",
    "core/sitina/orchestrator/code_mode_authority_broker.py",
    "core/sitina/orchestrator/code_mode_controller.py",
    "core/sitina/orchestrator/code_mode_runtime.py",
    "core/sitina/orchestrator/code_mode_reviewer.py",
    "core/sitina/orchestrator/production_identity.py",
    "scripts/code_mode_authority_host.py",
    "scripts/code_mode_reviewer_host.py",
    "scripts/code_mode_runner.py",
    "scripts/code_mode_worker.py",
    "tests/code_mode_host_fixture.py",
    "tests/code_mode_reviewer_fixture.py",
    "tests/test_code_mode_gate.py",
    "tests/test_code_mode_host_boundary.py",
    "tests/test_code_mode_runtime_integration.py",
    "tests/test_code_mode_worker_boundary.py",
)
_DEFAULT_TESTS = (
    "tests/test_true_multi_agent_cli_routing.py",
    "tests/test_execution_bridge.py",
    "tests/test_execution_bridge_integration.py",
    "tests/test_extensions.py",
    "tests/test_execution_target_v2.py",
    "tests/test_managed_processes.py",
    "tests/test_shell_mutation_guard.py",
    "tests/test_true_multi_agent_provider_transport.py",
)

_FILE_MUTATION_MARKERS = (
    ("create", "create"), ("new file", "create"), ("fix", "modify"),
    ("refactor", "modify"), ("implement", "modify"), ("write", "modify"),
    ("update", "modify"), ("change", "modify"), ("modify", "modify"),
    ("append", "append"), ("add", "append"), ("edit", "modify"),
    ("remove", "delete"), ("delete", "delete"), ("rename", "rename"),
    ("move", "rename"), ("install", "install"), ("build", "build"),
    ("创建", "create"), ("新建", "create"), ("修改", "modify"),
    ("修复", "modify"), ("重构", "modify"), ("实现", "modify"),
    ("写", "modify"), ("更新", "modify"), ("改", "modify"),
    ("追加", "append"), ("添加", "append"), ("删除", "delete"),
    ("移除", "delete"), ("重命名", "rename"), ("移动", "rename"),
    ("安装", "install"), ("构建", "build"),
)
_EXTERNAL_ACTION_MARKERS = (
    "commit", "push", "deploy", "publish", "release", "send", "提交", "推送", "部署", "发布", "发送",
)
_NEGATION = re.compile(
    r"(?:\bdo\s+not\b|\bdon't\b|\bnever\b|\bwithout\b|\bno\b|不要|勿|禁止|无需|不(?:要|得|能|再)?)(?:[^,.;!?，。！？；]{0,48})$",
    re.IGNORECASE,
)


def _is_negated(message: str, start: int) -> bool:
    prefix = message[max(0, start - 64):start]
    return bool(_NEGATION.search(prefix))


def classify_code_mode_intent(message: str) -> dict[str, Any]:
    """Classify explicit intent without turning negated constraints into writes.

    This is a routing/permission fact only.  It does not approve a tool call,
    create a candidate, or imply that a Reviewer has accepted a result.
    """

    text = str(message or "")
    folded = text.casefold()
    operations: list[str] = []
    negated: list[str] = []
    for marker, operation in _FILE_MUTATION_MARKERS:
        cursor = 0
        needle = marker.casefold()
        while True:
            found = folded.find(needle, cursor)
            if found < 0:
                break
            if _is_negated(text, found):
                negated.append(operation)
            else:
                operations.append(operation)
            cursor = found + max(1, len(needle))
    external_actions: list[str] = []
    for marker in _EXTERNAL_ACTION_MARKERS:
        cursor = 0
        while True:
            found = folded.find(marker.casefold(), cursor)
            if found < 0:
                break
            if not _is_negated(text, found):
                external_actions.append(marker)
            cursor = found + len(marker)
    return {
        "schema": "CODE_MODE_INTENT_V1",
        "operations": sorted(set(operations)),
        "negated_operations": sorted(set(negated)),
        "external_actions": sorted(set(external_actions)),
        "explicit_mutation": bool(operations),
        "explicit_external_action": bool(external_actions),
        "intent_hash": _hash_bytes(text.encode("utf-8")),
    }


@dataclass(frozen=True)
class CodeModeRuntimePolicy:
    """Small pre-tool policy for Code Mode; no artifact or activation input."""

    production_home: Path = Path("/Users/moss/SitinaHub")

    def __post_init__(self) -> None:
        # An authorization is a live, in-process capability.  The serialized
        # mapping is useful for the run record, but a caller cannot mint one
        # merely by copying ``allowed``/``intent_authorized`` fields.
        object.__setattr__(self, "_issued_authorizations", {})

    def authorize(
        self,
        *,
        mode: str,
        message: str,
        session_id: str,
        workspace: Path,
        access_mode: str = "workspace",
    ) -> dict[str, Any]:
        intent = classify_code_mode_intent(message)
        raw_target = Path(workspace).expanduser()
        if raw_target.is_symlink():
            target = raw_target.resolve(strict=False)
        else:
            target = raw_target.resolve(strict=True)
        root = self.production_home.expanduser().resolve(strict=False)
        reasons: list[str] = []
        if target == root and intent["explicit_mutation"]:
            reasons.append("Code Mode cannot mutate the frozen Production home")
        if raw_target.is_symlink() or not target.is_dir():
            reasons.append("selected workspace must be a non-symlink directory")
        if not str(session_id).strip():
            reasons.append("Code Mode mutation requires a current session")
        if access_mode not in {"workspace", "full"}:
            reasons.append("unknown access mode")
        if str(mode).upper() == "FAST" and intent["explicit_mutation"]:
            reasons.append("FAST is read-only; use /multi for code changes")
        token = secrets.token_urlsafe(32)
        authorization_ref = "code-mode-authorization:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        authorization = {
            "schema": "CODE_MODE_RUNTIME_AUTHORIZATION_V1",
            "mode": str(mode).upper(),
            "session_id": str(session_id),
            "authorization_ref": authorization_ref,
            "workspace": str(target),
            "access_mode": access_mode,
            "intent": intent,
            "intent_authorized": not reasons and intent["explicit_mutation"],
            "read_only": not intent["explicit_mutation"],
            "allowed": not reasons,
            "external_action_confirmation_required": bool(intent["explicit_external_action"]),
            "reasons": reasons,
        }
        issued_at = int(time.time())
        issued = {
            **authorization,
            "authorization_token": token,
            "issued_at": issued_at,
            "expires_at": issued_at + 900,
        }
        # Keep the complete issuance, including the immutable lifetime, in
        # the trusted in-process issuer.  Storing only the semantic mapping
        # allowed a caller to extend ``expires_at`` on the serialized copy.
        self._issued_authorizations[token] = dict(issued)
        return dict(issued)

    def validate_issued_authorization(
        self,
        binding: Mapping[str, Any],
        *,
        mode: str,
        message: str,
        session_id: str,
        workspace: Path,
        now: int | None = None,
    ) -> bool:
        """Validate an authorization issued by this live runtime instance."""

        token = binding.get("authorization_token")
        if not isinstance(token, str) or not token:
            return False
        issued = self._issued_authorizations.get(token)
        if not isinstance(issued, Mapping):
            return False
        moment = int(time.time()) if now is None else int(now)
        try:
            if int(binding.get("issued_at") or 0) != int(issued.get("issued_at") or 0):
                return False
            if int(binding.get("expires_at") or 0) != int(issued.get("expires_at") or 0):
                return False
            if int(issued.get("expires_at") or 0) <= moment:
                return False
            if int(issued.get("issued_at") or 0) > moment:
                return False
        except (TypeError, ValueError):
            return False
        expected_intent = classify_code_mode_intent(message)
        expected = {
            "schema": "CODE_MODE_RUNTIME_AUTHORIZATION_V1",
            "mode": str(mode).upper(),
            "session_id": str(session_id),
            "workspace": str(Path(workspace).expanduser().resolve(strict=True)),
            "access_mode": binding.get("access_mode"),
            "intent": expected_intent,
            "intent_authorized": True,
            "read_only": False,
            "allowed": True,
            "external_action_confirmation_required": bool(expected_intent["explicit_external_action"]),
            "reasons": [],
        }
        return (
            all(issued.get(key) == expected[key] for key in expected)
            and all(binding.get(key) == issued.get(key) for key in expected)
            and dict(binding).get("intent") == expected_intent
            and bool(binding.get("allowed"))
        )


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _hash_value(value: Any) -> str:
    return _hash_bytes(_canonical(value))


def _production_sentinel_digest(
    root: Path,
    *,
    identity_roots: Sequence[str] = DEFAULT_IDENTITY_ROOTS,
    runtime_excluded_roots: Sequence[str] = DEFAULT_RUNTIME_EXCLUDED_ROOTS,
) -> str:
    """Return the digest of the fixed, bounded production identity manifest."""
    try:
        return production_identity_digest(
            Path(root),
            identity_roots=identity_roots,
            runtime_excluded_roots=runtime_excluded_roots,
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError("production identity manifest could not be independently observed") from error


def _regular_hash(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return "sha256:" + digest.hexdigest()


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError(f"candidate path escapes workspace: {path}") from error


def _object_record(root: Path, path: Path) -> dict[str, Any]:
    relative = _relative(root, path)
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        return {
            "path": relative,
            "kind": "symlink",
            "mode": mode,
            "target_hash": _hash_bytes(os.fsencode(target)),
        }
    if stat.S_ISREG(info.st_mode):
        return {"path": relative, "kind": "file", "mode": mode, "sha256": _regular_hash(path)}
    if stat.S_ISDIR(info.st_mode):
        return {"path": relative, "kind": "directory", "mode": mode}
    if stat.S_ISBLK(info.st_mode):
        kind = "block"
    elif stat.S_ISCHR(info.st_mode):
        kind = "character"
    elif stat.S_ISFIFO(info.st_mode):
        kind = "fifo"
    elif stat.S_ISSOCK(info.st_mode):
        kind = "socket"
    else:
        kind = "special"
    return {"path": relative, "kind": kind, "mode": mode}


def _safe_relative_root(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("candidate source root must be relative")
    return path.as_posix()


def _validate_identity_path(value: str) -> str:
    """Accept only current source identity paths, never runtime evidence."""
    relative = _safe_relative_root(value)
    parts = Path(relative).parts
    # Exclusions are workspace-root policy, not basename policy.  In
    # particular ``core/sitina/journal`` and ``core/sitina/cas`` are source
    # identities and must not be confused with the top-level runtime roots.
    if parts and parts[0] in _DEFAULT_CANDIDATE_EXCLUDED_ROOTS:
        raise ValueError("candidate identity path points into an excluded runtime root")
    if not any(relative == root or relative.startswith(root + "/") for root in _DEFAULT_CANDIDATE_SOURCE_ROOTS if "/" not in root or relative.startswith(root + "/")):
        raise ValueError("candidate identity path is outside the source inventory")
    return relative


def _filesystem_inventory(
    root: Path,
    *,
    source_roots: Sequence[str] = _DEFAULT_CANDIDATE_SOURCE_ROOTS,
    excluded_roots: Sequence[str] = _DEFAULT_CANDIDATE_EXCLUDED_ROOTS,
    all_allowed: bool = False,
) -> list[dict[str, Any]]:
    """Inventory allowed workspace objects without following symlinks.

    Runtime outputs and evidence are deliberately outside the candidate
    identity.  ``all_allowed`` is used only for a post-execution candidate;
    its explicit exclusion specification is still part of the manifest so a
    verifier cannot silently broaden the inventory.  Baseline candidates keep
    the narrower configured source-root inventory.
    """
    records: list[dict[str, Any]] = []
    excluded = {_safe_relative_root(str(item)) for item in excluded_roots}
    starts = (root,) if all_allowed else tuple(
        root / source for source in sorted({_safe_relative_root(str(item)) for item in source_roots})
    )
    for start in starts:
        source = _relative(root, start) if start != root else None
        if source is not None:
            if not start.exists() and not start.is_symlink():
                records.append({"path": source, "kind": "absent"})
                continue
        elif not start.exists():
            raise ValueError("candidate workspace disappeared during inventory")
        if start.is_symlink() or not start.is_dir():
            records.append(_object_record(root, start))
            continue
        for current, directory_names, file_names in os.walk(start, followlinks=False):
            current_path = Path(current)
            relative_current = _relative(root, current_path)
            directory_names[:] = sorted(
                name for name in directory_names
                if not (
                    name in {".git", "__pycache__"}
                    or (
                        relative_current == "."
                        and name in excluded
                    )
                )
            )
            for name in sorted(file_names):
                path = current_path / name
                relative = _relative(root, path)
                if path.suffix == ".pyc" or path.name == ".DS_Store":
                    continue
                first_component = Path(relative).parts[0] if Path(relative).parts else ""
                if first_component in excluded:
                    continue
                records.append(_object_record(root, path))
            for name in list(directory_names):
                path = current_path / name
                if path.is_symlink():
                    records.append(_object_record(root, path))
    return sorted(records, key=lambda item: (item["path"], item["kind"]))


def _worktree_digest(
    *,
    git_head: str | None,
    git_status: Sequence[Mapping[str, Any]],
    git_metadata: Mapping[str, Any],
    objects: Sequence[Mapping[str, Any]],
    identity_files: Sequence[Mapping[str, Any]],
    changed_paths: Sequence[str],
) -> str:
    return _hash_value({
        "schema": WORKTREE_DIGEST_SCHEMA,
        "git_head": git_head,
        "git_status": list(git_status),
        "git_metadata": dict(git_metadata),
        "objects": list(objects),
        "identity_files": list(identity_files),
        "changed_paths": list(changed_paths),
    })


def _git_status(root: Path) -> tuple[list[dict[str, Any]], str | None, bool]:
    if not (root / ".git").exists():
        return [], None, True
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        raw = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all", "-z"],
            check=True, capture_output=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError, RuntimeError):
        # The Legacy frozen audit hook may deny subprocess creation.  Code
        # Mode must remain runnable for local permission/tool checks, but a
        # candidate without a complete Git identity can never become ready.
        return [{"code": "GIT_IDENTITY_UNAVAILABLE"}], None, False
    tokens = raw.split(b"\0")
    status: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if not token:
            continue
        decoded = os.fsdecode(token)
        code = decoded[:2]
        value = decoded[3:] if len(decoded) >= 4 else ""
        item: dict[str, Any] = {"code": code, "path": value}
        if "R" in code or "C" in code:
            if index >= len(tokens) or not tokens[index]:
                raise ValueError("malformed git rename/copy status")
            item["destination"] = os.fsdecode(tokens[index])
            index += 1
        paths = [str(item.get("path") or "")]
        if isinstance(item.get("destination"), str):
            paths.append(str(item["destination"]))
        def is_runtime_path(value: str) -> bool:
            parts = Path(value).parts
            return bool(parts) and (
                parts[0] in _DEFAULT_CANDIDATE_EXCLUDED_ROOTS
                or value in _CANDIDATE_RUNTIME_MARKERS
                or parts[0] in _CANDIDATE_RUNTIME_MARKERS
            )
        if not any(is_runtime_path(value) for value in paths):
            status.append(item)
    return status, head, True


def _git_metadata(root: Path) -> tuple[dict[str, str], bool]:
    """Hash Git identity inputs that can drift without changing the tree.

    The candidate manifest keeps only digests, never raw Git output or absolute
    paths.  Detached and symbolic HEAD are both represented; a failed probe is
    incomplete rather than silently treated as a frozen candidate.
    """

    if not (root / ".git").exists():
        return {"repository": "non_git_workspace"}, True
    probes = (
        ("git_dir", ["rev-parse", "--git-dir"]),
        ("common_dir", ["rev-parse", "--git-common-dir"]),
        ("head_ref", ["rev-parse", "--symbolic-full-name", "HEAD"]),
        ("index", ["ls-files", "--stage", "-z"]),
        ("refs", ["show-ref", "--head"]),
    )
    metadata: dict[str, str] = {}
    try:
        for name, command in probes:
            completed = subprocess.run(
                ["git", "-C", str(root), *command],
                check=False,
                capture_output=True,
                timeout=10,
            )
            # An empty repository has no refs, and detached HEAD has no
            # symbolic name; both remain valid only when the other identity
            # probes succeed.
            if completed.returncode not in {0, 1} or (
                completed.returncode == 1 and name not in {"head_ref", "refs"}
            ):
                return {"error": "GIT_METADATA_PROBE_FAILED"}, False
            metadata[name + "_sha256"] = hashlib.sha256(completed.stdout).hexdigest()
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return {"error": "GIT_METADATA_UNAVAILABLE"}, False
    return metadata, True


def _identity_files(root: Path, paths: Iterable[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for relative in sorted({_validate_identity_path(str(item)) for item in paths}):
        path = root / relative
        if path.is_symlink():
            result.append({"path": relative, "kind": "symlink", "target_hash": _hash_bytes(os.fsencode(os.readlink(path)))})
        elif path.is_file():
            result.append({"path": relative, "kind": "file", "sha256": _regular_hash(path)})
        else:
            result.append({"path": relative, "kind": "absent"})
    return result


def _allowed_changed_path(root: Path, value: str) -> str:
    """Normalize a patch path and enforce the candidate exclusion boundary."""

    raw = Path(str(value)).expanduser()
    if raw.is_absolute():
        try:
            relative = raw.resolve(strict=False).relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError("candidate changed path escapes the workspace") from error
    else:
        relative = raw.as_posix()
    if not relative or relative == "." or ".." in Path(relative).parts:
        raise ValueError("candidate changed path is invalid")
    if Path(relative).parts and Path(relative).parts[0] in _DEFAULT_CANDIDATE_EXCLUDED_ROOTS:
        raise ValueError("candidate changed path points into an excluded runtime root")
    return relative


def build_candidate_manifest(
    workspace: Path,
    *,
    identity_paths: Sequence[str] | None = _DEFAULT_IDENTITY_PATHS,
    changed_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Freeze a complete candidate identity; this does not write anything."""

    root = Path(workspace).expanduser().resolve(strict=True)
    if root == Path("/Users/moss/SitinaHub"):
        raise ValueError("Code Mode candidate cannot be the frozen Production home")
    if not root.is_dir():
        raise ValueError("Code Mode candidate must be a directory")
    status, head, git_identity_complete = _git_status(root)
    git_metadata, metadata_complete = _git_metadata(root)
    git_identity_complete = git_identity_complete and metadata_complete
    if not metadata_complete:
        status = [*status, {"code": str(git_metadata.get("error") or "GIT_METADATA_INCOMPLETE")}]
    all_allowed = identity_paths is None
    normalized_changed_paths = sorted(
        {_allowed_changed_path(root, str(item)) for item in changed_paths}
    )
    if all_allowed:
        objects = _filesystem_inventory(root, all_allowed=True)
        # For an output candidate the complete allowed inventory is the
        # identity inventory.  This intentionally does not reuse the
        # baseline's fixed identity-file list.
        identity_files = [dict(item) for item in objects]
        candidate_source_roots = [_ALL_ALLOWED_INVENTORY_SCOPE]
    else:
        identity_files = _identity_files(root, identity_paths)
        objects = _filesystem_inventory(root)
        candidate_source_roots = list(_DEFAULT_CANDIDATE_SOURCE_ROOTS)
    object_paths = {str(item.get("path")) for item in objects if isinstance(item, Mapping)}
    changed_path_records = [
        {"path": path, "kind": "present" if path in object_paths else "deleted"}
        for path in normalized_changed_paths
    ]
    worktree_digest = _worktree_digest(
        git_head=head,
        git_status=status,
        git_metadata=git_metadata,
        objects=objects,
        identity_files=identity_files,
        changed_paths=normalized_changed_paths,
    )
    source_manifest_hash = _hash_value({
        "source_roots": candidate_source_roots,
        "identity_files": identity_files,
        "changed_paths": normalized_changed_paths,
    })
    body = {
        "schema": "CODE_MODE_CANDIDATE_MANIFEST_V1",
        "workspace": str(root),
        "git_head": head,
        "git_status": status,
        "git_identity_complete": git_identity_complete,
        "git_metadata": git_metadata,
        "candidate_source_roots": candidate_source_roots,
        "candidate_excluded_roots": list(_DEFAULT_CANDIDATE_EXCLUDED_ROOTS),
        "candidate_inventory_scope": (
            _ALL_ALLOWED_INVENTORY_SCOPE if all_allowed else "explicit-source-roots"
        ),
        "objects": objects,
        "identity_files": identity_files,
        "changed_paths": normalized_changed_paths,
        "changed_path_records": changed_path_records,
        "source_manifest_hash": source_manifest_hash,
        "worktree_digest": worktree_digest,
    }
    return body | {
        "tree_hash": _hash_value(objects),
        "candidate_id": _hash_value(body),
    }


def verify_candidate_manifest(workspace: Path, manifest: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Recompute the frozen identity and reject candidate drift."""

    try:
        all_allowed = manifest.get("candidate_inventory_scope") == _ALL_ALLOWED_INVENTORY_SCOPE
        if all_allowed:
            identity_paths = None
        else:
            identity_paths = tuple(
                _validate_identity_path(str(item["path"]))
                for item in (manifest.get("identity_files") or [])
                if isinstance(item, Mapping) and isinstance(item.get("path"), str)
            )
            if not identity_paths:
                raise ValueError("candidate identity inventory is missing")
        current = build_candidate_manifest(
            workspace,
            identity_paths=identity_paths,
            changed_paths=tuple(
                str(item) for item in (manifest.get("changed_paths") or ())
                if isinstance(item, str)
            ),
        )
    except (OSError, ValueError) as error:
        return False, [str(error)]
    errors: list[str] = []
    for field in ("workspace", "git_head", "git_status", "git_identity_complete", "git_metadata", "candidate_source_roots", "candidate_excluded_roots", "candidate_inventory_scope", "objects", "identity_files", "changed_paths", "changed_path_records", "source_manifest_hash", "worktree_digest", "tree_hash", "candidate_id"):
        if current.get(field) != manifest.get(field):
            errors.append(f"candidate {field} drifted")
    changed_records = manifest.get("changed_path_records")
    if not isinstance(changed_records, list):
        errors.append("candidate changed-path closure is missing")
    else:
        object_paths = {
            str(item.get("path"))
            for item in (manifest.get("objects") or ())
            if isinstance(item, Mapping)
        }
        record_paths = {
            str(item.get("path")): item.get("kind")
            for item in changed_records
            if isinstance(item, Mapping) and isinstance(item.get("path"), str)
        }
        for path in (manifest.get("changed_paths") or ()):
            if not isinstance(path, str) or path not in record_paths:
                errors.append("candidate changed-path closure is incomplete")
                break
            if path in object_paths and record_paths[path] != "present":
                errors.append("candidate changed-path presence is inconsistent")
                break
            if path not in object_paths and record_paths[path] != "deleted":
                errors.append("candidate changed-path tombstone is inconsistent")
                break
    if manifest.get("git_identity_complete") is not True:
        errors.append("candidate Git identity is incomplete")
    return not errors, errors


def load_code_mode_profile(workspace: Path) -> dict[str, Any]:
    path = Path(workspace) / "config" / "code_mode_profile.json"
    if not path.is_file() or path.is_symlink():
        provider_profile = "configured-provider"
        provider_model = "configured-model"
        policy_path = Path(workspace) / "config" / "true_multi_agent_policy.json"
        if policy_path.is_file() and not policy_path.is_symlink():
            try:
                policy = json.loads(policy_path.read_text(encoding="utf-8"))
                provider_profile = str(policy.get("provider_profile") or provider_profile)
                allowlist = policy.get("provider_model_allowlist")
                if isinstance(allowlist, list) and len(allowlist) == 1 and isinstance(allowlist[0], str) and allowlist[0]:
                    provider_model = allowlist[0]
            except (OSError, json.JSONDecodeError):
                pass
        return {
            "schema": PROFILE_SCHEMA,
            "provider": {"profile": provider_profile, "model": provider_model, "no_fallback": True},
            "evidence_schema": EVIDENCE_SCHEMA,
            "identity_paths": list(_DEFAULT_IDENTITY_PATHS),
            "test_inventory": list(_DEFAULT_TESTS),
        }
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != PROFILE_SCHEMA:
        raise ValueError("invalid Code Mode profile")
    return value


def _passed_tests(test_result: Mapping[str, Any], inventory: Sequence[str]) -> bool:
    # Test evidence is an attestation input, not a convenience summary.  Empty
    # IDs or an omitted return code must never turn an otherwise self-reported
    # PASS into acceptance.
    ids = test_result.get("test_ids")
    if not isinstance(ids, Sequence) or isinstance(ids, (str, bytes)) or not ids:
        return False
    actual_ids = {str(item) for item in ids}
    if not actual_ids:
        return False
    return_code = test_result.get("return_code")
    if not isinstance(return_code, int) or isinstance(return_code, bool):
        return False
    expected = set(inventory)
    try:
        failures = tuple(int(test_result.get(field, 0) or 0) for field in ("failures", "errors", "skipped", "unexpected_successes"))
    except (TypeError, ValueError):
        return False
    return (
        test_result.get("passed") is True
        or test_result.get("status") in {"passed", "PASS", "OK"}
    ) and return_code == 0 and not any(failures) and expected <= actual_ids


def _reopen_offline_receipt(
    runtime_context: Any,
    locator: Mapping[str, Any] | None,
    *,
    schema: str,
    candidate: Mapping[str, Any],
    accepted_at: int | None = None,
) -> dict[str, Any]:
    """Reopen a runtime-owned CAS receipt; caller mappings are locators only."""
    if runtime_context is None or not isinstance(locator, Mapping):
        raise ValueError("trusted offline receipt locator is missing")
    reference_id = locator.get("reference_id")
    if not isinstance(reference_id, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", reference_id):
        raise ValueError("offline receipt reference is not a durable CAS reference")
    if not isinstance(locator.get("content_hash"), str) or locator.get("content_hash") != locator.get("receipt_hash"):
        raise ValueError("offline receipt locator hash binding is incomplete")
    try:
        from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
        from sitina.journal.model import parse_canonical_json
        if not isinstance(runtime_context, CodeModeRuntimeContext):
            raise ValueError("offline receipt requires a Code Mode runtime context")
        cas = runtime_context.open_cas_reader()
        object_ref = cas.resolve_reference(reference_id)
        published = cas.verify_existing(object_ref)
        if not published.fresh_verified or not published.no_replace_published:
            raise ValueError("offline receipt CAS proof is not fresh and no-replace")
        value = parse_canonical_json(cas.open_verified(object_ref))
    except Exception as error:
        raise ValueError("offline receipt could not be reopened") from error
    if not isinstance(value, Mapping) or value.get("schema") != schema:
        raise ValueError("offline receipt schema is invalid")
    if schema == "CODE_MODE_MACHINE_CHECK_RECEIPT_V1":
        if value.get("issuer_identity") != "code-mode-offline-runtime-v1" or value.get("authority_class") != "OFFLINE_NON_AUTHORITATIVE":
            raise ValueError("machine check producer identity is invalid")
        if (
            not isinstance(value.get("session_id"), str) or not value.get("session_id")
            or not isinstance(value.get("generation"), str)
            or not value.get("generation")
            or not isinstance(value.get("verifier_identity"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["verifier_identity"])
            or not all(
                isinstance(value.get(field), str) and re.fullmatch(r"[0-9a-f]{64}", value[field])
                for field in ("worktree_before_hash", "worktree_after_hash", "diff_hash")
            )
        ):
            raise ValueError("machine check lacks current execution binding")
    elif schema == "CODE_MODE_REVIEW_RECEIPT_V2":
        tty_authority = value.get("authority_class") == "TTY_REVIEW_AUTHORITY"
        if tty_authority:
            verifier = getattr(runtime_context, "_verify_tty_review_receipt", None)
            if not callable(verifier) or verifier(value) is not True:
                raise ValueError("TTY reviewer receipt nonce consumption is not trusted")
            if value.get("issuer_identity") != "code-mode-tty-authority":
                raise ValueError("TTY reviewer receipt issuer identity is invalid")
            if not isinstance(value.get("reviewer_session_id"), str) or not value.get("reviewer_session_id"):
                raise ValueError("TTY reviewer session binding is missing")
        else:
            if value.get("authority_class") != "INDEPENDENT_REVIEWER_AUTHORITY":
                raise ValueError("offline reviewer receipt producer identity is invalid")
            if value.get("issuer_identity") in (None, "", "code-mode-offline-runtime-v1"):
                raise ValueError("offline reviewer receipt is not independently issued")
            verifier = getattr(runtime_context, "_verify_offline_reviewer_receipt", None)
            if not callable(verifier) or verifier(value) is not True:
                raise ValueError("offline reviewer receipt issuer proof is not trusted")
            if value.get("reviewer_session_id") != value.get("issuer_id"):
                raise ValueError("offline reviewer session is not bound to its issuer")
            producer_id = value.get("producer_issuer_id")
            producer_key = value.get("producer_public_key")
            producer_signature = value.get("producer_signature")
            if (
                not isinstance(producer_id, str) or not producer_id
                or producer_id in {value.get("issuer_id"), value.get("reviewer_session_id")}
                or not isinstance(producer_key, str) or not re.fullmatch(r"[0-9a-f]{64}", producer_key)
                or not isinstance(producer_signature, str) or not re.fullmatch(r"[0-9a-f]{128}", producer_signature)
            ):
                raise ValueError("offline reviewer receipt lacks an independent producer proof")
        if value.get("verdict_decision") not in {"ACCEPT", "REJECT"}:
            raise ValueError("offline reviewer verdict decision is missing")
        if value.get("decision") not in {"ACCEPT", "REJECT"} or value.get("decision") != value.get("verdict_decision"):
            raise ValueError("review V2 receipt decision is not derived from its verdict")
        if not isinstance(value.get("review_evidence_hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["review_evidence_hash"]):
            raise ValueError("offline reviewer evidence hash is missing")
        if value.get("severity") not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"} or not isinstance(value.get("findings"), list):
            raise ValueError("offline reviewer findings are invalid")
        request_ref = value.get("review_request_ref")
        request_hash = value.get("review_request_hash")
        reopen_request = getattr(runtime_context, "_reopen_offline_review_request", None)
        if (
            not isinstance(request_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", request_ref)
            or not isinstance(request_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", request_hash)
            or not callable(reopen_request)
        ):
            raise ValueError("Review V2 receipt lacks a durable review request")
        try:
            request = reopen_request(
                candidate=candidate,
                request={"schema": "CODE_MODE_REVIEW_REQUEST_V2", "reference_id": request_ref, "content_hash": request_hash},
            )
        except Exception as error:
            raise ValueError("Review V2 request could not be reopened") from error
        if (
            request.get("machine_check_hash") != value.get("test_receipt_hash")
            or request.get("run_id") != value.get("run_id")
            or request.get("candidate_id") != value.get("candidate_id")
            or request.get("tree_hash") != value.get("tree_hash")
        ):
            raise ValueError("Review V2 receipt is not bound to its current request")
    else:
        raise ValueError("offline receipt schema is not supported")
    body = {key: item for key, item in value.items() if key != "content_hash"}
    if value.get("content_hash") != hashlib.sha256(_canonical(body)).hexdigest():
        raise ValueError("offline receipt content hash mismatch")
    if value.get("content_hash") != locator.get("content_hash"):
        raise ValueError("offline receipt locator does not match CAS content")
    if locator.get("object_hash") != object_ref.object_id:
        raise ValueError("offline receipt locator does not match CAS object identity")
    if value.get("content_hash") != payload_self_hash(value):
        raise ValueError("offline receipt payload self-hash is invalid")
    if value.get("candidate_id") != candidate.get("candidate_id") or value.get("tree_hash") != candidate.get("tree_hash"):
        raise ValueError("offline receipt candidate identity mismatch")
    if value.get("runtime_state_identity") != getattr(getattr(runtime_context, "identity", None), "state_identity", None):
        raise ValueError("offline receipt runtime identity mismatch")
    if value.get("runtime_journal_id") != getattr(getattr(runtime_context, "identity", None), "journal_id", None):
        raise ValueError("offline receipt Journal identity mismatch")
    expiry_ok = (
        type(value.get("expires_at")) is int
        and value["expires_at"] > int(time.time())
    )
    if not expiry_ok and not (
        schema == "CODE_MODE_REVIEW_RECEIPT_V2"
        and type(accepted_at) is int
        and accepted_at > 0
        and type(value.get("expires_at")) is int
        and accepted_at <= value["expires_at"]
    ):
        raise ValueError("offline receipt is expired")
    run_id = value.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("offline receipt run binding is missing")
    # CAS content must also have a typed, authenticated same-run Journal fact.
    # A caller-supplied locator or a second self-created CAS cannot manufacture
    # this producer event after the fact.
    try:
        journal = runtime_context.open_runtime_state_reader()
        try:
            fact_events = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1"
                and event.payload.get("reference_id") == reference_id
                and event.payload.get("content_hash") == value.get("content_hash")
                and event.payload.get("evidence_schema") == schema
                and event.payload.get("candidate_id") == value.get("candidate_id")
                and event.payload.get("tree_hash") == value.get("tree_hash")
                and event.payload.get("run_id") == run_id
                and event.payload.get("closing_root") is (value.get("closing_root") is True)
            ]
        finally:
            journal.close()
    except Exception as error:
        raise ValueError("offline receipt Journal fact could not be reopened") from error
    if len(fact_events) != 1:
        raise ValueError("offline receipt has no unique same-run Journal fact")
    journal_event_hash = locator.get("journal_event_hash")
    if not isinstance(journal_event_hash, str) or fact_events[0].event_hash != journal_event_hash:
        raise ValueError("offline receipt Journal closing root does not match the producer event")
    reopened = dict(value)
    reopened["reference_id"] = reference_id
    reopened["object_hash"] = object_ref.object_id
    reopened["payload_hash"] = str(value.get("content_hash"))
    reopened["plaintext_commitment"] = object_ref.plaintext_commitment
    return reopened


@dataclass(frozen=True)
class CodeModeAcceptanceV1:
    """Post-batch acceptance checks, never a pre-tool execution gate."""
    workspace: Path
    profile: Mapping[str, Any] | None = None
    production_sentinel: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        root = Path(self.workspace).expanduser().resolve(strict=True)
        object.__setattr__(self, "workspace", root)
        object.__setattr__(self, "profile", dict(self.profile or load_code_mode_profile(root)))

    def freeze_candidate(self) -> dict[str, Any]:
        profile = dict(self.profile or {})
        paths = tuple(str(item) for item in profile.get("identity_paths", _DEFAULT_IDENTITY_PATHS))
        return build_candidate_manifest(self.workspace, identity_paths=paths)

    def evaluate_offline(
        self,
        candidate: Mapping[str, Any],
        *,
        test_result: Mapping[str, Any] | None = None,
        reviewer: Mapping[str, Any] | None = None,
        test_inventory: Sequence[str] | None = None,
        runtime_context: Any | None = None,
        test_receipt: Mapping[str, Any] | None = None,
        reviewer_receipt: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        inventory = tuple(test_inventory or self.profile.get("test_inventory", _DEFAULT_TESTS))
        valid_candidate, drift = verify_candidate_manifest(self.workspace, candidate)
        trusted_test: dict[str, Any] | None = None
        trusted_review: dict[str, Any] | None = None
        receipt_reasons: list[str] = []
        try:
            trusted_test = _reopen_offline_receipt(
                runtime_context, test_receipt,
                schema="CODE_MODE_MACHINE_CHECK_RECEIPT_V1", candidate=candidate,
            )
            trusted_review = _reopen_offline_receipt(
                runtime_context, reviewer_receipt,
                schema="CODE_MODE_REVIEW_RECEIPT_V2", candidate=candidate,
            )
            if trusted_review.get("test_receipt_hash") != trusted_test.get("content_hash"):
                raise ValueError("review receipt is not bound to the test receipt")
            if trusted_review.get("run_id") != trusted_test.get("run_id"):
                raise ValueError("review receipt is not bound to the test run")
            if trusted_review.get("issuer_identity") == trusted_test.get("issuer_identity"):
                raise ValueError("test and reviewer receipts share a producer")
        except ValueError as error:
            receipt_reasons.append(str(error))
        tests_ok = False
        if trusted_test is not None:
            actual_ids = trusted_test.get("test_ids")
            current_worktree_ok = False
            try:
                from sitina.orchestrator.code_mode_runtime import _workspace_observation_hash
                test_root = Path(str(trusted_test.get("cwd") or "")).expanduser().resolve(strict=True)
                test_root.relative_to(self.workspace)
                current_worktree_ok = (
                    _workspace_observation_hash(test_root)
                    == trusted_test.get("workspace_observation_after_hash")
                )
            except Exception:
                current_worktree_ok = False
            expected_worktree_delta_hash = hashlib.sha256(_canonical({
                "before": trusted_test.get("worktree_before_hash"),
                "after": trusted_test.get("worktree_after_hash"),
            })).hexdigest()
            tests_ok = (
            trusted_test.get("schema") == "CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
                and trusted_test.get("status") == "MACHINE_CHECK_READY"
                and trusted_test.get("execution_observed") is True
                and isinstance(candidate.get("generation"), str)
                and trusted_test.get("generation") == candidate.get("generation")
                and trusted_test.get("source_manifest_hash") == candidate.get("source_manifest_hash")
                and trusted_test.get("candidate_worktree_digest") == candidate.get("worktree_digest")
                and trusted_test.get("command_hash") == hashlib.sha256(_canonical(trusted_test.get("command", []))).hexdigest()
                and trusted_test.get("inventory_hash") == hashlib.sha256(_canonical(list(inventory))).hexdigest()
                and trusted_test.get("test_inventory") == list(inventory)
                and isinstance(actual_ids, list) and actual_ids == list(inventory)
                and trusted_test.get("return_code") == 0
                and all(type(trusted_test.get(field)) is int and trusted_test.get(field) == 0 for field in ("failures", "errors", "skipped", "unexpected_successes"))
                and _SHA256.fullmatch(str(trusted_test.get("diff_hash") or ""))
                and trusted_test.get("worktree_delta_hash") == expected_worktree_delta_hash
                and current_worktree_ok
            )
        review_ready = bool(
            trusted_review is not None
            and trusted_review.get("decision") == "ACCEPT"
            and trusted_review.get("verdict_decision") == "ACCEPT"
            and trusted_review.get("severity") in {"NONE", "LOW"}
            and trusted_review.get("findings") == []
            and isinstance(trusted_review.get("reviewer_id"), str)
            and bool(trusted_review.get("reviewer_id"))
        )
        reasons = list(drift)
        if not tests_ok:
            reasons.append("offline test evidence receipt did not pass fail-closed")
        if not review_ready:
            reasons.append("trusted independent reviewer receipt is missing or invalid")
        reasons.extend(receipt_reasons)
        return {
            "schema": SCHEMA,
            "status": CODE_MODE_READY if valid_candidate and tests_ok and review_ready else CODE_MODE_BLOCKED,
            "legacy_bplus_status": LEGACY_STATUS,
            "legacy_foundation_consulted": False,
            "candidate_id": candidate.get("candidate_id"),
            "candidate_valid": valid_candidate,
            "candidate_drift": drift,
            "test_inventory": list(inventory),
            "tests_passed": tests_ok,
            "machine_check_status": trusted_test.get("status") if trusted_test else None,
            "review_status": trusted_review.get("decision") if trusted_review else None,
            "review_request_reopened": bool(trusted_review and trusted_review.get("review_request_ref")),
            "review_candidate_id": trusted_review.get("candidate_id") if trusted_review else None,
            "test_receipt": dict(test_receipt) if isinstance(test_receipt, Mapping) else None,
            "reviewer_receipt": dict(reviewer_receipt) if isinstance(reviewer_receipt, Mapping) else None,
            "trusted_receipts_reopened": trusted_test is not None and trusted_review is not None,
            "reasons": reasons,
            "provider_constraint": dict(self.profile.get("provider") or {}),
            "evidence_schema": self.profile.get("evidence_schema", EVIDENCE_SCHEMA),
        }

    def issue_canary_authorization(
        self,
        *,
        candidate: Mapping[str, Any],
        offline_gate: Mapping[str, Any],
        session_id: str,
        run_id: str,
        selected_workspace: Path,
        runtime_context: Any | None = None,
        offline_activation: bool = False,
        provider_override: Any | None = None,
        controller_session: Any | None = None,
        live_capability: Any | None = None,
    ) -> dict[str, Any]:
        if runtime_context is None:
            raise PermissionError("Code Mode canary authorization requires an issuer-bound runtime context")
        # Issuance is an operation of the active controller, not a convenience
        # method on a context.  A directly opened context can create offline
        # evidence, but it can never promote that evidence to a live canary.
        if controller_session is None or not callable(getattr(controller_session, "assert_canary_access", None)):
            raise PermissionError("Code Mode canary issuance requires the active controller session")
        if getattr(controller_session, "context", None) is not runtime_context:
            raise PermissionError("Code Mode canary controller/context mismatch")
        controller_session.assert_live()
        if not bool(getattr(controller_session, "authoritative", False)):
            raise PermissionError("offline Code Mode controller cannot issue a canary")
        if offline_activation or provider_override is not None:
            raise PermissionError("real Code Mode canary authorization cannot use offline or provider overrides")
        target = Path(selected_workspace).expanduser().resolve(strict=True)
        if offline_gate.get("status") != CODE_MODE_READY:
            raise PermissionError("Code Mode canary requires CODE_MODE_READY for the frozen candidate")
        if offline_gate.get("trusted_receipts_reopened") is not True or not isinstance(offline_gate.get("test_receipt"), Mapping) or not isinstance(offline_gate.get("reviewer_receipt"), Mapping):
            raise PermissionError("Code Mode canary requires re-opened trusted test and reviewer receipts")
        if offline_gate.get("candidate_id") != candidate.get("candidate_id"):
            raise PermissionError("canary authorization candidate binding mismatch")
        if not session_id.strip() or not run_id.strip():
            raise PermissionError("canary authorization requires session and run identities")
        # Before the broker signs the authorization, bind the exact tuple to
        # the controller that will later evaluate and consume it.
        controller_session.assert_canary_access(
            runtime_context,
            {
                "session_id": session_id,
                "session_instance_id": controller_session.session_instance_id,
                "run_id": run_id,
                "run_attempt": controller_session.run_attempt,
                "workspace": str(target),
            },
        )
        if target == Path("/Users/moss/SitinaHub") or not _is_within(target, self.workspace):
            raise PermissionError("canary workspace is outside the Code Mode candidate")
        provider = dict(self.profile.get("provider") or {})
        provider_profile = provider.get("profile")
        provider_model = provider.get("model")
        if (
            type(provider_profile) is not str or not provider_profile
            or type(provider_model) is not str or not provider_model
            or provider.get("no_fallback") is not True
        ):
            raise PermissionError("Code Mode canary requires a configured no-fallback provider profile")
        runtime_binding: dict[str, str] = {}
        try:
            from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
            if not isinstance(runtime_context, CodeModeRuntimeContext):
                raise PermissionError("canary runtime authority must be a Code Mode context")
            runtime_binding = runtime_context.canary_authority_binding()
            if runtime_binding.get("trust_scope") != "same-user-cli-parent-child-v1":
                raise PermissionError("Code Mode runtime trust scope is not the CLI local boundary")
        except Exception as error:
            raise PermissionError("canary runtime authority is not issuer-bound") from error
        def locator(value: object, label: str) -> str:
            if not isinstance(value, Mapping):
                raise PermissionError("canary requires a durable " + label + " locator")
            reference = value.get("reference_id")
            object_hash = str(value.get("object_hash") or "").removeprefix("sha256:")
            if (
                not isinstance(reference, str) or not reference.startswith("cas:")
                or not re.fullmatch(r"[0-9a-f]{64}", object_hash)
                or reference != "cas:" + object_hash
            ):
                raise PermissionError("canary " + label + " locator is not a verified CAS identity")
            return reference

        # A live permit is requested only with opaque addresses.  The host
        # reopens every object and derives candidate/run/attempt/time values;
        # no caller-built authorization body or scalar binding crosses this
        # boundary.
        candidate_locator = candidate.get("candidate_locator") or candidate.get("candidate_manifest_locator")
        package_locator = offline_gate.get("evidence_package_locator") or offline_gate.get("package_locator")
        core_locator = offline_gate.get("core_locator")
        request_locator = offline_gate.get("review_request_locator") or offline_gate.get("request_locator")
        review_locator = offline_gate.get("review_locator") or offline_gate.get("reviewer_receipt_locator")
        gate_locator = offline_gate.get("gate_locator")
        locator_request = {
            "schema": "CODE_MODE_CANARY_LOCATOR_REQUEST_V2",
            "run_locator": "run/" + run_id,
            "candidate_locator": locator(candidate_locator, "candidate"),
            "package_locator": locator(package_locator, "package"),
            "core_locator": locator(core_locator, "core"),
            "request_locator": locator(request_locator, "request"),
            "review_locator": locator(review_locator, "review"),
            "gate_locator": locator(gate_locator, "gate"),
        }
        if live_capability is None:
            capability_getter = getattr(controller_session, "live_capability_for_admission", None)
            if not callable(capability_getter):
                raise PermissionError("Code Mode canary requires a controller-owned live capability")
            live_capability = capability_getter()
        issuer = getattr(runtime_context, "issue_canary_authorization", None)
        if not callable(issuer):
            raise PermissionError(
                "Code Mode canary authorization requires the OS CodeModeAuthorityBroker"
            )
        authorization = issuer(locator_request, live_capability=live_capability)
        if not isinstance(authorization, Mapping):
            raise PermissionError("Code Mode broker returned an invalid canary authorization")
        runtime_context.register_canary_authorization(authorization)
        return dict(authorization)

    @staticmethod
    def _validate_journal_hash_closure(
        events: Sequence[Any],
        *,
        reference_id: str,
        journal_event_hashes: Any,
    ) -> Any:
        """Require a complete predecessor closure rooted by one final event."""

        versions = sorted(int(event.stream_version) for event in events)
        if not events or versions != list(range(1, max(versions) + 1)):
            raise ValueError("same-run Journal stream is absent or non-contiguous")
        roots = tuple(event for event in events if reference_id in tuple(event.object_refs))
        if len(roots) != 1:
            raise ValueError("run receipt must have exactly one Journal root event")
        root = roots[0]
        if int(root.stream_version) != max(versions):
            raise ValueError("run receipt Journal root must close the stream")
        if not isinstance(journal_event_hashes, list) or not journal_event_hashes:
            raise ValueError("run receipt Journal hash closure is incomplete")
        if len(journal_event_hashes) != len(set(journal_event_hashes)):
            raise ValueError("run receipt Journal hash closure contains duplicate events")
        predecessor_hashes = {
            str(event.event_hash) for event in events if event is not root
        }
        if set(journal_event_hashes) != predecessor_hashes or len(journal_event_hashes) != len(predecessor_hashes):
            raise ValueError("run receipt Journal hash closure is incomplete")
        return root

    @staticmethod
    def _related_run_events(events: Iterable[Any], run_id: Any) -> tuple[Any, ...]:
        """Select only authenticated-graph candidates for one Code Mode run.

        The Journal reader is shared by many runs.  A payload's run binding is
        required for task/effect/protocol streams; the main run and its Forge
        child streams have an explicit stream binding.  Callers must still
        verify event hashes before passing this result to fact validation.
        """
        bound_run = str(run_id or "")
        main_stream = f"run/{bound_run}"
        forge_prefix = f"run/forge-exec-{bound_run}-"
        selected: list[Any] = []
        for event in events:
            stream_id = str(getattr(event, "stream_id", ""))
            payload = getattr(event, "payload", None)
            payload_bound = isinstance(payload, Mapping) and payload.get("run_id") == run_id
            if stream_id == main_stream or stream_id.startswith(forge_prefix) or payload_bound:
                selected.append(event)
        return tuple(selected)

    @staticmethod
    def _validate_managed_process_cleanup_bindings(
        events: Sequence[Any],
        cleanup_observation: Any,
        *,
        cas: Any,
    ) -> None:
        """Verify every managed-process cleanup event and its CAS record.

        Multiple processes are valid.  Their receipt IDs are an ordered,
        exact list, and each referenced record is independently reopened from
        CAS; a count-only or set-based check would permit omission/reordering.
        """
        process_events = [
            event for event in events
            if isinstance(getattr(event, "payload", None), Mapping)
            and event.payload.get("event_type") == "autonomous.managed-process-cleanup"
        ]
        if not process_events:
            raise ValueError("Journal managed-process cleanup is missing")
        managed = cleanup_observation.get("managed_process") if isinstance(cleanup_observation, Mapping) else None
        process_cleanup_ids = managed.get("cleanup_event_ids") if isinstance(managed, Mapping) else None
        actual_ids = [str(event.event_id) for event in process_events]
        if not isinstance(process_cleanup_ids, list) or not process_cleanup_ids:
            raise ValueError("Journal managed-process cleanup IDs are missing")
        if [str(item) for item in process_cleanup_ids] != actual_ids:
            raise ValueError("Journal managed-process cleanup is not bound to the run receipt")
        if cas is None:
            raise ValueError("Journal managed-process cleanup has no verifiable CAS record")
        for process_event in process_events:
            process_ref = process_event.payload.get("record_ref")
            if not isinstance(process_ref, str):
                raise ValueError("Journal managed-process cleanup has no verifiable CAS record")
            try:
                process_record = json.loads(cas.open_verified(cas.resolve_reference(process_ref)).decode("utf-8"))
            except Exception as error:
                raise ValueError("Journal managed-process cleanup CAS record cannot be reopened") from error
            if not isinstance(process_record, Mapping) or process_record.get("event") != "managed_process_cleanup":
                raise ValueError("Journal managed-process cleanup CAS record is invalid")
            if not isinstance(process_record.get("payload"), Mapping) or process_record["payload"].get("failures") not in ([], None):
                raise ValueError("Journal managed-process cleanup reported failures")

    @staticmethod
    def _validate_journal_fact_bindings(
        events: Sequence[Any],
        receipt: Mapping[str, Any],
        authorization: Mapping[str, Any],
        *,
        cas: Any | None = None,
    ) -> None:
        """Rebuild the acceptance facts from authenticated Journal events.

        A receipt is a CAS index, not an attestation.  Each acceptance fact
        therefore has a typed event in the same contiguous run stream.  The
        event payloads are deliberately structured and contain only hashes,
        counters, paths and verdicts; model/provider bodies are never needed.
        """

        run_events = [
            event for event in events
            if (
                isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("run_id") == receipt.get("run_id")
            )
            or str(getattr(event, "stream_id", "")).startswith(
                f"run/forge-exec-{receipt.get('run_id')}-"
            )
            or str(getattr(event, "stream_id", "")) == "run/" + str(receipt.get("run_id") or "")
        ]
        payloads = [
            event.payload for event in run_events
            if isinstance(getattr(event, "payload", None), Mapping)
        ]
        observer_events = [
            event for event in events
            if isinstance(getattr(event, "payload", None), Mapping)
            and event.payload.get("run_id") == receipt.get("run_id")
        ]
        observed_ids = receipt.get("side_effect_observed_event_ids")
        if not isinstance(observed_ids, list) or not observed_ids or len(observed_ids) != len(set(observed_ids)):
            raise ValueError("Code Mode side-effect observer event closure is missing")
        observed_id_set = {str(item) for item in observed_ids}
        # The observer may legitimately see a task/effect event carrying the
        # parent run id while living on its own authenticated stream.  The
        # event id is still checked against the reopened Journal; it is not
        # accepted from the receipt alone.
        parent_event_ids = {
            str(event.event_id) for event in events
            if isinstance(getattr(event, "event_id", None), str)
        }
        if not observed_id_set.issubset(parent_event_ids):
            raise ValueError("Code Mode side-effect observer references another stream")
        observed_parent_events = [
            event for event in events if str(event.event_id) in observed_id_set
        ]
        if [str(event.event_id) for event in observed_parent_events] != [str(item) for item in observed_ids]:
            raise ValueError("Code Mode side-effect observer event order is invalid")
        observer_payload = {
            "schema": "CODE_MODE_SIDE_EFFECT_OBSERVATION_V1",
            "run_id": receipt.get("run_id"),
            "event_ids": [str(event.event_id) for event in observed_parent_events],
            "event_count": len(observed_parent_events),
        }
        expected_observer_receipt = hashlib.sha256(_canonical(observer_payload)).hexdigest()
        if receipt.get("side_effect_observation_receipt") != expected_observer_receipt:
            raise ValueError("Code Mode side-effect observer receipt is not derived from the same run")
        typed_fact_payloads = [
            payload for payload in payloads
            if str(payload.get("schema") or "").startswith("CODE_MODE_")
            and str(payload.get("schema") or "").endswith("_FACT_V1")
        ]
        if not typed_fact_payloads or any(
            payload.get("actor_id") != "code-mode-receipt-sealer"
            for payload in typed_fact_payloads
        ):
            raise ValueError("Code Mode typed facts were not emitted by the receipt sealer")
        forge_results = [
            payload for payload in payloads
            if payload.get("event_type") == "forge.execution.result"
        ]
        if len(forge_results) != 1:
            raise ValueError("Journal Forge execution result is missing or duplicated")
        forge_result = forge_results[0]
        if forge_result.get("accepted") is not True:
            raise ValueError("Journal Forge result is not accepted")
        if forge_result.get("embedded_tool_call_count") != receipt.get("tool_call_count"):
            raise ValueError("Journal Forge tool count does not match the run receipt")
        if forge_result.get("diff_paths") != receipt.get("changed_paths"):
            raise ValueError("Journal Forge diff does not match the run receipt")
        if forge_result.get("patch_manifest_hash") != receipt.get("diff_hash"):
            raise ValueError("Journal Forge patch manifest does not match the run receipt")
        auth_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_AUTHORIZATION_FACT_V1"
        ]
        if len(auth_events) != 1:
            raise ValueError("Journal authorization fact is missing or duplicated")
        auth_fact = auth_events[0]
        for key in (
            "authorization_id", "session_id", "candidate_id", "run_id",
            "workspace", "intent_authorized", "runtime_state_identity", "runtime_authority_handle_hash",
        ):
            expected = authorization.get(key)
            if key == "intent_authorized":
                expected = True
            if auth_fact.get(key) != expected:
                raise ValueError("Journal authorization fact does not match the run authorization")

        stage_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_STAGE_FACT_V1"
        ]
        expected_stages = receipt.get("stages")
        if not isinstance(expected_stages, Mapping):
            raise ValueError("receipt stage facts are invalid")
        required_stages = ("Controller", "Planner", "Forge", "Tester", "Reviewer")
        if {payload.get("stage") for payload in stage_events} != set(required_stages):
            raise ValueError("Journal is missing one or more execution stages")
        for stage in required_stages:
            matches = [payload for payload in stage_events if payload.get("stage") == stage]
            if len(matches) != 1 or matches[0].get("stage_result") != expected_stages.get(stage):
                raise ValueError("Journal stage fact does not match the run receipt")

        provider_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_PROVIDER_FACT_V1"
        ]
        if len(provider_events) != 1:
            raise ValueError("Journal provider fact is missing or duplicated")
        provider_fact = provider_events[0]
        expected_provider = {
            "provider_profile": receipt.get("provider_profile"),
            "provider_model": receipt.get("provider_model"),
            "physical_send_count": receipt.get("physical_send_count"),
            "fallback_count": receipt.get("fallback_count"),
            "token_usage": receipt.get("token_usage"),
            "transport_authoritative": receipt.get("transport_authoritative"),
            "transport_receipts": receipt.get("transport_receipts"),
            "transport_ledger_hash": receipt.get("transport_ledger_hash"),
        }
        if provider_fact.get("provider_facts") != expected_provider:
            raise ValueError("Journal provider fact does not match the run receipt")

        execution_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_EXECUTION_FACT_V1"
        ]
        if len(execution_events) != 1:
            raise ValueError("Journal execution fact is missing or duplicated")
        expected_execution = {
            "tool_call_count": receipt.get("tool_call_count"),
            "changed_paths": receipt.get("changed_paths"),
            "diff_hash": receipt.get("diff_hash"),
        }
        if execution_events[0].get("execution_facts") != expected_execution:
            raise ValueError("Journal tool or diff facts do not match the run receipt")

        tester_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_TESTER_FACT_V1"
        ]
        reviewer_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_REVIEWER_FACT_V1"
        ]
        if len(tester_events) != 1 or tester_events[0].get("tester") != receipt.get("tester"):
            raise ValueError("Journal Tester fact does not match the run receipt")
        if len(reviewer_events) != 1 or reviewer_events[0].get("reviewer") != receipt.get("reviewer"):
            raise ValueError("Journal post-execution Reviewer fact does not match the run receipt")
        tester_stage_events = [
            payload for payload in payloads
            if payload.get("event_type") == "execution.stage" and payload.get("stage") == "Tester"
        ]
        reviewer_stage_events = [
            payload for payload in payloads
            if payload.get("event_type") == "execution.stage" and payload.get("stage") == "Reviewer"
        ]
        if len(tester_stage_events) != 1 or tester_stage_events[0].get("accepted") is not True:
            raise ValueError("Journal Tester stage is not an accepted verification")
        if tester_stage_events[0].get("test_evidence_hash") != receipt["tester"].get("evidence_hash"):
            raise ValueError("Journal Tester evidence does not match the run receipt")
        if len(reviewer_stage_events) != 1 or reviewer_stage_events[0].get("post_execution") is not True:
            raise ValueError("Journal Reviewer stage is not a post-execution review")
        if str(reviewer_stage_events[0].get("decision") or "").casefold() != "accepted":
            raise ValueError("Journal Reviewer did not accept the execution")

        completion_events = [
            payload for payload in payloads
            if payload.get("schema") == "CODE_MODE_COMPLETION_FACT_V1"
        ]
        if len(completion_events) != 1:
            raise ValueError("Journal completion fact is missing or duplicated")
        completion = completion_events[0]
        expected_completion = {
            "side_effect_observation_receipt": receipt.get("side_effect_observation_receipt"),
            "side_effect_observed_event_ids": receipt.get("side_effect_observed_event_ids"),
            "side_effect_observer_hash": receipt.get("side_effect_observer_hash"),
            "cleanup": receipt.get("cleanup"),
            "cleanup_observation": receipt.get("cleanup_observation"),
            "production_sentinel_before": receipt.get("production_sentinel_before"),
            "production_sentinel_after": receipt.get("production_sentinel_after"),
            "production_sentinel_unchanged": receipt.get("production_sentinel_unchanged"),
            "production_sentinel_allowlist": receipt.get("production_sentinel_allowlist"),
        }
        if completion.get("completion_facts") != expected_completion:
            raise ValueError("Journal cleanup or sentinel facts do not match the run receipt")
        cleanup_events = [
            payload for payload in payloads
            if payload.get("event_type") == "execution.worktree.cleanup.finally"
        ]
        if len(cleanup_events) != 1 or receipt.get("cleanup_observation", {}).get("worktree") != {
            key: cleanup_events[0].get(key)
            for key in ("status", "removed", "physical_removed", "audit_recorded")
        }:
            raise ValueError("Journal worktree cleanup does not match the run receipt")
        CodeModeAcceptanceV1._validate_managed_process_cleanup_bindings(
            events,
            receipt.get("cleanup_observation"),
            cas=cas,
        )

    def evaluate_canary(
        self,
        *,
        authorization: Mapping[str, Any],
        evidence: Mapping[str, Any],
        reviewer: Mapping[str, Any],
        runtime_context: Any | None = None,
        expected_issuer_identity: str | None = None,
        controller_session: Any | None = None,
    ) -> dict[str, Any]:
        provider = dict(self.profile.get("provider") or {})
        run_id = authorization.get("run_id")
        run_receipt = evidence.get("run_receipt")
        reasons: list[str] = []
        actual: Mapping[str, Any] | None = None
        cas_receipt = None
        journal_events: tuple[Any, ...] = ()
        journal_closure_verified = False
        # A caller-supplied receipt is only a locator.  A plain mapping is not
        # evidence: the gate must reopen the trusted Code Mode state root and
        # verify the durable CAS object plus its same-run Journal reference.
        try:
            from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
            from sitina.journal.model import parse_canonical_json

            if not isinstance(runtime_context, CodeModeRuntimeContext):
                raise ValueError("trusted Code Mode runtime context is required")
            if controller_session is None:
                controller_session = getattr(runtime_context, "_active_controller_session", None)
            if controller_session is None or not callable(getattr(controller_session, "assert_canary_access", None)):
                raise ValueError("active Code Mode controller session is required")
            controller_session.assert_canary_access(runtime_context, authorization)
            if not isinstance(expected_issuer_identity, str) or not expected_issuer_identity:
                raise ValueError("controller issuer identity pin is required")
            runtime_binding = runtime_context.canary_authority_binding()
            if runtime_binding.get("issuer_id") != expected_issuer_identity:
                raise ValueError("active controller issuer identity does not match the external pin")
            if any(
                authorization.get(key) != value
                for key, value in runtime_binding.items()
            ):
                raise ValueError("canary authorization is not bound to this runtime authority")
            if not runtime_context.validate_canary_authorization(authorization):
                raise ValueError("canary authorization was not issued by this runtime authority")
            if not isinstance(run_receipt, Mapping):
                raise ValueError("run receipt locator is missing")
            reference_id = run_receipt.get("reference_id")
            if not isinstance(reference_id, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", reference_id):
                raise ValueError("run receipt locator is not a durable CAS reference")
            cas = runtime_context.open_cas_reader()
            object_ref = cas.resolve_reference(reference_id)
            cas_receipt = cas.verify_existing(object_ref)
            if not (cas_receipt.fresh_verified and cas_receipt.no_replace_published):
                raise ValueError("run receipt CAS proof is not fresh and no-replace")
            decoded = parse_canonical_json(cas.open_verified(object_ref))
            if not isinstance(decoded, Mapping) or decoded.get("schema") != "CODE_MODE_RUN_RECEIPT_V1":
                raise ValueError("run receipt schema is invalid")
            content_hash = decoded.get("content_hash")
            body = {key: value for key, value in decoded.items() if key != "content_hash"}
            if content_hash != _hash_value(body):
                raise ValueError("run receipt content hash mismatch")
            actual = decoded
            ledger_getter = getattr(runtime_context, "_authoritative_transport_ledger", None)
            if not callable(ledger_getter):
                raise ValueError("run receipt has no issuer-bound transport ledger")
            ledger, ledger_capability = ledger_getter()
            ledger_receipts = [dict(item) for item in ledger.snapshot(ledger_capability)]
            if decoded.get("transport_receipts") != ledger_receipts:
                raise ValueError("run receipt transport receipts are not ledger-complete")
            expected_ledger_hash = hashlib.sha256(_canonical(ledger_receipts)).hexdigest()
            if decoded.get("transport_ledger_hash") != expected_ledger_hash:
                raise ValueError("run receipt transport ledger hash mismatch")
            journal = runtime_context.open_runtime_state_reader()
            try:
                all_events = tuple(journal.iter_events(0))
                journal_events = tuple(
                    event for event in all_events
                    if event.stream_id == f"run/{run_id}"
                    and reference_id in tuple(event.object_refs)
                )
                all_stream_events = tuple(
                    event for event in all_events if event.stream_id == f"run/{run_id}"
                )
                # The observer commits task/effect/protocol events alongside
                # the main run.  Only exact run-bound graph members reach the
                # fact validator; unrelated Journal streams never do.
                related_stream_events = self._related_run_events(all_events, run_id)
            finally:
                journal.close()
            if not any(
                event.payload.get("authorization_id") == authorization.get("authorization_id")
                and event.payload.get("session_id") == authorization.get("session_id")
                and event.payload.get("candidate_id") == authorization.get("candidate_id")
                for event in all_stream_events
                if isinstance(event.payload, Mapping)
            ):
                raise ValueError("same-run Journal lacks the current authorization binding")
            if not journal_events or any(
                not isinstance(event.event_hash, str) or event.event_hash != event.computed_event_hash
                for event in related_stream_events
            ):
                raise ValueError("run receipt is not rooted in verified related Journal events")
            refs = actual.get("journal_event_hashes")
            self._validate_journal_hash_closure(
                all_stream_events,
                reference_id=reference_id,
                journal_event_hashes=refs,
            )
            # The root event itself carries the durable CAS reference; all
            # preceding authenticated events must be covered by the receipt.
            # Excluding that root avoids a circular receipt-hash dependency.
            self._validate_journal_fact_bindings(
                related_stream_events,
                actual,
                authorization,
                cas=cas,
            )
            journal_closure_verified = True
        except Exception as error:  # fail closed without exposing CAS/model content
            # Diagnostic detail is intentionally hash-only in the public
            # result; local debugging can use the exception class below.
            reasons.append(type(error).__name__ + ":run_receipt_not_reopened")

        required = (
            "schema", "run_id", "session_id", "candidate_id", "authorization_id", "workspace",
            "resolved_mode", "intent_authorized", "stages", "tool_call_count", "changed_paths",
            "diff_hash", "tester", "reviewer", "provider_profile", "provider_model",
            "physical_send_count", "fallback_count", "token_usage", "side_effect_observation_receipt",
            "side_effect_observed_event_ids",
            "side_effect_observer_hash", "cleanup", "cleanup_observation",
            "transport_authoritative", "transport_receipts",
            "transport_ledger_hash",
            "production_sentinel_before", "production_sentinel_after", "production_sentinel_allowlist",
            "production_sentinel_identity_roots", "production_sentinel_excluded_runtime_roots",
            "production_sentinel_observed", "production_sentinel_unchanged", "journal_event_hashes", "fresh_verified", "no_replace_published",
            "content_hash", "runtime_state_identity", "runtime_authority_handle_hash", "runtime_journal_id", "issuer_id",
        )
        actual_ok = isinstance(actual, Mapping) and all(key in actual for key in required)
        if not actual_ok:
            reasons.append("trusted run receipt fields are incomplete")
        data = actual if actual_ok else {}
        stages = data.get("stages") or {}
        required_stages = ("Controller", "Planner", "Forge", "Tester", "Reviewer")
        stage_ok = all(isinstance(stages.get(name), Mapping) and stages[name].get("status") == "passed" for name in required_stages)
        usage = data.get("token_usage") or {}
        integer_usage = isinstance(usage, Mapping) and all(
            type(usage.get(key)) is int and usage.get(key) >= 0 for key in ("input", "output", "total")
        )
        total_ok = integer_usage and usage["total"] == usage["input"] + usage["output"]
        production_unchanged = data.get("production_sentinel_before") == data.get("production_sentinel_after") and data.get("production_sentinel_unchanged") is True
        tester = data.get("tester") if isinstance(data.get("tester"), Mapping) else {}
        post_reviewer = data.get("reviewer") if isinstance(data.get("reviewer"), Mapping) else {}
        sentinel_config = dict(self.production_sentinel or {})
        # An acceptance object without an explicitly configured production
        # sentinel has no independent baseline.  Do not silently scan a
        # conventional path (which is both expensive and an authority
        # confusion); fail closed instead.  Production canary callers must
        # supply the approved sentinel root and allowlist.
        sentinel_root_value = sentinel_config.get("root")
        sentinel_root = Path(str(sentinel_root_value)) if sentinel_root_value else None
        configured_identity_roots = sentinel_config.get("identity_roots", DEFAULT_IDENTITY_ROOTS)
        configured_excluded_roots = sentinel_config.get(
            "runtime_excluded_roots", DEFAULT_RUNTIME_EXCLUDED_ROOTS
        )
        if (
            not isinstance(configured_identity_roots, Sequence)
            or isinstance(configured_identity_roots, (str, bytes))
            or not configured_identity_roots
            or not isinstance(configured_excluded_roots, Sequence)
            or isinstance(configured_excluded_roots, (str, bytes))
            or not configured_excluded_roots
        ):
            configured_identity_roots = configured_excluded_roots = ()
        try:
            independently_observed_sentinel = (
                _production_sentinel_digest(
                    sentinel_root,
                    identity_roots=configured_identity_roots,
                    runtime_excluded_roots=configured_excluded_roots,
                )
                if sentinel_root is not None
                and data.get("production_sentinel_identity_roots") == list(configured_identity_roots)
                and data.get("production_sentinel_excluded_runtime_roots") == list(configured_excluded_roots)
                else None
            )
        except ValueError:
            independently_observed_sentinel = None
        production_unchanged = (
            independently_observed_sentinel is not None
            and independently_observed_sentinel == data.get("production_sentinel_before")
            and data.get("production_sentinel_before") == data.get("production_sentinel_after")
            and data.get("production_sentinel_observed") is True
            and data.get("production_sentinel_unchanged") is True
        )
        checks = {
            "candidate_bound": data.get("candidate_id") == authorization.get("candidate_id") and data.get("workspace") == authorization.get("workspace"),
            "run_bound_receipt": actual_ok and data.get("run_id") == run_id and data.get("session_id") == authorization.get("session_id") and data.get("authorization_id") == authorization.get("authorization_id"),
            "runtime_authority_bound": actual_ok and all(
                data.get(key) == authorization.get(key)
                for key in ("runtime_state_identity", "runtime_authority_handle_hash", "runtime_journal_id", "issuer_id")
            ),
            "route_multi": data.get("resolved_mode") == "MULTI",
            "intent_authorized": data.get("intent_authorized") is True,
            "stages": stage_ok,
            "tool_calls": type(data.get("tool_call_count")) is int and data.get("tool_call_count") > 0,
            "real_diff": bool(data.get("changed_paths")) and isinstance(data.get("diff_hash"), str) and bool(_SHA256.fullmatch(str(data.get("diff_hash")))),
            "tests": tester.get("status") == "passed" and tester.get("return_code") == 0,
            "post_execution_reviewer": post_reviewer.get("post_execution") is True and post_reviewer.get("decision") == "ACCEPT",
            "physical_send": type(data.get("physical_send_count")) is int and data.get("physical_send_count") > 0,
            "physical_transport_receipts": (
                data.get("transport_authoritative") is True
                and isinstance(data.get("transport_receipts"), list)
                and bool(data.get("transport_receipts"))
                and all(
                    isinstance(item, Mapping)
                    and item.get("schema") == "CODE_MODE_PROVIDER_TRANSPORT_RECEIPT_V1"
                    and item.get("authority") == "network-transport-boundary-v1"
                    and (
                        item.get("run_id") == data.get("run_id")
                        or str(item.get("run_id") or "").startswith(
                            f"forge-exec-{data.get('run_id')}-"
                        )
                    )
                    and item.get("provider_profile") == data.get("provider_profile")
                    and item.get("provider_model") == data.get("provider_model")
                    for item in data.get("transport_receipts", [])
                )
            ),
            "provider": data.get("provider_profile") == provider.get("profile"),
            "model": data.get("provider_model") == provider.get("model"),
            "token_usage": integer_usage and usage["input"] > 0 and usage["output"] > 0 and total_ok,
            "no_fallback": type(data.get("fallback_count")) is int and data.get("fallback_count") == 0 and authorization.get("fallback_allowed") is False,
            "journal_cas_closure": journal_closure_verified and bool(journal_events) and cas_receipt is not None,
            "cleanup": data.get("cleanup") is True,
            "production_sentinel": production_unchanged,
        }
        reasons.extend(name for name, passed in checks.items() if not passed and name not in reasons)
        status = CANARY_PASSED if all(checks.values()) else CODE_MODE_BLOCKED
        if status == CANARY_PASSED and runtime_context is not None:
            try:
                runtime_context.consume_canary_authorization(authorization)
            except Exception:
                status = CODE_MODE_BLOCKED
                reasons.append("canary_authorization_replay_or_expiry")
        return {
            "schema": SCHEMA,
            "status": status,
            "legacy_bplus_status": LEGACY_STATUS,
            "candidate_id": authorization.get("candidate_id"),
            "authorization_id": authorization.get("authorization_id"),
            "checks": checks,
            "reasons": reasons,
            "deployment_triggered": False,
        }

    def issue_release_acceptance(
        self, *, canary: Mapping[str, Any], reviewer: Mapping[str, Any]
    ) -> dict[str, Any]:
        if canary.get("status") != CANARY_PASSED or reviewer.get("status") != "REVIEW_APPROVED":
            raise PermissionError("release acceptance requires successful canary and REVIEW_APPROVED")
        body = {
            "schema": "CODE_MODE_RELEASE_ACCEPTANCE_V1",
            "candidate_id": canary.get("candidate_id"),
            "canary_authorization_id": canary.get("authorization_id"),
            "review_status": "REVIEW_APPROVED",
            "activation_state": "INACTIVE_UNTIL_SEPARATE_RELEASE_AUTHORIZATION",
            "deployment_triggered": False,
            "legacy_bplus_status": LEGACY_STATUS,
        }
        return body | {"acceptance_hash": _hash_value(body)}

    def status_summary(self, *, candidate: Mapping[str, Any] | None = None) -> dict[str, Any]:
        candidate = candidate or self.freeze_candidate()
        valid, drift = verify_candidate_manifest(self.workspace, candidate)
        return {
            "schema": SCHEMA,
            "code_mode_status": "CODE_MODE_CANDIDATE_FROZEN" if valid else CODE_MODE_BLOCKED,
            "legacy_bplus_status": LEGACY_STATUS,
            "candidate_id": candidate.get("candidate_id"),
            "candidate_valid": valid,
            "candidate_drift": drift,
            "legacy_foundation_consulted": False,
            "deployment_triggered": False,
        }


# Compatibility for the paused prototype's import name.  Runtime execution
# only uses CodeModeRuntimePolicy; this alias is intentionally post-execution.
CodeModeGateV1 = CodeModeAcceptanceV1


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


__all__ = [
    "CANARY_PASSED",
    "CODE_MODE_BLOCKED",
    "CODE_MODE_READY",
    "CodeModeAcceptanceV1",
    "CodeModeGateV1",
    "CodeModeRuntimePolicy",
    "EVIDENCE_SCHEMA",
    "LEGACY_STATUS",
    "RELEASE_ACCEPTED",
    "build_candidate_manifest",
    "load_code_mode_profile",
    "verify_candidate_manifest",
]
