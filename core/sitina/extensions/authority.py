"""Shared extension-root preparation and authority facts for r4 batch 4A.

This module deliberately stops before trial/publication.  It gives extension
preparation one durable coordination surface, backed by the existing
LoopEventStore Journal/CAS pair, while keeping the legacy registry as an
untrusted compatibility projection.  The public APIs are intentionally small:
bind a root, prepare a complete candidate, inspect/rebuild the projection.
There is no "publish" shortcut in 4A.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.metadata as importlib_metadata
import json
import os
import platform
import shutil
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sitina.commands.model import CommandEnvelope
from sitina.journal.local import ExpectedStreamVersionConflict
from sitina.journal.model import EventEnvelope, canonical_json_bytes
from sitina.extension_context import ExtensionPreparationContext
from sitina.utils import iso_now, load_json_yaml, sha256_bytes, stable_json

from .spec import (
    ExtensionSpecError,
    PluginManifest,
    SkillDefinition,
    load_skill,
    read_json_object,
)


AUTHORITY_BINDING_SCHEMA = "SITINA_EXTENSION_AUTHORITY_BINDING_V1"
AUTHORITY_EVENT_SCHEMA = "SITINA_EXTENSION_AUTHORITY_EVENT_V1"
PROJECTION_SCHEMA = "SITINA_EXTENSION_PROJECTION_V1"
CANDIDATE_SCHEMA = "SITINA_EXTENSION_CANDIDATE_V1"
EXECUTION_SNAPSHOT_SCHEMA = "SITINA_EXTENSION_EXECUTION_SNAPSHOT_V1"
TRIAL_FACT_SCHEMA = "SITINA_EXTENSION_TRIAL_FACT_V1"
SLOT_SCHEMA = "SITINA_EXTENSION_SLOT_V1"
DEFAULT_RESOLUTION_SCHEMA = "SITINA_EXTENSION_DEFAULT_RESOLUTION_V1"
PUBLICATION_INTENT_SCHEMA = "SITINA_EXTENSION_PUBLICATION_INTENT_V1"
PUBLICATION_COMMIT_SCHEMA = "SITINA_EXTENSION_PUBLICATION_COMMIT_V1"
PUBLICATION_CHECK_OBLIGATION_SCHEMA = "SITINA_EXTENSION_PUBLICATION_CHECK_OBLIGATION_V1"
PUBLICATION_CHECK_SCHEMA = "SITINA_EXTENSION_PUBLICATION_CHECK_V1"
PUBLICATION_FAILURE_EVIDENCE_SCHEMA = "SITINA_EXTENSION_PUBLICATION_FAILURE_EVIDENCE_V1"
PUBLICATION_FAILURE_OBSERVATION_SCHEMA = "SITINA_EXTENSION_PUBLICATION_FAILURE_OBSERVATION_V1"
PUBLICATION_FAILURE_RECONCILIATION_SCHEMA = "SITINA_EXTENSION_PUBLICATION_FAILURE_RECONCILIATION_V1"
PUBLICATION_FAILURE_COMPLETION_PROOF_SCHEMA = "SITINA_EXTENSION_FAILURE_COMPLETION_PROOF_V1"
PUBLICATION_FAILURE_ACTION_SCHEMA = "SITINA_EXTENSION_PUBLICATION_FAILURE_ACTION_V1"
STREAM_PREFIX = "sitina-extension/"
TENANT = "sitina-extension"


class ExtensionAuthorityError(RuntimeError):
    pass


class ExtensionAuthorityConflict(ExtensionAuthorityError):
    pass


class PublicationCheckNotApplicable(ExtensionAuthorityError):
    """A durable consumer operation is valid but not the published check method."""


class CandidatePreparationError(ExtensionAuthorityError):
    pass


@dataclass(frozen=True)
class PreparedCandidate:
    candidate_id: str
    capability_id: str
    install_id: str
    kind: str
    name: str
    path: Path
    manifest_ref: str
    manifest_hash: str
    tree_hash: str
    event_id: str
    stream_version: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": CANDIDATE_SCHEMA,
            "candidate_id": self.candidate_id,
            "capability_id": self.capability_id,
            "install_id": self.install_id,
            "kind": self.kind,
            "name": self.name,
            "path": str(self.path),
            "manifest_ref": self.manifest_ref,
            "manifest_hash": self.manifest_hash,
            "tree_hash": self.tree_hash,
            "event_id": self.event_id,
            "stream_version": self.stream_version,
        }


@dataclass(frozen=True)
class ExecutionSnapshot:
    snapshot_id: str
    candidate_id: str
    capability_id: str
    kind: str
    name: str
    root: Path
    location_binding: str
    tree_hash: str
    environment: Mapping[str, Any]
    bindings: Mapping[str, Any]
    permissions: Mapping[str, Any]
    dependencies: tuple[Mapping[str, Any], ...]
    snapshot_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": EXECUTION_SNAPSHOT_SCHEMA,
            "snapshot_id": self.snapshot_id,
            "candidate_id": self.candidate_id,
            "capability_id": self.capability_id,
            "kind": self.kind,
            "name": self.name,
            "root": str(self.root),
            "location_binding": self.location_binding,
            "tree_hash": self.tree_hash,
            "environment": dict(self.environment),
            "bindings": dict(self.bindings),
            "permissions": dict(self.permissions),
            "dependencies": [dict(item) for item in self.dependencies],
            "snapshot_hash": self.snapshot_hash,
        }


@dataclass(frozen=True)
class ExtensionSlot:
    """Stable logical capability slot, independent from content/publication."""

    kind: str
    name: str

    @property
    def slot_id(self) -> str:
        return f"{self.kind}:{self.name}"

    def as_dict(self) -> dict[str, str]:
        return {
            "schema": SLOT_SCHEMA,
            "slot_id": self.slot_id,
            "kind": self.kind,
            "name": self.name,
        }


def _canonical_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _canonical_evidence_value(value: Any) -> Any:
    """Keep producer evidence within Journal canonical JSON's value domain."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        # Journal facts deliberately reject floating-point values.  Evidence
        # may still contain a timeout or tool output number; preserve its
        # printable value without allowing it to bypass canonicalization.
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_evidence_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_evidence_value(item) for item in value]
    return str(value)


def _normalize_slot(value: Mapping[str, Any] | ExtensionSlot | str) -> ExtensionSlot:
    if isinstance(value, ExtensionSlot):
        return value
    if isinstance(value, str):
        raw = value.strip().casefold()
        kind, separator, name = raw.partition(":")
        if not separator:
            raise ExtensionAuthorityError("extension slot must use kind:name")
    elif isinstance(value, Mapping):
        slot_id = str(value.get("slot_id") or "").strip().casefold()
        kind = str(value.get("kind") or "").strip().casefold()
        name = str(value.get("name") or "").strip().casefold()
        if slot_id and (not kind or not name):
            kind, separator, name = slot_id.partition(":")
            if not separator:
                raise ExtensionAuthorityError("extension slot must use kind:name")
    else:
        raise ExtensionAuthorityError("extension slot must be an object or kind:name")
    if kind not in {"skill", "plugin"} or not name or ":" in name or "/" in name:
        raise ExtensionAuthorityError("extension slot kind/name is invalid")
    return ExtensionSlot(kind=kind, name=name)


def _safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise CandidatePreparationError(f"path escapes candidate root: {path}") from exc
    return relative.as_posix()


def _tree_hash(root: Path, *, exclude_names: frozenset[str] = frozenset()) -> str:
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if relative.as_posix() in exclude_names:
            continue
        if path.is_symlink():
            raise CandidatePreparationError(f"symlinks are not allowed in a candidate: {relative}")
        if not path.is_file():
            continue
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _resource_hashes(root: Path) -> list[dict[str, Any]]:
    root = root.resolve(strict=True)
    resources: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise CandidatePreparationError(f"symlink resource is not allowed: {relative}")
        if not path.is_file():
            continue
        raw = path.read_bytes()
        resources.append({
            "path": relative.as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        })
    return resources


def _copy_tree_no_links(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise CandidatePreparationError("candidate source must be a directory")
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        relative = path.relative_to(source)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise CandidatePreparationError(f"source contains a symlink: {relative}")
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            raise CandidatePreparationError(f"unsupported source entry: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target, follow_symlinks=False)
    if _tree_hash(source) != _tree_hash(destination):
        raise CandidatePreparationError("candidate source changed while it was being copied")
    _fsync_tree(destination)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    """Persist candidate bytes and directory entries before authority facts."""

    files: list[Path] = []
    directories: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CandidatePreparationError(f"candidate contains a symlink during fsync: {path}")
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            directories.append(path)
    for path in sorted(files):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(path)
    _fsync_directory(root)


def _configuration_hash(home: Path) -> str:
    config = home / "config"
    if not config.is_dir():
        return hashlib.sha256(b"missing-config").hexdigest()
    digest = hashlib.sha256()
    for path in sorted(config.rglob("*"), key=lambda item: item.relative_to(config).as_posix()):
        relative = path.relative_to(config)
        if path.is_symlink():
            raise CandidatePreparationError(f"configuration contains a symlink: {relative}")
        if not path.is_file():
            continue
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _executable_identity(value: str | Path | None) -> dict[str, Any]:
    raw = str(value or "")
    resolved = Path(raw).expanduser().resolve(strict=False) if raw else Path("")
    if raw and not resolved.is_file() and "/" not in raw:
        located = shutil.which(raw)
        resolved = Path(located).resolve(strict=False) if located else resolved
    if not resolved.is_file() or resolved.is_symlink():
        return {"requested": raw, "path": str(resolved), "exists": False, "sha256": None}
    data = resolved.read_bytes()
    return {
        "requested": raw,
        "path": str(resolved),
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def _software_identity() -> dict[str, Any]:
    """Hash the concrete consumer implementation, not a runtime label.

    These logical component hashes deliberately omit absolute host paths so a
    candidate's stable content identity can move between isolated roots while
    still refusing reuse after a reader/runtime/executor implementation change.
    """

    package_root = Path(__file__).resolve().parents[1]
    components = {
        "extension_authority": Path(__file__).resolve(),
        "extension_tool_catalog": package_root / "extensions" / "tools.py",
        "extension_spec_parser": package_root / "extensions" / "spec.py",
        "extension_runtime": package_root / "extensions" / "runtime.py",
        "loop_task_runtime": package_root / "loop" / "task_runtime.py",
        "loop_request_delivery": package_root / "loop" / "request_delivery.py",
        "loop_backend": package_root / "loop" / "coordinator.py",
        "loop_command_runner": package_root / "loop" / "command_runner.py",
    }
    identity: dict[str, Any] = {}
    for name, path in components.items():
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise CandidatePreparationError(f"consumer implementation is unavailable: {name}") from error
        identity[name] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    return {
        "schema": "SITINA_EXTENSION_SOFTWARE_IDENTITY_V1",
        "components": identity,
    }


def _environment_identity(home: Path, extension_root: Path) -> dict[str, Any]:
    config_hash = _configuration_hash(home)
    del extension_root
    return {
        "schema": "SITINA_EXTENSION_ENVIRONMENT_V1",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "runtime": "sitina-extension-candidate-4b",
        "config_sha256": config_hash,
        "software_identity": _software_identity(),
        "executables": {
            "python": _executable_identity(sys.executable),
            "printf": _executable_identity("/usr/bin/printf"),
        },
    }


def _candidate_environment_compatible(manifest: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Instruction-only skills survive a Host update without changing their pin.

    A skill's scripts remain task resources, executed only through current task
    tools and policy. Registered handlers, agents and dependencies do not receive
    this compatibility rule. All non-software environment bindings stay exact.
    """
    prepared = manifest.get("environment")
    if not isinstance(prepared, Mapping):
        return False
    if prepared == current:
        return True
    bindings = manifest.get("bindings")
    permissions = manifest.get("permissions")
    if (not isinstance(bindings, Mapping)
            or set(bindings) != {"skills", "agents", "tools", "mcp", "hooks"}
            or manifest.get("dependencies") != []):
        return False
    instruction_only = (manifest.get("kind") == "skill"
        and all(bindings.get(key) == [] for key in ("agents", "tools", "mcp", "hooks"))
        and isinstance(permissions, Mapping) and permissions.get("granted") == ["read"])
    # A pure MCP package is connection data for the current native client,
    # not a bundled consumer implementation. Content, launch dependencies,
    # grants and non-software environment bindings are still verified below
    # and when the complete execution snapshot is rebuilt.
    mcp_configuration_only = (manifest.get("kind") == "plugin"
        and all(bindings.get(key) == [] for key in ("skills", "agents", "tools", "hooks"))
        and isinstance(bindings.get("mcp"), list) and bool(bindings["mcp"]))
    if not (instruction_only or mcp_configuration_only):
        return False
    return ({key: value for key, value in prepared.items() if key != "software_identity"}
            == {key: value for key, value in current.items() if key != "software_identity"})


def _entry_bindings(manifest: PluginManifest, root: Path) -> dict[str, Any]:
    """Return concrete, reviewable handler bindings; never trust labels alone."""

    bindings: dict[str, Any] = {"skills": [], "agents": [], "tools": [], "mcp": [], "hooks": []}
    skills = manifest.component_path("skills")
    if skills:
        for path in sorted(skills.glob("*/SKILL.md")):
            skill = load_skill(path, plugin_name=manifest.name)
            bindings["skills"].append({
                "qualified_name": skill.qualified_name,
                "relative_path": _safe_relative(path, root),
                "description": skill.description,
                "instructions_sha256": hashlib.sha256(skill.body.encode("utf-8")).hexdigest(),
                "allowed_tools": list(skill.allowed_tools),
            })
    agents = manifest.component_path("agents")
    if agents:
        for path in sorted(agents.glob("*.md")):
            # Agent parsing is intentionally delegated to PluginManifest's
            # existing validation; the path and content remain bound here.
            bindings["agents"].append({
                "relative_path": _safe_relative(path, root),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "executor_type": "agent-markdown",
            })
    tools_path = manifest.component_path("tools")
    if tools_path:
        raw = read_json_object(tools_path)
        for item in raw.get("tools", []):
            if not isinstance(item, Mapping) or not isinstance(item.get("command"), list):
                raise CandidatePreparationError("tool binding lacks a concrete command executor")
            bindings["tools"].append({
                "name": str(item.get("name") or ""),
                "description": str(item.get("description") or ""),
                "permission": str(item.get("permission") or ""),
                "input_schema": dict(item.get("input_schema") or {}),
                "command": list(item["command"]),
                "executor_type": "subprocess-command",
            })
    mcp_path = manifest.component_path("mcp")
    if mcp_path:
        raw = read_json_object(mcp_path)
        for item in raw.get("servers", []):
            if not isinstance(item, Mapping):
                raise CandidatePreparationError("MCP binding is not an object")
            transport = str(item.get("transport") or "stdio")
            if transport == "stdio":
                if not isinstance(item.get("command"), list):
                    raise CandidatePreparationError("stdio MCP binding lacks a concrete command executor")
                executor = {"command": list(item["command"])}
            elif transport in {"http", "streamable_http"}:
                if not isinstance(item.get("url"), str) or not str(item["url"]).startswith(("http://", "https://")):
                    raise CandidatePreparationError("remote MCP binding lacks a concrete URL executor")
                executor = {"url": str(item["url"])}
            else:
                raise CandidatePreparationError(f"unknown MCP executor type: {transport}")
            bindings["mcp"].append({
                "name": str(item.get("name") or ""),
                "transport": transport,
                "permission": str(item.get("permission") or ""),
                "executor": executor,
                "tools": list(item.get("tools") or []),
                "executor_type": "mcp-" + transport,
            })
    hooks_path = manifest.component_path("hooks")
    if hooks_path:
        raw = read_json_object(hooks_path)
        for event, hooks in sorted(dict(raw.get("events") or {}).items()):
            for item in hooks:
                if not isinstance(item, Mapping) or not isinstance(item.get("command"), list):
                    raise CandidatePreparationError("hook binding lacks a concrete command executor")
                bindings["hooks"].append({
                    "event": event,
                    "permission": str(item.get("permission") or ""),
                    "command": list(item["command"]),
                    "executor_type": "subprocess-command",
                })
    return bindings


def _declared_dependencies(manifest: PluginManifest) -> list[dict[str, Any]]:
    raw = read_json_object(manifest.manifest_path)
    values = raw.get("dependencies", [])
    if values in (None, []):
        return []
    if not isinstance(values, list):
        raise CandidatePreparationError("plugin dependencies must be an array")
    supported = {"python", "system", "command", "mcp"}
    result: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, Mapping):
            raise CandidatePreparationError("plugin dependency entries must be objects")
        kind = str(item.get("type") or "")
        name = str(item.get("name") or "")
        if kind not in supported or not name.strip():
            raise CandidatePreparationError(f"unknown or incomplete dependency type: {kind or '<missing>'}")
        result.append({str(key): value for key, value in item.items()})
    return result


def _execution_binding_view(bindings: Mapping[str, Any], root: Path, *, include_mcp_runtime: bool = True) -> dict[str, Any]:
    """Add content identities for every concrete command/MCP executable."""

    value = json.loads(json.dumps(dict(bindings), sort_keys=True))

    def enrich(item: dict[str, Any], command: Any) -> None:
        if not isinstance(command, list):
            return
        identities = []
        for index, raw in enumerate(command):
            token = str(raw)
            candidate = Path(token).expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            if index == 0 or "/" in token or candidate.is_file() or candidate.is_symlink():
                identities.append(_executable_identity(candidate))
        item["executable_identities"] = identities

    for item in value.get("tools", ()):
        if isinstance(item, dict):
            enrich(item, item.get("command"))
    for item in value.get("mcp", ()) if include_mcp_runtime else ():
        if isinstance(item, dict):
            executor = item.get("executor")
            if isinstance(executor, Mapping):
                enrich(item, executor.get("command"))
    for item in value.get("hooks", ()):
        if isinstance(item, dict):
            enrich(item, item.get("command"))
    return value


def _resolved_dependency_view(dependencies: tuple[Mapping[str, Any], ...]) -> tuple[Mapping[str, Any], ...]:
    resolved: list[Mapping[str, Any]] = []
    for dependency in dependencies:
        item = dict(dependency)
        kind = str(item.get("type") or "")
        name = str(item.get("name") or "")
        if kind in {"command", "system", "mcp"}:
            identity = _executable_identity(name)
        elif kind == "python":
            # Use distribution metadata and hash the installed file set; do
            # not call importlib find_spec (dotted resolution can execute a
            # parent package __init__).  Unpackaged workspace modules are
            # deliberately unsupported for a usable extension snapshot.
            top_level = name.split(".", 1)[0].replace("-", "_")
            distributions = importlib_metadata.packages_distributions().get(top_level, ())
            identity = {"requested": name, "exists": False, "sha256": None}
            for distribution_name in distributions:
                try:
                    distribution = importlib_metadata.distribution(distribution_name)
                    files = tuple(distribution.files or ())
                except importlib_metadata.PackageNotFoundError:
                    continue
                file_identities = []
                for relative in sorted(files, key=str):
                    path = Path(distribution.locate_file(relative)).resolve(strict=False)
                    if not path.is_file() or path.is_symlink():
                        continue
                    data = path.read_bytes()
                    file_identities.append({
                        "path": str(relative),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data),
                    })
                module_suffix = Path(*name.split("."))
                module_candidates = {
                    str(module_suffix) + ".py",
                    str(module_suffix / "__init__.py"),
                }
                if not any(item["path"] in module_candidates for item in file_identities):
                    continue
                identity = {
                    "requested": name,
                    "distribution": distribution.metadata.get("Name") or distribution_name,
                    "version": distribution.version,
                    "exists": True,
                    "files": file_identities,
                }
                break
        else:
            identity = {"requested": name, "exists": False, "sha256": None}
        if not identity.get("exists"):
            raise CandidatePreparationError(f"required dependency is unavailable: {kind}:{name}")
        item["resolved_identity"] = identity
        resolved.append(item)
    return tuple(resolved)


class ExtensionAuthority:
    """One shared extension-root coordinator backed by an existing Loop store."""

    def __init__(self, extension_root: Path, *, state_root: Path, backend: Any, sitina_home: Path | None = None):
        self.extension_root = _canonical_path(extension_root)
        self.state_root = _canonical_path(state_root)
        self.sitina_home = _canonical_path(sitina_home or state_root)
        self.backend = backend
        # The implicit per-user root is a production authority.  A task or
        # test store must use an explicit isolated extension root instead.
        # Check before mkdir, backend attachment, binding or legacy import.
        default_root = (Path.home() / ".sitina" / "extensions").resolve(strict=False)
        if self.extension_root == default_root:
            allowed_states = {
                (self.sitina_home / "runtime/loop/state").resolve(strict=False),
                (self.sitina_home / "runtime/loop/workspaces/skill-management/state").resolve(strict=False),
            }
            if self.state_root not in allowed_states:
                raise ExtensionAuthorityError(
                    "the per-user extension root requires a persistent installation management store; "
                    "tasks and tests must provide an isolated extension root"
                )
            required = (".sitina-session-runtime-v1", "key-bindings-v1.json", "journal/active.seg")
            if not all((self.state_root / name).is_file() for name in required):
                raise ExtensionAuthorityError("the per-user extension management store is not initialized")
        # The shared Backend uses this private authority handle only to
        # re-resolve a candidate snapshot at its fixed consumer boundary;
        # callers never supply a root/hash directly to grant a receipt.
        setattr(self.backend, "_extension_authority", self)
        try:
            self.backend.assert_extension_write_ready()
        except AttributeError as exc:
            raise ExtensionAuthorityError("extension authority requires the LoopBackend write bridge") from exc
        self.extension_root.mkdir(parents=True, exist_ok=True)
        self.candidates_root = self.extension_root / "candidates"
        self.candidates_root.mkdir(parents=True, exist_ok=True)
        self.binding_path = self.extension_root / ".sitina-extension-authority-v1.json"
        self.lock_path = self.extension_root / ".sitina-extension-authority.lock"
        self.stream_id = STREAM_PREFIX + hashlib.sha256(str(self.extension_root).encode("utf-8")).hexdigest()[:32]
        self._bind()
        self._record_legacy_inventory_if_needed()

    @contextmanager
    def _writer_lock(self):
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _bind(self) -> None:
        journal_home = _canonical_path(
            getattr(getattr(self.backend, "context", None), "home", self.state_root)
        )
        if journal_home != self.state_root:
            raise ExtensionAuthorityError("shared extension authority store is bound to another state root")
        expected = {
            "schema": AUTHORITY_BINDING_SCHEMA,
            "extension_root": str(self.extension_root),
            "state_root": str(self.state_root),
            "stream_id": self.stream_id,
                "journal_id": str(getattr(getattr(self.backend, "context", None), "journal_id", "")),
            "created_at": None,
        }
        with self._writer_lock():
            if self.binding_path.exists():
                try:
                    recorded = json.loads(self.binding_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ExtensionAuthorityError("extension authority binding is unreadable") from exc
                if not isinstance(recorded, Mapping) or any(
                    recorded.get(key) != value
                    for key, value in expected.items()
                    if key != "created_at"
                ):
                    raise ExtensionAuthorityError("extension root is already bound to another state root/stream")
                return
            # A projection or candidate tree without its durable binding is
            # not a fresh legacy root: accepting it would let another state
            # root silently become a second authority after a crash/window.
            projection_path = self.extension_root / "registry.json"
            r4_projection = False
            if projection_path.is_file():
                try:
                    recorded_projection = json.loads(projection_path.read_text(encoding="utf-8"))
                    r4_projection = isinstance(recorded_projection, Mapping) and (
                        recorded_projection.get("schema") == PROJECTION_SCHEMA
                    )
                except (OSError, json.JSONDecodeError):
                    r4_projection = False
            candidate_trace = any(
                path.is_file() for path in self.candidates_root.rglob("*")
            ) if self.candidates_root.is_dir() else False
            if r4_projection or candidate_trace:
                raise ExtensionAuthorityError(
                    "extension root contains r4 projection/candidate traces but no valid authority binding"
                )
            expected["created_at"] = iso_now()
            temporary = self.binding_path.with_name(f".{self.binding_path.name}.{os.getpid()}.tmp")
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(expected, sort_keys=True, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.binding_path)
            # The binding is the root-ownership credential; persist both the
            # file and its directory entry before reporting success.
            directory_fd = os.open(self.extension_root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def _journal_events(self) -> tuple[EventEnvelope, ...]:
        try:
            return tuple(self.backend.extension_events(self.stream_id))
        except AttributeError as exc:
            raise ExtensionAuthorityError("extension authority requires the LoopBackend extension bridge") from exc

    @property
    def frontier(self) -> int:
        events = self._journal_events()
        return max((int(event.stream_version) for event in events), default=0)

    def _existing_request(self, request_id: str) -> EventEnvelope | None:
        matches = [
            event for event in self._journal_events()
            if isinstance(event.payload, Mapping) and event.payload.get("request_id") == request_id
        ]
        if len(matches) > 1:
            raise ExtensionAuthorityError("one request_id maps to multiple extension authority events")
        return matches[0] if matches else None

    def _append_fact(
        self,
        *,
        request_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        referenced_contents: tuple[Any, ...] = (),
        referenced_proofs: tuple[Any, ...] = (),
    ) -> EventEnvelope:
        if not isinstance(request_id, str) or not request_id.strip():
            raise ExtensionAuthorityError("request_id is required")
        request_hash = _sha256_json(payload)
        existing = self._existing_request(request_id)
        if existing is not None:
            if existing.payload.get("request_hash") != request_hash:
                raise ExtensionAuthorityConflict("request_id was already used for a different extension fact")
            return existing
        raw = dict(payload)
        raw.update({
            "schema": AUTHORITY_EVENT_SCHEMA,
            "event_type": event_type,
            "request_id": request_id,
            "request_hash": request_hash,
        })
        content = self.backend.publish_extension_json(raw, purpose="sitina-extension-authority-event")
        command_id = "extension-command-" + hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:32]
        event_id = "extension-event-" + hashlib.sha256((request_id + "\0" + event_type).encode("utf-8")).hexdigest()[:32]
        timestamp = iso_now()
        command = CommandEnvelope(
            command_id,
            TENANT,
            self.stream_id,
            "extension.authority.fact",
            "extension-coordinator",
            timestamp,
            {"request_id": request_id, "request_hash": request_hash, "event_type": event_type},
        )
        refs = tuple(sorted({
            content.reference_id,
            *(item.reference_id for item in referenced_contents),
            *(getattr(item.object_ref, "reference_id", "") for item in referenced_proofs),
        } - {""}))
        event = EventEnvelope(
            event_id,
            event_type,
            TENANT,
            self.stream_id,
            self.frontier,
            0,
            timestamp,
            {**raw, "content_ref": content.reference_id, "content_hash": content.content_hash},
            refs,
        )
        try:
            receipt = self.backend.append_extension_event(
                command,
                self.frontier,
                event,
                content.proof,
                tuple(item.proof for item in referenced_contents) + tuple(referenced_proofs),
            )
        except BaseException as exc:
            # A Journal append can commit and then lose its return (for
            # example, a process/socket interruption).  Re-read the exact
            # request/hash before surfacing the error so recovery is a pure
            # replay and never retries the physical consumer.  If no matching
            # fact exists, preserve the original persistence error; only a
            # genuine frontier conflict is translated to the authority error.
            replay = self._existing_request(request_id)
            if replay is not None:
                if replay.payload.get("request_hash") == request_hash:
                    return replay
                raise ExtensionAuthorityConflict("extension authority request_id was already used differently") from exc
            if isinstance(exc, ExpectedStreamVersionConflict):
                raise ExtensionAuthorityConflict("extension authority frontier changed while appending") from exc
            raise
        return next(item for item in self._journal_events() if item.position == receipt.first_position)

    def _legacy_inventory(self) -> dict[str, Any] | None:
        registry_path = self.extension_root / "registry.json"
        audit_path = self.extension_root / "audit.jsonl"
        if not registry_path.exists() and not audit_path.exists():
            return None
        registry_raw = registry_path.read_bytes() if registry_path.is_file() else b""
        audit_raw = audit_path.read_bytes() if audit_path.is_file() else b""
        try:
            registry = json.loads(registry_raw) if registry_raw else None
        except json.JSONDecodeError as exc:
            raise ExtensionAuthorityError("legacy extension registry is corrupt; refusing empty replacement") from exc
        if registry is not None and not isinstance(registry, Mapping):
            raise ExtensionAuthorityError("legacy extension registry is not an object")
        entries = []
        if isinstance(registry, Mapping):
            for section in ("plugins", "skills", "marketplaces"):
                values = registry.get(section) or {}
                if isinstance(values, Mapping):
                    entries.extend({"section": section, "name": str(name), "record": dict(record or {})} for name, record in values.items())
        return {
            "schema": "SITINA_EXTENSION_LEGACY_INVENTORY_V1",
            "source_registry": str(registry_path),
            "registry_sha256": hashlib.sha256(registry_raw).hexdigest() if registry_raw else None,
            "registry_bytes": len(registry_raw),
            "registry": registry,
            "entries": entries,
            "source_audit": str(audit_path),
            "audit_sha256": hashlib.sha256(audit_raw).hexdigest() if audit_raw else None,
            "audit_bytes": len(audit_raw),
            "audit_line_count": audit_raw.count(b"\n"),
            "captured_at": iso_now(),
        }

    def _record_legacy_inventory_if_needed(self) -> None:
        inventory = self._legacy_inventory()
        if inventory is None:
            return
        if any(event.event_type == "extension.legacy-inventory-recorded" for event in self._journal_events()):
            return
        self._append_fact(
            request_id="legacy-inventory-" + hashlib.sha256(
                canonical_json_bytes({key: value for key, value in inventory.items() if key != "captured_at"})
            ).hexdigest()[:32],
            event_type="extension.legacy-inventory-recorded",
            payload=inventory,
        )

    def _projection_from_events(self, events: tuple[EventEnvelope, ...]) -> dict[str, Any]:
        candidates: dict[str, Any] = {}
        legacy: list[dict[str, Any]] = []
        publications: dict[str, Any] = {}
        defaults: dict[str, Any] = {}
        obligations: dict[str, Any] = {}
        for event in events:
            payload = dict(event.payload)
            if event.event_type == "extension.candidate-prepared":
                candidate = dict(payload.get("candidate") or {})
                candidate_id = str(candidate.get("candidate_id") or "")
                if candidate_id:
                    candidates[candidate_id] = {
                        **candidate,
                        "candidate_manifest_ref": payload.get("candidate_manifest_ref"),
                        "candidate_manifest_hash": payload.get("candidate_manifest_hash"),
                        "event_id": event.event_id,
                        "stream_version": event.stream_version,
                    }
            elif event.event_type == "extension.publication-committed":
                publication_id = str(payload.get("publication_id") or "")
                slot = dict(payload.get("slot") or {})
                slot_id = str(slot.get("slot_id") or "")
                if publication_id and slot_id:
                    publication = {
                        **payload,
                        "event_id": event.event_id,
                        "stream_version": event.stream_version,
                    }
                    publications[publication_id] = publication
                    defaults[slot_id] = {
                        "publication_id": publication_id,
                        "slot": slot,
                        "snapshot_id": dict(payload.get("published") or {}).get("snapshot_id"),
                        "snapshot_hash": dict(payload.get("published") or {}).get("snapshot_hash"),
                        "state": "ACTIVE",
                        "event_id": event.event_id,
                        "stream_version": event.stream_version,
                    }
                    obligation = dict(payload.get("check_obligation") or {})
                    obligation_id = str(obligation.get("obligation_id") or "")
                    if obligation_id:
                        obligations[obligation_id] = {
                            **obligation,
                            "publication_id": publication_id,
                            "slot_id": slot_id,
                            "event_id": event.event_id,
                            "stream_version": event.stream_version,
                        }
                    # Recovery publications settle the failed publication's
                    # existing default-action obligation in the same Journal
                    # decision that creates the new publication/check.  Keep
                    # the ordinary consumer-check obligation separate.
                    failure_action = dict(payload.get("failure_action") or {})
                    action_obligation_id = str(failure_action.get("obligation_id") or "")
                    if action_obligation_id:
                        prior_action = dict(obligations.get(action_obligation_id) or {})
                        obligations[action_obligation_id] = {
                            **prior_action,
                            **failure_action,
                            "obligation_id": action_obligation_id,
                            "publication_id": str(failure_action.get("failed_publication_id") or prior_action.get("publication_id") or ""),
                            "slot_id": slot_id,
                            "state": "COMPLETED",
                            "event_id": event.event_id,
                            "stream_version": event.stream_version,
                        }
            elif event.event_type in {"extension.skill-management-committed", "extension.mcp-management-committed"}:
                slot = dict(payload.get("slot") or {})
                slot_id = str(slot.get("slot_id") or "")
                if slot_id and payload.get("selection_changed") is True:
                    prior = dict(defaults.get(slot_id) or {})
                    if payload.get("enabled") is True:
                        publication_id = str(payload["publication_id"])
                        publication = {**payload, "event_id": event.event_id, "stream_version": event.stream_version}
                        publications[publication_id] = publication
                        defaults[slot_id] = {
                            "publication_id": publication_id, "slot": slot,
                            "snapshot_id": payload["published"]["snapshot_id"],
                            "snapshot_hash": payload["published"]["snapshot_hash"],
                            "candidate_id": payload["candidate_id"], "state": "ACTIVE",
                            "event_id": event.event_id, "stream_version": event.stream_version,
                        }
                    else:
                        defaults[slot_id] = {
                            **prior, "slot": slot, "candidate_id": payload["candidate_id"],
                            "state": "DISABLED", "event_id": event.event_id,
                            "stream_version": event.stream_version,
                        }
            elif event.event_type == "extension.publication-check-recorded":
                obligation_id = str(payload.get("obligation_id") or "")
                if obligation_id:
                    prior = dict(obligations.get(obligation_id) or {})
                    obligations[obligation_id] = {
                        **prior,
                        **payload,
                        "event_id": event.event_id,
                        "stream_version": event.stream_version,
                    }
            elif event.event_type == "extension.publication-failure-reconciled":
                failure = dict(payload.get("failed_publication") or {})
                slot_id = str(failure.get("slot_id") or payload.get("slot_id") or "")
                failed_publication_id = str(failure.get("publication_id") or "")
                if failed_publication_id:
                    publications.setdefault(failed_publication_id, {}).update({
                        "isolation": payload.get("isolation"),
                        "failure_event_id": event.event_id,
                    })
                    if slot_id and slot_id in defaults and str(defaults[slot_id].get("publication_id") or "") == failed_publication_id:
                        defaults[slot_id] = {
                            **dict(defaults[slot_id]),
                            "state": "ISOLATED",
                            "isolation": payload.get("isolation"),
                            "failure_event_id": event.event_id,
                        }
                obligation = dict(payload.get("default_action_obligation") or {})
                obligation_id = str(obligation.get("obligation_id") or "")
                if obligation_id:
                    prior_obligation = dict(obligations.get(obligation_id) or {})
                    # A later failure for the same A must not reopen an
                    # already-settled action or move a newer default back to
                    # PENDING.  Preserve the terminal action state while
                    # retaining the latest failure as audit metadata.
                    if str(prior_obligation.get("state") or "") in {"COMPLETED", "DISABLED", "PROTECTED"}:
                        obligations[obligation_id] = {
                            **prior_obligation,
                            "last_failure_event_id": event.event_id,
                            "last_failure_stream_version": event.stream_version,
                        }
                    else:
                        obligations[obligation_id] = {
                            **obligation,
                            "publication_id": failed_publication_id,
                            "slot_id": slot_id,
                            "event_id": event.event_id,
                            "stream_version": event.stream_version,
                        }
                replacement = dict(payload.get("replacement_default") or {})
                if slot_id and replacement:
                    replacement_publication_id = str(replacement.get("publication_id") or "")
                    if replacement_publication_id:
                        defaults[slot_id] = {
                            **replacement,
                            "state": replacement.get("state") or "ACTIVE",
                            "event_id": event.event_id,
                            "stream_version": event.stream_version,
                        }
                elif slot_id and str(payload.get("resolution") or "") == "DISABLED":
                    defaults.pop(slot_id, None)
            elif event.event_type == "extension.publication-failure-actioned":
                slot_id = str(payload.get("slot_id") or "")
                failed_publication_id = str(payload.get("failed_publication_id") or "")
                obligation = dict(payload.get("default_action_obligation") or {})
                obligation_id = str(payload.get("obligation_id") or obligation.get("obligation_id") or "")
                prior_obligation = dict(obligations.get(obligation_id) or {}) if obligation_id else {}
                if obligation_id:
                    obligations[obligation_id] = {
                        **prior_obligation,
                        **obligation,
                        "obligation_id": obligation_id,
                        "publication_id": failed_publication_id or prior_obligation.get("publication_id"),
                        "slot_id": slot_id,
                        "state": str(payload.get("action", {}).get("state") or "COMPLETED"),
                        "event_id": event.event_id,
                        "stream_version": event.stream_version,
                    }
                repair = dict(payload.get("repair_obligation") or {})
                repair_id = str(repair.get("obligation_id") or "")
                if repair_id:
                    obligations[repair_id] = {
                        **repair,
                        "slot_id": slot_id,
                        "publication_id": failed_publication_id,
                        "event_id": event.event_id,
                        "stream_version": event.stream_version,
                    }
                if slot_id and failed_publication_id:
                    current_default = dict(defaults.get(slot_id) or {})
                    if str(current_default.get("publication_id") or "") == failed_publication_id:
                        defaults.pop(slot_id, None)
                if failed_publication_id:
                    publications.setdefault(failed_publication_id, {}).update({
                        "failure_action": dict(payload.get("action") or {}),
                        "failure_action_event_id": event.event_id,
                    })
            elif event.event_type == "extension.legacy-inventory-recorded":
                legacy.append({"event_id": event.event_id, "stream_version": event.stream_version, **payload})
        last = events[-1] if events else None
        active_default = next(
            (
                value for value in defaults.values()
                if isinstance(value, Mapping) and str(value.get("state") or "ACTIVE") == "ACTIVE"
            ),
            {},
        )
        return {
            "schema": PROJECTION_SCHEMA,
            "stream_id": self.stream_id,
            "extension_root": str(self.extension_root),
            "applied_frontier": {
                "stream_version": int(last.stream_version) if last else 0,
                "event_id": last.event_id if last else None,
                "event_hash": last.event_hash if last else None,
            },
            "default_publication_id": active_default.get("publication_id") if len(defaults) == 1 else None,
            "defaults": defaults,
            "candidates": candidates,
            "legacy_inventory": legacy,
            "publications": publications,
            "obligations": obligations,
            "updated_at": iso_now(),
        }

    def rebuild_projection(self) -> dict[str, Any]:
        projection = self._projection_from_events(self._journal_events())
        projection_path = self.extension_root / "registry.json"
        with self._writer_lock():
            current = None
            if projection_path.exists():
                try:
                    loaded = json.loads(projection_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, Mapping) and loaded.get("schema") == PROJECTION_SCHEMA:
                        current = loaded
                except (OSError, json.JSONDecodeError):
                    current = None
            current_frontier = int(dict(current or {}).get("applied_frontier", {}).get("stream_version", 0))
            proposed_frontier = int(projection["applied_frontier"]["stream_version"])
            if current_frontier > proposed_frontier:
                raise ExtensionAuthorityError("projection frontier is ahead of the authoritative Journal")
            temporary = projection_path.with_name(f".{projection_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
            temporary.write_text(json.dumps(projection, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(temporary, projection_path)
        return projection

    def load_projection(self) -> dict[str, Any]:
        path = self.extension_root / "registry.json"
        events = self._journal_events()
        frontier = max((int(event.stream_version) for event in events), default=0)
        expected = self._projection_from_events(events)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            recorded = int(dict(value.get("applied_frontier") or {}).get("stream_version", -1))
            comparable = dict(value)
            comparable.pop("updated_at", None)
            expected_comparable = dict(expected)
            expected_comparable.pop("updated_at", None)
            if (
                value.get("schema") != PROJECTION_SCHEMA
                or value.get("stream_id") != self.stream_id
                or recorded != frontier
                or comparable != expected_comparable
            ):
                raise ValueError("projection is stale")
            return dict(value)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return self.rebuild_projection()

    def _stream_position(self, events: tuple[EventEnvelope, ...]) -> dict[str, Any]:
        last = events[-1] if events else None
        return {
            "stream_id": self.stream_id,
            "stream_version": int(last.stream_version) if last else 0,
            "position": int(last.position) if last else 0,
            "event_id": last.event_id if last else None,
            "event_hash": last.event_hash if last else None,
        }

    def _persist_projection_at(self, events: tuple[EventEnvelope, ...], projection: Mapping[str, Any]) -> None:
        """Persist a point-in-time view without overwriting a newer frontier."""

        projection_path = self.extension_root / "registry.json"
        proposed_frontier = int(dict(projection.get("applied_frontier") or {}).get("stream_version", 0))
        with self._writer_lock():
            current_frontier = -1
            if projection_path.exists():
                try:
                    current = json.loads(projection_path.read_text(encoding="utf-8"))
                    current_frontier = int(dict(current.get("applied_frontier") or {}).get("stream_version", -1))
                except (OSError, TypeError, ValueError, json.JSONDecodeError):
                    current_frontier = -1
            if current_frontier > proposed_frontier:
                return
            temporary = projection_path.with_name(
                f".{projection_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
            )
            temporary.write_text(
                json.dumps(dict(projection), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, projection_path)

    def _projection_at_read_position(self) -> tuple[dict[str, Any], dict[str, Any], tuple[EventEnvelope, ...]]:
        """Take one bounded Journal read and derive its exact point-in-time view."""

        events = tuple(self._journal_events())
        position = self._stream_position(events)
        projection = self._projection_from_events(events)
        # A cached projection may be ahead, but the caller must resolve the
        # state represented by this one read position rather than chase it.
        self._persist_projection_at(events, projection)
        return projection, position, events

    @staticmethod
    def _source_binding_view(source: Mapping[str, Any]) -> dict[str, Any]:
        fields = (
            "task_id", "session_id", "run_instance_id", "execution_epoch",
            "goal_version", "acceptance_version", "received_input_seq",
            "handled_input_seq", "artifact_ref", "actor_role",
            "publication_scope", "write_authorized",
        )
        return {key: source.get(key) for key in fields}

    def _assert_live_source_binding(
        self,
        source: Mapping[str, Any],
        snapshot_id: str,
        *,
        publication_operation_id: str | None = None,
    ) -> Any:
        task_id = str(source.get("task_id") or "")
        if not task_id:
            raise ExtensionAuthorityError("publication source task_id is required")
        task = self.backend.get_task(task_id)
        if task.is_terminal:
            raise ExtensionAuthorityError("publication source task is already terminal")
        if str(getattr(task.control_intent, "value", task.control_intent)) != "RUN":
            raise ExtensionAuthorityError("publication source task is not RUN")
        if task.received_input_seq != task.handled_input_seq:
            raise ExtensionAuthorityError("publication source task has unhandled input")
        expected = self._source_binding_view(source)
        try:
            backend_role = dict(self.backend.extension_publication_source_binding(task_id, snapshot_id))
        except Exception as error:
            raise ExtensionAuthorityError("Backend did not authorize the publication source") from error
        actual = self._source_binding_view({
            "task_id": task.task_id,
            "session_id": task.session_id,
            "run_instance_id": task.run_instance_id,
            "execution_epoch": task.execution_epoch,
            "goal_version": task.goal_version,
            "acceptance_version": task.acceptance_version,
            "received_input_seq": task.received_input_seq,
            "handled_input_seq": task.handled_input_seq,
            "artifact_ref": task.artifact_ref,
            **backend_role,
        })
        if expected != actual:
            raise ExtensionAuthorityError("publication source binding differs from the active task")
        if str(task.capability_snapshot_id or "") != str(snapshot_id):
            raise ExtensionAuthorityError("publication source task is not bound to the candidate snapshot")
        if publication_operation_id is not None:
            try:
                self.backend.assert_extension_publication_write(
                    task_id, publication_operation_id, self.extension_root
                )
            except Exception as error:
                raise ExtensionAuthorityError("publication lacks the active Backend WRITE boundary") from error
        return task

    @staticmethod
    def _publication_request_view(request: Mapping[str, Any]) -> dict[str, Any]:
        keys = (
            "slot", "candidate_id", "snapshot_id", "snapshot_hash", "location_binding",
            "source", "trial_request_id", "trial_event_id", "operation_id",
            "expected_previous_default", "expected_stream_position",
        )
        return {key: request.get(key) for key in keys}

    @staticmethod
    def _publication_intent_request_id(request_id: str) -> str:
        return "publication-intent:" + str(request_id)

    def _default_for_projection(self, projection: Mapping[str, Any], slot: ExtensionSlot) -> dict[str, Any] | None:
        defaults = projection.get("defaults") if isinstance(projection.get("defaults"), Mapping) else {}
        value = defaults.get(slot.slot_id)
        if not isinstance(value, Mapping):
            return None
        if str(value.get("state") or "ACTIVE") != "ACTIVE":
            return None
        publication_id = str(value.get("publication_id") or "")
        publication = projection.get("publications", {}).get(publication_id)
        if not isinstance(publication, Mapping):
            return None
        isolation = publication.get("isolation")
        if isinstance(isolation, Mapping) and str(isolation.get("state") or "") == "ISOLATED":
            return None
        return {**dict(value), "publication": dict(publication)}

    def _record_resolution_failure(
        self,
        slot: ExtensionSlot,
        position: Mapping[str, Any],
        publication: Mapping[str, Any],
        *,
        candidate_id: str,
        error: BaseException,
        concrete_snapshot_failure: bool,
    ) -> EventEnvelope:
        """Persist one resolver-owned selected-publication failure observation.

        This is deliberately not a public caller-controlled classification
        API.  ``resolve_default`` has already authenticated the Journal
        position and selected publication; the only durable source here is
        that fixed F plus the snapshot reconstruction error.  A no-default or
        basic request/permission rejection never reaches this method.
        """

        publication_id = str(publication.get("publication_id") or "")
        event_id = str(position.get("event_id") or "")
        request_id = (
            "publication-resolution-failure:"
            + hashlib.sha256(
                f"{slot.slot_id}\0{publication_id}\0{event_id}".encode("utf-8")
            ).hexdigest()[:40]
        )
        source = {
            "schema": PUBLICATION_FAILURE_EVIDENCE_SCHEMA,
            "kind": "SNAPSHOT_UNAVAILABLE" if concrete_snapshot_failure else "EXTERNAL_OR_UNKNOWN",
            "slot": slot.as_dict(),
            "publication_id": publication_id,
            "snapshot_id": dict(publication.get("published") or {}).get("snapshot_id"),
            "candidate_id": candidate_id,
            "read_position": dict(position),
            "error_type": type(error).__name__,
            "error_message": str(error),
        }
        payload = {
            "schema": PUBLICATION_FAILURE_OBSERVATION_SCHEMA,
            "event_type": "extension.publication-failure-observed",
            "source": source,
            "state": "PENDING_REVIEW",
            "resolution": (
                "SELECTED_PUBLICATION_UNAVAILABLE"
                if concrete_snapshot_failure
                else "EXTERNAL_OR_UNKNOWN"
            ),
        }
        if concrete_snapshot_failure:
            # A selected publication that can no longer satisfy its
            # authenticated snapshot contract is actionable failure evidence:
            # persist the resolver-owned F/source and isolate exactly that
            # publication in the same Journal decision.  Basic NO_DEFAULT or
            # request/permission errors never reach this branch.
            evidence_content = self._persist_publication_failure_evidence(source)
            publication_slot = slot.as_dict()
            obligation_id = f"{publication_id}:default-action:v1"
            reconciled = {
                "schema": PUBLICATION_FAILURE_RECONCILIATION_SCHEMA,
                "event_type": "extension.publication-failure-reconciled",
                "failure_source": {
                    "schema": PUBLICATION_FAILURE_EVIDENCE_SCHEMA,
                    "reference": evidence_content.reference_id,
                    "hash": evidence_content.content_hash,
                },
                "failed_publication": {
                    "slot_id": publication_slot.get("slot_id"),
                    "publication_id": publication_id,
                    "snapshot_id": source.get("snapshot_id"),
                    "read_position": dict(position),
                },
                "isolation": {
                    "state": "ISOLATED",
                    "publication_id": publication_id,
                    "reason": "SELECTED_PUBLICATION_UNAVAILABLE",
                },
                "default_action_obligation": {
                    "obligation_id": obligation_id,
                    "type": "CONDITIONAL_DEFAULT_ACTION",
                    "expected_current_publication_id": publication_id,
                    "state": "PENDING",
                },
                "replacement_default": None,
                "resolution": "PENDING_CONDITIONAL_ACTION",
                "source": {
                    "resolution_attempt_id": request_id,
                    "publication_id": publication_id,
                    "candidate_id": candidate_id,
                },
            }
            return self._append_fact(
                request_id=request_id,
                event_type="extension.publication-failure-reconciled",
                payload=reconciled,
                referenced_contents=(evidence_content,),
            )
        return self._append_fact(
            request_id=request_id,
            event_type="extension.publication-failure-observed",
            payload=payload,
        )

    def resolve_default(self, slot: Mapping[str, Any] | ExtensionSlot | str) -> dict[str, Any]:
        """Resolve one logical slot at a single committed Journal position."""

        normalized = _normalize_slot(slot)
        projection, position, _events = self._projection_at_read_position()
        current = self._default_for_projection(projection, normalized)
        if current is None:
            raise ExtensionAuthorityError(f"no active default publication for slot {normalized.slot_id}")
        publication = dict(current["publication"])
        published = dict(publication.get("published") or {})
        candidate_id = str(published.get("candidate_id") or "")
        if not candidate_id:
            raise ExtensionAuthorityError("default publication lacks candidate identity")
        try:
            snapshot = self.build_execution_snapshot(candidate_id).as_dict()
            if any(
                str(published.get(key) or "") != str(snapshot.get(key) or "")
                for key in ("snapshot_id", "snapshot_hash", "location_binding")
            ):
                raise CandidatePreparationError("default publication snapshot no longer matches its authenticated candidate")
        except CandidatePreparationError as error:
            # The resolver owns the authenticated F and the selected
            # publication identity.  Only a concrete selected-publication
            # snapshot failure becomes a durable observation; no-default and
            # basic request/permission rejection return through the original
            # typed入口 without minting a new publication relationship.
            self._record_resolution_failure(
                normalized,
                position,
                publication,
                candidate_id=candidate_id,
                error=error,
                concrete_snapshot_failure=True,
            )
            raise ExtensionAuthorityError(
                f"selected publication snapshot is unavailable for slot {normalized.slot_id}"
            ) from error
        except Exception as error:
            self._record_resolution_failure(
                normalized,
                position,
                publication,
                candidate_id=candidate_id,
                error=error,
                concrete_snapshot_failure=False,
            )
            raise ExtensionAuthorityError(
                f"default snapshot resolution is unavailable for slot {normalized.slot_id}"
            ) from error
        return {
            "schema": DEFAULT_RESOLUTION_SCHEMA,
            "stream_id": self.stream_id,
            "resolution_stream_id": self.stream_id,
            "stream_version": position["stream_version"],
            "read_position": position,
            "slot": normalized.as_dict(),
            "publication_id": str(publication.get("publication_id") or ""),
            "capability_id": str(published.get("capability_id") or snapshot.get("capability_id") or ""),
            "candidate_id": candidate_id,
            "snapshot_id": snapshot.get("snapshot_id"),
            "snapshot_hash": snapshot.get("snapshot_hash"),
            "location_binding": snapshot.get("location_binding"),
            "projection_ref": publication.get("content_ref"),
            "projection_hash": publication.get("content_hash"),
            "isolation": {"state": "ACTIVE", "publication_id": publication.get("publication_id")},
        }

    def verify_capability_binding(
        self,
        binding: Mapping[str, Any],
        *,
        historical_only: bool = False,
    ) -> dict[str, Any]:
        """Revalidate an admitted capability without resolving the current default.

        Admission stores the exact publication, snapshot identity, Journal
        read position, and CAS projection proof.  Recovery and normal
        execution use this method to re-open that binding; they never ask the
        current slot default which publication should be used now.
        """

        if not isinstance(binding, Mapping) or binding.get("schema") != "SITINA_LOOP_CAPABILITY_BINDING_V1":
            raise ExtensionAuthorityError("capability binding schema is invalid")
        publication_id = str(binding.get("publication_id") or "")
        candidate_id = str(binding.get("candidate_id") or "")
        resolution_stream_id = str(binding.get("resolution_stream_id") or "")
        resolution_ref = str(binding.get("resolution_ref") or "")
        resolution_hash = str(binding.get("resolution_hash") or "")
        if (
            not publication_id
            or not candidate_id
            or not resolution_stream_id
            or not resolution_ref
            or not resolution_hash
        ):
            raise ExtensionAuthorityError("capability binding identity is incomplete")
        if resolution_stream_id != self.stream_id:
            raise ExtensionAuthorityError("admitted capability resolution belongs to another Journal stream")
        read_position = binding.get("read_position")
        if not isinstance(read_position, Mapping):
            raise ExtensionAuthorityError("admitted capability lacks read-position or CAS proof")
        read_stream_id = str(read_position.get("stream_id") or "")
        if read_stream_id != self.stream_id:
            raise ExtensionAuthorityError("admitted capability read position belongs to another Journal stream")
        try:
            read_stream_version = int(read_position.get("stream_version"))
        except (TypeError, ValueError) as error:
            raise ExtensionAuthorityError("admitted capability read position is not an integer") from error
        read_event_id = str(read_position.get("event_id") or "")
        read_event_hash = str(read_position.get("event_hash") or "")
        if read_stream_version < 0 or not read_event_id or not read_event_hash:
            raise ExtensionAuthorityError("admitted capability read position is incomplete")

        # F is an authenticated historical point, not an assertion copied into
        # the descriptor.  Locate the exact extension-stream event and ensure
        # its identity/hash match before rebuilding the projection at that
        # point.  Later publications are intentionally allowed: the admitted
        # publication must simply have been the active default at F.
        events = tuple(self._journal_events())
        historical = [
            event for event in events
            if int(event.stream_version) == read_stream_version
            and event.stream_id == self.stream_id
        ]
        if len(historical) != 1:
            raise ExtensionAuthorityError("admitted capability read position is not a canonical Journal point")
        historical_event = historical[0]
        if historical_event.event_id != read_event_id or historical_event.event_hash != read_event_hash:
            raise ExtensionAuthorityError("admitted capability read position hash or event identity is invalid")
        if "position" in read_position:
            try:
                read_position_position = int(read_position.get("position"))
            except (TypeError, ValueError) as error:
                raise ExtensionAuthorityError("admitted capability read position is not an integer") from error
            if read_position_position != int(historical_event.position):
                raise ExtensionAuthorityError("admitted capability Journal position is invalid")
        historical_projection = self._projection_from_events(
            tuple(event for event in events if int(event.position) <= int(historical_event.position))
        )
        historical_default = dict(
            (historical_projection.get("defaults") or {}).get(str(binding.get("slot_id") or "")) or {}
        )
        if (
            str(historical_default.get("publication_id") or "") != publication_id
            or str(historical_default.get("state") or "ACTIVE") != "ACTIVE"
        ):
            raise ExtensionAuthorityError("admitted capability publication was not the active default at F")

        projection = self.load_projection()
        publication = dict(dict(projection.get("publications") or {}).get(publication_id) or {})
        if not publication:
            raise ExtensionAuthorityError("admitted capability publication is unavailable")
        slot = dict(publication.get("slot") or {})
        if str(slot.get("slot_id") or "").casefold() != str(binding.get("slot_id") or "").casefold():
            raise ExtensionAuthorityError("admitted capability slot differs from its publication")
        published = dict(publication.get("published") or {})
        if any(
            str(published.get(key) or "") != str(binding.get(key) or "")
            for key in ("candidate_id", "snapshot_id", "snapshot_hash", "location_binding")
        ):
            raise ExtensionAuthorityError("admitted capability snapshot differs from its publication")
        if str(publication.get("content_ref") or "") != resolution_ref or str(publication.get("content_hash") or "") != resolution_hash:
            raise ExtensionAuthorityError("admitted capability CAS projection differs from its publication")
        if not isinstance(binding.get("resolution_cas_proof"), Mapping):
            raise ExtensionAuthorityError("admitted capability lacks read-position or CAS proof")
        self.backend.read_extension_json(resolution_ref, expected_hash=resolution_hash)
        proof = dict(binding.get("resolution_cas_proof") or {})
        if proof.get("schema") != "SITINA_EXISTING_DURABLE_OBJECT_ROOT_PROOF_V1":
            raise ExtensionAuthorityError("admitted capability CAS proof schema is invalid")
        if str(proof.get("object_ref") or "") != resolution_ref:
            raise ExtensionAuthorityError("admitted capability CAS proof references another object")
        try:
            rooted_position = int(proof.get("rooted_position"))
            verified_frontier_position = int(proof.get("verified_frontier_position"))
        except (TypeError, ValueError) as error:
            raise ExtensionAuthorityError("admitted capability CAS proof coordinates are invalid") from error
        if rooted_position < 0 or verified_frontier_position < rooted_position:
            raise ExtensionAuthorityError("admitted capability CAS proof coordinates are invalid")
        try:
            canonical_proof = self.backend.extension_existing_object_proof(resolution_ref)
            journal = self.backend.store.journal
            head_position = int(journal.head_position)
            position_hash = getattr(journal, "_position_hash", {})
        except Exception as error:
            raise ExtensionAuthorityError("admitted capability CAS proof cannot be checked against the Journal") from error
        if (
            str(proof.get("journal_id") or "") != str(canonical_proof.journal_id)
            or str(proof.get("rooted_transaction_hash") or "") != str(canonical_proof.rooted_transaction_hash)
            or rooted_position != int(canonical_proof.rooted_position)
            or str(proof.get("object_reference_manifest_hash") or "")
            != str(canonical_proof.object_reference_manifest_hash)
        ):
            raise ExtensionAuthorityError("admitted capability CAS proof does not match the canonical object root")
        frontier_transaction_hash = str(proof.get("verified_frontier_transaction_hash") or "")
        if verified_frontier_position > head_position or int(historical_event.position) > verified_frontier_position:
            raise ExtensionAuthorityError("admitted capability CAS proof frontier is not canonical")
        if not frontier_transaction_hash:
            raise ExtensionAuthorityError("admitted capability CAS proof lacks frontier commitment")
        if verified_frontier_position not in position_hash:
            raise ExtensionAuthorityError("admitted capability CAS proof frontier is not a Journal position")
        if str(position_hash.get(verified_frontier_position) or "") != frontier_transaction_hash:
            raise ExtensionAuthorityError("admitted capability CAS proof frontier commitment is invalid")
        if historical_only:
            # Recovery/check settlement proves the original admission/F/root
            # binding without reopening the candidate tree or current
            # environment.  The historical operation/result/receipt are
            # checked separately by record_publication_check.
            return {
                key: binding.get(key)
                for key in (
                    "schema", "slot_id", "publication_id", "candidate_id", "snapshot_id",
                    "snapshot_hash", "location_binding", "resolution_stream_id", "read_position",
                    "resolution_ref", "resolution_hash", "resolution_cas_proof",
                )
            }
        snapshot = self.build_execution_snapshot(candidate_id).as_dict()
        for key in ("candidate_id", "snapshot_id", "snapshot_hash", "location_binding"):
            if str(snapshot.get(key) or "") != str(binding.get(key) or ""):
                raise ExtensionAuthorityError("admitted capability snapshot is stale or changed")
        return snapshot

    def assert_publication_dispatch_allowed(self, binding: Mapping[str, Any]) -> None:
        """Reject new dispatches for a publication already isolated by C3b-1.

        This read is intentionally separate from historical binding
        verification: an in-flight operation keeps its original identity,
        while any new dispatch must observe the latest isolation projection.
        """

        publication_id = str(binding.get("publication_id") or "") if isinstance(binding, Mapping) else ""
        slot_id = str(binding.get("slot_id") or "") if isinstance(binding, Mapping) else ""
        if not publication_id or not slot_id:
            raise ExtensionAuthorityError("publication dispatch binding is incomplete")
        projection = self.load_projection()
        publication = dict((projection.get("publications") or {}).get(publication_id) or {})
        if not publication:
            raise ExtensionAuthorityError("admitted publication is unavailable")
        isolation = publication.get("isolation")
        if isinstance(isolation, Mapping) and str(isolation.get("state") or "") == "ISOLATED":
            raise ExtensionAuthorityError("admitted publication is isolated")
        default = dict((projection.get("defaults") or {}).get(slot_id) or {})
        if str(default.get("publication_id") or "") == publication_id and str(default.get("state") or "ACTIVE") == "ISOLATED":
            raise ExtensionAuthorityError("admitted publication is isolated")

    def record_publication_intent(
        self,
        *,
        request_id: str,
        slot: Mapping[str, Any] | ExtensionSlot | str,
        candidate_id: str,
        snapshot: Mapping[str, Any],
        source: Mapping[str, Any],
    ) -> EventEnvelope:
        """Persist the expected old default before the trial begins."""

        intent_id = self._publication_intent_request_id(str(request_id))
        existing = self._existing_request(intent_id)
        if existing is not None:
            if existing.event_type != "extension.publication-intent-recorded":
                raise ExtensionAuthorityConflict("publication intent request_id belongs to another extension fact")
            # Replay is resolved from the original canonical intent before any
            # snapshot/environment/default read.  In particular, the first
            # intent itself advances the Journal frontier, so sampling a new F
            # here would make an exact retry falsely conflict.
            supplied_snapshot = dict(snapshot) if isinstance(snapshot, Mapping) else {}
            supplied = {
                "slot": _normalize_slot(slot).as_dict(),
                "candidate_id": str(candidate_id),
                "snapshot_id": supplied_snapshot.get("snapshot_id"),
                "snapshot_hash": supplied_snapshot.get("snapshot_hash"),
                "location_binding": supplied_snapshot.get("location_binding"),
                "source": self._source_binding_view(source),
            }
            recorded = {
                key: existing.payload.get(key)
                for key in ("slot", "candidate_id", "snapshot_id", "snapshot_hash", "location_binding", "source")
            }
            if supplied != recorded:
                raise ExtensionAuthorityConflict("publication intent request_id was already used differently")
            return existing

        normalized = _normalize_slot(slot)
        if not isinstance(snapshot, Mapping) or snapshot.get("schema") != EXECUTION_SNAPSHOT_SCHEMA:
            raise ExtensionAuthorityError("publication intent requires an authenticated execution snapshot")
        current_snapshot = self.build_execution_snapshot(str(candidate_id)).as_dict()
        if any(snapshot.get(key) != current_snapshot.get(key) for key in (
            "snapshot_id", "snapshot_hash", "location_binding", "candidate_id"
        )):
            raise ExtensionAuthorityError("publication intent snapshot is stale or mismatched")
        self._assert_live_source_binding(source, str(current_snapshot.get("snapshot_id") or ""))
        if normalized.kind != str(current_snapshot.get("kind") or "") or normalized.name != str(current_snapshot.get("name") or ""):
            raise ExtensionAuthorityError("publication slot does not match the candidate kind/name")
        projection, position, _events = self._projection_at_read_position()
        prior = self._default_for_projection(projection, normalized)
        prior_payload = {
            "publication_id": (prior or {}).get("publication_id"),
            "snapshot_id": dict((prior or {}).get("publication") or {}).get("published", {}).get("snapshot_id")
            if prior else None,
            "stream_position": position,
        }
        payload = {
            "schema": PUBLICATION_INTENT_SCHEMA,
            "event_type": "extension.publication-intent-recorded",
            "publication_request_id": str(request_id),
            "slot": normalized.as_dict(),
            "candidate_id": str(candidate_id),
            "snapshot_id": current_snapshot.get("snapshot_id"),
            "snapshot_hash": current_snapshot.get("snapshot_hash"),
            "location_binding": current_snapshot.get("location_binding"),
            "source": self._source_binding_view(source),
            "expected_previous_default": prior_payload,
            "expected_stream_position": position,
        }
        return self._append_fact(request_id=intent_id, event_type="extension.publication-intent-recorded", payload=payload)

    def _existing_reference_proofs(self, references: Sequence[Any]) -> tuple[Any, ...]:
        if not hasattr(self.backend, "extension_existing_object_proof"):
            raise ExtensionAuthorityError("Loop Backend lacks durable CAS proof lookup")
        proofs = []
        for reference in sorted({str(item) for item in references if str(item)}):
            proofs.append(self.backend.extension_existing_object_proof(reference))
        return tuple(proofs)

    def _commit_publication_locked(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_id = str(request.get("request_id") or "")
        existing = self._existing_request(request_id) if request_id else None
        if existing is not None:
            if existing.event_type != "extension.publication-committed":
                raise ExtensionAuthorityConflict("request_id belongs to another extension fact")
            supplied_hash = _sha256_json(self._publication_request_view(request))
            if supplied_hash != existing.payload.get("publication_request_hash"):
                raise ExtensionAuthorityConflict("publication request_id was already used differently")
            return {
                "schema": PUBLICATION_COMMIT_SCHEMA,
                "publication_id": existing.payload.get("publication_id"),
                "request_id": request_id,
                "event_id": existing.event_id,
                "stream_version": existing.stream_version,
                "content_ref": existing.payload.get("content_ref"),
                "content_hash": existing.payload.get("content_hash"),
                "check_obligation": dict(existing.payload.get("check_obligation") or {}),
                "replayed": True,
            }
        normalized = _normalize_slot(request.get("slot") or {})
        source = dict(request.get("source") or {})
        candidate_id = str(request.get("candidate_id") or "")
        snapshot_id = str(request.get("snapshot_id") or "")
        if not candidate_id or not snapshot_id:
            raise ExtensionAuthorityError("publication request lacks candidate/snapshot identity")
        self._assert_live_source_binding(
            source,
            snapshot_id,
            publication_operation_id=str(request.get("_publication_operation_id") or "") or None,
        )
        current_snapshot = self.build_execution_snapshot(candidate_id).as_dict()
        if any(str(request.get(key) or "") != str(current_snapshot.get(key) or "") for key in (
            "snapshot_id", "snapshot_hash", "location_binding"
        )):
            raise ExtensionAuthorityError("publication snapshot is no longer current")
        if normalized.kind != str(current_snapshot.get("kind") or "") or normalized.name != str(current_snapshot.get("name") or ""):
            raise ExtensionAuthorityError("publication slot does not match the authenticated candidate")
        projection, position, _events = self._projection_at_read_position()
        current = self._default_for_projection(projection, normalized)
        expected = dict(request.get("expected_previous_default") or {})
        current_id = (current or {}).get("publication_id")
        if current_id != expected.get("publication_id"):
            raise ExtensionAuthorityConflict("default publication changed after the publication intent")
        trial_request_id = str(request.get("trial_request_id") or "")
        trial_event = self._existing_request(trial_request_id) if trial_request_id else None
        if trial_event is None or trial_event.event_type != "extension.trial-recorded":
            raise ExtensionAuthorityError("publication requires a persisted trial event")
        if str(trial_event.event_id) != str(request.get("trial_event_id") or ""):
            raise ExtensionAuthorityError("publication trial event identity differs from the request")
        trial = dict(trial_event.payload)
        if trial.get("applicability") != "CURRENT_TASK_INPUT":
            raise ExtensionAuthorityError("publication trial is not current task evidence")
        if any(str(trial.get(key) or "") != str(request.get(key) or "") for key in (
            "candidate_id", "snapshot_id", "snapshot_hash"
        )):
            raise ExtensionAuthorityError("publication trial does not match its candidate snapshot")
        if str(trial.get("operation_id") or "") != str(request.get("operation_id") or ""):
            raise ExtensionAuthorityError("publication trial operation differs from the request")
        intent_event = self._existing_request(self._publication_intent_request_id(str(request.get("request_id") or "")))
        if intent_event is None or intent_event.event_type != "extension.publication-intent-recorded":
            raise ExtensionAuthorityError("publication intent was not persisted before trial")
        source_task = self.backend.get_task(str(source.get("task_id") or ""))
        operation = source_task.operations.get(str(request.get("operation_id") or ""))
        if operation is None or operation.result_ref is None or operation.unknown_effect:
            raise ExtensionAuthorityError("publication operation is not a settled known result")
        if operation.effect_status.value != "SUCCEEDED":
            raise ExtensionAuthorityError("publication operation did not succeed")
        if not operation.intent_ref:
            raise ExtensionAuthorityError("publication operation intent is unavailable")
        operation_intent = dict(self.backend.context_memory.read(str(operation.intent_ref)))
        operation_intent_event = next(
            (
                event for event in self.backend.store.task_events(source_task.task_id)
                if event.event_type == "loop.operation-intent-recorded"
                and event.payload.get("operation_id") == operation.operation_id
            ),
            None,
        )
        if operation_intent_event is None:
            raise ExtensionAuthorityError("publication operation intent event is unavailable")
        # Journal positions are the authoritative cross-stream ordering.  Keep
        # the occurred-at comparison as a defensive tie-breaker for stores that
        # expose equal positions during recovery.
        if (
            int(intent_event.position) > int(operation_intent_event.position)
            or (
                int(intent_event.position) == int(operation_intent_event.position)
                and str(intent_event.occurred_at) > str(operation_intent_event.occurred_at)
            )
        ):
            raise ExtensionAuthorityError("publication intent was recorded after trial operation dispatch")
        trial_task = dict(trial.get("task") or {})
        core_source_keys = (
            "task_id", "session_id", "run_instance_id", "execution_epoch",
            "goal_version", "acceptance_version", "received_input_seq",
            "handled_input_seq", "artifact_ref",
        )
        if any(trial_task.get(key) != source.get(key) for key in core_source_keys):
            raise ExtensionAuthorityError("publication trial task binding differs from its source task")
        if trial.get("operation_result_ref") != operation.result_ref:
            raise ExtensionAuthorityError("publication trial result ref differs from the task operation")
        if operation_intent.get("capability_snapshot_id") != request.get("snapshot_id"):
            raise ExtensionAuthorityError("publication operation intent uses another snapshot")
        operation_result = dict(self.backend.context_memory.read(str(operation.result_ref)))
        persisted_result = operation_result.get("result") if isinstance(operation_result.get("result"), Mapping) else operation_result
        if not isinstance(persisted_result, Mapping) or persisted_result.get("status") != "ok":
            raise ExtensionAuthorityError("publication operation result is not a successful consumer result")
        intent = dict(intent_event.payload)
        for key in ("slot", "candidate_id", "snapshot_id", "snapshot_hash", "location_binding", "source", "expected_previous_default", "expected_stream_position"):
            if intent.get(key) != request.get(key):
                raise ExtensionAuthorityConflict("publication request differs from its pre-trial intent")
        candidate = dict(self.candidate(candidate_id))
        # ``candidate()`` returns the authenticated manifest itself; the
        # manifest-root CAS proof is carried by the authoritative projection
        # record that pointed to it.
        candidate_record = dict(self.load_projection().get("candidates", {}).get(candidate_id) or {})
        candidate_manifest_ref = candidate_record.get("candidate_manifest_ref") or candidate_record.get("manifest_ref")
        candidate_manifest_hash = candidate_record.get("candidate_manifest_hash") or candidate_record.get("manifest_hash")
        if not isinstance(candidate_manifest_ref, str) or not candidate_manifest_ref.startswith("cas:"):
            raise ExtensionAuthorityError("candidate projection lacks its durable manifest root")
        publication_request_hash = _sha256_json(self._publication_request_view(request))
        publication_id = "publication-" + hashlib.sha256(
            (str(request.get("request_id") or "") + "\0" + publication_request_hash).encode("utf-8")
        ).hexdigest()[:40]
        obligation_id = f"{publication_id}:default-consumer-check:v1"
        published = {
            "capability_id": candidate.get("capability_id"),
            "candidate_id": candidate_id,
            "snapshot_id": snapshot_id,
            "snapshot_hash": request.get("snapshot_hash"),
            "location_binding": request.get("location_binding"),
        }
        method_plan_ref = str(operation_intent.get("effect_evidence_ref") or "")
        if not method_plan_ref:
            raise ExtensionAuthorityError("publication operation lacks persisted method-plan evidence")
        evidence_refs = (
            candidate_manifest_ref,
            trial.get("operation_result_ref"),
            method_plan_ref,
            dict(trial.get("consumer_receipt") or {}).get("reference"),
            trial_event.payload.get("content_ref"),
            intent_event.payload.get("content_ref"),
        )
        payload = {
            "schema": PUBLICATION_COMMIT_SCHEMA,
            "event_type": "extension.publication-committed",
            "publication_request_hash": publication_request_hash,
            "publication_id": publication_id,
            "slot": normalized.as_dict(),
            "previous_default": expected,
            "published": published,
            "source": source,
            "trial": {
                "trial_request_id": trial_request_id,
                "trial_event_id": trial_event.event_id,
                "operation_id": request.get("operation_id"),
                "operation_result_ref": trial.get("operation_result_ref"),
                "receipt_ref": dict(trial.get("consumer_receipt") or {}).get("reference"),
                "receipt_hash": dict(trial.get("consumer_receipt") or {}).get("hash"),
                "applicability": trial.get("applicability"),
                "method_id": dict(trial.get("method") or {}).get("method_id"),
            },
            "evidence": {
                "candidate_manifest_ref": candidate_manifest_ref,
                "candidate_manifest_hash": candidate_manifest_hash,
                "snapshot_hash": request.get("snapshot_hash"),
                "method_plan_ref": method_plan_ref,
                "raw_result_ref": trial.get("operation_result_ref"),
            },
            "source_task_id": source.get("task_id"),
            "expected_stream_position": position,
            "check_obligation": {
                "schema": PUBLICATION_CHECK_OBLIGATION_SCHEMA,
                "obligation_id": obligation_id,
                "type": "ordinary-new-session-consumer-check",
                "required_publication_id": publication_id,
                "required_snapshot_id": snapshot_id,
                "state": "PENDING",
            },
        }
        event = self._append_fact(
            request_id=str(request.get("request_id") or ""),
            event_type="extension.publication-committed",
            payload=payload,
            referenced_proofs=self._existing_reference_proofs(evidence_refs),
        )
        return {
            "schema": PUBLICATION_COMMIT_SCHEMA,
            "publication_id": publication_id,
            "request_id": request.get("request_id"),
            "event_id": event.event_id,
            "stream_version": event.stream_version,
            "content_ref": event.payload.get("content_ref"),
            "content_hash": event.payload.get("content_hash"),
            "check_obligation": dict(payload["check_obligation"]),
        }

    def commit_publication(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Commit one default publication through the Backend coordination lock."""

        if not isinstance(request, Mapping):
            raise ExtensionAuthorityError("publication request must be an object")
        request_id = str(request.get("request_id") or "")
        if not request_id:
            raise ExtensionAuthorityError("publication request_id is required")
        existing = self._existing_request(request_id)
        if existing is not None:
            if existing.event_type != "extension.publication-committed":
                raise ExtensionAuthorityConflict("request_id belongs to another extension fact")
            supplied_keys = set(request).intersection({
                "slot", "candidate_id", "snapshot_id", "snapshot_hash", "location_binding",
                "source", "trial_request_id", "trial_event_id", "operation_id",
                "expected_previous_default", "expected_stream_position",
            })
            if supplied_keys:
                canonical_existing = dict(request)
                if "slot" in canonical_existing:
                    canonical_existing["slot"] = _normalize_slot(canonical_existing["slot"]).as_dict()
                supplied_hash = _sha256_json(self._publication_request_view(canonical_existing))
                if supplied_hash != existing.payload.get("publication_request_hash"):
                    raise ExtensionAuthorityConflict("publication request_id was already used differently")
            obligation = dict(existing.payload.get("check_obligation") or {})
            return {
                "schema": PUBLICATION_COMMIT_SCHEMA,
                "publication_id": existing.payload.get("publication_id"),
                "request_id": request_id,
                "event_id": existing.event_id,
                "stream_version": existing.stream_version,
                "content_ref": existing.payload.get("content_ref"),
                "content_hash": existing.payload.get("content_hash"),
                "check_obligation": obligation,
                "replayed": True,
            }
        canonical = dict(request)
        canonical["slot"] = _normalize_slot(request.get("slot") or {}).as_dict()
        source = dict(canonical.get("source") or {})
        source_task_id = str(source.get("task_id") or "")
        snapshot_id = str(canonical.get("snapshot_id") or "")
        if not source_task_id or not snapshot_id:
            raise ExtensionAuthorityError("publication request lacks its Backend source binding")
        if not hasattr(self.backend, "execute_extension_publication"):
            raise ExtensionAuthorityError("Loop Backend lacks the publication WRITE bridge")

        def dispatch(publication_operation_id: str) -> Mapping[str, Any]:
            return self._commit_publication_locked(
                {
                    **canonical,
                    "request_id": request_id,
                    "_publication_operation_id": publication_operation_id,
                }
            )

        def replay_check() -> Mapping[str, Any] | None:
            # Recheck after the Backend WRITE lane is acquired.  The outer
            # fast path is intentionally only an optimization; concurrent
            # callers may both have observed an empty stream before one
            # appends.
            existing_locked = self._existing_request(request_id)
            if existing_locked is None:
                return None
            if existing_locked.event_type != "extension.publication-committed":
                raise ExtensionAuthorityConflict("request_id belongs to another extension fact")
            supplied_keys = set(request).intersection({
                "slot", "candidate_id", "snapshot_id", "snapshot_hash", "location_binding",
                "source", "trial_request_id", "trial_event_id", "operation_id",
                "expected_previous_default", "expected_stream_position",
            })
            if supplied_keys and _sha256_json(self._publication_request_view(canonical)) != existing_locked.payload.get("publication_request_hash"):
                raise ExtensionAuthorityConflict("publication request_id was already used differently")
            return {
                "replayed": True,
                "schema": PUBLICATION_COMMIT_SCHEMA,
                "publication_id": existing_locked.payload.get("publication_id"),
                "request_id": request_id,
                "event_id": existing_locked.event_id,
                "stream_version": existing_locked.stream_version,
                "content_ref": existing_locked.payload.get("content_ref"),
                "content_hash": existing_locked.payload.get("content_hash"),
                "check_obligation": dict(existing_locked.payload.get("check_obligation") or {}),
            }

        execution_result = self.backend.execute_extension_publication(
            source_task_id,
            request_id,
            self.extension_root,
            snapshot_id,
            dispatch,
            replay_check=replay_check,
            logical_operation_id=(
                str(request.get("_logical_operation_id") or "") or None
            ),
            business_attempt_id=(
                str(request.get("_business_attempt_id") or "") or None
            ),
            call_id=(str(request.get("_call_id") or "") or None),
        )
        if isinstance(execution_result, Mapping):
            return execution_result
        outcome, _operation_id = execution_result
        if str(getattr(outcome.status, "value", outcome.status)) != "SUCCEEDED":
            reason = str(dict(outcome.result or {}).get("error_message") or "publication WRITE operation failed")
            raise ExtensionAuthorityError(reason)
        publication = dict(dict(outcome.result or {}).get("publication") or {})
        if not publication:
            raise ExtensionAuthorityError("publication WRITE operation returned no decision")
        return publication

    def _publication_failure_observation(
        self,
        *,
        request_id: str,
        source: Mapping[str, Any],
        reason: str,
        evidence_content: Any | None = None,
    ) -> EventEnvelope:
        """Persist a producer-derived, non-isolating failure observation."""

        payload = {
            "schema": PUBLICATION_FAILURE_OBSERVATION_SCHEMA,
            "event_type": "extension.publication-failure-observed",
            "source": dict(source),
            "state": "PENDING_REVIEW",
            "resolution": "PENDING_REVIEW",
            "reason": str(reason),
        }
        refs = ()
        if evidence_content is not None:
            payload["evidence"] = {
                "reference": evidence_content.reference_id,
                "hash": evidence_content.content_hash,
            }
            # The evidence was just persisted and is not rooted by an earlier
            # Journal frame.  _append_fact receives its fresh proof directly
            # through referenced_contents below.
        return self._append_fact(
            request_id=request_id,
            event_type="extension.publication-failure-observed",
            payload=payload,
            referenced_contents=((evidence_content,) if evidence_content is not None else ()),
            referenced_proofs=refs,
        )

    def _persist_publication_failure_evidence(self, value: Mapping[str, Any]) -> Any:
        """Persist bounded failure evidence in the shared CAS before Journal append."""

        return self.backend.context_memory.persist(
            _canonical_evidence_value({
                "schema": PUBLICATION_FAILURE_EVIDENCE_SCHEMA,
                **dict(value),
            }),
            purpose="sitina-extension-publication-failure-evidence",
        )

    def record_publication_failure_from_task(self, task_id: str, operation_id: str) -> EventEnvelope | None:
        """Reconstruct one fixed-consumer failure using only task/operation identity.

        The producer derives applicability, completion trust, and failure kind
        from the immutable descriptor, operation intent/result, method plan,
        and the original publication fact.  Callers cannot provide a failure
        label, F, ``confirmed`` flag, or result body.
        """

        task_id = str(task_id or "")
        operation_id = str(operation_id or "")
        if not task_id or not operation_id:
            raise ExtensionAuthorityError("publication failure task and operation identities are required")
        request_id = f"publication-failure:{task_id}:{operation_id}"
        existing = self._existing_request(request_id)
        if existing is not None:
            if existing.event_type not in {
                "extension.publication-failure-observed",
                "extension.publication-failure-reconciled",
            }:
                raise ExtensionAuthorityConflict("publication failure request belongs to another extension fact")
            return existing

        task = self.backend.get_task(task_id)
        if not task.descriptor_ref or not task.descriptor_hash:
            return None
        try:
            descriptor = dict(
                self.backend.context_memory.read(
                    str(task.descriptor_ref), expected_hash=str(task.descriptor_hash)
                )
            )
        except Exception:
            return None
        binding = descriptor.get("capability_binding")
        if not isinstance(binding, Mapping) or not str(binding.get("publication_id") or ""):
            return None
        publication_id = str(binding.get("publication_id") or "")
        publication_event = next(
            (
                event for event in self._journal_events()
                if event.event_type == "extension.publication-committed"
                and str(event.payload.get("publication_id") or "") == publication_id
            ),
            None,
        )
        if publication_event is None:
            return None
        operation = task.operations.get(operation_id)
        if operation is None or not operation.intent_ref or not operation.result_ref:
            return None
        try:
            operation_intent = dict(self.backend.context_memory.read(str(operation.intent_ref)))
            effect_evidence = dict(
                self.backend.context_memory.read(str(operation_intent.get("effect_evidence_ref") or ""))
            )
            result_document = dict(self.backend.context_memory.read(str(operation.result_ref)))
        except Exception:
            return None
        method_plan = effect_evidence.get("method_plan")
        if not isinstance(method_plan, Mapping):
            method_plan = effect_evidence
        if method_plan.get("method_plan_schema") != "SITINA_EXTENSION_METHOD_PLAN_V1":
            return None
        if str(effect_evidence.get("consumer_dispatch") or "") not in {
            "skill-resource-reader", "plugin-command-runner",
        }:
            return None
        if str(operation_intent.get("capability_snapshot_id") or "") != str(binding.get("snapshot_id") or ""):
            return None
        raw_result = result_document.get("result")
        if not isinstance(raw_result, Mapping):
            return None
        raw_result = dict(raw_result)
        if raw_result.get("status") == "ok" and raw_result.get("program_status") in {None, "PASS"}:
            # The C3a success hook owns ordinary PASS settlement.  A normal
            # successful consumer is not a failure observation.
            return None
        source = {
            "schema": PUBLICATION_FAILURE_EVIDENCE_SCHEMA,
            "kind": "DEFAULT_CONSUMER_CHECK_FAILED",
            "task_id": task_id,
            "operation_id": operation_id,
            "publication_id": publication_id,
            "snapshot_id": str(binding.get("snapshot_id") or ""),
            "slot": dict(publication_event.payload.get("slot") or {}),
            "binding": {
                "publication_id": binding.get("publication_id"),
                "snapshot_id": binding.get("snapshot_id"),
                "snapshot_hash": binding.get("snapshot_hash"),
                "read_position": binding.get("read_position"),
            },
            "operation": {
                "intent_ref": operation.intent_ref,
                "result_ref": operation.result_ref,
                "effect_status": operation.effect_status.value,
                "unknown_effect": bool(operation.unknown_effect),
            },
            "method": {
                "method_schema": method_plan.get("method_schema"),
                "method_id": method_plan.get("method_id"),
                "input_hash": _sha256_json(method_plan.get("arguments") or {}),
                "contract_hash": _sha256_json(method_plan.get("method_contract") or {}),
            },
            "result": {
                "reference": operation.result_ref,
                "evaluation": "CONTRACT_MISMATCH",
                "status": raw_result.get("status"),
                "program_status": raw_result.get("program_status"),
            },
        }

        # Historical binding/F and original method/input must match before a
        # failure may be attributed to this publication.
        try:
            self.verify_capability_binding(binding, historical_only=True)
            original_method_ref = str(dict(publication_event.payload.get("evidence") or {}).get("method_plan_ref") or "")
            original_evidence = dict(self.backend.context_memory.read(original_method_ref))
            original_plan = original_evidence.get("method_plan") if isinstance(original_evidence.get("method_plan"), Mapping) else original_evidence
            if self._publication_check_method_view(original_plan) != self._publication_check_method_view(method_plan):
                raise PublicationCheckNotApplicable("consumer method/input differs from published trial")
        except Exception as error:
            evidence_content = self._persist_publication_failure_evidence({**source, "reason": str(error)})
            return self._publication_failure_observation(
                request_id=request_id,
                source=source,
                reason="binding-or-method-not-applicable",
                evidence_content=evidence_content,
            )

        # Operation and physical completion are separate from method result.
        # Plugin contract failures can therefore be SUCCEEDED/exit0 physically
        # while program_status is FAIL and no success receipt exists.
        if operation.unknown_effect or operation.effect_status.value == "UNKNOWN":
            evidence_content = self._persist_publication_failure_evidence({**source, "reason": "unknown-effect"})
            return self._publication_failure_observation(
                request_id=request_id,
                source=source,
                reason="unknown-effect",
                evidence_content=evidence_content,
            )
        contract = method_plan.get("method_contract")
        contract_kind = str(contract.get("kind") or "") if isinstance(contract, Mapping) else ""
        completion_proof = None
        if contract_kind == "plugin-command":
            try:
                from sitina.loop.command_runner import observe_command_evidence

                completion_observation = observe_command_evidence(
                    effect_evidence,
                    task_id=task_id,
                    operation_id=operation_id,
                )
            except Exception as error:
                completion_observation = {"decision": "UNKNOWN", "reason": type(error).__name__}
            if str(completion_observation.get("decision") or "") != "SUCCEEDED":
                evidence_content = self._persist_publication_failure_evidence({
                    **source,
                    "completion": {"decision": completion_observation.get("decision"), "reason": completion_observation.get("reason")},
                })
                return self._publication_failure_observation(
                    request_id=request_id,
                    source=source,
                    reason="completion-untrusted",
                    evidence_content=evidence_content,
                )
            completion = dict(completion_observation.get("completion") or {})
            source["completion"] = {
                "status": completion.get("status"),
                "exit_code": completion.get("exit_code"),
                "source_path": raw_result.get("completion_ref"),
                "source_hash": raw_result.get("completion_hash"),
                "manifest_path": raw_result.get("manifest_ref"),
                "manifest_hash": raw_result.get("manifest_hash"),
            }
            if (
                completion.get("status") != "COMPLETED"
                or completion.get("exit_code") != 0
                or raw_result.get("effect_settled") is not True
                or str(raw_result.get("completion_hash") or "") != str(completion_observation.get("completion_hash") or "")
            ):
                evidence_content = self._persist_publication_failure_evidence({**source, "reason": "failure-not-applicable"})
                return self._publication_failure_observation(
                    request_id=request_id,
                    source=source,
                    reason="failure-not-applicable",
                    evidence_content=evidence_content,
                )
            # Re-evaluate the registered Plugin contract from the verified
            # stdout rather than trusting ``program_status`` or an arbitrary
            # result label.  This covers the real invalid-JSON/schema-mismatch
            # path where the operation is physically FAILED and no program
            # status field is emitted.
            output_text = str(completion_observation.get("stdout") or "")
            observed_output: Any = output_text
            contract_failure = False
            if bool(contract.get("output_json", True)):
                try:
                    observed_output = json.loads(output_text or "null")
                except json.JSONDecodeError:
                    contract_failure = True
            output_schema = contract.get("output_schema")
            if not contract_failure and isinstance(output_schema, Mapping):
                try:
                    from sitina.runners.mcp_adapter import validate_json_schema

                    validate_json_schema(observed_output, dict(output_schema))
                except Exception:
                    contract_failure = True
            expected = contract.get("expected_output")
            if not contract_failure and expected is not None and observed_output != expected:
                contract_failure = True
            if not contract_failure:
                evidence_content = self._persist_publication_failure_evidence({
                    **source,
                    "reason": "completion-known-but-method-contract-did-not-prove-failure",
                })
                return self._publication_failure_observation(
                    request_id=request_id,
                    source=source,
                    reason="method-contract-failure-not-proven",
                    evidence_content=evidence_content,
                )
            source["result"]["evaluation"] = "CONTRACT_MISMATCH"
            source["result"]["observed_output"] = observed_output
            completion_proof = self.backend.context_memory.persist(
                _canonical_evidence_value({
                    "schema": PUBLICATION_FAILURE_COMPLETION_PROOF_SCHEMA,
                    "task_id": task_id,
                    "operation_id": operation_id,
                    "manifest_hash": completion_observation.get("manifest_hash"),
                    # Preserve the verifier's exact private protocol bytes
                    # and hashes; do not reserialize manifests/completions
                    # (which contain runtime floats such as timestamps).
                    "manifest_raw_b64": completion_observation.get("manifest_raw_b64"),
                    "completion_raw_b64": completion_observation.get("completion_raw_b64"),
                    "completion_hash": completion_observation.get("completion_hash"),
                    "stdout_hash": completion_observation.get("stdout_hash"),
                    "stderr_hash": completion_observation.get("stderr_hash"),
                    "completion_status": completion.get("status"),
                    "exit_code": completion.get("exit_code"),
                    "stdout_bytes": completion.get("stdout_bytes"),
                    "stderr_bytes": completion.get("stderr_bytes"),
                    "stdout_retained_bytes": completion.get("stdout_retained_bytes"),
                    "stderr_retained_bytes": completion.get("stderr_retained_bytes"),
                }),
                purpose="sitina-extension-failure-completion-proof",
            )
            source["completion"]["proof_ref"] = completion_proof.reference_id
            source["completion"]["proof_hash"] = completion_proof.content_hash
        elif raw_result.get("status") != "error" or raw_result.get("effect_settled") is not True:
            evidence_content = self._persist_publication_failure_evidence({**source, "reason": "failure-not-applicable"})
            return self._publication_failure_observation(
                request_id=request_id,
                source=source,
                reason="failure-not-applicable",
                evidence_content=evidence_content,
            )

        evidence_content = self._persist_publication_failure_evidence(source)
        obligation_id = f"{publication_id}:default-action:v1"
        failed_publication = {
            "slot_id": dict(publication_event.payload.get("slot") or {}).get("slot_id"),
            "publication_id": publication_id,
            "snapshot_id": binding.get("snapshot_id"),
            "read_position": binding.get("read_position"),
        }
        payload = {
            "schema": PUBLICATION_FAILURE_RECONCILIATION_SCHEMA,
            "event_type": "extension.publication-failure-reconciled",
            "failure_source": {
                "schema": PUBLICATION_FAILURE_EVIDENCE_SCHEMA,
                "reference": evidence_content.reference_id,
                "hash": evidence_content.content_hash,
            },
            "failed_publication": failed_publication,
            "isolation": {
                "state": "ISOLATED",
                "publication_id": publication_id,
                "reason": "CONFIRMED_CONTRACT_FAILURE",
            },
            "default_action_obligation": {
                "obligation_id": obligation_id,
                "type": "CONDITIONAL_DEFAULT_ACTION",
                "expected_current_publication_id": publication_id,
                "state": "PENDING",
            },
            "replacement_default": None,
            "resolution": "PENDING_CONDITIONAL_ACTION",
            "source": {
                "task_id": task_id,
                "operation_id": operation_id,
                "publication_id": publication_id,
            },
        }
        refs = [
            task.descriptor_ref,
            operation.intent_ref,
            operation.result_ref,
            str(dict(publication_event.payload.get("evidence") or {}).get("method_plan_ref") or ""),
        ]
        # Newly persisted evidence is supplied to _append_fact as
        # referenced_contents below; its own CAS proof must be used directly,
        # rather than looked up as an already-rooted Journal object.
        return self._append_fact(
            request_id=request_id,
            event_type="extension.publication-failure-reconciled",
            payload=payload,
            referenced_contents=tuple(
                item for item in (evidence_content, completion_proof) if item is not None
            ),
            referenced_proofs=self._existing_reference_proofs(tuple(refs)),
        )

    def _publication_failure_action_event_for_obligation(
        self, obligation_id: str
    ) -> EventEnvelope | None:
        """Return the one terminal action decision for a failure obligation."""

        matches: list[EventEnvelope] = []
        for event in self._journal_events():
            payload = dict(event.payload)
            if event.event_type == "extension.publication-failure-actioned":
                if str(payload.get("obligation_id") or "") == str(obligation_id):
                    matches.append(event)
            elif event.event_type == "extension.publication-committed":
                action = dict(payload.get("failure_action") or {})
                if str(action.get("obligation_id") or "") == str(obligation_id):
                    matches.append(event)
        if len(matches) > 1:
            raise ExtensionAuthorityError("one publication failure obligation has multiple action decisions")
        return matches[0] if matches else None

    @staticmethod
    def _publication_failure_action_result(
        event: EventEnvelope,
        *,
        replayed: bool,
    ) -> dict[str, Any]:
        payload = dict(event.payload)
        action = dict(payload.get("failure_action") or payload.get("action") or {})
        return {
            "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
            "status": str(action.get("state") or "COMPLETED").lower(),
            "resolution": str(action.get("resolution") or payload.get("resolution") or "COMPLETED"),
            "replayed": bool(replayed),
            "event_id": event.event_id,
            "stream_version": event.stream_version,
            "request_id": payload.get("request_id"),
            "obligation_id": payload.get("obligation_id") or action.get("obligation_id"),
            "publication_id": payload.get("publication_id"),
            "check_obligation": dict(payload.get("check_obligation") or {}),
            "repair_obligation": dict(payload.get("repair_obligation") or {}),
            "action": action,
        }

    def _recovery_publication_reference_ids(
        self,
        publication: Mapping[str, Any],
        projection: Mapping[str, Any],
    ) -> tuple[str, ...]:
        evidence = dict(publication.get("evidence") or {})
        refs = [
            evidence.get("candidate_manifest_ref"),
            evidence.get("method_plan_ref"),
            evidence.get("raw_result_ref"),
            publication.get("content_ref"),
        ]
        published = dict(publication.get("published") or {})
        candidate_id = str(published.get("candidate_id") or "")
        candidate_record = dict((projection.get("candidates") or {}).get(candidate_id) or {})
        refs.append(candidate_record.get("candidate_manifest_ref") or candidate_record.get("manifest_ref"))
        return tuple(str(ref) for ref in refs if str(ref))

    def _available_previous_publication(
        self,
        publication: Mapping[str, Any],
        projection: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Return (P, current snapshot) only when P's fixed method is usable."""

        if not isinstance(publication, Mapping):
            return None
        publication = dict(publication)
        isolation = publication.get("isolation")
        if isinstance(isolation, Mapping) and str(isolation.get("state") or "") == "ISOLATED":
            return None
        published = dict(publication.get("published") or {})
        candidate_id = str(published.get("candidate_id") or "")
        if not candidate_id:
            return None
        snapshot_id = str(published.get("snapshot_id") or "")
        # A confirmed isolation of the same immutable snapshot is sufficient
        # to disqualify P even when the isolated publication is not P itself.
        for other in (projection.get("publications") or {}).values():
            if not isinstance(other, Mapping):
                continue
            other_published = dict(other.get("published") or {})
            other_isolation = other.get("isolation")
            if (
                str(other_published.get("snapshot_id") or "") == snapshot_id
                and isinstance(other_isolation, Mapping)
                and str(other_isolation.get("state") or "") == "ISOLATED"
            ):
                return None
        try:
            snapshot = self.build_execution_snapshot(candidate_id).as_dict()
        except (CandidatePreparationError, FileNotFoundError):
            return None
        for key in ("snapshot_id", "snapshot_hash", "location_binding"):
            if str(snapshot.get(key) or "") != str(published.get(key) or ""):
                return None
        refs = self._recovery_publication_reference_ids(publication, projection)
        # Recovery must preserve the method/evidence roots used by the normal
        # C3a checker; missing roots make P unavailable rather than inventing
        # an unverified replacement.
        evidence = dict(publication.get("evidence") or {})
        if not str(evidence.get("method_plan_ref") or ""):
            return None
        try:
            for reference in refs:
                self.backend.extension_existing_object_proof(reference)
        except (CandidatePreparationError, FileNotFoundError, KeyError):
            return None
        return publication, snapshot

    def _append_failure_action_locked(
        self,
        *,
        obligation_id: str,
        request_id: str,
        action_request_hash: str,
        slot_id: str,
        failed_publication_id: str,
        owner_id: str,
        operation_id: str,
        current_default: Mapping[str, Any] | None,
        resolution: str,
        disposition: str,
        repair_obligation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
            "event_type": "extension.publication-failure-actioned",
            "action_request_hash": action_request_hash,
            "obligation_id": obligation_id,
            "slot_id": slot_id,
            "failed_publication_id": failed_publication_id,
            "expected_current_publication_id": failed_publication_id,
            "default_action_obligation": {
                "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
                "obligation_id": obligation_id,
                "type": "CONDITIONAL_DEFAULT_ACTION",
                "expected_current_publication_id": failed_publication_id,
                "state": "COMPLETED",
                "resolution": resolution,
            },
            "action": {
                "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
                "obligation_id": obligation_id,
                "state": "COMPLETED",
                "resolution": resolution,
                "disposition": disposition,
                "failed_publication_id": failed_publication_id,
                "owner_id": owner_id,
                "operation_id": operation_id,
                "request_id": request_id,
            },
            "current_default": dict(current_default or {}),
            "repair_obligation": dict(repair_obligation or {}),
        }
        event = self._append_fact(
            request_id=request_id,
            event_type="extension.publication-failure-actioned",
            payload=payload,
        )
        return self._publication_failure_action_result(event, replayed=False)

    def _process_publication_failure_obligation_locked(
        self,
        obligation_id: str,
        request_id: str,
        *,
        owner_id: str,
        operation_id: str,
    ) -> dict[str, Any]:
        """Settle one C3b-1 default-action obligation under Backend lock."""

        obligation_id = str(obligation_id or "")
        request_id = str(request_id or "")
        if not obligation_id or not request_id:
            raise ExtensionAuthorityError("publication failure obligation and request_id are required")
        action_identity = {"obligation_id": obligation_id}
        action_request_hash = _sha256_json(action_identity)
        existing = self._existing_request(request_id)
        if existing is not None:
            if existing.event_type not in {
                "extension.publication-failure-actioned",
                "extension.publication-committed",
            }:
                raise ExtensionAuthorityConflict("failure action request_id belongs to another extension fact")
            payload = dict(existing.payload)
            recorded_hash = str(payload.get("action_request_hash") or "")
            recorded_obligation = str(payload.get("obligation_id") or dict(payload.get("failure_action") or {}).get("obligation_id") or "")
            if recorded_obligation != obligation_id or (recorded_hash and recorded_hash != action_request_hash):
                raise ExtensionAuthorityConflict("failure action request_id was already used differently")
            return self._publication_failure_action_result(existing, replayed=True)

        prior = self._publication_failure_action_event_for_obligation(obligation_id)
        if prior is not None:
            return self._publication_failure_action_result(prior, replayed=True)

        projection = self.load_projection()
        obligation = dict((projection.get("obligations") or {}).get(obligation_id) or {})
        if not obligation:
            raise ExtensionAuthorityError("publication failure obligation is not present in the authoritative Journal")
        if str(obligation.get("state") or "PENDING") not in {"PENDING", "PENDING_REVIEW"}:
            raise ExtensionAuthorityError("publication failure obligation is not pending")
        source_event = next(
            (
                event for event in reversed(self._journal_events())
                if event.event_type == "extension.publication-failure-reconciled"
                and str(dict(event.payload.get("default_action_obligation") or {}).get("obligation_id") or "") == obligation_id
            ),
            None,
        )
        if source_event is None:
            raise ExtensionAuthorityError("publication failure obligation lacks its reconciliation source")
        source_payload = dict(source_event.payload)
        failed = dict(source_payload.get("failed_publication") or {})
        slot_id = str(failed.get("slot_id") or obligation.get("slot_id") or "")
        failed_publication_id = str(failed.get("publication_id") or obligation.get("publication_id") or "")
        if not slot_id or not failed_publication_id:
            raise ExtensionAuthorityError("publication failure obligation lacks slot/publication binding")
        defaults = projection.get("defaults") if isinstance(projection.get("defaults"), Mapping) else {}
        current_default = dict(defaults.get(slot_id) or {})
        current_id = str(current_default.get("publication_id") or "")

        # A later B wins.  The action only settles A's obligation and leaves
        # B's publication/default/check state untouched.
        if current_id and current_id != failed_publication_id:
            return self._append_failure_action_locked(
                obligation_id=obligation_id,
                request_id=request_id,
                action_request_hash=action_request_hash,
                slot_id=slot_id,
                failed_publication_id=failed_publication_id,
                owner_id=owner_id,
                operation_id=operation_id,
                current_default=current_default,
                resolution="PROTECTED_LATER_DEFAULT",
                disposition="LATER_DEFAULT_PROTECTED",
            )

        publications = projection.get("publications") if isinstance(projection.get("publications"), Mapping) else {}
        failed_publication = dict(publications.get(failed_publication_id) or {})
        if not failed_publication:
            raise ExtensionAuthorityError("failed publication is not present in the authoritative Journal")
        if current_id == failed_publication_id:
            current_isolation = failed_publication.get("isolation")
            current_state = str(current_default.get("state") or "ACTIVE")
            if current_state != "ISOLATED" and not (
                isinstance(current_isolation, Mapping)
                and str(current_isolation.get("state") or "") == "ISOLATED"
            ):
                raise ExtensionAuthorityConflict("failed publication is no longer isolated at the current default")

        previous = dict(failed_publication.get("previous_default") or {})
        previous_id = str(previous.get("publication_id") or "")
        previous_publication = dict(publications.get(previous_id) or {}) if previous_id else {}
        available = self._available_previous_publication(previous_publication, projection) if previous_publication else None
        if available is not None and current_id == failed_publication_id:
            previous_publication, snapshot = available
            published = dict(previous_publication.get("published") or {})
            publication_request_hash = _sha256_json({
                "obligation_id": obligation_id,
                "request_id": request_id,
                "failed_publication_id": failed_publication_id,
                "previous_publication_id": previous_id,
                "snapshot_id": snapshot.get("snapshot_id"),
            })
            publication_id = "publication-recovery-" + hashlib.sha256(
                (request_id + "\0" + publication_request_hash).encode("utf-8")
            ).hexdigest()[:40]
            recovery_action = {
                "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
                "obligation_id": obligation_id,
                "state": "COMPLETED",
                "resolution": "RESTORED_PREVIOUS_DEFAULT",
                "disposition": "RESTORED_PREVIOUS_DEFAULT_AS_NEW_PUBLICATION",
                "failed_publication_id": failed_publication_id,
                "restored_publication_id": previous_id,
                "owner_id": owner_id,
                "operation_id": operation_id,
                "request_id": request_id,
            }
            check_obligation_id = f"{publication_id}:default-consumer-check:v1"
            position = self._stream_position(self._journal_events())
            payload = {
                "schema": PUBLICATION_COMMIT_SCHEMA,
                "event_type": "extension.publication-committed",
                "publication_request_hash": publication_request_hash,
                "action_request_hash": action_request_hash,
                "publication_id": publication_id,
                "slot": dict(previous_publication.get("slot") or {"schema": SLOT_SCHEMA, "slot_id": slot_id}),
                "previous_default": {
                    "publication_id": failed_publication_id,
                    "snapshot_id": dict(failed_publication.get("published") or {}).get("snapshot_id"),
                    "stream_position": dict(failed_publication.get("expected_stream_position") or {}),
                },
                "published": {
                    "capability_id": published.get("capability_id"),
                    "candidate_id": published.get("candidate_id"),
                    "snapshot_id": snapshot.get("snapshot_id"),
                    "snapshot_hash": snapshot.get("snapshot_hash"),
                    "location_binding": snapshot.get("location_binding"),
                },
                "source": {
                    "kind": "failure-obligation-recovery",
                    "obligation_id": obligation_id,
                    "failed_publication_id": failed_publication_id,
                    "previous_publication_id": previous_id,
                },
                "recovery": {
                    "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
                    "obligation_id": obligation_id,
                    "failed_publication_id": failed_publication_id,
                    "previous_publication_id": previous_id,
                    "previous_publication_event_id": previous_publication.get("event_id"),
                    "previous_default": previous,
                },
                "evidence": dict(previous_publication.get("evidence") or {}),
                "source_task_id": None,
                "expected_stream_position": position,
                "failure_action": recovery_action,
                "check_obligation": {
                    "schema": PUBLICATION_CHECK_OBLIGATION_SCHEMA,
                    "obligation_id": check_obligation_id,
                    "type": "ordinary-new-session-consumer-check",
                    "required_publication_id": publication_id,
                    "required_snapshot_id": snapshot.get("snapshot_id"),
                    "state": "PENDING",
                },
            }
            refs = self._recovery_publication_reference_ids(previous_publication, projection)
            event = self._append_fact(
                request_id=request_id,
                event_type="extension.publication-committed",
                payload=payload,
                referenced_proofs=self._existing_reference_proofs(refs),
            )
            result = self._publication_failure_action_result(event, replayed=False)
            result.update({
                "publication_id": publication_id,
                "check_obligation": dict(payload["check_obligation"]),
                "action": recovery_action,
            })
            return result

        repair_id = f"{obligation_id}:repair:v1"
        repair = {
            "schema": PUBLICATION_FAILURE_ACTION_SCHEMA,
            "obligation_id": repair_id,
            "type": "EXTENSION_REPAIR_REQUIRED",
            "state": "PENDING",
            "reason": "NO_AVAILABLE_PREVIOUS_DEFAULT",
        }
        return self._append_failure_action_locked(
            obligation_id=obligation_id,
            request_id=request_id,
            action_request_hash=action_request_hash,
            slot_id=slot_id,
            failed_publication_id=failed_publication_id,
            owner_id=owner_id,
            operation_id=operation_id,
            current_default=current_default,
            resolution="DISABLED",
            disposition="DISABLED_NO_DEFAULT",
            repair_obligation=repair,
        )

    def process_publication_failure_obligation(
        self,
        obligation_id: str,
        request_id: str,
    ) -> Mapping[str, Any]:
        """Settle a persisted failure obligation through the Backend lane."""

        processor = getattr(self.backend, "process_publication_failure_obligation", None)
        if not callable(processor):
            raise ExtensionAuthorityError("Loop Backend lacks the failure-obligation action boundary")
        return processor(obligation_id, request_id)

    @staticmethod
    def _publication_check_request_view(request: Mapping[str, Any]) -> dict[str, Any]:
        """Return the stable identity of one ordinary-consumer check fact."""

        binding = request.get("capability_binding")
        binding_view = {
            key: binding.get(key)
            for key in ("slot_id", "publication_id", "candidate_id", "snapshot_id", "snapshot_hash", "location_binding")
        } if isinstance(binding, Mapping) else {}
        return {
            "obligation_id": str(request.get("obligation_id") or ""),
            "task_id": str(request.get("task_id") or ""),
            "operation_id": str(request.get("operation_id") or ""),
            "required_publication_id": str(request.get("required_publication_id") or ""),
            "required_snapshot_id": str(request.get("required_snapshot_id") or ""),
            "binding": binding_view,
        }

    def publication_check_event_for_obligation(self, obligation_id: str) -> EventEnvelope | None:
        """Read the one already-recorded PASS fact, if any, without CAS work."""

        matches = [
            event for event in self._journal_events()
            if event.event_type == "extension.publication-check-recorded"
            and str(event.payload.get("obligation_id") or "") == str(obligation_id)
        ]
        if len(matches) > 1:
            raise ExtensionAuthorityError("one publication check obligation has multiple check facts")
        return matches[0] if matches else None

    @staticmethod
    def _publication_check_method_view(value: Mapping[str, Any]) -> dict[str, Any]:
        """Compare fixed method semantics while ignoring per-call task/call IDs."""

        # Operation evidence wraps the canonical plan once (and older 4B
        # fixtures wrapped that document twice).  Compare the innermost
        # method plan so wrapper metadata cannot make an equivalent consumer
        # look different.
        current: Mapping[str, Any] = value
        for _ in range(3):
            nested = current.get("method_plan")
            if not isinstance(nested, Mapping) or nested is current:
                break
            current = nested
        ignored = {"task_id", "call_id"}
        return {
            str(key): current[key]
            for key in sorted(current)
            if key not in ignored
        }

    def _record_publication_check_locked(
        self,
        request: Mapping[str, Any],
        *,
        check_request_hash: str,
    ) -> EventEnvelope:
        obligation_id = str(request.get("obligation_id") or "")
        task_id = str(request.get("task_id") or "")
        operation_id = str(request.get("operation_id") or "")
        if not obligation_id or not task_id or not operation_id:
            raise ExtensionAuthorityError("publication check identity is incomplete")

        # Re-check both idempotency conditions after taking the Backend lock;
        # a concurrent consumer must not append a second fact for one passed
        # obligation, even when it has a different task/request identity.
        existing = self._existing_request(str(request.get("request_id") or ""))
        if existing is not None:
            if existing.event_type != "extension.publication-check-recorded":
                raise ExtensionAuthorityConflict("publication check request_id belongs to another extension fact")
            if existing.payload.get("check_request_hash") != check_request_hash:
                raise ExtensionAuthorityConflict("publication check request_id was already used differently")
            return existing
        prior = self.publication_check_event_for_obligation(obligation_id)
        if prior is not None:
            return prior

        projection = self.load_projection()
        obligation = dict((projection.get("obligations") or {}).get(obligation_id) or {})
        if not obligation:
            raise ExtensionAuthorityError("publication check obligation is not present in the authoritative Journal")
        required_publication_id = str(
            obligation.get("required_publication_id")
            or request.get("required_publication_id")
            or ""
        )
        required_snapshot_id = str(
            obligation.get("required_snapshot_id")
            or request.get("required_snapshot_id")
            or ""
        )
        if not required_publication_id or not required_snapshot_id:
            raise ExtensionAuthorityError("publication check obligation lacks its required publication/snapshot")

        publication_event = next(
            (
                event for event in self._journal_events()
                if event.event_type == "extension.publication-committed"
                and str(event.payload.get("publication_id") or "") == required_publication_id
            ),
            None,
        )
        if publication_event is None:
            raise ExtensionAuthorityError("publication check publication fact is unavailable")
        publication_payload = dict(publication_event.payload)
        published = dict(publication_payload.get("published") or {})
        if str(published.get("snapshot_id") or "") != required_snapshot_id:
            raise ExtensionAuthorityError("publication check publication snapshot differs from its obligation")

        task = self.backend.get_task(task_id)
        if not task.descriptor_ref or not task.descriptor_hash:
            raise ExtensionAuthorityError("publication check consumer task lacks an immutable descriptor")
        descriptor = dict(
            self.backend.context_memory.read(
                str(task.descriptor_ref), expected_hash=str(task.descriptor_hash)
            )
        )
        capability_binding = descriptor.get("capability_binding")
        if not isinstance(capability_binding, Mapping):
            raise ExtensionAuthorityError("publication check consumer task lacks capability binding")
        binding = dict(capability_binding)
        if str(binding.get("publication_id") or "") != required_publication_id:
            raise ExtensionAuthorityError("consumer task is bound to another publication")
        if str(binding.get("snapshot_id") or "") != required_snapshot_id:
            raise ExtensionAuthorityError("consumer task is bound to another snapshot")
        if str(task.capability_snapshot_id or "") != required_snapshot_id:
            raise ExtensionAuthorityError("consumer task projection differs from its capability binding")
        required_slot_id = str(dict(publication_payload.get("slot") or {}).get("slot_id") or "")
        if required_slot_id and str(binding.get("slot_id") or "") != required_slot_id:
            raise ExtensionAuthorityError("consumer task capability slot differs from the publication")
        # Prove the original admission read position/F and resolution CAS
        # root independently.  This historical path deliberately does not
        # call build_execution_snapshot or consult the current environment.
        self.verify_capability_binding(binding, historical_only=True)

        operation = task.operations.get(operation_id)
        if operation is None or not operation.intent_ref or not operation.result_ref:
            raise ExtensionAuthorityError("publication check operation lacks persisted intent/result")
        if operation.unknown_effect or operation.effect_status.value != "SUCCEEDED":
            raise ExtensionAuthorityError("publication check operation did not settle successfully")
        intent = dict(self.backend.context_memory.read(str(operation.intent_ref)))
        if str(intent.get("capability_snapshot_id") or "") != required_snapshot_id:
            raise ExtensionAuthorityError("consumer operation intent uses another snapshot")
        method_plan_ref = str(intent.get("effect_evidence_ref") or "")
        if not method_plan_ref:
            raise ExtensionAuthorityError("publication check operation lacks a persisted method plan")
        evidence = dict(self.backend.context_memory.read(method_plan_ref))
        method_plan = dict(evidence.get("method_plan") or evidence)
        if method_plan.get("method_plan_schema") != "SITINA_EXTENSION_METHOD_PLAN_V1":
            raise ExtensionAuthorityError("publication check method plan schema is invalid")
        if str(method_plan.get("task_id") or "") != task_id:
            raise ExtensionAuthorityError("publication check method plan is bound to another task")
        if str(method_plan.get("snapshot_id") or "") != required_snapshot_id:
            raise ExtensionAuthorityError("publication check method plan uses another snapshot")
        consumer_dispatch = str(evidence.get("consumer_dispatch") or "")
        if consumer_dispatch not in {"skill-resource-reader", "plugin-command-runner"}:
            raise ExtensionAuthorityError("publication check operation is not a fixed Skill/Plugin consumer")

        result_document = dict(self.backend.context_memory.read(str(operation.result_ref)))
        raw_result = result_document.get("result")
        if not isinstance(raw_result, Mapping):
            raise ExtensionAuthorityError("publication check result is not a persisted tool result")
        raw_result = dict(raw_result)
        if result_document.get("effect_status") != "SUCCEEDED" or raw_result.get("status") != "ok":
            raise PublicationCheckNotApplicable("publication check result is not successful")
        execution_binding = raw_result.get("execution_binding")
        if not isinstance(execution_binding, Mapping):
            raise ExtensionAuthorityError("publication check result lacks its execution binding")
        execution_binding = dict(execution_binding)
        for key in ("snapshot_id", "snapshot_hash", "candidate_id", "handler", "method_schema", "method_version", "method_id", "tool_name"):
            if execution_binding.get(key) != method_plan.get(key):
                raise ExtensionAuthorityError(f"publication check result binding differs at {key}")
        if str(raw_result.get("tool") or "") != str(method_plan.get("tool_name") or ""):
            raise ExtensionAuthorityError("publication check result tool differs from its method plan")
        if raw_result.get("arguments") != method_plan.get("arguments"):
            raise ExtensionAuthorityError("publication check arguments differ from its persisted method plan")
        receipt_ref = str(execution_binding.get("backend_receipt_ref") or "")
        receipt_hash = str(execution_binding.get("backend_receipt_hash") or "")
        if not receipt_ref or not receipt_hash:
            raise ExtensionAuthorityError("publication check result lacks a Backend receipt")
        receipt = dict(self.backend.read_extension_json(receipt_ref, expected_hash=receipt_hash))
        if receipt.get("schema") != "SITINA_EXTENSION_CONSUMER_RECEIPT_V1":
            raise ExtensionAuthorityError("publication check receipt schema is invalid")
        for key, expected in {
            "task_id": task_id,
            "operation_id": operation_id,
            "snapshot_id": method_plan.get("snapshot_id"),
            "snapshot_hash": method_plan.get("snapshot_hash"),
            "candidate_id": method_plan.get("candidate_id"),
            "tool_name": method_plan.get("tool_name"),
            "handler": method_plan.get("handler"),
            "method_schema": method_plan.get("method_schema"),
            "method_version": method_plan.get("method_version"),
            "method_id": method_plan.get("method_id"),
            "method_contract": method_plan.get("method_contract"),
            "dispatch": "LoopBackend.execute_operation",
        }.items():
            if receipt.get(key) != expected:
                raise ExtensionAuthorityError(f"publication check receipt differs at {key}")
        if receipt.get("result_hash") != hashlib.sha256(
            stable_json(raw_result.get("value")).encode("utf-8")
        ).hexdigest():
            raise ExtensionAuthorityError("publication check receipt does not bind the persisted output")

        method_contract = method_plan.get("method_contract")
        if not isinstance(method_contract, Mapping):
            raise ExtensionAuthorityError("publication check method contract is unavailable")
        contract_kind = str(method_contract.get("kind") or "")
        expected = method_plan.get("expected")
        observed_value = raw_result.get("value")
        if contract_kind == "skill-resource-read":
            if not isinstance(expected, Mapping) or not isinstance(observed_value, Mapping):
                raise PublicationCheckNotApplicable("Skill check lacks its fixed resource evidence")
            observed_arguments = raw_result.get("arguments")
            if not isinstance(observed_arguments, Mapping):
                raise PublicationCheckNotApplicable("Skill check lacks persisted input arguments")
            if observed_arguments.get("path") != expected.get("relative_path"):
                raise PublicationCheckNotApplicable("Skill check path differs from its persisted method")
            if observed_value.get("path") != expected.get("relative_path"):
                raise PublicationCheckNotApplicable("Skill check result path differs from its method")
            if observed_value.get("resource_sha256") != expected.get("sha256"):
                raise PublicationCheckNotApplicable("Skill check resource hash differs from its persisted method")
            content = observed_value.get("content")
            if not isinstance(content, str):
                raise PublicationCheckNotApplicable("Skill check lacks the persisted resource content")
            expected_bytes = expected.get("bytes")
            if isinstance(expected_bytes, int) and len(content.encode("utf-8")) != expected_bytes:
                raise PublicationCheckNotApplicable("Skill check persisted content length differs from its method")
        elif contract_kind == "plugin-command":
            if not isinstance(expected, Mapping) or expected.get("output") != observed_value:
                raise PublicationCheckNotApplicable("Plugin check output differs from its persisted method")
            if raw_result.get("program_status") != "PASS" or raw_result.get("effect_settled") is not True:
                raise PublicationCheckNotApplicable("Plugin check lacks a settled PASS completion")
            if raw_result.get("completion_status") != "COMPLETED" or not raw_result.get("completion_ref") or not raw_result.get("completion_hash"):
                raise ExtensionAuthorityError("Plugin check lacks its trusted completion evidence")
        else:
            raise ExtensionAuthorityError("publication check method kind is not connected")

        # C3a is intentionally limited to the same bounded method/input that
        # produced the published trial.  This avoids turning a static Plugin
        # expected_output into a general regression evaluator.
        publication_evidence_ref = str(dict(publication_payload.get("evidence") or {}).get("method_plan_ref") or "")
        if not publication_evidence_ref:
            raise ExtensionAuthorityError("publication evidence lacks the persisted trial method plan")
        original_evidence = dict(self.backend.context_memory.read(publication_evidence_ref))
        original_plan = dict(original_evidence.get("method_plan") or original_evidence)
        if self._publication_check_method_view(original_plan) != self._publication_check_method_view(method_plan):
            raise PublicationCheckNotApplicable("consumer method/input differs from the published trial method")

        result_event = next(
            (
                event for event in self.backend.store.task_events(task_id)
                if event.event_type == "loop.operation-result-recorded"
                and str(event.payload.get("operation_id") or "") == operation_id
            ),
            None,
        )
        result_hash = str(result_event.payload.get("result_hash") or "") if result_event is not None else ""
        if not result_hash:
            raise ExtensionAuthorityError("publication check result event lacks its CAS hash")
        operation_intent_event = next(
            (
                event for event in self.backend.store.task_events(task_id)
                if event.event_type == "loop.operation-intent-recorded"
                and str(event.payload.get("operation_id") or "") == operation_id
            ),
            None,
        )
        bound_artifact_ref = str(task.artifact_ref or "")
        if operation_intent_event is not None:
            # Recover the artifact that was current when this operation was
            # admitted.  The task projection may now point at a later result
            # artifact after Plugin/Skill completion and acceptance.
            for historical_event in self.backend.store.task_events(task_id):
                if int(historical_event.position) > int(operation_intent_event.position):
                    break
                if historical_event.event_type in {"loop.task-created", "loop.artifact-updated"}:
                    candidate_artifact_ref = str(historical_event.payload.get("artifact_ref") or "")
                    if candidate_artifact_ref:
                        bound_artifact_ref = candidate_artifact_ref
        consumer_task = {
            "task_id": str(intent.get("task_id") or task_id),
            "run_instance_id": intent.get("expected_run_instance_id"),
            "execution_epoch": intent.get("expected_execution_epoch"),
            "goal_version": intent.get("expected_goal_version"),
            "acceptance_version": intent.get("expected_acceptance_version"),
            "handled_input_seq": intent.get("expected_handled_input_seq"),
        }
        consumer_task.update({"session_id": task.session_id, "artifact_ref": bound_artifact_ref})
        operation_view = {
            "operation_id": operation_id,
            "intent_ref": operation.intent_ref,
            "result_ref": operation.result_ref,
            "result_hash": result_hash,
            "effect_status": operation.effect_status.value,
            "unknown_effect": bool(operation.unknown_effect),
        }
        method_view = {
            key: method_plan.get(key)
            for key in (
                "method_schema", "method_version", "method_id", "tool_name", "handler", "method_contract",
            )
        }
        payload = {
            "schema": PUBLICATION_CHECK_SCHEMA,
            "event_type": "extension.publication-check-recorded",
            "check_request_hash": check_request_hash,
            "obligation_id": obligation_id,
            "result": "PASS",
            "required_publication_id": required_publication_id,
            "observed_publication_id": str(binding.get("publication_id") or ""),
            "required_snapshot_id": required_snapshot_id,
            "observed_snapshot_id": str(binding.get("snapshot_id") or ""),
            "slot": dict(publication_payload.get("slot") or {}),
            "consumer_task": consumer_task,
            "operation": operation_view,
            "method": method_view,
            "receipt": {"schema": receipt.get("schema"), "reference": receipt_ref, "hash": receipt_hash},
            "binding": {
                key: binding.get(key)
                for key in (
                    "slot_id", "publication_id", "candidate_id", "snapshot_id", "snapshot_hash",
                    "location_binding", "resolution_stream_id", "read_position", "resolution_ref",
                    "resolution_hash", "resolution_cas_proof",
                )
            },
            "evidence": {
                "descriptor_ref": task.descriptor_ref,
                "descriptor_hash": task.descriptor_hash,
                "method_plan_ref": method_plan_ref,
                "operation_intent_ref": operation.intent_ref,
                "operation_result_ref": operation.result_ref,
                "receipt_ref": receipt_ref,
            },
            "state": "PASSED",
        }
        evidence_refs = tuple(
            ref for ref in (
                task.descriptor_ref, method_plan_ref, operation.intent_ref,
                operation.result_ref, receipt_ref, str(binding.get("resolution_ref") or ""),
            ) if ref
        )
        return self._append_fact(
            request_id=str(request.get("request_id") or ""),
            event_type="extension.publication-check-recorded",
            payload=payload,
            referenced_proofs=self._existing_reference_proofs(evidence_refs),
        )

    def record_publication_check(self, request: Mapping[str, Any]) -> EventEnvelope:
        """Append one PASS fact from a Backend-reconstructed consumer result.

        This API never accepts a result, receipt, method callback, or current
        default from its caller.  It re-reads the immutable descriptor and
        persisted operation evidence, and it is idempotent both by request and
        by obligation (a second successful consumer cannot append another CAS
        fact for an already-PASSED obligation).
        """

        if not isinstance(request, Mapping):
            raise ExtensionAuthorityError("publication check request must be an object")
        canonical = dict(request)
        request_id = str(canonical.get("request_id") or "")
        obligation_id = str(canonical.get("obligation_id") or "")
        if not request_id or not obligation_id:
            raise ExtensionAuthorityError("publication check request_id and obligation_id are required")
        check_request_hash = _sha256_json(self._publication_check_request_view(canonical))
        existing = self._existing_request(request_id)
        if existing is not None:
            if existing.event_type != "extension.publication-check-recorded":
                raise ExtensionAuthorityConflict("publication check request_id belongs to another extension fact")
            if existing.payload.get("check_request_hash") != check_request_hash:
                raise ExtensionAuthorityConflict("publication check request_id was already used differently")
            return existing
        prior = self.publication_check_event_for_obligation(obligation_id)
        if prior is not None:
            required_publication_id = str(canonical.get("required_publication_id") or "")
            required_snapshot_id = str(canonical.get("required_snapshot_id") or "")
            if required_publication_id and required_publication_id != str(prior.payload.get("required_publication_id") or ""):
                raise ExtensionAuthorityConflict("publication check obligation is bound to another publication")
            if required_snapshot_id and required_snapshot_id != str(prior.payload.get("required_snapshot_id") or ""):
                raise ExtensionAuthorityConflict("publication check obligation is bound to another snapshot")
            return prior
        if not hasattr(self.backend, "coordinate_extension_publication_check"):
            raise ExtensionAuthorityError("Loop Backend lacks the publication check coordination boundary")
        try:
            return self.backend.coordinate_extension_publication_check(
                lambda: self._record_publication_check_locked(
                    canonical,
                    check_request_hash=check_request_hash,
                )
            )
        except Exception as original_error:
            # The Journal append can commit and the caller can still lose its
            # return (for example an isolated OSError after fsync).  Before
            # exposing that error, perform a read-only lookup of the exact
            # request and canonical hash.  A matching committed fact is the
            # result; a missing or unverifiable fact retains the original
            # exception and never retries the consumer or CAS append.
            try:
                same_request = self._existing_request(request_id)
            except Exception:
                raise original_error
            if same_request is not None:
                if (
                    same_request.event_type == "extension.publication-check-recorded"
                    and same_request.payload.get("check_request_hash") == check_request_hash
                ):
                    return same_request
                raise original_error
            if isinstance(original_error, ExtensionAuthorityConflict):
                winner = self.publication_check_event_for_obligation(obligation_id)
                if winner is not None:
                    return winner
            raise original_error

    def create_preparation_context(
        self,
        task_id: str,
        source: str | Path,
        *,
        operation_id: str | None = None,
    ) -> ExtensionPreparationContext:
        """Ask the Loop backend for a context bound to this source/environment."""

        source_path = _canonical_path(source)
        source_root = source_path if source_path.is_dir() else source_path.parent
        source_hash = _tree_hash(source_root)
        environment_hash = _sha256_json(_environment_identity(self.sitina_home, self.extension_root))
        return self.backend.authorize_extension_preparation(
            task_id,
            source_path=source_root,
            extension_root=self.extension_root,
            source_tree_hash=source_hash,
            environment_hash=environment_hash,
            operation_id=operation_id,
        )

    @staticmethod
    def _candidate_identity_view(value: Mapping[str, Any]) -> dict[str, Any]:
        """Compare immutable capability content, not source/request metadata."""

        ignored = {
            "candidate_path",
            "provenance",
            "selection_binding",
            "trial",
            "publication_id",
            "available_for_trial",
        }
        return {str(key): value[key] for key in sorted(value) if key not in ignored}

    def _validate_preparation_context(
        self,
        context: ExtensionPreparationContext | None,
        *,
        source: Path,
        source_tree_hash: str,
    ) -> None:
        if context is None:
            raise CandidatePreparationError(
                "candidate preparation requires a Backend-issued execution context"
            )
        try:
            context.assert_issued_by(self.backend)
        except Exception as exc:
            raise CandidatePreparationError("candidate preparation context is not issued by this Backend") from exc
        if _canonical_path(context.source_path) != source:
            raise CandidatePreparationError("preparation source differs from its authorized context")
        if _canonical_path(context.extension_root) != self.extension_root:
            raise CandidatePreparationError("preparation extension root differs from its authorized context")
        if context.source_tree_hash and context.source_tree_hash != source_tree_hash:
            raise CandidatePreparationError("source changed before controlled preparation")
        current_environment_hash = _sha256_json(_environment_identity(self.sitina_home, self.extension_root))
        if context.environment_hash and context.environment_hash != current_environment_hash:
            raise CandidatePreparationError("extension environment changed before controlled preparation")

    def _prepare_controlled(
        self,
        *,
        context: ExtensionPreparationContext | None,
        kind: str,
        name: str,
        version: str,
        install_id: str,
        source: Path,
        bindings: Mapping[str, Any],
        permissions: Mapping[str, Any],
        dependencies: list[dict[str, Any]],
        provenance: Mapping[str, Any],
    ) -> PreparedCandidate:
        """Run candidate materialization as one durable Loop operation."""

        source = source.resolve(strict=True)
        initial_tree_hash = _tree_hash(source)
        self._validate_preparation_context(context, source=source, source_tree_hash=initial_tree_hash)
        assert context is not None  # narrowed by _validate_preparation_context
        result_holder: dict[str, PreparedCandidate] = {}
        stage: dict[str, Any] = {"stage": "AUTHORIZED"}

        def dispatch() -> Any:
            # Import the loop value types lazily: extension manager loading is
            # also used by loop child-model modules, so eager loop-package
            # imports would create a manager/loop import cycle.
            from sitina.loop.model import EffectStatus
            from sitina.loop.operations import OperationOutcome

            try:
                # This is the post-occupancy recheck.  The operation intent
                # and extension write lane are already durable at this point.
                current_hash = _tree_hash(source)
                self._validate_preparation_context(context, source=source, source_tree_hash=current_hash)
                stage["stage"] = "DISPATCH_VALIDATED"
                candidate = self._materialize_controlled(
                    kind=kind,
                    name=name,
                    version=version,
                    install_id=install_id,
                    source=source,
                    bindings=bindings,
                    permissions=permissions,
                    dependencies=dependencies,
                    provenance=provenance,
                    stage=stage,
                    preparation_context=context,
                )
                result_holder["candidate"] = candidate
                return OperationOutcome(
                    EffectStatus.SUCCEEDED,
                    {
                        "effect_dispatched": True,
                        "candidate_id": candidate.candidate_id,
                        "event_id": candidate.event_id,
                        "preparation_state": "PREPARED_ONLY",
                    },
                )
            except Exception as exc:
                committed = stage.get("stage") in {"FACT_COMMITTED", "REBUILDING_PROJECTION"}
                if committed:
                    # The authoritative fact already exists.  Projection
                    # repair may safely reuse that decision; never settle it
                    # as NO_EFFECT or overwrite it with another preparation.
                    try:
                        repaired = self.rebuild_projection()
                        candidate = stage.get("candidate")
                        if isinstance(candidate, PreparedCandidate):
                            result_holder["candidate"] = candidate
                            return OperationOutcome(
                                EffectStatus.SUCCEEDED,
                                {
                                    "effect_dispatched": True,
                                    "candidate_id": candidate.candidate_id,
                                    "event_id": candidate.event_id,
                                    "projection_repaired": True,
                                    "projection_frontier": repaired["applied_frontier"]["stream_version"],
                                    "preparation_state": "PREPARED_ONLY",
                                },
                            )
                    except Exception as repair_error:
                        exc = repair_error
                    return OperationOutcome(
                        EffectStatus.UNKNOWN,
                        {
                            "effect_dispatched": True,
                            "effect_requires_probe": True,
                            "effect_settled": False,
                            "recovery_decision": "HOLD_FOR_RECOVERY",
                            "reason": f"{type(exc).__name__}: {exc}",
                            "preparation_stage": str(stage.get("stage")),
                        },
                    )
                materialized = stage.get("stage") in {
                    "CANDIDATE_MATERIALIZED",
                    "PUBLISHING_MANIFEST",
                    "MANIFEST_PUBLISHED",
                    "APPENDING_FACT",
                }
                return OperationOutcome(
                    EffectStatus.UNKNOWN if materialized else EffectStatus.FAILED,
                    {
                        "effect_dispatched": True,
                        "effect_settled": not materialized,
                        "effect_requires_probe": materialized,
                        "recovery_decision": "HOLD_FOR_RECOVERY" if materialized else "NO_EFFECT",
                        "reason": f"{type(exc).__name__}: {exc}",
                        "preparation_stage": str(stage.get("stage")),
                    },
                )

        try:
            outcome = self.backend.execute_extension_preparation(context, dispatch)
        except Exception:
            raise
        from sitina.loop.model import EffectStatus

        if outcome.status is not EffectStatus.SUCCEEDED or "candidate" not in result_holder:
            reason = str(outcome.result.get("reason") or "controlled candidate preparation did not succeed")
            raise CandidatePreparationError(reason)
        return result_holder["candidate"]

    def _candidate_manifest(self, *, kind: str, name: str, install_id: str, source: Path, candidate_path: Path,
                            tree_hash: str, resources: list[dict[str, Any]], bindings: Mapping[str, Any],
                            permissions: Mapping[str, Any], dependencies: list[dict[str, Any]], version: str,
                            provenance: Mapping[str, Any]) -> dict[str, Any]:
        environment = _environment_identity(self.sitina_home, self.extension_root)
        core = {
            "schema": CANDIDATE_SCHEMA,
            "kind": kind,
            "name": name,
            "version": version,
            "install_id": install_id,
            "tree_hash": tree_hash,
            "resources": resources,
            "bindings": dict(bindings),
            "permissions": dict(permissions),
            "dependencies": list(dependencies),
            "environment": environment,
            "preparation_method": "sitina-extension-candidate-preparation-4a-v1",
        }
        capability_hash = _sha256_json(core)
        manifest = {
            **core,
            "candidate_id": "candidate-" + capability_hash[:40],
            "capability_id": "capability-" + capability_hash,
            "capability_hash": capability_hash,
            "candidate_path": str(candidate_path),
            "provenance": dict(provenance),
            "selection_binding": None,
            "trial": None,
            "publication_id": None,
            "available_for_trial": False,
        }
        return manifest

    def _materialize_controlled(self, *, kind: str, name: str, version: str, install_id: str, source: Path,
                 bindings: Mapping[str, Any], permissions: Mapping[str, Any], dependencies: list[dict[str, Any]],
                 provenance: Mapping[str, Any], stage: dict[str, Any] | None = None,
                 preparation_context: ExtensionPreparationContext) -> PreparedCandidate:
        stage = stage if stage is not None else {}
        stage["stage"] = "VALIDATED"
        source = source.resolve(strict=True)
        if (source / "candidate.json").exists():
            raise CandidatePreparationError(
                "candidate.json is reserved for authority metadata and cannot be copied from a source"
            )
        source_tree_hash = _tree_hash(source)
        if preparation_context.source_tree_hash != source_tree_hash:
            raise CandidatePreparationError(
                "source changed between authorization and controlled materialization"
            )
        current_environment_hash = _sha256_json(_environment_identity(self.sitina_home, self.extension_root))
        if preparation_context.environment_hash != current_environment_hash:
            raise CandidatePreparationError(
                "extension environment changed between authorization and controlled materialization"
            )
        # No directory creation/copy is allowed until the issued WRITE intent
        # is durably active and owns the modification lane.
        self.backend.assert_extension_preparation_current(
            preparation_context, require_active_operation=True
        )
        resources = _resource_hashes(source)
        self.backend.assert_extension_write_ready()
        preview_path = self.candidates_root / name / ("pending-" + source_tree_hash[:16])
        manifest = self._candidate_manifest(
            kind=kind, name=name, install_id=install_id, source=source,
            candidate_path=preview_path, tree_hash=source_tree_hash, resources=resources,
            bindings=bindings, permissions=permissions, version=version, provenance=provenance,
            dependencies=dependencies,
        )
        if _sha256_json(manifest["environment"]) != preparation_context.environment_hash:
            raise CandidatePreparationError("candidate environment differs from its authorized context")
        candidate_id = str(manifest["candidate_id"])
        destination = self.candidates_root / name / candidate_id
        manifest["candidate_path"] = str(destination)
        manifest["capability_hash"] = _sha256_json({key: value for key, value in manifest.items() if key not in {
            "candidate_id", "capability_id", "capability_hash", "candidate_path", "provenance", "selection_binding", "trial", "publication_id", "available_for_trial"
        }})
        # The capability ID must remain content/environment based.  Recompute
        # it after correcting the candidate path out of the hashed core.
        manifest["candidate_id"] = "candidate-" + manifest["capability_hash"][:40]
        manifest["capability_id"] = "capability-" + manifest["capability_hash"]
        destination = self.candidates_root / name / str(manifest["candidate_id"])
        manifest["candidate_path"] = str(destination)
        if destination.exists():
            existing_path = destination / "candidate.json"
            try:
                existing = json.loads(existing_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise CandidatePreparationError("existing candidate version is unreadable; refusing overwrite") from exc
            if (
                self._candidate_identity_view(existing) != self._candidate_identity_view(manifest)
                or _tree_hash(destination, exclude_names=frozenset({"candidate.json"})) != source_tree_hash
            ):
                raise CandidatePreparationError("candidate identity collision or changed installed version")
        else:
            stage["stage"] = "COPYING"
            staging = destination.parent / f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.staging"
            staging.mkdir(parents=True, exist_ok=False)
            try:
                _copy_tree_no_links(source, staging)
                if _tree_hash(staging) != source_tree_hash:
                    raise CandidatePreparationError("candidate copy tree hash does not match source")
                self._validate_preparation_context(
                    preparation_context, source=source, source_tree_hash=_tree_hash(source)
                )
                self.backend.assert_extension_preparation_current(
                    preparation_context, require_active_operation=True
                )
                self.backend.assert_extension_write_ready()
                metadata_path = staging / "candidate.json"
                with metadata_path.open("w", encoding="utf-8") as metadata_handle:
                    metadata_handle.write(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
                    metadata_handle.flush()
                    os.fsync(metadata_handle.fileno())
                _fsync_tree(staging)
                staging.rename(destination)
                # rename has made the candidate directory visible; from this
                # point onward any durability failure is a real materialized
                # effect and must settle UNKNOWN/hold the lane.
                stage["stage"] = "CANDIDATE_MATERIALIZED"
                _fsync_directory(destination.parent)
                _fsync_directory(self.candidates_root)
                self._validate_preparation_context(
                    preparation_context, source=source, source_tree_hash=_tree_hash(source)
                )
                self.backend.assert_extension_preparation_current(
                    preparation_context, require_active_operation=True
                )
            except BaseException:
                shutil.rmtree(staging, ignore_errors=True)
                raise
        provenance_request_hash = _sha256_json(provenance)[:24]
        request_id = "candidate-prepare-" + str(manifest["candidate_id"]) + "-" + provenance_request_hash
        self.backend.assert_extension_preparation_current(
            preparation_context, require_active_operation=True
        )
        existing_event = self._existing_request(request_id)
        if existing_event is not None:
            existing_payload = dict(existing_event.payload)
            existing_candidate = dict(existing_payload.get("candidate") or {})
            if (
                self._candidate_identity_view(existing_candidate)
                != self._candidate_identity_view(manifest)
                or str(existing_payload.get("source_tree_hash") or "") != source_tree_hash
            ):
                raise ExtensionAuthorityConflict("candidate preparation request identity changed")
            existing_ref = str(existing_payload.get("candidate_manifest_ref") or "")
            existing_hash = str(existing_payload.get("candidate_manifest_hash") or "")
            if not existing_ref or not existing_hash:
                raise ExtensionAuthorityError("existing candidate fact lacks its manifest root")
            existing_manifest = self.backend.read_extension_json(existing_ref, expected_hash=existing_hash)
            if self._candidate_identity_view(existing_manifest) != self._candidate_identity_view(manifest):
                raise ExtensionAuthorityError("existing candidate manifest differs from the requested capability")
            prepared = PreparedCandidate(
                str(manifest["candidate_id"]), str(manifest["capability_id"]), install_id, kind, name,
                destination, existing_ref, existing_hash, source_tree_hash,
                existing_event.event_id, existing_event.stream_version,
            )
            stage["candidate"] = prepared
            stage["stage"] = "FACT_COMMITTED"
            self.rebuild_projection()
            stage["stage"] = "SETTLED"
            return prepared
        raw = canonical_json_bytes(manifest)
        stage["stage"] = "PUBLISHING_MANIFEST"
        self._validate_preparation_context(
            preparation_context, source=source, source_tree_hash=_tree_hash(source)
        )
        self.backend.assert_extension_preparation_current(
            preparation_context, require_active_operation=True
        )
        manifest_content = self.backend.publish_extension_json(
            manifest, purpose="sitina-extension-candidate-manifest"
        )
        stage["stage"] = "MANIFEST_PUBLISHED"
        stage["stage"] = "APPENDING_FACT"
        self._validate_preparation_context(
            preparation_context, source=source, source_tree_hash=_tree_hash(source)
        )
        self.backend.assert_extension_preparation_current(
            preparation_context, require_active_operation=True
        )
        event = self._append_fact(
            request_id=request_id,
            event_type="extension.candidate-prepared",
            payload={
                "candidate": manifest,
                "candidate_manifest_ref": manifest_content.reference_id,
                "candidate_manifest_hash": hashlib.sha256(raw).hexdigest(),
                "source_tree_hash": source_tree_hash,
                "preparation_state": "PREPARED_ONLY",
            },
            referenced_contents=(manifest_content,),
        )
        prepared = PreparedCandidate(
            str(manifest["candidate_id"]), str(manifest["capability_id"]), install_id, kind, name,
            destination, manifest_content.reference_id, manifest_content.content_hash, source_tree_hash,
            event.event_id, event.stream_version,
        )
        stage["candidate"] = prepared
        stage["stage"] = "FACT_COMMITTED"
        self.rebuild_projection()
        stage["stage"] = "SETTLED"
        return prepared

    def prepare_plugin(
        self,
        source: str | Path,
        *,
        grants: tuple[str, ...] = (),
        expected_sha256: str | None = None,
        execution_context: ExtensionPreparationContext | None = None,
    ) -> PreparedCandidate:
        source = _canonical_path(source)
        tree_hash_before = _tree_hash(source)
        manifest = PluginManifest.load(source)
        tree_hash = _tree_hash(source)
        if tree_hash != tree_hash_before:
            raise CandidatePreparationError("plugin source changed while its manifest was being read")
        if expected_sha256 and tree_hash != str(expected_sha256).removeprefix("sha256:"):
            raise CandidatePreparationError("plugin source hash does not match expected hash")
        declared = set(manifest.permissions)
        requested = {str(item).strip() for item in grants if str(item).strip()}
        if not requested <= declared:
            raise CandidatePreparationError("candidate requests a permission not declared by the plugin")
        granted = sorted(requested | {"read"})
        missing = sorted(declared - set(granted))
        if missing:
            raise CandidatePreparationError(
                "plugin candidate requires explicit permission grants: " + ", ".join(missing)
            )
        return self._prepare_controlled(
            context=execution_context,
            kind="plugin", name=manifest.name, version=manifest.version,
            install_id=f"{manifest.version}-{tree_hash[:16]}", source=source,
            bindings=_entry_bindings(manifest, source),
            permissions={"declared": sorted(declared), "granted": granted},
            dependencies=_declared_dependencies(manifest),
            provenance={"source": str(source), "source_type": "local_directory", "content_sha256": tree_hash},
        )

    def _skill_management_write(self, commit: Any) -> Any:
        # Match the existing publisher's state-lock -> root-lock order.  Do not
        # hold these locks while fetching or preparing an immutable source.
        def locked() -> Any:
            with self._writer_lock():
                return commit()
        return self.backend.coordinate_extension_publication_commit(locked)

    def manage_mcp(self, request: Mapping[str, Any], *, user_initiated: bool = False) -> dict[str, Any]:
        """Install a user's MCP-only configuration, without claiming a business trial."""
        if user_initiated is not True:
            raise ExtensionAuthorityError("MCP installation requires an authenticated user action")
        allowed = {"action", "request_id", "source", "grants", "enable"}
        if not isinstance(request, Mapping) or set(request) - allowed or request.get("action") != "install_local":
            raise ExtensionAuthorityError("MCP management requires an install_local configuration")
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 160:
            raise ExtensionAuthorityError("MCP management request_id is invalid")
        if "enable" in request and type(request["enable"]) is not bool:
            raise ExtensionAuthorityError("MCP enable must be boolean")
        grants = request.get("grants", [])
        if not isinstance(grants, list) or any(not isinstance(value, str) for value in grants):
            raise ExtensionAuthorityError("MCP grants must be an explicit permission list")
        source_value = request.get("source")
        if not isinstance(source_value, str) or not Path(source_value).is_absolute():
            raise ExtensionAuthorityError("MCP source must be an absolute local directory")
        original = dict(request)
        digest = _sha256_json(original)
        key = hashlib.sha256(request_id.encode()).hexdigest()
        start_id, finish_id = "mcp-management-start-" + key, "mcp-management-finish-" + key

        def begin():
            prior = self._existing_request(start_id)
            if prior is not None and prior.payload.get("management_request") != original:
                raise ExtensionAuthorityConflict("MCP request_id was already used for another operation")
            finished = self._existing_request(finish_id)
            if finished is not None:
                return {**dict(finished.payload["result"]), "replayed": True}
            if prior is not None:
                return {"request_id": request_id, "state": "UNKNOWN", "replayed": True}
            self._append_fact(
                request_id=start_id, event_type="extension.mcp-management-requested",
                payload={"management_request": original, "management_request_hash": digest,
                         "management_actor": "authenticated-local-user", "state": "PENDING"},
            )
        prior_result = self._skill_management_write(begin)
        if prior_result is not None:
            return prior_result
        self.rebuild_projection()
        task_id, closed = None, False
        try:
            source = _canonical_path(source_value)
            manifest = PluginManifest.load(source)
            if manifest.component_path("mcp") is None or any(
                manifest.component_path(kind) is not None for kind in ("tools", "hooks", "agents", "skills")
            ):
                raise ExtensionAuthorityError("user MCP management admits MCP-only configurations")
            slot = _normalize_slot("plugin:" + manifest.name)
            existing = self.load_projection()["defaults"].get(slot.slot_id)
            if existing:
                publication = self.load_projection()["publications"].get(existing.get("publication_id"), {})
                if publication.get("management_kind") != "mcp-configuration":
                    raise ExtensionAuthorityConflict("an existing non-MCP-managed plugin owns this name")
            source_hash = _tree_hash(source)
            content = self.backend.publish_extension_json(
                {"management_request": original, "source_tree_hash": source_hash, "source_path": str(source)},
                purpose="mcp-user-management-source",
            )
            task_id = "mcp-management-" + key
            self.backend.create_task(
                task_id=task_id, session_id="mcp-management", task_kind="native_mcp_management",
                goal="Prepare the user's explicit MCP configuration; this is not a business capability test",
                required_outcome_ids=(), artifact_ref=content.reference_id,
                environment_ref=_sha256_json(_environment_identity(self.sitina_home, self.extension_root)),
                capability_snapshot_id="mcp-user-management", request_id=start_id,
            )
            context = self.create_preparation_context(task_id, source, operation_id="mcp-prepare-" + key)
            prepared = self.prepare_plugin(source, grants=tuple(grants), execution_context=context)
            snapshot = self.build_execution_snapshot(prepared.candidate_id).as_dict()
            from sitina.loop.model import CompletionProposal, TaskStatus
            task = self.backend.get_task(task_id)
            settled = self.backend.propose_terminal(task_id, CompletionProposal(
                proposal_id="mcp-prepared-" + key, terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision, expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch, expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq, artifact_ref=task.artifact_ref,
                final_result={"candidate_id": prepared.candidate_id, "preparation_state": "PREPARED_ONLY",
                              "business_validation": "NOT_CLAIMED"}, obligation_types=(),
            ))
            closed = settled.is_terminal
            if not closed:
                raise ExtensionAuthorityError("MCP preparation has not settled")
            enabled = request.get("enable", True)

            def commit():
                current = self.build_execution_snapshot(prepared.candidate_id).as_dict()
                if current != snapshot:
                    raise ExtensionAuthorityError("MCP configuration changed before installation")
                publication_id = "mcp-user-publication-" + key if enabled else None
                result = {"request_id": request_id, "state": "ACCEPTED", "action": "install_local",
                          "name": manifest.name, "candidate_id": prepared.candidate_id, "installed": True,
                          "enabled": enabled, "publication_id": publication_id,
                          "business_validation": "NOT_CLAIMED"}
                self._append_fact(
                    request_id=finish_id, event_type="extension.mcp-management-committed",
                    payload={"management_request": original, "management_request_hash": digest,
                             "management_actor": "authenticated-local-user", "management_kind": "mcp-configuration",
                             "name": manifest.name, "candidate_id": prepared.candidate_id,
                             "slot": slot.as_dict(), "source": str(source), "management_task_id": task_id,
                             "source_tree_hash": snapshot["tree_hash"], "selection_changed": bool(enabled),
                             "enabled": bool(enabled), "publication_id": publication_id,
                             "published": snapshot, "result": result},
                )
                return result
            result = self._skill_management_write(commit)
            self.rebuild_projection()
            return result
        except Exception as error:
            finished = self._existing_request(finish_id)
            if finished is not None:
                return {**dict(finished.payload["result"]), "replayed": True}
            result = {"request_id": request_id, "state": "UNKNOWN" if task_id and not closed else "FAILED",
                      "action": "install_local", "message": str(error), "management_task_id": task_id}
            def fail():
                self._append_fact(
                    request_id=finish_id, event_type="extension.mcp-management-failed",
                    payload={"management_request": original, "management_request_hash": digest, "result": result},
                )
            self._skill_management_write(fail)
            self.rebuild_projection()
            return result

    def manage_skill(
        self,
        request: Mapping[str, Any],
        *,
        user_initiated: bool = False,
        source_resolver: Any | None = None,
    ) -> dict[str, Any]:
        """Apply an authenticated user's global skill choice in this Journal.

        This is a management operation, not a business trial/publication pass.
        Immutable candidates and snapshots already admitted by tasks are retained.
        The caller must authenticate the user before setting user_initiated.
        """
        if user_initiated is not True:
            raise ExtensionAuthorityError("skill management requires an authenticated user action")
        allowed = {"action", "request_id", "source", "name", "version", "enable"}
        if not isinstance(request, Mapping) or set(request) - allowed:
            raise ExtensionAuthorityError("skill management request has unknown fields")
        action = request.get("action")
        if action not in {"install_local", "install_public", "enable", "disable", "rollback", "delete"}:
            raise ExtensionAuthorityError("unsupported skill management action")
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id.strip() or len(request_id) > 160:
            raise ExtensionAuthorityError("skill management request_id is required and must be bounded")
        if "enable" in request and type(request["enable"]) is not bool:
            raise ExtensionAuthorityError("skill enable must be a boolean")
        for key in ("source", "name", "version"):
            if key in request and (not isinstance(request[key], str) or not request[key].strip()):
                raise ExtensionAuthorityError(f"skill management {key} must be a nonempty string")
        if action.startswith("install") and not request.get("source"):
            raise ExtensionAuthorityError("skill installation requires a source")
        if not action.startswith("install") and not request.get("name"):
            raise ExtensionAuthorityError("skill management requires a skill name")
        original = dict(request)
        digest = _sha256_json(original)
        operation_key = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        start_id = "skill-management-start-" + operation_key
        finish_id = "skill-management-finish-" + operation_key
        def begin_management():
            prior = self._existing_request(start_id)
            if prior is not None and prior.payload.get("management_request") != original:
                raise ExtensionAuthorityConflict("skill request_id was already used for a different operation")
            completed = self._existing_request(finish_id)
            if completed is not None:
                result = dict(completed.payload["result"])
                result["replayed"] = True
                return result
            if prior is not None:
                return {
                    "request_id": request_id, "state": "UNKNOWN", "replayed": True,
                    "message": "技能操作已登记但尚无终态。保留原现场，不自动重新安装。",
                }
            self._append_fact(
                request_id=start_id, event_type="extension.skill-management-requested",
                payload={"management_request": original, "management_request_hash": digest,
                         "management_actor": "authenticated-local-user", "state": "PENDING"},
            )
        replay = self._skill_management_write(begin_management)
        if replay is not None:
            return replay
        self.rebuild_projection()
        prepared: PreparedCandidate | None = None
        management_task_id: str | None = None
        preparation_scope_closed = False
        try:
            if action.startswith("install"):
                if source_resolver is None:
                    raise ExtensionAuthorityError("skill source resolver is unavailable")
                with source_resolver(str(request["source"]), action, request_id) as source:
                    source = Path(source).expanduser().resolve(strict=True)
                    skill_file = source / "SKILL.md" if source.is_dir() else source
                    skill = load_skill(skill_file)
                    if request.get("name") and request["name"] != skill.name:
                        raise ExtensionAuthorityError("installed skill name differs from requested name")
                    source_root = skill_file.parent
                    source_tree_hash = _tree_hash(source_root)
                    content = self.backend.publish_extension_json(
                        {"management_request": original, "source_tree_hash": source_tree_hash,
                         "source_path": str(source_root), "source_kind": action},
                        purpose="skill-user-management-source",
                    )
                    management_task_id = "skill-management-" + operation_key
                    self.backend.create_task(
                        task_id=management_task_id, session_id="skill-management",
                        task_kind="native_skill_management", goal="Prepare the user-selected immutable skill version",
                        required_outcome_ids=(), artifact_ref=content.reference_id,
                        environment_ref=_sha256_json(_environment_identity(self.sitina_home, self.extension_root)),
                        capability_snapshot_id="skill-user-management",
                        request_id=start_id,
                    )
                    context = self.create_preparation_context(
                        management_task_id, source_root, operation_id="skill-prepare-" + operation_key,
                    )
                    prepared = self.prepare_skill(skill_file, execution_context=context)
                    # Complete this narrowly scoped native operation using its
                    # real prepared candidate.  It is not a business trial and
                    # schedules no Provider/experience-extraction obligation.
                    from sitina.loop.model import CompletionProposal, TaskStatus
                    task = self.backend.get_task(management_task_id)
                    closed = self.backend.propose_terminal(
                        management_task_id,
                        CompletionProposal(
                            proposal_id="prepared-" + operation_key, terminal_status=TaskStatus.SUCCEEDED,
                            expected_task_revision=task.task_revision,
                            expected_run_instance_id=task.run_instance_id,
                            expected_execution_epoch=task.execution_epoch,
                            expected_goal_version=task.goal_version,
                            expected_acceptance_version=task.acceptance_version,
                            expected_received_input_seq=task.received_input_seq,
                            expected_handled_input_seq=task.handled_input_seq,
                            artifact_ref=task.artifact_ref,
                            final_result={"candidate_id": prepared.candidate_id,
                                          "preparation_state": "PREPARED_ONLY",
                                          "management_request_id": request_id},
                            obligation_types=(),
                        ),
                    )
                    preparation_scope_closed = closed.is_terminal
                    if not preparation_scope_closed:
                        raise ExtensionAuthorityError("native skill preparation did not settle")
                name = prepared.name
                if request.get("name") and request["name"] != name:
                    raise ExtensionAuthorityError("installed skill name differs from requested name")
                candidate_id = prepared.candidate_id
            else:
                name = str(request["name"])
                slot = _normalize_slot("skill:" + name)
                projection = self.load_projection()
                candidates = [
                    dict(value) for value in projection["candidates"].values()
                    if value.get("kind") == "skill" and value.get("name") == slot.name
                ]
                if not candidates:
                    raise ExtensionAuthorityError(f"skill is not installed: {name}")
                current = dict(projection["defaults"].get(slot.slot_id) or {})
                prior_management = [
                    event.payload for event in self._journal_events()
                    if event.event_type == "extension.skill-management-committed"
                    and event.payload.get("name") == name
                    and event.payload.get("candidate_id")
                ]
                if (action != "delete" and prior_management
                        and prior_management[-1].get("result", {}).get("action") == "delete"):
                    raise ExtensionAuthorityError("技能已删除；请重新安装后启用。")
                current_id = str(current.get("candidate_id") or "")
                if not current_id and current.get("publication_id"):
                    publication = projection["publications"].get(current["publication_id"], {})
                    current_id = str(publication.get("published", {}).get("candidate_id") or "")
                if request.get("version"):
                    matches = [
                        value for value in candidates if request["version"] in {
                            value.get("candidate_id"), value.get("install_id"), value.get("version")
                        }
                    ]
                    if len(matches) != 1:
                        raise ExtensionAuthorityError("requested skill version is unavailable or ambiguous")
                    candidate_id = str(matches[0]["candidate_id"])
                elif action == "rollback":
                    previous_ids = [
                        str(value.get("candidate_id")) for value in prior_management
                        if value.get("candidate_id") != current_id
                    ]
                    if not previous_ids:
                        raise ExtensionAuthorityError("skill has no previous selected version")
                    candidate_id = previous_ids[-1]
                else:
                    candidate_id = current_id or str(
                        prior_management[-1]["candidate_id"] if prior_management
                        else max(candidates, key=lambda value: int(value.get("stream_version", 0)))["candidate_id"]
                    )
            if action in {"disable", "delete"}:
                manifest = self.candidate(candidate_id)
                snapshot = {
                    "candidate_id": candidate_id, "kind": manifest["kind"], "name": manifest["name"],
                    "tree_hash": manifest["tree_hash"], "root": manifest["candidate_path"],
                }
            else:
                snapshot = self.build_execution_snapshot(candidate_id).as_dict()
            if snapshot["kind"] != "skill" or snapshot["name"] != name:
                raise ExtensionAuthorityError("skill candidate identity does not match the selected name")
            enabled = action not in {"disable", "delete"} and (not action.startswith("install") or request.get("enable", True))
            activate = enabled or action in {"disable", "delete"}
            def commit_management():
                # The shared root lock serializes the default transition.  Recheck
                # candidate bytes at that boundary, without changing admitted pins.
                if action not in {"disable", "delete"} and _tree_hash(Path(snapshot["root"]), exclude_names=frozenset({"candidate.json"})) != snapshot["tree_hash"]:
                    raise ExtensionAuthorityError("skill version changed before management commit")
                publication_id = "skill-user-publication-" + operation_key if activate and enabled else None
                slot = _normalize_slot("skill:" + name)
                result = {
                    "request_id": request_id, "state": "ACCEPTED", "action": action,
                    "name": name, "candidate_id": candidate_id, "installed": action != "delete",
                    "enabled": enabled, "publication_id": publication_id,
                    "message": ("技能已从全局列表删除，新任务不再使用；旧任务固定版本与历史记录保留。"
                                if action == "delete" else "技能操作已确认；已有任务保留其固定版本。"),
                }
                self._append_fact(
                    request_id=finish_id, event_type="extension.skill-management-committed",
                    payload={
                        "management_request": original, "management_request_hash": digest,
                        "management_actor": "authenticated-local-user", "name": name,
                        "candidate_id": candidate_id, "slot": slot.as_dict(),
                        "source": request.get("source"), "management_task_id": management_task_id,
                        "source_tree_hash": snapshot["tree_hash"], "selection_changed": activate,
                        "enabled": enabled, "publication_id": publication_id,
                        "published": snapshot, "result": result,
                    },
                )
                return result
            result = self._skill_management_write(commit_management)
            self.rebuild_projection()
            return result
        except Exception as error:
            # A lost commit response is reconciled from the original Journal.
            finished = self._existing_request(finish_id)
            if finished is not None:
                return {**dict(finished.payload["result"]), "replayed": True}
            state = "UNKNOWN" if management_task_id is not None and not preparation_scope_closed else "FAILED"
            result = {
                "request_id": request_id, "state": state, "action": action,
                "message": str(error), "management_task_id": management_task_id,
            }
            def record_failure():
                self._append_fact(
                    request_id=finish_id, event_type="extension.skill-management-failed",
                    payload={"management_request": original, "management_request_hash": digest, "result": result},
                )
            self._skill_management_write(record_failure)
            self.rebuild_projection()
            return result

    def prepare_skill(
        self,
        source: str | Path,
        *,
        execution_context: ExtensionPreparationContext | None = None,
    ) -> PreparedCandidate:
        source = _canonical_path(source)
        skill_file = source / "SKILL.md" if source.is_dir() else source
        source_root = skill_file.parent
        tree_hash_before = _tree_hash(source_root)
        skill = load_skill(skill_file)
        tree_hash = _tree_hash(source_root)
        if tree_hash != tree_hash_before:
            raise CandidatePreparationError("skill source changed while its instructions were being read")
        binding = {
            "skills": [{
                "qualified_name": skill.qualified_name,
                "relative_path": _safe_relative(skill_file, source_root),
                "description": skill.description,
                "instructions_sha256": hashlib.sha256(skill.body.encode("utf-8")).hexdigest(),
                "allowed_tools": list(skill.allowed_tools),
            }],
            "agents": [], "tools": [], "mcp": [], "hooks": [],
        }
        version = str((skill.optional_metadata or {}).get("version") or "unversioned")
        return self._prepare_controlled(
            context=execution_context,
            kind="skill", name=skill.name, version=version, install_id=tree_hash[:16], source=source_root,
            bindings=binding, permissions={"declared": ["read"], "granted": ["read"]},
            dependencies=[],
            provenance={"source": str(source_root), "source_type": "local_directory", "content_sha256": tree_hash},
        )

    def candidate(self, candidate_id: str) -> Mapping[str, Any]:
        projection = self.load_projection()
        try:
            candidate = projection["candidates"][candidate_id]
        except (KeyError, TypeError) as exc:
            raise CandidatePreparationError(f"candidate is not present in the authoritative projection: {candidate_id}") from exc
        ref = candidate.get("candidate_manifest_ref") or candidate.get("manifest_ref")
        if not isinstance(ref, str):
            raise CandidatePreparationError("candidate projection lacks its CAS manifest reference")
        value = self.backend.read_extension_json(
            ref, expected_hash=str(candidate.get("candidate_manifest_hash") or "") or None
        )
        if value.get("candidate_id") != candidate_id:
            raise CandidatePreparationError("candidate CAS manifest identity differs from projection")
        return value

    def build_execution_snapshot(self, candidate_id: str, *, include_mcp_runtime: bool = True) -> ExecutionSnapshot:
        """Resolve one authenticated candidate into a complete consumer view."""

        manifest = dict(self.candidate(candidate_id))
        root = _canonical_path(str(manifest.get("candidate_path") or ""))
        if not root.is_dir() or root.is_symlink():
            raise CandidatePreparationError("candidate execution root is unavailable")
        tree_hash = _tree_hash(root, exclude_names=frozenset({"candidate.json"}))
        if tree_hash != str(manifest.get("tree_hash") or ""):
            raise CandidatePreparationError("candidate changed after preparation")
        environment = dict(manifest.get("environment") or {})
        current_environment = _environment_identity(self.sitina_home, self.extension_root)
        if not _candidate_environment_compatible(manifest, current_environment):
            raise CandidatePreparationError("candidate environment is no longer current")
        kind = str(manifest.get("kind") or "")
        name = str(manifest.get("name") or "")
        bindings = _execution_binding_view(dict(manifest.get("bindings") or {}), root, include_mcp_runtime=include_mcp_runtime)
        for section in ("tools", "hooks"):
            for item in bindings.get(section, ()):
                identities = item.get("executable_identities") if isinstance(item, Mapping) else None
                if not isinstance(identities, list) or not identities or not bool(identities[0].get("exists")):
                    raise CandidatePreparationError(f"{kind} handler executable is unavailable")
        for item in bindings.get("mcp", ()) if include_mcp_runtime else ():
            if not isinstance(item, Mapping) or item.get("transport") != "stdio":
                continue
            identities = item.get("executable_identities")
            if not isinstance(identities, list) or not identities or not bool(identities[0].get("exists")):
                raise CandidatePreparationError("stdio MCP handler executable is unavailable")
        permissions = dict(manifest.get("permissions") or {})
        dependencies = tuple(dict(item) for item in (manifest.get("dependencies") or ()) if isinstance(item, Mapping))
        dependencies = _resolved_dependency_view(tuple(item for item in dependencies
            if include_mcp_runtime or item.get("type") != "mcp"))
        core = {
            "candidate_id": str(manifest.get("candidate_id") or ""),
            "capability_id": str(manifest.get("capability_id") or ""),
            "kind": kind,
            "name": name,
            "tree_hash": tree_hash,
            "environment": environment,
            "bindings": bindings,
            "permissions": permissions,
            "dependencies": list(dependencies),
        }
        snapshot_hash = _sha256_json(core)
        location_binding = _sha256_json({"candidate_id": core["candidate_id"], "root": str(root)})
        snapshot_id = "execution-snapshot-" + snapshot_hash[:40]
        return ExecutionSnapshot(
            snapshot_id=snapshot_id,
            candidate_id=str(manifest["candidate_id"]),
            capability_id=str(manifest["capability_id"]),
            kind=kind,
            name=name,
            root=root,
            location_binding=location_binding,
            tree_hash=tree_hash,
            environment=environment,
            bindings=bindings,
            permissions=permissions,
            dependencies=dependencies,
            snapshot_hash=snapshot_hash,
        )

    def record_trial_fact(
        self,
        *,
        request_id: str,
        candidate_id: str,
        snapshot: Mapping[str, Any],
        task_binding: Mapping[str, Any],
        operation_id: str,
        method: Mapping[str, Any],
        raw_result: Mapping[str, Any],
        input_binding: Mapping[str, Any],
        artifact_binding: Mapping[str, Any],
    ) -> EventEnvelope:
        """Durably record one backend-verified execution trial.

        The trial is intentionally downstream of the normal Loop operation
        path: the referenced operation must already have a persisted,
        successful result in the task projection.  Callers cannot turn a
        model assertion into a PASS by supplying an arbitrary result.
        """

        if not isinstance(snapshot, Mapping) or snapshot.get("schema") != EXECUTION_SNAPSHOT_SCHEMA:
            raise ExtensionAuthorityError("trial requires a complete execution snapshot")
        current_snapshot = self.build_execution_snapshot(candidate_id).as_dict()
        if str(snapshot.get("snapshot_hash") or "") != str(current_snapshot.get("snapshot_hash") or ""):
            raise ExtensionAuthorityError("trial execution snapshot is stale or mismatched")
        if str(snapshot.get("location_binding") or "") != str(current_snapshot.get("location_binding") or ""):
            raise ExtensionAuthorityError("trial execution location is stale or mismatched")
        if not isinstance(task_binding, Mapping) or not isinstance(input_binding, Mapping):
            raise ExtensionAuthorityError("trial task and input bindings are required")
        if not isinstance(artifact_binding, Mapping) or not isinstance(method, Mapping):
            raise ExtensionAuthorityError("trial method and artifact bindings are required")
        if not isinstance(raw_result, Mapping):
            raise ExtensionAuthorityError("trial raw result must be the persisted result object")
        allowed_method_keys = frozenset({
            "snapshot_id", "snapshot_hash", "candidate_id", "location_binding",
            "tool_name", "handler", "qualified_name", "root", "command",
            "method_schema", "method_version", "method_id", "method_contract",
            "backend_receipt_schema", "backend_receipt_ref", "backend_receipt_hash", "call_id",
        })
        unknown_method_keys = set(method).difference(allowed_method_keys)
        if unknown_method_keys:
            raise ExtensionAuthorityError(
                "trial method contains undeclared fields: " + ", ".join(sorted(map(str, unknown_method_keys)))
            )

        # Idempotency is keyed by the complete logical trial request, not just
        # candidate/snapshot.  A caller may safely replay the exact request
        # after a reopen, but reusing its request id for a different method,
        # operation, task, input, artifact, or result must be rejected before
        # any backend/CAS work is performed.
        request_identity = {
            "candidate_id": str(candidate_id),
            "snapshot_hash": str(current_snapshot.get("snapshot_hash") or ""),
            "task": dict(task_binding),
            "operation_id": str(operation_id),
            "method": dict(method),
            "raw_result": dict(raw_result),
            "input": dict(input_binding),
            "artifact": dict(artifact_binding),
        }
        request_identity_hash = _sha256_json(request_identity)
        existing = self._existing_request(request_id)
        if existing is not None:
            if (
                existing.payload.get("candidate_id") != candidate_id
                or existing.payload.get("snapshot_hash") != current_snapshot.get("snapshot_hash")
            ):
                raise ExtensionAuthorityConflict("trial request_id was already used for another snapshot")
            existing_identity_hash = existing.payload.get("trial_request_hash")
            if existing_identity_hash is None:
                # Compatibility for an event written before the normalized
                # request hash field existed: derive the same stable subset
                # from its persisted evidence.
                existing_identity = {
                    "candidate_id": str(existing.payload.get("candidate_id") or ""),
                    "snapshot_hash": str(existing.payload.get("snapshot_hash") or ""),
                    "task": dict(existing.payload.get("task") or {}),
                    "operation_id": str(existing.payload.get("operation_id") or ""),
                    "method": {
                        key: (existing.payload.get("method") or {}).get(key)
                        for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")
                    },
                    "raw_result": dict(existing.payload.get("raw_result") or {}),
                    "input": dict(existing.payload.get("input") or {}),
                    "artifact": dict(existing.payload.get("artifact") or {}),
                }
                existing_identity_hash = _sha256_json(existing_identity)
            if existing_identity_hash != request_identity_hash:
                raise ExtensionAuthorityConflict("trial request_id was already used for a different logical trial")
            return existing

        task_id = str(task_binding.get("task_id") or "")
        task = self.backend.get_task(task_id)
        if task_binding.get("task_id") != task.task_id or task_binding.get("session_id") != task.session_id:
            raise ExtensionAuthorityError("trial task identity does not match the current projection")
        operation = task.operations.get(str(operation_id))
        if operation is None or operation.result_ref is None:
            raise ExtensionAuthorityError("trial operation is not present with a persisted result")
        if operation.effect_status.value != "SUCCEEDED" or operation.unknown_effect:
            raise ExtensionAuthorityError("trial operation did not settle successfully")
        if not operation.intent_ref:
            raise ExtensionAuthorityError("trial operation intent evidence is missing")
        intent = dict(self.backend.context_memory.read(str(operation.intent_ref)))
        intent_binding = {
            "task_id": task_id,
            "run_instance_id": intent.get("expected_run_instance_id"),
            "execution_epoch": intent.get("expected_execution_epoch"),
            "goal_version": intent.get("expected_goal_version"),
            "acceptance_version": intent.get("expected_acceptance_version"),
            "handled_input_seq": intent.get("expected_handled_input_seq"),
        }
        # The current task projection may legitimately have advanced its
        # acceptance/artifact lineage after the operation settled.  The
        # operation intent is the authoritative original execution identity;
        # caller-supplied current fields are used only for applicability and
        # request-id normalization, never for the historical trial fields.
        if task_binding.get("task_id") != task.task_id or task_binding.get("session_id") != task.session_id:
            raise ExtensionAuthorityError("trial task identity does not match the operation intent")
        if intent.get("capability_snapshot_id") != current_snapshot.get("snapshot_id"):
            raise ExtensionAuthorityError("trial operation was not authorized for this candidate capability")
        if input_binding.get("handled_input_seq") != intent.get("expected_handled_input_seq"):
            raise ExtensionAuthorityError("trial input binding does not match the operation intent")
        method_plan_ref = str(intent.get("effect_evidence_ref") or "")
        if not method_plan_ref:
            raise ExtensionAuthorityError("trial operation lacks a persisted pre-dispatch method plan")
        try:
            effect_evidence = dict(self.backend.context_memory.read(method_plan_ref))
            method_plan = dict(effect_evidence.get("method_plan") or effect_evidence)
        except Exception as error:
            raise ExtensionAuthorityError("trial pre-dispatch method plan is unavailable") from error
        if (
            method_plan.get("schema") != "SITINA_EXTENSION_METHOD_PLAN_V1"
            and method_plan.get("method_plan_schema") != "SITINA_EXTENSION_METHOD_PLAN_V1"
        ):
            raise ExtensionAuthorityError("trial pre-dispatch method plan schema is invalid")
        if any(
            method_plan.get(key) != expected
            for key, expected in {
                "task_id": task_id,
                "snapshot_id": current_snapshot.get("snapshot_id"),
                "snapshot_hash": current_snapshot.get("snapshot_hash"),
                "candidate_id": candidate_id,
            }.items()
        ):
            raise ExtensionAuthorityError("trial pre-dispatch method plan is bound to another task or snapshot")
        bound_attempt = str(operation.business_attempt_id or operation.attempt_id)
        plan = task.attempt_plans.get(bound_attempt) if isinstance(task.attempt_plans, Mapping) else None
        expected_artifact = str(plan.get("artifact_ref") or "") if isinstance(plan, Mapping) else str(task.artifact_ref)
        supplied_artifact = artifact_binding.get("artifact_ref")
        # A completed operation can be settled after the task has advanced to
        # a newer artifact lineage.  Accept the backend's current artifact as
        # the applicability witness, or the original attempt-plan artifact;
        # persist only the original plan value in the historical trial.
        if supplied_artifact not in {expected_artifact, task.artifact_ref}:
            raise ExtensionAuthorityError("trial artifact binding does not match the operation attempt")
        persisted_result = dict(self.backend.context_memory.read(str(operation.result_ref)))
        raw_tool_result = persisted_result.get("result") if isinstance(persisted_result.get("result"), Mapping) else persisted_result
        if canonical_json_bytes(dict(raw_result)) != canonical_json_bytes(dict(raw_tool_result)):
            raise ExtensionAuthorityError("trial raw result differs from the persisted operation result")
        execution_binding = raw_tool_result.get("execution_binding")
        if not isinstance(execution_binding, Mapping):
            raise ExtensionAuthorityError("trial result lacks an authenticated runtime execution receipt")
        for key in ("candidate_id", "snapshot_hash"):
            if execution_binding.get(key) != current_snapshot.get(key):
                raise ExtensionAuthorityError("trial execution receipt is not bound to the selected snapshot")
        if execution_binding.get("tool_name") != raw_tool_result.get("tool"):
            raise ExtensionAuthorityError("trial execution receipt tool differs from the persisted tool result")
        if method_plan.get("tool_name") != raw_tool_result.get("tool"):
            raise ExtensionAuthorityError("trial result tool differs from the persisted method plan")
        if method_plan.get("handler") != execution_binding.get("handler"):
            raise ExtensionAuthorityError("trial result handler differs from the persisted method plan")
        if method_plan.get("arguments") != raw_tool_result.get("arguments"):
            raise ExtensionAuthorityError("trial result arguments differ from the persisted method plan")
        receipt_ref = str(execution_binding.get("backend_receipt_ref") or "")
        receipt_hash = str(execution_binding.get("backend_receipt_hash") or "")
        if not receipt_ref or not receipt_hash:
            raise ExtensionAuthorityError("trial result lacks a durable Backend consumer receipt")
        try:
            receipt = dict(self.backend.read_extension_json(receipt_ref, expected_hash=receipt_hash))
        except Exception as error:
            raise ExtensionAuthorityError("trial Backend consumer receipt is unavailable") from error
        receipt_fields = {
            "schema": "SITINA_EXTENSION_CONSUMER_RECEIPT_V1",
            "task_id": task_id,
            "call_id": execution_binding.get("call_id"),
            "snapshot_id": current_snapshot.get("snapshot_id"),
            "snapshot_hash": current_snapshot.get("snapshot_hash"),
            "candidate_id": candidate_id,
            "tool_name": raw_tool_result.get("tool"),
            "handler": execution_binding.get("handler"),
            "method_schema": execution_binding.get("method_schema"),
            "method_version": execution_binding.get("method_version"),
            "method_id": execution_binding.get("method_id"),
            "method_contract": execution_binding.get("method_contract"),
            "dispatch": "LoopBackend.execute_operation",
        }
        if any(receipt.get(key) != value for key, value in receipt_fields.items()):
            raise ExtensionAuthorityError("trial Backend consumer receipt binding is invalid")
        if receipt.get("result_hash") != hashlib.sha256(
            stable_json(raw_tool_result.get("value")).encode("utf-8")
        ).hexdigest():
            raise ExtensionAuthorityError("trial Backend consumer receipt does not bind the persisted output")
        if any(
            method.get(key) != execution_binding.get(key)
            for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")
        ):
            raise ExtensionAuthorityError("trial method declaration differs from the runtime execution receipt")
        if execution_binding.get("method_schema") != "SITINA_EXTENSION_TRIAL_METHOD_V1":
            raise ExtensionAuthorityError("trial execution receipt uses an unsupported method schema")
        method_contract = execution_binding.get("method_contract")
        if not isinstance(method_contract, Mapping) or method_contract.get("schema") != "SITINA_EXTENSION_METHOD_EXPECTATION_V1":
            raise ExtensionAuthorityError("trial execution receipt lacks a registered method expectation")
        if "method_contract" in method and method.get("method_contract") != method_contract:
            raise ExtensionAuthorityError("trial method expectation differs from the runtime contract")
        if method_plan.get("method_contract") != method_contract:
            raise ExtensionAuthorityError("trial method expectation differs from the pre-dispatch plan")
        observed_arguments = raw_tool_result.get("arguments")
        if not isinstance(observed_arguments, Mapping):
            raise ExtensionAuthorityError("trial result lacks persisted tool arguments for effect verification")
        observed_value = raw_tool_result.get("value")
        if raw_tool_result.get("status") != method_contract.get("result_status"):
            raise ExtensionAuthorityError("trial result status does not satisfy the registered method expectation")
        contract_kind = str(method_contract.get("kind") or "")
        if contract_kind == "skill-resource-read":
            expected_skill = str(method_contract.get("skill") or "")
            observed_skill = str(observed_arguments.get("skill") or "")
            observed_path = str(observed_arguments.get("path") or "")
            expected_paths = tuple(str(item) for item in (method_contract.get("expected_paths") or ()))
            if observed_skill != expected_skill or not observed_path or Path(observed_path).is_absolute() or ".." in Path(observed_path).parts:
                raise ExtensionAuthorityError("trial resource arguments do not match the selected Skill")
            if expected_paths and observed_path not in expected_paths:
                raise ExtensionAuthorityError("trial resource path was not registered by the selected Skill")
            if not isinstance(observed_value, Mapping) or observed_value.get("path") != observed_path:
                raise ExtensionAuthorityError("trial resource result lacks its requested relative path")
            resource = Path(str(current_snapshot.get("root") or "")).resolve(strict=True) / observed_path
            try:
                resource = resource.resolve(strict=True)
                resource.relative_to(Path(str(current_snapshot.get("root") or "")).resolve(strict=True))
            except (OSError, ValueError) as error:
                raise ExtensionAuthorityError("trial resource result escapes the selected Skill root") from error
            resource_bytes = resource.read_bytes()
            if observed_value.get("resource_sha256") != hashlib.sha256(resource_bytes).hexdigest():
                raise ExtensionAuthorityError("trial resource hash does not match the selected candidate")
            if observed_value.get("content") != resource_bytes.decode("utf-8", errors="replace"):
                raise ExtensionAuthorityError("trial resource content does not match the selected candidate")
            expected_resource = method_plan.get("expected")
            if not isinstance(expected_resource, Mapping) or expected_resource.get("relative_path") != observed_path:
                raise ExtensionAuthorityError("trial resource differs from the pre-dispatch method plan")
            if expected_resource.get("sha256") != observed_value.get("resource_sha256"):
                raise ExtensionAuthorityError("trial resource changed after the method plan")
        elif contract_kind == "plugin-command":
            expected_command = method_contract.get("command")
            if not isinstance(expected_command, list) or execution_binding.get("command") != expected_command:
                raise ExtensionAuthorityError("trial Plugin command differs from the registered method")
            expected_output = method_contract.get("expected_output")
            if expected_output is None:
                raise ExtensionAuthorityError("trial Plugin method has no bounded output expectation")
            if observed_value != expected_output:
                raise ExtensionAuthorityError("trial Plugin output does not satisfy the registered expectation")
            expected_plugin = method_plan.get("expected")
            if not isinstance(expected_plugin, Mapping) or expected_plugin.get("output") != observed_value:
                raise ExtensionAuthorityError("trial Plugin output differs from the pre-dispatch method plan")
        elif contract_kind == "mcp-tool":
            from sitina.runners.mcp_client import McpRuntimeError, validate_mcp_result
            expected_mcp = method_plan.get("expected")
            generic = bool(method_contract.get("generic"))
            action = str(observed_arguments.get("action") or "call") if generic else "call"
            tool = str(observed_arguments.get("name") or "") if generic else str(method_contract.get("mcp_tool") or "")
            if expected_mcp != {"kind": "mcp-output", "action": action, "tool_name": tool}:
                raise ExtensionAuthorityError("trial MCP result differs from its pre-dispatch method")
            if action == "call" and (
                tool in method_contract.get("denied_tools", ())
                or (method_contract.get("allowed_tools") is not None and tool not in method_contract["allowed_tools"])
            ):
                raise ExtensionAuthorityError("trial MCP tool is outside its registered scope")
            try:
                validate_mcp_result(action, observed_value)
            except McpRuntimeError as error:
                raise ExtensionAuthorityError(str(error)) from error
        else:
            raise ExtensionAuthorityError("trial method expectation kind is not connected")

        # A result that was persisted for this task is authoritative evidence;
        # republish it through the shared CAS bridge to obtain a proof for the
        # extension Journal event as well.
        result_content = self.backend.publish_extension_json(
            persisted_result, purpose="sitina-extension-trial-operation-result"
        )
        # The backend state lock spans the final projection read and the
        # extension Journal append.  This gives task control/input commits a
        # single linearization point: if CANCEL is already durable, the trial
        # is late evidence; if the trial wins the lock, CANCEL is appended
        # afterwards and the trial remains current for the state it observed.
        if not hasattr(self.backend, "coordinate_extension_trial_commit"):
            raise ExtensionAuthorityError("Loop Backend lacks the extension trial coordination boundary")

        def commit_trial() -> EventEnvelope:
            current_for_commit = self.backend.get_task(task_id)
            # Applicability is anchored to the original operation intent and
            # attempt plan.  A caller may pass a fresh projection binding, but
            # that cannot make an old operation current after a goal/input or
            # artifact revision.
            original_binding_current = all(
                actual == expected
                for actual, expected in (
                    (current_for_commit.task_id, task_id),
                    (current_for_commit.session_id, task.session_id),
                    (current_for_commit.run_instance_id, intent.get("expected_run_instance_id")),
                    (current_for_commit.execution_epoch, intent.get("expected_execution_epoch")),
                    (current_for_commit.goal_version, intent.get("expected_goal_version")),
                    (current_for_commit.acceptance_version, intent.get("expected_acceptance_version")),
                    (current_for_commit.handled_input_seq, intent.get("expected_handled_input_seq")),
                    (current_for_commit.artifact_ref, expected_artifact),
                )
            )
            applicability = (
                "CURRENT_TASK_INPUT"
                if original_binding_current
                and current_for_commit.control_intent.value == "RUN"
                and current_for_commit.received_input_seq == current_for_commit.handled_input_seq
                else "LATE_EVIDENCE_ONLY"
            )
            trial = {
                "schema": TRIAL_FACT_SCHEMA,
                "candidate_id": candidate_id,
                "snapshot_id": current_snapshot.get("snapshot_id"),
                "snapshot_hash": current_snapshot.get("snapshot_hash"),
                "environment": dict(current_snapshot.get("environment") or {}),
                "environment_hash": _sha256_json(current_snapshot.get("environment") or {}),
                "method": dict(execution_binding),
                "task": {
                    "task_id": task_id,
                    "session_id": task.session_id,
                    "run_instance_id": intent.get("expected_run_instance_id"),
                    "execution_epoch": intent.get("expected_execution_epoch"),
                    "goal_version": intent.get("expected_goal_version"),
                    "acceptance_version": intent.get("expected_acceptance_version"),
                    "received_input_seq": intent.get("expected_handled_input_seq"),
                    "handled_input_seq": intent.get("expected_handled_input_seq"),
                    "artifact_ref": expected_artifact,
                },
                # These fields describe the original operation identity, not
                # the potentially changed task projection at commit time.
                "session_id": task.session_id,
                "run_instance_id": intent.get("expected_run_instance_id"),
                "execution_epoch": intent.get("expected_execution_epoch"),
                "goal_version": intent.get("expected_goal_version"),
                "acceptance_version": intent.get("expected_acceptance_version"),
                "input": dict(input_binding),
                "artifact": {**dict(artifact_binding), "artifact_ref": expected_artifact},
                "operation_id": str(operation_id),
                "operation_result_ref": str(operation.result_ref),
                "operation_result_hash": hashlib.sha256(canonical_json_bytes(persisted_result)).hexdigest(),
                "raw_result": dict(raw_tool_result),
                "operation_result": persisted_result,
                "trial_request_hash": request_identity_hash,
                "applicability": applicability,
                "verified_by": "LoopBackend.task_projection",
                "consumer_receipt": {
                    "reference": receipt_ref,
                    "hash": receipt_hash,
                },
            }
            return self._append_fact(
                request_id=request_id,
                event_type="extension.trial-recorded",
                payload=trial,
                referenced_contents=(result_content,),
            )

        return self.backend.coordinate_extension_trial_commit(commit_trial)

    def publish_candidate(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise ExtensionAuthorityError(
            "candidate publication is not available in 4A: a real consumer trial and 4B/4C coordinator decision are required"
        )
