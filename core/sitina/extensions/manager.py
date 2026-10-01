from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from sitina.extensions.spec import (
    MARKETPLACE_SCHEMA,
    READ_ONLY_PERMISSIONS,
    REGISTRY_SCHEMA,
    AgentDefinition,
    ExtensionSpecError,
    PluginManifest,
    SkillDefinition,
    load_agent,
    load_skill,
    read_json_object,
    validate_identifier,
)
from sitina.extensions.authority import (
    CandidatePreparationError,
    ExtensionAuthority,
    PreparedCandidate,
)
from sitina.legacy.fence import authorized_extension_effect
from sitina.utils import iso_now, write_json


class ExtensionInstallError(RuntimeError):
    pass


class PermissionGrantRequired(ExtensionInstallError):
    def __init__(self, plugin: str, missing: Iterable[str]):
        self.plugin = plugin
        self.missing = tuple(sorted(set(missing)))
        super().__init__(f"plugin {plugin} requires explicit grants: {', '.join(self.missing)}")


@dataclass(frozen=True)
class PreparedSource:
    root: Path
    source: str
    source_type: str
    git_commit: str | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None

    def close(self) -> None:
        if self.temporary is not None:
            self.temporary.cleanup()


def default_extension_root() -> Path:
    configured = os.environ.get("SITINA_EXTENSIONS_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".sitina" / "extensions"


class ExtensionManager:
    """Global immutable extension store shared by every Sitina task."""

    def __init__(self, sitina_home: Path, *, global_root: Path | None = None):
        self.sitina_home = Path(sitina_home).expanduser().resolve(strict=False)
        self.root = Path(global_root or default_extension_root()).expanduser().resolve(strict=False)
        self.registry_path = self.root / "registry.json"
        self.plugins_root = self.root / "plugins"
        self.skills_root = self.root / "skills"
        self.audit_path = self.root / "audit.jsonl"
        self._shared_authority: ExtensionAuthority | None = None

    @property
    def authority_bound(self) -> bool:
        return (self.root / ".sitina-extension-authority-v1.json").is_file()

    def bind_shared_authority(self, *, state_root: Path, backend: Any, store: Any | None = None) -> ExtensionAuthority:
        """Bind this extension root to the existing Loop Journal/CAS writer.

        The binding is persisted on the extension root, so another process
        cannot silently select the same root from a different state root and
        form a second authority.  The manager's legacy mutation methods are
        closed as soon as this succeeds.
        """

        if store is not None:
            raise ExtensionInstallError(
                "shared extension authority requires the LoopBackend bridge, not a raw Journal/CAS store"
            )
        self._shared_authority = ExtensionAuthority(
            self.root,
            state_root=Path(state_root),
            backend=backend,
            sitina_home=self.sitina_home,
        )
        return self._shared_authority

    @property
    def shared_authority(self) -> ExtensionAuthority:
        if self._shared_authority is None:
            raise ExtensionInstallError("extension root has no shared Journal/CAS authority client")
        return self._shared_authority

    def _assert_legacy_mutation_allowed(self) -> None:
        if self.authority_bound:
            raise ExtensionInstallError(
                "r4-managed extension root rejects the legacy registry write path; use the shared authority candidate API"
            )

    @staticmethod
    def empty_registry() -> dict[str, Any]:
        return {
            "schema": REGISTRY_SCHEMA,
            "generation": 1,
            "plugins": {},
            "skills": {},
            "marketplaces": {},
            "updated_at": None,
        }

    def load_registry(self) -> dict[str, Any]:
        if self.authority_bound:
            if self._shared_authority is None:
                raise ExtensionInstallError(
                    "bound r4 extension root requires a shared ExtensionAuthority client for registry reads"
                )
            # Validate/read the authoritative projection first.  A stale or
            # old-schema registry.json is never allowed to become an active
            # source; the legacy maps are intentionally empty compatibility
            # fields and active readers use the branches in skills() and
            # active_plugins() above.
            projection = self.shared_authority.load_projection()
            return {
                **projection,
                "plugins": {},
                "skills": {},
                "marketplaces": {},
            }
        if not self.registry_path.exists():
            return self.empty_registry()
        raw = read_json_object(self.registry_path)
        if raw.get("schema") == "SITINA_EXTENSION_PROJECTION_V1":
            raise ExtensionInstallError("extension projection requires a shared ExtensionAuthority client")
        if raw.get("schema") != REGISTRY_SCHEMA:
            raise ExtensionInstallError(f"extension registry must use schema {REGISTRY_SCHEMA}")
        for key in ("plugins", "skills", "marketplaces"):
            if not isinstance(raw.get(key), dict):
                raise ExtensionInstallError(f"extension registry field {key} must be an object")
        return raw

    def _save_registry(self, registry: Mapping[str, Any]) -> None:
        self._assert_legacy_mutation_allowed()
        value = dict(registry)
        value["generation"] = int(value.get("generation", 0)) + 1
        value["updated_at"] = iso_now()
        write_json(self.registry_path, value)

    def _audit(self, event: str, payload: Mapping[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        record = {"schema": "SITINA_EXTENSION_AUDIT_V1", "timestamp": iso_now(), "event": event, **dict(payload)}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    def install_plugin(
        self,
        source: str | Path,
        *,
        grants: Iterable[str] = (),
        approve_network: bool = False,
        expected_sha256: str | None = None,
        git_ref: str | None = None,
        update: bool = False,
    ) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        prepared = self._prepare_source(source, approve_network=approve_network, git_ref=git_ref)
        try:
            manifest = PluginManifest.load(prepared.root)
            content_sha = self._tree_sha256(prepared.root)
            normalized_expected = expected_sha256.removeprefix("sha256:") if expected_sha256 else None
            if normalized_expected and content_sha != normalized_expected:
                raise ExtensionInstallError(
                    f"plugin content hash mismatch: expected {normalized_expected}, received {content_sha}"
                )
            registry = self.load_registry()
            plugin_state = dict(registry["plugins"].get(manifest.name) or {})
            prior_active = plugin_state.get("active")
            if prior_active and not update:
                raise ExtensionInstallError(
                    f"plugin {manifest.name} is already installed; use explicit update to change its active version"
                )
            prior_record = self._version_record(plugin_state, str(prior_active)) if prior_active else None
            carried = set(prior_record.get("granted_permissions", [])) if prior_record else set()
            requested_grants = {str(item).strip() for item in grants if str(item).strip()}
            undeclared = sorted(requested_grants - set(manifest.permissions))
            if undeclared:
                raise ExtensionInstallError(
                    f"cannot grant permissions not declared by the plugin: {', '.join(undeclared)}"
                )
            effective_grants = (carried | requested_grants | set(READ_ONLY_PERMISSIONS)) & set(manifest.permissions)
            missing = set(manifest.permissions) - effective_grants
            if missing:
                raise PermissionGrantRequired(manifest.name, missing)
            install_id = f"{manifest.version}-{content_sha[:16]}"
            destination = self.plugins_root / manifest.name / install_id
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                staging = destination.parent / f".{install_id}.{os.getpid()}.staging"
                if staging.exists():
                    shutil.rmtree(staging)
                self._copy_tree(prepared.root, staging)
                installed_manifest = PluginManifest.load(staging)
                if installed_manifest.name != manifest.name or self._tree_sha256(staging) != content_sha:
                    shutil.rmtree(staging)
                    raise ExtensionInstallError("staged plugin changed during installation")
                staging.replace(destination)
            record = {
                "install_id": install_id,
                "version": manifest.version,
                "content_sha256": content_sha,
                "git_commit": prepared.git_commit,
                "source": prepared.source,
                "source_type": prepared.source_type,
                "path": str(destination),
                "declared_permissions": list(manifest.permissions),
                "granted_permissions": sorted(effective_grants),
                "installed_at": iso_now(),
            }
            versions = [dict(item) for item in plugin_state.get("versions", []) if item.get("install_id") != install_id]
            versions.append(record)
            registry["plugins"][manifest.name] = {
                "active": install_id,
                "versions": versions,
                "disabled": False,
            }
            self._save_registry(registry)
            self._audit(
                "plugin_updated" if prior_active else "plugin_installed",
                {
                    "plugin": manifest.name,
                    "install_id": install_id,
                    "previous_install_id": prior_active,
                    "content_sha256": content_sha,
                    "git_commit": prepared.git_commit,
                    "granted_permissions": sorted(effective_grants),
                },
            )
            return {"status": "ok", "plugin": manifest.name, "active": install_id, "record": record}
        finally:
            prepared.close()

    def rollback_plugin(self, name: str, *, install_id: str | None = None) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        name = validate_identifier(name, label="plugin name")
        registry = self.load_registry()
        state = dict(registry["plugins"].get(name) or {})
        if not state:
            raise ExtensionInstallError(f"plugin not installed: {name}")
        versions = list(state.get("versions", []))
        active = str(state.get("active") or "")
        if install_id is None:
            candidates = [str(item.get("install_id")) for item in versions if item.get("install_id") != active]
            if not candidates:
                raise ExtensionInstallError(f"plugin {name} has no previous version")
            install_id = candidates[-1]
        record = self._version_record(state, install_id)
        if not record or not Path(str(record.get("path"))).is_dir():
            raise ExtensionInstallError(f"plugin version is unavailable: {install_id}")
        PluginManifest.load(Path(str(record["path"])))
        state["active"] = install_id
        state["disabled"] = False
        registry["plugins"][name] = state
        self._save_registry(registry)
        self._audit("plugin_rolled_back", {"plugin": name, "from": active, "to": install_id})
        return {"status": "ok", "plugin": name, "active": install_id, "previous": active}

    def disable_plugin(self, name: str) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        name = validate_identifier(name, label="plugin name")
        registry = self.load_registry()
        state = dict(registry["plugins"].get(name) or {})
        if not state:
            raise ExtensionInstallError(f"plugin not installed: {name}")
        state["disabled"] = True
        registry["plugins"][name] = state
        self._save_registry(registry)
        self._audit("plugin_disabled", {"plugin": name, "active": state.get("active")})
        return {"status": "ok", "plugin": name, "disabled": True, "retained_versions": len(state.get("versions", []))}

    def list_plugins(self) -> list[dict[str, Any]]:
        registry = self.load_registry()
        result: list[dict[str, Any]] = []
        for name, raw_state in sorted(registry["plugins"].items()):
            state = dict(raw_state)
            active = self._version_record(state, str(state.get("active") or ""))
            result.append(
                {
                    "name": name,
                    "active": state.get("active"),
                    "version": active.get("version") if active else None,
                    "content_sha256": active.get("content_sha256") if active else None,
                    "git_commit": active.get("git_commit") if active else None,
                    "declared_permissions": list(active.get("declared_permissions", [])) if active else [],
                    "granted_permissions": list(active.get("granted_permissions", [])) if active else [],
                    "disabled": bool(state.get("disabled")),
                    "retained_version_count": len(state.get("versions", [])),
                }
            )
        return result

    def active_plugins(self) -> list[tuple[PluginManifest, dict[str, Any]]]:
        if self.authority_bound:
            if self._shared_authority is None:
                raise ExtensionInstallError(
                    "bound r4 extension root requires a shared ExtensionAuthority client for active plugin reads"
                )
            authority = self.shared_authority
            projection = authority.load_projection()
            result: list[tuple[PluginManifest, dict[str, Any]]] = []
            defaults = projection.get("defaults") if isinstance(projection.get("defaults"), Mapping) else {}
            for slot_id, default in sorted(defaults.items()):
                slot = dict(default.get("slot") or {}) if isinstance(default, Mapping) else {}
                if str(slot.get("kind") or "") != "plugin" or str(default.get("state") or "ACTIVE") != "ACTIVE":
                    continue
                # Resolve through the authoritative fixed-position resolver;
                # do not derive an active candidate from a cached registry
                # projection or independently rebuild a second default path.
                resolution = authority.resolve_default(slot_id)
                publication_id = str(resolution.get("publication_id") or "")
                candidate_id = str(resolution.get("candidate_id") or "")
                if not candidate_id:
                    continue
                candidate = dict(authority.candidate(candidate_id))
                snapshot = dict(resolution)
                path = Path(str(candidate.get("candidate_path") or ""))
                manifest = PluginManifest.load(path)
                permissions = dict(candidate.get("permissions") or {})
                declared_permissions = tuple(manifest.permissions)
                granted_permissions = tuple(
                    item for item in (permissions.get("granted") or declared_permissions)
                    if item in declared_permissions
                )
                record = {
                    "install_id": candidate.get("install_id"),
                    "version": candidate.get("version"),
                    "content_sha256": candidate.get("tree_hash"),
                    "path": str(path),
                    "declared_permissions": list(declared_permissions),
                    "granted_permissions": list(granted_permissions),
                    "candidate_id": candidate_id,
                    "snapshot_id": snapshot.get("snapshot_id"),
                    "publication_id": publication_id,
                }
                result.append((manifest, record))
            return result
        registry = self.load_registry()
        result: list[tuple[PluginManifest, dict[str, Any]]] = []
        for name, raw_state in sorted(registry["plugins"].items()):
            state = dict(raw_state)
            if state.get("disabled"):
                continue
            record = self._version_record(state, str(state.get("active") or ""))
            if not record:
                continue
            path = Path(str(record.get("path") or ""))
            manifest = PluginManifest.load(path)
            if self._tree_sha256(path) != str(record.get("content_sha256")):
                raise ExtensionInstallError(f"installed plugin integrity check failed: {name}")
            result.append((manifest, record))
        return result

    def install_skill(self, source: str | Path) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        source_path = Path(source).expanduser().resolve(strict=True)
        skill_file = source_path / "SKILL.md" if source_path.is_dir() else source_path
        skill = load_skill(skill_file)
        source_root = skill_file.parent
        content_sha = self._tree_sha256(source_root)
        install_id = content_sha[:16]
        destination = self.skills_root / skill.name / install_id
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            staging = destination.parent / f".{install_id}.{os.getpid()}.staging"
            if staging.exists():
                shutil.rmtree(staging)
            self._copy_tree(source_root, staging)
            load_skill(staging / "SKILL.md")
            staging.replace(destination)
        registry = self.load_registry()
        prior = dict(registry["skills"].get(skill.name) or {})
        versions = [dict(item) for item in prior.get("versions", []) if item.get("install_id") != install_id]
        record = {
            "install_id": install_id,
            "content_sha256": content_sha,
            "source": str(source_path),
            "path": str(destination),
            "installed_at": iso_now(),
        }
        versions.append(record)
        registry["skills"][skill.name] = {"active": install_id, "versions": versions, "disabled": False}
        self._save_registry(registry)
        self._audit("skill_installed", {"skill": skill.name, "install_id": install_id, "content_sha256": content_sha})
        return {"status": "ok", "skill": skill.name, "active": install_id, "record": record}

    def rollback_skill(self, name: str, *, install_id: str | None = None) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        name = validate_identifier(name, label="skill name")
        registry = self.load_registry()
        state = dict(registry["skills"].get(name) or {})
        if not state:
            raise ExtensionInstallError(f"skill not installed: {name}")
        versions = list(state.get("versions", []))
        active = str(state.get("active") or "")
        if install_id is None:
            candidates = [str(item.get("install_id")) for item in versions if item.get("install_id") != active]
            if not candidates:
                raise ExtensionInstallError(f"skill {name} has no previous version")
            install_id = candidates[-1]
        record = self._version_record(state, install_id)
        if not record or not Path(str(record.get("path"))).is_dir():
            raise ExtensionInstallError(f"skill version is unavailable: {install_id}")
        load_skill(Path(str(record["path"])) / "SKILL.md")
        state["active"] = install_id
        state["disabled"] = False
        registry["skills"][name] = state
        self._save_registry(registry)
        self._audit("skill_rolled_back", {"skill": name, "from": active, "to": install_id})
        return {"status": "ok", "skill": name, "active": install_id, "previous": active}

    def disable_skill(self, name: str) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        name = validate_identifier(name, label="skill name")
        registry = self.load_registry()
        state = dict(registry["skills"].get(name) or {})
        if not state:
            raise ExtensionInstallError(f"skill not installed: {name}")
        state["disabled"] = True
        registry["skills"][name] = state
        self._save_registry(registry)
        self._audit("skill_disabled", {"skill": name, "active": state.get("active")})
        return {"status": "ok", "skill": name, "disabled": True, "retained_versions": len(state.get("versions", []))}

    def skills(self) -> list[SkillDefinition]:
        if self.authority_bound:
            if self._shared_authority is None:
                raise ExtensionInstallError(
                    "bound r4 extension root requires a shared ExtensionAuthority client for active skill reads"
                )
            authority = self.shared_authority
            projection = authority.load_projection()
            result: list[SkillDefinition] = []
            defaults = projection.get("defaults") if isinstance(projection.get("defaults"), Mapping) else {}
            for _slot_id, default in sorted(defaults.items()):
                slot = dict(default.get("slot") or {}) if isinstance(default, Mapping) else {}
                if str(slot.get("kind") or "") != "skill" or str(default.get("state") or "ACTIVE") != "ACTIVE":
                    continue
                resolution = authority.resolve_default(str(_slot_id))
                candidate_id = str(resolution.get("candidate_id") or "")
                if not candidate_id:
                    continue
                candidate = dict(authority.candidate(candidate_id))
                path = Path(str(candidate.get("candidate_path") or ""))
                result.append(load_skill(path / "SKILL.md"))
            for manifest, _record in self.active_plugins():
                path = manifest.component_path("skills")
                if path:
                    result.extend(load_skill(item, plugin_name=manifest.name) for item in sorted(path.glob("*/SKILL.md")))
            return result
        registry = self.load_registry()
        result: list[SkillDefinition] = []
        for name, raw_state in sorted(registry["skills"].items()):
            state = dict(raw_state)
            if state.get("disabled"):
                continue
            record = self._version_record(state, str(state.get("active") or ""))
            if record:
                result.append(load_skill(Path(str(record["path"])) / "SKILL.md"))
        for manifest, _record in self.active_plugins():
            path = manifest.component_path("skills")
            if path:
                result.extend(load_skill(item, plugin_name=manifest.name) for item in sorted(path.glob("*/SKILL.md")))
        return result

    def agents(self) -> list[AgentDefinition]:
        result: list[AgentDefinition] = []
        for manifest, _record in self.active_plugins():
            path = manifest.component_path("agents")
            if path:
                result.extend(load_agent(item, plugin_name=manifest.name) for item in sorted(path.glob("*.md")))
        return result

    def select_skills(self, task: str) -> list[SkillDefinition]:
        text = task.casefold()
        explicit = set(re.findall(r"\$([a-z0-9][a-z0-9_-]{1,63}(?::[a-z0-9][a-z0-9_-]{1,63})?)", text))
        selected: list[SkillDefinition] = []
        for skill in self.skills():
            explicit_match = skill.qualified_name in explicit or (skill.plugin_name is None and skill.name in explicit)
            trigger_match = any(trigger and trigger in text for trigger in skill.triggers)
            name_match = len(skill.name) >= 4 and skill.name.replace("_", " ") in text
            if explicit_match or trigger_match or name_match:
                selected.append(skill)
        missing = explicit - {item.qualified_name for item in selected} - {item.name for item in selected if item.plugin_name is None}
        if missing:
            raise ExtensionInstallError(f"requested skills are not installed: {', '.join(sorted(missing))}")
        return selected

    def select_agents(self, task: str) -> list[AgentDefinition]:
        text = task.casefold()
        return [agent for agent in self.agents() if any(trigger and trigger in text for trigger in agent.triggers)]

    def add_marketplace(self, source: str, *, approve_network: bool = False) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        parsed = urlparse(source)
        if parsed.scheme in {"http", "https"}:
            if not approve_network:
                raise ExtensionInstallError("network approval is required to download a marketplace manifest")
            with authorized_extension_effect(
                permission="install_network",
                approval_granted=True,
                purpose="marketplace-download",
            ):
                with urllib.request.urlopen(source, timeout=30) as response:
                    raw_bytes = response.read()
            try:
                manifest = json.loads(raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ExtensionInstallError(f"marketplace response is not valid JSON: {exc}") from exc
        else:
            manifest = read_json_object(Path(source).expanduser().resolve(strict=True))
            raw_bytes = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode()
        if not isinstance(manifest, dict) or manifest.get("schema") != MARKETPLACE_SCHEMA:
            raise ExtensionInstallError(f"marketplace must use schema {MARKETPLACE_SCHEMA}")
        name = validate_identifier(str(manifest.get("name") or ""), label="marketplace name")
        plugins = manifest.get("plugins")
        if not isinstance(plugins, list) or any(not isinstance(item, dict) for item in plugins):
            raise ExtensionInstallError("marketplace plugins must be an array of objects")
        digest = hashlib.sha256(raw_bytes).hexdigest()
        registry = self.load_registry()
        registry["marketplaces"][name] = {
            "source": source,
            "sha256": digest,
            "manifest": manifest,
            "added_at": iso_now(),
        }
        self._save_registry(registry)
        self._audit("marketplace_added", {"marketplace": name, "source": source, "sha256": digest})
        return {"status": "ok", "marketplace": name, "sha256": digest, "plugin_count": len(plugins)}

    def install_from_marketplace(
        self,
        marketplace: str,
        plugin: str,
        *,
        grants: Iterable[str] = (),
        approve_network: bool = False,
    ) -> dict[str, Any]:
        self._assert_legacy_mutation_allowed()
        marketplace = validate_identifier(marketplace, label="marketplace name")
        plugin = validate_identifier(plugin, label="plugin name")
        registry = self.load_registry()
        record = dict(registry["marketplaces"].get(marketplace) or {})
        if not record:
            raise ExtensionInstallError(f"marketplace is not registered: {marketplace}")
        items = dict(record.get("manifest") or {}).get("plugins", [])
        entry = next((item for item in items if str(item.get("name") or "").casefold() == plugin), None)
        if not entry:
            raise ExtensionInstallError(f"plugin {plugin} is not present in marketplace {marketplace}")
        source = str(entry.get("source") or "")
        if not source:
            raise ExtensionInstallError("marketplace entry has no source")
        return self.install_plugin(
            source,
            grants=grants,
            approve_network=approve_network,
            expected_sha256=str(entry.get("sha256") or "") or None,
            git_ref=str(entry.get("git_ref") or "") or None,
            update=False,
        )

    def prepare_plugin_candidate(
        self,
        source: str | Path,
        *,
        grants: Iterable[str] = (),
        expected_sha256: str | None = None,
        execution_context: Any | None = None,
    ) -> PreparedCandidate:
        """Prepare a complete immutable plugin candidate without changing default."""

        if self._shared_authority is None:
            raise CandidatePreparationError(
                "candidate preparation requires a bound shared Journal/CAS authority"
            )
        return self._shared_authority.prepare_plugin(
            source,
            grants=tuple(str(item) for item in grants),
            expected_sha256=expected_sha256,
            execution_context=execution_context,
        )

    def prepare_skill_candidate(
        self,
        source: str | Path,
        *,
        execution_context: Any | None = None,
    ) -> PreparedCandidate:
        """Prepare a complete immutable Skill candidate without changing default."""

        if self._shared_authority is None:
            raise CandidatePreparationError(
                "candidate preparation requires a bound shared Journal/CAS authority"
            )
        return self._shared_authority.prepare_skill(source, execution_context=execution_context)

    def create_extension_preparation_context(
        self,
        task_id: str,
        source: str | Path,
        *,
        operation_id: str | None = None,
    ) -> Any:
        """Create the Loop-issued context required by candidate preparation."""

        if self._shared_authority is None:
            raise CandidatePreparationError(
                "candidate preparation requires a bound shared Journal/CAS authority"
            )
        return self._shared_authority.create_preparation_context(
            task_id,
            source,
            operation_id=operation_id,
        )

    @staticmethod
    def _version_record(state: Mapping[str, Any], install_id: str) -> dict[str, Any]:
        return next((dict(item) for item in state.get("versions", []) if item.get("install_id") == install_id), {})

    def _prepare_source(
        self,
        source: str | Path,
        *,
        approve_network: bool,
        git_ref: str | None,
    ) -> PreparedSource:
        raw = str(source)
        path = Path(raw).expanduser()
        if path.exists():
            resolved = path.resolve(strict=True)
            if resolved.is_dir():
                return PreparedSource(resolved, str(resolved), "local_directory")
            if resolved.is_file() and zipfile.is_zipfile(resolved):
                temporary = tempfile.TemporaryDirectory(prefix="sitina-plugin-zip-")
                root = Path(temporary.name)
                self._safe_extract_zip(resolved, root)
                plugin_root = self._locate_plugin_root(root)
                return PreparedSource(plugin_root, str(resolved), "local_zip", temporary=temporary)
            raise ExtensionInstallError("local plugin source must be a directory or zip archive")
        if not self._looks_like_git_source(raw):
            raise ExtensionInstallError(f"plugin source does not exist: {raw}")
        if not approve_network:
            raise ExtensionInstallError("network approval is required to clone a Git plugin source")
        temporary = tempfile.TemporaryDirectory(prefix="sitina-plugin-git-")
        clone_root = Path(temporary.name) / "repo"
        command = ["git", "clone", "--no-tags", "--filter=blob:none", raw, str(clone_root)]
        with authorized_extension_effect(
            permission="install_network",
            approval_granted=True,
            purpose="plugin-git-clone",
        ):
            result = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
            if result.returncode != 0:
                temporary.cleanup()
                raise ExtensionInstallError(f"Git clone failed: {result.stderr.strip()[-500:]}")
            if git_ref:
                checkout = subprocess.run(
                    ["git", "-C", str(clone_root), "checkout", "--detach", git_ref],
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if checkout.returncode != 0:
                    temporary.cleanup()
                    raise ExtensionInstallError(f"Git ref checkout failed: {checkout.stderr.strip()[-500:]}")
            commit_result = subprocess.run(
                ["git", "-C", str(clone_root), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        if commit_result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", commit_result.stdout.strip()):
            temporary.cleanup()
            raise ExtensionInstallError("could not pin the cloned Git commit")
        return PreparedSource(
            clone_root,
            raw,
            "git",
            git_commit=commit_result.stdout.strip(),
            temporary=temporary,
        )

    @staticmethod
    def _looks_like_git_source(value: str) -> bool:
        parsed = urlparse(value)
        return parsed.scheme in {"https", "http", "ssh", "git"} or value.startswith("git@")

    @staticmethod
    def _safe_extract_zip(source: Path, destination: Path) -> None:
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                relative = Path(info.filename)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ExtensionInstallError(f"zip entry escapes extraction root: {info.filename}")
                target = destination / relative
                try:
                    target.resolve(strict=False).relative_to(destination.resolve(strict=True))
                except ValueError as exc:
                    raise ExtensionInstallError(f"zip entry escapes extraction root: {info.filename}") from exc
                mode = info.external_attr >> 16
                if mode and (mode & 0o170000) == 0o120000:
                    raise ExtensionInstallError(f"zip symlinks are not allowed: {info.filename}")
            archive.extractall(destination)

    @staticmethod
    def _locate_plugin_root(root: Path) -> Path:
        direct = root / ".sitina-plugin" / "plugin.json"
        if direct.is_file():
            return root
        candidates = list(root.glob("*/.sitina-plugin/plugin.json"))
        if len(candidates) != 1:
            raise ExtensionInstallError("zip must contain exactly one Sitina plugin root")
        return candidates[0].parent.parent

    @staticmethod
    def _tree_sha256(root: Path) -> str:
        digest = hashlib.sha256()
        root = root.resolve(strict=True)
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            relative = path.relative_to(root)
            if ".git" in relative.parts:
                continue
            if path.is_symlink():
                raise ExtensionInstallError(f"plugin symlinks are not allowed: {relative}")
            if path.is_dir():
                continue
            digest.update(relative.as_posix().encode("utf-8") + b"\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\0")
        return digest.hexdigest()

    @staticmethod
    def _copy_tree(source: Path, destination: Path) -> None:
        def ignore(_directory: str, names: list[str]) -> set[str]:
            return {".git"} & set(names)

        shutil.copytree(source, destination, symlinks=False, ignore=ignore)
