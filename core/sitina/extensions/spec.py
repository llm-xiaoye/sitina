from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


PLUGIN_SCHEMA = "SITINA_PLUGIN_V1"
SKILL_SCHEMA = "SITINA_SKILL_V1"
AGENT_SCHEMA = "SITINA_PLUGIN_AGENT_V1"
TOOLS_SCHEMA = "SITINA_TOOLS_V1"
MCP_SCHEMA = "SITINA_MCP_V1"
HOOKS_SCHEMA = "SITINA_HOOKS_V1"
REGISTRY_SCHEMA = "SITINA_EXTENSION_REGISTRY_V1"
MARKETPLACE_SCHEMA = "SITINA_MARKETPLACE_V1"

PERMISSIONS = frozenset({"read", "write", "shell", "network", "external_service"})
READ_ONLY_PERMISSIONS = frozenset({"read"})
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class ExtensionSpecError(ValueError):
    pass


def validate_identifier(value: str, *, label: str) -> str:
    normalized = str(value).strip().lower()
    if not IDENTIFIER.fullmatch(normalized):
        raise ExtensionSpecError(f"{label} must match {IDENTIFIER.pattern}")
    return normalized


def validate_permissions(values: Any, *, label: str) -> tuple[str, ...]:
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ExtensionSpecError(f"{label} must be an array of permission names")
    normalized = tuple(sorted(set(str(item).strip() for item in values)))
    unknown = sorted(set(normalized) - PERMISSIONS)
    if unknown:
        raise ExtensionSpecError(f"{label} contains unsupported permissions: {', '.join(unknown)}")
    return normalized


def read_json_object(path: Path, *, schema: str | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ExtensionSpecError(f"required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ExtensionSpecError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ExtensionSpecError(f"{path} must contain one JSON object")
    if schema is not None and value.get("schema") != schema:
        raise ExtensionSpecError(f"{path} must use schema {schema}")
    return value


def _safe_component_path(root: Path, raw: str, *, label: str, required: bool = False) -> Path:
    relative = Path(str(raw))
    if relative.is_absolute() or ".." in relative.parts:
        raise ExtensionSpecError(f"{label} must be a relative path without '..'")
    path = root / relative
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ExtensionSpecError(f"{label} escapes the plugin root") from exc
    if required and not path.exists():
        raise ExtensionSpecError(f"{label} does not exist: {relative}")
    return path


def parse_json_frontmatter(path: Path, *, schema: str) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        raise ExtensionSpecError(f"{path} must start with Sitina JSON frontmatter between --- lines")
    try:
        closing = next(index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration as exc:
        raise ExtensionSpecError(f"{path} is missing the closing frontmatter delimiter") from exc
    raw = "\n".join(lines[1:closing]).strip()
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtensionSpecError(f"{path} frontmatter must be one JSON object: {exc}") from exc
    if not isinstance(metadata, dict) or metadata.get("schema") != schema:
        raise ExtensionSpecError(f"{path} frontmatter must use schema {schema}")
    body = "\n".join(lines[closing + 1 :]).strip()
    if not body:
        raise ExtensionSpecError(f"{path} must contain instructions after frontmatter")
    return metadata, body


@dataclass(frozen=True)
class SkillDefinition:
    name: str
    description: str
    triggers: tuple[str, ...]
    path: Path
    body: str
    plugin_name: str | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.plugin_name}:{self.name}" if self.plugin_name else self.name

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "description": self.description,
            "triggers": list(self.triggers),
            "plugin": self.plugin_name,
            "path": str(self.path),
        }


def load_skill(path: Path, *, plugin_name: str | None = None) -> SkillDefinition:
    metadata, body = parse_json_frontmatter(path, schema=SKILL_SCHEMA)
    name = validate_identifier(str(metadata.get("name") or ""), label="skill name")
    description = str(metadata.get("description") or "").strip()
    if not description:
        raise ExtensionSpecError(f"{path} requires a non-empty description")
    raw_triggers = metadata.get("triggers", [])
    if not isinstance(raw_triggers, list) or any(not isinstance(item, str) for item in raw_triggers):
        raise ExtensionSpecError(f"{path} triggers must be an array of strings")
    triggers = tuple(dict.fromkeys(item.strip().casefold() for item in raw_triggers if item.strip()))
    return SkillDefinition(name, description, triggers, path.resolve(), body, plugin_name)


@dataclass(frozen=True)
class AgentDefinition:
    name: str
    description: str
    triggers: tuple[str, ...]
    body: str
    path: Path
    plugin_name: str


def load_agent(path: Path, *, plugin_name: str) -> AgentDefinition:
    metadata, body = parse_json_frontmatter(path, schema=AGENT_SCHEMA)
    name = validate_identifier(str(metadata.get("name") or ""), label="agent name")
    description = str(metadata.get("description") or "").strip()
    raw_triggers = metadata.get("triggers", [])
    if not description or not isinstance(raw_triggers, list) or any(not isinstance(item, str) for item in raw_triggers):
        raise ExtensionSpecError(f"{path} requires description and string-array triggers")
    return AgentDefinition(
        name,
        description,
        tuple(dict.fromkeys(item.strip().casefold() for item in raw_triggers if item.strip())),
        body,
        path.resolve(),
        plugin_name,
    )


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    description: str
    permissions: tuple[str, ...]
    root: Path
    manifest_path: Path
    components: Mapping[str, str]

    @classmethod
    def load(cls, root: Path) -> "PluginManifest":
        root = Path(root).expanduser().resolve(strict=True)
        manifest_path = root / ".sitina-plugin" / "plugin.json"
        raw = read_json_object(manifest_path, schema=PLUGIN_SCHEMA)
        name = validate_identifier(str(raw.get("name") or ""), label="plugin name")
        version = str(raw.get("version") or "").strip()
        if not VERSION.fullmatch(version):
            raise ExtensionSpecError("plugin version is empty or invalid")
        description = str(raw.get("description") or "").strip()
        if not description:
            raise ExtensionSpecError("plugin description is required")
        permissions = validate_permissions(raw.get("permissions", []), label="plugin permissions")
        raw_components = raw.get("components", {})
        if not isinstance(raw_components, dict):
            raise ExtensionSpecError("plugin components must be an object")
        allowed = {"skills", "agents", "tools", "mcp", "hooks"}
        unknown = sorted(set(raw_components) - allowed)
        if unknown:
            raise ExtensionSpecError(f"plugin components contains unsupported keys: {', '.join(unknown)}")
        defaults = {
            "skills": "skills",
            "agents": "agents",
            "tools": ".sitina-plugin/tools.json",
            "mcp": ".sitina-plugin/mcp.json",
            "hooks": ".sitina-plugin/hooks.json",
        }
        components: dict[str, str] = {}
        for key, raw_path in {**defaults, **raw_components}.items():
            if raw_path is None:
                continue
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise ExtensionSpecError(f"component {key} must be a non-empty relative path")
            path = _safe_component_path(root, raw_path, label=f"component {key}")
            if key in raw_components and not path.exists():
                raise ExtensionSpecError(f"declared component {key} does not exist")
            if path.exists():
                components[key] = raw_path
        manifest = cls(name, version, description, permissions, root, manifest_path, components)
        manifest.validate_components()
        return manifest

    def component_path(self, name: str) -> Path | None:
        raw = self.components.get(name)
        return _safe_component_path(self.root, raw, label=f"component {name}") if raw else None

    def validate_components(self) -> None:
        skills = self.component_path("skills")
        if skills:
            if not skills.is_dir():
                raise ExtensionSpecError("skills component must be a directory")
            for skill_file in sorted(skills.glob("*/SKILL.md")):
                load_skill(skill_file, plugin_name=self.name)
        agents = self.component_path("agents")
        if agents:
            if not agents.is_dir():
                raise ExtensionSpecError("agents component must be a directory")
            for agent_file in sorted(agents.glob("*.md")):
                load_agent(agent_file, plugin_name=self.name)
        expected_schemas = {"tools": TOOLS_SCHEMA, "mcp": MCP_SCHEMA, "hooks": HOOKS_SCHEMA}
        for component, schema in expected_schemas.items():
            path = self.component_path(component)
            if path:
                raw = read_json_object(path, schema=schema)
                for permission in _component_permissions(component, raw):
                    if permission not in self.permissions:
                        raise ExtensionSpecError(
                            f"{component} requests permission {permission!r} not declared by the plugin"
                        )
                if component == "tools":
                    _validate_tools(raw)
                elif component == "mcp":
                    _validate_mcp(raw)
                else:
                    _validate_hooks(raw)

    def mapping(self) -> dict[str, Any]:
        return {
            "schema": PLUGIN_SCHEMA,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "permissions": list(self.permissions),
            "components": dict(self.components),
        }


def _component_permissions(component: str, raw: Mapping[str, Any]) -> tuple[str, ...]:
    if component == "tools":
        items = raw.get("tools", [])
    elif component == "mcp":
        items = raw.get("servers", [])
    else:
        items = [hook for hooks in dict(raw.get("events") or {}).values() for hook in (hooks or [])]
    if not isinstance(items, list):
        raise ExtensionSpecError(f"{component} entries must be an array")
    permissions: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise ExtensionSpecError(f"{component} entries must be objects")
        permission = str(item.get("permission") or "").strip()
        if permission not in PERMISSIONS:
            raise ExtensionSpecError(f"{component} entry has invalid permission {permission!r}")
        permissions.append(permission)
    return tuple(permissions)


def _validate_tools(raw: Mapping[str, Any]) -> None:
    tools = raw.get("tools", [])
    if not isinstance(tools, list):
        raise ExtensionSpecError("tools must be an array")
    names: set[str] = set()
    for item in tools:
        name = validate_identifier(str(item.get("name") or ""), label="tool name")
        if name in names:
            raise ExtensionSpecError(f"duplicate plugin tool name: {name}")
        names.add(name)
        if item.get("permission") != "shell":
            raise ExtensionSpecError(
                f"plugin command tool {name} must declare shell permission because it starts a process"
            )
        if not str(item.get("description") or "").strip():
            raise ExtensionSpecError(f"plugin tool {name} requires a description")
        command = item.get("command")
        if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
            raise ExtensionSpecError(f"plugin tool {name} command must be a non-empty string array")
        schema = item.get("input_schema", {"type": "object", "properties": {}})
        if not isinstance(schema, dict) or schema.get("type", "object") != "object":
            raise ExtensionSpecError(f"plugin tool {name} input_schema must describe an object")


def _validate_mcp(raw: Mapping[str, Any]) -> None:
    servers = raw.get("servers", [])
    if not isinstance(servers, list):
        raise ExtensionSpecError("MCP servers must be an array")
    names: set[str] = set()
    for server in servers:
        name = validate_identifier(str(server.get("name") or ""), label="MCP server name")
        if name in names:
            raise ExtensionSpecError(f"duplicate MCP server name: {name}")
        names.add(name)
        transport = str(server.get("transport") or "stdio")
        if transport == "stdio":
            if server.get("permission") != "shell":
                raise ExtensionSpecError(
                    f"stdio MCP server {name} must declare shell permission because it starts a process"
                )
            command = server.get("command")
            if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
                raise ExtensionSpecError(f"stdio MCP server {name} requires a non-empty command array")
        elif transport in {"http", "streamable_http"}:
            if server.get("permission") not in {"network", "external_service"}:
                raise ExtensionSpecError(
                    f"remote MCP server {name} must declare network or external_service permission"
                )
            url = str(server.get("url") or "")
            if not url.startswith(("https://", "http://")):
                raise ExtensionSpecError(f"remote MCP server {name} requires an absolute http(s) URL")
        else:
            raise ExtensionSpecError(f"MCP server {name} uses unsupported transport {transport!r}")
        advertised = server.get("tools")
        if advertised is not None:
            if not isinstance(advertised, list):
                raise ExtensionSpecError(f"MCP server {name} tools must be an array")
            for tool in advertised:
                if not isinstance(tool, dict):
                    raise ExtensionSpecError(f"MCP server {name} tool entries must be objects")
                validate_identifier(str(tool.get("name") or ""), label="MCP tool name")
                schema = tool.get("input_schema", {"type": "object", "properties": {}})
                if not isinstance(schema, dict) or schema.get("type", "object") != "object":
                    raise ExtensionSpecError(f"MCP tool schema for {name} must describe an object")


def _validate_hooks(raw: Mapping[str, Any]) -> None:
    events = raw.get("events", {})
    if not isinstance(events, dict):
        raise ExtensionSpecError("hook events must be an object")
    supported = {"before_agent", "after_agent", "before_tool", "after_tool"}
    unknown = sorted(set(events) - supported)
    if unknown:
        raise ExtensionSpecError(f"unsupported lifecycle hook events: {', '.join(unknown)}")
    for event, hooks in events.items():
        if not isinstance(hooks, list):
            raise ExtensionSpecError(f"hooks for {event} must be an array")
        for hook in hooks:
            if not isinstance(hook, dict):
                raise ExtensionSpecError(f"hooks for {event} must be objects")
            command = hook.get("command")
            if hook.get("permission") != "shell":
                raise ExtensionSpecError(
                    f"hook {event} must declare shell permission because it starts a process"
                )
            if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
                raise ExtensionSpecError(f"hook {event} command must be a non-empty string array")
