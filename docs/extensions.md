# Sitina-native Skills, Plugins, and autonomous tools

Sitina has its own extension format. It does not install or interpret Claude
Code or Codex plugin manifests. Installed extensions live under
`$SITINA_EXTENSIONS_HOME`, or `~/.sitina/extensions` when the variable is not
set. Set this variable explicitly for independent installations and test
instances. Global settings determine what a new task can bind; an existing
native task retains its authenticated Skill versions.

## Runtime behavior

`sitina agent` always runs the autonomous tool loop. Once at least one global
Skill or Plugin is active, `sitina chat` and live/auto `sitina run` use the same
loop. The model receives a unified catalog containing Sitina built-ins,
declarative plugin commands, local or remote MCP tools, and the resource reader
for selected Skills.

The loop supports both Anthropic Messages `tool_use`/`tool_result` and
OpenAI-compatible Chat Completions `tool_calls`/`tool` messages. There is no
fixed model-turn count, tool-call count, duplicate-call limit, or fixed
read-concurrency ceiling. A run ends when the model returns a final answer,
the caller cancels, the Provider fails, or approvals prevent further progress.

Read-only tools run automatically. Every write, shell, network, and external
service call requires a decision from the approval callback. A plugin can use
only permissions declared in its installed manifest and granted in the global
registry. Plugin Python is never imported into Sitina; command tools, hooks,
and stdio MCP servers run as child processes.

## Plugin format

A plugin root contains `.sitina-plugin/plugin.json`:

```json
{
  "schema": "SITINA_PLUGIN_V1",
  "name": "example_plugin",
  "version": "1.0.0",
  "description": "An example Sitina-native plugin.",
  "permissions": ["read", "shell"],
  "components": {
    "skills": "skills",
    "agents": "agents",
    "tools": ".sitina-plugin/tools.json",
    "mcp": ".sitina-plugin/mcp.json",
    "hooks": ".sitina-plugin/hooks.json"
  }
}
```

Component paths are optional. If omitted, existing conventional paths are
discovered. Absolute paths, traversal, and symlinks are rejected. Supported
permissions are `read`, `write`, `shell`, `network`, and `external_service`.

### Skills

Each Skill is a directory containing `SKILL.md`. Plugin Skills use
`skills/<name>/SKILL.md`; standalone Skills use the directory root. YAML
frontmatter is supported, and existing `SITINA_SKILL_V1` JSON frontmatter
remains compatible:

```markdown
---
name: release_notes
description: Creates release notes from changes.
version: '1'
triggers:
  - release notes
  - changelog
---
Follow the repository's release-note structure. Read references/style.md when needed.
```

Metadata participates in automatic selection. `$release_notes` and
`$plugin_name:release_notes` select a Skill explicitly. Multiple matching
Skills are inserted into the same model loop. References, assets, and script
sources remain outside the prompt until the model calls
`sitina_read_skill_resource`.

Standalone global Skills use the same file format and can be installed without
a Plugin. Descriptions and metadata support discovery; a task loads the body
and resources only when needed. Skill instructions and `allowed-tools` metadata
do not grant file, network, shell, or other execution permissions.

The Skills page supports local directories, single `SKILL.md` files, ZIP
packages, and anonymous public sources. For a Skill inside a GitHub repository,
use `https://github.com/owner/repo/tree/<40-hex-commit>/path/to/skill`.
The complete commit is required: branch names such as `main` are not pinned.
The existing anonymous gateway downloads that commit's archive and installs
the selected directory with its scripts, references, and assets. Sibling
directories are not installed as part of that Skill. Root Git repositories
and direct ZIP/Markdown sources remain supported; authenticated sources and
fallback download routes are not introduced.

Updating, disabling, enabling, and rolling back change the default for new
task bindings. They do not replace a version already bound by an existing
task. For example, a task bound to v1 keeps v1 after a global update to v2;
a new task receives v2. Disabling prevents new bindings while retaining
existing versions and their resources.

Native tasks expose `sitina_task_skills` to inspect or load their pinned roster
and to change task-local exclusions. An excluded Skill cannot be newly selected
or loaded, and its resource root is removed from the task's available reads.
History still records earlier use. Removing an exclusion restores access to
the task's original pinned version, without changing global settings.

### Declarative command tools

`.sitina-plugin/tools.json` uses `SITINA_TOOLS_V1`:

```json
{
  "schema": "SITINA_TOOLS_V1",
  "tools": [{
    "name": "inspect_project",
    "description": "Inspect the project and return JSON evidence.",
    "permission": "shell",
    "command": ["./scripts/inspect.py"],
    "input_schema": {"type":"object","properties":{"path":{"type":"string"}},"required":["path"]},
    "output_json": true
  }]
}
```

The tool receives its arguments as JSON on stdin. Relative executables resolve
inside the immutable installed plugin directory.

### MCP

`.sitina-plugin/mcp.json` uses `SITINA_MCP_V1`. `stdio`, `http`, and
`streamable_http` transports are accepted. Declaring individual tools gives
the model their exact schemas; omitting `tools` exposes one generic `call`
tool for the server.

```json
{
  "schema": "SITINA_MCP_V1",
  "servers": [{
    "name": "local_index",
    "transport": "stdio",
    "permission": "shell",
    "command": ["./bin/index-mcp"],
    "tools": [{
      "name": "search",
      "description": "Search the local index.",
      "input_schema": {"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}
    }]
  }]
}
```

Remote MCP entries use `url` and a declared `network` or `external_service`
permission. Optional `headers` are passed by the subprocess/network adapter;
secrets should remain in the local installation rather than the manifest.

### Hooks and plugin Agents

`.sitina-plugin/hooks.json` uses `SITINA_HOOKS_V1` and can declare
`before_agent`, `after_agent`, `before_tool`, and `after_tool` command arrays.
Every hook has its own permission and passes through the same approval gate.

Plugin Agents are `agents/*.md` with JSON frontmatter schema
`SITINA_PLUGIN_AGENT_V1`, `name`, `description`, and `triggers`. Matching Agent
instructions are composed with matching Skills; they do not create an
in-process Python extension point.

## Installation, update, and rollback

Local directories and zip files do not require network approval:

```bash
sitina plugin install ./my-plugin --grant shell
sitina plugin install ./my-plugin.zip --grant external_service
```

Git is always explicit and network-approved. A ref can be a branch, tag, or
commit; the resolved commit and complete content SHA-256 are pinned:

```bash
sitina plugin install https://example.com/team/plugin.git \
  --git-ref v1.2.0 --approve-network --grant shell
```

There is no automatic update. Updates are explicit, preserve every prior
installed version, and stop if a new permission has not been granted:

```bash
sitina plugin update example_plugin --approve-network --grant network
sitina plugin rollback example_plugin
sitina plugin rollback example_plugin --to 1.0.0-<content-prefix>
```

Disabling is recoverable and retains all files:

```bash
sitina plugin disable example_plugin
```

Standalone Skills:

```bash
sitina skill install ./release-notes-skill
sitina skill list
sitina skill show release_notes
sitina skill rollback release_notes
sitina skill disable release_notes
```

## Native marketplaces

A marketplace is a JSON object with schema `SITINA_MARKETPLACE_V1`, a native
name, and `plugins` entries containing `name`, `source`, and optional
`git_ref`/`sha256`. Registering a remote manifest and installing its entry both
require the explicit network flag:

```bash
sitina plugin marketplace-add https://example.com/sitina-marketplace.json --approve-network
sitina plugin marketplace-list
sitina plugin marketplace-install team example_plugin --approve-network --grant shell
```

## Running tasks

```bash
sitina agent '$release_notes summarize this repository'
sitina agent --workspace /path/to/project 'inspect and fix the failing tests'
sitina agent --mock-script examples/mock-tool-script.json 'offline tool-loop rehearsal'
sitina plugin install examples/sitina-native-plugin --grant shell
sitina agent --mock-script examples/mock-plugin-tool-script.json --approve-risky 'plugin rehearsal'
sitina chat
sitina run 'complete the task with the installed project tools'
```

In an interactive terminal, risky calls ask once per call. Non-interactive runs
deny risky calls unless `--approve-risky` is supplied. That flag applies only
to the current run and does not modify plugin grants.
