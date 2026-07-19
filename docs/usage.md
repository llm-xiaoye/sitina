# Sitina Usage

This document describes the current Python-backed Sitina harness in
`/Users/moss/SitinaHub`.

## Entry Point

Use the explicit entrypoint:

```bash
/Users/moss/SitinaHub/bin/sitina <command>
```

If your shell has `/Users/moss/SitinaHub/bin` on `PATH`, the shorter form also
works:

```bash
sitina <command>
```

## Interactive Conversation

Start a conversation by entering only:

```bash
sitina
```

This is equivalent to `sitina chat` in an interactive terminal. The default
mode is `AUTO`: a deterministic local router sends simple messages to `FAST`
and complex messages to `MULTI`. Routing itself does not call a Provider.
The prompt always shows the selected session mode:

```text
你 [auto] >
你 [fast] >
你 [multi] >
```

`FAST` uses one registered synthesis Agent and, on the normal success path,
exactly one logical DeepSeek call and one physical send. It has no Proposal
competition and no Reviewer. In `AUTO`, a FAST result may request escalation
or report low confidence; Sitina then hides the unreviewed candidate and runs
`MULTI`. Forced `/fast` never upgrades silently.

`MULTI` performs goal analysis, at least two independent candidate Proposals,
and independent review, then prints only the selected answer after a successful
terminal decision. Forced `/multi` uses that path even for a greeting.

Interactive commands:

```text
/fast   keep subsequent messages on one Agent; never auto-upgrade
/multi  keep subsequent messages on reviewed multi-Agent execution
/auto   restore deterministic automatic routing
/mode   show the current mode, previous actual route, and reasons
/new    clear successful in-process context and failed-message state; keep mode
/retry  rerun only the last failed or cancelled user message
/help   show every command and its effect
/exit   leave Sitina normally (/quit is equivalent)
```

Only successful final answers enter context. The current process keeps at most
six successful turns and 12,000 characters. Failures, cancellation, auth
errors, and network errors do not enter context. No conversation state is
restored from `state/active_conversation.json`, `logs/conversations`, or
Legacy SQLite.

All three modes are provider-text-only and read-only: chat cannot write project
files, run shell commands, mutate Git, call remote MCP, publish, or accept
Memory. Execution requests receive analysis or a plan and should be performed
through an explicit non-chat command. The path uses Sitina's Production
Journal/CAS, Effect/Result admission, usage accounting, and Secret scan. It
does not use Claude Code. Live turns require the configured DeepSeek profile,
network access, and an unlocked Production macOS login Keychain.

## Required Health Checks

Run these after changes:

```bash
/Users/moss/SitinaHub/bin/sitina config validate
/Users/moss/SitinaHub/bin/sitina doctor
/Users/moss/SitinaHub/bin/sitina eval
PYTHONPATH=/Users/moss/SitinaHub/core \
  /Users/moss/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 \
  -m unittest discover -s /Users/moss/SitinaHub/tests
```

Expected current results:

- `config validate`: `ok: true`
- `doctor`: `status: ok`
- `eval`: 15 safety cases pass
- `unittest`: 63 unit/integration tests are defined; the live provider smoke is
  skipped unless `SITINA_LIVE_TEST=1`

## Mock Runs

Mock mode is the default and does not call external model providers:

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode mock "smoke test"
```

Mock runs still exercise:

- run_state phase transitions
- controller/planner/tester/reviewer/summary/memory schema validation
- collaboration proposal rounds and evaluator-agent scoring where the task type
  enables proposal scheduling. `code_change` and `high_risk_code_change` use
  multi-proposal competition; `local_file_query` and `maintenance` use
  controlled single-proposal paths in v1.
- handoff accept/reject, arbitration, lease, blackboard, replay, and backlog
  gates in the fixture paths
- tester artifact registration
- harness-side evidence verification
- JSONL event log and audit log writes

## Live Runs

Live mode calls the provider profiles mapped in `config/roles.env`. It should be
treated as an opt-in integration path because it depends on local provider
credentials, current provider health, and network availability.

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode live "provider smoke only; do not propose or make file changes"
```

The current test role mapping may map every role to `deepseek`:

- controller -> `deepseek`
- planner -> `deepseek`
- coder -> `deepseek`
- tester -> `deepseek`
- reviewer -> `deepseek`
- security -> `deepseek`
- arbiter -> `deepseek`
- memory/summary/default -> `deepseek`

This is a valid single-provider multi-role test configuration. Multiple agents
remain distinct because the runtime records separate `agent_id` values,
role-specific input/output schemas, proposal/evaluation/arbitration/handoff
objects, ledger/audit rows, trace, and replay snapshots. Multi-provider mapping
is still supported by editing `config/roles.env` or using temporary
`--profile-override` values; it is not a hard requirement for the local test
configuration.

Temporary profile overrides remain available:

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode live \
  --profile-override controller=deepseek \
  --profile-override planner=deepseek \
  --profile-override tester=deepseek \
  --profile-override reviewer=deepseek \
  --profile-override summary=deepseek \
  "provider smoke only; do not propose or make file changes"
```

The live collaboration smoke test exists in `tests/test_sitina.py` and is
skipped by default. Run it explicitly when provider credentials are available:

```bash
SITINA_LIVE_TEST=1 PYTHONPATH=/Users/moss/SitinaHub/core \
  /Users/moss/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 \
  -m unittest tests.test_sitina.SitinaHarnessTests.test_live_provider_collaboration_smoke
```

Do not treat old run IDs as current evidence; rerun the command above for a
fresh live-provider result.

Trace and replay include an audit-safe provider identity summary for each agent
call: `agent_id`, `provider_mode`, `profile_name`, `model`, provider label,
base URL host, and `redaction_status`. They do not include provider auth tokens,
Authorization headers, `.env` source text, or full secret-bearing URLs.

Live/mock secret scanning is available through the verifier helpers in
`sitina.guards.secrets`. The scanner reports counts plus file path and field
names only; it does not return matched secret values. It covers ledger, audit,
blackboard, trace, replay, artifacts, reports, and docs while excluding
credential source files under `profiles/`.

## Approval Flow For Writes

If planner proposes files, Sitina does not write immediately. It returns:

```json
{
  "status": "awaiting_approval",
  "proposed_touched_files": ["..."]
}
```

Approve and continue:

```bash
/Users/moss/SitinaHub/bin/sitina approve-run <run_id>
```

Reject:

```bash
/Users/moss/SitinaHub/bin/sitina approve-run <run_id> --action reject
```

The approval is bound to `run_id`, `risk_scan_hash`, `scope_hash`, approved
files, approved commands, and expiry.

Confirmed mock approval flow:

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode mock approved-write-fixture
/Users/moss/SitinaHub/bin/sitina approve-run <run_id>
/Users/moss/SitinaHub/bin/sitina rollback <run_id> --approve-now
```

## Memory Review

The default run lifecycle calls the memory agent after summary. Memory output is
only stored as reviewable candidates; Sitina does not auto-accept them.

```bash
/Users/moss/SitinaHub/bin/sitina memory review
/Users/moss/SitinaHub/bin/sitina memory review --status pending
/Users/moss/SitinaHub/bin/sitina memory show <candidate_id>
/Users/moss/SitinaHub/bin/sitina memory accept <candidate_id>
/Users/moss/SitinaHub/bin/sitina memory reject <candidate_id> --reason "not durable"
```

Accepted candidates are appended idempotently to
the Journal/CAS-native Memory V1 store. The former `memory/global_memory.md`
path is legacy-fixture-only and is not consulted in protected production.
Sensitive candidates are blocked or redacted before
they can enter the pending review list. The legacy commands still work:

```bash
/Users/moss/SitinaHub/bin/sitina memory review --accept <candidate_id>
/Users/moss/SitinaHub/bin/sitina memory review --reject <candidate_id> --reason "not durable"
```

## Provider Smoke

To test a single profile without running the full workflow:

```bash
/Users/moss/SitinaHub/bin/sitina provider smoke deepseek
```

Confirmed result:

```text
profile: deepseek
model: deepseek-v4-pro
status: ok
text_preview: SITINA_PROVIDER_SMOKE_OK
```

The command intentionally prints only safe metadata and redacted previews. It
does not print provider tokens.

## Provider Health

Read cached provider health without network calls:

```bash
/Users/moss/SitinaHub/bin/sitina provider status
```

Manually check the configured health profiles (`gpt`, `qwen`, `minimax`,
`deepseek`) with smoke requests:

```bash
/Users/moss/SitinaHub/bin/sitina provider status --check
```

Failed profiles are temporarily marked `unavailable`; live agent routing prefers
healthy profiles and skips unavailable profiles until their retry window expires.
Coder fallback is only enabled when an approved write scope is already bound.

## Obsidian Retrieval

Configure vaults in `config/sitina.yaml` under `context.obsidian.vaults`, or set
`SITINA_OBSIDIAN_VAULTS` to a comma-separated list of vault paths.

Index vaults incrementally:

```bash
/Users/moss/SitinaHub/bin/sitina obsidian index
```

Search cached Markdown lines with line-based citations:

```bash
/Users/moss/SitinaHub/bin/sitina obsidian search "query"
```

Results include `citation` values in `path:line` form. Retrieved note text is
wrapped as untrusted local-note evidence.

## Read Commands

```bash
/Users/moss/SitinaHub/bin/sitina list
/Users/moss/SitinaHub/bin/sitina show <run_id>
/Users/moss/SitinaHub/bin/sitina export-run <run_id>
```

`export-run` writes a redacted JSON export under:

```text
/Users/moss/SitinaHub/artifacts/exports/
```

## Multi-Agent Observability

The collaboration runtime records proposal rounds, evaluator outputs, selected
and rejected proposals, handoff contracts, lease conflicts, arbitration
decisions, blackboard documents, task graph state, replay snapshots, and
long-term goal/backlog links.

Useful read-only inspection commands:

```bash
/Users/moss/SitinaHub/bin/sitina trace <run_id>
/Users/moss/SitinaHub/bin/sitina replay diff <run_id>
/Users/moss/SitinaHub/bin/sitina replay simulate <run_id>
/Users/moss/SitinaHub/bin/sitina run graph <run_id>
/Users/moss/SitinaHub/bin/sitina proposals list --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina blackboard show --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina handoff list --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina handoff show <handoff_id>
/Users/moss/SitinaHub/bin/sitina lease list --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina lease show <lease_id>
/Users/moss/SitinaHub/bin/sitina arbitration list --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina arbitration show <arbitration_id>
```

`replay simulate` is intentionally a dry-run consistency check by default. It
does not re-execute provider calls, MCP tools, git apply, memory acceptance, or
file writes. When a sandbox path is supplied, it must be inside Sitina-managed
`artifacts/` or `temp/`. The simulation result keeps
`changed_real_files=False`.

Sitina v1 uses controlled TaskGraph execution with dynamic proposal negotiation, receiver-driven handoff decisions, arbitration, leases, blackboard state, and replay gates. It is not a fully open-ended autonomous scheduler and does not implement automatic merge or replay of real side effects.

## Legacy `ask` Surface

The historical `sitina ask` command is not the interactive chat path and is
unavailable as a Production conversation authority. Do not use it to maintain
conversation state. Use `sitina` or `sitina chat`; those commands keep bounded
context only in memory and write durable execution evidence only through the
Production Journal/CAS path.

## High-Risk Commands

These commands are implemented as fail-closed surfaces:

```bash
/Users/moss/SitinaHub/bin/sitina doctor --fix
/Users/moss/SitinaHub/bin/sitina restore <archive>
/Users/moss/SitinaHub/bin/sitina rollback <run_id>
/Users/moss/SitinaHub/bin/sitina prune --older-than-days 30
```

Without approval, they return `status: blocked` and write risk scan artifacts.

For maintenance operations where the CLI invocation itself is the explicit user
approval, pass `--approve-now`:

```bash
/Users/moss/SitinaHub/bin/sitina rollback <run_id> --approve-now
/Users/moss/SitinaHub/bin/sitina prune --older-than-days 30 --approve-now
/Users/moss/SitinaHub/bin/sitina restore <archive> --approve-now
```

`restore` extracts safely by default. It applies restored config/schema/prompt
files only when `--apply` is also passed.

Do not bypass these commands with raw destructive shell operations.

## MCP And Git Patch Flow

MCP server/tool declarations live in `config/mcp/servers.yaml`; explicit
allowances live in `config/mcp/allowlist.yaml`. Unknown MCP tools still fail
closed under the default deny policy. Allowed tools execute only when the server
entry provides a real runtime transport, currently `transport: "stdio"` with a
configured command. If a tool is allowlisted but has no runtime transport,
Sitina returns `blocked` instead of pretending execution succeeded. remote MCP
servers remain disabled by default.

Invoke a configured MCP tool with a JSON payload:

```bash
/Users/moss/SitinaHub/bin/sitina mcp list
/Users/moss/SitinaHub/bin/sitina mcp validate
/Users/moss/SitinaHub/bin/sitina mcp invoke <server> <tool> --payload-json '{"key":"value"}'
/Users/moss/SitinaHub/bin/sitina mcp invoke filesystem list_dir --path /Users/moss/SitinaHub
/Users/moss/SitinaHub/bin/sitina mcp invoke git status --repo /Users/moss/SitinaHub
```

The built-in local stdio registry enables readonly `filesystem`, `git`,
`sqlite`, and `obsidian` servers. Remote placeholders such as `fetch`,
`web_search`, `browser`, `github`, `notion`, and `google_drive` remain disabled
and return `blocked` until a safe local transport is explicitly implemented.

`filesystem` roots are configured in `config/mcp/servers.yaml` under
`servers.filesystem.allowed_roots`. The long-lived local default is
`/Users/moss`, while `SITINA_ALLOWED_ROOTS` overrides that list for local runs
and uses the platform path separator, for example:

```bash
SITINA_ALLOWED_ROOTS="/Users/moss/Desktop:/Users/moss/Documents:/Users/moss/SitinaHub" \
  /Users/moss/SitinaHub/bin/sitina mcp invoke filesystem list_dir --path /Users/moss/Documents
```

The filesystem server remains readonly by default: `list_dir`, `read_file`, and
`stat_path` are enabled, while write/delete/move/overwrite tools are not
allowlisted unless separately configured with approval. Paths are canonicalized
before access, symlink escapes and `..` traversal are blocked, and sensitive
paths such as `.ssh`, `.env`, tokens, passwords, private keys, cookies, and
system directories fail closed.

Filesystem allowed roots do not trust Git patch files. Worktree patch/apply only
accepts Sitina-generated patch artifacts under Sitina-managed patch/worktree
output directories with a matching generation audit record.

Git worktree patch flow:

```bash
/Users/moss/SitinaHub/bin/sitina worktree prepare --repo <repo> --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina worktree patch --repo <repo> --source <worktree> --run-id <run_id>
/Users/moss/SitinaHub/bin/sitina worktree review --patch <patch_path> --run-id <run_id> --decision accept
/Users/moss/SitinaHub/bin/sitina worktree apply --repo <repo> --patch <patch_path>
/Users/moss/SitinaHub/bin/sitina worktree apply --repo <repo> --patch <patch_path> --approve
```

`patch` writes a patch sidecar artifact with `patch_id`, `patch_hash`, target
repo, worktree path, base commit, and changed files. `review` writes a reviewer
artifact bound to the same run, patch id, patch hash, and target repo.
`apply --approve` still requires a matching reviewer accept artifact, creates or
validates a matching approval artifact, recomputes `patch_hash`, and runs
`git apply --check` first. External patch paths, conflicts, drift, reviewer
rejection, missing approval, target repo mismatch, or hash mismatch return
`blocked` and are not auto-merged.
