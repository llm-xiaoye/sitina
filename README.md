# SitinaHub

SitinaHub is Sitina's standalone Journal/CAS-native Agent runtime. Its terminal
conversation path uses DeepSeek directly through Sitina's bounded Provider
Effect pipeline; it does not depend on Claude Code or the retired Legacy
SQLite conversation path.

The active entrypoint is:

```bash
/Users/moss/SitinaHub/bin/sitina
```

When the entrypoint is on `PATH`, running it without arguments opens the
Journal-native interactive conversation UI:

```bash
sitina
```

Interactive conversation starts in `AUTO`: simple messages use the one-Agent
`FAST` path, while comparison, architecture, audit, high-risk, and other
complex requests route to reviewed `MULTI`. Use `/fast`, `/multi`, or `/auto`
to override or restore routing; `/mode` explains the last decision, `/new`
clears in-process context without changing mode, and `/retry` retries only the
last failed or cancelled message. `/exit` and `/quit` leave normally.

`FAST` has the lowest normal latency and cost when no global extension is
active: one registered synthesis Agent,
one logical Provider call, and one physical send. `MULTI` performs goal
analysis, at least two independent candidate Proposals, and independent
review before displaying the winner. Once a global Sitina Skill or Plugin is
active, chat uses Sitina's autonomous multi-turn tool loop; read-only tools run
automatically and risky tools request approval. Context is bounded by the
token and recent-turn limits in `config/context_policy.json`; it exists only in
the current terminal process.

Detailed docs:

- `docs/usage.md`: commands, mock/live runs, provider smoke checks, and high-risk command behavior.
- `docs/conversation-routing.md`: AUTO/FAST/MULTI routing, evidence, and safety boundaries.
- `docs/architecture.md`: package layout, state/logging model, and safety boundaries.
- `docs/provider-runner.md`: provider profiles, live API path, schema parser, repair-once behavior, and smoke evidence.
- `docs/extensions.md`: Sitina-native Skills, Plugins, MCP, permissions, installation, autonomous tools, and rollback.

Core checks:

```bash
sitina config validate
sitina doctor
sitina eval
```

Useful operational commands:

```bash
sitina provider status
sitina provider status --check
sitina suggest "review this architecture and recommend a safe implementation plan"
sitina obsidian index
sitina obsidian search "query"
sitina worktree prepare --repo <repo> --run-id <run_id>
sitina worktree patch --repo <repo> --source <worktree> --run-id <run_id>
sitina worktree apply --repo <repo> --patch <patch_path> --approve
```

Agent runs default to the local mock provider so development does not spend
provider quota:

```bash
sitina run --provider-mode mock "smoke test"
```

The live provider path is implemented but must be requested explicitly:

```bash
sitina run --provider-mode live "task"
```

If a role profile is temporarily unavailable, use profile overrides without
editing `config/roles.env`:

```bash
sitina run --provider-mode live \
  --profile-override controller=deepseek \
  --profile-override planner=deepseek \
  --profile-override tester=deepseek \
  --profile-override reviewer=deepseek \
  --profile-override summary=deepseek \
  "provider smoke only; do not propose or make file changes"
```

High-risk built-ins such as `doctor --fix`, `restore`, `rollback`, and
`prune` are risk-scanned and block unless an approval-bound flow is supplied.
Profile `.env` files remain local secrets and must stay `chmod 600`.

Approved write flow:

```bash
sitina run --provider-mode mock approved-write-fixture
sitina approve-run <run_id>
```

Production chat does not retry automatically or fall back to another Provider.
Authentication, Keychain, network, quota, schema, and terminal failures remain
failed turns and can be retried explicitly with `/retry`.

`sitina suggest <task>` is a read-only, Provider-free preview of the real
router plus workflow/team policy. It reports the recommended task type, route,
proposal round, worktree, team/topology, and explicit token/time *estimates*;
those estimates are never Provider usage or precise work-time promises. Use
`--budget-tokens`, `--sla-class`, `--sla-remaining-ms`, `--risk`,
`--task-type`, or `--topology` to make assumptions explicit.

Safe defaults keep live Provider tests off, external side effects denied,
format write feature flags disabled until Journal activation, and storage
migration/rollback behind their runbooks and approvals. The phase-15 billable
gate must first pass the no-paid cumulative gate and publish its physical-call,
token, and cost ceilings; only an explicit approval for that exact run (or a
complete one-time `SITINA_LIVE_ACCEPTANCE_APPROVED=1` budget envelope) may
enable live calls. See `docs/usage.md` and `docs/storage-v2-operations.md`.
