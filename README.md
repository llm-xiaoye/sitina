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

Interactive conversation is AUTO-only. A deterministic local router sends a
simple read-only task through the current Loop's single main Agent, while a
complex or high-risk task uses the same Loop task and adds an independent
read-only reviewer. Both paths share one LoopHost, one LoopTaskRunner,
Journal/CAS state, authority lease, and recovery chain.

Routing cannot be forced from the public interface. `/mode` only explains the
latest automatic decision; `/help` lists the available commands, and `/exit`
or `/quit` leaves normally. The retired `chat` command remains an early,
side-effect-free refusal and is never used as a fallback.

Detailed docs:

- `RECOVERY.md`: rebuild a clean installation from this private repository.
- `docs/usage.md`: commands, mock/live runs, provider smoke checks, and high-risk command behavior.
- `docs/conversation-routing.md`: automatic routing, review, and safety boundaries.
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

The current Loop does not retry automatically or fall back to another
Provider. Authentication, Keychain, network, quota, schema, and terminal
failures remain durable task outcomes for the existing Loop status and
recovery surfaces; the AUTO-only interactive controller does not expose a
separate retry mode.

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

## 原生任务的评审请求超时

可在 `config/sitina.yaml` 的 `providers` 下设置可选的 `reviewer_request_timeout_seconds`，值为有限正数（秒）。通过原生 session 或 `loop task submit` 提交时，该值随提交身份与任务执行描述一起保存，恢复任务继续使用原值；相同提交 ID 携带不同的值会被拒绝。

此设置仅限制独立 reviewer 的单次模型请求，仍受 Provider 现有请求上限约束。未配置时保持原有行为；main 与 goal completion 的请求超时、模型、端点和重试策略不因此改变。它不是整个任务的执行时间上限，评审超时也不会产生通过结论。
