# Provider Runner

This document explains the live agent runner added for Sitina Phase 1.

## Files

```text
core/sitina/runners/provider.py       # provider HTTP client and profile resolver
core/sitina/runners/agent_parser.py   # strict single-JSON parser
core/sitina/runners/agent_runner.py   # mock/live agent runner and repair-once flow
core/sitina/orchestrator/engine.py    # run/ask integration
```

## Profiles

Profiles live in:

```text
/Users/moss/SitinaHub/profiles/*.env
```

Required fields:

```text
ANTHROPIC_BASE_URL
ANTHROPIC_AUTH_TOKEN
ANTHROPIC_MODEL
```

Profile files must be mode `600`. The runner refuses insecure profile files and
does not print token values.

## Role Mapping

Role mapping lives in:

```text
/Users/moss/SitinaHub/config/roles.env
```

Current test mapping:

```text
controller -> deepseek
planner    -> deepseek
coder      -> deepseek
tester     -> deepseek
reviewer   -> deepseek
security   -> deepseek
arbiter    -> deepseek
memory     -> deepseek
summary    -> default -> deepseek
```

This single-provider multi-role mapping is a valid test configuration. It does
not mean Sitina has collapsed into one agent: agent identity is carried by
`agent_id`, role-specific input contracts, output schemas, proposal/evaluation
records, handoff contracts, ledger/audit rows, trace, and replay. Multi-provider
mapping remains supported by changing `config/roles.env` or using
`--profile-override`, but different model names are not required for the
runtime to be multi-agent.

## Provider Protocols

The client first tries Anthropic-compatible messages:

```text
<base_url>/v1/messages
```

If the error clearly indicates an endpoint shape problem, it tries
OpenAI-compatible chat completions:

```text
<base_url>/v1/chat/completions
```

It does not hide or bypass:

- auth failure
- provider block
- risk block
- schema failure after one repair

It can retry per-agent fallback profiles for provider availability failures:

- HTTP 429 quota/exhaustion
- HTTP 5xx provider failures
- Cloudflare/browser-signature 403 availability blocks

Provider health is stored in SQLite. `sitina provider status` reads cached
health, while `sitina provider status --check` performs smoke requests for the
configured health profiles. Failed profiles are marked `unavailable` until their
retry window expires, and live agent routing prefers healthy profiles. Coder
fallback is only allowed when the coder input already contains an approved write
scope.

## Schema Parsing

Every agent must return exactly one JSON object. The parser rejects:

- prose before/after JSON
- arrays or strings as the top-level value
- invalid JSON
- unknown fields
- schema major mismatch
- reviewer accept with critical/major findings

Live mode allows one repair prompt if the first output is invalid. If repair
also fails, the run is blocked with `schema_error`.

## Provider Identity Audit

Agent calls record an audit-safe provider identity summary in ledger/audit
payloads and replay snapshots. The summary contains `provider_mode`,
`profile_name`, `model`, provider label, base URL host, and `redaction_status`.
It intentionally excludes `ANTHROPIC_AUTH_TOKEN`, API keys, Authorization
headers, raw `.env` lines, and full secret-bearing URLs.

Secret scanning uses `sitina.guards.secrets` and reports counts, paths, and field
names only. It covers ledger, audit, blackboard, trace, replay, artifacts,
reports, and docs; credential source files under `profiles/` are skipped because
they are the configured secret source, not a persistence leak.

## Mock Mode

Default command:

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode mock "smoke test"
```

Mock mode uses `MockProvider`, but still exercises:

- input contract validation
- output schema validation
- run_state transitions
- JSONL event logging
- audit logging
- artifact registration
- evidence verification

## Live Mode

Live role mapping:

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode live "task"
```

The current local test mapping can route all roles to `deepseek`. A production
or comparison setup can route roles to different profiles, for example
`controller=gpt`, `coder=qwen`, and `reviewer=deepseek`. Treat those as
configuration choices, not as a correctness requirement.

Temporary profile overrides:

```bash
/Users/moss/SitinaHub/bin/sitina run --provider-mode live \
  --profile-override controller=deepseek \
  --profile-override planner=deepseek \
  --profile-override tester=deepseek \
  --profile-override reviewer=deepseek \
  --profile-override summary=deepseek \
  "provider smoke only; do not propose or make file changes"
```

Live smoke status:

```text
The live provider smoke test exists, but it is skipped by default unless
SITINA_LIVE_TEST=1 is set and valid live provider credentials are configured.
The current v1 acceptance pass validates mock/local collaboration runtime
behavior and does not claim live provider multi-agent collaboration is verified.
```

When `SITINA_LIVE_TEST=1` is set, a deepseek-only live validation may verify the
single-provider multi-role path. A separate multi-provider live validation is
needed before claiming that several provider profiles were exercised in the
same run.

## Single-Profile Smoke

```bash
/Users/moss/SitinaHub/bin/sitina provider smoke deepseek
```

Confirmed:

```text
profile: deepseek
model: deepseek-v4-pro
status: ok
text_preview: SITINA_PROVIDER_SMOKE_OK
```

## Evidence Binding

The live run writes a tester artifact under:

```text
artifacts/command_outputs/<run_id>/config-validate.json
```

The artifact contains:

- `sitina config validate` result
- read-only filesystem smoke result

The harness registers the artifact hash and verifies it with:

```text
EvidenceVerifier.verify_artifact(...)
```

Final `verified` status requires the harness-side artifact check, not just a
model statement.

## Approved Coder Write Flow

When planner proposes touched files, the run stops at:

```text
phase: awaiting_approval
```

Approve and continue:

```bash
/Users/moss/SitinaHub/bin/sitina approve-run <run_id>
```

The approval flow:

1. Loads pending planner context from `artifacts/approvals/<run_id>.pending.json`.
2. Creates an `ApprovalRecord` bound to run id, risk scan hash, scope hash, and expiry.
3. Calls coder through the same schema-validated AgentRunner.
4. Requires `input_scope_hash` and `scope_compliance=in_scope`.
5. Requires each `extensions.file_writes` item to include a matching `before_hash`.
6. Applies only `extensions.file_writes` whose paths are in the approved scope.
7. Writes through `ToolExecutor`, preserving risk scan, approval id, path lease, before_hash, patch journal, and audit log.
8. Runs tester and reviewer after writes; success requires tester pass, reviewer accept, no critical/major findings, scope verification, and artifact verification.

Confirmed mock approval flow:

```text
run_id: 20260707-044823-a6a7
phase before approval: awaiting_approval
approve-run status: done
rollback status: ok
```
