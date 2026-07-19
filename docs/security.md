# Sitina Security Boundaries

This document records the current safety boundaries that must not be weakened
by feature work.

## Fail-Closed Principle

Sitina must fail closed when it cannot prove a required gate passed. A blocked
result is valid. A fake success is not.

Fail-closed surfaces include:

- unknown MCP server or tool
- disabled remote MCP transport
- MCP schema validation failure
- MCP timeout or malformed JSON-RPC response
- filesystem path outside allowed roots
- sensitive filesystem path
- missing approval
- missing reviewer artifact
- reviewer reject
- patch hash mismatch
- target repo mismatch
- not-git target
- worktree prepare failure
- tester failure
- reviewer critical or major finding
- handoff rejection on mandatory path
- arbitration `block` or `ask_user`
- lease conflict without a safe grant
- backlog item not `active`
- memory agent failure

Memory agent failure is a warning after summary and must not weaken tester or
reviewer gates.

## Approval Boundary

Coder writes require approval scope. The approved write flow must enforce:

- approved file list
- scope hash binding
- before-hash verification
- write output diff verification
- tester pass after write
- reviewer accept after tester evidence
- no success with critical or major reviewer findings

Approval cannot be synthesized to bypass reviewer artifacts. High-risk patch
apply requires reviewer acceptance, approval, patch hash verification, and a
managed patch artifact.

## Git Patch Boundary

Patch paths must be inside Sitina-managed output directories such as managed
worktree artifacts or patch artifact directories. External paths, even when
they are under broad local filesystem allow roots, cannot be used as trusted
patch sidecars.

Patch apply must:

- reload the patch from disk at apply time
- recompute the patch hash
- compare the recomputed hash to generated metadata
- compare reviewer artifact `run_id`, `patch_id`, `patch_hash`, and
  `target_repo`
- compare approval artifact `run_id`, `patch_id`, `patch_hash`, and
  `target_repo`
- block on missing reviewer artifact
- block on missing approval when approval is required
- block on patch drift
- block on target repo mismatch
- return `not_git` when the target repo is not a git repository

Conflict is blocked. Sitina does not automatically merge or auto-resolve patch
conflicts.

## MCP Boundary

Local MCP stdio servers are explicit allowlist surfaces. A tool must be:

- declared in `config/mcp/servers.yaml`
- enabled
- local stdio transport
- command-valid
- allowed by server allowlist
- schema-valid for the tool payload
- executable within timeout

Filesystem MCP is read-only by default. Write tools remain blocked unless a
separate approval-aware flow explicitly permits the operation. Sensitive paths
such as `.env`, `.ssh`, token-like files, system directories, and symlink
escapes are blocked and redacted.

Remote/browser/search style MCP tools remain blocked unless their local policy
explicitly enables them with approval.

Stub or mock results must be labeled as mock. A stub response cannot be
reported as a real MCP execution result.

## Provider Boundary

Mock mode is deterministic and local. Live mode is opt-in and depends on local
provider profiles and credentials.

Provider health can mark profiles temporarily unavailable. Agent routing should
prefer healthy profiles. Coder fallback is more restrictive than controller,
planner, tester, or reviewer fallback because coder can create file-write
intents.

Agent outputs must pass schema validation. Invalid output fails closed or uses
the controlled repair path where supported.

## Handoff Boundary

Handoff contracts validate:

- source and target agents
- ownership constraints
- required inputs
- provided artifact hashes
- required gates
- mutation intent constraints
- lease references
- side-effect descriptor references

A handoff is not complete until the receiver accepts it. Rejection is persisted
and, on a mandatory path, blocks the run. Rejection also creates
scope-conflict arbitration for audit.

## Arbitration Boundary

Arbitration decisions are independent conflict records. The controller can
request arbitration, but cannot silently override `block` or `ask_user`.

Blocking arbitration must produce:

- arbitration ledger/audit record
- blackboard arbitration note
- blocked task graph state when attached to the graph
- terminal blocked run state when the arbitration gates execution

## Lease Boundary

Exclusive leases protect resources from simultaneous mutation or apply claims.
Conflicts are visible. A loser of arbitration is recorded as blocked and must
not continue as the holder of the conflicting resource.

Lease validation checks:

- lease exists
- holder matches
- mode matches when required
- status is `granted`
- lease is not expired

Invalid leases block handoff for mutation-capable nodes.

## Blackboard Boundary

The blackboard is shared state, not a safety policy override. It cannot patch
safety fields such as `risk_level`, `approval_required`, `denylist`,
`permissions`, `verification_status`, or `allowed_scope`.

Blackboard summaries are redacted before they are surfaced in agent input
snapshots or replay. Sensitive candidate text must not be persisted in visible
blackboard context.

## Memory Boundary

The memory agent can propose candidates after summary. It cannot auto-accept.

Candidate lifecycle:

- created as `pending`
- sensitive candidates are `blocked` and redacted
- duplicates are deduplicated by stable candidate id/hash
- accept writes durable memory first
- database status changes to `accepted` only after the durable write succeeds
- reject records reviewer, reason, source, and reviewed timestamp

In protected production, accepted memory content is encrypted in CAS and every
candidate/review/accept/reject/revoke transition is committed to the Journal.
`memory/global_memory.md` is a retired legacy-fixture format and is never read
as production context or written by the protected runtime.

Runs that stop before summary record `memory_no_candidate` with a reason.

## Autonomy Boundary

Long-term goal and backlog autonomy is review-gated. A goal agent may propose
backlog candidates, but only reviewed `active` backlog items can link to a run.

Blocked statuses:

- `pending`
- `rejected`
- `done`
- unknown goal or backlog id

Blocked run linkage records ledger and audit events and must not mutate
`linked_run_ids`.

## Replay Boundary

Replay is a consistency verifier. It does not reproduce real side effects.

Replay may read:

- ledger events
- audit rows
- event rows
- task graph artifacts
- side-effect descriptors
- patch files for hash verification

Replay must not execute:

- provider calls
- MCP tools
- shell commands
- filesystem writes
- git apply
- memory acceptance
- approval mutation

Sandbox simulation paths must be inside Sitina-managed `artifacts/` or `temp/`.

## Audit Boundary

Blocked events are first-class audit records. The system should record a reason
for blocked handoff, blocked arbitration, blocked lease holder, blocked backlog
link, blocked MCP call, blocked git patch apply, blocked approval flow, and
blocked side-effect descriptor.

Audit output must be redacted. Secrets should not appear in visible logs,
replay summaries, memory candidates, blackboard context, or CLI JSON output.
