# SitinaHub Architecture

SitinaHub owns Sitina's harness state, schemas, prompts, provider profile
mapping, risk controls, audit logs, artifacts, and memory surfaces under:

```text
/Users/moss/SitinaHub
```

Claude Code may remain an external execution surface, but the Sitina CLI and
long-lived state are now owned by this directory.

## Package Layout

```text
bin/sitina
core/sitina/
  cli.py
  config.py
  constants.py
  utils.py
  schemas/models.py
  storage/store.py
  guards/
    risk.py
    approvals.py
    evidence.py
    diff.py
    path_lease.py
  runners/
    provider.py
    agent_parser.py
    agent_runner.py
    profiles.py
    tool_executor.py
  orchestrator/
    engine.py
    state_machine.py
    workflow.py
    context.py
    blackboard.py
  evals/safety_eval.py
```

## State Model

`run_state.json` is the current state snapshot. Harness-owned fields include:

- `phase`
- `active_agent`
- `risk_level`
- `approval_required`
- `approval_id`
- `open_findings`
- `verification_status`
- `locks_held`
- `risk_scan_result_ref`

Agent outputs are advisory; the harness decides state transitions and final
verification.

## Logging Model

JSONL logs are the append-only fact source:

```text
logs/events/YYYY-MM-DD.jsonl
logs/audit/YYYY-MM-DD.jsonl
logs/runs/<run_id>.jsonl
```

SQLite is a query/index cache:

```text
data/sitina.db
```

The database uses WAL mode and busy timeout.

## Agent Runner

The runner path is:

```text
engine -> AgentRunner -> ProviderClient/MockProvider -> AgentOutputParser -> Pydantic schema
```

Each agent output must be exactly one JSON object matching the corresponding
schema in `schemas/*.schema.json`.

Live mode:

- loads role-to-profile mapping from `config/roles.env`
- loads profile env from `profiles/<name>.env`
- requires profile file mode `600`
- supports Anthropic-compatible `/v1/messages`
- falls back to OpenAI-compatible `/v1/chat/completions` only for endpoint-shape errors
- falls back to configured profiles for retryable provider availability errors such as quota exhaustion, 5xx, and Cloudflare browser-signature blocks
- does not fall back on ordinary auth, risk, or schema blocks
- permits one schema repair attempt

Mock mode:

- never calls external providers
- still runs schema validation and audit/event logging
- is the default for `run` and `ask`

## Verification Model

Final `verification_status=verified` requires harness evidence, not only model
claims:

- config validation result is written to a command-output artifact
- artifact is registered in `artifact_registry`
- `EvidenceVerifier` confirms artifact belongs to the current run and command
- tester output says pass
- reviewer output says accept
- summary derives verified

Model-written `evidence_ref` strings are kept as agent claims, but final harness
verification uses the artifact registry.

## Safety Boundaries

Risk scanner:

- blocks secret reads/writes
- blocks `.ssh`, private keys, credentials, shell rc writes unless approved
- blocks `sudo`, `curl | sh`, `wget | sh`, `bash <(...)`, `git reset --hard`, `git clean`
- gates delete/move/overwrite/restore/rollback/prune/doctor-fix
- detects `..` path escape and symlink escape

Approval manager:

- binds `approval_id` to `run_id`
- binds approval to `risk_scan_hash`
- binds approval to `scope_hash`
- enforces expiry
- prevents override of `action=block`

ToolExecutor:

- runs risk scan before write/delete/move/shell
- uses path leases for writes
- records before_hash
- writes audit records
- uses isolated env without provider tokens

## Current Limitations

- Live provider smoke is an opt-in integration check. It is skipped by default
  unless `SITINA_LIVE_TEST=1` is set and valid provider credentials are
  configured. Mock/local runtime tests are the current v1 acceptance evidence;
  do not treat skipped live smoke as live provider verification.
- Approved coder write flow is implemented for schema-validated `file_writes`;
  richer patch formats and multi-file review loops can still be expanded.
- Approved restore/rollback/prune execution is implemented. `restore` safely
  extracts by default and applies config/schema/prompt files only with `--apply`.
- Memory runs after summary in the default lifecycle. Candidates remain pending
  until reviewed; accepted production candidates persist as CAS content plus
  Journal state transitions. `memory/global_memory.md` is retained only as a
  retired legacy-fixture format and is not a production authority.
- Git worktree prepare/patch/apply is implemented with patch artifacts,
  reviewer accept artifacts, approval artifacts, patch hash revalidation, and
  `git apply --check`; automatic merge remains future work.
- MCP adapter default-deny is implemented. External MCP tool execution is
  limited to local `stdio` JSON-RPC servers with executable commands; remote
  SSE/HTTP/browser/web-search placeholders return `blocked`.
- Obsidian on-demand retrieval writes SQLite cache; vector retrieval remains
  future work.
- Local knowledge-graph memory persistence remains future work; the current
  accepted-memory store is markdown.

## B+ Phase 0 Legacy compatibility control plane

Phase 0 adds a control plane around the existing Legacy runtime without changing
writer Authority. `LEGACY_ACTIVE` still resolves to the Legacy writer. No phase
name, CLI flag, Projection row, or Shadow record can authorize a writer.

Every Sitina runtime process installs an application-enforced mutation audit
guard. On its first filesystem or writable-SQLite mutation under `SITINA_HOME`,
the process acquires and retains a shared kernel `flock` lease. A future freezer
must acquire the same lock exclusively after all writers drain, then publish a
validated fence record. A valid fence makes top-level engine routes and direct
low-level filesystem/SQLite sinks fail closed. Control-plane-only programs set
`SITINA_CONTROL_PLANE_READONLY=1` before importing Sitina, so read-only
verification itself cannot bootstrap Production coordination metadata.

The only Phase 0 Production-facing CLI is read-only:

```text
sitina legacy status
sitina legacy inventory --output <disjoint-output-root>
```

There is deliberately no Production `legacy freeze` CLI in Phase 0. The freeze
API accepts only marked disposable fixtures. A real freeze requires a later
maintenance Manifest, writer drain, exclusive fence proof, backup/restore gates,
and the fixed Phase 6B protocol.

`LegacySQLiteReader` uses `mode=ro` plus `PRAGMA query_only=ON` for live sources.
`immutable=1` is accepted only by `open_snapshot()` for an independently
materialized database with no WAL/SHM dependency. Observational inventory is
labeled `LIVE_OBSERVATIONAL_INVENTORY`; it records changing sources rather than
claiming a coherent cutoff. Only an already-fenced capture may be labeled
`FROZEN_COHERENT_SNAPSHOT`.

Shadow facts live under a physically disjoint `shadow/<snapshot_id>` namespace,
carry `authority=false`, and cannot drive Provider, MCP, Tool, Approval, Timer,
Terminal, Effect, or Evidence Seal adapters. Dual-read reports are evidence only;
unclassified differences are `BLOCKING_MISMATCH` and cannot be waived by a
generic “legacy incomplete” label.

## B+ Phase 1 shadow Journal/CAS kernel

Phase 1 adds a controlled-fixture/shadow-only canonical kernel. Strict canonical
JSON feeds bounded binary frames under a gap-free local committed-prefix profile.
A fixed-inode kernel lock serializes writers; append acknowledgment follows frame
`fsync` and all object durability proofs, while uncertain I/O poisons the writer
until a fresh locked recovery adopts or rejects the physical prefix.

Encrypted CAS uses per-object AES-256-GCM DEKs, independent authenticated DEK
envelopes, tenant HMAC commitments, purpose-isolated key capabilities, fresh
verification, and same-filesystem no-replace publication. Only a fresh published
receipt or a proof rooted in a verified canonical frame admits an object
reference. GC uses epoch reference leases and Journal-backed frozen frontiers.

SQLite remains a disposable projection/catalog. Operational facts and command
outcomes are canonical Journal events; cache misses cannot synthesize authority.
No Phase 1 state is Production authority, and the default durability profile
makes no hardware power-loss RPO=0 claim.

## B+ Phase 2 Run and Task protocol runtime

Phase 2 layers pure, hash-bound protocol aggregates over the Phase 1
shadow/controlled-fixture Journal. Run Admission Generations and exact-purpose
Permits gate generic create-or-tombstone entity sagas. TaskGraph owns immutable
Task specifications and materialization lineage; Task Attempts own claims and
fencing tokens; Resource Leases require exact all-resource reservation and
progress-bound renewal.

Process Managers derive stable steps and reconcile unknown Command outcomes by
the original ID/hash pair. SchedulerDecision freezes source frontiers, filter
results, policy, score, and deterministic order. Dispatcher commits a Task Claim
before an in-memory fixture worker sees work and recovers lost ACKs with the same
fence. Durable timers persist UTC deadlines and integer monotonic nanoseconds,
fail closed on clock uncertainty, and never treat a projection candidate as a
firing fact.

Terminal eligibility covers ten blocker classes. Zero projection counts only
trigger authoritative full validation; the terminal Command is then applied
through the Run stream. The default-off compatibility adapter cannot dispatch
Providers, Tools, MCP, or worker effects and rejects Production Home. Legacy
remains the sole Production writer throughout Phase 2.

## B+ Phase 3 collaboration protocols

Phase 3 replaces shadow collaboration mutation paths with independent protocol
aggregates for Obligations, ProposalRound, Claims/Debate, Review and Artifact
Acceptance, Handoff, Merge, Arbitration/Appeal, Rework, and Blackboard MVCC.
Protocol terminal state and Run Obligation satisfaction are deliberately
separate. Successor Protocol/Obligation entities use the Phase 2 generic
Permit-backed Create-or-Tombstone saga.

Collaboration bodies remain CAS references. Blackboard enforces base
version/hash CAS, Namespace writer/evidence/merge/classification policy, current
Task fencing, and fresh encrypted-CAS publication receipts for large or secret
content. Conflicts mutate no document state and block only explicitly dependent
Obligations before Merge/Arbitration routing.

Protocol Coordinator Processes derive stable cross-stream Commands but never
mutate target streams directly. Arbitration blocks its binding scope until
enforcement proof commits; only enforced decisions settle their Obligation.
Read-only Legacy views preserve Proposal, Handoff, and Blackboard report shapes.
No Phase 3 stream, Projection, feature flag, or view is Production authority.

## B+ Phase 4 Effect and Observation boundary

Phase 4 routes every mock/shadow external trust-domain access through immutable
Effect and Effect Attempt identities. The Effect stream exclusively owns the
closed Outcome/Settlement/Basis/Cardinality matrix and transmission exposure;
authenticated Observation streams supply evidence but cannot directly mutate
that authority. Each Attempt has one application-body transmission boundary.
A crash after `InvocationStarted` becomes `MAY_HAVE_BEEN_SENT` and enters
reconciliation, never an implicit retry.

Signed Adapter Manifests declare recovery Level A/B/C, idempotency retention,
status-query and Not-found semantics, and disabled SDK/body-replay behavior.
Exact approvals, opaque short-lived credential handles, all-or-nothing Budget
Bundles, current Task/Dispatch Fences, and a final operational-breaker CAS all
bind the same Attempt before transmission. Compensation is always a new linked
Effect; policy settlement preserves Unknown remote truth and transfers future
monitoring before terminal.

Observation ingress separates encrypted-spool `DURABLY_RECEIVED` custody from
canonical-frame `JOURNAL_ADMITTED` history. Ordinary traffic cannot borrow the
Observation/Receipt/Closing reserve. Raw results use an encrypted inaccessible
quarantine, then bounded validation, secret/injection scanning, trust,
redaction, and normal encrypted-CAS publication; secret-positive bytes are
key-erased/deleted with an attestation.

Provider, MCP, and Tool runners retain exact Legacy behavior by default. The
explicit Phase 4 shadow bridge computes request identity and performs zero
physical sends without claiming authority. Checked-in activation remains
`MOCK_ONLY`; Legacy is still the sole Production writer, and no Phase 4 fact,
spool candidate, Projection, config flag, or report can authorize Production or
live external capability.

## B+ Phase 5 evidence, archive, backup, and retention model

Phase 5 introduces single-component signed O/P/T frontier vectors, coherent-cut
proofs, and a PreTerminal checkpoint over all business/barrier manifests. The
Terminal coordinator drains authoritative blockers, freezes P, permits only
evidence recording afterward, and commits one idempotent T. Evidence package
Core, Assessment, Seal, and Artifact identities form an acyclic four-layer hash
graph. Remediation appends a new immutable package generation; Supplements form
a separate CAS chain and cannot rewrite original terminal or seal bytes.

Completeness proof and verify/replay/inspect self-containment are orthogonal.
Only exact-policy PASSED assessments may reach the role-separated evidence
sealer. The current offline replay boundary is honestly classified
`APPLICATION_GUARDED_ZERO_EFFECT`; no qualified kernel-enforced sandbox is
claimed. zstandard is unavailable, so Phase 5 emits logical-directory artifacts
and refuses to label any output deterministic tar.zst.

Archive Job and Archive Copy are independent streams. Replica policy checks
copy count plus fault, region, provider, administration, key, and freshness
domains. Canonical backup holds the fixed-frontier reachable closure until an
isolated restore verifies. GC freezes epoch/catalog/hold inputs and may only
propose a dry-run retention operation after rechecks. The retention lifecycle
has no destructive executor, and every receipt states that physical deletion
did not occur.

All Phase 5 execution remains in marked disposable homes or the read-only
control plane. Legacy is still the sole Production writer. No evidence seal,
archive transfer, backup, restore drill, replay, GC proposal, compatibility
bundle, or projection is Production authority or cutover permission.

## B+ Phase 6A-R1 Production-capable cutover tooling

The original fixture-only Phase 6A readiness is superseded. R1 ships the exact
operator and runtime boundaries needed by Phase 6B, while proving them only in
marked controlled Production simulations. The signed readiness report itself
still grants no Production capability.

`AuthorityResolver` remains the sole writer selector. Prepared, pending,
ACK-unknown, unreadable, conflicting, corrupt, mismatched, or stale state selects
no writer. A durable runtime restart reads the exact Genesis and Legacy fence,
loads purpose-separated keys from macOS Keychain, scans authenticated Journal
segments without mutating them, and issues a short-lived resolution. Only then
may locked Journal recovery and business append begin.

Phase 6B physical data is split by authority:

```text
Production Home/
  state/.legacy-control/frozen.json        permanent Legacy no-writer fence
  state/bplus-production-genesis/          exact independently verified Genesis
  journal/                                 canonical control and business facts
  cas/                                     encrypted canonical objects
  projections/                             disposable derived views

Disjoint operational roots/
  frozen snapshot/                         immutable Legacy reader generation
  migration workspace/                     restart-stable batch plans
  canonical backup/                        retained hold and restore source
  control/                                 signed manifests and reports
```

The Legacy audit hook continues to deny all fenced Legacy paths while allowing
only the B+ physical roots whose own open/append APIs require an exact
Maintenance capability or fresh Journal authority. Migration preserves every
source file in encrypted CAS and commits typed provenance/control events; it
never grants business authority.

After committed Cutover, `SitinaEngine.run` routes Journal-first. CLI `list`,
`show`, `trace`, `report`, and `replay` merge canonical B+ events with an
immutable, snapshot-hash-labeled Legacy reader. They never initialize or mutate
the live Legacy SQLite store. Projection databases remain disposable and cannot
select a writer.

`scripts/cutover-phase6b.py` is executable only after a separate signed,
time-bounded, hash-pinned Maintenance Manifest is verified. It freezes Legacy,
creates and restores the canonical recovery point, migrates, submits the stable
Cutover command, runs a mock-only canary/rebuild, commits the manifest-frozen
CutoverVerified contract, and independently rereads authority. The external
capability ceiling remains `MOCK_ONLY`; deletion, Hot Eviction, crypto-erasure,
and live-effect activation remain outside Phase 6B.

## Storage V2 repair and lifecycle closure (2026-07-18)

The current post-cutover storage contract is documented in
[`storage-v2-operations.md`](storage-v2-operations.md). It supersedes older
operational assumptions about full-history startup, character-truncated
context, generic full-payload Projection rows, permanent historical CAS roots,
and direct Legacy SQLite reads. Historical phase descriptions above remain as
audit context; they are not permission to bypass current Journal authority,
feature activation, semantic-root, or read-only diagnostic boundaries.
