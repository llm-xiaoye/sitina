# Sitina storage V2 operations

This is the operational contract for the storage repair delivered on
2026-07-18. It does not authorize migration, garbage collection, archival,
Trash access, or a feature rollout.

## Authority boundaries

- Canonical Journal is the only event authority.
- Encrypted CAS is the only durable body store.
- Projection SQLite contains query-only derived state and is disposable.
- Authority Checkpoint authenticates Journal state, command bindings, stream
  heads, and the typed semantic-root snapshot. It never authenticates or
  depends on Projection bytes.
- macOS Keychain holds the checkpoint rollback anchor. A disk checkpoint below
  the anchored sequence, or a different commitment at the same sequence, fails
  closed.

The cross-store commit order is always `body -> authoritative reference ->
derived view`. A crash may leave a reclaimable staged/orphan body, or a lagging
Projection, but never a committed reference to an unpublished body.

## Compatibility and rollout

`config/format_capabilities.json` defines reader/writer versions, upcasters,
feature names, and rollback floors. `config/feature_flags.json` is requested
configuration only; it is not activation authority. A new writer becomes legal
only after compatible runtime leases and committed
`runtime.feature-prepared`/`runtime.feature-activated` Journal events.

Runtime recovery rebuilds feature state from those Journal events. Seeing a V2
first-write schema before its activation fails closed. Turning a configuration
flag off cannot lower a rollback floor after a first write. The checked-in write
flags remain off, so this change deploys readers and protocols without doing a
data-format migration.

Pure upcasters are registered for Journal Event V1, Run Checkpoint V1, Run
Evidence V1, and Agent Context Manifest V1. They use no clock, filesystem,
network, Projection, or Provider state and never rewrite stored bytes.

## Journal fast start

Rollover produces an immutable sealed segment, signed certificate, Merkle block
index, authenticated derived indexes, and Authority Checkpoint. Only an
activated `authority_checkpoint_v1_write` feature may attach automatic rollover
to a Production writer. Append acknowledgement is not delayed by the background
checkpoint; close waits for an in-flight checkpoint and surfaces a failure.

Default startup verifies checkpoint/certificate/index commitments and scans
only `active.seg`. `sitina list` selects a Projection V2 generation bound to the
same checkpoint, verifies semantic checksum and schema coverage, and applies
the exact active tail in memory. `show`, `trace`, and `replay` intentionally use
an explicit full-verification history path because they need historical event
payloads.

## Session, context, memory, checkpoint, and evidence

User messages are encrypted into CAS and Journal-rooted before Provider
admission. `config/context_policy.json` is the sole context budget source.
Legacy round/character bounds in router or `sitina.yaml` fail startup rather
than override it. The renderer preserves system rules, current goals and
constraints, and the current user message; it drops low-value memory and old
raw turns first. It records component hashes, policy hash, renderer version,
token count, and final input hash without storing a duplicate prompt.

Working State and rolling summaries are Base+Delta CAS objects rooted by
Journal events. Memory is strict, append-only, ACL-checked at read and write,
and follows `candidate -> accepted/rejected -> superseded/revoked/expired`.
Accepted current memories have independent semantic roots. Run Checkpoint V2
contains only the current run's incremental range and newly introduced refs;
terminal compaction is independently restorable. Evidence V2 contains refs and
totals, never copied bodies. Agent Context V2 is reconstructable from base and
delta refs. Once its Journal feature is activated, the Production Agent
executor publishes prompt template, conversation state, and per-call delta
through the deduplicating CAS path, stores only the small manifest as the input
identity, and keeps Provider transport bytes runtime-only. Before activation it
continues the old writer format.

## Projection

Generation layout is `current`, `previous`, and `building`; publication uses an
atomic pointer replace and prunes all other derived generations. Readers verify
Authority Checkpoint commitment, semantic checksum, schema coverage, and lag
before applying an exact tail. Unknown required schemas degrade and roll back
the Projection batch. Unknown optional schemas enter only `event_directory`.

Session/message/run/state/summary, Agent call, tool result, token/score, memory,
episode, Provider health, Run Checkpoint, and Evidence query tables retain
source position, source event ID, and schema version. Full Journal payloads are
not copied. Deleted sessions remain reconstructable but disappear from active
message and run views.

## CAS, roots, GC, Trash, and worktrees

CAS dual-reads uncompressed/zstd and loose/packed metadata. Safe dedup identity
includes tenant, purpose, private plaintext commitment, compression profile,
and crypto profile. New compression/pack writers require activated features.
Staging and quarantine have explicit reconciliation states; neither is silently
treated as canonical content.

GC marks only typed current roots: system, active session, active run, memory,
backup, Trash, legal retention, and in-flight reference leases. Historical
Journal references are evidence, not permanent roots. GC defaults to dry-run
and this release exposes no Production sweep path. Missing content with a valid
destruction attestation reports `PURGED` or `CRYPTO_SHREDDED`, not corruption.

Session deletion is a logical Trash transaction:

`DELETION_REQUESTED -> CHECKPOINTING -> TRASH_BUNDLE_PREPARED ->
TRASH_MOVE_COMPLETED -> DELETION_COMMITTED -> HIDDEN_FROM_PROJECTION`.

The bundle stores only identities, refs, frontier, and checksums. An active or
missing-grace Trash Lease remains a GC root. Finder restore is a manual import:
validate schema/checksums/deletion event/CAS refs, append `session.restored`,
rebuild roots, and never replay side effects. Project/user memory and
independently used private memory remain rooted; candidates and session/run
memory enter the Trash closure. Explicit revocation appends `memory.revoked`.

Worktree state stores base commit/branch, staged and unstaged diffs, each
untracked body once in CAS, and exact status. Reconstruction occurs in a new
temporary clone and never deletes the source repository, project, or branch.

## Read-only diagnostics

```text
sitina storage inspect
sitina journal startup-report
sitina journal verify --full
sitina journal scrub --background
sitina projection report
sitina projection coverage
sitina memory report
sitina storage gc --dry-run
sitina storage migration-plan
sitina storage archive-plan
sitina runtime compatibility
```

`memory review` (without accept/reject) and `memory show` use verified Journal
and CAS read views and cannot open a writer. Archive planning hashes every file,
computes a Merkle root, and estimates allocated reclaim, but has no archive or
delete method. A future execution requires a verified cold copy, isolated
offsite restore, signed catalog, second confirmation, and native Trash adapter.

## Recovery rules

- CAS published, Journal absent: retry the same idempotency key or reclaim after
  grace; do not invent an event.
- Journal committed, Projection absent/corrupt: rebuild/switch Projection; do
  not change Journal or Authority Checkpoint.
- Tool CAS published, Journal absent: retain the runtime receipt and reuse the
  same CAS refs on retry.
- Trash move failed: session remains active and retry resumes from the durable
  receipt.
- Trash bundle missing: enter `MISSING_GRACE`; do not release its roots until
  retention expires and an explicit confirmation is recorded.
- Checkpoint/certificate/Keychain mismatch: fail closed and run read-only full
  verification; never choose a writer from Projection state.
