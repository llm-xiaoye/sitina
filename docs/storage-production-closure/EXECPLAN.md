# Sitina Full Production Runtime + Storage Closure — Execution Plan

## Goal binding and current state

- Goal thread: `019f7643-f34d-7911-9bd6-82722c165f2e`
- Production home: `~/SitinaHub`
- Authority frontier: position `85449`, epoch `1`, commitment `d11944154b532489d9054a032ab0026388790ef4fbb1873a99d7247345aa1ce2`
- Final checkpoint: sequence `4`, complete active tail `0`
- Required success classification: `PRODUCTION_READY_VALIDATED`
- Current classification: `PRODUCTION_READY_VALIDATED`
- Approved exception: the active DeepSeek profile may retain its direct
  credential. Keychain migration is not a closure gate.

The Goal remains active. The user explicitly approved the narrow direct-storage
exception without authorizing migration, modification, rotation, or exposure.
The remaining actions are bounded revalidation: one Provider canary, expanded
security and backup scans, final Sentinel refresh, and aggregate classification.

## Authority invariants

1. Journal is the only event authority.
2. CAS is the only content/body authority.
3. SQLite is a signed, rebuildable projection and never an authority.
4. Process memory is derived and disposable.
5. User and assistant bodies publish to CAS before bounded Journal references.
6. Accepted memory is visible only after Journaled review state and survives
   restart through checkpoint-plus-tail reconstruction.
7. Recovery never repeats a committed Provider send.
8. Production mutations require Sentinel, backup, manifest, verification,
   evidence, and rollback coverage.

## Completed execution loop

### 1. Discovery and baseline — COMPLETE

- Read the complete Goal specification and reused the existing Goal.
- Confirmed no repository-level `AGENTS.md` and no Git metadata.
- Discovered Journal, CAS, projections, data, logs, state, runtime, memory,
  backups, artifacts, output(s), temp, archives, trash, retired state,
  acceptance, Downloads, and the external extensions registry.
- Captured the raw before Sentinel without runtime imports, SQLite, or Journal
  parsing. The later pre-activation Sentinel covers 810,784 entries and
  27,251,280,752 bytes.

### 2. Audit, reproduce, and repair — COMPLETE

- Traced CLI → Conversation Runtime → Router → FAST/MULTI → Provider → CAS →
  Journal → Projection → Replay → Recovery.
- Unified session lifecycle handling across FAST, direct MULTI, and autonomous
  extension execution.
- Moved user/assistant, context, evidence, and accepted-memory bodies behind CAS
  references with Journal state transitions.
- Repaired historical event compatibility, circular imports, committed-call
  recovery, projection publication, and ordinary resume behavior.
- Closed every internally repairable issue in `ISSUES.md`.

### 3. Storage V2 activation — COMPLETE

- Activated `agent_context_v2_write`, `memory_v1_write`, and `cas_zstd_write`.
- Published an Authority-signed projection generation at the exact checkpoint
  frontier.
- Integrated checkpoint-plus-authenticated-tail reads into ordinary session,
  memory, run, and replay paths.
- Proved ordinary restart performs zero full-history scan and zero Provider
  send while matching independent full replay.

### 4. Fault, concurrency, and compatibility acceptance — COMPLETE

- Passed 193 focused Journal, CAS, projection, checkpoint, lifecycle, replay,
  recovery, crash, and concurrency tests in four clean disposable homes.
- Covered truncation, framing corruption, missing/gapped events, invalid
  anchors, interrupted append/rollover/publication, stale locks, concurrent
  writers/readers, duplicate CAS publication, projection corruption/switch,
  memory crash windows, and committed-call recovery.
- Passed the final guarded full discovery suite: 916 tests, 21 intentional
  skips, zero network attempts, zero Production-storage attempts, and unchanged
  Production fingerprints.

### 5. Backup, restore, and post-checkpoint mutation — COMPLETE

- Published final backup
  `storage-closure-approved-exception-20260719T062020Z` with 322,890 files and
  6,082,843,449 logical bytes.
- Verified its immutable manifest and restored it into isolation.
- Replayed all 85,449 Journal events, verified 105,509 Journal-referenced CAS
  objects, rebuilt projection state, recovered six successful turns, and
  recovered one accepted and one rejected memory without credentials or
  external effects.
- On the restored clone only, appended a two-event memory candidate→accepted
  tail, proved candidate invisibility before review and visibility after
  acceptance, then proved checkpoint-plus-tail equals full replay.

### 6. Performance — COMPLETE

- Benchmarked 85,413 authoritative events with raw samples and memory data.
- p99 results: cold start 486.8 ms; runtime-state open 270.9 ms; conversation
  resume 786.4 ms; context reconstruction 0.288 ms; CAS verified read 0.335 ms;
  disposable Journal append 0.273 ms; CAS atomic publish 3.730 ms.
- Full replay measured 14.535 s and projection rebuild 41.285 s.
- No benchmark mutated Production or called a Provider.

### 7. Live runtime activation and canaries — COMPLETE

- Validated the default `sitina` PTY prompt and real Conversation Runtime.
- Passed bounded real Provider default/AUTO, four forced FAST, MULTI, restart,
  replay, and recovery canaries.
- Every FAST run recorded one logical call and one physical send.
- The recovered run recorded zero resend.
- MULTI used six agents and persisted proposal, review, rejection/correction,
  negotiation, handoff, and terminal execution; it recorded 13 logical and 13
  physical sends.
- Evidence contains hashes/references and counters, never message or response
  bodies.
- The approved-exception final canary added one successful forced-FAST turn
  with exactly one logical call, one physical send, zero retry/fallback, clean
  Journal/CAS exact scans, restart recovery, and unchanged profile identity,
  bytes, and mode.

### 8. Security and permissions — COMPLETE WITH ACCEPTED EXCEPTION

- Deep-scanned authenticated Journal events and decrypted/verified every CAS
  object, plus source, tests, logs, artifacts, reports, and permissions.
- Found zero exact persistence of the configured real-provider value in source,
  Journal, CAS, logs, artifacts, or reports.
- Hardened approved roots to owner-only directory/file modes without changing
  content, Journal, CAS, or the authority frontier.
- One real-provider profile still stores its credential directly under the
  explicit user-approved exception. The exception is valid only for the exact
  active DeepSeek profile and only if all prohibited persistence/exposure
  surfaces remain clean and access controls pass.
- The expanded audit passed with zero exact hits across named persistence and
  exposure surfaces, verified all five retained backups and all 105,513 CAS
  objects, and accepted 55 historical `0644` → `0600` metadata tightenings.
- Post-canary permission hardening restricted two new CAS bucket directories
  and twelve new backup config payloads to owner-only modes without changing
  content or authority.

### 9. Final closure — COMPLETE

- Final documents, source manifest, evidence manifest, after Sentinel, diff,
  full security audit, post-closure scan, and aggregate acceptance evidence are
  generated and verified by this closure pass.
- Do not migrate, modify, rotate, emit, hash, or copy the credential.
- Verify the existing profile with one bounded canary, rescan Journal, CAS,
  projections, checkpoints, evidence, logs, backups, reports, CLI/error/debug
  outputs, Sentinel, and artifacts, and validate protected-file access controls.
- The final Sentinel and aggregate evidence pass; the classification is
  `PRODUCTION_READY_VALIDATED`, completing the existing Goal without credential
  migration.

## Modified-file groups

The exact current source identity is recorded by the final source-content
manifest. Material changes are grouped as follows:

- Conversation/CLI: `core/sitina/cli.py`, `core/sitina/conversation/*`.
- Runtime/provider/multi-agent: `core/sitina/orchestrator/*`,
  `core/sitina/extensions/runtime.py`.
- Journal/CAS/Storage V2: `core/sitina/journal/*`,
  `core/sitina/compatibility/*`, `core/sitina/security/macos_keychain.py`.
- Projection/replay: `core/sitina/projections/*`.
- Backup/safety: `core/sitina/archive/production_backup.py`,
  `core/sitina/legacy/fence.py`, `core/sitina/guards/secrets.py`.
- Operational drivers: `scripts/storage-*.py` and
  `scripts/benchmark-storage-production.py`.
- Regression coverage: the storage, conversation, provider, projection,
  recovery, feature-rollout, backup, Sentinel, and full-suite tests listed in
  `FINAL_REPORT.md`.
- User documentation: architecture, security, usage, and this closure bundle.

## Rollback and resumption

- Pre-permission rollback: `backups/storage-closure-pre-permission-20260718T224500Z`.
- Definitive final restore point:
  `backups/storage-closure-approved-exception-20260719T062020Z`.
- Current projection rollback is a signed generation switch; SQLite can always
  be rebuilt from the Journal/CAS authority.
- Credential migration will not occur in this closure. The accepted exception
  leaves the active profile unchanged; rollback coverage and all non-exception
  security gates remain mandatory.
