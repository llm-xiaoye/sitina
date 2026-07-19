# Sitina Full Production Runtime + Storage Closure — Final Report

## 1. Final classification

`PRODUCTION_READY_VALIDATED`

The user explicitly approved one narrow exception: the active DeepSeek profile
may retain its direct credential. Keychain migration is no longer an acceptance
gate. The bounded Provider canary, final checkpoint/projection, immutable
backup/restore, expanded security audit, source/evidence bindings, Sentinel
comparison, and aggregate acceptance all pass. The credential value is not
printed, copied into evidence, or persisted as a hash. Every remaining gate
passes under the documented exception.

## 2. Modified files

The repository has no Git metadata. The final source-content manifest is the
exact file/hash identity; the material changes are:

- Core backup/safety: `core/sitina/archive/production_backup.py`,
  `core/sitina/guards/secrets.py`, `core/sitina/legacy/fence.py`,
  `core/sitina/security/macos_keychain.py`.
- Core compatibility/storage: `core/sitina/compatibility/feature_flags.py`,
  `core/sitina/compatibility/leases.py`, `core/sitina/compatibility/rollout.py`,
  `core/sitina/journal/fast_start.py`, `core/sitina/journal/local.py`,
  `core/sitina/projections/generations.py`,
  `core/sitina/projections/production.py`, `core/sitina/projections/schema.py`.
- Core conversation/runtime: `core/sitina/cli.py`,
  `core/sitina/conversation/__init__.py`, `context.py`, `fast_runtime.py`,
  `lifecycle.py`, `models.py`, `persistence.py`, `recovery.py`, and `runtime.py`.
- Core execution: `core/sitina/extensions/runtime.py`,
  `core/sitina/orchestrator/agent_context_v2.py`, `bplus_production.py`,
  `context.py`, `true_multi_agent.py`, and `true_multi_agent_runtime.py`.
- Drivers: `scripts/benchmark-storage-production.py`,
  `storage-closure-sentinel.py`, `storage-production-activate.py`,
  `storage-production-backup.py`, `storage-production-fault-concurrency-acceptance.py`,
  `storage-production-feature-rollout.py`, `storage-production-finalize.py`,
  `storage-production-full-suite.py`, `storage-production-live-evidence.py`,
  `storage-production-memory-canary.py`, `storage-production-permission-harden.py`,
  `storage-production-recovery-verify.py`, `storage-production-restore-verify.py`,
  `storage-production-runtime-state-activate.py`,
  `storage-production-security-audit.py`,
  `storage-restored-memory-post-checkpoint.py`, and `storage-source-manifest.py`.
- Tests: `tests/foundation/test_phase_minus1_acceptance.py`,
  `tests/test_agent_context_v2.py`, `test_chat_cli.py`,
  `test_conversation_storage_integration.py`, `test_evidence_hardening.py`,
  `test_extensions.py`, `test_fast_conversation_runtime.py`,
  `test_feature_rollout.py`, `test_journal_fast_start_integration.py`,
  `test_journal_fast_start_v2.py`, `test_legacy_compatibility.py`,
  `test_legacy_retirement_disabled.py`, `test_list_projection_fast_start.py`,
  `test_production_backup.py`, `test_projection_kernel.py`,
  `test_projection_stable_v2.py`, `test_provider_secret_references.py`,
  `test_session_context_v1.py`, `test_session_state_summary_v1.py`,
  `test_sitina.py`, `test_storage_closure_sentinel.py`, `test_suites.json`, and
  `test_true_multi_agent_cli_routing.py`.
- Documentation: `docs/architecture.md`, `docs/security.md`, `docs/usage.md`,
  and `docs/storage-production-closure/*`.
- Production state: required feature-activation Journal events, real bounded
  canary events/CAS bodies, one accepted-memory canary, Authority Checkpoint
  sequence 3, signed projection generations, owner-only permission metadata,
  verified backups, and the closure evidence manifest. No deletion or
  destructive GC occurred.

## 3. Runtime call graph

```text
sitina PTY / CLI
  → ConversationRuntime (resume/create durable session)
  → deterministic Router (requested mode → persisted decision)
  → FAST Agent Runtime or six-agent MULTI Runtime
  → Provider call accounting and recovery boundary
  → CAS publish of bodies/evidence
  → Journal state transition / reference
  → signed SQLite projection + authenticated active tail
  → offline replay / restart reconciliation / recovery
```

`computer_use` remains a tool capability; it does not replace Conversation
Runtime, routing, or agent execution.

## 4. Storage architecture

- Journal: sole ordered event authority, authenticated through frontier 85,449.
- CAS: sole encrypted content/body authority; 105,513 objects verified, of
  which 105,509 are Journal-referenced and four are unreferenced forensic/orphan material.
- SQLite: signed, immutable generation selected at the exact checkpoint
  commitment and rebuildable from Journal/CAS.
- Runtime memory: derived only.
- Fast Start: Authority Checkpoint base plus authenticated Journal tail.
- Session and Memory: projection acceleration with Journal/CAS write-through;
  no second event or content authority.

## 5. FAST evidence

Four forced real FAST canaries each used one agent, one logical Provider call,
and one physical send. Every run persisted route, run, usage, terminal,
session-link, CAS-reference, and replay evidence. The recovered committed-call
run performed zero resend. Evidence:
`storage-production-live-canaries.json` (SHA-256
`c20bdd348d59f984ca3ef86d8212d072e0e629461387d7daab43dcda82635e69`).

## 6. AUTO evidence

Default chat requested AUTO and persisted the route input hash, policy version,
local route source, decision path, requested mode, and resolved mode. Replay
reconstructed the same route without Provider or external calls. Both clean and
recovered AUTO paths resolved deterministically to FAST in the bounded canaries.

## 7. MULTI evidence

The live MULTI canary used six agents and persisted proposal, review,
rejection/correction, negotiation, handoff, and final execution. It recorded 13
logical calls and 13 physical sends, terminal success, Journal range, CAS
references, and replay. The collaboration was the real runtime, not a fixture.

## 8. Provider evidence

The existing real Provider and configured model completed default, FAST, AUTO,
MULTI, restart, and recovery runs. Usage events bind agent/call identities,
outcome, retry/fallback counts, logical calls, physical sends, token/cost
counters, and terminal state. Evidence contains no response or message bodies
and no credential values.

The final approved-exception canary used the unchanged active DeepSeek profile,
forced FAST, completed exactly one logical call and one physical send with zero
retry/fallback, found zero exact-value hits in its new Journal events and CAS
objects, recovered after restart, and left the profile inode, size, mode, and
content hash unchanged. Its body-free evidence is
`storage-production-approved-exception-provider-canary.json`.

## 9. Journal evidence

- Final frontier: position 85,449, epoch 1, commitment
  `d11944154b532489d9054a032ab0026388790ef4fbb1873a99d7247345aa1ce2`.
- Authority Checkpoint: sequence 4, complete coverage, active tail 0.
- Deep audit authenticated and scanned every event.
- Fault/concurrency acceptance covers ordered identity, framing, append
  durability, corruption, anchors, rollover, idempotency, stale locks,
  concurrent writers/readers, and safe unknown-version failure.
- No silent repair of authoritative history occurred.

## 10. CAS evidence

- 105,513 encrypted objects and 5,028,140,074 plaintext bytes were
  decrypted, commitment-verified, and scanned.
- 105,509 unique Journal references resolved; four unreferenced objects were
  retained, not destructively collected.
- Atomic publication, deterministic addressing, duplicate writers, concurrent
  publication, corruption, missing objects, orphan detection, quarantine, and
  reconciliation passed focused tests.
- Live V2 zstd publication was observed and replayed.

## 11. Projection evidence

Final generation `generation-d77a942f2b264231b4cd21f7f1b72218` is Authority
signed. Its database SHA-256 is
`b410378247bcafec9f8e04ec14a73aec00968b0eee3463f1cabf4d43bc9981a9`
and semantic checksum is
`3bfc5799c823b9d69597c1e0dd801b5c0a6b4c726e4648d06a82a52197bc595f`.
It contains 55 runtime-state events, one session/twelve messages, one accepted and
one rejected memory, and zero pending runs. Deleted/corrupt/stale/schema-mismatch
generation tests prove rebuild, validation, publication, switch, and rollback.

## 12. Recovery evidence

- Restart recovered six successful turns and accepted memory from signed
  projection+tail while a patched full verifier made any ordinary full replay fail.
- Committed-call reconciliation recovered terminal state with zero resend.
- Independent full replay equals Fast Start.
- A restored clone appended exactly two memory lifecycle events after the
  checkpoint; checkpoint+tail and full replay produced identical visibility.
- Fault tests cover CAS-before-Journal, Journal-before-projection, checkpoint,
  rollover, memory acceptance, and Provider uncertainty windows.

## 13. Backup evidence

Final backup `storage-closure-approved-exception-20260719T062020Z` contains
322,890 files and 6,082,843,449 logical bytes at frontier 85,449. Manifest hash:
`34ffd55f5dfd00b80b9a73538f83a83ccf1a48dbae76cc3335cf162e7d388ed7`.
The isolated restore verified all raw files, full Journal replay, CAS
references, clean projection rebuild, checkpoint, session, memory, and evidence
state. It copied no credentials, activated no writer, and executed no external
effects. Rollback backups are retained; no sole backup was overwritten.

## 14. Performance results

The final benchmark uses 85,413 authoritative events and includes raw samples
and process/Python memory instrumentation.

| Operation | p99 |
|---|---:|
| Cold start | 486.8 ms |
| Runtime-state open | 270.9 ms |
| Conversation resume | 786.4 ms |
| Context reconstruction | 0.288 ms |
| CAS verified read | 0.335 ms |
| Disposable Journal append | 0.273 ms |
| Disposable CAS atomic publish | 3.730 ms |
| Full replay | 14.535 s |
| Projection rebuild | 41.285 s |

Benchmark evidence is
`storage-production-85k-benchmark-v2.json` (SHA-256
`54e92569e95be2d078f44e08b4299aca179de68180b20fb5703e7628c2b05152`).
It performed zero Provider sends and zero Production mutations.

## 15. Security results

The final audit scans source, tests, logs, artifacts, reports, every
authenticated Journal event, and every decrypted/verified CAS object. Exact
matching of the configured real-provider value is performed in memory without
emitting or hashing it.

- Exact persistence hits outside the active profile: 0.
- Journal pattern or exact-value findings: 0.
- CAS pattern or exact-value findings: 0.
- Log/artifact/report unresolved findings: 0.
- Unsafe permission entries after hardening: 0.
- Evidence/log credential exposure: 0.
- Direct real-profile credentials: 1 — explicit accepted exception; every
  compensating control passed.

The expanded audit verified 85,449 authenticated Journal events, 105,513
decrypted CAS objects, five retained backup manifests and 1,613,291 logical
backup files (26,559,360,755 unique bytes scanned), and owner-only access across
1,936,244 protected files and 3,367 directories. Exact persistence/exposure
hits, unresolved source/artifact pattern findings, unsafe files, unsafe
directories, copied profiles, and backup CAS identity gaps are all zero.
The body-free final audit is
`storage-production-security-audit-final.json` (SHA-256
`dce4313ca5c12a305a1f4438b73ba68d15f1370530fd0178e6d9cd93680d37cf`).

The permission pass changed modes only and preserved content, Journal, CAS,
frontier, and commitment. The real credential was not modified.

Accepted risk: the active DeepSeek profile retains one directly stored
credential instead of a macOS Keychain reference.

Affected component: active DeepSeek Provider profile configuration and its
credential-loading path.

Reason for exception: the user explicitly chose to preserve the working active
profile and authorized closure without migration, rotation, modification, or
value exposure.

Mitigation controls: exact one-profile policy matching; owner-only regular-file
access; no-follow scanning; zero exact-value hits required in raw Journal, CAS,
projection, checkpoint, evidence, logs, backups, reports, Sentinel, artifacts,
CLI/error/debug outputs; verified backup manifests and payload identities; a
single bounded Provider canary; redacted body-free evidence; and fail-closed
acceptance for any mismatch or additional direct credential.

Future migration recommendation: when separately authorized, move the active
credential into macOS Keychain, replace the profile field with a Keychain
reference, rerun the bounded Provider canary and the full security/Sentinel
closure, and then retire this exception.

## 16. Sentinel comparison

The raw before/pre-activation Sentinel and final after Sentinel use the same
no-runtime-import, raw-byte algorithm. The deterministic diff records only
authorized changes:

- append-only Journal events for activation, canaries, and memory acceptance;
- corresponding encrypted CAS objects;
- Authority Checkpoint/index and signed projection generations;
- verified backup/evidence artifacts;
- owner-only permission metadata; and
- non-authoritative disposable rebuild/operational evidence retained for audit.

No authority deletion, destructive GC, credential change, or unexplained
external-root mutation is accepted. Evidence: `sentinel-before.json`,
`sentinel-pre-activation.json`, `sentinel-after.json`, and `sentinel-diff.json`.

## 17. Remaining assumptions

1. The user has approved retaining the active DeepSeek direct credential as a
   documented security exception; this does not authorize any value change,
   rotation, migration, emission, or copying.
2. macOS Keychain remains the recommended future credential authority; the existing Keychain
   integration and reference tests pass.
3. The retained four unreferenced CAS objects are non-authoritative and remain
   intentionally undeleted because destructive GC was not authorized.
4. Current hardware/platform measurements are specific to this Mac and the
   pinned Python runtime; correctness gates do not depend on those timings.
5. The accepted exception remains valid only while its exact one-profile shape
   and compensating controls continue to pass. Any additional direct credential
   or containment/access-control failure reopens the security gate.
