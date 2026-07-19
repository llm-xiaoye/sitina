# Sitina Storage Production Closure — Acceptance Matrix

`PASS` requires integrated runtime or authority evidence; code existence,
fixtures, mocks, and documentation do not qualify. The user has approved one
narrow security exception for the active DeepSeek profile to retain its direct
credential. The bounded canary, expanded deep audit, source/evidence bindings,
Sentinel refresh, and aggregate classification pass. Final classification:
`PRODUCTION_READY_VALIDATED`.

## Final gates

| Gate | State | Reproducible evidence |
|---|---|---|
| CLI and default prompt | PASS | Real PTY default chat canary enters Conversation Runtime at `你 [auto] >` |
| Conversation Runtime | PASS | Six real durable turns; CAS bodies, Journal session state, restart recovery |
| Router and AUTO | PASS | Local deterministic route input hash, policy version, decision path, replay |
| FAST | PASS | Four real forced runs; each exactly one logical call and one physical send |
| MULTI | PASS | Six agents; proposal, review, correction, negotiation, handoff, terminal execution |
| Provider | PASS | Real Provider/model usage; bounded counters; committed-call zero-resend recovery |
| Journal | PASS | 85,449 authenticated ordered events; checkpoint, replay, corruption, crash, concurrency |
| CAS | PASS | 105,513 objects verified; 105,509 referenced; atomicity, dedup, corruption, reconciliation |
| Projection | PASS | Signed generation, exact frontier, rebuild/switch/rollback/corruption tests |
| Replay | PASS | Live-run replay plus independent full replay equals Fast Start |
| Recovery | PASS | Restart, checkpoint+tail, committed-call reconciliation, no duplicate Provider send |
| Session persistence | PASS | One session, twelve messages, six successful turns recovered |
| Memory lifecycle | PASS | Candidate hidden pre-review; accepted visible and restart-stable; rejected unavailable |
| Storage V2 | PASS | Required writers active; old data readable; unknown versions fail safely |
| Backup and restore | PASS | Final immutable backup restored and semantically verified in isolation |
| Performance | PASS | 85,413-event raw benchmark with median/p95/p99/memory |
| Permissions/redaction | PASS | Owner-only roots, zero unsafe entries, no content/authority mutation |
| Secret persistence | PASS | Exact configured Provider value absent from Journal, CAS, source, logs, artifacts, reports |
| Provider profile storage | PASS_WITH_ACCEPTED_EXCEPTION | Active DeepSeek profile may retain its direct credential; exact exception matching and compensating controls are required |
| Evidence completeness | PASS | Required identifiers, counters, Journal ranges, CAS refs, replay/recovery receipts |
| Full regression | PASS | 916 tests; 21 intentional skips; zero network/Production-storage attempts; evidence SHA-256 `20245b29c1f95e8beb5e0c9e834baa58aa1a2ae31af5d29203f9a93174b34520` |

## Real canary evidence fields

- [x] Run and session identifiers
- [x] Provider and model
- [x] Logical-call and physical-send counts
- [x] Journal ranges and terminal positions
- [x] CAS references and ciphertext verification
- [x] Checkpoint identity and authority frontier
- [x] Replay status and semantic checksums
- [x] Recovery status, including zero resend
- [x] No message/response bodies or Provider credential values in evidence

## Journal, CAS, and projection fault matrix

- [x] Truncated record and invalid frame
- [x] Corrupted bytes and checksum failure
- [x] Duplicate event/command and missing sequence
- [x] Stale checkpoint and invalid anchor
- [x] Interrupted append and rollover
- [x] Concurrent writers, readers during append, and stale locks
- [x] Unknown schema fails safely; no silent authoritative-history repair
- [x] Missing/corrupted/hash-mismatched CAS object
- [x] Interrupted/duplicate/concurrent CAS publication
- [x] Orphan detection, quarantine, and reference reconciliation
- [x] Deleted/corrupted projection rebuild
- [x] Interrupted, stale, and schema-mismatched generation
- [x] Validate, atomic publish/switch, reader safety, and rollback

Focused fault/concurrency evidence passed 193 tests across four clean homes:
Journal 43, CAS 35, projection/checkpoint/compatibility 32, and
session/memory/replay/recovery 83.

## Lifecycle, recovery, and compatibility matrix

- [x] User and assistant bodies publish to CAS before Journal references
- [x] Context uses goal, constraints, working state, summary, accepted memory,
  and required history within its budget
- [x] Unreviewed and rejected memory are unavailable
- [x] Accepted memory survives restart and retrieval is deterministic
- [x] CAS-before-Journal and Journal-before-projection crash windows converge
- [x] Checkpoint, rollover, restore, and memory-acceptance faults recover
- [x] Committed Provider calls reconcile without resend
- [x] Old valid data remains readable; unknown shapes fail explicitly
- [x] Fast Start checkpoint+tail equals independent full replay
- [x] Ordinary restart performs zero full-history scan and zero Provider send

## Backup and restore matrix

- [x] Complete manifest, hashes, modes, metadata, and exact frontier
- [x] Journal/CAS consistency and Authority Checkpoint coverage
- [x] Isolated raw restore and full authenticated replay
- [x] Clean projection rebuild
- [x] Session, memory, checkpoint, and evidence recovery
- [x] No credentials copied and no external effects executed
- [x] Post-checkpoint clone-only memory write and tail replay

## Performance matrix

- [x] 85,413 events
- [x] Cold start and runtime-state open
- [x] Conversation resume / Fast Start
- [x] Full replay and projection rebuild
- [x] Context reconstruction
- [x] CAS publish/read and Journal append
- [x] Median, p95, p99, raw samples, and peak memory
- [x] Zero Production mutations and zero Provider sends

## Security and Sentinel matrix

- [x] Source, tests, logs, artifacts, and reports scanned
- [x] Every authenticated Journal event scanned
- [x] Every CAS object decrypted, verified, and scanned
- [x] Exact Provider-value match scan performed without emitting or persisting it
- [x] Owner-only permission verification
- [x] Errors and evidence redact sensitive values
- [x] Real Provider credentials left unmodified
- [x] Direct active-profile storage covered by the explicit user-approved
  exception; no migration, modification, rotation, or exposure performed
- [x] Zero exact-value persistence verified across raw Journal, CAS,
  projections, checkpoints, evidence, logs, backups, and reports
- [x] Zero exact-value exposure verified across CLI/errors/debug output,
  Sentinel, and artifacts
- [x] Every backup manifest/payload and protected-file access control verified
- [x] Raw before and after Sentinels and deterministic diff
- [x] Seventeen-section final report

## Accepted exception

The active DeepSeek profile retains its direct credential under the explicit
user-approved exception and compensating controls. Keychain migration is not a
gate for this closure. Any additional direct credential, exact-value
persistence/exposure hit, access-control failure, or exception-shape mismatch
invalidates this acceptance.
