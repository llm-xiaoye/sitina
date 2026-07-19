# Sitina Storage Production Closure — Issue Register

Every internally repairable issue completed the required transition:

`DISCOVERED → REPRODUCED → ROOT_CAUSED → PATCHED → TARGET_TESTED → INTEGRATION_TESTED → FAULT_TESTED → REGRESSION_TESTED → CLOSED`

SPC-014 is closed by an explicit user-approved security exception with passing
compensating controls. SPC-019 through SPC-024 record closure-evidence defects
found and repaired during that revalidation.

## Summary

| ID | Severity | Runtime path | State |
|---|---:|---|---|
| SPC-001 | Critical | Sentinel / Production safety boundary | CLOSED |
| SPC-002 | Critical | CLI → session → restart | CLOSED |
| SPC-003 | Critical | Memory review → context | CLOSED |
| SPC-004 | High | Storage V2 writer activation | CLOSED |
| SPC-005 | Critical | Backup → restore | CLOSED |
| SPC-006 | Critical | MULTI/autonomous session lifecycle | CLOSED |
| SPC-007 | Critical | Context composition | CLOSED |
| SPC-008 | Critical | Autonomous evidence/cleanup | CLOSED |
| SPC-009 | High | Startup / Fast Start | CLOSED |
| SPC-010 | High | Package bootstrap | CLOSED |
| SPC-011 | Critical | Historical Journal → projection rebuild | CLOSED |
| SPC-012 | Critical | Ordinary runtime-state resume | CLOSED |
| SPC-013 | High | Persistent-root permissions | CLOSED |
| SPC-014 | Critical | Real Provider profile storage | CLOSED_WITH_ACCEPTED_EXCEPTION |
| SPC-015 | High | In-memory SQLite projection | CLOSED |
| SPC-016 | High | Final regression harness | CLOSED |
| SPC-017 | High | Journal rollover → sparse index | CLOSED |
| SPC-018 | High | Security closure → audit evidence review | CLOSED |
| SPC-019 | High | Security closure → audit metadata review | CLOSED |
| SPC-020 | High | Finalizer → runtime-state validation | CLOSED |
| SPC-021 | Critical | Security closure → raw persistence surfaces | CLOSED |
| SPC-022 | High | CAS/backup creation → owner-only access | CLOSED |
| SPC-023 | Medium | External restore → permission hardening | CLOSED |
| SPC-024 | High | Source manifest → derived Sentinel evidence | CLOSED |

## SPC-001 — Sentinel omitted active authority roots

- **Severity:** Critical
- **Affected runtime path:** Production mutation boundary across Journal, CAS,
  projections, output, retired state, acceptance, and extensions.
- **Reproduction:** The legacy Sentinel helper omitted current authority roots.
- **Expected / actual:** Every persistent root must be covered; several were
  invisible to the old helper.
- **Root cause:** A legacy cutover root list was reused after storage evolved.
- **Violated invariant:** No Production mutation without complete before/after evidence.
- **Repair:** Added raw-byte, no-runtime-import Sentinel capture and deterministic diff.
- **Regression test:** `tests/test_storage_closure_sentinel.py`.
- **Integration test:** Pre-activation and final Production captures.
- **Fault injection:** Mutation during capture and symlink roots fail closed.
- **Performance impact:** Parallel bucketed hashing keeps large CAS evidence reviewable.
- **Evidence:** `scripts/storage-closure-sentinel.py` and Sentinel JSON files.
- **Status:** CLOSED.

## SPC-002 — Conversation state was process-only

- **Severity:** Critical
- **Affected runtime path:** CLI → Conversation Runtime → session/history → restart.
- **Reproduction:** A process restart lost active user/assistant/session state.
- **Expected / actual:** CAS+Journal must recover it; process memory was the effective state.
- **Root cause:** Session primitives were not wired into the real execution path.
- **Violated invariant:** Runtime memory is never authoritative.
- **Repair:** Added shared lifecycle, idempotent persistence, durable resume, and `/new` handling.
- **Regression test:** Session/context, FAST, CLI, and recovery tests.
- **Integration test:** Five live turns recovered after restart.
- **Fault injection:** Terminal-before-assistant and failed-turn restart windows.
- **Performance impact:** Ordinary resume now uses projection+tail rather than full replay.
- **Evidence:** Live canaries and runtime-state activation evidence.
- **Status:** CLOSED.

## SPC-003 — Accepted memory could diverge into a second authority

- **Severity:** Critical
- **Affected runtime path:** Candidate → review → accepted/rejected → retrieval → context.
- **Reproduction:** Legacy Markdown memory and native Memory V1 coexisted.
- **Expected / actual:** CAS content plus Journal review state only; the old path could bypass review.
- **Root cause:** Native Memory V1 and legacy context evolved independently.
- **Violated invariant:** No hidden or unjournaled accepted-memory authority.
- **Repair:** Runtime retrieval uses only native reviewed Memory V1; legacy authority use is disabled and docs corrected.
- **Regression test:** Native memory, context, and session restart suites.
- **Integration test:** Production canary plus clone-only post-checkpoint candidate→accepted write.
- **Fault injection:** Candidate visibility and acceptance crash windows.
- **Performance impact:** Projected lookup is bounded; context p99 is 0.288 ms.
- **Evidence:** Memory canary and restored-memory post-checkpoint evidence.
- **Status:** CLOSED.

## SPC-004 — Required Storage V2 writers were inactive

- **Severity:** High
- **Affected runtime path:** Agent context, Memory V1, compressed CAS, checkpoint/projection compatibility.
- **Reproduction:** Required write flags were disabled at the baseline frontier.
- **Expected / actual:** Reversible compatible activation; Production remained on old writes.
- **Root cause:** Implementation existed without a completed rollout proof.
- **Violated invariant:** Test-only or inactive capability is incomplete.
- **Repair:** Simulated, backed up, activated, and verified all three required writers.
- **Regression test:** Feature rollout and compatibility suites.
- **Integration test:** First live V2 context, Memory, and zstd CAS writes.
- **Fault injection:** Interrupted rollout, stale lease, invalid feature sequence.
- **Performance impact:** CAS compression reduces eligible stored bodies without weakening verification.
- **Evidence:** Feature rollout and live canary evidence.
- **Status:** CLOSED.

## SPC-005 — No verified Production backup existed

- **Severity:** Critical
- **Affected runtime path:** Authority roots → backup → isolated restore → replay/recovery.
- **Reproduction:** Baseline `backups/` did not exist.
- **Expected / actual:** Manifested, restorable authority backup; none was available.
- **Root cause:** Existing backup components were fixture/legacy scoped.
- **Violated invariant:** A copy is not a backup until restore succeeds.
- **Repair:** Added fixed-prefix, lock-bound, immutable Production backup/restore.
- **Regression test:** Lock, mutation, symlink, tamper, and restore tests.
- **Integration test:** Final 322,846-file backup and successful isolated restore.
- **Fault injection:** Mid-copy mutation, corrupted payload, and partial publication fail closed.
- **Performance impact:** Preserves hardlinks and streams hashing over 6.07 GB logical data.
- **Evidence:** `storage-final-backup-restore.json`.
- **Status:** CLOSED.

## SPC-006 — Alternate execution paths bypassed the session lifecycle

- **Severity:** Critical
- **Affected runtime path:** Router → direct MULTI/autonomous extension → restart.
- **Reproduction:** MULTI/extension branches could return without durable session turns.
- **Expected / actual:** All modes share one lifecycle; mode-specific bypasses existed.
- **Root cause:** Persistence was embedded in FAST.
- **Violated invariant:** Every real runtime path must reach CAS+Journal and replay.
- **Repair:** Shared turn identity, run links, finalization/failure, and writer cleanup.
- **Regression test:** MULTI routing and extension suites.
- **Integration test:** Real six-agent MULTI turn recovered from authority state.
- **Fault injection:** Activation/hook/tool failure and cleanup boundaries.
- **Performance impact:** Constant additional Journal state events per turn.
- **Evidence:** MULTI live evidence and full regression log.
- **Status:** CLOSED.

## SPC-007 — Durable context components were omitted from Provider input

- **Severity:** Critical
- **Affected runtime path:** Session/working/summary/memory → Provider context.
- **Reproduction:** Runtime passed blank durable components to the renderer.
- **Expected / actual:** Required state under one bounded policy; history alone was supplied.
- **Root cause:** No shared composition entry point.
- **Violated invariant:** Context must actually use all required durable state.
- **Repair:** Added bounded deterministic composition and duplicate suppression.
- **Regression test:** Required-component and token-pressure tests.
- **Integration test:** Restarted live session reconstructs the same durable context.
- **Fault injection:** Oversized history and missing optional components.
- **Performance impact:** Context reconstruction p99 0.288 ms.
- **Evidence:** Benchmark and live canary evidence.
- **Status:** CLOSED.

## SPC-008 — Autonomous evidence used an external sink and leaked writers

- **Severity:** Critical
- **Affected runtime path:** Extension Provider/tool intent → result → evidence → cleanup.
- **Reproduction:** External JSONL audit and failure paths outside shared writer cleanup.
- **Expected / actual:** CAS bodies plus Journal events; an independent sink existed.
- **Root cause:** Extension runtime predated the authority architecture.
- **Violated invariant:** No second event/content authority.
- **Repair:** Journal/CAS evidence, intent-before-effect ordering, and one outer failure/finally boundary.
- **Regression test:** Extension evidence and cleanup tests.
- **Integration test:** Autonomous path participates in the same runtime authority.
- **Fault injection:** Hook/tool failure closes writer and marks the turn failed.
- **Performance impact:** Bounded additional evidence events; no retry amplification.
- **Evidence:** Extension tests and full regression evidence.
- **Status:** CLOSED.

## SPC-009 — Startup replayed the entire Journal

- **Severity:** High
- **Affected runtime path:** CLI startup → session/memory/runtime-state resume.
- **Reproduction:** Baseline startup scanned 84,920 events and took about 47 seconds.
- **Expected / actual:** Verified checkpoint+tail; Fast Start was inactive.
- **Root cause:** No complete Authority Checkpoint and runtime projection integration.
- **Violated invariant:** Fast Start must equal authoritative replay without ordinary full scans.
- **Repair:** Checkpoint sequence 3, signed projection, authenticated tail view.
- **Regression test:** Fast Start V1/V2, projection, and conversation integration tests.
- **Integration test:** Frontier 85,413, tail 0, zero ordinary full scan.
- **Fault injection:** Stale/corrupt checkpoint and projection fallbacks fail safely.
- **Performance impact:** Cold-start p99 486.8 ms at benchmark frontier.
- **Evidence:** Final checkpoint/projection and benchmark evidence.
- **Status:** CLOSED.

## SPC-010 — Eager imports caused circular bootstrap

- **Severity:** High
- **Affected runtime path:** Extension import → conversation → orchestrator bootstrap.
- **Reproduction:** Combined runtime imports failed before execution.
- **Expected / actual:** Stable package bootstrap; eager convenience exports re-entered imports.
- **Root cause:** Heavy bidirectional package initialization.
- **Violated invariant:** Real runtime must start through the Conversation Runtime.
- **Repair:** Lazy conversation exports and dependency-boundary cleanup.
- **Regression test:** Combined CLI, extension, FAST, and MULTI imports.
- **Integration test:** Default PTY and all live modes start successfully.
- **Fault injection:** Import-order regression matrix.
- **Performance impact:** Less bootstrap work and no runtime behavior change.
- **Evidence:** Full regression and live PTY evidence.
- **Status:** CLOSED.

## SPC-011 — Historical events broke clean projection rebuild

- **Severity:** Critical
- **Affected runtime path:** Old Journal → current projection → restore/replay.
- **Reproduction:** Valid historical FAST and zero-agent run-open shapes raised a raw key error.
- **Expected / actual:** Old valid events readable; projector assumed current fields.
- **Root cause:** Generic event-type handling lacked schema-aware normalization.
- **Violated invariant:** Projection is rebuildable from all admitted authoritative history.
- **Repair:** Deterministic compatibility mapping and explicit unknown-shape failure.
- **Regression test:** Current, FAST historical, zero-agent, and unknown-shape tests.
- **Integration test:** All 85,413 events rebuild successfully.
- **Fault injection:** Incomplete unknown shape fails closed.
- **Performance impact:** Constant-time normalization; rebuild 41.285 s in final benchmark.
- **Evidence:** Restore and benchmark evidence.
- **Status:** CLOSED.

## SPC-012 — Ordinary resume bypassed the runtime projection

- **Severity:** Critical
- **Affected runtime path:** CLI/session/memory/pending-run reads after restart.
- **Reproduction:** Signed projection classes existed, but ordinary resume still opened full history.
- **Expected / actual:** Projection base plus authenticated tail; runtime path bypassed it.
- **Root cause:** No Journal-compatible state view joining projection and tail.
- **Violated invariant:** Integrated runtime evidence, not unused classes, defines completion.
- **Repair:** Added runtime state tables, handlers, signed publication, reader/writer, and merged tail view.
- **Regression test:** Runtime-state, session, memory, checkpoint, and recovery suites.
- **Integration test:** Ordinary restart recovers five turns and accepted memory with full verifier patched to fail.
- **Fault injection:** Pending-run reconciliation and restored two-event memory tail.
- **Performance impact:** Runtime-state open p99 270.9 ms; zero ordinary full scan.
- **Evidence:** Runtime-state activation and restored-memory evidence.
- **Status:** CLOSED.

## SPC-013 — Persistent roots had unsafe modes

- **Severity:** High
- **Affected runtime path:** Journal/CAS/projection/state/backups/evidence confidentiality.
- **Reproduction:** Audit found group/other-readable files and traversable directories.
- **Expected / actual:** Directories 0700 and files 0600; hundreds violated policy.
- **Root cause:** Historical creation/copy paths inherited permissive defaults.
- **Violated invariant:** Sensitive persistent state must be owner-only.
- **Repair:** Goal-bound inode/scope capability and exhaustive metadata-only hardening.
- **Regression test:** Capability scope and projection-creation mode tests.
- **Integration test:** Millions of entries verified with zero unsafe modes.
- **Fault injection:** Unapproved scope/type/symlink fails closed.
- **Performance impact:** One-time metadata traversal; no content or authority mutation.
- **Evidence:** Permission-hardening evidence and unchanged frontier/CAS counts.
- **Status:** CLOSED.

## SPC-014 — One real Provider profile stores a direct credential

- **Severity:** Critical
- **Affected runtime path:** Provider profile loading and credential-at-rest security.
- **Reproduction:** Exact-value-safe profile inspection finds one direct credential; three profiles use references.
- **Expected / actual:** References are preferred; one direct credential remains
  in the active profile under an explicit user-approved exception.
- **Root cause:** The active profile predates Keychain-reference enforcement.
- **Violated invariant:** Direct profile storage requires either migration or a
  narrowly documented, explicitly accepted exception with compensating controls.
- **Repair:** Applied an exact one-profile acceptance policy without reading,
  changing, rotating, migrating, emitting, or copying the credential value.
- **Regression test:** Reference resolution, exact exception-shape validation,
  and cross-chunk/no-follow exact-match scanners pass.
- **Integration test:** Existing credential still powers bounded real canaries; no value was exposed.
- **Fault injection:** Missing/unavailable reference paths fail closed in credential tests.
- **Performance impact:** The final exact scans are closure-time only; runtime
  Provider performance is unchanged.
- **Evidence:** Final security audit, Provider canary, backup scan, permission
  audit, and Sentinel evidence; exact persistence/exposure hits outside the
  approved profile must be zero.
- **Status:** CLOSED_WITH_USER_ACCEPTED_EXCEPTION.

## SPC-015 — Filesystem permission repair broke in-memory SQLite

- **Severity:** High
- **Affected runtime path:** Projection tests/tools using `:memory:`.
- **Reproduction:** `open_projection(":memory:")` attempted to chmod a nonexistent filename.
- **Expected / actual:** Memory database opens without filesystem operations; chmod raised `FileNotFoundError`.
- **Root cause:** Owner-only creation logic did not distinguish SQLite's memory sentinel.
- **Violated invariant:** Permission hardening must preserve valid non-filesystem projection modes.
- **Repair:** Skip path/symlink/mkdir/chmod operations only for exact in-memory databases.
- **Regression test:** Explicit in-memory and owner-only file-backed projection tests.
- **Integration test:** Complete projection suite and 916-test discovery pass.
- **Fault injection:** File-backed symlink rejection remains enforced.
- **Performance impact:** None.
- **Evidence:** Final full-suite evidence.
- **Status:** CLOSED.

## SPC-016 — Final regression harness selected stale control state and system Python

- **Severity:** High
- **Affected runtime path:** Clean-room acceptance and nested CLI smoke tests.
- **Reproduction:** Initial discovery selected a historical Phase −1 snapshot and nested launchers found macOS Python without dependencies.
- **Expected / actual:** Current source runs under approved Python; historical acceptance is suite-bound.
- **Root cause:** Generic discovery lacked executable pinning and the historical class lacked its registry layer guard.
- **Violated invariant:** Acceptance must be reproducible and environment-bound without weakening tests.
- **Repair:** Pin nested PATH/Python, raw-fingerprint Production, deny network/storage, and scope Phase −1 to its manifest-bound registry layer.
- **Regression test:** Full discovery itself.
- **Integration test:** 916 tests pass in one disposable home.
- **Fault injection:** Three setup mistakes failed closed before tests; disposable cleanup is unconditional.
- **Performance impact:** Final run 91.748 s; no Provider sends or Production mutation.
- **Evidence:** `storage-production-full-suite.json` and redacted log.
- **Status:** CLOSED.

## SPC-017 — Journal rollover published a permissive sparse index

- **Severity:** High
- **Affected runtime path:** Journal rollover/checkpoint → sparse index publication.
- **Reproduction:** The final checkpoint index was 0644 while all protected files require 0600.
- **Expected / actual:** New index files must be owner-only; `Path.write_text` inherited the process umask.
- **Root cause:** The rollover path did not use an explicit create mode.
- **Violated invariant:** Every sensitive persistent file is owner-only at creation.
- **Repair:** Publish with no-follow/exclusive `os.open` at 0600, fsync the file and index directory, and create Journal directories at 0700.
- **Regression test:** Rollover now asserts the sparse-index mode is exactly 0600.
- **Integration test:** Existing Production index hardened; final 916-test discovery passes.
- **Fault injection:** Existing-target and rollover fault boundaries retain fail-closed writer poisoning.
- **Performance impact:** No additional I/O beyond the fsync already required.
- **Evidence:** `storage-production-final-journal-index-permission.json` and final full-suite evidence.
- **Status:** CLOSED.

## SPC-018 — Security audit treated its own safe enum metadata as unresolved

- **Severity:** High
- **Affected runtime path:** Security closure → evidence artifact pattern review.
- **Reproduction:** The deep audit flagged its own redacted `secret_source` enum fields as sensitive findings.
- **Expected / actual:** Controlled schema metadata must be distinguished from unresolved secret-bearing data; the raw pattern count treated every finding as unresolved.
- **Root cause:** Artifact pattern review had no narrow validation rule for the audit's own fixed-schema, non-secret enum field.
- **Violated invariant:** Security evidence must fail closed without converting verified non-secret metadata into a false internal blocker.
- **Repair:** Added an exact review limited to the two named audit files, exact evidence root, exact schema, `secret_values_included: false`, indexed `provider_profiles.profiles[N].secret_source` fields, and `sensitive_field` findings; every other finding remains unresolved.
- **Regression test:** `tests/test_evidence_hardening.py` proves the exact safe self-audit finding is reviewed and an unrelated field remains unresolved.
- **Integration test:** Final 916-test guarded discovery and final deep security audit.
- **Fault injection:** Wrong file, root, schema, secret flag, field path, or pattern type remains unresolved and fails the internal gate.
- **Performance impact:** Negligible bounded validation over the audit's own findings.
- **Evidence:** Final full-suite evidence and `storage-production-security-audit-final.json`.
- **Status:** CLOSED.

## SPC-019 — Post-audit evidence used a sensitive-looking metadata label

- **Severity:** High
- **Affected runtime path:** Security closure → post-audit evidence review.
- **Reproduction:** The generic sensitive-pattern scanner matched a non-secret
  authorization-category metadata label in a closure artifact.
- **Expected / actual:** Closure metadata must remain machine-readable without
  creating an unresolved sensitive-field finding; the label triggered the
  fail-closed review.
- **Root cause:** The artifact schema reused terminology covered by the generic
  sensitive-field detector.
- **Violated invariant:** Final evidence must have zero unresolved sensitive
  findings without weakening the generic scanner.
- **Repair:** Renamed the non-secret field to `change_category`; the scanner and
  its fail-closed rules remain unchanged.
- **Regression test:** The current artifact corpus passes the generic scanner
  with zero unresolved findings.
- **Integration test:** Final deep audit scans the external evidence tree and
  report bundle together.
- **Fault injection:** Reintroducing a sensitive-looking field outside the
  narrow reviewed audit schema remains unresolved and fails acceptance.
- **Performance impact:** None.
- **Evidence:** Final deep-security audit and post-audit current-artifact scan.
- **Status:** CLOSED.

## SPC-020 — Finalizer assumed the pre-canary session cardinality

- **Severity:** High
- **Affected runtime path:** Final Provider canary → checkpoint/projection
  finalization.
- **Reproduction:** The finalizer required exactly ten messages and five turns,
  so a valid sixth bounded canary turn would fail finalization.
- **Expected / actual:** State checks must validate durable invariants at the
  current frontier; the code hard-coded the earlier frontier's counts.
- **Root cause:** Closure assertions captured an evidence snapshot instead of
  expressing monotonic session invariants.
- **Violated invariant:** A valid append-only Provider turn must remain
  finalizable without weakening session consistency.
- **Repair:** Validate one session, zero pending turns, even message cardinality,
  matching successful-turn count, and stable memory-review counts dynamically.
- **Regression test:** Dynamic-count tests accept twelve messages/six turns and
  reject an odd message count.
- **Integration test:** Post-canary finalization rebuilds and publishes the
  signed projection at the exact new frontier.
- **Fault injection:** Odd messages, pending turns, wrong session count, or
  changed accepted/rejected memory counts fail closed.
- **Performance impact:** Negligible bounded state validation.
- **Evidence:** Final checkpoint/projection evidence and focused regression
  results.
- **Status:** CLOSED.

## SPC-021 — Deep audit did not directly scan every raw persistence surface

- **Severity:** Critical
- **Affected runtime path:** Credential security closure → Journal, CAS,
  projection, checkpoint, backup, evidence, log, report, and Sentinel audit.
- **Reproduction:** The earlier audit semantically scanned Journal/CAS and
  scanned general artifacts, but did not separately report exact raw scans for
  projections, checkpoints, and every manifest-bound backup payload.
- **Expected / actual:** Each prohibited surface must have explicit zero-hit
  evidence; several were covered only indirectly.
- **Root cause:** The original closure gate predated the approved exception's
  expanded surface-specific acceptance criteria.
- **Violated invariant:** An accepted direct-storage exception must be proven
  contained across every named persistence and exposure boundary.
- **Repair:** Added streaming cross-chunk exact scans, no-follow path handling,
  surface-separated results, immutable backup manifest/mode/size/hash/hardlink
  verification, CAS identity checks, and profile-copy rejection.
- **Regression test:** Exact scanning detects a cross-chunk literal and a nested
  `profiles` path, and refuses symlink traversal.
- **Integration test:** Final audit scans all current raw and semantic authority
  surfaces plus every retained backup before acceptance.
- **Fault injection:** Any hit, unsafe symlink/type, payload mismatch, copied
  profile, invalid manifest, or permission defect fails the security gate.
- **Performance impact:** Closure-time scan is I/O-intensive; runtime paths are
  unchanged and unique hardlinked payloads are deduplicated by inode.
- **Evidence:** Final security audit and backup verification sections.
- **Status:** CLOSED.

## SPC-022 — Post-canary CAS and backup entries inherited permissive modes

- **Severity:** High
- **Affected runtime path:** CAS commitment-bucket publication and immutable
  backup/restore file creation.
- **Reproduction:** The final audit found two new CAS commitment directories at
  `0755` and twelve copied non-secret backup config files at `0644`.
- **Expected / actual:** Every protected directory/file must be born at
  `0700`/`0600`; new paths inherited the process umask or source-file mode.
- **Root cause:** CAS bucket creation omitted an explicit owner-only mode, and
  backup/restore copy descriptors reused source or manifest modes.
- **Violated invariant:** Access-control correctness must hold at creation, not
  depend on a later closure hardening pass.
- **Repair:** Hardened the exact 14 existing entries with content/frontier
  preservation; CAS now creates/chmods layout and bucket directories at `0700`,
  and backup/restore payloads and restore markers are created at `0600`.
- **Regression test:** Local CAS asserts new object/commitment bucket and file
  modes; backup/restore asserts every manifest payload, restored config file,
  and restore marker is owner-only.
- **Integration test:** Permission evidence verifies 1,936,143 files and 3,350
  directories in the affected CAS/backup roots with zero unsafe entries.
- **Fault injection:** Any broader or reverse mode delta still fails the backup
  verifier; symlinks, special files, content drift, inventory drift, and
  authority-frontier mutation remain fail-closed.
- **Performance impact:** Two bounded mode syscalls per new CAS directory and
  owner-only creation flags for copied files; no Provider or hot replay impact.
- **Evidence:** Final permission-repair evidence, targeted regressions, full
  suite, and final deep security audit.
- **Status:** CLOSED.

## SPC-023 — External-only permission hardening requested a Production capability

- **Severity:** Medium
- **Affected runtime path:** Isolated restore-drill access-control closure.
- **Reproduction:** Applying owner-only modes to the external restore root
  produced an empty Production-root set and the capability guard failed closed.
- **Expected / actual:** External-only paths require no Production mutation
  capability; the tool requested one with an empty scope.
- **Root cause:** The permission driver unconditionally entered the Production
  authorization context for both Production and external roots.
- **Violated invariant:** Capabilities must be least-authority and must describe
  the exact mutation boundary.
- **Repair:** External-only operations now use a no-op authorization context;
  any non-empty Production root set still requires the frozen-prefix,
  manifest-hash, Goal-id, and root-bound capability.
- **Regression test:** An external-only empty Production-root tuple enters and
  exits without requesting a Production capability.
- **Integration test:** External restore hardening changed exactly 16 modes and
  verified 2,258,043 files and 3,855 directories with zero unsafe entries and
  an unchanged Production frontier.
- **Fault injection:** Production roots continue through the original strict
  capability tests; invalid/duplicate/out-of-scope roots and content or
  inventory drift remain fail-closed.
- **Performance impact:** None beyond the requested external metadata traversal.
- **Evidence:** Final restore-permission evidence, focused regression, and full
  guarded suite.
- **Status:** CLOSED.

## SPC-024 — Source manifest included self-changing Sentinel evidence

- **Severity:** High
- **Affected runtime path:** Final source identity → Sentinel/diff → aggregate
  evidence binding.
- **Reproduction:** The source manifest contained five generated
  `sentinel-*.json` files; writing the final after/diff reports made the source
  identity stale after it had been bound into acceptance evidence.
- **Expected / actual:** Source identity must cover source/docs/tests/config but
  exclude derived closure evidence; generated Sentinel files were included.
- **Root cause:** The source-manifest exclusion policy separated artifact roots
  but did not recognize generated evidence stored inside the documentation tree.
- **Violated invariant:** Evidence derivation must be acyclic and every bound
  source hash must describe the final source state.
- **Repair:** Excluded only
  `docs/storage-production-closure/sentinel-*.json` from source identity while
  retaining Markdown closure documents, and changed manifest publication to an
  owner-only `0600` no-replace temporary file.
- **Regression test:** The exclusion helper rejects a generated after-Sentinel
  and retains `FINAL_REPORT.md` in source scope.
- **Integration test:** The regenerated final manifest contains zero Sentinel
  evidence entries, remains stable across Sentinel refresh/diff, and is rebound
  into the Production manifest and aggregate.
- **Fault injection:** Other documentation, source, test, schema, and non-secret
  config files remain included; symlinks/non-regular entries and concurrent
  source changes remain fail-closed.
- **Performance impact:** Removes large derived JSON from repeated source hash
  capture and has no runtime impact.
- **Evidence:** Final source manifest, final Sentinel/diff, post-closure scan,
  and aggregate hash audit.
- **Status:** CLOSED.
