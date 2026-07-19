# Sitina B+ Phase 6B Authorized Production Cutover Plan

> **For Codex execution:** This is a separate high-risk operational run, not a continuation of the Phase 6A test process. It requires a current PASSED `CutoverToolingReady` report plus an independently approved、time-bounded Phase 6B Maintenance Manifest naming the Production roots、Legacy Snapshot intent、Production Genesis、stable Cutover Command ID/Hash、operator quorum and maintenance window. The plan text alone grants no authority.

**Goal:** 在获权维护窗口中，把 Production Write Authority 从 Legacy 存储一次性切换到 B+ Journal，永久保留 Legacy 为只读材料，并以 committed `CutoverVerified` 事实完成稳定化验收。

**Architecture:** Phase 6B executes already verified tools and introduces no feature code. Authority is not inferred from the current task or phase. Before outcome proof, Legacy may be authorized only by verified control facts；while prepared or outcome-unknown there is no writer；only a verified committed Cutover Outcome authorizes Journal. After that outcome, Legacy can never regain write authority.

**Tech Stack:** Hash-pinned Phase 6A binaries/configs、Kernel Writer Fence、Authority Resolver、Production Migration Control Stream、maintenance operator CLI、Canonical Backup/Restore tooling、mock-only Effect Gateway.

## Global Constraints

- **Do not begin without explicit user/operator approval of the exact Maintenance Manifest and window.**
- No code、config、profile or schema edits are allowed during the window. Any required edit aborts the operation before Cutover submission.
- Back up all in-scope material；establish Canonical Backup Hold and a coherent frozen Legacy snapshot before migration/cutover.
- Never delete Legacy material or enable Hot Eviction.
- Never use dual writes. A no-writer interval is intentional and safer than uncertain simultaneous authority.
- Cutover outcome uncertainty permits only locked recovery/query of the same Command ID/Hash.
- After a committed Cutover Outcome, rollback is limited to Reader Generation、Journal-compatible binary、forward fix or a new Recovery Epoch；Legacy writer cannot resume.
- External capability remains `MOCK_ONLY` unless a separate later activation authorization exists.

---

### Gate 0: Admit the maintenance operation

**Inputs:**
- PASSED Phase -1 through Phase 5 reports.
- Current signed Phase 6A `CutoverToolingReady` report.
- Independently approved Phase 6B Maintenance Manifest.

- [ ] Verify report/manifests signatures、hashes、expiry、operator quorum and exact code/config/profile identities.
- [ ] Verify named paths resolve to the intended Production installation and are not Phase 6A fixtures.
- [ ] Verify stable Cutover Command ID/Request Hash and intended Production Genesis are frozen before mutations.
- [ ] Verify stop/abort criteria、communication channel、recovery owners and maximum no-writer window.
- [ ] If any input differs, stop before admission and issue no operational capability.

---

### Step 1: Drain and freeze Legacy authority

- [ ] Stop new Run/Command admissions and new outbound Effect transmissions.
- [ ] Drain runs or formally cancel/fail them；cancellation does not erase possible external exposure.
- [ ] Settle all Effect Attempts/Exposure or transfer Monitoring Obligations to durable successor owners.
- [ ] Acquire the global Legacy writer fence and prove every registered low-level sink/process is fenced.
- [ ] Resolve authority as `CUTOVER_PREPARED_NO_WRITER` before snapshot/import starts.
- [ ] Assert neither Legacy nor Journal business dispatch can pass while prepared.

---

### Step 2: Create the frozen source and recovery point

- [ ] Produce one independent consolidated `FROZEN_COHERENT_SNAPSHOT`; use SQLite `immutable=1` only on that non-WAL-changing snapshot, never on the live WAL database.
- [ ] Record source closure、hashes、file metadata、WAL/checkpoint disposition and Inventory version.
- [ ] Create Canonical Backup at a fixed frontier with Backup/GC Hold.
- [ ] Restore and verify the backup in an isolated destination before proceeding.
- [ ] A failed/unverifiable snapshot or restore aborts before Cutover submission；verified controls may then explicitly restore Legacy authorization.

---

### Step 3: Establish Production Genesis and migration control

- [ ] Create/verify the separately named Production root、Journal ID、Epoch、key namespace and permission profile.
- [ ] Confirm Production Genesis bytes match the Maintenance Manifest and have never been used by Shadow/Fixture roots.
- [ ] Run deterministic conversion in `MigrationWorkspaceRoot`.
- [ ] Independently verify workspace outputs, then append provenance/control facts to `ProductionMigrationControlStream`.
- [ ] Verify signed completion report、source closure、counts、unresolved `legacy_incomplete` classes and Migration Frontier.
- [ ] Keep all imported/migration facts typed as provenance/control；none grants business writer authority.

---

### Step 4: Pre-submit validation

- [ ] Run final fixed-frontier dual-read comparison against the Frozen Legacy Snapshot.
- [ ] Run Journal+CAS-only projection rebuild from the prepared Production root.
- [ ] Reverify writer-fence coverage、disk/emergency reserve、key health、Effect drain and Monitoring Transfer.
- [ ] Recompute `AuthorityResolution`; it must remain `CUTOVER_PREPARED_NO_WRITER`.
- [ ] Verify the exact stable Cutover Command body binds Legacy Snapshot、Production Genesis、pre-cutover/migration frontiers、code/config/policy/key/profile hashes、Effect drain、Monitoring Transfer and operator authorization.
- [ ] Any drift aborts before submission and requires a new separately approved Maintenance Manifest；never silently regenerate the command.

---

### Step 5: Submit the one Authority Cutover Command

- [ ] Submit the pre-frozen stable Command ID/Request Hash exactly once to the Production Authority Control Stream.
- [ ] Do not issue any second logical command for this Snapshot/Genesis.
- [ ] On a positive response, independently verify the committed Cutover Outcome bytes、transaction/position、hash chain、auth tag and exact command binding.
- [ ] On timeout、crash or ACK loss, resolve `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER` and query/recover only the same Command ID/Hash.
- [ ] While unknown, prohibit Legacy resume、Journal business dispatch、new migration facts and a replacement Cutover command.
- [ ] If authoritative absence is proven under the frozen contract, return only through the approved pre-commit abort path；if continuity cannot be proven, select `RECOVERY_REQUIRED_NO_WRITER`.
- [ ] Only a verified committed outcome may produce `JOURNAL_WRITER_AUTHORIZED`.

---

### Step 6: Activate Journal-first routing, never dual write

- [ ] Supply the fresh `JOURNAL_WRITER_AUTHORIZED` resolution to the routing boundary.
- [ ] Enable Journal-first command routing and the new Reader Generation atomically with respect to business admission.
- [ ] Verify every Legacy writer method fails closed and direct sink instrumentation records no write.
- [ ] Verify compatibility JSON/SQLite outputs are Projectors only.
- [ ] Run smoke commands with mock provider only；every stable Command Outcome must survive lost ACK and restart.
- [ ] Keep Legacy readers fixed at `as_of_cutover_frontier` and prohibit their data from authorizing new decisions.

---

### Step 7: Stabilize and commit Cutover Verification

- [ ] Observe command outcomes、projection lag、disk/emergency reserve、auth/key health、Effect custody/admission queues and writer-fence alerts for the manifest-defined interval.
- [ ] Run a Production Journal+CAS-only rebuild from the cutover frontier in a disposable location.
- [ ] Run fixed-frontier comparison against the Frozen Legacy Snapshot.
- [ ] Run zero-external replay at the actually qualified isolation capability and produce Evidence V1 package.
- [ ] Build the stable `CutoverVerified` Command using the frozen verification contract and bind every predicate/report hash.
- [ ] Submit it once；on ACK loss recover only the same ID/Hash.
- [ ] Phase 6B may exit only after the canonical Journal contains and independently verifies the committed `CutoverVerified` Event/Outcome.
- [ ] Retain Legacy under read-only retention/legal hold.

---

### Step 8: Final authority and exit audit

**Required exit evidence:**
- Verified committed Authority Cutover Command/Outcome.
- Verified committed `CutoverVerified` Command/Event/Outcome.
- Fresh `JOURNAL_WRITER_AUTHORIZED` resolution derived from those facts.
- Legacy global fence coverage report and post-cutover zero-write proof.
- Production Genesis、Migration Control、backup/restore、dual-read and rebuild reports.
- Effect capability ceiling still `MOCK_ONLY`, unless a separately scoped later operation proves otherwise.

- [ ] Independently re-read the Authority Control Stream and resolve authority without using in-memory phase state.
- [ ] Assert no transition can reactivate Legacy writer.
- [ ] Assert no Legacy deletion、GC deletion、Hot Eviction or live external mutation occurred.
- [ ] Record exact changed-file/material manifest and close the maintenance window.

Phase 6B authorizes only the exact cutover operation described by its approved Maintenance Manifest. It does not authorize later external-capability activation、Legacy deletion or Hot Eviction.
