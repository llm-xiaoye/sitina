# Sitina B+ Phase 7 Backend Scale-out Implementation Plan

> **For Codex execution:** Optional Phase；requires `CUTOVER_VERIFIED`, a separate backend-migration Execution Manifest, complete backup/restore evidence and no unresolved earlier-phase acceptance gap.

**Goal:** 在 B+ Authority Cutover 稳定后，可选地将 Physical Backend 扩展到 PostgreSQL、多 Worker、Remote CAS 和 Multi-journal O/P/T V2，同时保持既有 Stream、Version、Idempotency、Fence、Frontier、Effect、Evidence 和 Archive 语义不变。

**Architecture:** Backend 通过统一 Append/CAS/Projection 接口替换。PostgreSQL 初始使用 `SERIAL_APPEND_COORDINATOR + POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`：同一事务内锁定并更新计数器，回滚同时回滚 Position 分配，因此已提交前缀无洞。Notification 只唤醒。Remote CAS 必须原子 Conditional Create 并 Direct Verify。Multi-journal 使用 Signed Frontier Vector 和 Coherent-cut Proof。Production backend 切换必须执行独立 `Backend Authority Handoff`，不能由配置翻转或双写完成。

**Tech Stack:** PostgreSQL、Python DB Adapter、LISTEN/NOTIFY 或消息总线、Remote Object Store SDK、existing Journal/CAS interfaces、containerized integration tests、fault-injection tests。

## Global Constraints

- This phase is optional and starts only after CUTOVER_VERIFIED.
- No backend migration without complete backup and restore drill.
- PostgreSQL Sequence alone is never Commit Order.
- Queue/Notification is never Authority.
- Remote ETag/LIST/Range sample is never sufficient integrity proof.
- Multi-journal V2 must not weaken V1 terminal/evidence semantics.
- Initial PostgreSQL Position Profile is `POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`；it uses one transactional counter row under the serial append coordinator and must expose a gap-free committed prefix.
- SQL Sequence、out-of-transaction reservation and gapped allocation are forbidden in the initial profile. Any future reservation/gapped profile is a new protocol requiring its own omission proof、migration and approval；it is not an implementation shortcut.
- Backend generation/config/phase flags never select a writer；only a verified Backend Authority Handoff outcome does.
- Backend replacement must preserve all existing user-visible Legacy-compatible and B+ semantics；physical provenance changes are representation changes unless explicitly approved otherwise.

---

### Task 1: Backend conformance test suite

**Files:**
- Create: `tests/backend_conformance.py`
- Create: `tests/test_local_backend_conformance.py`

**Interfaces:**
- Defines one test contract for append, query, stream version, idempotency, Lost ACK, Frontier and recovery.

- [ ] Run against Local Journal/CAS first.
- [ ] Include same Command/different Hash、gap-free transactional position profile、atomic single-stream multi-event append、cold lookup and committed-prefix visibility.
- [ ] Commit.

---

### Task 2: PostgreSQL schema and append coordinator

**Files:**
- Create: `core/sitina/journal/postgres.py`
- Create: `data/migrations/bplus/001_postgres_journal.sql`
- Test: `tests/test_postgres_journal.py`

**Interfaces:**
- Implements existing `append/query/iter_events/head` interface with a gap-free committed prefix.

- [ ] Define events、stream_heads、command_bindings/outcomes、a singleton `journal_position_counter` row and append/profile metadata；do not create SQL Sequence or allocation-ledger tables in the initial profile.
- [ ] Implement transaction-scoped global advisory/row coordinator lock acquired before reading/updating the counter.
- [ ] Revalidate Stream Head and idempotency after lock acquisition.
- [ ] In the same transaction, allocate the exact contiguous range by updating the counter row, insert Events/Stream Head/Command Outcome, then hold the coordinator through COMMIT/ROLLBACK.
- [ ] Prove rollback restores the counter and consumes no Position；the next successful append reuses the uncommitted candidate range without identity conflict because no Event became visible.
- [ ] Publish `head` only from committed counter/Event state in the same database snapshot；every position `1..head` must exist exactly once.
- [ ] Kill transactions before counter update、after update、during inserts and at commit response loss；after recovery assert there is no committed-prefix gap and retry returns the original outcome or safely performs the absent command.
- [ ] Static-schema test rejects SQL Sequence、out-of-transaction allocator and `RESERVED/ABORTED` gap semantics for this profile.
- [ ] Commit.

---

### Task 3: PostgreSQL projection offsets and wakeup

**Files:**
- Create: `core/sitina/projections/postgres.py`
- Test: `tests/test_postgres_projections.py`

- [ ] Implement atomic semantic rows + offsets.
- [ ] Use LISTEN/NOTIFY only as wakeup; poll canonical positions after timeout/reconnect.
- [ ] Test lost notification and consumer restart.
- [ ] Commit.

---

### Task 4: Multi-worker authoritative claims

**Files:**
- Create: `core/sitina/runtime/workers.py`
- Test: `tests/test_multi_worker_claims.py`

- [ ] Separate API/Projector/Scheduler/Dispatcher/Gateway/Verifier/Sealer/Archiver worker roles.
- [ ] Test only Stream Claim/Fence decides winner.
- [ ] Test worker-local leases/queues cannot override authority.
- [ ] Test stale worker results remain observations but cannot commit business transition.
- [ ] Commit.

---

### Task 5: Remote Object Store capability contract

**Files:**
- Create: `core/sitina/cas/remote.py`
- Test: `tests/test_remote_cas_contract.py`

**Interfaces:**
- Produces `RemoteStoreCapabilities` and immutable publish/open/delete version contract.

- [ ] Test backend without atomic conditional create is rejected as canonical authority unless transactional indirection configured.
- [ ] Test conflict exact-match idempotency and mismatch incident.
- [ ] Test Direct Read verifies complete ciphertext digest/header/auth; ETag/LIST/range sample insufficient.
- [ ] Test exact version recorded and GC delete conditional on version+fence.
- [ ] Commit.

---

### Task 6: Canonical hot/cold Journal and CAS residency

**Files:**
- Create: `core/sitina/archive/residency.py`
- Test: `tests/test_canonical_residency.py`

- [ ] Test exact Segment bytes/identity/epoch/chain migrate and reader resolves same Journal identity.
- [ ] Test converted export cannot replace Segment.
- [ ] Test Bundle copy only becomes canonical CAS residency after explicit registration/verification.
- [ ] Commit.

---

### Task 7: Multi-journal Frontier Vector

**Files:**
- Create: `core/sitina/journal/frontier.py`
- Modify: `core/sitina/projections/consistency.py`
- Test: `tests/test_frontier_vectors.py`

**Interfaces:**
- Produces signed component map `(journal, epoch, shard) -> position, commitment`.

- [ ] Test positions from different journals are never numerically compared.
- [ ] Test Projection batch advances rows and all represented components atomically only when one backend transaction can cover them；otherwise use independent Projectors plus a Coherent-cut composition proof as required by the specification.
- [ ] Test required causal dependencies reachable in resulting vector.
- [ ] Commit.

---

### Task 8: O/P/T V2 coherent-cut proof

**Files:**
- Create: `core/sitina/evidence/coherent_cut_v2.py`
- Test: `tests/test_opt_v2.py`

- [ ] Include Business, Observation, Effect and Operational-control components.
- [ ] Prove every Observation≤O has Apply/Disposition≤P.
- [ ] Prove no required cross-journal reference points beyond cut unresolved.
- [ ] Include Cross-run Dependency Closure.
- [ ] Test late observations become Supplement.
- [ ] Commit.

---

### Task 9: Backend Authority Handoff tooling and rehearsal

**Files:**
- Create: `core/sitina/journal/backend_migration.py`
- Create: `core/sitina/journal/backend_handoff.py`
- Test: `tests/test_backend_migration.py`
- Test: `tests/test_backend_authority_handoff.py`

**Interfaces:**
- Produces a stable handoff command/proof and the only legal authority states: `SOURCE_AUTHORIZED`、`HANDOFF_PREPARED_NO_NEW_ADMISSIONS`、`SOURCE_RELEASED_NO_WRITER`、`HANDOFF_OUTCOME_UNKNOWN_NO_WRITER`、`TARGET_AUTHORIZED`、`RECOVERY_REQUIRED_NO_WRITER`.

- [ ] Freeze source Journal Frontier and Backup Hold while source remains the only business writer during preparation.
- [ ] Import exact Events to a target that is read-only for business commands, preserving Event IDs/Stream Versions/Hashes and recording new physical provenance.
- [ ] Compare canonical reads/checksums and run the full conformance suite before handoff.
- [ ] Freeze new admissions、drain appenders and bind source final frontier、target imported frontier、backend identities、profile hashes、backup and operator approval into one stable Handoff ID/Hash.
- [ ] Append `BackendAuthorityReleased` as the final authoritative source Event, then permanently fence the source writer before any target business append.
- [ ] Grant the target only a narrowly scoped control capability to verify the release proof and append `BackendAuthorityAccepted`; it cannot append business Events before acceptance commits.
- [ ] Only a verified committed Acceptance authorizes target business writes. Timeout、crash、lost ACK、unreadable proof or conflicting identity yields a no-writer state and recovery/query of the same Handoff ID/Hash.
- [ ] Test there is never a state in which source and target business writers are both authorized；backend generation/config/phase toggles cannot override the handoff outcome.
- [ ] Reader fallback may use the old backend at its released frontier but cannot reactivate its writer.
- [ ] Commit tooling; Production handoff execution requires a separately approved migration window and introduces no feature-code edits.

---

### Task 10: Capacity qualification for scale-out

**Files:**
- Create: `benchmarks/postgres_journal_benchmark.py`
- Create: `benchmarks/remote_cas_benchmark.py`
- Create: `docs/capacity-profiles/README.md`

- [ ] Run payload/transaction/concurrency/data-size/recovery/disk/soak matrix.
- [ ] Record hardware, storage, PostgreSQL, network, key/encryption and maintenance profile.
- [ ] Publish profile only after correctness tests; otherwise NOT_YET_QUALIFIED.
- [ ] Commit reports.

---

### Task 11: Phase 7 acceptance

- [ ] Run full local and PostgreSQL backend conformance.
- [ ] Kill coordinator transactions at allocation/insert/commit boundaries.
- [ ] Assert every committed PostgreSQL head has exactly positions `1..head`, including after rollback and lost commit ACK.
- [ ] Lose notifications and worker processes.
- [ ] Test Remote CAS consistency faults and overwrite attempts.
- [ ] Build O/P/T V2 package and replay from cold copies.
- [ ] Verify no authority semantics changed.
- [ ] Rehearse Backend Authority Handoff with faults at prepare、source release、source fence、target accept and acceptance ACK；prove dual-writer count is always zero or one and unknown always means zero.
- [ ] Compare user-visible behavior and audit/evidence semantics against the last accepted Local Backend Baseline；classify every difference.
- [ ] Commit and stop.

Phase 7 does not authorize a Production backend migration without a separately approved migration window.
