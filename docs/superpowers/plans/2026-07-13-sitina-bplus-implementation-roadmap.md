# Sitina B+ Implementation Roadmap

> **For Codex execution:** 本文件是路线图，不是全量执行授权。第一次进入 Phase -1 时，只能由 `PHASE_MINUS_1_BOOTSTRAP_V0` 授权 Foundation Tasks 1–3；稳定哈希产生并经人工批准后，所有后续会话必须验证 `EXECUTION_MANIFEST_V1`，只执行其中授权的 Phase/Task Range，并在 `required_stop_point` 停止。

**Goal:** 将当前 JSONL、SQLite 和 Mutable JSON 并存的 Sitina 运行时，分阶段迁移为 Canonical Journal + Encrypted CAS + Rebuildable Projections + Event-sourced Collaboration + Effect/Observation + Evidence/Archive 架构，同时始终保持单一 Authority Writer、可回滚 Reader 和零外部副作用 Replay。

**Architecture:** 采用 Phase -1、Phase 0–5、分离的 Phase 6A/6B 和可选 Phase 7，而不是 Big Bang：先建立安全、可复现且不触碰 Production 的执行基础，再盘点 Legacy Authority，实现 Journal/CAS/Projection Kernel，然后逐层迁移 Run/Task、协作协议、外部副作用、Evidence/Archive；Phase 6A 只证明切换工具，Phase 6B 才在另一次获权维护窗口执行 Authority Cutover。每个实现 Phase 都形成可独立运行、可 Crash-injection、可 Delete/Rebuild 的新路径；Feature Flag 只能选择非权威功能/Reader，绝不能选择 Writer Authority。

**Tech Stack:** 固定 Python 3.12 Profile、Pydantic v2、锁定的 AEAD/Signature Library、SQLite WAL、macOS APFS/kernel file locking、Canonical JSON、分层 `unittest` Runner、现有 Sitina CLI/Orchestrator；后期按 Phase 独立批准 zstandard、PostgreSQL Driver、远端 Object Store 和 macOS Keychain/KMS Adapter。

## Global Constraints

- **本计划只定义实施前方案；除严格受限的 `PHASE_MINUS_1_BOOTSTRAP_V0` 外，没有当前会话绑定的 `EXECUTION_MANIFEST_V1` 时，不得执行代码修改、迁移、部署、数据删除、数据库重建或 Authority Cutover。**
- 目标规范：`docs/superpowers/specs/2026-07-13-sitina-bplus-data-architecture-design.md`。
- 当前项目不是 Git 仓库；执行前必须由用户决定是否初始化 Git 或采用等价变更审计。计划中的 Commit 步骤只有在 Git 初始化后执行。
- 修改任何现有文件前必须有 Source-only Baseline；Production 数据/状态备份必须位于受控、加密或权限隔离位置，不得把 Secret 或 Runtime State 复制进源码仓库。
- Phase -1 未通过前，任何测试不得运行在 `~/SitinaHub` Production Home。
- Shadow、Fixture、Replay、`MigrationWorkspaceRoot` 和 Production Journal 使用不同 Physical Root、Journal Identity 和 Key Namespace；Shadow/Workspace 不得提升为 Production。获验的迁移 provenance/control 只写 `ProductionMigrationControlStream`。
- Legacy 与 B+ 并存时 Authority Writer 数量只能为零或一；Cutover prepared/unknown/recovery 状态必须为零。
- Writer Authority 只由获验的 Authority Control facts/Cutover Outcome 解析；Phase enum、CLI flag、Feature Flag、Readiness Report 或文件存在性都不能选择 Writer。
- Shadow Journal 永远 Non-authoritative，不得驱动真实 Provider、Tool、Approval、Timer、Terminal 或 Evidence Seal。
- 第一个 Journal-first 权威事实产生后，Legacy Writer 永久只读；Rollback 不得重新开启旧 Writer。
- Replay 必须禁用 Network、Provider、MCP、Git Push、Publication 和外部文件写入；普通 child process/monkeypatch 只能声称 `APPLICATION_GUARDED_ZERO_EFFECT`，只有获资格的 `ReplayIsolationProvider` 才能声称 `ENFORCED_SANDBOX_ZERO_EFFECT`。
- SQLite Cache Miss 不等于权威不存在。
- `BPLUS_OPT_V1_SINGLE_JOURNAL` 使用 exactly-one-component `SignedFrontierVectorV1`；Multi-journal V2 只扩展 component map。
- 单机初始 Position Profile 为 `LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1`。
- PostgreSQL 初始 Commit-order Protocol 为 `SERIAL_APPEND_COORDINATOR + POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`；同一事务更新计数器，回滚不消耗 Position，禁止 SQL Sequence/初始 gapped allocation。
- Automatic Hot Eviction 和 Delete 默认关闭；即使所有读取性检查通过，也必须另建独立 `retention-operation/<operation_id>`，经过 proposal/assessment/approval/fence/execution/reconciliation/verification 生命周期和单独授权。
- Capacity Profile 初始为 `NOT_YET_QUALIFIED`；吞吐、延迟、RTO 和增长数值必须经版本化 Benchmark Profile 验证后才能成为 Supported SLO。

## Plan Suite

| Phase | Plan | Authority at phase start | Exit gate |
|---|---|---|---|
| -1 | `2026-07-13-sitina-bplus-phase-minus-1-execution-foundation.md` | Legacy；Production 只读观察 | 固定环境、隔离 Test Home、变更审计、兼容性基线、计划完整性；无 Runtime 语义变化 |
| 0 | `2026-07-13-sitina-bplus-phase-0-legacy-compatibility.md` | Legacy SQLite/JSONL/JSON | Observational inventory、coherent-snapshot tooling、read-only adapter、shadow/diff harness；真实 Freeze 另行授权，无 Authority 变化 |
| 1 | `2026-07-13-sitina-bplus-phase-1-journal-cas-kernel.md` | Legacy | Journal/CAS/Projection Kernel 通过 Lost ACK、Crash、Delete/Rebuild；仍 Shadow |
| 2 | `2026-07-13-sitina-bplus-phase-2-run-task-scheduling.md` | Legacy | Run/Task/Process/Scheduling 在 Shadow/Controlled Profile 闭环运行 |
| 3 | `2026-07-13-sitina-bplus-phase-3-collaboration-protocols.md` | Legacy | Proposal/Handoff/Arbitration/Blackboard 通过状态矩阵与重放 |
| 4 | `2026-07-13-sitina-bplus-phase-4-effects-observations.md` | Legacy | Effect/Observation/Reconciliation 安全闭环；未知结果不盲重试 |
| 5 | `2026-07-13-sitina-bplus-phase-5-evidence-archive.md` | Legacy | O/P/T V1、Package/Seal/Archive/Restore Drill 通过 |
| 6A | `2026-07-13-sitina-bplus-phase-6a-cutover-tooling-readiness.md` | 由 Authority Resolver 证明的 Legacy Writer；测试根无 Production Authority | 隔离工具、lost-ACK、rebuild、dry-run 通过并签发 `CutoverToolingReady`；无 Production 变化 |
| 6B | `2026-07-13-sitina-bplus-phase-6b-authorized-production-cutover.md` | 获验 Legacy Writer，随后有意进入 no-writer window | 独立获权维护窗口完成 Cutover，且 Canonical Journal 已提交 `CutoverVerified`；Legacy 永久只读 |
| 7 | `2026-07-13-sitina-bplus-phase-7-backend-scaleout.md` | B+ Journal | PostgreSQL/Multi-worker/Remote CAS/O-P-T V2 可选扩展通过一致性测试 |

## Dependency Graph

```text
Phase -1 Execution Foundation
  → Phase 0 Legacy Fence/Inventory
    → Phase 1 Journal/CAS/Projection Kernel
      → Phase 2 Run/Task/Process/Scheduling
        → Phase 3 Collaboration Protocols
          → Phase 4 Effect/Observation
            → Phase 5 Evidence/Archive
              → Phase 6A Cutover Tooling/Readiness (isolated only)
                → Phase 6B Authorized Production Cutover (separate operation)
                  → Phase 7 Scale-out
```

任何 Phase 未通过 Exit Gate，后续 Phase 不得变更 Authority。Phase 1–5 可以在 Shadow 或 Controlled Fixture Namespace 中累积实现，但不得写入真实 Legacy 业务状态或执行真实外部副作用。

## Existing-function compatibility and optimization map

| Existing mechanism | Preserve before Cutover | B+ optimization | Acceptance evidence |
|---|---|---|---|
| CLI `init/doctor/run/ask/resume/cancel/list/show/trace/replay/report` | Legacy routing and exit semantics remain default | Phase 0 adds fence/read-only boundaries；Phase 6A proves routes，Phase 6B switches only from verified Cutover Outcome | Phase -1 CLI baseline + fixed-frontier dual-read report |
| SQLite + daily/per-run Event JSONL + Audit JSONL | Remain Legacy Authority and retained read-only evidence | Phase 1 Canonical Journal removes partial multi-representation authority；Projection replaces mutable query authority | Source inventory、Lost ACK、Delete/Rebuild、Legacy retention proof |
| Run State、Task Graph、Timeout、Claim/Lease | Existing workflow behavior remains available | Phase 2 independent Streams、Permit Saga、CAS/Fence、durable Timer/Process/Scheduler Decisions | Legacy semantic baseline + crash/replay matrix |
| Proposal、Review、Handoff、Arbitration、Blackboard | Existing user-visible collaboration/report behavior remains available | Phase 3 typed state machines、Obligations、Generation、MVCC/Merge、CAS content | Protocol transition matrix + compatibility classification |
| Provider、MCP、Tool、Approval、Risk、Side-effect accounting | Default remains Legacy until Authority Cutover；Mock remains zero-live-effect | Phase 4 immutable Effect/Attempt、Observation、Unknown/Reconciliation、Secret boundary、Budget/Breaker | Level A/B/C mock tests + side-effect audit + zero-live-effect gate |
| Checkpoint、Run Manifest、Replay Snapshot、Evidence Export | Preserved as Legacy compatibility artifacts | Phase 5 O/P/T、Package/Assessment/Seal、Supplement、isolated Replay、Archive Copy | Compatibility label + package/replay/archive acceptance |
| Maintenance、Backup、Restore、Rollback | Existing guarded operations remain available before Cutover | Phase 5 canonical backup/restore；Phase 6A verifies tooling，Phase 6B permits reader-only rollback and Recovery Epoch | Restore drill + rollback decision matrix |
| Mock and Live Provider modes | Mock behavior preserved；Live remains explicit opt-in | After Cutover, activation is staged `MOCK_ONLY → READ → REVERSIBLE → HIGH_RISK` | Per-level approval and capability activation report |

No row may be removed from the implementation scope merely because the new internal representation differs. An intentional semantic change requires an approved change record with old behavior、new behavior、migration impact and rollback/forward-fix policy。

## Cross-phase File Structure

### New package layout

```text
core/sitina/
  runtime/
    execution_contract.py # authorized phase/task/mutation/test-home contract
    capacity.py           # safety and qualified capacity profiles
  journal/
    model.py              # Command/Event/AppendReceipt/Frontier types
    codec.py              # Canonical serialization and frame parser
    local.py              # single-writer local journal
    recovery.py           # prefix scan, rollover recovery, integrity errors
    locks.py              # fixed-inode writer/maintenance locks
    postgres.py           # Phase 7 backend
  cas/
    model.py              # object identity/envelope/reference types
    local.py              # no-replace local publication
    crypto.py             # DEK/KEK/commitment interfaces
    gc.py                 # reference admission/GC fence
    remote.py             # Phase 7 object-store adapter
  projections/
    schema.py             # projection schema definitions
    runner.py             # atomic apply+offset/frontier
    consistency.py        # STRONG/EVENTUAL/STALE reads
    rebuild.py            # shadow/read generation rebuild
  commands/
    model.py              # CommandEnvelope and CommandResult
    gateway.py            # validation/idempotency/append orchestration
    outcomes.py           # canonical outcome lookup and client contract
  legacy/
    readonly.py           # immutable SQLite/JSONL/file adapters
    inventory.py          # source snapshot and provenance
    classify.py           # legacy fact classification
    shadow.py             # shadow import/compare harness
    cutover.py            # cutover commands/outcomes; never maps phase to writer
  authority/
    resolver.py           # verified control facts -> writer/no-writer resolution
  protocols/
    runtime.py            # reusable state-machine kernel
    obligations.py
    tasks.py
    proposals.py
    handoffs.py
    arbitration.py
    blackboard.py
  scheduling/
    decisions.py
    scheduler.py
    dispatcher.py
    timers.py
    processes.py
  effects/
    model.py
    gateway.py
    observations.py
    reconcile.py
    adapters.py
    budgets.py
    monitoring.py
  evidence/
    package.py
    assessment.py
    seal.py
    supplements.py
    replay.py
  archive/
    jobs.py
    copies.py
    retention.py
    retention_operations.py
    backup.py
    restore.py
```

Existing large modules such as `orchestrator/engine.py` remain compatibility coordinators during migration; new domain logic must live in focused packages rather than expanding the monolith.

## Global Verification Gates

Every Phase must use the approved Phase -1 runner. Bare `python3` and Production Home are forbidden:

```bash
<approved-python> ~/SitinaHub/scripts/test-bplus.py unit_fast
<approved-python> ~/SitinaHub/scripts/test-bplus.py integration_isolated
<approved-python> ~/SitinaHub/scripts/test-bplus.py crash_fault --phase <authorized-phase>
```

Expected: all applicable existing and new tests pass in a disposable Test Home; Production sentinel hashes/size/mtime remain unchanged；tests using real providers remain disabled unless explicitly authorized。

Additional required gates:

1. **Crash matrix:** kill after each write/sync/rename/CAS/offset boundary; restart produces deterministic state.
2. **Lost ACK:** same Command ID/Hash returns original AppendReceipt after adoption.
3. **Delete/Rebuild:** disposable Projection deletion and rebuild yields matching Semantic Checksums.
4. **Zero external Replay:** application adapters are disabled and instrumented；the report must say `APPLICATION_GUARDED_ZERO_EFFECT` unless a qualified isolation provider actually enforces and passes the `ENFORCED_SANDBOX_ZERO_EFFECT` adversarial suite.
5. **Authority scan:** no new direct writer to Legacy mutable files outside compatibility adapters.
6. **Secret scan:** Journal/CAS headers/Projection/Reports contain no raw credentials.
7. **Capacity qualification:** until benchmark passes, status remains `NOT_YET_QUALIFIED`.
8. **Production immutability:** default tests prove no change to Production DB/WAL/JSONL/State/Artifact/Output sentinels.
9. **Compatibility baseline:** every migrated Legacy mechanism is preserved, or its semantic difference is explicitly classified and approved.
10. **Plan integrity:** generated complete plan matches every source file line-for-line and SHA-256.

## Authority and Rollback Gates

### Before Phase 6A

- Legacy Writer remains sole production Authority.
- B+ writes use physically separate `controlled_fixture`、`MigrationWorkspaceRoot`、`replay` or `shadow` Roots；Production Journal Root 只允许经验证的 `ProductionMigrationControlStream` provenance/control facts。
- New Reader can be disabled without losing facts because it is not Authority.
- Shadow mismatch blocks cutover or becomes explicit `legacy_incomplete`.

### Phase 6A tooling/readiness

- Only isolated roots are permitted；Production must remain untouched.
- Verify Authority Resolver、writer fence、Genesis、migration control、routing、rebuild、lost-ACK and maintenance tooling.
- `CutoverToolingReady` is a signed readiness report, not a Cutover Outcome and not writer authority.
- Phase 6A stops before any Production freeze/import/cutover.

### Phase 6B authorized cutover

- Requires a separate explicit Maintenance Manifest and operator approval naming exact Production roots、window、snapshot intent、Genesis and stable Command ID/Hash.
- Resolve prepared state to `CUTOVER_PREPARED_NO_WRITER` and fence all Legacy writers before snapshot/import.
- Record signed Authority Cutover Frontier with stable Command ID/Request Hash and Lost-ACK query contract.
- On unknown outcome select `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER`；neither Legacy nor Journal business writer may run.
- Enable Journal-first commands only after verifying the committed Cutover Outcome yields `JOURNAL_WRITER_AUTHORIZED`.
- Keep Legacy DB/JSON/Artifacts read-only.
- Reader rollback may select the old read model only; it may not reactivate Legacy writes.
- Cutover completes only after Journal+CAS-only projection rebuild、dual-read acceptance and a committed canonical `CutoverVerified` Event/Outcome.
- Legacy Reader rollback is diagnostic/read-only only and cannot supply post-cutover authoritative preconditions.
- Live external capability activation is staged after Journal Authority Cutover and requires separate approvals.

### After Phase 6B

- All fixes move forward from the Journal.
- Canonical continuity failure creates Recovery Epoch; never writes back to Legacy.
- Legacy material remains protected after `CUTOVER_VERIFIED`；any future deletion/eviction needs its own Retention Operation and approval, not merely a passed retention predicate.

## Capacity Qualification Plan

Before publishing Supported SLOs, benchmark:

- Command envelope and Event/CAS payload matrix.
- 1/4/16/64 Events per transaction.
- Group commit delay/size matrix with APFS `fsync`.
- 10k/100k/1M/multi-million Events.
- 1–10 Runs and 1–32 active Agent Attempts.
- Journal/CAS growth and write amplification.
- Torn tail, rollover crash, writer death, key-provider outage.
- SQLite deletion/rebuild and cold lookup.
- Disk/inode pressure and emergency reserve.
- Backup during writes and Final Cold Restore.
- 24h+ soak for WAL, descriptors, memory and tail latency.

A Capacity Profile must record hardware, filesystem, durability, encryption/key profile, payload distribution, concurrency, background maintenance and measured percentiles. No profile means no Supported SLO.

## Plan-suite Completion Criteria

The full roadmap is complete only when:

- Phase -1 proves reproducible environment, isolated tests, Production immutability and source-only change audit.
- Current Legacy Source Map is frozen and reproducible.
- Single Journal Writer, CAS, Command Outcome and Projection Kernel pass crash/rebuild tests.
- All required Protocols and Effects are event-sourced and replayable.
- O/P/T V1, Evidence Package, Seal, Archive Copy and Restore Drill pass.
- Phase 6A tooling readiness passes without Production access；Authority Cutover is then explicitly approved and executed in a separate Phase 6B authorized session.
- Canonical Journal contains independently verified committed Cutover and `CutoverVerified` outcomes；Authority Resolver derives `JOURNAL_WRITER_AUTHORIZED` without using phase state.
- Legacy writers remain fenced permanently after cutover.
- PostgreSQL/Remote CAS, if adopted, preserve all Stream/Version/Position/Fence/Frontier semantics and use an explicit Backend Authority Handoff with a fail-closed no-writer interval.
- Every original Legacy mechanism is either preserved or has an explicitly approved semantic-change record.

No implementation task in this plan authorizes execution by itself. Each Phase requires a fresh user approval before code changes and another explicit approval before any outward-facing or destructive operation.
