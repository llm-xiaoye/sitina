# Sitina B+ 完整设计与实施前方案（唯一展示版）

- **状态：** 执行安全与兼容性优化修订完成；尚未实施
- **原始设计日期：** 2026-07-13
- **最终合同审查日期：** 2026-07-14
- **修订标识：** `BPLUS_PLAN_V3_CONTRACT_CLOSED_IMPLEMENTATION_READY`
- **唯一展示文件：** 本文件（由来源文件确定性生成，禁止手工修改）
- **内容策略：** 完整汇编，不做摘要替代，不因单文件展示而删减分阶段内容
- **禁止误读：** 除严格受限的 `PHASE_MINUS_1_BOOTSTRAP_V0` 外，没有当前用户会话绑定的 `EXECUTION_MANIFEST_V1` 时，本文件不授权代码修改、迁移、部署、数据删除、数据库重建、Authority Cutover、Live Effect 或 Hot Eviction

## 阅读与执行说明

本文件按以下顺序完整包含：

1. 正式 B+ 数据架构设计规范；
2. 实施总路线图；
3. Phase -1 Execution Foundation；
4. Phase 0 Legacy Compatibility；
5. Phase 1 Journal/CAS/Projection Kernel；
6. Phase 2 Run/Task/Process/Scheduling；
7. Phase 3 Collaboration Protocols；
8. Phase 4 Effect/Observation；
9. Phase 5 Evidence/Archive；
10. Phase 6A Cutover Tooling/Readiness；
11. Phase 6B Authorized Production Cutover；
12. Phase 7 Backend Scale-out。

来源文件是规范性编辑来源，本文件是生成的唯一展示产物。执行时必须先读取设计规范、路线图、当前授权 Phase 和所有前置 Acceptance Report；不得把整份 Checklist 解释为一次性全量授权。

## 首次执行入口

第一次实现会话只能用 `PHASE_MINUS_1_BOOTSTRAP_V0` 执行 Phase -1 Foundation Tasks 1–3；V0 只能引用已存在的输入，不能引用尚未生成的 Foundation Record 或 Manifest V1 哈希。稳定哈希产生后必须人工批准并签发 `EXECUTION_MANIFEST_V1`，此后才能继续 Phase -1。完成并提交 Phase -1 Acceptance Report 后必须停止；Phase 0 需要新的用户授权。

## 总体阶段依赖

```text
Phase -1 Execution Foundation
  ↓
Phase 0 Legacy Fence / Inventory
  ↓
Phase 1 Journal / CAS / Projection Kernel
  ↓
Phase 2 Run / Task / Process / Scheduling
  ↓
Phase 3 Collaboration Protocols
  ↓
Phase 4 Effect / Observation
  ↓
Phase 5 Evidence / Archive
  ↓
Phase 6A Cutover Tooling / Readiness (isolated only)
  ↓
Phase 6B Authorized Production Cutover (separate operation)
  ↓
Phase 7 Backend Scale-out
```

每个 Phase 都需要新的明确实施授权。Phase -1 只建立隔离执行基础；Phase 6A 只证明工具且不得访问 Production；Phase 6B Authority Cutover、Production Freeze、迁移、部署、Live Effect、删除和 Hot Eviction 必须分别确认。

## 来源完整性清单

| 顺序 | 来源文件 | 行数 | SHA-256 |
|---:|---|---:|---|
| 1 | `docs/superpowers/specs/2026-07-13-sitina-bplus-data-architecture-design.md` | 1405 | `3007b2230b0a2a1805351dcfe1f7d9c86125045ce2d08bee320915c4f5cb93e1` |
| 2 | `docs/superpowers/plans/2026-07-13-sitina-bplus-implementation-roadmap.md` | 249 | `74b6b7fe228325c63d1ef8fb010423be643b36bcdd335dd3744cc9085765a144` |
| 3 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-minus-1-execution-foundation.md` | 248 | `f9dbb1b75b55c1615c5c60e69402c56d563b967475cc3cbf792b8bf0dec55e74` |
| 4 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-0-legacy-compatibility.md` | 395 | `b881e1293e5ff607e366f6167d5536c17d01a5728a003375fa75f682dcdf278f` |
| 5 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-1-journal-cas-kernel.md` | 462 | `ae831f6e1c1b97805e795dfc20eb7dae4b6cdcfa65900641daae1a57cd742c26` |
| 6 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-2-run-task-scheduling.md` | 252 | `11c2067f68ac7aac9d6d281bc1f8c927ecb560803171b507b7ab5329ab2ae68a` |
| 7 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-3-collaboration-protocols.md` | 227 | `1bdf1137e0c2ea1b2afd9246bb416861533194eaa5d469281a5dd29ce69f1244` |
| 8 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-4-effects-observations.md` | 323 | `37df3a63ec7d176580b02aa9b1c9bb6364fe81ad7b6425633e424ee9177e30ce` |
| 9 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-5-evidence-archive.md` | 332 | `eabb84e2daa861fe5ba71ca8ea3b6872f5c5aa28f0ec8d489c1ee59ebe1df8c8` |
| 10 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-6a-cutover-tooling-readiness.md` | 225 | `42425b3af37e4331218401239cfc2805824f57d99b552a7c142e441de4fd1594` |
| 11 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-6b-authorized-production-cutover.md` | 133 | `884e753ea4925755cbafc533458773d40c6ad195b0176e20c650fc450c5b9ff5` |
| 12 | `docs/superpowers/plans/2026-07-13-sitina-bplus-phase-7-backend-scaleout.md` | 203 | `511a31add62236d4d7612bcdd92fae793945ca5c907425d960e57eaff89e4ab3` |


---

# 第一部分：完整正式设计规范

> 完整来源：`docs/superpowers/specs/2026-07-13-sitina-bplus-data-architecture-design.md`  
> 来源 SHA-256：`3007b2230b0a2a1805351dcfe1f7d9c86125045ce2d08bee320915c4f5cb93e1`

# Sitina B+ 数据架构设计规范

- **状态：** 已批准设计（执行安全与兼容性优化修订版）
- **日期：** 2026-07-13
- **范围：** Sitina 多 Agent 协作运行时的数据、协议、外部副作用、证据、归档和物理存储架构
- **实现状态：** 本文定义目标架构，不表示当前代码已经实现

## 1. 目标与约束

Sitina 的目标不是在固定流水线上叠加多个角色名称，而是构建真正的多 Agent 协作系统。Agent 可以动态协商、竞争、互评、委派、重试、交接和仲裁；所有协作都有明确状态机、共享状态、因果链、安全边界和审计闭环。

本设计采用 **B+：事件溯源热控制库 + 不可变 Run Bundle**：

```text
Canonical Event Journal
        ↓
SQLite Hot Projections
        ↓
Encrypted Content-Addressed Object Store
        ↓
Immutable Evidence Package / Run Bundle
```

确定的运行约束如下：

- 单机优先，但后端可平滑迁移到 PostgreSQL、多 Worker 和远端对象存储。
- 参考负载为 2–10 个并行 Run，每个 Run 5–30 个注册 Agent。
- 重要 Run 的完整证据长期保留；普通 Run 可以压缩和冷存，但必须可以重新加载、离线重放和审计。
- Provider Prompt、Output、Tool Result 等原始正文进入分级加密对象存储；在线数据库仅保存结构化脱敏字段、Hash 和引用。
- 交付语义为 at-least-once，加稳定身份、幂等键、CAS、Lease Fence 和确定性恢复。
- 不承诺普遍的物理 exactly-once external execution；承诺 exactly-once logical settlement。
- 大规模架构调整在范围内；最小改动不是目标。

### 1.1 非目标

本设计不承诺：

- 外部 Provider、网络或第三方系统物理执行恰好一次；
- 重放模型后生成与历史完全相同的自然语言输出；
- 用 SQLite、Bundle 或最终状态反造缺失的历史 Event；
- 在单机部署中抵抗同时控制操作系统管理员、Key Provider 管理员和硬件的攻击者；
- 通过降低 `fsync`、跳过验证或丢弃已接纳事实换取性能。

### 1.2 规范用语

本文中的“必须”“不得”是规范性要求；“建议”“默认”是可配置但应优先采用的安全基线。类型名称采用 `PascalCase`，字段采用 `snake_case`，状态常量采用 `UPPER_SNAKE_CASE`。

### 1.3 兼容性优先的优化原则

B+ 是对现有 Sitina 功能机制的 Authority、Durability、Concurrency、Effect Safety 和 Evidence 能力升级，不得以“架构重写”为理由静默删除现有 Run、Task Graph、Proposal、Review、Handoff、Arbitration、Blackboard、Lease、Approval、Risk、Replay、Evidence Export、CLI 或 Mock/Live Provider 行为。

每个迁移 Slice 都必须把现有 Legacy 行为分为：

```text
PRESERVED_SEMANTICS
EXPECTED_REPRESENTATION_CHANGE
APPROVED_SEMANTIC_CHANGE
LEGACY_DEFECT_NOT_CARRIED_FORWARD
UNRESOLVED_MISMATCH
```

只有 `EXPECTED_REPRESENTATION_CHANGE` 可以由版本化 Normalization Profile 自动接受；`APPROVED_SEMANTIC_CHANGE` 和 `LEGACY_DEFECT_NOT_CARRIED_FORWARD` 必须绑定明确批准、旧/新行为、影响面和回滚策略；`UNRESOLVED_MISMATCH` 阻止后续 Authority Cutover。Legacy Oracle 用于兼容性比较，不因此成为 B+ Authority。

### 1.4 执行基础与环境不变量

任何正式实现前必须完成 Phase -1 Execution Foundation。Phase -1 自身使用两级启动，避免 Manifest 引用尚未生成的自身产物：

- **`PHASE_MINUS_1_BOOTSTRAP_V0`：** 由用户人工审阅并绑定初始 Plan Hash、Production/Test Root、极窄 Mutation Roots、禁止操作和 Stop Point；只允许创建/固定 Python Profile、Dependency Lock、Source-only Audit 和 V1 Manifest Validator，不得运行 Runtime、测试或访问 Production Mutable Data。
- **`EXECUTION_MANIFEST_V1`：** 引用 V0 生成的 Python Profile Hash、Dependency Lock Hash、Plan-suite Hash、Baseline/Change-audit Identity；从 Phase -1 隔离测试开始，所有正式实现都必须使用 V1。

执行基础要求：

- 固定并验证 Python、依赖锁、平台和架构 Profile；不得使用解析到未批准系统 Python 的裸命令。
- 选择 Git Source-only 或等价 Content-addressed Change Manifest；Runtime State、Secret、备份和 Production 数据不得进入源码审计。
- Test Home 必须与 Production Home 物理隔离；测试进程解析到 Production Home、其父目录、Symlink Alias 或真实路径别名时 Fail Closed。
- 默认测试禁止真实 Provider、MCP、Tool、Publication 和外部 Mutation；Live Test 需要独立授权。
- 除明确受限的 V0 Bootstrap 外，每次实现会话必须有绑定 Phase、Task Range、Mutation Roots、Baseline、Plan Hash 和 Stop Point 的 V1 Execution Manifest；计划 Checklist 本身不是执行授权。
- 完整展示文件必须由来源文件确定性生成并校验；不得手工修改生成文件造成来源漂移。

执行基础不改变业务语义，但它是所有后续正确性声明、兼容性比较和验收报告的前提。

## 2. 权威模型与共同不变量

### 2.1 单一事实源

Canonical Event Journal 是业务、协调、Evidence 和 Archive 生命周期事实的唯一权威载体。初始单机实现使用一个全局顺序物理 Journal，多个 Logical Stream 的 Event 交错写入；未来可以拆成多个 Journal Namespace，但每个事实仍只能有一个权威 Stream，跨 Journal 一致性使用签名 Frontier Vector。

其他存储角色为：

- **CAS：** 保存不可变正文和 Artifact，不拥有生命周期事实。
- **SQLite：** 保存可删除、可重建的 Projection、查询索引和候选视图。
- **Evidence Package：** 对 Journal 事实的签名不可变表示，不是可写数据库。
- **Bundle Artifact：** Evidence Package 的物理封装，不等于 Package 本身。
- **Archive Copy：** 保存某个 Artifact 的物理驻留事实，不改变业务结果。

任何 Agent、Controller、Scheduler、Dispatcher、Process Manager、Protocol Engine、Tool Adapter 或 Projector 都不得直接修改业务状态。所有权威变化都必须经过：

```text
Command → Event(s) → Projection → Decision → Next Command
```

跨 Stream 协作必须经过：

```text
Committed Event
→ Process Manager
→ Typed Command
→ Target Stream State Machine
→ Target Stream Event
```

Shadow、Controlled Fixture、Replay、`MigrationWorkspaceRoot` 和 Production Journal 必须使用不同的 Physical Root、Journal Identity、Epoch/Namespace Policy 和 Key Namespace。Shadow/Workspace Journal 永远不能通过修改 Flag 或 Phase Row 被“提升”为 Production Authority；Production Authority 必须从独立 Production Genesis、`ProductionMigrationControlStream` 和签名 Cutover Frontier 建立。非权威 Event 即使物理字节有效，也永远不得成为原生业务事实。

### 2.2 Stream 与 Position

- Logical Stream 是状态机、事务一致性和乐观并发边界。
- `stream_version` 在同一 Stream 内严格连续。
- `global_position` 在同一 Journal Epoch 内唯一且单调；是否允许空洞由版本化 Backend Position Profile 明确声明。
- 初始单机后端必须使用 `LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1`：只为当前 Frame 实际提交的 Event 分配 Position；Recovery 截断的未提交 Frame 不占 Committed Position；同一 Epoch 的 Committed Event Position 连续。发现 Committed Gap 必须视为 Corruption 或 Incomplete Evidence，禁止跳过继续 Project。
- 通用数据库后端可以使用 `GAPPED_COMMITTED_PREFIX`，但每个 Gap 必须由 Fenced Allocation Ledger 或 Committed-prefix Watermark 证明为永远不会被后续提交填充。Gap 本身不是 Event，也不得掩盖缺失 Frame、遗漏 Event 或损坏。
- 初始 PostgreSQL 后端不得使用 Gapped Profile；它必须使用 `POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`，在同一 Append Transaction 和全局 Coordinator Lock 下更新 Transactional Position Counter。Rollback 同时回滚 Counter，因此不消费 Position。独立 Reservation/Gapped Profile 是未来单独设计和批准的扩展。
- `global_position` 用于物理排序、Barrier 和 Projector Scan，不是 Event 数量。Projector 在 `GAPPED_COMMITTED_PREFIX` 下扫描已发布 Committed Prefix 中的实际 Event，不等待合法 Gap，也不得跨越 `RESERVED` Range。
- Omission Proof 必须区分合法未分配/已终止 Allocation Gap 与遗漏 Event；只有 `stream_version` Gap 在所有 Backend 中都内在非法。
- 不得用 `head_position - offset_position` 计算 `lag_events`。
- 一个 Command 可以在一个 Logical Stream 中原子提交一个或多个 Event；不得伪装成跨 Stream 原子事务。

### 2.3 独立生命周期

以下生命周期彼此独立：

```text
Business:
ACTIVE → CLOSING → SUCCEEDED | FAILED | CANCELLED

Evidence Package Generation:
PENDING → BUILDING → BUILT → VERIFYING → SEALED | INCOMPLETE

Archive Job:
PENDING → STAGING → VERIFYING_STAGING → TRANSFERRING
        → VERIFYING_FINAL → COMPLETED | FAILED

Archive Copy Residency:
STORED | MOVED | MISSING | QUARANTINED | DELETED_BY_POLICY
```

Closing 阻断项由 Terminal Eligibility、Decision 和 Obligation Facts 表达；`CLOSING` 可以保持到阻断解除，或者通过 `AbortClosing → ACTIVE` 恢复普通业务。不得再持久化一套与 Business Lifecycle 重叠的 `CLOSING_BLOCKED` 状态。

`ARCHIVED_VERIFIED` 只允许作为带 Frontier 的 UI 派生标签，不得作为可写权威状态。

### 2.4 Authority Classification Matrix

Authority 按“事实类型和生命周期”分类，不按文件或数据库产品笼统分类。`Canonical Journal` 在本矩阵中包括受同一完整性、身份、恢复和 Frontier 规则约束的 Business、Security、Operational-control、Evidence 和 Archive Journal Namespace；它们不因此都成为 Business Event。

| Fact Class | 权威 Owner | 是否改变 Business State | 是否进入 Terminal Source Frontier O/P/T | 是否进入 Evidence Package |
|---|---|---:|---|---|
| Business Event | 对应 Domain Stream | 是 | 是 | 是 |
| Command Outcome | Target Transaction Frame；确定性拒绝由 `command-outcome/<command_id>` | 是或决定是否改变 | 是 | 是 |
| Security Intake | `command-intake/<record_id>`；不可安全解析的原始输入位于有界 Security Quarantine | 通常否；可创建 Security Obligation 或阻断 | 仅当影响 Admission、Terminal 或 Required Obligation | 按 Evidence Policy 保存脱敏事实和 Quarantine Attestation |
| Audit Fact | Audit Stream | 不直接 | Required Audit Predicate 或 Outcome 依赖时进入 | 是 |
| Operational Control | Durable Operational-control Stream | 可授权、阻断或 Fence，但不直接替代 Domain State | 影响 Dispatch、Effect、Closing 或 Terminal 时进入 | 是 |
| Dead Letter | `dead-letter/<dead_letter_id>` | 不创造原业务结果；Blocking 类型阻断 | Blocking 类型进入 | 是 |
| Projection Failure | Operational Failure Stream；Projection Row 仅为派生 | 不直接 | Terminal/Evidence Required Projector 失败时进入 | 是，连同 Resolution/Replay 结果 |
| Evidence Assessment | `evidence/<package_id>` 接受的不可变 Assessment | 否 | 不进入 T 的 Pre-terminal Source Frontier | 进入 T 后的 Evidence Record Frontier 和 Package |
| Archive Assessment | `archive-copy/<copy_id>` | 否 | 否 | 进入 Current Audit/Archive Evidence |
| Quarantine Record | 对应类型的 Quarantine Stream | 不直接；可阻断相关 Obligation、Seal 或恢复 | Required Material 被隔离时进入阻断证明 | 是；只保存允许的内容、Hash 和 Attestation |
| Projection Row / Cache / Summary | 无独立权威 Owner | 否 | 否 | 只可保存 Checksum/Freshness，不作为事实 |

Raw Secret、恶意大对象或无法安全解析的输入不得为了“完整审计”而污染 Business Stream；其脱敏 Metadata、拒绝结果、Quarantine、Capability Revocation 和 Destruction Attestation 才能作为受控证据。任何矩阵项只有一个权威 Owner；同一事实的 JSON、SQLite、Bundle 或 Report 表示均不得成为第二 Authority。

### 2.5 Authority Resolution State Machine

Authority Phase Name、CLI Flag、Projection Row 和进程内状态都不能决定 Writer。唯一合法的 Authority Resolution 输出为：

```text
LEGACY_WRITER_AUTHORIZED
CUTOVER_PREPARED_NO_WRITER
CUTOVER_OUTCOME_UNKNOWN_NO_WRITER
JOURNAL_WRITER_AUTHORIZED
RECOVERY_REQUIRED_NO_WRITER
```

`AuthorityResolver` 必须同时验证 Legacy Fence Control Record、Production Journal Genesis、稳定 Cutover Command ID/Request Hash 和 Journal-derived Command Outcome：

- 只有 Cutover 尚未准备、存在当前有效 `LEGACY_WRITER_ENABLED` Control Record 且 Journal 对绑定 Cutover Identity 具有权威 Absence Proof 时，返回 `LEGACY_WRITER_AUTHORIZED`。
- 一旦 Legacy Fence 进入 Cutover Prepared，Legacy Writer 即停止；在 Cutover Command 尚未提交前返回 `CUTOVER_PREPARED_NO_WRITER`。
- Cutover ACK 丢失、Journal Coverage 不可用、Outcome 无法重建或证据冲突时返回 `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER`；Legacy 和 Journal 都不得 Admission/Dispatch。
- 只有 Journal-derived Lookup 验证同一 Cutover Command `COMMITTED`、Genesis/Request/Frontier/Authorization 全部匹配时，返回 `JOURNAL_WRITER_AUTHORIZED`。
- Identity Collision、Continuity 不确定、双 Genesis、Fence Proof 缺失或不同来源给出冲突结果时返回 `RECOVERY_REQUIRED_NO_WRITER`。

Phase/Stage 只能作为 UI 和 Runbook 进度，不得实现 `phase → authoritative_writer` 属性。任何无 Writer 状态仍允许受限 Read-only Recovery/Query，但不得执行普通业务、Timer、Effect 或外部 Dispatch。

## 3. Runtime 组件与职责

### 3.1 核心组件

- **Command Gateway：** 安全解析、Schema 选择、Authorization、大小限制、Secret Classification 和 Idempotency 接入。
- **Stream Command Handler / Protocol Engine：** 在单一 Stream 上执行 Expected Version、Admission、Policy、Fence 和 Invariant 的最终裁决。
- **Canonical Journal Writer：** 序列化本地 Append，分配 Position，执行严格 Durability Barrier。
- **CAS Publisher：** 在 Event Append 前完成对象加密、持久化、认证和 Final Verification。
- **Projectors：** 将 Event 投影为 Hot Read Model，并在同一 SQLite 事务中推进 Offset。
- **Process Manager：** 消费已提交 Event，决定非调度型跨 Aggregate 下一步。
- **Scheduler：** 从 Projection 计算 Task/Agent/Resource 的 Eligibility、排序和 Selection，提交不可变 `SchedulerDecision`。
- **Dispatcher：** 消费已提交 Decision，按顺序幂等提交 Typed Command，不重新定义 Eligibility。
- **Tool Gateway：** 管理所有外部信任域访问、Effect Attempt、Receipt、Observation、Reconciliation 和 Compensation。
- **Evidence Builder / Verifier / Sealer：** 分别收集、只读验证和签名封存证据。
- **Archiver：** 将固定 Bundle Artifact 复制到冷存，并从最终位置重新验证。

### 3.2 职责分离

- Process Manager 决定“接下来需要做什么”。
- Scheduler 决定“哪些 Task/Agent/Resource 组合可以在何时尝试，并如何排序”。
- Dispatcher 只执行已提交的尝试计划。
- Protocol Engine 只裁决自身 Stream 的 Command 和状态转换。
- Projection 只用于观察、筛选和候选推导，不负责权威授权。
- Strong Projection Read 只能证明截至固定 Frontier 看到了什么，不能锁住未来；后续 Command 必须重新验证 Version、Admission 和 Fence。

## 4. Command、Event、Decision 与一致性

### 4.0 规范性编码、格式与密码 Profile

在持久化任何 B+ Byte 前必须冻结并版本化：

```text
canonical_serialization_profile
identifier_profile
segment_frame_profile
hash_domain_profile
encryption_profile
signature_profile
key_provider_profile
journal_auth_profile
position_profile
clock_profile
```

Canonical Serialization 必须精确定义 UTF-8、Unicode NFC、Object Key 顺序、Set-like Collection 排序、Array 保序、整数范围、浮点禁止或规范表示、Timestamp、Duplicate Key、Unknown Field 和 Null 语义。不得把现有 `json.dumps(sort_keys=True)` 当作未定义细节的长期协议。

Segment/Frame Profile 必须精确定义 Endianness、ID Byte Encoding、Length Bound、Header/Footer、CRC/Hash Preimage、自 Hash 排除、Padding、Major/Minor Compatibility 和 Golden Test Vector。`transaction_id(16)` 或 `command_id(16)` 只有在 Identifier Profile 明确要求 128-bit Identity 时才合法；否则必须使用有界 Length-prefixed Encoding。

Encryption/Signature Profile 必须在实现前固定算法、Library/Version Policy、Nonce/IV 生成和唯一性、AAD、Tag、Key Size、Key Purpose、Context-bound Envelope Encoding、Rotation 和 Known-answer Vector。Object Ciphertext 与 DEK Wrapping Envelope 必须分别认证；Rewrap 创建新的不可变 Envelope Version/ID 和受审计 Alias，不得原地修改 CAS Object、Object Ciphertext 或 Semantic Identity。不得把算法选择留给运行时默认值。

Journal Auth V1 使用独立 `JournalAuthKey` 的 HMAC-SHA-256，不复用 Object KEK、Tenant Commitment、External Credential、Evidence Signing 或 Verifier Identity Key。`event_core_bytes` 是排除 `event_hash` 和 `auth_tag`、但包含 `auth_key_id` 的 Stored Canonical Event Bytes；`event_hash = SHA-256(domain || event_core_bytes)`；`auth_tag = HMAC-SHA-256(JournalAuthKey, domain || journal_identity || epoch || event_hash)`。Transaction Hash 覆盖最终存储的 Event Bytes（包括 Event Hash 和 Auth Tag）。

Journal Auth Key Rotation 只允许通过旧 Key 认证的 `JournalAuthKeyTransition` Operational Event，并在 Segment Boundary 生效；新 Segment Header 绑定新 Key ID。所有仍受 Retention/Evidence Policy 约束的历史验证 Key 必须保留或有等价 Trust/Destruction Attestation。验证失败、Key 缺失或 Transition Chain 断裂一律 Fail Closed 并使相关 Evidence 降级；不得生成新 Key 假装验证旧 Event。Journal Auth Capability 与 Archive/Evidence Seal Signing Capability 永久分离。

### 4.1 Command Envelope

Command 表达意图，至少包含：

```text
command_id
command_type
command_schema_version
run_id
stream_id
actor
authorization_context_ref
expected_stream_version
idempotency_scope
idempotency_key
idempotency_namespace_version
command_request_hash
issued_at
received_at
deadline_at
timeout_budget_ms
causation_event_id
causation_decision_id
correlation_id
payload_ref
payload_schema
payload_schema_version
code_revision
config_hash
roles_hash
policy_hash
prompt_bundle_hash
schema_registry_version
```

外部 Root Command 可以没有 Causation；内部 Command 必须引用来源 Event 或 Decision。Command 解析失败、超大或恶意输入进入独立 Intake Security Log，不得污染目标业务 Stream。

`command_request_hash` 由版本化 Canonical Command Profile 计算：以 Domain Separator 绑定 Command Type、Schema Version、Target Stream、规范化 Payload/Ref、Authorization/Policy-sensitive Bindings 和 Idempotency Namespace；排除 `received_at`、重试次数、Transport Metadata 等易变字段。`keyed_idempotency_digest` 由独立 Idempotency Key Domain 对 `(scope, namespace_version, raw_key)` 计算，原始 Key 不必进入 Projection。相等规则只比较相同 Profile/Domain/Namespace 下的固定长度 Digest；Profile 或 Namespace 变化必须显式版本化。Journal Append Contract 必须同时携带 `command_id`、`command_request_hash`、Idempotency Scope/Digest/Namespace 和 Target Stream。

### 4.2 Event Envelope

Event 表达已经 Durably Committed 的不可变事实，至少包含：

```text
event_id
event_type
event_schema_version
payload_schema
payload_schema_version
global_position
stream_id
stream_version
run_id
transaction_id
transaction_index
transaction_size
actor
causation_command_id
correlation_id
payload_ref
payload_hash
content_hash
auth_tag
auth_key_id
previous_stream_event_hash
previous_segment_event_hash
event_hash
occurred_at
committed_at
code_revision
config_hash
roles_hash
policy_hash
classification
redaction_status
```

一个 Command 可以在同一 Stream 中原子产生多个 Event。Event Hash/Auth Tag 严格使用 4.0 定义的 Stored Canonical Preimage，不覆盖 Upcast 后的内存对象，也不得产生自引用 Hash。

### 4.3 Decision Envelope

Decision 是可审计推导，不直接改变状态：

```text
decision_id
decision_type
run_id
stream_id
actor
source_event_ids
source_projection_positions
state_snapshot_hash
candidate_actions
selected_action
blocked_actions
reason_code
reason_ref
policy_hash
created_at
code_revision
config_hash
```

Decision 必须作为权威 Event 或被权威 Event 引用，确保完整因果链可以重建。

### 4.4 Idempotency

- 相同 `command_id` 和相同 `request_hash` 返回原结果。
- 相同 `command_id` 和不同 `request_hash` 产生 Security Incident。
- 相同 `(idempotency_scope, keyed_digest)` 不得绑定不同 Request。
- Idempotency Namespace 的失效必须通过显式版本或 Policy Fact；不得因 Hot SQLite 清理而让旧 Key 静默重新绑定。
- External Effect 的 Provider-facing Key 在 Adapter/Endpoint/Tenant/Principal/Scope 内只能绑定一个 `effect_id`。

### 4.5 Lost ACK 与 Command Outcome 契约

必须区分三种 ACK：

1. **Journal Durability ACK：** AppendReceipt 证明 Canonical Frame 已越过 Durability Barrier；
2. **Command Result ACK：** 向 Caller 返回已提交或已确定拒绝的业务结果；
3. **Remote Effect ACK：** 远端系统的接收/完成 Observation，只能按 Effect 协议解释。

客户端查询 Command 的封闭结果集为：

```text
COMMITTED
REJECTED
CONFLICT
RETRYABLE_NOT_ACCEPTED
UNKNOWN
```

- **COMMITTED：** Canonical Frame 已提交；返回 `command_id`、`command_request_hash`、`transaction_id`、Event IDs、Position Range、Resulting Stream Version、Append Receipt Hash 和 Durability Profile。
- **REJECTED：** Authorization、Deadline、Policy、Schema 或 Invariant 已得到确定性拒绝；拒绝结果具有稳定 Identity。
- **CONFLICT：** 相同 Command ID/Idempotency Binding 对应不同 Request，或 Expected Stream Version 冲突。相同 ID 不同 Request 是 Security/Integrity Incident。
- **RETRYABLE_NOT_ACCEPTED：** 系统能证明没有发生 Durable Admission，例如 Capacity Gate 在持久化前拒绝；客户端使用相同 Command ID/Request Hash 重试。
- **UNKNOWN：** 当前既不能证明 Committed，也不能形成权威 Absence Proof；客户端只能查询或使用相同 Command ID/Request Hash 重试，不得创建新逻辑 Command。

成功 Command Outcome 由 Target Transaction Frame 中的 Command Binding 和已提交 Event 共同证明，不依赖另一个异步 Outcome Projection。`command-outcome/<command_id>` 用于确定性拒绝、Expiry、Collision、Intake Outcome 或附加结果摘要；SQLite `command_outcomes` 永远只是查询 Projection。

Recovery Adopt 并重新 Sync 未 ACK Frame 后，Journal-derived Lookup 必须可按相同 `command_id + command_request_hash` 返回原 AppendReceipt。若 Target Stream Event 已提交而 Outcome Projection 尚未追平，Query 直接从 Canonical Frame/Verified Lookup 得到 `COMMITTED`，不得重发 Command。Outbox 和 Process Manager 在 ACK 丢失或 Projection Lag 后重放相同 Stable Command ID，直到查询到原 Outcome；不得生成新 Step 或新外部动作。

Remote Effect ACK 丢失不属于 Command Lost ACK；它必须进入 Effect Outcome、Exposure、Observation 和 Reconciliation，不能因 Command 已提交而盲重试远端 Mutation。

### 4.6 Object Before Event

大正文写入顺序固定为：

1. Canonicalize、Classify、Redact、Schema Validate；
2. 在 CAS Staging 加密写入；
3. `fsync`；
4. Fresh-reader 验证 Header、Cipher Hash 和 Authentication；
5. Atomic No-replace Final Publication；
6. Directory Sync；
7. Reopen Final Object 并再次验证；
8. Journal Append 引用 Object Ref/Hash/Classification。

Journal Append 失败时 Object 只是 Orphan Candidate，不是业务事实。

Object-before-Event 必须由类型和 Writer API 强制，而不是只依赖调用顺序：

```text
append(
  command,
  expected_stream_version,
  events,
  object_reference_proofs: Sequence[ObjectReferenceProof]
) -> AppendReceipt

ObjectReferenceProof =
  PublishedObjectReceipt
  | ExistingDurableObjectRootProof
```

`PublishedObjectReceipt` 只能由 CAS `publish_verified()` 返回，至少绑定 Object/Cipher/Envelope Identity、Core Header Hash、Cipher Hash、Auth Verification、Final Publication Primitive、File/Directory Durability Receipt、Fresh-reader Verification、Profile、Publication Generation 和 Expiry。它是可验证 Capability，不是业务事实。

Journal Writer 必须从 Canonical Event Bytes 自行提取全部 Object Ref，并要求它们与 `object_reference_proofs` 精确相等：新 Object 使用仍有效的 `PublishedObjectReceipt`；已被其他 Committed Frame 引用的共享 Object 使用 `ExistingDurableObjectRootProof`。后者只能由 Journal 在获验 Frontier 内解析已有 Committed Frame 及其 Object-reference Manifest 后签发；CAS Object/Catalog/Projection 的存在本身不能签发 Durable Root Proof。Writer 不信任调用方声明，必须验证 Proof、Fresh-open Final Object、Profile/Identity，并在当前 GC Epoch 下取得 `ReferenceAdmissionLease`。Frame Header/Transaction Hash 绑定 `object_reference_manifest_hash`。

Reference Lease 持有到 Referencing Frame 越过 Durability Barrier；该 Frame 本身随后成为持久 GC Root。若 Append 未提交，Receipt 不创造业务 Root，对象保持受 Lease 保护的 Orphan Candidate，Lease Recovery 后才能由固定 Frontier GC 判定。任何缺 Proof、Proof 过期、Ref/Proof 不相等、Final Object 不可验证或 GC Fence 不兼容都在写 Frame 前 Fail Closed。

### 4.7 Projection 与读取一致性

Projector 按实际 Position 顺序扫描：

```text
BEGIN IMMEDIATE
  Apply Event Batch
  Update Semantic Rows
  Advance Projection Offset / Frontier
COMMIT
```

任何 Event 失败时整个 Batch 回滚，Offset 不前进。永久失败进入 Dead Letter；修复通过管理 Command 和新 Event 表达，不修改或跳过原 Event。

读取模式：

- **STRONG：** 等待 Caller 指定的 `required_position` 或 `required_frontier_vector`，不追逐移动 Head。
- **EVENTUAL：** 返回 `as_of_frontier`、真实 `lag_events`、`lag_seconds` 和 Projector Version。
- **STALE_ALLOWED：** 仅适用于明确允许 Stale 的 Endpoint，返回 Freshness 和超限标记。

## 5. Run Coordination Domain 与协作协议

### 5.1 Stream 归属

Run Coordination Domain 是协调域，不是巨型 Aggregate。推荐 Stream：

```text
run/<run_id>
goal/<goal_id>
task-graph/<graph_id>
task/<task_id>
obligation/<obligation_id>
knowledge-claim/<claim_id>
proposal-round/<round_id>
debate/<debate_id>
review/<review_id>
handoff/<handoff_id>
arbitration/<arbitration_id>
merge/<merge_id>
rework/<rework_id>
blackboard/<document_id>
process/<process_id>
scheduling/<decision_id>
resource-lease/<lease_id>
approval/<approval_id>
budget-reservation/<reservation_id>
operational-control/<control_id>
command-outcome/<command_id>
command-intake/<intake_record_id>
dead-letter/<dead_letter_id>
read-effect-session/<session_id>
effect/<effect_id>
effect-observation/<effect_id>
evidence/<package_id>
archive-job/<job_id>
archive-copy/<copy_id>
gc-cycle/<gc_cycle_id>
retention-operation/<operation_id>
backend-handoff/<handoff_id>
```

Run Stream 只拥有 Goal/Policy/Config/Code 引用、Business Lifecycle、Admission Generation、Closing Generation、Terminal Attempt 和唯一业务终态；不拥有各协议内部状态。

Protocol Registry 是可重建 Projection。协议实例的存在由自身 Stream 的 Created Event 证明，Registry 不能成为第二事实源。Resource Lease、Approval、Budget Reservation、Operational Control、Command Outcome、可安全解析的 Command Intake/Audit 和 Dead-letter Disposition 分别由上述 Journal-backed Stream 拥有；对应 SQLite 表仅是 Projection。Circuit Breaker 是 Operational-control Stream 中的版本化 Aggregate，不是进程内 Flag。无法安全解析或恶意输入保留在有界 Security Intake Domain，但不得作为业务事实。

### 5.2 Admission Permit 与 Closing

准入是否开放由 Business Lifecycle 派生；`admission_generation` 是单调 Fence，不是第二状态机。

可能创建 Task、Protocol、Claim、Resource Lease 或 Effect 的操作，先在 Run Stream 获得唯一 Permit。Grant、Consume、Expire、Revoke、Settle 与 `BeginClosing` 在 Run Stream CAS 下串行化。

进入 `CLOSING`：

- 递增 Admission Generation，禁止新普通 Task、Protocol、Attempt、Claim、Effect 和 Scheduling Round；
- 允许已有 Attempt 的提交/验收/失败、Receipt、Observation、Lease Release/Expire/Revoke、Compensation、Dead-letter Resolution、Checkpoint 和 Terminal Control；
- 新 Reconciliation、Compensation、Mandatory Disclosure 或 Evidence Control Effect 必须使用有 Purpose、Parent、Scope、Deadline、Budget、Child Count 和 Depth 限制的 Closing Permit；
- 若必须恢复普通业务，执行 `AbortClosing → ACTIVE` 并再次递增 Generation。

所有拥有独立 Stream Identity 的 Entity 创建都使用同一持久化 Saga Contract，覆盖 Task、Protocol、Obligation、Claim、Resource Lease、Read Effect 和 External Effect；**TaskGraph Node 不属于该集合**。Run Stream 预先冻结 `entity_id`、`create_command_id`、Entity Kind、Immutable Request Hash 和 Idempotency Binding；Target Stream 使用 `NO_STREAM` CAS 创建 `EntityCreated` 或 `EntityCreationAborted` Tombstone。`EntityCreated` 先赢得 CAS 时，Process Manager 必须前向完成 Permit Confirmation，不得释放 Permit；Tombstone 先赢得 CAS 时，Entity ID 永久占用，之后才允许释放 Permit。可恢复失败保持 Pending/Retryable；普通 Timeout、ACK 丢失、Projection Lag 和 Process Crash 通过相同 Command ID 重放恢复，不进入人工猜测。

Permit-to-Effect 是上述通用 Contract 的高风险专门化：它额外冻结 `effect_id`、Credential/Approval/Adapter/Provider Idempotency Binding，并以 `EffectRequested` 或 `EffectCreationAborted` 表达 Target 结果。只有 Journal 损坏、同 ID 不同 Payload、Permit Authenticity 不可验证或 Authority 永久丢失才进入 Manual Reconciliation。

### 5.3 Obligation

协议是否 Terminal 与 Run Obligation 是否满足分离。Obligation 状态：

```text
OPEN | SATISFIED | SUPERSEDED | FAILED | CANCELLED
```

协议终局产生：

```text
SATISFIED | SUCCESSOR_REQUIRED | RUN_FAILURE | IRRELEVANT
```

`SUCCESSOR_REQUIRED` 必须创建新的 Obligation 和 Successor Protocol。Run Terminal 取决于 Required Obligation 的结算，而不是“所有协议都 Terminal”。

### 5.4 Scheduler 与 Dispatcher

`SchedulerDecision` 固定 Source Events/Projection Frontiers、Snapshot Hash、Task Graph Hash、候选 Task/Agent、Filter Results、Scorecards、Ordered Attempts、Policy 和 Reason。

过滤顺序：

```text
eligibility → safety → dependencies → capability
→ lease availability → budget → policy
```

排序顺序：

```text
priority → aging → locality → cost → latency → confidence
```

Aging 只作用于已经通过 Eligibility 和 Safety 的候选。

Dispatcher 只消费 Committed Decision，按 Ordered Attempts 提交 Command；CAS 失败按稳定 Reason 选择 Try Next、Reobserve、Pause、Rework 或 Stop Round。`scheduling/<decision_id>` 唯一拥有 Decision 的消费与终局：至少记录 `SchedulerDecisionCommitted`、`DispatchAttemptRecorded`、`DispatcherDecisionRecorded`、`DecisionConsumed`、`DecisionExhausted`、`DecisionRejected` 和 `DecisionInvalidatedByClosing`。每个 Dispatcher Decision 引用 Scheduler Decision、Attempted Entries、Selected Attempt、Submitted Command、Command Outcome、CAS Failure Reason 和 Next Action。进入 Closing 后，未消费旧 Generation Decision 必须通过 `DecisionInvalidatedByClosing` 权威失效，Terminal Barrier 等待所有 Decision 和 Dispatch Outbox 进入可重建终局。

### 5.5 Task Graph、Task 与 Attempt

TaskGraph Stream 独占 Node Definition/Identity、Edge、Topology、Graph Generation、Dependencies、Required/Optional、Supersedes 和 Cycle Validation。TaskGraph Node 只能由 `AddTaskNode/TaskNodeAdded`、`TaskNodeMaterializationPending`、`TaskNodeMaterialized` 或 `TaskNodeMaterializationAborted` 等 TaskGraph Stream Event 创建/推进；不得存在 `task-graph-node/<id>` 独立 Stream 或第二个拓扑 Owner。

Task Stream 拥有绑定一个确切 `(graph_id, graph_generation, node_id, task_spec_hash)` 的 Immutable Specification Generation、Attempt、Claim/Fence、Artifact Acceptance 和最终 Disposition。新增 Node/Task 使用 `TaskDefinitionMaterializationProcess`：Run Permit 冻结 Graph Mutation Command、`node_id/task_id` 和 Spec Hash；TaskGraph CAS 先提交 Node/Pending Materialization；Process Manager 再以稳定 Command 在 `task/<task_id>` 执行 `NO_STREAM` Create；成功后 TaskGraph 记录 `TaskNodeMaterialized`，永久失败则记录 `TaskNodeMaterializationAborted`。Pending/Aborted Node 不可调度，且 Closing Barrier 等待所有 Materialization Process 终局。该协调允许中间 Pending，但不创造第二拓扑 Authority。

Projection 中的 `READY`、`WAITING_ON_DEPENDENCY`、`POLICY_BLOCKED`、`CAPABILITY_BLOCKED`、`BUDGET_BLOCKED` 不是 Task Stream 的权威状态。

Task Disposition：

```text
OPEN | ACCEPTED | FAILED | CANCELLED | SKIPPED | SUPERSEDED
```

Attempt Execution：

```text
CLAIMED | RUNNING | SUBMITTED | FAILED | CANCELLED | EXPIRED
```

Attempt Failure 不自动等于 Task Failure。Task 只有通过绑定确切 Artifact Hash 和 Acceptance Policy 的 Acceptance Event 才进入 `ACCEPTED`。

普通 Task Claim 与 Lease 在同一 Task Stream 原子产生：

```text
ClaimTask
→ TaskClaimed(task_attempt_id, holder, lease_id,
              claim_generation, expires_at, fencing_token)
```

共享稀缺资源才使用独立 Resource Lease Stream，并采用 Reserve Resources → Activate Task Claim → Dispatch；部分预留失败时补偿释放。Lease Renewal 必须引用已接纳的进展证据，如 Progress Event、Effect Receipt、Task Progress Version 或 Checkpoint，并受冻结的 `max_renewals`、`max_total_duration`、Renewal Deadline 和 Progress-required Policy 限制；连续 Heartbeat 本身不能无限续租。

### 5.6 Proposal、Debate、Review

ProposalRound 冻结 Participant/Evaluator Set、Rubric、Scoring Policy、Deadline、Cutoff、Minimum Score 和 Max Revisions。任何冻结条件变化创建新 Generation。同一 `(round_id, generation)` 最多一个 `ProposalSelected`。

Debate 围绕正式 Claim，Response 引用 Target、Claim、Evidence、Round 和 I/O Hash。`SynthesisFinalized` 必须列出 Included、Excluded、Unresolved Claims 和 Evidence Map，不得伪造共识。`NO_CONSENSUS` 创建 Proposal、Arbitration 或 Human Approval Obligation。

Review 绑定不可变 Artifact Hash、Rubric、Risk、Quorum 和 Independence Policy。Review Disposition 与 Artifact Acceptance 分离。旧 Approval 对原 Hash 仍是历史事实，但不适用于新 Hash。

### 5.7 Handoff、Arbitration、Merge、Rework

`handoff_id` 是稳定逻辑身份，所有 Generation 位于同一 Stream；Acceptance、Claim、Execution 和 Submission 绑定 `(handoff_id, generation)`。Rejected/Expired Generation 永久关闭，旧 Acceptance、Lease、Budget 和 Deadline 不复用。高风险 Handoff 由独立 Verifier 验收。

冲突路由：

- Blackboard 冲突先 Merge，失败后 Arbitration；
- 技术结论冲突进入 Independent Review/Reproducibility Check；
- 方案竞争进入 Frozen-rubric ProposalRound；
- 策略、安全和高风险副作用进入 Policy Arbiter 或 Human Approval。

Arbitration 只有裁决被执行后才满足 Obligation。Appeal 有 Generation、Evidence Requirement、Deadline 和 Max Count。

Rework 只有在需要独立多轮裁决时建立独立 Stream；简单修正使用新 Task 或 Attempt。

每个 Protocol State Machine 必须定义 Initial State、Owned/Allowed Commands、Emitted/Allowed Events、Allowed Transitions、Terminal/Retryable/Timeout States、Cancel 和 Invalid-transition Behavior；重复 Event 幂等，缺前置 Event 等待或 Fail Closed，非法 Command 返回稳定拒绝并在需要时写独立 Audit Stream。每个 Process Manager 记录 `generation`、`step_count`、`max_steps` 和 `visited_transition_hashes`；重复 Transition Hash、超过 Max Steps 或多维无进展触发受审计的 `StallDetected`，再选择 Split、Reassign、Rework、Arbitration、Ask User、Cancel 或 Fail。不得无限循环或无限重试。

### 5.8 Shared Blackboard

Blackboard 是 Event-backed MVCC 文档空间。Namespace 至少包括 Facts、Claims、Proposals、Working Notes、Decisions、Evidence、Constraints 和 Risks；每个 Namespace 有 Schema、Writer Policy、Evidence Rule、Merge Policy 和 Classification。

Patch 携带 `base_version`、`base_hash`、Patch Ref/Hash/Schema、Merge Policy 和 Classification。Stale Base 默认返回确定性冲突，不推进 Document Stream；审计记录进入 Command Intake/Audit Stream。

只有版本化策略证明为 Commutative、Append-only 或 CRDT-compatible 的操作可以自动 Rebase。“不同 JSON Path”本身不足以证明语义可交换。

Task/Handoff/Leased Worker 发出的 Patch 必须携带 Task ID、`task_attempt_id`、Claim Generation 和 Fencing Token；Stale Fence 即使 Base Version 最新也 Fail Closed。

### 5.9 Terminal Eligibility

Terminal Eligibility Projection 只做快速筛查，包含 Open Obligations/Tasks/Protocols、Unsettled Permits、Active Process/Steps、Pending Decisions/Outbox/Commands、Claims/Leases、Approvals、Blackboard Conflicts、Effects/Exposure、Dead Letters、Checkpoint 和 Last Frontier。

Run Terminal 顺序：

1. `BeginClosing`，关闭普通 Permit；
2. 结算 Permit、Process、Decision/Outbox、Command、Claim/Lease、Effect、Protocol 和 Obligation；
3. 固定 Observation Frontier `O` 和 Derived State Frontier `P`；
4. 提交 `PreTerminalCheckpointFlushed`；
5. Run Stream CAS 提交唯一 `RunSucceeded`、`RunFailed` 或 `RunCancelled`；
6. Evidence Package 覆盖真正 Terminal `T`。

`O`、`P`、`T` 都是包含 Journal Identity/Epoch/Shard、Position 和 Event/Prefix Commitment 的 Typed Reference，不得跨 Journal 比较裸 Position。V1 仍使用 `SignedFrontierVector` 类型，但它是**恰好一个 Component** 的退化 Vector，并要求 O/P/T 全部属于该 Component；V2 扩展为多个 Component 和 Cross-journal Proof。Terminal Event 必须引用 O、P、完整 Signed Frontier Vector Hash、Coherent-cut/Checkpoint Proof Hash、PreTerminal Checkpoint Hash、Terminal Eligibility Manifest Hash，以及决定 Outcome 的 Obligation/Failure/Cancellation Facts。Frontier Component 的 Hash 必须精确承诺该 Journal 在声明 Position 的 Published Committed Prefix 或对应 Event，不得使用未定义的普通 `head_hash`。

Outcome 规则：Required `RUN_FAILURE` 优先得到 `FAILED`；否则已接受 Cancellation 得到 `CANCELLED`；否则所有 Required Obligation 满足或被 Policy 合法解除才得到 `SUCCEEDED`。

## 6. Tool Gateway 与外部副作用

### 6.1 Effect 身份

每个需要 Gateway 访问外部信任域的操作都创建唯一 Effect Stream，包括 External Read、Disclosure、Mutation、Reconciliation Query 和 Compensation。纯本地、确定性、无外部 I/O 的计算可以不建 Effect。

身份分层：

- `effect_id`：不可变逻辑外部操作；
- `effect_attempt_id`：一次 Effect Dispatch Claim 和最多一次授权正文 Transmission；
- `task_attempt_id`：Task Stream 中的执行 Attempt；所有跨域引用必须明确 Attempt Kind 和 Owning Stream；
- `external_request_id`：远端请求/交易/任务身份，按 Adapter Manifest 可以是 Optional。

EffectRequest Admission 后，Request、Target、Policy、Semantic Manifest、Risk、Credential Principal/Scope 和 Idempotency Binding 全部不可变。语义变化创建新 `effect_id`，以 `supersedes_effect_id` 连接。Compensation 创建新 Effect，并使用 `compensates_effect_id`。

### 6.2 Outcome、Settlement 与 Exposure

Effect Stream 唯一拥有：

```text
outcome_state
settlement_state
settlement_basis
execution_cardinality_state
unresolved_transmission_exposure_count
potential_duplicate_risk
potential_loss_risk
obligation_linkage
```

Outcome：

```text
NOT_SENT | IN_FLIGHT | OUTCOME_UNKNOWN | SUCCEEDED
| FAILED_CONFIRMED | DENIED_BEFORE_SEND
| CANCELLED_BEFORE_SEND | EXPIRED_BEFORE_SEND
| OUTCOME_CONTRADICTED
```

Settlement：

```text
OPEN | RECONCILING | SETTLED
```

Basis：

```text
NONE | AUTHORITATIVE_REMOTE_OBSERVATION
| AUTHORITATIVE_LOCAL_PRE_SEND_FACT | POLICY_DISPOSITION
```

人工裁决可以接受风险并结算责任，但不能把 Unknown 伪造成 Confirmed Success/Failure。Late Confirmation 可以更新 Current Outcome/Cardinality/Risk，但不得改写原 Settlement Basis、Business Terminal 或 Seal。

Execution Cardinality 的封闭状态集为：

```text
NONE_CONFIRMED | AT_LEAST_ONE_CONFIRMED | EXACTLY_ONE_CONFIRMED
| MULTIPLE_CONFIRMED | UNKNOWN_CARDINALITY | CONTRADICTED_CARDINALITY
```

单个成功 Observation 最多证明 `AT_LEAST_ONE_CONFIRMED`。只有远端证据同时证明至少一次和至多一次、覆盖全部 Effect Attempts、Provider Scope、Idempotency Retention Window 且 Exposure 为零时，才能使用 `EXACTLY_ONE_CONFIRMED`。`MULTIPLE_CONFIRMED` 必须由不同 Remote Execution Identity 或等价权威证据证明，不能根据重复 Observation 数量推断。

Outcome、Settlement 和 Basis 的合法组合是封闭集合：

```text
NOT_SENT + OPEN + NONE
IN_FLIGHT + OPEN|RECONCILING + NONE
OUTCOME_UNKNOWN + RECONCILING + NONE
OUTCOME_UNKNOWN + SETTLED + POLICY_DISPOSITION
SUCCEEDED + RECONCILING + NONE
SUCCEEDED|FAILED_CONFIRMED + SETTLED + AUTHORITATIVE_REMOTE_OBSERVATION
SUCCEEDED|FAILED_CONFIRMED + SETTLED + POLICY_DISPOSITION
DENIED_BEFORE_SEND|CANCELLED_BEFORE_SEND|EXPIRED_BEFORE_SEND
  + SETTLED + AUTHORITATIVE_LOCAL_PRE_SEND_FACT
OUTCOME_CONTRADICTED + RECONCILING + NONE
OUTCOME_CONTRADICTED + SETTLED + POLICY_DISPOSITION
```

`SUCCEEDED + RECONCILING` 表示至少一次成功已确认，但仍有未解决的 Transmission Exposure。先以 Policy Settlement 结算 Unknown、后获得确认时，保持 `settlement_basis=POLICY_DISPOSITION` 并记录 `confirmed_after_settlement=true`。所有未列组合必须产生 `EffectStateInvariantRejected`；`OutcomeKnowledgeAdvanced` 可以更新 Current Outcome、Cardinality、Exposure 和 Risk，但不得改写已经 Settlement 的 Basis、Business Terminal 或 Seal。

### 6.3 Attempt 与 Transmission

一个 Effect Attempt 最多授权一次可能发送正文的应用层 Transmission。Adapter 和 SDK 必须关闭或暴露自动 Retry、Redirect Replay 和 Failover Replay。每次可能重发正文都需要新 `effect_attempt_id`、Dispatch Fence 和 Budget Reservation；同一 Effect 复用 Provider Idempotency Key。

Effect Attempt 本地终局：

```text
ABORTED_BEFORE_SEND
REJECTED_BEFORE_SEND
MAY_HAVE_BEEN_SENT
TRANSMITTED_WITH_OBSERVATION_AT_CLOSE
```

`Prepared` 固定 Request、Credential、Fence、Approval、Manifest；`InvocationStarted` 只证明本地即将调用 Transport，不证明远端已接收。其后崩溃且无权威“未发送”证据时，按 `MAY_HAVE_BEEN_SENT` 进入 Reconciliation。

晚到 Observation 通过 `AttemptObservationLinked(effect_attempt_id, observation_id, linked_at_position, resolution_effect)` 关联，不改写 Effect Attempt 当时的本地 Disposition。

### 6.4 Observation 双流单权威

`effect-observation/<effect_id>` 只保存经过 Admission 的不可变外部 Observation，不拥有 Outcome/Settlement。`effect/<effect_id>` 唯一裁决当前状态。

Observation Ingress：

```text
RECEIVED → AUTHENTICATING → AUTHENTICATED → MATCHING
→ ADMITTED | QUARANTINED | REJECTED
```

只有 `ADMITTED` Observation 进入权威 Observation Stream。Effect-owned Application Disposition：

```text
UNAPPLIED → APPLIED | ADVISORY | SUPERSEDED
```

只有 `APPLIED` 可以推进 Outcome。`ApplyAdmittedObservation` 携带 Observation ID、Observation Stream Version/Position 和 Expected Effect Stream Version；同一 Observation 最多应用一次。

外部 Source 不能直接 Append。Observation Validator 必须绑定 Raw Evidence Hash、Source Identity、Trust Policy、Adapter/Effect/Effect Attempt、Request Hash、Remote Identity、Nonce/Replay Key 和 Receive Time。Unauthenticated、Unmatched、Replay 或 Schema-invalid 输入进入 Security Quarantine。

`external_request_id` 是否必填由 Manifest 声明。缺失时，只能使用 Manifest 认可且能唯一绑定 Effect/Effect Attempt 的 Provider Response ID、Provider Idempotency Identity 或签名 Session/Request Identity。无法形成唯一映射时，Observation 只能进入 `ADVISORY`，不得推进 Outcome 或解除 Exposure；之后发现 External Identity 时追加新事实，不修改旧 Observation。

Effect Settlement 后只允许 Observation/Outcome Knowledge/Contradiction/Exposure/Successor/Evidence/Incident 等白名单控制 Event。

### 6.5 Adapter Manifest 与恢复等级

Adapter Manifest 固定 Identity/Version/Binary Hash、Publisher/Signature、Request/Result Schema、Operation、Externality、Reversibility、Remote Idempotency、Status Query、Not-found Semantics、Finality、Retention Window、Cancel/Fencing、Risk、Retry、Audit 和 Transport Retry Configuration。

恢复等级：

- **Level A：** 远端幂等键 + 状态查询；可以在 Deadline/Budget 内安全复用 Key 查询或重试。
- **Level B：** 状态查询但无幂等；只有权威证明未执行时才能新 Attempt。
- **Level C：** 无可靠幂等和查询；Mutation 一旦进入发送临界区不得盲重试，Unknown 进入人工裁决；不可逆操作默认拒绝，除非显式风险授权。

### 6.6 Approval、Credential 与结果安全

Approval 绑定 Effect、Exact Request Hash、Target、Amount/Scope、Policy、Risk、Credential Principal/Scope、Adapter Operation/Manifest、Expiry、Allowed Attempts/Transport Retries 和 Quorum。任一绑定变化后旧 Approval 不适用。

Journal、Projection、Receipt、Metrics、Trace、Report 和长期 CAS 不保存原始 Secret。Gateway 最后一刻从受控 Secret Provider 获取短期、最小权限、绑定 Principal/Host/Operation/Expiry 的 Credential。

原始结果先进入普通路径不可访问的加密 Quarantine，依次执行 Size、Decompression、Schema、Classification、Secret Scan、Prompt-injection Detection、Trust Assignment 和 Redaction；通过后发布长期 CAS Capability。Secret-positive Object 撤销普通 Capability，执行 Delete/Crypto-erasure，并保存 Destruction Attestation。

### 6.7 Reconciliation、Manual Resolution 与 Compensation

Reconciliation 只追加 Observation，不重写历史。`Not Found` 只有在 Manifest 明确保证时才证明未执行。矛盾 Observation 保留并进入 `OUTCOME_CONTRADICTED`。

Manual Resolution 只有两种作用：基于权威 Observation 确认 Outcome，或让 Outcome 保持 Unknown、按冻结 Policy 接受风险并结算责任。后者必须披露 Uncertainty、Residual Risk、Duplicate/Loss Risk、Authority、Monitoring 和 Obligation Disposition。

Compensation 是新 Effect，拥有独立 Request、Approval、Idempotency、Attempt 和 Outcome。`IRREVERSIBLE` Effect 不得伪造 Compensation，只能产生 Mitigation、Containment、Disclosure、Risk Acceptance 或 Incident Obligation。

### 6.8 Budget、Circuit Breaker 与 Monitoring

可计费 Effect Attempt 发送前创建 Budget Reservation Bundle；所有 Reservation 必须 `ACTIVATED`、绑定同一 Effect/`effect_attempt_id`/Fence、有效期覆盖 Dispatch，才允许 `InvocationStarted`。实际费用超额仍接纳真实 Receipt，并记录 Budget Overrun/Debt，阻止后续普通 Dispatch。

跨 Run Circuit Breaker 属于 Durable Operational-control Journal。最终 Dispatch 前必须以 CAS 获得绑定 `effect_attempt_id`/Fence 的 Authorization；`OPEN` 只阻止新 Transmission，不阻止 Receipt、Observation、Reconciliation、Required Compensation 或 Containment。

Policy-settled Unknown 允许 Run Terminal 前，必须将 Future Monitoring 通过幂等 Saga 转交 Durable Owner：Successor Stream 先提交 `MonitoringObligationAccepted`，原 Run 再提交 `MonitoringTransferAcknowledged`。Terminal 后的新行动由 Successor Run/Incident 的新 Authority 执行。

### 6.9 ReadEffectSession

高频、低风险 External Read 可以共享 `read-effect-session/<session_id>` 中的 Policy Context、Budget Context、Credential Principal、Adapter Scope、Expiry 和 Query Limit，但 Session 不替代单次 Effect。Session Query Permit 只是 Session-owned Query Slot/Budget Reservation，不是第二个业务 Admission Authority；Run/Closing Permit 仍是创建 Query Effect 的唯一准入。

每个 Query 必须创建独立 `query_effect_id`，走完整 Permit-to-Effect Saga，并拥有独立 Request Hash、Effect Attempt、Receipt、Observation 和 Provider Idempotency Identity。Session Slot 与 Run/Closing Permit 必须绑定相同 Query Effect ID/Request Hash：Effect Tombstone 先成功时释放 Session Reservation；`EffectRequested` 先成功时提交 Session Consumption。Process State 必须保证崩溃后不会留下“Slot 已消费但既无 Effect 也无 Tombstone”的不可恢复状态。

### 6.10 Side-effect Audit

Audit 分别报告 Logical Effect、Effect Attempt、Authorized Transmission、Adapter Invocation、Transport Submission、Remote Ack、Remote Business Completion、Confirmed Success/Failure、Policy-settled Unknown、Unresolved Unknown、Late Observation/Contradiction、Manual Resolution、Compensation/Mitigation、Quarantine/Destruction、Budget Overrun、Permit、Closing Effect 和 Evidence Supplement。

“逻辑责任已结算”不得解释为“外部事实已确定”。

## 7. Evidence Package、Bundle 与 Archive

### 7.1 Package、Assessment、Seal、Artifact

`package_id` 是一个 Run 下稳定 Evidence 系列；`(package_id, package_generation)` 是不可变代际。

无循环 Hash 分层：

1. **Package Core Manifest Hash：** 覆盖 Identity/Generation、O/P/T、Source Frontier、Dependency Closure、Object Commitments、Checkpoint、Evidence Policy 和 Material Inventory；排除 Assessment、Seal、Signature、Archive/Copy、Container Metadata 和 Self-hash。
2. **Assessment：** 绑定 Core Hash。
3. **Seal Statement：** 绑定 Core Hash + Assessment Hash。
4. **Bundle Artifact：** 封装固定 Core、Assessment、Seal；Container Byte Hash 覆盖实际容器。

同一 Generation 的多个 Artifact 只能改变格式、压缩和布局；Core、Assessment 或 Seal 变化必须新 Generation。

### 7.2 Assessment 与职责分离

Assessment 状态：

```text
PASSED | FAILED | INCOMPLETE | UNVERIFIABLE | CONTRADICTED
```

Assessment 是不可变事实，不直接修改 Package Lifecycle。只有当前 Evidence Policy 接受的 Seal-eligibility Assessment 才能触发 Package Sealed 或 Marked Incomplete。

Builder 无签名能力，只产 Content-addressed Core；Verifier 使用只读 Content Identity 和独立身份签发 Assessment；Sealer 只持 Seal Capability，必须重新读取 Exact Core 和 Assessment。单机只能声称 Capability Separation；抵抗本机管理员需要独立信任域或硬件保护。

### 7.3 O/P/T 与 Frontier

- `O`：本次 Terminal 接受的 Observation Frontier；
- `P`：影响 Terminal 的权威派生状态 Frontier；
- `T`：Run Stream 唯一 Business Terminal Event。

`terminal_source_frontier` 只覆盖 T 之前的 Business、Observation、Effect、Operational-control 和被 T 引用的 Migration Facts。Build、Assessment、Seal 和 Supplement 位于 T 后的 `evidence_record_frontier`，不进入 T 的 Coherent Cut。

多 Journal Frontier Component 为：

```text
journal_identity + epoch + shard → position + committed_prefix_or_event_hash
```

Coherent-cut Proof 必须证明 O 内每个 Admitted Observation 在 P 前已 Apply 或正式 Disposition，所有 Required Causation/Dependency 可解析，Required Projection 已追平，且不存在遗漏的 Required Obligation、Exposure 或 Blocking Dead Letter。

实施成熟度分级：

- **`LEGACY_TERMINAL_MANIFEST`：** 当前 SQLite Row ID、Terminal Summary、Replay Snapshot 和文件 Manifest。它不是 O/P/T Compliant，不得 Seal 为 B+ Evidence，也不得宣称 Journal Completeness。
- **`BPLUS_OPT_V1_SINGLE_JOURNAL`：** 单 Journal、单 Epoch；使用恰好一个 Component 的 `SignedFrontierVectorV1`，固定 Typed O/P Position 和 T Event Ref；使用 Committed-prefix/Event Commitment、PreTerminal Checkpoint Hash 和 Terminal Eligibility Manifest Hash。V1 必须满足完整 Task/Protocol/Effect/Obligation Closure，但不要求 Multi-component/Cross-journal Proof 或 Cross-run Cryptographic Closure。
- **`BPLUS_OPT_V2_MULTI_JOURNAL`：** Multi-journal Signed Frontier Vector、Cross-journal Coherent-cut Proof、Operational-control/Observation Application Frontier 和 Cross-run Dependency Closure。

目标数据模型保留 V2；Implementation Plan 第一阶段只需实现 V1。任何简化都不得让 Legacy Manifest 冒充 V1，也不得降低 Object、Effect、Terminal 或 Obligation 正确性。

### 7.4 Bundle 能力与 Completeness

Bundle 分别声明：

```text
verify_self_containment
replay_self_containment
inspect_self_containment
```

SELF_CONTAINED 必须嵌入相应操作所需的 Event Bytes、Object 或 Destruction Attestation、Cross-run Material、Canonicalization/Upcaster/Projector Definitions 和 Trust/Timestamp Material。HYBRID/REFERENTIAL 只有在 External Refs 当前可解析且满足 Hash/Trust/Retention 时才能完成相应能力。

Completeness Level：

```text
ASSERTED
STREAM_CHAIN_VERIFIED
JOURNAL_INDEX_PROVEN
CRYPTOGRAPHICALLY_COMPLETE
```

普通 Merkle Inclusion 不等于 Omission Proof。在未实现可信 Omission/Index Proof 前不得宣称 `CRYPTOGRAPHICALLY_COMPLETE`。

Evidence Completeness 与 Verify/Replay/Inspect Self-containment 是正交维度：SELF_CONTAINED 不自动等于 Cryptographically Complete，HYBRID 也不自动等于低 Completeness。

| Completeness Level | 必要证据 | 禁止声明 | CAS/Object 可用性 | Dependency Closure | Journal Index / Omission Proof |
|---|---|---|---|---|---|
| `ASSERTED` | Builder Material Inventory、Object/Event Hash 和声明的 Source Frontier | 不得称完整，不得声称遗漏已被证明 | Required Ref 可解析，或明确披露缺失/销毁 | 可是声明的 Root/Visited Set | 无；仅 Assertion |
| `STREAM_CHAIN_VERIFIED` | 所含每条已知 Stream 的连续 Version、Event/Head Hash Chain | 不得声称不存在遗漏 Stream 或 Cross-run Dependency | 已知 Stream 引用对象必须可验证或有合法 Destruction Attestation | 已知 Stream Closure | 无跨 Stream 枚举或 Omission Proof |
| `JOURNAL_INDEX_PROVEN` | 受信、版本化 Journal Index；Stream Enumeration 和 Position Range Proof | 不得称密码学完整 | Required CAS Closure 可验证；External Ref 必须满足 Availability/Trust Policy | Index 证明 Related Stream/Object 候选集合 | 可信 Index Proof，仍不等于密码学 Non-membership |
| `CRYPTOGRAPHICALLY_COMPLETE` | Signed Frontier、Inclusion + Omission/Non-membership Proof、完整 Dependency Closure 和可验证 Material Commitments | 不得依赖未认证的外部 Assertion 或不可验证 Catalog | Required Material 已嵌入，或 External Ref 具有等价密码学承诺、可用性和 Retention 证明 | Cryptographic Closure，包括 Required Cross-run Dependency | 必须具备密码学 Omission Proof |

任一级别在 Required CAS Material、Dependency、Index/Proof、Key/Trust 或 Frontier 不可用时，必须降级到实际仍可证明的级别或进入 `INCOMPLETE/UNVERIFIABLE`；不得保留原 Level 仅附 Warning。当前 Legacy Evidence Bundle 只能描述为 **Artifact-integrity-verified compatibility export**，不能宣称 `STREAM_CHAIN_VERIFIED` 或更高。

### 7.5 Dependency Closure

以 T、PreTerminal Checkpoint 和 Terminal Source Frontier 为根，按版本化 Edge Schema 递归遍历 Ownership、Causation、Permit、Approval、Effect、Observation、Obligation、Protocol、Process、Object 和 Cross-run Dependency。Manifest 固定 Root Set、Edge-set Hash、Visited Identity-set Hash 和 Journal Index Proof 或较低 Completeness Level。

### 7.6 Archive Job、Copy 与 Replica Policy

`archive-job/<job_id>` 拥有一次 Archive Workflow；`archive-copy/<copy_id>` 拥有一个物理 Copy 的 Identity、Residency、Verification Assessment 和 Deletion History。Summary 和 `ARCHIVED_VERIFIED` 都是 Projection。

Archive 流程：

1. 冻结 Package/Artifact Hash；
2. Materialize Staging，Flush/Close；
3. Fresh-reader 验证 Staging；
4. 传输 Final Cold Store；
5. 从 Final Location 重新打开；
6. 验证 Semantic/Container Hash、Signature 和 Trust；
7. 创建 Copy Assessment，提交 Job Completed。

Hot Eviction 前必须有满足 Replica Count、Fault Domain、Region、Provider、Administrative Domain、Key Domain 和 Verification Age 的 Exact Verified Copy Set，且 Eviction 后仍满足 Policy。

Bundle 不自动替代 Journal/CAS。只有保存 Exact Segment Bytes/Identity/Epoch/Chain 的 Canonical Journal Cold Tier，以及保存 Exact Ciphertext/Commitment/Envelope/Key/Attestation 并登记 Residency 的 Canonical CAS Cold Tier，才能继续承担原 Authority。

### 7.7 Retention 与 GC

Retention、Redaction 和 Crypto-erasure 不修改 Sealed Package/Bundle Bytes，只追加 Copy Residency、Object Destruction、Attestation 和 Supplement。删除最后可验证 Package Copy 会使 Current Evidence 进入 `INCOMPLETE` 或 `UNVERIFIABLE`。

每次 GC 使用 `gc-cycle/<gc_cycle_id>` 固定不可变 `GCMarkFrontier`：Signed Journal Frontier Vector、GC Epoch、Catalog Set/Versions、Hold Snapshot、Policy/Profile Hash 和 Mark Started Position。GC 只基于该 Frontier 扫描 Hot/Cold Journal Index、Package/Supplement、Migration Workspace/Production Migration Control、Foreign/Archive/Cross-run Catalog、Legal Hold、Backup/Restore/Read Lease。任一 Required Catalog 不可读、Coverage 不可证明或 Frontier 不一致时 Fail Closed；Projection Refcount 和最终一致 LIST 不得授权删除。

扫描期间的新 Object Reference 必须通过当前/后继 GC Epoch 的 `ReferenceAdmissionLease` 保护：Referencing Frame Durable 后成为 Post-frontier Root；未提交则保持受 Lease 保护的 Orphan Candidate。Sweep 只能选择在固定 Mark Frontier 不可达、没有 In-flight/Post-frontier/Read/Backup/Hold/Restore Reference，且经过 Sweep-time Fresh Recheck 的对象。Supplement、Archive Copy、Rebuild、Migration 和 Foreign Import 的引用都必须进入同一 Root/Catalog Contract。

Production Delete、Crypto-erasure 和 Hot Eviction 由独立 `retention-operation/<operation_id>` 状态机拥有，不是普通 Phase Step：

```text
PROPOSED → ASSESSED → APPROVED → FENCED → EXECUTING
         → RECONCILING → VERIFIED → COMPLETED
         ↘ ABORTED | FAILED_UNKNOWN
```

Operation 冻结稳定 Command ID/Request Hash、Exact Object/Copy/Segment Set、GC Mark Frontier、Replica/Legal Hold/Backup/Key/Evidence Assessment、审批 Quorum、Deadline 和 Rollback/Recovery Policy。实际删除前重新验证全部 Gate；每个物理结果追加 Receipt。ACK 丢失或删除结果不明进入 `RECONCILING/FAILED_UNKNOWN`，不得重复猜测执行。Hot Eviction、最后副本删除和 Crypto-erasure 必须是不同 Operation/Approval。Phase 5 只实现 Dry-run/State Machine；任何 Production Execution 需要独立不可逆维护授权。

### 7.8 Encryption 与 Trust

Object Identity 分离为 Semantic Content ID、Private Plaintext Commitment、Ciphertext Object ID、Encryption Envelope ID 和 Auth Tag。Sensitive Content 不使用公开 Plaintext Hash；Commitment Key 与 DEK/KEK 分离。

KEK Rewrap 不改变 Ciphertext 或 Semantic Identity；Re-encryption 创建新 Ciphertext ID，并以 Signed Alias 绑定原 Semantic ID。Crypto-erasure 后保留 Envelope/Commitment/Classification/Attestation，但不再承诺 Plaintext Replay。

Seal Trust 分别报告：

```text
valid_at_seal_time
currently_trusted
revoked_or_compromised_after_seal
historical_validity_indeterminate
```

Trust Package 固定 Policy、Certificate/Key Chain、Trusted Timestamp、OCSP/CRL/Transparency Material。后续 Compromise 不改原 Seal，通过新 Assessment/Supplement 降低 Current Audit。

### 7.9 Replay、Restore、Import 与 Migration

Replay 模式：

- `replay-original`：业务事实只重放到原 T；验证并呈现原 Assessment，但不重新生成 Assessment；
- `replay-current-audit`：原 Bundle + Accepted Supplements，计算当前 Audit；
- `verify-only`：验证 Signature/Trust/Hash/Frontier/Completeness/Causation；
- `inspect`：按 Authorization/Classification 只读查看。

Replay 必须禁用 Network、Provider、MCP、Git Push、Publication、External Filesystem Mutation、New Effect Admission 和 Live Journal Position。Recorded Effect 是 Evidence，不是重发指令。

Replay 禁用必须采用两层边界：应用层只注入 Read-only Replay Capability，不加载 Live Adapter；执行层通过可识别、可配置、可资格认证的 `ReplayIsolationProvider` 强制 Network/External-write/Subprocess/Privilege Policy。普通 Python Monkeypatch、环境变量清理或普通子进程只能声明 `APPLICATION_GUARDED_ZERO_EFFECT`，不能证明 OS 隔离。

只有 Container/VM/App Sandbox/OS Policy 等 Provider 通过 Capability Probe、Escape/adversarial Test 和平台 Profile 认证后，才可声明 `ENFORCED_SANDBOX_ZERO_EFFECT`。没有合格 Provider 时 Replay 仍可用于受控验证，但 Bundle/Report 必须降级 Capability，且不得把“未观察到外部调用”写成“OS 阻止了所有外部调用”。Recorded Effect 始终只是 Evidence，不是重发指令。

Temporary Rehydration 使用隔离 Disposable Projection，不写 Live Journal。Canonical Disaster Recovery 验证 Identity/Epoch/Segment Chain/Writer Authority；无法安全恢复原 Epoch 时创建新 Epoch Recovery Genesis。Foreign Bundle 进入 `foreign/<installation>/<run_id>`，不得覆盖本地事实。

迁移术语只有两个且不得混用：`MigrationWorkspaceRoot` 是物理隔离、Non-authoritative 的导入/转换工作区；`ProductionMigrationControlStream` 是 Production Journal 内保存已验证 Import Provenance、Conversion Outcome 和 Migration Frontier 的控制 Stream。Workspace Bytes 不能直接成为权威 Event。

Legacy Migration 始终通过 `ProductionMigrationControlStream` 在迁移时提交新 `MigratedFactRecorded` 或 `ImportedLegacyFact`，使用新 Event ID/Position/Committed Time，并保存 Historical Effective Time、Source Provenance、Workspace Manifest Hash 和 Confidence；不得伪装成原运行时 Native Event。

### 7.10 Evidence Supplement

Supplement 使用 Body → Assessment → Signature → Record Hash 的无循环结构，并由 Evidence Stream CAS 串行接受。Canonical Supplement Body 包含 Base Seal、Previous Supplement Record Hash、Coverage Frontier、Late Facts、Dependency Refs 和 Proposed Audit Conclusion，但排除 Assessment、Signature 和所有 Self-hash 字段；`supplement_body_hash` 只覆盖 Body。Assessment 绑定 Body Hash。Signature 绑定 Domain Separator、Body Hash、Assessment Hash、Base Seal Hash 和 Previous Record Hash。`supplement_record_hash` 覆盖 Canonical Body、Assessment Reference 和 Signature，但排除自身字段；下一 Supplement 引用该 Record Hash。Current Audit 只由 Evidence Stream 中按 CAS 顺序接受、验签且 Assessment 有效的 Supplement Chain 派生，不能直接相信 Supplement 自报状态。Late Evidence 可以把 Current Audit 从 Verified 改为 Incomplete、Contradicted 或 Unverifiable，但不改 Business Terminal、Original Seal、Original Assessment 或 Archive Residency。

## 8. 物理存储与运行

### 8.1 单机目录与 Writer

推荐：

```text
data/
  journal/v1/epochs/<epoch>/{active,sealed,indexes,quarantine,recovery}
  cas/v1/{staging,objects,quarantine,lost+found,gc}
  projections/{hot.sqlite,shadow,quarantine}
  evidence/{staging,packages}
  archive/{staging,indexes}
  recovery/
  emergency/
```

Canonical Journal/CAS 必须位于支持 Atomic No-replace、File/Directory `fsync`、Kernel Lock 和稳定 Crash Recovery 的本地文件系统；禁止 NFS、SMB、同步云盘和语义不明的 FUSE。

Writer 必须持有固定 Inode、No-follow 打开的 Kernel Exclusive Lock，贯穿 Recovery/Append/Truncate/Rollover。不得按 PID 或时间抢锁。`writer_generation` 只补充诊断，不能代替 Kernel Lock。

### 8.2 Transaction Frame 与 Commit

Frame 包含 Format、Transaction/Command/Request Hash、Stream、Event Count、Position/Stream Version Summaries、Canonical Event Bytes、CRC、Transaction Hash 和 Footer Magic。Frame 不跨 Segment，只包含一个 Stream。

Frame Committed 的条件：

- 已知成功的 Durability Barrier 覆盖其 Ending Byte Offset；或
- Recovery 把它纳入最长物理连续、结构/Hash 有效的 Frame Prefix，并在开放服务前重新 Sync 该 Prefix。

CRC/Hash 不证明崩溃前 `fsync` 成功。Group Sync 前冻结 `group_end_offset`；只有 Ending Offset 不超过该边界的完整 Frame 可以 ACK。

`write/fsync` 失败或结果未知时，无受影响 Transaction ACK，当前 Writer Poison，停止 Append/Seal，并重新执行 Recovery。

### 8.3 Segment Seal

`segment_hash` 覆盖 Exact Header、Frames 和将自身 Hash 字段省略或置零的 Canonical Footer。`.sidx` 是绑定 Segment Hash 的可重建缓存，不进入 Canonical Chain Hash。

Rollover 顺序为 Group Durability → Footer/Sync → No-replace Rename Active→Sealed → Sync 两目录 → O_EXCL 创建新 Active Temp/Header/Sync → No-replace Publish/Dir Sync。Sealed Segment 永不原地修改。

### 8.4 CAS No-replace 与 GC Fence

本地 Publication 使用平台原子 No-replace Primitive，如 macOS `renamex_np(RENAME_EXCL)`、Linux `renameat2(RENAME_NOREPLACE)` 或同文件系统 `linkat`。目标已存在时必须 Fresh-read 精确验证；不同 Bytes/Identity/Profile 是 Integrity Incident。

Object Reference Admission 与 GC 共享 Per-object/GC-epoch Fence 和 Durable In-flight Reference Lease，持有到 Referencing Frame Durable。GC Cycle 固定 Mark Frontier 和 Catalog Snapshot 后，只隔离其 Candidate Set；新 Admission 必须进入后继 Epoch/Post-frontier Root，不得被当前 Sweep 捕获。Quarantine/Retention Operation 在每个不可逆动作前再次检查 Committed/In-flight/Post-frontier/Read/Backup/Hold/Restore References。

### 8.5 SQLite Projection

建议 `WAL`、`synchronous=NORMAL`、Foreign Keys、Busy Timeout、Trusted Schema Off。`NORMAL` 只适用于可重建 Projection，不适用于 Journal。

SQLite Cache Miss 表示 `UNKNOWN`，不表示权威不存在。Writer 只有通过完整 Hot/Cold Journal 扫描，或具有无 False-negative Coverage 的 Journal-derived Lookup，才能作 Absence 判定。Cold Material 不可用时 Append Fail Closed。

Projection Batch 中 Semantic Rows 和 Offset/Frontier 同一事务更新。多 Journal Projector 使用 Frontier Vector；不能原子推进时拆为独立 Projector，并用 Coherent-cut Proof 组合。

### 8.6 Outbox、Process 与 Timer

Outbox Row 只表示候选。Dispatcher 必须提交权威 Claim/Consume Command，并等待 Committed Event 后派发。Process Manager 对相同 Source Event 生成稳定 Step Key 和 Command ID。

Deadline 持久化为 Canonical UTC + Clock Profile/Uncertainty；进程内等待使用 Monotonic Clock。Authoritative Expire/Revoke/Takeover 前重新读取批准 Wall Clock 并重验 Generation/Fence。Clock Uncertainty 超 Policy 时宁可延迟，不故意提前。

### 8.7 Backpressure 与 Emergency Capacity

Admission Class：Optional、Ordinary、Required、Closure、Observation、Recovery、Emergency。Load Shedding 先拒 Optional 和普通新 Effect，保留 Receipt、Authenticated Observation、Reconciliation、Compensation、Cancellation、Closing、Checkpoint、Terminal、Evidence Integrity 和 Recovery。

Emergency Capacity 独立预留，普通业务不得使用。Ingress ACK 严格区分：

- **`DURABLY_RECEIVED`：** 独立 Durable Ingress Spool 已持久接管原始输入/Hash；只证明 Custody，不证明 Schema、Authorization、Idempotency 或业务 Admission。Spool 不是业务 Authority。
- **`JOURNAL_ADMITTED`：** Canonical Journal 已提交 Intake/Command Admission 或确定性 Rejection Fact；只有此状态进入权威历史，后续再按 Command Outcome 契约返回业务结果。

Spool Record 必须以稳定 Intake ID 排空为 Journal Command，并在 Journal `IngressAdmitted/IngressRejected` 终局后才可确认清理。重复排空使用同一 ID/Hash。两者均不可用时停止 Writer/Outbound Dispatcher，返回无 Custody/Acceptance Receipt 的 Retryable Failure并触发 Critical Incident。任何 API 不得把 `DURABLY_RECEIVED` 命名或解释为业务 `Accepted`。

### 8.8 Recovery、RPO 与 Backup

Recovery 验证 Genesis、Identity、Epoch、Sealed Chain 和 Active Frames；只截断未完成 Active Tail；Mid-file/Sealed Corruption、双 Active、Identity/Fence/Prefix 不确定时拒绝普通启动。

默认单机 Durability Profile 为 `MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1`：在经过能力探测的本地 APFS 上使用 File/Directory `fsync`，只声明 Process/OS Crash Contract，不声明断电 RPO=0。

只有另行资格认证的 `MACOS_APFS_FULLFSYNC_POWERLOSS_QUALIFIED_V1` 才可声明指定硬件/OS/APFS/存储栈内的 Power-loss RPO=0。该 Profile 要求对 Frame/CAS/Segment 数据执行并验证 `F_FULLFSYNC` 或平台等价持久屏障、完成所需目录元数据同步、记录 Device/Filesystem Cache Contract，并通过真实断电/故障注入和 Restore Qualification。能力不可用、返回不确定或硬件/Profile 不匹配时降级为 Process/OS Crash Profile，AppendReceipt 必须携带实际 Profile，禁止默认声称 Power-loss RPO=0。

任何 RPO=0 声明都不覆盖介质毁损、Key Loss、相关故障域或 Site Loss，除非有同步复制 Authority ACK 同一 Frontier。

Canonical Backup 先固定 Journal/Frontier Vector 并创建 Backup/GC Hold，完成 Group Durability，强制 Rollover或冻结 Active Exact Prefix，再复制 Genesis/Segments/Prefix 和所有可达 CAS/Key/Attestation/Hold/Recovery Material；隔离 Restore 验证通过后才释放 Hold。

### 8.9 PostgreSQL、多 Worker 与远端对象存储

PostgreSQL 初始必须使用 `SERIAL_APPEND_COORDINATOR + POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`：Append Transaction 先获取 Transaction-scoped Exclusive Coordinator Lock，取得后重验 Idempotency/Stream Head，然后 `SELECT ... FOR UPDATE` 读取并更新单行 Transactional Position Counter。Event Insert、Stream Head、Command Binding 和 Counter Update 位于同一事务；Rollback 同时回滚 Counter，因此 Committed Prefix 无 Gap。不得使用 SQL Sequence 分配初始权威 Position。

未来 `COMMITTED_PREFIX_WATERMARK`/独立 Reservation Profile 不属于初始 Phase 7；若需要，必须先批准完整协议，包含独立持久 Reservation Transaction、Allocator Identity、Fencing Token、Lease/Timeout、Recovery、Abandonment Proof、Published Watermark 和 Replay/Rebuild 语义。没有该协议时，任何 Gap 都是 Corruption/Incomplete Evidence。

Queue/Notification 只负责唤醒；Consumer 从 Canonical Position/Frontier 恢复。Remote Object Store 必须提供 Atomic Conditional Create-if-absent 和 Direct Read-after-success；否则使用 Transactional Metadata Authority 或 Immutable Version Indirection。不得只信 ETag、Range Sample 或 LIST。

### 8.9A Backend Authority Handoff

Local Journal→PostgreSQL、Local CAS→Remote CAS 或任何 Authority Backend 替换都使用独立 `backend-handoff/<handoff_id>` 协议，禁止独立 Dual-write 同一事实。流程固定为：

1. Current Backend 提交 `BackendHandoffPrepared`，冻结 stable Handoff Command ID/Hash、Source Authority Epoch、Source Frontier、Target Genesis/Profile 和 Copy Manifest；停止新业务 Admission，Current Backend 仍是唯一已证明 Authority。
2. Target 以 Read-only Candidate 导入/验证 Exact Event/Object/Hash/Stream Version/Frontier；不能接受新权威写入。
3. Current Backend 以最后一个权威 Event 提交 `BackendAuthorityReleased`，绑定 Target Candidate Proof。此后 Source Writer 永久 Fence；ACK Unknown 时只能查询 Source，不得恢复写入。
4. Target 验证 Release Proof 后，以相同 Handoff Identity 原子提交 `BackendAuthorityAccepted`/新 Authority Epoch；只有 Target-derived Outcome `COMMITTED` 后才允许新写入。Target ACK Unknown 时双方保持 No-writer 并查询恢复。
5. `BackendHandoffVerified` 在 Conformance、Rebuild、Lost-ACK、Reader 和 Backup/Restore Gate 全部通过后提交。Reader 回退不改变 Writer Authority。

CAS Authority Transfer 使用同一 Control Protocol；Staging 期间允许复制不可变 Bytes，但新 CAS Reference Admission 只能由当前已证明 CAS Authority 接受。Source Release 后失败只能 Forward Activate Target、选择另一个 Recovery Target 或建立 Recovery Epoch，不能重新开启 Source Writer。

### 8.10 Writer Lock 与 Maintenance Operational Contract

Canonical Writer Lock 使用固定路径和固定 Inode，No-follow 打开并持有 Kernel Exclusive Lock；Crash 后由 Kernel 释放 Descriptor Lock。禁止删除、替换或按 PID/mtime/Lease Age 抢占 Lock File。检测 Lock Inode 替换、Descriptor 丢失、更高 Writer Generation、两个可写 Active Segment或 Writer Authority 不确定时必须 Fail Closed。

Maintenance 使用三个明确模式：

- **ONLINE_READ：** Verifier、Inspection 和 Backup 不竞争长期 Writer Exclusive Lock；获取固定 Frontier 和 Read/Backup/GC Hold，只读 Sealed Segment 或冻结 Active Prefix。
- **PROJECTION_EXCLUSIVE：** Shadow Rebuild、Reader Generation Switch 和 Projection Maintenance 使用独立 Projection Coordinator Lock，不停止 Canonical Writer。
- **CANONICAL_EXCLUSIVE：** Recovery Truncation、Epoch Transition、Canonical Restore 或 Authority-changing Maintenance 先停止新 Admission 和 Outbound Dispatch，Drain Writer 并正常释放 Lock，然后 Maintenance 获取同一 Canonical Writer Lock。

Archiver 只读取固定 Bundle Artifact 和 Copy Material，不得获取 Writer Authority 或修改 Package。Migration Shadow Writer 只能写非权威 Shadow Journal Namespace。Break-glass 不得偷锁：必须证明旧 Writer 已停止，记录 Authorization/Assessment，并在 Continuity 不确定时创建新 Epoch。Read-only 工具使用 Frontier/Hold，而不是让长期 Writer 与 Shared Lock 互相阻塞。

### 8.11 Capacity Envelope 与 Performance Qualification

Capacity 分为**规范性安全硬限制**和**经基准验证的 Capacity Profile**。安全限制必须在实现前固定并版本化，至少包含：

```text
max_command_envelope_bytes
max_inline_event_payload_bytes
max_canonical_event_bytes
max_events_per_transaction
max_frame_bytes
max_group_wait_ms
max_group_transactions
segment_target_bytes
segment_hard_limit_bytes
max_cas_object_bytes
max_decompression_ratio
max_schema_depth
```

初始建议值仅作为待验证 Default：Inline Event ≤ 64 KiB、Transaction Event Count ≤ 64、Group Commit Wait ≤ 5 ms、Segment Target 256 MiB。实现 Benchmark 可以收紧或调整这些值，但不得在无版本升级时突破 Hard Parser/Memory Limit。

性能和容量不得在未测量时宣称 Supported SLO。版本化 `capacity_profile` 至少记录：

```text
capacity_profile_id
qualification_status
hardware_profile
filesystem_and_durability_profile
encryption_and_key_profile
payload_distribution
concurrency_profile
commands_per_second
events_per_second
append_ack_p50_p95_p99
projection_lag_p95_p99
writer_recovery_rto
projection_rebuild_rto
journal_daily_growth_budget
cas_daily_growth_budget
emergency_capacity_baseline
disk_gate_profile
measured_at
```

在完成 Load/Crash/Restore/Soak Qualification 前，`qualification_status=NOT_YET_QUALIFIED`；参考的 2–10 Active Runs、每 Run 5–30 Registered Agents 只是 Benchmark Target，不是已支持容量承诺。

Disk Gate 同时使用 Usage Percent、Absolute Free Bytes/Inodes、Write Growth Rate、Active Segment Rollover Headroom、Maximum Staging Object、Emergency Reserve 和 Archive Backlog；以最严格结果决定 `NORMAL`、`WARNING`、`ORDINARY_ADMISSION_BLOCKED`、`LARGE_OBJECT_BLOCKED`、`EMERGENCY_ONLY` 或 `CRITICAL_EXHAUSTED`。80%/90%/95% 仅为初始百分比输入，不得取代绝对空间条件。

### 8.12 Key Management Profile

初始单机 Profile 为 `MACOS_KEYCHAIN_LOCAL_V1`，但 Key Provider 接口必须可替换为 KMS、HSM 或隔离 Key Service。Key Purpose 和 Capability 必须分离：

```text
External API Credential
Object DEK
Object KEK
Tenant Commitment Key
Journal Auth Key
Authority Control Signing Key
Evidence Signing Key
Verifier Identity Key
Trust/Timestamp Verification Material
```

Key ID 必须绑定 Purpose、Provider、Environment、Version 和 Algorithm Profile。Development、Test 和 Production Namespace 完全隔离。Runtime Writer 只能获得当前 Journal Auth Capability，不能获得 Evidence/Authority Signing Capability；Builder 无 Signing Key；Verifier 只持 Read-only Verification/Identity Capability；Sealer 只基于 Exact Core Hash 和 PASSED Assessment 使用 Evidence Signing Capability。Authority Control Signing、Journal Event Auth、Archive/Evidence Seal Signing 使用不同 Key Purpose 和访问主体。

Rotation、Rewrap、Re-encryption、Commitment Rotation、Journal Auth Rotation、Revocation、Compromise、Temporary Unavailability、Permanent Loss 和 Destruction 都必须使用不同状态和 Audit Fact。KEK Rewrap 不改变 Semantic Identity；Commitment/Journal Auth Key Rotation 保留旧验证材料或追加受信 Conversion/Destruction Attestation。Crypto-erasure 销毁 Per-object/Narrow-group DEK 或 Sole Wrapping，并生成可验证 Destruction Attestation。

Backup 默认保存 Wrapped Envelopes、Escrow/Recovery References、Public Trust/Timestamp Material 和 Attestations，不把 Plaintext Key 放入普通 Backup。Key Loss 必须使相关 Evidence 降级为 Incomplete/Unverifiable；不得静默生成新 Key 假装恢复历史。Python Memory Zeroization 不作保证，单机 Profile 不声称抵抗 OS Administrator。

### 8.13 Schema Evolution

版本维度包括 Segment/Frame、Event Envelope、Payload Schema、Projection Schema、Projector Semantic Version、Canonicalization 和 Upcaster Chain。Committed Bytes 永不修改；Upcaster 只在内存中纯确定解释；Unknown Major Version Fail Closed；修正追加新 Event。

Projection Migration 使用 Shadow DB、固定 First Frontier、Semantic Checksum/Read Comparison、追平 Second Frontier、Atomic Reader Generation Switch 和 Reader Lease 回收。Checksum 只在相同 Semantic Model/Profile/Upcaster Scope 下比较。

## 9. Legacy Compatibility and Cutover Architecture

### 9.1 当前 Legacy Source Map

当前 Sitina 是多表示系统，而不是可直接提升为 Canonical Journal 的实现：

- `data/sitina.db` 保存 Run、Event、Audit、Artifact、Approval、Risk Scan、Memory、Provider Health 等有效读模型；
- `logs/events/*.jsonl`、`logs/runs/<run_id>.jsonl` 和 `logs/audit/*.jsonl` 是分别写入的日志副本；
- `state/run_state.json`、`state/leases.json`、`state/handoffs.json`、`state/side_effects.json`、`state/run_controls/*` 和 Blackboard 文件是不同协议的 Mutable State；
- `artifacts/checkpoints`、Run Manifest、Replay Snapshot、Task Graph 和 Report 是独立写入的文件 Artifact；
- 现有 Evidence Bundle 是 Hash-verified Compatibility Export，不是 B+ Package/Assessment/Seal。

这些表示可能重复同一逻辑事实或在 Crash 后部分完成，不能逐 Row/逐文件全部导入为独立 Native Event。

### 9.2 Cutover 阶段

Readiness 进度与 Authority Operation 必须分开显示；Readiness Stage 不驱动 Writer：

```text
Readiness (Production remains independently resolved):
LEGACY_ACTIVE_PROVEN
→ SHADOW_JOURNAL
→ JOURNAL_FIRST_SHADOW_READ
→ DUAL_READ_VALIDATION
→ CUTOVER_TOOLING_READY

Authorized operation:
LEGACY_ACTIVE_PROVEN
→ SNAPSHOT_FENCED_NO_WRITER
→ CUTOVER_PREPARED_NO_WRITER
  ├─ pre-submit verified abort → LEGACY_ACTIVE_PROVEN
  └─ submit stable Cutover Command
       ├─ outcome unproven → CUTOVER_OUTCOME_UNKNOWN_NO_WRITER
       └─ committed outcome → JOURNAL_AUTHORITY_PROVEN
                              → LEGACY_RETAINED_READ_ONLY
                              → CUTOVER_VERIFIED
```

- **LEGACY_ACTIVE_PROVEN：** Authority Resolver 已验证当前 Legacy Fence Control Record 和 Cutover Absence Proof，Legacy Writer 是唯一 Authority；New Journal 不接受权威业务写入。
- **SNAPSHOT_FENCED_NO_WRITER：** 通过全局 Legacy Writer Fence 暂停所有写入并固定 DB/JSONL/State/Artifact Cutoff；这是运维进度标签，`AuthorityResolver` 返回 `CUTOVER_PREPARED_NO_WRITER`。只有在 Cutover Command 从未提交且有权威 Absence Proof 时，显式 `ResumeLegacyAfterSnapshot` Control Outcome 才可回到 `LEGACY_ACTIVE_PROVEN`。
- **SHADOW_JOURNAL：** 导入或镜像到独立、显式标记为 Non-authoritative 的 Journal Namespace；Shadow Event 不驱动真实 Effect、Approval、Timer 或 Terminal。
- **JOURNAL_FIRST_SHADOW_READ：** 在测试/受控范围运行 Command→Journal→Projection；Production Authority 仍由 `AuthorityResolver` 独立解析，Readiness Stage 不参与 Writer 选择。
- **DUAL_READ_VALIDATION：** 在固定 Frontier、Semantic Model 和 Canonicalization Profile 下比较 Legacy Read 与 Shadow Projection；Mismatch 阻止 Cutover，或被分类为有 Provenance/Reason 的 `legacy_incomplete`，不得静默忽略。
- **CUTOVER_TOOLING_READY：** Phase 6A 在隔离环境完成工具、模拟和 Readiness Report；Production 仍按 `LEGACY_ACTIVE_PROVEN` 运行，不表示维护条件已满足。
- **CUTOVER_PREPARED_NO_WRITER：** Phase 6B 已验证稳定 Cutover Intent/Command Identity、取得 Maintenance Fence，且在提交前继续冻结 Production Genesis、Snapshot/Import Frontier 等输入；Journal 尚未得到 Committed Outcome，双方都不接受业务。在 Cutover Command 从未提交且已形成权威 Absence Proof 时，只能通过显式 `AbortCutoverPreparation/ResumeLegacyAfterCutoverPreparation` Outcome 报废该 Command/Manifest 后恢复 Legacy；一旦提交或提交结果无法证明，就不得恢复。
- **CUTOVER_OUTCOME_UNKNOWN_NO_WRITER：** ACK/Coverage/Recovery 不足以证明 Outcome；只允许相同 Command Query/Recovery。
- **JOURNAL_AUTHORITY_PROVEN：** Journal-derived Lookup 证明绑定 Cutover Command `COMMITTED`；New Journal 是唯一 Writer，Legacy 永久 Fence。
- **LEGACY_RETAINED_READ_ONLY：** 旧 SQLite、JSONL、Ledger、Audit、Checkpoint、Manifest、Replay Snapshot、Blackboard 和 Evidence 保持只读，供验证、Provenance 和有限 Reader Rollback。
- **CUTOVER_VERIFIED：** 权威 Journal 已提交 `CutoverVerified` Event/Command Outcome，绑定 Journal+CAS-only Rebuild、零外部 Replay、Dual-read Diff、Command Outcome/Idempotency、Writer Fence、Legacy Dispatch Disabled、Audit/Evidence/Secret 和 Backup/Restore Proof。工具返回成功或 Phase 标记不能替代该 Event。

Frozen SQLite Snapshot 必须先在 Writer Fence 下通过 SQLite Backup API 或一致物理 DB+WAL Capture 生成 Staging Snapshot，再完成 WAL 内容收敛/回放、`integrity_check`、关闭所有连接、File/Directory Durability 和 Hash。只有经验证不再依赖外部 `-wal/-shm` 的独立 Snapshot DB 才能以 `immutable=1` 打开。`immutable=1` 永远不得直接用于 Live WAL Database，也不得被当作自动合并 WAL 的机制。

### 9.3 Legacy Fact Classification

迁移前必须建立版本化 Source Matrix：

- `run_ledger` Row：Coordination Fact Candidate；
- 非 Ledger Event：Supplementary Legacy Fact/Assertion；
- `audit_log`：Audit Representation，不是同一业务事实的第二 Event；
- Mutable JSON Snapshot：用于状态一致性验证，不用于补造缺失历史；
- Daily/Per-run JSONL：带 File/Line Provenance 的 Legacy Copy；
- Checkpoint、Manifest、Replay Snapshot 和 Evidence Bundle：Legacy Evidence Artifact，不是 Native Runtime Event。

每个 Imported Record 必须记录 Source Installation、DB/File/Table、Row/Line Identity、Original ID/Hash、Snapshot Hash、Historical Effective Time、Migration Commit Time、Conversion Rule Hash、Confidence 和 Completeness Reason。重复或冲突 Legacy ID 不得作为新 Canonical Identity。

能够证明的旧事实也必须在迁移时提交新的 `MigratedFactRecorded`；不完整记录使用 `ImportedLegacyFact` 或 `legacy_incomplete`，不得伪装成原运行时 Native Event，不得从最终 Projection 反造缺失 Causation、Actor、Timestamp、Payload 或 Stream History。

### 9.4 Authority Cutover 与 Rollback

Cutover 前可以回退 Shadow Reader、Importer 或非权威 Journal。`Backend/Authority Phase` 不决定 Writer；所有路径先调用 2.5 `AuthorityResolver`。Journal-derived Cutover Outcome `COMMITTED` 后，旧 Writer永久只读；“Rollback”只能：

- 切换到旧 Reader Generation；
- 回退应用 Binary，但继续遵循 New Journal Append Contract；
- Forward Fix；
- 在 Canonical Continuity 不可恢复时建立新 Recovery Epoch。

Cutover Command 必须使用预先冻结的稳定 `command_id + request_hash`，绑定 Frozen Legacy Snapshot、Production Journal Genesis、Pre-cutover Frontier、`ProductionMigrationControlStream` Frontier、Code/Config/Policy/Key/Profile、Reader Generation、Operator Authorization 和 Effect Drain/Monitoring Transfer Proof。Cutover ACK 丢失时只能 Recovery 后查询同一 Command；在既未证明 `COMMITTED`、也未形成权威 Absence Proof 前，Authority Resolver 返回 `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER`，不得恢复 Legacy Writer、创建新 Cutover Command 或切换 Authority。

正式操作顺序固定为：停止 Admission/Outbound Dispatch → 结算或转移 Effect/Monitoring → 获取全量 Legacy Writer Fence → 生成 Frozen Coherent Snapshot → 执行并验证 Legacy Import → 固定 Production Pre-cutover Frontier → 提交 Cutover Command → 查询并确认 Committed → 永久 Fence Legacy → 启用 Journal-first 内部路径。Shadow Journal 不参与 Authority Promotion。

Legacy Reader 回退只允许诊断、历史查询或明确标记 `as_of_cutover_frontier` 的兼容 Endpoint。它不得为 Cutover 后 Command、Approval、Effect、Scheduling、Closing 或 Terminal Decision 提供前置条件。真实外部能力必须在 Cutover 后按 `MOCK_ONLY → EXTERNAL_READ → REVERSIBLE_MUTATION → HIGH_RISK_OR_IRREVERSIBLE` 分级启用，每一级独立授权和验收。

`CutoverVerified` 使用稳定 Verification Command，只有当 `AuthorityResolver=JOURNAL_WRITER_AUTHORIZED`、Cutover Command/Outcome 可验证、Writer Fence Proof 和 Legacy Dispatch Disabled Proof 已进入 Operational-control Stream、Journal+CAS-only Rebuild 与所有 Required Gate 通过时才能提交。Phase 6B Exit Gate 必须查询到该 Command `COMMITTED` 和精确 Event Ref；Report/CLI Exit Code 不足以退出。

Cutover 后不得重新启用 Legacy SQLite/JSON/JSONL Writer，不得独立 Dual-write 同一业务事实。在 `CUTOVER_VERIFIED` 完成且 Legacy Retention/Legal Hold Policy 允许前，不得删除旧 SQLite、Ledger、Audit、Checkpoint、Manifest、Replay Snapshot、Blackboard 或 Evidence。未通过 Journal+CAS-only Rebuild 前不得进入 `CUTOVER_VERIFIED`；未通过 Final Cold Copy Restore Drill 前不得启用 Automatic Hot Eviction。

## 10. 安全与威胁假设

- 原始 Secret 不进入 Journal、Projection、Receipt、Metric、Report 或长期普通 CAS。
- 所有 External Input、Observation、Tool Result 和 Foreign Bundle 默认不可信，必须验证 Identity、Signature、Schema、Replay、Classification 和 Trust Policy。
- 任何同 Identity 不同 Hash、同 Command 不同 Request、同 CAS Path 不同 Bytes 都是 Integrity/Security Incident。
- Corrupt Committed Material、Missing Required Object、Invalid Signature/Trust、Unverifiable Frontier 或 Broken Causation 均 Fail Closed。
- Quarantine Domain 按 Intake Security、Unauthenticated Observation、Secret Content、Integrity Corruption、Import Collision、Migration Conflict、Key Failure 和 Archive Corruption 分隔权限。
- Manual Reconciliation 只能选择可信恢复来源、确认永久缺失、接受风险或创建 Incident/Successor，不得伪造 Event、覆盖 Collision 或把 Assertion 宣称为 Cryptographic Proof。

## 11. 验证与验收

实现必须通过以下类别：

1. **Execution Foundation：** 固定 Runtime/Dependency、Source-only Change Audit、隔离 Test Home、Production Sentinel 不变、计划来源完整性和 Legacy Behavior Baseline。
2. **Canonical/Crypto：** Canonical Serialization 稳定；语义变化破签；Container Metadata 不改 Semantic Hash；错误 Key/Nonce/Tag Fail Closed；Rotation/Erasure Attestation。
3. **Journal：** Frame/Stream Continuity、Group Recovery、Lost ACK、Torn Tail、Segment Chain、Cross-epoch、Position Gap、Idempotency Collision。
4. **CAS：** Object-before-Event、No-replace Race、Header/Auth、GC Fence、Shared References、Secret Quarantine/Destruction。
5. **Projection：** Apply+Offset Atomicity、Crash Rollback、Dead Letter、Delete SQLite/Rebuild、Shadow Migration、Multi-journal Frontier。
6. **Protocols：** Transition Matrix、Duplicate/Out-of-order Event、Task Claim/Fence、Proposal Selection、Handoff Generation、Arbitration Enforcement、Blackboard Conflict。
7. **Effects：** One Authorized Send/Attempt、Unknown/Reconciliation、Late Observation、Contradiction、Manual Policy Settlement、Compensation、Budget/Breaker/Monitoring Transfer。
8. **Terminal/Evidence：** O/P/T Coherent Cut、Every Barrier Blocker、Package Hash Layers、Assessment/Seal、Supplement Chain、Completeness Level。
9. **Archive/Recovery：** Final Cold Verification、Replica Policy、Eviction Crash Points、Canonical Backup/Restore、DR Epoch、Foreign Collision、Legacy Migration。
10. **Replay Safety：** Network/Provider/MCP/Push/Publish/External Write 全部禁用，Recorded Effect 绝不重发，并准确报告实际隔离能力等级。

任何 Required Predicate 失败必须产生明确 Reason，并阻止 Seal、Current Verified 声明或 Hot Eviction，但不得反向改写已经提交的 Business Terminal。

## 12. 实施分解原则

第一期不得同时落地所有 Stream，也不得 Big Bang 替换当前 Runtime。实施按可独立运行、可回滚 Reader、可 Crash-injection 验证的增量推进：

1. **Slice -1 — Execution Foundation：** 固定 Runtime/Dependency、隔离 Test Home、Source-only Change Audit、Execution Manifest、Legacy Behavior Baseline、Write-sink Inventory 和计划生成/校验；不改变 Runtime 语义。
2. **Slice 0 — Legacy Fence 与 Compatibility Inventory：** 全局 Legacy Writer Fence、Observational Inventory、Frozen Coherent Snapshot Tooling、Read-only Legacy Adapter、Fact Classification、Shadow Journal 和 Dual-read Harness。Legacy Writer 保持唯一 Authority。
3. **Slice 1 — Journal/CAS/Projection Kernel：** 最小 `Command → Single-stream Event → Durability → Projection → Delete/Rebuild → Lost ACK Recovery` 路径；实现 Writer Lock、Frame、CAS、Command Outcome、Operational Authority Primitives 和 Projection Offset。
4. **Slice 2 — Run/Task/Process/Scheduling：** Run Admission、Permit-to-Entity Saga、Task/Task Attempt/Claim/Fence、Process Manager、Scheduler/Dispatcher 和 Timer；形成可运行的基本协作闭环。
5. **Slice 3 — Proposal/Handoff/Arbitration：** ProposalRound、Debate/Review、Handoff、Merge/Arbitration、Rework、Obligation 和 Blackboard MVCC。
6. **Slice 4 — Effect/Observation：** Tool Gateway、Immutable Effect、Effect Attempt、Observation Admission/Application、Durable Ingress、Reconciliation、Manual Settlement、Budget/Breaker 和 Closing Permit。
7. **Slice 5 — Evidence/Archive：** B+ O/P/T V1、Package Core、Assessment、Seal、Supplement、Archive Copy、Replica/Retention/GC、Canonical Backup、Isolated Replay 和 Restore Drill。
8. **Slice 6A — Cutover Tooling & Readiness：** 只在隔离环境实现 Production Genesis、Authority Resolver、stable Cutover Command、Lost-ACK Recovery、Importer、Readiness/Dry-run 和模拟；不要求或执行 Production Freeze/Cutover。
9. **Slice 6B — Authorized Production Cutover：** 独立 Maintenance Manifest、维护窗口、Frozen Snapshot/Backup、双人授权、Import、Journal-first Switch、CutoverVerified 和 Legacy Read-only Retention；外部能力保持 `MOCK_ONLY` 并另行分级激活。
10. **Slice 7 — Scale-out：** PostgreSQL Transactional Contiguous Position、Backend Authority Handoff、Multi-worker、Remote CAS 和 B+ O/P/T V2。

每个 Slice 必须有 Feature Flag 或 Reader Generation，可在不丢失新 Journal Fact 的前提下关闭新 Reader；必须执行 Crash-injection、Lost ACK、Duplicate Command、Delete/Rebuild 和 Zero-external-effect Replay。Slice Rollback 不得重开已经被 Cutover Fence 禁止的 Legacy Writer。实际 Completeness Level 尚未达到 Evidence Policy 明确要求、Replica Policy/GC Fence 未验证、Journal+CAS-only Rebuild 未通过或 Final Cold Restore Drill 未完成时，不得启用 Automatic Hot Eviction。

## 13. 安全默认配置

以下选择不改变架构语义，默认采用安全基线，具体参数在实施计划中固定：

- Bundle：同时支持逻辑目录和 Deterministic `tar.zst`；Semantic Hash 与 Container Hash 分离。
- Canonical Serialization：UTF-8、Unicode NFC、稳定字段/集合顺序、RFC3339 UTC、禁止非规范浮点。
- Hash：SHA-256 或更强、带 Domain Separator；敏感 Plaintext 使用 Tenant-scoped Keyed Commitment。
- Encryption：每 Object 或窄组独立 DEK，AEAD；Signing Key 与 Encryption/Commitment Key 分离。
- Cross-tenant Plaintext Dedup：默认关闭。
- Ordinary Bundle：默认 HYBRID；重要 Run 和指定 Export 生成 Replay Self-contained Artifact。
- Evidence Repair：创建新 Package Generation，不重开旧 INCOMPLETE Generation。
- PostgreSQL：初始只允许 `SERIAL_APPEND_COORDINATOR + POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`；不得用 Sequence 分配权威 Position。
- Remote Object Store：不满足 Conditional Create + Direct Verify Contract 时不得成为 Canonical CAS Authority。
- Automatic Hot Eviction：默认关闭；即使 Gate 全部验证，Production Eviction/Delete/Crypto-erasure 仍需独立 `retention-operation` Command/Approval/Outcome，不能由 Phase 完成自动开启。
- Capacity Profile：初始为 `NOT_YET_QUALIFIED`；参考并发仅用于 Benchmark，不作 Supported SLO。
- Position Profile：初始单机使用 `LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1`；PostgreSQL 初始使用 `POSTGRES_TRANSACTIONAL_CONTIGUOUS_PREFIX_V1`。
- O/P/T：第一阶段使用 `BPLUS_OPT_V1_SINGLE_JOURNAL`；Multi-journal V2 后置。
- Key Provider：初始使用 `MACOS_KEYCHAIN_LOCAL_V1`；Development/Test/Production Key Namespace 分离。
- Durability：默认 `MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1`，不声明 Power-loss RPO=0；Full-fsync Profile 只有资格认证后可用。
- Replay：默认最多声明 `APPLICATION_GUARDED_ZERO_EFFECT`；只有经认证 Isolation Provider 才能声明 `ENFORCED_SANDBOX_ZERO_EFFECT`。

## 14. Normative Contract Registry

| Contract | 唯一定义/Owner | 实施阶段 | 禁止的替代解释 |
|---|---|---|---|
| Authority Writer | `AuthorityResolver` + verified Cutover/Backend Handoff Outcome | Phase 0、6A、6B、7 | Phase Enum、CLI Flag、Projection Row |
| Legacy Fence | Kernel-backed Legacy Fence Control Record | Phase 0 | 顶层布尔 Flag、PID/mtime Lease |
| Object Reference | `ObjectReferenceProof` + GC Epoch Lease + Durable Frame Root | Phase 1 | Caller 声明、SQLite Refcount |
| TaskGraph Node | `task-graph/<graph_id>` | Phase 2 | 独立 Node Stream |
| Task Execution | `task/<task_id>` bound to Graph Node | Phase 2 | Projection Task Row |
| V1 Frontier | one-component `SignedFrontierVectorV1` | Phase 5 | 裸 Position、非 Vector Head Hash |
| Ingress Custody | Durable Spool `DURABLY_RECEIVED` | Phase 4 | Business Accepted/Committed |
| Business Admission | Journal `JOURNAL_ADMITTED` + Command Outcome | Phase 1/4 | Spool Receipt |
| Migration Workspace | `MigrationWorkspaceRoot`，Non-authoritative | Phase 0/6A | Production Stream/Authority |
| Migration Control | `ProductionMigrationControlStream` | Phase 6B | Workspace File/Projection |
| GC Reachability | fixed `GCMarkFrontier` + Catalog Snapshot | Phase 1/5 | Moving Projection/LIST |
| Delete/Eviction | `retention-operation/<operation_id>` | Phase 5 tooling；独立授权执行 | 普通 Phase Step |
| Backend Authority | `backend-handoff/<handoff_id>` verified Outcome | Phase 7 | Config Switch、Dual-write |
| Replay Isolation | declared `ReplayIsolationProvider` capability | Phase 5 | Monkeypatch/普通子进程即 OS Sandbox |

任何章节、测试或实现若对同一 Contract 使用不同 Owner、状态集或证明条件，视为设计回归并阻止 Phase Exit。

## 15. 设计来源

本规范整合以下已批准的设计展示及其后续规范性修订；后出现的 Delta 在冲突处优先：

- `.superpowers/brainstorm/75633-1783877456/content/bplus-architecture-v2.html`
- `.superpowers/brainstorm/75633-1783877456/content/bplus-section1-runtime-architecture.html`
- `.superpowers/brainstorm/75633-1783877456/content/bplus-section2-envelopes-consistency.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section3-protocols-shared-state-v2.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section3-final-delta.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section4-tool-gateway-effects-security.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section4-final-delta.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section4-final-synthesis.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section4-approval-candidate.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section5-evidence-bundle-archive.html`
- `.superpowers/brainstorm/91066-1783881599/content/bplus-section5-final-delta.html`
- `.superpowers/brainstorm/97364-1783919079/content/bplus-section6-physical-storage-operations.html`
- `.superpowers/brainstorm/97364-1783919079/content/bplus-section6-final-delta.html`

## 16. 最终不变量

1. Journal 是唯一业务事实源；CAS、SQLite、Bundle 和 Archive Summary 都不能成为第二事实源。
2. 每条 Stream 是唯一事务和状态机边界；跨 Stream 只走 Event → Process Manager → Command。
3. Command 在单 Stream 内原子提交；Group Commit 只共享 `fsync`。
4. ACK 只在 Durability Barrier 后返回；未 ACK 的完整 Frame 可以在 Recovery Adopt+Sync 后成为 Committed。
5. CAS Object 永远先于引用它的 Event，Final Object 永不原地修改。
6. SQLite 只保存可重建 Projection；Cache Miss 不等于权威不存在。
7. Projection Apply 与 Offset/Frontier Advance 同事务。
8. Strong Read 等待固定 Position/Frontier，不追逐移动 Head。
9. Projection、Outbox、Timer 和 Process View 只发现候选；权威 Claim/Consume/Transition 回到 Stream。
10. Task Claim 与 Fence 在同一 Task Stream Transition 中产生。
11. Protocol Terminal 与 Obligation Satisfaction 分离。
12. Shared State 使用 MVCC、CAS、Merge 和 Arbitration，禁止 Last-write-wins。
13. 每个外部信任域访问都有 Effect；Unknown 不盲重试。
14. Observation Stream 保存认证事实，Effect Stream 唯一裁决 Outcome/Settlement。
15. Manual Resolution 可以结算责任，不能伪造远端事实。
16. Compensation 是新 Effect；不可逆 Effect 不伪造 Compensation。
17. Business Terminal、Evidence Seal 和 Archive Residency 严格分离。
18. T 只绑定 Pre-terminal Source Frontier；Evidence Record Frontier 位于 T 之后。
19. Package Core、Assessment、Seal、Bundle Container 分层 Hash，消除循环引用。
20. Bundle 不替代唯一 Journal/CAS Authority。
21. INCOMPLETE 无条件阻止 Seal、Current Verified 声明和 Hot Eviction。
22. Late Evidence 只追加 Supplement，不改旧 Terminal、Assessment 或 Seal。
23. Retention、Recovery、Migration、Trust Change 和 Crypto-erasure 只追加事实，不修改旧 Bytes。
24. Writer 使用 Kernel Lock；同一时刻最多一个本地 Writer 和一个可写 Active Segment。
25. Recovery 只截断未提交 Active Tail；Committed/Sealed Material 永不静默删除或原地修复。
26. PostgreSQL 必须显式解决 Position 与 Commit Order；Sequence 本身不足够。
27. Remote Object Store 必须通过 Sitina Digest、Header Authentication 和 AEAD 验证，不能只信 ETag。
28. Backpressure 必须为 Observation、Receipt、Closing 和 Recovery 保留容量，不得降低 Durability。
29. Replay 必须禁用外部 I/O，Recorded Effect 永远不是重发指令。
30. 所有仍按 Policy 保留且授权可读的状态必须能从 Journal、CAS、Frontier Proof、Assessment 和 Supplement Chain 离线重建并核验。
31. Legacy 与 B+ 并存期间最多一个 Authority Writer；Writer Authority 只由 `AuthorityResolver` 验证的 Control/Cutover Outcome 决定，Phase 名称不具有授权力。
32. Shadow Journal 永远标记为 Non-authoritative，不得驱动真实 Effect、Approval、Timer、Terminal 或 Evidence Seal。
33. Dual-read Comparison 必须绑定固定 Frontier 和 Semantic Profile；Mismatch 必须阻止 Cutover或形成显式、带 Provenance 的 `legacy_incomplete`，不得静默降级。
34. 在 `CUTOVER_VERIFIED` 完成且 Legacy Retention/Legal Hold Policy 允许前，不得删除旧 SQLite、JSONL、Ledger、Audit、Checkpoint、Manifest、Replay Snapshot、Blackboard 或 Evidence Material。
35. 第一个 Journal-first 权威事实产生后，Legacy Writer 永久只读；Rollback 只能切换 Reader、回退 Journal-compatible Binary、Forward Fix 或建立 Recovery Epoch。
36. 未通过 Journal+CAS-only Delete/Rebuild Drill，Cutover 不算完成；未通过 Final Cold Copy Restore Drill，Automatic Hot Eviction 必须保持关闭。
37. Capacity 与 Latency 只有在版本化 Capacity Profile 完成 Benchmark Qualification 后才能作为 Supported SLO；安全硬限制不依赖性能测试。
38. 单机 V1 和初始 PostgreSQL V1 都使用 Gap-free Committed Prefix；未来允许 Gap 的 Backend 必须先批准独立 Reservation/Allocation/Watermark Proof 协议。
39. Evidence Completeness Level 与 Self-containment Capability 正交，任何声明不得超过实际 Proof、CAS 可用性和 Dependency Closure 能力。
40. Runtime Writer、Verifier 和 Evidence Sealer 的 Key Capability 必须隔离；Key Loss、Compromise、Rotation 和 Destruction 只能追加事实，不得静默改写历史。
41. 所有默认测试必须运行在隔离 Test Home；测试触碰 Production Home 是 Gate Failure 和 Incident，不是普通测试失败。
42. 现有 Legacy 功能只能通过版本化兼容性分类被保留、显式优化或批准替换；不得在重构中静默消失。
43. Shadow/Fixture/Replay/`MigrationWorkspaceRoot` 与 Production Journal 物理身份和 Key Namespace 分离；只有 `ProductionMigrationControlStream` 保存权威迁移控制事实，Workspace 永不提升为 Authority。
44. 所有拥有独立 Stream Identity 的跨 Stream Entity 创建都使用 Create-or-Tombstone Saga；TaskGraph Node 由 TaskGraph Aggregate 独占，不建立独立 Node Stream。
45. Canonical Serialization、Frame、Hash、Encryption、Signature、Identifier 和 Clock Profile 在首个持久 Byte 前冻结并具有 Golden Vector。
46. Audit、Security Intake、Dead Letter、Projection Failure 和 Operational Control 必须由 Journal-backed Stream 拥有，不得只存在 SQLite 或日志文件。
47. Replay 的能力声明不得超过实际应用层和执行层隔离强度；Monkeypatch 不等于 OS Sandbox。
48. Cutover Lost ACK 使用同一稳定 Command 查询恢复；Authority 不确定时不得重开 Legacy 或发出第二个逻辑 Cutover。
49. Legacy Reader 回退不得参与 Cutover 后的权威决策，只能提供带 Frontier 和 Staleness 的只读兼容视图。
50. 初始 PostgreSQL 使用 Transactional Position Counter，Rollback 不消费 Position；Sequence 禁止作为权威 Position Allocator。
51. Cutover Prepared/Unknown 状态双方都无 Writer；只有相同 Cutover Command 的 Journal-derived COMMITTED Outcome 授权 Journal。
52. Journal Append 对每个 Object Ref 强制验证 `ObjectReferenceProof` 并持有 GC Epoch Lease；没有 Proof 不得写 Frame。
53. Spool `DURABLY_RECEIVED` 只证明 Custody；只有 Journal `JOURNAL_ADMITTED` 才进入权威历史。
54. V1 使用恰好一个 Component 的 Signed Frontier Vector；V2 才允许 Multi-component/Cross-journal Proof。
55. GC Mark/Sweep 绑定固定 Frontier、Catalog Snapshot 和 Epoch；移动 Projection、Refcount 或 LIST 不得授权删除。
56. Power-loss RPO=0 和 Enforced Sandbox 都是资格认证能力，默认 Profile 不得宣称。
57. Journal Auth、Authority Control Signing、Evidence Seal Signing、Object/Commitment Key Purpose 分离；历史验证材料缺失必须显式降级。
58. Phase 6A 只实现并验证工具；Phase 6B 才能在独立授权下执行 Production Cutover，并以 Committed `CutoverVerified` 为 Exit Proof。
59. Production Delete、Hot Eviction 和 Crypto-erasure 使用独立 Retention Operation、审批、Fence、Receipt 和 Lost-ACK Recovery；Phase Completion 不构成删除授权。
60. Backend Authority Handoff 禁止业务 Dual-write；Source Release 后只能激活已验证 Target 或进入 Recovery，不能恢复 Source Writer。

---

# 第二部分：实施总路线图

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-implementation-roadmap.md`  
> 来源 SHA-256：`74b6b7fe228325c63d1ef8fb010423be643b36bcdd335dd3744cc9085765a144`

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

---

# 第三部分：Phase -1 Execution Foundation

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-minus-1-execution-foundation.md`  
> 来源 SHA-256：`f9dbb1b75b55c1615c5c60e69402c56d563b967475cc3cbf792b8bf0dec55e74`

# Sitina B+ Phase -1 Execution Foundation Implementation Plan

**Goal:** 在不改变 Sitina 现有 Runtime、Legacy Authority、数据和外部行为的前提下，通过受限 Bootstrap V0 建立可复现解释器与依赖，再生成正式 Execution Manifest V1、隔离测试 Home、变更审计、执行授权契约和计划完整性工具，使后续 Phase 可以被 Codex 安全、分段、可验证地执行。

**Architecture:** Phase -1 只建立施工控制面。Production Home `~/SitinaHub` 始终只读；所有测试、Crash Injection、Fixture Run、Shadow Journal 和临时数据库必须位于一次性 Test Home。现有 Legacy 功能作为兼容性 Oracle 保留，不在本阶段重构。

**Tech Stack:** 固定 Python 3.12 Profile、Pydantic v2、经批准并锁定的密码库、标准依赖锁、`unittest` 分层 Runner、Git 或等价内容寻址变更审计、Canonical JSON Execution Manifest。

## Global Constraints

- Phase -1 不创建 Canonical Journal、CAS、Projection 或 Shadow Business Event。
- 不运行会把 `SITINA_HOME` 解析为 `~/SitinaHub` 的测试。
- 不修改、重建、Checkpoint、Vacuum 或扫描写入 Production SQLite。
- 不写 Production `logs/`、`state/`、`artifacts/`、`outputs/`、`memory/` 或 `backups/`。
- 不调用真实 Provider、MCP、Tool、Git Push、Publication 或外部 Mutation。
- 不初始化 Git，除非用户明确选择 Git 审计模式；选择前只生成 Dry-run Inventory。
- 不把 Runtime State、备份、密钥、Profile `.env` 或 Secret 加入变更审计。
- 任何 Task 完成后都必须停留在 Phase -1 授权范围；不得自动进入 Phase 0。
- `PHASE_MINUS_1_BOOTSTRAP_V0` 只允许创建 Tasks 1–3 的基础文件并计算稳定产物；V0 不要求引用尚不存在的 Python/Lock/Baseline Hash。
- Tasks 4–9、任何测试执行和所有后续 Phase 必须使用引用 Bootstrap 产物的 `EXECUTION_MANIFEST_V1`。

## Two-level bootstrap and execution manifests

### PHASE_MINUS_1_BOOTSTRAP_V0

由用户人工审阅，字段仅包含当前已存在且可直接验证的输入：

```text
bootstrap_id
authorized_phase = -1
authorized_task_range = 1..3
exact_authorized_files
production_home
bootstrap_workspace
initial_plan_suite_hash
prohibited_operations
required_stop_point = BOOTSTRAP_PROMOTION_REVIEW
approval_reference
```

V0 禁止导入/运行 Sitina Runtime、执行测试、读取 Production Mutable Data、初始化 Git、安装未列依赖或扩展 Mutation Root。它允许使用操作系统只读工具和指定 Python Binary 创建源码/锁文件、计算 Hash，并生成待人工批准的 Bootstrap Foundation Record。

### EXECUTION_MANIFEST_V1

Bootstrap Foundation Record 经人工复核后，V1 必须包含：

```text
execution_id
authorized_phase
authorized_task_range
authorized_mutation_roots
production_home
test_home
baseline_revision_or_manifest_hash
python_profile_hash
dependency_lock_hash
plan_suite_hash
prohibited_operations
required_stop_point
approval_reference
```

V1 首先授权在隔离 Test Home 中补跑 Tasks 1–3 的测试，然后才能执行 Tasks 4–9。缺失、冲突、过期或把 Production Home 作为 Test Home 时，只允许 Read-only Preflight，然后 Fail Closed。计划文件中的 Checklist 不构成授权；授权只来自当前用户会话绑定的 V0/V1 Manifest。

---

### Task 1: Execution contract and production-home guard

**Files:**
- Create: `core/sitina/runtime/execution_contract.py`
- Create: `tests/foundation/test_execution_contract.py`
- Create: `docs/bplus-execution-contract.md`

**Interfaces:**
- Produces: `BootstrapManifestV0`, `BootstrapFoundationRecord`, `ExecutionManifestV1`, `ExecutionScope`, `ProductionHomeGuard`, `assert_test_home_isolated()`.

- [ ] Implement a minimal standard-library V0 validator that accepts no self-generated hash fields and enforces exact Tasks 1–3 file scope.
- [ ] Test missing authorization fields fail closed.
- [ ] Test Production Home, its parent, symlink aliases and bind/real-path aliases cannot be Test Home.
- [ ] Test allowed mutation roots cannot contain Production `data/logs/state/artifacts`.
- [ ] Test phase/task expansion requires a new approval reference.
- [ ] Implement read-only manifest validation without modifying Production.
- [ ] Record canonical manifest hash and sanitized environment fingerprint.
- [ ] Under V0, write tests but do not execute them；execute them only after V1 promotion.

---

### Task 2: Source-only change-audit decision and baseline

**Files:**
- Modify: `.gitignore` only after source inventory and user approval
- Create: `docs/change-audit-policy.md`
- Create: `scripts/change-audit-dry-run.py`
- Test: `tests/foundation/test_change_audit.py`

**Interfaces:**
- Produces one selected mode: `GIT_SOURCE_ONLY_V1` or `CONTENT_MANIFEST_V1`.

- [ ] Inventory source/docs/tests/config schema files without reading credential values.
- [ ] Explicitly exclude Runtime data, mutable state, backups, temp files, reports, caches, `.env`, Keychain material and Secret-bearing profiles.
- [ ] In Git mode, show the exact initial add set and Secret-scan result before requesting user approval for `git init`/baseline commit.
- [ ] In Manifest mode, produce sorted path/mode/size/hash records plus previous-manifest linkage.
- [ ] Test no ignored Runtime path can enter either audit mode through symlink or path alias.
- [ ] Do not initialize Git automatically.

---

### Task 3: Reproducible Python and dependency profile

**Files:**
- Create: `pyproject.toml`
- Create: approved dependency lock file
- Create: `.python-version`
- Create: `scripts/bootstrap-bplus-dev.py`
- Create: `tests/foundation/test_runtime_profile.py`

**Interfaces:**
- Produces: `python_profile_hash`, `dependency_lock_hash`, reproducible local environment command.

- [ ] Pin Python 3.12 minor policy and reject system Python 3.9.
- [ ] Declare existing Pydantic v2 dependency and all newly approved cryptography/container dependencies.
- [ ] Keep PostgreSQL、zstandard、property/fuzz dependencies optional until their Phase is authorized.
- [ ] Record package names/versions/wheel hashes/platform/architecture.
- [ ] Test `bin/sitina` and test runner resolve the same approved Python Profile unless an explicitly validated override is supplied.
- [ ] Never copy bundled-runtime packages into the repository.

### Bootstrap promotion gate

After Tasks 1–3 files exist, stop at `BOOTSTRAP_PROMOTION_REVIEW`. Produce a `BootstrapFoundationRecord` containing Source-audit decision、Python Binary/Profile Hash、Dependency Lock Hash、Plan-suite Hash、exact changed-file manifest and Production sentinel observations. A user must approve this Record and issue `EXECUTION_MANIFEST_V1`; without it, do not run tests or continue to Task 4.

---

### Task 4: Isolated Test Home and Legacy fixture seed

**Files:**
- Create: `tests/fixtures/sitina_home_template/`
- Create: `tests/foundation/home_factory.py`
- Create: `tests/foundation/test_home_isolation.py`
- Modify: test bootstrap only; do not modify Runtime behavior

**Interfaces:**
- Produces: one disposable Test Home per test worker, derived from a versioned minimal fixture.

- [ ] Copy only non-secret config/schema/docs fixtures required by tests.
- [ ] Create fresh SQLite/JSONL/State/Artifact fixture roots under a temporary directory.
- [ ] Set `SITINA_HOME` before importing any `sitina` module.
- [ ] Test module import is rejected if `SITINA_HOME` resolves to Production.
- [ ] Record Production sentinel hashes/size/mtime before and after the entire test run; any change fails the gate.
- [ ] Ensure cleanup never follows symlinks and never targets a non-fixture directory.

---

### Task 5: Layered test runner and timeout budgets

**Files:**
- Create: `scripts/test-bplus.py`
- Create: `tests/test_suites.json`
- Modify: existing test discovery/bootstrap as needed for isolation
- Test: `tests/foundation/test_test_runner.py`

**Interfaces:**
- Produces suites:
  - `unit_fast`
  - `integration_isolated`
  - `crash_fault`
  - `legacy_readonly_observation`
  - `live_provider_opt_in`

- [ ] Every suite declares interpreter, Test Home policy, timeout, expected duration class and external-I/O policy.
- [ ] `unit_fast` and `integration_isolated` contain no Production paths.
- [ ] `legacy_readonly_observation` uses dedicated read-only adapters and never invokes `SitinaStore.init_db()`.
- [ ] `live_provider_opt_in` requires a separate current-session approval and is never part of a default Phase Gate.
- [ ] Timeout produces a diagnostic artifact and terminates child processes.
- [ ] Test count is generated from discovery; documentation must not hard-code one test class as the whole suite.

---

### Task 6: Existing-function compatibility baseline

**Files:**
- Create: `core/sitina/legacy/baseline.py`
- Create: `tests/foundation/test_legacy_baseline.py`
- Create: `artifacts/bplus/baselines/.gitkeep`

**Interfaces:**
- Produces a fixture-only `LegacyBehaviorBaseline` containing semantic outputs, not mutable Production bytes.

- [ ] Cover Run、Task Graph、Proposal、Review、Handoff、Arbitration、Blackboard、Lease、Side Effect accounting、Replay、Evidence Export and CLI exit semantics.
- [ ] Normalize timestamps, random IDs, local absolute paths and representation-only row IDs through a versioned profile.
- [ ] Preserve business dispositions, counts, hashes, approval requirements, safety decisions and external-call count.
- [ ] Classify differences as `EXPECTED_REPRESENTATION_CHANGE`, `APPROVED_SEMANTIC_CHANGE` or `REGRESSION`; only the first is automatic.
- [ ] Bind baseline to source revision/manifest, fixture hash, config/policy hash and Python Profile.

---

### Task 7: Plan-suite generator and integrity verifier

**Files:**
- Create: `docs/superpowers/build_complete_plan.py`
- Test: `tests/foundation/test_plan_suite_integrity.py`

**Interfaces:**
- Produces the single complete display file from ordered source documents.

- [ ] Source spec/roadmap/phase files are authoritative; the complete file is generated.
- [ ] Compute line counts and SHA-256 automatically.
- [ ] Verify every source is embedded exactly once and byte-for-byte.
- [ ] `--check` fails on stale hashes, missing Phase, reordered source or hand-edited generated output.
- [ ] Generator performs atomic replacement of the generated documentation file only.

---

### Task 8: Legacy write-sink inventory preflight

**Files:**
- Create: `core/sitina/legacy/write_sink_inventory.py`
- Create: `tests/foundation/test_write_sink_inventory.py`
- Create: `docs/legacy-write-sink-registry.md`

**Interfaces:**
- Produces a versioned registry of SQLite、JSONL、mutable JSON、Checkpoint、Manifest、Replay、Evidence、Tool and Maintenance sinks.

- [ ] Static scan direct and helper-mediated filesystem/SQLite mutation sites.
- [ ] Instrument isolated fixtures to record actual sink calls for representative Legacy behavior.
- [ ] Record entrypoint→sink paths and current guard status.
- [ ] Mark unknown dynamic writes as blockers for Phase 0 Frozen Snapshot work.
- [ ] Do not patch Production code in this task.

---

### Task 9: Phase -1 acceptance gate

**Files:**
- Create: `tests/foundation/test_phase_minus1_acceptance.py`
- Create: `docs/bplus-phase-minus1-acceptance.md`

- [ ] Approved Python and dependency profile resolves deterministically.
- [ ] V0 contains no forward reference to self-generated hashes；V1 binds the approved Bootstrap Foundation Record and all stable hashes.
- [ ] All default tests run only in disposable Test Homes.
- [ ] Production sentinel hashes/size/mtime remain unchanged across test execution.
- [ ] Live/external adapters receive zero calls.
- [ ] Git or content-manifest audit mode is explicitly selected and valid.
- [ ] Legacy behavior baseline is reproducible.
- [ ] Plan-suite `--check` passes.
- [ ] Write-sink inventory has no unknown entrypoint for planned Phase 0 fencing.
- [ ] Produce `phase-minus1-acceptance.json`, record changed-file manifest, and stop.

Phase -1 completion authorizes neither Phase 0 implementation nor any Production freeze. A new user-approved Execution Manifest is required.

---

# 第四部分：Phase 0 Legacy Compatibility

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-0-legacy-compatibility.md`  
> 来源 SHA-256：`b881e1293e5ff607e366f6167d5536c17d01a5728a003375fa75f682dcdf278f`

# Sitina B+ Phase 0 Legacy Compatibility Implementation Plan

> **For Codex execution:** Requires a PASSED Phase -1 Acceptance Report and a current Execution Manifest authorizing only the listed Phase 0 Task Range. Default work uses an isolated Test Home and must stop before any real Production freeze.

**Goal:** 在不改变 Production Authority 的前提下，建立可审计冻结机制并盘点当前 SQLite/JSONL/Mutable JSON/Artifact 来源，建立 Legacy Read-only Adapter、Fact Classification、Shadow Namespace 和 Dual-read Comparison Harness；真实 Production Freeze 仍需单独授权。

**Architecture:** Legacy Writer 在整个 Phase 0 仍是唯一 Production Authority；新增能力只负责 Inventory、Read-only Snapshot、Shadow Import 和 Comparison。所有 Shadow Event 明确标记 Non-authoritative，且不得驱动 Provider、Tool、Approval、Timer、Terminal 或 Evidence Seal。

**Tech Stack:** Phase -1 approved Python 3.12 Profile、SQLite read-only URI、JSON/JSONL、SHA-256、分层 `unittest`、文件树 Inventory、Kernel file lock（只为 Legacy Fence 协调，不替换 Phase 1 Canonical Writer Lock）。

## Global Constraints

- 不执行 Authority Cutover。
- 不删除、重写、Vacuum 或重建 `~/SitinaHub/data/sitina.db`。
- 不修改现有 JSONL、Checkpoint、Manifest、Replay Snapshot、Blackboard 或 Evidence Bundle。
- Production Commands 继续走 Legacy Writer；Shadow 只读取。
- 所有源码修改受 Phase -1 Source-only Baseline 保护；不得把 Runtime State 或 Secret 复制进源码备份。
- Shadow Replay 禁止所有外部 I/O。
- 默认测试只在 Phase -1 Disposable Test Home 运行；`legacy_readonly_observation` 是唯一允许读取 Production 的测试层。
- `LIVE_OBSERVATIONAL_INVENTORY` 不是一致性 Snapshot，不得用于迁移、Cutover 或 Journal Completeness 声明。
- `FROZEN_COHERENT_SNAPSHOT` 只能在单独批准的维护窗口中，通过全量低层 Writer Fence 固定统一 Cutoff 后生成。

---

### Task 1: Legacy source map and authority-state types

**Files:**
- Create: `core/sitina/legacy/__init__.py`
- Create: `core/sitina/legacy/model.py`
- Test: `tests/test_legacy_compatibility.py`

**Interfaces:**
- Produces: `LegacySourceKind`, `LegacyAuthorityStage`, `AuthorityResolution`, `AuthorityResolver`, `LegacySourceRecord`, `LegacyObservationManifest`, `LegacySnapshotManifest`.
- Consumes: `Path`, canonical UTC timestamps, SHA-256 helpers.

- [ ] **Step 1: Write failing model tests**

```python
from sitina.legacy.model import AuthorityResolution, LegacyAuthorityStage, LegacySourceKind, LegacySourceRecord


def test_stage_name_never_implies_authoritative_writer():
    assert not hasattr(LegacyAuthorityStage.CUTOVER_PREPARED_NO_WRITER, "authoritative_writer")


def test_unknown_cutover_outcome_has_no_writer():
    assert AuthorityResolution.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER.writer is None


def test_legacy_source_record_requires_provenance():
    record = LegacySourceRecord(
        kind=LegacySourceKind.SQLITE_TABLE,
        source_ref="data/sitina.db#events:42",
        content_hash="sha256:" + "0" * 64,
        observed_at="2026-07-13T00:00:00Z",
    )
    assert record.source_ref.endswith("events:42")
```

- [ ] **Step 2: Run the tests and verify failure**

Run:

```bash
<approved-python> ~/SitinaHub/scripts/test-bplus.py unit_fast --test tests/test_legacy_compatibility.py
```

Expected: import failure for `sitina.legacy.model`.

- [ ] **Step 3: Implement the immutable types**

```python
# core/sitina/legacy/model.py
from dataclasses import dataclass
from enum import Enum

class LegacySourceKind(str, Enum):
    SQLITE_TABLE = "sqlite_table"
    EVENT_JSONL = "event_jsonl"
    AUDIT_JSONL = "audit_jsonl"
    MUTABLE_SNAPSHOT = "mutable_snapshot"
    CHECKPOINT = "checkpoint"
    RUN_MANIFEST = "run_manifest"
    REPLAY_SNAPSHOT = "replay_snapshot"
    EVIDENCE_EXPORT = "evidence_export"

class LegacyAuthorityStage(str, Enum):
    LEGACY_ACTIVE_PROVEN = "legacy_active_proven"
    SNAPSHOT_FENCED_NO_WRITER = "snapshot_fenced_no_writer"
    SHADOW_JOURNAL = "shadow_journal"
    JOURNAL_FIRST_SHADOW_READ = "journal_first_shadow_read"
    DUAL_READ_VALIDATION = "dual_read_validation"
    CUTOVER_TOOLING_READY = "cutover_tooling_ready"
    CUTOVER_PREPARED_NO_WRITER = "cutover_prepared_no_writer"
    CUTOVER_OUTCOME_UNKNOWN_NO_WRITER = "cutover_outcome_unknown_no_writer"
    JOURNAL_AUTHORITY_PROVEN = "journal_authority_proven"
    LEGACY_RETAINED_READ_ONLY = "legacy_retained_read_only"
    CUTOVER_VERIFIED = "cutover_verified"

class AuthorityResolution(str, Enum):
    LEGACY_WRITER_AUTHORIZED = "legacy_writer_authorized"
    CUTOVER_PREPARED_NO_WRITER = "cutover_prepared_no_writer"
    CUTOVER_OUTCOME_UNKNOWN_NO_WRITER = "cutover_outcome_unknown_no_writer"
    JOURNAL_WRITER_AUTHORIZED = "journal_writer_authorized"
    RECOVERY_REQUIRED_NO_WRITER = "recovery_required_no_writer"

    @property
    def writer(self) -> str | None:
        if self is self.LEGACY_WRITER_AUTHORIZED:
            return "legacy"
        if self is self.JOURNAL_WRITER_AUTHORIZED:
            return "journal"
        return None

@dataclass(frozen=True)
class LegacySourceRecord:
    kind: LegacySourceKind
    source_ref: str
    content_hash: str
    observed_at: str
```

Add `LegacySnapshotManifest` with installation ID, cutoff, code/config/policy hashes, SQLite snapshot identity, JSONL inventory, state/artifact inventory and manifest hash.

Implement `AuthorityResolver` separately；it consumes verified Legacy Fence Record、Production Genesis/Cutover Identity and Journal-derived Outcome/Absence Proof. It must never derive Writer from `LegacyAuthorityStage`.

- [ ] **Step 4: Re-run model tests**

Expected: PASS.

- [ ] **Step 5: Commit after approval to initialize Git**

```bash
git add core/sitina/legacy tests/test_legacy_compatibility.py
git commit -m "feat: define legacy compatibility model"
```

If Git is still unavailable, record the exact changed-file manifest instead; do not initialize Git without user approval.

---

### Task 2: Dedicated read-only Legacy SQLite adapter

**Files:**
- Create: `core/sitina/legacy/readonly.py`
- Modify: `core/sitina/storage/store.py:128-145`
- Test: `tests/test_legacy_compatibility.py`

**Interfaces:**
- Produces: `LegacySQLiteReader.open(db_path)`, `iter_table_rows(table, after_id=0)`, `snapshot_identity()`.
- Must not call `PRAGMA journal_mode=WAL` or create files.

- [ ] **Step 1: Add a failing read-only mutation test**

```python
with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "legacy.db"
    sqlite3.connect(db).execute("create table events(id integer primary key, payload text)")
    reader = LegacySQLiteReader.open(db)
    with self.assertRaises(sqlite3.OperationalError):
        reader.connection.execute("insert into events(payload) values ('x')")
```

Also assert missing DB fails instead of creating it.

- [ ] **Step 2: Run the focused test**

Expected: FAIL because `LegacySQLiteReader` is undefined.

- [ ] **Step 3: Implement URI read-only connection**

```python
uri = f"file:{urllib.parse.quote(str(db_path.resolve()))}?mode=ro&immutable=1"
conn = sqlite3.connect(uri, uri=True, timeout=30)
conn.execute("PRAGMA query_only=ON")
```

Never use `immutable=1` on the Live WAL database. For live comparison use `mode=ro` and SQLite Backup API to create a staging snapshot. Under an approved Fence, capture/merge required WAL state, run `integrity_check`, close/fsync the snapshot and directory, verify that the snapshot no longer depends on external `-wal/-shm`, then reopen that independent snapshot with `immutable=1`. Add explicit methods for schema, counts, max row IDs and ordered row iteration.

- [ ] **Step 4: Add regression test for `SitinaStore.connect()`**

Confirm existing Legacy Runtime still uses its original writable path in Phase 0; new cutover code must use only `LegacySQLiteReader`.

- [ ] **Step 5: Run tests and commit**

Expected: read-only adapter tests and existing store tests pass.

---

### Task 3: Exhaustive Legacy writer-fence control plane

**Files:**
- Create: `core/sitina/legacy/fence.py`
- Modify: `core/sitina/cli.py`
- Modify: `core/sitina/orchestrator/engine.py:57-79`
- Test: `tests/test_legacy_compatibility.py`

**Interfaces:**
- Produces: `LegacyWriteGate.assert_writes_allowed()`, `freeze(snapshot_id)`, `status()`.
- Phase 0 default: `LEGACY_ACTIVE`; freeze command is explicit and high-risk.

- [ ] **Step 1: Write failing gate tests**

Test that `LEGACY_ACTIVE` permits writes, frozen mode rejects a new `SitinaEngine.run()`, and read-only inventory remains allowed.

- [ ] **Step 2: Add a non-destructive CLI command**

```text
sitina legacy status
sitina legacy inventory --output <path>
```

Do not add `freeze` execution until an implementation session receives separate user approval. Define the API and dry-run output now.

- [ ] **Step 3: Add defense-in-depth gates at top-level entries and every registered low-level sink**

Cover engine run/resume/cancel/initialize、maintenance rollback/restore/prune、direct tool/MCP execution、approval/risk acceptance、SQLite connect/init/write、JSONL append、`write_json`、Checkpoint、Manifest、Replay、Evidence、Blackboard、Handoff、Lease、Side Effect and Report writers. Top-level Gate provides fast rejection；low-level Sink Gate prevents bypass. Every writer process must hold the same Kernel-backed Legacy Writer Coordination Lock before its first mutation.

- [ ] **Step 4: Add static/dynamic coverage and bypass prevention tests**

Consume the Phase -1 Write-sink Registry；require every sink to be `GUARDED` or explicitly `READ_ONLY`. Instrument representative Legacy flows and assert no unregistered mutation occurs. When frozen, patch multiple top-level routes and call low-level helpers directly；all must fail before file/SQLite mutation。

- [ ] **Step 5: Run the applicable Phase -1 isolated suites and commit**

Expected: existing Legacy behavior unchanged while phase is active.

---

### Task 4: Immutable inventory and snapshot manifest

**Files:**
- Create: `core/sitina/legacy/inventory.py`
- Test: `tests/test_legacy_inventory.py`

**Interfaces:**
- Produces: `build_observational_inventory(home, output_dir) -> LegacyObservationManifest` and `build_frozen_snapshot(fenced_home, output_dir, cutoff) -> LegacySnapshotManifest`.
- Consumes: read-only SQLite snapshot, JSONL files, state/artifact trees, code/config/policy hashes.

- [ ] **Step 1: Write fixture inventory tests**

Create SQLite/JSONL/state/checkpoint fixtures and assert deterministic sorted entries and manifest hash.

- [ ] **Step 2: Implement observational inventory without modifying source**

Use SQLite online backup into an output snapshot, hash resulting DB bytes, record table counts/max IDs, and hash every source file with relative paths. Record file identity/size/mtime before and after reading；if a source changes, mark the entry `CHANGED_DURING_OBSERVATION` rather than claiming one coherent Cutoff. Reject symlinks and paths outside `home`.

Before copying, verify output is outside the source tree, estimate DB/WAL/tree bytes, require free-byte/inode/staging headroom under the Capacity Safety Policy, and record the check. Insufficient headroom fails before creating a partial Snapshot。

- [ ] **Step 3: Implement separately authorized frozen coherent snapshot**

Require the exhaustive Writer Fence, prove all known writer processes drained, freeze one Cutoff, then capture logical SQLite backup plus exact DB/WAL metadata、JSONL line cutoffs、State/Artifact hashes and Code/Config/Policy/Profile identities. Any sink coverage gap, open writer, changing file or unavailable source aborts the Snapshot. `sqlite-shm` is operational metadata, not a portable authority artifact；its treatment must be explicit。

- [ ] **Step 4: Add consistency observations**

Record, but do not “repair,” event JSONL vs SQLite counts, audit counts, checkpoint files vs index, duplicate legacy IDs and Blackboard source variants.

- [ ] **Step 5: Verify repeatability**

Two inventories over unchanged fixtures must have identical semantic manifest hash, excluding output location and observation time.

- [ ] **Step 6: Commit**

---

### Task 5: Legacy fact classification and provenance

**Files:**
- Create: `core/sitina/legacy/classify.py`
- Create: `config/legacy_fact_classification.json`
- Test: `tests/test_legacy_classification.py`

**Interfaces:**
- Produces: `classify(record) -> LegacyFactClassification` with `fact_kind`, `authority_weight`, `migration_event_type`, `completeness_reason`, `dedup_key`.

- [ ] **Step 1: Write table-driven tests**

Cover `run_ledger`, non-ledger events, audit rows, JSONL copies, mutable snapshots, checkpoints, manifests, replay snapshots and evidence exports.

- [ ] **Step 2: Implement the versioned matrix**

Rules:

```text
run_ledger                  -> coordination_fact_candidate
non-ledger event            -> supplementary_legacy_fact
same trace audit            -> audit_representation
mutable snapshot            -> state_assertion
checkpoint/manifest/bundle  -> legacy_evidence_artifact
```

Never classify a legacy row as native canonical event. Conflicting duplicate IDs receive new migration IDs and preserve both source refs.

- [ ] **Step 3: Add incomplete reason enum**

```text
MISSING_CAUSATION
MISSING_TIMESTAMP
MISSING_PAYLOAD
MISSING_ACTOR
MISSING_STREAM_HISTORY
UNVERIFIABLE_HASH
ORPHAN_RECORD
CONFLICTING_RECORD
```

- [ ] **Step 4: Run tests and commit**

---

### Task 6: Shadow import envelope and non-authority guard

**Files:**
- Create: `core/sitina/legacy/shadow.py`
- Create: `tests/test_shadow_journal_guards.py`

**Interfaces:**
- Produces: `ShadowFactEnvelope`, `ShadowImporter`, `ShadowExecutionGuard` in a physically isolated `MigrationWorkspaceRoot`/Shadow Root.
- Shadow writes use namespace `shadow/<snapshot_id>/...` and `authority=false`.

- [ ] **Step 1: Write tests that Shadow cannot dispatch**

Assert Provider, MCP, Tool, Approval, Timer, Terminal and Evidence Seal adapters reject `authority=false` contexts.

- [ ] **Step 2: Implement deterministic shadow identity**

Derive new migration fact ID from source installation, snapshot hash, source ref and conversion-rule hash. Preserve historical time only as payload metadata; `committed_at` is import time.

- [ ] **Step 3: Implement `MigratedFactRecorded` / `ImportedLegacyFact` conversion output**

No native historical Event impersonation.

- [ ] **Step 4: Run tests and commit**

---

### Task 7: Dual-read semantic comparison harness

**Files:**
- Create: `core/sitina/legacy/compare.py`
- Test: `tests/test_legacy_dual_read.py`

**Interfaces:**
- Produces: `ComparisonProfile`, `ComparisonResult`, `compare_run(run_id, legacy_reader, shadow_reader, frontier)`.

- [ ] **Step 1: Write deterministic comparison tests**

Compare terminal status, task/protocol counts, provider-call accounting, proposals/handoffs/arbitrations/leases, checkpoints, audit relationships, manifest/evidence hashes and secret-scan status.

- [ ] **Step 2: Implement semantic normalization**

Ignore legacy row IDs, local absolute paths and representation duplicates; do not ignore business identity, disposition, counts or hashes. Every ignored field must be listed in the versioned profile.

- [ ] **Step 3: Implement mismatch policy**

```text
MATCH
LEGACY_INCOMPLETE(reason, source_refs)
BLOCKING_MISMATCH(reason, source_refs)
```

A blocking mismatch prevents cutover. `LEGACY_INCOMPLETE` requires approved classification; it cannot be generated automatically for arbitrary differences.

- [ ] **Step 4: Produce machine-readable and Markdown reports**

Reports are evidence artifacts, not authority.

- [ ] **Step 5: Run tests and commit**

---

### Task 8: Phase 0 acceptance gate

**Files:**
- Create: `tests/test_phase0_acceptance.py`
- Modify: `docs/architecture.md` only after backup
- Create: `docs/legacy-cutover-operator-guide.md`

**Interfaces:**
- Produces: `phase0_acceptance.json` with source inventory, guard status, shadow safety and comparison profile hash.

- [ ] **Step 1: Run full existing suite**

Use Phase -1 `unit_fast` and `integration_isolated`; expected no regression and unchanged Production sentinels. The legacy unisolated discovery command is forbidden.

- [ ] **Step 2: Run fixture acceptance**

Prove inventory is non-mutating, Shadow cannot execute effects, read-only SQLite does not alter WAL/DB, duplicate legacy IDs preserve provenance, and comparison mismatch blocks progression.

- [ ] **Step 3: Document operator boundaries**

Explicitly state that Phase 0 does not change Authority and does not authorize freezing the real installation without a separate user-approved maintenance window.

- [ ] **Step 4: Record changed-file manifest and commit**

Phase 0 default exit does not freeze Production；it proves that a future separately authorized `FROZEN_COHERENT_SNAPSHOT` can be created safely and observably. If a real frozen snapshot is authorized later, its snapshot ID、cutoff、fence proof and manifest hash become separate acceptance artifacts and never silently replace the default observational report.

---

# 第五部分：Phase 1 Journal/CAS/Projection Kernel

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-1-journal-cas-kernel.md`  
> 来源 SHA-256：`ae831f6e1c1b97805e795dfc20eb7dae4b6cdcfa65900641daae1a57cd742c26`

# Sitina B+ Phase 1 Journal/CAS/Projection Kernel Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1/0 reports and a current Execution Manifest. Only physically separate `shadow` or `controlled_fixture` roots are writable；Production Journal Genesis/Cutover is forbidden。

**Goal:** 实现可在 Shadow/Controlled Namespace 运行的单机 Canonical Journal、Encrypted CAS、Command Outcome、Projection Kernel 和 Lost ACK Recovery，不改变 Production Legacy Authority。

**Architecture:** 单 Writer、单 Active Segment、单 Stream Transaction；单机 Position Profile 为 Gap-free Committed Prefix。CAS Object 完成 No-replace Publication 和 Fresh Verification 后才允许 Frame 引用。SQLite 只作为可删除重建的 Catalog/Projection；Command Outcome 可以从 Canonical Frame 查询。

**Tech Stack:** Approved Python 3.12 Profile、strict Canonical JSON、binary frame、`fcntl.flock`、macOS `renamex_np(RENAME_EXCL)` Native Adapter 或经能力探测验证的 `linkat` fallback、SQLite WAL、`cryptography` AES-256-GCM Object/Envelope Wrapping and Ed25519 Profiles、分层 `unittest`、Crash-injection subprocess tests。

## Global Constraints

- Production Authority 仍是 Legacy；Phase 1 Journal Namespace 必须标记 `shadow` 或 `controlled_fixture`。
- 不导入真实业务数据，不执行 Provider/Tool/MCP。
- 初始 Position Profile：`LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1`。
- 一个 Command 只修改一个 Logical Stream。
- ACK 只在 Frame 和所有 CAS Ref Durability Barrier 后返回。
- `write/fsync` 不确定后 Poison Writer，必须 Recovery。
- SQLite Cache Miss 只能返回 UNKNOWN。
- Canonical/Frame/Crypto/Identifier/Clock Profile 和 Golden Vectors 未冻结前，不得写入第一个持久 B+ Byte。
- Audit、Security Intake、Dead Letter、Projection Failure 和 Operational Control 事实必须进入 Journal-backed Stream。

---

### Task 0: Normative serialization, frame, identifier, hash and crypto profiles

**Files:**
- Create: `docs/bplus-profiles/canonical-json-v1.md`
- Create: `docs/bplus-profiles/local-frame-v1.md`
- Create: `docs/bplus-profiles/identifier-hash-v1.md`
- Create: `docs/bplus-profiles/crypto-v1.md`
- Create: `docs/bplus-profiles/journal-auth-v1.md`
- Create: `docs/bplus-profiles/macos-durability-v1.md`
- Create: `tests/vectors/bplus_v1_vectors.json`
- Test: `tests/test_bplus_profiles.py`

**Interfaces:**
- Produces immutable Profile IDs and cross-implementation Golden Vectors.

- [ ] Define UTF-8/NFC、Object Key sorting、Array order、Set-like field rules、integer bounds、float rejection、RFC3339 UTC、duplicate-key and unknown-field rejection.
- [ ] Define big-endian Frame fields, length-prefixed UTF-8 IDs, bounded 128-bit UUID encoding only for explicitly typed UUID fields, Hash preimages and self-hash exclusions.
- [ ] Fix SHA-256 domain-separated hashes and tenant HMAC-SHA-256 plaintext commitments.
- [ ] Fix per-object random 256-bit DEK、AES-256-GCM Object encryption、96-bit CSPRNG Object Nonce、immutable AAD Core Header and Ed25519 Evidence signatures.
- [ ] Wrap each DEK with KEK using a separate AES-256-GCM Envelope Nonce and AAD binding Core Header Hash、Object Identity、Key ID、Purpose and Wrap Profile；Rewrap creates a new immutable authenticated Envelope Version/ID and audited Alias without changing CAS Object bytes.
- [ ] Fix Journal Event Auth as HMAC-SHA-256 with a separate Journal Auth Key、exact Core/Event/Transaction preimages、Segment-boundary rotation and historical-key retention.
- [ ] Define default `MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1` and separately qualified `MACOS_APFS_FULLFSYNC_POWERLOSS_QUALIFIED_V1`; the default makes no power-loss RPO=0 claim.
- [ ] Produce valid/invalid Golden Vectors；Profile change requires new Major/Profile ID, never reinterpret committed bytes.
- [ ] Commit profiles before Task 1.

---

### Task 1: Canonical command, event, receipt, and outcome types

**Files:**
- Create: `core/sitina/journal/__init__.py`
- Create: `core/sitina/journal/model.py`
- Create: `core/sitina/commands/__init__.py`
- Create: `core/sitina/commands/model.py`
- Test: `tests/test_journal_model.py`

**Interfaces:**
- Produces:
  - `CommandEnvelope.canonical_request_bytes() -> bytes`
  - `EventEnvelope.canonical_bytes_for_hash() -> bytes`
  - `AppendReceipt`
  - `CommandStatus = COMMITTED|REJECTED|CONFLICT|RETRYABLE_NOT_ACCEPTED|UNKNOWN`
  - `FrontierRef(journal_id, epoch, shard, position, commitment)`.

- [ ] **Step 1: Write failing canonicalization tests**

```python
def test_command_hash_ignores_transport_received_at():
    left = command(received_at="2026-07-13T00:00:01Z")
    right = command(received_at="2026-07-13T00:00:02Z")
    assert left.command_request_hash == right.command_request_hash


def test_command_hash_changes_with_payload():
    assert command(payload={"x": 1}).command_request_hash != command(payload={"x": 2}).command_request_hash
```

- [ ] **Step 2: Run focused tests**

Expected: missing module.

- [ ] **Step 3: Implement frozen dataclasses and enums**

Implement the frozen Task 0 Canonical Profile exactly；do not reuse permissive Legacy `stable_json` as the canonical codec. Domain-separate command/event/transaction hashes. Define explicit JSON schema-to-dataclass conversion and reject duplicate keys、unknown fields and unknown major versions.

- [ ] **Step 4: Add type round-trip and invalid-field tests**

Assert stored bytes round-trip exactly；`event_core_bytes` excludes Event Hash/Auth Tag、Event Hash is unkeyed/domain-separated、Auth Tag binds Journal/Epoch/Event Hash、Transaction Hash covers final stored bytes。Test wrong/missing/rotated Key、broken Key Transition and historical Key loss fail closed.

- [ ] **Step 5: Run tests and commit**

---

### Task 2: Frame codec and parser limits

**Files:**
- Create: `core/sitina/journal/codec.py`
- Test: `tests/test_journal_codec.py`

**Interfaces:**
- Produces: `encode_frame(transaction) -> bytes`, `scan_frames(fileobj, limits) -> FrameScanResult`.
- Consumes: `CommandEnvelope`, `EventEnvelope`.

- [ ] **Step 1: Write failing frame tests**

Test one/multiple Events, CRC corruption, transaction-hash corruption, truncated Header/Body/Footer, unknown major version and oversized length rejected before allocation.

- [ ] **Step 2: Define V1 binary layout**

```text
magic(8) major(u16) minor(u16) header_len(u32) frame_len(u64)
transaction_id_len(u16) transaction_id(bytes)
command_id_len(u16) command_id(bytes) request_hash(32)
stream_id_len(u16) stream_id(bytes)
object_reference_count(u32) object_reference_manifest_hash(32)
event_count(u32) first_position(u64) last_position(u64)
first_stream_version(u64) last_stream_version(u64)
event_lengths[u32] + canonical_event_bytes
crc32(u32) transaction_hash(32) footer_magic(8)
```

For local V1 assert position span equals Event count; this assertion belongs to Position Profile, not generic codec.

All integer fields use the frozen byte order；all length/count fields are checked against Capacity Profile before allocation。Frame Hash covers the exact canonical Header/Body/CRC fields declared in the Profile and excludes only its own stored field。

- [ ] **Step 3: Implement bounded scanner**

Return complete Frame end offsets and first invalid/incomplete byte. Never allocate from unchecked length.

- [ ] **Step 4: Fuzz deterministic invalid inputs**

Use seeded random byte mutations; parser must fail closed without unbounded memory.

- [ ] **Step 5: Run tests and commit**

---

### Task 3: Fixed-inode Writer Lock

**Files:**
- Create: `core/sitina/journal/locks.py`
- Test: `tests/test_journal_lock.py`

**Interfaces:**
- Produces: `WriterLock.acquire(path, journal_id, epoch)`, context manager, `poison(reason)`.

- [ ] **Step 1: Write subprocess contention tests**

First process holds lock; second fails without deleting/replacing file. Test symlink rejection, inode replacement detection、fork/exec descriptor inheritance、duplicate FD close、filesystem capability mismatch and descriptor-close poisoning.

- [ ] **Step 2: Implement no-follow regular-file validation**

Use `os.open(..., O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0o600)`, `fstat`, `lstat`, device/inode comparison, `fcntl.flock(LOCK_EX|LOCK_NB)`.

- [ ] **Step 3: Persist writer generation diagnostic**

Under held kernel lock, atomically update control metadata and directory-sync. It never substitutes for `flock`.

- [ ] **Step 4: Run tests and commit**

---

### Task 4: Local segment writer, group durability, and rollover

**Files:**
- Create: `core/sitina/journal/local.py`
- Create: `core/sitina/journal/recovery.py`
- Test: `tests/test_local_journal.py`
- Test: `tests/test_journal_crash_matrix.py`

**Interfaces:**
- Produces:
  - `LocalJournal.open(home, profile)`
  - `append(command, expected_stream_version, events, object_reference_proofs) -> AppendReceipt`
  - `query_command(command_id, request_hash) -> CommandResult`
  - `lookup_existing_object_root_proof(object_ref, verified_frontier) -> ExistingDurableObjectRootProof`
  - `iter_events(after_position)`.

- [ ] **Step 1: Write failing append tests**

Assert single Stream、continuous Stream Version、local committed Position continuity、idempotent retry、conflict on same Command/different Hash、exact Event-ref/Object-proof equality and no ACK before Frame plus all referenced CAS durability succeeds. Missing/forged/expired Proof or unverified Final Object fails before Frame write.

- [ ] **Step 2: Implement single-thread Writer queue**

Freeze `group_end_offset` before durability barrier；ACK only covered Frames。Writer derives Object Refs from Canonical Event Bytes、validates `PublishedObjectReceipt|ExistingDurableObjectRootProof`、acquires GC Epoch Reference Leases and binds `object_reference_manifest_hash` in Frame。Release Lease only after Referencing Frame Durable. On write/sync error set poisoned flag and reject all further appends until reopen.

- [ ] **Step 3: Implement segment hash/footer and rebuildable index**

Segment hash excludes/zeroes its own field; `.sidx` binds segment hash but stays outside canonical chain. Use no-replace publication and directory sync. Existing durable-object root proof lookup must resolve a verified Committed Frame and exact object-reference manifest at/before the requested Frontier；a CAS catalog row or object existence alone cannot issue this proof.

- [ ] **Step 4: Implement recovery adoption**

Scan longest physically contiguous valid Frame prefix. Truncate only incomplete active tail. Adopt complete unacknowledged Frames, sync repaired/adopted prefix, rebuild Stream Heads/Command Bindings, then serve.

Recovery tests must distinguish short write、EINTR、ENOSPC、EIO、unknown write result、unknown `fsync` result、directory-sync failure and media corruption. Any unknown durability result poisons the Writer；only a fresh locked Recovery can adopt and re-sync a valid complete prefix。

- [ ] **Step 5: Implement rollover crash matrix**

Inject crash after each state: group sync, footer write/sync, rename, directory sync, new-active create/sync/publish, index build. Recovery yields all old Segments sealed and at most one Active.

- [ ] **Step 6: Run tests and commit**

---

### Task 5: Key Provider and encrypted CAS identity

**Files:**
- Create: `core/sitina/cas/__init__.py`
- Create: `core/sitina/cas/model.py`
- Create: `core/sitina/cas/crypto.py`
- Create: `core/sitina/security/key_provider.py`
- Create: `core/sitina/security/macos_keychain.py`
- Test: `tests/test_key_profiles.py`
- Test: `tests/test_cas_crypto.py`

**Interfaces:**
- Produces:
  - `KeyProvider.wrap_dek/unwrap_dek/sign/verify`
  - `JournalAuthProvider.authenticate/verify/rotate`
  - `ObjectEnvelope`
  - `encrypt_object(plaintext, profile) -> EncryptedObject`.

- [ ] **Step 1: Write purpose-isolation tests**

Test that runtime writer can request only current Journal Auth Capability and cannot request Evidence/Authority Signing Key；test/dev/prod namespaces cannot resolve one another；Key IDs bind purpose/provider/environment/version/profile。Journal、Authority Control and Evidence/Archive signatures never share a Key Purpose.

- [ ] **Step 2: Implement provider interface and in-memory test provider**

Production macOS adapter stores opaque references in Keychain; tests use deterministic in-memory keys. Never commit key bytes.

- [ ] **Step 3: Implement the frozen Crypto V1 profile**

Use the Phase -1 locked `cryptography` dependency and Task 0 AES-256-GCM Object/Envelope + Ed25519 Profile. A new random DEK per Object prevents Object Nonce reuse across Objects；immutable Core Header is Object AAD；rewrappable DEK Envelope uses its own Nonce and context-bound AAD. Separate DEK, KEK, Commitment and Signing Key purposes.

- [ ] **Step 4: Test rewrap and destruction semantics**

Rewrap preserves Semantic ID/Ciphertext; crypto-erasure makes decrypt fail and yields an Attestation fixture.

- [ ] **Step 5: Run tests and commit**

---

### Task 6: Local CAS no-replace publication

**Files:**
- Create: `core/sitina/cas/local.py`
- Create: `core/sitina/cas/native.py`
- Test: `tests/test_local_cas.py`

**Interfaces:**
- Produces: `LocalCAS.publish_verified(body, metadata) -> PublishedObjectReceipt` and `open_verified(ref)`. It never issues `ExistingDurableObjectRootProof`.

- [ ] **Step 1: Write publication tests**

Test staging sync、Fresh Verify、no-replace concurrency、exact-existing idempotency、collision incident、directory durability、Receipt identity/profile/expiry and missing/auth-failed object。Receipt cannot be constructed by callers and does not itself become a business/GC Root. Test CAS existence/catalog cannot manufacture an existing-root proof；only Task 4 Journal lookup can bind a Committed Frame root.

- [ ] **Step 2: Implement macOS no-replace adapter**

Bind `renamex_np(RENAME_EXCL)` with `ctypes` or use tested same-filesystem `linkat` strategy. Plain overwriting rename is forbidden.

- [ ] **Step 3: Implement ciphertext-digest path and authenticated header**

Do not expose plaintext hash. Reject symlink/path traversal.

- [ ] **Step 4: Run race tests and commit**

---

### Task 7: CAS reference-admission, fixed GC frontier and GC fence

**Files:**
- Create: `core/sitina/cas/gc.py`
- Test: `tests/test_cas_gc_fence.py`

**Interfaces:**
- Produces: `ReferenceLease`, `GCMarkFrontier`, `GCCycle`, `GCController.mark/quarantine/sweep`, `with_reference_lease(ref)`.

- [ ] **Step 1: Write append-vs-GC race tests**

Prove a durable in-flight reference lease blocks quarantine until Frame Durable; once GC transitions to QUARANTINING, new admission fails.

- [ ] **Step 2: Implement Journal-backed GC control records for shadow namespace**

Do not store sole fence state in SQLite. Freeze Signed Journal Frontier、GC Epoch、Catalog Set/Versions、Hold Snapshot and Policy Hash。Scan all fixture Journal/CAS/Package/Supplement/Archive/Migration/Rebuild catalogs at that Frontier；fail closed if required coverage is unavailable.

- [ ] **Step 3: Test post-frontier reference protection**

New Reference Admission enters a successor/Post-frontier Root under GC Epoch Lease and cannot be swept by the current Candidate Set. Sweep-time recheck rejects any Committed/In-flight/Post-frontier/Read/Backup/Hold/Restore reference.

- [ ] **Step 4: Test restart reconciliation**

GC cannot resume until Journal and lease reconciliation completes.

- [ ] **Step 5: Commit**

---

### Task 8: Projection schema and atomic runner

**Files:**
- Create: `core/sitina/projections/__init__.py`
- Create: `core/sitina/projections/schema.py`
- Create: `core/sitina/projections/runner.py`
- Create: `core/sitina/projections/rebuild.py`
- Test: `tests/test_projection_kernel.py`

**Interfaces:**
- Produces: `ProjectionRunner.apply_batch()`, `ProjectionGeneration.build/switch`, Event Catalog, Stream Head and Command Outcome projections.

- [ ] **Step 1: Write rollback tests**

A handler failure after row mutation must roll back rows and offset. Gapped-position arithmetic is not used. For local V1, a committed gap fails integrity checks.

- [ ] **Step 2: Implement schema**

Use WAL, `synchronous=NORMAL`, FK on, trusted schema off, one write coordinator. Store Event location Metadata, not payload copies.

- [ ] **Step 3: Implement atomic apply+offset**

No universal processed-events table. Use natural uniqueness and last applied Stream Version.

- [ ] **Step 4: Implement disposable rebuild**

Build a Shadow DB to fixed Frontier, compute semantic checksums, switch Reader Generation atomically.

- [ ] **Step 5: Run tests and commit**

---

### Task 8A: Journal-backed operational authority primitives

**Files:**
- Create: `core/sitina/journal/operational.py`
- Create: `core/sitina/journal/security_intake.py`
- Create: `core/sitina/journal/dead_letters.py`
- Create: `core/sitina/journal/schema_registry.py`
- Create: `core/sitina/commands/authorization.py`
- Test: `tests/test_operational_authority.py`

**Interfaces:**
- Produces typed Streams/handlers for Audit、Security Intake、Operational Control、Dead Letter、Projection Failure、Schema Registry and Capability/Authorization decisions.

- [ ] Test SQLite/log-only rows never become authoritative operational facts.
- [ ] Test unsafe/oversized/unparseable intake stores bounded redacted metadata or Quarantine Attestation, never raw secret/business payload.
- [ ] Test Blocking Dead Letter and Required Projection Failure enter Terminal Eligibility inputs.
- [ ] Test schema versions/upcaster chain hashes are immutable and unknown Major fails closed.
- [ ] Test authorization decision binds actor、capability、policy、target、request hash、expiry and audit reference.
- [ ] Ensure deterministic rejection can be queried through canonical Command Outcome.
- [ ] Commit before Phase 2.

---

### Task 9: Strong/Eventual/Stale read API

**Files:**
- Create: `core/sitina/projections/consistency.py`
- Test: `tests/test_projection_consistency.py`

**Interfaces:**
- Produces: `ReadOptions`, `ReadMetadata`, `wait_for_frontier()`.

- [ ] **Step 1: Test fixed-target waits**

Strong wait reaches Caller target and does not chase moving Head. Failed/Blocked/Incompatible Projector fails closed.

- [ ] **Step 2: Implement condition notification plus polling fallback**

No SQLite busy loop. Calculate `lag_events` from Event Catalog count.

- [ ] **Step 3: Test Multi-journal type even though Phase 1 uses one component**

Keep Vector-compatible API; single Position is a convenience wrapper.

- [ ] **Step 4: Commit**

---

### Task 10: Command Gateway and Lost ACK query

**Files:**
- Create: `core/sitina/commands/gateway.py`
- Create: `core/sitina/commands/outcomes.py`
- Test: `tests/test_command_outcomes.py`

**Interfaces:**
- Produces: `CommandGateway.submit()`, `query(command_id, request_hash) -> CommandResult`.

- [ ] **Step 1: Write all five result-state tests**

Cover COMMITTED, REJECTED, CONFLICT, RETRYABLE_NOT_ACCEPTED and UNKNOWN.

- [ ] **Step 2: Implement canonical lookup hierarchy**

In-memory verified index → segment indexes → canonical scan. SQLite miss returns UNKNOWN. Cold coverage unavailable fails closed.

- [ ] **Step 3: Test Lost ACK**

Kill after Frame durable and before response; reopen, resubmit same ID/hash, return identical AppendReceipt; different hash returns CONFLICT.

- [ ] **Step 4: Commit**

---

### Task 11: Capacity safety profile and emergency reserve

**Files:**
- Create: `core/sitina/runtime/capacity.py`
- Create: `config/capacity_profile.shadow.json`
- Test: `tests/test_capacity_gates.py`

**Interfaces:**
- Produces: hard parser limits, Admission Classes, Disk Gate, emergency quota.

- [ ] **Step 1: Test safety bounds**

Reject oversized envelope/Event/Frame before allocation; reserve cannot be consumed by Ordinary traffic.

- [ ] **Step 2: Implement NOT_YET_QUALIFIED profile**

Include explicit empty measured SLO fields; never expose defaults as supported capacity.

- [ ] **Step 3: Test disk gate combines percent, bytes, inode, rollover and staging headroom**

Most restrictive condition wins.

- [ ] **Step 4: Commit**

---

### Task 12: Kernel acceptance and benchmark harness

**Files:**
- Create: `tests/test_phase1_kernel_acceptance.py`
- Create: `benchmarks/journal_benchmark.py`
- Create: `docs/journal-kernel-operations.md`

**Interfaces:**
- Produces: fixture-only acceptance report and unqualified benchmark output.

- [ ] **Step 1: Run crash matrix**

Every append/CAS/rollover/offset/Object-proof/Reference-lease boundary under the default Process/OS Crash Profile. Full-fsync Power-loss Profile remains `NOT_YET_QUALIFIED` until hardware-specific qualification succeeds.

- [ ] **Step 2: Run delete/rebuild and zero-external tests**

Patch all external adapters to raise if called.

- [ ] **Step 3: Run benchmark matrix**

Record hardware/filesystem/profile and leave status `NOT_YET_QUALIFIED` until review approves thresholds.

- [ ] **Step 4: Run the applicable Phase -1 isolated suites**

Use Phase -1 `unit_fast`、`integration_isolated` and Phase 1 `crash_fault`; assert Production sentinels unchanged.

- [ ] **Step 5: Commit and stop**

Phase 1 exit does not authorize Production Cutover or Legacy data import.

---

# 第六部分：Phase 2 Run/Task/Process/Scheduling

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-2-run-task-scheduling.md`  
> 来源 SHA-256：`11c2067f68ac7aac9d6d281bc1f8c927ecb560803171b507b7ab5329ab2ae68a`

# Sitina B+ Phase 2 Run/Task/Process/Scheduling Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1/0/1 reports and a current Phase 2 Execution Manifest. All execution remains in an isolated `controlled_fixture` or `shadow` Physical Journal Root.

**Goal:** 在 Phase 1 Kernel 上实现 Run Admission、Task/TaskGraph、Task Attempt/Claim/Fence、Process Manager、SchedulerDecision、DispatcherDecision、Outbox 和 Timer 的最小可运行协作闭环。

**Architecture:** 每个拥有独立生命周期的 Entity 由自己的 Logical Stream 拥有；TaskGraph Node 是例外，由 TaskGraph Aggregate 独占定义/拓扑，物化后的执行生命周期才由绑定的 Task Stream 拥有。Projection 只产生 Eligibility/Candidate。Scheduler 提交不可变 Decision；Dispatcher 通过权威 Task Claim Command 赢得 CAS 后才派发。所有路径先在 Controlled/Shadow Profile 运行，不替换 Production Legacy Engine。

**Tech Stack:** Phase 1 Journal/CAS/Projection API、Python dataclasses/state machines、SQLite projections、现有 `task_graph.py`/`timeout_support.py` 作为 Legacy behavior oracle、`unittest`。

## Global Constraints

- Legacy Production Writer remains authoritative.
- No real provider or tool dispatch; use deterministic fixture worker.
- Task Claim and fencing token are one Task-stream transaction.
- `READY`/Blocked reasons are Projection states, not Task stream facts.
- Process/Timer/Outbox rows are candidates only.
- Every independent-stream Task/Protocol/Obligation/Resource creation uses the Phase 2 Permit-to-Entity Create-or-Tombstone Saga；TaskGraph Node remains owned only by TaskGraph Stream.
- Existing Legacy Task Graph、Timeout、Run Status、Replay and CLI semantics remain compatibility requirements unless a semantic change is explicitly approved.

---

### Task 1: Generic protocol state-machine kernel

**Files:**
- Create: `core/sitina/protocols/__init__.py`
- Create: `core/sitina/protocols/runtime.py`
- Test: `tests/test_protocol_runtime.py`

**Interfaces:**
- Produces: `ProtocolDefinition`, `Transition`, `TransitionResult`, `ProtocolTransitionRejected`.

- [ ] Write transition-matrix tests for allowed, invalid, terminal, duplicate and timeout transitions.
- [ ] Implement a pure transition function that emits Events but never writes storage.
- [ ] Bind protocol definition/policy hashes to instance creation.
- [ ] Run tests and commit.

---

### Task 2: Run lifecycle and Admission Permit

**Files:**
- Create: `core/sitina/protocols/run.py`
- Create: `core/sitina/protocols/permits.py`
- Test: `tests/test_run_admission.py`

**Interfaces:**
- Produces: `OpenRun`, `GrantPermit`, `ConsumePermit`, `BeginClosing`, `AbortClosing`, terminal commands.

- [ ] Test Permit Grant and BeginClosing serialize on Run stream CAS.
- [ ] Test old Admission Generation Commands fail closed.
- [ ] Implement Business Lifecycle `ACTIVE → CLOSING → terminal` with blocking facts, not `CLOSING_BLOCKED` state.
- [ ] Implement Closing Permit purpose/scope/count/depth validation.
- [ ] Run tests and commit.

---

### Task 2A: Generic independent-stream Permit-to-Entity creation saga

**Files:**
- Create: `core/sitina/protocols/entity_creation.py`
- Test: `tests/test_permit_entity_creation.py`

**Interfaces:**
- Produces: stable Entity Create Process for Task、Protocol、Obligation、Claim and Resource Lease. It explicitly rejects `TASK_GRAPH_NODE` as an independent Entity Kind.

- [ ] Freeze `entity_id/entity_kind/create_command_id/request_hash/idempotency_binding` in the Run Permit transaction.
- [ ] Target `NO_STREAM` CAS creates either immutable Entity Created fact or permanent Creation-aborted Tombstone.
- [ ] Test Created-first forces forward Permit confirmation；Tombstone-first permits release only after canonical query.
- [ ] Test ACK loss、process crash、projection lag and duplicate Source Event replay the same Command ID.
- [ ] Test same Entity ID/different Hash is an integrity incident.
- [ ] Test attempting to create `task-graph-node/<id>` as a Stream is rejected because TaskGraph owns Node identity/topology.
- [ ] Include pending creation processes in Closing/Terminal barriers.
- [ ] Commit before creating any Phase 2 Entity from another Stream.

---

### Task 3: TaskGraph stream and topology commands

**Files:**
- Create: `core/sitina/protocols/tasks.py`
- Test: `tests/test_task_graph_protocol.py`

**Interfaces:**
- Produces: Add/Supersede/Split/Merge Task and Add/Remove Dependency commands/events.

- [ ] Test expected graph version, cycle rejection, supersedes lineage and required-obligation impact.
- [ ] Implement immutable Task specification generation; never mutate business meaning in place.
- [ ] Implement explicit gating constraint for `BlockTaskNode`; do not write generic Task BLOCKED state.
- [ ] Implement `TaskDefinitionMaterializationProcess`: TaskGraph CAS owns `TaskNodeAdded/MaterializationPending`；stable `CreateTask` performs `NO_STREAM` Task Stream creation；TaskGraph then records `TaskNodeMaterialized` or permanent `TaskNodeMaterializationAborted`.
- [ ] Test Pending/Aborted Node cannot schedule、does not become a second Aggregate and blocks Closing until the materialization process reaches terminal disposition.
- [ ] Project topology and graph hash.
- [ ] Run tests and commit.

---

### Task 4: Task Attempt, Claim, Lease and Fence

**Files:**
- Modify: `core/sitina/protocols/tasks.py`
- Test: `tests/test_task_claims.py`

**Interfaces:**
- Produces: `ClaimTask -> TaskClaimed(task_attempt_id, claim_generation, fencing_token)` and renew/release/expire/submit/accept events.

- [ ] Test exactly one active Attempt per Task.
- [ ] Test duplicate Claim Command returns original fence.
- [ ] Test old fence cannot submit after expiry/reassign.
- [ ] Test Attempt failure does not automatically fail Task.
- [ ] Implement Acceptance bound to exact Artifact Hash and Policy.
- [ ] Run tests and commit.

---

### Task 5: Resource Lease protocol

**Files:**
- Create: `core/sitina/protocols/resource_leases.py`
- Test: `tests/test_resource_leases.py`

**Interfaces:**
- Produces: Reserve/Activate/Release/Revoke events and progress-evidence renewal.

- [ ] Test partial multi-resource reservation cannot activate Task.
- [ ] Test renew requires accepted progress evidence and respects max count/total duration.
- [ ] Implement compensation release process input.
- [ ] Run tests and commit.

---

### Task 6: Process Manager and durable step identity

**Files:**
- Create: `core/sitina/scheduling/__init__.py`
- Create: `core/sitina/scheduling/processes.py`
- Test: `tests/test_process_managers.py`

**Interfaces:**
- Produces: Journal-backed `process/<process_id>` state with stable `step_key`, `command_id`, generation/step/max/visited hashes.

- [ ] Test replaying same Source Event regenerates identical Command ID.
- [ ] Test repeated transition hash and max-steps produce StallDetected.
- [ ] Implement pending Command outcome reconciliation through Phase 1 Command Query.
- [ ] Prove Process Projection deletion cannot lose pending work because Source/Step/Outcome facts are recoverable from Journal.
- [ ] Run tests and commit.

---

### Task 7: SchedulerDecision

**Files:**
- Create: `core/sitina/scheduling/decisions.py`
- Create: `core/sitina/scheduling/scheduler.py`
- Test: `tests/test_scheduler_decisions.py`

**Interfaces:**
- Produces: immutable `SchedulerDecision` with candidates, filters, scorecards and ordered attempts.

- [ ] Test filter order eligibility→safety→dependencies→capability→lease→budget→policy.
- [ ] Test Aging never makes an ineligible candidate eligible.
- [ ] Test Decision records exact source Frontier/versions and Policy Hash.
- [ ] Implement deterministic tie-breaker using stable IDs, not iteration order.
- [ ] Run tests and commit.

---

### Task 8: Journal-backed Outbox and DispatcherDecision

**Files:**
- Create: `core/sitina/scheduling/dispatcher.py`
- Modify: `core/sitina/projections/schema.py`
- Test: `tests/test_dispatch_outbox.py`

**Interfaces:**
- Produces: projected Outbox rows; authoritative Decision Consume/Attempt/Exhaust/Invalidate events.

- [ ] Test SQLite-only status cannot dispatch.
- [ ] Test TaskClaimed must commit before fixture worker receives work.
- [ ] Test CAS conflict follows frozen next-action policy.
- [ ] Test Closing invalidates old decisions via `DecisionInvalidatedByClosing`.
- [ ] Implement Lost ACK recovery with same Command ID.
- [ ] Run tests and commit.

---

### Task 9: Durable timers and clock uncertainty

**Files:**
- Create: `core/sitina/scheduling/timers.py`
- Test: `tests/test_durable_timers.py`

**Interfaces:**
- Produces: projected due candidates and stable target Command IDs.

- [ ] Test restart rebuilds timers from UTC deadline.
- [ ] Test wall-clock rollback does not fire early.
- [ ] Test large uncertainty creates incident/holds takeover.
- [ ] Implement monotonic wait only within process lifetime.
- [ ] Run tests and commit.

---

### Task 10: Terminal Eligibility V1 projection

**Files:**
- Create: `core/sitina/protocols/terminal.py`
- Modify: `core/sitina/projections/schema.py`
- Test: `tests/test_terminal_eligibility.py`

**Interfaces:**
- Produces: incremental candidate counts and authoritative full-validation command input.

- [ ] Test every blocker: Permit, Process, Decision/Outbox, Command, Claim/Lease, Approval, Conflict, Effect placeholder, Dead Letter, Checkpoint.
- [ ] Test Projection eligibility cannot directly terminal Run.
- [ ] Implement deterministic FAILED/CANCELLED/SUCCEEDED choice from authoritative fact refs.
- [ ] Run tests and commit.

---

### Task 11: Compatibility adapter into existing Engine

**Files:**
- Create: `core/sitina/orchestrator/bplus_adapter.py`
- Modify: `core/sitina/orchestrator/engine.py`
- Modify: `config/sitina.yaml`
- Test: `tests/test_bplus_shadow_runtime.py`

**Interfaces:**
- Produces: Feature Flag `runtime.bplus_shadow_enabled` and fixture-only shadow execution.

- [ ] Test default remains Legacy and generates no Shadow Journal writes.
- [ ] Test Shadow mode mirrors safe inputs but cannot run real provider/tool.
- [ ] Test disabling Shadow leaves Legacy output unchanged.
- [ ] Compare output through the Phase -1 Legacy Behavior Baseline；classify every mismatch instead of relying only on byte equality.
- [ ] Run the applicable Phase -1 isolated suites and commit.

---

### Task 12: Phase 2 acceptance

**Files:**
- Create: `tests/test_phase2_acceptance.py`
- Create: `docs/bplus-run-task-operations.md`

- [ ] Execute one fixture Run end-to-end through Run→Task→Decision→Claim→Fixture Result→Acceptance→Closing Candidate.
- [ ] Kill at every Process/Outbox/Claim/Timer boundary and recover deterministically.
- [ ] Delete Shadow Projection and rebuild identical semantic state.
- [ ] Assert zero external calls.
- [ ] Run Phase -1 isolated suites plus Phase 2 crash/fault cases；assert Production sentinels unchanged.
- [ ] Record compatibility classification and acceptance report, commit, and stop.

Phase 2 does not authorize Production Task dispatch or Authority Cutover.

---

# 第七部分：Phase 3 Collaboration Protocols

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-3-collaboration-protocols.md`  
> 来源 SHA-256：`1bdf1137e0c2ea1b2afd9246bb416861533194eaa5d469281a5dd29ce69f1244`

# Sitina B+ Phase 3 Collaboration Protocols Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1 through Phase 2 reports and a current Phase 3 Execution Manifest. Production Legacy authority and mutable files remain untouched.

**Goal:** 在 Phase 2 基础上实现 Proposal、Debate、Peer Review、Handoff、Merge、Arbitration、Rework、Obligation 和 Shared Blackboard 协议，并替换 Shadow Runtime 中对应的 Mutable JSON 权威路径。

**Architecture:** 每个 Protocol Instance 拥有独立 Stream/Version；Run 只持引用。协议本地 Terminal 与 Obligation Effect 分离。Blackboard 使用 Event-backed MVCC/CAS；冲突只阻断显式依赖的 Obligation。Legacy modules remain read-only behavior oracles in Shadow mode.

**Tech Stack:** Phase 1/2 Journal/Projection/State-machine APIs、Python、现有 `proposals.py`/`collaboration.py`/`handoff.py`/`arbitration.py`/`blackboard.py` fixture comparison、`unittest` property/table tests。

## Global Constraints

- Production Legacy authority remains unchanged.
- Protocol commands never edit another protocol’s Projection.
- Every protocol defines initial, allowed command/event/transition, terminal, retry, timeout and cancel behavior.
- No direct writes to legacy Blackboard/Handoff/Lease files in B+ Shadow namespace.
- Every Protocol/Obligation creation consumes a Run Permit through the generic Create-or-Tombstone Saga.
- Proposal、Claim、Review、Handoff、Blackboard and Agent Output bodies obey CAS Object-before-Event, classification, inline-size and secret rules；Journal stores only allowed structured metadata and Object references.
- Every Command passes Phase 1 Schema/Authorization/Capability handling before the Protocol transition function.

---

### Task 1: Obligation stream and protocol registry projection

**Files:**
- Create: `core/sitina/protocols/obligations.py`
- Modify: `core/sitina/projections/schema.py`
- Test: `tests/test_obligations.py`

**Interfaces:**
- Produces: `CreateObligation`, `Satisfy`, `Supersede`, `Fail`, `Cancel`, `CreateSuccessor`.

- [ ] Test local protocol terminal does not satisfy Run automatically.
- [ ] Test SUCCESSOR_REQUIRED creates new Obligation and linked protocol.
- [ ] Test Obligation/Successor creation uses stable cross-stream Saga identities and survives ACK loss.
- [ ] Build Protocol Registry strictly from Created/Terminal Events.
- [ ] Test `required_for_run_terminal` accounting.
- [ ] Commit.

---

### Task 2: ProposalRound protocol

**Files:**
- Create: `core/sitina/protocols/proposals.py`
- Test: `tests/test_proposal_protocol.py`

**Interfaces:**
- Produces: frozen Round config, Proposal revisions, Evaluations, Selection/NoSelection.

- [ ] Table-test all Proposal/Round transitions.
- [ ] Enforce one selection per `(round_id, generation)` by stream CAS.
- [ ] Reject selecting REJECTED/NEEDS_REVISION proposals.
- [ ] Require new generation for participant/rubric/policy/deadline changes.
- [ ] Implement NoSelection next-action whitelist.
- [ ] Commit.

---

### Task 3: Knowledge Claim and Debate protocol

**Files:**
- Create: `core/sitina/protocols/claims.py`
- Create: `core/sitina/protocols/debate.py`
- Test: `tests/test_debate_protocol.py`

**Interfaces:**
- Produces: versioned Claim records, Responses and `SynthesisFinalized`.

- [ ] Test Response can reference only valid Claim/Target.
- [ ] Test Round/Token/Deadline bounds.
- [ ] Test synthesis includes included/excluded/unresolved claims and Evidence Map.
- [ ] Test NO_CONSENSUS creates successor Obligation instead of silent majority.
- [ ] Commit.

---

### Task 4: Peer Review and Artifact Acceptance

**Files:**
- Create: `core/sitina/protocols/reviews.py`
- Test: `tests/test_review_protocol.py`

**Interfaces:**
- Produces: ReviewRequest/Responses/Disposition and separate `AcceptArtifact` command.

- [ ] Test reviewer independence, capability, no conflicting lease and security-reviewer requirements.
- [ ] Test Review disposition does not accept Task.
- [ ] Test old Approval remains historical but is inapplicable to new Artifact Hash.
- [ ] Test Acceptance Process requires frozen reviews, criteria and exact hash.
- [ ] Commit.

---

### Task 5: Handoff protocol and generation identity

**Files:**
- Create: `core/sitina/protocols/handoffs.py`
- Test: `tests/test_handoff_protocol.py`

**Interfaces:**
- Produces: stable `handoff_id`, monotonic generation, Offer/Clarification/Accept/Reject/Claim/Execute/Submit/Verify/Rework.

- [ ] Test rejected generation never reopens.
- [ ] Test new generation revalidates policy/capability/budget/deadline and does not reuse acceptance/lease.
- [ ] Test accepted handoff cannot execute before valid Task Claim.
- [ ] Test high-risk sender/receiver cannot self-verify.
- [ ] Commit.

---

### Task 6: Merge protocol and Blackboard conflict routing

**Files:**
- Create: `core/sitina/protocols/merge.py`
- Test: `tests/test_merge_protocol.py`

**Interfaces:**
- Produces: Merge Open/Proposal/Validation/Merged/Failed/Escalated.

- [ ] Test schema-declared commutative/append-only/CRDT-compatible operations only.
- [ ] Test different JSON paths alone do not auto-merge.
- [ ] Test failed Merge creates Arbitration Obligation.
- [ ] Commit.

---

### Task 7: Arbitration and appeal

**Files:**
- Create: `core/sitina/protocols/arbitration.py`
- Test: `tests/test_arbitration_protocol.py`

**Interfaces:**
- Produces: Open/Admit/Decide/EnforcementPending/Enforced/Failed/Appeal.

- [ ] Test binding-effect scope and dispatcher block.
- [ ] Test only ENFORCED satisfies Arbitration Obligation.
- [ ] Test appeal generation/max/new-evidence/deadline/authority.
- [ ] Test same evidence cannot loop appeals.
- [ ] Commit.

---

### Task 8: Rework protocol

**Files:**
- Create: `core/sitina/protocols/rework.py`
- Test: `tests/test_rework_protocol.py`

**Interfaces:**
- Produces independent Rework only for multi-round adjudication; simple correction maps to new Task/Attempt.

- [ ] Test max retries and retry exhausted successor.
- [ ] Test failure-type enum and Acceptance Criteria binding.
- [ ] Commit.

---

### Task 9: Event-backed Blackboard MVCC

**Files:**
- Create: `core/sitina/protocols/blackboard.py`
- Test: `tests/test_blackboard_mvcc.py`

**Interfaces:**
- Produces: `PatchBlackboard`, document versions, conflict responses, merge requests.

- [ ] Test namespace-specific schema/writer/evidence/merge/classification.
- [ ] Test base version/hash CAS and stale conflict without document-stream mutation.
- [ ] Test Task/Handoff writes require valid `task_attempt_id` and fence.
- [ ] Test Agent read refs/versions and write intents/committed versions are recorded.
- [ ] Test conflict blocks only explicit dependent obligations.
- [ ] Test Patch/Object content above inline limit is published to encrypted CAS before Event and cannot leak secrets into Projection.
- [ ] Commit.

---

### Task 10: Protocol process integration

**Files:**
- Create: `core/sitina/protocols/coordinator.py`
- Modify: `core/sitina/scheduling/processes.py`
- Test: `tests/test_protocol_coordination.py`

**Interfaces:**
- Produces deterministic successor Commands from terminal protocol events.

- [ ] Test Event→Process→Command→Target Event chains.
- [ ] Test no cross-stream direct mutation.
- [ ] Test loop/stall detection across Debate→Proposal→Arbitration.
- [ ] Commit.

---

### Task 11: Legacy compatibility projections

**Files:**
- Create: `core/sitina/legacy/protocol_views.py`
- Modify: `core/sitina/orchestrator/bplus_adapter.py`
- Test: `tests/test_protocol_legacy_comparison.py`

**Interfaces:**
- Produces read-only compatibility views matching existing Proposal/Handoff/Blackboard reports.

- [ ] Compare fixed fixtures against current managers.
- [ ] Consume the Phase -1 Legacy Behavior Baseline and require explicit classification for changed Proposal/Handoff/Blackboard semantics.
- [ ] Ensure B+ Shadow path never writes `state/handoffs.json`, `state/blackboard*.json` or legacy proposal files.
- [ ] Report mismatches without changing authority.
- [ ] Commit.

---

### Task 12: Phase 3 acceptance

**Files:**
- Create: `tests/test_phase3_acceptance.py`
- Create: `docs/bplus-collaboration-protocols.md`

- [ ] Run a fixture with parallel proposals, review changes, handoff, Blackboard conflict, merge and arbitration.
- [ ] Crash/replay every protocol generation and enforcement boundary.
- [ ] Delete/rebuild Projection and compare protocol/obligation state.
- [ ] Assert zero external calls and no legacy mutable-file writes.
- [ ] Run isolated Phase -1 suites plus Phase 3 crash/replay cases；assert Production sentinels unchanged.
- [ ] Commit compatibility report and stop.

Phase 3 does not authorize Production Protocol Cutover.

---

# 第八部分：Phase 4 Effect/Observation

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-4-effects-observations.md`  
> 来源 SHA-256：`37df3a63ec7d176580b02aa9b1c9bb6364fe81ad7b6425633e424ee9177e30ce`

# Sitina B+ Phase 4 Effect/Observation Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1 through Phase 3 reports and a current Phase 4 Execution Manifest. All adapters are mock/simulated and use isolated Effect/Observation roots.

**Goal:** 实现所有外部信任域访问的 Effect/Attempt/Observation/Settlement 模型，确保 Lost Remote ACK、Timeout 和 Crash 不会触发盲目重复副作用。

**Architecture:** Immutable Effect Stream 唯一拥有 Outcome/Settlement；Observation Stream 只保存经过 Admission 的认证外部事实。每个 Effect Attempt 最多一次授权正文发送。Unknown 进入 Reconciliation 或 Policy Settlement；Compensation 是新 Effect。

**Tech Stack:** Phase 1–3 Journal/Protocol/Process APIs、现有 Provider/MCP/Tool Executor Adapter、Key Provider、CAS Quarantine、mock remote server、`unittest`。

## Global Constraints

- Phase 4 initially uses mock/simulated adapters only.
- No live mutation, message, publication, deletion, push or payment during acceptance.
- External Read/Disclosure also use Effect identity.
- Runtime Writer cannot access Evidence Signing Key.
- Task Fence authorizes new Transmission but never erases already possible external facts.
- External API Credential retrieval uses a dedicated `SecretProvider` capability, not the Object/Evidence `KeyProvider` interface.
- Observation/Receipt ingress may return only a custody receipt `DURABLY_RECEIVED` after the bounded Durable Ingress Spool barrier. Business/authority admission exists only as `JOURNAL_ADMITTED` after the Canonical Journal Frame is durable.
- A spool record is a stable intake candidate and never a business fact、Effect Outcome、Observation admission or authority root.
- Phase 4 implementation does not authorize any live capability；post-cutover activation is separately staged by risk class.

---

### Task 1: Effect model and exhaustive invariant matrix

**Files:**
- Create: `core/sitina/effects/__init__.py`
- Create: `core/sitina/effects/model.py`
- Test: `tests/test_effect_state_matrix.py`

**Interfaces:**
- Produces: immutable `EffectRequest`, Outcome/Settlement/Basis/Cardinality enums, invariant validator.

- [ ] Encode the exhaustive legal combinations from the specification.
- [ ] Test every legal combination and representative illegal combinations.
- [ ] Emit `EffectStateInvariantRejected` for unlisted combinations.
- [ ] Test semantic change requires new `effect_id`; safe retry only new `effect_attempt_id`.
- [ ] Commit.

---

### Task 2: Permit-to-Effect Saga and Tombstone

**Files:**
- Create: `core/sitina/effects/creation.py`
- Test: `tests/test_effect_creation_saga.py`

**Interfaces:**
- Produces: persistent Process state, `PermitConsumedPendingEffect`, `CreateEffect`, `EffectCreationAborted`.

- [ ] Test EffectRequested wins NO_STREAM CAS and forces Permit confirmation.
- [ ] Test Tombstone wins and only then permits release.
- [ ] Test ACK loss/retry automatically recovers.
- [ ] Test same ID/different Hash becomes Security Incident.
- [ ] Reserve Manual Reconciliation only for Authority/integrity loss.
- [ ] Commit.

---

### Task 3: Adapter capability manifest

**Files:**
- Create: `core/sitina/effects/adapters.py`
- Create: `config/effect_adapters.mock.json`
- Test: `tests/test_adapter_manifests.py`

**Interfaces:**
- Produces signed/versioned Adapter Manifest and Recovery Level A/B/C.

- [ ] Test semantic changes require new Effect ID.
- [ ] Test transport retry mode and `max_physical_sends_per_attempt=1`.
- [ ] Test idempotency retention window expiry changes risk policy.
- [ ] Reject untrusted/unsigned manifest in non-test profile.
- [ ] Commit.

---

### Task 4: Effect Attempt claim and transmission boundary

**Files:**
- Create: `core/sitina/effects/gateway.py`
- Test: `tests/test_effect_attempts.py`

**Interfaces:**
- Produces: Attempt Claim/Prepared/InvocationStarted/Disposition and dispatch fence.

- [ ] Test one active Attempt per Effect.
- [ ] Test Task and Dispatch Fence both valid before InvocationStarted.
- [ ] Test hidden SDK retry is disabled/exposed.
- [ ] Kill before/after InvocationStarted and verify ABORTED/MAY_HAVE_BEEN_SENT.
- [ ] Accept late observation even after Task fence expires.
- [ ] Commit.

---

### Task 5: Observation ingress and dual-stream application

**Files:**
- Create: `core/sitina/effects/observations.py`
- Test: `tests/test_effect_observations.py`

**Interfaces:**
- Produces: Ingress Admission, `ApplyAdmittedObservation`, Application disposition.

- [ ] Test signature/timestamp/nonce/replay/schema/manifest/effect/attempt/request identity.
- [ ] Quarantine unauthenticated/unmatched inputs.
- [ ] Test optional external ID fallback identities and ADVISORY behavior.
- [ ] Test Effect Stream CAS serializes concurrent observations.
- [ ] Test contradiction does not last-write-win.
- [ ] Commit.

---

### Task 6: Reconciliation and exposure accounting

**Files:**
- Create: `core/sitina/effects/reconcile.py`
- Test: `tests/test_effect_reconciliation.py`

**Interfaces:**
- Produces: Status Query Effects, Exposure resolution, current cardinality/risk.

- [ ] Test Level A idempotent retry/query.
- [ ] Test Level B queries before any new Attempt.
- [ ] Test Level C mutation enters Manual Action without retry.
- [ ] Test success plus unresolved second exposure => SUCCEEDED+RECONCILING.
- [ ] Test Not Found only proves absence when Manifest contract allows it.
- [ ] Commit.

---

### Task 7: Manual Policy Settlement

**Files:**
- Create: `core/sitina/effects/manual.py`
- Test: `tests/test_manual_effect_resolution.py`

**Interfaces:**
- Produces: authority-checked Resolution and Policy Disposition.

- [ ] Test Human Statement alone cannot confirm remote fact.
- [ ] Test Policy-settled Unknown preserves uncertainty, duplicate/loss risk and monitoring.
- [ ] Test late confirmation updates outcome but preserves settlement basis.
- [ ] Commit.

---

### Task 8: Compensation, mitigation and irreversible authorization

**Files:**
- Create: `core/sitina/effects/compensation.py`
- Test: `tests/test_compensation_effects.py`

**Interfaces:**
- Produces new linked Effect, chain depth, precondition and risk authorization.

- [ ] Test successful compensation does not rewrite original success.
- [ ] Test duplicate compensation prevented.
- [ ] Test irreversible Effect cannot claim compensated and requires mitigation/notification/risk acceptance.
- [ ] Commit.

---

### Task 9: Approval and credential boundary

**Files:**
- Create: `core/sitina/effects/approval.py`
- Create: `core/sitina/security/secret_provider.py`
- Create: `core/sitina/security/macos_secret_provider.py`
- Test: `tests/test_effect_approval_credentials.py`

**Interfaces:**
- Produces Journal-backed `approval/<approval_id>` exact approval binding and last-moment credential handle.

- [ ] Test request/target/amount/policy/risk/principal/scope/manifest changes invalidate approval.
- [ ] Test approval attempt/retry/expiry limits.
- [ ] Test SecretProvider returns an opaque, short-lived, minimum-scope handle only at Invocation boundary；raw value is unavailable to Runtime Writer/Verifier/Sealer.
- [ ] Assert raw secret absent from Journal/CAS metadata/Projection/Receipt/logs.
- [ ] Commit.

---

### Task 9A: Durable ingress spool and emergency intake capacity

**Files:**
- Create: `core/sitina/effects/ingress.py`
- Create: `core/sitina/effects/ingress_spool.py`
- Test: `tests/test_effect_ingress_durability.py`

**Interfaces:**
- Produces bounded Receipt/Observation intake with two non-interchangeable receipts: `DURABLY_RECEIVED` custody at the independent spool barrier and `JOURNAL_ADMITTED` authority admission at the Canonical Journal Frame barrier.

- [ ] Remove the ambiguous `Accepted` status. Test spool durability returns only `DURABLY_RECEIVED`; test only a durable Canonical Journal Frame returns `JOURNAL_ADMITTED`.
- [ ] Test `DURABLY_RECEIVED` cannot satisfy business acceptance、Effect Outcome、Observation admission、Closing、Projection authority or external-result settlement predicates.
- [ ] Test spool records bind source identity、raw evidence hash、classification、receive time、nonce/replay key and target hint without exposing raw secrets.
- [ ] Test restart drains the same stable Intake Command IDs into Security/Observation Streams and emits a durable mapping from the custody receipt to the resulting `JOURNAL_ADMITTED` receipt.
- [ ] Test invalid/quarantined intake reaches a terminal Journal disposition without ever being reported as admitted business truth.
- [ ] Test ordinary traffic cannot consume Observation/Receipt/Closing emergency reserve.
- [ ] Test both Journal and Spool unavailable stops outbound dispatch and returns an unreceived retryable failure；Spool-only availability never reports Journal admission.
- [ ] Commit before any live-ingress readiness claim.

---

### Task 10: Quarantine result pipeline

**Files:**
- Create: `core/sitina/effects/results.py`
- Modify: `core/sitina/cas/local.py`
- Test: `tests/test_tool_result_quarantine.py`

**Interfaces:**
- Produces Size/Decompression/Schema/Classify/Secret/Injection/Trust/Redaction pipeline.

- [ ] Test untrusted result never becomes system instruction.
- [ ] Test secret-positive object remains inaccessible and yields destruction attestation.
- [ ] Test clean redacted result publishes normal CAS capability.
- [ ] Commit.

---

### Task 11: Budget Bundle and operational circuit breaker

**Files:**
- Create: `core/sitina/effects/budgets.py`
- Create: `core/sitina/effects/breakers.py`
- Test: `tests/test_effect_budget_breaker.py`

**Interfaces:**
- Produces Journal-backed `budget-reservation/<reservation_id>` multi-budget process and `operational-control/<control_id>` final circuit-breaker authorization.

- [ ] Test InvocationStarted blocked until all Reservations activated.
- [ ] Test partial reservation compensation and leak obligation.
- [ ] Test actual cost overrun still records Receipt/Outcome.
- [ ] Test Breaker precheck plus final CAS authorization and bounded HALF_OPEN probes.
- [ ] Commit.

---

### Task 12: Closing Permit and Monitoring Transfer

**Files:**
- Create: `core/sitina/effects/closing.py`
- Create: `core/sitina/effects/monitoring.py`
- Test: `tests/test_effect_closing_monitoring.py`

**Interfaces:**
- Produces purpose/scope/depth bounded Closing Effect and durable Monitoring Transfer.

- [ ] Test Closing rejects ordinary effect expansion.
- [ ] Test Reconciliation/Compensation/Disclosure require linked Closing Permit.
- [ ] Test successor owner accepts before original Run ACK releases blocker.
- [ ] Test Terminal-after-transfer and late action uses successor authority.
- [ ] Commit.

---

### Task 13: ReadEffectSession

**Files:**
- Create: `core/sitina/effects/read_sessions.py`
- Test: `tests/test_read_effect_sessions.py`

**Interfaces:**
- Produces session query-slot/budget reservation, never business admission.

- [ ] Test every query still gets distinct Effect/Attempt/Receipt/Observation.
- [ ] Test Run/Closing Permit and Session Slot bind same Query Effect ID/Hash.
- [ ] Test tombstone releases slot; successful creation consumes slot.
- [ ] Commit.

---

### Task 14: Existing Provider/MCP/Tool adapters in shadow mode

**Files:**
- Modify: `core/sitina/runners/provider.py`
- Modify: `core/sitina/runners/mcp_adapter.py`
- Modify: `core/sitina/runners/tool_executor.py`
- Create: `core/sitina/effects/legacy_adapters.py`
- Test: `tests/test_effect_adapter_shadow.py`

**Interfaces:**
- Produces dry-run adapters that expose request/result identity without real mutation.

- [ ] First add tests proving existing direct execution ordering risks.
- [ ] Wrap calls behind Effect Gateway only under shadow feature flag.
- [ ] Ensure default Legacy behavior unchanged before cutover.
- [ ] Compare Provider/MCP/Tool accounting、approval、risk、CLI and replay behavior with the Phase -1 Legacy Baseline；classify every semantic difference.
- [ ] Disable live/mutating adapters in acceptance.
- [ ] Commit.

---

### Task 15: Side-effect Audit Manifest projection

**Files:**
- Create: `core/sitina/effects/audit.py`
- Test: `tests/test_side_effect_audit.py`

- [ ] Verify all admitted Effects, Attempts, fences, permits, approvals, observations, reconciliations, compensations, unknowns and budget events.
- [ ] Report confirmed outcome separately from Policy-settled Unknown.
- [ ] Fail predicate on unexplained in-flight/exposure/secret/destruction gap.
- [ ] Commit.

---

### Task 16: Phase 4 acceptance

**Files:**
- Create: `tests/test_phase4_acceptance.py`
- Create: `docs/bplus-effect-gateway-operations.md`

- [ ] Run mock adapters for Levels A/B/C with crash at each transmission window.
- [ ] Prove the mock Level A contract yields exactly-once logical settlement and no duplicate mock remote execution while the declared idempotency window is valid；do not generalize this to universal physical exactly-once.
- [ ] Prove Unknown is not blindly retried.
- [ ] Prove every spool receipt remains custody-only until a matching Canonical Frame yields `JOURNAL_ADMITTED`；no acceptance predicate consumes `DURABLY_RECEIVED`.
- [ ] Delete/rebuild Effect/Observation projections.
- [ ] Assert zero live external effects.
- [ ] Run isolated Phase -1 suites plus Phase 4 transmission-window crash cases；assert Production sentinels unchanged.
- [ ] Record a staged activation readiness matrix (`MOCK_ONLY`, `EXTERNAL_READ`, `REVERSIBLE_MUTATION`, `HIGH_RISK_OR_IRREVERSIBLE`), commit, and stop at `MOCK_ONLY`.

Phase 4 does not authorize live Tool Gateway Cutover.

---

# 第九部分：Phase 5 Evidence/Archive

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-5-evidence-archive.md`  
> 来源 SHA-256：`eabb84e2daa861fe5ba71ca8ea3b6872f5c5aa28f0ec8d489c1ee59ebe1df8c8`

# Sitina B+ Phase 5 Evidence/Archive Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1 through Phase 4 reports and a current Phase 5 Execution Manifest. Evidence/Archive remains Shadow/Controlled；Production Seal、Transfer、Delete and Eviction are forbidden。

**Goal:** 实现 B+ O/P/T V1、PreTerminal Checkpoint、Evidence Package Core/Assessment/Seal、Supplement、Archive Copy、Replica/Retention/GC、Canonical Backup 和隔离 Restore Drill。

**Architecture:** Business Terminal、Evidence Generation、Archive Job 和 Archive Copy 相互独立。Package Core→Assessment→Seal→Bundle 四层 Hash 无循环。V1 使用 exactly-one-component 的 `SignedFrontierVectorV1` 表达单 Journal/单 Epoch O/P/T；Multi-journal V2 只扩展组件数量，不更换类型。Bundle 不替代 Journal/CAS Authority。

**Tech Stack:** Phase 1–4 Journal/CAS/Protocol/Effect APIs、frozen Canonical/Crypto Profiles、Ed25519 signing capability、locked deterministic tar.zst profile、SQLite projections、capability-restricted and process-isolated replay environment、layered `unittest`。

## Global Constraints

- Still Shadow/Controlled; no Production Authority cutover.
- Evidence Builder cannot sign; Verifier read-only; Sealer only exact PASSED Assessment.
- Replay capability claims 必须分级：普通 child process/monkeypatch 只能声称 `APPLICATION_GUARDED_ZERO_EFFECT`；只有通过 adversarial qualification 的 `ReplayIsolationProvider` 才能声称 `ENFORCED_SANDBOX_ZERO_EFFECT`。
- Automatic hot eviction remains disabled.
- Legacy Evidence Bundle remains compatibility export.
- Evidence Package、Assessment、Seal、Supplement、Archive Job and Archive Copy lifecycle facts are Journal-backed Streams；filesystem artifacts and SQLite summaries are representations only.
- V1 Seal eligibility, minimum Completeness, Trust/Timestamp and Self-containment policy must be frozen before building a Package.

---

### Task 0: Evidence policy, trust and deterministic container profiles

**Files:**
- Create: `config/evidence_policy.bplus_v1.json`
- Create: `docs/bplus-profiles/evidence-trust-v1.md`
- Create: `docs/bplus-profiles/bundle-container-v1.md`
- Test: `tests/test_evidence_policy_profile.py`

**Interfaces:**
- Produces frozen Seal eligibility, minimum proof, signature/trust and container rules.

- [ ] Define the minimum accepted V1 Completeness Level；V1 cannot claim `CRYPTOGRAPHICALLY_COMPLETE` without omission proof.
- [ ] Define when `ASSERTED`、`STREAM_CHAIN_VERIFIED` or `JOURNAL_INDEX_PROVEN` can receive PASSED versus INCOMPLETE/UNVERIFIABLE assessment.
- [ ] Fix Ed25519 signature encoding、Key ID、Trust Package、trusted-time availability and degraded historical-validity semantics.
- [ ] Lock zstandard dependency/version/options and deterministic tar path/order/mode/uid/gid/mtime rules；if dependency is unavailable, support logical-directory Artifact without falsely claiming deterministic `tar.zst`.
- [ ] Bind the policy/profile hashes into Core、Assessment and Seal Statement.
- [ ] Commit before Task 1.

---

### Task 1: O/P/T V1 typed references and PreTerminal Checkpoint

**Files:**
- Create: `core/sitina/evidence/__init__.py`
- Create: `core/sitina/evidence/frontier.py`
- Create: `core/sitina/evidence/checkpoint.py`
- Test: `tests/test_opt_v1.py`

**Interfaces:**
- Produces: exactly-one-component `SignedFrontierVectorV1` for `ObservationFrontier`、`DerivedFrontier` and `TerminalRef`, plus `PreTerminalCheckpoint`.

- [ ] Test every V1 O/P/T carries exactly one signed component binding Journal ID/Epoch/Position/Commitment；zero or multiple components are rejected.
- [ ] Test the component shape is forward-compatible with Multi-journal V2 while V1 semantics remain degenerate single-component vectors.
- [ ] Test every admitted Observation ≤ O applied/dispositioned by P.
- [ ] Test checkpoint hashes TaskGraph/Blackboard/Protocol/Obligation/Effect/Eligibility/Object manifest.
- [ ] Test Terminal references O/P/proof/checkpoint/eligibility/outcome refs.
- [ ] Commit.

---

### Task 2: Terminal coordinator V1

**Files:**
- Create: `core/sitina/evidence/terminal.py`
- Modify: `core/sitina/protocols/terminal.py`
- Test: `tests/test_terminal_coordinator.py`

**Interfaces:**
- Produces BeginClosing→Drain→O/P→Checkpoint→unique T.

- [ ] Inject every blocker from spec.
- [ ] Test no forbidden mutation after P.
- [ ] Test duplicate terminal command returns original result.
- [ ] Test failed/cancelled/succeeded deterministic outcome.
- [ ] Commit.

---

### Task 3: Evidence Package Core and generation lifecycle

**Files:**
- Create: `core/sitina/evidence/package.py`
- Test: `tests/test_evidence_package.py`

**Interfaces:**
- Produces stable package ID, immutable generation, predecessor, Core Body/Hash.

- [ ] Test Core hash excludes Assessment/Seal/Artifact/self-hash.
- [ ] Test remediation creates new generation, old incomplete remains immutable.
- [ ] Test dependency closure traversal root/edge/visited hashes.
- [ ] Test `evidence/<package_id>` Events, not files/SQLite rows, own generation lifecycle and accepted assessments.
- [ ] Commit.

---

### Task 4: Completeness and self-containment assessment

**Files:**
- Create: `core/sitina/evidence/completeness.py`
- Test: `tests/test_evidence_completeness.py`

**Interfaces:**
- Produces ASSERTED/STREAM_CHAIN_VERIFIED/JOURNAL_INDEX_PROVEN/CRYPTOGRAPHICALLY_COMPLETE and verify/replay/inspect capabilities.

- [ ] Table-test necessary proofs and forbidden claims.
- [ ] Test self-containment remains orthogonal.
- [ ] Test missing CAS/key/dependency/index proof downgrades or fails.
- [ ] Ensure V1 cannot claim cryptographic completeness without omission proof.
- [ ] Commit.

---

### Task 5: Evidence Assessment and verifier identity

**Files:**
- Create: `core/sitina/evidence/assessment.py`
- Test: `tests/test_evidence_assessment.py`

**Interfaces:**
- Produces immutable Assessment with verifier binary/version/policy/canonicalization/predicates/hash.

- [ ] Test FAILED vs INCOMPLETE vs UNVERIFIABLE vs CONTRADICTED.
- [ ] Test verifier crash does not automatically terminal package.
- [ ] Test Assessment binds exact Core Hash.
- [ ] Enforce read-only verifier interface.
- [ ] Commit.

---

### Task 6: Seal Statement and capability separation

**Files:**
- Create: `core/sitina/evidence/seal.py`
- Modify: `core/sitina/security/key_provider.py`
- Test: `tests/test_evidence_seal.py`

**Interfaces:**
- Produces Seal Statement binding Core+Assessment, trusted-time status, signer identity.

- [ ] Test Builder cannot sign and Runtime Writer cannot request signing key.
- [ ] Test Sealer rejects non-PASSED/wrong Core/wrong policy Assessment.
- [ ] Test valid-at-seal vs currently-trusted states.
- [ ] Test key compromise creates new Assessment, not replacement signature.
- [ ] Commit.

---

### Task 7: Bundle Artifact formats

**Files:**
- Create: `core/sitina/evidence/bundle.py`
- Test: `tests/test_bundle_artifacts.py`

**Interfaces:**
- Produces logical directory and deterministic container artifact with semantic/container hashes.

- [ ] Test compression metadata/order/owner/path does not affect semantic hash.
- [ ] Test container byte changes affect container hash.
- [ ] Test same generation multiple Artifacts enclose identical Core/Assessment/Seal.
- [ ] Test capability manifest for embedded/external refs.
- [ ] Commit.

---

### Task 8: Offline replay and qualified isolation capabilities

**Files:**
- Create: `core/sitina/evidence/replay.py`
- Create: `core/sitina/evidence/sandbox.py`
- Create: `core/sitina/evidence/isolation_provider.py`
- Test: `tests/test_offline_replay.py`

**Interfaces:**
- Produces replay-original/current-audit/verify-only/inspect.

- [ ] Patch Provider/MCP/Tool/Git/Publish/File mutation to fail if called；this is defense in depth and by itself yields only `APPLICATION_GUARDED_ZERO_EFFECT`.
- [ ] Define `ReplayIsolationProvider` with declared network、process、filesystem、device、credential and host-control deny guarantees plus a stable provider/profile hash.
- [ ] An ordinary separate child process with sanitized environment and monkeypatch guards must never be labeled an OS sandbox.
- [ ] A container、VM、application sandbox or OS policy may claim `ENFORCED_SANDBOX_ZERO_EFFECT` only after its read-only input、dedicated output、no-credential、network/process/external-write policy passes the qualification suite.
- [ ] Startup capability probe selects `ENFORCED_SANDBOX_ZERO_EFFECT` only for a currently qualified provider；otherwise fail closed where policy requires it or downgrade explicitly to `APPLICATION_GUARDED_ZERO_EFFECT`.
- [ ] Attempt direct socket、DNS、subprocess、`ctypes`/FFI、absolute-path writes、symlink escape、device access and inherited-fd use in adversarial fixtures；all must be denied for the enforced profile.
- [ ] Test replay-original stops at T and presents existing Assessment without generating it.
- [ ] Test current-audit applies accepted Supplements only.
- [ ] Test disposable Projection and no live Position/Permit/Lease.
- [ ] Commit.

---

### Task 9: Evidence Supplement chain

**Files:**
- Create: `core/sitina/evidence/supplements.py`
- Test: `tests/test_evidence_supplements.py`

**Interfaces:**
- Produces Body→Assessment→Signature→Record Hash CAS chain.

- [ ] Test hash preimage exclusions and bindings.
- [ ] Test concurrent supplement CAS prevents forks.
- [ ] Test late contradiction changes current audit only.
- [ ] Test original Seal/Terminal/Assessment unchanged.
- [ ] Commit.

---

### Task 10: Archive Job and Copy streams

**Files:**
- Create: `core/sitina/archive/__init__.py`
- Create: `core/sitina/archive/jobs.py`
- Create: `core/sitina/archive/copies.py`
- Test: `tests/test_archive_copies.py`

**Interfaces:**
- Produces staged/final verification, Copy identity/residency/assessment.

- [ ] Test Staging verify then final-location reopen verify.
- [ ] Test Job completion does not imply long-term replica compliance.
- [ ] Test Copy can be STORED+CONTRADICTED.
- [ ] Test summaries are projections only.
- [ ] Test `archive-job/<job_id>` and `archive-copy/<copy_id>` Streams are the only lifecycle owners.
- [ ] Commit.

---

### Task 11: Replica policy and retention-operation authorization

**Files:**
- Create: `core/sitina/archive/retention.py`
- Create: `core/sitina/archive/retention_operations.py`
- Test: `tests/test_replica_eviction.py`

**Interfaces:**
- Produces policy-compliant Copy Set evaluator and Journal-backed `retention-operation/<operation_id>` lifecycle. This is independent of Evidence、Archive Job and GC Cycle streams.

- [ ] Test count/fault-domain/region/provider/admin/key-domain/verification-age.
- [ ] Test eviction-after set remains compliant.
- [ ] Test incomplete evidence/legal hold/active jobs/cross-run refs block.
- [ ] Test Bundle does not substitute Journal/CAS unless registered canonical residency.
- [ ] Implement the only legal lifecycle: `PROPOSED → ASSESSED → APPROVED → FENCED → EXECUTING → RECONCILING → VERIFIED → COMPLETED`, with terminal `ABORTED` and fail-closed `FAILED_UNKNOWN` branches.
- [ ] Bind operation kind、exact object/copy set、policy/catalog/frontier snapshots、holds、approval quorum、executor identity、deadline and reconciliation evidence into the operation hash.
- [ ] Test missing/stale approval、lost executor ACK、catalog drift、new hold、unknown outcome or verifier disagreement cannot reach `COMPLETED` and cannot be treated as authorization for another operation.
- [ ] Do not implement destructive delete in this phase；`EXECUTING` uses a no-op/dry-run executor and actual Delete/Hot Eviction remains capability-disabled.
- [ ] Commit.

---

### Task 12: Canonical backup barrier

**Files:**
- Create: `core/sitina/archive/backup.py`
- Test: `tests/test_canonical_backup.py`

**Interfaces:**
- Produces fixed Journal Frontier, Backup/GC Hold, reachable CAS closure and backup manifest.

- [ ] Test active prefix freeze or forced rollover.
- [ ] Test GC cannot delete held objects.
- [ ] Test missing reachable object fails backup.
- [ ] Test isolated verify/restore before hold release.
- [ ] Commit.

---

### Task 13: Restore and disaster recovery drill

**Files:**
- Create: `core/sitina/archive/restore.py`
- Test: `tests/test_restore_drill.py`

**Interfaces:**
- Produces temporary rehydration and canonical DR validation; no real writer activation by default.

- [ ] Test Journal/CAS identity/hash/chain/object closure.
- [ ] Test same ID/different Hash incident.
- [ ] Test different recovered bytes require new Epoch.
- [ ] Test restore uses final cold Copy, not staging.
- [ ] Commit.

---

### Task 14: Fixed-epoch GC mark/quarantine/destruction dry-run

**Files:**
- Modify: `core/sitina/cas/gc.py`
- Test: `tests/test_retention_gc.py`

- [ ] Start each `gc-cycle/<cycle_id>` by atomically freezing `GCMarkFrontier`、`SignedFrontierVectorV1`、GC Epoch、all participating catalog version IDs and hold snapshot IDs.
- [ ] Mark only against that immutable snapshot；scan all hot/cold catalogs、supplements、Migration Workspace roots、Production Migration Control roots、holds and leases.
- [ ] Treat canonical references and reference leases created after `GCMarkFrontier` as post-frontier roots that must be reconciled before any candidate can advance.
- [ ] Test required index unavailable => fail closed.
- [ ] Test catalog/version drift、unreadable hold snapshot、expired epoch or unresolved post-frontier root invalidates the candidate instead of silently widening/narrowing reachability.
- [ ] Test grace→quarantine→second confirmation.
- [ ] Route every candidate through its own Task 11 `retention-operation/<operation_id>`；a GC cycle can propose but cannot authorize deletion.
- [ ] Keep actual delete/crypto-erasure disabled；produce signed candidate and attestation preview only.
- [ ] Commit.

---

### Task 15: Legacy Evidence Bundle compatibility label

**Files:**
- Modify: `core/sitina/orchestrator/evidence_bundle.py`
- Test: `tests/test_legacy_evidence_label.py`

- [ ] Back up file first.
- [ ] Add explicit `artifact_integrity_verified_compatibility_export` label.
- [ ] Prevent legacy bundle from claiming B+ Seal/Completeness.
- [ ] Default Legacy behavior remains portable/hash-verified.
- [ ] Commit.

---

### Task 16: Phase 5 acceptance

**Files:**
- Create: `tests/test_phase5_acceptance.py`
- Create: `docs/bplus-evidence-archive-operations.md`

- [ ] Produce fixture Run T, Package Core, PASSED Assessment, Seal, Bundle, Archive Copy.
- [ ] Replay from final cold Copy with zero external I/O.
- [ ] Inject every Evidence Barrier blocker and assert no Seal/Eviction.
- [ ] Prove V1 rejects zero/multi-component frontiers and accepts exactly one signed component.
- [ ] Prove GC reachability is reproducible from the fixed frontier/epoch/catalog/hold snapshot and post-frontier roots are never lost.
- [ ] Prove retention-operation lost ACK enters `RECONCILING` or `FAILED_UNKNOWN`, never implicit success；assert destructive capabilities remain absent.
- [ ] Apply late Supplement and prove original bytes unchanged.
- [ ] Run isolated Phase -1 suites plus Phase 5 replay/archive fault cases；assert Production sentinels unchanged.
- [ ] Record actual Replay isolation capability and Evidence Policy hashes, commit, and stop.

Phase 5 does not authorize Production Seal, Archive Transfer, GC deletion or Hot Eviction.

---

# 第十部分：Phase 6A Cutover Tooling/Readiness

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-6a-cutover-tooling-readiness.md`  
> 来源 SHA-256：`42425b3af37e4331218401239cfc2805824f57d99b552a7c142e441de4fd1594`

# Sitina B+ Phase 6A Cutover Tooling and Readiness Implementation Plan

> **For Codex execution:** Requires PASSED Phase -1 through Phase 5 reports and a current Phase 6A Execution Manifest. Phase 6A is implementation、simulation and evidence generation only. It must not access、freeze、import into or mutate any Production root.

**Goal:** 完成并在隔离 fixture 上验证 Authority Resolver、Production Genesis、Migration Control、Journal-first routing、fixed-frontier comparison、rebuild、dry-run、lost-ACK recovery 和回退工具，产出可供另一次获权操作审查的 `CutoverToolingReady` 报告。

**Architecture:** Phase 6A does not transfer authority. It proves that every tool needed by Phase 6B is deterministic、fail-closed and independently reviewable. Authority is resolved only from verified Authority Control facts and the verified Cutover Outcome；a phase label、CLI flag、feature flag、file presence or readiness report can never select a writer.

**Tech Stack:** Phase 0–5 components、Kernel Writer Fence、Authority Control Stream、Legacy Read-only Adapter、Shadow Comparison、fixture-only Production Genesis builder、maintenance CLI、signed readiness report、isolated backup/restore fixtures.

## Global Constraints

- No Production path、credential、journal identity、key namespace、Legacy source or external capability may be supplied to a Phase 6A test or command.
- All roots are fixture/shadow roots that are syntactically and permission-wise distinguishable from Production.
- `CutoverToolingReady` is evidence only. It grants no maintenance window、writer authority、snapshot permission、migration permission or external capability.
- No phase enum maps directly to a writer. Every write attempt must consume a fresh `AuthorityResolution` produced by `AuthorityResolver` from verified control facts.
- Ambiguous、missing、unverifiable or ACK-unknown Authority Control state resolves to a no-writer state.
- No Legacy deletion、Hot Eviction、live Effect、Production Seal or real Archive Transfer.

---

### Task 1: Frozen cutover contracts and readiness predicate registry

**Files:**
- Create: `core/sitina/legacy/cutover_contracts.py`
- Create: `config/cutover_contracts.bplus_v1.json`
- Test: `tests/test_cutover_contracts.py`

**Interfaces:**
- Produces stable schemas and canonical hashes for Cutover Command、Outcome、Verification、Authority Resolution、Migration Control and readiness predicates.

- [ ] Freeze `command_id + request_hash` identity and canonical bytes before any operational use.
- [ ] Freeze the exhaustive predicate IDs for Phase -1–5 reports、capacity、keys、backup/restore、writer-fence coverage、Effect drain、monitoring transfer、migration、dual-read and rebuild.
- [ ] Reject unknown predicate IDs、schema drift、non-canonical hashes and unsigned policy input.
- [ ] Bind the exact contract/profile hashes into every later report.
- [ ] Commit before implementing state-dependent tooling.

---

### Task 2: Authority Resolver and fail-closed state machine

**Files:**
- Create: `core/sitina/authority/__init__.py`
- Create: `core/sitina/authority/resolver.py`
- Create: `core/sitina/authority/model.py`
- Test: `tests/test_authority_resolver.py`

**Interfaces:**
- Produces `AuthorityResolution` in exactly one of:
  - `LEGACY_WRITER_AUTHORIZED`
  - `CUTOVER_PREPARED_NO_WRITER`
  - `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER`
  - `JOURNAL_WRITER_AUTHORIZED`
  - `RECOVERY_REQUIRED_NO_WRITER`

- [ ] Derive `LEGACY_WRITER_AUTHORIZED` only from a verified legacy-authority fact plus absence proof for any conflicting committed Cutover.
- [ ] Derive `JOURNAL_WRITER_AUTHORIZED` only from the verified committed Cutover Outcome for the exact Production Genesis、Legacy Snapshot and stable Command ID/Hash.
- [ ] Resolve pending submission、lost ACK、unreadable control stream、signature failure、same-ID/different-hash、continuity uncertainty or conflicting evidence to a no-writer state.
- [ ] Prohibit all constructors/properties of Phase or Readiness enums from returning a writer.
- [ ] Bind resolution ID、verified input frontier、input hashes、resolver binary/profile and expiry/recheck rules.
- [ ] Table-test every legal and illegal combination, including restart and stale-cache behavior.
- [ ] Commit.

---

### Task 3: Revalidate global Legacy writer-fence coverage

**Files:**
- Modify: `core/sitina/legacy/fence.py`
- Modify: all top-level writer entry modules identified by Phase 0 scan
- Test: `tests/test_legacy_writer_fence_coverage.py`

**Interfaces:**
- Produces exhaustive guard registry and signed coverage report.

- [ ] Re-scan DB/JSONL/state/checkpoint/manifest/replay/evidence writers；any sink added after Phase 0 without a guard blocks readiness.
- [ ] Test a simulated frozen state prevents every direct mutation path.
- [ ] Test a stale or non-authorizing `AuthorityResolution` cannot open any sink.
- [ ] Allow only read-only fixture snapshot/inventory and the specifically authorized fixture Journal writer.
- [ ] Commit.

---

### Task 4: Separate Production Genesis builder and namespace barrier

**Files:**
- Create: `core/sitina/legacy/production_genesis.py`
- Test: `tests/test_production_journal_genesis.py`

**Interfaces:**
- Produces a genesis artifact whose identity cannot be confused with Shadow、Fixture or Migration Workspace artifacts. Phase 6A builds only fixtures.

- [ ] Require distinct real paths、journal IDs、epoch roots、key namespaces、permission profiles and environment attestations.
- [ ] Test a feature/phase flag cannot reinterpret a Shadow event as a Production event.
- [ ] Bind installation、format/profile、key/trust、baseline and intended Legacy Snapshot without claiming business authority.
- [ ] Treat same identity/different Genesis bytes as an integrity incident.
- [ ] Require a second operator/verifier to validate the eventual Phase 6B Genesis rather than copying a Phase 6A fixture identity.
- [ ] Commit.

---

### Task 5: Migration Workspace and Production Migration Control separation

**Files:**
- Create: `core/sitina/legacy/importer.py`
- Create: `core/sitina/legacy/migration_control.py`
- Test: `tests/test_legacy_import.py`

**Interfaces:**
- Produces deterministic candidate artifacts under `MigrationWorkspaceRoot` and authoritative provenance/control facts only under `ProductionMigrationControlStream`.

- [ ] Prohibit treating Migration Workspace files、SQLite indexes、reports or hashes as Production authority.
- [ ] Record source provenance、new canonical IDs、representation dedup and conflicting duplicate preservation.
- [ ] Prohibit projection-derived fact fabrication.
- [ ] Bind completion report to record counts、source closure、conversion rules、migration frontier and unresolved `legacy_incomplete` classes.
- [ ] Test Production Migration Control accepts only independently verified workspace outputs and remains non-business authority before Cutover.
- [ ] Commit.

---

### Task 6: Journal-first routing and reader-generation tooling

**Files:**
- Modify: `core/sitina/orchestrator/engine.py`
- Modify: `core/sitina/storage/store.py`
- Modify: `core/sitina/orchestrator/bplus_adapter.py`
- Modify: `core/sitina/cli.py`
- Create: `core/sitina/projections/readers.py`
- Test: `tests/test_journal_first_routing.py`
- Test: `tests/test_reader_generation.py`

**Interfaces:**
- Produces router and independent reader-generation registry driven only by current verified `AuthorityResolution`.

- [ ] Test Legacy-authorized fixture commands use only the Legacy sink and Journal-authorized fixture commands append Journal first.
- [ ] Test all no-writer resolutions reject business dispatch.
- [ ] Test CLI/phase/feature flags cannot override resolution.
- [ ] Test compatibility JSON/SQLite outputs are Projectors only.
- [ ] Test New→Legacy read-only reader rollback never invokes Legacy writer and always labels fixed Cutover Frontier/staleness.
- [ ] Prohibit Legacy Reader results from supplying Expected Version、Approval、Scheduler、Effect、Closing or Terminal preconditions.
- [ ] Keep Effect capability ceiling `MOCK_ONLY`.
- [ ] Commit.

---

### Task 7: Fixed-frontier dual-read comparison

**Files:**
- Modify: `core/sitina/legacy/compare.py`
- Test: `tests/test_cutover_dual_read.py`

- [ ] Compare at one signed frontier and frozen semantic profile.
- [ ] Require matches for terminal、task/protocol/effect accounting、checkpoints、audit、evidence and secret status.
- [ ] Permit only pre-approved `legacy_incomplete` classes.
- [ ] Produce a signed report binding input snapshot、journal frontier、reader generations and comparison binary/profile.
- [ ] Test catalog/profile drift invalidates the report.
- [ ] Commit.

---

### Task 8: Journal+CAS-only rebuild and recovery drills

**Files:**
- Create: `core/sitina/legacy/cutover_verify.py`
- Test: `tests/test_cutover_rebuild.py`

- [ ] Delete only a disposable fixture projection and rebuild solely from fixture Journal+CAS.
- [ ] Compare semantic checksums and Command Outcome/idempotency after projection loss.
- [ ] Inject crash/lost ACK before and after the simulated Cutover commit；recover only by querying the same Command ID/Hash.
- [ ] Prove unknown outcome selects `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER` across restart.
- [ ] Assert zero external calls and zero Production path access.
- [ ] Commit.

---

### Task 9: Maintenance dry-run and immutable operation manifest builder

**Files:**
- Create: `scripts/cutover-dry-run.py`
- Create: `core/sitina/legacy/maintenance_manifest.py`
- Create: `docs/cutover-runbook.md`
- Test: `tests/test_cutover_dry_run.py`

**Interfaces:**
- Produces a non-executing checklist and a candidate Phase 6B Maintenance Manifest.

- [ ] Dry-run displays backup/freeze/health/disk/key/restore/effect-drain/monitoring-transfer/rollback prerequisites.
- [ ] Refuse if reports、fence coverage、operator quorum or provider/tool drain evidence is absent.
- [ ] Freeze and display stable Cutover Command ID/Request Hash、intended snapshot and Production Genesis.
- [ ] No `--execute` path exists in the Phase 6A acceptance profile；the Phase 6B operator entry point requires a separately issued manifest and capability.
- [ ] Bind expiry、maintenance window、operators、allowed paths、expected pre-state and stop conditions.
- [ ] Commit.

---

### Task 10: Staged external-capability activation tooling

**Files:**
- Create: `core/sitina/effects/activation.py`
- Create: `docs/effect-capability-activation-runbook.md`
- Test: `tests/test_effect_capability_activation.py`

- [ ] Define readiness milestones `MOCK_ONLY → EXTERNAL_READ → REVERSIBLE_MUTATION → HIGH_RISK_OR_IRREVERSIBLE`；each needs a distinct later authorization/report.
- [ ] Define an active ceiling that can be lowered immediately without erasing readiness history or changing Journal authority.
- [ ] Test in-flight Receipt/Observation/Reconciliation remains accepted when new Transmission is disabled.
- [ ] Phase 6A never raises the ceiling above `MOCK_ONLY`.
- [ ] Commit.

---

### Task 11: Phase 6A acceptance and readiness issuance

**Files:**
- Create: `tests/test_phase6a_acceptance.py`
- Create: `docs/cutover-tooling-readiness-report.md`

- [ ] Run all cutover tooling against isolated fixture roots with Production-path denial instrumentation.
- [ ] Prove exactly one authorized writer or no writer for every Authority Control combination；never two.
- [ ] Prove lost ACK、corrupt outcome、stale resolver cache and restart remain fail-closed.
- [ ] Complete fixture import、fixed-frontier comparison、Journal+CAS rebuild and rollback matrix.
- [ ] Assert Effect ceiling `MOCK_ONLY` and all destructive capabilities absent.
- [ ] Record exact code/config/profile hashes and issue signed `CutoverToolingReady` only if all predicates pass.
- [ ] Stop. Do not freeze or modify Production and do not initiate Phase 6B.

Phase 6A readiness is not Authority Cutover authorization.

---

# 第十一部分：Phase 6B Authorized Production Cutover

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-6b-authorized-production-cutover.md`  
> 来源 SHA-256：`884e753ea4925755cbafc533458773d40c6ad195b0176e20c650fc450c5b9ff5`

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

---

# 第十二部分：Phase 7 Backend Scale-out

> 完整来源：`docs/superpowers/plans/2026-07-13-sitina-bplus-phase-7-backend-scaleout.md`  
> 来源 SHA-256：`511a31add62236d4d7612bcdd92fae793945ca5c907425d960e57eaff89e4ab3`

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
