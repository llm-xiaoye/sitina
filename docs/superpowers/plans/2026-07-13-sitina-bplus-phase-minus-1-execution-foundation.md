# Sitina B+ Phase -1 Execution Foundation Implementation Plan

**Goal:** 在不改变 Sitina 现有 Runtime、Legacy Authority、数据和外部行为的前提下，通过受限 Bootstrap V0 建立可复现解释器与依赖，再生成正式 Execution Manifest V1、隔离测试 Home、变更审计、执行授权契约和计划完整性工具，使后续 Phase 可以被 Codex 安全、分段、可验证地执行。

**Architecture:** Phase -1 只建立施工控制面。Production Home `/Users/moss/SitinaHub` 始终只读；所有测试、Crash Injection、Fixture Run、Shadow Journal 和临时数据库必须位于一次性 Test Home。现有 Legacy 功能作为兼容性 Oracle 保留，不在本阶段重构。

**Tech Stack:** 固定 Python 3.12 Profile、Pydantic v2、经批准并锁定的密码库、标准依赖锁、`unittest` 分层 Runner、Git 或等价内容寻址变更审计、Canonical JSON Execution Manifest。

## Global Constraints

- Phase -1 不创建 Canonical Journal、CAS、Projection 或 Shadow Business Event。
- 不运行会把 `SITINA_HOME` 解析为 `/Users/moss/SitinaHub` 的测试。
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
