# Sitina B+ Phase 0 Legacy Compatibility Implementation Plan

> **For Codex execution:** Requires a PASSED Phase -1 Acceptance Report and a current Execution Manifest authorizing only the listed Phase 0 Task Range. Default work uses an isolated Test Home and must stop before any real Production freeze.

**Goal:** 在不改变 Production Authority 的前提下，建立可审计冻结机制并盘点当前 SQLite/JSONL/Mutable JSON/Artifact 来源，建立 Legacy Read-only Adapter、Fact Classification、Shadow Namespace 和 Dual-read Comparison Harness；真实 Production Freeze 仍需单独授权。

**Architecture:** Legacy Writer 在整个 Phase 0 仍是唯一 Production Authority；新增能力只负责 Inventory、Read-only Snapshot、Shadow Import 和 Comparison。所有 Shadow Event 明确标记 Non-authoritative，且不得驱动 Provider、Tool、Approval、Timer、Terminal 或 Evidence Seal。

**Tech Stack:** Phase -1 approved Python 3.12 Profile、SQLite read-only URI、JSON/JSONL、SHA-256、分层 `unittest`、文件树 Inventory、Kernel file lock（只为 Legacy Fence 协调，不替换 Phase 1 Canonical Writer Lock）。

## Global Constraints

- 不执行 Authority Cutover。
- 不删除、重写、Vacuum 或重建 `/Users/moss/SitinaHub/data/sitina.db`。
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
<approved-python> /Users/moss/SitinaHub/scripts/test-bplus.py unit_fast --test tests/test_legacy_compatibility.py
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
