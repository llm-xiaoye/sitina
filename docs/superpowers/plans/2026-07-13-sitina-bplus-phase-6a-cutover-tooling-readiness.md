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
