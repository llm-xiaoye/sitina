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
