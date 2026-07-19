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
