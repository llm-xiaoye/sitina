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
