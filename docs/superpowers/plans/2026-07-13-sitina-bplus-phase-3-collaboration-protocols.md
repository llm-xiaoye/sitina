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
