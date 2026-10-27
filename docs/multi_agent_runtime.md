# Sitina Multi-Agent Runtime

This document describes the current local multi-agent collaboration runtime.
It is written as an implementation contract: code, tests, CLI output, and replay
must match these claims.

## Purpose

Sitina is no longer only a fixed role prompt pipeline. The v1 runtime is a controlled workflow with dynamic negotiation and safety gates. It is not a fully open-ended autonomous scheduler. The collaboration layer can:

- observe a run and classify task type
- select a dynamic team from the ownership registry
- dispatch the next task graph node within the controlled TaskGraph workflow
- run proposer agents through `AgentRunner`
- run evaluator agents through `AgentRunner`
- choose a proposal bid and reject lower-ranked alternatives
- escalate conflicts to an independent arbiter role
- accept or reject handoff contracts
- protect shared resources with leases
- record shared blackboard state
- block or complete the run from task graph state
- replay decisions from ledger, audit, and artifact metadata

The runtime remains safety-gated. Autonomy can propose work, but accepted
backlog state is required before a linked run can execute. Fully open-ended
self-scheduling, automatic merge, and replay of real side effects are outside
the v1 boundary.

Provider profile mapping is orthogonal to agent identity. In test mode, every
role may be mapped to the same provider profile such as `deepseek`. That remains
a multi-agent runtime as long as role-specific inputs, outputs, protocol
objects, proposal/evaluation/arbitration/handoff records, ledger/audit rows,
trace, and replay preserve distinct agent identities. Multi-provider mapping is
supported, but it is optional rather than a proof requirement.

Provider identity in trace/replay is an audit summary, not credential material.
Agent snapshots may include provider mode, profile name, model, provider label,
base URL host, and redaction status; they must not contain API keys, auth tokens,
Authorization headers, raw `.env` lines, or full secret-bearing URLs. The live
secret scan verifier reports counts plus path/field metadata only.

## Core Components

`CollaborationRuntime` is the coordination layer.

- `observe()` records the run goal hash and risk scan reference.
- `classify()` records the controller task classification.
- `dispatch_next()` reads the task graph and returns the next dispatchable
  mandatory node or a blocked/complete result. In v1 it participates in routing,
  traceability, and gate checks inside a controlled workflow; it is not a
  free-form autonomous scheduler loop.
- `negotiate()` opens a proposal round, gathers agent bids, gathers evaluator
  reviews, selects or blocks, and returns the selected task graph patch.
- `arbitrate()` delegates proposal, reviewer, scope, or lease conflicts to
  `ArbitrationManager`.
- `handoff()` closes a `HandoffContract` with accepted or rejected status.

`WorkflowPolicyEngine` owns the allowed task types and mandatory gates.
It compiles controller output into an `ExecutionPlan`.

`sitina suggest` is the read-only preview entrypoint for that same policy. It
uses `DynamicTeamBuilder.preview_team`, which shares capability, risk-ceiling,
required/optional/forbidden-agent, reviewer, tester, proposer, and evaluator
selection with live execution but records no event or audit. The suggested
topology comes from `config/orchestration_policy.json`; proposal-round and
worktree booleans come from proposal/workflow policy. Overrides are reported in
the result and never silently weaken a high-risk gate.

`TaskGraphRuntime` owns graph creation, graph transitions, contract reference
attachment, handoff requirement checks, dynamic arbitration nodes, and blocked
lease-holder nodes.

`ProposalManager` owns proposal rounds, proposal bids, evaluation records,
selection, rejected proposal audit, and proposal policy validation.

`ArbitrationManager` owns independent arbitration records and arbiter-agent
execution. It records a lease-backed arbitration node, runs the arbiter when
available, and fails closed when the arbiter cannot produce a safe decision.

`HandoffManager` owns handoff contract creation, validation, acceptance,
rejection, and scope-conflict arbitration on rejection.

`LeaseManager` owns resource leases and lease conflict arbitration. Exclusive
leases conflict on write/apply/approve modes. A non-selected holder can be
recorded as blocked instead of silently continuing.

`Blackboard` owns shared run-local documents. Agents receive a redacted
`blackboard_context` snapshot in collaboration inputs.

`AutonomyManager` owns long-term goals and backlog candidates. Only `active`
backlog items can be linked to a run.

`ReplayEngine` reconstructs decisions from recorded events. It never replays
real side effects.

## Proposal Protocol

Proposal scope is task-type specific. `code_change` and
`high_risk_code_change` use multi-proposal competition. `local_file_query` uses
a readonly controlled proposal path. `maintenance` uses an approval-first
controlled proposal path. `chat` uses a policy summary path and does not default
to proposal competition.

A proposal round is enabled by policy and task type. The runtime opens a round
with the dynamic team participants and then calls proposer agents through
`AgentRunner` where the task type supports proposer competition.

Each `ProposalBid` includes:

- `estimated_steps`
- `estimated_risk`
- `required_agents`
- `required_tools`
- `required_gates`
- `touched_files`
- `required_side_effects`
- `assumptions`
- `confidence`
- `rollback_plan`
- `verification_plan`
- `expected_artifacts`
- `safety_notes`

Evaluator agents review each proposal independently. The runtime records each
`ProposalEvaluation` with score, decision, reason, safety issues, quality
issues, and required changes.

The selection rule is deterministic:

- blocked proposals are excluded
- high-risk proposals require security evaluation
- any block evaluation excludes that proposal
- supported proposals are scored
- lower-ranked proposals are recorded as rejected
- the selected proposal id is bound to the task graph patch event

Rejected proposals do not drive the task graph patch. Mandatory tester and
reviewer agents may still run as gates, but not as owners of a rejected proposal
patch.

## Arbitration Protocol

Arbitration is independent of the controller decision. The controller can ask
for arbitration, but the `arbiter` role produces the decision when a runner is
available.

Supported conflict types:

- `proposal_conflict`
- `reviewer_conflict`
- `scope_conflict`
- `lease_conflict`

Supported decisions:

- `grant_agent_a`
- `grant_agent_b`
- `merge`
- `block`
- `ask_user`

`block` and `ask_user` are blocking decisions. The run must not continue to
execute the selected proposal when arbitration blocks the round. A blocked
arbitration is represented as:

- an arbitration decision in ledger/audit
- a blackboard arbitration note
- a blocked arbitration task graph node
- a terminal `run_failed` event
- a `memory_no_candidate` event when summary did not run

## Handoff Protocol

A handoff contract is not just a log entry. It has lifecycle status:

- `pending`
- `accepted`
- `rejected`
- `blocked`

The receiving agent must accept or reject the contract. Rejection records:

- `handoff_rejected`
- rejected reviewer and reason
- blocked task graph transition for the target node when invoked by the engine
- scope-conflict arbitration
- terminal run block when the rejected handoff is on a mandatory path

Acceptance records `handoff_accepted` and allows the graph node to proceed.

## Lease Protocol

Exclusive leases protect resources such as files, directories, approval scopes,
patches, and external tools.

A conflicting exclusive lease creates:

- a `lease_conflict_detected` event
- a lease-conflict arbitration node
- a blackboard arbitration note

If the arbiter grants one holder, non-selected conflicting holders must not
continue silently. The loser is recorded through `lease_holder_blocked` and can
be represented as a non-mandatory blocked task graph node.

If lease arbitration returns `block` or `ask_user`, the run is blocked and a
terminal `run_failed` event is recorded.

## Blackboard Protocol

The blackboard is run-local shared state. It records proposal summaries,
evaluation decisions, conflicts, arbitration notes, lease notes, backlog
candidates, and collaboration decisions.

Agent inputs receive `blackboard_context` during proposal, evaluation, and
arbitration calls. This context is redacted before recording and before replay
inspection. Sensitive markers such as passwords, tokens, provider names in
secret contexts, `.env`, and common test secrets are not persisted in visible
blackboard summaries.

Agents must not write safety policy fields through blackboard patching.

## Backlog And Long-Term Autonomy

The goal agent can create candidate backlog items. Candidates are `pending`
until review.

Run linkage policy:

- `pending` backlog item: cannot link a run
- `rejected` backlog item: cannot link a run
- `done` backlog item: cannot link a new run
- `active` backlog item: can link a run and becomes `in_progress`

Blocked run links record `run_backlog_link_blocked` and do not mutate
`linked_run_ids`.

This is long-term autonomy with review gates, not uncontrolled background
execution.

## Replay Contract

Replay reconstructs state from:

- run ledger
- events table
- audit log
- task graph artifacts
- side-effect descriptors
- patch metadata

Replay validates:

- required terminal events
- task graph state consistency
- patch hash consistency
- handoff chain reconstruction
- proposal selection and rejected proposal visibility
- lease and arbitration event visibility
- memory outcome visibility
- provider input/output snapshot presence
- input snapshot hash consistency when input payload snapshots exist. Agent
  calls record both the raw input hash and the safe/redacted input hash; replay
  verifies the persisted safe/redacted payload against the safe hash and keeps
  the raw hash as audit metadata.

Backlog pending/rejected/done early-block runs are valid replayable blocked
runs. They may have no task graph and no agent snapshots, but they must include
`run_started`, `run_backlog_link_blocked`, `run_failed`, and `memory_no_candidate`
or equivalent audit evidence. `replay simulate` remains dry-run and reports
`changed_real_files=false`.

Replay default mode is dry-run. It never re-executes provider calls, MCP tools,
file writes, memory acceptance, git apply, or external commands.

## CLI Observability

Use these commands to inspect collaboration state:

```bash
~/SitinaHub/bin/sitina trace <run_id>
~/SitinaHub/bin/sitina replay diff <run_id>
~/SitinaHub/bin/sitina replay simulate <run_id>
~/SitinaHub/bin/sitina run graph <run_id>
~/SitinaHub/bin/sitina proposals list --run-id <run_id>
~/SitinaHub/bin/sitina blackboard show --run-id <run_id>
~/SitinaHub/bin/sitina handoff list --run-id <run_id>
~/SitinaHub/bin/sitina handoff show <handoff_id>
~/SitinaHub/bin/sitina lease list --run-id <run_id>
~/SitinaHub/bin/sitina lease show <lease_id>
~/SitinaHub/bin/sitina arbitration list --run-id <run_id>
~/SitinaHub/bin/sitina arbitration show <arbitration_id>
~/SitinaHub/bin/sitina goal list
~/SitinaHub/bin/sitina backlog list
```

## Tested Fixtures

The runtime has fixture coverage for:

- default chat policy skip path
- code-change proposal competition
- proposal arbitration block
- handoff reject block
- lease conflict loser block
- lease arbitration block
- high-risk worktree gate block
- high-risk full patch gate apply
- retry/rework
- multi-reviewer rework
- memory candidate lifecycle
- backlog active-only run linkage
- replay simulate dry-run safety
