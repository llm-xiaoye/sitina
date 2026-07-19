# Orchestration policy

Phase 08 extends the existing authoritative `TaskGraph`, scheduler decision, task-attempt lease, shared contract, Blackboard, permission and trace owners. It does not introduce a second orchestration authority.

## Planning and scheduling

`SITINA_PLANNER_DAG_V1` requires every task to bind its ID, inputs, output schema, owner capability, risk, shared task-scoped `TokenBudgetContract`, deadline, completion criteria, resources and priority. Dependencies are versioned as required, optional or compensatable edges. Validation rejects missing endpoints, duplicates, self-loops, cycles, missing compensation tasks and incomplete task definitions before enqueue.

The reentrant scheduler accepts a Controller policy-decision reference, then independently computes ready sets. It runs dependency-ready nodes concurrently unless read/write resource claims conflict, checkpoints statuses and outputs, and reconstructs those values after Controller restart. Stable priority combines explicit priority, deadline, aging and task-ID tie-break. Dependency and runtime resource wait cycles produce an explainable cycle path.

## Execution boundaries

- Capability, risk, load and cost choose the minimum sufficient team and retain evidence for every considered Agent.
- Agent calls, handoffs and rework record tokens, elapsed time, physical calls and marginal benefit with exact run-total reconciliation.
- Shared structured `FailureContract` values propagate through required, optional and compensatable edges.
- Deadlines and user cancellation set a common cancellation event, stop admission of new Provider/tool calls, save recoverable checkpoints and run journal, lease and temporary-resource cleanup.
- Stable run/task/attempt/operation idempotency keys deduplicate tool effects, proposals and state commits, including concurrent retries.
- The centralized state table defines all legal transitions and makes every terminal state immutable.
- Hierarchical global, run, Provider and tool semaphores are acquired in a fixed order and always released.
- Shared `TraceContract` spans link run, task, attempt, Agent, handoff and tool under one correlation ID.

## Collaboration strategies

Pipeline, Supervisor, Network and Hierarchy are topology strategies over the same state, permission and terminal contracts. The low-risk hot path may omit planning/review stages only when it preserves the safety, budget and trace boundaries and proves result/policy equivalence while reducing calls and latency.

Reusable clients are scoped by tenant and Provider profile. Invocation prompt/context and credential values are never pooled; failed resources are evicted. The deterministic collaboration scenario suite covers success, rework, rejection, no consensus, arbitration, timeout, cancellation, checkpoint recovery, concurrent write conflict and resource exhaustion.
