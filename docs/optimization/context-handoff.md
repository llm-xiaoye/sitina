# Context and Handoff authority

Phase 04 closes Context/Handoff gaps without adding a persistence authority. Canonical run, Handoff, Task, Blackboard, and context publication facts remain Journal-owned; content remains CAS-owned. Context selection, token admission, allocation, history indexes, and retention eligibility are deterministic derived views over shared contracts or facts.

## Context admission and selection

- `ContextWindowPlanner` accepts the shared `SITINA_TOKEN_BUDGET_V1` contract and accounts for system prompt, tool schema, history, and output reserve against both the Provider/model context limit and remaining run budget.
- A Provider tokenizer is used when supplied. The offline counter is labelled `conservative-fallback`; it is admission-only and never reported as Provider usage.
- Selection priority is fixed as safety, user constraints, unfinished tasks, evidence, recent history, memory, then tool output. Required content fails closed if it cannot fit; optional selection is stable by category and ID.
- Structured summaries retain decisions, constraints, unfinished tasks, open questions, evidence references, and source references. Expendable detail is represented only by hashes, and compression fails if the essential fact set cannot fit.
- Controller, agent, tool-output, candidate, and summary allocations are a pure plan over the shared budget contract. Reclamation reduces existing reservations but the derived allocation can never cross the run ceiling.

## Handoff integrity and recovery

- The frozen `HandoffContract` binds objective, input hashes/refs, scope, capabilities, shared versioned `BlackboardDocumentRecord` values, output schema, acceptance criteria, policy, budget, deadline, and generation lineage.
- Receiver acknowledgement verifies the frozen receiver and reports exact missing capability/input/Blackboard/budget/state/schema/hash bindings. Only a complete acknowledgement is accepted.
- Repairable rejection may open a bounded new generation; permission and safety rejection fail closed; cancellation is terminal and records cleanup refs. Existing maximum-generation enforcement prevents repair loops.
- Fenced submission revalidates Task ID, attempt ID, claim generation, and fencing token at submission time. A reclaimed Task makes the old Handoff and Blackboard write intent stale.
- Crash recovery rebuilds the same aggregate from facts; unknown versions, expired offers, duplicate commands, and damaged hashes fail closed.

## Retention, redaction, and history

- Blackboard retention facts bind a versioned shared document. Collection requires a terminal run, frozen retention boundary, no legal/audit hold, and no active reference. The GC-eligibility fact is reconstructable after restart and carries the exact CAS reference for the existing GC owner.
- The shared security redaction owner handles structured write, read, log, and Handoff boundaries. It normalizes Unicode field names, detects nested/split/encoded secrets and common PII, records paths without values, and supports explicit exact-value allowlisting for known false positives.
- Authorized history is a rebuildable, read-only index of CAS references and evidence links. Queries are ACL-filtered, cursor-paginated, and evidence-addressable; results are never automatically injected into a new context.
