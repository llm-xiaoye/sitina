# Shared contracts and evolution guardrails

Phase 01 establishes versioned interchange contracts. These models validate data crossing module boundaries; they do not schedule work, persist canonical state, spend budgets, retry calls, redact secrets, or make evaluation decisions.

## Compatibility policy

- New records require an exact `schema` and `schema_version: "1.0"`.
- V1 readers reject unknown fields, unknown versions, malformed UTC timestamps, invalid stable IDs, duplicate identities, illegal structural states, and sensitive field names at any nesting depth.
- Deterministic V0-to-V1 readers preserve the record timestamp and stable identity, derive `correlation_id` from that identity, set `causation_id` to null, and mark legacy input `untrusted`. Upcasters do not read clocks, files, networks, providers, or mutable process state.
- Forward-version guessing is forbidden. An unrecognized version requires an explicit reader and migration.
- Extension data is permitted only inside the explicit `extensions` object and remains subject to the sensitive-field boundary.
- Shared-contract writes are guarded by `shared_contracts_v1_write`, which defaults to false. Old configuration without the field is read-compatible and write-disabled.

The generated schema bundle is `schemas/contracts/shared-contracts-v1.schema.json`; `scripts/generate-contract-schemas` is its deterministic generator.

## Single owners

| Concern | Unique owner | Contract-layer role |
| --- | --- | --- |
| Task graph, task, dependency truth | `sitina.protocols.tasks.TaskGraphAggregate` | Structural interchange view |
| Concurrency limits and dispatch | `sitina.scheduling.scheduler.Scheduler` | Consumer only |
| Failure classification, retry and circuit reliability | `sitina.orchestrator.retry.RetryPolicy` | Typed failure view |
| Token reservation and settlement | `sitina.effects.budgets.BudgetBundle` and `sitina.orchestrator.accounting.ProviderAccounting` | Budget/usage views |
| Trace/span facts | `sitina.journal.local.LocalJournal` using the shared Trace/Span model | Canonical event/span vocabulary |
| Frozen handoff | `sitina.protocols.handoff_contracts.HandoffContract` | Reference-only handoff view |
| Blackboard state | `sitina.protocols.blackboard.BlackboardDocument` | Reference-only document view |
| Memory state | `sitina.memory.native.MemoryDocument` | Reference-only memory view |
| Proposal/review evaluation | `sitina.protocols.proposals` and `sitina.protocols.reviews` | Evaluation result view |
| Security redaction | `sitina.security.redaction` | Rejects unredacted sensitive fields |

Reference-only views intentionally carry hashes or CAS references instead of copying objectives, Blackboard bodies, memory contents, findings, or provider receipts. This prevents the contract package from becoming a second fact store.

`task_graph_contract_view` is the reference adapter pattern: it derives a deterministic immutable view from `TaskGraphAggregate`, owns no repository or mutation method, and preserves the aggregate version and identities.

The cumulative gate supports `--all-tests`; each phase can therefore discover the complete checked-in test inventory without maintaining a second selector list.
