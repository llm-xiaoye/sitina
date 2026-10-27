# Sitina optimization baseline

This baseline is the authority for phase 00 of the 149-item optimization plan. It describes the isolated source repository at the bootstrap commit and records gaps without treating code presence as acceptance evidence.

## Source and rollback boundary

- Isolated repository: `~/Desktop/sitina/source-worktree`
- Branch: `codex/optimization-149`
- Verified bootstrap commit: `b9fca670ecbd63db8cf807296ccab75a6cef3e2b`
- Python: `3.12.13`
- Dependency lock: `requirements-bplus.lock`
- Source files imported from verified manifests: 571
- Test files: 155
- Production runtime `~/SitinaHub` is read-only input provenance, not this worktree.

The original source manifest omitted `agents`, `prompts`, `mcp_servers`, `benchmarks`, and three fixture-declared safe `config/*.env` mappings. Phase 00 restored those non-secret source inputs through chained manifests, verified every hash, and added a regression test so later source manifests cannot silently omit them. Provider profile environment files, Journal/CAS data, projections, runtime state, backups, and generated outputs were not imported.

## Baseline execution

The authoritative sanitized record is `docs/optimization/evidence/phase-00/baseline-summary.json`; raw logs remain outside Git under the optimization bootstrap evidence directory.

| Check | Result | Evidence |
| --- | --- | --- |
| Config/schema validation | PASS | exit 0 in both baseline attempts |
| Safety eval | PASS | exit 0 in both baseline attempts |
| Full unit/integration discovery | PASS after source-completeness repair | 922 tests, 21 live/environment skips |
| Doctor | PASS after `sitina init` in a fresh marked disposable home | setup and doctor both exit 0 |
| External network attempts | PASS | 0 |
| Production mutable-path attempts | PASS | 0 |
| Billable Provider calls | not run by design | reserved for phase 15 approval |

The first full-test attempt is deliberately retained as FAIL evidence: two role-mapping tests failed because the old source manifest had omitted `config/roles.env`. The repaired bootstrap rerun passed all 922 tests. An uninitialized disposable home intentionally reports `doctor: requires_user_action`; the official doctor check passed after initialization in a separate disposable home.

## Domain audit

`PASS_EXISTING` is used only where the current implementation has direct behavior tests. `PARTIAL` and `MISSING` are recorded in each ledger item's notes while their externally valid status remains `FAIL` until the owning phase closes the gap.

| Domain | Existing authority and tests | Main gaps | Initial audit |
| --- | --- | --- | --- |
| Blackboard | Protocol Blackboard MVCC, version/hash CAS, namespace policies; `test_blackboard_mvcc` | snapshots, field diffs, size quotas, structured query, subscriptions, deterministic stress | 1 PASS_EXISTING; remainder PARTIAL/MISSING |
| Memory | Journal/CAS-native Memory V1 lifecycle and provenance; `test_memory_native_v1` | tiers, consolidation, semantic retrieval, decay, conflict arbitration, capacity, poisoning isolation | PARTIAL/MISSING |
| Context/Handoff | token-aware renderer, durable session context, generation-bound handoff protocol | provider tokenizer contracts, structured lossless summaries, Blackboard GC, complete redaction and historical query | PARTIAL/MISSING |
| Reliability | retry hooks, effect attempt identity, creation saga, compensation and recovery evidence | unified failure taxonomy, complete policy ownership, DR exercise contract, user-safe notifications | 2 PASS_EXISTING; remainder PARTIAL/MISSING |
| Security | default-deny MCP, risk/approval/effect boundaries, secret and injection quarantine | resource/argument policy depth, unified timeout/retry ownership, full minimum-capability matrix | 2 PASS_EXISTING; remainder PARTIAL |
| Routing | deterministic AUTO/FAST/MULTI routing, escalation and Chinese fixtures | structured complexity, ambiguity classifier, feedback lifecycle, domain profiles, A/B, SLA and cost policy | PARTIAL/MISSING |
| Orchestration | TaskGraph/protocol runtime, scheduler decisions, dynamic team filters, fences and checkpoints | topology strategies, runtime deadlock/fairness proof, resource hierarchy and safe runtime reuse | 2 PASS_EXISTING; remainder PARTIAL/MISSING |
| Proposal/Review/Arbitration | versioned protocol aggregates, reviewer independence and bounded rework | diversity metric, chat-wide competition policy, parallel/timeout review, cache and review-quality validation | PARTIAL/MISSING |
| Agent prompts | all 12 role prompts and JSON schemas exist | machine-parsed prompt contracts, budget/source/injection guarantees, responsibility matrix and goldens | PARTIAL |
| Trace/Replay | event/replay evidence, hash-chain tests and guarded zero-effect replay | sampling, full span tree query, metrics/alerts, profiler, trajectory monitor | 1 PASS_EXISTING; remainder PARTIAL/MISSING |
| Performance/Cost | accounting, budget and capacity primitives | hierarchical token settlement, cache/batch/pooling, reproducible latency program and live cost monitor | PARTIAL/MISSING |
| Evaluation | safety eval and broad unit/integration suites | requirement-bound maps, routing metrics, topology/chaos/benchmark gates, RunEvaluator | PARTIAL/MISSING |
| Suggest | router and policy primitives only | versioned `sitina suggest` command and parity tests | MISSING |

Audit totals: 8 `PASS_EXISTING`, 98 `PARTIAL`, and 43 `MISSING`, exactly 149 provided IDs. `E-06` through `E-11` and the absent item 18 are listed as `SOURCE_NOT_PROVIDED` and do not count toward failures.

## Shared owners

- Task and dependency truth: `core/sitina/orchestrator/task_graph.py` and protocol runtime.
- State truth: Journal/CAS plus rebuildable projections; Blackboard extends the existing protocol implementation.
- Budget/accounting: `core/sitina/orchestrator/accounting.py` and `core/sitina/effects/budgets.py`.
- Retry/breaker/failure policy: reliability/effect boundary; call sites consume policy.
- Trace/replay: authoritative events and evidence replay; observability remains read-only.
- Redaction and injection handling: guards/security/effect-result intake boundaries.

Later phases must extend these owners instead of creating parallel stores or competing policy sources.
