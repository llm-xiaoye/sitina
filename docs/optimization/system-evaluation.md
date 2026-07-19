# System evaluation and test evidence

Phase 13 separates functional acceptance, chaos/concurrency verification, and repeatable performance benchmarks. All tests run in disposable homes with live Provider and network access disabled. The real Provider gate remains isolated in phase 15.

## Evaluation suites

The versioned R-08 routing fixture now declares language, domain, and risk for every case. `RoutingEvaluationSuite` reports policy and fixture versions, overall accuracy, false upgrades, false downgrades, dangerous high-risk downgrades, and language/domain slices.

Collaboration coverage executes pipeline, supervisor, network, and hierarchy topologies across success, rework, rejection, blocked capacity, ask-user, no-consensus, cancellation, restart, and partial-success outcomes. Each fixture records one terminal state commit and proves that no external call is admitted afterward.

Concurrency coverage binds six independently executable tests for Blackboard MVCC, token reservation, leases, scheduling fairness, cache fill, and terminal competition. Barrier-based cache-fill properties run at several worker counts without timing sleeps. Chaos coverage binds actual Provider, tool, Journal, CAS, projection, worker, and disk-full fault tests; each case names the fail-closed or recovery invariant it proves.

Performance benchmarks live under `tests/benchmarks/`, separate from functional acceptance. Routing, FAST, MULTI, handoff, Blackboard, and replay each record environment, warmup, samples, p50/p95 latency, throughput, peak resource units, errors, output hashes, and physical-call counts against explicit thresholds. These deterministic fixtures do not claim live latency or Provider cost.

## RunEvaluator

`RunEvaluator.evaluate(run_id)` reads the authoritative Journal or legacy ledger through read-only paths. It never initializes a database, writes an evaluation event, calls a Provider, opens a network connection, or executes an effect. Its stable, versioned result contains:

- tool correctness;
- state correctness;
- permission compliance;
- cost efficiency;
- recovery ability;
- final quality.

Every dimension carries a status, 0–100 score, reason codes, evidence references, and evaluator version. Missing required evidence is capped at 20. Any explicitly hash-bound event whose content is changed after signing adds `EVIDENCE_INTEGRITY_INVALID` and caps every dimension at 20. Identical event streams produce the same evaluation hash.

## Requirement map

`tests/optimization/requirement-test-map.json` contains exactly 149 requirement IDs. Every entry names at least one method-specific executable test and explains the assertion for that requirement. Validation imports every referenced method, rejects empty or deleted mappings, and forbids document-only evidence for `PASS_NEW` requirements. Shared tests remain allowed only with a per-requirement assertion.
