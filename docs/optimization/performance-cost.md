# Performance, cost, and concurrency

`config/performance_policy.json` is the versioned authority for token ceilings, concurrency quotas, provider-cache admission, benchmark shape, and resource-pool isolation. Configuration validation rejects missing or unsafe values.

## Budget and accounting

`HierarchicalTokenBudget` applies an atomic hard ceiling across run → stage → agent/tool scopes. Every call reserves before work, then settles from Provider usage or refunds. A response without usage remains `unsettled` and continues to consume its reservation until later reconciliation; it is never converted to zero. The same lock protects concurrent admission, preventing oversell.

`CostAttributionLedger` distinguishes logical calls from physical attempts and attributes input, output, cache-read, cache-write, cost, and latency to run, stage, agent, and logical call. Retries and fallbacks remain physical attempts. Cache hits remain logical calls but cannot claim a physical Provider attempt. Missing usage is counted as unsettled, and grouped totals reconcile exactly to the run total.

The existing O-13 hierarchical limiter remains the single concurrency implementation. It applies global, run, Provider, and tool quotas; the fair priority scheduler ages queued work; partial acquisition, timeout, exception, and cancellation all release acquired capacity.

## Cache, batching, and pooling

Provider-cache admission requires a deterministic, side-effect-free, complete response. Its key binds tenant, model, prompt, tools, policy, and permissions. Values are AES-GCM encrypted in memory, carry a TTL, and support tenant or policy invalidation. A lookup explicitly reports either `cache_hit` or `new_physical_call_required`, so cached work cannot inflate physical-call accounting.

Batch dispatch occurs only when the Provider declares support and every request shares the complete compatibility boundary. Item request and idempotency identities stay unique; response errors and usage remain item-local. Unsupported or incompatible groups fall back to individual calls.

Pooled clients and connections are isolated by tenant, Provider profile, and a one-way credential-reference fingerprint. Checkout and release are thread-safe. Expired or failed resources are closed and evicted, and pool shutdown refuses to race active leases.

## Latency and runtime monitoring

Critical-path analysis validates the dependency graph, identifies the longest path and its largest serial wait, and recommends parallelization or reuse only for a stage that declares that capability. The repeatable benchmark contract records environment, warmup and measured iterations, sample count, p50/p95, error count/rate, physical-call count, and output hashes. An optimization is accepted only when outputs are equivalent, errors stay at zero, p50 and p95 improve, and physical calls do not increase.

The phase-12 benchmark fixture is deterministic and Provider-free; it is latency evidence, not live token or cost evidence. Live Provider usage remains reserved for the explicitly approved phase-15 gate.

`sitina cost-status RUN_ID` reads the authoritative run ledger and returns a read-only snapshot of used, reserved, remaining, forecast tokens, predicted overrun, hard-stop signal, unsettled usage, data freshness, and source. It never mutates the budget or run.
