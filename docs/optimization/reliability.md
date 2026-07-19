# Reliability policy and disaster-recovery runbook

Phase 05 centralizes retry, fallback, rollback, failure, degradation, circuit, health, partial-success, and notification decisions. The canonical Journal remains the event authority; reliability services accept an event sink and do not create a second durable state store.

## Failure and retry contract

- `SITINA_FAILURE_ENVELOPE_V1` uses Failure Taxonomy 1.0: transient, permanent, auth, quota, schema, safety, cancelled, and unknown. Cross-Agent/Handoff payloads preserve stage, causal chain, retryability, and redacted diagnostics.
- `SITINA_RETRY_SCHEDULE_V1` owns retry count, exponential backoff, deterministic jitter, Retry-After, retryable classification, and deadline admission. Provider call sites only execute this returned schedule and record the decision.
- Unknown, auth, schema, safety, cancelled, and permanent failures do not retry. Only transient and quota failures are retryable.
- Degradation is capability-matrix based. High/critical risk, missing permission, uncovered capability, or uncertain side effects fail closed.
- Circuit state is isolated by Provider/tool/profile. A lock serializes the single half-open recovery probe.

## Effect and user-visible outcomes

- Existing `EffectRequest.idempotency_binding`, `EffectGateway`, reconciliation levels, and remote result reuse remain the side-effect idempotency authority. A lost response can be retried with the same binding without a second remote execution.
- Existing Effect outcome/settlement/cardinality state remains the transaction boundary. A confirmed result with unresolved exposure remains `RECONCILING`, never full success.
- Rollback executes through `RollbackCoordinator`; start, success, failure, and duplicate suppression are event facts. Repeated compensation does not execute again, and a compensation failure never rewrites the original outcome.
- Partial success uses `SITINA_PARTIAL_SUCCESS_V1` and always names completed work, failed work, missing capabilities, and an actionable next step.
- Failure notification is deduplicated by a stable run/failure/stage fingerprint and contains a user-readable reason, run ID, retryability, and safe advice without raw diagnostics.

## Executable isolated DR drill

Run from the repository root:

```sh
scripts/reliability-drill \
  --output /Users/moss/Desktop/sitina/output/optimization-bootstrap/phase-05-dr-drill.json
```

The command creates a marked disposable home, disables live Provider/network access, runs canonical backup plus cold-copy restore, replays restored event records, and verifies that no writer was activated. The drill refuses the production home as a restore target. A successful report must show:

- `status: PASS`;
- `external_attempt_count: 0`;
- `production_attempt_count: 0`;
- the reliability, canonical-backup, and restore-drill test selectors;
- `writer_activated: false` in the DR acceptance evidence.

Never point the drill at `/Users/moss/SitinaHub`; the executable gate creates and removes its own marked isolated copy.

## Health semantics

The readiness report covers Provider, Journal, CAS, projection, queue, and configuration. Liveness answers whether the process and components can respond; readiness is stricter and answers whether the run can safely accept work. Diagnostics pass through the shared log-boundary redactor before publication.
