# Observability, replay, and trajectory safety

`config/observability_policy.json` is the versioned authority for trace sampling, alert thresholds, profiling fields, and trajectory-anomaly actions. Configuration validation fails closed when the policy is absent or malformed.

## Trace and query contract

A complete trace links the run, task, agent, provider or tool, state, and effect layers. Every observation carries run and correlation identity, status, timestamps, policy and schema versions, and provider usage when applicable. Integrity validation rejects duplicate spans, mixed traces, missing or invalid roots, orphaned parents, illegal layer transitions, cycles, missing required layers, and incomplete terminal metadata.

Errors, high or critical risk, approvals, over-budget decisions, billing, and audit events are retained at 100%. Ordinary successful traces use a deterministic trace-ID bucket and the configured probability, so the same trace always receives the same sampling decision.

`sitina trace RUN_ID` remains backward compatible. `sitina trace RUN_ID --query` provides a read-only, structured, redacted and paginated view with optional agent, tool, status, time-window, and correlation filters. The run ledger remains authoritative.

## Replay, metrics, alerts, and logs

Replay consumes recorded ledger events only and never calls a provider, opens a network connection, or re-executes a real side effect. Consistency checks upcast the supported legacy event shape, remove the explicit volatile-time field set, and compare stable state hashes. Unsupported schema generations fail explicitly.

Business metrics cover task success, routing quality, rework, handoff and acceptance, budget exceedance, partial success, and recovery. Dimensions are bounded to policy version, risk band, and terminal status. Alerts cover multi-window SLO burn, repeated failures, queue backlog, and token or cost anomalies. Alert state deduplicates active incidents, emits recovery, and applies a cooldown after flapping.

Structured logs use a versioned JSON contract with level, event code, correlation identifiers, and boundary-aware redaction. A compact human rendering is available without changing the machine record.

## Propagation, profiling, and trajectory monitor

Trace context propagates across agent, thread, and process boundaries. Asynchronous queue consumption starts a new root span linked to the producer span, preserving causality without inventing a synchronous parent.

Low-overhead profiling is off by default. When enabled it reports only stage wall time, CPU time, memory delta, and queue wait; it never records request or response payloads.

`RunTrajectoryMonitor` detects repeated use of the same tool, repeated permission denial, unchanged-state loops, and token use at the configured budget multiplier. Thresholds are inclusive and deterministic. Actions are policy-bound to warning, circuit breaking, or pausing for human review. Fingerprints persist in monitor state so restart and re-evaluation do not duplicate an already reported anomaly.
