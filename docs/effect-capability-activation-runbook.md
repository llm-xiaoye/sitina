# Sitina B+ external capability activation runbook

External capability and Journal writer authority are independent controls. A
Cutover outcome never activates a Provider, Tool, MCP, message, publication,
payment, deletion, or remote mutation capability.

The ordered readiness milestones are:

```text
MOCK_ONLY
→ EXTERNAL_READ
→ REVERSIBLE_MUTATION
→ HIGH_RISK_OR_IRREVERSIBLE
```

Each transition requires a distinct later authorization and acceptance report.
Recording readiness does not raise the active ceiling. Phase 6A is permanently
locked at `MOCK_ONLY`; a phase or feature flag cannot override that ceiling.

The active ceiling may always be lowered immediately. Lowering or disabling new
Transmission preserves readiness history and does not change Journal authority.
Receipt, Observation, Reconciliation, and Containment intake remains available
when new Transmission is disabled so in-flight exposure can be settled safely.

Every future activation must bind the exact Adapter Manifest, credential
provider, approval class, Effect policy, Budget/Breaker policy, environment,
operation set, expiry, operator authorization, and rollback/containment plan.
High-risk or irreversible capability must remain absent until its independent
post-cutover gate passes.

