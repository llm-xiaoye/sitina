# Routing and intent policy

Phase 07 keeps `/fast`, `/multi`, and `/auto` stable. Forced modes have routing priority, while permissions, approvals, and Effect Gateway remain separate code boundaries that no route or classifier can override.

## AUTO decision order

1. Normalize simplified/traditional Chinese, mixed English, spacing, punctuation, and case.
2. Compute Complexity Score 1.0 from goals, dependency edges, risk, tool classes, side-effect classes, bounded context, ambiguity, expected artifact classes, and eligible prior-turn complexity. Keyword count is never used as the score.
3. Apply the versioned general, code, or compliance domain profile. A profile may change thresholds and rubric identity but cannot weaken the global safety floor.
4. Enforce high-risk review, run token upper bounds, and latency policy. A cheaper FAST path cannot replace required high-risk review.
5. Only inside the configured local-confidence interval, and only when token budget and latency permit, an injected classifier may return the exact versioned schema. Its first invalid response receives one repair attempt; any remaining error falls back to the deterministic decision. Physical calls and reported or upper-bound usage are recorded.
6. Assign the versioned A/B bucket from a stable subject hash. A kill switch always selects control; sensitive attributes are not classifier or bucket inputs.

Every decision includes an input hash, policy version, evidence codes, conflicts, integer scores and thresholds, token budget, latency class, experiment assignment, classifier usage, domain profile, final route, and decision path. Interactive `/mode` displays the compact explanation.

## Escalation, feedback, and degradation

- FAST-to-MULTI escalation carries the prior run ID, output hash, evidence reference, confidence, and physical-send count as sourced candidate evidence. It is not displayed as a second answer and cannot authorize a repeated side effect.
- Route correction records only the original input hash, decision hash, route labels, correction label, and preservation flags. It never stores the raw user message and never automatically reruns a successful side effect. Corrections can be revoked.
- Feedback produces offline candidate rules only. Evaluation, an exact approval hash, and a versioned publication are all required; online self-modification is forbidden.
- MULTI-to-FAST degradation is labeled as not independently reviewed and is allowed only when policy permits, risk is below high, and no side effect is uncertain. Other cases fail closed with the original failure retained.
- Latency classes are interactive, standard, and batch. A virtual or monotonic deadline selects normal, fast, partial-result, review-required, or fail-closed behavior explicitly.

The bilingual regression corpus is `tests/fixtures/routing_regression_v1.json`; it records expected route, allowed set, and reason code and supports policy-to-policy difference reporting.
