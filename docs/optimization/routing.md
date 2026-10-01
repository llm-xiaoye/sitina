# Routing and intent policy

The current public terminal interface exposes only AUTO. `/fast`, `/multi`,
and `/auto` cannot select a strategy, and `sitina suggest` has no public mode
override. Permissions, approvals, and the Effect Gateway remain separate code
boundaries that routing cannot weaken.

## AUTO decision order

1. Normalize simplified/traditional Chinese, mixed English, spacing,
   punctuation, and case.
2. Compute Complexity Score 1.0 from goals, dependency edges, risk, tool
   classes, side-effect classes, bounded context, ambiguity, expected artifact
   classes, and eligible prior-turn complexity. Keyword count is not the score.
3. Apply the versioned general, code, or compliance domain profile. A profile
   may change thresholds and rubric identity but cannot weaken the global
   safety floor.
4. Enforce high-risk review, run token upper bounds, and latency policy. Simple
   read-only work selects the single main Agent; complex or high-risk work
   selects that main Agent plus independent read-only review.
5. Assign the versioned A/B bucket from a stable subject hash. A kill switch
   always selects control; sensitive attributes are not classifier or bucket
   inputs.

The router may retain `FAST` and `MULTI` as internal compatibility labels in
its structured decision. They name the single-Agent and reviewed strategies;
they are not public session modes. The terminal controller uses the local,
deterministic decision and does not inject an optional model classifier.

Every decision includes an input hash, policy version, evidence codes,
conflicts, integer scores and thresholds, token budget, latency class,
experiment assignment, classifier usage, domain profile, final route, and
decision path. Interactive `/mode` displays AUTO plus the latest strategy and
its compact explanation without mutating state.

## Execution boundary

Each prompt becomes a task on the same current `LoopHost`. Both internal
strategies execute through `LoopTaskRunner.run_existing`, sharing the same
LoopBackend, Journal/CAS, authority lease, task state, workspace boundary,
terminal decision, and recovery path. The reviewed strategy enables the
Runner's existing independent reviewer; it does not start a second runtime or
state system.

Routing never grants write authority. A route correction or future policy
change must not automatically rerun a successful external effect. Feedback can
produce offline candidate rules only; evaluation and versioned publication are
required before a rule becomes active.

The bilingual regression corpus is `tests/fixtures/routing_regression_v1.json`;
it records expected internal route, allowed set, and reason code and supports
policy-to-policy difference reporting.
