# Proposal, review, and arbitration policy

Phase 09 adds policy controls above the existing authoritative `ProposalManager`, Proposal protocol, Review protocol and Arbitration protocol. Candidate, scoring, rejection, selection, arbitration-trigger and user-decision records are versioned structures.

## Candidate competition

Candidates declare a distinct strategy, assumptions and risk focus. A normalized similarity gate rejects near duplicates and requests one bounded regeneration before an explicit degraded outcome. Risk and available budget determine configured minimum and maximum counts; a MULTI round cannot claim competition completion below its minimum.

Chat is eligible for competition based on complexity, risk and budget. Only a route-proven simple, low-risk chat takes the hot path. All candidates reference the same immutable context, receive per-candidate and total token ceilings, and stop when marginal value is below policy.

## Independent evaluation and selection

Evaluation input contains the original requirements reference and candidate substance but excludes author identity and unrelated chain history. Self-review is forbidden. A distinct profile/model is preferred; with one Provider/model, the declared isolation level is limited to role, context and sampling independence.

The versioned rubric covers correctness, safety, completeness, evidence, implementability, cost and latency. Safety and evidence are hard gates and cannot be averaged away. Selection applies hard gates first, then normalized weighted scores, confidence, disagreement and a stable proposal-ID tie-break. Missing or invalid evaluations cannot win.

Rejections retain a reason code, rubric details, canonical evidence, repair suggestions and model/policy versions after redaction. Review-quality validation checks schema, reason depth, citation consistency, anomalous score spread and self-review bias, routing low-quality results to second validation or arbitration.

## Arbitration, recovery, and execution boundaries

Arbitration triggers are explicit thresholds for no eligible candidate, narrow score gap, reviewer conflict, risk disagreement and repeated schema failure. The Arbiter prefers a profile/model unused by authors and reviewers; fallback truthfully reports context-only isolation.

Repairable blocks have finite rework, authority blocks create resumable Ask-user records, and terminal/exhausted blocks stop. Ask-user requests expose options, reasons, risks, budget and a safe timeout default; answers bind run, request and decision hashes.

Conflict-free reviews run concurrently under a configured limit and aggregate in stable reviewer order. Deadlines close the review, reject late writes and require minimum quorum or arbitration. Proposal cache hits require exact normalized input, policy, model, prompt, permission and tenant bindings; side-effecting, marked-sensitive or detected-secret content is never cached.
