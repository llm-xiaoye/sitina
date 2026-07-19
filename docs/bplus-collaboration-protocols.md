# Sitina B+ Collaboration Protocol Operations

Phase 3 implements collaboration as independent, hash-bound protocol streams in
shadow/controlled-fixture namespaces. It does not change Production authority;
the Legacy writer remains the only Production writer.

## Obligation boundary

A protocol becoming terminal does not satisfy its Run Obligation. The
Obligation stream separately records `SATISFIED`, `SUPERSEDED`, `FAILED`, or
`CANCELLED`. `SUCCESSOR_REQUIRED` stays open for Run-terminal accounting until a
stable successor Obligation and successor Protocol are created through two
generic Permit-backed Create-or-Tombstone sagas. ACK loss is recovered with the
same entity IDs, Command IDs, request hashes, and idempotency bindings.

Protocol and Obligation registry rows are rebuilt only from canonical Created
and Terminal Events. A Projection row cannot invent or terminalize either
entity.

## Proposal, claims, debate, and review

ProposalRound freezes participant/evaluator sets, rubric, scoring policy,
deadline, minimum score, and revision bound. Any change opens a new generation.
One stream CAS permits at most one selection per generation, and rejected or
revision-required Proposals are ineligible. `NoSelection` can only route to a
new generation, Arbitration, Rework, or cancellation.

Knowledge Claims are versioned and body/evidence-reference bound. Debate
Responses must reference existing Claims under the exact target and remain
within round, token, and UTC deadline bounds. A Synthesis is an exact partition
of every Claim into included, excluded, and unresolved sets with a complete
Evidence Map. `NO_CONSENSUS` creates a successor Obligation; it cannot silently
convert a vote into consensus.

Review binds the immutable Artifact Hash, rubric, quorum, risk, independence,
and security-review policy. Artifact authors and conflicting lease holders
cannot review. Review disposition remains distinct from Artifact Acceptance.
Acceptance freezes exact response commitments, criteria, policy, and Artifact
Hash; an approval for an older hash remains historical but inapplicable.

## Handoff, merge, arbitration, and rework

`handoff_id` is stable across monotonically increasing generations. A rejected
generation never reopens. Each new generation rebinds specification, policy,
capability, budget, deadline, acceptance, Task Claim, and fence. Execution is
denied until the receiver accepts and the exact Task Attempt/fencing token is
bound. High-risk work requires a verifier independent of sender and receiver.

Merge accepts only operation kinds explicitly declared safe by the document
schema: commutative, append-only, or CRDT-compatible. Different JSON paths do
not make undeclared operations safe. Validation binds the base and operation
hashes. Failed Merge creates an Arbitration Obligation.

Arbitration Decisions freeze a binding-effect scope and block affected dispatch
until enforcement proof commits. Only `ENFORCED`, not `DECIDED`, satisfies the
Arbitration Obligation. Appeals require authorized identity, a new generation,
new evidence, an unexpired deadline, and remaining appeal count; reused evidence
cannot create a loop.

Rework is reserved for multi-round adjudication. Simple correction routes to a
new Task Attempt. Rework binds an enumerated failure type and exact Acceptance
Criteria Hash. Retry exhaustion creates a stable successor Obligation.

## Blackboard MVCC

Each Namespace has a frozen schema hash, writer capabilities, evidence rule,
merge policy, classification, and inline bound. Patch commands bind document
base version/hash, Agent read refs, write intent, Task Attempt, Claim generation,
and fencing token.

A stale base returns a conflict without mutating the document stream. Only
Obligations that explicitly depend on that document are blocked. Large or
secret-bearing content requires a fresh `PublishedObjectReceipt` issued by the
encrypted CAS before the Event; the Journal/Projection retains only the Object
reference and allowed metadata. Caller booleans or unverified `cas:` strings are
not publication proof.

## Recovery and compatibility

Protocol Coordinator Process steps derive stable successor Commands from
terminal Event hashes. They never directly mutate target streams. On restart,
rebuild Process state from canonical facts and query the same Command ID/request
hash. Repeated transitions or max-step exhaustion emit audited Stall facts with
a frozen successor-action set.

For recovery:

1. recover the canonical Journal prefix under a fresh writer lock;
2. rebuild Protocol/Obligation registries and Coordinator Processes from facts;
3. reconcile pending successor Commands by their original ID/hash;
4. retain Blackboard conflict state until Merge/Arbitration disposition;
5. keep dispatch blocked while Arbitration enforcement is pending;
6. compare rebuilt semantic state, not SQLite file bytes;
7. never write `state/handoffs.json`, Blackboard JSON, or Legacy proposal files
   from the B+ shadow path.

Legacy Proposal, Handoff, and Blackboard views are read-only representations.
Every semantic difference is classified; an unclassified or regression-class
difference blocks promotion. Phase 3 performs no real Provider, Tool, MCP,
worker effect, Production import, freeze, migration, or cutover.
