# Sitina B+ Run and Task Operations

Phase 2 is a shadow/controlled-fixture protocol runtime. It is not Production
authority. Production continues to use the Legacy writer, and the B+ shadow
adapter is disabled by default.

## Authority boundary

- `runtime.bplus_shadow_enabled` defaults to `false`.
- The adapter rejects `/Users/moss/SitinaHub` as a writable B+ Journal Home.
- An enabled adapter requires an isolated-home marker and records only a goal
  hash, length, and provider-mode class. It has no Provider, Tool, MCP, approval,
  worker-effect, or terminal authority adapter.
- SQLite outbox, timer, and terminal rows are candidates. A canonical Journal
  decision/fact must be revalidated before any protocol transition.
- Phase 2 fixture workers are in memory and report `external_calls=0`.

## Run admission and entity creation

A Run opens in `ACTIVE` with Admission Generation 1. Permits bind the Run,
generation, purpose, exact scope, count, depth, and UTC expiry. Beginning
`CLOSING` increments the generation, so old permits fail closed. Only a
`CLOSING_ENTITY_CREATE` permit may create a closing-time entity.

Entity creation is a durable create-or-tombstone saga:

1. consume the exact permit and freeze the entity ID, create Command ID,
   request hash, and idempotency binding;
2. query or issue the target create with the same Command ID and request hash;
3. accept only canonical `CREATED` or hash-bound `TOMBSTONED` disposition;
4. confirm Created forward or release the permit through Tombstone;
5. treat a different canonical request hash as an integrity incident.

TaskGraph Nodes are owned by the TaskGraph stream and cannot be created as
independent entity streams.

## Task graph, claims, and resources

Task specifications are immutable and hash-bound. Supersede, split, and merge
create explicit lineage. A node is schedulable only after its Task-definition
materialization reaches a canonical Created disposition. Pending
materializations and aborted required obligations block closing.

Every Task Claim creates a Task Attempt with a monotonically increasing claim
generation and a deterministic fencing token. Repeating the same claim Command
returns the same attempt and fence; an old or inactive fence is rejected. An
attempt failure does not itself fail the Task. Result acceptance binds the exact
submitted Artifact Hash and acceptance Policy Hash.

Multi-resource leases activate only when every declared requirement has an
exact reservation. Renewal requires accepted progress evidence and remains
bounded by renewal count and total extension. Release/revoke inputs are stable
compensation commands.

## Process, scheduling, dispatch, and timers

Process Manager steps derive stable step keys and Command IDs from the process
definition, generation, source Event hash, and action. Unknown outcomes are
queried with the same Command ID and request hash. Rebuild uses canonical
Process facts; repeated transitions or max-step exhaustion emit a recoverable
`PROCESS_STALL_DETECTED_V1` fact.

The scheduler evaluates filters in this order:

```text
eligibility -> safety -> dependencies -> capability -> lease -> budget -> policy
```

Aging is applied only after all filters pass. Final ordering is descending
score, then stable Task ID. SchedulerDecision binds the source frontier,
source-stream versions, policy hash, candidate evaluations, and order.

Dispatch requires that authoritative decision. It commits `TaskClaimed` before
the fixture worker receives work. Claim conflict behavior is frozen in the
decision path (`NEXT_CANDIDATE` or exhaust). Replaying after a lost ACK reuses
the Claim Command ID and fence. Beginning Run closing invalidates unconsumed
decisions.

Timers persist a UTC deadline, stable target Command ID, and canonical integer
monotonic nanoseconds. Monotonic elapsed time is used only in the same process
lifetime. After restart, conservative UTC time decides readiness. Excess clock
uncertainty records an incident and holds takeover; rollback or monotonic
shortfall cannot fire early.

## Closing and recovery checks

Terminal eligibility tracks all blocker classes: Permit, Process,
Decision/Outbox, Command, Claim Lease, Approval, Conflict, Effect Placeholder,
Dead Letter, and Checkpoint. A zero-count projection is only a candidate.
Authoritative full validation re-reads canonical blocker and outcome fact refs,
then deterministically chooses `CANCELLED`, `FAILED`, or `SUCCEEDED` in that
priority order and applies the result through the Run stream.

For diagnosis or restart:

1. acquire a fresh Journal writer lock and recover the committed prefix;
2. query pending Commands by their original ID and request hash;
3. rebuild Process Managers, timers, and projections from canonical facts;
4. compare rebuilt semantic tables, not SQLite file bytes;
5. keep takeover held on any clock, hash, generation, fence, or source-prefix
   uncertainty;
6. never infer authority from a projection row or shadow observation.

Phase 2 does not claim hardware power-loss RPO=0, Production cutover, live
provider validation, or supported Production capacity.
