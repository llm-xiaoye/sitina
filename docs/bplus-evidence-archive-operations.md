# Sitina B+ evidence and archive operations

## Scope and authority

Phase 5 is shadow/controlled only. It implements evidence, archive-copy,
backup/restore, and retention authorization models in marked disposable homes.
Legacy remains the sole Production writer. No Phase 5 package, seal, bundle,
copy, projection, report, or dry-run receipt creates Production authority or
authorizes Production seal, archive transfer, deletion, hot eviction,
crypto-erasure, Journal genesis, migration, or cutover.

The Legacy evidence bundle remains a portable, hash-verified compatibility
export labeled `artifact_integrity_verified_compatibility_export` with
`LEGACY_TERMINAL_MANIFEST` completeness. It is explicitly neither B+ OPT
compliant nor B+ sealed.

## Terminal and package generation

V1 O, P, and T are typed single-component signed frontier vectors for one
Journal, epoch, and shard. A coherent-cut proof requires `O <= P` and a durable
disposition by P for every admitted observation at or before O. The
PreTerminal checkpoint independently hashes TaskGraph, Blackboard, Protocol,
Obligation, Effect, Eligibility, and object manifests.

Closing drains every declared Task, Protocol, Obligation, Timer,
Materialization, Effect exposure, Monitoring-transfer, Projection-lag,
Object-integrity, Permit, Process, outbox, Command, Claim/Lease, Approval,
Conflict, Dead-letter, and Checkpoint barrier. After P, only evidence recording
is permitted. The unique terminal command is idempotent by command and request
hash; conflicting duplicates fail.

`evidence/<package_id>` owns immutable package generations. Remediation creates
a new generation with the exact predecessor Core hash; it never edits an old
generation. Files and SQLite rows are representations, not lifecycle owners.

## Assessment, seal, and supplement response

The verifier receives a read-only Core view and issues one immutable Assessment.
The sealer accepts only an exact-Core, exact-policy `PASSED` Assessment through
the role-bound evidence signing handle. A late fact uses the CAS-extended
Supplement stream; it may change current audit status while original Core,
Terminal, Assessment, Seal, and Artifact bytes remain unchanged.

For a contradiction:

1. retain both authenticated facts and the original evidence bytes;
2. issue and accept a separately assessed Supplement;
3. expose `CONTRADICTED` in current-audit replay;
4. do not replace a signature, lower a completeness requirement, or silently
   rewrite terminal history.

## Offline replay capability

Replay-original stops at T and presents the original Assessment without
generating another. Current-audit replay applies accepted Supplements only.
Both allocate no live Journal position, Permit, Lease, credential, or external
effect and write only a disposable projection.

The current host is classified `APPLICATION_GUARDED_ZERO_EFFECT`. Application
guards deny network constructors, DNS, subprocess, FFI, out-of-root writes,
symlink escape, device access, and inherited descriptor authority at the replay
API boundary. This is defense in depth, not a kernel-enforced sandbox claim.
The presence of `sandbox-exec` is insufficient; an enforced label requires a
currently qualified OS/container/VM provider that passes every declared and
adversarial guarantee.

## Archive copies and replica policy

`archive-job/<job_id>` owns created → staging materialized → staging verified →
final transferred → final reopened/verified → completed. Staging and final
locations receive fresh verification identities. `archive-copy/<copy_id>` owns
copy identity, residency, stored state, and assessment; a copy may remain
`STORED` while `CONTRADICTED`. Job completion never implies long-term replica
policy compliance.

Replica evaluation counts only verified canonical residency copies within the
verification-age bound and independently checks count, fault domain, region,
provider, administrative domain, and key domain. A bundle does not substitute
for Journal/CAS residency unless separately registered as canonical.

## Retention and GC dry run

Every retention candidate has an exact operation identity and snapshots of its
object/copy set, policy, catalogs, frontier, holds, quorum, executor, and
deadline. Legal holds, incomplete evidence, active jobs, cross-run references,
replica noncompliance, stale approval, snapshot drift, or an unknown executor
outcome prevent completion. A lost ACK enters reconciliation and is never
treated as implicit success or retried as another authority.

Phase 5 contains no destructive capability. Execution returns a dry-run receipt
with `physical_delete_executed=false`. GC freezes a signed frontier, epoch,
catalog versions/snapshot, and hold snapshot; unreadable or drifting inputs fail
closed. Post-frontier reference leases become roots. GC may propose a dry-run
retention operation only after grace and second confirmation; it cannot
authorize or perform deletion.

## Canonical backup and restore drill

Backup freezes an exact Journal frontier and active-prefix disposition, then
acquires holds over the reachable closure before checking or copying objects.
A missing object fails the backup and deliberately retains the hold. Holds
release only after an isolated restore verifies exact hashes.

Restore accepts a final cold copy, never staging. It verifies identity, Journal
frontier, file hashes, and closure without activating a writer. Same identity
with a different manifest is an integrity incident. Changed recovered bytes
cannot adopt the original epoch; an explicit strictly newer recovery epoch is
required and records a new recovery manifest.

Operators must stop immediately on any Production path resolution, sentinel
change, destructive capability request, catalog/hold drift, restore identity
incident, or unexplained external attempt and preserve diagnostics.
