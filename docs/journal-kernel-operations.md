# B+ Journal/CAS fixture kernel operations

Phase 1 operates only in a directory carrying
`.sitina-bplus-disposable-v1` or `.sitina-bplus-shadow-v1`. The implementation
explicitly rejects `~/SitinaHub` as a Journal or CAS home. Legacy is
the sole Production writer throughout Phase 1; no Phase 1 receipt, frontier,
shadow Journal, fixture projection, benchmark, or acceptance report can promote
itself to Production authority.

## Startup and recovery

1. Acquire `journal/writer.lock` with `O_NOFOLLOW`, verify its fixed device/inode,
   and take non-blocking exclusive `flock`. Never unlink or replace this file.
2. Reconcile any rollover hard-link publication, then scan sealed segments and
   the active segment with bounded lengths. Sealed corruption fails closed.
3. Truncate only an incomplete active tail. A complete unacknowledged frame is
   re-synced and adopted. Rebuild Command bindings, Stream heads, positions, and
   object-root proofs from canonical frames before serving.
4. Verify every Event hash and historical Journal-auth key. Missing historical
   keys or a broken transition blocks startup.

After any uncertain `write`/`fsync`/directory-sync result the existing writer is
poisoned. Do not retry a different Command. Close it, reacquire the fixed-inode
lock in a fresh recovery, and query the original Command ID/request hash. A
complete adopted frame returns its original receipt; a different request hash
returns `CONFLICT`; absence under verified coverage returns `UNKNOWN`.

## Object-before-event and GC

CAS publication stages, syncs, decrypt-verifies, publishes with same-filesystem
no-replace link semantics, and syncs the destination directory. An append must
present an unexpired `PublishedObjectReceipt`, or a root proof issued by Journal
lookup of an exact object-reference manifest at a verified frontier. Object
existence and SQLite rows cannot issue root proofs.

Reference admission takes a GC epoch lease before frame write. The lease becomes
a committed root only after the referencing frame is durable. Mark freezes the
Journal frontier, catalog versions, holds, and policy hash in Journal-backed
operational records. Quarantine and sweep recheck in-flight, committed,
post-frontier, read, backup, hold, and restore roots. Restart blocks both GC and
new reference admission until Journal and lease reconciliation completes.

## Projections and degraded state

Projection SQLite is disposable. Each batch updates handler rows, event-location
metadata, Stream heads, and its offset in one transaction. Handler failure rolls
everything back and creates a Journal-backed required-projection failure fact.
Strong reads wait for a fixed caller frontier and fail immediately when the
projector is Failed, Blocked, or Incompatible. Rebuild uses a new database,
semantic checksum, and atomic reader-generation pointer switch.

Blocking dead letters, security intake, authorization decisions, schema
registrations, audit, GC controls, and projection failures are authoritative only
when rooted in canonical Journal frames. Logs or SQLite-only rows are diagnostic.

## Durability and capacity claims

The qualified Phase 1 behavior is process/OS-crash recovery under
`MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1`. It does not claim power-loss RPO=0.
`MACOS_APFS_FULLFSYNC_POWERLOSS_QUALIFIED_V1` and supported throughput/latency
remain `NOT_YET_QUALIFIED`. Benchmark measurements are descriptive fixture data,
not supported capacity.
