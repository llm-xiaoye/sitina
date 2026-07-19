# Legacy compatibility and future Cutover operator guide

## Phase 0 boundary

Phase 0 does not freeze Production and does not create B+ writer Authority. The
existing Legacy writer remains authoritative. Shadow facts, inventory reports,
SQLite snapshots, comparisons, test fixtures, and readiness reports are never
Authority inputs.

Safe read-only commands:

```bash
sitina legacy status
sitina legacy inventory --output /path/outside/SITINA_HOME
```

`legacy status` must not create a lock or fence. `legacy inventory` requires a
physically disjoint output, rejects symlinks, performs capacity checks before
writing, copies SQLite through the online backup API, and labels the result
`LIVE_OBSERVATIONAL_INVENTORY`. If any source identity changes during reading,
the entry is marked `CHANGED_DURING_OBSERVATION`; the output is not a coherent
snapshot and must not be used for migration completeness or Cutover.

## SQLite rules

- Live Legacy databases open with URI `mode=ro` and `PRAGMA query_only=ON`.
- Never use `immutable=1` against a live WAL database.
- `immutable=1` is allowed only for an independently materialized snapshot after
  integrity check, connection close, file/directory durability, and proof that no
  external `-wal` or `-shm` is required.
- Never vacuum, rewrite, repair, or delete the Legacy database during inventory.

## Writer fence protocol

Every active Legacy writer retains a shared kernel lock from its first mutation.
A freezer must:

1. stop admission and outbound dispatch under a maintenance Manifest;
2. drain effects and active writers;
3. obtain the exclusive coordination lock;
4. commit a fence record bound to one snapshot identity;
5. verify every registered sink is guarded;
6. remain in no-writer state until snapshot/cutover recovery rules decide the
   next authoritative state.

Phase 0 exposes no Production freeze command. Its freeze/unfreeze methods reject
anything except marked disposable fixtures. The Standing Owner Authorization is
used later only after the required automatic gates and a Phase 6B maintenance
Manifest exist.

## Shadow and comparison rules

Shadow namespace is `shadow/<snapshot_id>` and every envelope has
`authority=false`. Provider, MCP, Tool, Approval, Timer, Terminal, Effect and
Evidence Seal operations reject that context. Legacy time is payload provenance;
Shadow commit time is import time.

Dual-read comparison fixes one frontier and preserves business identity, status,
counts, hashes, protocol/effect accounting and secret-scan status. Only listed
representation fields may normalize. Missing Legacy information requires an
approved reason enum plus exact source references. Every other difference is a
Cutover-blocking mismatch.

## Recovery

If a fence record is corrupt, a lock outcome is unknown, or a source changes
during capture, fail closed. Do not restore a writer by phase name or create a
second guessed command. Preserve the report and incident evidence, identify the
same command/snapshot, and follow the later recovery epoch protocol.
