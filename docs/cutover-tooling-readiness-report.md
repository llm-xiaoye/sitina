# CutoverToolingReady R1 report profile

The former Phase 6A `CutoverToolingReady` report is superseded because it proved
fixture primitives but did not contain a deployed Production operator, durable
authority rereader, persistent Production key transport, or Journal-first CLI
route. Phase 6A-R1 may issue a replacement readiness record only after all R1
predicates and cross-phase tests pass.

Required R1 evidence includes:

- signed, hash-bound, time-limited Phase 6B manifest admission with exact code
  identities and no fabricated human identity;
- deterministic Production Genesis bytes/hash, independent verifier binding,
  namespace separation, and idempotent persistence;
- direct Security.framework Keychain round-trip in an ephemeral non-Production
  keychain, purpose separation, restart verification, and no secret argv;
- kernel Legacy fence plus explicit allowance only for capability-checked B+
  `journal`, `cas`, `projections`, and Production-Genesis paths;
- coherent frozen snapshot, complete file/SQLite coverage, canonical backup
  hold, and isolated restore;
- encrypted CAS publication of every source file, Journal-rooted migration
  facts, and restart-stable batch/control timestamps;
- stable Cutover and CutoverVerified command contracts, lost-ACK recovery, and
  no dual-writer state;
- durable post-window authority reconstruction from authenticated Journal bytes,
  not process memory or a phase flag;
- deployed engine and CLI Journal-first routing with merged B+ and fixed-frontier
  Legacy `list`, `show`, `trace`, `report`, and zero-external `replay` readers;
- actual operator-CLI simulation through freeze, snapshot, backup/restore,
  migration, cutover, canary, rebuild, CutoverVerified, and durable reread;
- complete Phase 6A and cross-phase regression results, zero external/Production
  test attempts, and exact unchanged Production sentinels.

The report must explicitly retain:

```text
authority=false
maintenance_authorized=false
cutover_authorized=false
execute_capability_present=false
production_writer=legacy
```

These fields describe the readiness record itself. The shipped operator exists,
but cannot run against Production without a separately verified Phase 6B
capability. The R1 report is invalidated by any source/config/profile drift,
failed predicate, unaccounted skip, sentinel difference, or unresolved incident.
