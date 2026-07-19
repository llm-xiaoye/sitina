# Sitina B+ cutover runbook

## Readiness versus authority

The original Phase 6A fixture-only readiness is superseded. Phase 6A-R1 proves
the exact Production-capable tooling on controlled Production simulations, but
still grants no Production operation. `CutoverToolingReady` is signed evidence,
not a writer selection, maintenance window, Keychain permission, snapshot
permission, or Cutover command.

Production execution requires a separate signed and time-bounded
`PHASE6B_MAINTENANCE_MANIFEST_V1`. The verifier binds it to the standing owner
authorization and Goal thread, current readiness hash, exact source/config
hashes, disjoint roots, Production Genesis bytes/hash, stable Cutover and
CutoverVerified command contracts, three distinct technical roles, prerequisite
facts, and a window no longer than six hours. Any difference issues no
capability.

## Authority states

Only `AuthorityResolver` selects the writer:

| Resolved state | Authorized writer |
| --- | --- |
| `LEGACY_WRITER_AUTHORIZED` | Legacy only |
| `CUTOVER_PREPARED_NO_WRITER` | none |
| `CUTOVER_OUTCOME_UNKNOWN_NO_WRITER` | none |
| `JOURNAL_WRITER_AUTHORIZED` | Journal only |
| `RECOVERY_REQUIRED_NO_WRITER` | none |

A committed outcome must match the prepared fence, stable command ID/request
hash, exact Production Genesis, and snapshot intent. Invalid authentication,
gaps, conflicting facts, stale resolution, or lost outcome proof fails closed.
Recovery reopens the authenticated Journal and queries the same stable command;
it never invents a replacement command.

## Phase 6B operator

The only execution entrypoint is `scripts/cutover-phase6b.py`. It has no prompt
or flag that can manufacture authority. The operator must be passed both
control-artifact paths and their independently supplied expected hashes:

```text
python3 scripts/cutover-phase6b.py \
  --manifest <phase6b-maintenance-manifest.json> \
  --readiness <sitina-bplus-cutover-tooling-ready-r1.json> \
  --expected-manifest-sha256 <64-hex> \
  --expected-readiness-sha256 <64-hex>
```

`--allow-simulation` and `--memory-keychain` are accepted only for a marked,
disposable controlled simulation. Production always uses the local macOS
Security.framework Keychain backend; secret material never enters argv.

The operator performs these gates in order:

1. verify manifest/readiness signatures, identities, roots, window, and exact
   command contracts;
2. take a single-executor lock, drain/fence Legacy, and enter no-writer state;
3. create a coherent snapshot, complete Source Coverage, canonical backup/hold,
   and isolated restore proof;
4. persist the exact independently verified Production Genesis and initialize
   purpose-separated Keychain keys;
5. encrypt and root every frozen Legacy source file in CAS, append restart-stable
   migration batches, and commit Migration Control;
6. append the prepared fact, rebuild at the fixed frontier, and re-resolve
   `CUTOVER_PREPARED_NO_WRITER`;
7. submit the stable Cutover command once; after a crash or ACK loss, recover
   only that command ID/hash;
8. activate Journal-first routing, run a mock-only dynamic canary, expose both
   Journal and frozen-Legacy reader generations, and rebuild from canonical
   Journal facts;
9. submit the manifest-frozen CutoverVerified command contract and independently
   reread it from authenticated Journal bytes;
10. write the final control-plane report only after durable
    `JOURNAL_WRITER_AUTHORIZED` and committed `CutoverVerified` are both proven.

## Recovery and rollback

Before Cutover submission, a failed snapshot, coverage, backup, restore,
migration, rebuild, or identity check stops in no-writer state and preserves all
diagnostics. A partially materialized snapshot/backup without a valid manifest
is never silently reused. After submission uncertainty, only locked Journal
recovery of the same command is permitted.

After a committed Cutover, Legacy can never resume write authority. Rollback is
limited to a reader generation, Journal-compatible binary, forward fix, or a new
Recovery Epoch. The frozen Legacy SQLite reader uses `mode=ro&immutable=1`, has
no WAL/SHM sidecars, is labeled with its snapshot frontier, and cannot supply
business preconditions. Legacy bytes and the canonical backup remain under
hold; deletion, Hot Eviction, and crypto-erasure are outside this operation.

Stop on sentinel drift, path aliasing, writer-lock contention, Keychain failure,
coverage omission, restore mismatch, source/config drift, command conflict,
unknown outcome, dual-read failure, rebuild failure, or any attempted capability
above `MOCK_ONLY`.
