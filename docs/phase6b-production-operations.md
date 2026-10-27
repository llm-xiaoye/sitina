# Phase 6B Production operations

## Persisted authority inputs

Production runtime startup reconstructs its state from four durable inputs:

1. `state/.legacy-control/frozen.json`, including the exact fence hash, snapshot
   destination, snapshot intent, Journal ID, and stable Cutover command identity;
2. `state/bplus-production-genesis/genesis.json`, whose full body and hash were
   frozen in the signed Maintenance Manifest;
3. purpose-separated keys in macOS Keychain under the Genesis namespace;
4. authenticated, gap-free Journal segments containing the prepared and exact
   committed Cutover facts.

No Maintenance capability is required after the window to read these facts.
`ProductionAuthorityReader` performs a no-lock, no-fsync, no-truncation scan and
issues a short-lived resolution. A writer open then takes the Journal lock and
performs normal locked recovery using that fresh resolution.

## Reader generations

The deployed reader merges:

- `bplus-journal-v1`: canonical post-cutover events and runs;
- `legacy-frozen-snapshot-v1`: immutable SQLite history from the exact snapshot
  destination recorded in the fence.

Every Legacy row is labeled with the snapshot-manifest hash. The reader refuses
symlinks, invalid manifests, a mismatched snapshot intent, missing database, or
WAL/SHM sidecars. It never opens live `~/SitinaHub/data/sitina.db`.

## Operational invariants

- Legacy fence remains permanent after committed Cutover.
- Business appends require a fresh unique Journal authority resolution.
- Maintenance capability can append only control/migration/operational facts;
  after business activation it can append only the exact CutoverVerified fact.
- All client retry paths reuse the original command identity and frozen
  timestamp.
- Projection databases are disposable and never grant authority.
- Reports and replay are read-only after cutover; CLI compatibility evidence is
  not written back to Legacy.
- Effect capability remains `MOCK_ONLY` until a separate later authorization.

## Incident rule

Any unexpected Production entry stops the run. Record its device/inode/mode,
hash, holders, exact cause, and recovery scope. Remove only an exact newly
created unheld entry under a separate recovery manifest, fsync its parent, and
recompute both Production sentinels. Never normalize a sentinel by changing the
baseline.
