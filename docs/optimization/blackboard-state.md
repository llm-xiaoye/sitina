# Blackboard state management

Phase 02 extends `sitina.protocols.blackboard.Blackboard`; it does not add a database, JSON state file, or competing writer. Journal facts are canonical, CAS holds bodies that are large or sensitive, and in-memory documents, snapshots, indexes, cursors, and subscriptions are derived views.

## Accepted behavior

- MVCC commits are serialized by the aggregate lock. A stale version/hash produces a retryable conflict fact and never mutates the document stream.
- Read-only snapshots bind tenant, run, Journal position, selected document versions, schema metadata, content references, and a deterministic hash. Restore is fail-closed and only initializes an empty recovery aggregate.
- Patch facts include actor, before/after hashes, causation ID, field-level commitments, and no raw sensitive values. Diff replay checks the complete version/hash chain.
- `config/blackboard_limits.json` controls total, document, and field byte limits plus a warning threshold. Missing legacy config uses conservative built-in defaults. Rejected writes emit an audit fact after proving the document state is unchanged.
- Namespace policy decides `RUN_LOCAL` versus `PROJECT_SHARED`. Reuse preserves the original identity and hash; run-local promotion, cross-run snapshot restore, and cross-tenant reuse fail closed.
- Structured bodies use `SITINA_BLACKBOARD_BODY_V1` with explicit `notes`, `data`, and `tags`. The only legacy migration is deterministic V0 text to V1 notes; unknown versions and fields are rejected.
- Query indexes are rebuilt from the selected snapshot and filter namespace, nested key, tag, run, and version. Cursors bind the snapshot position, so concurrent writes cannot change later pages. Unauthorized documents are omitted.
- Reader/writer capabilities and writable paths are frozen in namespace policy. Safety fields are denied recursively after alias normalization; denial is a redacted audit fact.
- Subscriptions replay committed Journal facts after an acknowledged position. Notification IDs are deterministic, duplicate event IDs are idempotent, slow consumers retain lag, and polling uses the same deduplicated facts.

The deterministic phase test uses barriers, seeded interleavings, snapshot crash recovery, conflict retries, and 16 concurrent writers. It contains no timing sleeps.
