# Sitina B+ execution contract

Phase -1 uses two immutable authorization levels. `PHASE_MINUS_1_BOOTSTRAP_V0`
may create only the listed Foundation Tasks 1–3 files and control records. It
cannot import the Sitina runtime, run tests, open production SQLite, or touch
production mutable roots. `EXECUTION_MANIFEST_V1` binds the resulting source
baseline, Python profile, dependency lock, complete-plan hash, mutation scope,
test-home root, stable command identity, stop point, and owner approval.

`ProductionHomeGuard` resolves real paths and fails closed when a test home is
the production home, a descendant, an ancestor, or a symlink alias. Mutation
roots are also rejected if they overlap `data`, `logs`, `state`, `artifacts`,
`outputs`, `memory`, `backups`, or `temp` in production.

All control records use canonical UTF-8 JSON with sorted keys and SHA-256. The
environment fingerprint contains only platform, interpreter, architecture, and
the normalized `SITINA_HOME`; environment variable values that may be secrets
are never copied into a manifest.

An absent, malformed, stale, hash-mismatched, scope-expanded, or production-
aliasing manifest authorizes read-only preflight only. It never falls back to a
phase flag, CLI option, or in-memory approval.
