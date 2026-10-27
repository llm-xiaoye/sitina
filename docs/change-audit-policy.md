# Sitina B+ source-only change audit policy

This installation uses `CONTENT_MANIFEST_V1` because `~/SitinaHub`
is not a Git repository. The audit records sorted relative paths, POSIX modes,
sizes, and SHA-256 hashes for source, tests, scripts, schemas, documentation,
and non-secret YAML/JSON configuration. Each new manifest links to the prior
manifest hash.

The following are never source-audit inputs: `data`, `logs`, `state`,
`artifacts`, `outputs`, `memory`, `backups`, `temp`, caches, `.env` files,
credential-bearing profiles, Keychain material, and secret-bearing files.
Symlinks are rejected rather than followed, so an ignored runtime path cannot
enter through an alias. Runtime data has separate inventory, backup, migration,
and retention evidence; exclusion here does not mean it is discarded.

The manifest tool is a dry-run by default. Writing a manifest requires an
explicit output path outside production mutable roots. No Git repository is
initialized and no source file is modified by the audit.
