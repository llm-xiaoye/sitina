# Sitina storage compatibility and rollback matrix

Configuration requests a rollout, but cannot activate a writer by itself. A
committed `runtime.feature-prepared` event, compatible live-process leases, and
a committed `runtime.feature-activated` event are all required. Once a new
format is written, the Authority Checkpoint and external rollback anchor retain
the rollback floor; turning a flag off does not erase that history.

| Reader / writer case | Required behavior |
|---|---|
| New reader, old format | Read directly or deterministically upcast to the canonical in-memory form. |
| New reader, new format | Read with full semantics when its capability is declared. |
| Old reader, new optional event | It may index only Event Directory metadata and must report incomplete semantic coverage. |
| Old reader, new required event | Fail closed; the Projection is DEGRADED and the writer must not infer missing state. |
| Old reader, zstd CAS | Writer activation is blocked until every live lease advertises `cas-zstd`. |
| Old reader, packed Envelope/Alias | Writer activation is blocked until every live lease advertises `alias-pack-v1`. |
| Code rollback after new-format write | Only a binary at or above the recorded rollback floor with all active reader capabilities may open the writer. |
| Projection reader failure | Journal authority remains writable; queries degrade and Projection is rebuilt. |

Upcasters are pure, deterministic functions. They do not read a clock, network,
Provider, Projection, or mutable runtime state; replay records the upcaster name,
version, implementation hash, input hash, and canonical output hash. Stored
Journal bytes are never rewritten.

## Threat model

The local integrity model covers accidental media damage, silent file changes,
sealed-segment replacement, full-Journal rollback, checkpoint rollback, stale
writers, and wall-clock rollback. Ordering relies on Journal position, stream
version, checkpoint sequence, and fencing token. Wall time is advisory; lease
holders use monotonic elapsed time within a process and conservative expiry
after a detected clock anomaly. The trust assumption is that the macOS Keychain
authentication key and rollback anchor are not both compromised with the data
directory.
