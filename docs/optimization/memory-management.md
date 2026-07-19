# Memory management authority and safety

Phase 03 extends the existing `MemoryRepository`, Local Journal, and Local CAS. The Journal remains the only lifecycle and conflict authority; CAS remains the only body/evidence byte authority. Retrieval scores, consolidation decisions, capacity selections, and query results are derived values, not a second state store.

## Lifecycle and trust boundaries

- Every candidate starts in the `working` tier. Only an accepted, non-quarantined record may be promoted, and promotion is strictly `working -> episodic -> long_term` with reviewer identity and reason recorded in the memory stream.
- Memory bodies always carry `content_trust=untrusted`. Retrieval returns them inside an `UNTRUSTED_MEMORY_DATA` boundary marked `instructions=false`; memory text cannot become a system or developer instruction.
- Pollution assessment records quarantine and confidence reduction in the same memory stream. Current retrieval and active CAS roots exclude quarantined records, and consolidation rejects them so they cannot propagate.
- TTL is evaluated at read time and never rewrites Journal history. `legal-retention` records remain current until an explicit audited lifecycle transition.

## Consolidation, retrieval, and conflicts

- Consolidation requires the same scope, owner, and namespace, intersects ACLs, keeps all source events/runs/agents/evidence, takes conservative trust/confidence/tier values, and creates a deterministic candidate in the existing repository.
- A retrieval backend may provide semantic scores from `0..1000`. Missing, unavailable, or malformed backends fall back to deterministic Unicode-normalized lexical similarity. ACL filtering happens before the backend receives candidate bodies.
- Conflicting accepted records coexist. Detection writes an `OPEN` conflict fact to the Journal; only an authorized reviewer can select a record, revoke the others, and append the terminal `RESOLVED` fact. There is no last-writer-wins path or in-memory conflict authority.

## Capacity and provenance

- `config/memory_capacity.json` defines strict positive record and byte limits. Resolution order is exact namespace, repository tenant, then default.
- Eviction is preflighted before mutation, excludes explicitly referenced and legal-retention records, and orders eligible records by lowest confidence, oldest timestamp, then stable ID. Each expiration has a `capacity-eviction` reason and a structured explanation.
- Provenance verification recomputes the content hash, resolves every evidence CAS reference, and verifies source event and run identities against Journal facts. Any orphan fails closed.

All new management writes reuse the existing `memory_v1_write` Journal activation and therefore remain disabled by the shipped default feature configuration until the existing compatibility-lease activation protocol authorizes them.
