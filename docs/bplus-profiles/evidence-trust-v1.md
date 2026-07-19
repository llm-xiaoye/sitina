# Sitina B+ evidence trust profile V1

## Frozen scope

`SITINA_EVIDENCE_POLICY_BPLUS_V1` is the Phase 5 trust contract. Its canonical
JSON hash is bound into the package core, verifier identity, and seal. The
minimum sealable completeness level is `STREAM_CHAIN_VERIFIED`; only a
`PASSED` assessment is seal eligible. `ASSERTED` evidence cannot be sealed.

The signature encoding is raw Ed25519: exactly 64 signature bytes represented
as 128 lowercase hexadecimal characters. A statement also carries its full key
ID, purpose, environment, namespace, version, and profile. Authority-frontier
signing and evidence-seal signing are purpose separated. Evidence signing
requires a provider-issued, role-bound `evidence-sealer` capability; builders,
runtime writers, and verifiers cannot obtain that handle.

## Completeness and trust

Completeness and self-containment are separate axes. Verification, replay, and
inspection each declare `SELF_CONTAINED`, `HYBRID`, or `REFERENTIAL`. A package
may be stream-chain complete but referential for replay, or self-contained but
only asserted; neither property implies the other.

The levels are cumulative:

- `ASSERTED` requires a material inventory and source frontier, but is not
  cryptographic proof.
- `STREAM_CHAIN_VERIFIED` additionally requires verified stream chain, CAS and
  dependency closure, and available keys.
- `JOURNAL_INDEX_PROVEN` additionally requires the Journal index and stream
  enumeration proofs.
- `CRYPTOGRAPHICALLY_COMPLETE` additionally requires signed-frontier,
  inclusion, omission, and trust-material proofs. Missing omission proof is a
  forbidden claim, not a warning.

`FAILED` means a verification predicate is false. `INCOMPLETE` means required
material/proof is absent. `UNVERIFIABLE` means required trust/key material is
unavailable. `CONTRADICTED` preserves conflicting authenticated facts. These
statuses are distinct and fail closed.

## Time and later compromise

Trusted time, when available, is recorded in the seal statement. Without it,
the frozen disposition is `HISTORICAL_VALIDITY_INDETERMINATE`; the system must
not invent historical validity. Later revocation or compromise produces a new
trust assessment and never replaces the original signature or seal bytes.

Phase 5 sealing is limited to marked disposable homes. No Production seal,
authority, archive transfer, retention execution, or cutover is authorized.

