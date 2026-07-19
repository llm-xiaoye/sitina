# Sitina B+ bundle container profile V1

## Hash layers

An evidence generation has four acyclic identities:

1. the Core hash excludes Assessment, Seal, Artifact, and its own hash;
2. the Assessment hash binds the exact Core, verifier identity, policy,
   completeness result, and predicates;
3. the Seal hash binds the exact Core and PASSED Assessment plus trust/time and
   signer material;
4. an Artifact carries a semantic hash and an independent container hash.

Artifact layout, compression, owner, mode, and time metadata do not alter the
semantic hash. The container hash commits to every relative path, file mode,
size, and exact file bytes. A byte or layout change therefore changes the
container hash even when semantic content is unchanged.

## Logical directory fallback

The preferred portable archive profile is `DETERMINISTIC_TAR_ZST_V1`, but this
runtime has no qualified frozen zstandard dependency. The only honest Phase 5
artifact is therefore `LOGICAL_DIRECTORY_V1`. A call requesting deterministic
tar.zst fails with `ContainerUnavailable`; it never emits an uncompressed tar,
uses an ambient compressor, or labels nondeterministic bytes as tar.zst.

Logical directories contain canonical `core.json`, `assessment.json`,
`seal.json`, `capabilities.json`, `semantic.json`, and `layout.json`. Paths are
relative, symlinks are forbidden, and all output is under a marked disposable
home. Capability manifests state which verify/replay/inspect inputs are embedded
or external.

When a later phase supplies and freezes zstandard, it must pin the compressor
version and options and normalize path order, owner/group, mode, mtime, and
header fields before this profile can claim deterministic tar.zst.

