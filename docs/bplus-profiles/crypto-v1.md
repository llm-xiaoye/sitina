# Sitina encrypted CAS and evidence crypto profile

Profile ID: `SITINA_CRYPTO_V1`

Every CAS object receives a fresh random 256-bit DEK and a fresh 96-bit CSPRNG
object nonce. Object bytes use AES-256-GCM; the immutable canonical Core Header is
AAD. Plaintext identity is a tenant-scoped HMAC-SHA-256 commitment using a
Commitment-purpose key and is never used as a storage path. The storage identity
is SHA-256 of the authenticated object bytes.

The DEK is wrapped by a separate AES-256-GCM KEK with an independent fresh
96-bit envelope nonce. Envelope AAD binds the Core Header hash, ciphertext object
identity, KEK key ID/version/environment, purpose, and wrap profile. Rewrap emits
a new immutable authenticated envelope version and audited alias; it cannot
change Core Header or ciphertext bytes.

Ed25519 signs Evidence and Authority records under separate purposes. Journal
event authentication uses the separate HMAC profile. DEK, KEK, Commitment,
Journal Auth, Evidence Signing, and Authority Signing keys cannot be resolved
through one another's capabilities. Test, development, and production provider
namespaces are disjoint. Key bytes are never serialized to source, reports,
Journal events, envelopes, or logs.

Decrypt verifies ciphertext digest, envelope AAD, object GCM tag, length, and
tenant commitment. Any mismatch or destroyed key fails closed.

