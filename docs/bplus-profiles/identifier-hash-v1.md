# Sitina identifier and hash profile

Profile ID: `SITINA_IDENTIFIER_HASH_V1`

- Journal, tenant, stream, command, event, object, key, envelope, projection,
  policy, and capability IDs are NFC UTF-8 strings of 1–255 bytes. They match
  `[A-Za-z0-9][A-Za-z0-9._:/@-]*` and may not contain `..`, NUL, path separators
  outside the literal `/` already present in a schema-approved logical ID, or
  leading/trailing whitespace.
- Fields explicitly typed as UUID contain a 16-byte RFC 9562 UUID. UUID-looking
  strings in ordinary ID fields remain strings. UUID integer values outside 128
  bits are rejected.
- Hashes are SHA-256 and represented as 64 lowercase hexadecimal characters.
  Every hash uses the domain-separated preimage from `SITINA_CANONICAL_JSON_V1`.
- `COMMAND_REQUEST` excludes transport receipt time. `EVENT_CORE` excludes the
  event hash and Journal auth fields. `TRANSACTION_FRAME` covers exact stored
  bytes declared by the frame profile. `CAS_CORE_HEADER`, `CAS_ENVELOPE_AAD`,
  `OBJECT_REFERENCE_MANIFEST`, and `PROJECTION_SEMANTIC` are distinct domains.
- A self-hashed JSON record explicitly omits only its named self-hash field.

