# Sitina strict canonical JSON profile

Profile ID: `SITINA_CANONICAL_JSON_V1`

This profile is immutable. A behavioral change requires a new profile ID and
major version; already committed bytes are never reinterpreted.

## Encoding

- Text is UTF-8 without a BOM. Object member names and string values are
  normalized to Unicode NFC before encoding.
- Objects are ordered by normalized member name using Unicode code-point order.
  Arrays retain input order. A field is treated as set-like only when its schema
  explicitly says so; its normalized elements are then sorted by canonical byte
  order and duplicates are rejected.
- JSON separators are exactly `,` and `:` with no insignificant whitespace.
- `null`, booleans, strings, arrays, objects, and signed 64-bit integers are
  allowed. Floats, decimals, NaN, infinity, integers outside
  `[-9223372036854775808, 9223372036854775807]`, non-string object keys, and
  surrogate code points are rejected.
- Timestamps use RFC3339 UTC in the exact form `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
  Fractions have one through nine digits and trailing zeroes are significant.
- Decoders reject duplicate member names before schema conversion. Persisted
  objects reject unknown fields, missing required fields, and unknown major
  versions. A decoded persisted value must re-encode byte-for-byte to its input.

## Domain-separated digest

`SHA256("SITINA-BPLUS-V1" || 0x00 || ASCII(domain) || 0x00 || canonical_bytes)`.
Domains are uppercase ASCII identifiers frozen by the owning profile.

