# Sitina Journal event authentication profile

Profile ID: `SITINA_JOURNAL_AUTH_V1`

Event authentication is HMAC-SHA-256 under a Journal-Auth-purpose key. The exact
preimage is:

`"SITINA-JOURNAL-AUTH-V1" || 0x00 || journal_id || 0x00 || epoch_u64_be || 0x00 || key_id || 0x00 || event_hash_bytes`.

The event hash is the unkeyed `EVENT_CORE` domain hash. Transaction hashes bind
the final stored event bytes, including auth key ID and auth tag. A key transition
is a canonical event at a segment boundary and binds old key ID, new key ID,
epoch, previous segment commitment, effective next position, and transition
policy hash. The old key authenticates that event. Rotation between frames in a
segment is forbidden. Historical keys remain available for verification until an
audited retention/archival gate says otherwise. Missing/wrong/expired keys,
broken transitions, and historical-key loss fail verification closed.

