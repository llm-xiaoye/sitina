# Sitina local Journal frame profile

Profile ID: `SITINA_LOCAL_FRAME_V1`

Position profile: `LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1`. A committed local
segment has no position gaps and one transaction modifies exactly one logical
stream.

All integers are unsigned big-endian. The frame layout is:

```text
magic="SITBPF01"(8) major(u16=1) minor(u16=0) header_len(u32) frame_len(u64)
transaction_id_len(u16) transaction_id(UTF-8)
command_id_len(u16) command_id(UTF-8) request_hash(32)
stream_id_len(u16) stream_id(UTF-8)
object_reference_count(u32) object_reference_manifest_hash(32)
event_count(u32) first_position(u64) last_position(u64)
first_stream_version(u64) last_stream_version(u64)
event_lengths[event_count](u32 each) canonical_event_bytes
crc32(u32) transaction_hash(32) footer_magic="SITEND01"(8)
```

`header_len` ends immediately before the event-length vector. `frame_len`
includes every byte from magic through footer magic. CRC32 covers the prefix,
header, event-length vector, and event bytes. Transaction hash is
`DomainHash("TRANSACTION_FRAME", all bytes through CRC32)`. Only the transaction
hash field itself and footer are excluded.

Limits profile `SITINA_FRAME_LIMITS_SHADOW_V1` rejects lengths before allocation:
frame 16 MiB, header 64 KiB, event 4 MiB, 4,096 events, 4,096 object references,
and UTF-8 IDs 1,024 bytes. Unknown major versions, non-canonical event bytes,
invalid spans, CRC/hash mismatch, invalid UTF-8, and incomplete data fail closed.

