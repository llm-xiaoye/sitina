from __future__ import annotations

import io
import random
import struct
import unittest
import zlib

from sitina.journal.codec import FOOTER_MAGIC, PREFIX, FrameCorruption, FrameLimits, decode_one, encode_frame, scan_frames
from sitina.journal.model import (
    EventEnvelope,
    JournalModelError,
    JournalTransaction,
    domain_hash,
    event_replay_projection,
    event_replay_projection_bytes,
)


class _Auth:
    def authenticate(self, *_args):
        return "journal-auth:test:v1", "ab" * 32

    def verify(self, *_args):
        return True


def transaction(count=1):
    events = []
    for index in range(count):
        event = EventEnvelope(
            f"event-{index+1}", "fixture.changed", "tenant-1", "stream-1", index + 1, index + 1,
            "2026-07-13T00:00:00Z", {"index": index},
        ).seal(journal_id="journal-1", epoch=1, authenticator=_Auth())
        events.append(event)
    return JournalTransaction("tx-1", "cmd-1", "12" * 32, "stream-1", tuple(events))


class JournalCodecTests(unittest.TestCase):
    def test_one_and_multiple_event_frames_round_trip(self) -> None:
        for count in (1, 3):
            with self.subTest(count=count):
                original = transaction(count)
                decoded = decode_one(encode_frame(original))
                self.assertEqual(decoded.transaction, original)
                self.assertEqual(len(decoded.transaction_hash), 64)

    def test_multiple_frames_scan_as_contiguous_prefix(self) -> None:
        raw = encode_frame(transaction()) + encode_frame(transaction(2))
        result = scan_frames(io.BytesIO(raw))
        self.assertTrue(result.clean)
        self.assertEqual(len(result.frames), 2)
        self.assertEqual(result.valid_end_offset, len(raw))

    def test_crc_and_transaction_hash_corruption_fail_closed(self) -> None:
        raw = bytearray(encode_frame(transaction()))
        for index in (30, -20):
            damaged = bytearray(raw)
            damaged[index] ^= 1
            result = scan_frames(io.BytesIO(damaged))
            self.assertEqual(result.first_invalid_offset, 0)
            self.assertFalse(result.clean)

    def test_truncated_header_body_and_footer_are_incomplete(self) -> None:
        raw = encode_frame(transaction(2))
        for end in (1, 24, len(raw) // 2, len(raw) - 1):
            with self.subTest(end=end):
                result = scan_frames(io.BytesIO(raw[:end]))
                self.assertEqual(result.first_incomplete_offset, 0)

    def test_unknown_major_and_oversize_rejected_before_body_read(self) -> None:
        raw = bytearray(encode_frame(transaction()))
        raw[8:10] = struct.pack(">H", 2)
        self.assertEqual(scan_frames(io.BytesIO(raw)).first_invalid_offset, 0)
        prefix = struct.pack(">8sHHIQ", b"SITBPF01", 1, 0, 1, FrameLimits().max_frame_bytes + 1)
        stream = io.BytesIO(prefix)
        result = scan_frames(stream)
        self.assertEqual(result.first_invalid_offset, 0)
        self.assertEqual(stream.tell(), len(prefix))

    def test_legacy_frame_with_object_refs_reopens_with_explicit_legacy_proof_marker(self) -> None:
        """Old frames remain readable, but their proof identity is not replay authority."""
        reference = "cas:" + "a" * 64
        event = EventEnvelope(
            "event-legacy-ref", "fixture.changed", "tenant-1", "stream-legacy", 1, 1,
            "2026-07-13T00:00:00Z", {"legacy": True}, (reference,),
        ).seal(journal_id="journal-1", epoch=1, authenticator=_Auth())
        transaction = JournalTransaction(
            "tx-legacy", "cmd-legacy", "34" * 32, "stream-legacy", (event,),
            (reference,), proof_manifest=({"reference_id": reference, "proof_type": "legacy_v1"},),
        )
        current = encode_frame(transaction)
        magic, major, minor, header_len, frame_len = PREFIX.unpack_from(current)
        # The current extension is marker + proof count + one length-prefixed
        # canonical proof entry.  Remove it to model a deployed V1 frame.
        header_start = PREFIX.size
        header = current[header_start : header_start + header_len]
        # The proof entry length is immediately before its canonical bytes;
        # locate the final canonical object and decode the extension tail.
        entry_start = header.rfind(b"{")
        entry_length_offset = entry_start - 4
        entry_length = struct.unpack_from(">I", header, entry_length_offset)[0]
        proof_count_offset = entry_length_offset - 4
        proof_count = struct.unpack_from(">I", header, proof_count_offset)[0]
        self.assertEqual(proof_count, 1)
        extension_length = 1 + 4 + 4 + entry_length
        legacy_header = header[:-extension_length]
        body_and_tail = current[header_start + header_len :]
        legacy_frame_len = PREFIX.size + len(legacy_header) + len(body_and_tail)
        legacy_prefix = PREFIX.pack(magic, major, minor, len(legacy_header), legacy_frame_len)
        covered = legacy_prefix + legacy_header + body_and_tail[:-4 - 32 - len(FOOTER_MAGIC)]
        crc = struct.pack(">I", zlib.crc32(covered) & 0xFFFFFFFF)
        legacy_hash = bytes.fromhex(domain_hash("TRANSACTION_FRAME", covered + crc))
        legacy = covered + crc + legacy_hash + FOOTER_MAGIC
        decoded = decode_one(legacy)
        self.assertEqual(decoded.transaction.proof_manifest, ({"reference_id": reference, "proof_type": "legacy_v1"},))

    def test_replay_projection_is_shared_schema_and_preserves_json_types(self) -> None:
        event = EventEnvelope(
            "projection-event", "projection", "tenant-1", "stream-1", 0, 0,
            "2026-07-18T00:00:00Z", {"value": 1},
        )
        projection = event_replay_projection(event)
        self.assertEqual(event_replay_projection_bytes((event,)), event_replay_projection_bytes((projection,)))
        changed_type = dict(projection)
        changed_type["payload"] = {"value": True}
        self.assertNotEqual(event_replay_projection_bytes((projection,)), event_replay_projection_bytes((changed_type,)))
        schema_drift = dict(projection)
        schema_drift["schema_major"] = 1
        with self.assertRaises(JournalModelError):
            event_replay_projection_bytes((schema_drift,))

    def test_deterministic_mutation_fuzz_never_raises_or_allocates_from_length(self) -> None:
        randomizer = random.Random(20260713)
        raw = encode_frame(transaction(3))
        for _ in range(200):
            damaged = bytearray(raw)
            for _ in range(randomizer.randint(1, 4)):
                index = randomizer.randrange(len(damaged))
                damaged[index] ^= randomizer.randrange(1, 256)
            result = scan_frames(io.BytesIO(damaged), FrameLimits(max_frame_bytes=len(raw) + 16))
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
