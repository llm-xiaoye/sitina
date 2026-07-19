from __future__ import annotations

import io
import random
import struct
import unittest

from sitina.journal.codec import FrameCorruption, FrameLimits, decode_one, encode_frame, scan_frames
from sitina.journal.model import EventEnvelope, JournalTransaction


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
