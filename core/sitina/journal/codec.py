from __future__ import annotations

import io
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO

from .model import EventEnvelope, JournalTransaction, canonical_json_bytes, domain_hash, object_reference_manifest_hash, parse_canonical_json


FRAME_PROFILE_ID = "SITINA_LOCAL_FRAME_V1"
POSITION_PROFILE_ID = "LOCAL_CONTIGUOUS_COMMITTED_PREFIX_V1"
MAGIC = b"SITBPF01"
FOOTER_MAGIC = b"SITEND01"
PREFIX = struct.Struct(">8sHHIQ")
U16 = struct.Struct(">H")
U32 = struct.Struct(">I")
U64 = struct.Struct(">Q")
U8 = struct.Struct(">B")


class FrameCodecError(ValueError):
    pass


class FrameCorruption(FrameCodecError):
    pass


@dataclass(frozen=True)
class FrameLimits:
    max_frame_bytes: int = 16 * 1024 * 1024
    max_header_bytes: int = 64 * 1024
    max_event_bytes: int = 4 * 1024 * 1024
    max_events: int = 4096
    max_object_references: int = 4096
    max_id_bytes: int = 1024


@dataclass(frozen=True)
class DecodedFrame:
    start_offset: int
    end_offset: int
    transaction: JournalTransaction
    transaction_hash: str
    raw: bytes


@dataclass(frozen=True)
class FrameScanResult:
    frames: tuple[DecodedFrame, ...]
    valid_end_offset: int
    first_incomplete_offset: int | None = None
    first_invalid_offset: int | None = None
    error: str | None = None

    @property
    def clean(self) -> bool:
        return self.first_incomplete_offset is None and self.first_invalid_offset is None


def _encoded_id(value: str, limits: FrameLimits) -> bytes:
    encoded = value.encode("utf-8")
    if not 1 <= len(encoded) <= limits.max_id_bytes or len(encoded) > 0xFFFF:
        raise FrameCodecError("identifier length exceeds frame profile")
    return U16.pack(len(encoded)) + encoded


def encode_frame(transaction: JournalTransaction, limits: FrameLimits | None = None) -> bytes:
    limits = limits or FrameLimits()
    if len(transaction.events) > limits.max_events:
        raise FrameCodecError("event count exceeds frame profile")
    if len(transaction.object_references) > limits.max_object_references:
        raise FrameCodecError("object reference count exceeds frame profile")
    event_bytes = [event.canonical_stored_bytes() for event in transaction.events]
    if any(len(item) > limits.max_event_bytes for item in event_bytes):
        raise FrameCodecError("event length exceeds frame profile")
    header = b"".join(
        (
            _encoded_id(transaction.transaction_id, limits),
            _encoded_id(transaction.command_id, limits),
            bytes.fromhex(transaction.command_request_hash),
            _encoded_id(transaction.stream_id, limits),
            U32.pack(len(transaction.object_references)),
            bytes.fromhex(transaction.object_reference_manifest_hash),
            U32.pack(len(transaction.events)),
            U64.pack(transaction.first_position),
            U64.pack(transaction.last_position),
            U64.pack(transaction.first_stream_version),
            U64.pack(transaction.last_stream_version),
            U8.pack(1 if transaction.authenticated_seal_stream_id is not None else 0),
            (_encoded_id(transaction.authenticated_seal_stream_id, limits)
             if transaction.authenticated_seal_stream_id is not None else b""),
            U32.pack(len(transaction.proof_manifest)),
            *(
                U32.pack(len(encoded)) + encoded
                for encoded in (
                    canonical_json_bytes(dict(item))
                    for item in transaction.proof_manifest
                )
            ),
        )
    )
    if len(header) > limits.max_header_bytes:
        raise FrameCodecError("header exceeds frame profile")
    body = b"".join(U32.pack(len(item)) for item in event_bytes) + b"".join(event_bytes)
    frame_len = PREFIX.size + len(header) + len(body) + U32.size + 32 + len(FOOTER_MAGIC)
    if frame_len > limits.max_frame_bytes:
        raise FrameCodecError("frame exceeds frame profile")
    prefix = PREFIX.pack(MAGIC, 1, 0, len(header), frame_len)
    covered = prefix + header + body
    crc = U32.pack(zlib.crc32(covered) & 0xFFFFFFFF)
    transaction_hash = bytes.fromhex(domain_hash("TRANSACTION_FRAME", covered + crc))
    return covered + crc + transaction_hash + FOOTER_MAGIC


class _Reader:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.offset = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.raw):
            raise FrameCorruption("frame field exceeds declared boundary")
        result = self.raw[self.offset : self.offset + length]
        self.offset += length
        return result

    def u16(self) -> int:
        return U16.unpack(self.take(U16.size))[0]

    def u32(self) -> int:
        return U32.unpack(self.take(U32.size))[0]

    def u64(self) -> int:
        return U64.unpack(self.take(U64.size))[0]

    def identifier(self, limits: FrameLimits) -> str:
        length = self.u16()
        if not 1 <= length <= limits.max_id_bytes:
            raise FrameCorruption("identifier length exceeds limit")
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as error:
            raise FrameCorruption("identifier is not UTF-8") from error


def _decode_frame(raw: bytes, start: int, limits: FrameLimits) -> DecodedFrame:
    if len(raw) < PREFIX.size:
        raise FrameCorruption("truncated prefix")
    magic, major, minor, header_len, frame_len = PREFIX.unpack_from(raw)
    if magic != MAGIC:
        raise FrameCorruption("wrong frame magic")
    if major != 1 or minor != 0:
        raise FrameCorruption("unknown frame version")
    if frame_len != len(raw):
        raise FrameCorruption("frame length mismatch")
    if header_len > limits.max_header_bytes:
        raise FrameCorruption("header exceeds limit")
    if frame_len > limits.max_frame_bytes:
        raise FrameCorruption("frame exceeds limit")
    minimum_tail = U32.size + 32 + len(FOOTER_MAGIC)
    if PREFIX.size + header_len + minimum_tail > len(raw):
        raise FrameCorruption("header overlaps footer")
    if raw[-len(FOOTER_MAGIC) :] != FOOTER_MAGIC:
        raise FrameCorruption("wrong footer magic")
    stored_crc = U32.unpack(raw[-(minimum_tail) : -(32 + len(FOOTER_MAGIC))])[0]
    covered = raw[: -(minimum_tail)]
    if zlib.crc32(covered) & 0xFFFFFFFF != stored_crc:
        raise FrameCorruption("CRC mismatch")
    through_crc = raw[: -(32 + len(FOOTER_MAGIC))]
    stored_hash = raw[-(32 + len(FOOTER_MAGIC)) : -len(FOOTER_MAGIC)].hex()
    if domain_hash("TRANSACTION_FRAME", through_crc) != stored_hash:
        raise FrameCorruption("transaction hash mismatch")

    header = _Reader(raw[PREFIX.size : PREFIX.size + header_len])
    transaction_id = header.identifier(limits)
    command_id = header.identifier(limits)
    request_hash = header.take(32).hex()
    stream_id = header.identifier(limits)
    object_count = header.u32()
    object_manifest = header.take(32).hex()
    event_count = header.u32()
    first_position, last_position = header.u64(), header.u64()
    first_version, last_version = header.u64(), header.u64()
    authenticated_seal_stream_id = None
    # Older frames ended after the last stream version. New frames carry an
    # explicit transaction-level marker; a root payload alone is insufficient
    # during recovery.
    if header.offset < len(header.raw):
        marker = U8.unpack(header.take(U8.size))[0]
        if marker == 1:
            authenticated_seal_stream_id = header.identifier(limits)
        elif marker != 0:
            raise FrameCorruption("invalid authenticated seal marker")
    proof_manifest: tuple[dict, ...] = ()
    legacy_proof_manifest = False
    if header.offset < len(header.raw):
        proof_count = header.u32()
        if proof_count > limits.max_object_references:
            raise FrameCorruption("proof manifest exceeds limit")
        values = []
        for _ in range(proof_count):
            length = header.u32()
            if length > limits.max_event_bytes:
                raise FrameCorruption("proof manifest entry exceeds limit")
            value = parse_canonical_json(header.take(length))
            if not isinstance(value, dict):
                raise FrameCorruption("proof manifest entry is not an object")
            values.append(value)
        proof_manifest = tuple(values)
    else:
        # V1 frames had no proof extension.  Keep them reopenable by deriving
        # a stable, explicitly legacy marker from their object references.
        # This marker is not a proof for a new replay; a replay must present
        # current typed proofs and will fail the manifest comparison.
        legacy_proof_manifest = True
    if header.offset != len(header.raw):
        raise FrameCorruption("unknown header extension")
    if not 1 <= event_count <= limits.max_events:
        raise FrameCorruption("event count exceeds limit")
    if object_count > limits.max_object_references:
        raise FrameCorruption("object count exceeds limit")
    if last_position - first_position + 1 != event_count or last_version - first_version + 1 != event_count:
        raise FrameCorruption("local contiguous span mismatch")
    body_end = len(raw) - minimum_tail
    body = _Reader(raw[PREFIX.size + header_len : body_end])
    lengths = [body.u32() for _ in range(event_count)]
    if any(length > limits.max_event_bytes for length in lengths):
        raise FrameCorruption("event exceeds limit")
    if sum(lengths) != len(body.raw) - body.offset:
        raise FrameCorruption("event lengths do not cover body")
    events = tuple(EventEnvelope.from_stored_bytes(body.take(length)) for length in lengths)
    if body.offset != len(body.raw):
        raise FrameCorruption("unconsumed frame body")
    if [event.position for event in events] != list(range(first_position, last_position + 1)):
        raise FrameCorruption("event positions disagree with header")
    if [event.stream_version for event in events] != list(range(first_version, last_version + 1)):
        raise FrameCorruption("event stream versions disagree with header")
    references = tuple(sorted({reference for event in events for reference in event.object_refs}))
    if len(references) != object_count or object_reference_manifest_hash(references) != object_manifest:
        raise FrameCorruption("object reference manifest mismatch")
    if legacy_proof_manifest and references:
        proof_manifest = tuple(
            {"reference_id": reference, "proof_type": "legacy_v1"}
            for reference in references
        )
    transaction = JournalTransaction(
        transaction_id, command_id, request_hash, stream_id, events, references,
        authenticated_seal_stream_id,
        proof_manifest,
    )
    return DecodedFrame(start, start + len(raw), transaction, stored_hash, raw)


def scan_frames(fileobj: BinaryIO, limits: FrameLimits | None = None) -> FrameScanResult:
    limits = limits or FrameLimits()
    frames: list[DecodedFrame] = []
    start = fileobj.tell()
    valid_end = start
    while True:
        prefix = fileobj.read(PREFIX.size)
        if not prefix:
            return FrameScanResult(tuple(frames), valid_end)
        if len(prefix) < PREFIX.size:
            return FrameScanResult(tuple(frames), valid_end, first_incomplete_offset=start, error="truncated prefix")
        try:
            magic, major, minor, header_len, frame_len = PREFIX.unpack(prefix)
            if magic != MAGIC or major != 1 or minor != 0:
                raise FrameCorruption("invalid frame prefix")
            if frame_len < PREFIX.size + U32.size + 32 + len(FOOTER_MAGIC):
                raise FrameCorruption("declared frame is too small")
            if frame_len > limits.max_frame_bytes or header_len > limits.max_header_bytes:
                raise FrameCorruption("declared length exceeds capacity profile")
            remainder = fileobj.read(frame_len - PREFIX.size)
            if len(remainder) != frame_len - PREFIX.size:
                return FrameScanResult(tuple(frames), valid_end, first_incomplete_offset=start, error="truncated frame")
            decoded = _decode_frame(prefix + remainder, start, limits)
        except (FrameCodecError, ValueError, OverflowError) as error:
            return FrameScanResult(tuple(frames), valid_end, first_invalid_offset=start, error=str(error))
        frames.append(decoded)
        valid_end = decoded.end_offset
        start = valid_end


def decode_one(raw: bytes, limits: FrameLimits | None = None) -> DecodedFrame:
    result = scan_frames(io.BytesIO(raw), limits)
    if not result.clean or len(result.frames) != 1 or result.valid_end_offset != len(raw):
        raise FrameCorruption(result.error or "expected exactly one complete frame")
    return result.frames[0]
