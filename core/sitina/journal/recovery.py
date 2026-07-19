from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .codec import FrameScanResult, scan_frames


class JournalRecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RecoveryResult:
    scan: FrameScanResult
    original_size: int
    recovered_size: int
    truncated_incomplete_tail: bool
    adopted_complete_frames: int


def recover_active_segment(path: Path) -> RecoveryResult:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        original_size = os.fstat(descriptor).st_size
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as handle:
            scan = scan_frames(handle)
        if scan.first_invalid_offset is not None:
            raise JournalRecoveryError(f"media corruption at byte {scan.first_invalid_offset}: {scan.error}")
        truncated = scan.first_incomplete_offset is not None
        if truncated:
            os.ftruncate(descriptor, scan.valid_end_offset)
        os.fsync(descriptor)
        return RecoveryResult(scan, original_size, scan.valid_end_offset, truncated, len(scan.frames))
    finally:
        os.close(descriptor)


def scan_sealed_segment(path: Path) -> FrameScanResult:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            result = scan_frames(handle)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    if not result.clean:
        raise JournalRecoveryError(f"sealed segment is not a complete valid prefix: {result.error}")
    return result


def scan_active_segment_read_only(path: Path) -> FrameScanResult:
    """Inspect an active prefix without truncation, adoption, fsync, or locks."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            result = scan_frames(handle)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    if result.first_invalid_offset is not None or result.first_incomplete_offset is not None:
        raise JournalRecoveryError("active Journal prefix requires locked recovery before authority can be resolved")
    return result
