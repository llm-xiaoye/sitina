from __future__ import annotations

import os
from pathlib import Path

from .model import CASError


NO_REPLACE_PROFILE = "MACOS_LINKAT_NO_REPLACE_SAME_FILESYSTEM_V1"


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_no_replace(source: Path, target: Path) -> None:
    if source.is_symlink() or target.is_symlink():
        raise CASError("CAS publication rejects symlinks")
    if source.parent.stat().st_dev != target.parent.stat().st_dev:
        raise CASError("CAS no-replace publication requires one filesystem")
    try:
        os.link(source, target, follow_symlinks=False)
    except FileExistsError:
        raise
    except OSError as error:
        raise CASError(f"no-replace link publication failed: {error}") from error
    if os.environ.get("SITINA_AUDIT_RETAIN_STAGING") != "1":
        os.unlink(source)
    else:
        # Clean revalidation forbids deletion.  The published target is still
        # the same atomically linked inode; retaining the staging hardlink
        # preserves a complete audit trail without weakening no-replace.
        sync_directory(source.parent)
    sync_directory(target.parent)
