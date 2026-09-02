"""Runtime identity of the active Journal-native Sitina installation."""

from __future__ import annotations

from pathlib import Path


LEGACY_PRODUCTION_HOME = Path("/Users/moss/SitinaHub").resolve(strict=False)


def canonical_journal_native_home() -> Path:
    """Return the active installation path for the current user environment."""

    return (Path.home() / "SitinaHub").resolve(strict=False)


__all__ = ["LEGACY_PRODUCTION_HOME", "canonical_journal_native_home"]
