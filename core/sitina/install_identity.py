"""Runtime identity of the active Journal-native Sitina installation."""

from __future__ import annotations

import os
import pwd
from pathlib import Path


def account_production_home() -> Path:
    """Locate the account's protected installation independently of HOME.

    The POSIX account database is the authority for legacy production guards.
    A caller-controlled HOME may select an isolated Journal-native environment,
    but must never remove protection from the real account's installation.
    Failure to resolve the account is deliberately fatal, not a HOME fallback.
    """
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    if not home.is_absolute() or home == Path("/"):
        raise RuntimeError("cannot determine an absolute production account home")
    return (home / "SitinaHub").resolve(strict=False)


LEGACY_PRODUCTION_HOME = account_production_home()


def canonical_journal_native_home() -> Path:
    """Return the active installation path for the current user environment."""

    return (Path.home() / "SitinaHub").resolve(strict=False)


__all__ = ["LEGACY_PRODUCTION_HOME", "account_production_home", "canonical_journal_native_home"]
