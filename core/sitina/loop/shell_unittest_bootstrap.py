"""Trusted unittest entry for the fenced Loop shell command."""

from __future__ import annotations

import os
import sys
import sysconfig


def _load_stdlib_unittest():
    """Import stdlib unittest before the input directory is importable.

    The command cwd is an untrusted input copy.  Loading this package while
    that cwd is first on ``sys.path`` would allow ``unittest.py`` in the input
    to replace the trusted runner.  The bootstrap temporarily removes cwd and
    input entries, imports the standard library package, then restores normal
    test discovery imports with the trusted package cached in ``sys.modules``.
    """

    original = list(sys.path)
    stdlib = [
        value
        for value in (
            sysconfig.get_path("stdlib"),
            sysconfig.get_path("platstdlib"),
            sysconfig.get_path("purelib"),
        )
        if isinstance(value, str) and value
    ]
    cwd = os.path.abspath(os.getcwd())
    try:
        sys.path[:] = stdlib + [value for value in original if os.path.abspath(value or os.curdir) != cwd]
        import unittest  # noqa: WPS433 - deliberate trusted bootstrap import

        return unittest
    finally:
        sys.path[:] = original


def main() -> None:
    unittest = _load_stdlib_unittest()
    # ``-I`` keeps the bootstrap itself off the business import path.  Only
    # after trusted stdlib imports are cached do we expose the copied cwd so
    # unittest can import the user's test modules.
    cwd = os.path.abspath(os.getcwd())
    sys.path.insert(0, cwd)
    unittest.main(module=None)


if __name__ == "__main__":
    main()
