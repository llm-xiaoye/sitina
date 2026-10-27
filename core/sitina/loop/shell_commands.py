"""Narrow parser and identity model for the Loop ``sitina_shell`` surface."""

from __future__ import annotations

import math
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


SHELL_CAPABILITY = "LOOP_SHELL_UNITTEST_V1"
SHELL_ENTRY_VERSION = "trusted-stdlib-unittest-bootstrap-v1"
DEFAULT_SHELL_TIMEOUT_SECONDS = 300.0
MAX_SHELL_TIMEOUT_SECONDS = 300.0

_SHORT_FLAGS = {"-v", "-q", "-f", "-b"}
_TEST_NAME = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_SHELL_METACHARS = frozenset(";|&><`$")


@dataclass(frozen=True)
class ShellCommandSpec:
    """A parsed command or an honest pre-dispatch unsupported decision."""

    kind: str
    logical_argv: tuple[str, ...]
    unsupported_reason: str | None = None
    detail: str = ""

    @property
    def supported(self) -> bool:
        return self.kind == "unittest" and self.unsupported_reason is None


def _unsupported(argv: Sequence[str], reason: str, detail: str) -> ShellCommandSpec:
    return ShellCommandSpec("unsupported", tuple(str(item) for item in argv), reason, detail)


def _relative_path(value: str, *, allow_dot: bool = True) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        return False
    if "\\" in value or Path(value).is_absolute():
        return False
    parts = value.split("/")
    if any(part in {"", ".."} for part in parts):
        return False
    if not allow_dot and any(part == "." for part in parts):
        return False
    return True


def _test_target(value: str) -> bool:
    if value.endswith(".py"):
        return _relative_path(value)
    return bool(_TEST_NAME.fullmatch(value))


def _pattern(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
        and not value.startswith("-")
    )


def parse_shell_command(command: str) -> ShellCommandSpec:
    """Parse only the frozen shell grammar; never invokes a shell."""

    if not isinstance(command, str) or not command.strip():
        return _unsupported((), "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "empty command")
    if any(character in command for character in ("\x00", "\n", "\r")):
        return _unsupported((), "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "NUL/newline is not allowed")
    if any(character in command for character in _SHELL_METACHARS):
        return _unsupported((), "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "shell operators and substitutions are not allowed")
    try:
        argv = shlex.split(command, posix=True)
    except (TypeError, ValueError):
        return _unsupported((), "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "invalid shell quoting")
    if not argv:
        return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "empty command")

    if argv == ["sitina", "config", "validate"] or argv == ["sitina", "doctor"]:
        return _unsupported(argv, "UNSUPPORTED_REAL_INSTALL_STATE", "real installation/profile state is not bound")
    if argv == ["sitina", "eval"]:
        return _unsupported(argv, "UNSUPPORTED_RUNTIME_WRITE_REQUIRED", "private writable eval runtime-home is not bound")
    if argv[:1] == ["sitina"]:
        return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "only the reviewed sitina commands are recognized")
    if len(argv) < 3 or tuple(argv[:3]) != ("python", "-m", "unittest"):
        return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "prefix must be exactly python -m unittest")

    tokens = list(argv[3:])
    seen_flags: set[str] = set()
    normalized_flags: list[str] = []
    discover = False
    targets: list[str] = []
    discover_values: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "discover":
            if discover:
                return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "duplicate discover")
            discover = True
            index += 1
            continue
        if token in _SHORT_FLAGS:
            if token in seen_flags:
                return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "duplicate unittest flag")
            seen_flags.add(token)
            normalized_flags.append(token)
            index += 1
            continue
        if token.startswith("-"):
            if discover and token in {"-s", "-p", "-t"}:
                if token in discover_values or index + 1 >= len(tokens):
                    return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "duplicate or missing discover value")
                value = tokens[index + 1]
                if token == "-p":
                    valid = _pattern(value)
                else:
                    valid = _relative_path(value)
                if not valid:
                    return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "discover value escapes input")
                discover_values[token] = value
                index += 2
                continue
            return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", f"unsupported unittest flag: {token}")
        if discover:
            return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "discover accepts only -s/-p/-t and flags")
        if not _test_target(token):
            return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "test target is not a relative .py path or dotted name")
        targets.append(token)
        index += 1

    if "-v" in seen_flags and "-q" in seen_flags:
        return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "verbose and quiet conflict")
    if discover and targets:
        return _unsupported(argv, "UNSUPPORTED_ALLOWLIST_ARGUMENTS", "discover cannot include positional targets")
    return ShellCommandSpec(
        "unittest",
        tuple(argv),
        detail=("discover" if discover else "targets"),
    )


def validate_timeout(value: Any) -> tuple[float | None, str | None]:
    if value is None:
        return DEFAULT_SHELL_TIMEOUT_SECONDS, None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, "timeout must be a finite positive number"
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0 or numeric > MAX_SHELL_TIMEOUT_SECONDS:
        return None, "timeout must be greater than zero and at most 300 seconds"
    return numeric, None
