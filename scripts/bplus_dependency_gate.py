#!/usr/bin/env python3
"""Fail-closed dependency-lock audit for the dedicated Sitina test runtime."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Mapping, Sequence


SUMMARY_MARKER = "SITINA_DEPENDENCY_GATE_JSON:"
SCHEMA = "SITINA_BPLUS_DEPENDENCY_GATE_V1"
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\\\s]+)(?:\s*\\)?$")


class DependencyLockError(ValueError):
    """The dependency lock is empty, malformed, or ambiguous."""


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def parse_locked_requirements(lock_path: Path) -> dict[str, str]:
    """Return canonical distribution names and exact versions from a hash lock."""

    requirements: dict[str, str] = {}
    for line_number, raw_line in enumerate(lock_path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("--hash="):
            continue
        match = _PIN.fullmatch(stripped)
        if match is None:
            raise DependencyLockError(
                f"unsupported requirement at {lock_path}:{line_number}: {stripped!r}"
            )
        name = _canonical_name(match.group(1))
        version = match.group(2)
        if name in requirements:
            raise DependencyLockError(f"duplicate locked distribution: {name}")
        requirements[name] = version
    if not requirements:
        raise DependencyLockError(f"dependency lock has no exact pins: {lock_path}")
    return requirements


def _current_installed_versions(names: Sequence[str]) -> dict[str, str]:
    installed: dict[str, str] = {}
    for name in names:
        try:
            installed[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return installed


def audit_dependency_lock(
    lock_path: Path,
    *,
    expected_python: tuple[int, int, int] = (3, 12, 13),
    expected_lock_sha256: str | None = None,
    installed_versions: Mapping[str, str] | None = None,
    actual_python: tuple[int, int, int] | None = None,
    python_executable: str | None = None,
) -> dict[str, object]:
    """Compare the active interpreter and installed distributions to the lock."""

    resolved_lock = lock_path.resolve(strict=True)
    lock_sha256 = hashlib.sha256(resolved_lock.read_bytes()).hexdigest()
    locked = parse_locked_requirements(resolved_lock)
    installed = (
        {_canonical_name(name): version for name, version in installed_versions.items()}
        if installed_versions is not None
        else _current_installed_versions(tuple(locked))
    )
    missing = sorted(name for name in locked if name not in installed)
    version_mismatches = [
        {
            "name": name,
            "locked_version": locked[name],
            "installed_version": installed[name],
        }
        for name in sorted(locked)
        if name in installed and installed[name] != locked[name]
    ]
    running_python = actual_python or tuple(sys.version_info[:3])
    python_match = running_python == expected_python
    normalized_expected_hash = (
        expected_lock_sha256.removeprefix("sha256:") if expected_lock_sha256 is not None else None
    )
    manifest_binding_match = (
        normalized_expected_hash is None or normalized_expected_hash == lock_sha256
    )
    dependencies_match = not missing and not version_mismatches
    accepted = dependencies_match and python_match and manifest_binding_match
    return {
        "schema": SCHEMA,
        "accepted": accepted,
        "lock_path": str(resolved_lock),
        "lock_sha256": lock_sha256,
        "expected_lock_sha256": normalized_expected_hash,
        "manifest_binding_match": manifest_binding_match,
        "python_executable": python_executable or sys.executable,
        "python_version": ".".join(str(item) for item in running_python),
        "expected_python_version": ".".join(str(item) for item in expected_python),
        "python_match": python_match,
        "locked_distribution_count": len(locked),
        "dependencies_match": dependencies_match,
        "missing": missing,
        "version_mismatches": version_mismatches,
        "locked_versions": dict(sorted(locked.items())),
        "installed_locked_versions": {
            name: installed[name] for name in sorted(locked) if name in installed
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--expected-lock-sha256")
    parser.add_argument("--expected-python", default="3.12.13")
    arguments = parser.parse_args(argv)
    try:
        expected_python = tuple(int(item) for item in arguments.expected_python.split("."))
    except ValueError:
        parser.error("--expected-python must contain numeric dot-separated components")
    if len(expected_python) != 3:
        parser.error("--expected-python must contain exactly three components")
    try:
        report = audit_dependency_lock(
            arguments.lock,
            expected_python=expected_python,
            expected_lock_sha256=arguments.expected_lock_sha256,
        )
    except (DependencyLockError, OSError) as exc:
        report = {
            "schema": SCHEMA,
            "accepted": False,
            "lock_path": str(arguments.lock),
            "errors": [str(exc)],
        }
    print(SUMMARY_MARKER + json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
