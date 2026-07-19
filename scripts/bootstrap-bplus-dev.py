#!/usr/bin/env python3
"""Create or verify the pinned Sitina B+ Python profile."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import venv
from pathlib import Path


EXPECTED_PYTHON = (3, 12, 13)
PROFILE_ID = "CPYTHON_3_12_13_MACOS_ARM64_V1"
REQUIRED = {
    "annotated-types": "0.7.0",
    "cffi": "2.0.0",
    "cryptography": "49.0.0",
    "pycparser": "3.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.2",
}


class ProfileError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_interpreter() -> None:
    actual = sys.version_info[:3]
    if actual != EXPECTED_PYTHON:
        raise ProfileError(f"expected CPython {EXPECTED_PYTHON}, got {actual}")
    if platform.python_implementation() != "CPython":
        raise ProfileError("only CPython is approved")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ProfileError("this lock is approved only for macOS arm64")


def assert_target_isolated(target: Path, production_home: Path) -> Path:
    candidate = target.expanduser().resolve(strict=False)
    production = production_home.expanduser().resolve(strict=False)
    try:
        candidate.relative_to(production)
        unsafe = True
    except ValueError:
        unsafe = False
    try:
        production.relative_to(candidate)
        unsafe = True
    except ValueError:
        pass
    if unsafe:
        raise ProfileError(f"profile target overlaps production: {candidate}")
    return candidate


def installed_versions() -> dict[str, str]:
    return {name: importlib.metadata.version(name) for name in REQUIRED}


def verify_installed() -> dict[str, str]:
    actual = installed_versions()
    mismatches = {
        name: {"expected": expected, "actual": actual.get(name)}
        for name, expected in REQUIRED.items()
        if actual.get(name) != expected
    }
    if mismatches:
        raise ProfileError(f"dependency mismatch: {json.dumps(mismatches, sort_keys=True)}")
    return actual


def create_profile(target: Path, lock: Path) -> Path:
    if target.exists():
        raise ProfileError(f"profile target already exists: {target}")
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=True).create(target)
    python = target / "bin/python3"
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "-r",
            str(lock),
        ],
        check=True,
    )
    return python


def profile_report(python: Path, lock: Path, dependencies: dict[str, str]) -> dict:
    core = {
        "schema": "BPLUS_PYTHON_PROFILE_V1",
        "profile_id": PROFILE_ID,
        "python": str(python.resolve()),
        "python_sha256": sha256_file(python.resolve()),
        "python_version": ".".join(str(part) for part in EXPECTED_PYTHON),
        "platform": f"macOS-{platform.mac_ver()[0]}-{platform.machine()}",
        "dependency_lock": str(lock.resolve()),
        "dependency_lock_sha256": sha256_file(lock),
        "dependencies": dependencies,
    }
    encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return {**core, "python_profile_sha256": hashlib.sha256(encoded).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-home", type=Path, default=Path("/Users/moss/SitinaHub"))
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "requirements-bplus.lock")
    parser.add_argument("--create", type=Path)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args(argv)
    assert_interpreter()
    python = Path(sys.executable)
    if arguments.create:
        target = assert_target_isolated(arguments.create, arguments.production_home)
        python = create_profile(target, arguments.lock)
        command = [str(python), str(Path(__file__).resolve()), "--lock", str(arguments.lock)]
        if arguments.report:
            command.extend(["--report", str(arguments.report)])
        return subprocess.run(command, check=False).returncode
    dependencies = verify_installed()
    report = profile_report(python, arguments.lock, dependencies)
    if arguments.report:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(arguments.report, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    else:
        print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProfileError as error:
        print(f"profile error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
