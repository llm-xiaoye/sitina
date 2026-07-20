#!/usr/bin/env python3
"""Run the complete Sitina test suite in a guarded disposable home."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
DEFAULT_TEST_ROOT = Path("/Users/moss/Desktop/sitina/bplus-test-homes")
DEFAULT_OUTPUT = Path(
    "/Users/moss/Desktop/sitina/output/storage-production-closure/"
    "storage-production-full-suite.json"
)
PRODUCTION_STORAGE_ROOTS = (
    "journal",
    "cas",
    "projections",
    "data",
    "logs",
    "state",
    "runtime",
    "memory",
    "backups",
    "artifacts",
    "output",
    "outputs",
    "temp",
    "cold-archives",
    "trash",
    "legacy-retired",
    "acceptance",
    "Downloads",
    "profiles",
)


GUARD = r'''
import ipaddress
import json
import os
import socket
import sys

_external_log = os.environ["SITINA_EXTERNAL_ATTEMPT_LOG"]
_production_log = os.environ["SITINA_PRODUCTION_ATTEMPT_LOG"]
_production_home = os.path.realpath(os.environ["SITINA_PRODUCTION_HOME"])
_protected = tuple(
    os.path.join(_production_home, item)
    for item in json.loads(os.environ["SITINA_PRODUCTION_PROTECTED_ROOTS"])
)
_original_connect = socket.socket.connect
_original_create_connection = socket.create_connection

def _resolved(value):
    if isinstance(value, int) or value is None:
        return None
    try:
        raw = os.fsdecode(value)
    except (TypeError, ValueError):
        return None
    if not os.path.isabs(raw):
        raw = os.path.join(os.getcwd(), raw)
    return os.path.realpath(raw)

def _inside_protected(value):
    candidate = _resolved(value)
    return candidate is not None and any(
        candidate == root or candidate.startswith(root + os.sep) for root in _protected
    )

def _record(path, value):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")

def _audit(event, arguments):
    indexes = {
        "open": (0,),
        "os.listdir": (0,),
        "os.scandir": (0,),
        "os.remove": (0,),
        "os.rmdir": (0,),
        "os.mkdir": (0,),
        "os.chmod": (0,),
        "os.chown": (0,),
        "os.truncate": (0,),
        "os.utime": (0,),
        "os.symlink": (0, 1),
        "os.link": (0, 1),
        "os.rename": (0, 1),
        "sqlite3.connect": (0,),
    }.get(event, ())
    selected = tuple(arguments[index] for index in indexes if index < len(arguments))
    if any(_inside_protected(value) for value in selected):
        _record(_production_log, {"event": event, "denied": True})
        raise PermissionError("isolated full-suite guard denied Production storage access")

sys.addaudithook(_audit)

def _loopback(host):
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

def _deny(address):
    _record(_external_log, {"denied": True})
    raise RuntimeError("isolated full-suite guard denied external network")

def _connect(self, address):
    host = address[0] if isinstance(address, tuple) and address else str(address)
    if not _loopback(host):
        return _deny(address)
    return _original_connect(self, address)

def _create_connection(address, *args, **kwargs):
    host = address[0] if isinstance(address, tuple) and address else str(address)
    if not _loopback(host):
        return _deny(address)
    return _original_create_connection(address, *args, **kwargs)

socket.socket.connect = _connect
socket.create_connection = _create_connection
'''


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _provider_literals(home: Path) -> tuple[str, ...]:
    values: set[str] = set()
    for path in (home / "profiles").glob("*.env"):
        if path.name.endswith(".template"):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            if key.removeprefix("export ").strip() == "ANTHROPIC_AUTH_TOKEN":
                literal = value.strip().strip("'\"")
                if literal:
                    values.add(literal)
    return tuple(values)


def _redact(value: str, literals: tuple[str, ...]) -> str:
    result = value
    for literal in literals:
        result = result.replace(literal, "<redacted-provider-secret>")
    rules = (
        (r"(?i)(api[_-]?key|auth[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+", r"\1=<redacted>"),
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1<redacted>"),
        (r"\bsk-[A-Za-z0-9_-]{8,}\b", "<redacted-key>"),
    )
    for pattern, replacement in rules:
        result = re.sub(pattern, replacement, result)
    return result


def _inventory(root: Path, *, hash_contents: bool) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    if not root.exists():
        return {"entry_count": 0, "total_bytes": 0, "sha256": digest.hexdigest()}
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
        metadata = path.stat()
        digest.update(
            (
                f"{path.relative_to(root).as_posix()}\0{metadata.st_mode & 0o7777}\0"
                f"{metadata.st_size}\0{metadata.st_mtime_ns}\0{metadata.st_ino}\0"
            ).encode("utf-8")
        )
        if hash_contents:
            digest.update(_sha256(path).encode("ascii"))
        digest.update(b"\n")
        count += 1
        total_bytes += metadata.st_size
    return {"entry_count": count, "total_bytes": total_bytes, "sha256": digest.hexdigest()}


def _storage_snapshot(home: Path) -> dict[str, Any]:
    cas_digest = hashlib.sha256()
    cas_count = 0
    cas_bytes = 0
    for path in sorted((home / "cas/objects").glob("*/*.obj"), key=lambda item: item.as_posix()):
        metadata = path.stat()
        record = (
            f"{path.relative_to(home).as_posix()}\0{metadata.st_size}\0"
            f"{metadata.st_mtime_ns}\0{metadata.st_ino}\n"
        ).encode("utf-8")
        cas_digest.update(record)
        cas_count += 1
        cas_bytes += metadata.st_size
    pointer = home / "projections/current-generation.json"
    pointer_value = json.loads(pointer.read_text(encoding="utf-8"))
    current_database = (home / "projections" / str(pointer_value["database_path"])).resolve(strict=True)
    if home not in current_database.parents:
        raise RuntimeError("active Projection database escaped Production")
    checkpoints = sorted((home / "journal/checkpoints").glob("checkpoint-*.json"))
    if not checkpoints:
        raise RuntimeError("Production Authority Checkpoint is unavailable")
    checkpoint = json.loads(checkpoints[-1].read_text(encoding="utf-8"))
    return {
        "journal_id": checkpoint["journal_id"],
        "epoch": checkpoint["epoch"],
        "checkpoint_sequence": checkpoint["checkpoint_sequence"],
        "checkpoint_verified_through_position": checkpoint["verified_through_position"],
        "checkpoint_last_transaction_hash": checkpoint["last_transaction_hash"],
        "journal_raw_fingerprint": _inventory(home / "journal", hash_contents=True),
        "cas_object_count": cas_count,
        "cas_total_stored_bytes": cas_bytes,
        "cas_inventory_sha256": cas_digest.hexdigest(),
        "projection_pointer_sha256": _sha256(pointer),
        "projection_database_sha256": _sha256(current_database),
        "checkpoint_count": len(checkpoints),
        "latest_checkpoint_sha256": _sha256(checkpoints[-1]),
        "primary_mutable_inventory": {
            name: _inventory(home / name, hash_contents=False)
            for name in (
                "projections",
                "data",
                "logs",
                "state",
                "runtime",
                "memory",
                "artifacts",
                "output",
                "outputs",
                "temp",
            )
        },
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--test-root", type=Path, default=DEFAULT_TEST_ROOT)
    parser.add_argument("--evidence-output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    return parser.parse_args()


def _run_isolated(
    *,
    home: Path,
    repository: Path,
    output: Path,
    timeout_seconds: int,
    literals: tuple[str, ...],
) -> tuple[str, Path, list[str], list[str], int, bool, float]:
    guard_root = home / ".guard"
    guard_root.mkdir(mode=0o700)
    os.chmod(guard_root, 0o700)
    _write(guard_root / "sitecustomize.py", GUARD.encode("utf-8"))
    external_log = guard_root / "external-attempts.jsonl"
    production_log = guard_root / "production-attempts.jsonl"
    log_path = output.parent / "full-suite-logs" / "complete-unittest-discovery.log"
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                (
                    str(guard_root),
                    str(repository),
                    str(repository / "core"),
                    str(repository / "tests/foundation"),
                )
            ),
            "SITINA_HOME": str(home),
            "SITINA_LIVE_TEST": "0",
            "SITINA_PYTHON": sys.executable,
            "SITINA_PRODUCTION_HOME": str(repository),
            "SITINA_PRODUCTION_PROTECTED_ROOTS": json.dumps(PRODUCTION_STORAGE_ROOTS),
            "SITINA_EXTERNAL_ATTEMPT_LOG": str(external_log),
            "SITINA_PRODUCTION_ATTEMPT_LOG": str(production_log),
            "HOME": str(home),
            "PATH": os.pathsep.join((str(Path(sys.executable).parent), environment.get("PATH", ""))),
        }
    )
    for key in tuple(environment):
        if any(fragment in key.upper() for fragment in ("API_KEY", "AUTH_TOKEN", "PASSWORD", "PRIVATE_KEY")):
            environment.pop(key, None)
    command = (
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        str(repository / "tests"),
        "-p",
        "test_*.py",
    )
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=home,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        raw_output, _ = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            raw_output, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            raw_output, _ = process.communicate()
    duration = time.monotonic() - started
    redacted = _redact(raw_output, literals)
    _write(log_path, redacted.encode("utf-8"))
    external_attempts = external_log.read_text(encoding="utf-8").splitlines() if external_log.exists() else []
    production_attempts = production_log.read_text(encoding="utf-8").splitlines() if production_log.exists() else []
    return (
        redacted,
        log_path,
        external_attempts,
        production_attempts,
        int(process.returncode),
        timed_out,
        duration,
    )


def main() -> int:
    args = _arguments()
    repository = args.repository.expanduser().resolve(strict=True)
    test_root = args.test_root.expanduser().resolve(strict=False)
    if test_root == PRODUCTION_HOME or PRODUCTION_HOME in test_root.parents:
        raise RuntimeError("full-suite test root must remain outside Production")
    test_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    test_root = test_root.resolve(strict=True)
    output = args.evidence_output.expanduser().resolve(strict=False)
    if repository != PRODUCTION_HOME:
        raise RuntimeError("full-suite runner is bound to the installed source")
    if output == repository or repository in output.parents:
        raise RuntimeError("full-suite evidence must remain outside Production")
    if args.timeout_seconds < 1:
        raise RuntimeError("full-suite timeout must be positive")

    literals = _provider_literals(repository)
    started_at = _utc_now()
    before = _storage_snapshot(repository)
    previous_control = os.environ.get("SITINA_CONTROL_PLANE_READONLY")
    os.environ["SITINA_CONTROL_PLANE_READONLY"] = "1"
    sys.path.insert(0, str(repository / "core"))
    sys.path.insert(0, str(repository / "tests/foundation"))
    try:
        from home_factory import DisposableHomeFactory
    finally:
        if previous_control is None:
            os.environ.pop("SITINA_CONTROL_PLANE_READONLY", None)
        else:
            os.environ["SITINA_CONTROL_PLANE_READONLY"] = previous_control

    disposable = DisposableHomeFactory(repository, PRODUCTION_HOME, test_root).create(
        prefix="storage-full-suite-"
    )
    try:
        (
            redacted,
            log_path,
            external_attempts,
            production_attempts,
            process_return_code,
            timed_out,
            duration,
        ) = _run_isolated(
            home=disposable.path,
            repository=repository,
            output=output,
            timeout_seconds=args.timeout_seconds,
            literals=literals,
        )
    finally:
        disposable.cleanup()
    after = _storage_snapshot(repository)

    matches = re.findall(r"Ran\s+(\d+)\s+tests?\s+in", redacted)
    skipped_matches = re.findall(r"skipped=(\d+)", redacted)
    test_count = int(matches[-1]) if matches else 0
    skipped_count = int(skipped_matches[-1]) if skipped_matches else 0
    return_code = 124 if timed_out else process_return_code
    source_test_file_count = sum(1 for _ in (repository / "tests").rglob("test_*.py"))
    secret_absent = all(literal not in redacted for literal in literals)
    storage_unchanged = before == after
    status = (
        "passed"
        if return_code == 0
        and test_count > 0
        and not external_attempts
        and not production_attempts
        and secret_absent
        and storage_unchanged
        else "failed"
    )
    evidence: dict[str, Any] = {
        "schema": "SITINA_STORAGE_PRODUCTION_FULL_SUITE_V1",
        "status": status,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "duration_seconds": round(duration, 6),
        "repository": str(repository),
        "test_root": str(test_root),
        "source_test_file_count": source_test_file_count,
        "test_count": test_count,
        "skipped_count": skipped_count,
        "exit_code": return_code,
        "timed_out": timed_out,
        "external_attempt_count": len(external_attempts),
        "production_storage_attempt_count": len(production_attempts),
        "provider_send_count": 0,
        "live_provider_enabled": False,
        "production_storage_before": before,
        "production_storage_after": after,
        "production_storage_unchanged": storage_unchanged,
        "log_path": str(log_path),
        "log_sha256": _sha256(log_path),
        "log_bytes": log_path.stat().st_size,
        "provider_secret_absent_from_log": secret_absent,
        "secret_values_included": False,
    }
    _write(output, json.dumps(evidence, sort_keys=True, indent=2).encode("utf-8") + b"\n")
    print(
        json.dumps(
            {
                "status": status,
                "test_count": test_count,
                "skipped_count": skipped_count,
                "duration_seconds": round(duration, 6),
                "external_attempt_count": len(external_attempts),
                "production_storage_attempt_count": len(production_attempts),
                "production_storage_unchanged": storage_unchanged,
                "evidence_output": str(output),
                "evidence_sha256": _sha256(output),
                "secret_values_included": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0 if status == "passed" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed_closed",
                    "error_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
                    "secret_values_included": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise
