#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
DEFAULT_OUTPUT = Path("/Users/moss/Desktop/sitina/output/storage-production-closure")
GROUPS = {
    "journal_crash_and_concurrency": (
        "tests.test_journal_model",
        "tests.test_journal_codec",
        "tests.test_local_journal",
        "tests.test_journal_crash_matrix",
        "tests.test_journal_lock",
        "tests.test_journal_fast_start_integration",
        "tests.test_journal_fast_start_v2",
    ),
    "cas_atomicity_and_reconciliation": (
        "tests.test_cas_crypto",
        "tests.test_local_cas",
        "tests.test_cas_compression_dedup",
        "tests.test_cas_lifecycle_semantic_gc",
        "tests.test_cas_metadata_packs",
        "tests.test_cas_gc_fence",
        "tests.test_atomic_storage_protocols",
    ),
    "projection_checkpoint_and_compatibility": (
        "tests.test_projection_kernel",
        "tests.test_projection_consistency",
        "tests.test_projection_stable_v2",
        "tests.test_checkpoint_resume_v1",
        "tests.test_run_checkpoint_evidence_v2",
        "tests.test_storage_compatibility",
        "tests.test_journal_fast_start_integration",
    ),
    "session_memory_replay_and_recovery": (
        "tests.test_conversation_storage_integration",
        "tests.test_fast_conversation_runtime",
        "tests.test_memory_native_v1",
        "tests.test_offline_replay",
        "tests.test_provider_recovery_projection",
        "tests.test_runtime_reliability",
    ),
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    text = value
    for literal in literals:
        text = text.replace(literal, "<redacted-provider-secret>")
    patterns = (
        (r"(?i)(api[_-]?key|auth[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+", r"\1=<redacted>"),
        (r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1<redacted>"),
        (r"\bsk-[A-Za-z0-9_-]{8,}\b", "<redacted-key>"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _run_group(
    name: str,
    modules: tuple[str, ...],
    *,
    repository: Path,
    test_home: Path,
    log_root: Path,
    literals: tuple[str, ...],
) -> dict[str, Any]:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join((str(repository), str(repository / "core"))),
            "SITINA_HOME": str(test_home),
            "SITINA_LIVE_TEST": "0",
            "HOME": str(test_home),
        }
    )
    for key in tuple(environment):
        if any(fragment in key.upper() for fragment in ("API_KEY", "AUTH_TOKEN", "PASSWORD", "PRIVATE_KEY")):
            environment.pop(key, None)
    command = (sys.executable, "-m", "unittest", "-v", *modules)
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=test_home,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=900,
        check=False,
    )
    duration = time.perf_counter() - started
    redacted = _redact(result.stdout, literals)
    log_path = log_root / f"{name}.log"
    _write(log_path, redacted.encode("utf-8"))
    matches = re.findall(r"Ran (\d+) tests? in", redacted)
    test_count = int(matches[-1]) if matches else 0
    return {
        "group": name,
        "status": "passed" if result.returncode == 0 and test_count > 0 else "failed",
        "module_count": len(modules),
        "modules": list(modules),
        "test_count": test_count,
        "exit_code": result.returncode,
        "duration_seconds": round(duration, 6),
        "log_path": str(log_path),
        "log_sha256": _sha256(log_path),
        "log_bytes": log_path.stat().st_size,
        "provider_secret_redacted": all(literal not in redacted for literal in literals),
        "secret_values_included": False,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run isolated crash, recovery, and concurrency acceptance groups.")
    parser.add_argument("--repository", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--test-home", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, default=DEFAULT_OUTPUT / "storage-production-fault-concurrency-acceptance.json")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    repository = args.repository.expanduser().resolve(strict=True)
    test_root = args.test_home.expanduser().resolve(strict=True)
    output = args.evidence_output.expanduser().resolve(strict=False)
    if repository != PRODUCTION_HOME or test_root == repository or not test_root.is_dir():
        raise RuntimeError("fault/concurrency acceptance requires the installed source and an isolated test root")
    log_root = output.parent / "fault-concurrency-logs"
    log_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(log_root, 0o700)
    literals = _provider_literals(repository)
    started_at = _utc_now()
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
    factory = DisposableHomeFactory(repository, PRODUCTION_HOME, test_root)
    disposables = {name: factory.create(prefix=f"storage-fault-{name}-") for name in GROUPS}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(GROUPS)) as executor:
            futures = {
                name: executor.submit(
                    _run_group,
                    name,
                    modules,
                    repository=repository,
                    test_home=disposables[name].path,
                    log_root=log_root,
                    literals=literals,
                )
                for name, modules in GROUPS.items()
            }
            results = [futures[name].result() for name in sorted(futures)]
    finally:
        for disposable in disposables.values():
            disposable.cleanup()
    total_tests = sum(int(item["test_count"]) for item in results)
    status = "passed" if results and all(item["status"] == "passed" for item in results) else "failed"
    evidence: dict[str, object] = {
        "schema": "SITINA_STORAGE_PRODUCTION_FAULT_CONCURRENCY_ACCEPTANCE_V1",
        "status": status,
        "started_at": started_at,
        "completed_at": _utc_now(),
        "repository": str(repository),
        "test_root": str(test_root),
        "disposable_home_count": len(disposables),
        "production_home_passed_to_workers": False,
        "group_count": len(results),
        "test_count": total_tests,
        "groups": results,
        "acceptance_scope": {
            "journal": ["atomic framing", "crash recovery", "corruption", "rollover", "concurrent writers", "stale locks"],
            "cas": ["atomic publish", "duplicate writers", "corruption", "orphan detection", "quarantine", "reconciliation"],
            "projection": ["build", "validate", "publish", "switch", "rollback", "corruption", "stale/schema mismatch"],
            "lifecycle": ["session", "context", "memory acceptance", "restart", "replay", "provider committed-call recovery"],
        },
        "provider_send_count": 0,
        "production_mutation_count": 0,
        "secret_values_included": False,
    }
    _write(output, json.dumps(evidence, sort_keys=True, indent=2).encode("utf-8") + b"\n")
    print(
        json.dumps(
            {
                "status": status,
                "group_count": len(results),
                "test_count": total_tests,
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
