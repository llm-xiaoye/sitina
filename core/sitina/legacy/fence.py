"""Kernel-coordinated Legacy writer fence with fail-closed sink instrumentation."""

from __future__ import annotations

import contextlib
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


class LegacyFenceError(RuntimeError):
    pass


class LegacyFenceBusy(LegacyFenceError):
    pass


class LegacyWriteDenied(LegacyFenceError):
    pass


_SNAPSHOT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$")
_guard_installed = False
_guard_home: Path | None = None
_writer_fds: dict[Path, int] = {}
_network_egress_nonces: set[str] = set()
_sandbox_execution_nonces: set[str] = set()
_local = threading.local()
_state_lock = threading.RLock()

_BPLUS_MUTATION_ROOTS = (
    "journal",
    "cas",
    "projections",
    "acceptance",
    "state/bplus-production-genesis",
)

_PRODUCTION_PERMISSION_HARDENING_ROOTS = frozenset(
    {
        "journal",
        "cas",
        "projections",
        "state",
        "data",
        "backups",
        "profiles",
        "artifacts",
        "output",
        "outputs",
        "logs",
        "memory",
    }
)


AUTHORITY_GUARDED_WRITER_ENTRYPOINTS = {
    "orchestrator.engine.start": "LEGACY_GATE_OR_JOURNAL_FIRST_ROUTER",
    "orchestrator.engine.resume": "LEGACY_GATE_OR_JOURNAL_FIRST_ROUTER",
    "orchestrator.engine.cancel": "LEGACY_GATE_OR_JOURNAL_FIRST_ROUTER",
    "orchestrator.engine.restore": "LEGACY_GATE_OR_JOURNAL_FIRST_ROUTER",
    "storage.store.sqlite_connect": "AUTHORITY_RESOLUTION_REQUIRED",
    "storage.store.json_write": "AUTHORITY_RESOLUTION_REQUIRED",
    "cli.business_dispatch": "AUTHORITY_RESOLUTION_REQUIRED",
    "orchestrator.bplus_adapter.dispatch": "AUTHORITY_RESOLUTION_REQUIRED",
    "checkpoint.writer": "PACKAGE_AUDIT_HOOK_PLUS_KERNEL_WRITER_LEASE",
    "manifest.writer": "PACKAGE_AUDIT_HOOK_PLUS_KERNEL_WRITER_LEASE",
    "replay_snapshot.writer": "PACKAGE_AUDIT_HOOK_PLUS_KERNEL_WRITER_LEASE",
    "evidence_compatibility_export.writer": "PACKAGE_AUDIT_HOOK_PLUS_KERNEL_WRITER_LEASE",
}


@dataclass(frozen=True)
class FrozenNetworkEgressCapability:
    """Narrow non-mutating network permission while Legacy remains frozen.

    The capability does not bypass filesystem, SQLite, subprocess, or any
    other Legacy fence check.  It can be issued only from a fresh unique
    Journal authority resolution and is limited to exact hosts, operation,
    activation manifest, and expiry.
    """

    capability_id: str
    manifest_hash: str
    operation: str
    allowed_hosts: tuple[str, ...]
    expires_at: int
    _nonce: str


@dataclass(frozen=True)
class FrozenSandboxExecutionCapability:
    """One-use authority for one exact OS-sandbox runner invocation.

    This does not authorize a shell or a generic subprocess.  It binds the
    frozen-home escape hatch to immutable code/policy/input identities and the
    exact argv/cwd/read/write/resource scope used by the sandbox launcher.
    """

    capability_id: str
    authority_resolution_id: str
    authority_input_frontier_hash: str
    run_id: str
    diff_hash: str
    test_plan_hash: str
    runner_executable: str
    runner_executable_hash: str
    python_executable_hash: str
    worker_path: str
    worker_hash: str
    argv: tuple[str, ...]
    argv_hash: str
    cwd: str
    read_roots: tuple[str, ...]
    write_roots: tuple[str, ...]
    sandbox_policy_hash: str
    resource_limits: tuple[tuple[str, int], ...]
    expires_at: int
    _nonce: str


def _sha256_regular_file(path: Path) -> str:
    candidate = Path(path).expanduser().resolve(strict=True)
    if candidate.is_symlink() or not candidate.is_file():
        raise LegacyWriteDenied(f"sandbox executable/input is not a regular file: {candidate}")
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frozen_sandbox_profile(
    python_executable: Path,
    worker_path: Path,
    read_roots: tuple[Path, ...],
    write_roots: tuple[Path, ...],
) -> str:
    """Build the only Seatbelt policy eligible for frozen execution."""

    python = Path(python_executable).expanduser().resolve(strict=True)
    worker = Path(worker_path).expanduser().resolve(strict=True)
    reads = tuple(sorted((Path(path).expanduser().resolve(strict=True) for path in read_roots), key=str))
    writes = tuple(sorted((Path(path).expanduser().resolve(strict=True) for path in write_roots), key=str))
    read_rules = (python.parents[1], worker, *reads, *writes)

    def sbpl(path: Path) -> str:
        rendered = str(path)
        if "\n" in rendered or "\r" in rendered or "\x00" in rendered:
            raise LegacyWriteDenied("sandbox path contains forbidden characters")
        return json.dumps(rendered)

    lines = [
        "(version 1)",
        "(deny default)",
        "(import \"system.sb\")",
        "(deny network*)",
        "(deny process-fork)",
        "(deny process-exec)",
        f"(allow process-exec (literal {sbpl(python)}))",
        "(allow file-read* file-test-existence",
        *(f"  (subpath {sbpl(path)})" for path in read_rules),
        ")",
        "(allow file-write*",
        *(f"  (subpath {sbpl(path)})" for path in writes),
        ")",
    ]
    return "\n".join(lines) + "\n"


def issue_frozen_sandbox_execution_capability(
    authority_resolution: object | None,
    *,
    home: Path,
    run_id: str,
    diff_hash: str,
    test_plan_hash: str,
    runner_executable: Path,
    python_executable: Path,
    worker_path: Path,
    argv: tuple[str, ...],
    cwd: Path,
    read_roots: tuple[Path, ...],
    write_roots: tuple[Path, ...],
    sandbox_policy_hash: str,
    resource_limits: tuple[tuple[str, int], ...],
    expires_at: int,
    now: int | None = None,
    fixture_authorization: bool = False,
) -> FrozenSandboxExecutionCapability:
    """Issue a one-use capability for an exact Seatbelt runner command."""

    moment = int(time.time()) if now is None else int(now)
    canonical_home = Path(home).expanduser().resolve(strict=True)
    if LegacyWriteGate(canonical_home).status().state != "FROZEN_NO_WRITER":
        raise LegacyWriteDenied("sandbox execution capability requires a verified frozen home")
    if fixture_authorization:
        if canonical_home == Path("/Users/moss/SitinaHub") or not (
            canonical_home / ".sitina-bplus-disposable-v1"
        ).is_file():
            raise LegacyWriteDenied("sandbox fixture authorization requires a disposable non-Production home")
        authority_resolution_id = "fixture-authority"
        authority_frontier_hash = "fixture-frontier"
    else:
        from sitina.authority.model import AuthorityResolution

        if type(authority_resolution) is not AuthorityResolution:
            raise LegacyWriteDenied("sandbox execution requires an authentic AuthorityResolution")
        try:
            authority_resolution.assert_fresh(now=moment)  # type: ignore[union-attr]
            journal_authorized = bool(authority_resolution.authorizes_journal)  # type: ignore[union-attr]
            writer_count = int(authority_resolution.writer_count)  # type: ignore[union-attr]
        except Exception as error:
            raise LegacyWriteDenied("sandbox execution requires a fresh authority resolution") from error
        if not journal_authorized or writer_count != 1:
            raise LegacyWriteDenied("sandbox execution requires one Journal writer authority")
        authority_resolution_id = str(authority_resolution.resolution_id)
        authority_frontier_hash = str(authority_resolution.input_frontier_hash)
        if not re.fullmatch(r"[0-9a-f]{64}", authority_resolution_id) or not re.fullmatch(
            r"[0-9a-f]{64}", authority_frontier_hash
        ):
            raise LegacyWriteDenied("sandbox execution authority identity is invalid")

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,255}", str(run_id)):
        raise LegacyWriteDenied("sandbox execution run_id is invalid")
    for label, value in (
        ("diff", diff_hash),
        ("test plan", test_plan_hash),
        ("policy", sandbox_policy_hash),
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value)):
            raise LegacyWriteDenied(f"sandbox execution {label} hash is invalid")
    if expires_at <= moment or expires_at - moment > 300:
        raise LegacyWriteDenied("sandbox execution expiry is invalid")

    runner = Path(runner_executable).expanduser().resolve(strict=True)
    python = Path(python_executable).expanduser().resolve(strict=True)
    worker = Path(worker_path).expanduser().resolve(strict=True)
    working_directory = Path(cwd).expanduser().resolve(strict=True)
    reads = tuple(sorted(str(Path(path).expanduser().resolve(strict=True)) for path in read_roots))
    writes = tuple(sorted(str(Path(path).expanduser().resolve(strict=True)) for path in write_roots))
    if not reads or not writes:
        raise LegacyWriteDenied("sandbox execution argv or filesystem scope is invalid")
    if any(not isinstance(name, str) or not name or not isinstance(value, int) or value <= 0 for name, value in resource_limits):
        raise LegacyWriteDenied("sandbox execution resource limits are invalid")

    normalized_limits = tuple(sorted((str(name), int(value)) for name, value in resource_limits))
    expected_profile = frozen_sandbox_profile(
        python,
        worker,
        tuple(Path(path) for path in reads),
        tuple(Path(path) for path in writes),
    )
    expected_prefix = (
        str(runner),
        "-p",
        expected_profile,
        str(python),
        "-I",
        "-S",
        str(worker),
        "--request",
    )
    if len(argv) != 9 or tuple(argv[:8]) != expected_prefix:
        raise LegacyWriteDenied("sandbox execution is not the exact trusted worker command")
    if hashlib.sha256(expected_profile.encode("utf-8")).hexdigest() != sandbox_policy_hash:
        raise LegacyWriteDenied("sandbox execution policy hash does not match the trusted policy")
    try:
        request = json.loads(base64.urlsafe_b64decode(argv[8].encode("ascii")))
    except Exception as error:
        raise LegacyWriteDenied("sandbox execution worker request is invalid") from error
    if (
        not isinstance(request, dict)
        or request.get("resource_limits") != dict(normalized_limits)
        or request.get("test_plan_hash") != test_plan_hash
    ):
        raise LegacyWriteDenied("sandbox execution worker request is not resource-bound")

    runner_hash = _sha256_regular_file(runner)
    python_hash = _sha256_regular_file(python)
    worker_hash = _sha256_regular_file(worker)
    argv_hash = hashlib.sha256(_canonical(list(argv))).hexdigest()
    nonce = os.urandom(32).hex()
    core = {
        "authority_resolution_id": authority_resolution_id,
        "authority_input_frontier_hash": authority_frontier_hash,
        "run_id": run_id,
        "diff_hash": diff_hash,
        "test_plan_hash": test_plan_hash,
        "runner_executable": str(runner),
        "runner_executable_hash": runner_hash,
        "python_executable_hash": python_hash,
        "worker_path": str(worker),
        "worker_hash": worker_hash,
        "argv_hash": argv_hash,
        "cwd": str(working_directory),
        "read_roots": list(reads),
        "write_roots": list(writes),
        "sandbox_policy_hash": sandbox_policy_hash,
        "resource_limits": [[name, value] for name, value in normalized_limits],
        "expires_at": expires_at,
        "nonce_hash": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
    }
    identity = hashlib.sha256(_canonical(core)).hexdigest()
    with _state_lock:
        _sandbox_execution_nonces.add(nonce)
    return FrozenSandboxExecutionCapability(
        "sandbox-execution:" + identity,
        authority_resolution_id,
        authority_frontier_hash,
        str(run_id),
        str(diff_hash),
        str(test_plan_hash),
        str(runner),
        runner_hash,
        python_hash,
        str(worker),
        worker_hash,
        tuple(argv),
        argv_hash,
        str(working_directory),
        reads,
        writes,
        str(sandbox_policy_hash),
        normalized_limits,
        int(expires_at),
        nonce,
    )


@contextlib.contextmanager
def authorized_frozen_sandbox_execution(
    capability: FrozenSandboxExecutionCapability | None,
    *,
    argv: tuple[str, ...],
    cwd: Path,
    diff_hash: str,
    test_plan_hash: str,
    now: int | None = None,
) -> Iterator[None]:
    """Consume one capability and scope it to exactly one Popen audit event."""

    if capability is None:
        yield
        return
    moment = int(time.time()) if now is None else int(now)
    resolved_cwd = str(Path(cwd).expanduser().resolve(strict=True))
    if (
        not isinstance(capability, FrozenSandboxExecutionCapability)
        or tuple(argv) != capability.argv
        or resolved_cwd != capability.cwd
        or diff_hash != capability.diff_hash
        or test_plan_hash != capability.test_plan_hash
        or moment >= capability.expires_at
        or _sha256_regular_file(Path(capability.runner_executable)) != capability.runner_executable_hash
        or len(capability.argv) < 4
        or _sha256_regular_file(Path(capability.argv[3])) != capability.python_executable_hash
        or _sha256_regular_file(Path(capability.worker_path)) != capability.worker_hash
        or hashlib.sha256(_canonical(list(capability.argv))).hexdigest() != capability.argv_hash
        or hashlib.sha256(capability.argv[2].encode("utf-8")).hexdigest() != capability.sandbox_policy_hash
    ):
        raise LegacyWriteDenied("frozen sandbox execution capability is invalid, expired, or out of scope")
    with _state_lock:
        if capability._nonce not in _sandbox_execution_nonces:
            raise LegacyWriteDenied("frozen sandbox execution capability was already consumed")
        _sandbox_execution_nonces.remove(capability._nonce)
    previous = getattr(_local, "sandbox_execution", None)
    _local.sandbox_execution = (capability, False)
    try:
        yield
    finally:
        _local.sandbox_execution = previous


def issue_frozen_network_egress_capability(
    authority_resolution: object,
    *,
    manifest_hash: str,
    operation: str,
    allowed_hosts: tuple[str, ...],
    expires_at: int,
    now: int | None = None,
) -> FrozenNetworkEgressCapability:
    """Issue an in-process capability without weakening the Legacy fence."""

    moment = int(time.time()) if now is None else int(now)
    try:
        authority_resolution.assert_fresh(now=moment)  # type: ignore[attr-defined]
        journal_authorized = bool(authority_resolution.authorizes_journal)  # type: ignore[attr-defined]
        writer_count = int(authority_resolution.writer_count)  # type: ignore[attr-defined]
    except Exception as error:
        raise LegacyWriteDenied("frozen network egress requires a fresh authority resolution") from error
    if not journal_authorized or writer_count != 1:
        raise LegacyWriteDenied("frozen network egress requires one Journal writer authority")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_hash):
        raise LegacyWriteDenied("frozen network egress requires an exact activation manifest hash")
    if operation != "model_text_generation":
        raise LegacyWriteDenied("frozen network egress operation is outside the non-mutating allowlist")
    normalized = tuple(sorted({str(host).strip().lower() for host in allowed_hosts}))
    if not normalized or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
        or ".." in host
        or host.startswith(".")
        or host.endswith(".")
        for host in normalized
    ):
        raise LegacyWriteDenied("frozen network egress hosts are invalid")
    if expires_at <= moment or expires_at - moment > 3600:
        raise LegacyWriteDenied("frozen network egress expiry is invalid")
    nonce = os.urandom(32).hex()
    identity = hashlib.sha256(
        _canonical(
            {
                "manifest_hash": manifest_hash,
                "operation": operation,
                "allowed_hosts": list(normalized),
                "expires_at": expires_at,
                "nonce_hash": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
            }
        )
    ).hexdigest()
    _network_egress_nonces.add(nonce)
    return FrozenNetworkEgressCapability(
        f"network-egress:{identity}", manifest_hash, operation, normalized, expires_at, nonce
    )


@contextlib.contextmanager
def authorized_frozen_network_egress(
    capability: FrozenNetworkEgressCapability | None,
    *,
    host: str,
    operation: str,
    now: int | None = None,
) -> Iterator[None]:
    """Scope one concrete socket connection to a validated capability."""

    moment = int(time.time()) if now is None else int(now)
    if capability is None:
        yield
        return
    normalized_host = str(host).strip().lower()
    if (
        not isinstance(capability, FrozenNetworkEgressCapability)
        or capability._nonce not in _network_egress_nonces
        or capability.operation != operation
        or normalized_host not in capability.allowed_hosts
        or moment >= capability.expires_at
    ):
        raise LegacyWriteDenied("frozen network egress capability is invalid, expired, or out of scope")
    previous = getattr(_local, "network_egress", None)
    _local.network_egress = capability
    try:
        yield
    finally:
        _local.network_egress = previous


@contextlib.contextmanager
def authorized_extension_effect(
    *,
    permission: str,
    approval_granted: bool,
    purpose: str,
) -> Iterator[None]:
    """Admit one approved Sitina extension effect through the retired Legacy fence.

    Plugins cannot enter this context themselves because Sitina never imports
    plugin code. The extension runtime enters it only after its per-call
    approval gate succeeds. The context is thread-local and ends with the one
    handler invocation.
    """

    allowed = {"write", "shell", "network", "external_service", "install_network"}
    if not approval_granted or permission not in allowed or not str(purpose).strip():
        raise LegacyWriteDenied("extension effect requires an explicit scoped approval")
    previous = getattr(_local, "extension_effect", None)
    _local.extension_effect = permission
    try:
        yield
    finally:
        _local.extension_effect = previous


@contextlib.contextmanager
def authorized_production_backup(
    frozen_prefix: object,
    *,
    destination: Path,
    goal_thread_id: str,
) -> Iterator[None]:
    """Permit publication only beneath one exact backup destination.

    The capability exists only while the canonical Journal fixed-inode lock is
    held.  It cannot authorize writes to Journal, CAS, projections, state, or
    any other Production root.
    """

    from sitina.archive.production_backup import FrozenProductionPrefix

    if not isinstance(frozen_prefix, FrozenProductionPrefix):
        raise LegacyWriteDenied("Production backup requires the canonical frozen-prefix capability")
    frozen_prefix.assert_healthy()
    home = frozen_prefix.path.parent.parent.resolve(strict=True)
    target = Path(destination).resolve(strict=False)
    backup_root = home / "backups"
    if target.parent != backup_root or not str(goal_thread_id).strip():
        raise LegacyWriteDenied("Production backup scope or Goal binding is invalid")
    fence = LegacyWriteGate(home).read_verified_record()
    if fence is None or fence.get("state") != "FROZEN_NO_WRITER":
        raise LegacyWriteDenied("Production backup requires the verified Legacy no-writer fence")
    previous = getattr(_local, "production_backup", None)
    _local.production_backup = (backup_root, target, str(goal_thread_id))
    try:
        yield
    finally:
        _local.production_backup = previous


@contextlib.contextmanager
def authorized_production_permission_hardening(
    frozen_prefix: object,
    *,
    roots: tuple[Path, ...],
    manifest_sha256: str,
    goal_thread_id: str,
) -> Iterator[None]:
    """Permit only owner-mode hardening beneath exact Production data roots.

    The capability is bound to the canonical fixed-inode Journal lock, one
    process, a content-bound change manifest, and the verified no-writer
    fence. It admits ``os.chmod`` only; it cannot authorize content writes,
    renames, deletion, subprocesses, sockets, or SQLite mutation.
    """

    from sitina.archive.production_backup import FrozenProductionPrefix

    if not isinstance(frozen_prefix, FrozenProductionPrefix):
        raise LegacyWriteDenied("Production permission hardening requires the canonical frozen-prefix capability")
    frozen_prefix.assert_healthy()
    home = frozen_prefix.path.parent.parent.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest_sha256)) or not str(goal_thread_id).strip():
        raise LegacyWriteDenied("Production permission hardening requires exact Goal and manifest bindings")
    approved: list[Path] = []
    for root in roots:
        path = Path(root).resolve(strict=True)
        try:
            relative = path.relative_to(home)
        except ValueError as error:
            raise LegacyWriteDenied("Production permission hardening root is outside Production") from error
        if len(relative.parts) != 1 or relative.parts[0] not in _PRODUCTION_PERMISSION_HARDENING_ROOTS:
            raise LegacyWriteDenied("Production permission hardening root is outside the approved data allowlist")
        if path.is_symlink() or not path.is_dir():
            raise LegacyWriteDenied("Production permission hardening root is invalid")
        approved.append(path)
    if not approved or len(set(approved)) != len(approved):
        raise LegacyWriteDenied("Production permission hardening roots must be unique and non-empty")
    fence = LegacyWriteGate(home).read_verified_record()
    if fence is None or fence.get("state") != "FROZEN_NO_WRITER":
        raise LegacyWriteDenied("Production permission hardening requires the verified Legacy no-writer fence")
    if getattr(_local, "production_permission_hardening", None) is not None:
        raise LegacyWriteDenied("nested Production permission hardening is denied")
    if any(
        getattr(_local, name, None) is not None
        for name in ("compatibility_rollout", "production_backup", "extension_effect")
    ):
        raise LegacyWriteDenied("Production permission hardening cannot overlap another mutation capability")
    previous = getattr(_local, "production_permission_hardening", None)
    _local.production_permission_hardening = (
        home,
        tuple(approved),
        frozen_prefix,
        str(manifest_sha256),
        str(goal_thread_id),
        os.getpid(),
    )
    try:
        yield
    finally:
        _local.production_permission_hardening = previous


@contextlib.contextmanager
def authorized_compatibility_rollout(
    journal: object,
    *,
    goal_thread_id: str,
    process_id: str,
) -> Iterator[None]:
    """Permit one compatibility lease identity while its Journal writer is live.

    This capability does not admit general ``runtime`` writes.  It is bound to
    the canonical fixed-inode Journal lock and permits only the hashed lease,
    fence, and atomic-staging names used by ``CompatibilityLeaseRegistry``.
    """

    if not str(goal_thread_id).strip() or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(process_id)
    ):
        raise LegacyWriteDenied("compatibility rollout identity or Goal binding is invalid")
    try:
        home = Path(getattr(journal, "home")).resolve(strict=True)
        journal_root = Path(getattr(journal, "root")).resolve(strict=True)
        writer_lock = getattr(journal, "writer_lock")
        writer_lock.assert_healthy()
        lock_path = Path(writer_lock.path).resolve(strict=True)
    except Exception as error:
        raise LegacyWriteDenied("compatibility rollout requires a healthy Journal writer lock") from error
    if journal_root != home / "journal" or lock_path != journal_root / "writer.lock":
        raise LegacyWriteDenied("compatibility rollout writer is not bound to the canonical Journal lock")
    fence = LegacyWriteGate(home).read_verified_record()
    if fence is None or fence.get("state") != "FROZEN_NO_WRITER":
        raise LegacyWriteDenied("compatibility rollout requires the verified Legacy no-writer fence")
    runtime_root = home / "runtime"
    lease_root = runtime_root / "compatibility-leases"
    for candidate in (runtime_root, lease_root):
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
            raise LegacyWriteDenied("compatibility rollout root is not a real directory")
    if getattr(_local, "compatibility_rollout", None) is not None:
        raise LegacyWriteDenied("nested compatibility rollout authorization is denied")
    if getattr(_local, "production_backup", None) is not None or getattr(_local, "extension_effect", None) is not None:
        raise LegacyWriteDenied("compatibility rollout cannot overlap another mutation capability")
    basename = hashlib.sha256(str(process_id).encode("utf-8")).hexdigest()
    previous = getattr(_local, "compatibility_rollout", None)
    _local.compatibility_rollout = (
        home,
        runtime_root,
        lease_root,
        basename,
        writer_lock,
        str(goal_thread_id),
        os.getpid(),
    )
    try:
        yield
    finally:
        _local.compatibility_rollout = previous


def build_authority_fence_coverage(registry: dict[str, str]) -> dict[str, Any]:
    required = set(AUTHORITY_GUARDED_WRITER_ENTRYPOINTS)
    missing = sorted(required - set(registry))
    invalid = sorted(name for name, guard in registry.items() if not guard or guard == "NONE")
    core = {
        "schema": "AUTHORITY_WRITER_FENCE_COVERAGE_V1",
        "entrypoints": dict(sorted(registry.items())),
        "entrypoint_count": len(registry),
        "missing": missing,
        "invalid": invalid,
        "blocker_count": len(missing) + len(invalid),
    }
    return {**core, "coverage_hash": "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


@contextlib.contextmanager
def _bypass() -> Iterator[None]:
    previous = bool(getattr(_local, "bypass", False))
    _local.bypass = True
    try:
        yield
    finally:
        _local.bypass = previous


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _path_from_audit(value: object) -> Path | None:
    if isinstance(value, int) or value is None:
        return None
    try:
        text = os.fsdecode(value)
    except (TypeError, ValueError):
        return None
    if text.startswith("file:"):
        text = text[5:].split("?", 1)[0]
    raw = Path(text).expanduser()
    if not raw.is_absolute():
        return None
    return raw.resolve(strict=False)


def _open_is_mutating(arguments: tuple[Any, ...]) -> bool:
    mode = arguments[1] if len(arguments) > 1 else None
    flags = arguments[2] if len(arguments) > 2 and isinstance(arguments[2], int) else 0
    return (isinstance(mode, str) and any(character in mode for character in "wax+")) or bool(
        flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    )


def _marker(home: Path) -> Path:
    return home / "state/.legacy-control/frozen.json"


def _lock_path(home: Path) -> Path:
    return home / "state/.legacy-control/writer.lock"


def _marker_present(home: Path) -> bool:
    try:
        return _marker(home).exists()
    except OSError:
        return True


def _inside_bplus_mutation_plane(path: Path, home: Path) -> bool:
    return any(_inside(path, home / relative) for relative in _BPLUS_MUTATION_ROOTS)


def _compatibility_rollout_path_allowed(
    event: str,
    path: Path,
    *,
    runtime_root: Path,
    lease_root: Path,
    basename: str,
) -> bool:
    if path == runtime_root or path == lease_root:
        return event == "os.mkdir"
    if path.parent != lease_root:
        return False
    final_names = {f"{basename}.lease.json", f"{basename}.fence.json"}
    if path.name in final_names:
        return event in {"open", "os.remove", "os.rename"}
    return event in {"open", "os.remove", "os.rename"} and any(
        re.fullmatch(re.escape(name) + r"\.tmp-[0-9a-f]{32}", path.name)
        for name in final_names
    )


def _ensure_control_directory(home: Path) -> None:
    with _bypass():
        _lock_path(home).parent.mkdir(parents=True, exist_ok=True)


def _acquire_process_writer_lease(home: Path) -> None:
    canonical_home = home.resolve(strict=True)
    with _state_lock:
        if canonical_home in _writer_fds:
            return
        if _marker_present(canonical_home):
            raise LegacyWriteDenied("Legacy writer fence is active; no Legacy mutation is authorized")
        _ensure_control_directory(canonical_home)
        with _bypass():
            descriptor = os.open(_lock_path(canonical_home), os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as error:
            os.close(descriptor)
            raise LegacyFenceBusy("Legacy freezer holds the writer coordination lock") from error
        if _marker_present(canonical_home):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            raise LegacyWriteDenied("Legacy writer fence became active while acquiring writer lease")
        _writer_fds[canonical_home] = descriptor


def release_process_writer_lease(home: Path | None = None) -> None:
    with _state_lock:
        targets = [home.resolve(strict=True)] if home is not None else list(_writer_fds)
        for target in targets:
            descriptor = _writer_fds.pop(target, None)
            if descriptor is None:
                continue
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _audit_guard(event: str, arguments: tuple[Any, ...]) -> None:
    home = _guard_home
    if home is None or getattr(_local, "bypass", False):
        return
    if event == "subprocess.Popen":
        if _marker_present(home):
            if getattr(_local, "extension_effect", None) in {"shell", "install_network"}:
                return
            sandbox_scope = getattr(_local, "sandbox_execution", None)
            if sandbox_scope is not None:
                capability, used = sandbox_scope
                executable = str(arguments[0]) if arguments else ""
                raw_argv = arguments[1] if len(arguments) > 1 else ()
                requested_argv = tuple(str(item) for item in raw_argv) if isinstance(raw_argv, (list, tuple)) else ()
                requested_cwd = arguments[2] if len(arguments) > 2 else None
                resolved_cwd = str(Path(requested_cwd).expanduser().resolve(strict=False)) if requested_cwd else capability.cwd
                if (
                    not used
                    and executable == capability.runner_executable
                    and requested_argv == capability.argv
                    and resolved_cwd == capability.cwd
                ):
                    _local.sandbox_execution = (capability, True)
                    return
                raise LegacyWriteDenied("Legacy fence denies an out-of-scope or repeated sandbox subprocess")
            raise LegacyWriteDenied(f"Legacy fence denies {event} while frozen")
        return
    if event == "socket.connect":
        if _marker_present(home):
            if getattr(_local, "extension_effect", None) in {"network", "external_service", "install_network"}:
                return
            capability = getattr(_local, "network_egress", None)
            if (
                isinstance(capability, FrozenNetworkEgressCapability)
                and capability._nonce in _network_egress_nonces
                and int(time.time()) <= capability.expires_at
            ):
                return
            raise LegacyWriteDenied(f"Legacy fence denies {event} while frozen")
        return
    mutating = False
    indexes: tuple[int, ...] = ()
    if event == "open":
        mutating = _open_is_mutating(arguments)
        indexes = (0,)
    elif event == "sqlite3.connect":
        target = str(arguments[0]) if arguments else ""
        mutating = "mode=ro" not in target
        indexes = (0,)
    elif event in {"shutil.copyfile", "shutil.copytree"}:
        mutating = True
        # The source is read-only input; only the destination is mutated.
        indexes = (1,)
    elif event in {
        "os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.truncate",
        "os.utime", "os.rename", "os.symlink", "os.link",
    }:
        mutating = True
        indexes = (0, 1) if event in {"os.rename", "os.symlink", "os.link"} else (0,)
    if not mutating:
        return
    paths = [_path_from_audit(arguments[index]) for index in indexes if index < len(arguments)]
    production_paths = [path for path in paths if path is not None and _inside(path, home)]
    if production_paths:
        if _marker_present(home):
            permission_scope = getattr(_local, "production_permission_hardening", None)
            if isinstance(permission_scope, tuple) and len(permission_scope) == 6:
                (
                    hardening_home,
                    hardening_roots,
                    frozen_prefix,
                    manifest_sha256,
                    goal_thread_id,
                    owner_pid,
                ) = permission_scope
                try:
                    frozen_prefix.assert_healthy()
                    permission_healthy = (
                        hardening_home == home
                        and owner_pid == os.getpid()
                        and bool(str(goal_thread_id).strip())
                        and bool(re.fullmatch(r"[0-9a-f]{64}", str(manifest_sha256)))
                    )
                except Exception:
                    permission_healthy = False
                if (
                    permission_healthy
                    and event == "os.chmod"
                    and all(any(_inside(path, root) for root in hardening_roots) for path in production_paths)
                ):
                    return
            rollout_scope = getattr(_local, "compatibility_rollout", None)
            if isinstance(rollout_scope, tuple) and len(rollout_scope) == 7:
                (
                    rollout_home,
                    runtime_root,
                    lease_root,
                    basename,
                    writer_lock,
                    _goal_thread_id,
                    owner_pid,
                ) = rollout_scope
                try:
                    writer_lock.assert_healthy()
                    rollout_healthy = rollout_home == home and owner_pid == os.getpid()
                except Exception:
                    rollout_healthy = False
                if rollout_healthy and all(
                    _compatibility_rollout_path_allowed(
                        event,
                        path,
                        runtime_root=runtime_root,
                        lease_root=lease_root,
                        basename=basename,
                    )
                    for path in production_paths
                ):
                    return
            backup_scope = getattr(_local, "production_backup", None)
            if isinstance(backup_scope, tuple) and len(backup_scope) == 3:
                backup_root, backup_target, _goal_thread_id = backup_scope
                if all(
                    path == backup_root or path == backup_target or _inside(path, backup_target)
                    for path in production_paths
                ):
                    return
            extension_permission = getattr(_local, "extension_effect", None)
            if extension_permission in {"write", "shell"}:
                return
            if all(_inside_bplus_mutation_plane(path, home) for path in production_paths):
                return
            raise LegacyWriteDenied(f"Legacy writer fence denies mutation event {event}")
        _acquire_process_writer_lease(home)


def install_legacy_mutation_guard(home: Path) -> None:
    global _guard_installed, _guard_home
    canonical = Path(home).expanduser().resolve(strict=False)
    with _state_lock:
        if _guard_installed:
            if _guard_home != canonical:
                raise LegacyFenceError("Legacy mutation guard is already bound to another home")
            return
        _guard_home = canonical
        sys.addaudithook(_audit_guard)
        _guard_installed = True


@dataclass(frozen=True)
class FenceStatus:
    state: str
    snapshot_id: str | None = None
    record_hash: str | None = None
    frozen_at: str | None = None
    snapshot_destination: str | None = None


def build_fence_coverage(inventory: dict[str, Any]) -> dict[str, Any]:
    """Bind every Phase -1 sink finding to the installed fail-closed guard layer."""

    if inventory.get("schema") != "LEGACY_WRITE_SINK_INVENTORY_V1":
        raise ValueError("unsupported sink inventory schema")
    covered: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for entry in inventory.get("entries", []):
        classification = str(entry.get("classification", ""))
        if classification.startswith("READ_ONLY"):
            guard = "READ_ONLY_NO_WRITER_LEASE"
            status = "READ_ONLY"
        elif "MUTATION" in classification:
            guard = "PACKAGE_AUDIT_HOOK_PLUS_KERNEL_SHARED_WRITER_LEASE"
            status = "GUARDED"
        elif "EXTERNAL" in classification:
            guard = "FROZEN_SUBPROCESS_AND_SOCKET_DENY_PLUS_TOP_LEVEL_POLICY"
            status = "GUARDED"
        else:
            guard = "NONE"
            status = "BLOCKER"
        record = {
            "path": entry.get("path"),
            "line": entry.get("line"),
            "function": entry.get("function"),
            "operation": entry.get("operation"),
            "classification": classification,
            "guard": guard,
            "status": status,
        }
        covered.append(record)
        if status == "BLOCKER":
            blockers.append(record)
    core = {
        "schema": "LEGACY_FENCE_COVERAGE_V1",
        "inventory_sha256": inventory.get("inventory_sha256"),
        "entries": covered,
        "summary": {
            "entry_count": len(covered),
            "guarded_count": sum(item["status"] == "GUARDED" for item in covered),
            "read_only_count": sum(item["status"] == "READ_ONLY" for item in covered),
            "blocker_count": len(blockers),
        },
    }
    core["coverage_hash"] = "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()
    return core


class LegacyWriteGate:
    def __init__(self, home: Path):
        self.home = Path(home).expanduser().resolve(strict=True)

    @property
    def marker_path(self) -> Path:
        return _marker(self.home)

    @property
    def coordination_lock_path(self) -> Path:
        return _lock_path(self.home)

    def read_verified_record(self) -> dict[str, Any] | None:
        if not self.marker_path.exists():
            return None
        try:
            value = json.loads(self.marker_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise LegacyFenceError("Legacy writer fence record is not an object")
            declared = value["record_hash"]
            core = dict(value)
            core.pop("record_hash")
            actual = "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()
            if declared != actual or value.get("state") != "FROZEN_NO_WRITER":
                raise LegacyFenceError("Legacy writer fence record is invalid")
            return value
        except LegacyFenceError:
            raise
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise LegacyFenceError("Legacy writer fence record cannot be verified") from error

    def status(self) -> FenceStatus:
        if not self.marker_path.exists():
            return FenceStatus("LEGACY_ACTIVE")
        try:
            value = self.read_verified_record()
            if value is None:
                return FenceStatus("LEGACY_ACTIVE")
            return FenceStatus(
                "FROZEN_NO_WRITER",
                snapshot_id=value.get("snapshot_id"),
                record_hash=value.get("record_hash"),
                frozen_at=value.get("frozen_at"),
                snapshot_destination=value.get("snapshot_destination"),
            )
        except LegacyFenceError:
            return FenceStatus("FROZEN_INVALID_NO_WRITER")

    def assert_writes_allowed(self) -> None:
        status = self.status()
        if status.state != "LEGACY_ACTIVE":
            raise LegacyWriteDenied(f"Legacy writes denied: {status.state}")
        _acquire_process_writer_lease(self.home)

    def assert_writes_authorized(self, resolution: object, *, now: int) -> None:
        from sitina.authority.model import AuthorityResolution

        if not isinstance(resolution, AuthorityResolution):
            raise LegacyWriteDenied("Legacy sink requires a verified AuthorityResolution")
        try:
            resolution.assert_fresh(now=now)
        except Exception as error:
            raise LegacyWriteDenied("stale AuthorityResolution cannot open Legacy sink") from error
        if not resolution.authorizes_legacy or resolution.writer_count != 1:
            raise LegacyWriteDenied("AuthorityResolution does not authorize the Legacy writer")
        self.assert_writes_allowed()

    def acquire_process_writer_lease(self) -> None:
        self.assert_writes_allowed()

    def dry_run_freeze(self, snapshot_id: str) -> dict[str, Any]:
        if not _SNAPSHOT_ID.fullmatch(snapshot_id):
            raise ValueError("invalid snapshot_id")
        status = self.status()
        return {
            "status": "DRY_RUN_ONLY",
            "snapshot_id": snapshot_id,
            "current_state": status.state,
            "would_require": ["fixture_or_maintenance_authorization", "all_writer_leases_drained", "exclusive_kernel_lock"],
            "production_mutated": False,
        }

    def freeze(self, snapshot_id: str, *, fixture_authorization: bool = False) -> FenceStatus:
        if not _SNAPSHOT_ID.fullmatch(snapshot_id):
            raise ValueError("invalid snapshot_id")
        marker = self.home / ".sitina-bplus-disposable-v1"
        if not fixture_authorization or not marker.is_file() or self.home == Path("/Users/moss/SitinaHub"):
            raise LegacyWriteDenied("Phase 0 freeze execution is restricted to marked disposable fixtures")
        current = self.status()
        if current.state == "FROZEN_NO_WRITER":
            if current.snapshot_id != snapshot_id:
                raise LegacyWriteDenied("a different snapshot already owns the fixture fence")
            return current
        if current.state != "LEGACY_ACTIVE":
            raise LegacyWriteDenied(f"cannot freeze from {current.state}")
        release_process_writer_lease(self.home)
        _ensure_control_directory(self.home)
        with _bypass():
            descriptor = os.open(self.coordination_lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise LegacyFenceBusy("one or more Legacy writer processes still hold leases") from error
            core = {
                "schema": "LEGACY_WRITER_FENCE_RECORD_V1",
                "state": "FROZEN_NO_WRITER",
                "snapshot_id": snapshot_id,
                "home": str(self.home),
                "frozen_at": _utc_now(),
                "coordination_profile": "KERNEL_FLOCK_SHARED_WRITERS_EXCLUSIVE_FREEZER_V1",
                "freezer_pid": os.getpid(),
            }
            value = {**core, "record_hash": "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()}
            temporary = self.marker_path.with_name(f".{self.marker_path.name}.{os.getpid()}.tmp")
            with _bypass():
                with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                    json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.marker_path)
                directory_fd = os.open(self.marker_path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        return self.status()

    def freeze_authorized(self, snapshot_id: str, capability: object, *, now: int) -> FenceStatus:
        """Acquire the real Phase 6B fence only from an exact Maintenance capability."""
        from sitina.operations.phase6b import Phase6BOperationalCapability

        if not isinstance(capability, Phase6BOperationalCapability):
            raise LegacyWriteDenied("Production freeze requires a verified Phase 6B capability")
        capability.assert_operation("FREEZE_LEGACY_WRITER", self.home, now=now)
        if capability.production_home != self.home:
            raise LegacyWriteDenied("Production freeze root differs from the Maintenance Manifest")
        if not _SNAPSHOT_ID.fullmatch(snapshot_id):
            raise ValueError("invalid snapshot_id")
        current = self.status()
        if current.state == "FROZEN_NO_WRITER":
            if current.snapshot_id != snapshot_id:
                raise LegacyWriteDenied("a different snapshot already owns the Production fence")
            return current
        if current.state != "LEGACY_ACTIVE":
            raise LegacyWriteDenied(f"cannot freeze from {current.state}")
        release_process_writer_lease(self.home)
        _ensure_control_directory(self.home)
        with _bypass():
            descriptor = os.open(
                self.coordination_lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise LegacyFenceBusy("one or more Legacy writer processes still hold leases") from error
            core = {
                "schema": "LEGACY_WRITER_FENCE_RECORD_V1",
                "state": "FROZEN_NO_WRITER",
                "snapshot_id": snapshot_id,
                "home": str(self.home),
                "frozen_at": _utc_now(),
                "coordination_profile": "KERNEL_FLOCK_SHARED_WRITERS_EXCLUSIVE_FREEZER_V1",
                "freezer_pid": os.getpid(),
                "phase6b_manifest_sha256": capability.manifest_sha256,
                "cutover_command_id": str(capability.cutover_command["command_id"]),
                "cutover_request_hash": str(capability.cutover_command["request_hash"]),
                "intended_snapshot_hash": str(capability.production_genesis["intended_snapshot_hash"]),
                "snapshot_destination": str(capability.snapshot_root),
                "production_genesis_journal_id": str(capability.production_genesis["journal_id"]),
            }
            value = {**core, "record_hash": "sha256:" + hashlib.sha256(_canonical(core)).hexdigest()}
            temporary = self.marker_path.with_name(f".{self.marker_path.name}.{os.getpid()}.tmp")
            with _bypass():
                with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                    json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.marker_path)
                directory_fd = os.open(self.marker_path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        return self.status()

    def unfreeze_fixture(self) -> None:
        marker = self.home / ".sitina-bplus-disposable-v1"
        if not marker.is_file() or self.home == Path("/Users/moss/SitinaHub"):
            raise LegacyWriteDenied("only marked disposable fixtures may be unfrozen in Phase 0")
        with _bypass():
            self.marker_path.unlink(missing_ok=True)
            if self.marker_path.parent.exists():
                directory_fd = os.open(self.marker_path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)

    def unfreeze_fixture_if_present(self) -> None:
        if self.marker_path.exists():
            self.unfreeze_fixture()
