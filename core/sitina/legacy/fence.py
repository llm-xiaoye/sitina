"""Kernel-coordinated Legacy writer fence with fail-closed sink instrumentation."""

from __future__ import annotations

import contextlib
import base64
import datetime as dt
import fcntl
import hashlib
import hmac
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
_network_egress_records: dict[str, dict[str, Any]] = {}
_native_network_owners: dict[int, tuple[object, int]] = {}
_sandbox_execution_nonces: dict[str, str] = {}
_code_mode_sandbox_nonces: dict[str, str] = {}
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
    provider_name: str = ""
    credential_reference: str = ""


@dataclass(frozen=True)
class FrozenSandboxExecutionCapability:
    """One-use authority for one exact signing-supervisor invocation.

    This does not authorize a shell or a generic subprocess.  It binds the
    frozen-home escape hatch to immutable supervisor, sandbox, policy and input
    identities plus the exact argv/cwd/read/write/resource scope.  The trusted
    supervisor is the only direct child; it launches the bound Seatbelt
    executor without ever importing target code.
    """

    capability_id: str
    authority_resolution_id: str
    authority_input_frontier_hash: str
    run_id: str
    diff_hash: str
    test_plan_hash: str
    runner_executable: str
    runner_executable_hash: str
    sandbox_executable: str
    sandbox_executable_hash: str
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
    proposer_id: str
    proposer_role: str
    proposer_capability: str
    proposer_identity_hash: str
    proposer_registry_ref: str
    executor_id: str
    executor_role: str
    executor_role_authorization_ref: str
    verifier_id: str
    verifier_role: str
    verifier_capability: str
    verifier_identity_hash: str
    verifier_registry_ref: str
    registry_hash: str
    execution_policy_hash: str
    authority_ref: str
    identity_binding_hash: str
    issued_at: int
    _nonce: str


@dataclass(frozen=True)
class CodeModeSandboxExecutionCapability:
    """One-use sandbox admission for the independent Code Mode runtime.

    This is deliberately not a Legacy/B+ activation capability.  It binds
    only the trusted sandbox supervisor invocation to the current Code Mode
    run and is issued by the already-authorized local execution verifier.
    """

    capability_id: str
    run_id: str
    attempt: int
    diff_hash: str
    test_plan_hash: str
    parent_authorization_hash: str
    runner_executable: str
    worker_path: str
    cwd: str
    read_roots: tuple[str, ...]
    write_roots: tuple[str, ...]
    argv: tuple[str, ...]
    expires_at: int
    _nonce: str


def _sandbox_capability_identity(
    capability: FrozenSandboxExecutionCapability,
) -> str:
    core = {
        "authority_resolution_id": capability.authority_resolution_id,
        "authority_input_frontier_hash": capability.authority_input_frontier_hash,
        "run_id": capability.run_id,
        "diff_hash": capability.diff_hash,
        "test_plan_hash": capability.test_plan_hash,
        "runner_executable": capability.runner_executable,
        "runner_executable_hash": capability.runner_executable_hash,
        "sandbox_executable": capability.sandbox_executable,
        "sandbox_executable_hash": capability.sandbox_executable_hash,
        "python_executable_hash": capability.python_executable_hash,
        "worker_path": capability.worker_path,
        "worker_hash": capability.worker_hash,
        "argv_hash": capability.argv_hash,
        "cwd": capability.cwd,
        "read_roots": list(capability.read_roots),
        "write_roots": list(capability.write_roots),
        "sandbox_policy_hash": capability.sandbox_policy_hash,
        "resource_limits": [
            [name, value] for name, value in capability.resource_limits
        ],
        "expires_at": capability.expires_at,
        "proposer_id": capability.proposer_id,
        "proposer_role": capability.proposer_role,
        "proposer_capability": capability.proposer_capability,
        "proposer_identity_hash": capability.proposer_identity_hash,
        "proposer_registry_ref": capability.proposer_registry_ref,
        "executor_id": capability.executor_id,
        "executor_role": capability.executor_role,
        "executor_role_authorization_ref": capability.executor_role_authorization_ref,
        "verifier_id": capability.verifier_id,
        "verifier_role": capability.verifier_role,
        "verifier_capability": capability.verifier_capability,
        "verifier_identity_hash": capability.verifier_identity_hash,
        "verifier_registry_ref": capability.verifier_registry_ref,
        "registry_hash": capability.registry_hash,
        "execution_policy_hash": capability.execution_policy_hash,
        "authority_ref": capability.authority_ref,
        "identity_binding_hash": capability.identity_binding_hash,
        "issued_at": capability.issued_at,
        "nonce_hash": hashlib.sha256(capability._nonce.encode("ascii")).hexdigest(),
    }
    return hashlib.sha256(_canonical(core)).hexdigest()


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
    runtime_reads = [python.parents[1]]
    venv_config = python.parents[1] / "pyvenv.cfg"
    if venv_config.is_file():
        # A copied venv still imports its standard library from the base
        # runtime named by this interpreter's own configuration.
        homes = [value.strip() for line in venv_config.read_text(encoding="utf-8").splitlines()
                 if "=" in line for key, value in [line.split("=", 1)] if key.strip() == "home"]
        if len(homes) != 1 or not Path(homes[0]).is_absolute():
            raise LegacyWriteDenied("sandbox venv base runtime is ambiguous")
        base_lib = (Path(homes[0]).resolve(strict=True).parent / "lib").resolve(strict=True)
        if not base_lib.is_dir():
            raise LegacyWriteDenied("sandbox venv base library is unavailable")
        runtime_reads.append(base_lib)
    read_rules = (*runtime_reads, worker, *reads, *writes)

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
    proposer_id: str = "",
    executor_id: str = "",
    verifier_id: str = "",
    identity_binding: object | None = None,
    agent_registry: object | None = None,
    execution_policy_hash: str = "",
    now: int | None = None,
    fixture_authorization: bool = False,
) -> FrozenSandboxExecutionCapability:
    """Issue a one-use capability for an exact measured supervisor command."""

    moment = int(time.time()) if now is None else int(now)
    canonical_home = Path(home).expanduser().resolve(strict=True)
    if LegacyWriteGate(canonical_home).status().state != "FROZEN_NO_WRITER":
        raise LegacyWriteDenied("sandbox execution capability requires a verified frozen home")
    from sitina.orchestrator.execution_bridge import (
        ExecutionBridgeError,
        ExecutionIdentityBinding,
    )

    if fixture_authorization:
        if canonical_home == Path("/Users/moss/SitinaHub") or not (
            canonical_home / ".sitina-bplus-disposable-v1"
        ).is_file():
            raise LegacyWriteDenied("sandbox fixture authorization requires a disposable non-Production home")
        if identity_binding is None:
            identity_binding = ExecutionIdentityBinding.fixture(
                proposer_id=proposer_id or "fixture-proposer",
                executor_id=executor_id or "forge-execution-role",
                verifier_id=verifier_id or "fixture-verifier",
            )
        if type(identity_binding) is not ExecutionIdentityBinding:
            raise LegacyWriteDenied("sandbox fixture execution identity is invalid")
        authority_resolution_id = identity_binding.authority_resolution_id
        authority_frontier_hash = identity_binding.authority_input_frontier_hash
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
        if type(identity_binding) is not ExecutionIdentityBinding:
            raise LegacyWriteDenied("sandbox execution requires bound production principals")
        try:
            identity_binding.assert_current(
                agent_registry,
                policy_hash=execution_policy_hash,
                authority_resolution=authority_resolution,
                now=moment,
            )
        except (ExecutionBridgeError, ValueError, TypeError) as error:
            raise LegacyWriteDenied(
                "sandbox execution principals are not currently authorized"
            ) from error
        if (
            identity_binding.authority_resolution_id != authority_resolution_id
            or identity_binding.authority_input_frontier_hash
            != authority_frontier_hash
        ):
            raise LegacyWriteDenied("sandbox execution authority binding differs")

    assert isinstance(identity_binding, ExecutionIdentityBinding)
    if any(
        supplied and supplied != expected
        for supplied, expected in (
            (proposer_id, identity_binding.proposer_id),
            (executor_id, identity_binding.executor_id),
            (verifier_id, identity_binding.verifier_id),
        )
    ):
        raise LegacyWriteDenied("sandbox execution principal arguments differ")

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
        str(python),
        "-I",
        "-S",
        str(worker),
        "--request",
    )
    if len(argv) != 6 or tuple(argv[:5]) != expected_prefix:
        raise LegacyWriteDenied("sandbox execution is not the exact trusted worker command")
    if hashlib.sha256(expected_profile.encode("utf-8")).hexdigest() != sandbox_policy_hash:
        raise LegacyWriteDenied("sandbox execution policy hash does not match the trusted policy")
    try:
        request = json.loads(base64.urlsafe_b64decode(argv[5].encode("ascii")))
    except Exception as error:
        raise LegacyWriteDenied("sandbox execution worker request is invalid") from error
    expected_executor_profile = frozen_sandbox_profile(
        python,
        worker,
        tuple(Path(path) for path in reads),
        tuple(Path(path) for path in writes),
    )
    expected_executor = {
        "schema": "SITINA_SANDBOX_EXECUTOR_BINDING_V1",
        "sandbox_executable": str(runner),
        "python_executable": str(python),
        "worker_path": str(worker),
        "sandbox_policy": expected_executor_profile,
        "sandbox_policy_hash": hashlib.sha256(expected_executor_profile.encode("utf-8")).hexdigest(),
    }
    if (
        not isinstance(request, dict)
        or request.get("resource_limits") != dict(normalized_limits)
        or request.get("test_plan_hash") != test_plan_hash
        or request.get("executor") != expected_executor
    ):
        raise LegacyWriteDenied("sandbox execution worker request is not resource-bound")

    sandbox_hash = _sha256_regular_file(runner)
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
        "runner_executable": str(python),
        "runner_executable_hash": python_hash,
        "sandbox_executable": str(runner),
        "sandbox_executable_hash": sandbox_hash,
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
        "proposer_id": identity_binding.proposer_id,
        "proposer_role": identity_binding.proposer_role,
        "proposer_capability": identity_binding.proposer_capability,
        "proposer_identity_hash": identity_binding.proposer_identity_hash,
        "proposer_registry_ref": identity_binding.proposer_registry_ref,
        "executor_id": identity_binding.executor_id,
        "executor_role": identity_binding.executor_role,
        "executor_role_authorization_ref": identity_binding.executor_role_authorization_ref,
        "verifier_id": identity_binding.verifier_id,
        "verifier_role": identity_binding.verifier_role,
        "verifier_capability": identity_binding.verifier_capability,
        "verifier_identity_hash": identity_binding.verifier_identity_hash,
        "verifier_registry_ref": identity_binding.verifier_registry_ref,
        "registry_hash": identity_binding.registry_hash,
        "execution_policy_hash": identity_binding.policy_hash,
        "authority_ref": identity_binding.authority_ref,
        "identity_binding_hash": identity_binding.binding_hash,
        "issued_at": moment,
        "nonce_hash": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
    }
    identity = hashlib.sha256(_canonical(core)).hexdigest()
    capability_id = "sandbox-execution:" + identity
    with _state_lock:
        _sandbox_execution_nonces[nonce] = capability_id
    return FrozenSandboxExecutionCapability(
        capability_id,
        authority_resolution_id,
        authority_frontier_hash,
        str(run_id),
        str(diff_hash),
        str(test_plan_hash),
        str(python),
        python_hash,
        str(runner),
        sandbox_hash,
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
        identity_binding.proposer_id,
        identity_binding.proposer_role,
        identity_binding.proposer_capability,
        identity_binding.proposer_identity_hash,
        identity_binding.proposer_registry_ref,
        identity_binding.executor_id,
        identity_binding.executor_role,
        identity_binding.executor_role_authorization_ref,
        identity_binding.verifier_id,
        identity_binding.verifier_role,
        identity_binding.verifier_capability,
        identity_binding.verifier_identity_hash,
        identity_binding.verifier_registry_ref,
        identity_binding.registry_hash,
        identity_binding.policy_hash,
        identity_binding.authority_ref,
        identity_binding.binding_hash,
        moment,
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
    authority_resolution: object | None = None,
    identity_binding: object | None = None,
    agent_registry: object | None = None,
    execution_policy_hash: str = "",
    now: int | None = None,
) -> Iterator[None]:
    """Consume one capability and scope it to exactly one Popen audit event."""

    if capability is None:
        yield
        return
    from sitina.orchestrator.execution_bridge import (
        ExecutionBridgeError,
        ExecutionIdentityBinding,
    )

    moment = int(time.time()) if now is None else int(now)
    if type(capability) is not FrozenSandboxExecutionCapability:
        raise LegacyWriteDenied(
            "frozen sandbox execution capability is invalid, expired, or out of scope"
        )
    resolved_cwd = str(Path(cwd).expanduser().resolve(strict=True))
    fixture_registry_hash = hashlib.sha256(
        b"sitina-execution-fixture-registry-v1"
    ).hexdigest()
    if identity_binding is None and capability.registry_hash == fixture_registry_hash:
        identity_binding = ExecutionIdentityBinding.fixture(
            proposer_id=capability.proposer_id,
            executor_id=capability.executor_id,
            verifier_id=capability.verifier_id,
        )
    identity_valid = type(identity_binding) is ExecutionIdentityBinding
    if identity_valid:
        identity_valid = (
            capability.proposer_id == identity_binding.proposer_id
            and capability.proposer_role == identity_binding.proposer_role
            and capability.proposer_capability == identity_binding.proposer_capability
            and capability.proposer_identity_hash
            == identity_binding.proposer_identity_hash
            and capability.proposer_registry_ref
            == identity_binding.proposer_registry_ref
            and capability.executor_id == identity_binding.executor_id
            and capability.executor_role == identity_binding.executor_role
            and capability.executor_role_authorization_ref
            == identity_binding.executor_role_authorization_ref
            and capability.verifier_id == identity_binding.verifier_id
            and capability.verifier_role == identity_binding.verifier_role
            and capability.verifier_capability == identity_binding.verifier_capability
            and capability.verifier_identity_hash
            == identity_binding.verifier_identity_hash
            and capability.verifier_registry_ref
            == identity_binding.verifier_registry_ref
            and capability.registry_hash == identity_binding.registry_hash
            and capability.execution_policy_hash == identity_binding.policy_hash
            and capability.authority_resolution_id
            == identity_binding.authority_resolution_id
            and capability.authority_input_frontier_hash
            == identity_binding.authority_input_frontier_hash
            and capability.authority_ref == identity_binding.authority_ref
            and capability.identity_binding_hash == identity_binding.binding_hash
        )
    production_identity = (
        identity_valid and capability.registry_hash != fixture_registry_hash
    )
    if production_identity:
        try:
            identity_binding.assert_current(
                agent_registry,
                policy_hash=execution_policy_hash,
                authority_resolution=authority_resolution,
                now=moment,
            )
            authority_issued_at = int(authority_resolution.issued_at)  # type: ignore[union-attr]
            authority_expires_at = int(authority_resolution.expires_at)  # type: ignore[union-attr]
        except (ExecutionBridgeError, AttributeError, TypeError, ValueError):
            identity_valid = False
            authority_issued_at = 0
            authority_expires_at = 0
        else:
            identity_valid = (
                authority_issued_at <= capability.issued_at < authority_expires_at
            )
    if (
        not identity_valid
        or capability.capability_id
        != "sandbox-execution:" + _sandbox_capability_identity(capability)
        or tuple(argv) != capability.argv
        or resolved_cwd != capability.cwd
        or diff_hash != capability.diff_hash
        or test_plan_hash != capability.test_plan_hash
        or capability.issued_at > moment
        or capability.expires_at - capability.issued_at > 300
        or moment >= capability.expires_at
        or _sha256_regular_file(Path(capability.runner_executable)) != capability.runner_executable_hash
        or _sha256_regular_file(Path(capability.sandbox_executable)) != capability.sandbox_executable_hash
        or _sha256_regular_file(Path(capability.argv[0])) != capability.python_executable_hash
        or _sha256_regular_file(Path(capability.worker_path)) != capability.worker_hash
        or hashlib.sha256(_canonical(list(capability.argv))).hexdigest() != capability.argv_hash
        or hashlib.sha256(
            frozen_sandbox_profile(
                Path(capability.runner_executable),
                Path(capability.worker_path),
                tuple(Path(path) for path in capability.read_roots),
                tuple(Path(path) for path in capability.write_roots),
            ).encode("utf-8")
        ).hexdigest()
        != capability.sandbox_policy_hash
    ):
        raise LegacyWriteDenied("frozen sandbox execution capability is invalid, expired, or out of scope")
    with _state_lock:
        if _sandbox_execution_nonces.get(capability._nonce) != capability.capability_id:
            raise LegacyWriteDenied("frozen sandbox execution capability was already consumed")
        del _sandbox_execution_nonces[capability._nonce]
    previous = getattr(_local, "sandbox_execution", None)
    _local.sandbox_execution = (capability, False)
    try:
        yield
    finally:
        _local.sandbox_execution = previous


def _issue_trusted_code_mode_sandbox_capability(
    *,
    run_id: str,
    attempt: int,
    diff_hash: str,
    test_plan_hash: str,
    parent_authorization_hash: str,
    runner_executable: Path,
    worker_path: Path,
    cwd: Path,
    read_roots: tuple[Path, ...],
    write_roots: tuple[Path, ...],
    argv: tuple[str, ...],
    expires_at: int,
    now: int | None = None,
) -> CodeModeSandboxExecutionCapability:
    """Issue a child capability for a trusted Code Mode runtime only."""

    moment = int(time.time()) if now is None else int(now)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,255}", str(run_id)):
        raise LegacyWriteDenied("Code Mode sandbox run_id is invalid")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise LegacyWriteDenied("Code Mode sandbox attempt is invalid")
    if any(
        not re.fullmatch(r"[0-9a-f]{64}", str(value))
        for value in (diff_hash, test_plan_hash, parent_authorization_hash)
    ):
        raise LegacyWriteDenied("Code Mode sandbox input hash is invalid")
    if expires_at <= moment or expires_at - moment > 300:
        raise LegacyWriteDenied("Code Mode sandbox expiry is invalid")
    runner = Path(runner_executable).expanduser().resolve(strict=True)
    worker = Path(worker_path).expanduser().resolve(strict=True)
    working_directory = Path(cwd).expanduser().resolve(strict=True)
    if (
        runner.is_symlink() or not runner.is_file()
        or worker.is_symlink() or not worker.is_file()
        or working_directory.is_symlink() or not working_directory.is_dir()
    ):
        raise LegacyWriteDenied("Code Mode sandbox executable or cwd is unsafe")
    normalized_argv = tuple(str(item) for item in argv)
    if not normalized_argv or normalized_argv[0] != str(runner):
        raise LegacyWriteDenied("Code Mode sandbox argv is not bound to the trusted supervisor")
    if str(worker) not in normalized_argv:
        raise LegacyWriteDenied("Code Mode sandbox argv is not bound to the trusted worker")
    normalized_reads = tuple(sorted(str(Path(item).expanduser().resolve(strict=True)) for item in read_roots))
    normalized_writes = tuple(sorted(str(Path(item).expanduser().resolve(strict=True)) for item in write_roots))
    if not normalized_reads or not normalized_writes:
        raise LegacyWriteDenied("Code Mode sandbox filesystem scope is empty")
    if any(not Path(item).is_dir() or Path(item).is_symlink() for item in (*normalized_reads, *normalized_writes)):
        raise LegacyWriteDenied("Code Mode sandbox filesystem scope is unsafe")
    if not any(working_directory == Path(item) or Path(item) in working_directory.parents for item in normalized_reads):
        raise LegacyWriteDenied("Code Mode sandbox cwd is outside the parent authorization scope")
    nonce = os.urandom(32).hex()
    identity = hashlib.sha256(
        _canonical(
            {
                "run_id": str(run_id),
                "attempt": int(attempt),
                "diff_hash": str(diff_hash),
                "test_plan_hash": str(test_plan_hash),
                "parent_authorization_hash": str(parent_authorization_hash),
                "runner_executable": str(runner),
                "worker_path": str(worker),
                "cwd": str(working_directory),
                "read_roots": list(normalized_reads),
                "write_roots": list(normalized_writes),
                "argv": list(normalized_argv),
                "expires_at": int(expires_at),
                "nonce_hash": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
            }
        )
    ).hexdigest()
    capability = CodeModeSandboxExecutionCapability(
        capability_id="code-mode-sandbox:" + identity,
        run_id=str(run_id),
        attempt=int(attempt),
        diff_hash=str(diff_hash),
        test_plan_hash=str(test_plan_hash),
        parent_authorization_hash=str(parent_authorization_hash),
        runner_executable=str(runner),
        worker_path=str(worker),
        cwd=str(working_directory),
        read_roots=normalized_reads,
        write_roots=normalized_writes,
        argv=normalized_argv,
        expires_at=int(expires_at),
        _nonce=nonce,
    )
    _code_mode_sandbox_nonces[nonce] = capability.capability_id
    return capability


def issue_code_mode_sandbox_execution_capability(*args: Any, **kwargs: Any) -> CodeModeSandboxExecutionCapability:
    """Reject direct/public capability minting.

    Code Mode sandbox capabilities must come from the live runtime context,
    which verifies the opaque parent record and its immutable expiry.  Keeping
    this compatibility name fail-closed prevents model output, controls, or a
    caller with a copied parent hash from minting a capability.
    """

    del args, kwargs
    raise LegacyWriteDenied(
        "Code Mode sandbox capability must be derived by a trusted runtime parent"
    )


@contextlib.contextmanager
def authorized_code_mode_sandbox_execution(
    capability: CodeModeSandboxExecutionCapability,
    *,
    argv: tuple[str, ...],
    cwd: Path,
    attempt: int,
    diff_hash: str,
    test_plan_hash: str,
    parent_authorization_hash: str,
    read_roots: tuple[Path, ...],
    write_roots: tuple[Path, ...],
    now: int | None = None,
) -> Iterator[None]:
    """Admit exactly one trusted Code Mode sandbox Popen call."""

    moment = int(time.time()) if now is None else int(now)
    resolved_cwd = str(Path(cwd).expanduser().resolve(strict=True))
    if (
        type(capability) is not CodeModeSandboxExecutionCapability
        or _code_mode_sandbox_nonces.get(capability._nonce) != capability.capability_id
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or int(attempt) != capability.attempt
        or tuple(str(item) for item in argv) != capability.argv
        or resolved_cwd != capability.cwd
        or str(diff_hash) != capability.diff_hash
        or str(test_plan_hash) != capability.test_plan_hash
        or str(parent_authorization_hash) != capability.parent_authorization_hash
        or tuple(sorted(str(Path(item).expanduser().resolve(strict=True)) for item in read_roots)) != capability.read_roots
        or tuple(sorted(str(Path(item).expanduser().resolve(strict=True)) for item in write_roots)) != capability.write_roots
        or moment >= capability.expires_at
    ):
        raise LegacyWriteDenied("Code Mode sandbox capability is invalid, expired, or out of scope")
    del _code_mode_sandbox_nonces[capability._nonce]
    previous = getattr(_local, "code_mode_sandbox_execution", None)
    _local.code_mode_sandbox_execution = (capability, False)
    try:
        yield
    finally:
        _local.code_mode_sandbox_execution = previous


def _register_native_network_authority(owner: object) -> None:
    from sitina.loop.control import LoopControlAuthority
    from sitina.loop.coordinator import LoopBackend

    if type(owner) is not LoopControlAuthority or type(owner.backend) is not LoopBackend:
        raise LegacyWriteDenied("native network authority requires the live Loop owner")
    with _state_lock:
        current = _native_network_owners.get(id(owner.backend))
        if current is not None and current[0] is not owner:
            raise LegacyWriteDenied("native network authority already has another owner")
        _native_network_owners[id(owner.backend)] = (owner, os.getpid())


def _unregister_native_network_authority(owner: object) -> None:
    backend = getattr(owner, "backend", None)
    with _state_lock:
        current = _native_network_owners.get(id(backend))
        if current is not None and current[0] is owner:
            del _native_network_owners[id(backend)]
            revoked = [nonce for nonce, record in _network_egress_records.items() if record["backend"] is backend]
            for nonce in revoked:
                _network_egress_records.pop(nonce)
                _network_egress_nonces.discard(nonce)


def _native_network_binding(
    backend: object,
    task_id: str | None,
    *,
    obligation_id: str | None = None,
    request_id: str | None = None,
    attempt_count: int | None = None,
    candidate_id: str | None = None,
) -> dict[str, object]:
    from sitina.loop.control import LoopAuthorityLease, LoopControlAuthority
    from sitina.loop.coordinator import LoopBackend
    from sitina.loop.model import ControlIntent
    from sitina.loop.storage import LoopRuntimeContext

    if type(backend) is not LoopBackend or type(backend.context) is not LoopRuntimeContext:
        raise LegacyWriteDenied("native network authority requires the real LoopBackend")
    if obligation_id is None and any(
        value is not None for value in (request_id, attempt_count, candidate_id)
    ):
        raise LegacyWriteDenied("native obligation authority is incomplete")
    with _state_lock:
        registered = _native_network_owners.get(id(backend))
    if registered is None or registered[1] != os.getpid():
        raise LegacyWriteDenied("native network owner is not registered in this process")
    owner = registered[0]
    lease = getattr(owner, "_lease", None)
    obligation_binding: dict[str, object] = {}
    try:
        if (
            type(owner) is not LoopControlAuthority
            or owner.backend is not backend
            or type(lease) is not LoopAuthorityLease
            or lease._file is None or lease._file.closed
            or owner._stop.is_set() or not owner._authority_owned
            or owner._thread is None or not owner._thread.is_alive()
            or owner._socket is None or owner._socket.fileno() < 0
            or owner.state_root != backend.context.home
            or lease.state_root != owner.state_root
            or owner._socket.getsockname() != str(owner.socket_path)
        ):
            raise LegacyWriteDenied("native network owner or lease is no longer live")
        held = os.fstat(lease._file.fileno())
        current = lease.lock_path.stat()
        endpoint = owner.socket_path.lstat()
        if (
            (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)
            or (endpoint.st_dev, endpoint.st_ino) != owner._bound_endpoint_identity
            or backend.persistence_fenced
            or backend.run_instance_id != backend.context.run_instance_id
        ):
            raise LegacyWriteDenied("native network writer binding changed")
        with backend._state_lock:
            if obligation_id is None:
                task = backend.get_task(task_id)
                if (
                    task.is_terminal or task.control_intent is not ControlIntent.RUN
                    or task.run_instance_id != backend.run_instance_id
                    or any(operation.unknown_effect for operation in task.operations.values())
                ):
                    raise LegacyWriteDenied("native network task/run is not authorized")
            else:
                if (
                    not isinstance(obligation_id, str) or not obligation_id
                    or not isinstance(request_id, str) or not request_id
                    or type(attempt_count) is not int or attempt_count < 1
                    or (candidate_id is not None and (
                        not isinstance(candidate_id, str) or not candidate_id
                    ))
                ):
                    raise LegacyWriteDenied("native obligation dispatch identity is invalid")
                obligation = backend._experience_obligation_projection().get(obligation_id)
                if (
                    obligation is None
                    or obligation.get("obligation_type") != "EXPERIENCE_EXTRACTION"
                    or obligation.get("obligation_id") != obligation_id
                    or obligation.get("unknown_effect") is True
                ):
                    raise LegacyWriteDenied("native experience obligation is unavailable")
                source_task_id = obligation.get("task_id")
                if task_id is not None and task_id != source_task_id:
                    raise LegacyWriteDenied("native obligation source task differs")
                task = backend.get_task(source_task_id)
                terminal_events = tuple(
                    event for event in backend.store.task_events(task.task_id)
                    if event.event_type == "loop.task-terminated"
                )
                if not task.is_terminal or not terminal_events:
                    raise LegacyWriteDenied("native obligation has no terminal source")
                closure = backend._terminal_source_closure(task, terminal_events[-1])
                if (
                    _canonical(obligation.get("source_closure")) != _canonical(closure)
                    or obligation.get("actual_envelope_event_id") != closure["actual_envelope_event_id"]
                    or obligation.get("terminal_event_id") != closure["terminal_event_id"]
                    or obligation.get("processor_version") != closure["processor_version"]
                    or "EXPERIENCE_EXTRACTION" not in closure["obligation_types"]
                    or obligation_id != ":".join((
                        closure["terminal_event_id"], "EXPERIENCE_EXTRACTION",
                        closure["processor_version"],
                    ))
                ):
                    raise LegacyWriteDenied("native obligation terminal source differs")
                if candidate_id is None:
                    if (
                        obligation.get("state") != "DISPATCHED"
                        or obligation.get("dispatch_request_id") != request_id
                        or obligation.get("attempt_count") != attempt_count
                        or attempt_count > int(obligation.get("max_attempts") or 0)
                        or obligation.get("result_request_id") is not None
                    ):
                        raise LegacyWriteDenied("native extraction dispatch is no longer active")
                    provider_profile = obligation.get("provider_profile")
                else:
                    prior = (obligation.get("candidate_dispositions") or {}).get(candidate_id) or {}
                    revision = (obligation.get("candidate_revisions") or {}).get(candidate_id)
                    if (
                        obligation.get("state") != "CANDIDATE_REVIEW"
                        or obligation.get("review_request_id") != request_id
                        or obligation.get("review_candidate_id") != candidate_id
                        or candidate_id not in (obligation.get("candidate_ids") or ())
                        or not revision
                        or obligation.get("review_candidate_revision") != revision
                        or prior.get("disposition") not in {None, "NEEDS_WORK"}
                        or attempt_count != int(prior.get("attempt_count") or 0) + 1
                        or attempt_count > int(prior.get("max_attempts") or 3)
                        or not request_id.endswith(
                            f":candidate:{candidate_id}:attempt:{attempt_count}"
                        )
                    ):
                        raise LegacyWriteDenied("native candidate review is no longer active")
                    provider_profile = obligation.get("review_provider_profile")
                    obligation_binding.update({
                        "candidate_id": candidate_id,
                        "candidate_revision": revision,
                        "review_memory_binding_hash": hashlib.sha256(
                            _canonical(obligation.get("review_memory_binding"))
                        ).hexdigest(),
                    })
                if not isinstance(provider_profile, str) or not provider_profile:
                    raise LegacyWriteDenied("native obligation provider profile is missing")
                obligation_binding.update({
                    "obligation_id": obligation_id,
                    "request_id": request_id,
                    "attempt_count": attempt_count,
                    "provider_profile": provider_profile,
                    "source_closure_hash": closure["closure_hash"],
                    "terminal_event_id": closure["terminal_event_id"],
                    "actual_envelope_event_id": closure["actual_envelope_event_id"],
                })
    except LegacyWriteDenied:
        raise
    except Exception as error:
        raise LegacyWriteDenied("native network authority could not be verified") from error
    return {
        "state_root": str(backend.context.home),
        "journal_id": backend.context.journal_id,
        "run_instance_id": backend.run_instance_id,
        "task_id": task.task_id,
        "execution_epoch": task.execution_epoch,
        "goal_version": task.goal_version,
        "acceptance_version": task.acceptance_version,
        "handled_input_seq": task.handled_input_seq,
        "capability_snapshot_id": task.capability_snapshot_id,
        "owner_pid": os.getpid(),
        "lease_identity": [held.st_dev, held.st_ino],
        "endpoint_identity": list(owner._bound_endpoint_identity),
        **obligation_binding,
    }

def issue_frozen_network_egress_capability(
    authority_resolution: object,
    *,
    manifest_hash: str | None,
    operation: str,
    allowed_hosts: tuple[str, ...],
    expires_at: int,
    now: int | None = None,
    provider_name: str = "",
    credential_reference: str = "",
    _native_backend: object | None = None,
    _native_task_id: str | None = None,
    _native_obligation_id: str | None = None,
    _native_request_id: str | None = None,
    _native_attempt_count: int | None = None,
    _native_candidate_id: str | None = None,
) -> FrozenNetworkEgressCapability:
    """Issue an in-process grant from the existing Production or native owner."""

    moment = int(time.time()) if now is None else int(now)
    native_binding = None
    if _native_backend is not None:
        if authority_resolution is not None or (not _native_task_id and not _native_obligation_id):
            raise LegacyWriteDenied("native network authority must not impersonate Production")
        native_binding = _native_network_binding(
            _native_backend, _native_task_id,
            obligation_id=_native_obligation_id, request_id=_native_request_id,
            attempt_count=_native_attempt_count, candidate_id=_native_candidate_id,
        )
        if _native_obligation_id is not None and operation != "model_text_generation":
            raise LegacyWriteDenied("native obligation only authorizes model text generation")
        if operation not in {"model_text_generation", "tool_http_request"}:
            raise LegacyWriteDenied("native network operation is outside the allowlist")
        derived_manifest = hashlib.sha256(_canonical(native_binding)).hexdigest()
        if manifest_hash is not None and manifest_hash != derived_manifest:
            raise LegacyWriteDenied("native network manifest does not match its live task binding")
        manifest_hash = derived_manifest
    else:
        if any(value is not None for value in (
            _native_task_id, _native_obligation_id, _native_request_id,
            _native_attempt_count, _native_candidate_id,
        )):
            raise LegacyWriteDenied("native authority cannot be transferred to Production")
        try:
            authority_resolution.assert_fresh(now=moment)
            journal_authorized = bool(authority_resolution.authorizes_journal)
            writer_count = int(authority_resolution.writer_count)
        except Exception as error:
            raise LegacyWriteDenied("frozen network egress requires a fresh authority resolution") from error
        if not journal_authorized or writer_count != 1:
            raise LegacyWriteDenied("frozen network egress requires one Journal writer authority")
        if operation != "model_text_generation":
            raise LegacyWriteDenied("frozen network egress operation is outside the non-mutating allowlist")
    if not isinstance(manifest_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_hash):
        raise LegacyWriteDenied("frozen network egress requires an exact activation manifest hash")
    normalized = tuple(sorted({str(host).strip().lower() for host in allowed_hosts}))
    if not normalized or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
        or ".." in host or host.startswith(".") or host.endswith(".")
        for host in normalized
    ):
        raise LegacyWriteDenied("frozen network egress hosts are invalid")
    if expires_at <= moment or expires_at - moment > 3600:
        raise LegacyWriteDenied("frozen network egress expiry is invalid")
    if bool(provider_name) != bool(credential_reference):
        raise LegacyWriteDenied("network provider and credential reference must be bound together")
    if native_binding is not None and (not provider_name or not credential_reference):
        raise LegacyWriteDenied("native network grant requires provider and credential scope")
    nonce = os.urandom(32).hex()
    identity = hashlib.sha256(_canonical({
        "manifest_hash": manifest_hash,
        "operation": operation,
        "allowed_hosts": list(normalized),
        "expires_at": expires_at,
        "provider_name": provider_name,
        "credential_reference": credential_reference,
        "nonce_hash": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
    })).hexdigest()
    capability = FrozenNetworkEgressCapability(
        f"network-egress:{identity}", manifest_hash, operation, normalized, expires_at,
        nonce, provider_name, credential_reference,
    )
    with _state_lock:
        _network_egress_nonces.add(nonce)
        _network_egress_records[nonce] = {
            "capability": capability, "pid": os.getpid(),
            "authority": authority_resolution, "backend": _native_backend,
            "task_id": _native_task_id, "native_binding": native_binding,
            "obligation_id": _native_obligation_id, "request_id": _native_request_id,
            "attempt_count": _native_attempt_count, "candidate_id": _native_candidate_id,
            "credential_digest": None,
        }
    return capability


def _validate_network_capability(
    capability: FrozenNetworkEgressCapability | None,
    *, host: str, operation: str, provider_name: str = "",
    credential_reference: str = "", now: int | None = None,
    _native_renewal: bool = False,
) -> dict[str, Any]:
    moment = int(time.time()) if now is None else int(now)
    if type(capability) is not FrozenNetworkEgressCapability:
        raise LegacyWriteDenied("network access requires an issued capability")
    with _state_lock:
        record = _network_egress_records.get(capability._nonce)
    if (
        record is None or record["capability"] is not capability
        or record["pid"] != os.getpid() or capability._nonce not in _network_egress_nonces
        or capability.operation != operation
        or str(host).strip().lower() not in capability.allowed_hosts
        or capability.provider_name != provider_name
        or capability.credential_reference != credential_reference
        or (
            moment >= capability.expires_at
            and not (
                _native_renewal and record["backend"] is not None
                and record.get("obligation_id") is None
            )
        )
    ):
        raise LegacyWriteDenied("network capability is invalid, expired, or out of scope")
    if record["backend"] is not None:
        current = _native_network_binding(
            record["backend"], record["task_id"],
            obligation_id=record.get("obligation_id"), request_id=record.get("request_id"),
            attempt_count=record.get("attempt_count"), candidate_id=record.get("candidate_id"),
        )
        if current != record["native_binding"]:
            raise LegacyWriteDenied("network capability belongs to a stale native task/run")
    else:
        try:
            record["authority"].assert_fresh(now=moment)
            if not record["authority"].authorizes_journal or record["authority"].writer_count != 1:
                raise LegacyWriteDenied("network writer authority is no longer valid")
        except LegacyWriteDenied:
            raise
        except Exception as error:
            raise LegacyWriteDenied("network writer authority is stale") from error
    return record


def _renew_native_network_egress_capability(
    capability: FrozenNetworkEgressCapability,
    *, host: str, provider_name: str, credential_reference: str, token: str,
) -> FrozenNetworkEgressCapability:
    """Reissue only a live native task's same-scope, credential-bound grant.

    Expiry is ignored only while checking eligibility for a new grant. The
    old grant still cannot authorize a connection, and revoked, changed or
    unresolved task authority cannot be renewed.
    """

    record = _validate_network_capability(
        capability, host=host, operation="model_text_generation",
        provider_name=provider_name, credential_reference=credential_reference,
        _native_renewal=True,
    )
    if record["backend"] is None or record.get("obligation_id") is not None:
        raise LegacyWriteDenied("network renewal requires a live native task")
    if (
        not isinstance(token, str) or not token or record["credential_digest"] is None
        or not hmac.compare_digest(
            record["credential_digest"], hashlib.sha256(token.encode("utf-8")).digest(),
        )
    ):
        raise LegacyWriteDenied("network renewal requires the same authorized credential")
    renewed = issue_frozen_network_egress_capability(
        None, manifest_hash=capability.manifest_hash,
        operation=capability.operation, allowed_hosts=capability.allowed_hosts,
        expires_at=int(time.time()) + 1200,
        provider_name=capability.provider_name,
        credential_reference=capability.credential_reference,
        _native_backend=record["backend"], _native_task_id=record["task_id"],
    )
    with _state_lock:
        if (
            _network_egress_records.get(capability._nonce) is not record
            or capability._nonce not in _network_egress_nonces
        ):
            _network_egress_records.pop(renewed._nonce, None)
            _network_egress_nonces.discard(renewed._nonce)
            raise LegacyWriteDenied("network grant was revoked during renewal")
        _network_egress_records[renewed._nonce]["credential_digest"] = record["credential_digest"]
        _network_egress_records.pop(capability._nonce)
        _network_egress_nonces.discard(capability._nonce)
    return renewed


def _authorize_network_credential(
    capability: FrozenNetworkEgressCapability | None,
    *, host: str, provider_name: str, credential_reference: str,
    token: str | None = None,
) -> None:
    record = _validate_network_capability(
        capability, host=host, operation="model_text_generation",
        provider_name=provider_name, credential_reference=credential_reference,
    )
    if token is None:
        return
    if not isinstance(token, str) or not token:
        raise LegacyWriteDenied("network credential token is missing")
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    with _state_lock:
        if record["credential_digest"] is None or not hmac.compare_digest(record["credential_digest"], digest):
            raise LegacyWriteDenied("network token does not match the authorized credential read")


def _bind_network_credential(
    capability: FrozenNetworkEgressCapability | None,
    *, host: str, provider_name: str, credential_reference: str, token: str,
) -> None:
    record = _validate_network_capability(
        capability, host=host, operation="model_text_generation",
        provider_name=provider_name, credential_reference=credential_reference,
    )
    if not isinstance(token, str) or not token:
        raise LegacyWriteDenied("loaded network credential is empty")
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    with _state_lock:
        if record["credential_digest"] is not None and not hmac.compare_digest(record["credential_digest"], digest):
            raise LegacyWriteDenied("credential changed; a fresh authorization is required")
        record["credential_digest"] = digest


@contextlib.contextmanager
def authorized_frozen_network_egress(
    capability: FrozenNetworkEgressCapability | None,
    *, host: str, operation: str, now: int | None = None,
    provider_name: str = "", credential_reference: str = "",
) -> Iterator[None]:
    """Validate before the concrete connection, including non-frozen homes."""

    _validate_network_capability(
        capability, host=host, operation=operation, now=now,
        provider_name=provider_name, credential_reference=credential_reference,
    )
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
        code_mode_scope = getattr(_local, "code_mode_sandbox_execution", None)
        if code_mode_scope is not None:
            capability, used = code_mode_scope
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
                _local.code_mode_sandbox_execution = (capability, True)
                return
            raise LegacyWriteDenied("Legacy fence denies an out-of-scope Code Mode sandbox subprocess")
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
