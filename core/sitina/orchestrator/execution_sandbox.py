"""Capability-bound macOS OS sandbox for executing untrusted test code."""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from sitina.evidence.isolation_provider import ReplayIsolationProvider
from sitina.legacy.fence import (
    FrozenSandboxExecutionCapability,
    LegacyWriteGate,
    authorized_frozen_sandbox_execution,
    frozen_sandbox_profile,
    issue_frozen_sandbox_execution_capability,
)


class ExecutionSandboxError(RuntimeError):
    pass


class ExecutionSandboxUnavailable(ExecutionSandboxError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def hash_diff(paths: Sequence[Path]) -> tuple[str, tuple[tuple[str, str], ...]]:
    entries: list[tuple[str, str]] = []
    candidates = sorted((Path(path).expanduser().absolute() for path in paths), key=str)
    for candidate in candidates:
        if candidate.is_symlink():
            raise ExecutionSandboxError(f"sandbox target is a symlink: {candidate}")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            raise ExecutionSandboxError(f"sandbox target is not a regular file: {resolved}")
        entries.append((str(resolved), _sha256_file(resolved)))
    return _sha256_bytes(_canonical([[path, digest] for path, digest in entries])), tuple(entries)


@dataclass(frozen=True)
class SandboxResourceLimits:
    cpu_seconds: int = 10
    memory_bytes: int = 1024 * 1024 * 1024
    file_bytes: int = 2 * 1024 * 1024
    process_count: int = 1
    open_files: int = 64
    wall_seconds: int = 20

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in self.mapping().values()
        ):
            raise ValueError("sandbox resource limits must be positive integers")
        if self.wall_seconds > 120 or self.cpu_seconds > self.wall_seconds:
            raise ValueError("sandbox time limits are outside the bounded policy")

    def mapping(self) -> dict[str, int]:
        return {
            "cpu_seconds": self.cpu_seconds,
            "memory_bytes": self.memory_bytes,
            "file_bytes": self.file_bytes,
            "process_count": self.process_count,
            "open_files": self.open_files,
            "wall_seconds": self.wall_seconds,
        }

    def capability_items(self) -> tuple[tuple[str, int], ...]:
        return tuple(sorted(self.mapping().items()))


@dataclass(frozen=True)
class TestEvidence:
    run_id: str
    diff_hash_before: str
    diff_hash_after: str
    target_hashes: tuple[tuple[str, str], ...]
    collected_test_count: int
    executed_test_count: int
    passed_test_count: int
    failed_test_count: int
    skipped_test_count: int
    error_test_count: int
    expected_failure_count: int
    unexpected_success_count: int
    runner_return_code: int
    timed_out: bool
    runner_executable_hash: str
    python_executable_hash: str
    worker_hash: str
    argv_hash: str
    sandbox_policy_hash: str
    sandbox_provider_id: str
    sandbox_capability_id: str
    cwd: str
    read_roots: tuple[str, ...]
    write_roots: tuple[str, ...]
    resource_limits: tuple[tuple[str, int], ...]
    stdout_hash: str
    stderr_hash: str
    started_at: str
    finished_at: str
    duration_milliseconds: int

    def __post_init__(self) -> None:
        hashes = (
            self.diff_hash_before,
            self.diff_hash_after,
            self.runner_executable_hash,
            self.python_executable_hash,
            self.worker_hash,
            self.argv_hash,
            self.sandbox_policy_hash,
            self.stdout_hash,
            self.stderr_hash,
        )
        if any(len(value) != 64 or any(character not in "0123456789abcdef" for character in value) for value in hashes):
            raise ValueError("TestEvidence requires exact SHA-256 hashes")
        counts = (
            self.collected_test_count,
            self.executed_test_count,
            self.passed_test_count,
            self.failed_test_count,
            self.skipped_test_count,
            self.error_test_count,
            self.expected_failure_count,
            self.unexpected_success_count,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("TestEvidence counts must be non-negative integers")

    @property
    def execution_complete(self) -> bool:
        return self.collected_test_count > 0 and self.executed_test_count == self.collected_test_count

    @property
    def accepted(self) -> bool:
        return (
            self.runner_return_code == 0
            and not self.timed_out
            and self.diff_hash_before == self.diff_hash_after
            and self.execution_complete
            and self.passed_test_count == self.executed_test_count
            and self.failed_test_count == 0
            and self.skipped_test_count == 0
            and self.error_test_count == 0
            and self.expected_failure_count == 0
            and self.unexpected_success_count == 0
        )

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "SITINA_TEST_EVIDENCE_V1",
            "run_id": self.run_id,
            "diff_hash_before": self.diff_hash_before,
            "diff_hash_after": self.diff_hash_after,
            "target_hashes": [[path, digest] for path, digest in self.target_hashes],
            "collected_test_count": self.collected_test_count,
            "executed_test_count": self.executed_test_count,
            "passed_test_count": self.passed_test_count,
            "failed_test_count": self.failed_test_count,
            "skipped_test_count": self.skipped_test_count,
            "error_test_count": self.error_test_count,
            "expected_failure_count": self.expected_failure_count,
            "unexpected_success_count": self.unexpected_success_count,
            "runner_return_code": self.runner_return_code,
            "timed_out": self.timed_out,
            "runner_executable_hash": self.runner_executable_hash,
            "python_executable_hash": self.python_executable_hash,
            "worker_hash": self.worker_hash,
            "argv_hash": self.argv_hash,
            "sandbox_policy_hash": self.sandbox_policy_hash,
            "sandbox_provider_id": self.sandbox_provider_id,
            "sandbox_capability_id": self.sandbox_capability_id,
            "cwd": self.cwd,
            "read_roots": list(self.read_roots),
            "write_roots": list(self.write_roots),
            "resource_limits": {name: value for name, value in self.resource_limits},
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_milliseconds": self.duration_milliseconds,
            "execution_complete": self.execution_complete,
            "accepted": self.accepted,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical(self.mapping())

    @property
    def evidence_hash(self) -> str:
        return _sha256_bytes(self.canonical_bytes())


class TestEvidencePublisher(Protocol):
    def publish(self, raw: bytes, *, evidence_hash: str) -> str: ...


class FilesystemTestEvidencePublisher:
    """Content-addressed no-replace publisher used by isolated verification tests."""

    def __init__(self, root: Path):
        self.root = Path(root).expanduser().resolve(strict=False)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ExecutionSandboxError("test evidence root is unsafe")

    def publish(self, raw: bytes, *, evidence_hash: str) -> str:
        if _sha256_bytes(raw) != evidence_hash:
            raise ExecutionSandboxError("test evidence publication hash mismatch")
        target = self.root / f"{evidence_hash}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target, flags, 0o400)
        except FileExistsError:
            if target.is_symlink() or target.read_bytes() != raw:
                raise ExecutionSandboxError("test evidence identity collision")
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        return "test-evidence:" + evidence_hash


class CASTestEvidencePublisher:
    """Publish encrypted evidence through the production no-replace CAS."""

    def __init__(self, cas: Any, keys: Any):
        self.cas = cas
        self.keys = keys

    def publish(self, raw: bytes, *, evidence_hash: str) -> str:
        if _sha256_bytes(raw) != evidence_hash:
            raise ExecutionSandboxError("test evidence publication hash mismatch")
        from sitina.cas.crypto import encrypt_object
        from sitina.cas.model import CASError
        from sitina.security.key_provider import KeyProviderError

        try:
            receipt = self.cas.publish_verified(
                encrypt_object(raw, self.keys, tenant_id="sitina-execution", purpose="test-evidence")
            )
        except (CASError, KeyProviderError, OSError, ValueError) as error:
            raise ExecutionSandboxError("immutable CAS test evidence publication failed") from error
        reference = receipt.object_ref.reference_id
        if not receipt.fresh_verified or not receipt.no_replace_published:
            raise ExecutionSandboxError("CAS did not prove immutable test evidence publication")
        return reference


@dataclass(frozen=True)
class _Invocation:
    response: Mapping[str, Any] | None
    return_code: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    argv_hash: str
    policy_hash: str
    capability_id: str
    duration_milliseconds: int


class ExecutionSandboxRunner:
    WORKER_MARKER = "SITINA_SANDBOX_WORKER_RESULT:"

    def __init__(
        self,
        *,
        home: Path,
        authority_resolution: object | None = None,
        fixture_authorization: bool = False,
        sandbox_executable: Path = Path("/usr/bin/sandbox-exec"),
        python_executable: Path = Path(sys.executable),
        worker_path: Path | None = None,
        limits: SandboxResourceLimits | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.authority_resolution = authority_resolution
        self.fixture_authorization = fixture_authorization
        self.sandbox_executable = Path(sandbox_executable).expanduser().resolve(strict=True)
        self.python_executable = Path(python_executable).expanduser().resolve(strict=True)
        self.worker_path = Path(worker_path or Path(__file__).with_name("execution_sandbox_worker.py")).resolve(strict=True)
        self.limits = limits or SandboxResourceLimits()
        if platform.system() != "Darwin" or self.sandbox_executable != Path("/usr/bin/sandbox-exec"):
            raise ExecutionSandboxUnavailable("qualified macOS sandbox-exec is unavailable")
        for candidate in (self.sandbox_executable, self.python_executable, self.worker_path):
            if candidate.is_symlink() or not candidate.is_file():
                raise ExecutionSandboxUnavailable(f"sandbox executable is unsafe: {candidate}")
        self.runner_hash = _sha256_file(self.sandbox_executable)
        self.python_hash = _sha256_file(self.python_executable)
        self.worker_hash = _sha256_file(self.worker_path)

    def _profile(self, read_roots: tuple[Path, ...], write_roots: tuple[Path, ...]) -> str:
        return frozen_sandbox_profile(
            self.python_executable, self.worker_path, read_roots, write_roots
        )

    def _capability(
        self,
        *,
        run_id: str,
        diff_hash: str,
        argv: tuple[str, ...],
        cwd: Path,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
        policy_hash: str,
    ) -> FrozenSandboxExecutionCapability | None:
        if LegacyWriteGate(self.home).status().state != "FROZEN_NO_WRITER":
            return None
        return issue_frozen_sandbox_execution_capability(
            self.authority_resolution,
            home=self.home,
            run_id=run_id,
            diff_hash=diff_hash,
            runner_executable=self.sandbox_executable,
            python_executable=self.python_executable,
            worker_path=self.worker_path,
            argv=argv,
            cwd=cwd,
            read_roots=read_roots,
            write_roots=write_roots,
            sandbox_policy_hash=policy_hash,
            resource_limits=self.limits.capability_items(),
            expires_at=int(time.time()) + min(120, self.limits.wall_seconds + 30),
            fixture_authorization=self.fixture_authorization,
        )

    @staticmethod
    def _signal_sandbox(process: subprocess.Popen[bytes], requested_signal: signal.Signals) -> None:
        """Signal the whole sandbox, with a safe exact-PID Darwin fallback.

        The worker's kernel RLIMIT_NPROC=1 and the qualified Seatbelt profile
        both deny descendants.  Some Darwin releases nevertheless return EPERM
        for killpg() across the Seatbelt boundary; in that case the runner PID
        is the entire sandbox process tree and is safe to signal directly.
        """

        try:
            os.killpg(process.pid, requested_signal)
            return
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        try:
            os.kill(process.pid, requested_signal)
        except ProcessLookupError:
            return

    def _invoke(
        self,
        request: dict[str, object],
        *,
        run_id: str,
        diff_hash: str,
        cwd: Path,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
        scratch: Path,
    ) -> _Invocation:
        result_token = uuid.uuid4().hex
        request = {**request, "result_token": result_token, "resource_limits": self.limits.mapping()}
        encoded_request = base64.urlsafe_b64encode(_canonical(request)).decode("ascii")
        profile = self._profile(read_roots, write_roots)
        policy_hash = _sha256_bytes(profile.encode("utf-8"))
        argv = (
            str(self.sandbox_executable),
            "-p",
            profile,
            str(self.python_executable),
            "-I",
            "-S",
            str(self.worker_path),
            "--request",
            encoded_request,
        )
        argv_hash = _sha256_bytes(_canonical(list(argv)))
        capability = self._capability(
            run_id=run_id,
            diff_hash=diff_hash,
            argv=argv,
            cwd=cwd,
            read_roots=read_roots,
            write_roots=write_roots,
            policy_hash=policy_hash,
        )
        stem = uuid.uuid4().hex
        stdout_path = scratch / f"{stem}.stdout"
        stderr_path = scratch / f"{stem}.stderr"
        environment = {
            "HOME": str(scratch),
            "TMPDIR": str(scratch),
            "PATH": "",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
        }
        started = time.monotonic()
        timed_out = False
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            with authorized_frozen_sandbox_execution(capability, argv=argv, cwd=cwd, diff_hash=diff_hash):
                try:
                    process = subprocess.Popen(
                        list(argv),
                        cwd=cwd,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        close_fds=True,
                        start_new_session=True,
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    raise ExecutionSandboxUnavailable("OS sandbox runner could not start") from error
            try:
                return_code = process.wait(timeout=self.limits.wall_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._signal_sandbox(process, signal.SIGTERM)
                try:
                    return_code = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._signal_sandbox(process, signal.SIGKILL)
                    return_code = process.wait()
                return_code = 124
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = stdout_path.read_bytes()[: self.limits.file_bytes]
        stderr = stderr_path.read_bytes()[: self.limits.file_bytes]
        prefix = self.WORKER_MARKER + result_token + ":"
        matches = [line[len(prefix):] for line in stdout.decode("utf-8", errors="replace").splitlines() if line.startswith(prefix)]
        response: Mapping[str, Any] | None = None
        if len(matches) == 1:
            try:
                decoded = base64.urlsafe_b64decode(matches[0].encode("ascii"))
                candidate = json.loads(decoded)
            except Exception:
                candidate = None
            if isinstance(candidate, dict):
                response = candidate
        return _Invocation(
            response=response,
            return_code=return_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            argv_hash=argv_hash,
            policy_hash=policy_hash,
            capability_id=capability.capability_id if capability else "sandbox-direct-nonfrozen",
            duration_milliseconds=duration_ms,
        )

    def _qualify(
        self,
        *,
        run_id: str,
        diff_hash: str,
        cwd: Path,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
        scratch: Path,
    ) -> str:
        outside_write = scratch.parent / f"sitina-sandbox-denied-{uuid.uuid4().hex}"
        outside_read = scratch.parent / f"sitina-sandbox-read-probe-{uuid.uuid4().hex}"
        outside_read.write_bytes(b"sandbox-read-must-be-denied")
        link = scratch / "escape-link"
        link.symlink_to(scratch.parent, target_is_directory=True)
        try:
            probe = self._invoke(
                {
                    "mode": "probe",
                    "outside_read": str(outside_read),
                    "outside_write": str(outside_write),
                    "symlink_escape": str(link / outside_write.name),
                },
                run_id=run_id + ":probe",
                diff_hash=diff_hash,
                cwd=cwd,
                read_roots=read_roots,
                write_roots=write_roots,
                scratch=scratch,
            )
        finally:
            with contextlib.suppress(OSError):
                outside_read.unlink()
        if outside_write.exists():
            with contextlib.suppress(OSError):
                outside_write.unlink()
            raise ExecutionSandboxUnavailable("sandbox qualification allowed an out-of-scope write")
        response = probe.response or {}
        results = response.get("results") if isinstance(response.get("results"), dict) else {}
        if probe.return_code != 0 or response.get("worker_ok") is not True:
            raise ExecutionSandboxUnavailable("sandbox qualification worker failed")
        guarantees = {
            "network_denied": bool(results.get("socket") and results.get("dns")),
            "process_spawn_denied": bool(results.get("subprocess")),
            "ffi_denied": bool(results.get("ctypes")),
            "write_scope_confined": bool(results.get("absolute_write") and results.get("symlink_escape")),
            "read_scope_confined": bool(results.get("absolute_read")),
            "device_denied": bool(results.get("device")),
            "inherited_authority_denied": bool(results.get("inherited_fd")),
        }
        try:
            provider = ReplayIsolationProvider.qualified(
                "macos-seatbelt-sandbox-exec-v1",
                kernel_enforced=True,
                guarantees=guarantees,
                adversarial_results={name: bool(results.get(name)) for name in ReplayIsolationProvider.REQUIRED_ADVERSARIAL_TESTS},
            )
        except ValueError as error:
            raise ExecutionSandboxUnavailable("OS sandbox failed adversarial qualification") from error
        return provider.provider_id

    def run_tests(
        self,
        paths: Sequence[Path],
        *,
        run_id: str,
        diff_paths: Sequence[Path] | None = None,
    ) -> TestEvidence:
        raw_targets = tuple(Path(path).expanduser().absolute() for path in paths)
        if any(path.is_symlink() for path in raw_targets):
            raise ExecutionSandboxError("sandbox test target may not be a symlink")
        targets = tuple(path.resolve(strict=True) for path in raw_targets)
        if not targets:
            raise ExecutionSandboxError("sandbox test execution requires targets")
        raw_diff_paths = tuple(
            Path(path).expanduser().absolute() for path in (diff_paths if diff_paths is not None else paths)
        )
        if not raw_diff_paths or any(path.is_symlink() for path in raw_diff_paths):
            raise ExecutionSandboxError("sandbox diff evidence paths are invalid")
        evidence_paths = tuple(path.resolve(strict=True) for path in raw_diff_paths)
        if any(path not in evidence_paths for path in targets):
            raise ExecutionSandboxError("sandbox test target is not bound into the diff evidence")
        diff_before, target_hashes = hash_diff(evidence_paths)
        common = Path(os.path.commonpath([str(path) for path in evidence_paths])).resolve(strict=True)
        cwd = common if common.is_dir() else common.parent
        if len(cwd.parts) < 4:
            raise ExecutionSandboxError("sandbox diff does not have a narrowly confined workspace root")
        if any(not _inside(path, cwd) for path in targets):
            raise ExecutionSandboxError("sandbox targets do not share a confined workspace")
        read_roots = (cwd,)
        scratch = Path(tempfile.mkdtemp(prefix="sitina-test-sandbox-")).resolve(strict=True)
        write_roots = (scratch,)
        started_at = _utc_now()
        total_started = time.monotonic()
        try:
            provider_id = self._qualify(
                run_id=run_id,
                diff_hash=diff_before,
                cwd=cwd,
                read_roots=read_roots,
                write_roots=write_roots,
                scratch=scratch,
            )
            raw_targets: list[dict[str, str]] = []
            for path in targets:
                source = path.read_text(encoding="utf-8", errors="strict")
                mode = "unittest" if "test_" in path.name else "doctest"
                if mode == "doctest" and ">>>" not in source:
                    continue
                raw_targets.append({"path": str(path), "mode": mode})
            if not raw_targets:
                raise ExecutionSandboxError("no executable test evidence")
            invocation = self._invoke(
                {"mode": "tests", "targets": raw_targets, "read_roots": [str(root) for root in read_roots]},
                run_id=run_id,
                diff_hash=diff_before,
                cwd=cwd,
                read_roots=read_roots,
                write_roots=write_roots,
                scratch=scratch,
            )
            response = invocation.response or {}
            counts = response.get("counts") if isinstance(response.get("counts"), dict) else {}
            worker_ok = response.get("worker_ok") is True
            diff_after, _after_hashes = hash_diff(evidence_paths)
            finished_at = _utc_now()
            duration_ms = int((time.monotonic() - total_started) * 1000)
            return TestEvidence(
                run_id=run_id,
                diff_hash_before=diff_before,
                diff_hash_after=diff_after,
                target_hashes=target_hashes,
                collected_test_count=int(counts.get("collected", 0) or 0),
                executed_test_count=int(counts.get("executed", 0) or 0),
                passed_test_count=int(counts.get("passed", 0) or 0),
                failed_test_count=int(counts.get("failed", 0) or 0),
                skipped_test_count=int(counts.get("skipped", 0) or 0),
                error_test_count=int(counts.get("errors", 0) or 0) + (0 if worker_ok else 1),
                expected_failure_count=int(counts.get("expected_failures", 0) or 0),
                unexpected_success_count=int(counts.get("unexpected_successes", 0) or 0),
                runner_return_code=invocation.return_code,
                timed_out=invocation.timed_out,
                runner_executable_hash=self.runner_hash,
                python_executable_hash=self.python_hash,
                worker_hash=self.worker_hash,
                argv_hash=invocation.argv_hash,
                sandbox_policy_hash=invocation.policy_hash,
                sandbox_provider_id=provider_id,
                sandbox_capability_id=invocation.capability_id,
                cwd=str(cwd),
                read_roots=tuple(str(root) for root in read_roots),
                write_roots=tuple(str(root) for root in write_roots),
                resource_limits=self.limits.capability_items(),
                stdout_hash=_sha256_bytes(invocation.stdout),
                stderr_hash=_sha256_bytes(invocation.stderr),
                started_at=started_at,
                finished_at=finished_at,
                duration_milliseconds=duration_ms,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
