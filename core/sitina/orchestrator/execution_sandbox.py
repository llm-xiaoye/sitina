"""Capability-bound macOS OS sandbox for executing untrusted test code.

The parent controller owns planning, process lifecycle, protocol cardinality,
schema/count validation and final attestation.  An exact capability/hash-bound
supervisor owns the one-use HMAC key but never imports or executes target code.
For tests it launches one Seatbelt-confined process per sealed item and builds
the structured observation outside those processes from their exact mapping
and raw stdout/stderr.  A hash-bound UTF-8 PURE_DOCTEST AST subset excludes
imports, reflection, process control, descriptors, and observer primitives;
the exact admitted bytes are compiled directly without a path loader or pyc.
Target code receives neither the signing key nor a structured result channel.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import datetime as dt
import doctest
import hashlib
import hmac
import json
import os
import platform
import select
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
    CodeModeSandboxExecutionCapability,
    FrozenSandboxExecutionCapability,
    LegacyWriteGate,
    authorized_frozen_sandbox_execution,
    authorized_code_mode_sandbox_execution,
    frozen_sandbox_profile,
    issue_frozen_sandbox_execution_capability,
)
from sitina.orchestrator.execution_bridge import ExecutionIdentityBinding


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


def _test_case_classes(tree: ast.Module) -> set[str]:
    """Resolve local unittest.TestCase subclasses without importing target code."""

    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    resolved: set[str] = set()
    pending = set(classes)
    while pending:
        progressed = False
        for name in tuple(pending):
            node = classes[name]
            bases = {
                base.id
                for base in node.bases
                if isinstance(base, ast.Name)
            } | {
                base.attr
                for base in node.bases
                if isinstance(base, ast.Attribute)
            }
            if "TestCase" in bases or bases.intersection(resolved):
                resolved.add(name)
                pending.remove(name)
                progressed = True
        if not progressed:
            break
    return resolved


def _trusted_test_plan(paths: Sequence[Path]) -> tuple[dict[str, object], str]:
    """Build and seal the executable TestPlan before target modules are loaded."""

    parser = doctest.DocTestParser()
    planned_targets: list[dict[str, object]] = []
    collected = 0
    for ordinal, path in enumerate(paths):
        source_bytes = path.read_bytes()
        source = source_bytes.decode("utf-8", errors="strict")
        tree = ast.parse(source, filename=str(path))
        mode = "unittest" if path.name.startswith("test_") and path.suffix == ".py" else "doctest"
        planned_ids: list[str] = []
        planned_examples: list[dict[str, object]] = []
        if mode == "unittest":
            test_classes = _test_case_classes(tree)
            for node in sorted(
                (item for item in tree.body if isinstance(item, ast.ClassDef)),
                key=lambda item: item.name,
            ):
                if not isinstance(node, ast.ClassDef) or node.name not in test_classes:
                    continue
                for member in sorted(
                    (
                        item
                        for item in node.body
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name.startswith("test")
                    ),
                    key=lambda item: item.name,
                ):
                    planned_ids.append(
                        f"_sitina_sandbox_target_{ordinal}.{node.name}.{member.name}"
                    )
            expected_count = len(planned_ids)
        else:
            documented_nodes = sorted(
                (
                    node
                    for node in ast.walk(tree)
                    if isinstance(
                        node,
                        (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
                    )
                ),
                key=lambda node: (
                    int(getattr(node, "lineno", 0)),
                    int(getattr(node, "col_offset", 0)),
                    type(node).__name__,
                    str(getattr(node, "name", "")),
                ),
            )
            for node in documented_nodes:
                docstring = ast.get_docstring(node, clean=False)
                if docstring:
                    for example in parser.get_examples(docstring):
                        options = [
                            [int(flag), bool(enabled)]
                            for flag, enabled in sorted(example.options.items())
                        ]
                        identity = {
                            "source": example.source,
                            "want": example.want,
                            "exc_msg": example.exc_msg,
                            "options": options,
                        }
                        planned_examples.append(
                            {
                                "index": len(planned_examples),
                                "fingerprint": _sha256_bytes(_canonical(identity)),
                                "want": example.want,
                                "exc_msg": example.exc_msg,
                                "options": options,
                            }
                        )
            expected_count = len(planned_examples)
        collected += expected_count
        planned_targets.append(
            {
                "index": ordinal,
                "path": str(path),
                "mode": mode,
                "source_hash": _sha256_bytes(source_bytes),
                "expected_count": expected_count,
                "planned_test_ids": planned_ids,
                "planned_examples": planned_examples,
            }
        )
    plan: dict[str, object] = {
        "schema": "SITINA_TRUSTED_TEST_PLAN_V1",
        "execution_contract": "HASH_BOUND_UTF8_PURE_DOCTEST_AST_SUBSET_V1",
        "targets": planned_targets,
        "collected_test_count": collected,
    }
    if collected <= 0:
        raise ExecutionSandboxError("trusted TestPlan contains zero executable tests")
    return plan, _sha256_bytes(_canonical(plan))


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
    test_plan_hash: str
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
    identity: ExecutionIdentityBinding
    controller_protocol_response_present: bool
    controller_protocol_key_hash: str
    controller_response_hash: str
    controller_attestation_hash: str
    cwd: str
    read_roots: tuple[str, ...]
    write_roots: tuple[str, ...]
    resource_limits: tuple[tuple[str, int], ...]
    stdout_hash: str
    stderr_hash: str
    started_at: str
    finished_at: str
    duration_milliseconds: int
    runner_argv: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        hashes = (
            self.test_plan_hash,
            self.diff_hash_before,
            self.diff_hash_after,
            self.runner_executable_hash,
            self.python_executable_hash,
            self.worker_hash,
            self.argv_hash,
            self.sandbox_policy_hash,
            self.controller_protocol_key_hash,
            self.controller_response_hash,
            self.controller_attestation_hash,
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
        if not isinstance(self.controller_protocol_response_present, bool):
            raise ValueError("TestEvidence controller response presence must be boolean")
        if type(self.identity) is not ExecutionIdentityBinding:
            raise ValueError("TestEvidence execution identity binding is invalid")
        if not isinstance(self.runner_argv, tuple) or any(
            not isinstance(value, str) or not value for value in self.runner_argv
        ):
            raise ValueError("TestEvidence runner argv is invalid")
        if self.runner_argv and _sha256_bytes(_canonical(list(self.runner_argv))) != self.argv_hash:
            raise ValueError("TestEvidence runner argv is not bound to argv hash")
        if not self.controller_attestation_valid:
            raise ValueError("TestEvidence controller attestation is invalid")

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
            and self.controller_attestation_valid
        )

    @property
    def controller_attestation_valid(self) -> bool:
        expected = _sha256_bytes(
            _canonical(
                {
                    "schema": "SITINA_SANDBOX_CONTROLLER_ATTESTATION_V2",
                    "controller_identity": self.sandbox_capability_id,
                    "diff_hash": self.diff_hash_before,
                    "test_plan_hash": self.test_plan_hash,
                    "execution_identity_hash": self.identity.binding_hash,
                    "protocol_key_hash": self.controller_protocol_key_hash,
                    "response_hash": self.controller_response_hash,
                    "worker_hash": self.worker_hash,
                    "argv_hash": self.argv_hash,
                    "runner_return_code": self.runner_return_code,
                    "timed_out": self.timed_out,
                    "protocol_response_present": self.controller_protocol_response_present,
                }
            )
        )
        return self.controller_attestation_hash == expected

    def mapping(self) -> dict[str, object]:
        unittest_runner = (
            len(self.runner_argv) >= 3 and self.runner_argv[1:3] == ("-m", "unittest")
        )
        return {
            "schema": "SITINA_TEST_EVIDENCE_V2",
            "run_id": self.run_id,
            "test_plan_hash": self.test_plan_hash,
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
            "runner_argv": list(self.runner_argv),
            "sandbox_policy_hash": self.sandbox_policy_hash,
            "sandbox_provider_id": self.sandbox_provider_id,
            "sandbox_capability_id": self.sandbox_capability_id,
            "execution_identity": self.identity.mapping(),
            "execution_identity_hash": self.identity.binding_hash,
            "controller_protocol_response_present": self.controller_protocol_response_present,
            "controller_protocol_key_hash": self.controller_protocol_key_hash,
            "controller_response_hash": self.controller_response_hash,
            "controller_attestation_hash": self.controller_attestation_hash,
            "controller_attestation_valid": self.controller_attestation_valid,
            "trust_boundary": {
                "schema": "SITINA_SANDBOX_TRUST_BOUNDARY_V1",
                "trusted_controller_owns_sealed_plan_protocol_and_verdict": True,
                "trusted_controller_computes_counts_from_item_observations": not unittest_runner,
                "executor_reports_aggregate_test_verdict": False,
                "generic_unittest_result_source": (
                    "CONTROLLER_PARSED_HASH_BOUND_WORKER_OUTPUT_V1"
                    if unittest_runner
                    else "FAIL_CLOSED_UNSUPPORTED"
                ),
                "supported_result_source": (
                    "CONTROLLER_PARSED_STDLIB_UNITTEST_SUMMARY_V1"
                    if unittest_runner
                    else "SUPERVISOR_OBSERVED_PURE_DOCTEST_BYTES_V2"
                ),
                "signing_supervisor_is_exact_hash_bound_tcb": True,
                "signing_supervisor_executes_target_code": False,
                "target_executor_is_separate_process": True,
                "one_seatbelt_process_per_attempted_item": True,
                "structured_observations_constructed_outside_target_process": True,
                "target_result_channel_access": (
                    "CONTROLLER_SEES_BOUNDED_HASH_BOUND_STDOUT_SUMMARY"
                    if unittest_runner
                    else "NONE_RAW_STDOUT_STDERR_ONLY"
                ),
                "target_lifecycle_channel_access": "NONE",
                "execution_contract": (
                    "HASH_BOUND_UTF8_UNITTEST_TARGET_AST_PLAN_V1"
                    if unittest_runner
                    else "HASH_BOUND_UTF8_PURE_DOCTEST_AST_SUBSET_V1"
                ),
                "target_source_execution": "SINGLE_READ_BYTES_COMPILE_EXEC_NO_PATH_LOADER_OR_PYC",
                "completion_owner": "SIGNING_SUPERVISOR_NEVER_EXECUTES_TARGET_CODE",
                "target_can_access_completion_primitive": False,
                "target_exit_status_alone_can_signal_completion": False,
                "item_exception_source": "SUPERVISOR_OBSERVED_PURE_DOCTEST_EXIT_AND_RAW_STDERR",
                "target_receives_sealed_expected_output": False,
                "target_protocol_key_exposure": "NEVER_PASSED_TO_EXECUTOR_PROCESS",
                "authenticated_channel": "ONE_USE_CONTROLLER_KEYED_HMAC_SHA256_SEPARATE_SUPERVISOR_PROCESS",
                "target_cannot_frame_introspect_signing_supervisor": True,
            },
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


@dataclass(frozen=True)
class ArtifactEvidence:
    """Immutable evidence that a produced artifact was verified by real observation.

    Peer of :class:`TestEvidence` for goals that produce a concrete artifact but
    carry no executable test suite.  Every count and digest comes from reading
    the bytes back off disk, and optionally from executing the artifact in a
    separate process and hashing its real stdout.  No field is a placeholder: a
    path that cannot be read back, or whose bytes disagree with the sealed
    expectation, is counted as such and the evidence is not ``accepted``.
    """

    run_id: str
    artifact_plan_hash: str
    diff_hash_before: str
    diff_hash_after: str
    target_hashes: tuple[tuple[str, str], ...]
    readback_hashes: tuple[tuple[str, str], ...]
    expected_content_hashes: tuple[tuple[str, str], ...]
    verified_path_count: int
    matched_path_count: int
    mismatched_path_count: int
    unreadable_path_count: int
    execution_performed: bool
    execution_return_code: int
    execution_timed_out: bool
    execution_stdout_hash: str
    execution_stderr_hash: str
    expected_stdout_hash: str
    stdout_matched: bool
    runner_executable_hash: str
    python_executable_hash: str
    worker_hash: str
    argv_hash: str
    sandbox_policy_hash: str
    sandbox_provider_id: str
    sandbox_capability_id: str
    identity: ExecutionIdentityBinding
    controller_protocol_response_present: bool
    controller_protocol_key_hash: str
    controller_response_hash: str
    controller_attestation_hash: str
    cwd: str
    read_roots: tuple[str, ...]
    write_roots: tuple[str, ...]
    resource_limits: tuple[tuple[str, int], ...]
    started_at: str
    finished_at: str
    duration_milliseconds: int
    runner_argv: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        hashes = (
            self.artifact_plan_hash,
            self.diff_hash_before,
            self.diff_hash_after,
            self.runner_executable_hash,
            self.python_executable_hash,
            self.worker_hash,
            self.argv_hash,
            self.sandbox_policy_hash,
            self.controller_protocol_key_hash,
            self.controller_response_hash,
            self.controller_attestation_hash,
            self.execution_stdout_hash,
            self.execution_stderr_hash,
            self.expected_stdout_hash,
        )
        if any(len(value) != 64 or any(character not in "0123456789abcdef" for character in value) for value in hashes):
            raise ValueError("ArtifactEvidence requires exact SHA-256 hashes")
        counts = (
            self.verified_path_count,
            self.matched_path_count,
            self.mismatched_path_count,
            self.unreadable_path_count,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("ArtifactEvidence counts must be non-negative integers")
        if (
            self.matched_path_count + self.mismatched_path_count + self.unreadable_path_count
            != self.verified_path_count
        ):
            raise ValueError("ArtifactEvidence counts do not reconcile with the verified path total")
        for flag in (
            self.execution_performed,
            self.execution_timed_out,
            self.stdout_matched,
            self.controller_protocol_response_present,
        ):
            if not isinstance(flag, bool):
                raise ValueError("ArtifactEvidence flags must be boolean")
        if type(self.identity) is not ExecutionIdentityBinding:
            raise ValueError("ArtifactEvidence execution identity binding is invalid")
        for label, entries in (
            ("readback", self.readback_hashes),
            ("expected content", self.expected_content_hashes),
            ("target", self.target_hashes),
        ):
            if not isinstance(entries, tuple) or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0]
                or not isinstance(item[1], str)
                or len(item[1]) != 64
                for item in entries
            ):
                raise ValueError(f"ArtifactEvidence {label} hashes are invalid")
        if len(self.readback_hashes) != self.verified_path_count:
            raise ValueError("ArtifactEvidence readback hashes do not match the verified path count")
        if not isinstance(self.runner_argv, tuple) or any(
            not isinstance(value, str) or not value for value in self.runner_argv
        ):
            raise ValueError("ArtifactEvidence runner argv is invalid")
        if self.runner_argv and _sha256_bytes(_canonical(list(self.runner_argv))) != self.argv_hash:
            raise ValueError("ArtifactEvidence runner argv is not bound to argv hash")
        if self.execution_performed and not self.runner_argv:
            raise ValueError("ArtifactEvidence claims execution without a bound argv")
        if not self.execution_performed and (
            self.execution_return_code != 0 or self.execution_timed_out or self.stdout_matched
        ):
            raise ValueError("ArtifactEvidence execution fields are set without an execution")
        if not self.controller_attestation_valid:
            raise ValueError("ArtifactEvidence controller attestation is invalid")

    @property
    def controller_attestation_valid(self) -> bool:
        expected = _sha256_bytes(
            _canonical(
                {
                    "schema": "SITINA_SANDBOX_ARTIFACT_ATTESTATION_V1",
                    "controller_identity": self.sandbox_capability_id,
                    "diff_hash": self.diff_hash_before,
                    "artifact_plan_hash": self.artifact_plan_hash,
                    "execution_identity_hash": self.identity.binding_hash,
                    "protocol_key_hash": self.controller_protocol_key_hash,
                    "response_hash": self.controller_response_hash,
                    "worker_hash": self.worker_hash,
                    "argv_hash": self.argv_hash,
                    "readback_hashes": [[path, digest] for path, digest in self.readback_hashes],
                    "execution_performed": self.execution_performed,
                    "execution_return_code": self.execution_return_code,
                    "execution_timed_out": self.execution_timed_out,
                    "stdout_hash": self.execution_stdout_hash,
                    "protocol_response_present": self.controller_protocol_response_present,
                }
            )
        )
        return self.controller_attestation_hash == expected

    @property
    def verification_complete(self) -> bool:
        return self.verified_path_count > 0 and self.matched_path_count == self.verified_path_count

    @property
    def accepted(self) -> bool:
        if self.execution_performed and (
            self.execution_return_code != 0 or self.execution_timed_out or not self.stdout_matched
        ):
            return False
        return (
            self.verification_complete
            and self.mismatched_path_count == 0
            and self.unreadable_path_count == 0
            and self.diff_hash_before == self.diff_hash_after
            and self.controller_attestation_valid
        )

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "SITINA_ARTIFACT_EVIDENCE_V1",
            "run_id": self.run_id,
            "artifact_plan_hash": self.artifact_plan_hash,
            "diff_hash_before": self.diff_hash_before,
            "diff_hash_after": self.diff_hash_after,
            "target_hashes": [[path, digest] for path, digest in self.target_hashes],
            "readback_hashes": [[path, digest] for path, digest in self.readback_hashes],
            "expected_content_hashes": [
                [path, digest] for path, digest in self.expected_content_hashes
            ],
            "verified_path_count": self.verified_path_count,
            "matched_path_count": self.matched_path_count,
            "mismatched_path_count": self.mismatched_path_count,
            "unreadable_path_count": self.unreadable_path_count,
            "execution_performed": self.execution_performed,
            "execution_return_code": self.execution_return_code,
            "execution_timed_out": self.execution_timed_out,
            "execution_stdout_hash": self.execution_stdout_hash,
            "execution_stderr_hash": self.execution_stderr_hash,
            "expected_stdout_hash": self.expected_stdout_hash,
            "stdout_matched": self.stdout_matched,
            "runner_executable_hash": self.runner_executable_hash,
            "python_executable_hash": self.python_executable_hash,
            "worker_hash": self.worker_hash,
            "argv_hash": self.argv_hash,
            "runner_argv": list(self.runner_argv),
            "sandbox_policy_hash": self.sandbox_policy_hash,
            "sandbox_provider_id": self.sandbox_provider_id,
            "sandbox_capability_id": self.sandbox_capability_id,
            "execution_identity": self.identity.mapping(),
            "execution_identity_hash": self.identity.binding_hash,
            "controller_protocol_response_present": self.controller_protocol_response_present,
            "controller_protocol_key_hash": self.controller_protocol_key_hash,
            "controller_response_hash": self.controller_response_hash,
            "controller_attestation_hash": self.controller_attestation_hash,
            "controller_attestation_valid": self.controller_attestation_valid,
            "trust_boundary": {
                "schema": "SITINA_ARTIFACT_TRUST_BOUNDARY_V1",
                "evidence_source": "CONTROLLER_READ_ARTIFACT_BYTES_FROM_DISK_V1",
                "counts_derived_from_acceptance_prose": False,
                "counts_derived_from_real_readback": True,
                "expected_bytes_sealed_before_readback": bool(self.expected_content_hashes),
                "execution_observed_in_separate_process": self.execution_performed,
                "signing_controller_executes_target_code": False,
            },
            "cwd": self.cwd,
            "read_roots": list(self.read_roots),
            "write_roots": list(self.write_roots),
            "resource_limits": {name: value for name, value in self.resource_limits},
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_milliseconds": self.duration_milliseconds,
            "verification_complete": self.verification_complete,
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
    argv: tuple[str, ...]
    argv_hash: str
    policy_hash: str
    capability_id: str
    controller_protocol_response_present: bool
    controller_protocol_key_hash: str
    controller_response_hash: str
    controller_attestation_hash: str
    duration_milliseconds: int


_TEST_COUNT_FIELDS = (
    "collected",
    "executed",
    "passed",
    "failed",
    "skipped",
    "errors",
    "expected_failures",
    "unexpected_successes",
)


def _evaluated_test_observations(
    response: Mapping[str, Any],
    *,
    test_plan: Mapping[str, object],
    test_plan_hash: str,
) -> dict[str, int] | None:
    """Validate raw observations and independently derive every test count.

    Target processes never report structured observations, pass/fail or
    aggregate counts.  The signing supervisor admits only exact hash-bound
    PURE_DOCTEST source bytes, constructs item observations from OS-visible
    process I/O, and only this parent controller compares them with sealed
    expected values.
    """

    if (
        set(response)
        != {"schema", "mode", "test_plan_hash", "observations", "worker_ok"}
        or response.get("schema") != "SITINA_SANDBOX_TEST_OBSERVATIONS_V1"
        or response.get("mode") != "tests"
        or response.get("test_plan_hash") != test_plan_hash
        or response.get("worker_ok") is not True
    ):
        return None
    planned_targets = test_plan.get("targets")
    result_targets = response.get("observations")
    if (
        not isinstance(planned_targets, list)
        or not isinstance(result_targets, list)
        or len(result_targets) != len(planned_targets)
    ):
        return None
    aggregate = {name: 0 for name in _TEST_COUNT_FIELDS}
    seen_paths: set[str] = set()
    checker = doctest.OutputChecker()
    for planned, result in zip(planned_targets, result_targets, strict=True):
        if not isinstance(planned, dict) or not isinstance(result, dict):
            return None
        allowed = {"path", "mode", "examples"}
        if set(result) != allowed:
            return None
        path = planned.get("path")
        if (
            not isinstance(path, str)
            or path in seen_paths
            or result.get("path") != path
            or result.get("mode") != planned.get("mode")
            or planned.get("mode") != "doctest"
        ):
            return None
        seen_paths.add(path)
        planned_examples = planned.get("planned_examples")
        observations = result.get("examples")
        if (
            not isinstance(planned_examples, list)
            or not isinstance(observations, list)
            or len(observations) != len(planned_examples)
            or planned.get("expected_count") != len(planned_examples)
        ):
            return None
        aggregate["collected"] += len(planned_examples)
        for expected, observed in zip(planned_examples, observations, strict=True):
            if not isinstance(expected, dict) or not isinstance(observed, dict):
                return None
            if set(observed) != {
                "index",
                "fingerprint",
                "attempted",
                "stdout",
                "exception_type",
                "exception_text",
            }:
                return None
            exception_type = observed.get("exception_type")
            exception_text = observed.get("exception_text")
            if (
                observed.get("index") != expected.get("index")
                or observed.get("fingerprint") != expected.get("fingerprint")
                or not isinstance(observed.get("attempted"), bool)
                or not isinstance(observed.get("stdout"), str)
                or not (
                    (exception_type is None and exception_text is None)
                    or (isinstance(exception_type, str) and isinstance(exception_text, str))
                )
            ):
                return None
            raw_options = expected.get("options")
            if not isinstance(raw_options, list) or any(
                not isinstance(item, list)
                or len(item) != 2
                or not isinstance(item[0], int)
                or isinstance(item[0], bool)
                or not isinstance(item[1], bool)
                for item in raw_options
            ):
                return None
            option_flags = 0
            for flag, enabled in raw_options:
                option_flags = option_flags | flag if enabled else option_flags & ~flag
            aggregate["executed"] += 1
            if not observed["attempted"]:
                if not option_flags & doctest.SKIP or exception_type is not None or observed["stdout"]:
                    return None
                aggregate["skipped"] += 1
                continue
            expected_exception = expected.get("exc_msg")
            if exception_type is not None:
                if not isinstance(expected_exception, str):
                    aggregate["errors"] += 1
                    continue
                matched = checker.check_output(expected_exception, exception_text, option_flags)
                if not matched and option_flags & doctest.IGNORE_EXCEPTION_DETAIL:
                    matched = checker.check_output(
                        doctest._strip_exception_details(expected_exception),
                        doctest._strip_exception_details(exception_text),
                        option_flags,
                    )
                aggregate["passed" if matched else "failed"] += 1
                continue
            want = expected.get("want")
            if not isinstance(want, str) or expected_exception is not None:
                aggregate["failed"] += 1
                continue
            matched = checker.check_output(want, observed["stdout"], option_flags)
            aggregate["passed" if matched else "failed"] += 1
    if aggregate["collected"] != test_plan.get("collected_test_count"):
        return None
    return aggregate


class ExecutionSandboxRunner:
    WORKER_MARKER = "SITINA_SANDBOX_WORKER_RESULT:"
    WORKER_PROOF_MARKER = "SITINA_SANDBOX_WORKER_PROOF:"
    WORKER_KEY_MARKER = "SITINA_SANDBOX_CONTROLLER_KEY:"
    WORKER_CHALLENGE_MARKER = "SITINA_SANDBOX_PARENT_CHALLENGE:"

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
        proposer_id: str = "",
        executor_id: str = "",
        verifier_id: str = "",
        identity_binding: ExecutionIdentityBinding | None = None,
        agent_registry: object | None = None,
        execution_policy_hash: str = "",
        code_mode_authorization: Mapping[str, Any] | bool = False,
        code_mode_parent_authority: Any | None = None,
        code_mode_parent: Any | None = None,
        code_mode_attempt: int = 1,
        code_mode_scratch_root: Path | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.authority_resolution = authority_resolution
        self.fixture_authorization = fixture_authorization
        self.sandbox_executable = Path(sandbox_executable).expanduser().resolve(strict=True)
        self.python_executable = Path(python_executable).expanduser().resolve(strict=True)
        self.worker_path = Path(worker_path or Path(__file__).with_name("execution_sandbox_worker.py")).resolve(strict=True)
        self.limits = limits or SandboxResourceLimits()
        if identity_binding is None:
            if authority_resolution is not None and not fixture_authorization:
                raise ExecutionSandboxUnavailable(
                    "production sandbox execution identity binding is unavailable"
                )
            identity_binding = ExecutionIdentityBinding.fixture(
                proposer_id=proposer_id or "fixture-proposer",
                executor_id=executor_id or "forge-execution-role",
                verifier_id=verifier_id or "fixture-verifier",
            )
        if type(identity_binding) is not ExecutionIdentityBinding:
            raise ExecutionSandboxUnavailable(
                "sandbox execution identity binding is invalid"
            )
        self.identity = identity_binding
        self.agent_registry = agent_registry
        self.execution_policy_hash = execution_policy_hash
        self.code_mode_authorization = code_mode_authorization
        self.code_mode_parent_authority = code_mode_parent_authority
        self.code_mode_parent = code_mode_parent
        self.code_mode_attempt = int(code_mode_attempt)
        self.code_mode_scratch_root = (
            Path(code_mode_scratch_root).expanduser().resolve(strict=False)
            if code_mode_scratch_root is not None
            else None
        )
        token = (
            code_mode_authorization.get("authorization_token")
            if isinstance(code_mode_authorization, Mapping)
            else None
        )
        if self.code_mode_authorization and self.worker_path != Path(__file__).with_name("execution_sandbox_worker.py").resolve(strict=True):
            raise ExecutionSandboxUnavailable(
                "Code Mode sandbox admits only the bundled trusted worker"
            )
        self.code_mode_parent_authorization_hash = (
            str(getattr(self.code_mode_parent, "parent_hash", "")) or None
            if self.code_mode_parent is not None
            else None
        )
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

    def _executor_binding(
        self,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
    ) -> dict[str, str]:
        profile = frozen_sandbox_profile(
            self.python_executable, self.worker_path, read_roots, write_roots
        )
        return {
            "schema": "SITINA_SANDBOX_EXECUTOR_BINDING_V1",
            "sandbox_executable": str(self.sandbox_executable),
            "python_executable": str(self.python_executable),
            "worker_path": str(self.worker_path),
            "sandbox_policy": profile,
            "sandbox_policy_hash": _sha256_bytes(profile.encode("utf-8")),
        }

    def _capability(
        self,
        *,
        run_id: str,
        diff_hash: str,
        test_plan_hash: str,
        argv: tuple[str, ...],
        cwd: Path,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
        policy_hash: str,
    ) -> FrozenSandboxExecutionCapability | CodeModeSandboxExecutionCapability | None:
        if self.code_mode_authorization:
            if (
                not isinstance(self.code_mode_authorization, Mapping)
                or not self.code_mode_parent_authorization_hash
                or self.code_mode_parent_authority is None
                or self.code_mode_parent is None
            ):
                raise ExecutionSandboxUnavailable(
                    "Code Mode sandbox requires a trusted parent authorization"
                )
            issuer = getattr(self.code_mode_parent_authority, "issue_sandbox_child_capability", None)
            if not callable(issuer):
                raise ExecutionSandboxUnavailable(
                    "Code Mode sandbox parent issuer is not trusted"
                )
            return issuer(
                self.code_mode_parent,
                run_id=run_id,
                attempt=self.code_mode_attempt,
                diff_hash=diff_hash,
                test_plan_hash=test_plan_hash,
                runner_executable=self.python_executable,
                worker_path=self.worker_path,
                cwd=cwd,
                read_roots=read_roots,
                write_roots=write_roots,
                argv=argv,
                expires_at=int(time.time()) + min(120, self.limits.wall_seconds + 30),
            )
        if LegacyWriteGate(self.home).status().state != "FROZEN_NO_WRITER":
            return None
        return issue_frozen_sandbox_execution_capability(
            self.authority_resolution,
            home=self.home,
            run_id=run_id,
            diff_hash=diff_hash,
            test_plan_hash=test_plan_hash,
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
            proposer_id=self.identity.proposer_id,
            executor_id=self.identity.executor_id,
            verifier_id=self.identity.verifier_id,
            identity_binding=self.identity,
            agent_registry=self.agent_registry,
            execution_policy_hash=self.execution_policy_hash,
            fixture_authorization=self.fixture_authorization,
        )

    @staticmethod
    def _signal_sandbox(process: subprocess.Popen[bytes], requested_signal: signal.Signals) -> None:
        """Signal the whole sandbox, with a safe exact-PID Darwin fallback.

        The trusted supervisor owns at most one active Seatbelt item process;
        each has kernel RLIMIT_NPROC=1 and a profile denying descendants.  Some Darwin releases
        return EPERM for killpg() across the Seatbelt boundary; the exact
        supervisor PID remains the safe fallback target.
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
        test_plan_hash: str,
        cwd: Path,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
        scratch: Path,
    ) -> _Invocation:
        request = {
            **request,
            "test_plan_hash": test_plan_hash,
            "resource_limits": self.limits.mapping(),
            "executor": self._executor_binding(read_roots, write_roots),
        }
        encoded_request = base64.urlsafe_b64encode(_canonical(request)).decode("ascii")
        profile = self._profile(read_roots, write_roots)
        policy_hash = _sha256_bytes(profile.encode("utf-8"))
        argv = (
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
            test_plan_hash=test_plan_hash,
            argv=argv,
            cwd=cwd,
            read_roots=read_roots,
            write_roots=write_roots,
            policy_hash=policy_hash,
        )
        controller_identity = (
            capability.capability_id
            if capability is not None
            else "sandbox-direct-fixture:"
            + _sha256_bytes(os.urandom(32) + argv_hash.encode("ascii"))
        )
        stem = uuid.uuid4().hex
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
        stdout = b""
        with stderr_path.open("wb") as stderr_handle:
            if self.code_mode_authorization:
                execution_scope = authorized_code_mode_sandbox_execution(
                    capability,
                    argv=argv,
                    cwd=cwd,
                    attempt=self.code_mode_attempt,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    parent_authorization_hash=capability.parent_authorization_hash,
                    read_roots=read_roots,
                    write_roots=write_roots,
                )
            else:
                execution_scope = authorized_frozen_sandbox_execution(
                    capability,
                    argv=argv,
                    cwd=cwd,
                    diff_hash=diff_hash,
                    test_plan_hash=test_plan_hash,
                    authority_resolution=self.authority_resolution,
                    identity_binding=self.identity,
                    agent_registry=self.agent_registry,
                    execution_policy_hash=self.execution_policy_hash,
                )
            with execution_scope:
                try:
                    process = subprocess.Popen(
                        list(argv),
                        cwd=cwd,
                        env=environment,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=stderr_handle,
                        close_fds=True,
                        start_new_session=True,
                    )
                except (OSError, subprocess.SubprocessError) as error:
                    raise ExecutionSandboxUnavailable("OS sandbox runner could not start") from error
            if process.stdin is None or process.stdout is None:
                raise ExecutionSandboxUnavailable("sandbox protocol pipes are unavailable")
            protocol_key = os.urandom(32)
            protocol_key_hash = _sha256_bytes(protocol_key)
            try:
                process.stdin.write(
                    (self.WORKER_KEY_MARKER + protocol_key.hex() + "\n").encode("ascii")
                )
                process.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                self._signal_sandbox(process, signal.SIGTERM)
                process.wait()
                raise ExecutionSandboxUnavailable(
                    "sandbox worker did not accept its controller key"
                ) from error
            deadline = time.monotonic() + self.limits.wall_seconds
            stdout_buffer = bytearray()
            line_buffer = bytearray()
            result_payloads: list[bytes] = []
            proof_values: list[str] = []
            response: Mapping[str, Any] | None = None
            expected_proof: str | None = None
            protocol_invalid = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                readable, _writable, _exceptional = select.select(
                    [process.stdout], [], [], min(remaining, 0.1)
                )
                if readable:
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                    if not chunk:
                        break
                    stdout_buffer.extend(chunk)
                    line_buffer.extend(chunk)
                    if len(stdout_buffer) > self.limits.file_bytes:
                        protocol_invalid = True
                        break
                    while b"\n" in line_buffer:
                        raw_line, _, remainder = line_buffer.partition(b"\n")
                        line_buffer = bytearray(remainder)
                        line = raw_line.decode("utf-8", errors="replace")
                        if line.startswith(self.WORKER_MARKER):
                            result_payloads.append(raw_line[len(self.WORKER_MARKER):])
                            if len(result_payloads) != 1:
                                protocol_invalid = True
                                continue
                            try:
                                decoded = base64.urlsafe_b64decode(result_payloads[0])
                                candidate = json.loads(decoded)
                            except Exception:
                                protocol_invalid = True
                                continue
                            if not isinstance(candidate, dict):
                                protocol_invalid = True
                                continue
                            response = candidate
                            challenge = os.urandom(32).hex()
                            expected_proof = hmac.new(
                                protocol_key,
                                challenge.encode("ascii") + b"\0" + _canonical(candidate),
                                hashlib.sha256,
                            ).hexdigest()
                            try:
                                process.stdin.write(
                                    (self.WORKER_CHALLENGE_MARKER + challenge + "\n").encode("ascii")
                                )
                                process.stdin.flush()
                                process.stdin.close()
                            except (BrokenPipeError, OSError):
                                protocol_invalid = True
                        elif line.startswith(self.WORKER_PROOF_MARKER):
                            proof_values.append(line[len(self.WORKER_PROOF_MARKER):])
                elif process.poll() is not None:
                    # A final select/read observes EOF and exits the loop.
                    continue
            if timed_out or protocol_invalid:
                self._signal_sandbox(process, signal.SIGTERM)
            try:
                return_code = process.wait(
                    timeout=(
                        2
                        if (timed_out or protocol_invalid)
                        else max(0.1, deadline - time.monotonic())
                    )
                )
            except subprocess.TimeoutExpired:
                self._signal_sandbox(process, signal.SIGKILL)
                return_code = process.wait()
            if timed_out:
                return_code = 124
            with contextlib.suppress(OSError):
                process.stdin.close()
            with contextlib.suppress(OSError):
                process.stdout.close()
            stdout = bytes(stdout_buffer[: self.limits.file_bytes])
            if (
                protocol_invalid
                or len(result_payloads) != 1
                or len(proof_values) != 1
                or expected_proof is None
                or proof_values[0] != expected_proof
            ):
                response = None
        duration_ms = int((time.monotonic() - started) * 1000)
        stderr = stderr_path.read_bytes()[: self.limits.file_bytes]
        controller_response_hash = _sha256_bytes(
            _canonical(response) if response is not None else b""
        )
        controller_attestation_hash = _sha256_bytes(
            _canonical(
                {
                    "schema": "SITINA_SANDBOX_CONTROLLER_ATTESTATION_V2",
                    "controller_identity": controller_identity,
                    "diff_hash": diff_hash,
                    "test_plan_hash": test_plan_hash,
                    "execution_identity_hash": self.identity.binding_hash,
                    "protocol_key_hash": protocol_key_hash,
                    "response_hash": controller_response_hash,
                    "worker_hash": self.worker_hash,
                    "argv_hash": argv_hash,
                    "runner_return_code": return_code,
                    "timed_out": timed_out,
                    "protocol_response_present": response is not None,
                }
            )
        )
        return _Invocation(
            response=response,
            return_code=return_code,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            argv=tuple(argv),
            argv_hash=argv_hash,
            policy_hash=policy_hash,
            capability_id=controller_identity,
            controller_protocol_response_present=response is not None,
            controller_protocol_key_hash=protocol_key_hash,
            controller_response_hash=controller_response_hash,
            controller_attestation_hash=controller_attestation_hash,
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
        probe_request: dict[str, object] = {
            "mode": "probe",
            "outside_read": str(outside_read),
            "outside_write": str(outside_write),
            "symlink_escape": str(link / outside_write.name),
        }
        probe_plan_hash = _sha256_bytes(
            _canonical(
                {
                    "schema": "SITINA_SANDBOX_QUALIFICATION_PLAN_V1",
                    "request": probe_request,
                }
            )
        )
        try:
            probe = self._invoke(
                probe_request,
                run_id=run_id + ":probe",
                diff_hash=diff_hash,
                test_plan_hash=probe_plan_hash,
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
            error_type = str(response.get("error_type") or "missing-response")[:120]
            error_detail = str(response.get("error") or "")[:500]
            raise ExecutionSandboxUnavailable(
                f"sandbox qualification worker failed: {error_type}: {error_detail}"
            )
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
        test_plan, test_plan_hash = _trusted_test_plan(targets)
        common = Path(os.path.commonpath([str(path) for path in evidence_paths])).resolve(strict=True)
        cwd = common if common.is_dir() else common.parent
        if len(cwd.parts) < 4:
            raise ExecutionSandboxError("sandbox diff does not have a narrowly confined workspace root")
        if any(not _inside(path, cwd) for path in targets):
            raise ExecutionSandboxError("sandbox targets do not share a confined workspace")
        read_roots = (cwd,)
        if self.code_mode_scratch_root is not None:
            scratch = self.code_mode_scratch_root
            if scratch.exists():
                if scratch.is_symlink() or not scratch.is_dir() or any(scratch.iterdir()):
                    raise ExecutionSandboxError("Code Mode scratch root is not fresh and regular")
            else:
                scratch.mkdir(parents=True, mode=0o700)
            scratch = scratch.resolve(strict=True)
        else:
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
                mode = "unittest" if path.name.startswith("test_") and path.suffix == ".py" else "doctest"
                raw_targets.append({"path": str(path), "mode": mode})
            if not raw_targets:
                raise ExecutionSandboxError("no executable test evidence")
            invocation = self._invoke(
                {
                    "mode": "tests",
                    "targets": raw_targets,
                    "read_roots": [str(root) for root in read_roots],
                    "test_plan": test_plan,
                },
                run_id=run_id,
                diff_hash=diff_before,
                test_plan_hash=test_plan_hash,
                cwd=cwd,
                read_roots=read_roots,
                write_roots=write_roots,
                scratch=scratch,
            )
            response = invocation.response or {}
            evaluated_counts = _evaluated_test_observations(
                response,
                test_plan=test_plan,
                test_plan_hash=test_plan_hash,
            )
            counts = evaluated_counts or {"collected": int(test_plan["collected_test_count"])}
            worker_ok = evaluated_counts is not None and invocation.return_code == 0
            diff_after, _after_hashes = hash_diff(evidence_paths)
            finished_at = _utc_now()
            duration_ms = int((time.monotonic() - total_started) * 1000)
            return TestEvidence(
                run_id=run_id,
                test_plan_hash=test_plan_hash,
                diff_hash_before=diff_before,
                diff_hash_after=diff_after,
                target_hashes=target_hashes,
                collected_test_count=int(counts.get("collected", test_plan["collected_test_count"]) or 0),
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
                identity=self.identity,
                controller_protocol_response_present=invocation.controller_protocol_response_present,
                controller_protocol_key_hash=invocation.controller_protocol_key_hash,
                controller_response_hash=invocation.controller_response_hash,
                controller_attestation_hash=invocation.controller_attestation_hash,
                cwd=str(cwd),
                read_roots=tuple(str(root) for root in read_roots),
                write_roots=tuple(str(root) for root in write_roots),
                resource_limits=self.limits.capability_items(),
                stdout_hash=_sha256_bytes(invocation.stdout),
                stderr_hash=_sha256_bytes(invocation.stderr),
                started_at=started_at,
                finished_at=finished_at,
                duration_milliseconds=duration_ms,
                runner_argv=invocation.argv,
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
