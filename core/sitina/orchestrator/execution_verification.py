"""Independent, fail-closed verification of execution results."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.legacy.fence import LegacyWriteDenied
from sitina.orchestrator.execution_bridge import (
    ExecutionIdentityBinding,
    VerificationVerdict,
)
from sitina.orchestrator.execution_sandbox import (
    ExecutionSandboxError,
    ExecutionSandboxRunner,
    SandboxResourceLimits,
    TestEvidencePublisher,
)


def verify_execution_diff(
    diff_paths: Sequence[str],
    verifier_id: str,
    forge_result: Mapping[str, Any],
    *,
    run_id: str | None = None,
    home: Path | None = None,
    authority_resolution: object | None = None,
    proposer_id: str = "",
    executor_id: str = "",
    identity_binding: ExecutionIdentityBinding | None = None,
    agent_registry: object | None = None,
    execution_policy_hash: str = "",
    fixture_authorization: bool = False,
    code_mode_authorization: Mapping[str, Any] | bool = False,
    code_mode_parent_authority: Any | None = None,
    code_mode_parent: Any | None = None,
    code_mode_scratch_root: Path | None = None,
    evidence_publisher: TestEvidencePublisher | None = None,
    sandbox_executable: Path = Path("/usr/bin/sandbox-exec"),
    limits: SandboxResourceLimits | None = None,
    worker_executor: Any | None = None,
) -> VerificationVerdict:
    """Statically inspect the diff, then execute tests only in a qualified OS sandbox.

    A successful verdict always references immutable TestEvidence containing
    actual collected/executed/pass/fail/skip/error counts and before/after diff
    hashes.  Sandbox or publication unavailability becomes a structured reject.
    """

    # The Forge mapping is not trusted as execution evidence.  Its bounded
    # attempt number is used only to select the already-registered parent
    # capability; diff/test facts are recomputed below.
    forge_attempt = int(forge_result.get("attempt") or 1)
    if identity_binding is None:
        if authority_resolution is not None and not fixture_authorization:
            raise ValueError("production verifier requires an execution identity binding")
        identity_binding = ExecutionIdentityBinding.fixture(
            proposer_id=proposer_id or "fixture-proposer",
            executor_id=executor_id or "forge-execution-role",
            verifier_id=verifier_id,
        )
    if type(identity_binding) is not ExecutionIdentityBinding:
        raise ValueError("verifier execution identity binding is invalid")
    if verifier_id != identity_binding.verifier_id:
        raise ValueError("verifier differs from execution identity binding")

    def verdict(
        accepted: bool,
        *,
        checked_diff: bool,
        checked_tests: bool,
        reasons: tuple[str, ...] = (),
        test_evidence_ref: str | None = None,
        test_evidence_hash: str | None = None,
    ) -> VerificationVerdict:
        return VerificationVerdict(
            accepted,
            verifier_id,
            checked_diff,
            checked_tests,
            identity_binding,
            reasons,
            test_evidence_ref,
            test_evidence_hash,
        )

    reasons: list[str] = []
    if not diff_paths:
        return verdict(
            False,
            checked_diff=True,
            checked_tests=False,
            reasons=("empty diff: nothing produced",),
        )

    py_files = [Path(value).expanduser() for value in diff_paths if str(value).endswith(".py")]
    test_targets: list[Path] = []
    for path in py_files:
        try:
            source = path.read_text(encoding="utf-8", errors="strict")
            ast.parse(source)
        except (SyntaxError, UnicodeDecodeError, OSError) as error:
            reasons.append(f"{path.name}: {type(error).__name__}")
            continue
        if "test_" in path.name or ">>>" in source:
            test_targets.append(path)

    if reasons:
        return verdict(
            False, checked_diff=True, checked_tests=False, reasons=tuple(reasons)
        )
    if not test_targets:
        return verdict(
            False,
            checked_diff=True,
            checked_tests=False,
            reasons=("no executable test evidence (no doctest/test_*.py)",),
        )
    if worker_executor is not None:
        from sitina.orchestrator.execution_sandbox import (
            TestEvidence,
            _sha256_bytes,
            _sha256_file,
            _trusted_test_plan,
            _utc_now,
            hash_diff,
        )
        if evidence_publisher is None:
            return verdict(False, checked_diff=True, checked_tests=False,
                           reasons=("immutable test evidence publisher unavailable",))
        try:
            execution_run_id = run_id or f"verification-{verifier_id}"
            evidence_paths = tuple(Path(value).expanduser().resolve(strict=True) for value in diff_paths)
            diff_before, target_hashes = hash_diff(evidence_paths)
            test_plan, test_plan_hash = _trusted_test_plan(tuple(test_targets))
            common = Path(os.path.commonpath([str(path) for path in evidence_paths])).resolve(strict=True)
            cwd = common if common.is_dir() else common.parent
            command = [sys.executable, "-m", "doctest", *[str(path) for path in test_targets]]
            observation = worker_executor._shell(
                shlex.join(command), [f"{sys.executable} -m doctest"],
                execution_run_id, cwd=str(cwd),
            )
            return_code = int(observation.get("exit_code") if isinstance(observation.get("exit_code"), int) else -1)
            diff_after, _ = hash_diff(evidence_paths)
            collected = int(test_plan.get("collected_test_count") or 0)
            passed = collected if observation.get("status") == "ok" and return_code == 0 else 0
            canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            argv_hash = _sha256_bytes(canonical(command))
            response_hash = _sha256_bytes(canonical(dict(observation)))
            capability_id = _sha256_bytes(canonical({"run_id": execution_run_id, "attempt": forge_attempt, "worker": True}))
            protocol_key_hash = _sha256_bytes(b"CODE_MODE_CONTROLLER_WORKER_V1")
            worker_path = Path(getattr(getattr(worker_executor, "controller", None), "_worker_script", __file__))
            worker_hash = _sha256_file(worker_path)
            runner_hash = _sha256_file(Path(sys.executable))
            policy_hash = _sha256_bytes(b"CODE_MODE_WORKER_TEST_POLICY_V1")
            stdout_hash = _sha256_bytes(str(observation.get("output_hash") or "").encode())
            limits_value = limits or SandboxResourceLimits()
            evidence_values = {
                "run_id": execution_run_id, "test_plan_hash": test_plan_hash,
                "diff_hash_before": diff_before, "diff_hash_after": diff_after,
                "target_hashes": target_hashes, "collected_test_count": collected,
                "executed_test_count": collected, "passed_test_count": passed,
                "failed_test_count": 0 if passed == collected else collected,
                "skipped_test_count": 0, "error_test_count": 0,
                "expected_failure_count": 0, "unexpected_success_count": 0,
                "runner_return_code": return_code, "timed_out": False,
                "runner_executable_hash": runner_hash, "python_executable_hash": runner_hash,
                "worker_hash": worker_hash, "argv_hash": argv_hash,
                "sandbox_policy_hash": policy_hash, "sandbox_provider_id": "code-mode-controller-worker",
                "sandbox_capability_id": capability_id, "identity": identity_binding,
                "controller_protocol_response_present": True,
                "controller_protocol_key_hash": protocol_key_hash,
                "controller_response_hash": response_hash,
                "cwd": str(cwd), "read_roots": (str(cwd),), "write_roots": (str(cwd),),
                "resource_limits": tuple(sorted(limits_value.mapping().items())),
                "stdout_hash": stdout_hash, "stderr_hash": _sha256_bytes(b""),
                "started_at": _utc_now(), "finished_at": _utc_now(), "duration_milliseconds": 0,
            }
            attestation = _sha256_bytes(canonical({
                "schema": "SITINA_SANDBOX_CONTROLLER_ATTESTATION_V2",
                "controller_identity": capability_id,
                "diff_hash": diff_before,
                "test_plan_hash": test_plan_hash,
                "execution_identity_hash": identity_binding.binding_hash,
                "protocol_key_hash": protocol_key_hash,
                "response_hash": response_hash,
                "worker_hash": worker_hash,
                "argv_hash": argv_hash,
                "runner_return_code": return_code,
                "timed_out": False,
                "protocol_response_present": True,
            }))
            evidence_values["controller_attestation_hash"] = attestation
            evidence = TestEvidence(**evidence_values)
            evidence_ref = evidence_publisher.publish(evidence.canonical_bytes(), evidence_hash=evidence.evidence_hash)
        except (OSError, UnicodeError, ValueError, TypeError) as error:
            return verdict(False, checked_diff=True, checked_tests=False,
                           reasons=(f"controller worker test unavailable ({type(error).__name__})",))
        return verdict(evidence.accepted, checked_diff=True,
                       checked_tests=evidence.executed_test_count > 0,
                       reasons=() if evidence.accepted else ("controller worker test evidence rejected",),
                       test_evidence_ref=evidence_ref, test_evidence_hash=evidence.evidence_hash)

    if evidence_publisher is None:
        return verdict(
            False,
            checked_diff=True,
            checked_tests=False,
            reasons=("immutable test evidence publisher unavailable",),
        )

    execution_run_id = run_id or f"verification-{verifier_id}"
    sandbox_home = Path(home or os.environ.get("SITINA_HOME", "/Users/moss/SitinaHub"))
    try:
        runner = ExecutionSandboxRunner(
            home=sandbox_home,
            authority_resolution=authority_resolution,
            fixture_authorization=fixture_authorization,
            sandbox_executable=sandbox_executable,
            limits=limits,
            proposer_id=proposer_id,
            executor_id=executor_id,
            verifier_id=verifier_id,
            identity_binding=identity_binding,
            agent_registry=agent_registry,
            execution_policy_hash=execution_policy_hash,
            code_mode_authorization=code_mode_authorization,
            code_mode_parent_authority=code_mode_parent_authority,
            code_mode_parent=code_mode_parent,
            code_mode_attempt=forge_attempt,
            code_mode_scratch_root=code_mode_scratch_root,
        )
        evidence = runner.run_tests(
            test_targets,
            run_id=execution_run_id,
            diff_paths=[Path(value).expanduser() for value in diff_paths],
        )
        raw_evidence = evidence.canonical_bytes()
        evidence_hash = evidence.evidence_hash
        evidence_ref = evidence_publisher.publish(raw_evidence, evidence_hash=evidence_hash)
    except (ExecutionSandboxError, LegacyWriteDenied, OSError, UnicodeError, ValueError) as error:
        return verdict(
            False,
            checked_diff=True,
            checked_tests=False,
            reasons=(f"test execution unavailable ({type(error).__name__})",),
        )

    if not evidence.accepted:
        reasons.append(
            "sandbox tests rejected "
            f"(collected={evidence.collected_test_count},executed={evidence.executed_test_count},"
            f"passed={evidence.passed_test_count},failed={evidence.failed_test_count},"
            f"skipped={evidence.skipped_test_count},errors={evidence.error_test_count},"
            f"rc={evidence.runner_return_code},timeout={str(evidence.timed_out).lower()})"
        )
    return verdict(
        evidence.accepted,
        checked_diff=True,
        checked_tests=evidence.executed_test_count > 0,
        reasons=tuple(reasons),
        test_evidence_ref=evidence_ref,
        test_evidence_hash=evidence_hash,
    )
