"""Independent, fail-closed verification of execution results."""
from __future__ import annotations

import ast
import os
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
    evidence_publisher: TestEvidencePublisher | None = None,
    sandbox_executable: Path = Path("/usr/bin/sandbox-exec"),
    limits: SandboxResourceLimits | None = None,
) -> VerificationVerdict:
    """Statically inspect the diff, then execute tests only in a qualified OS sandbox.

    A successful verdict always references immutable TestEvidence containing
    actual collected/executed/pass/fail/skip/error counts and before/after diff
    hashes.  Sandbox or publication unavailability becomes a structured reject.
    """

    del forge_result  # execution self-report is deliberately not verification input
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
