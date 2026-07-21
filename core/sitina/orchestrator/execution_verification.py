"""Independent, fail-closed verification of execution results."""
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from sitina.legacy.fence import LegacyWriteDenied
from sitina.orchestrator.execution_bridge import VerificationVerdict
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
    reasons: list[str] = []
    if not diff_paths:
        return VerificationVerdict(
            False,
            verifier_id,
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
        return VerificationVerdict(
            False, verifier_id, checked_diff=True, checked_tests=False, reasons=tuple(reasons)
        )
    if not test_targets:
        return VerificationVerdict(
            False,
            verifier_id,
            checked_diff=True,
            checked_tests=False,
            reasons=("no executable test evidence (no doctest/test_*.py)",),
        )
    if evidence_publisher is None:
        return VerificationVerdict(
            False,
            verifier_id,
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
        return VerificationVerdict(
            False,
            verifier_id,
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
    return VerificationVerdict(
        evidence.accepted,
        verifier_id,
        checked_diff=True,
        checked_tests=evidence.executed_test_count > 0,
        reasons=tuple(reasons),
        test_evidence_ref=evidence_ref,
        test_evidence_hash=evidence_hash,
    )
