"""Independent verification of execution results.

Extracted from _execute_winner to enable direct testing and eliminate test-mirror drift.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path
from typing import Sequence, Mapping, Any

from sitina.orchestrator.execution_bridge import VerificationVerdict
from sitina.legacy.fence import LegacyWriteDenied
from sitina.utils import isolated_env


def verify_execution_diff(
    diff_paths: Sequence[str],
    verifier_id: str,
    forge_result: Mapping[str, Any],
) -> VerificationVerdict:
    """Independent, read-only verification of execution diff.

    Performs:
    1. Syntax check (ast.parse) on all .py files
    2. Runs doctests/unittest on files with test evidence
    3. Returns verdict with checked_tests=True only if real tests executed

    Args:
        diff_paths: Paths to produced files (absolute)
        verifier_id: Identity of the verifier (must differ from executor)
        forge_result: Forge execution result (unused, for interface consistency)

    Returns:
        VerificationVerdict with:
        - checked_diff=True (always reads actual files)
        - checked_tests=True only if executable tests ran
        - accepted=True only if syntax ok AND tests ran AND all passed
        - reasons: list of failure reasons (empty if accepted)

    Note:
        Currently calls subprocess.run which is DENIED by the frozen fence.
        This will fail in production frozen homes with LegacyWriteDenied.
        A future fix must use an authorized execution channel or in-process execution.
    """
    reasons: list[str] = []

    if not diff_paths:
        return VerificationVerdict(
            False, verifier_id, checked_diff=True, checked_tests=False,
            reasons=("empty diff: nothing produced",)
        )

    py_files = [p for p in diff_paths if p.endswith(".py")]

    # Syntax check
    for p in py_files:
        try:
            ast.parse(Path(p).read_text(encoding="utf-8", errors="strict"))
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            reasons.append(f"{Path(p).name}: {type(exc).__name__}")

    if reasons:
        return VerificationVerdict(
            False, verifier_id, checked_diff=True, checked_tests=False,
            reasons=tuple(reasons)
        )

    # Run tests (doctest / unittest)
    ran_tests = False
    for p in py_files:
        try:
            src = Path(p).read_text(encoding="utf-8", errors="strict")
        except OSError:
            continue

        is_testfile = Path(p).name.startswith("test_") or "test_" in Path(p).name
        has_doctest = ">>>" in src

        if not (is_testfile or has_doctest):
            continue

        mod = "unittest" if is_testfile else "doctest"
        try:
            proc = subprocess.run(
                [sys.executable, "-m", mod, p],
                cwd=str(Path(p).parent),
                env=isolated_env(),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (LegacyWriteDenied, subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as exc:
            # Fail-closed on inability to run tests — including the frozen
            # fence's LegacyWriteDenied. PRECISE catch: KeyboardInterrupt /
            # SystemExit / GeneratorExit must propagate, never be masked into a
            # verdict. The diagnostic is preserved (not overwritten below).
            reasons.append(f"{Path(p).name}: test execution unavailable ({type(exc).__name__})")
            continue

        ran_tests = True
        if proc.returncode != 0:
            reasons.append(f"{Path(p).name}: tests failed rc={proc.returncode}")

    # Fail-closed: no executable test evidence -> cannot accept. Preserve any
    # per-file diagnostics (e.g. LegacyWriteDenied) already collected; only add
    # the generic reason when there is none.
    if not ran_tests:
        if not reasons:
            reasons.append("no executable test evidence (no doctest/test_*.py)")
        return VerificationVerdict(
            False, verifier_id, checked_diff=True, checked_tests=False,
            reasons=tuple(reasons)
        )

    accepted = not reasons
    return VerificationVerdict(
        accepted, verifier_id, checked_diff=True,
        checked_tests=True, reasons=tuple(reasons)
    )
