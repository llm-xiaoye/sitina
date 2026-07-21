"""Safety-equivalence layer for the winner->bridge execution path (method 2).

Migrates the handoff invariants that execution actually needs into a single,
deterministic, dependency-injected orchestrator so they are enforced regardless
of whether Atlas emitted a "handoff" protocol:

  H4  boundary redaction  -> boundary_check on the deliverable/diff, fail-closed
                             BEFORE it crosses the persistence boundary
  H11 executor independence -> executor_id != verifier_id, asserted
  H12 independent verify  -> verifier inspects the ACTUAL diff/tests/workspace
  H6  bounded rework      -> max_attempts, failed attempts isolated, fail-closed

The bridge return value is a formal ExecutionResult; the caller must only
terminalize as SUCCEEDED when result.accepted is True.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable, Mapping, Sequence


class ExecutionBridgeError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionBinding:
    """Immutable identity every execution attempt is bound to (Req 5)."""

    winner_output_hash: str
    approved_scope: tuple[str, ...]
    policy_hash: str
    run_id: str


@dataclass(frozen=True)
class VerificationVerdict:
    """Result of an INDEPENDENT verifier inspecting the real diff (Req 6)."""

    accepted: bool
    verifier_id: str
    checked_diff: bool
    checked_tests: bool
    reasons: tuple[str, ...] = ()
    test_evidence_ref: str | None = None
    test_evidence_hash: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    """Formal, non-discardable bridge result (Req 4). terminalize as SUCCEEDED
    only when accepted is True."""

    status: str  # "accepted" | "rejected" | "blocked" | "failed"
    accepted: bool
    binding: ExecutionBinding
    attempts: int
    workspace: str
    diff_paths: tuple[str, ...] = ()
    verification: VerificationVerdict | None = None
    redaction_ok: bool = False
    notes: tuple[str, ...] = ()

    def as_event(self) -> dict[str, Any]:
        return {
            "schema": "FORGE_EXECUTION_RESULT_V1",
            "status": self.status,
            "accepted": self.accepted,
            "winner_output_hash": self.binding.winner_output_hash,
            "approved_scope": list(self.binding.approved_scope),
            "policy_hash": self.binding.policy_hash,
            "run_id": self.binding.run_id,
            "attempts": self.attempts,
            "workspace": self.workspace,
            "diff_paths": list(self.diff_paths),
            "redaction_ok": self.redaction_ok,
            "verifier_id": self.verification.verifier_id if self.verification else None,
            "verification_accepted": self.verification.accepted if self.verification else None,
            "test_evidence_ref": self.verification.test_evidence_ref if self.verification else None,
            "test_evidence_hash": self.verification.test_evidence_hash if self.verification else None,
            "notes": list(self.notes),
        }

def run_safe_execution(
    *,
    binding: ExecutionBinding,
    executor_id: str,
    workspace: str,
    forge_runner: Callable[[int, str], Mapping[str, Any]],
    collect_diff: Callable[[], Sequence[str]],
    boundary_check: Callable[[Sequence[str]], Sequence[str]],
    verifier: Callable[[Sequence[str], Mapping[str, Any]], VerificationVerdict],
    rollback: Callable[[int], None],
    max_attempts: int = 2,
) -> ExecutionResult:
    """Deterministic safe-execution orchestrator. All effects are injected so
    this is fully unit-testable without a provider.

    forge_runner(attempt, workspace) -> runtime result mapping (the Forge loop).
    collect_diff() -> the ACTUAL changed paths in the workspace.
    boundary_check(diff_paths) -> list of redacted/sensitive paths (empty == ok).
    verifier(diff_paths, forge_result) -> VerificationVerdict (independent).
    rollback(attempt) -> undo/isolate a rejected attempt's workspace changes.
    """
    if max_attempts < 1:
        raise ExecutionBridgeError("max_attempts must be >= 1")
    notes: list[str] = []
    last_diff: tuple[str, ...] = ()

    for attempt in range(1, max_attempts + 1):
        forge_result = forge_runner(attempt, workspace)
        # If the Forge loop itself failed/hit its guards, isolate and retry.
        if str(forge_result.get("terminal_state")) != "SUCCEEDED":
            notes.append(f"attempt{attempt}:forge_not_succeeded:{forge_result.get('terminal_state')}")
            rollback(attempt)
            continue

        diff_paths = tuple(collect_diff())
        last_diff = diff_paths

        # H4: sensitive-content hard gate on the deliverable/diff BEFORE accept.
        # SL1 already blocks per-write; this is the deliverable-level boundary.
        sensitive = tuple(boundary_check(diff_paths))
        if sensitive:
            notes.append(f"attempt{attempt}:boundary_blocked:{','.join(sensitive)}")
            rollback(attempt)
            # sensitive content is not a "try again differently" condition;
            # fail-closed immediately rather than loop.
            return ExecutionResult(
                status="blocked", accepted=False, binding=binding, attempts=attempt,
                workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                notes=tuple(notes),
            )

        # H11: executor must not be its own verifier.
        verdict = verifier(diff_paths, forge_result)
        if verdict.verifier_id == executor_id:
            raise ExecutionBridgeError(
                f"executor and verifier must differ (both {executor_id})"
            )
        # H12: verifier must have actually inspected the diff (not text self-report).
        if not verdict.checked_diff:
            raise ExecutionBridgeError("verifier did not inspect the actual diff")
        # H12 (test evidence): an ACCEPT is only valid with real executed-test
        # evidence. Syntax-only ("checked_tests=False") must never be accepted —
        # that was the hollow-acceptance bug. Fail-closed: downgrade to reject.
        evidence_bound = (
            isinstance(verdict.test_evidence_ref, str)
            and bool(re.fullmatch(r"(?:cas|test-evidence):[0-9a-f]{64}", verdict.test_evidence_ref))
            and isinstance(verdict.test_evidence_hash, str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", verdict.test_evidence_hash))
        )
        if verdict.accepted and (not verdict.checked_tests or not evidence_bound):
            notes.append(f"attempt{attempt}:rejected:accept_without_test_evidence")
            rollback(attempt)
            continue

        if verdict.accepted:
            notes.append(f"attempt{attempt}:accepted")
            return ExecutionResult(
                status="accepted", accepted=True, binding=binding, attempts=attempt,
                workspace=workspace, diff_paths=diff_paths, verification=verdict,
                redaction_ok=True, notes=tuple(notes),
            )

        # H6: rejected -> isolate this attempt and rework (bounded).
        notes.append(f"attempt{attempt}:rejected:{';'.join(verdict.reasons) or 'no-reason'}")
        rollback(attempt)

    # Bounded rework exhausted -> fail-closed.
    return ExecutionResult(
        status="rejected", accepted=False, binding=binding, attempts=max_attempts,
        workspace=workspace, diff_paths=last_diff, redaction_ok=True,
        notes=tuple(notes) + ("rework_exhausted_fail_closed",),
    )
