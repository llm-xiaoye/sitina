from __future__ import annotations

import unittest

from sitina.orchestrator.execution_bridge import (
    ExecutionBinding,
    ExecutionBridgeError,
    VerificationVerdict,
    run_safe_execution,
)


def binding() -> ExecutionBinding:
    return ExecutionBinding(
        winner_output_hash="a" * 64, approved_scope=("src/",), policy_hash="b" * 64, run_id="run-1"
    )


def ok_forge(attempt, workspace):
    return {"terminal_state": "SUCCEEDED", "tool_call_count": 1}


def accepted_verdict(verifier_id="agent-delta", *, checked_diff=True):
    return VerificationVerdict(
        True,
        verifier_id,
        checked_diff,
        True,
        test_evidence_ref="test-evidence:" + "c" * 64,
        test_evidence_hash="c" * 64,
    )


class ExecutionBridgeTests(unittest.TestCase):
    def test_accept_path_returns_accepted_result(self) -> None:
        rolled: list[int] = []
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge,
            collect_diff=lambda: ["src/add.py"],
            boundary_check=lambda diff: [],
            verifier=lambda diff, res: accepted_verdict(),
            rollback=lambda a: rolled.append(a),
            max_attempts=2,
        )
        self.assertTrue(result.accepted)
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.attempts, 1)
        self.assertEqual(result.diff_paths, ("src/add.py",))
        self.assertEqual(rolled, [])  # no rollback on accept

    def test_bad_diff_rejected_then_bounded_rework_then_fail_closed(self) -> None:
        rolled: list[int] = []
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge,
            collect_diff=lambda: ["src/bad.py"],
            boundary_check=lambda diff: [],
            verifier=lambda diff, res: VerificationVerdict(False, "agent-delta", True, True, ("test failed",)),
            rollback=lambda a: rolled.append(a),
            max_attempts=2,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.attempts, 2)          # tried the bound
        self.assertEqual(rolled, [1, 2])              # each rejected attempt isolated
        self.assertIn("rework_exhausted_fail_closed", result.notes)

    def test_accept_without_test_evidence_is_downgraded_to_reject(self) -> None:
        # FIX1-A: verdict.accepted=True but checked_tests=False must NOT be
        # accepted (the hollow-acceptance bug). Fail-closed -> bounded rework.
        rolled: list[int] = []
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: VerificationVerdict(True, "agent-delta", True, False),  # no test evidence
            rollback=lambda a: rolled.append(a), max_attempts=2,
        )
        self.assertFalse(result.accepted)
        self.assertIn("rework_exhausted_fail_closed", result.notes)
        self.assertEqual(rolled, [1, 2])

    def test_accept_without_immutable_evidence_reference_is_rejected(self) -> None:
        rolled: list[int] = []
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: VerificationVerdict(True, "agent-delta", True, True),
            rollback=lambda a: rolled.append(a), max_attempts=1,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(rolled, [1])

    def test_executor_cannot_be_its_own_verifier(self) -> None:
        with self.assertRaises(ExecutionBridgeError):
            run_safe_execution(
                binding=binding(), executor_id="agent-forge", workspace="/ws",
                forge_runner=ok_forge, collect_diff=lambda: ["x"],
                boundary_check=lambda d: [],
                verifier=lambda d, r: accepted_verdict("agent-forge"),  # same id!
                rollback=lambda a: None, max_attempts=1,
            )

    def test_verifier_must_inspect_actual_diff(self) -> None:
        with self.assertRaises(ExecutionBridgeError):
            run_safe_execution(
                binding=binding(), executor_id="agent-forge", workspace="/ws",
                forge_runner=ok_forge, collect_diff=lambda: ["x"],
                boundary_check=lambda d: [],
                verifier=lambda d, r: accepted_verdict(checked_diff=False),  # checked_diff=False
                rollback=lambda a: None, max_attempts=1,
            )

    def test_sensitive_diff_blocked_before_accept_fail_closed(self) -> None:
        verifier_called: list[bool] = []
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge,
            collect_diff=lambda: ["src/leak.py"],
            boundary_check=lambda diff: ["src/leak.py"],  # sensitive!
            verifier=lambda d, r: (verifier_called.append(True), accepted_verdict())[1],
            rollback=lambda a: None, max_attempts=2,
        )
        self.assertEqual(result.status, "blocked")
        self.assertFalse(result.accepted)
        self.assertFalse(result.redaction_ok)
        self.assertEqual(verifier_called, [])  # blocked BEFORE verification/accept

    def test_forge_failure_isolated_and_retried(self) -> None:
        attempts_seen: list[int] = []
        def flaky_forge(attempt, ws):
            attempts_seen.append(attempt)
            return {"terminal_state": "FAILED" if attempt == 1 else "SUCCEEDED"}
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=flaky_forge, collect_diff=lambda: ["src/ok.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: accepted_verdict(),
            rollback=lambda a: None, max_attempts=2,
        )
        self.assertTrue(result.accepted)
        self.assertEqual(attempts_seen, [1, 2])

    def test_result_carries_immutable_binding(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["x"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: accepted_verdict(),
            rollback=lambda a: None, max_attempts=1,
        )
        ev = result.as_event()
        self.assertEqual(ev["winner_output_hash"], "a" * 64)
        self.assertEqual(ev["policy_hash"], "b" * 64)
        self.assertEqual(ev["approved_scope"], ["src/"])
        self.assertTrue(ev["accepted"])
        self.assertEqual(ev["test_evidence_hash"], "c" * 64)


if __name__ == "__main__":
    unittest.main()
