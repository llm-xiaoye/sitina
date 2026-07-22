from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from sitina.orchestrator.execution_bridge import (
    ExecutionBinding,
    ExecutionBridgeError,
    VerificationVerdict,
    run_safe_execution,
)
from sitina.orchestrator.execution_patch import (
    ExecutionPatchError,
    build_patch_manifest,
    replay_patch_manifest,
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
                forge_runner=ok_forge, collect_diff=lambda: ["src/x"],
                boundary_check=lambda d: [],
                verifier=lambda d, r: accepted_verdict("agent-forge"),  # same id!
                rollback=lambda a: None, max_attempts=1,
            )

    def test_verifier_must_inspect_actual_diff(self) -> None:
        with self.assertRaises(ExecutionBridgeError):
            run_safe_execution(
                binding=binding(), executor_id="agent-forge", workspace="/ws",
                forge_runner=ok_forge, collect_diff=lambda: ["src/x"],
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
            forge_runner=ok_forge, collect_diff=lambda: ["src/x"],
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

    def test_out_of_scope_diff_is_blocked_before_boundary_or_verifier(self) -> None:
        observed: list[str] = []
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["../escape.py"],
            boundary_check=lambda d: observed.append("boundary") or [],
            verifier=lambda d, r: observed.append("verifier") or accepted_verdict(),
            rollback=lambda a: observed.append(f"rollback:{a}"), max_attempts=1,
        )
        self.assertEqual(result.status, "blocked")
        self.assertFalse(result.accepted)
        self.assertEqual(observed, ["rollback:1"])

    def test_duplicate_diff_path_is_blocked(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py", "src/x.py"],
            boundary_check=lambda d: [], verifier=lambda d, r: accepted_verdict(),
            rollback=lambda a: None, max_attempts=1,
        )
        self.assertEqual(result.status, "blocked")

    def test_filesystem_evidence_reference_must_match_hash(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id="agent-forge", workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: VerificationVerdict(
                True, "agent-delta", True, True,
                test_evidence_ref="test-evidence:" + "d" * 64,
                test_evidence_hash="c" * 64,
            ),
            rollback=lambda a: None, max_attempts=1,
        )
        self.assertFalse(result.accepted)

    def test_patch_manifest_is_deterministic_and_replay_verified(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            workspace = Path(parent) / "workspace"
            workspace.mkdir()
            target = workspace / "src" / "result.py"
            target.parent.mkdir()
            content = b"VALUE = 1\n"
            target.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            reference = "test-content:" + digest
            event = {
                "schema": "SITINA_FILE_MUTATION_EVENT_V1",
                "sequence": 1,
                "operation": "create",
                "path": str(target.resolve()),
                "before_hash": None,
                "after_hash": "sha256:" + digest,
                "authorization_ref": "approval-fixture",
                "denied": False,
            }
            arguments = {
                "run_id": "run-1",
                "execution_attempt_id": "execution-attempt:" + "a" * 64,
                "workspace": workspace,
                "diff_paths": [str(target)],
                "mutation_events": [event],
                "content_refs": {str(target.resolve()): reference},
            }
            first, first_hash = build_patch_manifest(**arguments)
            second, second_hash = build_patch_manifest(**arguments)
            self.assertEqual(first, second)
            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first["entries"][0]["mutation_operations"], ["create"])
            destination = Path(parent) / "replayed"
            tree_hash = replay_patch_manifest(
                first,
                destination=destination,
                load_content=lambda value: content if value == reference else b"",
            )
            self.assertEqual(tree_hash, first["after_tree_hash"])
            self.assertEqual((destination / "src/result.py").read_bytes(), content)

    def test_patch_replay_rejects_content_identity_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            workspace = Path(parent) / "workspace"
            workspace.mkdir()
            target = workspace / "x.py"
            target.write_text("x = 1\n", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            manifest, _digest = build_patch_manifest(
                run_id="run-1",
                execution_attempt_id="execution-attempt:" + "b" * 64,
                workspace=workspace,
                diff_paths=[str(target)],
                mutation_events=[
                    {
                        "sequence": 1,
                        "operation": "create",
                        "path": str(target.resolve()),
                        "before_hash": None,
                        "after_hash": digest,
                        "authorization_ref": "approval-fixture",
                        "denied": False,
                    }
                ],
                content_refs={str(target.resolve()): "test-content:" + digest},
            )
            with self.assertRaises(ExecutionPatchError):
                replay_patch_manifest(
                    manifest,
                    destination=Path(parent) / "tampered",
                    load_content=lambda _reference: b"tampered",
                )

    def test_patch_manifest_rejects_hidden_or_unsupported_successful_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            workspace = Path(parent) / "workspace"
            workspace.mkdir()
            target = workspace / "result.txt"
            hidden = workspace / "hidden.txt"
            target.write_text("result", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            base_event = {
                "sequence": 1,
                "operation": "modify",
                "path": str(target.resolve()),
                "before_hash": "1" * 64,
                "after_hash": digest,
                "authorization_ref": "approval-result",
                "denied": False,
            }
            with self.assertRaisesRegex(
                ExecutionPatchError, "exactly match the collected diff"
            ):
                build_patch_manifest(
                    run_id="run-hidden",
                    execution_attempt_id="execution-attempt:" + "c" * 64,
                    workspace=workspace,
                    diff_paths=[str(target)],
                    mutation_events=[
                        base_event,
                        {
                            **base_event,
                            "sequence": 2,
                            "path": str(hidden.resolve(strict=False)),
                            "authorization_ref": "approval-hidden",
                        },
                    ],
                    content_refs={str(target.resolve()): "content:" + digest},
                )
            for operation in ("delete", "rename"):
                with self.subTest(operation=operation), self.assertRaisesRegex(
                    ExecutionPatchError,
                    "destructive mutation is outside the accepted Step6 contract",
                ):
                    build_patch_manifest(
                        run_id="run-" + operation,
                        execution_attempt_id="execution-attempt:" + "d" * 64,
                        workspace=workspace,
                        diff_paths=[str(target)],
                        mutation_events=[{**base_event, "operation": operation}],
                        content_refs={str(target.resolve()): "content:" + digest},
                    )

    def test_patch_replay_rejects_tampered_destructive_operation(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            workspace = Path(parent) / "workspace"
            workspace.mkdir()
            target = workspace / "result.txt"
            target.write_text("result", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            manifest, _manifest_hash = build_patch_manifest(
                run_id="run-tampered-operation",
                execution_attempt_id="execution-attempt:" + "e" * 64,
                workspace=workspace,
                diff_paths=[str(target)],
                mutation_events=[
                    {
                        "sequence": 1,
                        "operation": "create",
                        "path": str(target.resolve()),
                        "before_hash": None,
                        "after_hash": digest,
                        "authorization_ref": "approval-result",
                        "denied": False,
                    }
                ],
                content_refs={str(target.resolve()): "content:" + digest},
            )
            manifest["entries"][0]["operation"] = "delete"
            with self.assertRaisesRegex(
                ExecutionPatchError, "operation contract is invalid"
            ):
                replay_patch_manifest(
                    manifest,
                    destination=Path(parent) / "tampered-operation",
                    load_content=lambda _reference: target.read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
