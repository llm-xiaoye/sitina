from __future__ import annotations

import dataclasses
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.orchestrator.execution_bridge import (
    ExecutionBinding,
    ExecutionBridgeError,
    ExecutionIdentityBinding,
    VerificationVerdict,
    run_safe_execution,
)
from sitina.orchestrator.true_multi_agent import (
    DynamicCollaborationError,
    RunEvidence,
    TrueMultiAgentProductionRuntime,
    UsageAggregationError,
    _embedded_usage_delta,
    _merge_embedded_attempt_accounting,
)
from sitina.orchestrator.true_multi_agent_runtime import AgentIdentity, AgentRegistry
from sitina.orchestrator.execution_patch import (
    ExecutionPatchError,
    build_patch_manifest,
    replay_patch_manifest,
)


EXECUTOR_ID = "forge-execution-role"


def identity() -> ExecutionIdentityBinding:
    return ExecutionIdentityBinding.fixture(
        proposer_id="agent-atlas",
        executor_id=EXECUTOR_ID,
        verifier_id="agent-delta",
        policy_hash="b" * 64,
    )


def identity_variants() -> dict[str, ExecutionIdentityBinding]:
    common = {
        "proposer_id": "agent-atlas",
        "executor_id": EXECUTOR_ID,
        "verifier_id": "agent-delta",
        "policy_hash": "b" * 64,
    }
    return {
        "proposer_id": ExecutionIdentityBinding.fixture(
            **{**common, "proposer_id": "agent-borealis"}
        ),
        "verifier_id": ExecutionIdentityBinding.fixture(
            **{**common, "verifier_id": "agent-horizon"}
        ),
        "registry_hash": ExecutionIdentityBinding.fixture(
            **common, registry_hash="c" * 64
        ),
        "policy_hash": ExecutionIdentityBinding.fixture(
            **{**common, "policy_hash": "d" * 64}
        ),
        "executor_role_authorization_ref": ExecutionIdentityBinding.fixture(
            **{**common, "policy_hash": "e" * 64}
        ),
        "authority_ref": ExecutionIdentityBinding.fixture(
            **common, authority_resolution_id="f" * 64
        ),
    }


def binding() -> ExecutionBinding:
    return ExecutionBinding(
        winner_output_hash="a" * 64,
        approved_scope=("src/",),
        policy_hash=identity().policy_hash,
        run_id="run-1",
        identity=identity(),
    )


def ok_forge(attempt, workspace):
    return {"terminal_state": "SUCCEEDED", "tool_call_count": 1}


def accepted_verdict(verifier_id="agent-delta", *, checked_diff=True):
    return VerificationVerdict(
        True,
        verifier_id,
        checked_diff,
        True,
        identity(),
        test_evidence_ref="test-evidence:" + "c" * 64,
        test_evidence_hash="c" * 64,
    )


class ExecutionBridgeTests(unittest.TestCase):
    def test_accept_path_returns_accepted_result(self) -> None:
        rolled: list[int] = []
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
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
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge,
            collect_diff=lambda: ["src/bad.py"],
            boundary_check=lambda diff: [],
            verifier=lambda diff, res: VerificationVerdict(
                False, "agent-delta", True, True, identity(), ("test failed",)
            ),
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
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: VerificationVerdict(
                True, "agent-delta", True, False, identity()
            ),  # no test evidence
            rollback=lambda a: rolled.append(a), max_attempts=2,
        )
        self.assertFalse(result.accepted)
        self.assertIn("rework_exhausted_fail_closed", result.notes)
        self.assertEqual(rolled, [1, 2])

    def test_accept_without_immutable_evidence_reference_is_rejected(self) -> None:
        rolled: list[int] = []
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: VerificationVerdict(
                True, "agent-delta", True, True, identity()
            ),
            rollback=lambda a: rolled.append(a), max_attempts=1,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(rolled, [1])

    def test_executor_cannot_be_its_own_verifier(self) -> None:
        with self.assertRaisesRegex(ValueError, "three distinct"):
            ExecutionIdentityBinding.fixture(
                proposer_id="agent-atlas",
                executor_id=EXECUTOR_ID,
                verifier_id=EXECUTOR_ID,
            )

    def test_verifier_must_inspect_actual_diff(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: accepted_verdict(checked_diff=False),  # checked_diff=False
            rollback=lambda a: None, max_attempts=1,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.attempt_ledger[0]["failure_type"], "TesterBindingError")

    def test_sensitive_diff_blocked_before_accept_fail_closed(self) -> None:
        verifier_called: list[bool] = []
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
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
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=flaky_forge, collect_diff=lambda: ["src/ok.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: accepted_verdict(),
            rollback=lambda a: None, max_attempts=2,
        )
        self.assertTrue(result.accepted)
        self.assertEqual(attempts_seen, [1, 2])

    def test_forge_exception_is_bounded_and_replanned_from_typed_failure(self) -> None:
        forge_attempts: list[int] = []
        rollback_attempts: list[int] = []
        replans: list[dict[str, object]] = []

        def forge(attempt, _workspace):
            forge_attempts.append(attempt)
            raise ValueError("fixture forge failure")

        def replan(attempt, failure):
            replans.append({"attempt": attempt, **dict(failure)})
            return {"plan_hash": "c" * 64, "prior_failure_hash": failure["failure_hash"]}

        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda _diff: [], verifier=lambda _diff, _result: accepted_verdict(),
            rollback=lambda attempt: rollback_attempts.append(attempt), max_attempts=2,
            replan=replan,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.status, "rejected")
        self.assertEqual(forge_attempts, [1, 2])
        self.assertEqual(rollback_attempts, [1, 2])
        self.assertEqual(len(replans), 1)
        self.assertEqual(replans[0]["failure_type"], "ValueError")
        self.assertEqual(len(result.attempt_ledger), 2)
        self.assertEqual(result.attempt_ledger[0]["failure_type"], "ValueError")
        self.assertTrue(result.attempt_ledger[1]["replan"])
        self.assertTrue(result.attempt_ledger[1]["same_failure"])
        self.assertEqual(result.attempt_ledger[1]["prior_failure_hash"], result.attempt_ledger[0]["failure_hash"])
        self.assertEqual(result.attempt_ledger[1]["plan_hash"], "c" * 64)
        self.assertTrue(all(item["rollback"] == "ok" for item in result.attempt_ledger))

    def test_forge_failure_ledger_seals_reason_stage_mutation_and_original_plan(self) -> None:
        original_plan_hash = "d" * 64
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=lambda _attempt, _workspace: {
                "terminal_state": "FAILED",
                "error_type": "ProviderHTTPError",
                "error_hash": "e" * 64,
                "reason_code": "PROVIDER_HTTP_FAILURE",
                "failure_stage": "Forge",
                "mutation_count": 0,
                "forge_bound": True,
            },
            collect_diff=lambda: [], boundary_check=lambda _diff: [],
            verifier=lambda _diff, _result: accepted_verdict(),
            rollback=lambda _attempt: None, max_attempts=1,
            original_plan_hash=original_plan_hash,
        )
        self.assertFalse(result.accepted)
        failure = result.attempt_ledger[0]
        self.assertEqual(failure["reason_code"], "PROVIDER_HTTP_FAILURE")
        self.assertEqual(failure["failure_stage"], "Forge")
        self.assertEqual(failure["mutation_count"], 0)
        self.assertEqual(failure["original_plan_hash"], original_plan_hash)

    def test_rollback_failure_terminalizes_failed_and_is_recorded(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=lambda _attempt, _workspace: (_ for _ in ()).throw(RuntimeError("forge")),
            collect_diff=lambda: [], boundary_check=lambda _diff: [],
            verifier=lambda _diff, _result: accepted_verdict(),
            rollback=lambda _attempt: (_ for _ in ()).throw(OSError("rollback")),
            max_attempts=2,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.attempts, 1)
        self.assertEqual(len(result.attempt_ledger), 1)
        self.assertEqual(result.attempt_ledger[0]["rollback"], "failed")
        self.assertEqual(result.attempt_ledger[0]["rollback_failure_type"], "OSError")

    def test_usage_aggregation_fault_is_typed_before_totals_are_mutated(self) -> None:
        with self.assertRaises(UsageAggregationError):
            _embedded_usage_delta({"provider_token_total": "not-an-integer"})
        self.assertEqual(
            _embedded_usage_delta({"provider_call_count": 1, "provider_token_total": 7})["total_tokens"],
            7,
        )

    def test_post_settlement_forge_failure_uses_executor_delta(self) -> None:
        before = {
            "provider_calls": 2, "physical_sends": 2, "input_tokens": 10,
            "output_tokens": 5, "cache_read_tokens": 0, "cache_write_tokens": 0,
            "total_tokens": 15, "cost_micro_usd": 4, "retry_count": 1,
            "fallback_count": 0, "unsettled_usage_count": 0,
        }
        after = {**before, "provider_calls": 3, "physical_sends": 3,
                 "input_tokens": 12, "output_tokens": 6, "total_tokens": 18,
                 "cost_micro_usd": 5}
        result = _merge_embedded_attempt_accounting(
            {"status": "error", "error_type": "ToolRuntimeError"},
            before,
            after,
            provider_profile="fallback",
            provider_model="model-b",
        )
        self.assertEqual(result["provider_call_count"], 1)
        self.assertEqual(result["provider_physical_send_count"], 1)
        self.assertEqual(result["provider_input_tokens"], 2)
        self.assertEqual(result["provider_output_tokens"], 1)
        self.assertEqual(result["provider_token_total"], 3)
        self.assertEqual(result["provider_profile"], "fallback")
        self.assertEqual(result["provider_model"], "model-b")
        self.assertEqual(result["provider_usage_status"], "settled")

    def test_runtime_cleanup_event_precedes_terminal_evidence_and_binds_failure(self) -> None:
        class Stream:
            def __init__(self):
                self.events = []

            def append(self, stage, facts, **_kwargs):
                self.events.append((stage, facts))

        runtime = object.__new__(TrueMultiAgentProductionRuntime)
        runtime.home = Path(tempfile.mkdtemp())
        evidence = RunEvidence("run-cleanup-runtime", "change", "a" * 64, "b" * 64)
        stream = Stream()
        report = {
            "run_id": evidence.run_id,
            "repo": "/tmp/target",
            "worktree": "/tmp/worktree",
            "status": "ok",
            "registered_before": True,
            "registered_after": False,
            "removed": True,
            "physical_removed": True,
            "audit_recorded": True,
            "porcelain_before_sha256": "c" * 64,
            "porcelain_after_sha256": "d" * 64,
        }
        with patch("sitina.orchestrator.git_ops.GitWorktreeManager") as manager_type:
            manager_type.return_value.cleanup_for_run.return_value = report
            actual = runtime._cleanup_before_terminalize(
                run_id=evidence.run_id,
                controls={"execution_workspace": "/tmp/target"},
                run_stream=stream,
                evidence=evidence,
            )
        self.assertEqual(actual["status"], "ok")
        stream.append("run-terminal", ({"event_type": "run.terminal"},))
        self.assertLess(
            next(i for i, item in enumerate(stream.events) if item[0] == "execution-worktree-cleanup-finally"),
            next(i for i, item in enumerate(stream.events) if item[0] == "run-terminal"),
        )
        self.assertEqual(evidence.expected_terminal, "SUCCEEDED")

        failing_stream = Stream()
        failing_evidence = RunEvidence("run-cleanup-failure", "change", "e" * 64, "f" * 64)
        manager_type.return_value.cleanup_for_run.return_value = {
            **report, "run_id": failing_evidence.run_id, "status": "failed", "removed": False,
            "audit_recorded": False,
        }
        with patch("sitina.orchestrator.git_ops.GitWorktreeManager", manager_type):
            failed = runtime._cleanup_before_terminalize(
                run_id=failing_evidence.run_id,
                controls={"execution_workspace": "/tmp/target"},
                run_stream=failing_stream,
                evidence=failing_evidence,
            )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failing_evidence.expected_terminal, "FAILED")
        self.assertTrue(failing_evidence.execution_result["cleanup_failed"])

        class BrokenStream(Stream):
            def append(self, *_args, **_kwargs):
                raise RuntimeError("journal append fault")

        event_failure_evidence = RunEvidence("run-cleanup-event-failure", "change", "1" * 64, "2" * 64)
        with patch("sitina.orchestrator.git_ops.GitWorktreeManager", manager_type):
            runtime._cleanup_before_terminalize(
                run_id=event_failure_evidence.run_id,
                controls={"execution_workspace": "/tmp/target"},
                run_stream=BrokenStream(),
                evidence=event_failure_evidence,
            )
        self.assertEqual(event_failure_evidence.expected_terminal, "FAILED")
        self.assertTrue(event_failure_evidence.execution_result["cleanup_failed"])

    def test_tester_exception_is_ledgered_and_reworked(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/tested.py"],
            boundary_check=lambda _diff: [],
            verifier=lambda _diff, _result: (_ for _ in ()).throw(RuntimeError("tester unavailable")),
            rollback=lambda _attempt: None, max_attempts=2,
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.attempts, 2)
        self.assertEqual([item["failure_type"] for item in result.attempt_ledger], ["TesterExecutionError", "TesterExecutionError"])
        self.assertTrue(result.attempt_ledger[1]["same_failure"])

    def test_result_carries_immutable_binding(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
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
        execution_identity = ev["execution_identity"]
        self.assertEqual(execution_identity["proposer_id"], "agent-atlas")
        self.assertEqual(execution_identity["executor_id"], EXECUTOR_ID)
        self.assertEqual(execution_identity["verifier_id"], "agent-delta")
        for field in (
            "registry_hash",
            "policy_hash",
            "executor_role_authorization_ref",
            "authority_ref",
        ):
            self.assertTrue(execution_identity[field])

    def test_every_identity_binding_changes_verdict_result_and_event_hashes(self) -> None:
        first = run_safe_execution(
            binding=binding(),
            executor_id=EXECUTOR_ID,
            workspace="/ws",
            forge_runner=ok_forge,
            collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: accepted_verdict(),
            rollback=lambda a: None,
            max_attempts=1,
        )
        assert first.verification is not None
        base_mapping = first.binding.identity.mapping()
        for field, alternate_identity in identity_variants().items():
            with self.subTest(field=field):
                self.assertNotEqual(
                    base_mapping[field],
                    alternate_identity.mapping()[field],
                )
                alternate_binding = ExecutionBinding(
                    "a" * 64,
                    ("src/",),
                    alternate_identity.policy_hash,
                    "run-1",
                    alternate_identity,
                )
                alternate_verdict = VerificationVerdict(
                    True,
                    alternate_identity.verifier_id,
                    True,
                    True,
                    alternate_identity,
                    test_evidence_ref="test-evidence:" + "c" * 64,
                    test_evidence_hash="c" * 64,
                )
                second = run_safe_execution(
                    binding=alternate_binding,
                    executor_id=EXECUTOR_ID,
                    workspace="/ws",
                    forge_runner=ok_forge,
                    collect_diff=lambda: ["src/x.py"],
                    boundary_check=lambda d: [],
                    verifier=lambda d, r, value=alternate_verdict: value,
                    rollback=lambda a: None,
                    max_attempts=1,
                )
                self.assertNotEqual(
                    first.verification.verdict_hash,
                    alternate_verdict.verdict_hash,
                )
                self.assertNotEqual(first.execution_attempt_id, second.execution_attempt_id)
                self.assertNotEqual(first.result_id, second.result_id)
                self.assertNotEqual(first.event_hash, second.event_hash)

    def test_result_rejects_verdict_bound_to_another_identity(self) -> None:
        other = identity_variants()["registry_hash"]
        with self.assertRaisesRegex(ValueError, "verifier identity differs"):
            dataclasses.replace(
                run_safe_execution(
                    binding=binding(),
                    executor_id=EXECUTOR_ID,
                    workspace="/ws",
                    forge_runner=ok_forge,
                    collect_diff=lambda: ["src/x.py"],
                    boundary_check=lambda d: [],
                    verifier=lambda d, r: accepted_verdict(),
                    rollback=lambda a: None,
                    max_attempts=1,
                ),
                verification=VerificationVerdict(
                    True,
                    other.verifier_id,
                    True,
                    True,
                    other,
                    test_evidence_ref="test-evidence:" + "c" * 64,
                    test_evidence_hash="c" * 64,
                ),
            )

    def test_no_qualified_independent_verifier_fails_closed(self) -> None:
        proposer_only = AgentIdentity(
            "agent-proposer",
            "proposer",
            ("proposal", "read-only"),
            "fixture",
            1,
            ("read-only", "provider-text-only"),
        )
        review_only = AgentIdentity(
            "agent-review-only",
            "reviewer",
            ("review", "read-only"),
            "fixture",
            1,
            ("read-only", "provider-text-only"),
        )
        runtime = object.__new__(TrueMultiAgentProductionRuntime)
        runtime.registry = AgentRegistry(
            1, (proposer_only, review_only), "a" * 64
        )
        with self.assertRaisesRegex(
            DynamicCollaborationError, "no qualified independent verifier"
        ):
            runtime._independent_verifier_id(
                proposer_only.agent_id, EXECUTOR_ID
            )

    def test_out_of_scope_diff_is_blocked_before_boundary_or_verifier(self) -> None:
        observed: list[str] = []
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
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
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py", "src/x.py"],
            boundary_check=lambda d: [], verifier=lambda d, r: accepted_verdict(),
            rollback=lambda a: None, max_attempts=1,
        )
        self.assertEqual(result.status, "blocked")

    def test_filesystem_evidence_reference_must_match_hash(self) -> None:
        result = run_safe_execution(
            binding=binding(), executor_id=EXECUTOR_ID, workspace="/ws",
            forge_runner=ok_forge, collect_diff=lambda: ["src/x.py"],
            boundary_check=lambda d: [],
            verifier=lambda d, r: VerificationVerdict(
                True, "agent-delta", True, True,
                identity(),
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

    def test_patch_manifest_rejects_hidden_successful_mutations(self) -> None:
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
    def test_patch_manifest_supports_delete_tombstone_and_rename(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            workspace = Path(parent) / "workspace"
            workspace.mkdir()
            source = workspace / "old.py"
            destination = workspace / "new.py"
            source.write_bytes(b"value = 1\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            source.rename(destination)
            rename_event = {
                "sequence": 1, "operation": "rename", "path": str(source.resolve()),
                "destination": str(destination.resolve()), "before_hash": digest,
                "after_hash": digest, "authorization_ref": "appr-rename", "denied": False,
            }
            rename_manifest, _ = build_patch_manifest(
                run_id="run-rename", execution_attempt_id="execution-attempt:" + "d" * 64,
                workspace=workspace, diff_paths=[str(source)], mutation_events=[rename_event],
                content_refs={str(source.resolve()): "content:" + digest},
            )
            self.assertEqual(rename_manifest["schema"], "SITINA_EXECUTION_PATCH_MANIFEST_V2")
            self.assertEqual(rename_manifest["entries"][0]["operation"], "rename")
            self.assertEqual(rename_manifest["entries"][0]["destination"], "new.py")
            replay_root = Path(parent) / "rename-replay"
            replay_patch_manifest(
                rename_manifest, destination=replay_root,
                load_content=lambda _reference: b"value = 1\n",
            )
            self.assertEqual((replay_root / "new.py").read_bytes(), b"value = 1\n")

            deleted = workspace / "delete.py"
            deleted.write_bytes(b"remove me\n")
            deleted_digest = hashlib.sha256(deleted.read_bytes()).hexdigest()
            deleted.unlink()
            delete_manifest, _ = build_patch_manifest(
                run_id="run-delete", execution_attempt_id="execution-attempt:" + "e" * 64,
                workspace=workspace, diff_paths=[str(deleted)], mutation_events=[{
                    "sequence": 1, "operation": "delete", "path": str(deleted.resolve()),
                    "before_hash": deleted_digest, "after_hash": None,
                    "authorization_ref": "appr-delete", "denied": False,
                }], content_refs={},
            )
            self.assertTrue(delete_manifest["entries"][0]["tombstone"])
            self.assertIsNone(delete_manifest["entries"][0]["after_hash"])

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
                ExecutionPatchError, "explicit tombstone"
            ):
                replay_patch_manifest(
                    manifest,
                    destination=Path(parent) / "tampered-operation",
                    load_content=lambda _reference: target.read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
