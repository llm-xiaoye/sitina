from __future__ import annotations

import json
import hashlib
import hmac
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sitina.orchestrator.code_mode_gate import (
    CANARY_PASSED,
    CODE_MODE_BLOCKED,
    CODE_MODE_READY,
    CodeModeAcceptanceV1,
    CodeModeRuntimePolicy,
    build_candidate_manifest,
    classify_code_mode_intent,
    verify_candidate_manifest,
)
from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext, open_trusted_code_mode_context
from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBroker
from sitina.orchestrator.code_mode_controller import CodeModeControllerSession
from tests.code_mode_host_fixture import launch_code_mode_host
from tests.code_mode_reviewer_fixture import launch_code_mode_reviewer
from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream, TrueMultiAgentRuntimeError
from sitina.security.key_provider import InMemoryKeyProvider
from sitina.journal.model import canonical_json_bytes
from sitina.cas.crypto import encrypt_object


def _bootstrap_context(home: Path, *, provider: InMemoryKeyProvider | None = None) -> CodeModeRuntimeContext:
    repo = Path(__file__).resolve().parents[1]
    workspace = home / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    keys = provider or InMemoryKeyProvider(environment="code-mode", namespace="gate-bootstrap")
    preview = CodeModeRuntimeContext.open(home, provider=keys, source_root=repo)
    broker = launch_code_mode_host(
        state_root=home, workspace=workspace,
        runtime_state_identity=preview.identity.state_identity,
        runtime_journal_id=preview.identity.journal_id,
        source_root=repo, provider=keys,
    )
    context = broker.context_factory(provider=keys, source_root=repo)(home)
    # Keep the broker alive for the lifetime of the context.  The test process
    # owns cleanup at interpreter exit; no signing key crosses this boundary.
    context._test_broker = broker
    return context


class CodeModeRuntimePolicyTests(unittest.TestCase):
    def test_negated_constraints_do_not_authorize_mutation(self) -> None:
        self.assertFalse(classify_code_mode_intent("Do not modify files or push.")["explicit_mutation"])
        self.assertTrue(classify_code_mode_intent("Do not push, but update the file.")["explicit_mutation"])
        self.assertTrue(classify_code_mode_intent("不要推送，但修改文件")["explicit_mutation"])

    def test_plan_discussion_and_nested_markers_do_not_authorize_mutation(self) -> None:
        readonly = classify_code_mode_intent("只读分析修复方案，不要修改文件")
        self.assertFalse(readonly["explicit_mutation"])
        self.assertEqual(readonly["negated_operations"], ["modify"])
        self.assertTrue(classify_code_mode_intent("修复代码但不要提交")["explicit_mutation"])

    def test_fast_is_read_only_and_multi_requires_current_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            policy = CodeModeRuntimePolicy()
            fast = policy.authorize(
                mode="FAST", message="update this file", session_id="session-1", workspace=workspace
            )
            self.assertFalse(fast["allowed"])
            self.assertIn("FAST", " ".join(fast["reasons"]))
            no_session = policy.authorize(
                mode="MULTI", message="update this file", session_id="", workspace=workspace
            )
            self.assertFalse(no_session["allowed"])
            multi = policy.authorize(
                mode="MULTI", message="update this file", session_id="session-1", workspace=workspace
            )
            self.assertTrue(multi["allowed"])
            self.assertTrue(multi["intent_authorized"])

    def test_issued_authorization_rejects_mapping_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            policy = CodeModeRuntimePolicy()
            authorization = policy.authorize(
                mode="MULTI", message="update this file", session_id="session-1", workspace=workspace
            )
            tampered = dict(authorization)
            tampered["workspace"] = str(workspace.parent)
            self.assertFalse(
                policy.validate_issued_authorization(
                    tampered,
                    mode="MULTI",
                    message="update this file",
                    session_id="session-1",
                    workspace=workspace,
                )
            )

    def test_issued_authorization_rejects_extended_or_expired_parent_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            policy = CodeModeRuntimePolicy()
            authorization = policy.authorize(
                mode="MULTI", message="update this file", session_id="session-1", workspace=workspace
            )
            extended = dict(authorization)
            extended["expires_at"] = int(authorization["expires_at"]) + 3600
            self.assertFalse(policy.validate_issued_authorization(
                extended, mode="MULTI", message="update this file", session_id="session-1", workspace=workspace
            ))
            expired = dict(authorization)
            expired["expires_at"] = int(authorization["issued_at"])
            self.assertFalse(policy.validate_issued_authorization(
                expired, mode="MULTI", message="update this file", session_id="session-1", workspace=workspace
            ))

    def test_production_and_symlink_targets_fail_closed_for_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            policy = CodeModeRuntimePolicy(production_home=workspace)
            denied = policy.authorize(
                mode="MULTI", message="create a file", session_id="session-1", workspace=workspace
            )
            self.assertFalse(denied["allowed"])
            link = workspace / "link"
            target = workspace / "target"
            target.mkdir()
            link.symlink_to(target, target_is_directory=True)
            denied_link = CodeModeRuntimePolicy().authorize(
                mode="MULTI", message="create a file", session_id="session-1", workspace=link
            )
            self.assertFalse(denied_link["allowed"])


class CodeModePostExecutionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp())
        (self.workspace / "config").mkdir()
        (self.workspace / "config" / "code_mode_profile.json").write_text(
            json.dumps(
                {
                    "schema": "CODE_MODE_PROFILE_V1",
                    "provider": {"profile": "deepseek", "model": "deepseek-v4-pro", "no_fallback": True},
                    "identity_paths": ["config/code_mode_profile.json"],
                    "test_inventory": ["tests/code_mode"],
                }
            ),
            encoding="utf-8",
        )
        self.gate = CodeModeAcceptanceV1(self.workspace)
        self._reviewer_sessions = []

    def tearDown(self) -> None:
        import shutil

        for reviewer in self._reviewer_sessions:
            reviewer.close()
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_real_v2_gate_ready_canary_issue_is_one_use_and_drift_is_rejected(self) -> None:
        """Run the real offline handoff before exercising the live gate boundary.

        The scripted provider is deliberately non-authoritative and performs
        no network request.  It still drives ConversationRuntime → MULTI →
        file tool → Tester/package/request.  The test-only TTY seam consumes
        those real locators; it does not manufacture a test or authorization
        receipt.  Canary issuance is exercised only as a broker-signed,
        no-fallback authorization; no physical transport is attempted.
        """
        from tests.test_code_mode_runtime_integration import _ScriptedCodeModeProvider
        from sitina.conversation.runtime import ConversationRuntime
        from sitina.orchestrator.true_multi_agent import TrueMultiAgentProductionRuntime

        repo = Path(__file__).resolve().parents[1]
        runtime_home = Path(tempfile.mkdtemp(prefix="code-mode-gate-runtime-"))
        reviewer = launch_code_mode_reviewer()
        self._reviewer_sessions.append(reviewer)
        original_profile = (self.workspace / "config" / "code_mode_profile.json").read_bytes()
        try:
            shutil.copytree(repo / "config", runtime_home / "config")
            (runtime_home / "state").mkdir()
            keys = InMemoryKeyProvider(environment="code-mode", namespace="gate-positive")
            provider = _ScriptedCodeModeProvider(self.workspace)
            preview = CodeModeRuntimeContext.open(runtime_home, provider=keys, source_root=repo)
            broker = launch_code_mode_host(
                state_root=runtime_home, workspace=self.workspace,
                runtime_state_identity=preview.identity.state_identity,
                runtime_journal_id=preview.identity.journal_id,
                source_root=repo, provider=keys,
                reviewer_verification=reviewer.tty_verification_material,
            )

            def context_factory(root: Path) -> CodeModeRuntimeContext:
                return CodeModeRuntimeContext.open(root, provider=keys)

            trusted_context_factory = broker.context_factory(provider=keys, source_root=repo)

            multi = TrueMultiAgentProductionRuntime(
                runtime_home,
                runtime_context_factory=trusted_context_factory,
                provider_client=provider,
                provider_profile=provider.profile,
            )
            conversation = ConversationRuntime(
                runtime_home,
                workspace=self.workspace,
                multi_runtime=multi,
                runtime_context_factory=trusted_context_factory,
            )
            session = conversation.resume_or_create_session()
            with patch(
                "sitina.orchestrator.bplus_production.ProductionRuntimeContext.load",
                side_effect=AssertionError("Code Mode Gate must not consult Legacy B+"),
            ):
                pending = conversation.execute_turn(
                    session,
                    "Please create gate-positive.py and run the focused test; do not commit or push.",
                )
            self.assertEqual(pending["terminal_state"], "REVIEW_PENDING", pending)
            self.assertTrue((self.workspace / "hello.py").is_file())
            self.assertEqual(provider.physical_requests, 0)
            for key in ("machine_check_receipt", "evidence_package", "review_request"):
                self.assertIsInstance(pending[key], dict)

            # Reopen the host-issued TTY receipt through the same attested
            # Code Mode context used by the controller.  A direct offline
            # context is intentionally unable to verify the receipt.
            context = trusted_context_factory(runtime_home)
            conversation.code_mode_reviewer_session = reviewer

            def tty_rpc(request: dict[str, object]) -> dict[str, object]:
                if request.get("method") == "tty_confirm":
                    review = request["review_request"]
                    self.assertIsInstance(review, dict)
                    summary = {
                        key: review.get(key)
                        for key in (
                            "candidate_id", "tree_hash", "run_id",
                            "evidence_package_ref", "evidence_package_hash",
                        )
                    }
                    summary["nonce"] = review["tty_nonce"]
                    summary["expires_at"] = review["tty_expires_at"]
                    proof = {
                        "schema": "CODE_MODE_TTY_CONFIRMATION_V1",
                        "issuer_id": str(reviewer.identity["issuer_id"]),
                        "request_ref": review["reference_id"],
                        "request_hash": review["content_hash"],
                        "nonce_hash": hashlib.sha256(str(review["tty_nonce"]).encode()).hexdigest(),
                        "expires_at": review["tty_expires_at"],
                        "issued_at": int(time.time()),
                        "confirmed_at": int(time.time()),
                        "summary_hash": hashlib.sha256(canonical_json_bytes(summary)).hexdigest(),
                    }
                    proof["issuer_signature"] = hmac.new(
                        bytes.fromhex(str(reviewer.tty_verification_material["mac_key_hex"])),
                        canonical_json_bytes(proof), hashlib.sha256,
                    ).hexdigest()
                    return {"proof": proof}
                if request.get("method") == "verify_tty_confirmation":
                    return {"valid": True}
                raise AssertionError("unexpected test-only TTY request")

            with patch.object(reviewer, "_rpc", side_effect=tty_rpc):
                accepted = conversation.maybe_confirm_tty_review(pending)
            self.assertEqual(accepted["code_mode_status"], "CODE_MODE_READY", accepted)
            self.assertEqual(accepted["review_status"], "ACCEPT")
            self.assertEqual(accepted["terminal_state"], "SUCCEEDED")

            gate_ready = self.gate.evaluate_offline(
                accepted["candidate"],
                test_inventory=pending["test_inventory"],
                runtime_context=context,
                test_receipt=pending["test_receipt"],
                reviewer_receipt=accepted["tty_review_receipt"],
            )
            self.assertEqual(gate_ready["status"], CODE_MODE_READY, gate_ready)
            # Live admission receives only the opaque handoff locators.  The
            # Gate projection above is not an authorization body and cannot
            # be forwarded to the host as one.
            gate_ready.update({
                "candidate_locator": accepted["candidate_locator"],
                "evidence_package_locator": accepted["evidence_package"],
                "core_locator": accepted["execution_core_locator"],
                "review_request_locator": accepted["review_request"],
                "review_locator": accepted["tty_review_receipt"],
                "gate_locator": {"reference_id": accepted["gate_locator"], "object_hash": accepted["gate_locator"].removeprefix("cas:")},
            })
            self.assertNotEqual(
                pending["machine_check_receipt"]["reference_id"],
                pending["evidence_package"]["reference_id"],
            )
            self.assertNotEqual(
                pending["review_request"]["reference_id"],
                pending["evidence_package"]["reference_id"],
            )

            # Mutating an identity file after the real handoff invalidates the
            # locators; the original receipt is not a license to ignore drift.
            (self.workspace / "config" / "code_mode_profile.json").write_bytes(original_profile + b"\n")
            drifted = self.gate.evaluate_offline(
                accepted["candidate"],
                test_inventory=pending["test_inventory"],
                runtime_context=context,
                test_receipt=pending["test_receipt"],
                reviewer_receipt=accepted["tty_review_receipt"],
            )
            self.assertEqual(drifted["status"], CODE_MODE_BLOCKED, drifted)
            (self.workspace / "config" / "code_mode_profile.json").write_bytes(original_profile)

            # A real external broker signs the authorization only after the
            # positive, re-opened offline Gate result.  This does not send.
            trusted_context = broker.context_factory(provider=keys, source_root=repo)(runtime_home)
            trusted_context.issue_pre_provider_authorization(
                session_id=pending["conversation_session_id"],
                turn_index=pending["turn_index"],
                run_id=accepted["run_id"],
                run_attempt=1,
                generation=accepted["candidate"]["generation"],
                provider_profile=provider.profile.name,
                provider_model=provider.profile.model,
            )
            policy = CodeModeRuntimePolicy()
            message = "Please create gate-positive.py and run the focused test; do not commit or push."
            controller_authorization = policy.authorize(
                mode="MULTI", message=message,
                session_id=pending["conversation_session_id"], workspace=self.workspace,
            )
            controller_authorization = {
                **controller_authorization,
                "session_instance_id": trusted_context.session_instance_id,
                "run_id": accepted["run_id"],
                "run_attempt": 1,
                "generation": accepted["candidate"]["generation"],
            }
            # The scripted execution deliberately owns an offline controller.
            # Close that session before constructing the explicit no-network
            # authoritative host seam; reusing it and flipping a boolean would
            # incorrectly turn a non-authoritative model transport into a
            # canary issuer.
            existing_controller = multi._active_code_mode_controller
            self.assertIsInstance(existing_controller, CodeModeControllerSession)
            existing_controller.close()
            trusted_context._active_controller_session = None
            controller = CodeModeControllerSession(
                context=trusted_context,
                run_id=accepted["run_id"],
                session_id=pending["conversation_session_id"],
                authorization=controller_authorization,
                workspace=self.workspace,
                offline=False,
                session_instance_id=trusted_context.session_instance_id,
            )
            trusted_context._active_controller_session = controller
            try:
                authorization = self.gate.issue_canary_authorization(
                    candidate={**accepted["candidate"], "candidate_locator": accepted["candidate_locator"]}, offline_gate=gate_ready,
                    session_id=pending["conversation_session_id"], run_id=accepted["run_id"],
                    selected_workspace=self.workspace, runtime_context=trusted_context,
                    controller_session=controller,
                )
                self.assertFalse(authorization["fallback_allowed"])
                self.assertEqual(authorization["candidate_id"], accepted["candidate"]["candidate_id"])
                trusted_context.consume_canary_authorization(authorization)
                with self.assertRaises(PermissionError):
                    trusted_context.consume_canary_authorization(authorization)
            finally:
                controller.close()
                trusted_context._test_broker = broker
        finally:
            if "broker" in locals():
                broker.close()
            shutil.rmtree(runtime_home, ignore_errors=True)

    def test_candidate_drift_is_post_execution_failure_not_start_license(self) -> None:
        candidate = self.gate.freeze_candidate()
        (self.workspace / "config" / "code_mode_profile.json").write_text(
            json.dumps({
                "schema": "CODE_MODE_PROFILE_V1",
                "provider": {"profile": "deepseek", "model": "deepseek-v4-pro", "no_fallback": True},
                "identity_paths": ["config/code_mode_profile.json"],
                "test_inventory": ["tests/code_mode"],
                "candidate_revision": "changed",
            }),
            encoding="utf-8",
        )
        valid, errors = verify_candidate_manifest(self.workspace, candidate)
        self.assertFalse(valid)
        self.assertTrue(errors)

    def test_runtime_artifact_is_excluded_but_source_root_change_drifts(self) -> None:
        candidate = self.gate.freeze_candidate()
        (self.workspace / "artifacts").mkdir()
        (self.workspace / "artifacts" / "old-canary.json").write_text("runtime\n", encoding="utf-8")
        valid, errors = verify_candidate_manifest(self.workspace, candidate)
        self.assertTrue(valid, errors)
        (self.workspace / "config" / "code_mode_profile.json").write_text(
            json.dumps({"schema": "CODE_MODE_PROFILE_V1", "identity_paths": ["config/code_mode_profile.json"], "test_inventory": ["tests/code_mode"], "revision": "source-change"}),
            encoding="utf-8",
        )
        valid, errors = verify_candidate_manifest(self.workspace, candidate)
        self.assertFalse(valid)
        self.assertIn("candidate objects drifted", errors)

    def test_post_execution_inventory_covers_root_and_all_file_mutations(self) -> None:
        from sitina.orchestrator.code_mode_gate import build_candidate_manifest

        baseline = build_candidate_manifest(self.workspace)
        root_file = self.workspace / "hello.py"
        data_file = self.workspace / "data" / "user.txt"
        data_file.parent.mkdir()
        root_file.write_text("print('hello')\n", encoding="utf-8")
        data_file.write_text("user data\n", encoding="utf-8")
        created = build_candidate_manifest(
            self.workspace,
            identity_paths=None,
            changed_paths=("hello.py", "data/user.txt"),
        )
        created_paths = {item["path"] for item in created["objects"]}
        self.assertIn("hello.py", created_paths)
        self.assertIn("data/user.txt", created_paths)
        self.assertIn("hello.py", created["changed_paths"])
        self.assertIn("hello.py", {item["path"] for item in created["identity_files"]})
        self.assertTrue(
            set(created["changed_paths"]) <= (
                {item["path"] for item in created["objects"]}
                | {item["path"] for item in created["changed_path_records"]}
            )
        )
        self.assertNotEqual(created["candidate_id"], baseline["candidate_id"])
        self.assertNotEqual(created["tree_hash"], baseline["tree_hash"])
        self.assertNotEqual(created["worktree_digest"], baseline["worktree_digest"])
        valid, errors = verify_candidate_manifest(self.workspace, created)
        self.assertTrue(valid, errors)

        old_file = self.workspace / "old.py"
        old_file.write_text("old\n", encoding="utf-8")
        before_rename = build_candidate_manifest(self.workspace, identity_paths=None)
        new_file = self.workspace / "renamed.py"
        old_file.rename(new_file)
        renamed = build_candidate_manifest(
            self.workspace,
            identity_paths=None,
            changed_paths=("old.py", "renamed.py"),
        )
        renamed_paths = {item["path"] for item in renamed["objects"]}
        self.assertIn("renamed.py", renamed_paths)
        self.assertNotIn("old.py", renamed_paths)
        self.assertTrue(
            set(renamed["changed_paths"]) <= (
                renamed_paths | {item["path"] for item in renamed["changed_path_records"]}
            )
        )
        self.assertEqual(
            renamed["changed_path_records"],
            [
                {"path": "old.py", "kind": "deleted"},
                {"path": "renamed.py", "kind": "present"},
            ],
        )
        self.assertNotEqual(renamed["candidate_id"], before_rename["candidate_id"])
        self.assertNotEqual(renamed["tree_hash"], before_rename["tree_hash"])
        self.assertNotEqual(renamed["worktree_digest"], before_rename["worktree_digest"])

        delete_target = self.workspace / "delete-me.py"
        delete_target.write_text("delete\n", encoding="utf-8")
        before_delete = build_candidate_manifest(self.workspace, identity_paths=None)
        delete_target.unlink()
        deleted = build_candidate_manifest(
            self.workspace,
            identity_paths=None,
            changed_paths=("delete-me.py",),
        )
        self.assertEqual(
            deleted["changed_path_records"],
            [{"path": "delete-me.py", "kind": "deleted"}],
        )
        self.assertTrue(
            set(deleted["changed_paths"]) <= {
                item["path"] for item in deleted["changed_path_records"]
            }
        )
        self.assertNotEqual(deleted["candidate_id"], before_delete["candidate_id"])
        self.assertNotEqual(deleted["tree_hash"], before_delete["tree_hash"])
        self.assertNotEqual(deleted["worktree_digest"], before_delete["worktree_digest"])

        tampered = dict(created)
        tampered["changed_paths"] = ["not-in-the-verified-closure.py"]
        valid, errors = verify_candidate_manifest(self.workspace, tampered)
        self.assertFalse(valid)
        self.assertTrue(any("changed-path closure" in error for error in errors))

        # Omitting any real mutation from the declared closure is invalid,
        # including the newly-created root file.  The same invariant covers
        # rename tombstones and deletes through their changed-path records.
        omitted = dict(created)
        omitted["changed_paths"] = ["data/user.txt"]
        valid, errors = verify_candidate_manifest(self.workspace, omitted)
        self.assertFalse(valid)
        self.assertTrue(any("changed_path_records" in error for error in errors))

        omitted_rename = dict(renamed)
        omitted_rename["changed_paths"] = ["renamed.py"]
        valid, errors = verify_candidate_manifest(self.workspace, omitted_rename)
        self.assertFalse(valid)
        self.assertTrue(any("changed_path_records" in error for error in errors))

        omitted_delete = dict(deleted)
        omitted_delete["changed_paths"] = []
        valid, errors = verify_candidate_manifest(self.workspace, omitted_delete)
        self.assertFalse(valid)
        self.assertTrue(any("changed_path_records" in error for error in errors))

    def test_historical_artifacts_and_runtime_roots_are_excluded_from_candidate(self) -> None:
        candidate = self.gate.freeze_candidate()
        for relative in (
            "artifacts/deepseek-token-canary/old-run.json",
            "review-evidence/old-review.json",
            "reports/old-report.json",
            "canary/old-evidence.json",
            "manifests/old-manifest.json",
            "runtime/old-ledger.json",
        ):
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("historical object\n", encoding="utf-8")
        valid, errors = verify_candidate_manifest(self.workspace, candidate)
        self.assertTrue(valid, errors)
        self.assertFalse(any(item["path"].startswith("artifacts/") for item in candidate["objects"]))
        self.assertFalse(any(item["path"].startswith("review-evidence/") for item in candidate["objects"]))

    def test_manifest_cannot_reintroduce_historical_identity_path(self) -> None:
        candidate = self.gate.freeze_candidate()
        tampered = dict(candidate)
        tampered["identity_files"] = [{"path": "artifacts/deepseek-token-canary/old-run.json", "kind": "file"}]
        valid, errors = verify_candidate_manifest(self.workspace, tampered)
        self.assertFalse(valid)
        self.assertTrue(any("excluded runtime root" in error for error in errors))

    def test_old_pass_and_receipt_mappings_cannot_be_current_offline_inputs(self) -> None:
        candidate = self.gate.freeze_candidate()
        old_test = {
            "status": "passed", "return_code": 0, "test_ids": ["tests/code_mode"],
            "candidate_id": candidate["candidate_id"], "artifact": "artifacts/deepseek-token-canary/old-run.json",
        }
        old_review = {
            "decision": "LOCAL_CANARY_READY", "reviewer_id": "old-reviewer",
            "evidence": "review-evidence/old-review.json",
        }
        result = self.gate.evaluate_offline(
            candidate, test_result=old_test, reviewer=old_review,
            test_inventory=["tests/code_mode"],
        )
        self.assertEqual(result["status"], CODE_MODE_BLOCKED)
        self.assertFalse(result["trusted_receipts_reopened"])
        self.assertTrue(any("receipt" in reason for reason in result["reasons"]))

    def test_worktree_digest_is_recomputed_and_drifted_with_identity(self) -> None:
        candidate = self.gate.freeze_candidate()
        self.assertEqual(candidate["worktree_digest"].count(":"), 1)
        (self.workspace / "config" / "code_mode_profile.json").write_text(
            json.dumps({"schema": "CODE_MODE_PROFILE_V1", "identity_paths": ["config/code_mode_profile.json"], "test_inventory": ["tests/code_mode"], "revision": "digest-change"}),
            encoding="utf-8",
        )
        valid, errors = verify_candidate_manifest(self.workspace, candidate)
        self.assertFalse(valid)
        self.assertIn("candidate worktree_digest drifted", errors)

    def test_offline_ready_requires_independent_review_and_tests(self) -> None:
        candidate = self.gate.freeze_candidate()
        blocked = self.gate.evaluate_offline(
            candidate,
            test_result={"status": "passed", "return_code": 0, "test_ids": ["tests/code_mode"]},
            reviewer={"status": "NOT_REVIEWED", "candidate_id": candidate["candidate_id"]},
            test_inventory=["tests/code_mode"],
        )
        self.assertEqual(blocked["status"], CODE_MODE_BLOCKED)
        context = CodeModeRuntimeContext.open(Path(tempfile.mkdtemp(prefix="code-mode-offline-evidence-")))
        with self.assertRaises(PermissionError):
            context.seal_offline_test_receipt(
                candidate=candidate, command=[sys.executable, "-m", "unittest"],
                test_inventory=["tests/code_mode"], interpreter=sys.executable,
                dependencies={}, cwd=self.workspace, return_code=0, test_ids=["tests/code_mode"],
                output_summary={},
            )
        with self.assertRaises(PermissionError):
            context.run_controlled_tester(
                candidate=candidate, command=(sys.executable, "-m", "unittest", "-h"),
                test_inventory=("tests/code_mode",), interpreter=sys.executable,
                dependencies={}, cwd=self.workspace,
            )
        # The production headless reviewer has no semantic verdict source in
        # this offline fixture.  A real execution handoff is review-pending;
        # it is not promoted to CODE_MODE_READY by machine-only evidence.
        self.assertEqual(blocked["status"], CODE_MODE_BLOCKED)
        self.assertIn("trusted independent reviewer", " ".join(blocked["reasons"]))

    def test_test_evidence_requires_nonempty_inventory_and_explicit_return_code(self) -> None:
        candidate = self.gate.freeze_candidate()
        reviewer = {"status": "LOCAL_CANARY_READY", "candidate_id": candidate["candidate_id"]}
        for evidence in (
            {"status": "passed", "test_ids": [], "return_code": 0},
            {"status": "passed", "test_ids": ["tests/code_mode"]},
            {"status": "passed", "test_ids": ["tests/code_mode"], "return_code": "0"},
        ):
            result = self.gate.evaluate_offline(
                candidate, test_result=evidence, reviewer=reviewer, test_inventory=["tests/code_mode"]
            )
            self.assertEqual(result["status"], CODE_MODE_BLOCKED)

    def test_old_foundation_or_pass_fields_cannot_make_canary_pass(self) -> None:
        candidate = self.gate.freeze_candidate()
        issuer_context = _bootstrap_context(Path(tempfile.mkdtemp(prefix="code-mode-issuer-")))
        with self.assertRaises(PermissionError):
            self.gate.issue_canary_authorization(
                candidate=candidate, offline_gate={}, session_id="session-1",
                run_id="run-1", selected_workspace=self.workspace,
                runtime_context=issuer_context,
            )
        authorization = {
            "schema": "CODE_MODE_CANARY_AUTHORIZATION_V1",
            "candidate_id": candidate["candidate_id"], "tree_hash": candidate["tree_hash"],
            "session_id": "session-1", "run_id": "run-1",
            "workspace": str(self.workspace.resolve()), "fallback_allowed": False,
        }
        evidence = {
            "legacy_foundation_hash": "old",
            "resolved_mode": "MULTI",
            "intent_authorized": True,
            "candidate_id": candidate["candidate_id"],
            "stages": {name: {"status": "passed"} for name in ("Controller", "Planner", "Forge", "Tester", "Reviewer")},
            "tool_call_count": 0,
            "changed_paths": [],
            "tester": {"status": "passed"},
            "physical_send_count": 0,
            "provider": "deepseek",
            "model": "deepseek-v4-pro",
            "token_usage": {"input": 0, "output": 0, "total": 0},
            "fallback_count": 0,
            "journal_cas_closure": True,
            "cleanup": True,
            "production_sentinel_before": "a",
            "production_sentinel_after": "a",
            "production_sentinel_unchanged": True,
        }
        result = self.gate.evaluate_canary(
            authorization=authorization,
            evidence=evidence,
            reviewer={"post_execution": True, "decision": "ACCEPT"},
        )
        self.assertEqual(result["status"], CODE_MODE_BLOCKED)
        self.assertIn("tool_calls", result["reasons"])
        self.assertIn("physical_send", result["reasons"])
        self.assertFalse(result["deployment_triggered"])

    def test_canary_counts_require_a_fresh_same_run_receipt(self) -> None:
        candidate = self.gate.freeze_candidate()
        issuer_context = _bootstrap_context(Path(tempfile.mkdtemp(prefix="code-mode-issuer-")))
        with self.assertRaises(PermissionError):
            self.gate.issue_canary_authorization(
                candidate=candidate, offline_gate={}, session_id="session-1",
                run_id="run-1", selected_workspace=self.workspace,
                runtime_context=issuer_context,
            )
        authorization = {
            "schema": "CODE_MODE_CANARY_AUTHORIZATION_V1",
            "candidate_id": candidate["candidate_id"], "tree_hash": candidate["tree_hash"],
            "session_id": "session-1", "run_id": "run-1",
            "workspace": str(self.workspace.resolve()), "fallback_allowed": False,
        }
        evidence = {
            "run_id": "run-1", "candidate_id": candidate["candidate_id"], "resolved_mode": "MULTI",
            "intent_authorized": True,
            "stages": {name: {"status": "passed"} for name in ("Controller", "Planner", "Forge", "Tester", "Reviewer")},
            "tool_call_count": 1, "changed_paths": ["changed.py"], "tester": {"status": "passed"},
            "physical_send_count": 1, "provider": "deepseek", "model": "deepseek-v4-pro",
            "token_usage": {"input": 2, "output": 3, "total": 5}, "fallback_count": 0,
            "journal_cas_closure": True, "cleanup": True,
            "production_sentinel_before": "a", "production_sentinel_after": "a", "production_sentinel_unchanged": True,
            "run_receipt": {
                "schema": "CODE_MODE_RUN_RECEIPT_V1", "run_id": "run-1", "session_id": "session-1",
                "candidate_id": candidate["candidate_id"], "reference_id": "cas:" + "0" * 64,
                "fresh_verified": True, "no_replace_published": True, "physical_send_count": 1,
                "fallback_count": 0, "token_usage": {"input": 2, "output": 3, "total": 5},
                "side_effect_observation_receipt": "a" * 64,
            },
        }
        accepted = self.gate.evaluate_canary(
            authorization=authorization, evidence=evidence,
            reviewer={"post_execution": True, "decision": "ACCEPT"},
        )
        self.assertEqual(accepted["status"], CODE_MODE_BLOCKED)
        self.assertIn("run_receipt_not_reopened", " ".join(accepted["reasons"]))
        evidence["run_receipt"] = dict(evidence["run_receipt"], run_id="other-run")
        rejected = self.gate.evaluate_canary(
            authorization=authorization, evidence=evidence,
            reviewer={"post_execution": True, "decision": "ACCEPT"},
        )
        self.assertEqual(rejected["status"], CODE_MODE_BLOCKED)
        self.assertIn("run_bound_receipt", rejected["reasons"])

    def test_self_created_runtime_context_is_not_canary_trust_root(self) -> None:
        candidate = self.gate.freeze_candidate()
        issuer_context = _bootstrap_context(Path(tempfile.mkdtemp(prefix="code-mode-issuer-")))
        with self.assertRaises(PermissionError):
            self.gate.issue_canary_authorization(
                candidate=candidate, offline_gate={}, session_id="session-2",
                run_id="run-2", selected_workspace=self.workspace,
                runtime_context=issuer_context,
            )
        evidence = {"run_id": "run-2", "run_receipt": {"reference_id": "cas:" + "0" * 64}}
        result = self.gate.evaluate_canary(
            authorization={"run_id": "run-2", "candidate_id": candidate["candidate_id"],
                           "session_id": "session-2", "workspace": str(self.workspace.resolve())}, evidence=evidence,
            reviewer={"post_execution": True, "decision": "ACCEPT"}, runtime_context=issuer_context,
        )
        self.assertEqual(result["status"], CODE_MODE_BLOCKED, result)
        self.assertTrue(result["reasons"])

    def test_issued_context_requires_complete_journal_fact_closure(self) -> None:
        candidate = self.gate.freeze_candidate()
        runtime_home = Path(tempfile.mkdtemp(prefix="code-mode-issued-runtime-"))
        keys = InMemoryKeyProvider(environment="code-mode", namespace="issued-gate-test")
        context = _bootstrap_context(runtime_home, provider=keys)
        # A directly opened/host-attached test context is not enough to mint a
        # canary.  The current production path requires the active controller
        # and a real, independently produced evidence closure; no hand-built
        # Journal/CAS archive is accepted as a substitute.
        with self.assertRaises(PermissionError):
            self.gate.issue_canary_authorization(
                candidate=candidate, offline_gate={}, session_id="session-issued",
                run_id="run-issued", selected_workspace=self.workspace,
                runtime_context=context,
            )
        result = self.gate.evaluate_canary(
            authorization={"run_id": "run-issued", "candidate_id": candidate["candidate_id"]},
            evidence={"run_id": "run-issued", "run_receipt": {"reference_id": "cas:" + "0" * 64}},
            reviewer={"post_execution": True, "decision": "ACCEPT"},
            runtime_context=context,
        )
        self.assertEqual(result["status"], CODE_MODE_BLOCKED, result)
        self.assertTrue(result["reasons"])

    def test_incomplete_hash_closure_is_rejected_by_gate_helper(self) -> None:
        reference_id = "cas:" + "a" * 64
        events = [
            SimpleNamespace(stream_version=1, event_hash="h1", object_refs=()),
            SimpleNamespace(stream_version=2, event_hash="h2", object_refs=()),
            SimpleNamespace(stream_version=3, event_hash="root", object_refs=(reference_id,)),
        ]
        with self.assertRaises(ValueError):
            CodeModeAcceptanceV1._validate_journal_hash_closure(
                events, reference_id=reference_id, journal_event_hashes=["h1"]
            )

    def test_related_run_event_selector_excludes_unrelated_journal_streams(self) -> None:
        events = [
            SimpleNamespace(event_id="main", stream_id="run/run-1", payload={}),
            SimpleNamespace(event_id="forge", stream_id="run/forge-exec-run-1-1", payload={}),
            SimpleNamespace(event_id="task", stream_id="task/task-1", payload={"run_id": "run-1"}),
            SimpleNamespace(event_id="other-run", stream_id="run/run-2", payload={"run_id": "run-2"}),
            SimpleNamespace(event_id="unbound", stream_id="task/task-2", payload={}),
        ]
        related = CodeModeAcceptanceV1._related_run_events(events, "run-1")
        self.assertEqual([event.event_id for event in related], ["main", "forge", "task"])

    def test_multiple_managed_process_cleanup_ids_are_ordered_and_each_cas_reopened(self) -> None:
        events = [
            SimpleNamespace(
                event_id="cleanup-1", stream_id="task/process-1", payload={
                    "event_type": "autonomous.managed-process-cleanup",
                    "run_id": "run-1",
                    "record_ref": "cas:" + "1" * 64,
                }
            ),
            SimpleNamespace(
                event_id="cleanup-2", stream_id="task/process-2", payload={
                    "event_type": "autonomous.managed-process-cleanup",
                    "run_id": "run-1",
                    "record_ref": "cas:" + "2" * 64,
                }
            ),
            SimpleNamespace(
                event_id="cleanup-other-run", stream_id="task/process-other", payload={
                    "event_type": "autonomous.managed-process-cleanup",
                    "run_id": "run-2",
                    "record_ref": "cas:" + "3" * 64,
                }
            ),
        ]

        class FakeCas:
            def __init__(self) -> None:
                self.reopened: list[str] = []

            def resolve_reference(self, reference: str) -> str:
                return reference

            def open_verified(self, reference: str) -> bytes:
                self.reopened.append(reference)
                return json.dumps({"event": "managed_process_cleanup", "payload": {"failures": []}}).encode()

        cas = FakeCas()
        observation = {"managed_process": {"cleanup_event_ids": ["cleanup-1", "cleanup-2"]}}
        related = CodeModeAcceptanceV1._related_run_events(events, "run-1")
        self.assertEqual([event.event_id for event in related], ["cleanup-1", "cleanup-2"])
        CodeModeAcceptanceV1._validate_managed_process_cleanup_bindings(related, observation, cas=cas)
        self.assertEqual(cas.reopened, ["cas:" + "1" * 64, "cas:" + "2" * 64])

        with self.assertRaises(ValueError):
            CodeModeAcceptanceV1._validate_managed_process_cleanup_bindings(events, observation, cas=cas)

        for bad_ids in ([], ["cleanup-2", "cleanup-1"], ["cleanup-1"], ["cleanup-1", "other"]):
            with self.subTest(bad_ids=bad_ids), self.assertRaises(ValueError):
                CodeModeAcceptanceV1._validate_managed_process_cleanup_bindings(
                    events, {"managed_process": {"cleanup_event_ids": bad_ids}}, cas=cas
                )

        class BrokenCas(FakeCas):
            def open_verified(self, reference: str) -> bytes:
                raise OSError("receipt unavailable")

        with self.assertRaises(ValueError):
            CodeModeAcceptanceV1._validate_managed_process_cleanup_bindings(
                events, observation, cas=BrokenCas()
            )

    def test_missing_typed_journal_facts_fail_closed(self) -> None:
        authorization = {
            "authorization_id": "auth", "session_id": "session", "candidate_id": "candidate",
            "run_id": "run", "workspace": "/tmp/workspace",
            "runtime_state_identity": "state", "runtime_authority_handle_hash": "handle",
        }
        with self.assertRaises(ValueError):
            CodeModeAcceptanceV1._validate_journal_fact_bindings(
                [SimpleNamespace(payload={
                    "schema": "CODE_MODE_AUTHORIZATION_FACT_V1",
                    **authorization,
                })],
                {"stages": {}},
                authorization,
            )


if __name__ == "__main__":
    unittest.main()
