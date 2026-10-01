from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Mapping

from sitina.conversation.models import ChatMode
from sitina.conversation.runtime import CodeModeRuntimeUnavailable, ConversationRuntime
from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope
from sitina import cli
from sitina.legacy.fence import (
    LegacyWriteDenied,
    authorized_code_mode_sandbox_execution,
    issue_code_mode_sandbox_execution_capability,
)
from sitina.orchestrator.code_mode_runtime import (
    CodeModeRuntimeContext,
    CodeModeScriptedProvider,
    open_trusted_code_mode_context,
)
from sitina.orchestrator.output_contracts import resolve_output_contract, validate_output_contract
from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBroker
from sitina.orchestrator.code_mode_controller import CodeModeControllerError, CodeModeControllerSession
from tests.code_mode_host_fixture import launch_code_mode_host
from tests.code_mode_reviewer_fixture import launch_code_mode_reviewer
from sitina.orchestrator.code_mode_reviewer import ReviewerReceiptCapability
from sitina.orchestrator.code_mode_reviewer import _review_evidence_from_test_receipt
from sitina.orchestrator.code_mode_gate import CodeModeAcceptanceV1, CODE_MODE_READY, CodeModeRuntimePolicy
from sitina.orchestrator.execution_sandbox import ExecutionSandboxRunner, ExecutionSandboxUnavailable
from sitina.orchestrator.git_ops import GitWorktreeManager
from sitina.journal.model import EventEnvelope, canonical_json_bytes
from sitina.journal.local import LocalJournal, LocalJournalError
from sitina.orchestrator.true_multi_agent import (
    DynamicCollaborationError,
    TrueMultiAgentProductionRuntime,
    _require_current_attempt_planner,
    _require_exact_replan_bytes,
)
from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream, TrueMultiAgentRuntimeError
from sitina.runners.provider import (
    ProviderCompletion, ProviderHTTPError, ProviderProfile, ProviderToolCall,
    ProviderToolTurn,
)
from sitina.security.key_provider import InMemoryKeyProvider
from sitina.runners.tool_executor import ToolExecutor


class _ScriptedCodeModeProvider:
    """Local provider adapter: no socket and no physical Provider request."""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.profile = ProviderProfile(
            "scripted-code-mode", "https://api.deepseek.com", "", "deepseek-v4-pro"
        )
        self.text_calls = 0
        self.tool_calls = 0
        self.network_requests = 0
        self.physical_requests = 0
        self.tool_result_feedback_seen = False
        self.review_prompts: list[str] = []

    def load_profile(self, _name: str) -> ProviderProfile:
        return self.profile

    @staticmethod
    def _agent_id(system_prompt: str) -> str:
        match = re.search(r"Agent ([A-Za-z0-9-]+)", system_prompt)
        if not match:
            raise AssertionError("scripted provider did not receive a bound Agent identity")
        return match.group(1)

    def _value(self, system_prompt: str, user_prompt: str) -> dict[str, object]:
        agent_id = self._agent_id(system_prompt)
        kind = "review" if "kind exactly 'review'" in system_prompt else "proposal"
        if "Analyze this goal" in user_prompt:
            return {
                "agent_id": agent_id, "kind": "proposal", "complexity": "standard",
                "risk_level": "low", "protocols": ["proposal"],
                "task_graph": ["code-change"], "proposal_count": 1,
                "domain_capability": "python", "requires_rework": False,
                "requires_conflict": False, "requires_handoff_reject": False,
                "requires_reassignment": False, "requires_provider_unknown": False,
                "rationale": "A bounded workspace code change with focused verification.",
            }
        if (
            "Produce a new implementation plan after a failed execution attempt" in user_prompt
            or "Re-plan the requested code change" in user_prompt
            or "Recover the original requested implementation" in user_prompt
        ):
            return {
                "agent_id": agent_id, "kind": "replan",
                "approach": "Repeat the bounded file change and verify the exact resulting diff.",
                "acceptance_checks": ["focused test passes"],
            }
        if (
            "Review only the completed Forge execution" in user_prompt
            or "Independently review this execution evidence" in user_prompt
        ):
            self.review_prompts.append(user_prompt)
            return {
                "agent_id": agent_id, "kind": "review", "decision": "accept",
                "reason": "The actual diff and Tester evidence are present.",
                "evidence_checks": ["diff", "tests", "patch manifest"],
            }
        if "Round 2." in user_prompt:
            match = re.search(r"parent output hash is ([0-9a-f]{64})", user_prompt)
            if not match:
                raise AssertionError("round-two scripted prompt lost its parent hash")
            return {
                "agent_id": agent_id, "kind": "proposal",
                "summary": "The revised workspace implementation remains bounded.",
                "parent_output_hash": match.group(1),
                "responses_to_objections": ["addressed" for _ in range(4)],
                "acceptance_checks": ["focused test passes" for _ in range(4)],
            }
        if (
            "Independently score" in user_prompt
            or "Re-review revision" in user_prompt
            or "Review round-2 revision hash" in user_prompt
        ):
            return {
                "agent_id": agent_id, "kind": "review", "verdict": "approved",
                "score": 90, "reason": "The bounded proposal is feasible and safe.", "defects": [],
            }
        if "Create an independent solution" in user_prompt:
            return {
                "agent_id": agent_id, "kind": "proposal", "summary": "Create the requested file.",
                "approach": "Use the approved workspace file tool and run the focused check.",
                "risks": ["The change is limited to the selected workspace."],
                "assumptions": ["The focused local test is available."],
                "acceptance_checks": ["focused test passes"],
            }
        raise AssertionError("unexpected scripted text-provider prompt")

    def _complete_openai(self, _profile: ProviderProfile, *, system_prompt: str, user_prompt: str, **_kwargs):
        self.text_calls += 1
        payload = json.dumps(self._value(system_prompt, user_prompt), sort_keys=True)
        return ProviderCompletion(
            payload,
            {
                "protocol": "openai_chat_completions",
                "provider_request_id": f"scripted-text-{self.text_calls}",
                "provider_response_id": f"scripted-response-{self.text_calls}",
                "token_usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10},
            },
        )

    def complete_tool_turn(self, _profile: ProviderProfile, **kwargs: object) -> ProviderToolTurn:
        self.tool_calls += 1
        if self.tool_calls > 1:
            messages = kwargs.get("messages") or ()
            self.tool_result_feedback_seen = any(
                isinstance(message, dict)
                and str(message.get("role") or "") in {"tool", "tool_result"}
                for message in messages
            )
            if not self.tool_result_feedback_seen:
                raise AssertionError("scripted provider did not receive the file-tool result")
        if self.tool_calls == 1:
            return ProviderToolTurn(
                "",
                (
                    ProviderToolCall(
                        "scripted-write-1",
                        "sitina_write_file",
                        {
                            "path": str(self.workspace / "hello.py"),
                            "content": (
                                "def hello():\n"
                                "    \"\"\"Return a greeting.\n\n"
                                "    >>> hello()\n"
                                "    'hello'\n"
                                "    \"\"\"\n"
                                "    return 'hello'\n"
                            ),
                        },
                    ),
                ),
                "tool_calls",
                {
                    "protocol": "mock", "physical_send_count": 1,
                    "token_usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10},
                },
            )
        return ProviderToolTurn(
            "implemented and verified",
            (),
            "stop",
            {
                "protocol": "mock", "physical_send_count": 1,
                "token_usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10},
            },
        )


class CodeModeRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[1]
        self.home = Path(tempfile.mkdtemp(prefix="sitina-code-mode-home-"))
        self.workspace = self.home / "workspace"
        self.workspace.mkdir()
        shutil.copytree(self.repo / "config", self.home / "config")
        (self.home / "state").mkdir()
        self.keys = InMemoryKeyProvider(environment="code-mode", namespace="runtime")
        self.provider = _ScriptedCodeModeProvider(self.workspace)
        self.code_mode_policy = CodeModeRuntimePolicy()

        def context_factory(root: Path) -> CodeModeRuntimeContext:
            return CodeModeRuntimeContext.open(root, provider=self.keys)

        self.context_factory = context_factory
        # The trusted fixture uses the same process boundary as the CLI; tests
        # never receive a broker signing key or an in-process issuer.  The
        # launcher fixes roots and runtime identity before the host starts.
        preview = CodeModeRuntimeContext.open(
            self.home, provider=self.keys, source_root=self.repo,
        )
        self.reviewer = launch_code_mode_reviewer()
        self.broker = launch_code_mode_host(
            state_root=self.home, workspace=self.workspace,
            runtime_state_identity=preview.identity.state_identity,
            runtime_journal_id=preview.identity.journal_id,
            source_root=self.repo, provider=self.keys,
            reviewer_verification=self.reviewer.tty_verification_material,
        )
        self._extra_brokers = []
        primary_factory = self.broker.context_factory(
            provider=self.keys, source_root=self.repo
        )

        def trusted_context_factory(root: Path) -> CodeModeRuntimeContext:
            # Each attested host is fixed to exactly one launcher-selected
            # state root.  Tests that exercise an independent root get a new
            # host with its own fixed bootstrap; no host is rebound by RPC.
            resolved = root.expanduser().resolve(strict=False)
            if resolved == self.home.resolve():
                return primary_factory(root)
            preview_root = CodeModeRuntimeContext.open(
                resolved, provider=self.keys, source_root=self.repo,
            )
            workspace = resolved / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            extra = launch_code_mode_host(
                state_root=resolved, workspace=workspace,
                runtime_state_identity=preview_root.identity.state_identity,
                runtime_journal_id=preview_root.identity.journal_id,
                source_root=self.repo, provider=self.keys,
                reviewer_verification=self.reviewer.tty_verification_material,
            )
            self._extra_brokers.append(extra)
            return extra.context_factory(provider=self.keys, source_root=self.repo)(resolved)

        self.trusted_context_factory = trusted_context_factory
        self.multi = TrueMultiAgentProductionRuntime(
            self.home,
            runtime_context_factory=self.trusted_context_factory,
            provider_client=self.provider,
            provider_profile=self.provider.profile,
        )
        self.runtime = ConversationRuntime(
            self.home,
            workspace=self.workspace,
            multi_runtime=self.multi,
            runtime_context_factory=self.trusted_context_factory,
        )

    def tearDown(self) -> None:
        self.reviewer.close()
        for broker in getattr(self, "_extra_brokers", ()):
            broker.close()
        self.broker.close()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_offline_scripted_provider_emits_strict_execution_replan_contract(self) -> None:
        provider = CodeModeScriptedProvider(self.workspace)
        completion = provider._complete_openai(
            provider.profile,
            system_prompt="You are Agent cirrus.",
            user_prompt="Produce a new implementation plan after a failed execution attempt.",
        )
        value = json.loads(completion.text)
        spec = resolve_output_contract("execution-replan-2", "replan")
        validate_output_contract(value, spec)
        self.assertEqual(value["kind"], "replan")
        self.assertTrue(value["approach"])
        self.assertEqual(value["acceptance_checks"], ["focused test passes"])

    def _run_controlled_tester(self, context: CodeModeRuntimeContext, *, candidate: dict, **kwargs: object) -> dict:
        # The production API derives run_id from the controller binding.  The
        # fixture only creates a fresh controller identity; it never passes a
        # run identity through to the Tester.
        effective_run_id = "offline-tester-" + secrets.token_hex(8)
        controller = CodeModeControllerSession(
            context=context, run_id=effective_run_id, session_id="offline-tester-session",
            authorization={
                "authorization_ref": "offline-tester-authorization-" + effective_run_id,
                "session_id": "offline-tester-session", "run_id": effective_run_id,
                "session_instance_id": context.session_instance_id,
                "run_attempt": 1,
                "expires_at": int(time.time()) + 120,
            }, workspace=self.workspace, offline=True,
        )
        try:
            context.bind_code_mode_request(
                session_instance_id=context.session_instance_id,
                session_id=controller.session_id,
                run_id=controller.run_id,
                candidate_id=str(candidate.get("candidate_id") or ""),
                workspace=self.workspace,
                run_attempt=1,
                generation=str(candidate.get("generation") or context.identity.epoch_root),
            )
            return controller.run_tester(context, candidate=candidate, **kwargs)
        finally:
            controller.close()

    def _tty_review_for_pending(self, result: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
        """Use only the explicit test reviewer seam to produce a real V2 receipt."""
        # Final reviewed receipts carry the authority-host signature and must
        # be reopened through the same trusted Code Mode context as the
        # controller.  A directly opened offline context is intentionally
        # unable to verify an authoritative terminal.
        context = self.trusted_context_factory(self.home)
        reviewer = self.reviewer

        def tty_rpc(request: dict[str, object]) -> dict[str, object]:
            if request.get("method") == "tty_confirm":
                review = request["review_request"]
                assert isinstance(review, dict)
                summary = {
                    key: review.get(key)
                    for key in ("candidate_id", "tree_hash", "run_id", "evidence_package_ref", "evidence_package_hash")
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
            raise AssertionError("test TTY seam received an unexpected RPC")

        with patch.object(reviewer, "_rpc", side_effect=tty_rpc):
            candidate = context.reopen_candidate_manifest(
                dict(result["candidate_locator"]), run_id=str(result["run_id"])
            )
            receipt = context.confirm_tty(
                review=dict(result["review_request"]), candidate=candidate, reviewer_session=reviewer
            )
        gate = CodeModeAcceptanceV1(self.workspace).evaluate_offline(
            candidate=candidate,
            runtime_context=context,
            test_receipt=dict(result["test_receipt"]),
            reviewer_receipt=receipt,
            test_inventory=result.get("test_inventory"),
        )
        self.assertEqual(gate.get("status"), "CODE_MODE_READY", gate)
        return dict(receipt), dict(gate)

    def test_code_mode_sandbox_capability_rejects_tampered_command(self) -> None:
        python = str(Path(sys.executable).resolve(strict=True))
        from sitina.orchestrator import execution_sandbox
        worker = Path(execution_sandbox.__file__).with_name("execution_sandbox_worker.py").resolve(strict=True)
        argv = (python, str(worker), "--request", "request")
        context = self.context_factory(self.home)
        message = "Please create hello.py."
        code_authorization = self.code_mode_policy.authorize(
            mode="MULTI", message=message, session_id="session-1", workspace=self.workspace
        )
        parent_expiry = int(time.time()) + 60
        parent = context.register_execution_parent(
            code_mode_authorization=code_authorization,
            execution_authorization={
                "schema": "SITINA_EXECUTION_AUTHORIZATION_V1",
                "authorization_ref": "execution-authorization:test",
                "session_id": "session-1",
                "run_id": "code-mode-capability-test",
                "workspace": str(self.workspace.resolve()),
                "scope": [str(self.workspace.resolve())],
                "risk_level": "workspace",
                "expires_at": parent_expiry,
            },
            session_id="session-1",
            run_id="code-mode-capability-test",
            intent_hash=str(code_authorization["intent"]["intent_hash"]),
            workspace=self.workspace,
            scope=(str(self.workspace),),
            expires_at=parent_expiry,
            trusted_authorizer=self.code_mode_policy,
            authorization_message=message,
            risk_level="workspace",
        )
        capability = context.issue_sandbox_child_capability(
            parent,
            run_id="code-mode-capability-test",
            attempt=1,
            diff_hash="a" * 64,
            test_plan_hash="b" * 64,
            runner_executable=Path(python),
            worker_path=worker,
            cwd=self.workspace,
            read_roots=(self.workspace,),
            write_roots=(self.workspace,),
            argv=argv,
        )
        with self.assertRaises(LegacyWriteDenied):
            with authorized_code_mode_sandbox_execution(
                capability,
                argv=(python, str(worker), "--request", "tampered"),
                cwd=self.workspace,
                attempt=capability.attempt,
                diff_hash="a" * 64,
                test_plan_hash="b" * 64,
                parent_authorization_hash=capability.parent_authorization_hash,
                read_roots=(self.workspace,),
                write_roots=(self.workspace,),
            ):
                pass

    def test_public_code_mode_capability_mint_is_fail_closed(self) -> None:
        with self.assertRaises(LegacyWriteDenied):
            issue_code_mode_sandbox_execution_capability()

    def test_side_effect_counts_come_from_runtime_observation(self) -> None:
        context = self.context_factory(self.home)
        self.assertEqual(context.side_effect_counts()["observation_status"], "unknown-run")
        counts = context.side_effect_counts(run_id="run-with-no-events")
        self.assertEqual(counts["observation_status"], "journal-derived")
        self.assertEqual(counts["observation_run_id"], "run-with-no-events")
        self.assertIsNone(counts["sqlite_connect_count"])
        self.assertIsNone(counts["sqlite_write_count"])
        self.assertEqual(counts["legacy_read_count"], 0)
        self.assertEqual(counts["acceptance_runtime_read_count"], 0)

    def test_sandbox_parent_hash_expiry_and_attempt_are_immutable(self) -> None:
        context = self.context_factory(self.home)
        message = "Please create hello.py."
        code_authorization = self.code_mode_policy.authorize(
            mode="MULTI", message=message, session_id="session-2", workspace=self.workspace
        )
        parent_expiry = int(time.time()) + 60
        parent = context.register_execution_parent(
            code_mode_authorization=code_authorization,
            execution_authorization={"schema": "SITINA_EXECUTION_AUTHORIZATION_V1", "authorization_ref": "execution-authorization:test-2", "session_id": "session-2", "run_id": "run-2", "workspace": str(self.workspace.resolve()), "scope": [str(self.workspace.resolve())], "risk_level": "workspace", "expires_at": parent_expiry},
            session_id="session-2", run_id="run-2", intent_hash=str(code_authorization["intent"]["intent_hash"]),
            workspace=self.workspace, scope=(str(self.workspace),), expires_at=parent_expiry,
            trusted_authorizer=self.code_mode_policy, authorization_message=message,
            risk_level="workspace",
        )
        from dataclasses import replace
        with self.assertRaises(PermissionError):
            context.issue_sandbox_child_capability(
                replace(parent, expires_at=parent.expires_at + 600),
                run_id="run-2", attempt=1, diff_hash="d" * 64, test_plan_hash="e" * 64,
                runner_executable=Path(sys.executable).resolve(strict=True),
                worker_path=Path(__import__("sitina.orchestrator.execution_sandbox", fromlist=["__file__"]).__file__).with_name("execution_sandbox_worker.py").resolve(strict=True),
                cwd=self.workspace, read_roots=(self.workspace,), write_roots=(self.workspace,),
                argv=(str(Path(sys.executable).resolve(strict=True)),),
            )

        worker = Path(__import__("sitina.orchestrator.execution_sandbox", fromlist=["__file__"]).__file__).with_name("execution_sandbox_worker.py").resolve(strict=True)
        python = Path(sys.executable).resolve(strict=True)
        argv = (str(python), str(worker), "--request", "attempt-1")
        capability_one = context.issue_sandbox_child_capability(
            parent, run_id="run-2", attempt=1, diff_hash="d" * 64, test_plan_hash="e" * 64,
            runner_executable=python, worker_path=worker, cwd=self.workspace,
            read_roots=(self.workspace,), write_roots=(self.workspace,), argv=argv,
        )
        capability_two = context.issue_sandbox_child_capability(
            parent, run_id="run-2", attempt=2, diff_hash="d" * 64, test_plan_hash="e" * 64,
            runner_executable=python, worker_path=worker, cwd=self.workspace,
            read_roots=(self.workspace,), write_roots=(self.workspace,), argv=(str(python), str(worker), "--request", "attempt-2"),
        )
        self.assertEqual(capability_one.attempt, 1)
        self.assertEqual(capability_two.attempt, 2)
        self.assertNotEqual(capability_one.capability_id, capability_two.capability_id)
        with self.assertRaises(PermissionError):
            context.issue_sandbox_child_capability(
                parent, run_id="run-2", attempt=2, diff_hash="d" * 64, test_plan_hash="e" * 64,
                runner_executable=python, worker_path=worker, cwd=self.workspace,
                read_roots=(self.workspace,), write_roots=(self.workspace,), argv=argv,
            )

        with self.assertRaises(PermissionError):
            context.issue_sandbox_child_capability(
                replace(parent, parent_hash="f" * 64),
                run_id="run-2", attempt=1, diff_hash="d" * 64, test_plan_hash="e" * 64,
                runner_executable=python, worker_path=worker, cwd=self.workspace,
                read_roots=(self.workspace,), write_roots=(self.workspace,), argv=argv,
            )
        with self.assertRaises(PermissionError):
            context.issue_sandbox_child_capability(
                replace(parent, risk_level="high"),
                run_id="run-2", attempt=1, diff_hash="d" * 64, test_plan_hash="e" * 64,
                runner_executable=python, worker_path=worker, cwd=self.workspace,
                read_roots=(self.workspace,), write_roots=(self.workspace,), argv=argv,
            )
        with self.assertRaises(PermissionError):
            context.issue_sandbox_child_capability(
                parent,
                run_id="run-2", attempt=1, diff_hash="d" * 64, test_plan_hash="e" * 64,
                runner_executable=python, worker_path=worker, cwd=self.workspace.parent,
                read_roots=(self.workspace.parent,), write_roots=(self.workspace.parent,), argv=argv,
            )
        context.revoke_execution_parent(parent)
        with self.assertRaises(PermissionError):
            context.issue_sandbox_child_capability(
                parent,
                run_id="run-2", attempt=1, diff_hash="d" * 64, test_plan_hash="e" * 64,
                runner_executable=python, worker_path=worker, cwd=self.workspace,
                read_roots=(self.workspace,), write_roots=(self.workspace,), argv=argv,
            )

    def test_child_authorization_requires_exact_canonical_parent_fields(self) -> None:
        """Every parent field is issuer data, not caller-supplied metadata."""
        context = self.context_factory(self.home)
        message = "Please create hello.py."
        managed = self.home / "managed-worktree"
        managed.mkdir()
        code_authorization = self.code_mode_policy.authorize(
            mode="MULTI", message=message, session_id="session-parent", workspace=self.workspace
        )
        expiry = int(time.time()) + 60
        parent = context.register_execution_parent(
            code_mode_authorization=code_authorization,
            execution_authorization={
                "schema": "SITINA_EXECUTION_AUTHORIZATION_V1",
                "authorization_ref": "execution-authorization:canonical-parent",
                "session_id": "session-parent", "run_id": "parent-run",
                "workspace": str(self.workspace.resolve()),
                "scope": [str(self.workspace.resolve()), str(managed.resolve())], "risk_level": "workspace",
                "expires_at": expiry,
            },
            session_id="session-parent", run_id="parent-run",
            intent_hash=str(code_authorization["intent"]["intent_hash"]),
            workspace=self.workspace, scope=(str(self.workspace), str(managed)), expires_at=expiry,
            trusted_authorizer=self.code_mode_policy, authorization_message=message,
            risk_level="workspace",
        )
        child = context.issue_execution_child_authorization(
            parent, attempt=1, purpose="forge-attempt",
            workspace=managed, scope=(str(managed),), expires_at=expiry,
        )
        self.assertEqual(child["workspace"], child["execution_root"])
        self.assertEqual(child["scope"], [str(managed.resolve())])
        from dataclasses import replace

        mutations = {
            "session_id": "tampered-session", "run_id": "tampered-run",
            "intent_hash": "f" * 64, "workspace": str(self.workspace.parent),
            "scope": (str(self.workspace.parent),), "risk_level": "high",
            "attempt": 7, "expires_at": expiry + 1,
            "handle": "tampered-handle", "parent_hash": "f" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                tampered = replace(parent, **{field: value})
                with self.assertRaises(PermissionError):
                    context.issue_execution_child_authorization(
                        tampered, attempt=2, purpose="forge-attempt",
                        workspace=self.workspace, scope=(str(self.workspace),),
                        expires_at=expiry,
                    )

    def test_public_trusted_runtime_factory_requires_issuer_capability(self) -> None:
        with self.assertRaises(PermissionError):
            open_trusted_code_mode_context(Path(tempfile.mkdtemp(prefix="untrusted-code-mode-")))
        with self.assertRaises(PermissionError):
            CodeModeRuntimeContext._make_bootstrap_context_factory()
        with self.assertRaises(AttributeError):
            CodeModeAuthorityBroker.launch()
        with self.assertRaises(AttributeError):
            CodeModeAuthorityBroker.launch(host_process=True)
        with self.assertRaises(PermissionError):
            self.broker.request({"method": "hello"})
        with self.assertRaises(PermissionError):
            self.broker.issue_canary("", {})

    def test_only_active_controller_session_can_use_host_proof(self) -> None:
        context = self.trusted_context_factory(Path(tempfile.mkdtemp(prefix="controller-proof-")))
        authorization = {
            "authorization_ref": "execution-authorization:controller-proof",
            "session_id": "controller-session",
            "run_id": "controller-run",
            "session_instance_id": context.session_instance_id,
            "run_attempt": 1,
            "expires_at": int(time.time()) + 120,
        }
        first = CodeModeControllerSession(
            context=context, run_id="controller-run", session_id="controller-session",
            authorization=authorization, workspace=self.workspace, offline=False,
        )
        second = None
        try:
            with self.assertRaises(CodeModeControllerError):
                second = CodeModeControllerSession(
                    context=context, run_id="controller-run", session_id="controller-session",
                    authorization=authorization, workspace=self.workspace, offline=False,
                )
            self.assertFalse(first.authoritative)
            setattr(context, "_active_controller_session", first)
            self.assertTrue(first.authoritative)
            self.assertIsNone(second)
            with self.assertRaises(PermissionError):
                CodeModeControllerSession(
                    context=context, run_id="controller-run", session_id="controller-session",
                    authorization=authorization, workspace=self.workspace, offline=False,
                ).assert_canary_access(context, authorization)
        finally:
            first.close()
            if second is not None:
                second.close()

    def test_handwritten_transport_receipt_cannot_enter_runtime_ledger(self) -> None:
        context = self.trusted_context_factory(Path(tempfile.mkdtemp(prefix="ledger-issuer-")))
        ledger, capability = context._authoritative_transport_ledger()
        forged = {
            "schema": "CODE_MODE_PROVIDER_TRANSPORT_RECEIPT_V1",
            "authority": "network-transport-boundary-v1",
            "run_id": "forged-run",
            "physical_sequence": 1,
        }
        self.assertFalse(ledger.contains(forged))
        with self.assertRaises(PermissionError):
            ledger.settle(
                capability,
                object(),
                provider_response_id="forged-response",
                token_usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            )

    def test_direct_context_and_tampered_broker_binding_are_not_authoritative(self) -> None:
        direct = self.context_factory(self.home)
        with self.assertRaises(PermissionError):
            direct.canary_authority_binding()
        with self.assertRaises(PermissionError):
            direct._authoritative_transport_ledger()
        with self.assertRaises(PermissionError):
            direct._attach_authority_broker(object(), "session", {}, "token")

        broker_home = Path(tempfile.mkdtemp(prefix="broker-binding-"))
        context = self.trusted_context_factory(broker_home)
        original = dict(context._broker_binding)
        context._broker_binding["broker_pid"] = int(original["broker_pid"]) + 1
        with self.assertRaises(PermissionError):
            context.canary_authority_binding()
        context._broker_binding.clear()
        context._broker_binding.update(original)
        context._broker_binding["runtime_state_identity"] = "forged-state"
        with self.assertRaises(PermissionError):
            context.canary_authority_binding()
        context._broker_binding.clear()
        context._broker_binding.update(original)
        self.assertEqual(context.canary_authority_binding()["runtime_state_identity"], context.identity.state_identity)

    def test_broker_transport_receipt_is_one_use_and_session_bound(self) -> None:
        context = self.trusted_context_factory(Path(tempfile.mkdtemp(prefix="ledger-replay-")))
        ledger, capability = context._authoritative_transport_ledger()
        with self.assertRaises(PermissionError):
            ledger.begin(
                capability,
                run_id="broker-run", effect_attempt_id="effect-1",
                provider_profile="deepseek", provider_model="deepseek-v4-pro",
            )
        with self.assertRaises(Exception):
            self.broker.request({"method": "transport_snapshot", "session": "wrong-session", "capability": "wrong"})

    def test_broker_transport_is_bound_to_issued_canary_and_exact_run(self) -> None:
        home = Path(tempfile.mkdtemp(prefix="broker-canary-binding-"))
        context = self.trusted_context_factory(home)
        binding = context.canary_authority_binding()
        now = int(time.time())
        # The context owns the host connection for this independently fixed
        # state root; a different host client cannot submit its session.
        # A public broker client cannot mint a permit from a caller-built
        # authorization body.  The positive transport path is exercised by
        # the real Gate handoff test, which supplies the complete typed
        # locator set to the host.
        with self.assertRaises(PermissionError):
            context._broker_client.issue_bound_canary(
                context._broker_session,
                {
                    "schema": "CODE_MODE_CANARY_AUTHORIZATION_V1",
                    "candidate_id": "candidate-broker-test",
                    "session_id": "conversation-broker-test",
                    "run_id": "broker-canary-run",
                    "run_attempt": 1,
                    "workspace": str((home / "workspace").resolve()),
                    "provider_profile": "deepseek",
                    "provider_model": "deepseek-v4-pro",
                    "fallback_allowed": False,
                    "issued_at": now,
                    "expires_at": now + 60,
                    "nonce": "broker-test-nonce",
                    **binding,
                },
            )

    def test_direct_mutation_rejects_fabricated_execution_child_mapping(self) -> None:
        context = self.context_factory(self.home)
        fake = {
            "schema": "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1",
            "authorization_ref": "execution-authorization-child:" + "f" * 64,
            "run_id": "forge-exec-run-fake-2", "parent_run_id": "run-fake",
            "attempt": 2, "parent_authorization_hash": "a" * 64,
            "session_id": "session-fake", "intent_hash": "b" * 64,
            "workspace": str(self.workspace.resolve()), "scope": [str(self.workspace.resolve())],
            "risk_level": "workspace", "expires_at": int(time.time()) + 60,
        }
        executor = ToolExecutor(
            self.home, authorization_binding=fake, authorization_authority=context,
        )
        with self.assertRaises(ValueError):
            executor._mint_direct_capability(
                run_id=fake["run_id"], authorization_ref=fake["authorization_ref"],
                target_repo=str(self.workspace), allowed_roots=[str(self.workspace)], purpose="test",
            )
        for schema in ("SITINA_EXECUTION_AUTHORIZATION_V1", "untrusted-mapping"):
            ordinary = dict(fake, schema=schema)
            untrusted_executor = ToolExecutor(self.home, authorization_binding=ordinary)
            with self.assertRaises(ValueError):
                untrusted_executor._mint_direct_capability(
                    run_id=ordinary["run_id"], authorization_ref=ordinary["authorization_ref"],
                    target_repo=str(self.workspace), allowed_roots=[str(self.workspace)], purpose="test",
                )

    def test_sandbox_parent_registration_rejects_untrusted_mapping(self) -> None:
        context = self.context_factory(self.home)
        with self.assertRaises(PermissionError):
            context.register_execution_parent(
                code_mode_authorization={"authorization_token": "arbitrary-model-supplied-value"},
                execution_authorization={
                    "schema": "SITINA_EXECUTION_AUTHORIZATION_V1",
                    "authorization_ref": "execution-authorization:fake",
                    "session_id": "session-fake",
                    "run_id": "run-fake",
                },
                session_id="session-fake", run_id="run-fake", intent_hash="f" * 64,
                workspace=self.workspace, scope=(str(self.workspace),), expires_at=int(time.time()) + 60,
                trusted_authorizer=object(), authorization_message="Please create hello.py.", risk_level="workspace",
            )

    def test_code_mode_sandbox_rejects_custom_worker(self) -> None:
        custom_worker = self.home / "custom-worker.py"
        custom_worker.write_text("raise SystemExit(0)\n", encoding="utf-8")
        with self.assertRaises(ExecutionSandboxUnavailable):
            ExecutionSandboxRunner(
                home=self.home,
                worker_path=custom_worker,
                code_mode_authorization={"authorization_token": "opaque-parent"},
            )

    def test_real_conversation_runtime_reaches_multi_tools_without_legacy_foundation(self) -> None:
        session = self.runtime.resume_or_create_session()
        self.assertEqual(session.mode, ChatMode.AUTO)
        # The test must prove the independent context is the actual entry
        # path, rather than merely succeeding because a legacy context was
        # available in the process.
        from sitina.orchestrator.bplus_production import ProductionRuntimeContext
        with patch.object(
            ProductionRuntimeContext,
            "load",
            side_effect=AssertionError("Code Mode must not load Legacy B+ context"),
        ):
            result = self.runtime.execute_turn(
                session,
                "Please create hello.py and run the focused test; do not commit or push.",
            )
        self.assertEqual(result["resolved_mode"], "MULTI")
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        self.assertTrue(result["conversation_completion_blocked"])
        self.assertEqual(self.provider.network_requests, 0)
        self.assertEqual(self.provider.physical_requests, 0)
        self.assertGreaterEqual(self.provider.text_calls, 3)
        self.assertGreaterEqual(self.provider.tool_calls, 2)
        self.assertTrue(self.provider.tool_result_feedback_seen)
        self.assertIn(">>> hello()", (self.workspace / "hello.py").read_text(encoding="utf-8"))
        self.assertFalse((self.home / "state" / "bplus-production-genesis").exists())
        self.assertFalse((self.home / ".sitina-bplus-disposable-v1").exists())
        journal = self.context_factory(self.home).open_runtime_state_reader()
        try:
            events = tuple(journal.iter_events(0))
        finally:
            journal.close()
        stages = [event.payload.get("stage") for event in events if event.event_type == "execution.stage"]
        self.assertIn("Controller", stages)
        self.assertIn("Planner", stages)
        self.assertIn("Forge", stages)
        self.assertIn("Tester", stages)
        self.assertIn("Reviewer", stages)
        self.assertTrue(any(event.event_type == "execution.authorization.bound" for event in events))
        child_events = [event for event in events if event.event_type in {
            "execution.authorization.child-bound",
            "execution.authorization.forge-child-bound",
        }]
        self.assertTrue(child_events)
        self.assertTrue(all(event.payload.get("parent_authorization_ref") for event in child_events))
        tester_events = [event for event in events if event.event_type == "execution.stage" and event.payload.get("stage") == "Tester"]
        self.assertTrue(tester_events)
        self.assertTrue(tester_events[-1].payload.get("accepted"))
        self.assertTrue(tester_events[-1].payload.get("test_evidence_hash"))
        forge_results = [event for event in events if event.event_type == "forge.execution.result"]
        self.assertTrue(forge_results)
        self.assertTrue(forge_results[-1].payload.get("accepted"))
        self.assertTrue(forge_results[-1].payload.get("diff_paths"))
        self.assertEqual(forge_results[-1].payload.get("workspace_mode"), "direct")
        self.assertTrue(
            any(item.get("worker_observed") is True for item in forge_results[-1].payload.get("mutation_events", []))
        )
        reviewer_events = [event for event in events if event.event_type == "execution.stage" and event.payload.get("stage") == "Reviewer"]
        self.assertTrue(reviewer_events)
        self.assertEqual(len(reviewer_events), 1)
        self.assertEqual(reviewer_events[-1].payload.get("decision"), "accepted")
        self.assertEqual(len(self.provider.review_prompts), 1)
        review_payload = json.loads(self.provider.review_prompts[0].split("\n", 1)[1])
        verified = review_payload.get("verified_evidence")
        self.assertIsInstance(verified, Mapping)
        self.assertEqual(verified["tester"]["accepted"], True)
        self.assertGreaterEqual(verified["tester"]["passed_test_count"], 1)
        self.assertEqual(verified["tester"]["failed_test_count"], 0)
        self.assertTrue(verified["patch_manifest"]["entries"])
        self.assertEqual(
            verified["patch_manifest_hash"], review_payload["patch_manifest_hash"]
        )
        issued_tokens = tuple(self.runtime.code_mode_policy._issued_authorizations)
        serialized_events = json.dumps([event.payload for event in events], sort_keys=True)
        self.assertTrue(all(token not in serialized_events for token in issued_tokens))
        persisted_bytes = b"".join(
            path.read_bytes()
            for path in self.home.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        self.assertTrue(
            all(token.encode("utf-8") not in persisted_bytes for token in issued_tokens),
            "opaque authorization token leaked into temporary Journal/CAS/log state",
        )
        self.assertTrue(any(event.event_type == "execution.stage" and event.payload.get("stage") == "Reviewer" for event in events))

    def test_existing_untracked_unittest_is_selected_for_code_mode_tester(self) -> None:
        """A pre-existing test file is executable evidence, not a patch path."""
        test_file = self.workspace / "test_hello.py"
        test_file.write_text(
            "import unittest\n"
            "from hello import hello\n\n"
            "class HelloTests(unittest.TestCase):\n"
            "    def test_hello(self):\n"
            "        self.assertEqual(hello(), 'hello')\n",
            encoding="utf-8",
        )
        baseline_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create hello.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        context = self.context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            run_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == f"run/{result['run_id']}"
            ]
        finally:
            journal.close()
        tester = [
            event for event in run_events
            if event.event_type == "execution.stage" and event.payload.get("stage") == "Tester"
        ][-1]
        evidence_ref = tester.payload.get("test_evidence_ref")
        self.assertIsInstance(evidence_ref, str)
        cas = context.open_cas_reader()
        evidence = json.loads(cas.open_verified(cas.resolve_reference(evidence_ref)).decode())
        self.assertEqual(evidence["runner_argv"][1:3], ["-m", "unittest"])
        self.assertEqual(evidence["runner_argv"][3:], ["test_hello.py"])
        self.assertEqual(evidence["collected_test_count"], 1)
        self.assertEqual(evidence["executed_test_count"], 1)
        self.assertEqual(evidence["passed_test_count"], 1)
        self.assertEqual(evidence["failed_test_count"], 0)
        self.assertEqual(
            baseline_hash,
            hashlib.sha256(test_file.read_bytes()).hexdigest(),
            "unchanged test evidence must not be mutated",
        )
        forge = [event for event in run_events if event.event_type == "forge.execution.result"][-1]
        self.assertEqual(forge.payload.get("diff_paths"), [str((self.workspace / "hello.py").resolve())])

    def test_provider_http_failure_resumes_original_plan_without_replan_provider_call(self) -> None:
        """A no-write transport fault cannot rewrite the product goal."""
        class HTTPFailingProvider(_ScriptedCodeModeProvider):
            def __init__(self, workspace: Path, *, reason_code: str | None = None):
                super().__init__(workspace)
                self.fail_once = True
                self.reason_code = reason_code
                self.replan_prompts: list[str] = []

            def _value(self, system_prompt: str, user_prompt: str) -> dict[str, object]:
                if "Recover the original requested implementation" in user_prompt:
                    self.replan_prompts.append(user_prompt)
                return super()._value(system_prompt, user_prompt)

            def complete_tool_turn(self, _profile: ProviderProfile, **kwargs: object) -> ProviderToolTurn:
                if self.fail_once:
                    self.fail_once = False
                    self.tool_calls = 0
                    error = ProviderHTTPError(400, "controlled local transport fault")
                    if self.reason_code is not None:
                        error.reason_code = self.reason_code
                    raise error
                return super().complete_tool_turn(_profile, **kwargs)

        provider = HTTPFailingProvider(self.workspace)
        runtime = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.context_factory,
            provider_client=provider, provider_profile=provider.profile,
        )
        conversation = ConversationRuntime(
            self.home, workspace=self.workspace, multi_runtime=runtime,
            runtime_context_factory=self.context_factory,
        )
        session = conversation.resume_or_create_session()
        result = conversation.execute_turn(
            session, "Please create http-recovery.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        self.assertEqual(provider.replan_prompts, [])
        context = self.context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
        finally:
            journal.close()
        forge = [event for event in events if event.event_type == "forge.execution.result"][-1]
        self.assertTrue(forge.payload.get("accepted"))
        self.assertEqual(forge.payload.get("attempts"), 2)
        ledger = forge.payload.get("attempt_ledger")
        self.assertEqual(ledger[0].get("reason_code"), "PROVIDER_HTTP_FAILURE")
        self.assertEqual(ledger[0].get("mutation_count"), 0)
        advance = [
            event for event in events
            if event.payload.get("schema") == "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
        ][0].payload
        self.assertEqual(advance["execution_authorization"].get("recovery_mode"), "resume-original")
        self.assertEqual(
            advance["execution_authorization"].get("original_plan_hash"),
            advance["code_mode_authorization"].get("original_plan_hash"),
        )
        self.assertNotIn("Provider retry/backoff", json.dumps(advance, ensure_ascii=False))

    def test_provider_http_status_reason_resumes_original_plan_without_replan_provider_call(self) -> None:
        """Host/broker status diagnostics remain exact without changing recovery."""
        class BrokerShapedHTTPFailureProvider(_ScriptedCodeModeProvider):
            def __init__(self, workspace: Path):
                super().__init__(workspace)
                self.fail_once = True
                self.replan_prompts: list[str] = []

            def _value(self, system_prompt: str, user_prompt: str) -> dict[str, object]:
                if "Recover the original requested implementation" in user_prompt:
                    self.replan_prompts.append(user_prompt)
                return super()._value(system_prompt, user_prompt)

            def complete_tool_turn(self, _profile: ProviderProfile, **kwargs: object) -> ProviderToolTurn:
                if self.fail_once:
                    self.fail_once = False
                    self.tool_calls = 0
                    error = ProviderHTTPError(400, "controlled local transport fault")
                    # This is the redacted host/broker diagnostic, not a
                    # provider-specific branch in the recovery controller.
                    error.reason_code = "PROVIDER_HTTP_STATUS_400"
                    raise error
                return super().complete_tool_turn(_profile, **kwargs)

        provider = BrokerShapedHTTPFailureProvider(self.workspace)
        runtime = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.context_factory,
            provider_client=provider, provider_profile=provider.profile,
        )
        conversation = ConversationRuntime(
            self.home, workspace=self.workspace, multi_runtime=runtime,
            runtime_context_factory=self.context_factory,
        )
        result = conversation.execute_turn(
            conversation.resume_or_create_session(),
            "Please create status-recovery.py and run the focused test; do not commit or push.",
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        self.assertEqual(provider.replan_prompts, [])
        journal = self.context_factory(self.home).open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
        finally:
            journal.close()
        forge = [event for event in events if event.event_type == "forge.execution.result"][-1]
        ledger = forge.payload.get("attempt_ledger")
        self.assertEqual(forge.payload.get("attempts"), 2)
        self.assertEqual(ledger[0].get("reason_code"), "PROVIDER_HTTP_STATUS_400")
        self.assertEqual(ledger[0].get("mutation_count"), 0)
        advance = [
            event for event in events
            if event.payload.get("schema") == "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
        ][0].payload
        self.assertEqual(advance["execution_authorization"].get("recovery_mode"), "resume-original")
        self.assertNotIn("Provider retry/backoff", json.dumps(advance, ensure_ascii=False))

    def test_post_execution_reviewer_rejection_replans_with_new_attempt_child(self) -> None:
        provider = _ScriptedCodeModeProvider(self.workspace)
        original_value = provider._value
        rejected = {"value": True}

        def review_once(system_prompt: str, user_prompt: str) -> dict[str, object]:
            value = original_value(system_prompt, user_prompt)
            if "Independently review this execution evidence" in user_prompt and rejected["value"]:
                rejected["value"] = False
                # The rejected attempt is rolled back; restart the scripted
                # tool sequence so the reworked attempt performs a real write.
                provider.tool_calls = 0
                value = {
                    "agent_id": provider._agent_id(system_prompt), "kind": "review",
                    "decision": "reject", "reason": "synthetic post-execution defect",
                    "evidence_checks": ["diff", "tests"],
                }
            return value

        provider._value = review_once  # type: ignore[method-assign]
        runtime = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.context_factory,
            provider_client=provider, provider_profile=provider.profile,
        )
        conversation = ConversationRuntime(
            self.home, workspace=self.workspace, multi_runtime=runtime,
            runtime_context_factory=self.context_factory,
        )
        session = conversation.resume_or_create_session()
        result = conversation.execute_turn(
            session, "Please create reviewer-rework.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        self.assertTrue((self.workspace / "hello.py").is_file())
        journal = self.context_factory(self.home).open_runtime_state_reader()
        try:
            events = tuple(journal.iter_events(0))
        finally:
            journal.close()
        self.assertTrue(any(event.event_type == "execution.rework.reviewer-rejected" for event in events))
        child_events = [event for event in events if event.event_type == "execution.authorization.forge-child-bound"]
        self.assertGreaterEqual(len(child_events), 2)
        self.assertEqual(sorted(event.payload.get("run_attempt") for event in child_events)[-2:], [1, 2])
        self.assertTrue(any(event.event_type == "execution.rework.started" and event.payload.get("attempt") == 2 for event in events))
        attempt_advance_events = [
            event for event in events
            if event.payload.get("schema") == "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
        ]
        self.assertEqual(len(attempt_advance_events), 1)
        advance = attempt_advance_events[0].payload
        self.assertEqual(advance.get("previous_run_attempt"), 1)
        self.assertEqual(advance.get("run_attempt"), 2)
        self.assertNotEqual(advance.get("previous_authorization_ref"), advance.get("authorization_ref"))
        self.assertTrue(advance.get("authorization_receipt_ref", "").startswith("cas:"))
        self.assertEqual(advance.get("code_mode_authorization", {}).get("run_attempt"), 2)
        durable_code_auth = advance["code_mode_authorization"]
        self.assertNotIn("authorization_token", durable_code_auth)
        self.assertRegex(durable_code_auth.get("authorization_token_hash", ""), r"^[0-9a-f]{64}$")
        issued_tokens = tuple(conversation.code_mode_policy._issued_authorizations)
        self.assertIn(
            durable_code_auth["authorization_token_hash"],
            {hashlib.sha256(token.encode("utf-8")).hexdigest() for token in issued_tokens},
        )
        new_ref = advance["authorization_ref"]
        replan = advance.get("replan_plan")
        self.assertIsInstance(replan, dict)
        self.assertEqual(advance.get("plan_hash"), advance.get("replan_plan_hash"))
        self.assertEqual(
            advance["replan_plan_hash"],
            hashlib.sha256(canonical_json_bytes(replan)).hexdigest(),
        )
        self.assertTrue(advance.get("replan_plan_ref", "").startswith("cas:"))
        self.assertIn(advance["replan_plan_ref"], attempt_advance_events[0].object_refs)
        self.assertNotEqual(advance.get("prior_plan_hash"), advance.get("plan_hash"))
        self.assertTrue(advance.get("prior_failure_type"))
        self.assertTrue(advance.get("prior_failure_hash"))
        self.assertEqual(advance["execution_authorization"].get("plan_hash"), advance["plan_hash"])
        self.assertEqual(advance["execution_authorization"].get("replan_plan"), replan)
        self.assertEqual(advance["code_mode_authorization"].get("replan_plan"), replan)
        attempt_two_children = [event for event in child_events if event.payload.get("run_attempt") == 2]
        self.assertTrue(attempt_two_children)
        self.assertTrue(all(event.payload.get("parent_authorization_ref") == new_ref for event in attempt_two_children))
        reviewer_events = [
            event for event in events
            if event.event_type == "execution.stage"
            and event.payload.get("stage") == "Reviewer"
            and event.payload.get("post_execution") is True
        ]
        self.assertEqual(len(reviewer_events), 2)
        self.assertEqual(
            [event.payload.get("decision") for event in reviewer_events],
            ["rejected", "accepted"],
        )
        self.assertEqual(
            [event.payload.get("attempt") for event in reviewer_events], [1, 2]
        )
        self.assertEqual(
            [event.payload.get("authorization_ref") for event in reviewer_events],
            [advance.get("previous_authorization_ref"), new_ref],
        )
        self.assertFalse(any("execution-review-admission" in str(event.payload) for event in events))
        forge_events = [
            event for event in events if event.event_type == "execution.stage" and event.payload.get("stage") == "Forge"
        ]
        self.assertEqual([event.payload.get("attempt") for event in forge_events], [1, 2])
        self.assertEqual([event.payload.get("authorization_ref") for event in forge_events], [advance.get("previous_authorization_ref"), new_ref])
        planner_replans = [
            event for event in events
            if event.event_type == "execution.stage"
            and event.payload.get("stage") == "Planner"
            and event.payload.get("replan") is True
        ]
        self.assertEqual(len(planner_replans), 1)
        self.assertEqual(planner_replans[0].payload.get("run_attempt"), 2)
        self.assertEqual(planner_replans[0].payload.get("authorization_ref"), new_ref)
        self.assertEqual(planner_replans[0].payload.get("plan_hash"), advance.get("plan_hash"))
        self.assertEqual(planner_replans[0].payload.get("prior_failure_hash"), advance.get("prior_failure_hash"))
        result_events = [event for event in events if event.event_type == "forge.execution.result"]
        self.assertTrue(result_events)
        self.assertEqual(result_events[-1].payload.get("run_attempt"), 2)
        self.assertEqual(result_events[-1].payload.get("authorization_ref"), new_ref)
        tester_events = [
            event for event in events
            if event.event_type == "execution.stage" and event.payload.get("stage") == "Tester"
        ]
        self.assertTrue(tester_events)
        self.assertEqual(tester_events[-1].payload.get("run_attempt"), 2)
        self.assertEqual(tester_events[-1].payload.get("authorization_ref"), new_ref)
        ledger = result_events[-1].payload.get("attempt_ledger")
        self.assertIsInstance(ledger, list)
        self.assertEqual([item.get("attempt") for item in ledger], [1, 2])
        self.assertEqual(ledger[0].get("failure_type"), "PostExecutionReviewerRejected")
        self.assertEqual(ledger[0].get("stage"), "Reviewer")
        self.assertEqual(ledger[0].get("rollback"), "ok")
        self.assertTrue(ledger[1].get("replan"))
        self.assertEqual(result_events[-1].payload.get("attempts"), 2)

    def test_stable_conversation_binding_rejects_mismatched_or_future_attempt(self) -> None:
        """Stable turn bindings cannot disagree or outrun the latest attempt."""
        from types import SimpleNamespace

        from scripts.code_mode_authority_host import AuthorityService

        session_id = "stable-conversation-session"
        run_id = "stable-conversation-run"
        session_instance_id = "stable-session-instance"
        generation = "stable-generation"
        body = "stable conversation body"
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        body_ref = "cas:" + "a" * 64
        message = {
            "schema": "SESSION_MESSAGE_APPENDED_V1",
            "event_type": "session.message-appended",
            "session_id": session_id,
            "role": "user",
            "turn_index": 1,
            "session_instance_id": session_instance_id,
            "run_attempt": 1,
            "generation": generation,
            "body_ref": body_ref,
            "body_hash": body_hash,
        }
        link = {
            "schema": "SESSION_RUN_LINKED_V1",
            "event_type": "session.run-linked",
            "session_id": session_id,
            "turn_index": 1,
            "run_id": run_id,
            "session_instance_id": session_instance_id,
            "run_attempt": 1,
            "generation": generation,
            "workspace": str(self.workspace),
        }

        class _MessageCAS:
            @staticmethod
            def resolve_reference(reference: str) -> str:
                return reference

            @staticmethod
            def verify_existing(_reference: str) -> SimpleNamespace:
                return SimpleNamespace(purpose_class="session-message")

            @staticmethod
            def open_verified(_reference: str) -> bytes:
                return body.encode()

        service = object.__new__(AuthorityService)
        service._workspace = self.workspace
        service._workspace_identity = str(self.workspace)
        service._formal_cas = lambda: _MessageCAS()

        def snapshot(message_payload: Mapping[str, object], link_payload: Mapping[str, object]):
            message_event = SimpleNamespace(
                event_type="session.message-appended",
                payload=dict(message_payload),
                stream_version=1,
            )
            link_event = SimpleNamespace(
                event_type="session.run-linked",
                payload=dict(link_payload),
                stream_version=2,
            )
            transaction = SimpleNamespace(
                stream_id=f"session/{session_id}",
                events=(message_event, link_event),
            )
            return (SimpleNamespace(transaction=transaction),)

        def reopen(message_payload: Mapping[str, object], link_payload: Mapping[str, object]):
            return service._bound_conversation(
                f"session/{session_id}",
                session_id=session_id,
                turn_index=1,
                run_id=run_id,
                session_instance_id=session_instance_id,
                run_attempt=2,
                generation=generation,
                message_hash=body_hash,
                snapshot=snapshot(message_payload, link_payload),
            )

        self.assertEqual(reopen(message, link)[0], f"session/{session_id}")
        with self.assertRaises(PermissionError):
            reopen(message, dict(link, run_attempt=2))
        with self.assertRaises(PermissionError):
            reopen(dict(message, run_attempt=3), dict(link, run_attempt=3))

    def test_ordinary_append_cannot_create_or_replay_attempt_advance(self) -> None:
        """Reserved rebound facts require the Journal's dedicated API."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create reserved-attempt.py and run the focused test; do not commit or push."
        )
        run_id = str(result["run_id"])
        journal = self.context_factory(self.home).open_runtime_state_reader()
        try:
            before_reserved = sum(
                event.payload.get("schema") == "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
                for event in journal.iter_events(0)
                if event.stream_id == f"run/{run_id}"
                and isinstance(event.payload, Mapping)
            )
            from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
            stream = CanonicalStream(journal, run_id, f"run/{run_id}", self.multi.policy_hash)
            for command_id, fact in (
                (
                    "ordinary-rebound-schema",
                    {
                        "schema": "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1",
                        "event_type": "ordinary.event",
                    },
                ),
                (
                    "ordinary-rebound-event-type",
                    {
                        "schema": "ORDINARY_FACT_V1",
                        "event_type": "execution.authorization.attempt_advanced",
                    },
                ),
            ):
                with self.assertRaises((LocalJournalError, TrueMultiAgentRuntimeError)):
                    stream.append(command_id, (fact,), actor="ordinary-caller")
            after_reserved = sum(
                event.payload.get("schema") == "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
                for event in journal.iter_events(0)
                if event.stream_id == f"run/{run_id}"
                and isinstance(event.payload, Mapping)
            )
            self.assertEqual(after_reserved, before_reserved)
        finally:
            journal.close()

    def test_replan_sealer_rejects_conflicting_planner_before_or_after_correct(self) -> None:
        """A current attempt may have exactly one Planner fact, never last-one-wins."""
        correct = {
            "event_type": "execution.stage",
            "stage": "Planner",
            "run_id": "run-r042",
            "run_attempt": 2,
            "authorization_ref": "auth-h2",
            "plan_hash": "h2",
        }
        conflicting = dict(correct, authorization_ref="auth-h1", plan_hash="h1")
        for ordered in ((conflicting, correct), (correct, conflicting)):
            with self.assertRaises(DynamicCollaborationError):
                _require_current_attempt_planner(
                    ordered, run_id="run-r042", run_attempt=2
                )
        self.assertEqual(
            _require_current_attempt_planner(
                (correct,), run_id="run-r042", run_attempt=2
            ),
            correct,
        )

    def test_replan_sealer_requires_canonical_raw_bytes_and_strict_json_types(self) -> None:
        """CAS replan identity is byte-exact, not Python mapping equality."""
        expected = {
            "schema": "SITINA_EXECUTION_REPLAN_PLAN_V1",
            "session_instance_id": "instance-r042",
            "session_id": "conversation-r042",
            "run_id": "run-r042",
            "run_attempt": 2,
            "previous_authorization_ref": "auth-h1",
            "prior_plan_hash": "a" * 64,
            "prior_failure_type": "PostExecutionReviewerRejected",
            "prior_failure_hash": "b" * 64,
            "plan_hash": "c" * 64,
            "approach": "Use the revised implementation plan.",
            "acceptance_checks": ["focused test passes"],
        }
        canonical = canonical_json_bytes(expected)
        self.assertEqual(_require_exact_replan_bytes(canonical, expected), expected)
        attacks = (
            canonical + b" ",
            canonical.replace(b'"run_attempt":2', b'"run_attempt":2.0'),
            canonical.replace(b'"run_attempt":2', b'"run_attempt":true'),
            canonical.replace(
                b'"schema":"SITINA_EXECUTION_REPLAN_PLAN_V1"',
                b'"schema":"SITINA_EXECUTION_REPLAN_PLAN_V1","schema":"other"',
            ),
            b'{"approach":"Use the revised implementation plan.",'
            b'"acceptance_checks":["focused test passes"],"schema":"SITINA_EXECUTION_REPLAN_PLAN_V1",'
            b'"session_instance_id":"instance-r042","session_id":"conversation-r042",'
            b'"run_id":"run-r042","run_attempt":2,"previous_authorization_ref":"auth-h1",'
            b'"prior_plan_hash":"' + (b"a" * 64) + b'","prior_failure_type":"PostExecutionReviewerRejected",'
            b'"prior_failure_hash":"' + (b"b" * 64) + b'","plan_hash":"' + (b"c" * 64) + b'"}',
        )
        for raw in attacks:
            with self.assertRaises(DynamicCollaborationError):
                _require_exact_replan_bytes(raw, expected)

    def test_real_finalization_rejects_conflicting_planner_after_current_fact(self) -> None:
        """The R-042 planner attack reaches the real sealer boundary.

        This deliberately injects the conflicting fact through the real
        Journal stream after an offline execution has produced its handoff;
        it does not call the planner-count helper.  A valid TTY review cannot
        promote a run whose current-attempt Planner set is no longer unique.
        """
        run_id_holder: dict[str, str] = {}
        original_append = CanonicalStream.append
        injected = False

        def append_conflicting_planner(
            stream: CanonicalStream, stage: str, facts: object, **kwargs: object
        ) -> object:
            nonlocal injected
            if not injected and stage == "execution-stage-planner":
                fact_sequence = tuple(facts)  # type: ignore[arg-type]
                current = dict(fact_sequence[0])
                run_id_holder["run_id"] = str(stream.run_id)
                conflicting = dict(current)
                conflicting["authorization_ref"] = "stale-authorization-ref"
                conflicting["plan_hash"] = "0" * 64
                injected = True
                original_append(
                    stream, "r042-conflicting-planner", (conflicting,), **kwargs
                )
            return original_append(stream, stage, facts, **kwargs)

        session = self.runtime.resume_or_create_session()
        with patch.object(CanonicalStream, "append", new=append_conflicting_planner):
            result = self.runtime.execute_turn(
                session,
                "Please create r042-outer.py and run the focused test; do not commit or push.",
            )
        self.assertTrue(injected)
        self.assertEqual(result["terminal_state"], "FAILED", result)
        run_id = run_id_holder["run_id"]
        reader = self.context_factory(self.home).open_runtime_state_reader()
        try:
            events = tuple(
                event for event in reader.iter_events(0)
                if event.stream_id == f"run/{run_id}"
            )
            self.assertFalse(
                any(
                    event.payload.get("schema") == "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1"
                    or event.payload.get("event_type") == "code-mode.final-root"
                    for event in events
                    if isinstance(event.payload, Mapping)
                )
            )
        finally:
            reader.close()

    def test_post_execution_reviewer_rejection_exhausts_budget_fail_closed(self) -> None:
        provider = _ScriptedCodeModeProvider(self.workspace)
        original_value = provider._value

        def reject_every_post_review(system_prompt: str, user_prompt: str) -> dict[str, object]:
            value = original_value(system_prompt, user_prompt)
            if "Independently review this execution evidence" in user_prompt:
                # Each bounded attempt must get a fresh scripted tool turn;
                # this reset is fixture state, not production retry-budget
                # state.  The runtime still owns the max-attempts budget.
                provider.tool_calls = 0
                return {
                    "agent_id": provider._agent_id(system_prompt), "kind": "review",
                    "decision": "reject", "reason": "persistent synthetic defect",
                    "evidence_checks": ["diff", "tests", "patch manifest"],
                }
            return value

        provider._value = reject_every_post_review  # type: ignore[method-assign]
        runtime = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.context_factory,
            provider_client=provider, provider_profile=provider.profile,
        )
        conversation = ConversationRuntime(
            self.home, workspace=self.workspace, multi_runtime=runtime,
            runtime_context_factory=self.context_factory,
        )
        session = conversation.resume_or_create_session()
        result = conversation.execute_turn(
            session, "Please create reviewer-budget.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "FAILED", result)
        self.assertTrue(result.get("execution_failed_closed"), result)
        self.assertFalse((self.workspace / "hello.py").exists())
        journal = self.context_factory(self.home).open_runtime_state_reader()
        try:
            events = tuple(journal.iter_events(0))
        finally:
            journal.close()
        reviewer_events = [
            event for event in events
            if event.event_type == "execution.stage"
            and event.payload.get("stage") == "Reviewer"
            and event.payload.get("post_execution") is True
        ]
        self.assertEqual(len(reviewer_events), 2)
        self.assertEqual({event.payload.get("decision") for event in reviewer_events}, {"rejected"})
        rework = [event for event in events if event.event_type == "execution.rework"]
        self.assertTrue(rework)
        self.assertEqual(rework[-1].payload.get("attempts"), 2)
        result_events = [event for event in events if event.event_type == "forge.execution.result"]
        self.assertTrue(result_events)
        self.assertEqual(result_events[-1].payload.get("accepted"), False)
        self.assertIn("rework_exhausted_fail_closed", result_events[-1].payload.get("notes", []))
        terminal_events = [
            event for event in events
            if event.payload.get("event_type") in {
                "code-mode.terminal-success", "code-mode.terminal-failed",
            }
        ]
        self.assertEqual(len(terminal_events), 1)
        self.assertEqual(terminal_events[0].payload.get("event_type"), "code-mode.terminal-failed")
        self.assertEqual(terminal_events[0].payload.get("schema"), "CODE_MODE_TERMINAL_FAILED_V1")
        self.assertEqual(terminal_events[0].payload.get("terminal_state"), "FAILED")

    def test_new_code_mode_run_starts_a_fresh_attempt_namespace(self) -> None:
        """Conversation turns create new runs; only in-run rework increments."""
        session = self.runtime.resume_or_create_session()
        first = self.runtime.execute_turn(
            session, "Please create first-run.py and run the focused test; do not commit or push."
        )
        self.assertEqual(first["terminal_state"], "REVIEW_PENDING", first)
        first_run_id = str(first["run_id"])

        # Reset only the offline scripted provider's deterministic fixture
        # sequence.  The production run owner remains the ConversationRuntime
        # and must issue attempt one for the new run.
        self.provider.tool_calls = 0
        second = self.runtime.execute_turn(
            session, "Please create second-run.py and run the focused test; do not commit or push."
        )
        self.assertEqual(second["terminal_state"], "REVIEW_PENDING", second)
        self.assertNotEqual(first_run_id, str(second["run_id"]))

        journal = self.context_factory(self.home).open_runtime_state_reader()
        try:
            events = tuple(journal.iter_events(0))
        finally:
            journal.close()
        for run_id in (first_run_id, str(second["run_id"])):
            auth_events = [
                event for event in events
                if event.stream_id == f"run/{run_id}"
                and event.event_type == "execution.authorization.bound"
            ]
            self.assertEqual(len(auth_events), 1, run_id)
            self.assertEqual(auth_events[0].payload.get("run_attempt"), 1, run_id)
            tester_events = [
                event for event in events
                if event.stream_id == f"run/{run_id}"
                and event.event_type == "execution.stage"
                and event.payload.get("stage") == "Tester"
            ]
            self.assertTrue(tester_events, run_id)
            self.assertEqual(tester_events[-1].payload.get("run_attempt"), 1, run_id)

    def test_real_code_mode_execution_seals_review_handoff_and_canary_stays_blocked(self) -> None:
        """A real offline MULTI execution produces a durable Review V2 handoff."""
        from sitina.orchestrator.bplus_production import ProductionRuntimeContext
        from sitina.orchestrator.code_mode_gate import build_candidate_manifest
        baseline_candidate = build_candidate_manifest(self.workspace)
        session = self.runtime.resume_or_create_session()
        with patch.object(
            ProductionRuntimeContext, "load",
            side_effect=AssertionError("Code Mode must not load Legacy B+ context"),
        ):
            result = self.runtime.execute_turn(
                session, "Please create hello.py and run the focused test; do not commit or push."
            )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        self.assertEqual(self.provider.physical_requests, 0)
        self.assertTrue((self.workspace / "hello.py").is_file())
        self.assertTrue(result["headless_review_pending"])
        self.assertEqual(result["review_status"], "REVIEW_PENDING")
        self.assertTrue(result["candidate"]["candidate_id"])
        # The pre-tool identity authorizes the starting workspace only.  The
        # handoff candidate is independently re-frozen from the final
        # workspace; compare it to a fresh recomputation rather than trusting
        # a scalar returned by the execution layer.
        baseline_identity = result["baseline_authorization_identity"]
        self.assertEqual(baseline_identity["candidate_id"], baseline_candidate["candidate_id"])
        self.assertNotEqual(result["candidate"]["candidate_id"], baseline_candidate["candidate_id"])
        self.assertNotEqual(result["candidate"]["worktree_digest"], baseline_candidate["worktree_digest"])

        # Derive the changed-path set from the durable patch manifest, not
        # from the output candidate.  This prevents the producer and this
        # assertion from silently sharing a baseline identity list and both
        # omitting a newly-created root file.
        context = self.context_factory(self.home)
        cas = context.open_cas_reader()
        package = None
        try:
            package = json.loads(
                cas.open_verified(cas.resolve_reference(result["evidence_package"]["reference_id"])).decode()
            )
            patch_ref = package["execution_receipt_refs"]["patch_manifest"]
            patch_manifest = json.loads(
                cas.open_verified(cas.resolve_reference(patch_ref)).decode()
            )
        finally:
            pass
        patch_changed_paths = set()
        for entry in patch_manifest["entries"]:
            patch_changed_paths.add(entry["path"])
            if entry.get("operation") == "rename":
                patch_changed_paths.add(entry["destination"])
        self.assertIn("hello.py", patch_changed_paths)
        candidate_changed_paths = set(result["candidate"]["changed_paths"])
        self.assertTrue(patch_changed_paths <= candidate_changed_paths)
        candidate_inventory = {
            item["path"] for item in result["candidate"]["objects"]
        } | {
            item["path"] for item in result["candidate"]["changed_path_records"]
        }
        self.assertTrue(patch_changed_paths <= candidate_inventory)
        final_candidate = build_candidate_manifest(
            self.workspace,
            identity_paths=None,
            changed_paths=sorted(patch_changed_paths),
        )
        final_candidate["generation"] = result["candidate"]["generation"]
        for field in ("candidate_id", "tree_hash", "source_manifest_hash", "worktree_digest", "generation"):
            self.assertEqual(result["candidate"][field], final_candidate[field], field)
        self.assertIsInstance(result["candidate"]["generation"], str)
        self.assertIn("hello.py", {item["path"] for item in result["candidate"]["objects"]})
        self.assertIn("hello.py", {item["path"] for item in result["candidate"]["identity_files"]})
        self.assertIn("hello.py", candidate_changed_paths)
        self.assertNotIn("candidate_id", result["review_request"])
        self.assertEqual(result["test_receipt"]["schema"], "CODE_MODE_MACHINE_CHECK_RECEIPT_V1")
        self.assertNotEqual(
            result["machine_check_receipt"]["reference_id"],
            result["evidence_package"]["reference_id"],
        )
        self.assertEqual(package["schema"], "CODE_MODE_EVIDENCE_PACKAGE_V1")
        self.assertEqual(package["run_id"], result["run_id"])
        self.assertEqual(package["candidate_id"], result["candidate"]["candidate_id"])
        self.assertEqual(package["tree_hash"], result["candidate"]["tree_hash"])
        self.assertEqual(package["candidate_worktree_digest"], result["candidate"]["worktree_digest"])
        self.assertTrue(package["tool_ledger"]["observed"])
        self.assertTrue(package["closing_root"]["sealed"])
        machine = json.loads(
            cas.open_verified(cas.resolve_reference(result["machine_check_receipt"]["reference_id"])).decode()
        )
        for field in (
            "source_manifest_hash", "worktree_before_hash", "worktree_after_hash",
            "diff_hash", "worktree_delta_hash", "generation", "verifier_identity",
        ):
            self.assertEqual(machine[field], package[field], field)
        journal = context.open_runtime_state_reader()
        try:
            run_events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
            self.assertFalse(any(
                event.event_type == "run.terminal"
                and event.payload.get("terminal_state") == "SUCCEEDED"
                for event in run_events
            ))
            self.assertTrue(any(event.event_type == "run.review-pending" for event in run_events))
            self.assertEqual(
                sum(event.event_type == "run.review-pending" for event in run_events), 1
            )
            self.assertFalse(any(
                event.event_type == "code-mode.final-reviewer-fact"
                or event.payload.get("schema") == "CODE_MODE_REVIEWER_FACT_V1"
                for event in run_events
            ))
            self.assertEqual(
                sum(event.payload.get("schema") == "CODE_MODE_EXECUTION_REVIEW_FACT_V1" for event in run_events),
                1,
            )
            session_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == f"session/{result['session_id']}"
            ]
            self.assertFalse(any(
                event.event_type == "session.message-appended"
                and event.payload.get("role") == "assistant"
                for event in session_events
            ))
        finally:
            journal.close()
        pending = self.runtime.maybe_confirm_tty_review(result)
        self.assertEqual(pending["code_mode_status"], "CODE_MODE_REVIEW_PENDING")
        self.assertNotIn("tty_review_receipt", pending)
        self.assertIn(
            pending.get("review_reason_type"),
            {"MISSING_CONTROLLER_REVIEW_HANDOFF", "REVIEWER_HOST_UNAVAILABLE"},
        )

    def test_tty_acceptance_reopens_run_before_single_success_terminal(self) -> None:
        """A test-only host proof exercises the real post-review commit path."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create tty-reviewed.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        # Reopen the authoritative terminal through the CLI-attested context;
        # the direct offline context intentionally cannot verify host-signed
        # completion plans.
        context = self.trusted_context_factory(self.home)
        reviewer = self.reviewer
        self.runtime.code_mode_reviewer_session = reviewer

        def tty_rpc(request: dict[str, object]) -> dict[str, object]:
            if request.get("method") == "tty_confirm":
                review = request["review_request"]
                assert isinstance(review, dict)
                summary = {
                    key: review.get(key)
                    for key in ("candidate_id", "tree_hash", "run_id", "evidence_package_ref", "evidence_package_hash")
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
            raise AssertionError("test TTY seam received an unexpected RPC")

        with patch.object(reviewer, "_rpc", side_effect=tty_rpc):
            accepted = self.runtime.maybe_confirm_tty_review(result)
        self.assertEqual(accepted["code_mode_status"], "CODE_MODE_READY", accepted)
        self.assertEqual(accepted["review_status"], "ACCEPT")
        self.assertEqual(accepted["terminal_state"], "SUCCEEDED")
        final_locator = accepted["code_mode_run_receipt"]
        self.assertEqual(final_locator["schema"], "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1")
        self.assertNotIn("headless_review_pending", final_locator)
        self.assertEqual(final_locator["receipt_hash"], final_locator["content_hash"])
        with self.assertRaises(DynamicCollaborationError):
            self.multi.finalize_code_mode_review(
                run_id=result["run_id"],
                review_receipt=accepted["tty_review_receipt"],
                gate_result={"status": "CODE_MODE_READY", "candidate_id": "forged-candidate"},
            )
        self.assertEqual(accepted["tty_review_receipt"]["authority_class"], "TTY_REVIEW_AUTHORITY")
        journal = context.open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
            accepted_positions = [
                event.position for event in events if event.event_type == "run.review-accepted"
            ]
            review_accepted_events = [
                event for event in events if event.event_type == "run.review-accepted"
            ]
            terminal_events = [
                event for event in events
                if event.event_type == "code-mode.terminal-success"
                and event.payload.get("terminal_state") == "SUCCEEDED"
            ]
            self.assertFalse(any(event.event_type == "run.terminal" for event in events))
            self.assertEqual(len(accepted_positions), 1)
            self.assertEqual(len(review_accepted_events), 1)
            self.assertEqual(len(terminal_events), 1)
            self.assertLess(accepted_positions[0], terminal_events[0].position)
            final_roots = [
                event for event in events
                if event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
            ]
            self.assertEqual(len(final_roots), 1)
            self.assertLess(terminal_events[0].position, final_roots[0].position)
            self.assertEqual(final_roots[0].payload["final_receipt_ref"], final_locator["reference_id"])
            self.assertEqual(final_roots[0].payload["final_receipt_hash"], final_locator["content_hash"])
            cas = context.open_cas_reader()
            final_body = json.loads(
                cas.open_verified(cas.resolve_reference(final_locator["reference_id"])).decode("utf-8")
            )
            journal.close()
            reopened_final = context.reopen_reviewed_terminal_receipt(
                final_locator, run_id=result["run_id"]
            )
            journal = context.open_runtime_state_reader()
            self.assertEqual(reopened_final["content_hash"], final_locator["content_hash"])
            self.assertEqual(reopened_final["root_event_id"], final_roots[0].event_id)
            self.assertEqual(final_body["schema"], "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1")
            self.assertEqual(final_body["status"], "SUCCEEDED")
            self.assertEqual(final_body["review_request_ref"], accepted["review_request"]["reference_id"])
            self.assertEqual(final_body["tty_review_receipt_ref"], accepted["tty_review_receipt"]["reference_id"])
            # The final receipt is pre-acceptance deterministic; the physical
            # terminal id is assigned later by Journal and is bound through
            # the signed terminal stage mapping.
            self.assertEqual(final_body["terminal_event_id"], "logical:terminal")
            self.assertTrue(final_body["terminal_event_hash"])
            accepted_payload = review_accepted_events[0].payload
            self.assertEqual(
                accepted_payload["package_ref"],
                accepted["evidence_package"]["reference_id"],
            )
            self.assertEqual(
                accepted_payload["request_ref"],
                accepted["review_request"]["reference_id"],
            )
            self.assertEqual(
                accepted_payload["review_receipt_ref"],
                accepted["tty_review_receipt"]["reference_id"],
            )
            self.assertEqual(accepted_payload["gate_status"], "CODE_MODE_READY")
            final_reviewer_facts = [
                event for event in events
                if event.payload.get("schema") == "CODE_MODE_FINAL_REVIEWER_FACT_V1"
            ]
            self.assertEqual(len(final_reviewer_facts), 1)
            final_reviewer = final_reviewer_facts[0].payload
            self.assertEqual(final_reviewer["package_ref"], accepted["evidence_package"]["reference_id"])
            self.assertEqual(final_reviewer["request_ref"], accepted["review_request"]["reference_id"])
            self.assertEqual(final_reviewer["review_receipt_ref"], accepted["tty_review_receipt"]["reference_id"])
            self.assertEqual(final_reviewer["decision"], "ACCEPT")
            self.assertEqual(final_reviewer["authority_class"], "TTY_REVIEW_AUTHORITY")
            self.assertFalse(any(
                event.event_type == "run.terminal"
                and event.payload.get("terminal_state") == "SUCCEEDED"
                and event.position < accepted_positions[0]
                for event in events
            ))
            session_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == f"session/{result['session_id']}"
            ]
            self.assertEqual(
                sum(event.event_type == "session.message-appended" and event.payload.get("role") == "assistant"
                    for event in session_events), 1
            )
            reopened_stream = CanonicalStream(
                journal, result["run_id"], f"run/{result['run_id']}", self.multi.policy_hash
            )
            with self.assertRaises(TrueMultiAgentRuntimeError):
                reopened_stream.append(
                    "after-final-root",
                    ({"schema": "MUST_NOT_APPEND_AFTER_FINAL_ROOT"},),
                    actor="test",
                )
        finally:
            journal.close()

    def _managed_pending_run(
        self, message: str, *, unborn: bool = False,
    ) -> tuple[dict[str, object], Path]:
        """Create one real managed-worktree REVIEW_PENDING handoff.

        ``unborn`` deliberately leaves the selected source at ``git init``
        with no refs or commits.  GitWorktreeManager then uses its isolated
        snapshot path while the source candidate remains an authentic unborn
        worktree.
        """
        session = self.runtime.resume_or_create_session()
        git_env = os.environ.copy()
        git_env.update({
            "GIT_AUTHOR_NAME": "Sitina managed-gate test",
            "GIT_AUTHOR_EMAIL": "managed-gate-test@invalid",
            "GIT_COMMITTER_NAME": "Sitina managed-gate test",
            "GIT_COMMITTER_EMAIL": "managed-gate-test@invalid",
        })
        subprocess.run(["git", "-C", str(self.workspace), "init", "--quiet"], check=True, env=git_env)
        if not unborn:
            subprocess.run(["git", "-C", str(self.workspace), "add", "-A"], check=True, env=git_env)
            subprocess.run(
                ["git", "-C", str(self.workspace), "commit", "--quiet", "--allow-empty", "-m", "managed-gate baseline"],
                check=True, env=git_env,
            )
        original_prepare = GitWorktreeManager.prepare

        def prepare_and_rebind(manager: GitWorktreeManager, repo: str, run_id: str):
            prepared = original_prepare(manager, repo, run_id)
            self.provider.workspace = Path(str(prepared["worktree"])).resolve(strict=True)
            return prepared

        with patch(
            "sitina.orchestrator.true_multi_agent._execution_isolation_required",
            return_value=True,
        ), patch.object(
            GitWorktreeManager, "prepare", autospec=True, side_effect=prepare_and_rebind
        ):
            result = self.runtime.execute_turn(
                session,
                message,
            )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        self.assertTrue(result["managed_worktree_for_review"])
        managed_root = (
            self.home / "artifacts" / "worktrees" / str(result["run_id"])
        ).resolve(strict=True)
        self.assertEqual(Path(result["execution_root"]).resolve(strict=True), managed_root)
        self.assertTrue(managed_root.is_dir())
        return result, managed_root

    def _managed_tty_rpc(self, request: dict[str, object]) -> dict[str, object]:
        reviewer = self.reviewer
        if request.get("method") == "tty_confirm":
            review = request["review_request"]
            assert isinstance(review, dict)
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
        raise AssertionError("managed TTY seam received an unexpected RPC")

    def test_managed_tty_gate_uses_source_candidate_and_execution_root(self) -> None:
        """The real ConversationRuntime handoff passes a managed Tester root.

        Candidate identity is still sealed from the selected source workspace;
        only the live Tester observation is rooted in the run-scoped managed
        worktree.  The fixture uses the normal worktree manager and TTY seam,
        so this covers the public ConversationRuntime -> Gate -> finalizer
        path without fabricating a Gate result.
        """
        result, managed_root = self._managed_pending_run(
            "Please create managed-tty.py and run the focused test; do not commit or push.",
            unborn=True,
        )

        self.runtime.code_mode_reviewer_session = self.reviewer
        with patch.object(self.reviewer, "_rpc", side_effect=self._managed_tty_rpc):
            accepted = self.runtime.maybe_confirm_tty_review(result)
        self.assertEqual(accepted["terminal_state"], "SUCCEEDED", accepted)
        self.assertEqual(accepted["code_mode_status"], "CODE_MODE_READY")
        self.assertFalse(managed_root.exists())
        head = subprocess.run(
            ["git", "-C", str(self.workspace), "rev-parse", "--verify", "HEAD"],
            check=False, capture_output=True, text=True,
        )
        refs = subprocess.run(
            ["git", "-C", str(self.workspace), "show-ref", "--head"],
            check=False, capture_output=True, text=True,
        )
        self.assertNotEqual(head.returncode, 0)
        self.assertEqual(refs.stdout, "")

    def test_managed_tester_observation_drift_fails_and_cleans(self) -> None:
        """A changed managed root is abandoned, not returned as retryable."""
        result, managed_root = self._managed_pending_run(
            "Please create managed-drift.py and run the focused test; do not commit or push."
        )
        self.runtime.code_mode_reviewer_session = self.reviewer
        controller = self.multi._active_code_mode_controller
        self.assertIsNotNone(controller)
        original_gate = CodeModeAcceptanceV1.evaluate_offline
        gate_calls = 0

        def gate_then_drift(gate: CodeModeAcceptanceV1, *args: object, **kwargs: object) -> dict[str, object]:
            nonlocal gate_calls
            evaluated = original_gate(gate, *args, **kwargs)
            gate_calls += 1
            if gate_calls == 1:
                (managed_root / "hello.py").write_text(
                    (managed_root / "hello.py").read_text(encoding="utf-8") + "\n# drift\n",
                    encoding="utf-8",
                )
            return evaluated

        # The first Gate is the real ConversationRuntime path.  The mutation
        # occurs only after that attestation and before the finalizer reopens
        # the machine receipt, so the second Gate detects the live drift and
        # exercises the production abandonment/cleanup guard.
        with patch.object(self.reviewer, "_rpc", side_effect=self._managed_tty_rpc), patch.object(
            CodeModeAcceptanceV1, "evaluate_offline", autospec=True, side_effect=gate_then_drift
        ):
            failed = self.runtime.maybe_confirm_tty_review(result)
        self.assertEqual(failed["terminal_state"], "FAILED", failed)
        self.assertEqual(failed["review_status"], "FAILED")
        self.assertEqual(failed["review_reason_type"], "CODE_MODE_REVIEW_ABANDONED")
        self.assertTrue(failed["review_abandoned"])
        self.assertEqual(gate_calls, 1)
        self.assertFalse(managed_root.exists())
        self.assertNotIn(result["run_id"], self.multi._pending_code_mode_runs)
        self.assertIsNone(self.multi._active_code_mode_controller)
        self.assertTrue(getattr(controller, "_closed", False))
        context = self.context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
        finally:
            journal.close()
        self.assertEqual(
            sum(event.payload.get("event_type") == "execution.worktree.cleanup.finally" for event in events),
            1,
        )
        self.assertEqual(
            sum(event.payload.get("event_type") == "code-mode.review-abandoned" for event in events),
            1,
        )
        self.assertFalse(any(
            event.event_type == "code-mode.terminal-success"
            or event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
            for event in events
        ))

    def test_managed_cleanup_fact_allows_idempotent_finalize_retry(self) -> None:
        """A crash after cleanup is recoverable without a second removal."""
        result, managed_root = self._managed_pending_run(
            "Please create managed-retry.py and run the focused test; do not commit or push."
        )
        self.runtime.code_mode_reviewer_session = self.reviewer
        captured: dict[str, object] = {}
        original_finalize = self.multi.finalize_code_mode_review
        original_cleanup = self.multi._cleanup_pending_code_mode_worktree
        cleanup_invocations = 0

        def capture_finalize(**kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return original_finalize(**kwargs)

        def cleanup_spy(**kwargs: object) -> Mapping[str, object]:
            nonlocal cleanup_invocations
            cleanup_invocations += 1
            return original_cleanup(**kwargs)

        def terminal_then_crash(*args: object, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("crash after durable cleanup fact")

        with patch.object(self.reviewer, "_rpc", side_effect=self._managed_tty_rpc), patch.object(
            self.multi, "finalize_code_mode_review", side_effect=capture_finalize
        ), patch.object(
            self.multi, "_cleanup_pending_code_mode_worktree", side_effect=cleanup_spy
        ), patch.object(
            self.multi, "_terminalize_code_mode", side_effect=terminal_then_crash
        ):
            pending = self.runtime.maybe_confirm_tty_review(result)
        self.assertEqual(pending["terminal_state"], "REVIEW_PENDING")
        self.assertTrue(captured)
        self.assertFalse(managed_root.exists())
        self.assertEqual(cleanup_invocations, 1)
        accepted = original_finalize(**captured)
        self.assertEqual(accepted["terminal_state"], "SUCCEEDED", accepted)
        self.assertFalse(managed_root.exists())
        self.assertEqual(cleanup_invocations, 1)
        context = self.context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
        finally:
            journal.close()
        self.assertEqual(
            sum(event.payload.get("event_type") == "execution.worktree.cleanup.finally" for event in events),
            1,
        )
        self.assertEqual(
            sum(event.payload.get("event_type") == "code-mode.terminal-success" for event in events),
            1,
        )
        self.assertEqual(
            sum(event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2" for event in events),
            1,
        )

    def test_review_pending_recovers_from_journal_after_controller_restart(self) -> None:
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create restart-reviewed.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING")
        context = self.context_factory(self.home)
        reviewer = self.reviewer

        def tty_rpc(request: dict[str, object]) -> dict[str, object]:
            if request.get("method") == "tty_confirm":
                review = request["review_request"]
                assert isinstance(review, dict)
                summary = {
                    key: review.get(key)
                    for key in ("candidate_id", "tree_hash", "run_id", "evidence_package_ref", "evidence_package_hash")
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
            raise AssertionError("test TTY seam received an unexpected RPC")

        with patch.object(reviewer, "_rpc", side_effect=tty_rpc):
            candidate_context = self.trusted_context_factory(self.home)
            candidate = candidate_context.reopen_candidate_manifest(
                result["candidate_locator"], run_id=result["run_id"]
            )
            review_receipt = candidate_context.confirm_tty(
                review=result["review_request"], candidate=candidate, reviewer_session=reviewer
            )
            external_gate = CodeModeAcceptanceV1(self.workspace).evaluate_offline(
                candidate=candidate, runtime_context=candidate_context,
                test_receipt=result["test_receipt"], reviewer_receipt=review_receipt,
                test_inventory=result["test_inventory"],
            )
            restarted = TrueMultiAgentProductionRuntime(
                self.home, runtime_context_factory=self.trusted_context_factory,
                provider_client=self.provider, provider_profile=self.provider.profile,
            )
            recovered = restarted.finalize_code_mode_review(
                run_id=result["run_id"], review_receipt=review_receipt,
                gate_result=external_gate,
                conversation_message=result["conversation_message"],
                conversation_session_id=result["conversation_session_id"],
                conversation_turn_index=result["conversation_turn_index"],
            )
        self.assertEqual(recovered["terminal_state"], "SUCCEEDED")
        self.assertEqual(
            recovered["code_mode_run_receipt"]["schema"],
            "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1",
        )

    def test_success_terminal_without_final_root_recovers_only_from_bound_evidence(self) -> None:
        """A crash after terminal commit is recoverable, but only from current facts."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create terminal-recovery.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        review_receipt, gate = self._tty_review_for_pending(result)

        original_append = LocalJournal.append_planned_authority_operation

        def fail_final_root(journal: LocalJournal, command: object, expected_version: int,
                            events: object, proofs: object = (), **kwargs: object):
            plan = kwargs.get("completion_plan")
            operation_id = kwargs.get("logical_operation_id")
            operations = plan.get("operations", ()) if isinstance(plan, dict) else ()
            operation = next(
                (item for item in operations if isinstance(item, dict)
                 and item.get("logical_operation_id") == operation_id),
                None,
            )
            if isinstance(operation, dict) and operation.get("operation") == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1":
                raise OSError("synthetic final-root interruption")
            return original_append(journal, command, expected_version, events, proofs, **kwargs)

        with patch.object(LocalJournal, "append_planned_authority_operation", autospec=True, side_effect=fail_final_root):
            with self.assertRaises(OSError):
                self.multi.finalize_code_mode_review(
                    run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=result["conversation_message"],
                    conversation_session_id=result["conversation_session_id"],
                    conversation_turn_index=result["conversation_turn_index"],
                )

        context = self.trusted_context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}")
            self.assertEqual(
                sum(event.event_type == "code-mode.terminal-success" and event.payload.get("terminal_state") == "SUCCEEDED" for event in events),
                1,
            )
            self.assertFalse(any(event.event_type == "run.terminal" for event in events))
            self.assertEqual(sum(event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2" for event in events), 0)
            terminal = next(event for event in events if event.event_type == "code-mode.terminal-success")
            evidence = json.loads(
                context.open_cas_reader().open_verified(
                    context.open_cas_reader().resolve_reference(terminal.payload["evidence_package_ref"])
                ).decode()
            )
        finally:
            journal.close()
        binding = evidence.get("code_mode_terminal_binding")
        self.assertIsInstance(binding, dict)
        for field in (
            "candidate_id", "source_manifest_hash", "worktree_digest", "machine_check_ref",
            "machine_check_hash", "evidence_package_ref", "evidence_package_hash",
            "review_request_ref", "review_request_hash", "tty_review_receipt_ref",
            "tty_review_receipt_hash", "generation", "verifier_identity", "user_response_hash",
        ):
            self.assertTrue(binding.get(field), field)

        restarted = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.trusted_context_factory,
            provider_client=self.provider, provider_profile=self.provider.profile,
        )
        recovered = restarted.finalize_code_mode_review(
            run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
            conversation_message=result["conversation_message"],
            conversation_session_id=result["conversation_session_id"],
            conversation_turn_index=result["conversation_turn_index"],
        )
        self.assertEqual(recovered["terminal_state"], "SUCCEEDED")
        reopened = context.reopen_reviewed_terminal_receipt(
            recovered["code_mode_run_receipt"], run_id=result["run_id"]
        )
        self.assertEqual(reopened["status"], "SUCCEEDED")

    def test_recovery_rejects_a_non_success_terminal_in_a_pending_code_mode_run(self) -> None:
        """Only the narrowly recoverable success-before-root window is accepted."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create terminal-rejection.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        context = self.context_factory(self.home)
        journal = context.open_runtime_writer()
        try:
            stream = CanonicalStream(
                journal, result["run_id"], f"run/{result['run_id']}", self.multi.policy_hash
            )
            stream.append(
                "injected-non-success-terminal",
                ({
                    "schema": "RUN_TERMINAL_FAILURE_INJECTION_V1",
                    "event_type": "run.terminal",
                    "run_id": result["run_id"],
                    "terminal_state": "FAILED",
                },),
                actor="offline-fault-test",
            )
        finally:
            journal.close()
        restarted = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.context_factory,
            provider_client=self.provider, provider_profile=self.provider.profile,
        )
        recovered = restarted._recover_pending_code_mode_run(result["run_id"])
        self.assertTrue(recovered.get("recovered"))
        self.assertEqual(recovered["code_receipt"]["review_status"], "REVIEW_PENDING")
        recovery_context = restarted.runtime_context_factory(self.home)
        recovery_journal = recovery_context.open_runtime_state_reader()
        try:
            recovered_events = tuple(
                event for event in recovery_journal.iter_events(0)
                if event.stream_id == f"run/{result['run_id']}"
            )
        finally:
            recovery_journal.close()
        self.assertFalse(any(
            event.event_type == "code-mode.terminal-success"
            or event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
            for event in recovered_events
        ))

    def test_finalization_retries_idempotent_conversation_after_lifecycle_failure(self) -> None:
        """A root/terminal survive a lifecycle fault and complete exactly once on retry."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create lifecycle-retry.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        review_receipt, gate = self._tty_review_for_pending(result)
        from sitina.conversation.lifecycle import ConversationLifecycle
        original_complete = ConversationLifecycle.complete_turn
        calls = {"count": 0}

        def fail_once(lifecycle: ConversationLifecycle, **kwargs: object):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("synthetic lifecycle interruption")
            return original_complete(lifecycle, **kwargs)

        with patch.object(ConversationLifecycle, "complete_turn", autospec=True, side_effect=fail_once):
            with self.assertRaises(OSError):
                self.multi.finalize_code_mode_review(
                    run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=result["conversation_message"],
                    conversation_session_id=result["conversation_session_id"],
                    conversation_turn_index=result["conversation_turn_index"],
                )
            retried = self.multi.finalize_code_mode_review(
                run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
                conversation_message=result["conversation_message"],
                conversation_session_id=result["conversation_session_id"],
                conversation_turn_index=result["conversation_turn_index"],
            )
        self.assertEqual(retried["terminal_state"], "SUCCEEDED")
        self.assertEqual(calls["count"], 2)
        context = self.context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            run_events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{result['run_id']}"]
            session_events = [event for event in journal.iter_events(0) if event.stream_id == f"session/{result['session_id']}"]
        finally:
            journal.close()
        self.assertEqual(sum(event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2" for event in run_events), 1)
        self.assertEqual(sum(event.event_type == "code-mode.terminal-success" and event.payload.get("terminal_state") == "SUCCEEDED" for event in run_events), 1)
        self.assertFalse(any(event.event_type == "run.terminal" for event in run_events))
        self.assertEqual(
            sum(event.event_type == "session.message-appended" and event.payload.get("role") == "assistant" for event in session_events),
            1,
        )

    def test_restart_finalize_reopens_checkpoint_message_without_caller_arguments(self) -> None:
        """Recovery must bind the persisted user message, not a caller replay."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create restart-no-args.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING")
        review_receipt, gate = self._tty_review_for_pending(result)
        restarted = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.trusted_context_factory,
            provider_client=self.provider, provider_profile=self.provider.profile,
        )
        recovered = restarted.finalize_code_mode_review(
            run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
        )
        self.assertEqual(recovered["terminal_state"], "SUCCEEDED")
        self.assertTrue(recovered["code_mode_run_receipt"]["reference_id"].startswith("cas:"))
        context = self.context_factory(self.home)
        journal = context.open_runtime_state_reader()
        try:
            session_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == f"session/{result['session_id']}"
                and event.payload.get("event_type") == "session.message-appended"
                and event.payload.get("role") == "assistant"
            ]
        finally:
            journal.close()
        self.assertEqual(len(session_events), 1)

    def test_authenticated_root_survives_restart_and_rejects_direct_journal_append(self) -> None:
        """The durable Journal seal, not only CanonicalStream, closes a run."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create durable-root.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING")
        review_receipt, gate = self._tty_review_for_pending(result)
        accepted = self.multi.finalize_code_mode_review(
            run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
            conversation_message=result["conversation_message"],
            conversation_session_id=result["conversation_session_id"],
            conversation_turn_index=result["conversation_turn_index"],
        )
        context = self.context_factory(self.home)
        journal = context.open_runtime_writer()
        try:
            stream = CanonicalStream(journal, result["run_id"], f"run/{result['run_id']}", self.multi.policy_hash)
            with self.assertRaises(TrueMultiAgentRuntimeError):
                stream.append("after-restart-root", ({"schema": "MUST_NOT_APPEND"},), actor="fault-test")
            direct_command = CommandEnvelope(
                "direct-after-code-mode-root",
                "default",
                f"run/{result['run_id']}",
                "code-mode.direct-after-root",
                "fault-test",
                "2026-01-01T00:00:00Z",
                {"run_id": result["run_id"], "attempt": "after-root"},
            )
            direct_event = EventEnvelope(
                "direct-after-code-mode-root-event",
                "code-mode.direct-after-root",
                "default",
                f"run/{result['run_id']}",
                0,
                0,
                "2026-01-01T00:00:00Z",
                {"schema": "MUST_NOT_APPEND"},
            )
            with self.assertRaises(Exception):
                journal.append(
                    direct_command,
                    getattr(journal, "_stream_heads", {}).get(f"run/{result['run_id']}", 0),
                    [direct_event],
                )
            rolled = journal.rollover()
            self.assertIsNotNone(rolled)
        finally:
            journal.close()
        second = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.trusted_context_factory,
            provider_client=self.provider, provider_profile=self.provider.profile,
        )
        again = second.finalize_code_mode_review(run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate)
        self.assertEqual(again["code_mode_run_receipt"]["content_hash"], accepted["code_mode_run_receipt"]["content_hash"])

    def test_plain_writer_root_fields_do_not_establish_durable_seal(self) -> None:
        """Self-reported V2 root fields are ordinary facts without finalization."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create ordinary-root.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING")
        context = self.context_factory(self.home)
        journal = context.open_runtime_writer()
        try:
            stream = CanonicalStream(journal, result["run_id"], f"run/{result['run_id']}", self.multi.policy_hash)
            with self.assertRaises(LocalJournalError):
                stream.append(
                    "ordinary-root-shaped-fact",
                    ({
                        "schema": "CODE_MODE_FINAL_ROOT_V2",
                        "event_type": "code-mode.final-root",
                        "run_id": result["run_id"],
                        "seal_command_id": "caller-self-report",
                        "authenticated_seal": True,
                        "gate_status": "CODE_MODE_READY",
                        "final_receipt_ref": "cas:" + "a" * 64,
                        "final_receipt_hash": "b" * 64,
                        "terminal_event_id": "caller-terminal",
                        "terminal_event_hash": "c" * 64,
                    },),
                    actor="ordinary-writer",
                )
            # A syntax-valid sidecar without a protected final-root
            # transaction is untrusted cache data and must not DoS reopen or
            # mark this stream sealed.
            sidecar = journal._seal_index_root / (
                "code-mode-seal-" + hashlib.sha256(f"run/{result['run_id']}".encode()).hexdigest() + ".json"
            )
            sidecar.write_text(json.dumps({
                "schema": "CODE_MODE_AUTHENTICATED_SEAL_INDEX_V1",
                "journal_id": journal.journal_id,
                "epoch": journal.epoch,
                "stream_id": f"run/{result['run_id']}",
                "command_id": "fake-sidecar-command",
                "transaction_id": "fake-sidecar-transaction",
                "transaction_hash": "a" * 64,
                "start_stream_version": 1,
                "end_stream_version": 1,
                "root_event_id": "fake-root-event",
                "root_event_hash": "b" * 64,
            }, sort_keys=True), encoding="utf-8")
            (journal._seal_index_root / "code-mode-seal-malformed.json").write_text(
                "{not-canonical-sidecar", encoding="utf-8"
            )
            stream.append("after-untrusted-root", ({"schema": "ALLOWED_AFTER_UNTRUSTED_ROOT"},), actor="ordinary-writer")
        finally:
            journal.close()
        # Reopen the durable writer: a self-reported root must remain an
        # ordinary event after restart, because only the authenticated
        # finalization transaction metadata can reconstruct a seal.
        restarted_context = self.context_factory(self.home)
        restarted_journal = restarted_context.open_runtime_writer()
        try:
            restarted_stream = CanonicalStream(
                restarted_journal, result["run_id"], f"run/{result['run_id']}", self.multi.policy_hash
            )
            restarted_stream.append(
                "after-untrusted-root-restart",
                ({"schema": "ALLOWED_AFTER_UNTRUSTED_ROOT_RESTART"},),
                actor="ordinary-writer",
            )
        finally:
            restarted_journal.close()

    def test_live_and_recovered_finalization_reject_foreign_conversation_message(self) -> None:
        """The checkpoint message hash protects both live and restart paths."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create message-binding.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        review_receipt, gate = self._tty_review_for_pending(result)
        args = dict(
            run_id=result["run_id"], review_receipt=review_receipt, gate_result=gate,
            conversation_session_id=result["conversation_session_id"],
            conversation_turn_index=result["conversation_turn_index"],
        )
        foreign_review = {
            "schema": "CODE_MODE_REVIEW_RECEIPT_V2",
            "reference_id": "cas:" + "f" * 64,
            "content_hash": "e" * 64,
            "receipt_hash": "e" * 64,
            "run_id": result["run_id"],
        }
        with self.assertRaises(DynamicCollaborationError):
            self.multi.finalize_code_mode_review(
                review_receipt=foreign_review, conversation_message=result["conversation_message"], **{
                    key: value for key, value in args.items() if key != "review_receipt"
                }
            )
        with self.assertRaises(DynamicCollaborationError):
            self.multi.finalize_code_mode_review(conversation_message="foreign message", **args)
        restarted = TrueMultiAgentProductionRuntime(
            self.home, runtime_context_factory=self.context_factory,
            provider_client=self.provider, provider_profile=self.provider.profile,
        )
        with self.assertRaises(DynamicCollaborationError):
            restarted.finalize_code_mode_review(conversation_message="foreign message", **args)
        self.assertEqual(
            self.multi.finalize_code_mode_review(
                conversation_message=result["conversation_message"], **args
            )["terminal_state"],
            "SUCCEEDED",
        )

    def test_live_provider_none_observes_sentinel_before_activation(self) -> None:
        runtime = TrueMultiAgentProductionRuntime(
            self.home,
            runtime_context_factory=self.context_factory,
            provider_client=None,
            provider_profile=None,
        )
        with patch.object(
            runtime, "_observe_code_mode_production_sentinel", return_value="live-sentinel"
        ) as observe, patch(
            "sitina.orchestrator.true_multi_agent.activate_runtime",
            side_effect=DynamicCollaborationError("stop before live provider activation"),
        ):
            with self.assertRaises(DynamicCollaborationError):
                runtime.execute(
                    "Please update hello.py.",
                    overrides={"canary_authorization": {"run_id": "live-sentinel-run"}},
                )
        observe.assert_called_once_with()

    def test_offline_scripted_provider_marks_sentinel_unobserved_and_gate_blocked(self) -> None:
        provider = _ScriptedCodeModeProvider(self.workspace)
        runtime = TrueMultiAgentProductionRuntime(
            self.home,
            runtime_context_factory=self.context_factory,
            provider_client=provider,
            provider_profile=provider.profile,
        )
        self.assertIsNotNone(runtime.provider_client)
        self.assertFalse(bool(getattr(runtime.provider_client, "authoritative_physical", False)))

    def test_production_sentinel_commits_file_contents_not_mtime_shape(self) -> None:
        sentinel_root = self.home / "sentinel-root"
        sentinel_root.mkdir()
        target = sentinel_root / "state.json"
        target.write_bytes(b"aaaa")
        sentinel_args = {
            "identity_roots": ("state.json",),
            "runtime_excluded_roots": ("cache", "artifacts"),
        }
        first = TrueMultiAgentProductionRuntime._observe_code_mode_production_sentinel(
            sentinel_root, **sentinel_args
        )
        original_stat = target.stat()
        target.write_bytes(b"bbbb")
        os.utime(target, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        second = TrueMultiAgentProductionRuntime._observe_code_mode_production_sentinel(
            sentinel_root, **sentinel_args
        )
        self.assertNotEqual(first, second)

    def test_production_identity_ignores_explicit_runtime_cache_but_detects_new_identity_file(self) -> None:
        sentinel_root = self.home / "bounded-sentinel"
        (sentinel_root / "core").mkdir(parents=True)
        (sentinel_root / "cache").mkdir()
        identity = sentinel_root / "core" / "runner.py"
        identity.write_bytes(b"one")
        (sentinel_root / "cache" / "large-runtime.bin").write_bytes(b"x" * 1024 * 1024)
        kwargs = {
            "identity_roots": ("core", "entrypoint.py"),
            "runtime_excluded_roots": ("cache", "state", "artifacts"),
        }
        before = TrueMultiAgentProductionRuntime._observe_code_mode_production_sentinel(
            sentinel_root, **kwargs
        )
        identity.write_bytes(b"two")
        after = TrueMultiAgentProductionRuntime._observe_code_mode_production_sentinel(
            sentinel_root, **kwargs
        )
        self.assertNotEqual(before, after)
        (sentinel_root / "cache" / "large-runtime.bin").write_bytes(b"y" * 1024 * 1024)
        self.assertEqual(
            after,
            TrueMultiAgentProductionRuntime._observe_code_mode_production_sentinel(
                sentinel_root, **kwargs
            ),
        )
        (sentinel_root / "entrypoint.py").write_bytes(b"new")
        self.assertNotEqual(
            after,
            TrueMultiAgentProductionRuntime._observe_code_mode_production_sentinel(
                sentinel_root, **kwargs
            ),
        )

    def test_formal_cli_bootstrap_reaches_reviewer_pending_and_closes_host(self) -> None:
        """The ordinary CLI bootstrap owns the reviewer host lifecycle.

        This is intentionally a pending-path test: the bundled test process
        has no controlling TTY and the fabricated locators below are rejected
        before any receipt can be issued.  It proves the formal launcher and
        ConversationRuntime handoff are reachable without a fixture-owned
        reviewer, while preserving fail-closed behavior.
        """
        state = self.home / "formal-reviewer-state"
        self.broker.close()
        self.reviewer.close()
        runtime_home, factory, multi = cli._build_code_mode_runtime(
            self.workspace, state_root=state, provider=self.provider,
        )
        reviewer = getattr(factory, "reviewer_session")
        try:
            self.assertTrue(reviewer.is_attested_reviewer())
            runtime = ConversationRuntime(
                runtime_home, workspace=self.workspace, multi_runtime=multi,
                runtime_context_factory=factory,
            )
            pending = runtime.maybe_confirm_tty_review({
                "run_id": "formal-review-run",
                "review_status": "HEADLESS_REVIEW_PENDING",
                "review_request": {
                    "schema": "CODE_MODE_REVIEW_REQUEST_V2",
                    "reference_id": "cas:" + "a" * 64,
                    "content_hash": "b" * 64,
                    "candidate_id": "candidate-formal",
                    "tree_hash": "tree-formal",
                    "run_id": "formal-review-run",
                    "evidence_package_ref": "cas:" + "c" * 64,
                    "evidence_package_hash": "d" * 64,
                    "tty_nonce": "nonce-formal",
                    "tty_expires_at": 4102444800,
                },
                "candidate": {"candidate_id": "candidate-formal", "tree_hash": "tree-formal"},
                "test_receipt": {"content_hash": "e" * 64},
            })
            self.assertEqual(pending["code_mode_status"], "CODE_MODE_REVIEW_PENDING")
            self.assertIn("review_reason_type", pending)
            self.assertNotIn("tty_review_receipt", pending)
        finally:
            factory.close()
        self.assertTrue(reviewer._closed)
        self.assertIsNotNone(reviewer._process.poll())

    def test_review_v2_requires_runtime_request_and_one_use_consumption(self) -> None:
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create review-v2.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        context = self.context_factory(self.home)
        candidate = result["candidate"]
        test_receipt = result["machine_check_receipt"]
        package = result["evidence_package"]
        request = result["review_request"]
        with self.assertRaises(TypeError):
            context.run_controlled_tester(  # type: ignore[call-arg]
                candidate=candidate, command=(sys.executable, "-m", "unittest", "-h"),
                test_inventory=("tests/code_mode",), interpreter=sys.executable,
                dependencies={"lock": "fixture-lock"}, cwd=self.workspace,
                run_id="caller-selected-run", controller_session=object(),
            )
        reviewer = launch_code_mode_reviewer()
        try:
            self.assertFalse(hasattr(reviewer, "approve_review"))
            with self.assertRaises(PermissionError):
                reviewer._rpc({"method": "approve", "review_token": "caller-forged"})  # type: ignore[attr-defined]
            with self.assertRaises(PermissionError):
                context.create_review_request(
                    candidate=candidate, run_receipt_ref=test_receipt,
                    evidence_package_ref=test_receipt,
                )
            self.assertEqual(request["schema"], "CODE_MODE_REVIEW_REQUEST_V2")
            self.assertTrue(request["reference_id"].startswith("cas:"))
            self.assertNotIn("evidence_package_ref", request)
            reopened_request = context._reopen_offline_review_request(  # type: ignore[attr-defined]
                candidate=candidate, request=request,
            )
            self.assertEqual(reopened_request["evidence_package_ref"], package["reference_id"])
            self.assertNotEqual(reopened_request["machine_check_ref"], reopened_request["evidence_package_ref"])
            tampered = dict(request, content_hash="0" * 64)
            with self.assertRaises(PermissionError):
                context.review_headless(
                    candidate=candidate, review_request=tampered, reviewer_session=reviewer,
                )
            with self.assertRaises(Exception):
                reviewer.prepare_review({
                    "schema": "CODE_MODE_REVIEW_REQUEST_V2", "reference_id": "cas:" + "0" * 64,
                    "content_hash": "0" * 64, "candidate_id": candidate["candidate_id"],
                    "tree_hash": candidate["tree_hash"], "run_id": test_receipt["run_id"],
                })
            # The headless producer now decides from the controller-sealed
            # objective facts, and labels its own verdict as a deterministic
            # machine review so nothing downstream can read it as a human
            # having confirmed the diff.
            approval = context.review_headless(
                candidate=candidate, review_request=request, reviewer_session=reviewer,
            )
            self.assertIsNotNone(approval)
            verdict = getattr(approval, "_verdict", None)
            self.assertIsInstance(verdict, Mapping)
            self.assertEqual(verdict["schema"], "CODE_MODE_REVIEW_VERDICT_V2")
            self.assertEqual(verdict["review_class"], "DETERMINISTIC_MACHINE_REVIEW_V1")
            self.assertEqual(verdict["human_confirmed"], "false")
            self.assertIn(verdict["decision"], {"ACCEPT", "REJECT"})
            self.assertTrue(verdict.get("producer_signature"))
        finally:
            reviewer.close()

    def test_reviewer_receipt_requires_distinct_one_use_authority(self) -> None:
        """The test producer cannot promote its own status to a review."""
        session = self.runtime.resume_or_create_session()
        result = self.runtime.execute_turn(
            session, "Please create reviewer-bound.py and run the focused test; do not commit or push."
        )
        self.assertEqual(result["terminal_state"], "REVIEW_PENDING", result)
        context = self.context_factory(self.home)
        candidate = result["candidate"]
        test_receipt = result["machine_check_receipt"]
        request = result["review_request"]
        # The former string-based API is gone.  A runtime/context cannot
        # self-select reviewer_id or ACCEPT.
        with self.assertRaises(TypeError):
            context.seal_offline_reviewer_receipt(  # type: ignore[call-arg]
                candidate=candidate, test_receipt=test_receipt,
                reviewer_id="same-runtime", decision="LOCAL_CANARY_READY",
            )
        with self.assertRaises(PermissionError):
            context._publish_offline_evidence_receipt(  # type: ignore[attr-defined]
                {"schema": "CODE_MODE_REVIEW_EVIDENCE_RECEIPT_V1"},
                reviewer_proof={
                    "issuer_id": "forged-reviewer", "issuer_signature": "forged",
                    "review_binding_hash": "forged", "reviewer_id": "forged",
                    "decision": "LOCAL_CANARY_READY",
                    "authority_class": "INDEPENDENT_REVIEWER_AUTHORITY",
                },
            )
        reviewer = launch_code_mode_reviewer()
        foreign_reviewer = launch_code_mode_reviewer()
        stale_reviewer = launch_code_mode_reviewer()
        try:
            capability = reviewer.bind(
                candidate_id=candidate["candidate_id"], tree_hash=candidate["tree_hash"],
                test_receipt_hash=test_receipt["content_hash"], run_id=test_receipt["run_id"],
                expires_at=int(time.time()) + 120,
            )
            foreign_capability = foreign_reviewer.bind(
                candidate_id=candidate["candidate_id"], tree_hash=candidate["tree_hash"],
                test_receipt_hash=test_receipt["content_hash"], run_id=test_receipt["run_id"],
                expires_at=int(time.time()) + 120,
            )
            # A caller can know the public host identity and provide a
            # self-consistent ACCEPT mapping, but it cannot produce the
            # independent producer's Ed25519 signature.  Exercise the host
            # protocol directly as an attack, without exposing such an API to
            # production callers.
            forged_evidence = _review_evidence_from_test_receipt(test_receipt)
            forged_verdict = {
                "schema": "CODE_MODE_REVIEW_VERDICT_V2",
                "reviewer_session_id": reviewer.independent_producer_identity["producer_id"],
                "candidate_id": candidate["candidate_id"], "tree_hash": candidate["tree_hash"],
                "test_receipt_hash": test_receipt["content_hash"], "run_id": test_receipt["run_id"],
                "review_evidence": forged_evidence,
                "review_evidence_hash": hashlib.sha256(json.dumps(
                    forged_evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode()).hexdigest(),
                "findings": [], "severity": "NONE", "decision": "ACCEPT",
                "producer_issuer_id": reviewer.independent_producer_identity["producer_id"],
                "producer_public_key": reviewer.independent_producer_identity["public_key"],
                "producer_signature": "0" * 128,
            }
            with self.assertRaises(PermissionError):
                reviewer._rpc({  # type: ignore[attr-defined]
                    "method": "issue", "capability_token": capability._token,
                    "candidate_id": candidate["candidate_id"], "tree_hash": candidate["tree_hash"],
                    "test_receipt_hash": test_receipt["content_hash"], "run_id": test_receipt["run_id"],
                    "verdict": forged_verdict,
                })
            with self.assertRaises(PermissionError):
                reviewer.issue_receipt(
                    foreign_capability, candidate_id=candidate["candidate_id"],
                    tree_hash=candidate["tree_hash"], test_receipt_hash=test_receipt["content_hash"],
                    run_id=test_receipt["run_id"], test_receipt=test_receipt,
                )
            with self.assertRaises(PermissionError):
                reviewer.issue_receipt(
                    capability, candidate_id=candidate["candidate_id"], tree_hash=candidate["tree_hash"],
                    test_receipt_hash=test_receipt["content_hash"], run_id=test_receipt["run_id"],
                    test_receipt=test_receipt,
                )
            with self.assertRaises(PermissionError):
                stale_reviewer.bind(
                    candidate_id=candidate["candidate_id"], tree_hash=candidate["tree_hash"],
                    test_receipt_hash=test_receipt["content_hash"], run_id=test_receipt["run_id"],
                    expires_at=int(time.time()) - 1,
                )
            with self.assertRaises((TypeError, AttributeError)):
                capability._binding["tree_hash"] = "tampered-tree"  # type: ignore[index]
            self.assertEqual(request["schema"], "CODE_MODE_REVIEW_REQUEST_V2")
            # Headless review produces a signed machine verdict, but sealing
            # still requires that verdict to be presented: a capability alone
            # cannot promote the runtime's own machine receipt into a review.
            context.review_headless(
                candidate=candidate, review_request=request, reviewer_session=reviewer,
            )
            with self.assertRaises(PermissionError):
                context.seal_offline_reviewer_receipt(
                    candidate=candidate, test_receipt=test_receipt,
                    reviewer_session=reviewer, reviewer_capability=capability,
                )
            copied = ReviewerReceiptCapability(reviewer, capability._token, capability._binding)
            with self.assertRaises(PermissionError):
                reviewer.issue_receipt(
                    copied, candidate_id=candidate["candidate_id"], tree_hash=candidate["tree_hash"],
                    test_receipt_hash=test_receipt["content_hash"], run_id=test_receipt["run_id"],
                    test_receipt=test_receipt,
                )
        finally:
            stale_reviewer.close()
            foreign_reviewer.close()
            reviewer.close()

    def test_code_mode_context_construction_failure_is_fail_closed(self) -> None:
        def broken_context_factory(_root: Path) -> CodeModeRuntimeContext:
            raise RuntimeError("synthetic context construction failure")

        runtime = ConversationRuntime(
            self.home,
            workspace=self.workspace,
            multi_runtime=self.multi,
            runtime_context_factory=broken_context_factory,
        )
        with self.assertRaises(CodeModeRuntimeUnavailable):
            runtime.resume_or_create_session()

    def test_code_mode_direct_entry_never_falls_back_to_legacy_context(self) -> None:
        runtime = TrueMultiAgentProductionRuntime(self.home, provider_client=self.provider, provider_profile=self.provider.profile)
        with patch(
            "sitina.orchestrator.bplus_production.ProductionRuntimeContext.load",
            side_effect=AssertionError("Code Mode must reject before Legacy B+ context load"),
        ):
            with self.assertRaises(DynamicCollaborationError):
                runtime.execute(
                    "Please create hello.py.",
                    overrides={"code_mode": True, "code_mode_authorization": {"intent_authorized": True}},
                )

    def test_execute_rejects_invalid_code_mode_schema_before_writer_or_run_created(self) -> None:
        """Malformed Code Mode auth cannot reach context or durable evidence."""
        issued = self.code_mode_policy.authorize(
            mode="MULTI",
            message="Please create schema-guard.py.",
            session_id="schema-guard-session",
            workspace=self.workspace,
        )
        secret = str(issued["authorization_token"])
        context_calls: list[Path] = []

        def context_must_not_open(root: Path) -> CodeModeRuntimeContext:
            context_calls.append(root)
            raise AssertionError("invalid authorization reached context/writer creation")

        runtime = TrueMultiAgentProductionRuntime(
            self.home,
            runtime_context_factory=context_must_not_open,
            provider_client=self.provider,
            provider_profile=self.provider.profile,
        )
        invalid_mappings = []
        missing_schema = dict(issued)
        missing_schema.pop("schema")
        invalid_mappings.append(missing_schema)
        wrong_schema = dict(issued)
        wrong_schema["schema"] = "CODE_MODE_RUNTIME_AUTHORIZATION_V0"
        invalid_mappings.append(wrong_schema)
        for authorization in invalid_mappings:
            with self.assertRaises(DynamicCollaborationError):
                runtime.execute(
                    "Please create schema-guard.py.",
                    overrides={"code_mode_authorization": authorization},
                )
        self.assertEqual(context_calls, [])
        persisted = b"".join(
            path.read_bytes()
            for path in self.home.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        self.assertNotIn(secret.encode("utf-8"), persisted)
        self.assertNotIn(b"run.created", persisted)


if __name__ == "__main__":
    unittest.main()
