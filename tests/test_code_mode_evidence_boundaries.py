from __future__ import annotations

import sys
import tempfile
import threading
import unittest
import multiprocessing as mp
from pathlib import Path
from typing import Any

from sitina.orchestrator.code_mode_controller import CodeModeControllerSession
from sitina.orchestrator.code_mode_runtime import (
    CodeModeRuntimeContext,
    _tty_nonce_consumption_command_id,
)
from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream


def _process_nonce_submit(
    context: CodeModeRuntimeContext,
    barrier: Any,
    results: Any,
    run_id: str,
    command_id: str,
    facts: tuple[dict[str, object], ...],
    request_nonce: str,
) -> None:
    """Forked writer used only to exercise the real Journal lock boundary."""
    journal = None
    try:
        barrier.wait(timeout=5)
        journal = context.open_runtime_writer()
        stream = CanonicalStream(journal, run_id, f"run/{run_id}", context.identity.genesis_hash)
        stream.append_tty_nonce_consumption(
            facts[0],
            actor="code-mode-tty-authority", command_id=command_id,
            request_nonce=request_nonce,
        )
    except Exception:
        results.put("fail")
    else:
        results.put("success")
    finally:
        if journal is not None:
            journal.close()


class CodeModeEvidenceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="code-mode-evidence-workspace-"))
        self.home = Path(tempfile.mkdtemp(prefix="code-mode-evidence-home-"))
        self.context = CodeModeRuntimeContext.open(self.home)
        self.candidate = {"candidate_id": "candidate-current", "tree_hash": "tree-current"}
        self.controller = CodeModeControllerSession(
            context=self.context,
            run_id="tester-run-current",
            session_id="tester-session-current",
            authorization={
                "authorization_ref": "tester-authorization-current",
                "session_id": "tester-session-current",
                "session_instance_id": self.context.session_instance_id,
                "run_id": "tester-run-current",
                "run_attempt": 1,
                "expires_at": 4102444800,
            },
            workspace=self.workspace,
            offline=True,
        )
        self.context.bind_code_mode_request(
            session_instance_id=self.context.session_instance_id,
            session_id=self.controller.session_id,
            run_id=self.controller.run_id,
            candidate_id=self.candidate["candidate_id"],
            workspace=self.workspace,
            run_attempt=1,
            generation=self.context.identity.epoch_root,
        )

    def tearDown(self) -> None:
        self.controller.close()
        import shutil
        shutil.rmtree(self.workspace, ignore_errors=True)
        shutil.rmtree(self.home, ignore_errors=True)

    def test_help_only_and_command_inventory_mismatch_never_ready(self) -> None:
        for command, inventory in (
            ((sys.executable, "-m", "unittest", "-h"), ("tests.code_mode",)),
            ((sys.executable, "-m", "unittest", "tests.missing"), ("tests.other",)),
            ((sys.executable, "-m", "unittest"), ("tests.code_mode",)),
        ):
            receipt = self.controller.run_tester(
                self.context,
                candidate=self.candidate,
                command=command,
                test_inventory=inventory,
                interpreter=sys.executable,
                dependencies={"lock": "fixture"},
                cwd=self.workspace,
            )
            self.assertEqual(receipt["status"], "MACHINE_CHECK_FAILED")
            self.assertFalse(receipt["execution_observed"])
            self.assertTrue(receipt["preflight_failure"])
            self.assertNotIn("evidence_package_ref", receipt)

    def test_tester_cannot_seal_a_constant_evidence_package(self) -> None:
        with self.assertRaises(PermissionError):
            self.context._publish_offline_evidence_receipt({  # type: ignore[attr-defined]
                "schema": "CODE_MODE_EVIDENCE_PACKAGE_V1",
                "run_id": self.controller.run_id,
            })

    def test_review_requires_real_package_and_headless_is_not_ready(self) -> None:
        receipt = self.controller.run_tester(
            self.context,
            candidate=self.candidate,
            command=(sys.executable, "-m", "unittest", "-h"),
            test_inventory=("tests.code_mode",),
            interpreter=sys.executable,
            dependencies={"lock": "fixture"},
            cwd=self.workspace,
        )
        with self.assertRaises(PermissionError):
            self.context.create_review_request(
                candidate=self.candidate,
                run_receipt_ref=receipt,
                evidence_package_ref=receipt,
            )
        with self.assertRaises(TypeError):
            self.context.confirm_tty(  # type: ignore[call-arg]
                review=receipt,
                reviewer_session=object(),
                summary={},
                tty_path="/tmp/attacker-pty",
            )

    def test_headless_reviewer_without_semantic_producer_is_blocked(self) -> None:
        from tests.code_mode_reviewer_fixture import launch_code_mode_reviewer

        reviewer = launch_code_mode_reviewer()
        try:
            with self.assertRaises(PermissionError):
                reviewer._prepare_review({  # type: ignore[attr-defined]
                    "schema": "CODE_MODE_REVIEW_REQUEST_V2",
                    "reference_id": "cas:" + "a" * 64,
                    "content_hash": "b" * 64,
                    "candidate_id": "candidate-current",
                    "tree_hash": "tree-current",
                    "run_id": "tester-run-current",
                })
        finally:
            reviewer.close()

    def test_tty_receipt_path_rejects_fake_confirmation_and_headless_fallback(self) -> None:
        from unittest.mock import patch
        from sitina.orchestrator.code_mode_reviewer import TTYReviewConfirmation

        # A TTY receipt cannot be minted by passing a mapping or by invoking
        # the offline sealer with a caller-created object.
        with self.assertRaises(PermissionError):
            self.context._publish_offline_evidence_receipt(  # type: ignore[attr-defined]
                {
                    "schema": "CODE_MODE_REVIEW_RECEIPT_V2",
                    "candidate_id": self.candidate["candidate_id"],
                    "tree_hash": self.candidate["tree_hash"],
                    "decision": "ACCEPT",
                    "authority_class": "TTY_REVIEW_AUTHORITY",
                    "run_id": self.controller.run_id,
                },
                reviewer_session=object(), tty_confirmation={"confirmed": True},
            )

        # Even with a valid Review V2-shaped request, the reviewer client must
        # stop at the real controlling TTY boundary.  It must never call the
        # blocked headless producer as a fallback.
        from tests.code_mode_reviewer_fixture import launch_code_mode_reviewer
        reviewer = launch_code_mode_reviewer()
        try:
            manually_constructed = TTYReviewConfirmation(
                reviewer, ("cas:" + "a" * 64, "b" * 64), "c" * 64,
                "caller-nonce", 4102444800, 4102444700,
                {"schema": "CODE_MODE_TTY_CONFIRMATION_V1", "issuer_id": "forged",
                 "issuer_signature": "0" * 64},
            )
            self.assertFalse(reviewer.verify_tty_confirmation(manually_constructed))
            request = {
                "schema": "CODE_MODE_REVIEW_REQUEST_V2",
                "reference_id": "cas:" + "a" * 64,
                "content_hash": "b" * 64,
                "candidate_id": self.candidate["candidate_id"],
                "tree_hash": self.candidate["tree_hash"],
                "run_id": self.controller.run_id,
                "evidence_package_ref": "cas:" + "c" * 64,
                "evidence_package_hash": "d" * 64,
                "tty_nonce": "nonce-for-test",
                "tty_expires_at": 4102444800,
            }
            with patch.object(reviewer, "_prepare_review", side_effect=AssertionError("headless fallback")):
                with self.assertRaises(PermissionError):
                    reviewer.confirm_tty(request)
        finally:
            reviewer.close()

    def test_tty_nonce_consume_requires_controller_confirmation_object(self) -> None:
        with self.assertRaises(PermissionError):
            self.context._consume_tty_nonce(  # type: ignore[attr-defined]
                request={
                    "reference_id": "cas:" + "a" * 64,
                    "content_hash": "b" * 64,
                    "run_id": self.controller.run_id,
                },
                confirmation={"nonce": "caller-controlled"},
            )

    def test_tty_nonce_concurrent_consumption_has_one_fixed_command_winner(self) -> None:
        """The nonce command identity is stable and racing submissions conflict."""
        journal = self.context.open_runtime_writer()
        run_id = "tty-concurrent-run"
        consumption_id = "a" * 64
        command_id = _tty_nonce_consumption_command_id(consumption_id)
        facts = ({
            "schema": "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1",
            "consumption_id": consumption_id,
            "nonce_hash": "b" * 64,
            "request_ref": "cas:" + "c" * 64,
            "request_hash": "d" * 64,
            "run_id": run_id,
            "session_id": self.controller.session_id,
            "generation": "generation-test",
            "consumed": True,
        },)
        first = CanonicalStream(journal, run_id, f"run/{run_id}", self.context.identity.genesis_hash)
        second = CanonicalStream(journal, run_id, f"run/{run_id}", self.context.identity.genesis_hash)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def submit(stream: CanonicalStream, nonce: str) -> None:
            barrier.wait()
            try:
                stream.append_tty_nonce_consumption(
                    facts[0],
                    actor="code-mode-tty-authority",
                    command_id=command_id,
                    request_nonce=nonce,
                )
            except Exception:
                with lock:
                    outcomes.append("fail")
            else:
                with lock:
                    outcomes.append("success")

        threads = (
            threading.Thread(target=submit, args=(first, "submission-a")),
            threading.Thread(target=submit, args=(second, "submission-b")),
        )
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(sorted(outcomes), ["fail", "success"])
            events = [
                event for event in journal.iter_events(0)
                if event.stream_id == f"run/{run_id}"
                and isinstance(event.payload, dict)
                and event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
                and event.payload.get("consumption_id") == consumption_id
            ]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].payload.get("causation_command_id"), command_id)
        finally:
            journal.close()

    def test_tty_nonce_two_processes_have_one_command_winner(self) -> None:
        """Separate Journal writers cannot both consume one nonce identity."""
        if "fork" not in mp.get_all_start_methods():
            self.skipTest("the disposable macOS runtime has no fork start method")
        run_id = "tty-process-race"
        consumption_id = "e" * 64
        command_id = _tty_nonce_consumption_command_id(consumption_id)
        facts = ({
            "schema": "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1",
            "consumption_id": consumption_id,
            "nonce_hash": "f" * 64,
            "request_ref": "cas:" + "1" * 64,
            "request_hash": "2" * 64,
            "run_id": run_id,
            "session_id": self.controller.session_id,
            "generation": "generation-process-test",
            "consumed": True,
        },)
        context = self.context
        # Materialize the ephemeral Journal authenticator before fork so both
        # disposable child writers inherit the same key bytes.  They still
        # open independent Journal instances and race on the real writer lock.
        bootstrap_journal = context.open_runtime_writer()
        bootstrap_journal.close()
        # Opening an empty Journal does not yet materialize its authenticator;
        # force the shared in-memory test key before the fork.
        from sitina.security.key_provider import KeyPurpose
        descriptor = context.provider.current_descriptor(
            KeyPurpose.JOURNAL_AUTH, context.provider.runtime_journal_capability,
        )
        context.provider.symmetric_for_id(
            descriptor.key_id, KeyPurpose.JOURNAL_AUTH, context.provider.runtime_journal_capability,
        )
        process_context = mp.get_context("fork")
        barrier = process_context.Barrier(2)
        results = process_context.Queue()
        processes = [
            process_context.Process(
                target=_process_nonce_submit,
                args=(context, barrier, results, run_id, command_id, facts, "process-a"),
            ),
            process_context.Process(
                target=_process_nonce_submit,
                args=(context, barrier, results, run_id, command_id, facts, "process-b"),
            ),
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
        self.assertTrue(all(not process.is_alive() for process in processes))
        self.assertEqual(sorted(results.get(timeout=2) for _ in processes), ["fail", "success"])
        reopened = self.context.open_runtime_state_reader()
        try:
            events = [
                event for event in reopened.iter_events(0)
                if event.stream_id == f"run/{run_id}"
                and isinstance(event.payload, dict)
                and event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
                and event.payload.get("consumption_id") == consumption_id
            ]
        finally:
            reopened.close()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload.get("causation_command_id"), command_id)

    def test_forged_tty_receipt_without_same_run_consumption_is_not_gateable(self) -> None:
        forged = {
            "schema": "CODE_MODE_REVIEW_RECEIPT_V2",
            "authority_class": "TTY_REVIEW_AUTHORITY",
            "issuer_identity": "code-mode-tty-authority",
            "decision": "ACCEPT",
            "candidate_id": self.candidate["candidate_id"],
            "tree_hash": self.candidate["tree_hash"],
            "run_id": self.controller.run_id,
            "session_id": self.controller.session_id,
            "tty_consumption_ref": "cas:" + "a" * 64,
            "tty_consumption_hash": "b" * 64,
            "tty_nonce_hash": "c" * 64,
            "tty_consumption_event_hash": "event-forged",
            "review_request_ref": "cas:" + "d" * 64,
            "review_request_hash": "e" * 64,
        }
        self.assertFalse(self.context._verify_tty_review_receipt(forged))  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
