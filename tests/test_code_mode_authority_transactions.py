"""Production-path checks for Code Mode authority transactions.

These tests deliberately use the existing disposable CLI-host fixture and the
real ConversationRuntime/TrueMultiAgent path.  They are offline: the scripted
provider is never allowed to produce an authoritative physical send.
"""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from sitina.cas.crypto import encrypt_object
from sitina.commands.model import CommandEnvelope
from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
from sitina.journal.model import (
    EventEnvelope, JournalModelError, acceptance_event_projection_hash, canonical_json_bytes,
    planned_operation_hash,
)
from sitina.journal.local import LocalJournal

from tests.test_code_mode_runtime_integration import CodeModeRuntimeIntegrationTests


class CodeModeAuthorityTransactionTests(unittest.TestCase):
    """Keep this suite small; the inherited integration class is a fixture."""

    def setUp(self) -> None:
        self._barrier_dir = None
        if self._testMethodName == "test_acceptance_rejects_authenticated_conversation_drift_between_validate_and_sign":
            self._barrier_dir = Path(tempfile.mkdtemp(prefix="sitina-acceptance-barrier-"))
            os.environ["SITINA_CODE_MODE_TEST_HOOKS"] = "1"
            os.environ["SITINA_CODE_MODE_ACCEPTANCE_BARRIER_READY"] = str(self._barrier_dir / "ready")
            os.environ["SITINA_CODE_MODE_ACCEPTANCE_BARRIER_RELEASE"] = str(self._barrier_dir / "release")
        self.fixture = CodeModeRuntimeIntegrationTests(
            "test_tty_acceptance_reopens_run_before_single_success_terminal"
        )
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()
        if self._barrier_dir is not None:
            os.environ.pop("SITINA_CODE_MODE_TEST_HOOKS", None)
            os.environ.pop("SITINA_CODE_MODE_ACCEPTANCE_BARRIER_READY", None)
            os.environ.pop("SITINA_CODE_MODE_ACCEPTANCE_BARRIER_RELEASE", None)
            shutil.rmtree(self._barrier_dir, ignore_errors=True)

    def test_real_execution_publishes_plan_acceptance_mapping_and_root_schemas(self) -> None:
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(
            session,
            "Please create authority-transaction.py and run the focused test; do not commit or push.",
        )
        self.assertEqual(pending.get("terminal_state"), "REVIEW_PENDING", pending)
        run_id = str(pending["run_id"])
        context = fixture.trusted_context_factory(fixture.home)
        journal = context.open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{run_id}"]
            schemas = {event.payload.get("schema") for event in events}
            self.assertIn("CODE_MODE_EXECUTION_FACT_V1", schemas)
            self.assertNotIn("CODE_MODE_COMPLETION_PLAN_FACT_V1", schemas)
            self.assertNotIn("CODE_MODE_FINAL_ROOT_V2", schemas)
            cas = context.open_cas_reader()
            try:
                core_fact = next(
                    event for event in events
                    if event.payload.get("evidence_schema") == "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1"
                )
                core_body = json.loads(
                    cas.open_verified(cas.resolve_reference(core_fact.payload["reference_id"])).decode("utf-8")
                )
                self.assertEqual(core_body.get("schema"), "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1")
            finally:
                del cas
        finally:
            journal.close()

        review_receipt, gate = fixture._tty_review_for_pending(pending)
        finalized = fixture.multi.finalize_code_mode_review(
            run_id=run_id,
            review_receipt=review_receipt,
            gate_result=gate,
            conversation_message=pending["conversation_message"],
            conversation_session_id=pending["conversation_session_id"],
            conversation_turn_index=pending["conversation_turn_index"],
        )
        self.assertEqual(finalized.get("terminal_state"), "SUCCEEDED")
        self.assertEqual(finalized["code_mode_run_receipt"]["schema"], "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1")
        journal = context.open_runtime_state_reader()
        try:
            events = [event for event in journal.iter_events(0) if event.stream_id == f"run/{run_id}"]
            schemas = {event.payload.get("schema") for event in events}
            self.assertIn("CODE_MODE_FINAL_ROOT_V2", schemas)
            plan_fact = next(event for event in events if event.payload.get("schema") == "CODE_MODE_COMPLETION_PLAN_FACT_V1")
            cas = context.open_cas_reader()
            try:
                plan_body = json.loads(
                    cas.open_verified(cas.resolve_reference(plan_fact.payload["reference_id"])).decode("utf-8")
                )
            finally:
                del cas
            self.assertEqual(plan_body.get("schema"), "CODE_MODE_COMPLETION_PLAN_V1")
            self.assertNotIn("acceptance_transaction", plan_body)
            self.assertEqual(len(plan_body.get("operations") or ()), 3)
            for operation in plan_body["operations"]:
                self.assertEqual(operation["logical_operation_hash"], planned_operation_hash(operation))
                self.assertIsInstance(operation.get("event_count"), int)
                self.assertEqual(len(operation["event_schema_order"]), operation["event_count"])
                self.assertRegex(operation["event_projection_hash"], r"^[0-9a-f]{64}$")
                self.assertRegex(operation["proof_manifest_hash"], r"^[0-9a-f]{64}$")
                self.assertIsInstance(operation.get("cas_object_hashes"), list)
                self.assertIsInstance(operation.get("frontier_commitment"), str)
                self.assertRegex(operation.get("stage_draft_ref", ""), r"^cas:[0-9a-f]{64}$")
                self.assertRegex(operation.get("stage_draft_hash", ""), r"^[0-9a-f]{64}$")
                self.assertIsInstance(operation.get("stage_actual_event_projection"), list)
                self.assertRegex(operation.get("stage_actual_event_projection_hash", ""), r"^[0-9a-f]{64}$")
                self.assertIsInstance(operation.get("stage_actual_proof_manifest"), list)
                self.assertRegex(operation.get("stage_actual_proof_manifest_hash", ""), r"^[0-9a-f]{64}$")
                stage_transaction = operation.get("stage_transaction")
                self.assertIsInstance(stage_transaction, dict)
                self.assertEqual(stage_transaction.get("schema"), "AUTHORITY_STAGE_TRANSACTION_V1")
                self.assertEqual(stage_transaction.get("logical_operation_id"), operation["logical_operation_id"])
                self.assertEqual(stage_transaction.get("logical_operation_hash"), operation["logical_operation_hash"])
                self.assertTrue(stage_transaction.get("signature_hex"))
                self.assertRegex(operation.get("stage_transaction_hash", ""), r"^[0-9a-f]{64}$")
            authority_operations = [
                event.payload.get("authority_operation")
                for event in events
                if isinstance(event.payload.get("authority_operation"), dict)
            ]
            self.assertGreaterEqual(len(authority_operations), 3)
            self.assertTrue(all(item.get("signature_hex") for item in authority_operations))
            self.assertTrue(all(item.get("payload_hash") for item in authority_operations))
            root = next(event for event in events if event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2")
            terminal = next(
                event for event in events
                if event.event_type == "code-mode.terminal-success"
                and event.payload.get("terminal_state") == "SUCCEEDED"
            )
            plan_ref = plan_fact.payload["reference_id"]
            plan_hash = plan_body["content_hash"]
            self.assertEqual(root.payload["completion_plan_ref"], plan_ref)
            self.assertEqual(root.payload["completion_plan_hash"], plan_hash)
            self.assertEqual(root.payload["terminal_event_id"], terminal.event_id)
            self.assertEqual(root.payload["terminal_event_hash"], terminal.event_hash)
            self.assertEqual(root.payload["seal_command_id"], root.payload["causation_command_id"])
            self.assertTrue(root.payload["seal_command_id"].startswith("code-mode-final-root-"))
            mapping = journal.authority_operation_mapping(
                root.payload["authority_operation"]["operation_id"],
                stream_id=f"run/{run_id}",
            )
            self.assertEqual(mapping["schema"], "AUTHORITY_OPERATION_COMMIT_MAPPING_V1")
            self.assertEqual(mapping["stream_id"], f"run/{run_id}")
            self.assertEqual(mapping["command_id"], root.payload["seal_command_id"])
            terminal_operation = next(
                operation for operation in plan_body["operations"]
                if operation["operation"] == "LOGICAL_TERMINAL_OPERATION_V1"
            )
            terminal_mapping = journal.authority_operation_mapping(
                terminal_operation["logical_operation_id"],
                stream_id=f"run/{run_id}",
            )
            terminal_mapping_events = [
                event for event in events
                if isinstance(event.payload.get("authority_operation"), dict)
                and event.payload["authority_operation"].get("operation_id")
                == terminal_operation["logical_operation_id"]
            ]
            self.assertEqual(
                terminal_mapping["event_hashes"],
                [event.event_hash for event in terminal_mapping_events],
            )
            self.assertEqual(terminal_mapping_events[-1].event_id, root.payload["terminal_event_id"])
            self.assertEqual(terminal_mapping_events[-1].event_hash, root.payload["terminal_event_hash"])
            session_stream = f"session/{pending['conversation_session_id']}"
            conversation_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == session_stream
                and event.payload.get("schema") == "CODE_MODE_CONVERSATION_COMPLETION_V1"
            ]
            self.assertEqual(len(conversation_events), 1)
            conversation_operation = conversation_events[0].payload["authority_operation"]
            conversation_mapping = journal.authority_operation_mapping(
                conversation_operation["operation_id"], stream_id=session_stream
            )
            self.assertEqual(conversation_mapping["schema"], "AUTHORITY_OPERATION_COMMIT_MAPPING_V1")
            self.assertEqual(conversation_mapping["stream_id"], session_stream)
            self.assertEqual(
                conversation_events[0].payload["assistant_message_id"],
                f"{session_stream.removeprefix('session/')}-assistant-{pending['conversation_turn_index']}",
            )
        finally:
            journal.close()

    def test_real_terminal_stage_body_tamper_is_rejected_before_terminal_append(self) -> None:
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(
            session,
            "Please create stage-tamper.py and run the focused test; do not commit or push.",
        )
        review_receipt, gate = fixture._tty_review_for_pending(pending)
        original_append = LocalJournal.append_planned_authority_operation

        def tamper_terminal(journal, command, expected_version, events, proofs=(), **kwargs):
            plan = kwargs.get("completion_plan")
            operation_id = kwargs.get("logical_operation_id")
            operation = next(
                (
                    item for item in (plan.get("operations") or ())
                    if isinstance(item, dict) and item.get("logical_operation_id") == operation_id
                ),
                None,
            ) if isinstance(plan, dict) else None
            if isinstance(operation, dict) and operation.get("operation") == "LOGICAL_TERMINAL_OPERATION_V1":
                altered = replace(
                    events[0],
                    payload={**dict(events[0].payload), "stage_body_tampered": True},
                )
                events = (altered, *tuple(events[1:]))
            return original_append(journal, command, expected_version, events, proofs, **kwargs)

        with patch.object(LocalJournal, "append_planned_authority_operation", autospec=True, side_effect=tamper_terminal):
            with self.assertRaises(Exception):
                fixture.multi.finalize_code_mode_review(
                    run_id=pending["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=pending["conversation_message"],
                    conversation_session_id=pending["conversation_session_id"],
                    conversation_turn_index=pending["conversation_turn_index"],
                )

        context = fixture.trusted_context_factory(fixture.home)
        journal = context.open_runtime_state_reader()
        try:
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == f"run/{pending['run_id']}")
            self.assertFalse(any(
                isinstance(event.payload.get("authority_operation"), dict)
                and event.payload["authority_operation"].get("operation") == "LOGICAL_TERMINAL_OPERATION_V1"
                for event in events
            ))
            self.assertFalse(any(event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2" for event in events))
        finally:
            journal.close()

    def test_real_terminal_stage_proof_tamper_is_rejected_before_terminal_append(self) -> None:
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(
            session,
            "Please create stage-proof-tamper.py and run the focused test; do not commit or push.",
        )
        review_receipt, gate = fixture._tty_review_for_pending(pending)
        original_append = LocalJournal.append_planned_authority_operation

        def tamper_terminal_proof(journal, command, expected_version, events, proofs=(), **kwargs):
            plan = kwargs.get("completion_plan")
            operation_id = kwargs.get("logical_operation_id")
            operation = next(
                (
                    item for item in (plan.get("operations") or ())
                    if isinstance(item, dict) and item.get("logical_operation_id") == operation_id
                ),
                None,
            ) if isinstance(plan, dict) else None
            if isinstance(operation, dict) and operation.get("operation") == "LOGICAL_TERMINAL_OPERATION_V1":
                proofs = (replace(proofs[0], purpose_class="tampered-stage-proof"), *tuple(proofs[1:]))
            return original_append(journal, command, expected_version, events, proofs, **kwargs)

        with patch.object(LocalJournal, "append_planned_authority_operation", autospec=True, side_effect=tamper_terminal_proof):
            with self.assertRaises(Exception):
                fixture.multi.finalize_code_mode_review(
                    run_id=pending["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=pending["conversation_message"],
                    conversation_session_id=pending["conversation_session_id"],
                    conversation_turn_index=pending["conversation_turn_index"],
                )

        context = fixture.trusted_context_factory(fixture.home)
        journal = context.open_runtime_state_reader()
        try:
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == f"run/{pending['run_id']}")
            self.assertFalse(any(
                isinstance(event.payload.get("authority_operation"), dict)
                and event.payload["authority_operation"].get("operation") == "LOGICAL_TERMINAL_OPERATION_V1"
                for event in events
            ))
            self.assertFalse(any(event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2" for event in events))
        finally:
            journal.close()

    def test_real_host_rejects_tampered_stage_draft_before_signing_plan(self) -> None:
        """A semantically wrong draft must fail at the host RPC boundary."""
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(
            session,
            "Please create host-draft-tamper.py and run the focused test; do not commit or push.",
        )
        review_receipt, gate = fixture._tty_review_for_pending(pending)
        original_request = CodeModeRuntimeContext.request_completion_plan

        def replace_terminal_draft(context, plan_inputs):
            altered_inputs = dict(plan_inputs)
            source_reference = altered_inputs["terminal_stage_draft_locator"]
            cas = context.open_cas()
            try:
                raw = cas.open_verified(cas.resolve_reference(source_reference))
                draft = json.loads(raw.decode("utf-8"))
                projection = list(draft["event_projection"])
                first = dict(projection[0])
                first_payload = dict(first["payload"])
                first_payload["generation"] = "foreign-generation-from-caller"
                first["payload"] = first_payload
                projection[0] = first
                draft["event_projection"] = projection
                draft["event_projection_hash"] = hashlib.sha256(
                    b"SITINA-CODE-MODE-ACTUAL-STAGE-V1\0"
                    + canonical_json_bytes(projection)
                ).hexdigest()
                replacement = cas.publish_plaintext(
                    canonical_json_bytes(draft),
                    tenant_id="code-mode-evidence",
                    purpose_class="code-mode-stage-draft-terminal",
                    media_type="application/json",
                )
                altered_inputs["terminal_stage_draft_locator"] = (
                    replacement.receipt.object_ref.reference_id
                )
            finally:
                del cas
            return original_request(context, altered_inputs)

        with patch.object(
            CodeModeRuntimeContext,
            "request_completion_plan",
            autospec=True,
            side_effect=replace_terminal_draft,
        ):
            with self.assertRaisesRegex(Exception, "stage draft"):
                fixture.multi.finalize_code_mode_review(
                    run_id=pending["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=pending["conversation_message"],
                    conversation_session_id=pending["conversation_session_id"],
                    conversation_turn_index=pending["conversation_turn_index"],
                )

        context = fixture.trusted_context_factory(fixture.home)
        journal = context.open_runtime_state_reader()
        try:
            events = tuple(
                event for event in journal.iter_events(0)
                if event.stream_id == f"run/{pending['run_id']}"
            )
            self.assertFalse(any(
                event.payload.get("schema") == "CODE_MODE_COMPLETION_PLAN_FACT_V1"
                for event in events
            ))
            self.assertFalse(any(
                isinstance(event.payload.get("authority_operation"), dict)
                and event.payload["authority_operation"].get("operation")
                in {"AUTHORITY_STAGE_TRANSACTION_V1", "LOGICAL_ACCEPTANCE_OPERATION_V1"}
                for event in events
            ))
            self.assertFalse(any(
                event.payload.get("schema") in {
                    "CODE_MODE_FINAL_ROOT_V2", "CODE_MODE_REVIEW_ACCEPTED_V1",
                }
                for event in events
            ))
        finally:
            journal.close()

    def _assert_root_mutation_rejected(self, prompt: str, mutate) -> None:
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(session, prompt)
        review_receipt, gate = fixture._tty_review_for_pending(pending)
        original_append = LocalJournal.append_planned_authority_operation

        def intercepted(journal, command, expected_version, events, proofs=(), **kwargs):
            plan = kwargs.get("completion_plan")
            operation_id = kwargs.get("logical_operation_id")
            operation = next(
                (item for item in (plan.get("operations") or ())
                 if isinstance(item, dict) and item.get("logical_operation_id") == operation_id),
                None,
            ) if isinstance(plan, dict) else None
            if isinstance(operation, dict) and operation.get("operation") == "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1":
                events, proofs = mutate(journal, command, events, proofs, kwargs)
            return original_append(journal, command, expected_version, events, proofs, **kwargs)

        with patch.object(LocalJournal, "append_planned_authority_operation", autospec=True, side_effect=intercepted):
            with self.assertRaises(Exception):
                fixture.multi.finalize_code_mode_review(
                    run_id=pending["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=pending["conversation_message"],
                    conversation_session_id=pending["conversation_session_id"],
                    conversation_turn_index=pending["conversation_turn_index"],
                )

        context = fixture.trusted_context_factory(fixture.home)
        journal = context.open_runtime_state_reader()
        try:
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == f"run/{pending['run_id']}")
            self.assertFalse(any(event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2" for event in events))
        finally:
            journal.close()

    def test_acceptance_rejects_authenticated_conversation_drift_between_validate_and_sign(self) -> None:
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(
            session, "Please create acceptance-race.py and run the focused test; do not commit or push."
        )
        review_receipt, gate = fixture._tty_review_for_pending(pending)
        result: list[BaseException] = []
        opened_writers = []
        original_open_runtime_writer = CodeModeRuntimeContext.open_runtime_writer

        def capture_writer(context, *args, **kwargs):
            writer = original_open_runtime_writer(context, *args, **kwargs)
            opened_writers.append(writer)
            return writer

        def finalize() -> None:
            try:
                fixture.multi.finalize_code_mode_review(
                    run_id=pending["run_id"], review_receipt=review_receipt, gate_result=gate,
                    conversation_message=pending["conversation_message"],
                    conversation_session_id=pending["conversation_session_id"],
                    conversation_turn_index=pending["conversation_turn_index"],
                )
            except BaseException as error:
                result.append(error)

        # Publish the CAS body before the host barrier.  The mutation at the
        # barrier itself is only the authenticated Journal event, avoiding a
        # second-writer/CAS lock wait while the finalizer holds its writer.
        binding = pending["candidate"]
        session_id = str(pending["conversation_session_id"])
        turn_index = int(pending["conversation_turn_index"]) + 1
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        message_id = "snapshot-drift-" + str(pending["run_id"])
        prep_context = fixture.trusted_context_factory(fixture.home)
        prep_cas = prep_context.open_cas()
        try:
            published = prep_cas.publish_verified(encrypt_object(
                b"authenticated conversation drift", fixture.keys,
                tenant_id="sitina-conversation", purpose="session-message",
            ))
        finally:
            del prep_cas
        payload = {
            "schema": "SESSION_MESSAGE_APPENDED_V1",
            "event_type": "session.message-appended",
            "session_id": session_id,
            "message_id": message_id,
            "role": "user",
            "body_ref": published.object_ref.reference_id,
            "body_hash": hashlib.sha256(b"authenticated conversation drift").hexdigest(),
            "body_tenant_id": published.object_ref.tenant_id,
            "body_plaintext_commitment": published.object_ref.plaintext_commitment,
            "body_commitment_key_id": published.object_ref.commitment_key_id,
            "turn_index": turn_index,
            "created_at": created_at,
            "session_instance_id": binding["session_instance_id"],
            "run_attempt": binding["run_attempt"],
            "generation": binding["generation"],
        }
        digest = hashlib.sha256(canonical_json_bytes({
            "session_id": session_id, "stage": "append-message",
            "event_type": "session.message-appended", "payload": payload,
        })).hexdigest()
        stream_id = "session/" + session_id
        drift_command = CommandEnvelope(
            "session-command-" + digest[:44], "sitina-conversation", stream_id,
            "session.append-message", "journal-session-repository", created_at,
            {"session_id": session_id, "event_hash": digest},
        )
        drift_event = EventEnvelope(
            "session-event-" + digest[:46], "session.message-appended",
            "sitina-conversation", stream_id, 0, 0, created_at, payload,
            (published.object_ref.reference_id,),
        )

        worker = threading.Thread(target=finalize, daemon=True)
        with patch.object(CodeModeRuntimeContext, "open_runtime_writer", new=capture_writer):
            worker.start()
            ready = self._barrier_dir / "ready"
            deadline = time.monotonic() + 15.0
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "authority host did not reach post-validation barrier")
            self.assertTrue(opened_writers, "finalization did not expose its authenticated Journal writer")
            journal = next(
                (candidate for candidate in reversed(opened_writers)
                 if not getattr(candidate.writer_lock, "_closed", True)
                 and not candidate.poisoned_reason),
                None,
            )
            self.assertIsNotNone(journal, "finalization exposed no healthy Journal writer at the barrier")
            journal.writer_lock.assert_healthy()
            expected = journal._stream_heads.get(stream_id, 0)
            journal.append(
                drift_command, expected, [drift_event], object_reference_proofs=(published,)
            )
            (self._barrier_dir / "release").touch()
            worker.join(timeout=15.0)
        self.assertFalse(worker.is_alive(), "acceptance race test left a live finalizer")
        self.assertEqual(len(result), 1, "snapshot drift unexpectedly produced an acceptance")
        self.assertIn("snapshot changed before acceptance signing", str(result[0]))

        context = fixture.trusted_context_factory(fixture.home)
        journal = context.open_runtime_state_reader()
        try:
            events = tuple(event for event in journal.iter_events(0) if event.stream_id == f"run/{pending['run_id']}")
            self.assertFalse(any(
                event.payload.get("schema") in {
                    "CODE_MODE_FINAL_REVIEWER_FACT_V1", "CODE_MODE_REVIEW_ACCEPTED_V1",
                }
                for event in events
            ))
            self.assertFalse(any(
                isinstance(event.payload.get("authority_operation"), dict)
                and event.payload["authority_operation"].get("operation") == "LOGICAL_ACCEPTANCE_OPERATION_V1"
                for event in events
            ))
            self.assertFalse(any(
                str(item).startswith("code-mode-accept-")
                for item in getattr(journal, "_authority_operation_commands", {})
            ))
        finally:
            journal.close()

    def test_real_root_rejects_wrong_completion_plan_proof_before_append(self) -> None:
        def mutate(_journal, _command, events, proofs, _kwargs):
            self.assertTrue(proofs)
            return events, (*tuple(proofs[:-1]), replace(proofs[-1], purpose_class="wrong-plan-proof"))

        self._assert_root_mutation_rejected(
            "Please create wrong-plan-proof.py and run the focused test; do not commit or push.",
            mutate,
        )

    def test_real_root_rejects_wrong_terminal_mapping_before_append(self) -> None:
        def mutate(_journal, _command, events, proofs, _kwargs):
            altered = replace(
                events[0],
                payload={**dict(events[0].payload), "terminal_event_id": "foreign-terminal-event"},
            )
            return (altered, *tuple(events[1:])), proofs

        self._assert_root_mutation_rejected(
            "Please create wrong-terminal-mapping.py and run the focused test; do not commit or push.",
            mutate,
        )

    def test_real_root_rejects_wrong_seal_command_before_append(self) -> None:
        def mutate(_journal, _command, events, proofs, _kwargs):
            altered = replace(events[0], payload={**dict(events[0].payload), "seal_command_id": "wrong-root-command"})
            return (altered, *tuple(events[1:])), proofs

        self._assert_root_mutation_rejected(
            "Please create wrong-seal-command.py and run the focused test; do not commit or push.",
            mutate,
        )

    def test_direct_context_cannot_submit_authority_transaction(self) -> None:
        context = self.fixture.context_factory(self.fixture.home)
        with self.assertRaises(AttributeError):
            getattr(context, "sign_completion_plan")

    def test_direct_context_rejects_legacy_caller_built_authority_requests(self) -> None:
        context = self.fixture.context_factory(self.fixture.home)
        with self.assertRaises(PermissionError):
            context.request_completion_plan({"schema": "CODE_MODE_COMPLETION_PLAN_V1"})
        with self.assertRaises(PermissionError):
            context.request_acceptance_transaction(locators={"schema": "CODE_MODE_ACCEPTANCE_REQUEST_V1"})

    def test_acceptance_projection_binds_typed_turn_and_event_owned_refs(self) -> None:
        reviewer = {
            "schema": "CODE_MODE_FINAL_REVIEWER_FACT_V1",
            "event_type": "code-mode.final-reviewer-fact",
            "run_id": "run-1", "session_id": "session-1", "turn_index": 1,
            "_object_refs": ["cas:" + "1" * 64],
        }
        accepted = {
            "schema": "CODE_MODE_REVIEW_ACCEPTED_V1",
            "event_type": "run.review-accepted",
            "run_id": "run-1", "session_id": "session-1", "turn_index": 1,
            "_object_refs": ["cas:" + "2" * 64],
        }
        original = acceptance_event_projection_hash([reviewer, accepted])
        altered_turn = dict(accepted, turn_index=True)
        with self.assertRaises(JournalModelError):
            acceptance_event_projection_hash([reviewer, altered_turn])
        altered_refs = dict(accepted, _object_refs=["cas:" + "1" * 64])
        self.assertNotEqual(original, acceptance_event_projection_hash([reviewer, altered_refs]))
        with self.assertRaises(JournalModelError):
            acceptance_event_projection_hash([dict(reviewer, turn_index=True), accepted])
        with self.assertRaises(JournalModelError):
            acceptance_event_projection_hash([dict(reviewer, session_id=""), accepted])

    def test_host_rejects_valid_cas_used_as_foreign_reviewer_locator(self) -> None:
        fixture = self.fixture
        session = fixture.runtime.resume_or_create_session()
        pending = fixture.runtime.execute_turn(
            session, "Please create reviewer-binding.py and run the focused test; do not commit or push."
        )
        context = fixture.trusted_context_factory(fixture.home)
        candidate_ref = str(pending["candidate_locator"]["reference_id"])
        request_ref = str(pending["review_request"]["reference_id"])
        package_ref = str(pending["evidence_package"]["reference_id"])
        journal = context.open_runtime_state_reader()
        try:
            checkpoint_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == "run/" + str(pending["run_id"])
                and event.payload.get("schema") == "CODE_MODE_REVIEW_PENDING_CHECKPOINT_V1"
            ]
            self.assertEqual(len(checkpoint_events), 1, pending)
            core_locator = checkpoint_events[0].payload.get("execution_core_locator")
        finally:
            journal.close()
        self.assertIsInstance(core_locator, dict, pending)
        core_ref = str(core_locator["reference_id"])
        locators = {
            "schema": "CODE_MODE_COMPLETION_LOCATOR_REQUEST_V2",
            "run_locator": "run/" + str(pending["run_id"]),
            "conversation_locator": "session/" + str(pending["conversation_session_id"]),
            "request_locator": request_ref,
            "candidate_locator": candidate_ref,
            "package_locator": package_ref,
            "core_locator": core_ref,
            # A valid candidate CAS object is deliberately used in the
            # reviewer slot; host must reject by reopened schema, before any
            # authority plan/signature is produced.
            "review_locator": candidate_ref,
            "gate_locator": candidate_ref,
            # This is the broker-issued binding value, not the opaque RPC
            # session token.  The latter is deliberately not interchangeable
            # with the runtime authority handle.
            "runtime_authority_handle_hash": str(
                context._broker_binding["runtime_authority_handle_hash"]
            ),
        }
        with self.assertRaises(Exception):
            context._broker_client.request_completion_plan(context._broker_session, locators)

    def test_host_rejects_caller_supplied_frontier_hash_and_locator_objects(self) -> None:
        """The attested host must derive identity, not sign RPC projections."""
        context = self.fixture.trusted_context_factory(self.fixture.home)
        malformed_plan = {
            "schema": "CODE_MODE_COMPLETION_LOCATOR_REQUEST_V2",
            "run_locator": {
                "run_id": "caller-selected", "stream_id": "run/caller-selected",
                "generation": "caller-generation",
                "frontier": {"stream_version": 0, "commitment": "0" * 64},
            },
            "conversation_locator": {"stream_id": "session/caller", "stream_version": 0, "binding_hash": "0" * 64},
            **{name: {"reference_id": "cas:" + "0" * 64, "object_hash": "0" * 64}
               for name in ("request_locator", "candidate_locator", "package_locator", "core_locator", "review_locator", "gate_locator")},
        }
        with self.assertRaises(Exception):
            context._broker_client.request_completion_plan(context._broker_session, malformed_plan)

        malformed_acceptance = {
            "schema": "CODE_MODE_ACCEPTANCE_LOCATOR_REQUEST_V2",
            "run_locator": malformed_plan["run_locator"],
            **{name: {"reference_id": "cas:" + "0" * 64, "object_hash": "0" * 64}
               for name in ("request_locator", "candidate_locator", "package_locator", "core_locator", "review_locator", "gate_locator", "completion_plan_locator")},
        }
        with self.assertRaises(Exception):
            context._broker_client.request_acceptance_transaction(context._broker_session, malformed_acceptance)

    def test_authority_pin_is_durable_and_not_rebuilt_from_event_shape(self) -> None:
        """Session authority is not a durable cross-restart issuer pin.

        The product boundary is the current CLI session: its attested host
        may be reopened while that session is alive, but a fresh writer must
        not recover authority from a JSON pin or a root-shaped event.  This
        preserves the negative guarantee that the old durable-pin path is not
        silently used as a cross-process authorization source.
        """
        context = self.fixture.trusted_context_factory(self.fixture.home)
        writer = context.open_runtime_writer()
        try:
            pin_path = writer.index_root / "authority-pin-v1.json"
            self.assertFalse(pin_path.exists())
            session_key = writer._external_authority_key_id
        finally:
            writer.close()
        reopened = context.open_runtime_writer()
        try:
            self.assertEqual(reopened._external_authority_key_id, session_key)
            self.assertFalse((reopened.index_root / "authority-pin-v1.json").exists())
        finally:
            reopened.close()

    def test_command_replay_validates_current_cas_proof_before_idempotent_return(self) -> None:
        """A replay cannot bypass proof identity/purpose validation."""
        context = self.fixture.context_factory(self.fixture.home)
        journal = context.open_runtime_writer()
        cas = context.open_cas()
        try:
            first = cas.publish_plaintext(
                b"proof-one", tenant_id="code-mode-test", purpose_class="replay-proof",
                media_type="application/octet-stream",
            ).receipt
            second = cas.publish_plaintext(
                b"proof-two", tenant_id="code-mode-test", purpose_class="replay-proof",
                media_type="application/octet-stream",
            ).receipt
            stream_id = "run/proof-replay"
            command = CommandEnvelope(
                "proof-replay-command", "default", stream_id, "proof-replay", "test",
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), {"case": "proof"},
            )
            event = EventEnvelope(
                "proof-replay-event", "proof-replay", "default", stream_id, 0, 0,
                "2026-01-01T00:00:00Z", {"schema": "PROOF_REPLAY_V1"},
                (first.object_ref.reference_id,),
            )
            journal.append(command, 0, (event,), (first,))
            with self.assertRaises(Exception):
                journal.append(command, 0, (event,), (second,))
        finally:
            journal.close()

    def test_replay_rejects_json_type_and_purpose_identity_changes(self) -> None:
        context = self.fixture.context_factory(self.fixture.home)
        journal = context.open_runtime_writer()
        cas = context.open_cas()
        try:
            receipt = cas.publish_plaintext(
                b"stable-proof", tenant_id="code-mode-test", purpose_class="stable-purpose",
                media_type="application/octet-stream",
            ).receipt
            command = CommandEnvelope(
                "typed-replay-command", "default", "run/typed-replay", "typed-replay", "test",
                "2026-01-01T00:00:00Z", {"case": "typed"},
            )
            event = EventEnvelope(
                "typed-replay-event", "typed-replay", "default", "run/typed-replay", 0, 0,
                "2026-01-01T00:00:00Z", {"value": 1}, (receipt.object_ref.reference_id,),
            )
            journal.append(command, 0, (event,), (receipt,))
            with self.assertRaises(Exception):
                journal.append(command, 0, (replace(event, payload={"value": True}),), (receipt,))
            with self.assertRaises(Exception):
                journal.append(command, 0, (event,), (replace(receipt, purpose_class="different-purpose"),))
        finally:
            journal.close()


if __name__ == "__main__":
    unittest.main()
