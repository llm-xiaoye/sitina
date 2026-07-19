from __future__ import annotations

import base64
import unittest

from pydantic import ValidationError

from sitina.contracts.models import BlackboardDocumentRecord, SourceDescriptor, TokenBudgetContract
from sitina.conversation.context_management import (
    AuthorizedContextHistory,
    ContextAllocationRequest,
    ContextBudgetAllocator,
    ContextCandidate,
    ContextHistoryEntry,
    ContextManagementError,
    ContextWindowPlanner,
    DeterministicContextSelector,
    StructuredSummaryCompressor,
)
from sitina.protocols.blackboard import Blackboard, BlackboardError, BlackboardNamespace, NamespacePolicy, PatchIntent
from sitina.protocols.context_retention import BlackboardRetention, ContextRetentionError
from sitina.protocols.handoff_contracts import HandoffContract, HandoffContractError
from sitina.protocols.handoffs import Handoff, HandoffError, HandoffState
from sitina.protocols.tasks import TaskAggregate
from sitina.security.redaction import redact_boundary_value


T0 = "2026-07-19T12:00:00Z"
T1 = "2026-07-19T12:01:00Z"
T2 = "2026-07-19T12:02:00Z"
T3 = "2026-07-19T12:03:00Z"


class ExactTokenizer:
    name = "fixture-provider-tokenizer-v1"

    def count(self, text: str) -> int:
        return len(text.encode("utf-8"))


def source() -> SourceDescriptor:
    return SourceDescriptor(component="context-tests", actor_id="agent-controller", source_ref="event-context-source")


def budget(*, maximum: int = 1_000, reserved: int = 0, consumed: int = 0) -> TokenBudgetContract:
    return TokenBudgetContract(
        schema="SITINA_TOKEN_BUDGET_V1",
        schema_version="1.0",
        correlation_id="run-context-tests",
        causation_id=None,
        created_at=T0,
        source=source(),
        trust="verified",
        budget_id="budget-context-tests",
        scope_type="run",
        scope_id="run-context-tests",
        maximum_tokens=maximum,
        reserved_tokens=reserved,
        consumed_tokens=consumed,
        hard_limit=True,
    )


def blackboard_record(document_id: str = "document-context") -> BlackboardDocumentRecord:
    return BlackboardDocumentRecord(
        schema="SITINA_BLACKBOARD_DOCUMENT_V1",
        schema_version="1.0",
        correlation_id="run-context-tests",
        causation_id=None,
        created_at=T0,
        source=source(),
        trust="verified",
        document_id=document_id,
        namespace="FACTS",
        document_version=1,
        document_hash="11" * 32,
        content_ref="cas:" + "12" * 32,
        classification="internal",
        writer_policy_hash="13" * 32,
        merge_policy_hash="14" * 32,
        last_writer_id="agent-controller",
    )


def contract(*, max_generations: int = 3, objective: str = "verify a bounded result") -> HandoffContract:
    return HandoffContract(
        handoff_id="handoff-context",
        generation=1,
        sender_id="agent-controller",
        receiver_id="agent-worker",
        task_id="task-context",
        objective=objective,
        scope=("read-only analysis",),
        required_capabilities=("handoff-receive",),
        input_refs=("21" * 32,),
        input_hashes=("22" * 32,),
        current_state_ref="23" * 32,
        output_schema={"type": "object", "required": ["result"]},
        acceptance_criteria=("result is hash-bound",),
        assumptions=("inputs are current",),
        residual_risks=("provider uncertainty",),
        open_questions=("none",),
        budget_tokens=200,
        deadline="2026-07-20T00:00:00Z",
        policy_hash="24" * 32,
        blackboard_documents=(blackboard_record(),),
        max_generations=max_generations,
    )


def protocol_handoff(handoff_id: str = "handoff-protocol", *, max_generations: int = 3) -> tuple[Handoff, dict]:
    return Handoff.offer(
        handoff_id,
        1,
        "agent-controller",
        "agent-worker",
        "task-context",
        "31" * 32,
        policy_hash="32" * 32,
        capability_hash="33" * 32,
        budget=200,
        deadline="2026-07-20T00:00:00Z",
        high_risk=False,
        max_generations=max_generations,
        required_capabilities=("handoff-receive",),
        receiver_capabilities=("handoff-receive",),
        input_freeze_hash="34" * 32,
        output_schema_hash="35" * 32,
    )


def next_generation(value: Handoff) -> tuple[Handoff, dict]:
    return value.new_generation(
        specification_hash="41" * 32,
        policy_hash="42" * 32,
        capability_hash="43" * 32,
        budget=150,
        deadline="2026-07-21T00:00:00Z",
        required_capabilities=("handoff-receive",),
        receiver_capabilities=("handoff-receive",),
        input_freeze_hash="44" * 32,
        output_schema_hash="45" * 32,
        previous_generation_ref="cas:" + "46" * 32,
        previous_rejection_event_ref="event-handoff-rejection",
        reject_reason_resolution_hash="47" * 32,
    )


class ContextHandoffManagementTests(unittest.TestCase):
    def test_h01_provider_tokenizer_accounts_system_tools_history_output_and_fallback(self) -> None:
        exact = ContextWindowPlanner.plan(
            budget=budget(maximum=2_000),
            provider_model="provider/model-v1",
            provider_context_limit=1_500,
            system_prompt="安全规则 中文 emoji 🧪",
            tool_schema='{"tool":"run","code":"print(1)"}',
            history="user: hello\nassistant: 你好",
            output_reserve_tokens=200,
            tokenizer=ExactTokenizer(),
        )
        self.assertEqual(exact.counting_mode, "provider-tokenizer")
        self.assertEqual(
            exact.total_reserved_tokens,
            exact.system_tokens + exact.tool_schema_tokens + exact.history_tokens + exact.output_reserve_tokens,
        )
        fallback = ContextWindowPlanner.plan(
            budget=budget(maximum=2_000),
            provider_model="provider/model-v1",
            provider_context_limit=1_500,
            system_prompt="安全规则 中文 emoji 🧪",
            tool_schema='{"tool":"run"}',
            history="mixed English 中文 code()",
            output_reserve_tokens=200,
        )
        self.assertEqual(fallback.counting_mode, "conservative-fallback")
        with self.assertRaises(ContextManagementError):
            ContextWindowPlanner.plan(
                budget=budget(maximum=100),
                provider_model="provider/model-v1",
                provider_context_limit=100,
                system_prompt="system",
                tool_schema="x" * 1_000,
                history="history",
                output_reserve_tokens=20,
            )

    def test_h02_deterministic_priority_never_evicts_safety_constraints_or_unfinished_work(self) -> None:
        values = (
            ContextCandidate("item-tool", "tool_output", "large tool " * 80, "event-tool"),
            ContextCandidate("item-safety", "safety", "never disclose secrets", "event-safety"),
            ContextCandidate("item-user", "user_constraint", "do not modify files", "event-user"),
            ContextCandidate("item-task", "unfinished_task", "finish phase four", "event-task"),
            ContextCandidate("item-evidence", "evidence", "evidence ref is valid", "event-evidence"),
        )
        first = DeterministicContextSelector.select(values, token_limit=30)
        second = DeterministicContextSelector.select(tuple(reversed(values)), token_limit=30)
        selected = {item.item_id for item in first.selected}
        self.assertTrue({"item-safety", "item-user", "item-task"}.issubset(selected))
        self.assertEqual(first.selection_hash, second.selection_hash)
        self.assertIn("item-tool", first.omitted_item_ids)

    def test_h03_structured_compression_preserves_required_fact_set_and_source_evidence(self) -> None:
        summary = StructuredSummaryCompressor.compress(
            decisions=("use Journal authority",),
            constraints=("no live Provider",),
            unfinished_tasks=("complete phase 04",),
            open_questions=("billable approval pending",),
            evidence_refs=("cas:" + "51" * 32,),
            source_refs=("event-context-source",),
            expendable_details=("long conversational aside", "duplicate prose"),
            token_limit=100,
        )
        expected = {
            "decisions:use Journal authority",
            "constraints:no live Provider",
            "unfinished_tasks:complete phase 04",
            "open_questions:billable approval pending",
            "evidence_refs:cas:" + "51" * 32,
            "source_refs:event-context-source",
        }
        self.assertEqual(summary.essential_facts, expected)
        self.assertEqual(len(summary.dropped_detail_hashes), 2)
        with self.assertRaises(ContextManagementError):
            StructuredSummaryCompressor.compress(
                decisions=("required decision",),
                constraints=("required constraint",),
                unfinished_tasks=(),
                open_questions=(),
                evidence_refs=(),
                source_refs=("event-source",),
                expendable_details=(),
                token_limit=1,
            )

    def test_h04_manifest_acknowledgement_accepts_complete_and_lists_every_missing_binding(self) -> None:
        value = contract()
        missing = value.acknowledge(
            receiver_id="agent-worker",
            occurred_at=T1,
            expected_contract_hash="0" * 64,
            available_capabilities=(),
            available_input_refs=(),
            available_blackboard_document_ids=(),
            accepted_budget_tokens=10,
            verified_objective_ref="0" * 64,
            verified_scope_ref="0" * 64,
            acceptance_criteria_confirmed=False,
            verified_policy_hash="0" * 64,
            verified_current_state_ref="0" * 64,
            verified_output_schema_hash="0" * 64,
        )
        self.assertEqual(missing.status, "REJECTED")
        self.assertIn("contract_hash", missing.missing_fields)
        self.assertIn("budget_tokens", missing.missing_fields)
        self.assertIn("objective_ref", missing.missing_fields)
        self.assertIn("scope_ref", missing.missing_fields)
        self.assertIn("acceptance_criteria", missing.missing_fields)
        self.assertIn("policy_hash", missing.missing_fields)
        self.assertIn("capability:handoff-receive", missing.missing_fields)
        self.assertIn("blackboard_document:document-context", missing.missing_fields)
        accepted = value.acknowledge(
            receiver_id="agent-worker",
            occurred_at=T1,
            expected_contract_hash=value.contract_hash,
            available_capabilities=("handoff-receive",),
            available_input_refs=value.input_refs,
            available_blackboard_document_ids=("document-context",),
            accepted_budget_tokens=value.budget_tokens,
            verified_objective_ref=value.objective_ref,
            verified_scope_ref=value.scope_ref,
            acceptance_criteria_confirmed=True,
            verified_policy_hash=value.policy_hash,
            verified_current_state_ref=value.current_state_ref,
            verified_output_schema_hash=value.output_schema_hash,
        )
        self.assertEqual((accepted.status, accepted.missing_fields), ("ACCEPTED", ()))

    def test_h05_repairable_rework_is_finite_permission_safety_fail_closed_and_cancel_cleans_up(self) -> None:
        first, _ = protocol_handoff(max_generations=2)
        repairable, fact = first.reject_classified(
            "agent-worker",
            reason_code="missing-input",
            classification="repairable",
        )
        self.assertEqual(repairable.state, HandoffState.REWORK)
        self.assertTrue(fact["rework_allowed"])
        second, _ = next_generation(repairable)
        second, _ = second.reject_classified(
            "agent-worker",
            reason_code="still-missing",
            classification="repairable",
        )
        with self.assertRaises(HandoffError) as captured:
            next_generation(second)
        self.assertEqual(captured.exception.fact["schema"], "HANDOFF_GENERATION_LIMIT_REACHED_V1")

        denied, _ = protocol_handoff("handoff-permission")
        denied, denied_fact = denied.reject_classified(
            "agent-worker",
            reason_code="permission-denied",
            classification="permission",
        )
        self.assertEqual(denied.state, HandoffState.FAILED)
        self.assertTrue(denied_fact["fail_closed"])
        unsafe, _ = protocol_handoff("handoff-safety")
        unsafe, unsafe_fact = unsafe.reject_classified(
            "agent-worker",
            reason_code="unsafe-scope",
            classification="safety",
        )
        self.assertEqual(unsafe.state, HandoffState.FAILED)
        self.assertTrue(unsafe_fact["fail_closed"])
        cancelled, _ = protocol_handoff("handoff-cancel")
        cancelled, cancel_fact = cancelled.cancel(
            "agent-controller",
            reason_code="user-cancelled",
            cleanup_refs=("cas:" + "52" * 32,),
        )
        self.assertEqual(cancelled.state, HandoffState.CANCELLED)
        self.assertTrue(cancel_fact["cleanup_required"])

    def test_h06_success_missing_tamper_expiry_duplicate_version_rework_and_restart(self) -> None:
        value = contract()
        offered = value.offered_fact(contract_object_ref="cas:" + "53" * 32)
        self.assertEqual(offered["schema"], "HANDOFF_CONTRACT_FROZEN_V1")
        tampered = value.acknowledge(
            receiver_id="agent-worker",
            occurred_at=T1,
            expected_contract_hash="f" * 64,
            available_capabilities=("handoff-receive",),
            available_input_refs=value.input_refs,
            available_blackboard_document_ids=("document-context",),
            accepted_budget_tokens=200,
            verified_objective_ref=value.objective_ref,
            verified_scope_ref=value.scope_ref,
            acceptance_criteria_confirmed=True,
            verified_policy_hash=value.policy_hash,
            verified_current_state_ref=value.current_state_ref,
            verified_output_schema_hash=value.output_schema_hash,
        )
        self.assertIn("contract_hash", tampered.missing_fields)

        aggregate, offered_fact = protocol_handoff("handoff-restart")
        accepted, accepted_fact = aggregate.accept("agent-worker", now=T1)
        with self.assertRaises(HandoffError):
            accepted.accept("agent-worker", now=T1)
        restarted = Handoff.rebuild((offered_fact, accepted_fact))
        self.assertEqual(restarted.state, HandoffState.ACCEPTED)
        rejected, rejected_fact = aggregate.reject_classified(
            "agent-worker",
            reason_code="missing-input",
            classification="repairable",
        )
        corrected, opened = next_generation(rejected)
        rebuilt = Handoff.rebuild((offered_fact, rejected_fact, opened))
        self.assertEqual((corrected.generation, rebuilt.generation), (2, 2))
        with self.assertRaises(HandoffError):
            Handoff.rebuild(({"schema": "HANDOFF_OFFERED_V99"},))
        expired, _ = protocol_handoff("handoff-expired")
        expired = Handoff.offer(
            expired.handoff_id,
            1,
            expired.sender_id,
            expired.receiver_id,
            expired.task_id,
            expired.specification_hash,
            policy_hash=expired.policy_hash,
            capability_hash=expired.capability_hash,
            budget=expired.budget,
            deadline=T1,
            high_risk=False,
        )[0]
        with self.assertRaises(HandoffError):
            expired.accept("agent-worker", now=T1)

    def test_h07_handoff_binds_shared_versioned_blackboard_document_not_free_text(self) -> None:
        value = contract()
        mapping = value.mapping()
        bound = mapping["blackboard_documents"][0]
        self.assertEqual(bound["schema"], "SITINA_BLACKBOARD_DOCUMENT_V1")
        self.assertEqual(bound["document_version"], 1)
        self.assertEqual(bound["document_hash"], "11" * 32)
        with self.assertRaises(ValidationError):
            BlackboardDocumentRecord.model_validate({**bound, "free_form_state": "bypass"})

    def test_h08_blackboard_interleaving_and_handoff_submission_reject_stale_task_fence(self) -> None:
        policy = NamespacePolicy(
            schema_hash="61" * 32,
            writer_capabilities=("facts-write",),
            reader_capabilities=("facts-read",),
            evidence_required=False,
            merge_policy="APPEND_ONLY",
            classification="INTERNAL",
            inline_limit=4096,
            writable_paths=("/",),
            persistence_scope="RUN_LOCAL",
        )
        board = Blackboard(
            {BlackboardNamespace.FACTS: policy},
            tenant_id="tenant-context",
            run_id="run-context",
            clock=lambda: T1,
        )
        document, _ = board.create("document-fence", BlackboardNamespace.FACTS)
        task, attempt, _ = TaskAggregate("task-context", "62" * 32).claim(
            claim_command_id="claim-context-1",
            lease_expires_at=T1,
            holder_agent_id="agent-worker",
        )
        intent = PatchIntent(
            document.document_id,
            document.version,
            document.document_hash,
            {"generation": 1},
            "agent-worker",
            ("facts-write",),
            task.task_id,
            attempt.task_attempt_id,
            attempt.claim_generation,
            attempt.fencing_token,
            (),
            (),
            merge_policy_hash=document.merge_policy_hash,
        )
        committed = board.patch(intent, task=task)
        task, _ = task.expire(attempt.fencing_token, observed_at=T2)
        task, second_attempt, _ = task.claim(
            claim_command_id="claim-context-2",
            lease_expires_at=T2,
            holder_agent_id="agent-worker",
        )
        stale_intent = PatchIntent(
            committed.document.document_id,
            committed.document.version,
            committed.document.document_hash,
            {"generation": "stale"},
            "agent-worker",
            ("facts-write",),
            task.task_id,
            attempt.task_attempt_id,
            attempt.claim_generation,
            attempt.fencing_token,
            (),
            (),
            merge_policy_hash=committed.document.merge_policy_hash,
        )
        with self.assertRaises(BlackboardError):
            board.patch(stale_intent, task=task)

        handoff, _ = protocol_handoff("handoff-stale-fence")
        handoff, _ = handoff.accept("agent-worker", now=T1)
        handoff, _ = handoff.mark_claim_pending(
            "agent-worker",
            task_claim_ref="63" * 32,
            fencing_token=second_attempt.fencing_token,
        )
        handoff, _ = handoff.bind_claim(task, second_attempt.fencing_token)
        handoff, _ = handoff.execute("agent-worker")
        task, _ = task.expire(second_attempt.fencing_token, observed_at=T2)
        task, _third_attempt, _ = task.claim(
            claim_command_id="claim-context-3",
            lease_expires_at="2026-07-20T00:00:00Z",
            holder_agent_id="agent-worker",
        )
        with self.assertRaises(HandoffError):
            handoff.submit_fenced(
                "agent-worker",
                "64" * 32,
                task=task,
                output_schema_hash="35" * 32,
                schema_validation_evidence_hash="65" * 32,
            )
        current_intent = PatchIntent(
            committed.document.document_id,
            committed.document.version,
            committed.document.document_hash,
            {"generation": 3},
            "agent-worker",
            ("facts-write",),
            task.task_id,
            _third_attempt.task_attempt_id,
            _third_attempt.claim_generation,
            _third_attempt.fencing_token,
            (),
            (),
            merge_policy_hash=committed.document.merge_policy_hash,
        )
        self.assertEqual(board.patch(current_intent, task=task).document.version, 2)
        current_handoff, _ = protocol_handoff("handoff-current-fence")
        current_handoff, _ = current_handoff.accept("agent-worker", now=T1)
        current_handoff, _ = current_handoff.mark_claim_pending(
            "agent-worker",
            task_claim_ref="66" * 32,
            fencing_token=_third_attempt.fencing_token,
        )
        current_handoff, _ = current_handoff.bind_claim(task, _third_attempt.fencing_token)
        current_handoff, _ = current_handoff.execute("agent-worker")
        current_handoff, submitted = current_handoff.submit_fenced(
            "agent-worker",
            "67" * 32,
            task=task,
            output_schema_hash="35" * 32,
            schema_validation_evidence_hash="68" * 32,
        )
        self.assertEqual(current_handoff.state, HandoffState.SUBMITTED)
        self.assertTrue(submitted["current_fencing_token_verified"])

    def test_h09_terminal_retention_holds_references_gc_boundary_and_restart(self) -> None:
        retention, registered = BlackboardRetention.register(
            blackboard_record("document-retention"),
            run_id="run-context-tests",
            registered_at=T0,
            retain_until=T2,
        )
        retention, terminal = retention.mark_run_terminal(terminal_at=T1)
        with self.assertRaises(ContextRetentionError):
            retention.collect(at=T1, actor="agent-controller")
        retention, held = retention.set_holds(legal_hold=True, audit_hold=False, actor="agent-controller")
        with self.assertRaises(ContextRetentionError):
            retention.collect(at=T2, actor="agent-controller")
        retention, clear = retention.set_holds(legal_hold=False, audit_hold=False, actor="agent-controller")
        retention, referenced = retention.set_references(("handoff-context",), actor="agent-controller")
        with self.assertRaises(ContextRetentionError):
            retention.collect(at=T2, actor="agent-controller")
        retention, released = retention.set_references((), actor="agent-controller")
        retention, collected = retention.collect(at=T2, actor="agent-controller")
        self.assertEqual(retention.status, "COLLECTED")
        self.assertTrue(collected["holds_verified_clear"])
        rebuilt = BlackboardRetention.rebuild(
            (registered, terminal, held, clear, referenced, released, collected)
        )
        self.assertEqual(rebuilt.status, "COLLECTED")

    def test_h10_write_read_log_handoff_redaction_handles_encoding_nesting_fragments_unicode_and_allowlist(self) -> None:
        encoded = base64.b64encode(b"api_key=hidden-value").decode()
        payload = {
            "nested": {"ｐａｓｓｗｏｒｄ": "hidden"},
            "encoded": encoded,
            "fragments": ["sk-", "abcdefgh123456"],
            "email": "person@example.com",
            "safe": "token_budget=1200",
            "allow": "docs@example.com",
        }
        for boundary in ("write", "read", "log", "handoff"):
            result = redact_boundary_value(payload, boundary=boundary, allowlist=("docs@example.com",))
            rendered = str(result.value)
            self.assertNotIn("hidden-value", rendered)
            self.assertNotIn("person@example.com", rendered)
            self.assertNotIn("abcdefgh123456", rendered)
            self.assertIn("docs@example.com", rendered)
            self.assertIn("token_budget=1200", rendered)
            self.assertTrue(result.redacted_paths)
        with self.assertRaises(HandoffContractError):
            contract(objective="api_key=hidden-value").offered_fact(
                contract_object_ref="cas:" + "66" * 32
            )

    def test_h11_controller_agent_tool_candidate_summary_allocations_reclaim_without_ceiling_overrun(self) -> None:
        shared = budget(maximum=100, reserved=40, consumed=10)
        requests = (
            ContextAllocationRequest("controller", 10, 30, 0),
            ContextAllocationRequest("agent", 10, 30, 1),
            ContextAllocationRequest("tool-output", 5, 20, 2),
            ContextAllocationRequest("candidate", 5, 15, 3),
            ContextAllocationRequest("summary", 5, 15, 4),
        )
        first = ContextBudgetAllocator.allocate(shared, requests)
        reclaimed = ContextBudgetAllocator.allocate(shared, requests, reclaimed_tokens=20)
        self.assertLess(first.allocated_tokens, reclaimed.allocated_tokens)
        self.assertLessEqual(first.allocated_tokens, first.ceiling_tokens)
        self.assertLessEqual(reclaimed.allocated_tokens, reclaimed.ceiling_tokens)
        self.assertEqual(reclaimed.ceiling_tokens, 70)

    def test_h12_authorized_paginated_evidence_history_finds_early_context_without_auto_injection(self) -> None:
        entries = tuple(
            ContextHistoryEntry(
                index,
                f"context-{index}",
                f"2026-07-19T12:0{index}:00Z",
                "cas:" + f"{index:02x}" * 32,
                f"{index + 10:02x}" * 32,
                ("cas:" + "71" * 32,) if index == 1 else (),
                ("agent-controller",) if index < 3 else ("agent-private",),
            )
            for index in range(1, 4)
        )
        history = AuthorizedContextHistory(entries)
        first = history.query(actor="agent-controller", limit=1)
        self.assertEqual(first.entries[0].context_id, "context-1")
        self.assertEqual(first.next_position, 1)
        second = history.query(actor="agent-controller", after_position=first.next_position or 0, limit=1)
        self.assertEqual(second.entries[0].context_id, "context-2")
        by_evidence = history.query(
            actor="agent-controller",
            evidence_ref="cas:" + "71" * 32,
        )
        self.assertEqual(tuple(item.context_id for item in by_evidence.entries), ("context-1",))
        self.assertFalse(by_evidence.auto_injected)
        self.assertNotIn("context-3", {item.context_id for item in history.query(actor="agent-controller").entries})


if __name__ == "__main__":
    unittest.main()
