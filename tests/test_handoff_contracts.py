from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts._deepseek_token_canary_harness import canonical, evaluate_evidence_closure, export_evidence, safe_event
from sitina.protocols.handoff_contracts import HandoffContract, HandoffContractError


class HandoffContractTests(unittest.TestCase):
    def contract(self, generation: int = 1) -> HandoffContract:
        return HandoffContract(
            "handoff-a", generation, "agent-source", "agent-target", "task-a", "verify a bounded result",
            ("read-only analysis",), ("handoff-receive",), ("a" * 64,), ("b" * 64,), "c" * 64,
            {"type": "object", "required": ["result"]}, ("result is hash-bound",), ("inputs are current",),
            ("provider uncertainty",), ("none",), 1024, "2026-07-20T00:00:00Z", "d" * 64,
        )

    def test_contract_binds_all_required_fields_and_cas_reference(self) -> None:
        contract = self.contract()
        fact = contract.offered_fact(contract_object_ref="cas:" + "e" * 64)
        self.assertEqual(fact["objective"], contract.objective)
        self.assertEqual(fact["generation"], 1)
        self.assertEqual(fact["_object_refs"], ["cas:" + "e" * 64])
        self.assertEqual(len(fact["contract_hash"]), 64)

    def test_runtime_handoff_task_id_is_not_misclassified_as_secret(self) -> None:
        contract = HandoffContract(
            "handoff-a", 1, "agent-source", "agent-target", "handoff-task-" + "a" * 64,
            "verify a bounded result", ("read-only analysis",), ("handoff-receive",),
            ("a" * 64,), ("b" * 64,), "c" * 64,
            {"type": "object", "required": ["result"]}, ("result is hash-bound",),
            ("inputs are current",), ("provider uncertainty",), ("none",), 1024,
            "2026-07-20T00:00:00Z", "d" * 64,
        )
        fact = contract.offered_fact(contract_object_ref="cas:" + "e" * 64)
        self.assertEqual(fact["task_id"], contract.task_id)

    def test_real_secret_token_still_fails_closed_at_handoff_boundary(self) -> None:
        contract = self.contract()
        unsafe = dataclasses.replace(contract, objective="api_key=hidden-value")
        with self.assertRaises(HandoffContractError):
            unsafe.offered_fact(contract_object_ref="cas:" + "e" * 64)

    def test_canary_evidence_exports_handoff_identity_without_reason_or_model_text(self) -> None:
        event = SimpleNamespace(
            payload={
                "schema": "HANDOFF_REJECTED_GENERATION_CLOSED_V1",
                "event_type": "handoff.rejected",
                "handoff_id": "handoff-a",
                "generation": 2,
                "contract_hash": "a" * 64,
                "semantic_delta_hash": "b" * 64,
                "reason_hash": "c" * 64,
                "reason": "secret provider response must never be exported",
                "model_output": "secret model text",
                "worktree_lifecycle": {
                    "repo": "/unrelated/private/repo",
                    "worktree": "/unrelated/private/worktree",
                    "registration_after_sha256": "d" * 64,
                    "removed": True,
                },
            }
        )
        exported = safe_event(event)
        self.assertEqual(exported["handoff_id"], "handoff-a")
        self.assertEqual(exported["contract_hash"], "a" * 64)
        self.assertEqual(exported["semantic_delta_hash"], "b" * 64)
        self.assertNotIn("reason", exported)
        self.assertNotIn("model_output", exported)
        self.assertNotIn("repo", exported["worktree_lifecycle"])
        self.assertEqual(exported["worktree_lifecycle"]["removed"], True)

    def test_canary_evidence_closure_requires_correlated_streams_and_verified_cas(self) -> None:
        package = {
            "calls": [{"task_id": "handoff-contract-assessment-1"}],
            "handoff_protocol_count": 1,
        }
        package_hash = hashlib.sha256(canonical(package)).hexdigest()
        base_events = [
            SimpleNamespace(
                stream_id="effect/run-a/effect-1", stream_version=1,
                payload={"run_id": "run-a"},
            ),
            SimpleNamespace(
                stream_id="task/handoff-contract-assessment-1", stream_version=1,
                payload={"run_id": "run-a", "task_id": "handoff-contract-assessment-1"},
            ),
            SimpleNamespace(
                stream_id="protocol/run-a/handoff/h-1", stream_version=1,
                payload={
                    "run_id": "run-a", "schema": "HANDOFF_ACCEPTED_V1",
                    "event_type": "handoff.accepted", "handoff_id": "h-1",
                    "generation": 1, "contract_hash": "a" * 64,
                    "selected_proposal_projection_hash": "b" * 64,
                },
            ),
        ]
        receipt = [{"reference_id": "cas:" + "b" * 64,
                    "fresh_verified": True, "no_replace_published": True}]
        complete = evaluate_evidence_closure(
            run_id="run-a", run_result={"provider_call_count": 1, "handoff_protocol_count": 1,
                                         "evidence_package_hash": package_hash},
            evidence_ref="cas:" + "b" * 64, package=package, events=base_events,
            cas_receipts=receipt,
        )
        self.assertTrue(complete["complete"])
        with self.subTest("missing task stream"):
            self.assertFalse(evaluate_evidence_closure(
                run_id="run-a", run_result={"provider_call_count": 1, "handoff_protocol_count": 1,
                                             "evidence_package_hash": package_hash},
                evidence_ref="cas:" + "b" * 64, package=package, events=base_events[:1] + base_events[2:],
                cas_receipts=receipt,
            )["complete"])
        with self.subTest("stream version gap"):
            gap_events = base_events + [SimpleNamespace(
                stream_id="task/handoff-contract-assessment-1", stream_version=3,
                payload={"run_id": "run-a", "task_id": "handoff-contract-assessment-1"},
            )]
            self.assertFalse(evaluate_evidence_closure(
                run_id="run-a", run_result={"provider_call_count": 1, "handoff_protocol_count": 1,
                                             "evidence_package_hash": package_hash},
                evidence_ref="cas:" + "b" * 64, package=package, events=gap_events,
                cas_receipts=receipt,
            )["complete"])
        with self.subTest("cas receipt failure"):
            self.assertFalse(evaluate_evidence_closure(
                run_id="run-a", run_result={"provider_call_count": 1, "handoff_protocol_count": 1,
                                             "evidence_package_hash": package_hash},
                evidence_ref="cas:" + "b" * 64, package=package, events=base_events,
                cas_receipts=[{"verified": False}],
            )["complete"])
        with self.subTest("handoff call without protocol"):
            self.assertFalse(evaluate_evidence_closure(
                run_id="run-a", run_result={"provider_call_count": 1},
                evidence_ref="cas:" + "b" * 64, package=package, events=base_events[:2],
                cas_receipts=receipt,
            )["complete"])

    def test_latest_handoff_generation_must_have_terminal_and_same_chain_predecessor(self) -> None:
        package = {
            "calls": [{"task_id": "handoff-contract-assessment-1"}],
            "handoff_protocol_count": 1,
        }
        package_hash = hashlib.sha256(canonical(package)).hexdigest()
        shared = {
            "run_id": "run-a", "handoff_id": "h-1", "contract_hash": "a" * 64,
        }
        events = [
            SimpleNamespace(event_id="reject-1", stream_id="effect/run-a/effect-1", stream_version=1,
                             payload={"run_id": "run-a"}),
            SimpleNamespace(event_id="task-1", stream_id="task/handoff-contract-assessment-1", stream_version=1,
                             payload={"run_id": "run-a", "task_id": "handoff-contract-assessment-1"}),
            SimpleNamespace(event_id="protocol-1", stream_id="protocol/run-a/handoff/h-1", stream_version=1,
                             payload={**shared, "schema": "HANDOFF_REJECTED_GENERATION_CLOSED_V1",
                                      "event_type": "handoff.rejected", "generation": 1,
                                      "contract_object_ref": "cas:" + "c" * 64,
                                      "selected_proposal_projection_hash": "e" * 64}),
            SimpleNamespace(event_id="offer-2", stream_id="protocol/run-a/handoff/h-1", stream_version=2,
                             payload={**shared, "schema": "HANDOFF_CONTRACT_FROZEN_V1", "generation": 2,
                                      "contract_hash": "b" * 64, "previous_generation_ref": "cas:" + "c" * 64,
                                      "previous_rejection_event_ref": "protocol-1",
                                      "reject_reason_resolution_hash": "d" * 64,
                                      "selected_proposal_projection_hash": "f" * 64}),
        ]
        receipt = [{"reference_id": "cas:" + "b" * 64,
                    "fresh_verified": True, "no_replace_published": True}]
        result = {"provider_call_count": 1, "handoff_protocol_count": 1,
                  "evidence_package_hash": package_hash}
        open_latest = evaluate_evidence_closure(
            run_id="run-a", run_result=result, evidence_ref="cas:" + "b" * 64,
            package=package, events=events, cas_receipts=receipt,
        )
        self.assertFalse(open_latest["complete"])
        self.assertFalse(open_latest["handoff_chains"][0]["latest_generation_has_terminal"])
        events.append(SimpleNamespace(event_id="accepted-2", stream_id="protocol/run-a/handoff/h-1", stream_version=3,
                                      payload={**shared, "schema": "HANDOFF_ACCEPTED_V1",
                                               "event_type": "handoff.accepted", "generation": 2,
                                               "contract_hash": "b" * 64,
                                               "selected_proposal_projection_hash": "f" * 64}))
        closed = evaluate_evidence_closure(
            run_id="run-a", run_result=result, evidence_ref="cas:" + "b" * 64,
            package=package, events=events, cas_receipts=receipt,
        )
        self.assertTrue(closed["complete"])

        broken = list(events)
        broken[3] = SimpleNamespace(event_id="offer-2", stream_id="protocol/run-a/handoff/h-1", stream_version=2,
                                     payload={**shared, "schema": "HANDOFF_CONTRACT_FROZEN_V1", "generation": 2,
                                              "contract_hash": "b" * 64, "previous_generation_ref": "cas:" + "c" * 64,
                                              "previous_rejection_event_ref": "other-handoff-event",
                                              "reject_reason_resolution_hash": "d" * 64,
                                              "selected_proposal_projection_hash": "f" * 64})
        self.assertFalse(evaluate_evidence_closure(
            run_id="run-a", run_result=result, evidence_ref="cas:" + "b" * 64,
            package=package, events=broken, cas_receipts=receipt,
        )["complete"])

    def test_export_renderer_uses_closure_streams_and_fails_closed_on_incomplete_closure(self) -> None:
        run_id = "run-export"
        evidence_ref = "cas:" + "e" * 64
        package = {
            "calls": [{
                "call_id": "call-1", "task_id": "handoff-contract-assessment-1",
                "agent_id": "agent-a", "role": "reviewer", "output_hash": "a" * 64,
                "outcome": "SUCCEEDED", "settlement": "CONFIRMED_REMOTE_OBSERVATION",
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }],
            "handoff_protocol_count": 1,
        }
        package_hash = hashlib.sha256(canonical(package)).hexdigest()
        events = [
            SimpleNamespace(event_id="effect-1", event_type="effect.created", stream_id=f"effect/{run_id}/effect-1",
                             stream_version=1, position=1, event_hash="1" * 64, object_refs=(evidence_ref,),
                             payload={"run_id": run_id}),
            SimpleNamespace(event_id="task-1", event_type="task.accepted", stream_id="task/handoff-contract-assessment-1",
                             stream_version=1, position=2, event_hash="2" * 64, object_refs=(evidence_ref,),
                             payload={"run_id": run_id, "task_id": "handoff-contract-assessment-1"}),
            SimpleNamespace(event_id="protocol-1", event_type="handoff.accepted", stream_id=f"protocol/{run_id}/handoff/h-1",
                             stream_version=1, position=3, event_hash="3" * 64, object_refs=(evidence_ref,),
                             payload={"run_id": run_id, "event_type": "handoff.accepted", "schema": "HANDOFF_ACCEPTED_V1",
                                      "handoff_id": "h-1", "generation": 1, "contract_hash": "a" * 64,
                                      "selected_proposal_projection_hash": "b" * 64}),
        ]
        receipt = SimpleNamespace(
            core_header_hash="c" * 64, envelope_id="d" * 64,
            fresh_verified=True, no_replace_published=True,
        )
        fake_cas = SimpleNamespace(
            resolve_reference=lambda ref: SimpleNamespace(
                reference_id=ref, object_id=ref.removeprefix("cas:"), plaintext_commitment="f" * 64,
            ),
            open_verified=lambda _ref: canonical(package),
            verify_existing=lambda _ref: receipt,
        )
        fake_context = SimpleNamespace(open_cas=lambda: fake_cas, events=events)
        profile = {"status": "verified", "findings": []}
        run_result = {
            "run_id": run_id, "terminal_state": "SUCCEEDED", "accepted": True,
            "provider_call_count": 1, "handoff_protocol_count": 1,
            "evidence_package_ref": evidence_ref, "evidence_package_hash": package_hash,
            "provider_physical_send_count": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_path = root / "artifact.json"
            with patch("scripts._deepseek_token_canary_harness.ProductionRuntimeContext.load", return_value=fake_context), \
                 patch("scripts._deepseek_token_canary_harness.ProfileLoader", return_value=SimpleNamespace(inspect_profile_security=lambda _name: profile)), \
                 patch("scripts._deepseek_token_canary_harness.capture_production_sentinel", return_value={"report_sha256": "0" * 64}), \
                 patch("scripts._deepseek_token_canary_harness.snapshot", side_effect=[{}, {}]):
                artifact = export_evidence(
                    sim=root / "sim", target=root / "target", ops=root / "ops", backend=Mock(),
                    run_result=run_result, before={}, production_before="0" * 64,
                    profile_before=profile, profile_digest="1" * 64, session_id="session-a",
                    bootstrap_metadata={}, artifact_path=artifact_path,
                )
            rendered = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(rendered["evidence_capture_status"], "COMPLETE")
            self.assertEqual(rendered["task_streams_exported"], ["task/handoff-contract-assessment-1"])
            self.assertEqual(rendered["task_streams_exported"], rendered["handoff_lineage"]["closure"]["task_streams_exported"])

            missing_task = [events[0], events[2]]
            fake_context.events = missing_task
            with patch("scripts._deepseek_token_canary_harness.ProductionRuntimeContext.load", return_value=fake_context), \
                 patch("scripts._deepseek_token_canary_harness.ProfileLoader", return_value=SimpleNamespace(inspect_profile_security=lambda _name: profile)), \
                 patch("scripts._deepseek_token_canary_harness.capture_production_sentinel", return_value={"report_sha256": "0" * 64}), \
                 patch("scripts._deepseek_token_canary_harness.snapshot", side_effect=[{}, {}]):
                incomplete = export_evidence(
                    sim=root / "sim", target=root / "target", ops=root / "ops", backend=Mock(),
                    run_result=run_result, before={}, production_before="0" * 64,
                    profile_before=profile, profile_digest="1" * 64, session_id="session-a",
                    bootstrap_metadata={}, artifact_path=root / "incomplete.json",
                )
            self.assertEqual(json.loads(incomplete.read_text(encoding="utf-8"))["evidence_capture_status"], "INCOMPLETE")

    def test_input_hashes_must_be_bare_64_hex_not_sha256_prefixed(self) -> None:
        # Regression: the runtime's sha256_bytes() yields a "sha256:"-prefixed
        # 71-char hash; _handoff must strip it before it enters input_hashes,
        # symmetric with the cas: strip on input_refs. A prefixed hash must fail.
        prefixed = "sha256:" + "a" * 64  # 71 chars, as sha256_bytes returns
        with self.assertRaises(HandoffContractError):
            HandoffContract(
                "handoff-a", 1, "agent-source", "agent-target", "task-a", "verify a bounded result",
                ("read-only analysis",), ("handoff-receive",), ("a" * 64,), (prefixed, "b" * 64), "c" * 64,
                {"type": "object", "required": ["result"]}, ("result is hash-bound",), ("inputs are current",),
                ("provider uncertainty",), ("none",), 1024, "2026-07-20T00:00:00Z", "d" * 64,
            )
        # The stripped form (what the fix produces) is accepted.
        stripped = prefixed.removeprefix("sha256:")
        ok = HandoffContract(
            "handoff-a", 1, "agent-source", "agent-target", "task-a", "verify a bounded result",
            ("read-only analysis",), ("handoff-receive",), ("a" * 64,), (stripped, "b" * 64), "c" * 64,
            {"type": "object", "required": ["result"]}, ("result is hash-bound",), ("inputs are current",),
            ("provider uncertainty",), ("none",), 1024, "2026-07-20T00:00:00Z", "d" * 64,
        )
        self.assertEqual(len(ok.input_hashes[0]), 64)

    def test_contract_rejects_missing_acceptance_scope_or_non_cas_object(self) -> None:
        value = self.contract()
        with self.assertRaises(HandoffContractError):
            value.offered_fact(contract_object_ref="e" * 64)
        with self.assertRaises(HandoffContractError):
            HandoffContract(
                value.handoff_id, value.generation, value.sender_id, value.receiver_id, value.task_id, value.objective, (),
                value.required_capabilities, value.input_refs, value.input_hashes, value.current_state_ref,
                value.output_schema, value.acceptance_criteria, value.assumptions, value.residual_risks,
                value.open_questions, value.budget_tokens, value.deadline, value.policy_hash,
            )

    def test_generation_two_binds_rejection_lineage_resolution_refrozen_input_and_fence(self) -> None:
        first = self.contract()
        second = HandoffContract(
            "handoff-a", 2, "agent-source", "agent-target", "task-a", "verify a corrected bounded result",
            ("read-only analysis",), ("handoff-receive",), ("e" * 64,),
            ("f" * 64, "1" * 64), "2" * 64,
            {"type": "object", "required": ["result"]}, ("result is hash-bound",),
            ("inputs are current",), ("provider uncertainty",), (), 900,
            "2026-07-20T00:00:00Z", "3" * 64,
            previous_generation_ref="cas:" + "4" * 64,
            previous_rejection_event_ref="event-rejection-generation-1",
            reject_reason_resolution_map={"missing exact checks": "added exact checks and output schema"},
            blackboard_version_refs=("document-a@2:" + "5" * 64,),
            task_claim_ref="6" * 64, fencing_token="7" * 64, max_generations=3,
        )
        mapping = second.mapping()
        self.assertEqual(mapping["from_agent"], "agent-source")
        self.assertEqual(mapping["to_agent"], "agent-target")
        self.assertEqual(mapping["generation"], 2)
        self.assertEqual(mapping["task_id"], "task-a")
        self.assertEqual(mapping["previous_generation_ref"], "cas:" + "4" * 64)
        self.assertNotEqual(mapping["input_freeze_hash"], first.input_freeze_hash)
        self.assertEqual(mapping["fencing_token"], "7" * 64)


if __name__ == "__main__":
    unittest.main()
