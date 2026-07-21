from __future__ import annotations

import unittest

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
