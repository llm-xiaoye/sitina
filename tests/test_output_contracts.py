import unittest

from sitina.orchestrator.output_contracts import (
    OutputContractError,
    is_critical_contract_task,
    resolve_output_contract,
    validate_output_contract,
)
from sitina.orchestrator.true_multi_agent_runtime import ProviderExecutor, TrueMultiAgentRuntimeError, structured_response_tools
from sitina.runners.provider import provider_tools_for_wire


class OutputContractTests(unittest.TestCase):
    def test_discovery_and_candidate_are_distinct_wire_contracts(self) -> None:
        fast = resolve_output_contract("conversation-answer", "conversation_answer")
        self.assertEqual(fast.task_type, "conversation_answer")
        discovery = resolve_output_contract("goal-discovery", "proposal")
        candidate = resolve_output_contract("proposal-1", "proposal")
        self.assertNotEqual(discovery.output_contract_id, candidate.output_contract_id)
        for protocol in ("openai_chat_completions", "anthropic_messages"):
            wire = provider_tools_for_wire(structured_response_tools(discovery), protocol)
            if protocol == "openai_chat_completions":
                self.assertEqual(wire[0]["function"]["name"], "sitina_structured_response")
                schema = wire[0]["function"]["parameters"]
            else:
                self.assertEqual(wire[0]["name"], "sitina_structured_response")
                schema = wire[0]["input_schema"]
            self.assertEqual(set(discovery.required), set(schema["required"]))

    def test_recursive_bounds_and_types_are_shared_with_wire_shape(self) -> None:
        spec = resolve_output_contract("proposal-1", "proposal")
        valid = {"agent_id": "agent", "kind": "proposal", "summary": "x", "approach": "y",
                 "risks": ["bounded"], "assumptions": ["bounded"], "acceptance_checks": ["check"]}
        validate_output_contract(valid, spec)
        for invalid in (
            {**valid, "summary": ""},
            {**valid, "risks": [1]},
            {**valid, "acceptance_checks": ["x"] * 13},
        ):
            with self.assertRaises(OutputContractError):
                validate_output_contract(invalid, spec)
        replan = resolve_output_contract("execution-replan-1", "replan")
        base_replan = {"agent_id": "agent", "kind": "replan", "approach": "repair"}
        for invalid in (
            {**base_replan, "acceptance_checks": []},
            {**base_replan, "acceptance_checks": [1]},
            {**base_replan, "acceptance_checks": ["check"] * 9},
        ):
            with self.assertRaises(OutputContractError):
                validate_output_contract(invalid, replan)

    def test_unknown_identity_and_missing_critical_identity_fail_closed(self) -> None:
        self.assertTrue(is_critical_contract_task("execution-replan-1"))
        with self.assertRaises(OutputContractError):
            resolve_output_contract(
                "goal-discovery", "proposal", output_contract_id="typo", task_type="goal_discovery", schema_id="typo"
            )
        with self.assertRaises(OutputContractError):
            resolve_output_contract("unbound-task", "proposal")
        with self.assertRaises(TrueMultiAgentRuntimeError):
            ProviderExecutor.call(
                object(), agent=object(), task_id="goal-discovery", kind="proposal",
                system_prompt="", user_prompt="", input_context={}, validate=lambda value: None,
            )

    def test_readonly_claim_contract_has_identical_wire_and_local_bounds(self) -> None:
        answer = resolve_output_contract("readonly-answer-1", "readonly_answer")
        review = resolve_output_contract("readonly-review-1", "readonly_review")
        answer_value = {
            "agent_id": "agent", "kind": "readonly_answer", "claim_id": "claim-1",
            "evidence_hash": "a" * 64, "answer_fragment": "READ_ONLY_MARKER",
        }
        validate_output_contract(answer_value, answer)
        for protocol in ("openai_chat_completions", "anthropic_messages"):
            wire = provider_tools_for_wire(structured_response_tools(answer), protocol)
            schema = wire[0]["function"]["parameters"] if protocol == "openai_chat_completions" else wire[0]["input_schema"]
            self.assertEqual(set(schema["required"]), set(answer.required))
        review_value = {
            "agent_id": "agent", "kind": "readonly_review", "verdict": "approved",
            "score": 90, "reason": "verified", "defects": [], "verified_claim_ids": ["claim-1"],
        }
        validate_output_contract(review_value, review)
        for invalid in (
            {**answer_value, "answer_fragment": ""},
            {**review_value, "verified_claim_ids": [1]},
            {**review_value, "defects": ["x"] * 9},
        ):
            with self.assertRaises(OutputContractError):
                validate_output_contract(invalid, answer if "answer_fragment" in invalid else review)


if __name__ == "__main__":
    unittest.main()
