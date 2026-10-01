from __future__ import annotations

import copy
import json

import pytest

from sitina.loop.termination import (
    CHILD_CONTRACT_SCHEMA,
    REVIEW_SCHEMA_V2,
    TERMINATION_CONTRACT_VERSION,
    ReviewProtocolError,
    child_delegation_id,
    review_rule_manifest,
    review_subject_lineage,
    validate_child_contract,
    validate_child_result,
    validate_parent_child_settlement,
    validate_review_document,
)


def child_contract(*, generation: int = 1, prior_id: str | None = None) -> dict:
    scope = {
        "max_control_segments": 3,
        "allowed_action_kinds": ["READ", "ANALYZE", "REPORT"],
        "allowed_source_refs": ["history:goal"],
        "exit_conditions": ["answer produced", "parent control changed"],
    }
    binding = {
        "task_id": "parent-task",
        "attempt_id": "parent-attempt",
        "run_instance_id": "run-1",
        "execution_epoch": 1,
        "goal_version": 2,
        "acceptance_version": 3,
        "criteria_lineage_version": 2,
        "handled_input_seq": 4,
        "artifact_ref": "cas:artifact",
        "parent_scope_lineage_id": "scope:parent:1",
        "control_intent": "RUN",
    }
    delegation_id = child_delegation_id(
        parent_task_id=binding["task_id"],
        parent_scope_lineage_id=binding["parent_scope_lineage_id"],
        stable_problem_id="problem:read-only-analysis",
        scope=scope,
        generation=generation,
    )
    return {
        "schema": CHILD_CONTRACT_SCHEMA,
        "termination_contract_version": TERMINATION_CONTRACT_VERSION,
        "contract_only": True,
        "runtime_wiring": False,
        "delegation_id": delegation_id,
        "parent_binding": binding,
        "lineage": {
            "stable_problem_id": "problem:read-only-analysis",
            "generation": generation,
            "prior_delegation_id": prior_id,
            "depth": 1,
            "max_depth": 2,
            "inherited_evidence_refs": [],
            "inherited_attempt_ids": [],
            "inherited_review_issue_ids": [],
        },
        "objective": "Inspect the bound evidence",
        "question_or_hypothesis": "Does the evidence support the hypothesis?",
        "scope": scope,
        "ownership": {
            "owner_id": "child-owner-1",
            "exclusive_problem_owner": True,
            "owned_resource_ids": [],
        },
        "acceptance": {
            "required_outcome_ids": ["analysis-result"],
            "required_evidence_kinds": ["source-citation"],
            "completion_condition": "return one evidence-bound analysis result",
        },
        "result_contract": {
            "schema": "SITINA_LOOP_CHILD_RESULT_V1",
            "required_fields": ["result_refs", "settlement_status"],
            "return_to_parent_task_id": "parent-task",
        },
        "dependency_ids": [],
        "cancellation": {
            "policy": "RETURN_AT_CHECKPOINT",
            "stop_new_dispatch_on_parent_change": True,
            "late_result_policy": "EVIDENCE_ONLY",
        },
        "reconciliation": {
            "parent_validates": True,
            "child_may_approve_parent": False,
            "binding_mismatch_policy": "LATE_EVIDENCE_ONLY",
        },
        "lifecycle": {
            "required_before_parent_terminal": "SETTLED_CANCELLED_VERIFIED_OR_HANDED_OFF",
            "handoff_requires_receipt": True,
            "unknown_effect_blocks_parent_terminal": True,
        },
    }


def test_child_contract_is_read_only_and_explicitly_contract_only() -> None:
    value = child_contract()
    assert validate_child_contract(value) == value
    elevated = copy.deepcopy(value)
    elevated["scope"]["allowed_action_kinds"] = ["WRITE"]
    elevated["delegation_id"] = child_delegation_id(
        parent_task_id="parent-task",
        parent_scope_lineage_id="scope:parent:1",
        stable_problem_id="problem:read-only-analysis",
        scope=elevated["scope"],
        generation=1,
    )
    with pytest.raises(ValueError, match="write or side-effect"):
        validate_child_contract(elevated)


def test_repeat_delegation_inherits_lineage_without_inventing_nonexistent_history() -> None:
    first = child_contract()
    validate_child_contract(first)
    second = child_contract(generation=2, prior_id=first["delegation_id"])
    assert validate_child_contract(second, prior_contracts=(first,)) == second
    reset = child_contract()
    with pytest.raises(ValueError, match="first delegation generation"):
        validate_child_contract(reset, prior_contracts=(first,))


def test_child_depth_and_transitive_dependency_cycles_use_trusted_context() -> None:
    value = child_contract()
    with pytest.raises(ValueError, match="depth"):
        validate_child_contract(value, parent_depth=1, trusted_max_depth=2)
    value["dependency_ids"] = ["delegation:B"]
    siblings = (
        {"delegation_id": "delegation:B", "lineage": {"stable_problem_id": "B", "generation": 1},
         "dependency_ids": ["delegation:C"]},
        {"delegation_id": "delegation:C", "lineage": {"stable_problem_id": "C", "generation": 1},
         "dependency_ids": [value["delegation_id"]]},
    )
    with pytest.raises(ValueError, match="cycle"):
        validate_child_contract(value, sibling_contracts=siblings)


def test_late_child_result_is_evidence_only_and_parent_join_is_strict() -> None:
    contract = child_contract()
    validate_child_contract(contract)
    result = {
        "schema": "SITINA_LOOP_CHILD_RESULT_V1",
        "delegation_id": contract["delegation_id"],
        "parent_binding": contract["parent_binding"],
        "result_refs": ["cas:result"],
        "settlement_status": "SETTLED",
        "approves_parent": False,
    }
    current = dict(contract["parent_binding"])
    current["handled_input_seq"] += 1
    assert validate_child_result(contract, result, current_parent_binding=current)["applicability"] == "LATE_EVIDENCE_ONLY"
    with pytest.raises(ValueError, match="booleans"):
        validate_parent_child_settlement(({
            "delegation_id": contract["delegation_id"], "required": 1, "status": "RUNNING",
            "unknown_effect": 0, "handoff_receipt_ref": None,
        },))
    assert validate_parent_child_settlement(({
        "delegation_id": contract["delegation_id"], "required": True, "status": "HANDED_OFF",
        "unknown_effect": False, "handoff_receipt_ref": "cas:handoff",
    },)) == (contract["delegation_id"],)


def test_two_host_slotted_review_issues_coexist_and_old_open_id_cannot_be_omitted() -> None:
    rules = review_rule_manifest("outcome-1", program_method_id=None, object_ids=("a.py", "b.py"))
    subject = review_subject_lineage("task-review", "outcome-1")
    rule = rules[0]
    evidence = "history:evidence"
    findings = [
        {
            "stable_issue_id": None,
            "issue_slot_id": rule["issue_slot_ids"][index],
            "rule_id": rule["rule_id"],
            "locus_id": rule["locus_id"],
            "object_id": object_id,
            "finding_code": rule["allowed_finding_codes"][0],
            "disposition": "OPEN",
            "evidence_refs": [evidence],
            "summary": f"independent issue in {object_id}",
        }
        for index, object_id in enumerate(("a.py", "b.py"))
    ]
    document = {
        "schema": REVIEW_SCHEMA_V2,
        "termination_contract_version": TERMINATION_CONTRACT_VERSION,
        "acceptance_item_id": "outcome-1",
        "review_subject_lineage": subject,
        "observed_artifact_ref": "cas:artifact-1",
        "verdict": "BLOCK",
        "reason": "two independent issues",
        "findings": findings,
    }
    for mutation, expected_missing, expected_unexpected in (
        ("missing_id", ["stable_issue_id"], []),
        ("extra_field", [], ["extra"]),
    ):
        malformed = copy.deepcopy(document)
        if mutation == "missing_id":
            del malformed["findings"][0]["stable_issue_id"]
        else:
            malformed["findings"][0]["extra"] = "not in the response contract"
        with pytest.raises(ReviewProtocolError) as error:
            validate_review_document(
                malformed,
                acceptance_item_id="outcome-1",
                review_subject_lineage_id=subject,
                observed_artifact_ref="cas:artifact-1",
                criteria_lineage_id="criteria:task-review:1",
                rules=rules,
                queried_source_refs=(evidence,),
                unresolved_issues={},
            )
        assert error.value.kind == "FORMAT_INVALID"
        assert str(error.value) == (
            "review finding fields are not exact: missing="
            + json.dumps(expected_missing) + "; unexpected=" + json.dumps(expected_unexpected)
        )
        # Diagnostics must not repair or discard model fields behind its back.
        assert ("stable_issue_id" in malformed["findings"][0]) == (mutation != "missing_id")
        assert ("extra" in malformed["findings"][0]) == (mutation == "extra_field")

    canonical = validate_review_document(
        document,
        acceptance_item_id="outcome-1",
        review_subject_lineage_id=subject,
        observed_artifact_ref="cas:artifact-1",
        criteria_lineage_id="criteria:task-review:1",
        rules=rules,
        queried_source_refs=(evidence,),
        unresolved_issues={},
        source_facts={evidence: {"kind": "artifact", "semantic_fingerprint": "fact-1",
                                "relevant_object_ids": ["a.py", "b.py"], "resolution_eligible": False}},
        object_fingerprints={"a.py": "a1", "b.py": "b1"},
    )
    assert len({item["stable_issue_id"] for item in canonical["findings"]}) == 2
    inventory = {
        item["stable_issue_id"]: {**item, "status": "OPEN", "disagreement_count": 1}
        for item in canonical["findings"]
    }
    renamed = copy.deepcopy(document)
    renamed["findings"] = [copy.deepcopy(findings[1])]
    renamed["findings"][0]["stable_issue_id"] = canonical["findings"][1]["stable_issue_id"]
    with pytest.raises(ReviewProtocolError, match="omitted unresolved issue"):
        validate_review_document(
            renamed,
            acceptance_item_id="outcome-1",
            review_subject_lineage_id=subject,
            observed_artifact_ref="cas:artifact-1",
            criteria_lineage_id="criteria:task-review:1",
            rules=rules,
            queried_source_refs=(evidence,),
            unresolved_issues=inventory,
            source_facts={evidence: {"kind": "artifact", "semantic_fingerprint": "fact-1",
                                    "relevant_object_ids": ["a.py", "b.py"], "resolution_eligible": False}},
            object_fingerprints={"a.py": "a1", "b.py": "b1"},
        )


def test_review_issue_slots_page_forward_without_reusing_historical_slots() -> None:
    first = review_rule_manifest("outcome-1", program_method_id=None, issue_slots_per_rule=2)
    rule_id = first[0]["rule_id"]
    second = review_rule_manifest(
        "outcome-1",
        program_method_id=None,
        issue_slots_per_rule=2,
        registered_issue_slots={rule_id: first[0]["issue_slot_ids"]},
    )
    assert second[0]["issue_slot_ids"][:2] == first[0]["issue_slot_ids"]
    assert len(set(second[0]["issue_slot_ids"])) == 4
