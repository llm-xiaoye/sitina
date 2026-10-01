from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from sitina.loop import EffectStatus, LoopBackend, OperationMode, OperationOutcome
from sitina.loop.model import OperationRejected, TaskConflict
from sitina.loop.termination import (
    COUNT_NO_PROGRESS,
    AttemptPlan,
    action_observations,
    structured_progress_decision,
)
from sitina.security.macos_keychain import MemoryKeychainBackend

from test_loop_batch_1a import create_task, operation_intent


def attempt_plan(attempt_id: str = "attempt-1") -> AttemptPlan:
    return AttemptPlan(
        attempt_id=attempt_id,
        lineage_id="lineage:goal-1:stable-blocker",
        acceptance_item_id="outcome-1",
        blocker_id="stable-blocker",
        blocker_source="goal-source",
        question_or_hypothesis="Read the bound source and identify a new relevant fact.",
        max_control_segments=4,
        max_provider_responses=4,
        max_tool_call_groups=4,
        allowed_action_kinds=("read",),
        exit_conditions=("new-fact", "confirmed-repeat", "scope-exhausted"),
        relevant_object_ids=("/workspace/source.txt",),
    )


def test_plan_checkpoint_operation_and_settlement_survive_cold_replay(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    state = tmp_path / "state"
    with LoopBackend.open(state, keychain_backend=keys) as backend:
        create_task(backend, "task-cold")
        backend.plan_attempt("task-cold", attempt_plan())
        intent = replace(
            operation_intent(backend, "task-cold", "read-1", mode=OperationMode.READ),
            business_attempt_id="attempt-1",
        )
        backend.execute_operation(
            "task-cold",
            intent,
            lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"content_hash": "stable"}),
        )
        operation_ref = backend.get_task("task-cold").operations["read-1"].result_ref
        assert operation_ref is not None
        backend.checkpoint_attempt(
            "task-cold",
            checkpoint_id="checkpoint-1",
            attempt_id="attempt-1",
            reason="SEGMENT_COMPLETED",
            operation_refs=(operation_ref,),
            evidence_refs=(operation_ref,),
            action_observations=({"progress_eligible": True, "fingerprint": "fact-1"},),
            segment_index=1,
            scope_consumed={
                "control_segments": 1,
                "provider_responses": 1,
                "tool_call_groups": 1,
            },
        )
        hot = backend.settle_attempt(
            "task-cold",
            attempt_id="attempt-1",
            blocker_id="stable-blocker",
            outcome="scope completed without another fact",
            relevant_progress=False,
            evidence_refs=(operation_ref,),
            count_effect=COUNT_NO_PROGRESS,
        )

    with LoopBackend.open(state, keychain_backend=keys) as reopened:
        cold = reopened.get_task("task-cold")
        assert cold.attempt_plans == hot.attempt_plans
        assert cold.attempt_checkpoints == hot.attempt_checkpoints
        assert cold.attempt_settlements == hot.attempt_settlements
        assert cold.operations["read-1"].business_attempt_id == "attempt-1"


def test_business_operation_requires_the_named_open_plan(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend()) as backend:
        create_task(backend, "task-plan-first")
        missing = replace(
            operation_intent(backend, "task-plan-first", "read-1", mode=OperationMode.READ),
            business_attempt_id="not-planned",
        )
        with pytest.raises(OperationRejected, match="committed attempt plan"):
            backend.execute_operation(
                "task-plan-first",
                missing,
                lambda: OperationOutcome(EffectStatus.SUCCEEDED, {}),
            )

        backend.plan_attempt("task-plan-first", attempt_plan())
        backend.settle_attempt(
            "task-plan-first",
            attempt_id="attempt-1",
            blocker_id="stable-blocker",
            outcome="no progress",
            relevant_progress=False,
            evidence_refs=(),
            count_effect=COUNT_NO_PROGRESS,
        )
        closed = replace(
            operation_intent(backend, "task-plan-first", "read-2", mode=OperationMode.READ),
            business_attempt_id="attempt-1",
        )
        with pytest.raises(OperationRejected, match="already settled"):
            backend.execute_operation(
                "task-plan-first",
                closed,
                lambda: OperationOutcome(EffectStatus.SUCCEEDED, {}),
            )


def test_action_fingerprint_ignores_transport_envelope_but_not_content() -> None:
    common = {
        "name": "sitina_read_file",
        "arguments": {"path": "source.txt"},
        "status": "ok",
        "result": "same semantic content",
    }
    first = action_observations(
        ({**common, "call_id": "wire-1", "completed_at": "2026-01-01T00:00:00Z"},),
        relevant_object_ids=("/workspace/source.txt",),
        object_base="/workspace",
    )[0]
    second = action_observations(
        ({**common, "call_id": "wire-2", "completed_at": "2027-01-01T00:00:00Z"},),
        relevant_object_ids=("/workspace/source.txt",),
        object_base="/workspace",
    )[0]
    changed = action_observations(
        ({**common, "result": "new semantic content"},),
        relevant_object_ids=("/workspace/source.txt",),
        object_base="/workspace",
    )[0]
    unknown = action_observations(
        ({"name": "plugin_unknown", "status": "ok", "result": {"receipt": "new"}},),
    )[0]
    self_generated = action_observations(
        (common,),
        relevant_object_ids=("/workspace/source.txt",),
        self_modified_object_ids=("/workspace/source.txt",),
        object_base="/workspace",
    )[0]

    assert first["progress_eligible"] is True
    assert first["fingerprint"] == second["fingerprint"]
    assert changed["fingerprint"] != first["fingerprint"]
    assert unknown["progress_eligible"] is False
    assert self_generated["progress_eligible"] is False
    assert self_generated["ineligible_reason"] == (
        "self_generated_object_requires_independent_verification"
    )


def check_progress(satisfied: tuple[str, ...], remaining: tuple[str, ...]) -> dict[str, object]:
    return {
        "schema": "SITINA_LOOP_CHECK_PROGRESS_V1",
        "satisfied": list(satisfied),
        "remaining": list(remaining),
    }


def test_progress_uses_historical_facts_and_rejects_renamed_universes() -> None:
    a = check_progress(("A",), ("B", "C"))
    ab = check_progress(("A", "B"), ("C",))
    renamed = check_progress(("A", "renamed-B"), ("C",))

    first_ab = structured_progress_decision((a,), ab)
    second_ab = structured_progress_decision((a, ab, a), ab)
    incompatible = structured_progress_decision((a, ab), renamed)

    assert first_ab["relevant_progress"] is True
    assert second_ab["relevant_progress"] is False
    assert second_ab["recovered_prior_state"] is True
    assert second_ab["oscillation_detected"] is True
    assert incompatible["compatible"] is False
    assert incompatible["relevant_progress"] is False
    assert incompatible["incompatible_history"] is True


def test_only_one_open_plan_is_allowed(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend()) as backend:
        create_task(backend, "task-open")
        backend.plan_attempt("task-open", attempt_plan())
        with pytest.raises(TaskConflict, match="remains open"):
            backend.plan_attempt("task-open", attempt_plan("attempt-2"))
