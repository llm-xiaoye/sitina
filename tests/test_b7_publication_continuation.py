from __future__ import annotations

from pathlib import Path

import pytest

from sitina.extensions.tools import ToolCatalog
from sitina.loop import InputKind, LoopBackend
from sitina.loop.model import OperationRejected
from sitina.loop.task_runtime import LoopOperationAdapter
from sitina.loop.termination import AttemptPlan
from sitina.runners.provider import ProviderToolCall

from test_extensions_batch_4c import _prepare, _task_binding


_LINEAGE = "lineage:1:main-investigation:outcome-1"
_BLOCKER = "main-investigation:outcome-1"


def _plan(backend: LoopBackend, attempt_id: str, prior_attempt_id: str | None = None):
    task = backend.get_task("publisher")
    return backend.plan_attempt(
        "publisher",
        AttemptPlan(
            attempt_id=attempt_id,
            lineage_id=_LINEAGE,
            acceptance_item_id="outcome-1",
            blocker_id=_BLOCKER,
            blocker_source=task.goal_ref,
            question_or_hypothesis="Advance the current outcome using a finite evidence/action investigation.",
            max_control_segments=8,
            max_provider_responses=8,
            max_tool_call_groups=8,
            allowed_action_kinds=("provider-response", "tool-call-group"),
            exit_conditions=(
                "investigation scope completed",
                "local control-segment scope exhausted",
            ),
            prior_attempt_id=prior_attempt_id,
        ),
    )


def _run_skill_trial(
    backend: LoopBackend,
    manager,
    snapshot,
    workspace: Path,
    attempt_id: str,
):
    workspace.mkdir(parents=True, exist_ok=True)
    catalog = ToolCatalog(manager, workspace=workspace)
    catalog.bind_execution_snapshot(snapshot)
    adapter = LoopOperationAdapter(
        backend,
        "publisher",
        workspace,
        mutation_allowed=False,
        business_attempt_id=attempt_id,
    )
    call = ProviderToolCall(
        "read-resource",
        "sitina_read_skill_resource",
        {"skill": "count-fruit", "path": "references/facts.md"},
    )
    catalog.bind_loop_consumer(
        backend=backend,
        task_id="publisher",
        snapshot_id=snapshot["snapshot_id"],
        call_id=call.call_id,
    )
    try:
        adapter.tool_call(
            "prior-run",
            call,
            lambda: catalog.execute(call.name, call.arguments),
            permission="read",
            method_plan=catalog.consumer_method_plan(
                call.name,
                call.arguments,
                task_id="publisher",
                call_id=call.call_id,
            ),
        )
    finally:
        catalog.clear_loop_consumer()
    task = backend.get_task("publisher")
    operation_id = adapter.operation_ids[0]
    operation = task.operations[operation_id]
    persisted = dict(backend.context_memory.read(str(operation.result_ref)))
    raw_result = dict(persisted["result"])
    binding = dict(raw_result["execution_binding"])
    return task, operation_id, raw_result, binding


def _prepare_continuation(
    tmp_path: Path,
    *,
    settlement_outcome: str = "LOCAL_SCOPE_YIELD",
    continuation_depth: int = 1,
):
    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    source = _task_binding(backend.get_task("publisher"))
    source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
    intent = authority.record_publication_intent(
        request_id="publish-continuation-1",
        slot="skill:count-fruit",
        candidate_id=prepared.candidate_id,
        snapshot=snapshot,
        source=source,
    )
    prior_id = "attempt-prior"
    _plan(backend, prior_id)
    task, operation_id, raw_result, binding = _run_skill_trial(
        backend, manager, snapshot, tmp_path / "workspace", prior_id
    )
    backend.settle_attempt(
        "publisher",
        attempt_id=prior_id,
        blocker_id=_BLOCKER,
        outcome=settlement_outcome,
        relevant_progress=False,
        evidence_refs=(),
        progress_basis={"relevant_progress": False},
        count_effect="NO_PROGRESS",
        progress_decision={"relevant_progress": False},
    )
    parent_id = prior_id
    for index in range(continuation_depth - 1):
        intermediate_id = f"attempt-intermediate-{index}"
        _plan(backend, intermediate_id, parent_id)
        backend.settle_attempt(
            "publisher",
            attempt_id=intermediate_id,
            blocker_id=_BLOCKER,
            outcome="LOCAL_SCOPE_YIELD",
            relevant_progress=False,
            evidence_refs=(),
            progress_basis={"relevant_progress": False},
            count_effect="NO_PROGRESS",
            progress_decision={"relevant_progress": False},
        )
        parent_id = intermediate_id
    current_id = "attempt-current"
    _plan(backend, current_id, parent_id)
    return backend, manager, authority, prepared, snapshot, intent, current_id, operation_id, raw_result, binding


def test_publication_trial_may_cross_one_local_scope_yield(tmp_path: Path) -> None:
    (
        backend,
        manager,
        authority,
        prepared,
        snapshot,
        intent,
        current_id,
        operation_id,
        raw_result,
        binding,
    ) = _prepare_continuation(tmp_path)
    try:
        decision = backend.execute_extension_publication_tool(
            "publisher",
            slot_id="skill:count-fruit",
            candidate_id=prepared.candidate_id,
            trial_operation_id=operation_id,
            request_id="publish-continuation-1",
            run_id="run-continuation",
            call_id="call-continuation",
            business_attempt_id=current_id,
            publication_context={
                "request_id": "publish-continuation-1",
                "slot_id": "skill:count-fruit",
                "candidate_id": prepared.candidate_id,
            },
        )
        assert decision["publication_id"].startswith("publication-")
        task = backend.get_task("publisher")
        assert task.operations[operation_id].business_attempt_id == "attempt-prior"
        publication_operation = task.operations[backend.extension_publication_operation_id("publish-continuation-1")]
        assert publication_operation.business_attempt_id == current_id
        events = tuple(authority._journal_events())
        assert sum(event.event_type == "extension.trial-recorded" for event in events) == 1
        assert sum(event.event_type == "extension.publication-committed" for event in events) == 1
    finally:
        backend.close()


def test_publication_trial_may_cross_multiple_local_scope_yields(tmp_path: Path) -> None:
    (
        backend,
        manager,
        authority,
        prepared,
        snapshot,
        intent,
        current_id,
        operation_id,
        raw_result,
        binding,
    ) = _prepare_continuation(tmp_path, continuation_depth=3)
    try:
        decision = backend.execute_extension_publication_tool(
            "publisher",
            slot_id="skill:count-fruit",
            candidate_id=prepared.candidate_id,
            trial_operation_id=operation_id,
            request_id="publish-continuation-1",
            run_id="run-continuation-multi",
            call_id="call-continuation-multi",
            business_attempt_id=current_id,
        )
        assert decision["publication_id"].startswith("publication-")
        task = backend.get_task("publisher")
        publication_operation = task.operations[backend.extension_publication_operation_id("publish-continuation-1")]
        assert publication_operation.business_attempt_id == current_id
        assert task.operations[operation_id].business_attempt_id == "attempt-prior"
    finally:
        backend.close()


def test_publication_trial_rejects_unrelated_current_attempt(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot, intent, current_id, operation_id, raw_result, binding = _prepare_continuation(tmp_path)
    try:
        with pytest.raises(OperationRejected, match="lineage|continuation|persisted"):
            backend.execute_extension_publication_tool(
                "publisher",
                slot_id="skill:count-fruit",
                candidate_id=prepared.candidate_id,
                trial_operation_id=operation_id,
                request_id="publish-continuation-1",
                run_id="run-unrelated",
                call_id="call-unrelated",
                business_attempt_id="attempt-unrelated",
            )
        assert not any(
            event.event_type == "extension.publication-committed"
            for event in authority._journal_events()
        )
    finally:
        backend.close()


def test_publication_trial_rejects_non_yield_settlement(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot, intent, current_id, operation_id, raw_result, binding = _prepare_continuation(
        tmp_path,
        settlement_outcome="CONFIRMED_REPEAT",
    )
    try:
        with pytest.raises(OperationRejected, match="LOCAL_SCOPE_YIELD"):
            backend.execute_extension_publication_tool(
                "publisher",
                slot_id="skill:count-fruit",
                candidate_id=prepared.candidate_id,
                trial_operation_id=operation_id,
                request_id="publish-continuation-1",
                run_id="run-non-yield",
                call_id="call-non-yield",
                business_attempt_id=current_id,
            )
        assert not any(
            event.event_type == "extension.publication-committed"
            for event in authority._journal_events()
        )
    finally:
        backend.close()
