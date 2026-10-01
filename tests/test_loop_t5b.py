from __future__ import annotations

from pathlib import Path

import pytest

from sitina.loop import InputKind, LoopBackend
from sitina.loop.model import TaskConflict
from sitina.security.macos_keychain import MemoryKeychainBackend


def _backend_task(tmp_path: Path):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "facts.txt"
    source.write_text("immutable facts", encoding="utf-8")
    backend = LoopBackend.open(state, keychain_backend=MemoryKeychainBackend())
    backend.admit_task(
        task_id="parent",
        session_id="session",
        task_kind="readonly",
        goal="inspect facts",
        workspace_path=str(workspace),
        provider_profile="fixture",
        environment_ref="environment",
        capability_snapshot_id="capabilities",
        provider_identity="fixture-provider",
        software_identity="fixture-software",
        config_identity="fixture-config",
        submission_id="submission-parent",
    )
    return backend, source


def _admit(backend, source, *, problem_id="facts", objective="read facts"):
    return backend.admit_child_delegation(
        "parent",
        problem_id=problem_id,
        objective=objective,
        sources=({"kind": "file", "path": str(source)},),
    )


def test_t5b_pre_dispatch_recovery_verifies_no_send_and_reuses_identity(tmp_path: Path) -> None:
    backend, source = _backend_task(tmp_path)
    try:
        child = _admit(backend, source)
        recovered = backend.recover_child_delegations("parent")
        projection = recovered.child_delegations[child.delegation_id]
        assert projection["delegation_id"] == child.delegation_id
        # An admitted child with no provider dispatch marker remains
        # resumable under the original delegation identity.  Recovery must
        # not invent a cancellation for work that never had a send boundary.
        assert projection["status"] == "ADMITTED"
        assert not projection["unknown_effect"]
    finally:
        backend.close()


def test_t5b_settled_result_gets_new_applicability_evidence_after_correction(tmp_path: Path) -> None:
    backend, source = _backend_task(tmp_path)
    try:
        child = _admit(backend, source)
        source_id = child.source_manifest[0]["source_id"]

        settled = backend.dispatch_child_delegation(
            "parent",
            child.delegation_id,
            lambda capability: (
                capability.read_source(source_id),
                capability.report(summary="facts", evidence_source_ids=(source_id,))[0]
            )[1],
        )
        assert settled.status == "SETTLED"
        backend.accept_input("parent", input_id="correction", kind=InputKind.CORRECTION, body="new target")
        backend.handle_next_input("parent", affects_goal=True, affects_acceptance=True)
        refreshed = backend.refresh_child_applicability("parent", child.delegation_id)
        assert refreshed.status == "SETTLED"
        assert refreshed.applicability == "LATE_EVIDENCE_ONLY"
        assert refreshed.as_dict().get("applicability") == "LATE_EVIDENCE_ONLY"
        assert any(
            event.event_type == "loop.child-delegation-applicability-updated"
            for event in backend.store.task_events("parent")
        )
    finally:
        backend.close()


def test_t5b_provider_turn_without_child_result_is_recovery_blocked(tmp_path: Path) -> None:
    backend, source = _backend_task(tmp_path)
    try:
        child = _admit(backend, source)
        with backend._state_lock:
            task = backend.get_task("parent")
            backend._append(
                task_id="parent",
                expected_stream_version=task.task_revision,
                request_id=f"test-dispatch:{child.delegation_id}",
                command_type="loop.child-delegation.dispatch-start",
                event_type="loop.child-delegation-dispatch-started",
                payload={
                    "schema": "SITINA_LOOP_CHILD_DELEGATION_DISPATCH_STARTED_V1",
                    "task_id": "parent",
                    "delegation_id": child.delegation_id,
                    "dispatch_epoch": 1,
                    "executor_slot": "readonly-slot-1",
                    "physical_send_state": "NOT_APPLICABLE",
                },
            )

        class Turn:
            text = "model returned"
            tool_calls = ()
            reasoning_content = ""
            metadata = {"physical_send_count": 0}

        backend.execute_child_provider_turn("parent", child.delegation_id, lambda: Turn())
        blocked = backend.recover_child_delegations("parent")
        projection = blocked.child_delegations[child.delegation_id]
        assert projection["status"] == "RECOVERY_BLOCKED"
        assert projection["unknown_effect"] is True
        assert projection["blocker_id"] == "CHILD_RESULT_MISSING_AFTER_DISPATCH"
        assert backend.can_propose_terminal("parent") is False
    finally:
        backend.close()


def test_t5b_cancel_input_wins_before_child_recovery_dispatch(tmp_path: Path) -> None:
    backend, source = _backend_task(tmp_path)
    try:
        child = _admit(backend, source, problem_id="facts", objective="old objective")
        backend.accept_input("parent", input_id="cancel", kind=InputKind.CANCEL, body="stop")
        backend.handle_next_input("parent")
        recovered = backend.recover_child_delegations("parent")
        assert recovered.child_delegations[child.delegation_id]["status"] == "CANCELLED_VERIFIED"
        assert backend.dispatch_child_delegation("parent", child.delegation_id, lambda _capability: {}).status == "CANCELLED_VERIFIED"
    finally:
        backend.close()
