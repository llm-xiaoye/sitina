from __future__ import annotations

from pathlib import Path

import pytest

from sitina.loop import (
    EffectStatus,
    InputKind,
    LoopBackend,
    OperationIntent,
    OperationMode,
    OperationOutcome,
    RecoveryPolicy,
    TaskStatus,
)
from sitina.loop.control import authority_socket_path
from sitina.loop.model import TaskConflict
from sitina.security.macos_keychain import MemoryKeychainBackend


def _task(backend: LoopBackend, task_id: str = "owner"):
    return backend.create_task(
        task_id=task_id,
        session_id=task_id,
        task_kind="code_change",
        goal="handoff a verified workspace",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact",
        environment_ref="environment",
        capability_snapshot_id="capabilities",
    )


def _write_intent(backend: LoopBackend, task_id: str, operation_id: str, resource: Path) -> OperationIntent:
    task = backend.get_task(task_id)
    return OperationIntent(
        operation_id=operation_id,
        logical_operation_id=f"logical-{operation_id}",
        attempt_id=f"attempt-{operation_id}",
        mode=OperationMode.WRITE,
        description="verified handoff fixture",
        resources=(str(resource.resolve()),),
        expected_task_revision=task.task_revision,
        expected_run_instance_id=task.run_instance_id,
        expected_execution_epoch=task.execution_epoch,
        expected_goal_version=task.goal_version,
        expected_acceptance_version=task.acceptance_version,
        expected_handled_input_seq=task.handled_input_seq,
        capability_snapshot_id=task.capability_snapshot_id,
        preconditions=(),
        recovery=RecoveryPolicy(
            probe="inspect",
            retry="only after no effect",
            partial="retain",
            cancel="stop",
            unknown_exit="retain resource",
            reconsider_at="explicit recovery",
        ),
    )


def test_verified_resource_handoff_is_idempotent_and_replays(tmp_path: Path) -> None:
    state = tmp_path / "state"
    project = tmp_path / "project"
    project.mkdir()
    (project / "input.txt").write_text("stable\n")
    keychain = MemoryKeychainBackend()
    with LoopBackend.open(state, keychain_backend=keychain) as backend:
        _task(backend)
        intent = _write_intent(backend, "owner", "write", project)
        backend.execute_operation("owner", intent, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"ok": True}))
        with pytest.raises(TaskConflict):
            backend.stabilize_resources(
                "owner",
                handoff_id="fake",
                resources=(str(project.resolve()),),
                stable_state="caller says stable",
                evidence_refs=("cas:does-not-exist",),
            )
        observation = backend.observe_resource_handoff(
            "owner",
            handoff_id="handoff",
            resources=(str(project.resolve()),),
            stable_state="hashes and scene are durable",
        )
        released = backend.stabilize_resources(
            "owner",
            handoff_id="handoff",
            resources=(str(project.resolve()),),
            stable_state="hashes and scene are durable",
            observation=observation,
        )
        assert released.owned_resources == ()
        assert backend.stabilize_resources(
            "owner",
            handoff_id="handoff",
            resources=(str(project.resolve()),),
            stable_state="hashes and scene are durable",
            observation=observation,
        ).owned_resources == ()
    with LoopBackend.open(state, keychain_backend=keychain) as reopened:
        assert reopened._project("owner", reopened.store.task_events("owner")).owned_resources == ()


def test_resource_scene_change_invalidates_observation_without_release(tmp_path: Path) -> None:
    state = tmp_path / "state"
    project = tmp_path / "project"
    project.mkdir()
    target = project / "input.txt"
    target.write_text("before\n")
    with LoopBackend.open(state, keychain_backend=MemoryKeychainBackend()) as backend:
        _task(backend)
        intent = _write_intent(backend, "owner", "write", project)
        backend.execute_operation("owner", intent, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {}))
        observation = backend.observe_resource_handoff(
            "owner", handoff_id="scene-race", resources=(str(project.resolve()),), stable_state="stable"
        )
        target.write_text("changed after observation\n")
        with pytest.raises(TaskConflict, match="scene|root changed"):
            backend.stabilize_resources(
                "owner", handoff_id="scene-race", resources=(str(project.resolve()),),
                stable_state="stable", observation=observation
            )
        assert backend.get_task("owner").owned_resources == (str(project.resolve()),)


def test_cancel_with_unknown_effect_docks_and_retains_responsibility(tmp_path: Path) -> None:
    state = tmp_path / "state"
    project = tmp_path / "project"
    project.mkdir()
    with LoopBackend.open(state, keychain_backend=MemoryKeychainBackend()) as backend:
        _task(backend)
        intent = _write_intent(backend, "owner", "unknown", project)
        backend.execute_operation(
            "owner", intent,
            lambda: (_ for _ in ()).throw(RuntimeError("effect boundary lost")),
        )
        backend.accept_input("owner", input_id="cancel", kind=InputKind.CANCEL, body="stop")
        docked = backend.cancel_safely("owner")
        assert docked.status is TaskStatus.RECOVERY_BLOCKED
        assert docked.control_intent.value == "CANCEL"
        assert docked.received_input_seq > docked.handled_input_seq
        assert docked.unresolved_effects and docked.owned_resources
        assert not docked.is_terminal


def test_authority_endpoint_is_independent_of_tmpdir(tmp_path: Path, monkeypatch) -> None:
    first = authority_socket_path(tmp_path / "state")
    monkeypatch.setenv("TMPDIR", str(tmp_path / "other-temp"))
    second = authority_socket_path(tmp_path / "state")
    assert first == second
    assert len(str(first).encode()) < 104
