from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from sitina.loop import AcceptanceSubmission, CompletionProposal, InputKind, LoopBackend, LoopHost, TaskStatus
from sitina.loop.control import send_control_request
from sitina.loop.model import StaleProposal
from sitina.security.macos_keychain import MemoryKeychainBackend


def _context() -> dict[str, str]:
    return {
        "provider_identity": "fixture-provider:model-a:capacity-1",
        "environment_ref": "fixture-environment:v1",
        "capability_snapshot_id": "fixture-capabilities:v1",
        "software_identity": "fixture-software:3b",
        "config_identity": "fixture-config:v1",
    }


def _submit(workspace: Path, task_id: str = "task-3b") -> dict[str, object]:
    return {
        "command": "submit",
        "task_id": task_id,
        "submission_id": "submission-3b",
        "task_kind": "readonly",
        "goal": "inspect the fixture",
        "workspace": str(workspace),
        "check_command": ["python", "-m", "pytest"],
        "provider_profile": "fixture",
        "approve_writes": False,
    }


def test_resume_intent_is_stable_and_duplicate_does_not_schedule_twice(tmp_path: Path) -> None:
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with LoopHost(state, keychain_backend=MemoryKeychainBackend(), descriptor_context=_context()) as host:
        host._handle_command(_submit(workspace))
        paused = send_control_request(
            state,
            {"command": "input", "task_id": "task-3b", "input_id": "pause-1", "kind": InputKind.PAUSE.value, "body": "pause"},
        )
        assert paused["task"]["control_intent"] == "PAUSE"
        first = host._handle_command({"command": "resume", "task_id": "task-3b", "resume_request_id": "resume-1"})
        second = host._handle_command({"command": "resume", "task_id": "task-3b", "resume_request_id": "resume-1"})
        assert first["disposition"] == "pending_recovery"
        assert second["disposition"] == "existing"
        assert second["scheduled"] is False


def test_restart_bootstrap_claims_old_run_before_runner_dispatch(tmp_path: Path) -> None:
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    keys = MemoryKeychainBackend()
    with LoopHost(state, keychain_backend=keys, descriptor_context=_context()) as first:
        created = first._handle_command(_submit(workspace, "task-restart"))
        prior_run = created["task"]["run_instance_id"]

    seen: list[dict[str, object]] = []
    ready = threading.Event()

    def runner(_backend: object, _task_id: str, task: dict[str, object]) -> None:
        seen.append(task)
        ready.set()

    second = LoopHost(
        state,
        keychain_backend=keys,
        descriptor_context=_context(),
        runner_executor=runner,
    ).start()
    try:
        assert ready.wait(3)
        assert seen[0]["run_instance_id"] != prior_run
        assert seen[0]["execution_epoch"] == int(created["task"]["execution_epoch"]) + 1
        assert seen[0]["recovery_state"] == "READY_RECOVERED"
    finally:
        second.close()


def _acceptance(task, acceptance_id: str = "acceptance-3b") -> AcceptanceSubmission:
    return AcceptanceSubmission(
        acceptance_id=acceptance_id,
        outcome_id="outcome-1",
        evidence_refs=("cas:evidence-3b",),
        program_status="PASS",
        reviewer_status="PASS",
        delivery_verified=True,
        expected_task_revision=task.task_revision,
        expected_run_instance_id=task.run_instance_id,
        expected_execution_epoch=task.execution_epoch,
        expected_goal_version=task.goal_version,
        expected_acceptance_version=task.acceptance_version,
        expected_handled_input_seq=task.handled_input_seq,
        artifact_ref=task.artifact_ref,
    )


def _proposal(task, proposal_id: str = "proposal-3b") -> CompletionProposal:
    return CompletionProposal(
        proposal_id=proposal_id,
        terminal_status=TaskStatus.SUCCEEDED,
        expected_task_revision=task.task_revision,
        expected_run_instance_id=task.run_instance_id,
        expected_execution_epoch=task.execution_epoch,
        expected_goal_version=task.goal_version,
        expected_acceptance_version=task.acceptance_version,
        expected_received_input_seq=task.received_input_seq,
        expected_handled_input_seq=task.handled_input_seq,
        artifact_ref=task.artifact_ref,
        final_result={"response": "verified"},
    )


def _backend_task(backend: LoopBackend, task_id: str) -> object:
    return backend.create_task(
        task_id=task_id,
        session_id="session-3b",
        task_kind="code_change",
        goal="verify the committed artifact",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact-3b",
        environment_ref="environment-3b",
        capability_snapshot_id="capabilities-3b",
    )


def test_record_acceptance_external_guard_rejects_without_mutation_then_commits(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "acceptance-guard", keychain_backend=MemoryKeychainBackend()) as backend:
        task = _backend_task(backend, "task-acceptance-guard")
        submission = _acceptance(task)
        before = backend.get_task(task.task_id)
        before_events = len(backend.store.task_events(task.task_id))
        with pytest.raises(StaleProposal, match="artifact content changed"):
            backend.record_acceptance(
                task.task_id,
                submission,
                require_current=True,
                external_guard=lambda: False,
            )
        unchanged = backend.get_task(task.task_id)
        assert unchanged.task_revision == before.task_revision
        assert unchanged.acceptances == {}
        assert len(backend.store.task_events(task.task_id)) == before_events

        committed = backend.record_acceptance(
            task.task_id,
            submission,
            require_current=True,
            external_guard=lambda: True,
        )
        assert committed.task_revision > before.task_revision
        assert committed.acceptances[submission.acceptance_id].acceptance_id == submission.acceptance_id


def test_propose_terminal_external_guard_rejects_without_mutation_then_commits(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "terminal-guard", keychain_backend=MemoryKeychainBackend()) as backend:
        task = _backend_task(backend, "task-terminal-guard")
        task = backend.record_acceptance(task.task_id, _acceptance(task), require_current=True, external_guard=lambda: True)
        proposal = _proposal(task)
        before = backend.get_task(task.task_id)
        before_events = len(backend.store.task_events(task.task_id))
        with pytest.raises(StaleProposal, match="artifact content changed"):
            backend.propose_terminal(task.task_id, proposal, external_guard=lambda: False)
        unchanged = backend.get_task(task.task_id)
        assert unchanged.task_revision == before.task_revision
        assert unchanged.terminal_event_id is None
        assert len(backend.store.task_events(task.task_id)) == before_events

        completed = backend.propose_terminal(task.task_id, proposal, external_guard=lambda: True)
        assert completed.status is TaskStatus.SUCCEEDED
        assert completed.terminal_event_id
