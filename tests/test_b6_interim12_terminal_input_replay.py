from __future__ import annotations

from pathlib import Path

import pytest

from sitina.loop import AcceptanceSubmission, CompletionProposal, InputKind, LoopBackend, TaskStatus
from sitina.loop.model import TaskConflict
from sitina.security.macos_keychain import MemoryKeychainBackend


def test_terminal_input_replay_is_observation_only_and_new_input_stays_rejected(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend()) as backend:
        task = backend.create_task(
            task_id="task-b6-interim-12",
            session_id="session-b6-interim-12",
            task_kind="readonly",
            goal="verify terminal input replay",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:artifact-b6-interim-12",
            environment_ref="environment-b6-interim-12",
            capability_snapshot_id="capabilities-b6-interim-12",
        )
        first = backend.accept_input(
            task.task_id,
            input_id="input-terminal-replay",
            kind=InputKind.CORRECTION,
            body="same durable input",
        )
        handled = backend.handle_next_input(task.task_id, derive_effects_from_record=True)
        accepted = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-b6-interim-12",
                outcome_id="outcome-1",
                evidence_refs=("cas:evidence-b6-interim-12",),
                program_status="PASS",
                reviewer_status="PASS",
                delivery_verified=True,
                expected_task_revision=handled.task_revision,
                expected_run_instance_id=handled.run_instance_id,
                expected_execution_epoch=handled.execution_epoch,
                expected_goal_version=handled.goal_version,
                expected_acceptance_version=handled.acceptance_version,
                expected_handled_input_seq=handled.handled_input_seq,
                artifact_ref=handled.artifact_ref,
            ),
        )
        terminal = backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-b6-interim-12",
                terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=accepted.task_revision,
                expected_run_instance_id=accepted.run_instance_id,
                expected_execution_epoch=accepted.execution_epoch,
                expected_goal_version=accepted.goal_version,
                expected_acceptance_version=accepted.acceptance_version,
                expected_received_input_seq=accepted.received_input_seq,
                expected_handled_input_seq=accepted.handled_input_seq,
                artifact_ref=accepted.artifact_ref,
                final_result={"result": "done"},
            ),
        )
        before_replay_events = len(backend.store.task_events(task.task_id))

        replay = backend.accept_input(
            task.task_id,
            input_id="input-terminal-replay",
            kind=InputKind.CORRECTION,
            body="same durable input",
        )
        assert replay.as_dict() == terminal.as_dict()
        assert len(backend.store.task_events(task.task_id)) == before_replay_events
        assert replay.status is TaskStatus.SUCCEEDED

        with pytest.raises(TaskConflict, match="different content"):
            backend.accept_input(
                task.task_id,
                input_id="input-terminal-replay",
                kind=InputKind.CORRECTION,
                body="different durable input",
            )
        with pytest.raises(TaskConflict, match="terminal task"):
            backend.accept_input(
                task.task_id,
                input_id="new-input-after-terminal",
                kind=InputKind.MESSAGE,
                body="new work must remain rejected",
            )
        assert len(backend.store.task_events(task.task_id)) == before_replay_events
        assert backend.get_task(task.task_id).received_input_seq == first.received_input_seq == 1
