from __future__ import annotations

import multiprocessing
import threading
from pathlib import Path

import pytest

from sitina.loop import (
    AcceptanceSubmission,
    CompletionProposal,
    EffectStatus,
    FilePrecondition,
    InputKind,
    LoopBackend,
    OperationIntent,
    OperationMode,
    OperationOutcome,
    RecoveryPolicy,
    TaskStatus,
)
from sitina.loop.model import OperationRejected, PersistenceFenced, StaleProposal, TaskConflict
from sitina.security.key_provider import KeyProviderError
from sitina.security.macos_keychain import MemoryKeychainBackend


class SharedKeychainBackend:
    def __init__(self, items, lock) -> None:
        self.items = items
        self.lock = lock

    def get(self, service: str, account: str) -> bytes | None:
        with self.lock:
            value = self.items.get((service, account))
            return bytes(value) if value is not None else None

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        with self.lock:
            key = (service, account)
            if key in self.items and not replace:
                raise KeyProviderError("Keychain item already exists")
            self.items[key] = bytes(value)

    def public_inventory(self) -> dict[str, object]:
        return {"schema": "SHARED_TEST_KEYCHAIN_V1", "secret_values_included": False}


def _child_read_only_open(root: str, items, lock, output) -> None:
    try:
        with LoopBackend.open(root, keychain_backend=SharedKeychainBackend(items, lock)) as backend:
            task = backend.get_task("task-reopen")
            output.put(
                {
                    "existing_only": backend.context.key_readback.existing_only_reopen,
                    "task_ids": backend.task_ids(),
                    "status": task.status.value,
                    "recovery_state": task.recovery_state,
                    "event_count": len(backend.store.task_events("task-reopen")),
                }
            )
    except BaseException as error:  # pragma: no cover - returned to parent assertion
        output.put({"error": f"{type(error).__name__}: {error}"})


def create_task(backend: LoopBackend, task_id: str, *, kind: str = "code_change"):
    return backend.create_task(
        task_id=task_id,
        session_id="session-1",
        task_kind=kind,
        goal="produce the required result",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact-v1",
        environment_ref="environment-v1",
        capability_snapshot_id="capabilities-v1",
    )


def recovery_policy() -> RecoveryPolicy:
    return RecoveryPolicy(
        probe="inspect the durable target",
        retry="only after proving no effect",
        partial="record partial result",
        cancel="stop new dispatch",
        unknown_exit="hold resource ownership",
        reconsider_at="after an explicit recovery decision",
    )


def operation_intent(
    backend: LoopBackend,
    task_id: str,
    operation_id: str,
    *,
    mode: OperationMode,
    resources: tuple[str, ...] = (),
    preconditions: tuple[FilePrecondition, ...] = (),
) -> OperationIntent:
    task = backend.get_task(task_id)
    return OperationIntent(
        operation_id=operation_id,
        logical_operation_id=f"logical-{operation_id}",
        attempt_id=f"attempt-{operation_id}",
        mode=mode,
        description=f"execute {operation_id}",
        resources=resources,
        expected_task_revision=task.task_revision,
        expected_run_instance_id=task.run_instance_id,
        expected_execution_epoch=task.execution_epoch,
        expected_goal_version=task.goal_version,
        expected_acceptance_version=task.acceptance_version,
        expected_handled_input_seq=task.handled_input_seq,
        capability_snapshot_id=task.capability_snapshot_id,
        preconditions=preconditions,
        recovery=recovery_policy(),
    )


def acceptance_submission(task, acceptance_id: str = "acceptance-1") -> AcceptanceSubmission:
    return AcceptanceSubmission(
        acceptance_id=acceptance_id,
        outcome_id="outcome-1",
        evidence_refs=("cas:evidence-1",),
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


def completion_proposal(task, proposal_id: str = "proposal-1", *, result: str = "first"):
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
        final_result={"result": result},
    )


@pytest.mark.parametrize("kind", [InputKind.CORRECTION, InputKind.PAUSE, InputKind.CANCEL])
def test_persisted_correction_pause_and_cancel_beat_stale_completion(tmp_path: Path, kind: InputKind) -> None:
    with LoopBackend.open(tmp_path / kind.value.lower(), keychain_backend=MemoryKeychainBackend()) as backend:
        task = create_task(backend, f"task-{kind.value.lower()}")
        task = backend.record_acceptance(task.task_id, acceptance_submission(task))
        stale = completion_proposal(task)
        backend.accept_input(task.task_id, input_id="input-1", kind=kind, body="new user intent")
        backend.handle_next_input(task.task_id)
        with pytest.raises(StaleProposal):
            backend.propose_terminal(task.task_id, stale)


def test_task_creation_is_idempotent_only_for_the_same_initial_goal(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "task-create-idempotency", keychain_backend=MemoryKeychainBackend()) as backend:
        first = create_task(backend, "task-create")
        repeated = create_task(backend, "task-create")
        assert repeated.task_revision == first.task_revision
        assert len(backend.store.task_events("task-create")) == 1
        with pytest.raises(TaskConflict, match="different creation fields"):
            backend.create_task(
                task_id="task-create",
                session_id="session-1",
                task_kind="code_change",
                goal="a different initial goal",
                required_outcome_ids=("outcome-1",),
                artifact_ref="cas:artifact-v1",
                environment_ref="environment-v1",
                capability_snapshot_id="capabilities-v1",
            )
        initial_goal = backend.context_memory.read(first.goal_ref)
        assert initial_goal["goal"] == "produce the required result"


def test_input_identity_deduplicates_exact_content_and_rejects_rebinding(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    root = tmp_path / "input-dedupe"
    with LoopBackend.open(root, keychain_backend=keys) as backend:
        create_task(backend, "task-input-dedupe")
        first = backend.accept_input(
            "task-input-dedupe", input_id="input-1", kind=InputKind.MESSAGE, body="same body"
        )
        repeated = backend.accept_input(
            "task-input-dedupe", input_id="input-1", kind=InputKind.MESSAGE, body="same body"
        )
        assert repeated.task_revision == first.task_revision
        assert repeated.received_input_seq == 1
        with pytest.raises(TaskConflict, match="different content"):
            backend.accept_input(
                "task-input-dedupe", input_id="input-1", kind=InputKind.MESSAGE, body="different body"
            )
        handled = backend.handle_next_input("task-input-dedupe")
        assert handled.received_input_seq == handled.handled_input_seq == 1
    with LoopBackend.open(root, keychain_backend=keys) as reopened:
        restored = reopened.get_task("task-input-dedupe")
        assert restored.received_input_seq == restored.handled_input_seq == 1
        assert restored.inputs[0].input_id == "input-1"


def test_only_one_logical_terminal_event_is_committed(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "terminal", keychain_backend=MemoryKeychainBackend()) as backend:
        task = create_task(backend, "task-terminal")
        task = backend.record_acceptance(task.task_id, acceptance_submission(task))
        first = backend.propose_terminal(task.task_id, completion_proposal(task, "proposal-1", result="one"))
        second = backend.propose_terminal(task.task_id, completion_proposal(task, "proposal-2", result="two"))
        terminal_events = [
            event for event in backend.store.task_events(task.task_id)
            if event.event_type == "loop.task-terminated"
        ]
        assert first.terminal_event_id == second.terminal_event_id
        assert second.terminal_result["final_result"] == {"result": "one"}
        assert len(terminal_events) == 1


def test_concurrent_terminal_proposals_share_one_logical_terminal_position(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "terminal-race", keychain_backend=MemoryKeychainBackend()) as backend:
        task = create_task(backend, "task-terminal-race")
        task = backend.record_acceptance(task.task_id, acceptance_submission(task))
        first = completion_proposal(task, "proposal-a", result="a")
        second = completion_proposal(task, "proposal-b", result="b")
        results: list[object] = []
        barrier = threading.Barrier(3)

        def submit(proposal: CompletionProposal) -> None:
            barrier.wait()
            results.append(backend.propose_terminal(task.task_id, proposal))

        threads = [threading.Thread(target=submit, args=(proposal,)) for proposal in (first, second)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(5)
            assert not thread.is_alive()
        assert len(results) == 2
        assert len({result.terminal_event_id for result in results}) == 1
        assert len(
            [event for event in backend.store.task_events(task.task_id) if event.event_type == "loop.task-terminated"]
        ) == 1


def test_intent_persistence_failure_prevents_effect_and_fences_backend(tmp_path: Path) -> None:
    armed = {"value": False}

    def fail_intent(event_type: str) -> None:
        if armed["value"] and event_type == "loop.operation-intent-recorded":
            raise OSError("simulated durable append failure")

    called = {"value": False}
    with LoopBackend.open(
        tmp_path / "append-failure",
        keychain_backend=MemoryKeychainBackend(),
        append_fault=fail_intent,
    ) as backend:
        create_task(backend, "task-append")
        target = str((tmp_path / "effect.txt").resolve())
        intent = operation_intent(
            backend,
            "task-append",
            "operation-append",
            mode=OperationMode.WRITE,
            resources=(target,),
        )
        armed["value"] = True

        def dispatch() -> OperationOutcome:
            called["value"] = True
            return OperationOutcome(EffectStatus.SUCCEEDED, {})

        with pytest.raises(OSError):
            backend.execute_operation("task-append", intent, dispatch)
        assert not called["value"]
        assert backend.persistence_fenced
        with pytest.raises(PersistenceFenced):
            backend.accept_input("task-append", input_id="later", kind=InputKind.MESSAGE, body="later")


def test_write_rechecks_file_precondition_after_waiting_for_lane(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    target = tmp_path / "shared.txt"
    target.write_text("v1", encoding="utf-8")
    resource = str(target.resolve())
    first_resource = str((tmp_path / "unrelated-first-write").resolve())
    with LoopBackend.open(tmp_path / "queued", keychain_backend=keys) as backend:
        create_task(backend, "task-b")
        create_task(backend, "task-a")
        entered = threading.Event()
        release = threading.Event()
        second_dispatched = {"value": False}
        results: dict[str, object] = {}

        first_intent = operation_intent(
            backend, "task-b", "operation-b", mode=OperationMode.WRITE, resources=(first_resource,)
        )

        def first_dispatch() -> OperationOutcome:
            entered.set()
            assert release.wait(5)
            return OperationOutcome(EffectStatus.SUCCEEDED, {"written": True})

        first_thread = threading.Thread(
            target=lambda: results.setdefault("first", backend.execute_operation("task-b", first_intent, first_dispatch))
        )
        first_thread.start()
        assert entered.wait(5)
        second_intent = operation_intent(
            backend,
            "task-a",
            "operation-a",
            mode=OperationMode.WRITE,
            resources=(resource,),
            preconditions=(FilePrecondition.capture(target),),
        )

        def run_second() -> None:
            try:
                backend.execute_operation(
                    "task-a",
                    second_intent,
                    lambda: second_dispatched.__setitem__("value", True) or OperationOutcome(EffectStatus.SUCCEEDED, {}),
                )
            except BaseException as error:
                results["second_error"] = error

        second_thread = threading.Thread(target=run_second)
        second_thread.start()
        assert backend.operations.owner == ("task-b", "operation-b")
        target.write_text("v2", encoding="utf-8")
        release.set()
        first_thread.join(5)
        second_thread.join(5)
        assert not first_thread.is_alive() and not second_thread.is_alive()
        assert isinstance(results.get("second_error"), OperationRejected)
        assert not second_dispatched["value"]
        assert any(
            event.event_type == "loop.operation-precondition-changed"
            for event in backend.store.task_events("task-a")
        )


def test_operation_intent_is_durable_before_effect(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "intent-first", keychain_backend=MemoryKeychainBackend()) as backend:
        create_task(backend, "task-intent")
        target = str((tmp_path / "intent-target").resolve())
        intent = operation_intent(
            backend, "task-intent", "operation-intent", mode=OperationMode.WRITE, resources=(target,)
        )

        def dispatch() -> OperationOutcome:
            assert backend.store.task_events("task-intent")[-1].event_type == "loop.operation-intent-recorded"
            return OperationOutcome(EffectStatus.SUCCEEDED, {"observed": "intent-first"})

        backend.execute_operation("task-intent", intent, dispatch)


def test_long_write_does_not_block_independent_read_or_input(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "nonblocking", keychain_backend=MemoryKeychainBackend()) as backend:
        create_task(backend, "task-write")
        create_task(backend, "task-read")
        create_task(backend, "task-input")
        entered = threading.Event()
        release = threading.Event()
        writer_done = threading.Event()
        resource = str((tmp_path / "long-target").resolve())
        write_intent = operation_intent(
            backend, "task-write", "operation-write", mode=OperationMode.WRITE, resources=(resource,)
        )

        def write_dispatch() -> OperationOutcome:
            entered.set()
            assert release.wait(5)
            return OperationOutcome(EffectStatus.SUCCEEDED, {})

        def run_writer() -> None:
            backend.execute_operation("task-write", write_intent, write_dispatch)
            writer_done.set()

        thread = threading.Thread(target=run_writer)
        thread.start()
        assert entered.wait(5)
        read_intent = operation_intent(
            backend, "task-read", "operation-read", mode=OperationMode.READ
        )
        outcome = backend.execute_operation(
            "task-read", read_intent, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"read": True})
        )
        input_task = backend.accept_input(
            "task-input", input_id="input-now", kind=InputKind.MESSAGE, body="accepted while write runs"
        )
        assert outcome.status is EffectStatus.SUCCEEDED
        assert input_task.received_input_seq == 1
        assert not writer_done.is_set()
        release.set()
        thread.join(5)
        assert writer_done.is_set()


def test_bound_model_work_outside_coordinator_does_not_block_input(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "model-nonblocking", keychain_backend=MemoryKeychainBackend()) as backend:
        create_task(backend, "task-model")
        started = threading.Event()
        release = threading.Event()

        def simulate_model() -> None:
            binding = backend.bind_agent_request("task-model")
            assert binding.task_id == "task-model"
            started.set()
            assert release.wait(5)

        thread = threading.Thread(target=simulate_model)
        thread.start()
        assert started.wait(5)
        received = backend.accept_input(
            "task-model", input_id="correction-during-model", kind=InputKind.CORRECTION, body="new goal"
        )
        assert received.received_input_seq == 1
        release.set()
        thread.join(5)
        assert not thread.is_alive()


def test_unknown_write_effect_holds_lane_but_not_inputs_or_reads_and_restores_on_reopen(tmp_path: Path) -> None:
    import json

    config = Path(__file__).resolve().parents[1] / "config"
    limits = json.loads((config / "orchestration_policy.json").read_text())["resource_limits"]
    limits["operation_output_bytes"] = 1024
    monitoring = json.loads((config / "observability_policy.json").read_text())
    keys = MemoryKeychainBackend()
    root = tmp_path / "unknown"
    resource = str((tmp_path / "shared-effect").resolve())
    with LoopBackend.open(root, keychain_backend=keys) as backend:
        backend.configure_resource_monitoring(limits, monitoring)
        create_task(backend, "task-unknown")
        create_task(backend, "task-conflict")
        create_task(backend, "task-read")
        intent = operation_intent(
            backend, "task-unknown", "operation-unknown", mode=OperationMode.WRITE, resources=(resource,)
        )
        outcome = backend.execute_operation(
            "task-unknown",
            intent,
            lambda: (_ for _ in ()).throw(RuntimeError("transport outcome unknown")),
        )
        assert outcome.status is EffectStatus.UNKNOWN
        assert backend.operations.unknown_effect_owner == ("task-unknown", "operation-unknown")
        assert backend.get_task("task-unknown").status is TaskStatus.WAITING_OPERATION
        assert backend.get_task("task-unknown").owned_resources == (resource,)
        conflicting = operation_intent(
            backend, "task-conflict", "operation-conflict", mode=OperationMode.WRITE, resources=(resource,)
        )
        with pytest.raises(OperationRejected):
            backend.execute_operation(
                "task-conflict", conflicting, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {})
            )
        paused = backend.accept_input(
            "task-unknown", input_id="pause-unknown", kind=InputKind.PAUSE, body="pause"
        )
        assert paused.control_intent.value == "PAUSE"
        read = operation_intent(backend, "task-read", "read-after-unknown", mode=OperationMode.READ)
        completed = backend.execute_operation(
            "task-read", read, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"read": True, "payload": "x" * 2048})
        )
        assert completed.status is EffectStatus.SUCCEEDED
        assert completed.result["result_discarded"] is True
        assert completed.result["original_effect_status"] == "SUCCEEDED"
        saved = backend.context_memory.read(backend.get_task("task-read").operations[read.operation_id].result_ref)
        assert len(json.dumps(saved)) < 1024
        timed = operation_intent(backend, "task-read", "settled-timeout", mode=OperationMode.READ)
        settled_timeout = backend.execute_operation(
            "task-read", timed, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {
                "tool": "sitina_shell", "status": "error", "program_status": "FAIL",
                "completion_status": "TIMED_OUT", "execution_started": True, "effect_settled": True,
                "stdout": "x" * 2048,
            }),
        )
        assert settled_timeout.status is EffectStatus.SUCCEEDED
        assert settled_timeout.result["result_discarded"] is True
        assert settled_timeout.result["completion_status"] == "TIMED_OUT"
        unreported = operation_intent(backend, "task-read", "provider-unreported", mode=OperationMode.READ)
        backend.execute_operation("task-read", unreported, lambda: OperationOutcome(
            EffectStatus.SUCCEEDED, {"work_purpose": "execute", "turn": 1, "metadata": {}},
        ))
        observed = backend.monitoring_status()
        assert observed["metrics"]["unknown_effect_count"] == 1
        assert observed["metrics"]["cost_ratio_ppm"] is None
        assert observed["metrics"]["timeout_count"] == 1
        assert observed["metrics"]["error_count"] >= 2
        assert observed["metrics"]["retry_count"] is None
        assert observed["metrics"]["retry_unknown_count"] == 1
        assert observed["metrics"]["cost_unknown_count"] == 1
        assert "TIMEOUT" in {n["code"] for n in observed["notifications"]}
        assert {n["code"] for n in observed["notifications"]} >= {"UNKNOWN_EFFECT", "RESOURCE_LIMIT"}

    with LoopBackend.open(root, keychain_backend=keys) as reopened:
        reopened.configure_resource_monitoring(limits, monitoring)
        restored = reopened.monitoring_status()
        assert restored["notifications"] == observed["notifications"]
        assert restored["source_position"] == observed["source_position"]
        assert reopened.operations.unknown_effect_owner == ("task-unknown", "operation-unknown")
        create_task(reopened, "task-new-after-restart")
        blocked = operation_intent(
            reopened,
            "task-new-after-restart",
            "operation-new",
            mode=OperationMode.WRITE,
            resources=(resource,),
        )
        with pytest.raises(OperationRejected):
            reopened.execute_operation(
                "task-new-after-restart", blocked, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {})
            )
        reopened.configure_resource_monitoring({**limits, "global": 1}, monitoring)
        guarded = operation_intent(reopened, "task-new-after-restart", "guarded-read", mode=OperationMode.READ)
        dispatched = []
        with pytest.raises(OperationRejected, match="native resource limit global"):
            reopened.execute_operation("task-new-after-restart", guarded, lambda: dispatched.append(True))
        assert dispatched == []
        assert "guarded-read" not in reopened.get_task("task-new-after-restart").operations


def test_pending_write_intent_restores_frozen_lane_after_result_persistence_failure(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    root = tmp_path / "pending-intent"
    armed = {"value": False}

    def fail_result(event_type: str) -> None:
        if armed["value"] and event_type == "loop.operation-result-recorded":
            raise OSError("simulated result append failure")

    resource = str((tmp_path / "pending-project").resolve())
    with LoopBackend.open(root, keychain_backend=keys, append_fault=fail_result) as backend:
        create_task(backend, "task-pending")
        intent = operation_intent(
            backend, "task-pending", "operation-pending", mode=OperationMode.WRITE, resources=(resource,)
        )
        effect = {"count": 0}

        def dispatch() -> OperationOutcome:
            effect["count"] += 1
            armed["value"] = True
            return OperationOutcome(EffectStatus.SUCCEEDED, {"effect": True})

        with pytest.raises(OSError):
            backend.execute_operation("task-pending", intent, dispatch)
        assert effect["count"] == 1
        assert backend.operations.unknown_effect_owner == ("task-pending", "operation-pending")

    with LoopBackend.open(root, keychain_backend=keys) as reopened:
        pending = reopened.get_task("task-pending")
        assert len(pending.active_operations) == 1
        assert reopened.operations.unknown_effect_owner == ("task-pending", "operation-pending")
        create_task(reopened, "task-after-pending")
        next_intent = operation_intent(
            reopened,
            "task-after-pending",
            "operation-after-pending",
            mode=OperationMode.WRITE,
            resources=(resource,),
        )
        dispatched = {"value": False}
        with pytest.raises(OperationRejected):
            reopened.execute_operation(
                "task-after-pending",
                next_intent,
                lambda: dispatched.__setitem__("value", True) or OperationOutcome(EffectStatus.SUCCEEDED, {}),
            )
        assert not dispatched["value"]


def test_project_resource_ownership_survives_success_until_persisted_stable_handoff(tmp_path: Path) -> None:
    root = tmp_path / "project-owner"
    project = tmp_path / "project"
    project.mkdir()
    child = project / "nested.txt"
    with LoopBackend.open(root, keychain_backend=MemoryKeychainBackend()) as backend:
        create_task(backend, "task-owner")
        create_task(backend, "task-other")
        owner_resource = str(project.resolve())
        owner_intent = operation_intent(
            backend,
            "task-owner",
            "operation-owner",
            mode=OperationMode.WRITE,
            resources=(owner_resource,),
        )
        backend.execute_operation(
            "task-owner", owner_intent, lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"stable": True})
        )
        assert backend.get_task("task-owner").owned_resources == (owner_resource,)
        child_resource = str(child.resolve())
        other_intent = operation_intent(
            backend,
            "task-other",
            "operation-other",
            mode=OperationMode.WRITE,
            resources=(child_resource,),
        )
        other_effect = {"value": False}
        with pytest.raises(OperationRejected, match="remains owned"):
            backend.execute_operation(
                "task-other",
                other_intent,
                lambda: other_effect.__setitem__("value", True) or OperationOutcome(EffectStatus.SUCCEEDED, {}),
            )
        assert not other_effect["value"]

        observation = backend.observe_resource_handoff(
            "task-owner",
            handoff_id="handoff-1",
            resources=(owner_resource,),
            stable_state="working tree and evidence are durably inspectable",
        )
        released = backend.stabilize_resources(
            "task-owner",
            handoff_id="handoff-1",
            resources=(owner_resource,),
            stable_state="working tree and evidence are durably inspectable",
            observation=observation,
        )
        assert released.owned_resources == ()
        assert backend.execute_operation(
            "task-other",
            other_intent,
            lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"now_allowed": True}),
        ).status is EffectStatus.SUCCEEDED


def test_late_acceptance_keeps_old_binding_and_cannot_complete_new_goal(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "late-review", keychain_backend=MemoryKeychainBackend()) as backend:
        task = create_task(backend, "task-review")
        old_review = acceptance_submission(task, "review-v1")
        backend.accept_input(
            task.task_id, input_id="correction-1", kind=InputKind.CORRECTION, body="new goal"
        )
        backend.handle_next_input(task.task_id)
        after_late = backend.record_acceptance(task.task_id, old_review)
        assert "review-v1" not in after_late.acceptances
        late_event = backend.store.task_events(task.task_id)[-1]
        assert late_event.event_type == "loop.acceptance-result-recorded"
        assert not late_event.payload["applicable_to_current_task"]
        with pytest.raises(StaleProposal, match="lacks current evidence"):
            backend.propose_terminal(task.task_id, completion_proposal(after_late, "proposal-after-late"))

        current = backend.record_acceptance(
            task.task_id,
            acceptance_submission(after_late, "review-v2"),
        )
        completed = backend.propose_terminal(
            task.task_id,
            completion_proposal(current, "proposal-after-current"),
        )
        assert completed.status is TaskStatus.SUCCEEDED


def test_binding_write_and_readback_failures_precede_journal_state(tmp_path: Path, monkeypatch) -> None:
    import sitina.loop.storage as storage

    write_root = tmp_path / "binding-write-failure"
    real_write = storage._durable_write_bindings

    def fail_write(_path, _value) -> None:
        raise OSError("simulated binding write failure")

    monkeypatch.setattr(storage, "_durable_write_bindings", fail_write)
    with pytest.raises(KeyProviderError, match="not durably committed"):
        LoopBackend.open(write_root, keychain_backend=MemoryKeychainBackend())
    assert not (write_root / "journal").exists()

    monkeypatch.setattr(storage, "_durable_write_bindings", real_write)
    read_root = tmp_path / "binding-read-failure"

    def fail_read(_path, _value):
        raise KeyProviderError("simulated binding read-back failure")

    monkeypatch.setattr(storage, "_read_and_verify_bindings", fail_read)
    with pytest.raises(KeyProviderError, match="not durably committed"):
        LoopBackend.open(read_root, keychain_backend=MemoryKeychainBackend())
    assert not (read_root / "journal").exists()


def test_existing_namespace_with_missing_keys_never_generates_replacements(tmp_path: Path) -> None:
    root = tmp_path / "missing-recovery-key"
    original = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=original) as backend:
        create_task(backend, "task-missing-key")
    empty = MemoryKeychainBackend()
    with pytest.raises(KeyProviderError, match="registry is unavailable"):
        LoopBackend.open(root, keychain_backend=empty)
    assert empty.public_inventory()["item_count"] == 0


def test_fresh_empty_root_initializes_and_new_process_reopens_read_only(tmp_path: Path, monkeypatch) -> None:
    context = multiprocessing.get_context("fork")
    with multiprocessing.Manager() as manager:
        items = manager.dict()
        lock = manager.RLock()
        output = context.Queue()
        backend_keys = SharedKeychainBackend(items, lock)
        root = tmp_path / "fresh-existing-directory"
        root.mkdir()
        with LoopBackend.open(root, keychain_backend=backend_keys) as backend:
            create_task(backend, "task-reopen", kind="read_only")
            assert backend.context.key_readback.persisted_before_business_state
            assert not backend.context.key_readback.existing_only_reopen
            assert (root / "key-bindings-v1.json").is_file()
            original_events = backend.store.task_events("task-reopen")
            original_contents = {
                ref: backend.store.read_json(ref)
                for event in original_events for ref in event.object_refs
            }

        process = context.Process(target=_child_read_only_open, args=(str(root), items, lock, output))
        process.start()
        process.join(10)
        assert process.exitcode == 0
        result = output.get(timeout=2)
        assert "error" not in result
        assert result == {
            "existing_only": True,
            "task_ids": ("task-reopen",),
            "status": "RECOVERY_BLOCKED",
            "recovery_state": "RESTART_DETECTED",
            "event_count": 1,
        }


        # A backup retains the original cryptographic identity at another path.
        import hashlib
        import os
        from dataclasses import replace

        from sitina.archive.backup import BackupHoldRegistry, CanonicalBackupBuilder
        from sitina.journal.local import LocalJournal, LocalJournalError
        from sitina.journal.model import FrontierRef, canonical_json_bytes, domain_hash
        from sitina.journal.recovery import JournalRecoveryError, scan_active_segment_read_only
        from sitina.loop.storage import LoopRuntimeContext, open_loop_archive_read_only
        from sitina.security.key_provider import JournalAuthProvider
        from sitina.security.macos_keychain import MacOSKeychainProvider

        (tmp_path / ".sitina-bplus-disposable-v1").write_bytes(b"unit-test\n")
        last_frame = scan_active_segment_read_only(root / "journal" / "active.seg").frames[-1]
        original_journal_id = "loop-journal-" + hashlib.sha256(str(root).encode()).hexdigest()[:24]
        frontier = FrontierRef(original_journal_id, 1, "local",
                               last_frame.transaction.last_position, last_frame.transaction_hash)
        paths = sorted(path.relative_to(root).as_posix() for path in root.rglob("*")
                       if path.is_symlink() or path.is_file())
        builder = CanonicalBackupBuilder(BackupHoldRegistry())
        manifest = builder.build(backup_id="loop-read-only-archive", source_root=root,
                                 destination=tmp_path / "archive", frontier=frontier,
                                 reachable_paths=paths, active_prefix_disposition="FROZEN_EXACT_PREFIX")
        restored = tmp_path / "restored"
        builder.verify_restore(manifest, restore_root=restored)

        def snapshot(directory):
            values = {}
            for path in [directory, *sorted(directory.rglob("*"))]:
                info = path.lstat()
                raw = os.fsencode(os.readlink(path)) if path.is_symlink() else (
                    path.read_bytes() if path.is_file() else b"")
                values[path.relative_to(directory).as_posix()] = (
                    info.st_mode, info.st_ino, info.st_mtime_ns, hashlib.sha256(raw).hexdigest())
            return values

        original_before = snapshot(root)
        restore_before = snapshot(restored)
        keys_before = dict(items)
        with pytest.raises(KeyProviderError, match="recovery key binding is invalid"):
            LoopRuntimeContext.open(restored, backend=backend_keys)

        def no_writer(*_args, **_kwargs):
            raise AssertionError("archive reader attempted a writer capability")

        monkeypatch.setattr(LoopRuntimeContext, "open", no_writer)
        monkeypatch.setattr(LoopRuntimeContext, "open_store", no_writer)
        monkeypatch.setattr(LocalJournal, "open", no_writer)
        monkeypatch.setattr(SharedKeychainBackend, "put", no_writer)
        view = open_loop_archive_read_only(restored, manifest=manifest,
                                          expected_manifest_hash=manifest.manifest_hash,
                                          backend=backend_keys)
        assert view.source_root == root
        assert view.key_readback.existing_only_reopen
        assert view.task_ids() == ("task-reopen",)
        assert view.task_events("task-reopen") == original_events
        assert not view.task_events("task-reopen", after_position=original_events[-1].position)
        assert all(view.read_json(ref) == value for ref, value in original_contents.items())
        assert not hasattr(view, "conditional_append")
        assert not hasattr(view, "publish_json")

        with pytest.raises(KeyProviderError, match="manifest identity"):
            open_loop_archive_read_only(restored, manifest=manifest,
                                        expected_manifest_hash="0" * 64, backend=backend_keys)
        with pytest.raises(KeyProviderError, match="source key binding"):
            open_loop_archive_read_only(restored, manifest=replace(manifest, source_root=tmp_path / "wrong-source"),
                                        expected_manifest_hash=manifest.manifest_hash, backend=backend_keys)
        wrong_frontier = replace(manifest, frontier=replace(frontier, position=frontier.position + 1))
        wrong_frontier = replace(wrong_frontier, manifest_hash=domain_hash(
            "CANONICAL_BACKUP_MANIFEST", canonical_json_bytes(wrong_frontier.mapping())))
        with pytest.raises(JournalRecoveryError, match="frozen frontier"):
            open_loop_archive_read_only(restored, manifest=wrong_frontier,
                                        expected_manifest_hash=wrong_frontier.manifest_hash, backend=backend_keys)
        empty = MemoryKeychainBackend()
        with pytest.raises(KeyProviderError, match="registry is unavailable"):
            open_loop_archive_read_only(restored, manifest=manifest,
                                        expected_manifest_hash=manifest.manifest_hash, backend=empty)
        assert empty.public_inventory()["item_count"] == 0
        provider = MacOSKeychainProvider(environment="sitina-loop", namespace=view.key_readback.namespace,
                                        backend=backend_keys)
        with pytest.raises(LocalJournalError, match="isolated Code Mode"):
            LocalJournal.read_authenticated_frames(restored, JournalAuthProvider(provider),
                                                   journal_id=original_journal_id, epoch=1)
        assert snapshot(root) == original_before
        assert snapshot(restored) == restore_before
        assert dict(items) == keys_before

def test_restart_dock_is_persistent_and_does_not_claim_recovery_or_repeat(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    root = tmp_path / "restart-dock"
    with LoopBackend.open(root, keychain_backend=keys) as first:
        create_task(first, "task-dock")
    with LoopBackend.open(root, keychain_backend=keys) as second:
        docked = second.dock_after_restart("task-dock")
        assert docked.status is TaskStatus.RECOVERY_BLOCKED
        assert docked.recovery_state == "RECOVERY_NOT_CONNECTED"
        assert len(second.store.task_events("task-dock")) == 2
    with LoopBackend.open(root, keychain_backend=keys) as third:
        still_docked = third.dock_after_restart("task-dock")
        assert still_docked.status is TaskStatus.RECOVERY_BLOCKED
        assert still_docked.recovery_state == "RECOVERY_NOT_CONNECTED"
        assert len(third.store.task_events("task-dock")) == 2
