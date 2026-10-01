from __future__ import annotations

from pathlib import Path

import pytest

from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.loop import AcceptanceSubmission, CompletionProposal, LoopBackend, TaskStatus
from sitina.loop.host import LoopHost
from sitina.loop.model import InputKind, TaskConflict
from sitina.memory.native import MemoryACL, MemoryRepository
from sitina.security.macos_keychain import MemoryKeychainBackend


def _memory_activations(home: Path) -> FeatureActivationRegistry:
    leases = CompatibilityLeaseRegistry(home)
    leases.register(RuntimeCompatibilityLease.build(
        process_id="b6-interim-09",
        binary_version="2.0.0",
        reader_capabilities=("memory-v1",),
        writer_capabilities=("memory-v1",),
        started_at="2026-07-18T00:00:00Z",
        lease_expires_at="2026-07-18T01:00:00Z",
        fencing_token=1,
    ))
    registry = FeatureActivationRegistry()
    registry.prepare(
        "memory_v1_write", required_reader_capabilities=("memory-v1",), leases=leases,
        now="2026-07-18T00:00:01Z", journal_position=1,
        journal_control_event={"schema": "RUNTIME_FEATURE_PREPARED_V1", "event_type": "runtime.feature-prepared", "feature": "memory_v1_write"},
    )
    registry.activate(
        "memory_v1_write", rollback_floor_version=2, journal_position=2,
        journal_control_event={"schema": "RUNTIME_FEATURE_ACTIVATED_V1", "event_type": "runtime.feature-activated", "feature": "memory_v1_write", "rollback_safe_after_first_write": True},
    )
    return registry


def _task(backend: LoopBackend, task_id: str, *, memory_view=None):
    return backend.create_task(
        task_id=task_id,
        session_id="session-b6-interim-09",
        task_kind="readonly",
        goal="continue after memory correction",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact-b6-interim-09",
        environment_ref="environment-b6-interim-09",
        capability_snapshot_id="capabilities-b6-interim-09",
        memory_view=memory_view,
    )


def _terminalize(backend: LoopBackend, task):
    task = backend.record_acceptance(
        task.task_id,
        AcceptanceSubmission(
            acceptance_id="acceptance-b6-interim-09",
            outcome_id="outcome-1",
            evidence_refs=("cas:evidence-b6-interim-09",),
            program_status="PASS", reviewer_status="PASS", delivery_verified=True,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref,
        ),
    )
    return backend.propose_terminal(
        task.task_id,
        CompletionProposal(
            proposal_id="proposal-b6-interim-09", terminal_status=TaskStatus.SUCCEEDED,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_received_input_seq=task.received_input_seq,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref, final_result={"result": "done"},
        ),
    )


def _accepted_memory(repository: MemoryRepository, *, memory_id: str = "memory-b6-correction") -> None:
    acl = MemoryACL(readers=("memory-agent", "reviewer-1"), writers=("memory-agent",), reviewers=("reviewer-1",))
    repository.create_candidate(
        memory_id=memory_id, scope="project_shared", owner_id="project/b6",
        namespace="project/b6/interim09", content="original reviewed fact",
        source_event_ids=(), source_run_ids=(), evidence_refs=(), confidence=0.9,
        sensitivity="low", valid_from="2026-09-11T00:00:00Z", expires_at=None,
        retention_policy="explicit-revocation", supersedes=(), acl=acl,
        actor="memory-agent", source_trust="derived", observed_at="2026-09-11T00:00:00Z",
    )
    repository.apply_memory_decision(
        decision_id="memory-decision-b6-correction-accept",
        source_closure={"task_id": "task-b6-interim-09", "source_hash": "a" * 64},
        candidate_actions=[{
            "memory_id": memory_id, "expected_status": "candidate",
            "to_status": "accepted", "reason_code": "review-approved",
        }],
        actor="reviewer-1", occurred_at="2026-09-11T00:00:01Z",
    )


def test_extraction_persisted_due_survives_reopen_and_claim_guard(tmp_path: Path) -> None:
    root = tmp_path / "due-reopen"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-due-1") as backend:
        task = _terminalize(backend, _task(backend, "task-due-reopen"))
        extraction = next(
            item for item in backend.pending_experience_obligations()
            if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
        )
        future = "2999-01-01T00:00:00Z"
        backend._append_experience_obligation_event(
            event_type="loop.experience-obligation-updated",
            payload={
                "schema": "SITINA_LOOP_EXPERIENCE_OBLIGATION_V1",
                "obligation_id": extraction["obligation_id"],
                "patch": {"next_due_at": future},
            },
            request_id="due-reopen-test",
        )
        assert not any(item["obligation_id"] == extraction["obligation_id"] for item in backend.pending_experience_obligations())
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-due-2") as reopened:
        assert not any(item["obligation_id"] == extraction["obligation_id"] for item in reopened.pending_experience_obligations())
        calls = []
        with pytest.raises(TaskConflict, match="not due"):
            reopened.process_experience_obligation(
                extraction["obligation_id"], request_id="due-reopen-dispatch",
                provider_profile="offline", provider_dispatch=lambda request: calls.append(request) or {"status": "FAILED"},
            )
        assert calls == []


def test_memory_correction_revalidates_original_view_and_reopens_guard(tmp_path: Path) -> None:
    root = tmp_path / "memory-correction"
    keys = MemoryKeychainBackend()
    repository = None
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-memory-correction") as backend:
        repository = MemoryRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        _accepted_memory(repository)
        view = backend.build_memory_view_from_repository(
            repository, memory_ids=("memory-b6-correction",), actor="reviewer-1",
            selection_reasons=("initial reviewed selection",),
        )
        task = _task(backend, "task-memory-correction", memory_view=view)
        backend.dock_waiting(
            task.task_id, status=TaskStatus.WAITING_INPUT,
            blocker_id="memory-view-revoked", reason="fresh correction required", evidence_refs=(),
        )
        repository.apply_memory_decision(
            decision_id="memory-decision-b6-correction-revoke",
            source_closure={"task_id": task.task_id, "source_hash": "b" * 64},
            candidate_actions=[{
                "memory_id": "memory-b6-correction", "expected_status": "accepted",
                "to_status": "revoked", "reason_code": "user-correction",
            }],
            actor="reviewer-1", occurred_at="2026-09-11T00:00:02Z",
        )
        with pytest.raises(TaskConflict, match="stale or revoked"):
            backend.assert_task_memory_view_actionable(task.task_id)
        backend.accept_input(task.task_id, input_id="correction-1", kind=InputKind.CORRECTION, body="that fact is no longer valid")
        handled = backend.handle_next_input(task.task_id, derive_effects_from_record=True)
        revalidated = backend.revalidate_task_memory_view_after_correction(
            task.task_id, correction_input_seq=handled.handled_input_seq,
        )
        assert revalidated.memory_view_ref == task.memory_view_ref
        assert revalidated.memory_view_hash == task.memory_view_hash
        assert revalidated.memory_view_exclusions[0]["memory_id"] == "memory-b6-correction"
        assert revalidated.acceptances == {}
        effective = backend.read_task_memory_view(task.task_id)
        assert effective["selected_memory_ids"] == []
        assert effective["excluded_memory_ids"] == ["memory-b6-correction"]
        backend.assert_task_memory_view_actionable(task.task_id)
        backend.accept_input(task.task_id, input_id="status-after-correction", kind=InputKind.STATUS, body="show status")
        backend.handle_next_input(task.task_id, derive_effects_from_record=True)
        backend.assert_task_memory_view_actionable(task.task_id)
        backend.accept_input(task.task_id, input_id="correction-2", kind=InputKind.CORRECTION, body="confirm the exclusion")
        handled_again = backend.handle_next_input(task.task_id, derive_effects_from_record=True)
        again = backend.revalidate_task_memory_view_after_correction(
            task.task_id, correction_input_seq=1 + 2,
        )
        assert again.memory_view_revalidation_input_seq == handled_again.handled_input_seq
        assert again.memory_view_exclusions[0]["memory_id"] == "memory-b6-correction"
        backend.assert_task_memory_view_actionable(task.task_id)
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-memory-correction-reopen") as reopened:
        assert reopened.read_task_memory_view("task-memory-correction")["excluded_memory_ids"] == ["memory-b6-correction"]
        reopened.assert_task_memory_view_actionable("task-memory-correction")


def test_same_host_correction_revalidation_wakes_waiting_task(tmp_path: Path) -> None:
    root = tmp_path / "host-correction"
    keys = MemoryKeychainBackend()
    repositories: list[MemoryRepository] = []

    def repository_factory(backend):
        repository = MemoryRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        repositories.append(repository)
        return repository

    host = LoopHost(
        root, keychain_backend=keys, memory_repository_factory=repository_factory,
        memory_actor="reviewer-1", descriptor_context={
            "provider_identity": "fixture-provider", "environment_ref": "fixture-environment",
            "capability_snapshot_id": "fixture-capabilities", "software_identity": "fixture-software",
            "config_identity": "fixture-config",
        },
    ).start()
    try:
        repository = repositories[-1]
        _accepted_memory(repository, memory_id="memory-b6-host-correction")
        response = host._handle_command({
            "command": "submit", "task_id": "task-host-correction", "submission_id": "submission-host-correction",
            "session_id": "session-host-correction", "task_kind": "readonly",
            "goal": "use the reviewed fact", "workspace": str(root), "provider_profile": "offline",
            "authorization": "host", "provider_identity": "fixture-provider", "environment_ref": "fixture-environment",
            "capability_snapshot_id": "fixture-capabilities", "software_identity": "fixture-software",
            "config_identity": "fixture-config", "memory_ids": ["memory-b6-host-correction"],
            "memory_selection_reasons": ["same project"],
        })
        assert response["disposition"] == "created"
        task = host.backend.get_task("task-host-correction")
        host.backend.dock_waiting(
            task.task_id, status=TaskStatus.WAITING_INPUT,
            blocker_id="memory-view-revoked", reason="fresh correction required", evidence_refs=(),
        )
        repository.apply_memory_decision(
            decision_id="memory-decision-b6-host-revoke",
            source_closure={"task_id": task.task_id, "source_hash": "c" * 64},
            candidate_actions=[{
                "memory_id": "memory-b6-host-correction", "expected_status": "accepted",
                "to_status": "revoked", "reason_code": "user-correction",
            }],
            actor="reviewer-1", occurred_at="2026-09-11T00:00:03Z",
        )
        host.runner_executor = lambda _backend, task_id, _task: setattr(host, "_test_woken_task", task_id)
        reply = host.control._dispatch({
            "command": "input", "task_id": task.task_id, "input_id": "host-correction-1",
            "kind": "CORRECTION", "body": "replace the revoked fact",
        })
        assert reply["status"] == "accepted"
        deadline = __import__("time").monotonic() + 3
        while __import__("time").monotonic() < deadline and not hasattr(host, "_test_woken_task"):
            __import__("time").sleep(0.02)
        assert getattr(host, "_test_woken_task", None) == task.task_id
        assert host.backend.read_task_memory_view(task.task_id)["excluded_memory_ids"] == ["memory-b6-host-correction"]
    finally:
        host.begin_drain()
        host.wait_for_quiescence(5)
        host.close()


def test_cancel_finishes_when_memory_authority_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "cancel-memory-unavailable"
    host = LoopHost(root, keychain_backend=MemoryKeychainBackend()).start()
    try:
        task = host.backend.create_task(
            task_id="task-cancel-memory-unavailable",
            session_id="session-cancel-memory-unavailable",
            task_kind="readonly",
            goal="cancel despite unavailable memory authority",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:artifact-cancel-memory-unavailable",
            environment_ref="environment-cancel-memory-unavailable",
            capability_snapshot_id="capabilities-cancel-memory-unavailable",
            memory_view={
                "selected_memory_ids": ["memory-unavailable"],
                "selected_memory_versions": {"memory-unavailable": 1},
                "selection_reasons": ["focused cancellation boundary"],
                "entries": [{"memory_id": "memory-unavailable", "status": "accepted", "text": "opaque"}],
            },
        )
        host.backend.dock_waiting(
            task.task_id, status=TaskStatus.WAITING_INPUT,
            blocker_id="memory-view-revoked", reason="memory authority unavailable", evidence_refs=(),
        )
        # Simulate a native authority that has not been connected in this
        # process.  CANCEL must still use the existing control/safe-terminal
        # path; the memory helper is not allowed to become a prerequisite.
        host.backend._memory_repository = None
        response = host.control._dispatch({
            "command": "input", "task_id": task.task_id, "input_id": "cancel-memory-unavailable",
            "kind": "CANCEL", "body": "cancel now",
        })
        assert response["status"] == "accepted"
        deadline = __import__("time").monotonic() + 3
        final = None
        while __import__("time").monotonic() < deadline:
            final = host.backend.get_task(task.task_id)
            if final.is_terminal:
                break
            __import__("time").sleep(0.02)
        assert final is not None and final.status is TaskStatus.CANCELLED
    finally:
        host.begin_drain()
        host.wait_for_quiescence(5)
        host.close()
