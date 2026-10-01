from __future__ import annotations

from pathlib import Path
import time

import pytest

from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.loop import AcceptanceSubmission, CompletionProposal, LoopBackend, TaskStatus
from sitina.loop.host import BoundedExperienceProviderFactory, BoundedExperienceReviewFactory, LoopHost
from sitina.loop.model import TaskConflict
from sitina.memory.native import EpisodeRepository, MemoryACL, MemoryRepository
from sitina.security.macos_keychain import MemoryKeychainBackend


def _memory_activations(home: Path) -> FeatureActivationRegistry:
    leases = CompatibilityLeaseRegistry(home)
    leases.register(RuntimeCompatibilityLease.build(
        process_id="b6-loop-episode-test",
        binary_version="2.0.0",
        reader_capabilities=("memory-v1",),
        writer_capabilities=("memory-v1",),
        started_at="2026-07-18T00:00:00Z",
        lease_expires_at="2026-07-18T01:00:00Z",
        fencing_token=1,
    ))
    registry = FeatureActivationRegistry()
    registry.prepare(
        "memory_v1_write",
        required_reader_capabilities=("memory-v1",),
        leases=leases,
        now="2026-07-18T00:00:01Z",
        journal_position=1,
        journal_control_event={"schema": "RUNTIME_FEATURE_PREPARED_V1", "event_type": "runtime.feature-prepared", "feature": "memory_v1_write"},
    )
    registry.activate(
        "memory_v1_write",
        rollback_floor_version=2,
        journal_position=2,
        journal_control_event={"schema": "RUNTIME_FEATURE_ACTIVATED_V1", "event_type": "runtime.feature-activated", "feature": "memory_v1_write", "rollback_safe_after_first_write": True},
    )
    return registry


def _task(backend: LoopBackend, task_id: str):
    return backend.create_task(
        task_id=task_id,
        session_id="session-b6",
        task_kind="readonly",
        goal="produce a terminal source closure",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact-v1",
        environment_ref="environment-v1",
        capability_snapshot_id="capabilities-v1",
    )


def test_terminal_reconciles_exact_obligations_from_envelope_and_reopens(tmp_path: Path) -> None:
    root = tmp_path / "loop"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6") as backend:
        task = _task(backend, "task-b6-terminal")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-1",
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
            ),
        )
        backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-1",
                terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref,
                final_result={"result": "ok"},
            ),
        )
        pending = backend.pending_experience_obligations()
        assert {item["obligation_type"] for item in pending} == {"EPISODE", "EXPERIENCE_EXTRACTION"}
        assert all(item["source_closure"]["actual_envelope_event_id"].startswith("loop-event-") for item in pending)
        assert all(item["source_closure"]["terminal_event_id"].startswith("task-terminal-") for item in pending)
        assert all(item["source_closure"]["run_instance_id"] == "run-b6" for item in pending)
        episode_obligation = next(item for item in pending if item["obligation_type"] == "EPISODE")
        episodes = EpisodeRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        settled_episode = backend.materialize_episode_obligation(
            str(episode_obligation["obligation_id"]),
            episode_repository=episodes,
        )
        assert settled_episode["state"] == "EPISODE_SETTLED"
        created_count = len(
            [event for event in backend.store.journal.iter_events(0) if event.event_type == "loop.experience-obligation-created"]
        )
        assert created_count == 2
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6-reopen") as reopened:
        pending = reopened.pending_experience_obligations()
        assert len(pending) == 1
        assert pending[0]["obligation_type"] == "EXPERIENCE_EXTRACTION"
        assert len(
            [event for event in reopened.store.journal.iter_events(0) if event.event_type == "loop.experience-obligation-created"]
        ) == 2


def test_new_task_memory_view_is_fixed_and_action_guard_fails_closed(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "memory-view", keychain_backend=MemoryKeychainBackend()) as backend:
        task = backend.create_task(
            task_id="task-memory-view",
            session_id="session-b6",
            task_kind="readonly",
            goal="use the reviewed memory",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:artifact-v1",
            environment_ref="environment-v1",
            capability_snapshot_id="capabilities-v1",
            memory_view={
                "selected_memory_ids": ["memory-a"],
                "selected_memory_versions": {"memory-a": 3},
                "selection_reasons": ["same project and acceptance scope"],
                "entries": [{"memory_id": "memory-a", "status": "accepted", "text": "untrusted fact"}],
            },
        )
        assert task.memory_view_ids == ("memory-a",)
        assert backend.read_task_memory_view(task.task_id)["schema"] == "SITINA_UNTRUSTED_MEMORY_DATA_V1"
        with pytest.raises(TaskConflict, match="native authority"):
            backend.assert_task_memory_view_actionable(task.task_id)
    with LoopBackend.open(tmp_path / "memory-view-revoked", keychain_backend=MemoryKeychainBackend()) as backend:
        task = backend.create_task(
            task_id="task-memory-view-revoked",
            session_id="session-b6",
            task_kind="readonly",
            goal="do not use revoked memory",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:artifact-v1",
            environment_ref="environment-v1",
            capability_snapshot_id="capabilities-v1",
            memory_view={
                "selected_memory_ids": ["memory-a"],
                "selected_memory_versions": {"memory-a": 3},
                "selection_reasons": ["reviewed"],
                "entries": [{"memory_id": "memory-a", "status": "revoked"}],
            },
        )
        with pytest.raises(TaskConflict, match="native authority"):
            backend.assert_task_memory_view_actionable(task.task_id)


def test_experience_provider_dispatch_is_durable_and_unknown_is_not_resent(tmp_path: Path) -> None:
    root = tmp_path / "provider-boundary"
    with LoopBackend.open(root, keychain_backend=MemoryKeychainBackend(), run_instance_id="run-b6") as backend:
        task = _task(backend, "task-provider-boundary")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-1",
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
            ),
        )
        backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-1",
                terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref,
                final_result={"result": "ok"},
            ),
        )
        obligations = backend.pending_experience_obligations()
        extraction = next(item for item in obligations if item["obligation_type"] == "EXPERIENCE_EXTRACTION")
        calls: list[dict[str, object]] = []

        def scripted(request):
            calls.append(dict(request))
            return {
                "status": "SUCCEEDED",
                "manifest": {
                    "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                    "batch_id": "batch-1",
                    "source_closure_hash": request["source_closure"]["closure_hash"],
                    "status": "COMPLETE",
                    "candidates": [
                        {"candidate_id": "candidate-a", "revision": "rev-a", "content": "lesson a"},
                        {"candidate_id": "candidate-b", "revision": "rev-b", "content": "lesson b"},
                    ],
                },
            }

        result = backend.process_experience_obligation(
            str(extraction["obligation_id"]),
            request_id="experience-request-1",
            provider_profile="deepseek-normal-scripted",
            provider_dispatch=scripted,
        )
        assert result["state"] == "MANIFEST_RECORDED"
        assert calls and calls[0]["obligation_id"] == extraction["obligation_id"]
        assert backend.get_task(task.task_id).terminal_event_id
        memory_repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        candidate_memory_ids = backend.materialize_experience_candidates(
            str(extraction["obligation_id"]),
            memory_repository=memory_repository,
            actor="memory-agent",
            acl=MemoryACL(
                readers=("memory-agent", "reviewer-1"),
                writers=("memory-agent",),
                reviewers=("reviewer-1",),
            ),
            owner_id="project/example",
            namespace="project/example/b6",
        )
        assert set(candidate_memory_ids) == {"candidate-a", "candidate-b"}
        assert all(memory_repository.verify_provenance(memory_id)["verified"] for memory_id in candidate_memory_ids.values())
        review_calls: list[dict[str, object]] = []

        def scripted_review(request):
            review_calls.append(dict(request))
            return {"disposition": "PUBLISHED" if request["candidate_id"] == "candidate-a" else "REJECTED"}

        after_a = backend.process_experience_candidate_review(
            str(extraction["obligation_id"]),
            request_id="review-request-a",
            provider_profile="deepseek-normal-scripted",
            review_dispatch=scripted_review,
            memory_repository=memory_repository,
            memory_actor="reviewer-1",
        )
        assert after_a["state"] == "CANDIDATE_REVIEW"
        after_b = backend.process_experience_candidate_review(
            str(extraction["obligation_id"]),
            request_id="review-request-b",
            provider_profile="deepseek-normal-scripted",
            review_dispatch=scripted_review,
            memory_repository=memory_repository,
            memory_actor="reviewer-1",
        )
        assert after_b["state"] == "SETTLED"
        assert {item["candidate_id"] for item in review_calls} == {"candidate-a", "candidate-b"}
        assert [item.memory_id for item in memory_repository.retrieve(actor="reviewer-1")] == [candidate_memory_ids["candidate-a"]]

        episode = next(item for item in obligations if item["obligation_type"] == "EPISODE")

        def send_then_crash(_request):
            raise RuntimeError("transport-return-unknown")

        with pytest.raises(RuntimeError, match="transport-return-unknown"):
            backend.process_experience_obligation(
                str(episode["obligation_id"]),
                request_id="experience-request-unknown",
                provider_profile="deepseek-normal-scripted",
                provider_dispatch=send_then_crash,
            )
        unknown = backend._experience_obligation_projection()[str(episode["obligation_id"])]
        assert unknown["state"] == "UNKNOWN"
        with pytest.raises(Exception):
            backend.process_experience_obligation(
                str(episode["obligation_id"]),
                request_id="experience-request-unknown-2",
                provider_profile="deepseek-normal-scripted",
                provider_dispatch=scripted,
            )


def test_host_scripted_experience_factory_materializes_and_commits_native_candidates(tmp_path: Path) -> None:
    root = tmp_path / "host-experience"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6-host") as backend:
        task = _task(backend, "task-host-experience")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-host",
                outcome_id="outcome-1",
                evidence_refs=("cas:evidence-host",),
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
            ),
        )
        backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-host",
                terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref,
                final_result={"result": "host"},
            ),
        )

    repositories: list[MemoryRepository] = []
    provider_calls: list[dict[str, object]] = []
    review_calls: list[dict[str, object]] = []

    def repository_factory(backend):
        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        repositories.append(repository)
        return repository

    def provider_factory(request):
        provider_calls.append(dict(request))
        return {
            "status": "SUCCEEDED",
            "manifest": {
                "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                "batch_id": "host-batch-1",
                "source_closure_hash": request["source_closure"]["closure_hash"],
                "status": "COMPLETE",
                "candidates": [
                    {"candidate_id": "host-candidate-a", "revision": "host-rev-a", "content": "host lesson a"},
                    {"candidate_id": "host-candidate-b", "revision": "host-rev-b", "content": "host lesson b"},
                ],
            },
        }

    def review_factory(request):
        review_calls.append(dict(request))
        return {"disposition": "PUBLISHED" if request["candidate_id"] == "host-candidate-a" else "REJECTED"}

    host = LoopHost(
        root,
        keychain_backend=keys,
        experience_provider_factory=provider_factory,
        experience_provider_profile="deepseek-normal-scripted",
        experience_review_factory=review_factory,
        memory_repository_factory=repository_factory,
        memory_actor="reviewer-1",
        memory_materializer_actor="memory-agent",
        memory_candidate_acl=MemoryACL(
            readers=("memory-agent", "reviewer-1"),
            writers=("memory-agent",),
            reviewers=("reviewer-1",),
        ),
        memory_candidate_owner_id="project/host",
        memory_candidate_namespace="project/host/b6",
        publication_obligation_poll_interval=0.02,
    ).start()
    try:
        deadline = time.monotonic() + 10
        extraction = None
        while time.monotonic() < deadline:
            obligations = host.backend._experience_obligation_projection()
            extraction = next(
                (
                    item for item in obligations.values()
                    if item.get("obligation_type") == "EXPERIENCE_EXTRACTION"
                ),
                None,
            )
            if extraction is not None and extraction.get("state") == "SETTLED":
                break
            time.sleep(0.02)
        assert extraction is not None
        assert extraction["state"] == "SETTLED"
        assert len(provider_calls) == 1
        assert {item["candidate_id"] for item in review_calls} == {"host-candidate-a", "host-candidate-b"}
        assert repositories
        assert [item.memory_id for item in repositories[-1].retrieve(actor="reviewer-1")] == [
            extraction["candidate_memory_ids"]["host-candidate-a"]
        ]
    finally:
        host.begin_drain()
        host.wait_for_quiescence(10)
        host.close()


def test_host_auto_selects_and_fixes_authoritative_native_memory_view(tmp_path: Path) -> None:
    root = tmp_path / "host-memory-selection"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6-memory") as backend:
        task = _task(backend, "task-memory-source")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-memory",
                outcome_id="outcome-1",
                evidence_refs=("cas:evidence-memory",),
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
            ),
        )
        backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-memory",
                terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref,
                final_result={"result": "memory-source"},
            ),
        )
        events = backend.store.task_events(task.task_id)
        terminal = next(event for event in events if event.event_type == "loop.task-terminated")
        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        repository.create_candidate(
            memory_id="memory-auto-selected",
            scope="project_shared",
            owner_id="project/host",
            namespace="project/host/b6",
            content="Use UTC for report timestamps.",
            source_event_ids=(terminal.event_id,),
            source_run_ids=(task.run_instance_id,),
            evidence_refs=(task.goal_ref, terminal.payload["result_ref"]),
            confidence=0.9,
            sensitivity="low",
            valid_from=terminal.occurred_at,
            expires_at=None,
            retention_policy="until-superseded",
            supersedes=(),
            acl=MemoryACL(
                readers=("memory-agent", "reviewer-1"),
                writers=("memory-agent",),
                reviewers=("reviewer-1",),
            ),
            actor="memory-agent",
            source_trust="derived",
            observed_at=terminal.occurred_at,
        )
        repository.apply_memory_decision(
            decision_id="memory-decision-auto-select",
            source_closure={
                "terminal_event_id": task.terminal_event_id,
                "actual_envelope_event_id": terminal.event_id,
                "run_instance_id": task.run_instance_id,
            },
            candidate_actions=[{
                "memory_id": "memory-auto-selected",
                "expected_status": "candidate",
                "to_status": "accepted",
                "reason_code": "review-approved",
            }],
            actor="reviewer-1",
            occurred_at=terminal.occurred_at,
        )

    repositories: list[MemoryRepository] = []

    def repository_factory(backend):
        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        repositories.append(repository)
        return repository

    def selector(_backend, payload):
        assert payload.get("memory_ids") in (None, [])
        return tuple(item["root_id"] for item in repositories[-1].active_roots())

    host = LoopHost(
        root,
        keychain_backend=keys,
        memory_repository_factory=repository_factory,
        memory_actor="reviewer-1",
        memory_selector=selector,
        descriptor_context={
            "provider_identity": "fixture-provider",
            "environment_ref": "fixture-environment",
            "capability_snapshot_id": "fixture-capabilities",
            "software_identity": "fixture-software",
            "config_identity": "fixture-config",
        },
        publication_obligation_poll_interval=0.02,
    ).start()
    try:
        response = host._handle_command({
            "command": "submit",
            "task_id": "task-memory-consumer",
            "submission_id": "submission-memory-consumer",
            "session_id": "session-memory-consumer",
            "task_kind": "readonly",
            "goal": "Use the reviewed UTC memory.",
            "workspace": str(root),
            "provider_profile": "deepseek-normal-scripted",
            "authorization": "host",
            "provider_identity": "fixture-provider",
            "environment_ref": "fixture-environment",
            "capability_snapshot_id": "fixture-capabilities",
            "software_identity": "fixture-software",
            "config_identity": "fixture-config",
            "memory_selection_reasons": ["same project and acceptance scope"],
        })
        assert response["disposition"] == "created"
        task = host.backend.get_task("task-memory-consumer")
        assert task.memory_view_ids == ("memory-auto-selected",)
        assert host.backend.read_task_memory_view(task.task_id)["entries"][0]["text"] == "Use UTC for report timestamps."
        # Completion can cite and read the selected native view without
        # promoting recalled data into a user requirement.
        from sitina.loop.context_window import LoopContextIndex, LoopHistoryQuery
        index = LoopContextIndex(host.backend.store, task.task_id)
        index.refresh()
        sources = [entry for entry in index.entries if entry.kind == "memory_view"]
        assert len(sources) == 1
        assert sources[0].internal_cas_ref == task.memory_view_ref
        assert sources[0].content_hash == task.memory_view_hash
        assert sources[0] not in index.requirement_entries()
        page = LoopHistoryQuery(index, max_page_bytes=8192).read(
            source_ref=sources[0].source_ref, max_bytes=8192,
        )
        assert page["status"] == "OK" and page["has_more"] is False
        assert page["kind"] == "memory_view"
        assert "Use UTC for report timestamps." in page["readable_text"]
        host.backend.assert_task_memory_view_actionable(task.task_id)
    finally:
        host.begin_drain()
        host.wait_for_quiescence(10)
        host.close()


def test_bounded_experience_factories_project_public_results_without_reasoning() -> None:
    calls: list[Mapping[str, object]] = []

    def transport(request):
        calls.append(dict(request))
        return {
            "status": "SUCCEEDED",
            "manifest": {
                "schema": "SITINA_EXPERIENCE_MANIFEST_V1", "status": "COMPLETE",
                "batch_id": "bounded-batch", "source_closure_hash": "c" * 64,
                "candidates": [{"candidate_id": "candidate-1", "revision": "r1", "content": "lesson", "reasoning_content": "private"}],
                "reasoning_content": "private manifest reasoning",
            },
            "reasoning_content": "private provider reasoning must not be exposed",
            "raw_response": "private envelope",
        }

    provider = BoundedExperienceProviderFactory(transport, max_request_bytes=2048, max_result_bytes=2048)
    result = provider({
        "schema": "SITINA_EXPERIENCE_PROVIDER_REQUEST_V1",
        "request_id": "bounded-provider-request",
        "provider_profile": "deepseek-normal-scripted",
        "obligation_id": "obligation-1",
        "source_closure": {"closure_hash": "c" * 64},
    })
    assert result["status"] == "SUCCEEDED"
    assert "reasoning_content" not in result and "raw_response" not in result
    assert "reasoning_content" not in result["manifest"] and "reasoning_content" not in result["manifest"]["candidates"][0]
    assert len(calls) == 1

    review = BoundedExperienceReviewFactory(
        lambda _request: {
            "disposition": "PUBLISHED",
            "reason": "approved",
            "reasoning_content": "private review rationale",
        },
        max_request_bytes=2048,
        max_result_bytes=2048,
    )
    reviewed = review({
        "schema": "SITINA_EXPERIENCE_REVIEW_REQUEST_V1",
        "request_id": "bounded-review-request",
        "candidate_id": "candidate-1",
        "candidate_revision": "revision-1",
    })
    assert reviewed == {"disposition": "PUBLISHED", "reason": "approved"}


def test_candidate_review_binding_rejects_legacy_mutation_after_dispatch(tmp_path: Path) -> None:
    root = tmp_path / "review-binding"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6-binding") as backend:
        task = _task(backend, "task-review-binding")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-binding",
                outcome_id="outcome-1",
                evidence_refs=("cas:evidence-binding",),
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
            ),
        )
        backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-binding",
                terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref,
                final_result={"result": "binding"},
            ),
        )
        extraction = next(
            item for item in backend.pending_experience_obligations()
            if item.get("obligation_type") == "EXPERIENCE_EXTRACTION"
        )
        backend.process_experience_obligation(
            str(extraction["obligation_id"]),
            request_id="binding-provider-request",
            provider_profile="deepseek-normal-scripted",
            provider_dispatch=lambda request: {
                "status": "SUCCEEDED",
                "manifest": {
                    "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                    "batch_id": "binding-batch",
                    "source_closure_hash": request["source_closure"]["closure_hash"],
                    "status": "COMPLETE",
                    "candidates": [{"candidate_id": "binding-candidate", "revision": "binding-rev", "content": "binding lesson"}],
                },
            },
        )
        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        candidate_memory_ids = backend.materialize_experience_candidates(
            str(extraction["obligation_id"]),
            memory_repository=repository,
            actor="memory-agent",
            acl=MemoryACL(
                readers=("memory-agent", "reviewer-1"),
                writers=("memory-agent",),
                reviewers=("reviewer-1",),
            ),
            owner_id="project/binding",
            namespace="project/binding/b6",
        )

        def stale_review(request):
            repository.transition(
                candidate_memory_ids["binding-candidate"], "accepted", actor="reviewer-1",
                occurred_at="2026-07-18T00:01:00Z", reason_code="legacy-race",
            )
            return {"disposition": "PUBLISHED"}

        result = backend.process_experience_candidate_review(
            str(extraction["obligation_id"]),
            request_id="binding-review-request",
            provider_profile="deepseek-normal-scripted",
            review_dispatch=stale_review,
            memory_repository=repository,
            memory_actor="reviewer-1",
        )
        assert result["candidate_dispositions"]["binding-candidate"]["disposition"] == "UNKNOWN"
        assert not any(event.event_type == "memory.decision-committed" for event in backend.store.journal.iter_events(0))
