from __future__ import annotations

from pathlib import Path

import pytest
import sitina.loop.coordinator as coordinator_module

from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.loop import (
    AcceptanceSubmission,
    CompletionProposal,
    InputKind,
    LoopBackend,
    TaskStatus,
)
from sitina.loop.model import PersistenceFenced
from sitina.loop.host import BoundedExperienceProviderFactory
from sitina.memory.native import MemoryACL, MemoryRepository
from sitina.security.macos_keychain import MemoryKeychainBackend


def _memory_activations(home: Path) -> FeatureActivationRegistry:
    leases = CompatibilityLeaseRegistry(home)
    leases.register(RuntimeCompatibilityLease.build(
        process_id="b7-memory-evidence",
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
        journal_control_event={
            "schema": "RUNTIME_FEATURE_PREPARED_V1",
            "event_type": "runtime.feature-prepared",
            "feature": "memory_v1_write",
        },
    )
    registry.activate(
        "memory_v1_write",
        rollback_floor_version=2,
        journal_position=2,
        journal_control_event={
            "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
            "event_type": "runtime.feature-activated",
            "feature": "memory_v1_write",
            "rollback_safe_after_first_write": True,
        },
    )
    return registry


def _finish_task(
    backend: LoopBackend,
    task_id: str,
    *,
    inputs: tuple[tuple[str, InputKind, str], ...] = (),
) -> str:
    task = backend.create_task(
        task_id=task_id,
        session_id="session-b7-memory",
        task_kind="readonly",
        goal="produce a bounded experience source",
        required_outcome_ids=("outcome-1",),
        artifact_ref=f"artifact-{task_id}",
        environment_ref="environment-b7-memory",
        capability_snapshot_id="capabilities-b7-memory",
    )
    for input_id, kind, body in inputs:
        backend.accept_input(task_id, input_id=input_id, kind=kind, body=body)
        task = backend.handle_next_input(task_id, derive_effects_from_record=True)
    task = backend.record_acceptance(
        task_id,
        AcceptanceSubmission(
            acceptance_id=f"acceptance-{task_id}",
            outcome_id="outcome-1",
            evidence_refs=(f"evidence-{task_id}",),
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
        task_id,
        CompletionProposal(
            proposal_id=f"proposal-{task_id}",
            terminal_status=TaskStatus.SUCCEEDED,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_received_input_seq=task.received_input_seq,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref,
            final_result={"result": "bounded"},
        ),
    )
    return next(
        str(item["obligation_id"])
        for item in backend.pending_experience_obligations()
        if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
        and item["task_id"] == task_id
    )


def _empty(request: dict) -> dict:
    return {
        "status": "SUCCEEDED",
        "manifest": {
            "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
            "batch_id": "batch-b7-memory",
            "source_closure_hash": request["source_closure"]["closure_hash"],
            "status": "EMPTY",
            "candidates": [],
        },
    }


def _seed_review_candidate(
    backend: LoopBackend,
    root: Path,
    task_id: str,
) -> tuple[str, MemoryRepository, str, str]:
    obligation_id = _finish_task(
        backend,
        task_id,
        inputs=(("correction-1", InputKind.CORRECTION, "correct this task only"),),
    )
    extraction_requests: list[dict] = []
    backend.process_experience_obligation(
        obligation_id,
        request_id=f"extract-{task_id}",
        provider_profile="deepseek-scripted",
        provider_dispatch=lambda request: extraction_requests.append(request) or {
            "status": "SUCCEEDED",
            "manifest": {
                "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                "batch_id": f"batch-{task_id}",
                "source_closure_hash": request["source_closure"]["closure_hash"],
                "status": "COMPLETE",
                "candidates": [{
                    "candidate_id": f"candidate-{task_id}",
                    "revision": f"revision-{task_id}",
                    "content": "Keep this task-scoped procedure.",
                    "applicability_scope": "task_specific",
                    "applicability_condition": "Only for this task's correction.",
                    "evidence_input_sequences": [1],
                }],
            },
        },
    )
    repository = MemoryRepository(
        backend.store.journal,
        backend.store.cas,
        backend.context.provider,
        feature_activations=_memory_activations(root),
    )
    candidate_id = f"candidate-{task_id}"
    memory_ids = backend.materialize_experience_candidates(
        obligation_id,
        memory_repository=repository,
        actor="memory-agent",
        acl=MemoryACL(
            readers=("memory-agent",),
            writers=("memory-agent",),
            reviewers=("memory-agent",),
        ),
        owner_id="project/b7-memory",
        namespace=f"project/b7-memory/{task_id}",
    )
    input_evidence = extraction_requests[0]["source_evidence"]["input_evidence"]
    body_ref = str(input_evidence["records"][0]["body_ref"])
    return obligation_id, repository, str(memory_ids[candidate_id]), body_ref


def test_experience_input_evidence_is_ordered_and_condition_survives_memory_materialization(
    tmp_path: Path,
) -> None:
    root = tmp_path / "ordered"
    with LoopBackend.open(root, keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _finish_task(
            backend,
            "task-b7-ordered",
            inputs=(
                ("message-1", InputKind.MESSAGE, "original request"),
                ("correction-1", InputKind.CORRECTION, "only for this task's correction"),
            ),
        )
        requests: list[dict] = []

        def provider(request: dict) -> dict:
            requests.append(request)
            return {
                "status": "SUCCEEDED",
                "manifest": {
                    "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                    "batch_id": "batch-b7-ordered",
                    "source_closure_hash": request["source_closure"]["closure_hash"],
                    "status": "COMPLETE",
                    "candidates": [{
                        "candidate_id": "candidate-b7-ordered",
                        "revision": "revision-b7-ordered",
                        "content": "Use the bounded procedure for this task.",
                        "applicability_scope": "task_specific",
                        "applicability_condition": "Only for this task's correction.",
                        "evidence_input_sequences": [2],
                    }],
                },
            }

        backend.process_experience_obligation(
            obligation_id,
            request_id="extract-b7-ordered",
            provider_profile="deepseek-scripted",
            provider_dispatch=provider,
        )
        evidence = requests[0]["source_evidence"]["input_evidence"]
        assert [item["sequence"] for item in evidence["records"]] == [1, 2]
        assert evidence["semantic_input_sequences"] == [1, 2]
        assert [item["body"] for item in evidence["records"]] == [
            "original request", "only for this task's correction"
        ]
        review_evidence = backend._verified_experience_source_evidence(
            backend._experience_obligation_projection()[obligation_id],
            candidate_id="candidate-b7-ordered",
        )
        assert review_evidence["input_evidence"] == evidence

        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        memory_ids = backend.materialize_experience_candidates(
            obligation_id,
            memory_repository=repository,
            actor="memory-agent",
            acl=MemoryACL(
                readers=("memory-agent",),
                writers=("memory-agent",),
                reviewers=("memory-agent",),
            ),
            owner_id="project/b7-memory",
            namespace="project/b7-memory/evidence",
        )
        document, content = repository.get(
            memory_ids["candidate-b7-ordered"],
            actor="memory-agent",
            include_content=True,
        )
        assert document.status == "candidate"
        assert "Applicability condition: Only for this task's correction." in str(content)


def test_goal_only_candidate_accepts_empty_input_citations(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "goal-only", keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _finish_task(backend, "task-b7-goal-only")
        requests: list[dict] = []
        backend.process_experience_obligation(
            obligation_id,
            request_id="extract-b7-goal-only",
            provider_profile="deepseek-scripted",
            provider_dispatch=lambda request: requests.append(request) or {
                "status": "SUCCEEDED",
                "manifest": {
                    "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                    "batch_id": "batch-b7-goal-only",
                    "source_closure_hash": request["source_closure"]["closure_hash"],
                    "status": "COMPLETE",
                    "candidates": [{
                        "candidate_id": "candidate-b7-goal-only",
                        "revision": "revision-b7-goal-only",
                        "content": "The original goal/result supports this bounded lesson.",
                        "applicability_scope": "reusable",
                        "evidence_input_sequences": [],
                    }],
                },
            },
        )
        assert requests[0]["source_evidence"]["input_evidence"]["semantic_input_sequences"] == []


def test_control_only_or_oversized_input_never_becomes_provider_evidence(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "invalid", keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _finish_task(
            backend,
            "task-b7-control",
            inputs=(("status-1", InputKind.STATUS, "status only"),),
        )
        provider_calls: list[dict] = []
        with pytest.raises(ValueError, match="control-only"):
            backend.process_experience_obligation(
                obligation_id,
                request_id="extract-b7-control",
                provider_profile="deepseek-scripted",
                provider_dispatch=lambda request: provider_calls.append(request) or {
                    "status": "SUCCEEDED",
                    "manifest": {
                        "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                        "batch_id": "batch-b7-control",
                        "source_closure_hash": request["source_closure"]["closure_hash"],
                        "status": "COMPLETE",
                        "candidates": [{
                            "candidate_id": "candidate-b7-control",
                            "revision": "revision-b7-control",
                            "content": "invalid",
                            "applicability_scope": "reusable",
                            "evidence_input_sequences": [1],
                        }],
                    },
                },
            )
        assert len(provider_calls) == 1
        failure = backend._experience_obligation_projection()[obligation_id]["validation_failure"]
        assert failure["request_id"] == "extract-b7-control"
        assert failure["attempt_count"] == 1
        assert failure["stage"] == "CANDIDATE_INPUT_EVIDENCE"
        assert failure["candidate_index"] == 0
        assert failure["reason_code"] == "INPUT_EVIDENCE_UNVERIFIED"
        assert failure["detail"] == "experience manifest candidate cites an unverified or control-only input"

    with LoopBackend.open(tmp_path / "oversized", keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _finish_task(
            backend,
            "task-b7-oversized",
            inputs=(("message-large", InputKind.MESSAGE, "x" * (16 * 1024 + 1)),),
        )
        provider_calls: list[dict] = []
        with pytest.raises(PersistenceFenced, match="bounded budget"):
            backend.process_experience_obligation(
                obligation_id,
                request_id="extract-b7-oversized",
                provider_profile="deepseek-scripted",
                provider_dispatch=lambda request: provider_calls.append(request) or _empty(request),
            )
        assert provider_calls == []
        projection = backend._experience_obligation_projection()[obligation_id]
        assert projection["provider_dispatch_facts"]["provider_send_status"] == "not_sent"


def test_bounded_adapter_preserves_applicability_fields_through_materialization(tmp_path: Path) -> None:
    root = tmp_path / "adapter"
    with LoopBackend.open(root, keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _finish_task(
            backend,
            "task-b7-adapter",
            inputs=(("correction-1", InputKind.CORRECTION, "correct this task only"),),
        )

        def transport(request: dict) -> dict:
            return {
                "status": "SUCCEEDED",
                "reasoning_content": "private reasoning must not cross the adapter",
                "unrecognized": "drop this field",
                "manifest": {
                    "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                    "batch_id": "batch-b7-adapter",
                    "source_closure_hash": request["source_closure"]["closure_hash"],
                    "status": "COMPLETE",
                    "candidates": [{
                        "candidate_id": "candidate-b7-adapter",
                        "revision": "revision-b7-adapter",
                        "content": "Keep this task-scoped procedure.",
                        "applicability_scope": "task_specific",
                        "applicability_condition": "Only for this task's correction.",
                        "evidence_input_sequences": [1],
                        "unknown_candidate_field": "drop this too",
                    }],
                },
            }

        provider = BoundedExperienceProviderFactory(transport)
        backend.process_experience_obligation(
            obligation_id,
            request_id="extract-b7-adapter",
            provider_profile="deepseek-scripted",
            provider_dispatch=provider,
        )
        obligation = backend._experience_obligation_projection()[obligation_id]
        manifest = backend.store.read_json(
            str(obligation["manifest_ref"]),
            expected_hash=str(obligation["manifest_hash"]),
        )
        candidate = manifest["candidates"][0]
        assert candidate["applicability_scope"] == "task_specific"
        assert candidate["applicability_condition"] == "Only for this task's correction."
        assert candidate["evidence_input_sequences"] == [1]
        assert "unknown_candidate_field" not in candidate
        result = backend.store.read_json(
            str(obligation["result_ref"]),
            expected_hash=str(obligation["result_hash"]),
        )
        assert "reasoning_content" not in result
        assert "unrecognized" not in result

        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        memory_ids = backend.materialize_experience_candidates(
            obligation_id,
            memory_repository=repository,
            actor="memory-agent",
            acl=MemoryACL(
                readers=("memory-agent",),
                writers=("memory-agent",),
                reviewers=("memory-agent",),
            ),
            owner_id="project/b7-memory",
            namespace="project/b7-memory/adapter",
        )
        _document, content = repository.get(
            memory_ids["candidate-b7-adapter"],
            actor="memory-agent",
            include_content=True,
        )
        assert "Applicability condition: Only for this task's correction." in str(content)


def test_review_source_preflight_failure_is_durable_bounded_and_zero_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "review-preflight"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys) as backend:
        obligation_id, repository, _memory_id, body_ref = _seed_review_candidate(
            backend, root, "task-b7-review-preflight"
        )
        original_read = backend.context_memory.read

        def unreadable(reference_id: str, *, expected_hash: str | None = None):
            if reference_id == body_ref:
                raise FileNotFoundError(reference_id)
            return original_read(reference_id, expected_hash=expected_hash)

        monkeypatch.setattr(backend.context_memory, "read", unreadable)
        provider_calls: list[dict] = []
        first = backend.process_experience_candidate_review(
            obligation_id,
            request_id="host-review-stem:review",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda request: provider_calls.append(request) or {"disposition": "PUBLISHED"},
            memory_repository=repository,
            memory_actor="memory-agent",
        )
        disposition = first["candidate_dispositions"]["candidate-task-b7-review-preflight"]
        assert first["state"] == "CANDIDATE_REVIEW"
        assert disposition["disposition"] == "NEEDS_WORK"
        assert disposition["attempt_count"] == 1
        assert disposition["provider_dispatch_facts"]["provider_send_count"] == 0
        assert disposition["provider_dispatch_facts"]["provider_send_status"] == "not_sent"
        assert disposition["request_id"].endswith(":attempt:1:preflight:1")
        assert disposition["next_due_at"]
        assert provider_calls == []

        # Host-style request stems are reused, but the durable due gate must
        # prevent a second read or Provider dispatch before the recorded due.
        again = backend.process_experience_candidate_review(
            obligation_id,
            request_id="host-review-stem:review",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda request: provider_calls.append(request) or {"disposition": "PUBLISHED"},
            memory_repository=repository,
            memory_actor="memory-agent",
        )
        assert again["candidate_dispositions"]["candidate-task-b7-review-preflight"]["attempt_count"] == 1
        assert provider_calls == []

    with LoopBackend.open(root, keychain_backend=keys) as reopened:
        repository = MemoryRepository(
            reopened.store.journal,
            reopened.store.cas,
            reopened.context.provider,
            feature_activations=_memory_activations(root),
        )
        original_read = reopened.context_memory.read

        def still_unreadable(reference_id: str, *, expected_hash: str | None = None):
            if reference_id == body_ref:
                raise FileNotFoundError(reference_id)
            return original_read(reference_id, expected_hash=expected_hash)

        monkeypatch.setattr(reopened.context_memory, "read", still_unreadable)
        provider_calls: list[dict] = []
        persisted = reopened._experience_obligation_projection()[obligation_id]
        assert persisted["candidate_dispositions"]["candidate-task-b7-review-preflight"]["attempt_count"] == 1
        before_due = reopened.process_experience_candidate_review(
            obligation_id,
            request_id="host-review-stem:review",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda request: provider_calls.append(request) or {"disposition": "PUBLISHED"},
            memory_repository=repository,
            memory_actor="memory-agent",
        )
        assert before_due["candidate_dispositions"]["candidate-task-b7-review-preflight"]["attempt_count"] == 1
        assert provider_calls == []

        # Open the recorded due for this fixture, then exercise the same
        # Host-style request stem through attempts 2 and 3.
        monkeypatch.setattr(coordinator_module, "iso_now", lambda: "9999-01-01T00:00:00.000000Z")
        second = reopened.process_experience_candidate_review(
            obligation_id,
            request_id="host-review-stem:review",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda request: provider_calls.append(request) or {"disposition": "PUBLISHED"},
            memory_repository=repository,
            memory_actor="memory-agent",
        )
        second_disposition = second["candidate_dispositions"]["candidate-task-b7-review-preflight"]
        assert second_disposition["disposition"] == "NEEDS_WORK"
        assert second_disposition["attempt_count"] == 2
        assert second_disposition["request_id"].endswith(":attempt:2:preflight:2")
        assert provider_calls == []
        third = reopened.process_experience_candidate_review(
            obligation_id,
            request_id="host-review-stem:review",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda request: provider_calls.append(request) or {"disposition": "PUBLISHED"},
            memory_repository=repository,
            memory_actor="memory-agent",
        )
        third_disposition = third["candidate_dispositions"]["candidate-task-b7-review-preflight"]
        assert third["state"] == "SETTLED"
        assert third_disposition["disposition"] == "FAILED_FINAL"
        assert third_disposition["attempt_count"] == 3
        assert third_disposition["next_due_at"] is None
        assert provider_calls == []


def test_normal_review_receives_input_evidence_and_retains_condition(tmp_path: Path) -> None:
    root = tmp_path / "review-normal"
    with LoopBackend.open(root, keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id, repository, memory_id, _body_ref = _seed_review_candidate(
            backend, root, "task-b7-review-normal"
        )
        review_requests: list[dict] = []
        result = backend.process_experience_candidate_review(
            obligation_id,
            request_id="normal-review-stem:review",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda request: review_requests.append(request) or {
                "disposition": "PUBLISHED",
                "reason": "condition is bounded to the task correction",
            },
            memory_repository=repository,
            memory_actor="memory-agent",
        )
        assert result["state"] == "SETTLED"
        assert result["candidate_dispositions"]["candidate-task-b7-review-normal"]["disposition"] == "PUBLISHED"
        assert review_requests[0]["source_evidence"]["input_evidence"]["semantic_input_sequences"] == [1]
        _document, content = repository.get(memory_id, actor="memory-agent", include_content=True)
        assert "Applicability condition: Only for this task's correction." in str(content)
