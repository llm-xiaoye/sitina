from __future__ import annotations

import threading
import time
from pathlib import Path

from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.loop import AcceptanceSubmission, CompletionProposal, LoopBackend, TaskStatus
from sitina.loop.model import TaskConflict
from sitina.loop.host import LoopHost, NativeExperienceProviderFactory
from sitina.extensions.runtime import BoundedToolTurnClient
from sitina.memory.native import EpisodeRepository, MemoryACL, MemoryRepository
from sitina.runners.provider import ProviderProfile, ProviderReadTimeout, ProviderToolCall, ProviderToolTurn
from sitina.security.macos_keychain import MemoryKeychainBackend


def _memory_activations(home: Path) -> FeatureActivationRegistry:
    leases = CompatibilityLeaseRegistry(home)
    leases.register(RuntimeCompatibilityLease.build(
        process_id="b6-interim-04",
        binary_version="2.0.0",
        reader_capabilities=("memory-v1",),
        writer_capabilities=("memory-v1",),
        started_at="2026-07-18T00:00:00Z",
        lease_expires_at="2026-07-18T01:00:00Z",
        fencing_token=1,
    ))
    registry = FeatureActivationRegistry()
    registry.prepare("memory_v1_write", required_reader_capabilities=("memory-v1",), leases=leases,
                     now="2026-07-18T00:00:01Z", journal_position=1,
                     journal_control_event={"schema": "RUNTIME_FEATURE_PREPARED_V1", "event_type": "runtime.feature-prepared", "feature": "memory_v1_write"})
    registry.activate("memory_v1_write", rollback_floor_version=2, journal_position=2,
                      journal_control_event={"schema": "RUNTIME_FEATURE_ACTIVATED_V1", "event_type": "runtime.feature-activated", "feature": "memory_v1_write", "rollback_safe_after_first_write": True})
    return registry


def _task(backend: LoopBackend, task_id: str):
    return backend.create_task(
        task_id=task_id,
        session_id="session-b6-interim-04",
        task_kind="readonly",
        goal="produce a terminal source closure",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact-b6-interim-04",
        environment_ref="environment-b6-interim-04",
        capability_snapshot_id="capabilities-b6-interim-04",
    )


def _seed_review_obligation(backend: LoopBackend, repository: MemoryRepository, task_id: str, prefix: str) -> str:
    """Create one durable manifest-backed candidate for review-boundary tests."""
    task = _task(backend, task_id)
    task = backend.record_acceptance(
        task.task_id,
        AcceptanceSubmission(
            acceptance_id=f"acceptance-{prefix}", outcome_id="outcome-1",
            evidence_refs=(f"cas:evidence-{prefix}",), program_status="PASS",
            reviewer_status="PASS", delivery_verified=True,
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
            proposal_id=f"proposal-{prefix}", terminal_status=TaskStatus.SUCCEEDED,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_received_input_seq=task.received_input_seq,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref, final_result={"result": prefix},
        ),
    )
    repository_backend = backend
    extraction = next(
        item for item in repository_backend.pending_experience_obligations()
        if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
    )
    backend.process_experience_obligation(
        extraction["obligation_id"], request_id=f"extract-{prefix}",
        provider_profile="deepseek-scripted",
        provider_dispatch=lambda request: {
            "status": "SUCCEEDED",
            "manifest": {
                "schema": "SITINA_EXPERIENCE_MANIFEST_V1", "batch_id": f"batch-{prefix}",
                "source_closure_hash": request["source_closure"]["closure_hash"],
                "status": "COMPLETE",
                "candidates": [{
                    "candidate_id": f"candidate-{prefix}", "revision": f"revision-{prefix}",
                    "content": f"lesson-{prefix}",
                }],
            },
        },
    )
    backend.materialize_experience_candidates(
        extraction["obligation_id"], memory_repository=repository,
        actor="memory-agent",
        acl=MemoryACL(
            readers=("memory-agent", "reviewer-1"), writers=("memory-agent",), reviewers=("reviewer-1",)
        ),
        owner_id=f"project/{prefix}", namespace=f"project/{prefix}/b6",
    )
    return extraction["obligation_id"]


class _FakeClient:
    def __init__(self, turn: ProviderToolTurn | None = None, *, block: bool = False):
        self.turn = turn
        self.block = block
        self.cancel_seen = threading.Event()
        self.last_request_kwargs = None

    def complete_tool_turn(self, _profile, **kwargs):
        self.last_request_kwargs = kwargs
        cancel_check = kwargs.get("cancel_check")
        if self.block:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if callable(cancel_check) and cancel_check():
                    self.cancel_seen.set()
                    break
                time.sleep(0.005)
            raise TimeoutError("fake transport stopped")
        return self.turn


class _TimeoutClient:
    def __init__(self):
        self.calls = 0

    def complete_tool_turn(self, _profile, **_kwargs):
        self.calls += 1
        raise ProviderReadTimeout("unknown physical result")


class _StuckClient:
    """Hold one native transport slot until the test explicitly releases it."""

    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def complete_tool_turn(self, _profile, **_kwargs):
        self.started.set()
        while not self.release.is_set():
            time.sleep(0.005)
        raise TimeoutError("stuck transport released by test")


def _profile() -> ProviderProfile:
    return ProviderProfile("deepseek", "mock://deepseek/v1", "offline", "deepseek-chat", "openai_chat_completions")


def test_native_experience_factory_projects_tool_result_without_reasoning() -> None:
    client = _FakeClient(ProviderToolTurn(
        "private reasoning must not escape",
        (ProviderToolCall("call-1", "experience_result", {"status": "SUCCEEDED", "program_status": "PASS"}),),
        "stop",
        {"physical_send_count": 1, "physical_send_count_status": "exact", "token_usage": {"total_tokens": 4}},
        "secret reasoning",
    ))
    factory = NativeExperienceProviderFactory(client, _profile(), max_tokens=64, timeout_seconds=1)
    result = factory({
        "schema": "SITINA_EXPERIENCE_PROVIDER_REQUEST_V1",
        "request_id": "request-1",
        "source_closure": {"closure_hash": "a" * 64},
        "source_evidence": {"input_evidence": {
            "semantic_input_sequences": [1], "handled_input_seq": 2,
            "records": [{"sequence": 1, "kind": "CORRECTION"}, {"sequence": 2, "kind": "CLARIFICATION"}],
        }},
    })
    assert result["response_received"] is True
    assert result["provider_send_count"] == 1
    assert result["usage_known"] is True
    assert "reasoning_content" not in result
    assert "text" not in result
    tool = client.last_request_kwargs["tools"][0]
    citations = tool["input_schema"]["properties"]["manifest"]["properties"]["candidates"]["items"]["properties"]["evidence_input_sequences"]
    assert citations["items"]["enum"] == [1]
    assert citations["maxItems"] == 1
    assert citations["uniqueItems"] is True
    assert "program-verified sequence IDs: [1]" in client.last_request_kwargs["system_prompt"]
    shared = NativeExperienceProviderFactory.EXTRACTION_RESULT_TOOL["input_schema"]["properties"]["manifest"]["properties"]["candidates"]["items"]["properties"]["evidence_input_sequences"]
    assert "enum" not in shared["items"]
    assert shared["maxItems"] == 64


def test_native_experience_factory_timeout_signals_cancel_without_retry() -> None:
    client = _FakeClient(block=True)
    factory = NativeExperienceProviderFactory(client, _profile(), max_tokens=64, timeout_seconds=0.02)
    try:
        factory({"schema": "SITINA_EXPERIENCE_REVIEW_REQUEST_V1", "request_id": "request-2"})
    except TimeoutError as error:
        assert "deadline" in str(error)
    else:  # pragma: no cover
        raise AssertionError("expected bounded Provider timeout")
    time.sleep(0.03)
    assert client.cancel_seen.is_set()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"]:
        time.sleep(0.005)
    assert NativeExperienceProviderFactory.lifecycle_snapshot() == {"active_executions": 0, "max_executions": 1}


def test_native_experience_factory_slot_busy_is_known_not_sent() -> None:
    stuck = _StuckClient()
    first = NativeExperienceProviderFactory(stuck, _profile(), max_tokens=64, timeout_seconds=0.02)
    first_error: list[BaseException] = []

    def hold_slot() -> None:
        try:
            first({"schema": "SITINA_EXPERIENCE_REVIEW_REQUEST_V1", "request_id": "slot-holder"})
        except BaseException as error:  # the holder is expected to time out while still draining
            first_error.append(error)

    holder = threading.Thread(target=hold_slot, daemon=True)
    holder.start()
    assert stuck.started.wait(1)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"] != 1:
        time.sleep(0.005)
    assert NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"] == 1
    try:
        second = NativeExperienceProviderFactory(_FakeClient(), _profile(), max_tokens=64, timeout_seconds=0.2)
        try:
            second({"schema": "SITINA_EXPERIENCE_REVIEW_REQUEST_V1", "request_id": "slot-busy"})
        except TimeoutError as error:
            assert getattr(error, "sitina_not_sent_retryable") is True
            assert getattr(error, "sitina_provider_send_count") == 0
            assert getattr(error, "sitina_provider_send_count_status") == "exact"
            assert getattr(error, "sitina_physical_send_status") == "not_sent"
            assert getattr(error, "sitina_response_received") is False
        else:  # pragma: no cover
            raise AssertionError("expected bounded slot-busy failure")
    finally:
        stuck.release.set()
        holder.join(2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"]:
            time.sleep(0.005)
        assert NativeExperienceProviderFactory.lifecycle_snapshot() == {"active_executions": 0, "max_executions": 1}
    assert first_error and isinstance(first_error[0], TimeoutError)


def test_experience_transport_zero_retry_preserves_unknown_send_boundary() -> None:
    raw = _TimeoutClient()
    bounded = BoundedToolTurnClient(raw, _profile(), retry_limit=0, fallback_allowed=False)
    try:
        bounded.complete_tool_turn(_profile(), system_prompt="x", messages=(), tools=(), max_tokens=8)
    except ProviderReadTimeout as error:
        assert getattr(error, "sitina_physical_send_count_status") == "lower_bound_with_uncertain_attempts"
        assert getattr(error, "sitina_uncertain_physical_send_attempt_count") == 1
    else:  # pragma: no cover
        raise AssertionError("expected unknown Provider send")
    assert raw.calls == 1


def test_native_decision_reconciles_lost_loop_disposition_and_keeps_later_revoke(tmp_path: Path) -> None:
    root = tmp_path / "loop"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6-interim-04") as backend:
        task = _task(backend, "task-b6-interim-04")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-b6-interim-04",
                outcome_id="outcome-1",
                evidence_refs=("cas:evidence-b6-interim-04",),
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
                proposal_id="proposal-b6-interim-04",
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
        repository = MemoryRepository(
            backend.store.journal,
            backend.store.cas,
            backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        backend.bind_memory_repository(repository, actor="reviewer-1")
        extraction = next(
            item for item in backend.pending_experience_obligations()
            if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
        )
        provider_requests = []
        backend.process_experience_obligation(
            extraction["obligation_id"],
            request_id="provider-b6-interim-04",
            provider_profile="deepseek-scripted",
            provider_dispatch=lambda request: (
                provider_requests.append(dict(request)) or {
                    "status": "SUCCEEDED",
                    "manifest": {
                        "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
                        "batch_id": "batch-b6-interim-04",
                        "source_closure_hash": request["source_closure"]["closure_hash"],
                        "status": "COMPLETE",
                        "candidates": [{
                            "candidate_id": "candidate-b6-interim-04",
                            "revision": "revision-b6-interim-04",
                            "content": "durable lesson",
                        }],
                    },
                }
            ),
        )
        assert provider_requests[0]["source_evidence"]["goal"]["goal"] == "produce a terminal source closure"
        assert provider_requests[0]["source_evidence"]["terminal_result"]["final_result"] == {"result": "ok"}
        extraction = backend._experience_obligation_projection()[extraction["obligation_id"]]
        candidate_ids = backend.materialize_experience_candidates(
            extraction["obligation_id"],
            memory_repository=repository,
            actor="memory-agent",
            acl=MemoryACL(
                readers=("memory-agent", "reviewer-1"),
                writers=("memory-agent",),
                reviewers=("reviewer-1",),
            ),
            owner_id="project/interim-04",
            namespace="project/interim-04/b6",
        )
        # A review was dispatched and the loop recorded UNKNOWN, but the
        # native decision was committed before the process died.
        backend.process_experience_candidate_review(
            extraction["obligation_id"],
            request_id="review-b6-interim-04",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda _request: (_ for _ in ()).throw(RuntimeError("lost return")),
            memory_repository=repository,
            memory_actor="reviewer-1",
        )
        after_unknown = backend._experience_obligation_projection()[extraction["obligation_id"]]
        memory_id = candidate_ids["candidate-b6-interim-04"]
        request_id = after_unknown["review_request_id"]
        repository.apply_memory_decision(
            decision_id="memory-decision-b6-interim-04",
            source_closure=after_unknown["source_closure"],
            candidate_actions=[{
                "memory_id": memory_id,
                "expected_status": "candidate",
                "to_status": "accepted",
                "reason_code": "review-ok",
            }],
            actor="reviewer-1",
            occurred_at="2026-09-11T00:00:00Z",
            decision_kind="experience-review",
            review_request_id=request_id,
            candidate_revisions={memory_id: after_unknown["candidate_revisions"]["candidate-b6-interim-04"]},
            review_binding=after_unknown["review_memory_binding"],
        )
        # A later native revoke remains current native state; it must not
        # prevent the historical PUBLISHED disposition from being recovered.
        repository.apply_memory_decision(
            decision_id="memory-decision-b6-interim-04-revoke",
            source_closure=after_unknown["source_closure"],
            candidate_actions=[{
                "memory_id": memory_id,
                "expected_status": "accepted",
                "to_status": "revoked",
                "reason_code": "source-revoked",
            }],
            actor="reviewer-1",
            occurred_at="2026-09-11T00:01:00Z",
            decision_kind="source-revocation",
        )
        pending = backend.pending_experience_obligations()
        assert not any(item["obligation_id"] == extraction["obligation_id"] for item in pending)
        final = backend._experience_obligation_projection()[extraction["obligation_id"]]
        assert final["state"] == "SETTLED"
        assert final["candidate_dispositions"]["candidate-b6-interim-04"]["disposition"] == "PUBLISHED"
        assert repository.get(memory_id, actor="reviewer-1", include_content=False)[0].status == "revoked"


def test_host_repository_factories_reuse_one_backend_store(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    def backend_factory(root):
        return LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-b6-store")

    def memory_factory(backend):
        return MemoryRepository(backend.store.journal, backend.store.cas, backend.context.provider,
                                feature_activations=FeatureActivationRegistry.from_journal_events(
                                    backend.store.journal.iter_events(0)))

    def episode_factory(backend):
        return EpisodeRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=FeatureActivationRegistry.from_journal_events(
                backend.store.journal.iter_events(0)))

    host = LoopHost(
        tmp_path / "host",
        backend_factory=backend_factory,
        memory_repository_factory=memory_factory,
        episode_repository_factory=episode_factory,
        memory_actor="loop-memory-reviewer",
    ).start()
    try:
        assert host.memory_repository.journal is host.backend.store.journal
        assert host.memory_repository.cas is host.backend.store.cas
        assert host.memory_repository.keys is host.backend.context.provider
        assert host.episode_repository.journal is host.backend.store.journal
        assert host.episode_repository.cas is host.backend.store.cas
        assert host.episode_repository.keys is host.backend.context.provider
    finally:
        host.close()


def test_backend_rejects_foreign_memory_authority(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    with LoopBackend.open(tmp_path / "a", keychain_backend=keys, run_instance_id="run-a") as first:
        with LoopBackend.open(tmp_path / "b", keychain_backend=keys, run_instance_id="run-b") as second:
            foreign = MemoryRepository(
                second.store.journal, second.store.cas, second.context.provider,
                feature_activations=FeatureActivationRegistry.from_journal_events(second.store.journal.iter_events(0)),
            )
            try:
                first.bind_memory_repository(foreign, actor="reviewer-1")
            except TaskConflict as error:
                assert "Journal/CAS/key authority" in str(error)
            else:  # pragma: no cover
                raise AssertionError("foreign native memory authority was accepted")


def test_host_restart_materializes_persisted_manifest_before_review(tmp_path: Path) -> None:
    root = tmp_path / "restart-manifest"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-manifest") as backend:
        task = _task(backend, "task-manifest-restart")
        task = backend.record_acceptance(
            task.task_id,
            AcceptanceSubmission(
                acceptance_id="acceptance-manifest-restart",
                outcome_id="outcome-1",
                evidence_refs=("cas:evidence-manifest-restart",),
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
        backend.propose_terminal(
            task.task_id,
            CompletionProposal(
                proposal_id="proposal-manifest-restart", terminal_status=TaskStatus.SUCCEEDED,
                expected_task_revision=task.task_revision,
                expected_run_instance_id=task.run_instance_id,
                expected_execution_epoch=task.execution_epoch,
                expected_goal_version=task.goal_version,
                expected_acceptance_version=task.acceptance_version,
                expected_received_input_seq=task.received_input_seq,
                expected_handled_input_seq=task.handled_input_seq,
                artifact_ref=task.artifact_ref, final_result={"result": "restart"},
            ),
        )
        extraction = next(
            item for item in backend.pending_experience_obligations()
            if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
        )
        backend.process_experience_obligation(
            extraction["obligation_id"], request_id="extract-before-restart",
            provider_profile="deepseek-scripted",
            provider_dispatch=lambda request: {
                "status": "SUCCEEDED",
                "manifest": {
                    "schema": "SITINA_EXPERIENCE_MANIFEST_V1", "batch_id": "restart-batch",
                    "source_closure_hash": request["source_closure"]["closure_hash"],
                    "status": "COMPLETE",
                    "candidates": [{
                        "candidate_id": "restart-candidate", "revision": "restart-revision",
                        "content": "restart lesson",
                    }],
                },
            },
        )
        assert backend._experience_obligation_projection()[extraction["obligation_id"]]["state"] == "MANIFEST_RECORDED"

    provider_calls = []
    review_calls = []
    def memory_factory(backend):
        return MemoryRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=_memory_activations(root),
        )
    def provider_after_restart(_request):
        provider_calls.append(1)
        raise AssertionError("persisted manifest must not re-extract after restart")
    def review_after_restart(request):
        review_calls.append(dict(request))
        return {"disposition": "REJECTED", "reason": "restart-review"}

    host = LoopHost(
        root,
        keychain_backend=keys,
        experience_provider_factory=provider_after_restart,
        experience_provider_profile="deepseek-scripted",
        experience_review_factory=review_after_restart,
        memory_repository_factory=memory_factory,
        memory_actor="reviewer-1",
        memory_materializer_actor="memory-agent",
        memory_candidate_acl=MemoryACL(
            readers=("memory-agent", "reviewer-1"),
            writers=("memory-agent",),
            reviewers=("reviewer-1",),
        ),
        memory_candidate_owner_id="project/interim-restart",
        memory_candidate_namespace="project/interim-restart/b6",
        publication_obligation_poll_interval=0.02,
    ).start()
    try:
        deadline = time.monotonic() + 8
        final = None
        while time.monotonic() < deadline:
            final = host.backend._experience_obligation_projection().get(extraction["obligation_id"])
            if final and final.get("state") == "SETTLED":
                break
            time.sleep(0.02)
        assert final is not None and final["state"] == "SETTLED"
        assert not provider_calls
        assert review_calls and final.get("candidate_memory_ids", {}).get("restart-candidate")
    finally:
        host.begin_drain()
        host.wait_for_quiescence(8)
        host.close()


def test_acceptance_memory_guard_serializes_against_native_revoke(tmp_path: Path) -> None:
    root = tmp_path / "memory-guard-race"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-memory-guard") as backend:
        repository = MemoryRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        acl = MemoryACL(
            readers=("memory-agent", "reviewer-1"),
            writers=("memory-agent",),
            reviewers=("reviewer-1",),
        )
        repository.create_candidate(
            memory_id="memory-guard-race", scope="project_shared", owner_id="project/guard",
            namespace="project/guard/b6", content="guarded memory", source_event_ids=(),
            source_run_ids=(), evidence_refs=(), confidence=0.8, sensitivity="low",
            valid_from="2026-09-11T00:00:00Z", expires_at=None, retention_policy="until-superseded",
            supersedes=(), acl=acl, actor="memory-agent",
        )
        repository.apply_memory_decision(
            decision_id="memory-decision-guard-accept",
            source_closure={"terminal_event_id": "guard-terminal", "source_hash": "g" * 64},
            candidate_actions=[{"memory_id": "memory-guard-race", "expected_status": "candidate", "to_status": "accepted", "reason_code": "guard-ok"}],
            actor="reviewer-1", occurred_at="2026-09-11T00:00:01Z",
        )
        memory_view = backend.build_memory_view_from_repository(
            repository, memory_ids=("memory-guard-race",), actor="reviewer-1",
            selection_reasons=("native-guard-race-test",),
        )
        task = backend.create_task(
            task_id="task-memory-guard-race", session_id="session-memory-guard",
            task_kind="readonly", goal="guard race", required_outcome_ids=("outcome-1",),
            artifact_ref="cas:artifact-memory-guard", environment_ref="environment-memory-guard",
            capability_snapshot_id="capabilities-memory-guard", memory_view=memory_view,
        )
        entered = threading.Event()
        revoke_done = threading.Event()

        def revoke() -> None:
            entered.wait(2)
            repository.apply_memory_decision(
                decision_id="memory-decision-guard-revoke",
                source_closure={"terminal_event_id": "guard-terminal", "source_hash": "r" * 64},
                candidate_actions=[{"memory_id": "memory-guard-race", "expected_status": "accepted", "to_status": "revoked", "reason_code": "guard-revoked"}],
                actor="reviewer-1", occurred_at="2026-09-11T00:00:02Z",
            )
            revoke_done.set()

        revoker = threading.Thread(target=revoke, daemon=True)
        revoker.start()

        def guard() -> bool:
            backend.assert_task_memory_view_actionable(task.task_id)
            entered.set()
            time.sleep(0.05)
            return True

        submission = AcceptanceSubmission(
            acceptance_id="acceptance-memory-guard-race", outcome_id="outcome-1",
            evidence_refs=("cas:evidence-memory-guard",), program_status="PASS",
            reviewer_status="PASS", delivery_verified=True,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref,
        )
        backend.record_acceptance(task.task_id, submission, require_current=True, external_guard=guard)
        assert revoke_done.wait(2)
        acceptance_position = next(
            event.position for event in backend.store.task_events(task.task_id)
            if event.event_type == "loop.acceptance-result-recorded"
        )
        revoke_position = next(
            event.position for event in backend.store.journal.iter_events(0)
            if event.event_type == "memory.decision-committed" and event.payload.get("decision_id") == "memory-decision-guard-revoke"
        )
        assert acceptance_position < revoke_position
        assert repository.get("memory-guard-race", actor="reviewer-1", include_content=False)[0].status == "revoked"


def test_review_slot_busy_is_needs_work_without_consuming_attempt(tmp_path: Path) -> None:
    root = tmp_path / "review-slot-busy"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-review-slot") as backend:
        repository = MemoryRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        obligation_id = _seed_review_obligation(backend, repository, "task-review-slot", "review-slot")
        stuck = _StuckClient()
        holder_factory = NativeExperienceProviderFactory(stuck, _profile(), max_tokens=64, timeout_seconds=0.02)

        def hold_slot() -> None:
            try:
                holder_factory({"schema": "SITINA_EXPERIENCE_REVIEW_REQUEST_V1", "request_id": "review-holder"})
            except BaseException:
                pass

        holder = threading.Thread(target=hold_slot, daemon=True)
        holder.start()
        assert stuck.started.wait(1)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"] != 1:
            time.sleep(0.005)
        assert NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"] == 1
        try:
            review_factory = NativeExperienceProviderFactory(_FakeClient(), _profile(), max_tokens=64, timeout_seconds=0.2)
            reviewed = backend.process_experience_candidate_review(
                obligation_id,
                request_id="review-slot-busy",
                provider_profile="deepseek-scripted",
                review_dispatch=review_factory,
                memory_repository=repository,
                memory_actor="reviewer-1",
            )
            candidate = reviewed["candidate_dispositions"]["candidate-review-slot"]
            assert reviewed["state"] == "CANDIDATE_REVIEW"
            assert candidate["disposition"] == "NEEDS_WORK"
            assert candidate["attempt_count"] == 0
            assert candidate["next_due_at"]
            facts = candidate["provider_dispatch_facts"]
            assert facts["provider_send_count"] == 0
            assert facts["provider_send_count_status"] == "exact"
            assert facts["provider_send_status"] == "not_sent"
            assert facts["uncertain_physical_send_attempt_count"] == 0
            assert not any(item["obligation_id"] == obligation_id for item in backend.pending_experience_obligations())
        finally:
            stuck.release.set()
            holder.join(2)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and NativeExperienceProviderFactory.lifecycle_snapshot()["active_executions"]:
                time.sleep(0.005)
            assert NativeExperienceProviderFactory.lifecycle_snapshot() == {"active_executions": 0, "max_executions": 1}


def test_candidate_review_natural_language_reason_is_bound_and_auditable(tmp_path: Path) -> None:
    root = tmp_path / "review-natural-reason"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-review-natural") as backend:
        repository = MemoryRepository(
            backend.store.journal, backend.store.cas, backend.context.provider,
            feature_activations=_memory_activations(root),
        )
        obligation_id = _seed_review_obligation(backend, repository, "task-review-natural", "review-natural")
        raw_reason = "Controlled native review"
        reviewed = backend.process_experience_candidate_review(
            obligation_id,
            request_id="review-natural-request",
            provider_profile="deepseek-scripted",
            review_dispatch=lambda _request: {"disposition": "PUBLISHED", "reason": raw_reason},
            memory_repository=repository,
            memory_actor="reviewer-1",
        )
        assert reviewed["state"] == "SETTLED"
        disposition = reviewed["candidate_dispositions"]["candidate-review-natural"]
        assert disposition["reason"] == raw_reason
        decision = next(iter(repository.decision_projection()["by_decision"].values()))
        reason_code = decision["candidate_actions"][0]["reason_code"]
        assert reason_code.startswith("review-natural-")
        assert reason_code != raw_reason
