from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from sitina.journal.model import canonical_json_bytes
from sitina.loop.context_window import (
    ContextCoreError,
    ContextCoverageBlocked,
    HistoryQueryError,
    LoopContextIndex,
    LoopHistoryQuery,
    ModelCapacityRegistry,
    ProtocolGroupSelector,
    ProtocolMessageGroup,
    ProviderContextIdentity,
    ProviderRequestPlanner,
    RequirementCoverageVerifier,
    TaskContextProjector,
    normalize_provider_endpoint,
    render_provider_tool_request,
)
from sitina.loop.coordinator import LoopBackend
from sitina.loop.model import EffectStatus, InputKind, OperationMode, TaskConflict, TaskStatus
from sitina.loop.operations import OperationIntent, OperationOutcome, RecoveryPolicy
from sitina.runners.provider import ANTHROPIC_MESSAGES, OPENAI_CHAT_COMPLETIONS
from sitina.security.macos_keychain import MemoryKeychainBackend


def create_task(backend: LoopBackend, task_id: str, *, session_id: str = "session-1", goal: str = "EARLY-REQ"):
    return backend.create_task(
        task_id=task_id,
        session_id=session_id,
        task_kind="no_change",
        goal=goal,
        required_outcome_ids=("outcome-1",),
        artifact_ref=f"cas:artifact-{task_id}",
        environment_ref="environment-v1",
        capability_snapshot_id="capabilities-v1",
    )


def recovery_policy() -> RecoveryPolicy:
    return RecoveryPolicy(
        probe="inspect committed evidence",
        retry="only after proving absence",
        partial="persist partial result",
        cancel="stop new dispatch",
        unknown_exit="retain responsibility",
        reconsider_at="after verified evidence",
    )


def read_intent(backend: LoopBackend, task_id: str, operation_id: str) -> OperationIntent:
    task = backend.get_task(task_id)
    return OperationIntent(
        operation_id=operation_id,
        logical_operation_id=f"logical-{operation_id}",
        attempt_id=f"attempt-{operation_id}",
        mode=OperationMode.READ,
        description="produce test evidence",
        resources=(),
        expected_task_revision=task.task_revision,
        expected_run_instance_id=task.run_instance_id,
        expected_execution_epoch=task.execution_epoch,
        expected_goal_version=task.goal_version,
        expected_acceptance_version=task.acceptance_version,
        expected_handled_input_seq=task.handled_input_seq,
        capability_snapshot_id=task.capability_snapshot_id,
        preconditions=(),
        recovery=recovery_policy(),
    )


def capacity_mapping(identity: ProviderContextIdentity, *, capacity: int, reserve: int = 64, mode: str = "conservative_utf8"):
    return {
        "schema": "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1",
        "entries": [
            {
                **identity.as_dict(),
                "context_capacity_tokens": capacity,
                "next_tool_turn_receipt_reserve_tokens": reserve,
                "history_query_max_bytes": 4096,
                "counter": {
                    "mode": mode,
                    "name": "fixture-wire-counter-v1",
                    "applicability": "fixture exact endpoint/model/wire only",
                    "protocol_margin_tokens": 32,
                },
            }
        ],
    }


@pytest.mark.parametrize("wire", [OPENAI_CHAT_COMPLETIONS, ANTHROPIC_MESSAGES])
def test_request_rendering_and_per_call_admission_count_exact_wire_body(wire: str) -> None:
    identity = ProviderContextIdentity("fixture", "https://API.EXAMPLE.test/gateway/v1/", "model-a", wire)
    messages = [
        {"role": "user", "content": "task and constraints"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "call-1", "name": "read", "arguments": {"path": "x"}}],
        },
        {"role": "tool", "tool_call_id": "call-1", "name": "read", "content": "receipt", "is_error": False},
    ]
    tools = [{"name": "read", "description": "read", "input_schema": {"type": "object"}}]
    rendered = render_provider_tool_request(
        identity,
        system_prompt="system",
        messages=messages,
        tools=tools,
        max_tokens=128,
    )
    exact_transport_bytes = json.dumps(rendered.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert rendered.canonical_body == exact_transport_bytes
    detached = rendered.body
    detached["messages"][-1]["content"] = "x" * 100_000
    detached["tools"][0]["function" if wire == OPENAI_CHAT_COMPLETIONS else "input_schema"] = {"mutated": True}
    assert len(rendered.canonical_body) == len(exact_transport_bytes)
    assert rendered.body_for_send(identity)["messages"][-1] != detached["messages"][-1]
    assert rendered.body_hash
    assert set(rendered.component_bytes) == {"system", "tool_schemas", "messages", "protocol_body"}
    capacity = len(exact_transport_bytes) + 32 + 128 + 64
    planner = ProviderRequestPlanner(
        ModelCapacityRegistry.from_mapping(capacity_mapping(identity, capacity=capacity))
    )
    admission = planner.plan(rendered)
    assert admission.admitted
    assert admission.input_bound_tokens == len(exact_transport_bytes) + 32
    assert admission.total_reserved_tokens == capacity
    assert admission.as_dict()["cumulative_task_budget_applied"] is False
    assert admission.as_dict()["provider_reported_actual_usage"] is False
    assert "response_format" not in rendered.body
    json_rendered = render_provider_tool_request(
        identity,
        system_prompt="Return a JSON object.",
        messages=messages,
        tools=tools,
        max_tokens=128,
        expect_json=True,
    )
    if wire == OPENAI_CHAT_COMPLETIONS:
        assert json_rendered.body["response_format"] == {"type": "json_object"}
    else:
        assert "response_format" not in json_rendered.body
    assert json_rendered.body["tools"] == rendered.body["tools"]
    exact_json_bytes = json.dumps(
        json_rendered.body, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    assert json_rendered.canonical_body == exact_json_bytes
    assert json_rendered.body_for_send(identity) == json_rendered.body
    json_admission = planner.plan(json_rendered)
    assert json_admission.body_hash == json_rendered.body_hash
    assert json_admission.input_bound_tokens == len(exact_json_bytes) + 32


def test_capacity_identity_keeps_base_path_and_missing_or_unqualified_counter_blocks() -> None:
    identity = ProviderContextIdentity(
        "fixture", "https://api.example.test/v1", "model-a", OPENAI_CHAT_COMPLETIONS
    )
    rendered = render_provider_tool_request(
        identity,
        system_prompt="system",
        messages=[{"role": "user", "content": "task"}],
        tools=[],
        max_tokens=16,
    )
    assert normalize_provider_endpoint("https://API.EXAMPLE.test/v1/") == "https://api.example.test/v1"
    other_path = ProviderContextIdentity(
        "fixture", "https://api.example.test/other/v1", "model-a", OPENAI_CHAT_COMPLETIONS
    )
    missing = ProviderRequestPlanner(
        ModelCapacityRegistry.from_mapping(capacity_mapping(other_path, capacity=10_000))
    ).plan(rendered)
    assert not missing.admitted
    assert missing.context_capacity_tokens is None
    exact_registry = ModelCapacityRegistry.from_mapping(
        capacity_mapping(identity, capacity=10_000, mode="qualified_tokenizer")
    )
    unqualified = ProviderRequestPlanner(exact_registry).plan(rendered)
    assert not unqualified.admitted
    assert "unavailable" in unqualified.reason
    too_small = ProviderRequestPlanner(
        ModelCapacityRegistry.from_mapping(capacity_mapping(identity, capacity=100))
    ).plan(rendered)
    assert not too_small.admitted
    assert "exceeds" in too_small.reason


def group(number: int, *, content: str = "receipt") -> ProtocolMessageGroup:
    return ProtocolMessageGroup(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": f"call-{number}", "name": "read", "arguments": {"n": number, "ratio": 0.5}}],
        },
        (
            {
                "role": "tool",
                "tool_call_id": f"call-{number}",
                "name": "read",
                "content": content,
                "is_error": False,
            },
        ),
        (f"cas:{number:064x}",),
    )


def test_protocol_groups_are_selected_atomically_and_latest_cannot_be_orphaned() -> None:
    first, latest = group(1), group(2)
    latest_size = len(json.dumps(list(latest.messages()), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    selection = ProtocolGroupSelector.select((first, latest), max_serialized_bytes=latest_size)
    assert selection.groups == (latest,)
    assert first.source_refs[0] in selection.omitted_source_refs
    assert [item["role"] for item in selection.groups[0].messages()] == ["assistant", "tool"]
    with pytest.raises(ContextCoverageBlocked):
        ProtocolGroupSelector.select((latest,), max_serialized_bytes=latest_size - 1)
    with pytest.raises(ContextCoreError):
        ProtocolMessageGroup(
            latest.assistant,
            ({"role": "tool", "tool_call_id": "wrong", "content": "x"},),
            latest.source_refs,
        )


def test_history_query_pages_exact_canonical_bytes_and_holds_fixed_frontier(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-a")
        bodies = ("", "中文🙂" * 80, "LATEST-REQ")
        for sequence, body in enumerate(bodies, start=1):
            kind = InputKind.CORRECTION if sequence == len(bodies) else InputKind.MESSAGE
            backend.accept_input("task-a", input_id=f"input-{sequence}", kind=kind, body=body)
            backend.handle_next_input("task-a", affects_goal=True, affects_acceptance=True)
        large_value = {"stdout": "证据🙂" * 8_000, "status": "ok"}
        backend.execute_operation(
            "task-a",
            read_intent(backend, "task-a", "operation-large"),
            lambda: OperationOutcome(EffectStatus.SUCCEEDED, large_value),
        )
        index = LoopContextIndex(backend.store, "task-a")
        query = LoopHistoryQuery(index, max_page_bytes=4096)

        first = query.list(limit=1, max_bytes=1600)
        assert first["status"] == "OK" and first["has_more"]
        assert first["response_bytes"] == len(canonical_json_bytes(first))
        fixed_frontier = first["frontier"]
        cursor = first["next_cursor"]
        backend.accept_input("task-a", input_id="later-input", kind=InputKind.MESSAGE, body="AFTER-FRONTIER")
        backend.handle_next_input("task-a", affects_goal=True, affects_acceptance=True)
        listed = list(first["entries"])
        while cursor:
            page = query.list(cursor=cursor, limit=1, max_bytes=1600)
            assert page["status"] == "OK"
            assert page["frontier"] == fixed_frontier
            assert len(canonical_json_bytes(page)) <= 1600
            assert page["response_bytes"] == len(canonical_json_bytes(page))
            listed.extend(page["entries"])
            cursor = page["next_cursor"]
        assert listed
        assert all(int(item["event_position"]) <= fixed_frontier for item in listed)
        assert all(item["subject_id"] != "later-input" for item in listed)
        invalid = query.list(cursor="not-a-cursor", max_bytes=1600)
        assert invalid["status"] == "INVALID_CURSOR"

        operation_entry = next(
            item for item in index.entries
            if item.kind == "operation_result" and item.subject_id == "operation-large"
        )
        expected_document = backend.store.read_json(
            operation_entry.internal_cas_ref, expected_hash=operation_entry.content_hash
        )
        expected = canonical_json_bytes(expected_document)
        receipt = query.receipt_for_operation_result("operation-large", max_bytes=900)
        assert receipt["status"] == "OK"
        assert receipt["source_ref"] == operation_entry.source_ref
        assert receipt["response_bytes"] == len(canonical_json_bytes(receipt))
        recovered = bytearray()
        offset = 0
        while True:
            page = query.read(source_ref=operation_entry.source_ref, offset=offset, max_bytes=900)
            assert page["status"] == "OK"
            assert len(canonical_json_bytes(page)) <= 900
            assert page["response_bytes"] == len(canonical_json_bytes(page))
            recovered.extend(base64.b64decode(page["data_base64"]))
            if not page["has_more"]:
                break
            assert int(page["next_offset"]) > offset
            offset = int(page["next_offset"])
        assert bytes(recovered) == expected
        assert json.loads(bytes(recovered))["result"] == large_value

        empty_entry = next(item for item in index.entries if item.input_sequence == 1)
        empty_page = query.read(source_ref=empty_entry.source_ref, max_bytes=1600)
        empty_document = json.loads(base64.b64decode(empty_page["data_base64"]))
        assert empty_document["body"] == ""
        with pytest.raises(HistoryQueryError):
            query.read(source_ref=empty_entry.source_ref, max_bytes=query.MIN_PAGE_BYTES - 1)
        with pytest.raises(HistoryQueryError):
            query.read(source_ref=empty_entry.source_ref, max_bytes=query.max_page_bytes + 1)
    finally:
        backend.close()


def test_history_query_is_task_scoped_and_stale_committed_ref_stays_visible(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-a", session_id="session-a")
        create_task(backend, "task-b", session_id="session-b")
        index_a = LoopContextIndex(backend.store, "task-a")
        index_a.refresh()
        source_a = index_a.entries[0]
        query_b = LoopHistoryQuery(LoopContextIndex(backend.store, "task-b"), max_page_bytes=4096)
        assert query_b.read(source_ref=source_a.source_ref, max_bytes=1200)["status"] == "NOT_VISIBLE"
        assert query_b.read(source_ref=source_a.internal_cas_ref, max_bytes=1200)["status"] == "NOT_VISIBLE"

        query_a = LoopHistoryQuery(index_a, max_page_bytes=4096)
        object_ref = backend.store.cas.resolve_reference(source_a.internal_cas_ref)
        backend.store.cas._object_path(object_ref.object_id).unlink()
        stale = query_a.read(source_ref=source_a.source_ref, max_bytes=1200)
        assert stale["status"] == "STALE_SOURCE"
        listed = query_a.list(max_bytes=1600)
        assert any(item["source_ref"] == source_a.source_ref for item in listed["entries"])
    finally:
        backend.close()


def test_context_index_refresh_uses_incremental_journal_cursor_without_reading_old_cas(
    tmp_path: Path, monkeypatch
) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-incremental")
        backend.execute_operation(
            "task-incremental",
            read_intent(backend, "task-incremental", "large-old-result"),
            lambda: OperationOutcome(EffectStatus.SUCCEEDED, {"output": "x" * 500_000}),
        )
        index = LoopContextIndex(backend.store, "task-incremental")
        index.refresh()
        first_frontier = index.frontier
        backend.accept_input(
            "task-incremental", input_id="new-input", kind=InputKind.MESSAGE, body="new"
        )
        backend.handle_next_input("task-incremental", affects_goal=True, affects_acceptance=True)

        original_task_events = backend.store.task_events
        observed_cursors: list[int] = []

        def incremental_events(task_id, *, after_position=0):
            observed_cursors.append(after_position)
            return original_task_events(task_id, after_position=after_position)

        monkeypatch.setattr(backend.store, "task_events", incremental_events)
        monkeypatch.setattr(
            backend.store,
            "read_json",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("index refresh decrypted CAS")),
        )
        index.refresh()
        assert observed_cursors == [first_frontier]
        assert index.frontier > first_frontier
    finally:
        backend.close()


def test_task_projection_keeps_early_goal_and_latest_correction_verbatim_and_is_bounded(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-projection", goal="EARLY-HARD-CONSTRAINT")
        for number in range(20):
            backend.execute_operation(
                "task-projection",
                read_intent(backend, "task-projection", f"read-{number}"),
                lambda number=number: OperationOutcome(
                    EffectStatus.SUCCEEDED,
                    {"output": f"replaceable evidence {number} " + ("x" * 2_000)},
                ),
            )
        backend.accept_input(
            "task-projection",
            input_id="latest-correction",
            kind=InputKind.CORRECTION,
            body="LATEST-HARD-CORRECTION",
        )
        backend.handle_next_input("task-projection", affects_goal=True, affects_acceptance=True)
        index = LoopContextIndex(backend.store, "task-projection")
        projection = TaskContextProjector(index).build(max_bytes=7000, max_history_rows=100)
        assert len(projection.serialized) <= 7000
        texts = [item.text for item in projection.requirements]
        assert texts == ["EARLY-HARD-CONSTRAINT", "LATEST-HARD-CORRECTION"]
        assert len(projection.history_directory) < 40
        assert RequirementCoverageVerifier.verify(index, projection).verified

        backend.accept_input(
            "task-projection",
            input_id="newer-correction",
            kind=InputKind.CORRECTION,
            body="NEWEST-HARD-CORRECTION",
        )
        backend.handle_next_input("task-projection", affects_goal=True, affects_acceptance=True)
        stale = RequirementCoverageVerifier.verify(index, projection)
        assert not stale.verified
        assert "task binding changed after projection" in stale.reasons

        with pytest.raises(ContextCoverageBlocked) as blocked:
            TaskContextProjector(index).build(max_bytes=1800)
        assert "semantic requirement compaction is not implemented" in blocked.value.reason
        assert blocked.value.as_dict()["status"] == "CONTEXT_BLOCKED"
    finally:
        backend.close()


def test_projection_stops_reading_required_bodies_after_overflow_is_proven(tmp_path: Path, monkeypatch) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-overflow", goal="G" * 10_000)
        for number in range(2):
            backend.accept_input(
                "task-overflow",
                input_id=f"correction-{number}",
                kind=InputKind.CORRECTION,
                body=f"CORRECTION-{number}",
            )
            backend.handle_next_input("task-overflow", affects_goal=True, affects_acceptance=True)
        index = LoopContextIndex(backend.store, "task-overflow")
        expected_refs = tuple(item.source_ref for item in index.requirement_entries())
        original_read = backend.store.read_json
        reads: list[str] = []

        def counted_read(reference_id, *, expected_hash=None):
            reads.append(reference_id)
            return original_read(reference_id, expected_hash=expected_hash)

        monkeypatch.setattr(backend.store, "read_json", counted_read)
        with pytest.raises(ContextCoverageBlocked) as blocked:
            TaskContextProjector(index).build(max_bytes=2_000)
        assert len(reads) == 1
        assert blocked.value.required_source_refs == tuple(sorted(expected_refs))
    finally:
        backend.close()


def test_pinned_blocker_and_recent_attempts_survive_many_unrelated_history_rows(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-pinned")
        backend.execute_operation(
            "task-pinned",
            read_intent(backend, "task-pinned", "blocker-evidence"),
            lambda: OperationOutcome(EffectStatus.FAILED, {"finding": "direct blocker evidence"}),
        )
        task = backend.get_task("task-pinned")
        result_ref = str(task.operations["blocker-evidence"].result_ref)
        backend.dock_waiting(
            "task-pinned",
            status=TaskStatus.WAITING_INPUT,
            blocker_id="stable-blocker",
            reason="CURRENT-BLOCKER-REASON",
            evidence_refs=(result_ref,),
        )
        for number in range(30):
            backend.settle_attempt(
                "task-pinned",
                attempt_id=f"later-attempt-{number}",
                blocker_id=f"unclassified-{number}",
                outcome="unrelated committed history row",
                relevant_progress=False,
                evidence_refs=(),
            )
        projection = TaskContextProjector(LoopContextIndex(backend.store, "task-pinned")).build(
            max_bytes=8_000,
            max_history_rows=2,
            max_recent_attempts=4,
        )
        assert projection.current_blocker["blocker_id"] == "stable-blocker"
        assert projection.current_blocker["reason"] == "CURRENT-BLOCKER-REASON"
        assert projection.current_blocker["reference_resolution_complete"] is True
        assert projection.current_blocker["evidence_verification_status"] == "VERIFIED"
        assert projection.current_blocker["evidence_sources"][0]["verification_status"] == "VERIFIED"
        assert projection.ready_for_request is True
        assert len(projection.recent_attempts) == 4
        assert projection.eliminated_method_index["methods"] == []
        assert projection.eliminated_method_index["classification_status"] == "NOT_CLASSIFIED"
        assert len(projection.history_directory) <= 2
        assert projection.open_obligations[0]["status"] == "OPEN_OR_UNVERIFIED"
    finally:
        backend.close()


def test_stale_current_blocker_evidence_cannot_claim_request_coverage(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-stale-blocker")
        backend.execute_operation(
            "task-stale-blocker",
            read_intent(backend, "task-stale-blocker", "stale-evidence"),
            lambda: OperationOutcome(EffectStatus.FAILED, {"finding": "will become stale"}),
        )
        task = backend.get_task("task-stale-blocker")
        result_ref = str(task.operations["stale-evidence"].result_ref)
        backend.dock_waiting(
            "task-stale-blocker",
            status=TaskStatus.WAITING_INPUT,
            blocker_id="stale-blocker",
            reason="depends on committed evidence",
            evidence_refs=(result_ref,),
        )
        index = LoopContextIndex(backend.store, "task-stale-blocker")
        index.refresh()
        evidence_entry = next(
            item for item in index.entries
            if item.kind == "operation_result" and item.subject_id == "stale-evidence"
        )
        object_ref = backend.store.cas.resolve_reference(evidence_entry.internal_cas_ref)
        backend.store.cas._object_path(object_ref.object_id).unlink()

        projection = TaskContextProjector(index).build(max_bytes=8_000)
        assert projection.current_blocker["reference_resolution_complete"] is True
        assert projection.current_blocker["evidence_verification_status"] == "STALE"
        assert projection.current_blocker["evidence_sources"][0]["verification_status"] == "STALE"
        assert projection.ready_for_request is False
        verification = RequirementCoverageVerifier.verify(index, projection)
        assert not verification.verified
        assert "current blocker evidence is stale or unverifiable" in verification.reasons
        query = LoopHistoryQuery(index, max_page_bytes=4096)
        assert query.read(source_ref=evidence_entry.source_ref, max_bytes=1200)["status"] == "STALE_SOURCE"
    finally:
        backend.close()


def test_coverage_verifier_rechecks_blocker_evidence_after_projection(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-blocker-race")
        backend.execute_operation(
            "task-blocker-race",
            read_intent(backend, "task-blocker-race", "race-evidence"),
            lambda: OperationOutcome(EffectStatus.FAILED, {"finding": "present at projection time"}),
        )
        task = backend.get_task("task-blocker-race")
        result_ref = str(task.operations["race-evidence"].result_ref)
        backend.dock_waiting(
            "task-blocker-race",
            status=TaskStatus.WAITING_INPUT,
            blocker_id="race-blocker",
            reason="evidence can become stale after projection",
            evidence_refs=(result_ref,),
        )
        index = LoopContextIndex(backend.store, "task-blocker-race")
        projection = TaskContextProjector(index).build(max_bytes=8_000)
        assert projection.current_blocker["evidence_verification_status"] == "VERIFIED"
        assert projection.ready_for_request is True

        evidence_entry = next(
            item for item in index.entries
            if item.kind == "operation_result" and item.subject_id == "race-evidence"
        )
        object_ref = backend.store.cas.resolve_reference(evidence_entry.internal_cas_ref)
        backend.store.cas._object_path(object_ref.object_id).unlink()

        verification = RequirementCoverageVerifier.verify(index, projection)
        assert not verification.verified
        assert "current blocker evidence became stale after projection" in verification.reasons
    finally:
        backend.close()


def test_coverage_verifier_rechecks_binding_after_concurrent_correction(tmp_path: Path, monkeypatch) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-verify-race", goal="EARLY")
        index = LoopContextIndex(backend.store, "task-verify-race")
        projection = TaskContextProjector(index).build(max_bytes=4_000)
        original_read = backend.store.read_json
        injected = False

        def read_then_correct(reference_id, *, expected_hash=None):
            nonlocal injected
            if not injected:
                injected = True
                backend.accept_input(
                    "task-verify-race",
                    input_id="during-verification",
                    kind=InputKind.CORRECTION,
                    body="LATEST",
                )
                backend.handle_next_input("task-verify-race", affects_goal=True, affects_acceptance=True)
            return original_read(reference_id, expected_hash=expected_hash)

        monkeypatch.setattr(backend.store, "read_json", read_then_correct)
        result = RequirementCoverageVerifier.verify(index, projection)
        assert injected
        assert not result.verified
        assert "task binding changed after projection" in result.reasons
    finally:
        backend.close()


def test_context_block_commit_is_bound_nonterminal_and_not_no_progress(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        task = create_task(backend, "task-block")
        index = LoopContextIndex(backend.store, "task-block")
        refs = tuple(sorted(item.source_ref for item in index.requirement_entries()))
        blocked = backend.dock_context_blocked(
            "task-block",
            reason="required constraints exceed the qualified request capacity",
            capacity_identity={"profile": "fixture", "endpoint": "https://api.example.test/v1", "model": "m"},
            counting={"mode": "conservative_utf8", "input_bound_tokens": 1001, "capacity_tokens": 1000},
            required_source_refs=refs,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_handled_input_seq=task.handled_input_seq,
            expected_artifact_ref=task.artifact_ref,
        )
        assert blocked.status is TaskStatus.CONTEXT_BLOCKED
        assert not blocked.is_terminal
        assert blocked.attempt_settlements == ()
        assert blocked.operations == {}
        assert blocked.waiting_reason["provider_effect_created"] is False
        assert blocked.waiting_reason["no_progress_incremented"] is False

        old = blocked
        backend.accept_input("task-block", input_id="correction", kind=InputKind.CORRECTION, body="new requirement")
        resumed = backend.handle_next_input("task-block", affects_goal=True, affects_acceptance=True)
        assert resumed.status is TaskStatus.RUNNABLE
        assert resumed.waiting_reason is None
        with pytest.raises(TaskConflict):
            backend.dock_context_blocked(
                "task-block",
                reason="stale blocker",
                capacity_identity={"profile": "fixture"},
                counting={"mode": "fixture"},
                required_source_refs=refs,
                expected_task_revision=old.task_revision,
                expected_run_instance_id=old.run_instance_id,
                expected_execution_epoch=old.execution_epoch,
                expected_goal_version=old.goal_version,
                expected_acceptance_version=old.acceptance_version,
                expected_handled_input_seq=old.handled_input_seq,
                expected_artifact_ref=old.artifact_ref,
            )
    finally:
        backend.close()


@pytest.mark.parametrize("kind", [InputKind.PAUSE, InputKind.CANCEL])
def test_context_block_cannot_overwrite_pause_or_cancel(tmp_path: Path, kind: InputKind) -> None:
    backend = LoopBackend.open(tmp_path / kind.value, keychain_backend=MemoryKeychainBackend())
    try:
        task = create_task(backend, f"task-{kind.value.lower()}")
        backend.accept_input(task.task_id, input_id="control", kind=kind, body="")
        current = backend.handle_next_input(task.task_id)
        with pytest.raises(TaskConflict):
            backend.dock_context_blocked(
                task.task_id,
                reason="must not override control",
                capacity_identity={"profile": "fixture"},
                counting={"mode": "fixture"},
                required_source_refs=("history:fixture",),
                expected_task_revision=current.task_revision,
                expected_run_instance_id=current.run_instance_id,
                expected_execution_epoch=current.execution_epoch,
                expected_goal_version=current.goal_version,
                expected_acceptance_version=current.acceptance_version,
                expected_handled_input_seq=current.handled_input_seq,
                expected_artifact_ref=current.artifact_ref,
            )
    finally:
        backend.close()


def test_context_block_does_not_replace_unknown_effect_responsibility(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        task = create_task(backend, "task-unknown")
        backend.execute_operation(
            task.task_id,
            read_intent(backend, task.task_id, "unknown-read"),
            lambda: OperationOutcome(EffectStatus.UNKNOWN, {"requires_probe": True}),
        )
        current = backend.get_task(task.task_id)
        assert current.unresolved_effects
        with pytest.raises(TaskConflict):
            backend.dock_context_blocked(
                task.task_id,
                reason="must not replace unknown effect",
                capacity_identity={"profile": "fixture"},
                counting={"mode": "fixture"},
                required_source_refs=("history:fixture",),
                expected_task_revision=current.task_revision,
                expected_run_instance_id=current.run_instance_id,
                expected_execution_epoch=current.execution_epoch,
                expected_goal_version=current.goal_version,
                expected_acceptance_version=current.acceptance_version,
                expected_handled_input_seq=current.handled_input_seq,
                expected_artifact_ref=current.artifact_ref,
            )
        assert backend.get_task(task.task_id).unresolved_effects
    finally:
        backend.close()
