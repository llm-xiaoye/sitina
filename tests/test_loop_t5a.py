from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from sitina.loop import InputKind, LoopBackend, LoopHost
from sitina.loop.child_model import ReadonlyChildModelRunner
from sitina.loop.context_window import LoopContextIndex
from sitina.loop.delegation import (
    CHILD_RUNTIME_RESULT_SCHEMA,
    CHILD_RUNTIME_SCHEMA,
    ReadonlyChildCapability,
    ReadonlySourceDenied,
)
from sitina.loop.delegation import ReadonlyChildError
from sitina.loop.model import TaskConflict, TaskStatus
from sitina.security.macos_keychain import MemoryKeychainBackend
from sitina.runners.provider import ProviderProfile, ProviderToolCall, ProviderToolTurn, ScriptedMockToolClient
from sitina.extensions.runtime import BoundedToolTurnClient


def _backend_task(tmp_path: Path, *, task_id: str = "parent"):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "facts.txt"
    source.write_text("immutable facts", encoding="utf-8")
    backend = LoopBackend.open(state, keychain_backend=MemoryKeychainBackend())
    backend.admit_task(
        task_id=task_id,
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
        submission_id=f"submission-{task_id}",
    )
    return backend, workspace, source


def test_t5a_admission_is_new_runtime_schema_and_exactly_idempotent(tmp_path: Path) -> None:
    backend, workspace, source = _backend_task(tmp_path)
    try:
        first = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        repeated = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        assert first.delegation_id == repeated.delegation_id
        assert first.status == "ADMITTED"
        assert backend.get_task("parent").as_dict()["child_delegation_count"] == 1
        contract_event = backend.store.task_events("parent")[-1]
        contract = backend.context_memory.read(
            str(contract_event.payload["contract_ref"]),
            expected_hash=str(contract_event.payload["contract_hash"]),
        )
        assert contract["schema"] == CHILD_RUNTIME_SCHEMA
        assert contract["delegation_contract_version"] == "sitina-delegation-v1"
        assert contract["recursive_delegation"] is False
        for index in range(1, backend.READONLY_CHILD_DELEGATION_LIMIT):
            backend.admit_child_delegation(
                "parent",
                problem_id=f"facts-{index}",
                objective=f"inspect bounded question {index}",
                sources=({"kind": "file", "path": str(source)},),
            )
        before = backend.get_task("parent").task_revision
        with pytest.raises(TaskConflict, match="readonly child delegation limit"):
            backend.admit_child_delegation(
                "parent",
                problem_id="overflow",
                objective="one more independent question",
                sources=({"kind": "file", "path": str(source)},),
            )
        assert backend.get_task("parent").task_revision == before
        repeated_at_limit = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        assert repeated_at_limit.delegation_id == first.delegation_id
        assert backend.get_task("parent").as_dict()["child_delegation_count"] == backend.READONLY_CHILD_DELEGATION_LIMIT
    finally:
        backend.close()


def test_t5a_actual_child_capability_reads_only_declared_sources(tmp_path: Path) -> None:
    from dataclasses import replace

    from sitina.loop.context_window import LoopHistoryQuery
    from sitina.loop.model import EffectStatus, OperationMode
    from sitina.loop.operations import OperationIntent, OperationOutcome, RecoveryPolicy
    from sitina.loop.task_runtime import _completion_business_evidence, _workspace_snapshot
    from sitina.loop.termination import AttemptPlan

    backend, workspace, source = _backend_task(tmp_path)
    try:
        backend.plan_attempt("parent", AttemptPlan(
            attempt_id="business-evidence", lineage_id="parent:main-investigation:outcome-1",
            acceptance_item_id="outcome-1", blocker_id="inspect", blocker_source="goal",
            question_or_hypothesis="Inspect declared facts and the history boundary.",
            max_control_segments=10, max_provider_responses=2, max_tool_call_groups=3,
            allowed_action_kinds=("READ",), exit_conditions=("observations recorded",),
        ))

        def execute(call_id, payload):
            current = backend.get_task("parent")
            return backend.execute_operation("parent", OperationIntent(
                operation_id="evidence-" + call_id, logical_operation_id="evidence:" + call_id,
                attempt_id="physical-" + call_id, mode=OperationMode.READ,
                description="existing child evidence regression", resources=(),
                expected_task_revision=current.task_revision,
                expected_run_instance_id=current.run_instance_id,
                expected_execution_epoch=current.execution_epoch,
                expected_goal_version=current.goal_version,
                expected_acceptance_version=current.acceptance_version,
                expected_handled_input_seq=current.handled_input_seq,
                capability_snapshot_id=current.capability_snapshot_id, preconditions=(),
                recovery=RecoveryPolicy("inspect", "never", "retain", "retain", "block", "reconcile"),
                business_attempt_id="business-evidence",
            ), lambda: OperationOutcome(EffectStatus.SUCCEEDED, payload()))

        foreign_ref = "history:" + "0" * 64 + ":1:" + "1" * 64
        history_arguments = {"operation": "read", "source_ref": foreign_ref, "offset": 0, "max_bytes": 4096}
        delegate_arguments = {
            "problem_id": "facts", "objective": "read the facts",
            "sources": [{"kind": "file", "path": str(source)}],
        }
        execute("provider-turn:1", lambda: {
            "turn": 1, "tool_calls": [
                {"id": "history", "name": "sitina_history_query", "arguments": history_arguments},
                {"id": "delegate", "name": "sitina_delegate_readonly", "arguments": delegate_arguments},
            ],
        })
        index = LoopContextIndex(backend.store, "parent")
        history = LoopHistoryQuery(index, max_page_bytes=4096)
        denial = history.read(source_ref=foreign_ref)
        assert denial["status"] == "NOT_VISIBLE"
        execute("history", lambda: {
            "tool": "sitina_history_query", "status": "ok",
            "arguments": history_arguments, "value": denial,
        })
        children = []

        def delegate():
            child = backend.admit_child_delegation("parent", **delegate_arguments)
            children.append(child)
            # Match the native pending tool receipt; the full parent binding
            # lives in its separately committed child contract.
            pending = {key: child.as_dict()[key] for key in (
                "schema", "delegation_id", "child_task_id", "parent_task_id", "generation", "problem_id",
            )}
            pending["status"] = "WAITING_CHILD"
            return {"tool": "sitina_delegate_readonly", "status": "ok",
                    "arguments": delegate_arguments, "value": pending}

        execute("delegate", delegate)
        child = children[0]
        source_id = child.source_manifest[0]["source_id"]
        goal = {"acceptance_conditions": ["Explain the observed query and child result.", "Read facts.txt."]}
        snapshot = _workspace_snapshot(workspace)

        def evidence(current):
            return _completion_business_evidence(current, index, goal, snapshot, workspace)

        assert not any(
            item.get("observation_kind") == "COMMITTED_CHILD_RESULT"
            for item in evidence(backend.get_task("parent"))["business_facts"]
        )

        def work(capability: ReadonlyChildCapability):
            assert capability.read_source(source_id) == "immutable facts"
            with pytest.raises(ReadonlySourceDenied):
                capability.read_source("source:not-declared")
            with pytest.raises(ReadonlySourceDenied):
                capability.deny("write_file")
            return capability.report(summary="facts read", evidence_source_ids=(source_id,))

        settled = backend.dispatch_child_delegation("parent", child.delegation_id, work)
        assert settled.status == "SETTLED"
        result = backend.context_memory.read(str(settled.result_ref))
        assert result["schema"] == CHILD_RUNTIME_RESULT_SCHEMA
        assert result["approves_parent"] is False
        assert result["observations"][0]["source_id"] == source_id
        current = backend.get_task("parent")
        observed = evidence(current)
        child_facts = [item for item in observed["business_facts"]
                       if item.get("observation_kind") == "COMMITTED_CHILD_RESULT"]
        assert len(child_facts) == 1
        child_fact = child_facts[0]
        index.refresh()
        child_entry = next(entry for entry in index.entries if entry.kind == "child_result")
        assert child_fact["source_ref"] == child_entry.source_ref
        assert child_fact["content_hash"] == child_entry.content_hash
        assert child_fact["result_ref"] == settled.result_ref
        assert child_fact["content_objects"] == []
        queries = [item for item in observed["business_facts"]
                   if item.get("observation_kind") == "COMMITTED_HISTORY_QUERY_RESULT"]
        assert len(queries) == 1
        query = queries[0]
        assert query["status"] == "SUCCEEDED"
        assert query["query_result_status"] == "NOT_VISIBLE"
        assert query["content_objects"] == []
        assert foreign_ref not in {item["source_ref"] for item in observed["business_facts"]}
        assert observed["completed_sources"] == []
        assert observed["condition_observations"][0]["host_observation_satisfied"] is None
        assert observed["condition_observations"][1]["host_observation_satisfied"] is False
        # Reading these receipts cannot manufacture underlying file coverage.
        for reference in (query["source_ref"], child_fact["source_ref"]):
            assert history.read(source_ref=reference)["status"] == "OK"
        assert evidence(current) == observed

        for field, invalid in (
            ("status", "RESULT_PERSISTED"), ("applicability", "LATE_EVIDENCE_ONLY"),
            ("parent_task_id", "another-parent"), ("parent_attempt_id", "another-attempt"),
            ("result_hash", "0" * 64), ("settlement_hash", "0" * 64),
            ("unknown_effect", True),
        ):
            children = {key: dict(value) for key, value in current.child_delegations.items()}
            children[child.delegation_id][field] = invalid
            rejected = evidence(replace(current, child_delegations=children))
            assert not any(item.get("observation_kind") == "COMMITTED_CHILD_RESULT"
                           for item in rejected["business_facts"]), field
        newer_input = replace(current, received_input_seq=current.received_input_seq + 1)
        assert not any(item.get("observation_kind") == "COMMITTED_CHILD_RESULT"
                       for item in evidence(newer_input)["business_facts"])
    finally:
        backend.close()


def test_t5a_empty_child_evidence_is_explicit_rejection_not_success(tmp_path: Path) -> None:
    backend, _workspace, source = _backend_task(tmp_path)
    try:
        child = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )

        def rejected(capability: ReadonlyChildCapability):
            result = capability.report(summary="no source was actually read", evidence_source_ids=())
            assert result["status"] == "REJECTED"
            assert result["evidence_source_ids"] == []
            return result

        settled = backend.dispatch_child_delegation("parent", child.delegation_id, rejected)
        assert settled.status == "SETTLED"
        result = backend.context_memory.read(str(settled.result_ref))
        assert result["status"] == "REJECTED"
        assert result["observations"] == []
    finally:
        backend.close()


@pytest.mark.parametrize(
    "bad_result",
    [
        {"schema": "SITINA_LOOP_CHILD_RESULT_V1", "summary": "old envelope"},
        {"schema": CHILD_RUNTIME_RESULT_SCHEMA, "summary": "never read", "approves_parent": False},
    ],
)
def test_t5a_invalid_child_report_is_failed_and_execution_is_cleared(tmp_path: Path, bad_result) -> None:
    backend, _workspace, source = _backend_task(tmp_path)
    try:
        child = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        settled = backend.dispatch_child_delegation("parent", child.delegation_id, lambda _capability: bad_result)
        assert settled.status == "SETTLED"
        assert ("parent", child.delegation_id) not in backend._child_running
        result = backend.context_memory.read(str(settled.result_ref))
        assert result["status"] in {"FAILED", "REJECTED"}
        assert result["evidence_source_ids"] == []
    finally:
        backend.close()


def test_t5a_provider_runner_reads_source_and_persists_private_turn_operation(tmp_path: Path) -> None:
    backend, _workspace, source = _backend_task(tmp_path)
    try:
        source.write_bytes(b"abcdefgh" * 12)
        child = backend.admit_child_delegation(
            "parent", problem_id="facts", objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        source_id = child.source_manifest[0]["source_id"]
        metadata = {"protocol": "mock", "physical_send_count": 1,
                    "token_usage": {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150}}
        turns = [
            ProviderToolTurn(
                "", (ProviderToolCall("read-" + str(i), "sitina_child_read_source",
                                     {"source_id": source_id, "offset": i * 8, "max_bytes": 8}),),
                "tool_calls", dict(metadata), "private reasoning" if i == 0 else "",
            ) for i in range(9)
        ]
        turns.append(ProviderToolTurn(
            "", (ProviderToolCall("report", "sitina_child_report",
                                 {"summary": "facts read", "evidence_source_ids": [source_id]}),),
            "tool_calls", dict(metadata),
        ))
        client = ScriptedMockToolClient(turns)
        profile = ProviderProfile("mock", "mock://offline", "", "scripted-mock")
        runner = ReadonlyChildModelRunner(
            BoundedToolTurnClient(client, profile, retry_limit=0, fallback_allowed=False),
            profile, max_tokens=4096,
        )
        settled = backend.dispatch_child_delegation(
            "parent", child.delegation_id,
            lambda capability: runner.run(
                capability, capability.objective,
                provider_call=lambda dispatch: backend.execute_child_provider_turn(
                    "parent", child.delegation_id, dispatch
                ),
            ),
        )
        assert settled.status == "SETTLED"
        result = backend.context_memory.read(str(settled.result_ref))
        assert result["execution_mode"] == "provider_model"
        assert result["provider_call_count"] == 10
        assert result["evidence_source_ids"] == [source_id]
        control = result["execution_control"]
        assert control["explicit_turn_limit"] is None
        assert control["explicit_total_token_budget"] is None
        assert control["verified_evidence_bytes"] == 72
        assert control["cumulative_reported_usage"]["total_tokens"] == 1500
        assert len({item["allocated_output_tokens"] for item in control["controls"]}) > 1
        assert all(item["allocated_output_tokens"] <= 4096 for item in control["controls"])
        provider_ops = [
            operation for operation in backend.get_task("parent").operations.values()
            if operation.logical_operation_id.startswith(f"child:{child.delegation_id}:provider:")
        ]
        assert len(provider_ops) == 10
        assert all(operation.result_ref for operation in provider_ops)
        assert any(item.get("reasoning_content") == "private reasoning"
                   for item in client.received_messages[1])
        assert "reasoning_content" not in result
    finally:
        backend.close()


def test_t5a_child_tool_schema_enforces_bounded_read_types(tmp_path: Path) -> None:
    import itertools
    import json

    from sitina.loop.context_window import ModelCapacityRegistry, ProviderContextIdentity
    from sitina.runners.provider import ProviderHTTPError, ProviderReadTimeout

    backend, _workspace, source = _backend_task(tmp_path)
    try:
        child = backend.admit_child_delegation(
            "parent", problem_id="facts", objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        source_id = child.source_manifest[0]["source_id"]
        profile = ProviderProfile("mock", "mock://offline", "", "scripted-mock")
        metadata = {"protocol": "mock", "physical_send_count": 1,
                    "token_usage": {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150}}

        def read_turn():
            return ProviderToolTurn(
                "", (ProviderToolCall("read", "sitina_child_read_source", {"source_id": source_id}),),
                "tool_calls", dict(metadata),
            )

        def report_turn(summary="complete", stop="tool_calls", repaired=False):
            return ProviderToolTurn(
                "", (ProviderToolCall("report", "sitina_child_report",
                                     {"summary": summary, "evidence_source_ids": [source_id]}),),
                stop, {**metadata, "json_repair_count": int(repaired)},
            )

        class ObservedClient:
            def __init__(self, sequence):
                self.sequence = list(sequence)
                self.requests = []

            def complete_tool_turn(self, selected_profile, **kwargs):
                self.requests.append({"max_tokens": kwargs["max_tokens"], "profile": selected_profile.name})
                value = self.sequence.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return value

        def setup(sequence, *, selected_profile=profile, **limits):
            client = ObservedClient(sequence)
            options = {"max_tokens": 4096, **limits}
            runner = ReadonlyChildModelRunner(
                BoundedToolTurnClient(client, selected_profile, retry_limit=0, fallback_allowed=False),
                selected_profile, **options,
            )
            capability = ReadonlyChildCapability(child.source_manifest, parent_binding=child.parent_binding)
            return runner, client, capability

        capability = ReadonlyChildCapability(child.source_manifest, parent_binding=child.parent_binding)
        for invalid_bound in (True, 65537):
            with pytest.raises(ReadonlyChildError):
                ReadonlyChildModelRunner._dispatch_tool(
                    capability, "sitina_child_read_source",
                    {"source_id": source_id, "max_bytes": invalid_bound},
                )

        # Neither a length-stopped report nor repaired arguments may be used
        # as an executable decision. A subsequent complete response is needed.
        runner, client, capability = setup(
            [read_turn(), report_turn("PARTIAL", "length"), report_turn()]
        )
        result = runner.run(capability, "read the facts")
        assert result["summary"] == "complete"
        assert len(client.requests) == 3
        assert client.requests[2]["max_tokens"] > client.requests[1]["max_tokens"]
        assert result["execution_control"]["controls"][2]["recovery"]["basis"] == "observed_output_truncation"

        runner, client, capability = setup(
            [read_turn(), report_turn("REPAIRED", repaired=True), report_turn()]
        )
        assert runner.run(capability, "read the facts")["summary"] == "complete"
        assert len(client.requests) == 3

        # New byte coverage was proved above beyond eight turns; repeated
        # reads of the same immutable bytes must not refresh the idle clock.
        runner, client, capability = setup([read_turn() for _ in range(20)])
        ticks = itertools.count(0.0, 100.0)
        runner._monotonic = lambda: next(ticks)
        with pytest.raises(ReadonlyChildError, match="no verified evidence progress"):
            runner.run(capability, "read the facts")
        assert 1 < len(client.requests) < 20

        runner, client, capability = setup([read_turn(), report_turn()], max_turns=1)
        with pytest.raises(ReadonlyChildError, match="explicitly supplied turn budget"):
            runner.run(capability, "read the facts")
        assert len(client.requests) == 1

        # A timed-out/unknown send has no recovery proof and must not repeat.
        unknown = ProviderReadTimeout("response body remains unknown")
        unknown.sitina_physical_send_count = None
        unknown.sitina_physical_send_status = "response_received"
        runner, client, capability = setup([unknown, read_turn(), report_turn()])
        with pytest.raises(ProviderReadTimeout):
            runner.run(capability, "read the facts")
        assert len(client.requests) == 1

        def throttled(message):
            error = ProviderHTTPError(429, message, retry_after_seconds=0.001)
            error.sitina_physical_send_count = 1
            error.sitina_physical_send_status = "http_error"
            return error

        runner, client, capability = setup([throttled("wait"), read_turn(), report_turn()])
        result = runner.run(capability, "read the facts")
        assert result["summary"] == "complete" and len(client.requests) == 3
        recovery = result["execution_control"]["controls"][0]["retry_evidence"]
        assert len(recovery) == 1
        assert recovery[0]["waited_milliseconds"] >= recovery[0]["retry_after_milliseconds"]
        assert result["execution_control"]["cumulative_reported_usage"]["total_tokens"] is None

        runner, client, capability = setup([throttled("first"), throttled("different wording"), read_turn()])
        with pytest.raises(ProviderHTTPError):
            runner.run(capability, "read the facts")
        assert len(client.requests) == 2

        # Cancellation/version/source restrictions remain send/tool barriers.
        for field, value in (("control_intent", "CANCEL"), ("goal_version", 999)):
            runner, client, _ = setup([read_turn(), report_turn()])
            stale = ReadonlyChildCapability(
                child.source_manifest, parent_binding=child.parent_binding,
                binding_guard=lambda field=field, value=value: {**child.parent_binding, field: value},
            )
            with pytest.raises(ReadonlyChildError):
                runner.run(stale, "read the facts")
            assert client.requests == []
        forbidden = ProviderToolTurn(
            "", (ProviderToolCall("forbidden", "shell", {"command": "write"}),),
            "tool_calls", dict(metadata),
        )
        runner, client, capability = setup([forbidden, report_turn()])
        with pytest.raises(ReadonlyChildError):
            runner.run(capability, "read the facts")
        assert len(client.requests) == 1

        config = json.loads((Path(__file__).parents[1] / "config/loop_context_capacity.json").read_text())
        entry = config["entries"][0]
        registry = ModelCapacityRegistry.from_mapping(config)
        actual_profile = ProviderProfile(
            entry["profile"], entry["endpoint"], "", entry["model"], entry["wire_protocol"]
        )
        identity = ProviderContextIdentity(
            entry["profile"], entry["endpoint"], entry["model"], entry["wire_protocol"]
        )
        configured = {"selected_profile": actual_profile, "max_tokens": None,
                      "capacity_registry": registry, "capacity_identity": identity}
        runner, client, capability = setup([read_turn(), report_turn()],
                                            total_token_budget=1, **configured)
        with pytest.raises(ReadonlyChildError, match="explicitly supplied token budget"):
            runner.run(capability, "read the facts")
        assert client.requests == []
        runner, client, capability = setup([read_turn(), report_turn()],
                                            total_token_budget=100000, **configured)
        result = runner.run(capability, "read the facts")
        assert result["execution_control"]["budget_charge"] == 300
        assert all(item["request_token_bound"] is not None
                   for item in result["execution_control"]["controls"])
        runner, client, capability = setup([read_turn(), report_turn()], **configured)
        with pytest.raises(ReadonlyChildError, match="context policy"):
            runner.run(capability, "facts " * 210000)
        assert client.requests == []
    finally:
        backend.close()


def test_t5a_history_source_uses_model_visible_public_handle_and_projection(tmp_path: Path) -> None:
    backend, _workspace, _source = _backend_task(tmp_path)
    try:
        index = LoopContextIndex(backend.store, "parent")
        index.refresh()
        goal_ref = next(entry.source_ref for entry in index.entries if entry.kind == "goal")
        child = backend.admit_child_delegation(
            "parent",
            problem_id="history",
            objective="inspect the parent goal",
            sources=({"kind": "history", "source_ref": goal_ref},),
        )
        capability = ReadonlyChildCapability(
            child.source_manifest,
            parent_binding=child.parent_binding,
        )
        page = capability.read_source(child.source_manifest[0]["source_id"])
        assert page["status"] == "OK"
        assert page["source_ref"] == goal_ref
    finally:
        backend.close()


def test_t5a_parent_control_change_blocks_pre_dispatch_and_terminal_waits_for_child(tmp_path: Path) -> None:
    backend, _workspace, source = _backend_task(tmp_path)
    try:
        child = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        backend.accept_input("parent", input_id="cancel", kind=InputKind.CANCEL, body="stop")
        backend.handle_next_input("parent")
        blocked = backend.dispatch_child_delegation(
            "parent",
            child.delegation_id,
            lambda _capability: {"summary": "must not run"},
        )
        assert blocked.status == "CANCELLED_VERIFIED"
        assert blocked.result_ref is None
        assert backend.can_propose_terminal("parent") is True
    finally:
        backend.close()


def test_t5a_late_result_keeps_original_binding_and_does_not_approve_parent(tmp_path: Path) -> None:
    backend, _workspace, source = _backend_task(tmp_path)
    try:
        child = backend.admit_child_delegation(
            "parent",
            problem_id="facts",
            objective="read the facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        source_id = child.source_manifest[0]["source_id"]
        started = threading.Event()
        release = threading.Event()

        def work(capability):
            started.set()
            release.wait(2)
            return capability.report(summary="old facts", evidence_source_ids=())

        result: list[object] = []
        thread = threading.Thread(
            target=lambda: result.append(
                backend.dispatch_child_delegation("parent", child.delegation_id, work)
            ),
            daemon=True,
        )
        thread.start()
        assert started.wait(2)
        # The child was already dispatched; the changed parent target makes
        # its eventual result historical evidence, not a new current answer.
        backend.accept_input("parent", input_id="correction", kind=InputKind.CORRECTION, body="new target")
        backend.handle_next_input("parent")
        release.set()
        thread.join(2)
        late = result[0]
        assert late.status == "SETTLED"
        assert late.applicability == "LATE_EVIDENCE_ONLY"
        assert backend.can_propose_terminal("parent") is True
    finally:
        backend.close()


def test_t5a_host_child_slot_and_drain_hold_until_result(tmp_path: Path) -> None:
    import json

    config = Path(__file__).resolve().parents[1] / "config"
    limits = json.loads((config / "orchestration_policy.json").read_text())["resource_limits"]
    monitoring = json.loads((config / "observability_policy.json").read_text())
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "facts.txt"
    source.write_text("facts", encoding="utf-8")
    context = {
        "provider_identity": "fixture-provider",
        "environment_ref": "fixture-environment",
        "capability_snapshot_id": "fixture-capability",
        "software_identity": "fixture-software",
        "config_identity": "fixture-config",
    }
    started = threading.Event()
    release = threading.Event()

    def child_work(capability):
        started.set()
        release.wait(2)
        source_id = capability.list_sources()[0]["source_id"]
        capability.read_source(source_id)
        return capability.report(summary="done", evidence_source_ids=(source_id,))

    host = LoopHost(
        root,
        keychain_backend=MemoryKeychainBackend(),
        descriptor_context=context,
        child_work=child_work,
        resource_limits=limits,
        observability_policy=monitoring,
    ).start()
    try:
        assert host.health()["monitoring"]["enabled"] is True
        assert host._queue.maxsize == limits["queue_capacity"]
        host._handle_command(
            {
                "command": "submit",
                "task_id": "parent",
                "submission_id": "submission",
                "task_kind": "readonly",
                "goal": "inspect facts",
                "workspace": str(workspace),
                "provider_profile": "fixture",
                "approve_writes": False,
            }
        )
        receipt = host.backend.delegate_readonly(
            "parent",
            problem_id="facts",
            objective="read facts",
            sources=({"kind": "file", "path": str(source)},),
        )
        assert receipt["status"] == "WAITING_CHILD"
        assert started.wait(2)
        host.begin_drain()
        assert host.close() is None
        # close keeps the lease while the child can still append its result.
        assert host.lease is not None
        release.set()
        deadline = time.monotonic() + 3
        while host._child_executor.active() and time.monotonic() < deadline:
            time.sleep(0.02)
        host.close()
        assert host.lease is None
    finally:
        release.set()
        host.close()
