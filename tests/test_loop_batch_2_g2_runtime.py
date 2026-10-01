from __future__ import annotations

import hashlib
import base64
import json
import sys
import threading
from pathlib import Path
from typing import Any, Mapping

import pytest

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.loop import EffectStatus, InputKind, LoopBackend, OperationMode
from sitina.loop.context_window import (
    ContextAdmissionBlocked,
    ContextCoverageBlocked,
    LoopContextIndex,
    LoopHistoryQuery,
    LoopRequestAssembler,
    ModelCapacityRegistry,
    ProviderContextIdentity,
    render_provider_tool_request,
)
from sitina.loop.development import DevelopmentBoundary
from sitina.loop.control import send_control_request
from sitina.loop.operations import OperationIntent, OperationOutcome, RecoveryPolicy
from sitina.loop.task_runtime import LoopTaskRunner, _verified_history_read_source_refs
from sitina.runners.provider import (
    ANTHROPIC_MESSAGES,
    OPENAI_CHAT_COMPLETIONS,
    AnthropicCompatibleClient,
    ProviderMalformedResponse,
    ProviderProfile,
    ProviderToolCall,
    ProviderToolTurn,
)
from sitina.security.key_provider import KeyProviderError
from tests.test_loop_batch_1b_runtime import scripted_factory


class MemoryKeychainBackend:
    provider_id = "memory-keychain-g2"

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}

    def get(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        key = (service, account)
        if key in self.items and not replace:
            raise KeyProviderError("already exists")
        self.items[key] = bytes(value)

    def public_inventory(self) -> dict[str, object]:
        return {"schema": "MEMORY_KEYCHAIN_G2", "secret_values_included": False}


MOCK_IDENTITY = ProviderContextIdentity(
    "mock",
    "mock://offline",
    "scripted",
    OPENAI_CHAT_COMPLETIONS,
)


def capacity_registry(
    *,
    capacity: int = 1_000_000,
    history_max: int = 8192,
    counter_mode: str = "conservative_utf8",
    identity: ProviderContextIdentity = MOCK_IDENTITY,
) -> ModelCapacityRegistry:
    return ModelCapacityRegistry.from_mapping({
        "schema": "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1",
        "entries": [{
            **identity.as_dict(),
            "context_capacity_tokens": capacity,
            "next_tool_turn_receipt_reserve_tokens": 512,
            "history_query_max_bytes": history_max,
            "counter": {
                "mode": counter_mode,
                "name": "g2-fixture-counter",
                "applicability": "offline exact-wire G2 fixture",
                "protocol_margin_tokens": 128,
            },
        }],
    })


def boundary_fixture(tmp_path: Path, *, include_capacity: bool = True) -> DevelopmentBoundary:
    root = tmp_path / "dev"
    interpreter = root / ".venv-r4/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(Path(sys.executable).resolve(strict=True))
    config = root / "config"
    config.mkdir()
    source_config = Path(__file__).resolve().parents[1] / "config"
    for name in ("permissions.yaml", "roles.env", "sitina.yaml"):
        source = source_config / name
        if source.is_file():
            (config / name).write_bytes(source.read_bytes())
    if include_capacity:
        (config / "loop_context_capacity.json").write_text(
            json.dumps({
                "schema": "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1",
                "entries": [{
                    **MOCK_IDENTITY.as_dict(),
                    "context_capacity_tokens": 1_000_000,
                    "next_tool_turn_receipt_reserve_tokens": 512,
                    "history_query_max_bytes": 8192,
                    "counter": {
                        "mode": "conservative_utf8",
                        "name": "g2-fixture-counter",
                        "applicability": "offline exact-wire G2 fixture",
                        "protocol_margin_tokens": 128,
                    },
                }],
            }),
            encoding="utf-8",
        )
    credential = tmp_path / "deepseek.env"
    credential.write_text("DEEPSEEK_API_KEY=fixture", encoding="utf-8")
    (root / "profiles").mkdir()
    (root / "profiles/deepseek.env").symlink_to(credential)
    (root / ".sitina-r4-development-root-v1.json").write_text(
        json.dumps({
            "schema": "SITINA_R4_DEVELOPMENT_ROOT_V1",
            "development_root": str(root),
            "runtime_relative_root": "runtime/r4-loop-dev",
            "state_authority_relative_root": "runtime/r4-loop-dev/state/task",
            "credential_references": [{"path": "profiles/deepseek.env", "access": "read_only_reference"}],
            "forbidden_write_roots": [str(tmp_path / "forbidden")],
        }),
        encoding="utf-8",
    )
    return DevelopmentBoundary.validate(
        source_root=root,
        interpreter=interpreter,
        state_root=root / "runtime/r4-loop-dev/state/task",
        business_workspace=root / "runtime/r4-loop-dev/workspaces/task",
        environment={"SITINA_HOME": str(root), "SITINA_R4_DEV_ROOT": str(root)},
    )


def create_task(backend: LoopBackend, task_id: str, goal: str = "goal") -> None:
    artifact = backend.context_memory.persist(
        {"schema": "SITINA_LOOP_ARTIFACT_V1", "task_id": task_id, "phase": "initial"},
        purpose="loop-task-artifact",
    )
    backend.create_task(
        task_id=task_id,
        session_id=f"session-{task_id}",
        task_kind="no_change",
        goal=goal,
        required_outcome_ids=("outcome-1",),
        artifact_ref=artifact.reference_id,
        artifact_content=artifact,
        environment_ref="g2-fixture",
        capability_snapshot_id="g2-fixture-capabilities",
    )


def read_intent(backend: LoopBackend, task_id: str, operation_id: str) -> OperationIntent:
    task = backend.get_task(task_id)
    return OperationIntent(
        operation_id=operation_id,
        logical_operation_id=operation_id,
        attempt_id=f"attempt-{operation_id}",
        mode=OperationMode.READ,
        description="G2 fixture read",
        resources=(),
        expected_task_revision=task.task_revision,
        expected_run_instance_id=task.run_instance_id,
        expected_execution_epoch=task.execution_epoch,
        expected_goal_version=task.goal_version,
        expected_acceptance_version=task.acceptance_version,
        expected_handled_input_seq=task.handled_input_seq,
        capability_snapshot_id=task.capability_snapshot_id,
        preconditions=(),
        recovery=RecoveryPolicy("probe", "retry", "partial", "cancel", "unknown", "later"),
    )


def assembler_for(
    backend: LoopBackend,
    task_id: str,
    registry: ModelCapacityRegistry,
    *,
    projection_max_bytes: int = 128 * 1024,
    protocol_groups_max_bytes: int = 64 * 1024,
    scope_attempt_ids: tuple[str, ...] = (),
) -> LoopRequestAssembler:
    return LoopRequestAssembler(
        LoopContextIndex(backend.store, task_id),
        registry,
        identity=MOCK_IDENTITY,
        role="main",
        projection_max_bytes=projection_max_bytes,
        protocol_groups_max_bytes=protocol_groups_max_bytes,
        receipt_max_bytes=4096,
        scope_attempt_ids=scope_attempt_ids,
    )


def test_soft_projection_target_does_not_block_requirement_that_fits_hard_capacity(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        required = "REQ-LARGE-" + ("界" * 46_000)
        create_task(backend, "task-large", required)
        assembler = assembler_for(backend, "task-large", capacity_registry())
        prepared = assembler.prepare(MOCK_IDENTITY, system_prompt="system", tools=(), max_tokens=512)
        assert prepared.admission.admitted
        assert prepared.admission.total_reserved_tokens < 1_000_000
        assert required in str(prepared.messages[0]["content"])
        assert len(prepared.projection.serialized) > 128 * 1024
    finally:
        backend.close()


def test_optional_history_is_removed_before_declaring_context_blocked(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-history", "short required goal")
        for index in range(20):
            backend.execute_operation(
                "task-history",
                read_intent(backend, "task-history", f"read-{index}"),
                lambda index=index: OperationOutcome(EffectStatus.SUCCEEDED, {"evidence": index}),
            )
        assembler = assembler_for(
            backend,
            "task-history",
            capacity_registry(capacity=8192),
        )
        prepared = assembler.prepare(MOCK_IDENTITY, system_prompt="s", tools=(), max_tokens=256)
        assert prepared.admission.admitted
        assert prepared.projection.history_directory == ()
        assert assembler.compaction_count == 1
        assert assembler.compaction_receipts[0]["removed_source_refs"]
    finally:
        backend.close()


def test_thinking_tool_continuation_replays_private_reasoning_but_filters_user_result(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    private_marker = "PRIVATE-REASONING-SENTINEL-7419"
    private_reasoning = private_marker + ("R" * 20_000)
    visible_marker = "VISIBLE-CONTENT-SENTINEL-8527"
    registry = ModelCapacityRegistry.from_mapping({
        "schema": "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1",
        "entries": [{
            **MOCK_IDENTITY.as_dict(),
            "context_capacity_tokens": 1_000_000,
            "next_tool_turn_receipt_reserve_tokens": 16384,
            "history_query_max_bytes": 8192,
            "execution": {"thinking_mode": "enabled", "max_output_tokens": 16384},
            "counter": {
                "mode": "conservative_utf8",
                "name": "thinking-continuation-fixture",
                "applicability": "exact protected reasoning continuation fixture",
                "protocol_margin_tokens": 128,
            },
        }],
    })

    class ThinkingClient:
        def __init__(self) -> None:
            self.calls = 0
            self.second_body = ""
            self.visible_tool_messages: list[Mapping[str, Any]] = []

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, max_tokens, prepared_request=None, **_kwargs):
            self.calls += 1
            self.visible_tool_messages = [dict(item) for item in messages if item.get("role") == "tool"]
            assert prepared_request is not None
            assert max_tokens == 16384
            assert prepared_request.body["thinking"] == {"type": "enabled"}
            wire_roles = [item["role"] for item in prepared_request.body["messages"] if item["role"] != "system"]
            assert wire_roles == ["user"] + ["assistant", "tool"] * (self.calls - 1)
            if self.calls == 1:
                return ProviderToolTurn(
                    "internal progress",
                    (ProviderToolCall("thinking-list", "sitina_history_query", {
                        "operation": "list",
                        "limit": 5,
                        "max_bytes": 4096,
                    }),),
                    "tool_calls",
                    {
                        "physical_send_count": 0,
                        "reasoning_content_present": True,
                        "reasoning_content_bytes": len(private_reasoning),
                        "reasoning_content_hash": hashlib.sha256(private_reasoning.encode()).hexdigest(),
                    },
                    private_reasoning,
                )
            if self.calls == 2:
                self.second_body = json.dumps(prepared_request.body, ensure_ascii=False)
                assert private_marker in self.second_body
                assistant = next(
                    item for item in prepared_request.body["messages"]
                    if item.get("role") == "assistant" and item.get("tool_calls")
                )
                assert assistant["reasoning_content"] == private_reasoning
                list_message = next(
                    item for item in reversed(messages)
                    if item.get("role") == "tool" and item.get("name") == "sitina_history_query"
                )
                listed = json.loads(str(list_message["content"]))["result"]
                assert listed["status"] == "OK", listed
                provider_entry = next(
                    item for item in listed["entries"]
                    if item["kind"] == "operation_result"
                    and str(item["subject_id"]).startswith("provider-")
                )
                return ProviderToolTurn(
                    "continue internally",
                    (ProviderToolCall("thinking-read", "sitina_history_query", {
                        "operation": "read",
                        "source_ref": provider_entry["source_ref"],
                        "offset": 0,
                        "max_bytes": 8192,
                    }),),
                    "tool_calls",
                    {
                        "physical_send_count": 0,
                        "reasoning_content_present": True,
                        "reasoning_content_bytes": 31,
                        "reasoning_content_hash": "f" * 64,
                    },
                    "SECOND-PRIVATE-REASONING-9631",
                )
            read_message = next(
                item for item in reversed(messages)
                if item.get("role") == "tool" and item.get("name") == "sitina_history_query"
            )
            read_page = json.loads(str(read_message["content"]))["result"]
            assert read_page["content_projection"] == "provider-result-public-fields-v1"
            assert read_page["content_hash_scope"] == "projected-readable-content"
            assert read_page["source_content_hash"] != read_page["content_hash"]
            assert read_page["has_more"] is False
            projected_bytes = base64.b64decode(read_page["data_base64"])
            assert hashlib.sha256(projected_bytes).hexdigest() == read_page["content_hash"]
            assert private_marker not in read_page["readable_text"]
            assert private_marker.encode() not in projected_bytes
            assert '"reasoning_content":' not in read_page["readable_text"]
            return ProviderToolTurn(
                visible_marker,
                (),
                "stop",
                {
                    "physical_send_count": 0,
                    "reasoning_content_present": True,
                    "reasoning_content_bytes": 31,
                    "reasoning_content_hash": "f" * 64,
                },
                "SECOND-PRIVATE-REASONING-9631",
            )

    client = ThinkingClient()
    business_attempt_ids: set[str] = set()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(_role, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return interpretation_factory(_role, _adapter)
        business_attempt_ids.add(_adapter.business_attempt_id)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
        context_registry=registry,
    ).run(
        task_id="task-thinking-filter",
        task_kind="no_change",
        goal="Use one history tool turn, then return only the final content.",
    )
    serialized_result = json.dumps(result, ensure_ascii=False)
    assert result["status"] == "succeeded"
    assert client.calls == 3
    assert visible_marker in serialized_result
    assert private_marker not in serialized_result
    assert "SECOND-PRIVATE-REASONING-9631" not in serialized_result
    assert result["context_compaction_count"] == 0
    reopened = LoopBackend.open(boundary.state_root, keychain_backend=keys)
    try:
        task = reopened.get_task("task-thinking-filter")
        persisted_reasoning = []
        for operation in task.operations.values():
            if not operation.result_ref:
                continue
            document = reopened.context_memory.read(operation.result_ref)
            value = document.get("result", {})
            if isinstance(value, Mapping) and "reasoning_content" in value:
                persisted_reasoning.append(value["reasoning_content"])
        assert private_reasoning in persisted_reasoning
        assert "SECOND-PRIVATE-REASONING-9631" in persisted_reasoning
        restored = assembler_for(
            reopened, "task-thinking-filter", registry,
            scope_attempt_ids=tuple(sorted(business_attempt_ids)),
        )
        assert restored.restore_protocol_groups_from_history() == 2
        assert restored.history_reads_in_last_request() == []
        recovered_request = restored.prepare(
            MOCK_IDENTITY, system_prompt="system", tools=(), max_tokens=16384
        ).rendered_request
        recovered_messages = [item for item in recovered_request.body["messages"] if item["role"] != "system"]
        assert [item["role"] for item in recovered_messages] == ["user", "assistant", "tool", "assistant", "tool"]
        assert [item["reasoning_content"] for item in recovered_messages if item["role"] == "assistant"] == [
            private_reasoning, "SECOND-PRIVATE-REASONING-9631"
        ]
        assert [item["tool_call_id"] for item in recovered_messages if item["role"] == "tool"] == [
            "thinking-list", "thinking-read"
        ]
        # Restoring a history query must preserve the exact model-visible page
        # and its untrusted-data envelope, not replace it with another receipt.
        assert {
            item["tool_call_id"]: item["content"]
            for item in recovered_messages if item["role"] == "tool"
        } == {
            item["tool_call_id"]: item["content"] for item in client.visible_tool_messages
        }
        restored_reads = restored.history_reads_in_last_request()
        read_pages = [item for item in restored_reads if item["arguments"].get("operation") == "read"]
        assert len(read_pages) == 1
        page = read_pages[0]["result"]
        expected_ref = read_pages[0]["arguments"]["source_ref"]
        assert _verified_history_read_source_refs(
            {"tool_results": read_pages}, task_session_binding=page["task_session_binding"],
            read_coverage={},
        ) == {expected_ref}
        assert not _verified_history_read_source_refs(
            {"tool_results": read_pages}, task_session_binding="other-task-binding",
            read_coverage={},
        )
        incomplete = {**read_pages[0], "result": {**page, "offset": 1}}
        assert not _verified_history_read_source_refs(
            {"tool_results": [incomplete]}, task_session_binding=page["task_session_binding"],
            read_coverage={},
        )
    finally:
        reopened.close()


def test_length_truncated_tool_arguments_are_hashed_and_never_repaired_or_executed(
    monkeypatch,
) -> None:
    client = object.__new__(AnthropicCompatibleClient)
    raw_calls = [{
        "id": "truncated-write",
        "type": "function",
        "function": {"name": "sitina_write_file", "arguments": '{"path":"x","content":'},
    }]

    def response(*_args, **_kwargs):
        return ({
            "choices": [{
                "message": {
                    "content": "",
                    "reasoning_content": "PRIVATE-TRUNCATED-REASONING",
                    "tool_calls": raw_calls,
                },
                "finish_reason": "length",
            }],
            "usage": {"completion_tokens": 16384, "total_tokens": 17000},
        }, {"physical_send_count": 1})

    monkeypatch.setattr(client, "_request_json", response)
    profile = ProviderProfile("deepseek", "https://api.deepseek.com", "", "deepseek-v4-pro")
    turn = client._tool_turn_openai(
        profile,
        system_prompt="s",
        messages=({"role": "user", "content": "u"},),
        tools=(),
        max_tokens=16384,
        request_timeout_seconds=1,
    )
    assert turn.stop_reason == "length"
    assert turn.tool_calls == ()
    assert turn.metadata["truncated_tool_call_count"] == 1
    assert turn.metadata["truncated_tool_calls_hash"] == "sha256:" + hashlib.sha256(
        json.dumps(raw_calls, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert turn.reasoning_content == "PRIVATE-TRUNCATED-REASONING"


def test_malformed_post_response_envelope_preserves_observed_physical_send(monkeypatch) -> None:
    client = object.__new__(AnthropicCompatibleClient)

    def response(*_args, **_kwargs):
        return {}, {"physical_send_count": 1, "request_body_hash": "observed-body"}

    monkeypatch.setattr(client, "_request_json", response)
    profile = ProviderProfile(
        "deepseek",
        "https://api.deepseek.com",
        "deepseek-v4-pro",
        OPENAI_CHAT_COMPLETIONS,
    )
    with pytest.raises(ProviderMalformedResponse) as caught:
        client._tool_turn_openai(
            profile,
            system_prompt="system",
            messages=(),
            tools=(),
            max_tokens=16,
            request_timeout_seconds=1,
        )
    assert caught.value.sitina_physical_send_count == 1
    assert caught.value.sitina_physical_send_status == "response_received"


def test_reviewer_failed_history_read_cannot_satisfy_required_evidence() -> None:
    source_ref = "history:" + ("a" * 64) + ":7:" + ("b" * 64)
    claimed_pass = {
        "response": json.dumps({
            "schema": "SITINA_LOOP_REVIEW_V1",
            "verdict": "PASS",
            "reason": "claimed without evidence",
            "artifact_ref": "cas:" + ("c" * 64),
        }),
        "tool_results": [{
            "name": "sitina_history_query",
            "status": "ok",
            "arguments": {
                "operation": "read",
                "source_ref": source_ref,
                "offset": 999999,
                "max_bytes": 4096,
            },
            "result": {
                "schema": "SITINA_LOOP_HISTORY_STATUS_V1",
                "status": "INVALID_OFFSET",
                "task_session_binding": "binding-1",
                "source_ref": source_ref,
                "reason": "offset is outside canonical content",
            },
        }],
    }
    assert _verified_history_read_source_refs(
        claimed_pass,
        task_session_binding="binding-1",
    ) == set()


def test_true_required_context_overflow_still_blocks_without_send(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-overflow", "REQUIRED-" + ("x" * 7000))
        assembler = assembler_for(
            backend,
            "task-overflow",
            capacity_registry(capacity=4096),
        )
        with pytest.raises((ContextAdmissionBlocked, ContextCoverageBlocked)):
            assembler.prepare(MOCK_IDENTITY, system_prompt="s", tools=(), max_tokens=256)
        assert assembler.admission_receipts == []
    finally:
        backend.close()


def test_exact_policy_selects_its_own_query_and_receipt_limits(tmp_path: Path) -> None:
    other = ProviderContextIdentity("other", "https://other.example/v1", "other-model", ANTHROPIC_MESSAGES)
    raw = {
        "schema": "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1",
        "entries": [],
    }
    for identity, history_max in ((MOCK_IDENTITY, 8000), (other, 1000)):
        raw["entries"].append({
            **identity.as_dict(),
            "context_capacity_tokens": 100000,
            "next_tool_turn_receipt_reserve_tokens": 512,
            "history_query_max_bytes": history_max,
            "counter": {
                "mode": "conservative_utf8",
                "name": "exact-fixture",
                "applicability": "exact identity fixture",
                "protocol_margin_tokens": 128,
            },
        })
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-limits")
        assembler = LoopRequestAssembler(
            LoopContextIndex(backend.store, "task-limits"),
            ModelCapacityRegistry.from_mapping(raw),
            identity=MOCK_IDENTITY,
            role="main",
            receipt_max_bytes=9000,
        )
        assert assembler.history_query_max_bytes == 8000
        assert assembler.receipt_max_bytes == 8000
    finally:
        backend.close()


def test_explicit_thinking_execution_mode_is_inside_protected_admitted_wire(tmp_path: Path) -> None:
    raw = {
        "schema": "SITINA_LOOP_CONTEXT_CAPACITY_POLICY_V1",
        "entries": [{
            **MOCK_IDENTITY.as_dict(),
            "context_capacity_tokens": 100000,
            "next_tool_turn_receipt_reserve_tokens": 512,
            "history_query_max_bytes": 8192,
            "execution": {"thinking_mode": "enabled", "max_output_tokens": 16384},
            "counter": {
                "mode": "conservative_utf8",
                "name": "thinking-fixture",
                "applicability": "exact protected execution-mode fixture",
                "protocol_margin_tokens": 128,
            },
        }],
    }
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-thinking")
        assembler = assembler_for(
            backend,
            "task-thinking",
            ModelCapacityRegistry.from_mapping(raw),
        )
        prepared = assembler.prepare(MOCK_IDENTITY, system_prompt="s", tools=(), max_tokens=16384)
        assert prepared.rendered_request.body["thinking"] == {"type": "enabled"}
        assert prepared.rendered_request.body["reasoning_effort"] == "high"
        assert prepared.admission.body_hash == prepared.rendered_request.body_hash
        assert prepared.admission.admitted
        assert "response_format" not in prepared.rendered_request.body
        json_prepared = assembler.prepare(
            MOCK_IDENTITY, system_prompt="Return a JSON object.", tools=(),
            max_tokens=16384, expect_json=True,
        )
        assert json_prepared.rendered_request.body["response_format"] == {"type": "json_object"}
        assert json_prepared.rendered_request.body["tools"] == []
        assert json_prepared.rendered_request.body["thinking"] == {"type": "enabled"}
        assert json_prepared.rendered_request.body["reasoning_effort"] == "high"
        assert json_prepared.admission.body_hash == json_prepared.rendered_request.body_hash
        assert json_prepared.admission.admitted
    finally:
        backend.close()


def test_empty_history_repeated_prepare_does_not_invent_compactions(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-no-compaction")
        assembler = assembler_for(backend, "task-no-compaction", capacity_registry())
        hashes = {
            assembler.prepare(MOCK_IDENTITY, system_prompt="s", tools=(), max_tokens=256).rendered_request.body_hash
            for _ in range(3)
        }
        assert len(hashes) == 1
        assert assembler.compaction_count == 0
        assert assembler.compaction_receipts == []
    finally:
        backend.close()


@pytest.mark.parametrize("wire_protocol", [OPENAI_CHAT_COMPLETIONS, ANTHROPIC_MESSAGES])
def test_provider_transport_uses_the_exact_prepared_body(
    tmp_path: Path,
    monkeypatch,
    wire_protocol: str,
) -> None:
    identity = ProviderContextIdentity("fixture", "https://provider.example/v1", "model", wire_protocol)
    profile = ProviderProfile("fixture", "https://provider.example/v1", "secret", "model", wire_protocol)
    prepared = render_provider_tool_request(
        identity,
        system_prompt="system",
        messages=({"role": "user", "content": "hello"},),
        tools=(),
        max_tokens=256,
        expect_json=wire_protocol == OPENAI_CHAT_COMPLETIONS,
    )
    client = object.__new__(AnthropicCompatibleClient)
    captured: dict[str, Any] = {}

    def request(_url, body, _headers, **_kwargs):
        captured["body"] = body
        if wire_protocol == OPENAI_CHAT_COMPLETIONS:
            return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}, {}
        return {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}, {}

    monkeypatch.setattr(client, "_request_json", request)
    kwargs = {
        "system_prompt": "mutated-system-that-must-not-win",
        "messages": ({"role": "user", "content": "mutated"},),
        "tools": (),
        "max_tokens": 256,
        "request_timeout_seconds": 1.0,
        "prepared_request": prepared,
    }
    if wire_protocol == OPENAI_CHAT_COMPLETIONS:
        turn = client._tool_turn_openai(profile, **kwargs)
    else:
        turn = client._tool_turn_anthropic(profile, **kwargs)
    assert turn.text == "ok"
    body_bytes = json.dumps(captured["body"], ensure_ascii=False, separators=(",", ":")).encode()
    assert hashlib.sha256(body_bytes).hexdigest() == prepared.body_hash
    assert captured["body"] == prepared.body
    if wire_protocol == OPENAI_CHAT_COMPLETIONS:
        assert captured["body"]["response_format"] == {"type": "json_object"}
    else:
        assert "response_format" not in captured["body"]


def test_non_loop_runtime_keeps_original_tool_client_signature(tmp_path: Path) -> None:
    class OldSignatureClient:
        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(
            self,
            _profile,
            *,
            system_prompt,
            messages,
            tools,
            max_tokens=4096,
            request_timeout_seconds=None,
            cancel_check=None,
        ):
            return ProviderToolTurn("done", (), "stop", {"physical_send_count": 0})

    home = tmp_path / "home"
    (home / "config").mkdir(parents=True)
    runtime = AutonomousRuntime(
        home,
        manager=ExtensionManager(home),
        client=OldSignatureClient(),
        profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
        workspace=home,
        max_turns=None,
    )
    assert runtime.run("task")["response"] == "done"


def test_bounded_empty_final_repair_reaches_the_next_exact_request(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()

    class EmptyThenFinalClient:
        def __init__(self) -> None:
            self.prepared = []

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, prepared_request=None, **_kwargs):
            assert prepared_request is not None
            self.prepared.append(prepared_request)
            text = "" if len(self.prepared) == 1 else "bounded repair complete"
            return ProviderToolTurn(text, (), "stop", {"physical_send_count": 0})

    client = EmptyThenFinalClient()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(_role, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return interpretation_factory(_role, _adapter)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    ).run(task_id="task-empty-repair", task_kind="no_change", goal="finish")
    assert result["status"] == "succeeded"
    assert len(client.prepared) == 2
    first = json.dumps(client.prepared[0].body, ensure_ascii=False)
    second = json.dumps(client.prepared[1].body, ensure_ascii=False)
    assert "do not call tools" not in first
    assert "do not call tools" in second
    assert client.prepared[1].body_hash == hashlib.sha256(
        json.dumps(
            client.prepared[1].body,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_history_query_is_read_only_and_returns_readable_task_bound_content(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    runtimes: list[AutonomousRuntime] = []

    class QueryClient:
        def __init__(self) -> None:
            self.calls = 0
            self.source_ref = ""
            self.tool_content = ""

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, tools, prepared_request=None, **_kwargs):
            self.calls += 1
            assert prepared_request is not None
            history_schema = next(item for item in tools if item["name"] == "sitina_history_query")
            assert history_schema["input_schema"]["properties"]["max_bytes"]["maximum"] == 8192
            if self.calls == 1:
                context = json.loads(str(messages[0]["content"]))
                requirement = context["task_context"]["current_requirements"][0]
                self.source_ref = requirement["source_ref"]
                return ProviderToolTurn(
                    "",
                    (ProviderToolCall("history-read", "sitina_history_query", {
                        "operation": "read",
                        "source_ref": self.source_ref,
                        "offset": 0,
                        "max_bytes": 4096,
                    }),),
                    "tool_calls",
                    {"physical_send_count": 0},
                )
            tool_message = next(item for item in messages if item.get("role") == "tool")
            self.tool_content = str(tool_message["content"])
            assert "readable_text" in self.tool_content
            assert "QUERY-TARGET-界" in self.tool_content
            return ProviderToolTurn("query complete", (), "stop", {"physical_send_count": 0})

    client = QueryClient()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(_role, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return interpretation_factory(_role, _adapter)
        home = boundary.state_root / "provider-home"
        runtime = AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )
        runtimes.append(runtime)
        return runtime

    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    ).run(
        task_id="task-history-tool",
        task_kind="no_change",
        goal="Recover QUERY-TARGET-界 through the task history tool",
    )
    assert result["status"] == "succeeded"
    definition = runtimes[0].catalog.get("sitina_history_query")
    assert definition.permission == "read"
    assert definition.origin == "sitina-loop"
    assert client.source_ref.startswith("history:")
    assert "SITINA_LOOP_HISTORY_READ_V1" in client.tool_content


def test_multimegabyte_unicode_tool_result_is_persisted_then_paged_by_history_query(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True)
    large_path = boundary.business_workspace / "large-unicode.txt"
    large_path.write_text("多字节界" * 190_000, encoding="utf-8")
    keys = MemoryKeychainBackend()

    class UnicodeQueryClient:
        def __init__(self) -> None:
            self.calls = 0
            self.source_ref = ""
            self.next_offset = 0
            self.second_page = ""

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, prepared_request=None, **_kwargs):
            self.calls += 1
            assert prepared_request is not None
            if self.calls == 1:
                return ProviderToolTurn(
                    "",
                    (ProviderToolCall("read-large", "sitina_read_file", {"path": str(large_path)}),),
                    "tool_calls",
                    {"physical_send_count": 0},
                )
            tool_document = json.loads(next(
                str(item["content"]) for item in messages if item.get("role") == "tool"
            ))
            page = tool_document["result"]
            if self.calls == 2:
                assert page["status"] == "OK"
                assert page["total_bytes"] > 2_000_000
                assert page["has_more"] is True
                self.source_ref = page["source_ref"]
                self.next_offset = page["next_offset"]
                return ProviderToolTurn(
                    "",
                    (ProviderToolCall("page-large", "sitina_history_query", {
                        "operation": "read",
                        "source_ref": self.source_ref,
                        "offset": self.next_offset,
                        "max_bytes": 4096,
                    }),),
                    "tool_calls",
                    {"physical_send_count": 0},
                )
            assert page["status"] == "OK"
            assert page["offset"] == self.next_offset
            assert page["returned_bytes"] > 0
            self.second_page = page["readable_text"]
            return ProviderToolTurn("unicode recovery complete", (), "stop", {"physical_send_count": 0})

    client = UnicodeQueryClient()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(_role, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return interpretation_factory(_role, _adapter)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
        protocol_groups_max_bytes=12_000,
    ).run(
        task_id="task-unicode-pages",
        task_kind="no_change",
        goal="Read the large Unicode fixture and recover a later page through task history.",
    )
    assert result["status"] == "succeeded"
    assert client.calls == 3
    assert "多字节界" in client.second_page
    assert len(json.dumps(result, ensure_ascii=False).encode("utf-8")) < 200_000, json.dumps({
        "top_level_bytes": {
            name: len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
            for name, value in result.items()
        },
    }, sort_keys=True)
    first_tool_record = result["task"]["status"]
    assert first_tool_record == "SUCCEEDED"


def test_over_one_hundred_meaningful_rounds_survive_corrections_and_three_real_compactions(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()

    class LongLoopClient:
        def __init__(self) -> None:
            self.calls = 0
            self.adapter = None
            self.injected: set[int] = set()
            self.last_prepared = None
            self.source_ref = ""
            self.next_offset = 0
            self.verified_pages: list[tuple[int, int, int]] = []
            self.recovered = bytearray()

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, prepared_request=None, **_kwargs):
            self.calls += 1
            assert prepared_request is not None
            self.last_prepared = prepared_request
            expected_hash = hashlib.sha256(json.dumps(
                prepared_request.body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            assert prepared_request.body_hash == expected_hash
            current_positions = [i for i, item in enumerate(messages) if item.get("role") == "user"]
            assert len(current_positions) == 1
            current_position = current_positions[0]
            input_boundary_call = max(self.injected, default=0)
            calls_in_request = []
            results_in_request = []
            for position, message in enumerate(messages):
                if message.get("role") == "assistant":
                    for call in message["tool_calls"]:
                        call_id = call["id"]
                        calls_in_request.append(call_id)
                        call_number = int(call_id.removeprefix("history-read-"))
                        assert (position < current_position) == (call_number < input_boundary_call)
                elif message.get("role") == "tool":
                    results_in_request.append(message["tool_call_id"])
            assert calls_in_request == results_in_request
            assert len(calls_in_request) == len(set(calls_in_request))
            tool_messages = [item for item in messages if item.get("role") == "tool"]
            if not self.source_ref:
                context = json.loads(str(messages[current_position]["content"]))
                self.source_ref = context["task_context"]["current_requirements"][0]["source_ref"]
            if tool_messages:
                tool_document = json.loads(str(tool_messages[-1]["content"]))
                page = tool_document["result"]
                assert page["schema"] == "SITINA_LOOP_HISTORY_READ_V1"
                assert page["status"] == "OK"
                assert page["source_ref"] == self.source_ref
                assert page["offset"] == self.next_offset
                raw = base64.b64decode(page["data_base64"])
                assert raw.decode("utf-8") == page["readable_text"]
                assert len(raw) == page["returned_bytes"] > 0
                next_offset = page["next_offset"]
                assert isinstance(next_offset, int) and next_offset > self.next_offset
                self.verified_pages.append((self.next_offset, len(raw), next_offset))
                self.recovered.extend(raw)
                self.next_offset = next_offset
            if self.calls in {30, 70} and self.calls not in self.injected:
                self.injected.add(self.calls)
                assert self.adapter is not None
                label = "REQ-MID" if self.calls == 30 else "REQ-LATEST"
                self.adapter.backend.accept_input(
                    "task-long-loop",
                    input_id=f"correction-{self.calls}",
                    kind=InputKind.CORRECTION,
                    body=f"{label}: retain this corrected requirement",
                )
                self.adapter.backend.handle_next_input(
                    "task-long-loop",
                    affects_goal=True,
                    affects_acceptance=True,
                )
            if len(self.verified_pages) < 105:
                return ProviderToolTurn(
                    "",
                    (ProviderToolCall(f"history-read-{self.calls}", "sitina_history_query", {
                        "operation": "read",
                        "source_ref": self.source_ref,
                        "offset": self.next_offset,
                        "max_bytes": 1200,
                    }),),
                    "tool_calls",
                    {"physical_send_count": 0},
                )
            return ProviderToolTurn("long bounded loop complete", (), "stop", {"physical_send_count": 0})

    client = LongLoopClient()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(_role, adapter):
        if adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return interpretation_factory(_role, adapter)
        client.adapter = adapter
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    numbered_evidence = "\n".join(
        f"EVIDENCE-{index:04d}:" + (chr(65 + index % 26) * 82)
        for index in range(400)
    )
    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
        protocol_groups_max_bytes=12_000,
        receipt_max_bytes=4096,
    ).run(
        task_id="task-long-loop",
        task_kind="no_change",
        goal=(
            "REQ-EARLY: preserve the first requirement and sequentially verify the numbered evidence.\n"
            + numbered_evidence
        ),
    )
    assert result["status"] == "succeeded"
    assert client.calls >= 108
    assert len(client.verified_pages) == 105
    assert len({item[0] for item in client.verified_pages}) == 105
    assert all(
        current[2] == following[0]
        for current, following in zip(client.verified_pages, client.verified_pages[1:])
    )
    assert client.recovered.count(b"EVIDENCE-") >= 100
    assert result["task"]["goal_version"] == 3
    assert result["context_compaction_count"] >= 3
    receipts = result["context_compaction_receipts"]
    assert len(receipts) == result["context_compaction_count"]
    assert all(item["removed_residency"] and item["removed_source_refs"] for item in receipts)
    final_body = json.dumps(client.last_prepared.body, ensure_ascii=False)
    assert "REQ-EARLY" in final_body
    assert "REQ-MID" in final_body
    assert "REQ-LATEST" in final_body
    assert len(final_body.encode("utf-8")) < 1_000_000


def test_reviewer_receives_only_refs_and_actively_queries_artifact_program_and_main_result(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    main_marker = "MAIN-EVIDENCE-BEGIN-"
    program_marker = "PROGRAM-EVIDENCE-BEGIN-"
    reviewer_client = None
    runtimes: list[tuple[str, AutonomousRuntime]] = []

    class MainClient:
        def __init__(self) -> None:
            self.calls = 0

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, prepared_request=None, **_kwargs):
            self.calls += 1
            assert prepared_request is not None
            if self.calls == 1:
                first_body = json.dumps(prepared_request.body, ensure_ascii=False)
                assert "The backend will run the program check" in first_body
                return ProviderToolTurn(
                    "",
                    (ProviderToolCall("write-review", "sitina_write_file", {
                        "path": "review.txt",
                        "content": "ok",
                    }),),
                    "tool_calls",
                    {"physical_send_count": 0},
                )
            return ProviderToolTurn(
                main_marker + ("M" * 120_000),
                (),
                "stop",
                {"physical_send_count": 0},
            )

    class ReviewerClient:
        def __init__(self) -> None:
            self.calls = 0
            self.execution_context: Mapping[str, Any] = {}
            self.initial_body = ""
            self.pages: dict[str, Mapping[str, Any]] = {}
            self.required_reads: list[tuple[str, str]] = []

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, prepared_request=None, **_kwargs):
            self.calls += 1
            assert prepared_request is not None
            if self.calls == 1:
                context = json.loads(str(messages[0]["content"]))
                assert context["role"] == "reviewer"
                self.execution_context = context["execution_context"]
                self.initial_body = json.dumps(prepared_request.body, ensure_ascii=False)
                assert self.execution_context["full_main_result_inline"] is False
                assert self.execution_context["full_program_output_inline"] is False
                assert "you MUST call sitina_history_query read" in self.initial_body
                assert "one bare JSON object" in self.initial_body
                assert main_marker not in self.initial_body
                assert program_marker not in self.initial_body
                self.required_reads = [
                    ("artifact", self.execution_context["artifact_source_ref"]),
                    ("program", self.execution_context["program_source_ref"]),
                    ("main", self.execution_context["main_result_source_ref"]),
                    *(
                        (f"preflight-{index}", source_ref)
                        for index, source_ref in enumerate(
                            self.execution_context["preflight_source_refs"]
                        )
                    ),
                ]
            else:
                tool_document = json.loads(next(
                    str(item["content"]) for item in reversed(messages) if item.get("role") == "tool"
                ))
                page = tool_document["result"]
                assert page["status"] == "OK"
                self.pages[self.required_reads[self.calls - 2][0]] = page
            if self.calls <= len(self.required_reads):
                source_ref = self.required_reads[self.calls - 1][1]
                assert isinstance(source_ref, str) and source_ref.startswith("history:")
                return ProviderToolTurn(
                    "",
                    (ProviderToolCall(f"review-read-{self.calls}", "sitina_history_query", {
                        "operation": "read",
                        "source_ref": source_ref,
                        "offset": 0,
                        "max_bytes": 4096,
                    }),),
                    "tool_calls",
                    {"physical_send_count": 0},
                )
            assert '"changed_paths":["review.txt"]' in self.pages["artifact"]["readable_text"]
            assert program_marker in self.pages["program"]["readable_text"]
            assert main_marker in self.pages["main"]["readable_text"]
            contract = self.execution_context["response_contract"]
            return ProviderToolTurn(
                json.dumps({
                    "schema": "SITINA_LOOP_REVIEW_V2",
                    "termination_contract_version": contract["termination_contract_version"],
                    "acceptance_item_id": contract["acceptance_item_id"],
                    "review_subject_lineage": contract["review_subject_lineage"],
                    "observed_artifact_ref": contract["observed_artifact_ref"],
                    "verdict": "PASS",
                    "reason": "All three proof-bound sources were retrieved read-only.",
                    "findings": [],
                }),
                (),
                "stop",
                {"physical_send_count": 0},
            )

    main_client = MainClient()
    reviewer_client = ReviewerClient()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(role, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return interpretation_factory(role, _adapter)
        home = boundary.state_root / "provider-home"
        client = reviewer_client if role == "reviewer" else main_client
        runtime = AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            approval_callback=lambda _request: role == "main",
            workspace=boundary.business_workspace,
            max_turns=None,
            enforce_write_boundary=True,
            strict_workspace=True,
        )
        runtimes.append((role, runtime))
        return runtime

    check_command = (
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            "assert Path('review.txt').read_text() == 'ok'; "
            f"print({program_marker!r} + 'P' * 120000)"
        ),
    )
    result = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
        protocol_groups_max_bytes=32_000,
    ).run(
        task_id="task-review-history",
        task_kind="code_change",
        goal="Create review.txt containing exactly ok and prove it with the fixed check.",
        check_command=check_command,
    )
    assert result["status"] == "succeeded"
    assert result["review_status"] == "PASS"
    assert reviewer_client.calls == 5
    reviewer_runtime = next(runtime for role, runtime in runtimes if role == "reviewer")
    history_definition = reviewer_runtime.catalog.get("sitina_history_query")
    assert history_definition.permission == "read"
    assert history_definition.origin == "sitina-loop"
    assert len(reviewer_client.initial_body.encode("utf-8")) < 128 * 1024


@pytest.mark.parametrize(
    ("control", "expected_status"),
    [("PAUSE", "paused"), ("CANCEL", "cancelled")],
)
def test_control_remains_responsive_while_history_body_read_is_blocked_and_stale_result_cannot_commit(
    tmp_path: Path,
    monkeypatch,
    control: str,
    expected_status: str,
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    entered = threading.Event()
    release = threading.Event()
    blocked_once = False
    original_read = LoopHistoryQuery.read

    def blocking_read(history, *, source_ref, offset=0, max_bytes=4096):
        nonlocal blocked_once
        if not blocked_once:
            blocked_once = True
            entered.set()
            assert release.wait(10)
        return original_read(history, source_ref=source_ref, offset=offset, max_bytes=max_bytes)

    monkeypatch.setattr(LoopHistoryQuery, "read", blocking_read)

    class OneQueryClient:
        def __init__(self) -> None:
            self.calls = 0

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, prepared_request=None, **_kwargs):
            self.calls += 1
            assert self.calls == 1, "control barrier must prevent a second Provider request"
            assert prepared_request is not None
            context = json.loads(str(messages[0]["content"]))
            source_ref = context["task_context"]["current_requirements"][0]["source_ref"]
            return ProviderToolTurn(
                "",
                (ProviderToolCall("blocked-history-read", "sitina_history_query", {
                    "operation": "read",
                    "source_ref": source_ref,
                    "offset": 0,
                    "max_bytes": 4096,
                }),),
                "tool_calls",
                {"physical_send_count": 0},
            )

    client = OneQueryClient()
    interpretation_factory, _ = scripted_factory(boundary, {})

    def factory(_role, _adapter):
        if _adapter.work_purpose == "goal_interpretation":
            return interpretation_factory(_role, _adapter)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    )
    output: dict[str, Any] = {}
    failure: list[BaseException] = []

    def run_task() -> None:
        try:
            output.update(runner.run(
                task_id=f"task-history-control-{control.casefold()}",
                task_kind="no_change",
                goal="Read this committed goal while preserving the control barrier.",
            ))
        except BaseException as error:
            failure.append(error)

    thread = threading.Thread(target=run_task)
    thread.start()
    assert entered.wait(10)
    task_id = f"task-history-control-{control.casefold()}"
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": task_id,
        "input_id": f"control-{control.casefold()}",
        "kind": control,
        "body": control.casefold(),
    })
    assert response["status"] == "accepted"
    assert thread.is_alive(), "history read remains blocked while control is already accepted"
    release.set()
    thread.join(15)
    assert not thread.is_alive()
    assert failure == []
    assert output["status"] == expected_status
    assert client.calls == 1
    assert output["task"]["acceptance_ids"] == []


def test_stale_context_error_is_not_rebound_to_new_input(tmp_path: Path, monkeypatch) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    backend_holder: dict[str, LoopBackend] = {}
    clients: list[Any] = []
    interpretation_factory, _ = scripted_factory(boundary, {})
    business_context_active = False

    class FinalClient:
        def __init__(self) -> None:
            self.received_messages: list[Any] = []

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, _profile, *, messages, **_kwargs):
            self.received_messages.append(messages)
            return ProviderToolTurn("done", (), "stop", {"physical_send_count": 0})

    def backend_factory(root: Path) -> LoopBackend:
        backend = LoopBackend.open(root, keychain_backend=keys)
        backend_holder["backend"] = backend
        return backend

    def runtime_factory(_role: str, _adapter):
        nonlocal business_context_active
        business_context_active = _adapter.work_purpose not in {"goal_interpretation", "goal_completion"}
        if not business_context_active:
            return interpretation_factory(_role, _adapter)
        client = FinalClient()
        clients.append(client)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    original = LoopRequestAssembler.prepare
    injected = False

    def fail_old_context_once(assembler, *args, **kwargs):
        nonlocal injected
        if not business_context_active or injected:
            return original(assembler, *args, **kwargs)
        injected = True
        binding = assembler.index.current_binding()
        refs = tuple(item.source_ref for item in assembler.index.requirement_entries())
        error = ContextCoverageBlocked(
            "OLD_VERSION_ONLY_CONTEXT_FAILURE",
            refs,
            context_binding=binding,
        )
        backend = backend_holder["backend"]
        backend.accept_input(
            "task-stale-error",
            input_id="new-correction",
            kind=InputKind.CORRECTION,
            body="NEW requirement",
        )
        backend.handle_next_input(
            "task-stale-error",
            affects_goal=True,
            affects_acceptance=True,
        )
        raise error

    monkeypatch.setattr(LoopRequestAssembler, "prepare", fail_old_context_once)
    runner = LoopTaskRunner(
        boundary,
        backend_factory=backend_factory,
        runtime_factory=runtime_factory,
    )
    result = runner.run(task_id="task-stale-error", task_kind="no_change", goal="OLD requirement")
    assert result["status"] == "succeeded"
    assert result["task"]["goal_version"] == 2
    assert clients[0].received_messages == []
    assert "NEW requirement" in str(clients[1].received_messages[0][0]["content"])
    reopened = LoopBackend.open(boundary.state_root, keychain_backend=keys)
    try:
        assert not any(
            event.event_type == "loop.task-context-blocked"
            for event in reopened.store.task_events("task-stale-error")
        )
    finally:
        reopened.close()


def test_missing_capacity_config_persists_context_block_without_constructing_provider(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path, include_capacity=False)
    keys = MemoryKeychainBackend()
    constructed = False

    def factory(_role, _adapter):
        nonlocal constructed
        constructed = True
        raise AssertionError("Provider fixture must not be constructed")

    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    ).run(task_id="task-missing-policy", task_kind="no_change", goal="goal")
    assert result["status"] == "context_blocked"
    assert result["task"]["status"] == "CONTEXT_BLOCKED"
    assert result["provider_physical_send_count"] == 0
    assert result["task"]["attempt_settlement_count"] == 0
    assert constructed is False


@pytest.mark.parametrize("mode", ["missing_identity", "qualified_counter_unavailable"])
def test_runtime_policy_rejection_is_persisted_before_any_provider_send(tmp_path: Path, mode: str) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()

    class NoSendClient:
        calls = 0

        def load_profile(self, _name: str) -> ProviderProfile:
            return ProviderProfile("mock", "mock://offline", "", "scripted")

        def complete_tool_turn(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("rejected request must not reach Provider")

    client = NoSendClient()

    def factory(_role, _adapter):
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    registry = (
        capacity_registry(identity=ProviderContextIdentity(
            "different", "https://different.example/v1", "different", ANTHROPIC_MESSAGES
        ))
        if mode == "missing_identity"
        else capacity_registry(counter_mode="qualified_tokenizer")
    )
    result = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
        context_registry=registry,
    ).run(task_id=f"task-{mode}", task_kind="no_change", goal="goal")
    assert result["status"] == "context_blocked"
    assert result["task"]["status"] == "CONTEXT_BLOCKED"
    assert result["rejected_request_physical_send_count"] == 0
    assert result["no_progress_incremented"] is False
    assert client.calls == 0


def test_incremental_projection_matches_cold_replay_and_returns_detached_snapshots(tmp_path: Path) -> None:
    backend = LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend())
    try:
        create_task(backend, "task-cache")
        for index in range(12):
            backend.execute_operation(
                "task-cache",
                read_intent(backend, "task-cache", f"cache-read-{index}"),
                lambda index=index: OperationOutcome(EffectStatus.SUCCEEDED, {"index": index}),
            )
        hot = backend.get_task("task-cache")
        reads = 0
        original_read = backend.store.read_json

        def counted_read(*args, **kwargs):
            nonlocal reads
            reads += 1
            return original_read(*args, **kwargs)

        backend.store.read_json = counted_read  # type: ignore[method-assign]
        detached = backend.get_task("task-cache")
        detached.operations.clear()
        again = backend.get_task("task-cache")
        assert len(again.operations) == 12
        assert reads == 0
        cold = backend._project("task-cache", backend.store.task_events("task-cache"))
        assert cold.as_dict() == hot.as_dict()
        assert reads > 0
    finally:
        backend.close()
