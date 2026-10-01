from __future__ import annotations

from pathlib import Path
import json
import time

import pytest

from sitina.loop import AcceptanceSubmission, CompletionProposal, LoopBackend, TaskStatus
from sitina.loop.host import NativeExperienceProviderFactory
from sitina.loop.model import TaskConflict
from sitina.runners.provider import ProviderProfile, ProviderToolCall, ProviderToolTurn
from sitina.security.macos_keychain import MemoryKeychainBackend


def _profile() -> ProviderProfile:
    return ProviderProfile("deepseek", "mock://deepseek/v1", "offline", "deepseek-chat", "openai_chat_completions")


class _Client:
    def __init__(self, turn: ProviderToolTurn):
        self.turn = turn
        self.calls = []

    def complete_tool_turn(self, _profile, **_kwargs):
        self.calls.append(_kwargs)
        return self.turn


def _request(schema: str = "SITINA_EXPERIENCE_PROVIDER_REQUEST_V1") -> dict:
    return {"schema": schema, "request_id": "response-test", "source_closure": {"closure_hash": "a" * 64}}


def test_native_response_facts_reject_finish_length_and_partial_tool_call() -> None:
    turn = ProviderToolTurn(
        "private reasoning",
        (ProviderToolCall("c1", "experience_result", {"status": "SUCCEEDED"}),),
        "length",
        {
            "physical_send_count": 1,
            "physical_send_count_status": "exact",
            "physical_send_status": "response_received",
            "truncated_tool_call_count": 1,
            "token_usage": {"input_tokens": 10, "output_tokens": 32},
        },
        "secret reasoning",
    )
    factory = NativeExperienceProviderFactory(_Client(turn), _profile(), max_tokens=4096, timeout_seconds=1)
    with pytest.raises(ValueError) as caught:
        factory(_request())
    error = caught.value
    assert getattr(error, "sitina_error_code") == "provider-result-truncated"
    assert getattr(error, "sitina_finish_reason") == "length"
    assert getattr(error, "sitina_output_truncation") == "tool_call_truncated"
    assert getattr(error, "sitina_truncated_tool_call_count") == 1
    assert getattr(error, "sitina_provider_send_count") == 1
    assert getattr(error, "sitina_response_received") is True
    assert not hasattr(error, "reasoning_content")


def test_native_response_facts_malformed_metadata_fail_closed() -> None:
    turn = ProviderToolTurn(
        "",
        (ProviderToolCall("c1", "experience_result", {"status": "FAILED", "error_code": "provider-http-error"}),),
        "tool_calls",
        {
            "physical_send_count": "one",
            "physical_send_count_status": "not-a-status",
            "physical_send_status": "response_received",
            "truncated_tool_call_count": "not-an-int",
        },
    )
    factory = NativeExperienceProviderFactory(_Client(turn), _profile(), max_tokens=4096, timeout_seconds=1)
    with pytest.raises(ValueError) as caught:
        factory(_request())
    error = caught.value
    assert getattr(error, "sitina_error_code") == "provider-result-metadata-invalid"
    assert getattr(error, "sitina_provider_metadata_status") == "malformed"
    assert getattr(error, "sitina_provider_send_count") is None
    assert getattr(error, "sitina_provider_send_count_status") == "unknown"


def test_native_response_facts_normal_result_are_bounded() -> None:
    turn = ProviderToolTurn(
        "",
        (ProviderToolCall("c1", "experience_result", {"status": "FAILED", "error_code": "provider-http-error"}),),
        "tool_calls",
        {
            "physical_send_count": 1,
            "physical_send_count_status": "exact",
            "physical_send_status": "response_received",
            "truncated_tool_call_count": 0,
            "token_usage": {"input_tokens": 10, "output_tokens": 2, "raw": "drop-me"},
            "sitina_provider_profile": "deepseek",
            "sitina_provider_model": "deepseek-chat",
        },
        "private reasoning",
    )
    result = NativeExperienceProviderFactory(_Client(turn), _profile(), max_tokens=4096, timeout_seconds=1)(_request())
    assert result["error_code"] == "provider-http-error"
    assert result["finish_reason"] == "tool_calls"
    assert result["output_truncation"] == "not_truncated"
    assert result["provider_send_count"] == 1
    assert result["provider_usage"] == {"input_tokens": 10, "output_tokens": 2}
    assert result["output_limit_tokens"] == 4096
    assert "raw" not in result["provider_usage"]
    assert "reasoning_content" not in result and "text" not in result

    # Invalid structured arguments retain only bounded field observations.
    for arguments in ({}, {"status": None}, {"status": 7}, {"status": {"private": "content"}},
                      {"status": "COMPLETE"}, {"status": "private-value-" * 100}):
        invalid = ProviderToolTurn(
            "private reasoning", (ProviderToolCall("c1", "experience_result", arguments),),
            "tool_calls", {**turn.metadata, "json_repair_count": 0,
                           "response_refusal_present": False, "response_error_present": False,
                           "uncertain_physical_send_attempt_count": 0}, "secret reasoning",
        )
        with pytest.raises(ValueError, match="no valid status") as caught:
            NativeExperienceProviderFactory(_Client(invalid), _profile(), max_tokens=4096, timeout_seconds=1)(_request())
        observation = caught.value.sitina_provider_output_observation
        assert observation["tool_names"] == ["experience_result"]
        assert observation["tool_call_count"] == 1
        assert observation["arguments_is_mapping"] is True
        assert observation["status_present"] is ("status" in arguments)
        assert observation["status_type"] == (type(arguments["status"]).__name__ if "status" in arguments else "missing")
        assert observation["status_value"] == ("COMPLETE" if arguments.get("status") == "COMPLETE" else None)
        assert observation["json_repair_count"] == 0
        assert "private-value" not in json.dumps(observation)
        assert "private reasoning" not in json.dumps(observation)
        if "status" in arguments:
            assert observation["status_value_bytes"] == len(json.dumps(arguments["status"], sort_keys=True, separators=(",", ":")).encode())
            assert len(observation["status_value_sha256"]) == 64


def _create_extraction(backend: LoopBackend, task_id: str) -> str:
    task = backend.create_task(
        task_id=task_id,
        session_id="session-b6-response",
        task_kind="readonly",
        goal="response correction test",
        required_outcome_ids=("outcome-1",),
        artifact_ref=f"cas:artifact-{task_id}",
        environment_ref="environment-b6-response",
        capability_snapshot_id="capabilities-b6-response",
    )
    task = backend.record_acceptance(
        task.task_id,
        AcceptanceSubmission(
            acceptance_id=f"acceptance-{task_id}", outcome_id="outcome-1", evidence_refs=(f"cas:evidence-{task_id}",),
            program_status="PASS", reviewer_status="PASS", delivery_verified=True,
            expected_task_revision=task.task_revision, expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch, expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version, expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref,
        ),
    )
    backend.propose_terminal(
        task.task_id,
        CompletionProposal(
            proposal_id=f"proposal-{task_id}", terminal_status=TaskStatus.SUCCEEDED,
            expected_task_revision=task.task_revision, expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch, expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version, expected_received_input_seq=task.received_input_seq,
            expected_handled_input_seq=task.handled_input_seq, artifact_ref=task.artifact_ref,
            final_result={"result": "ok"},
        ),
    )
    return next(
        item["obligation_id"] for item in backend.pending_experience_obligations()
        if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
    )


def test_coordinator_unknown_invalid_result_persists_unknown_without_zero(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "unknown", keychain_backend=MemoryKeychainBackend(), run_instance_id="run-unknown") as backend:
        obligation_id = _create_extraction(backend, "task-unknown")

        def dispatch(_request):
            raise ValueError("invalid result from worker with no transport facts")

        with pytest.raises(ValueError):
            backend.process_experience_obligation(
                obligation_id, request_id="request-unknown", provider_profile="deepseek", provider_dispatch=dispatch
            )
        projection = backend._experience_obligation_projection()[obligation_id]
        assert projection["state"] == "UNKNOWN"
        assert projection["unknown_effect"] is True
        facts = projection["provider_dispatch_facts"]
        assert facts["provider_send_count"] is None
        assert facts["provider_send_count_status"] == "unknown"
        failure = projection["validation_failure"]
        assert failure["obligation_id"] == obligation_id
        assert failure["request_id"] == "request-unknown"
        assert failure["attempt_count"] == 1
        assert failure["stage"] == "PROVIDER_DISPATCH"
        assert failure["reason_code"] == "UNCLASSIFIED_AT_STAGE"
        assert "invalid result from worker" not in failure["detail"]


def test_coordinator_known_http_invalid_result_persists_failed_with_exact_facts(tmp_path: Path) -> None:
    with LoopBackend.open(tmp_path / "known", keychain_backend=MemoryKeychainBackend(), run_instance_id="run-known") as backend:
        obligation_id = _create_extraction(backend, "task-known")

        def dispatch(_request):
            error = ValueError("structured result rejected after HTTP response")
            error.sitina_provider_send_count = 1
            error.sitina_provider_send_count_status = "exact"
            error.sitina_physical_send_status = "response_received"
            error.sitina_response_received = True
            error.sitina_uncertain_physical_send_attempt_count = 0
            error.sitina_http_status = 402
            error.sitina_error_code = "provider-http-error"
            raise error

        with pytest.raises(ValueError):
            backend.process_experience_obligation(
                obligation_id, request_id="request-known", provider_profile="deepseek", provider_dispatch=dispatch
            )
        projection = backend._experience_obligation_projection()[obligation_id]
        assert projection["state"] == "FAILED_FINAL"
        assert projection["unknown_effect"] is False
        facts = projection["provider_dispatch_facts"]
        assert facts["provider_send_count"] == 1
        assert facts["provider_send_count_status"] == "exact"
        assert facts["provider_http_status"] == 402
        assert facts["error_code"] == "provider-http-error"
        failure = projection["validation_failure"]
        assert failure["request_id"] == "request-known"
        assert failure["candidate_index"] is None
        assert failure["stage"] == "PROVIDER_DISPATCH"
        assert failure["reason_code"] == "UNCLASSIFIED_AT_STAGE"
        assert "structured result rejected" not in failure["detail"]

    # One program-owned correction uses the durable obligation budget, never
    # an in-dispatch resend, and cannot bypass the existing manifest boundary.
    for scenario in ("corrected", "still-invalid", "unbound-manifest", "unknown", "truncated", "refusal", "wrong-tool", "missing-tool"):
        with LoopBackend.open(tmp_path / scenario, keychain_backend=MemoryKeychainBackend(), run_instance_id="run-" + scenario) as backend:
            obligation_id = _create_extraction(backend, "task-" + scenario)
            task_before = backend.get_task("task-" + scenario)
            metadata = {
                "physical_send_count": 1, "physical_send_count_status": "exact",
                "physical_send_status": "response_received", "uncertain_physical_send_attempt_count": 0,
                "truncated_tool_call_count": 0, "json_repair_count": 0,
                "response_refusal_present": False, "response_error_present": False,
                "token_usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4},
                "sitina_provider_profile": "deepseek", "sitina_provider_model": "deepseek-chat",
            }
            calls = (ProviderToolCall("c1", "experience_result", {"status": "COMPLETE", "manifest": {"status": "EMPTY"}}),)
            finish = "tool_calls"
            if scenario == "unknown":
                metadata.update({"physical_send_count_status": "lower_bound_with_uncertain_attempts",
                                 "uncertain_physical_send_attempt_count": 1})
            elif scenario == "truncated":
                metadata["truncated_tool_call_count"] = 1
                finish = "length"
            elif scenario == "refusal":
                metadata["response_refusal_present"] = True
            elif scenario == "wrong-tool":
                calls = (ProviderToolCall("c1", "other_tool", {"status": "COMPLETE"}),)
            elif scenario == "missing-tool":
                calls = ()
            client = _Client(ProviderToolTurn("private", calls, finish, metadata, "reasoning"))
            factory = NativeExperienceProviderFactory(client, _profile(), max_tokens=4096, timeout_seconds=1)
            first_id = "request-" + scenario + "-1"
            with pytest.raises(ValueError):
                backend.process_experience_obligation(obligation_id, request_id=first_id,
                    provider_profile="deepseek", provider_dispatch=factory)
            first = backend._experience_obligation_projection()[obligation_id]
            assert len(client.calls) == 1
            assert first["attempt_count"] == 1
            assert first["max_attempts"] == 3
            if scenario in {"unknown", "truncated", "refusal", "wrong-tool", "missing-tool"}:
                assert first["state"] == ("UNKNOWN" if scenario == "unknown" else "FAILED_FINAL")
                assert first.get("status_correction") is None
                assert first["next_due_at"] is None
                with pytest.raises(TaskConflict):
                    backend.process_experience_obligation(obligation_id, request_id=first_id + "-forbidden",
                        provider_profile="deepseek", provider_dispatch=factory)
                assert len(client.calls) == 1
                continue
            assert first["state"] == "PENDING"
            assert first["validation_failure"]["reason_code"] == "PROVIDER_EXTRACTION_STATUS_INVALID"
            assert first["validation_failure"]["field"] == "status"
            assert first["validation_failure"]["output_observation"]["status_value"] == "COMPLETE"
            assert first["status_correction"] == first["validation_failure"]
            assert first["next_due_at"] is not None
            assert not backend._experience_obligation_is_due(first)
            assert first.get("manifest_ref") is None
            assert not first.get("candidate_ids")
            time.sleep(0.6)
            assert backend._experience_obligation_is_due(first)
            with pytest.raises(TaskConflict):
                backend.process_experience_obligation(obligation_id, request_id=first_id,
                    provider_profile="deepseek", provider_dispatch=factory)
            assert len(client.calls) == 1
            if scenario != "still-invalid":
                client.turn = ProviderToolTurn("", (ProviderToolCall("c2", "experience_result", {
                    "status": "SUCCEEDED", "manifest": {
                        "schema": "SITINA_EXPERIENCE_MANIFEST_V1", "batch_id": "batch-" + scenario,
                        "source_closure_hash": first["source_closure"]["closure_hash"] if scenario == "corrected" else "0" * 64,
                        "status": "COMPLETE", "candidates": [{"candidate_id": "candidate-" + scenario,
                            "revision": "revision-1", "content": "bounded lesson"}],
                    },
                }),), "tool_calls", metadata)
            second_id = "request-" + scenario + "-2"
            if scenario == "corrected":
                backend.process_experience_obligation(obligation_id, request_id=second_id,
                    provider_profile="deepseek", provider_dispatch=factory)
            else:
                with pytest.raises(ValueError):
                    backend.process_experience_obligation(obligation_id, request_id=second_id,
                        provider_profile="deepseek", provider_dispatch=factory)
            second = backend._experience_obligation_projection()[obligation_id]
            assert second["attempt_count"] == 2 and second["max_attempts"] == 3
            assert len(client.calls) == 2
            feedback_request = json.loads(client.calls[1]["messages"][0]["content"])
            assert feedback_request["request_id"] == second_id
            assert feedback_request["validation_feedback"] == first["validation_failure"]
            assert "manifest.status is a separate nested field" in client.calls[1]["system_prompt"]
            assert client.calls[0]["prepared_request"] != client.calls[1]["prepared_request"]
            patches = [event.payload["patch"] for event in backend._experience_obligation_events()
                       if event.payload["obligation_id"] == obligation_id and event.event_type == "loop.experience-obligation-updated"]
            retained = [patch for patch in patches if isinstance(patch.get("validation_failure"), dict)]
            assert retained[0]["validation_failure"] == first["validation_failure"]
            attempts = [patch["provider_dispatch_facts"] for patch in patches if "provider_dispatch_facts" in patch]
            assert sum(item["provider_send_count"] for item in attempts) == 2
            assert sum(item["provider_usage"]["total_tokens"] for item in attempts) == 8
            assert backend.get_task("task-" + scenario).task_revision == task_before.task_revision
            assert backend.get_task("task-" + scenario).status == TaskStatus.SUCCEEDED
            if scenario == "corrected":
                assert second["state"] == "MANIFEST_RECORDED"
                assert second["candidate_dispositions"] == {}
            else:
                assert second["state"] == "FAILED_FINAL"
                assert second.get("manifest_ref") is None
                assert not second.get("candidate_ids")
                assert second["validation_failure"]["reason_code"] == (
                    "PROVIDER_EXTRACTION_STATUS_INVALID" if scenario == "still-invalid" else "MANIFEST_INCOMPLETE_OR_UNBOUND")
                with pytest.raises(TaskConflict):
                    backend.process_experience_obligation(obligation_id, request_id=second_id + "-forbidden",
                        provider_profile="deepseek", provider_dispatch=factory)
                assert len(client.calls) == 2
