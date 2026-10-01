from __future__ import annotations

from pathlib import Path

import pytest

from sitina.journal.model import canonical_json_bytes
from sitina.loop import AcceptanceSubmission, CompletionProposal, LoopBackend, TaskStatus
from sitina.loop.coordinator import EXPERIENCE_OBLIGATION_SCHEMA
from sitina.loop.model import PersistenceFenced
from sitina.security.macos_keychain import MemoryKeychainBackend


def _create_extraction(backend: LoopBackend, task_id: str, final_result: dict) -> str:
    task = backend.create_task(
        task_id=task_id,
        session_id="session-b6-preflight",
        task_kind="readonly",
        goal="produce a bounded experience source",
        required_outcome_ids=("outcome-1",),
        artifact_ref="cas:artifact-b6-preflight",
        environment_ref="environment-b6-preflight",
        capability_snapshot_id="capabilities-b6-preflight",
    )
    task = backend.record_acceptance(
        task.task_id,
        AcceptanceSubmission(
            acceptance_id="acceptance-b6-preflight",
            outcome_id="outcome-1",
            evidence_refs=("cas:evidence-b6-preflight",),
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
            proposal_id="proposal-b6-preflight",
            terminal_status=TaskStatus.SUCCEEDED,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_received_input_seq=task.received_input_seq,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref,
            final_result=final_result,
        ),
    )
    return next(
        str(item["obligation_id"])
        for item in backend.pending_experience_obligations()
        if item["obligation_type"] == "EXPERIENCE_EXTRACTION"
    )


def _empty_manifest(request: dict) -> dict:
    return {
        "status": "SUCCEEDED",
        "manifest": {
            "schema": "SITINA_EXPERIENCE_MANIFEST_V1",
            "batch_id": "batch-b6-preflight",
            "source_closure_hash": request["source_closure"]["closure_hash"],
            "status": "EMPTY",
            "candidates": [],
        },
    }


def test_bounded_terminal_projection_keeps_result_and_checks(tmp_path: Path) -> None:
    final_result = {
        "response": "useful scientific result",
        "changed_paths": ["scientific-result.json"],
        "cycle": 1,
        "review_status": "PASS",
        "source_sha256": "a" * 64,
        "preflight_check": {
            "program_status": "PASS",
            "exit_code": 0,
            "source_ref": "cas:preflight-ref",
            "command": ["/very/long/path"] * 2000,
        },
        "program_check": {
            "program_status": "PASS",
            "exit_code": 0,
            "result_ref": "cas:program-ref",
            "stderr": "diagnostic " * 2000,
        },
        "shared_contract_evaluation": {"status": "PASS", "evidence": "ok"},
        "verbose_command_log": "x" * 40_000,
    }
    with LoopBackend.open(tmp_path / "bounded", keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _create_extraction(backend, "task-b6-bounded", final_result)
        requests: list[dict] = []
        backend.process_experience_obligation(
            obligation_id,
            request_id="extract-b6-bounded",
            provider_profile="deepseek-scripted",
            provider_dispatch=lambda request: requests.append(dict(request)) or _empty_manifest(request),
        )
        evidence = requests[0]["source_evidence"]
        terminal = evidence["terminal_result"]
        projected = terminal["final_result"]
        assert len(canonical_json_bytes(terminal)) <= 8192
        assert projected["response"] == "useful scientific result"
        assert projected["changed_paths"] == ["scientific-result.json"]
        assert projected["source_sha256"] == "a" * 64
        assert projected["preflight_check"]["program_status"] == "PASS"
        assert projected["program_check"]["program_status"] == "PASS"


def test_source_preflight_failure_stays_pending_and_never_dispatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with LoopBackend.open(tmp_path / "preflight", keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _create_extraction(backend, "task-b6-preflight", {"response": "ok"})
        provider_calls: list[dict] = []

        def fail_before_dispatch(_obligation: dict):
            raise PersistenceFenced("deterministic source preflight failed")

        monkeypatch.setattr(backend, "_verified_experience_source_evidence", fail_before_dispatch)
        with pytest.raises(PersistenceFenced, match="deterministic source preflight"):
            backend.process_experience_obligation(
                obligation_id,
                request_id="extract-b6-preflight-fail",
                provider_profile="deepseek-scripted",
                provider_dispatch=lambda request: provider_calls.append(dict(request)) or _empty_manifest(request),
            )
        projection = backend._experience_obligation_projection()[obligation_id]
        assert projection["state"] == "PENDING"
        assert projection["preflight_request_id"] == "extract-b6-preflight-fail"
        assert projection["last_error"] == "source-preflight-failed-before-dispatch"
        assert projection["unknown_effect"] is False
        assert projection["provider_dispatch_facts"]["provider_send_count"] == 0
        assert projection["provider_dispatch_facts"]["provider_send_status"] == "not_sent"
        assert not provider_calls
        dispatched = [
            event
            for event in backend._experience_obligation_events()
            if event.event_type == "loop.experience-obligation-updated"
            and (event.payload.get("patch") or {}).get("state") == "DISPATCHED"
        ]
        assert not dispatched


def test_source_preflight_budget_is_durable_and_finite_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "finite-preflight"
    keys = MemoryKeychainBackend()
    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-preflight-1") as backend:
        obligation_id = _create_extraction(backend, "task-b6-finite", {"response": "ok"})

        def fail_before_dispatch(_obligation: dict):
            raise PersistenceFenced("deterministic source preflight failed")

        monkeypatch.setattr(backend, "_verified_experience_source_evidence", fail_before_dispatch)
        with pytest.raises(PersistenceFenced):
            backend.process_experience_obligation(
                obligation_id,
                request_id="extract-b6-finite",
                provider_profile="deepseek-scripted",
                provider_dispatch=lambda _request: pytest.fail("Provider callback must not run"),
            )
        first = backend._experience_obligation_projection()[obligation_id]
        assert first["state"] == "PENDING"
        assert first["preflight_attempt_count"] == 1
        assert first["preflight_max_attempts"] == 3
        assert first["next_due_at"]

    def force_due(backend: LoopBackend, request_id: str) -> None:
        backend._append_experience_obligation_event(
            event_type="loop.experience-obligation-updated",
            payload={
                "schema": EXPERIENCE_OBLIGATION_SCHEMA,
                "obligation_id": obligation_id,
                "patch": {"state": "PENDING", "next_due_at": "1970-01-01T00:00:00+00:00"},
            },
            request_id=request_id,
        )

    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-preflight-2") as backend:
        monkeypatch.setattr(backend, "_verified_experience_source_evidence", fail_before_dispatch)
        projection = backend._experience_obligation_projection()[obligation_id]
        assert projection["preflight_attempt_count"] == 1
        force_due(backend, "force-due-2")
        with pytest.raises(PersistenceFenced):
            backend.process_experience_obligation(
                obligation_id,
                request_id="extract-b6-finite",
                provider_profile="deepseek-scripted",
                provider_dispatch=lambda _request: pytest.fail("Provider callback must not run"),
            )
        assert backend._experience_obligation_projection()[obligation_id]["preflight_attempt_count"] == 2
        force_due(backend, "force-due-3")
        with pytest.raises(PersistenceFenced):
            backend.process_experience_obligation(
                obligation_id,
                request_id="extract-b6-finite",
                provider_profile="deepseek-scripted",
                provider_dispatch=lambda _request: pytest.fail("Provider callback must not run"),
            )
        exhausted = backend._experience_obligation_projection()[obligation_id]
        assert exhausted["state"] == "FAILED_FINAL"
        assert exhausted["preflight_attempt_count"] == 3
        assert exhausted["last_error"] == "source-preflight-budget-exhausted"
        assert exhausted["provider_dispatch_facts"]["provider_send_count"] == 0

    with LoopBackend.open(root, keychain_backend=keys, run_instance_id="run-preflight-3") as backend:
        exhausted = backend._experience_obligation_projection()[obligation_id]
        assert exhausted["state"] == "FAILED_FINAL"
        assert not any(
            item.get("obligation_id") == obligation_id
            for item in backend.pending_experience_obligations()
        )


def test_long_success_narrative_cannot_displace_failure_and_source_identity(tmp_path: Path) -> None:
    final_result = {
        "response": "successful-looking narrative " * 2000,
        "summary": "another long narrative " * 2000,
        "status": "FAILED",
        "error_code": "acceptance-failed",
        "reason": "program check rejected the artifact " * 1000,
        "error": "verified failure detail " * 1000,
        "source_sha256": "b" * 64,
        "source_refs": ["cas:source-ref-" + ("x" * 2000)] * 8,
        "evidence_refs": ["cas:evidence-ref-" + ("y" * 2000)] * 8,
        "changed_paths": ["artifacts/" + ("z" * 2000)] * 8,
        "program_check": {
            "status": "FAIL",
            "program_status": "FAIL",
            "exit_code": 1,
            "source_ref": "cas:program-source",
            "result_ref": "cas:program-result",
            "error": "real check failure " * 1000,
            "command": ["/long/command/path"] * 2000,
        },
        "preflight_check": {
            "status": "PASS",
            "program_status": "PASS",
            "exit_code": 0,
            "source_ref": "cas:preflight-source",
        },
    }
    with LoopBackend.open(tmp_path / "long-failure", keychain_backend=MemoryKeychainBackend()) as backend:
        obligation_id = _create_extraction(backend, "task-b6-long-failure", final_result)
        requests: list[dict] = []
        backend.process_experience_obligation(
            obligation_id,
            request_id="extract-b6-long-failure",
            provider_profile="deepseek-scripted",
            provider_dispatch=lambda request: requests.append(dict(request)) or _empty_manifest(request),
        )
        projected = requests[0]["source_evidence"]["terminal_result"]["final_result"]
        assert len(canonical_json_bytes(requests[0]["source_evidence"]["terminal_result"])) <= 8192
        assert projected["status"] == "FAILED"
        assert projected["error_code"] == "acceptance-failed"
        assert projected["source_sha256"] == "b" * 64
        assert projected["program_check"]["status"] == "FAIL"
        assert projected["program_check"]["source_ref"] == "cas:program-source"
        assert projected["preflight_check"]["program_status"] == "PASS"
        assert projected["preflight_check"]["source_ref"] == "cas:preflight-source"
        assert projected["_projection_truncated"] is True
