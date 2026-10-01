from __future__ import annotations

from pathlib import Path

from sitina.extensions.authority import (
    PUBLICATION_FAILURE_RECONCILIATION_SCHEMA,
)
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.tools import ToolCatalog
from sitina.loop import InputKind, LoopBackend
from sitina.loop.task_runtime import LoopOperationAdapter
from sitina.runners.provider import ProviderToolCall
from sitina.security.macos_keychain import MemoryKeychainBackend

from test_extensions_batch_4c import _prepare, _skill, _task_binding
from test_loop_batch_1b_runtime import boundary_fixture


def _run_skill_trial_for(backend, manager, snapshot, task_id: str, workspace: Path):
    workspace.mkdir(parents=True, exist_ok=True)
    catalog = ToolCatalog(manager, workspace=workspace)
    catalog.bind_execution_snapshot(snapshot)
    call = ProviderToolCall("read-resource", "sitina_read_skill_resource", {
        "skill": "count-fruit", "path": "references/facts.md",
    })
    catalog.bind_loop_consumer(
        backend=backend, task_id=task_id, snapshot_id=snapshot["snapshot_id"], call_id=call.call_id,
    )
    adapter = LoopOperationAdapter(backend, task_id, workspace, mutation_allowed=False)
    try:
        adapter.tool_call(
            f"{task_id}-run", call, lambda: catalog.execute(call.name, call.arguments), permission="read",
            method_plan=catalog.consumer_method_plan(call.name, call.arguments, task_id=task_id, call_id=call.call_id),
        )
    finally:
        catalog.clear_loop_consumer()
    task = backend.get_task(task_id)
    operation_id = adapter.operation_ids[0]
    operation = task.operations[operation_id]
    persisted = dict(backend.context_memory.read(str(operation.result_ref)))
    raw_result = dict(persisted["result"])
    return task, operation_id, raw_result, dict(raw_result["execution_binding"])


def _publish_candidate(backend, manager, authority, prepared, snapshot, task_id, request_id, trial_request_id, workspace):
    backend.create_task(
        task_id=task_id, session_id=task_id, task_kind="code_change", goal="publish",
        required_outcome_ids=("published",), artifact_ref=f"artifact-{task_id}",
        environment_ref="environment-publisher", capability_snapshot_id=snapshot["snapshot_id"],
    )
    task = backend.get_task(task_id)
    source = _task_binding(task)
    source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
    intent = authority.record_publication_intent(
        request_id=request_id, slot="skill:count-fruit", candidate_id=prepared.candidate_id,
        snapshot=snapshot, source=source,
    )
    task, operation_id, raw_result, binding = _run_skill_trial_for(
        backend, manager, snapshot, task_id, workspace,
    )
    trial = authority.record_trial_fact(
        request_id=trial_request_id, candidate_id=prepared.candidate_id, snapshot=snapshot,
        task_binding=source, operation_id=operation_id,
        method={key: binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
        raw_result=raw_result, input_binding={"handled_input_seq": task.handled_input_seq},
        artifact_binding={"artifact_ref": task.artifact_ref},
    )
    decision = authority.commit_publication({
        "request_id": request_id, "slot": "skill:count-fruit", "candidate_id": prepared.candidate_id,
        "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"],
        "location_binding": snapshot["location_binding"], "source": source,
        "trial_request_id": trial_request_id, "trial_event_id": trial.event_id,
        "operation_id": operation_id,
        "expected_previous_default": intent.payload["expected_previous_default"],
        "expected_stream_position": intent.payload["expected_stream_position"],
    })
    return decision


def test_failure_obligation_restores_previous_default_as_new_publication_and_checks_it(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    backend, manager, authority, prepared_p, snapshot_p = _prepare(tmp_path)
    try:
        p = _publish_candidate(
            backend, manager, authority, prepared_p, snapshot_p, "publisher-p",
            "publish-p-c3b2", "trial-p-c3b2", tmp_path / "workspace-p",
        )
        backend.accept_input("publisher-p", input_id="finish-p", kind=InputKind.CANCEL, body="done")
        backend.handle_next_input("publisher-p")
        backend.cancel_safely("publisher-p")
        source_a = _skill(tmp_path / "source-a")
        (source_a / "references" / "facts.md").write_text("candidate-a\n", encoding="utf-8")
        backend.create_task(
            task_id="prepare-a-c3b2", session_id="prepare-a-c3b2", task_kind="code_change",
            goal="prepare A", required_outcome_ids=("prepared",), artifact_ref="artifact-prepare-a",
            environment_ref="environment-prepare", capability_snapshot_id="prepare-a-snapshot",
        )
        prepared_a = manager.prepare_skill_candidate(
            source_a,
            execution_context=manager.create_extension_preparation_context("prepare-a-c3b2", source_a),
        )
        backend.accept_input("prepare-a-c3b2", input_id="finish", kind=InputKind.CANCEL, body="done")
        backend.handle_next_input("prepare-a-c3b2")
        backend.cancel_safely("prepare-a-c3b2")
        snapshot_a = authority.build_execution_snapshot(prepared_a.candidate_id).as_dict()
        a = _publish_candidate(
            backend, manager, authority, prepared_a, snapshot_a, "publisher-a",
            "publish-a-c3b2", "trial-a-c3b2", tmp_path / "workspace-a",
        )
        backend.accept_input("publisher-a", input_id="finish-a", kind=InputKind.CANCEL, body="done")
        backend.handle_next_input("publisher-a")
        backend.cancel_safely("publisher-a")
        events = authority._journal_events()
        a_event = next(event for event in events if event.payload.get("publication_id") == a["publication_id"])
        failure_obligation = f"{a['publication_id']}:default-action:v1"
        authority._append_fact(
            request_id="failure-a-c3b2",
            event_type="extension.publication-failure-reconciled",
            payload={
                "schema": PUBLICATION_FAILURE_RECONCILIATION_SCHEMA,
                "event_type": "extension.publication-failure-reconciled",
                "failure_source": {"kind": "DEFAULT_CONSUMER_CHECK_FAILED", "reference": "cas:failure-a", "hash": "f" * 64},
                "failed_publication": {
                    "slot_id": "skill:count-fruit", "publication_id": a["publication_id"],
                    "snapshot_id": snapshot_a["snapshot_id"], "read_position": {"stream_version": a_event.stream_version},
                },
                "isolation": {"state": "ISOLATED", "publication_id": a["publication_id"], "reason": "CONFIRMED_CONTRACT_FAILURE"},
                "default_action_obligation": {
                    "obligation_id": failure_obligation, "type": "CONDITIONAL_DEFAULT_ACTION",
                    "expected_current_publication_id": a["publication_id"], "state": "PENDING",
                },
                "resolution": "PENDING_CONDITIONAL_ACTION",
            },
        )
        action = backend.process_publication_failure_obligation(failure_obligation, "action-a-c3b2")
        assert action["resolution"] == "RESTORED_PREVIOUS_DEFAULT"
        assert action["publication_id"] not in {p["publication_id"], a["publication_id"]}
        c = action["publication_id"]
        projection = authority.load_projection()
        assert projection["defaults"]["skill:count-fruit"]["publication_id"] == c
        assert projection["obligations"][failure_obligation]["state"] == "COMPLETED"
        assert action["check_obligation"]["required_publication_id"] == c

        resolution = authority.resolve_default("skill:count-fruit")
        proof = backend.extension_existing_object_proof(resolution["projection_ref"])
        binding = {
            "schema": "SITINA_LOOP_CAPABILITY_BINDING_V1",
            "slot_id": resolution["slot"]["slot_id"],
            "publication_id": resolution["publication_id"],
            "candidate_id": resolution["candidate_id"],
            "snapshot_id": resolution["snapshot_id"],
            "snapshot_hash": resolution["snapshot_hash"],
            "location_binding": resolution["location_binding"],
            "resolution_stream_id": resolution["stream_id"],
            "read_position": dict(resolution["read_position"]),
            "resolution_ref": resolution["projection_ref"],
            "resolution_hash": resolution["projection_hash"],
            "resolution_cas_proof": {
                "schema": "SITINA_EXISTING_DURABLE_OBJECT_ROOT_PROOF_V1",
                "object_ref": proof.object_ref.reference_id,
                "journal_id": proof.journal_id,
                "rooted_transaction_hash": proof.rooted_transaction_hash,
                "rooted_position": proof.rooted_position,
                "verified_frontier_position": proof.verified_frontier_position,
                "verified_frontier_transaction_hash": backend.store.journal._position_hash.get(proof.verified_frontier_position),
                "object_reference_manifest_hash": proof.object_reference_manifest_hash,
            },
        }
        backend.admit_task(
            task_id="consumer-c3b2", session_id="consumer-c3b2", task_kind="readonly",
            goal="consume restored C", workspace_path=str(tmp_path / "business-workspace"),
            provider_profile="deepseek", authorization="cli", submission_id="consumer-c3b2",
            capability_selection="skill:count-fruit", capability_binding=binding,
            environment_ref="environment-publisher", capability_snapshot_id=binding["snapshot_id"],
            provider_identity="fixture-provider", software_identity="fixture-software", config_identity="fixture-config",
        )
        _task, operation_id, _raw, _binding = _run_skill_trial_for(
            backend, manager, snapshot_p, "consumer-c3b2", tmp_path / "workspace-consumer",
        )
        check = backend.record_extension_publication_check_from_task("consumer-c3b2", operation_id)
        assert check and check["status"] == "passed"
        before = tuple(authority._journal_events())
        replay = backend.process_publication_failure_obligation(failure_obligation, "action-a-c3b2")
        assert replay["replayed"] is True
        assert tuple(authority._journal_events()) == before
    finally:
        backend.close()


def test_failure_obligation_without_previous_default_disables_and_creates_repair(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    try:
        a = _publish_candidate(
            backend, manager, authority, prepared, snapshot, "publisher-disable-a",
            "publish-disable-a", "trial-disable-a", tmp_path / "workspace-disable-a",
        )
        backend.accept_input("publisher-disable-a", input_id="finish", kind=InputKind.CANCEL, body="done")
        backend.handle_next_input("publisher-disable-a")
        backend.cancel_safely("publisher-disable-a")
        failure_obligation = f"{a['publication_id']}:default-action:v1"
        authority._append_fact(
            request_id="failure-disable-a",
            event_type="extension.publication-failure-reconciled",
            payload={
                "schema": PUBLICATION_FAILURE_RECONCILIATION_SCHEMA,
                "event_type": "extension.publication-failure-reconciled",
                "failed_publication": {"slot_id": "skill:count-fruit", "publication_id": a["publication_id"], "snapshot_id": snapshot["snapshot_id"]},
                "isolation": {"state": "ISOLATED", "publication_id": a["publication_id"]},
                "default_action_obligation": {"obligation_id": failure_obligation, "state": "PENDING"},
                "resolution": "PENDING_CONDITIONAL_ACTION",
            },
        )
        action = backend.process_publication_failure_obligation(failure_obligation, "action-disable-a")
        assert action["resolution"] == "DISABLED"
        assert action["publication_id"] is None
        assert action["repair_obligation"]["state"] == "PENDING"
        assert "skill:count-fruit" not in authority.load_projection()["defaults"]
    finally:
        backend.close()


def test_failure_obligation_protects_later_default(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    try:
        a = _publish_candidate(
            backend, manager, authority, prepared, snapshot, "publisher-protect-a",
            "publish-protect-a", "trial-protect-a", tmp_path / "workspace-protect-a",
        )
        backend.accept_input("publisher-protect-a", input_id="finish", kind=InputKind.CANCEL, body="done")
        backend.handle_next_input("publisher-protect-a")
        backend.cancel_safely("publisher-protect-a")
        b = _publish_candidate(
            backend, manager, authority, prepared, snapshot, "publisher-protect-b",
            "publish-protect-b", "trial-protect-b", tmp_path / "workspace-protect-b",
        )
        backend.accept_input("publisher-protect-b", input_id="finish", kind=InputKind.CANCEL, body="done")
        backend.handle_next_input("publisher-protect-b")
        backend.cancel_safely("publisher-protect-b")
        failure_obligation = f"{a['publication_id']}:default-action:v1"
        authority._append_fact(
            request_id="failure-protect-a",
            event_type="extension.publication-failure-reconciled",
            payload={
                "schema": PUBLICATION_FAILURE_RECONCILIATION_SCHEMA,
                "event_type": "extension.publication-failure-reconciled",
                "failed_publication": {"slot_id": "skill:count-fruit", "publication_id": a["publication_id"], "snapshot_id": snapshot["snapshot_id"]},
                "isolation": {"state": "ISOLATED", "publication_id": a["publication_id"]},
                "default_action_obligation": {"obligation_id": failure_obligation, "state": "PENDING"},
                "resolution": "PENDING_CONDITIONAL_ACTION",
            },
        )
        action = backend.process_publication_failure_obligation(failure_obligation, "action-protect-a")
        assert action["resolution"] == "PROTECTED_LATER_DEFAULT"
        assert authority.resolve_default("skill:count-fruit")["publication_id"] == b["publication_id"]
        assert authority.load_projection()["obligations"][failure_obligation]["state"] == "COMPLETED"
    finally:
        backend.close()
