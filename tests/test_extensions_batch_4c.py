from __future__ import annotations

import json
from pathlib import Path

import pytest

from sitina.extensions.authority import ExtensionAuthorityConflict, ExtensionAuthorityError
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.tools import ToolCatalog
from sitina.loop import InputKind, LoopBackend
from sitina.loop.task_runtime import LoopOperationAdapter
from sitina.runners.provider import ProviderToolCall
from sitina.security.macos_keychain import MemoryKeychainBackend


def _skill(root: Path) -> Path:
    source = root / "count-fruit"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text(
        "---\nname: count-fruit\ndescription: Read the selected fixture.\n---\nUse the selected resource.\n",
        encoding="utf-8",
    )
    (source / "references").mkdir()
    (source / "references" / "facts.md").write_text("candidate-resource\n", encoding="utf-8")
    return source


def _task_binding(task):
    return {
        field: getattr(task, field)
        for field in (
            "task_id", "session_id", "run_instance_id", "execution_epoch",
            "goal_version", "acceptance_version", "received_input_seq",
            "handled_input_seq", "artifact_ref",
        )
    }


def _prepare(tmp_path: Path):
    home = tmp_path / "home"
    (home / "config").mkdir(parents=True)
    extension_root = tmp_path / "extensions"
    state_root = tmp_path / "state"
    backend = LoopBackend.open(state_root, keychain_backend=MemoryKeychainBackend())
    manager = ExtensionManager(home, global_root=extension_root)
    authority = manager.bind_shared_authority(state_root=state_root, backend=backend)
    backend.create_task(
        task_id="prepare", session_id="prepare-session", task_kind="code_change", goal="prepare",
        required_outcome_ids=("prepared",), artifact_ref="artifact-prepare",
        environment_ref="environment-prepare", capability_snapshot_id="prepare-capability",
    )
    source = _skill(tmp_path / "source")
    prepared = manager.prepare_skill_candidate(
        source, execution_context=manager.create_extension_preparation_context("prepare", source)
    )
    # Candidate preparation owns the shared extension-root resource until its
    # source task settles.  Close the preparation task through the normal Loop
    # CANCEL/terminal path before the publisher exercises the same write lane.
    backend.accept_input("prepare", input_id="finish-preparation", kind=InputKind.CANCEL, body="done")
    backend.handle_next_input("prepare")
    backend.cancel_safely("prepare")
    snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
    backend.create_task(
        task_id="publisher", session_id="publisher-session", task_kind="code_change", goal="publish",
        required_outcome_ids=("published",), artifact_ref="artifact-publisher",
        environment_ref="environment-publisher", capability_snapshot_id=snapshot["snapshot_id"],
    )
    return backend, manager, authority, prepared, snapshot


def _run_skill_trial(backend, manager, snapshot, workspace: Path):
    workspace.mkdir(parents=True, exist_ok=True)
    catalog = ToolCatalog(manager, workspace=workspace)
    catalog.bind_execution_snapshot(snapshot)
    adapter = LoopOperationAdapter(backend, "publisher", workspace, mutation_allowed=False)
    call = ProviderToolCall("read-resource", "sitina_read_skill_resource", {
        "skill": "count-fruit", "path": "references/facts.md",
    })
    catalog.bind_loop_consumer(
        backend=backend, task_id="publisher", snapshot_id=snapshot["snapshot_id"], call_id=call.call_id,
    )
    try:
        adapter.tool_call(
            "publisher-run", call, lambda: catalog.execute(call.name, call.arguments), permission="read",
            method_plan=catalog.consumer_method_plan(
                call.name, call.arguments, task_id="publisher", call_id=call.call_id,
            ),
        )
    finally:
        catalog.clear_loop_consumer()
    task = backend.get_task("publisher")
    operation_id = adapter.operation_ids[0]
    operation = task.operations[operation_id]
    persisted = dict(backend.context_memory.read(str(operation.result_ref)))
    raw_result = dict(persisted["result"])
    binding = dict(raw_result["execution_binding"])
    return task, operation_id, raw_result, binding


def test_active_task_publication_is_single_journal_decision_and_exactly_replayable(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    try:
        task = backend.get_task("publisher")
        source = _task_binding(task)
        source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
        intent = authority.record_publication_intent(
            request_id="publish-count-fruit-1", slot="skill:count-fruit",
            candidate_id=prepared.candidate_id, snapshot=snapshot, source=source,
        )
        intent_events_before_replay = tuple(authority._journal_events())
        replayed_intent = authority.record_publication_intent(
            request_id="publish-count-fruit-1", slot="skill:count-fruit",
            candidate_id=prepared.candidate_id, snapshot=snapshot, source=source,
        )
        assert replayed_intent.event_id == intent.event_id
        assert tuple(authority._journal_events()) == intent_events_before_replay
        task, operation_id, raw_result, binding = _run_skill_trial(backend, manager, snapshot, tmp_path / "workspace")
        trial = authority.record_trial_fact(
            request_id="trial-count-fruit-1", candidate_id=prepared.candidate_id, snapshot=snapshot,
            task_binding=source, operation_id=operation_id,
            method={key: binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
            raw_result=raw_result, input_binding={"handled_input_seq": task.handled_input_seq},
            artifact_binding={"artifact_ref": task.artifact_ref},
        )
        request = {
            "request_id": "publish-count-fruit-1",
            "slot": "skill:count-fruit",
            "candidate_id": prepared.candidate_id,
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_hash": snapshot["snapshot_hash"],
            "location_binding": snapshot["location_binding"],
            "source": source,
            "trial_request_id": "trial-count-fruit-1",
            "trial_event_id": trial.event_id,
            "operation_id": operation_id,
            "expected_previous_default": intent.payload["expected_previous_default"],
            "expected_stream_position": intent.payload["expected_stream_position"],
        }
        decision = authority.commit_publication(request)
        assert decision["publication_id"].startswith("publication-")
        assert decision["check_obligation"]["state"] == "PENDING"
        events_before = tuple(authority._journal_events())
        replay = authority.commit_publication({"request_id": request["request_id"]})
        assert replay["replayed"] is True
        assert replay["publication_id"] == decision["publication_id"]
        full_replay = authority.commit_publication(request)
        assert full_replay["replayed"] is True
        assert full_replay["publication_id"] == decision["publication_id"]
        assert tuple(authority._journal_events()) == events_before

        resolution = authority.resolve_default("skill:count-fruit")
        assert resolution["publication_id"] == decision["publication_id"]
        assert resolution["snapshot_id"] == snapshot["snapshot_id"]
        assert resolution["read_position"]["stream_version"] >= decision["stream_version"]

        with pytest.raises(ExtensionAuthorityConflict):
            authority.commit_publication({**request, "slot": "skill:other"})
    finally:
        backend.close()


def test_default_projection_rebuilds_and_admitted_resolution_stays_pinned(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    try:
        task = backend.get_task("publisher")
        source = _task_binding(task)
        source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
        intent = authority.record_publication_intent(
            request_id="publish-count-fruit-2", slot="skill:count-fruit",
            candidate_id=prepared.candidate_id, snapshot=snapshot, source=source,
        )
        task, operation_id, raw_result, binding = _run_skill_trial(backend, manager, snapshot, tmp_path / "workspace")
        trial = authority.record_trial_fact(
            request_id="trial-count-fruit-2", candidate_id=prepared.candidate_id, snapshot=snapshot,
            task_binding=source, operation_id=operation_id,
            method={key: binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
            raw_result=raw_result, input_binding={"handled_input_seq": task.handled_input_seq},
            artifact_binding={"artifact_ref": task.artifact_ref},
        )
        request = {
            "request_id": "publish-count-fruit-2", "slot": "skill:count-fruit",
            "candidate_id": prepared.candidate_id, "snapshot_id": snapshot["snapshot_id"],
            "snapshot_hash": snapshot["snapshot_hash"], "location_binding": snapshot["location_binding"],
            "source": source, "trial_request_id": "trial-count-fruit-2", "trial_event_id": trial.event_id,
            "operation_id": operation_id, "expected_previous_default": intent.payload["expected_previous_default"],
            "expected_stream_position": intent.payload["expected_stream_position"],
        }
        decision = authority.commit_publication(request)
        admitted = authority.resolve_default("skill:count-fruit")
        (authority.extension_root / "registry.json").unlink()
        rebuilt = authority.resolve_default("skill:count-fruit")
        assert rebuilt["publication_id"] == decision["publication_id"]
        assert rebuilt["stream_version"] == admitted["stream_version"]
        assert rebuilt["snapshot_id"] == admitted["snapshot_id"]
        assert json.loads((authority.extension_root / "registry.json").read_text(encoding="utf-8"))["schema"] == "SITINA_EXTENSION_PROJECTION_V1"
    finally:
        backend.close()


def test_publication_rejects_intent_recorded_after_actual_operation_dispatch(tmp_path: Path) -> None:
    """A trial event alone cannot retroactively authorize its extension write."""

    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    try:
        task, operation_id, raw_result, binding = _run_skill_trial(
            backend, manager, snapshot, tmp_path / "workspace"
        )
        source = _task_binding(task)
        source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
        trial = authority.record_trial_fact(
            request_id="trial-count-fruit-late-intent", candidate_id=prepared.candidate_id,
            snapshot=snapshot, task_binding=source, operation_id=operation_id,
            method={key: binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
            raw_result=raw_result, input_binding={"handled_input_seq": task.handled_input_seq},
            artifact_binding={"artifact_ref": task.artifact_ref},
        )
        intent = authority.record_publication_intent(
            request_id="publish-count-fruit-late-intent", slot="skill:count-fruit",
            candidate_id=prepared.candidate_id, snapshot=snapshot, source=source,
        )
        request = {
            "request_id": "publish-count-fruit-late-intent", "slot": "skill:count-fruit",
            "candidate_id": prepared.candidate_id, "snapshot_id": snapshot["snapshot_id"],
            "snapshot_hash": snapshot["snapshot_hash"], "location_binding": snapshot["location_binding"],
            "source": source, "trial_request_id": "trial-count-fruit-late-intent",
            "trial_event_id": trial.event_id, "operation_id": operation_id,
            "expected_previous_default": intent.payload["expected_previous_default"],
            "expected_stream_position": intent.payload["expected_stream_position"],
        }
        with pytest.raises(ExtensionAuthorityError, match="recorded after trial operation dispatch"):
            authority.commit_publication(request)
        assert not any(event.event_type == "extension.publication-committed" for event in authority._journal_events())
    finally:
        backend.close()


def test_publication_source_role_fields_cannot_grant_authority(tmp_path: Path) -> None:
    backend, manager, authority, prepared, snapshot = _prepare(tmp_path)
    try:
        task = backend.get_task("publisher")
        source = _task_binding(task)
        source.update({"actor_role": "forged", "publication_scope": "extension-root", "write_authorized": True})
        with pytest.raises(ExtensionAuthorityError, match="Backend did not authorize|binding differs"):
            authority.record_publication_intent(
                request_id="publish-count-fruit-forged-role", slot="skill:count-fruit",
                candidate_id=prepared.candidate_id, snapshot=snapshot, source=source,
            )
    finally:
        backend.close()
