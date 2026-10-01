from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from sitina.extensions.authority import ExtensionAuthorityError
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.tools import ToolCatalog
from sitina.loop import InputKind, LoopBackend
from sitina.loop.task_runtime import LoopOperationAdapter, LoopTaskRunner
from sitina.runners.provider import ProviderToolCall
from sitina.security.macos_keychain import MemoryKeychainBackend

from test_extensions_batch_4c import _task_binding
from test_extensions_batch_4c3a import _binding_resolver
from test_loop_batch_1b_runtime import boundary_fixture


def _time_boundary_plugin(root: Path) -> tuple[Path, float]:
    source = root / "time-fail"
    metadata = source / ".sitina-plugin"
    metadata.mkdir(parents=True)
    # The immutable boundary is part of the candidate source.  The first
    # trial runs before it; the later consumer observes a deterministic
    # contract mismatch without a marker file or an external side channel.
    boundary = time.time() + 3.0
    (metadata / "plugin.json").write_text(json.dumps({
        "schema": "SITINA_PLUGIN_V1",
        "name": "time-fail",
        "version": "1.0.0",
        "description": "time-boundary failure fixture",
        "permissions": ["shell"],
        "components": {"tools": ".sitina-plugin/tools.json"},
    }), encoding="utf-8")
    (metadata / "tools.json").write_text(json.dumps({
        "schema": "SITINA_TOOLS_V1",
        "tools": [{
            "name": "emit",
            "description": "emit the fixed time-boundary result",
            "permission": "shell",
            "command": [sys.executable, "runner.py"],
            "output_json": True,
            "expected_output": {"value": "PASS"},
            "input_schema": {"type": "object", "properties": {}},
            "output_schema": {
                "type": "object",
                "required": ["value"],
                "properties": {"value": {"type": "string"}},
            },
        }],
    }), encoding="utf-8")
    (source / "runner.py").write_text(
        "import json, time\n"
        f"BOUNDARY = {boundary!r}\n"
        "print(json.dumps({'value': 'PASS' if time.time() < BOUNDARY else 'FAIL'}))\n",
        encoding="utf-8",
    )
    return source, boundary


def _prepare_plugin(boundary, tmp_path: Path, backend: LoopBackend, manager: ExtensionManager):
    backend.create_task(
        task_id="prepare-c3b1",
        session_id="prepare-c3b1",
        task_kind="code_change",
        goal="prepare plugin",
        required_outcome_ids=("prepared",),
        artifact_ref="artifact-prepare-c3b1",
        environment_ref="environment-prepare-c3b1",
        capability_snapshot_id="prepare-c3b1",
    )
    source, boundary_at = _time_boundary_plugin(tmp_path / "source")
    prepared = manager.prepare_plugin_candidate(
        source,
        grants=("shell",),
        execution_context=manager.create_extension_preparation_context("prepare-c3b1", source),
    )
    backend.accept_input("prepare-c3b1", input_id="finish", kind=InputKind.CANCEL, body="done")
    backend.handle_next_input("prepare-c3b1")
    backend.cancel_safely("prepare-c3b1")
    return prepared, boundary_at


def _run_plugin(backend, manager, boundary, task_id: str, snapshot, workspace: Path):
    workspace.mkdir(parents=True, exist_ok=True)
    catalog = ToolCatalog(manager, workspace=workspace, approval_callback=lambda _request: True)
    catalog.bind_execution_snapshot(snapshot)
    public_name = "time-fail__emit"
    call = ProviderToolCall("emit", public_name, {})
    method_plan = catalog.consumer_method_plan(public_name, {}, task_id=task_id, call_id=call.call_id)
    adapter = LoopOperationAdapter(backend, task_id, workspace, mutation_allowed=True)
    runner = LoopTaskRunner(boundary, execution_snapshot=snapshot)
    adapter.bind_plugin_runtime(
        lambda bound_adapter, run_id, provider_call, permission, plan: runner._plugin_tool_call(
            bound_adapter,
            run_id,
            provider_call,
            permission,
            plan,
            authorizer=catalog.authorize_for_loop,
        )
    )
    result = adapter.tool_call(
        "plugin-run",
        call,
        lambda: catalog.execute(public_name, {}),
        permission="shell",
        method_plan=method_plan,
    )
    task = backend.get_task(task_id)
    operation_id = adapter.operation_ids[-1]
    operation = task.operations[operation_id]
    persisted = dict(backend.context_memory.read(str(operation.result_ref)))
    return result, task, operation_id, dict(persisted["result"]), dict(method_plan)


def test_time_boundary_plugin_failure_isolated_and_new_dispatch_blocked(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    backend = LoopBackend.open(boundary.state_root, keychain_backend=keys)
    manager = ExtensionManager(boundary.source_root, global_root=boundary.state_root / "extensions")
    authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
    try:
        prepared, boundary_at = _prepare_plugin(boundary, tmp_path, backend, manager)
        snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
        backend.create_task(
            task_id="publisher-c3b1", session_id="publisher-c3b1", task_kind="code_change",
            goal="publish plugin", required_outcome_ids=("published",),
            artifact_ref="artifact-publisher-c3b1", environment_ref="environment-c3b1",
            capability_snapshot_id=snapshot["snapshot_id"],
        )
        publisher = backend.get_task("publisher-c3b1")
        source = _task_binding(publisher)
        source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
        intent = authority.record_publication_intent(
            request_id="publish-time-fail-c3b1", slot="plugin:time-fail",
            candidate_id=prepared.candidate_id, snapshot=snapshot, source=source,
        )
        first_result, trial_task, trial_operation, first_raw, trial_plan = _run_plugin(
            backend, manager, boundary, "publisher-c3b1", snapshot, tmp_path / "trial-workspace",
        )
        assert first_result.status == "ok", first_result
        assert first_raw.get("program_status") == "PASS"
        trial_binding = dict(first_raw["execution_binding"])
        trial = authority.record_trial_fact(
            request_id="trial-time-fail-c3b1", candidate_id=prepared.candidate_id, snapshot=snapshot,
            task_binding=source, operation_id=trial_operation,
            method={key: trial_binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
            raw_result=first_raw, input_binding={"handled_input_seq": trial_task.handled_input_seq},
            artifact_binding={"artifact_ref": trial_task.artifact_ref},
        )
        authority.commit_publication({
            "request_id": "publish-time-fail-c3b1", "slot": "plugin:time-fail",
            "candidate_id": prepared.candidate_id, "snapshot_id": snapshot["snapshot_id"],
            "snapshot_hash": snapshot["snapshot_hash"], "location_binding": snapshot["location_binding"],
            "source": source, "trial_request_id": "trial-time-fail-c3b1", "trial_event_id": trial.event_id,
            "operation_id": trial_operation,
            "expected_previous_default": intent.payload["expected_previous_default"],
            "expected_stream_position": intent.payload["expected_stream_position"],
        })

        assert time.time() < boundary_at
        time.sleep(max(0.0, boundary_at - time.time() + 0.15))
        binding = _binding_resolver(boundary, boundary.state_root / "extensions")(backend, "plugin:time-fail")
        consumer, created = backend.admit_task(
            task_id="consumer-c3b1", session_id="consumer-c3b1", task_kind="code_change",
            goal="consume plugin", workspace_path=str(boundary.business_workspace),
            provider_profile="deepseek", authorization="cli", submission_id="consumer-c3b1",
            capability_selection="plugin:time-fail", capability_binding=binding,
            environment_ref="environment-c3b1", capability_snapshot_id=binding["snapshot_id"],
            provider_identity="fixture-provider", software_identity="fixture-software",
            config_identity="fixture-config",
        )
        assert created
        second_result, consumer_task, consumer_operation, second_raw, _ = _run_plugin(
            backend, manager, boundary, "consumer-c3b1", snapshot, tmp_path / "consumer-workspace",
        )
        assert second_result.status == "error"
        assert second_raw.get("program_status") == "FAIL"
        assert second_raw.get("completion_status") == "COMPLETED"
        assert second_raw.get("effect_settled") is True
        assert second_raw.get("completion_ref") and second_raw.get("completion_hash")
        assert "success_receipt" not in second_raw

        failure = backend.record_extension_publication_failure_from_task("consumer-c3b1", consumer_operation)
        assert failure["status"] == "isolated"
        events = authority._journal_events()
        reconciled = [event for event in events if event.event_type == "extension.publication-failure-reconciled"]
        assert len(reconciled) == 1
        assert reconciled[0].payload["isolation"]["state"] == "ISOLATED"
        assert reconciled[0].payload["failed_publication"]["publication_id"] == binding["publication_id"]
        assert reconciled[0].payload["default_action_obligation"]["state"] == "PENDING"

        with pytest.raises(ExtensionAuthorityError, match="no active default|unavailable"):
            authority.resolve_default("plugin:time-fail")
        replay = backend.record_extension_publication_failure_from_task("consumer-c3b1", consumer_operation)
        assert replay["replayed"] is True
        assert len([event for event in authority._journal_events() if event.event_type == "extension.publication-failure-reconciled"]) == 1

        # A fresh operation using the old admitted binding is stopped before
        # the Plugin executor can dispatch another physical effect.
        blocked_workspace = tmp_path / "blocked-workspace"
        blocked_workspace.mkdir()
        catalog = ToolCatalog(manager, workspace=blocked_workspace, approval_callback=lambda _request: True)
        catalog.bind_execution_snapshot(snapshot)
        adapter = LoopOperationAdapter(backend, "consumer-c3b1", blocked_workspace, mutation_allowed=True)
        blocked_runner = LoopTaskRunner(boundary, execution_snapshot=snapshot)
        adapter.bind_plugin_runtime(
            lambda bound_adapter, run_id, provider_call, permission, method: blocked_runner._plugin_tool_call(
                bound_adapter, run_id, provider_call, permission, method,
                authorizer=catalog.authorize_for_loop,
            )
        )
        call = ProviderToolCall("blocked", "time-fail__emit", {})
        plan = catalog.consumer_method_plan(call.name, {}, task_id="consumer-c3b1", call_id=call.call_id)
        with pytest.raises(Exception, match="isolated|unavailable|publication"):
            adapter.tool_call("blocked-run", call, lambda: catalog.execute(call.name, {}), permission="shell", method_plan=plan)
    finally:
        backend.close()
