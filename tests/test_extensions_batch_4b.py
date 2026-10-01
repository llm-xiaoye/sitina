from __future__ import annotations

import json
from pathlib import Path

import pytest

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.tools import ToolCatalog, ToolRuntimeError
from sitina.loop import LoopBackend
from sitina.loop.task_runtime import LoopOperationAdapter
from sitina.runners.provider import ProviderToolCall
from sitina.security.macos_keychain import MemoryKeychainBackend


def test_bound_skill_consumer_records_backend_verified_trial_and_retries_idempotently(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "config").mkdir(parents=True)
    extension_root = tmp_path / "extensions"
    source = tmp_path / "source" / "count-fruit"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text(
        "---\nname: count-fruit\ndescription: Read the selected fixture.\n---\nUse the selected resource.\n",
        encoding="utf-8",
    )
    (source / "references").mkdir()
    (source / "references" / "facts.md").write_text("candidate-resource\n", encoding="utf-8")
    with LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend()) as backend:
        manager = ExtensionManager(home, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=tmp_path / "state", backend=backend)
        backend.create_task(
            task_id="prepare", session_id="prepare-session", task_kind="readonly", goal="prepare",
            required_outcome_ids=("prepared",), artifact_ref="artifact-prepare",
            environment_ref="environment-prepare", capability_snapshot_id="prepare-capability",
        )
        prepared = manager.prepare_skill_candidate(
            source, execution_context=manager.create_extension_preparation_context("prepare", source)
        )
        snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
        backend.create_task(
            task_id="consumer", session_id="consumer-session", task_kind="readonly", goal="consume",
            required_outcome_ids=("consumed",), artifact_ref="artifact-consumer",
            environment_ref="environment-consumer", capability_snapshot_id=snapshot["snapshot_id"],
        )
        catalog = ToolCatalog(manager, workspace=tmp_path)
        catalog.bind_execution_snapshot(snapshot)
        adapter = LoopOperationAdapter(backend, "consumer", tmp_path, mutation_allowed=False)
        call = ProviderToolCall("read-resource", "sitina_read_skill_resource", {
            "skill": "count-fruit", "path": "references/facts.md",
        })
        catalog.bind_loop_consumer(
            backend=backend, task_id="consumer", snapshot_id=snapshot["snapshot_id"], call_id=call.call_id,
        )
        try:
            adapter.tool_call(
                "consumer-run", call, lambda: catalog.execute(call.name, call.arguments), permission="read",
                method_plan=catalog.consumer_method_plan(
                    call.name, call.arguments, task_id="consumer", call_id=call.call_id,
                ),
            )
        finally:
            catalog.clear_loop_consumer()
        task = backend.get_task("consumer")
        operation_id = adapter.operation_ids[0]
        operation = task.operations[operation_id]
        persisted = dict(backend.context_memory.read(str(operation.result_ref)))
        raw_result = dict(persisted["result"])
        binding = dict(raw_result["execution_binding"])
        task_binding = {
            field: getattr(task, field)
            for field in (
                "task_id", "session_id", "run_instance_id", "execution_epoch",
                "goal_version", "acceptance_version", "received_input_seq",
                "handled_input_seq", "artifact_ref",
            )
        }
        event = authority.record_trial_fact(
            request_id="trial-consumer-read-1", candidate_id=prepared.candidate_id,
            snapshot=snapshot, task_binding=task_binding, operation_id=operation_id,
            method={key: binding[key] for key in (
                "method_schema", "method_version", "method_id", "tool_name", "handler",
            )}, raw_result=raw_result,
            input_binding={"handled_input_seq": task.handled_input_seq},
            artifact_binding={"artifact_ref": task.artifact_ref},
        )
        retry = authority.record_trial_fact(
            request_id="trial-consumer-read-1", candidate_id=prepared.candidate_id,
            snapshot=snapshot, task_binding=task_binding, operation_id=operation_id,
            method={key: binding[key] for key in (
                "method_schema", "method_version", "method_id", "tool_name", "handler",
            )}, raw_result=raw_result,
            input_binding={"handled_input_seq": task.handled_input_seq},
            artifact_binding={"artifact_ref": task.artifact_ref},
        )
        assert event.event_id == retry.event_id
        assert event.event_type == "extension.trial-recorded"
        assert event.payload["applicability"] == "CURRENT_TASK_INPUT"
        assert event.payload["consumer_receipt"]["reference"] == binding["backend_receipt_ref"]


def test_bound_printf_plugin_handler_is_rejected_without_a_fixed_executor(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "config").mkdir(parents=True)
    extension_root = tmp_path / "extensions"
    source = tmp_path / "source" / "printf-plugin"
    metadata = source / ".sitina-plugin"
    metadata.mkdir(parents=True)
    (metadata / "plugin.json").write_text(json.dumps({
        "schema": "SITINA_PLUGIN_V1", "name": "printf-plugin", "version": "1.0.0",
        "description": "fixed command fixture", "permissions": ["shell"],
        "components": {"tools": ".sitina-plugin/tools.json"},
    }), encoding="utf-8")
    (metadata / "tools.json").write_text(json.dumps({
        "schema": "SITINA_TOOLS_V1", "tools": [{
            "name": "emit", "description": "emit fixed output", "permission": "shell",
            "command": ["/usr/bin/printf", "candidate-command-output"], "output_json": False,
            "input_schema": {"type": "object", "properties": {}},
        }],
    }), encoding="utf-8")
    with LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend()) as backend:
        manager = ExtensionManager(home, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=tmp_path / "state", backend=backend)
        backend.create_task(
            task_id="prepare", session_id="prepare-session", task_kind="readonly", goal="prepare",
            required_outcome_ids=("prepared",), artifact_ref="artifact-prepare",
            environment_ref="environment-prepare", capability_snapshot_id="prepare-capability",
        )
        prepared = manager.prepare_plugin_candidate(
            source, grants=("shell",),
            execution_context=manager.create_extension_preparation_context("prepare", source),
        )
        snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
        consumer_workspace = tmp_path / "consumer-workspace"
        consumer_workspace.mkdir()
        catalog = ToolCatalog(manager, workspace=consumer_workspace, approval_callback=lambda _request: True)
        with pytest.raises(ToolRuntimeError, match="unsupported plugin command executor"):
            catalog.bind_execution_snapshot(snapshot)
