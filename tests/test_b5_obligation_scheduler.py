from __future__ import annotations

import time
from pathlib import Path

import pytest

from sitina.extensions.authority import ExtensionAuthority
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.tools import ToolCatalog
from sitina.loop import InputKind, LoopBackend
from sitina.loop.host import LoopHost
from sitina.loop.operations import BusinessModificationLane
from sitina.loop.task_runtime import LoopOperationAdapter, LoopTaskRunner
from sitina.runners.provider import ProviderToolCall
from sitina.security.macos_keychain import MemoryKeychainBackend
from sitina.loop.model import OperationRejected

from test_extensions_batch_4c import _task_binding
from test_extensions_batch_4c3a import _binding_resolver
from test_extensions_batch_4c3b1 import _prepare_plugin, _run_plugin, _time_boundary_plugin
from test_loop_batch_1b_runtime import boundary_fixture


def _publish_time_plugin(boundary, tmp_path: Path, keys: MemoryKeychainBackend):
    extension_root = boundary.state_root / "extensions"
    backend = LoopBackend.open(boundary.state_root, keychain_backend=keys)
    manager = ExtensionManager(boundary.source_root, global_root=extension_root)
    authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
    prepared, boundary_at = _prepare_plugin(boundary, tmp_path, backend, manager)
    snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
    backend.create_task(
        task_id="publisher-b5",
        session_id="publisher-b5",
        task_kind="code_change",
        goal="publish plugin",
        required_outcome_ids=("published",),
        artifact_ref="artifact-publisher-b5",
        environment_ref="environment-b5",
        capability_snapshot_id=snapshot["snapshot_id"],
    )
    publisher = backend.get_task("publisher-b5")
    source = _task_binding(publisher)
    source.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
    intent = authority.record_publication_intent(
        request_id="publish-time-fail-b5",
        slot="plugin:time-fail",
        candidate_id=prepared.candidate_id,
        snapshot=snapshot,
        source=source,
    )
    workspace = tmp_path / "trial-workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    catalog = ToolCatalog(manager, workspace=workspace, approval_callback=lambda _request: True)
    catalog.bind_execution_snapshot(snapshot)
    call = ProviderToolCall("emit", "time-fail__emit", {})
    method_plan = catalog.consumer_method_plan("time-fail__emit", {}, task_id="publisher-b5", call_id=call.call_id)
    adapter = LoopOperationAdapter(backend, "publisher-b5", workspace, mutation_allowed=True)
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
        "plugin-trial",
        call,
        lambda: catalog.execute("time-fail__emit", {}),
        permission="shell",
        method_plan=method_plan,
    )
    task = backend.get_task("publisher-b5")
    operation_id = adapter.operation_ids[-1]
    operation = task.operations[operation_id]
    raw = dict(backend.context_memory.read(str(operation.result_ref)))['result']
    binding = dict(raw["execution_binding"])
    trial = authority.record_trial_fact(
        request_id="trial-time-fail-b5",
        candidate_id=prepared.candidate_id,
        snapshot=snapshot,
        task_binding=source,
        operation_id=operation_id,
        method={key: binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
        raw_result=raw,
        input_binding={"handled_input_seq": task.handled_input_seq},
        artifact_binding={"artifact_ref": task.artifact_ref},
    )
    authority.commit_publication({
        "request_id": "publish-time-fail-b5",
        "slot": "plugin:time-fail",
        "candidate_id": prepared.candidate_id,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_hash": snapshot["snapshot_hash"],
        "location_binding": snapshot["location_binding"],
        "source": source,
        "trial_request_id": "trial-time-fail-b5",
        "trial_event_id": trial.event_id,
        "operation_id": operation_id,
        "expected_previous_default": intent.payload["expected_previous_default"],
        "expected_stream_position": intent.payload["expected_stream_position"],
    })
    backend.accept_input("publisher-b5", input_id="finish-publisher-b5", kind=InputKind.CANCEL, body="done")
    backend.handle_next_input("publisher-b5")
    backend.cancel_safely("publisher-b5")
    backend.close()
    return prepared, snapshot, boundary_at


def test_lane_acquire_has_finite_background_timeout() -> None:
    lane = BusinessModificationLane()
    lane.acquire("owner-a", "operation-a")
    try:
        started = time.monotonic()
        with pytest.raises(OperationRejected, match="timed out"):
            lane.acquire("owner-b", "operation-b", timeout=0.02)
        assert time.monotonic() - started < 0.5
    finally:
        lane.release("owner-a", "operation-a")


def test_pending_scan_only_authorizes_reconciled_pending_actions(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    backend = LoopBackend.open(boundary.state_root, keychain_backend=MemoryKeychainBackend())

    class _ProjectionAuthority:
        def load_projection(self):
            return {
                "obligations": {
                    "pending-action": {
                        "obligation_id": "pending-action",
                        "type": "CONDITIONAL_DEFAULT_ACTION",
                        "state": "PENDING",
                        "stream_version": 2,
                    },
                    "review-action": {
                        "obligation_id": "review-action",
                        "type": "CONDITIONAL_DEFAULT_ACTION",
                        "state": "PENDING_REVIEW",
                        "stream_version": 1,
                    },
                    "missing-state": {
                        "obligation_id": "missing-state",
                        "type": "CONDITIONAL_DEFAULT_ACTION",
                        "stream_version": 3,
                    },
                    "empty-state": {
                        "obligation_id": "empty-state",
                        "type": "CONDITIONAL_DEFAULT_ACTION",
                        "state": "",
                        "stream_version": 4,
                    },
                }
            }

    backend._extension_authority = _ProjectionAuthority()
    try:
        pending = backend.pending_publication_failure_obligations()
        assert [item["obligation_id"] for item in pending] == ["pending-action"]
    finally:
        backend.close()


def test_native_host_failure_wakes_scheduler_and_actions_obligation(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    prepared, snapshot, boundary_at = _publish_time_plugin(boundary, tmp_path, keys)
    extension_root = boundary.state_root / "extensions"
    def runner_executor(backend, task_id, _task):
        manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
        _run_plugin(
            backend,
            manager,
            boundary,
            task_id,
            snapshot,
            tmp_path / "consumer-workspace",
        )

    host = LoopHost(
        boundary.state_root,
        keychain_backend=keys,
        backend_factory=lambda root, **kwargs: LoopBackend.open(root, **kwargs),
        runner_executor=runner_executor,
        capability_resolver=_binding_resolver(boundary, extension_root),
        authorized_workspace_root=boundary.runtime_root,
        publication_obligation_lane_timeout=0.05,
        publication_obligation_poll_interval=0.02,
        descriptor_context={
            "provider_identity": "fixture-provider",
            "environment_ref": "fixture-environment",
            "capability_snapshot_id": "fixture-host-capabilities",
            "software_identity": "fixture-software",
            "config_identity": "fixture-config",
        },
    ).start()
    try:
        while time.time() < boundary_at:
            time.sleep(0.02)
        response = host._handle_command({
            "command": "submit",
            "task_id": "consumer-b5",
            "submission_id": "consumer-b5",
            "session_id": "consumer-b5",
            "task_kind": "readonly",
            "goal": "Consume the admitted plugin.",
            "workspace": str(boundary.business_workspace),
            "provider_profile": "deepseek",
            "authorization": "cli",
            "capability_selection": "plugin:time-fail",
            "provider_identity": "ignored",
            "environment_ref": "ignored",
            "capability_snapshot_id": "ignored",
            "software_identity": "ignored",
            "config_identity": "ignored",
        })
        assert response["disposition"] == "created"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            events = ExtensionManager(boundary.source_root, global_root=extension_root).bind_shared_authority(
                state_root=boundary.state_root, backend=host.backend
            )._journal_events()
            if any(event.event_type == "extension.publication-failure-actioned" for event in events):
                break
            time.sleep(0.05)
        authority = ExtensionManager(boundary.source_root, global_root=extension_root).bind_shared_authority(
            state_root=boundary.state_root, backend=host.backend
        )
        events = authority._journal_events()
        reconciled = [event for event in events if event.event_type == "extension.publication-failure-reconciled"]
        actions = [event for event in events if event.event_type in {"extension.publication-failure-actioned", "extension.publication-committed"} and (event.event_type != "extension.publication-committed" or event.payload.get("failure_action") )]
        assert len(reconciled) == 1, {
            "errors": host.worker_errors,
            "obligation_errors": host.health(),
            "task_status": host.backend.get_task("consumer-b5").status.value,
            "task_operations": list(host.backend.get_task("consumer-b5").operations),
            "event_types": [event.event_type for event in events if "publication" in event.event_type],
        }
        assert reconciled[0].payload["default_action_obligation"]["state"] == "PENDING"
        assert actions, {"errors": host.worker_errors, "health": host.health()}
        assert host.backend.get_task("consumer-b5").task_id == "consumer-b5"
    finally:
        host.begin_drain()
        host.wait_for_quiescence(10)
        host.close()
