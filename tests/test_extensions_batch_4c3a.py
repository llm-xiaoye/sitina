from __future__ import annotations

import time

import pytest

from sitina.extensions.authority import ExtensionAuthority
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.loop import LoopBackend
from sitina.loop.host import LoopHost
from sitina.loop.task_runtime import LoopTaskRunner
from sitina.runners.provider import ProviderProfile, ScriptedMockToolClient
from sitina.security.macos_keychain import MemoryKeychainBackend

from test_extensions_batch_4c2b import (
    _MainProvider,
    _prepare_and_publish,
)
from test_loop_batch_1b_runtime import boundary_fixture, reviewer_evidence_turn, review_v2_document, turn


class _Reviewer(ScriptedMockToolClient):
    def __init__(self):
        super().__init__([])
        self.read = False

    def complete_tool_turn(self, _profile, *, messages=(), **_kwargs):
        self.received_messages.append([dict(item) for item in messages])
        if not self.read:
            self.read = True
            return reviewer_evidence_turn(messages, call_prefix="c3a-review")
        return turn(review_v2_document(messages, verdict="PASS", reason="Bound capability evidence was read."))


def _binding_resolver(boundary, extension_root):
    def resolve(backend, slot):
        manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
        resolution = authority.resolve_default(slot)
        proof = backend.extension_existing_object_proof(resolution["projection_ref"])
        return {
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
                "verified_frontier_transaction_hash": backend.store.journal._position_hash.get(
                    proof.verified_frontier_position
                ),
                "object_reference_manifest_hash": proof.object_reference_manifest_hash,
            },
        }

    return resolve


@pytest.mark.parametrize("lost_return", [False, True])
def test_real_host_successful_skill_consumer_auto_settles_publication_check(tmp_path, monkeypatch, lost_return):
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    _prepared, _snapshot = _prepare_and_publish(boundary, keys, tmp_path)
    extension_root = boundary.state_root / "extensions"
    clients = []
    append_original = ExtensionAuthority._append_fact
    lost_return_injected = False

    if lost_return:
        def append_with_lost_return(authority, *args, **kwargs):
            nonlocal lost_return_injected
            if kwargs.get("event_type") == "extension.publication-check-recorded" and not lost_return_injected:
                lost_return_injected = True
                append_original(authority, *args, **kwargs)
                raise OSError("simulated lost check return after commit")
            return append_original(authority, *args, **kwargs)

        monkeypatch.setattr(ExtensionAuthority, "_append_fact", append_with_lost_return)

    def runner_executor(backend, task_id, _task):
        projection = backend.get_task(task_id)
        descriptor = backend.context_memory.read(
            projection.descriptor_ref, expected_hash=projection.descriptor_hash
        )
        manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
        execution_snapshot = authority.verify_capability_binding(descriptor["capability_binding"])

        def runtime_factory(role, adapter):
            runtime_manager = ExtensionManager(boundary.source_root, global_root=extension_root)
            runtime_manager.bind_shared_authority(state_root=boundary.state_root, backend=adapter.backend)
            client = _Reviewer() if role == "reviewer" else _MainProvider()
            clients.append((role, client))
            return AutonomousRuntime(
                boundary.state_root / "provider-home",
                manager=runtime_manager,
                client=client,
                profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
                workspace=boundary.business_workspace,
                approval_callback=lambda _request: False,
                enforce_write_boundary=True,
                strict_workspace=True,
                max_turns=None,
            )

        runner = LoopTaskRunner(
            boundary,
            provider_profile="deepseek",
            runtime_factory=runtime_factory,
            execution_snapshot=execution_snapshot,
        )
        runner.run_existing(
            backend,
            task_id=task_id,
            task_kind=projection.task_kind,
            baseline_snapshot=(descriptor.get("workspace") or {}).get("content_snapshot", {}),
        )

    host = LoopHost(
        boundary.state_root,
        keychain_backend=keys,
        backend_factory=lambda root, **kwargs: LoopBackend.open(root, **kwargs),
        runner_executor=runner_executor,
        capability_resolver=_binding_resolver(boundary, extension_root),
        authorized_workspace_root=boundary.runtime_root,
        descriptor_context={
            "provider_identity": "fixture-provider",
            "environment_ref": "fixture-environment",
            "capability_snapshot_id": "fixture-host-capabilities",
            "software_identity": "fixture-software",
            "config_identity": "fixture-config",
        },
    ).start()
    try:
        response = host._handle_command({
            "command": "submit",
            "task_id": "normal-consumer-c3a",
            "submission_id": "normal-consumer-c3a",
            "session_id": "normal-consumer-c3a",
            "task_kind": "readonly",
            "goal": "Consume the admitted capability.",
            "workspace": str(boundary.business_workspace),
            "provider_profile": "deepseek",
            "authorization": "cli",
            "capability_selection": "skill:count-fruit",
            "provider_identity": "ignored-host-observation",
            "environment_ref": "ignored-host-observation",
            "capability_snapshot_id": "ignored-host-observation",
            "software_identity": "ignored-host-observation",
            "config_identity": "ignored-host-observation",
        })
        assert response["disposition"] == "created"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if host.backend.get_task("normal-consumer-c3a").status.value != "RUNNABLE":
                break
            time.sleep(0.05)
        host.begin_drain()
        assert host.wait_for_quiescence(20)
        events = list(
            ExtensionManager(boundary.source_root, global_root=extension_root)
            .bind_shared_authority(state_root=boundary.state_root, backend=host.backend)
            ._journal_events()
        )
        checks = [event for event in events if event.event_type == "extension.publication-check-recorded"]
        assert len(checks) == 1, {
            "errors": host.worker_errors,
            "task": host.backend.get_task("normal-consumer-c3a").as_dict(),
        }
        assert checks[0].payload["state"] == "PASSED"
        assert checks[0].payload["required_publication_id"].startswith("publication-")
        assert checks[0].payload["observed_publication_id"] == checks[0].payload["required_publication_id"]
        assert any(role == "main" for role, _client in clients)
        if lost_return:
            assert lost_return_injected is True
            assert not any("publication-check deferred" in error for error in host.worker_errors)
        frontier_before_replay = len(events)
        replay = host.backend.record_extension_publication_check_from_task("normal-consumer-c3a")
        events_after_replay = list(
            ExtensionManager(boundary.source_root, global_root=extension_root)
            .bind_shared_authority(state_root=boundary.state_root, backend=host.backend)
            ._journal_events()
        )
        assert replay["status"] == "passed" and replay["replayed"] is True
        assert len(events_after_replay) == frontier_before_replay
    finally:
        host.close()
