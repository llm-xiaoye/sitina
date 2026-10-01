from __future__ import annotations

import json
import time
from pathlib import Path

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.loop import InputKind, LoopBackend
from sitina.loop.host import LoopHost
from sitina.loop.task_runtime import LoopTaskRunner
from sitina.runners.provider import ProviderProfile, ProviderToolCall, ScriptedMockToolClient
from sitina.security.macos_keychain import MemoryKeychainBackend

from test_extensions_batch_4c import _run_skill_trial, _skill, _task_binding
from test_loop_batch_1b_runtime import boundary_fixture, reviewer_evidence_turn, review_v2_document, turn


def _prepare_and_publish(boundary, keys, tmp_path: Path):
    extension_root = boundary.state_root / "extensions"
    backend = LoopBackend.open(boundary.state_root, keychain_backend=keys)
    manager = ExtensionManager(boundary.source_root, global_root=extension_root)
    authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
    backend.create_task(
        task_id="prepare-c2b",
        session_id="prepare-c2b",
        task_kind="code_change",
        goal="Prepare the admitted capability",
        required_outcome_ids=("prepared",),
        artifact_ref="fixture-preparation",
        environment_ref="fixture-environment",
        capability_snapshot_id="fixture-preparation-snapshot",
    )
    source = _skill(tmp_path / "source")
    prepared = manager.prepare_skill_candidate(
        source,
        execution_context=manager.create_extension_preparation_context("prepare-c2b", source),
    )
    backend.accept_input("prepare-c2b", input_id="finish-preparation", kind=InputKind.CANCEL, body="done")
    backend.handle_next_input("prepare-c2b")
    backend.cancel_safely("prepare-c2b")
    snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
    backend.create_task(
        task_id="publisher",
        session_id="publisher-c2b",
        task_kind="code_change",
        goal="Publish the prepared capability",
        required_outcome_ids=("published",),
        artifact_ref="fixture-publisher",
        environment_ref="fixture-environment",
        capability_snapshot_id=snapshot["snapshot_id"],
    )
    task = backend.get_task("publisher")
    source_binding = _task_binding(task)
    source_binding.update({"actor_role": "main", "publication_scope": "extension-root", "write_authorized": True})
    request_id = "publish-c2b-a"
    intent = authority.record_publication_intent(
        request_id=request_id,
        slot="skill:count-fruit",
        candidate_id=prepared.candidate_id,
        snapshot=snapshot,
        source=source_binding,
    )
    task, operation_id, raw_result, binding = _run_skill_trial(
        backend, manager, snapshot, tmp_path / "trial-workspace"
    )
    trial = authority.record_trial_fact(
        request_id="trial-c2b-a",
        candidate_id=prepared.candidate_id,
        snapshot=snapshot,
        task_binding=source_binding,
        operation_id=operation_id,
        method={key: binding[key] for key in ("method_schema", "method_version", "method_id", "tool_name", "handler")},
        raw_result=raw_result,
        input_binding={"handled_input_seq": task.handled_input_seq},
        artifact_binding={"artifact_ref": task.artifact_ref},
    )
    authority.commit_publication({
        "request_id": request_id,
        "slot": "skill:count-fruit",
        "candidate_id": prepared.candidate_id,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_hash": snapshot["snapshot_hash"],
        "location_binding": snapshot["location_binding"],
        "source": source_binding,
        "trial_request_id": "trial-c2b-a",
        "trial_event_id": trial.event_id,
        "operation_id": operation_id,
        "expected_previous_default": intent.payload["expected_previous_default"],
        "expected_stream_position": intent.payload["expected_stream_position"],
    })
    backend.close()
    return prepared, snapshot


class _MainProvider(ScriptedMockToolClient):
    def __init__(self):
        super().__init__([])
        self.stage = 0

    def complete_tool_turn(self, _profile, *, messages=(), **_kwargs):
        self.received_messages.append([dict(item) for item in messages])
        if self.stage == 0:
            self.stage += 1
            return turn(
                "",
                ProviderToolCall(
                    "read-capability",
                    "sitina_read_skill_resource",
                    {"skill": "count-fruit", "path": "references/facts.md"},
                ),
            )
        self.stage += 1
        return turn("The admitted capability was consumed successfully.")


class _Reviewer(ScriptedMockToolClient):
    def __init__(self):
        super().__init__([])
        self.read = False

    def complete_tool_turn(self, _profile, *, messages, **_kwargs):
        self.received_messages.append([dict(item) for item in messages])
        if not self.read:
            self.read = True
            return reviewer_evidence_turn(messages, call_prefix="c2b-review")
        return turn(json.dumps(review_v2_document(messages, verdict="PASS", reason="Bound capability evidence was read.")))


def test_normal_host_admission_binds_one_published_default_and_consumes_it(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    prepared, snapshot = _prepare_and_publish(boundary, keys, tmp_path)
    extension_root = boundary.state_root / "extensions"
    resolver_calls: list[str] = []
    clients = []

    def resolve_capability(backend, slot):
        resolver_calls.append(slot)
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

    def runner_executor(backend, task_id, _task):
        projection = backend.get_task(task_id)
        descriptor = backend.context_memory.read(projection.descriptor_ref, expected_hash=projection.descriptor_hash)
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
        capability_resolver=resolve_capability,
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
        payload = {
            "command": "submit",
            "task_id": "normal-consumer-c2b",
            "submission_id": "normal-consumer-c2b",
            "session_id": "normal-consumer-c2b",
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
        }
        first = host._handle_command(payload)
        duplicate = host._handle_command(payload)
        assert first["status"] == "accepted" and first["disposition"] == "created"
        assert duplicate["status"] == "accepted" and duplicate["disposition"] == "existing"
        assert resolver_calls == ["skill:count-fruit"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if host.backend.get_task("normal-consumer-c2b").status.value != "RUNNABLE":
                break
            time.sleep(0.05)
        host.begin_drain()
        assert host.wait_for_quiescence(20)
        task = host.backend.get_task("normal-consumer-c2b")
        descriptor = host.backend.context_memory.read(task.descriptor_ref, expected_hash=task.descriptor_hash)
        binding = descriptor["capability_binding"]
        assert binding["publication_id"]
        assert binding["snapshot_id"] == snapshot["snapshot_id"]
        assert binding["candidate_id"] == prepared.candidate_id
        assert task.capability_snapshot_id == snapshot["snapshot_id"]
        assert task.status.value == "SUCCEEDED", {
            "errors": host.worker_errors,
            "clients": [role for role, _client in clients],
            "active": host.health(),
            "task": task.as_dict(),
        }
        assert any(role == "main" for role, _client in clients)
    finally:
        host.close()
