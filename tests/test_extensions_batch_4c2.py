from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime
from sitina.loop import InputKind, LoopBackend
from sitina.loop.task_runtime import LoopTaskRunner
from sitina.runners.provider import ProviderProfile, ProviderToolCall, ScriptedMockToolClient
from sitina.security.macos_keychain import MemoryKeychainBackend

from test_loop_batch_1b_runtime import (
    boundary_fixture,
    review_v2_document,
    reviewer_evidence_turn,
    turn,
)


def _objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _objects(child)


def _publication_context(messages):
    for message in messages:
        if message.get("role") != "system":
            continue
        try:
            document = json.loads(message.get("content", ""))
        except (TypeError, ValueError):
            continue
        for value in _objects(document):
            context = value.get("publication")
            if isinstance(context, dict) and all(
                context.get(key) for key in ("slot_id", "candidate_id", "request_id")
            ):
                return dict(context)
    for message in messages:
        match = re.search(
            r"slot_id=([^,\s]+),\s*candidate_id=([^,\s]+),.*?request_id=([A-Za-z0-9._:-]+)",
            str(message.get("content") or ""),
            flags=re.DOTALL,
        )
        if match:
            return {
                "slot_id": match.group(1),
                "candidate_id": match.group(2),
                "request_id": match.group(3).rstrip("."),
            }
    raise AssertionError("normal main messages did not expose publication context")


def _trial_id(messages):
    message = next(
        (
            item
            for item in reversed(messages)
            if item.get("role") == "tool" and item.get("tool_call_id") == "read-resource"
        ),
        None,
    )
    assert message is not None, "main provider did not receive the resource result"
    envelope = json.loads(message["content"])
    result = envelope.get("result") if envelope.get("schema") == "SITINA_UNTRUSTED_TOOL_DATA_V1" else envelope
    assert isinstance(result, dict)
    readable = str(result.get("readable_text") or "")
    match = re.search(r'"operation_id"\s*:\s*"([^"\\]+)"', readable)
    assert match, "resource receipt did not expose the persisted trial operation id"
    return match.group(1)


class _PublicationProvider(ScriptedMockToolClient):
    def __init__(self, *, candidate_id: str, request_id: str):
        super().__init__([])
        self.candidate_id = candidate_id
        self.request_id = request_id
        self.stage = 0
        self.tool_sets = []

    def complete_tool_turn(self, _profile, *, messages, tools=(), **_kwargs):
        self.received_messages.append([dict(item) for item in messages])
        self.tool_sets.append([str((item.get("function") or item).get("name") or "") for item in tools])
        stage = self.stage
        self.stage += 1
        if stage == 0:
            return turn(
                "",
                ProviderToolCall(
                    "read-resource",
                    "sitina_read_skill_resource",
                    {"skill": "count-fruit", "path": "references/facts.md"},
                ),
            )
        if stage == 1:
            context = _publication_context(messages)
            operation_id = _trial_id(messages)
            return turn(
                "",
                ProviderToolCall(
                    "publish-first",
                    "sitina_publish_extension",
                    {
                        "slot_id": context["slot_id"],
                        "candidate_id": context["candidate_id"],
                        "trial_operation_id": operation_id,
                        "request_id": context["request_id"],
                    },
                ),
            )
        if stage == 2:
            return turn(
                "",
                ProviderToolCall(
                    "write-result",
                    "sitina_write_file",
                    {"path": "result.txt", "content": "publication-fixture-complete\n"},
                ),
            )
        return turn("The admitted candidate was trialed and published; result.txt is saved.")


class _PublicationReviewer(ScriptedMockToolClient):
    def __init__(self):
        super().__init__([])
        self.tool_sets = []
        self.did_read = False

    def complete_tool_turn(self, _profile, *, messages, tools=(), **_kwargs):
        self.received_messages.append([dict(item) for item in messages])
        self.tool_sets.append([str((item.get("function") or item).get("name") or "") for item in tools])
        if not self.did_read:
            self.did_read = True
            return reviewer_evidence_turn(messages, call_prefix="publication-review")
        return turn(
            json.dumps(
                review_v2_document(
                    messages,
                    verdict="PASS",
                    reason="Read the persisted artifact and program-check evidence.",
                )
            )
        )


def test_main_runtime_publication_tool_reaches_authority_from_real_provider_calls(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    extension_root = boundary.state_root / "extensions"
    source = tmp_path / "source" / "count-fruit"
    source.mkdir(parents=True)
    (source / "SKILL.md").write_text(
        "---\nname: count-fruit\ndescription: Read the publication fixture.\n---\n"
        "Read references/facts.md through sitina_read_skill_resource.\n",
        encoding="utf-8",
    )
    (source / "references").mkdir()
    (source / "references" / "facts.md").write_text("C2A apples=23 pears=41\n", encoding="utf-8")

    with LoopBackend.open(boundary.state_root, keychain_backend=keys) as backend:
        manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=boundary.state_root, backend=backend)
        backend.create_task(
            task_id="prepare-c2a",
            session_id="prepare-c2a",
            task_kind="code_change",
            goal="Prepare a publication candidate",
            required_outcome_ids=("prepared",),
            artifact_ref="fixture-preparation",
            environment_ref="fixture-environment",
            capability_snapshot_id="fixture-preparation-snapshot",
        )
        prepared = manager.prepare_skill_candidate(
            source,
            execution_context=manager.create_extension_preparation_context("prepare-c2a", source),
        )
        snapshot = authority.build_execution_snapshot(prepared.candidate_id).as_dict()
        backend.accept_input(
            "prepare-c2a",
            input_id="prepare-c2a-complete",
            kind=InputKind.CANCEL,
            body="The bounded preparation is complete.",
        )
        backend.handle_next_input("prepare-c2a")
        backend.cancel_safely("prepare-c2a")

    clients = []

    def runtime_factory(role, adapter):
        runtime_manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        runtime_manager.bind_shared_authority(state_root=boundary.state_root, backend=adapter.backend)
        client = (
            _PublicationReviewer()
            if role == "reviewer"
            else _PublicationProvider(candidate_id=prepared.candidate_id, request_id="publish-runtime-1")
        )
        clients.append((role, client))
        return AutonomousRuntime(
            boundary.state_root / "provider-home",
            manager=runtime_manager,
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            approval_callback=lambda _request: role == "main",
            enforce_write_boundary=True,
            strict_workspace=True,
            max_turns=None,
        )

    runner = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=runtime_factory,
        execution_snapshot=snapshot,
        publication_context={
            "slot_id": "skill:count-fruit",
            "candidate_id": prepared.candidate_id,
            "request_id": "publish-runtime-1",
        },
    )
    result = runner.run(
        task_id="publisher-c2a",
        task_kind="code_change",
        goal="Read the admitted fruit candidate, publish it, and save result.txt.",
        check_command=(
            sys.executable,
            "-c",
            "from pathlib import Path; assert Path('result.txt').read_text() == 'publication-fixture-complete\\n'",
        ),
    )
    assert result["status"] == "succeeded", result

    with LoopBackend.open(boundary.state_root, keychain_backend=keys) as backend:
        final_manager = ExtensionManager(boundary.source_root, global_root=extension_root)
        final_authority = final_manager.bind_shared_authority(
            state_root=boundary.state_root, backend=backend
        )
        events = list(final_authority._journal_events())
        publications = [event for event in events if event.event_type == "extension.publication-committed"]
        assert len(publications) == 1
        assert publications[0].payload["published"]["candidate_id"] == prepared.candidate_id

    main_clients = [client for role, client in clients if role == "main"]
    reviewer_clients = [client for role, client in clients if role == "reviewer"]
    assert main_clients and any("sitina_publish_extension" in tools for tools in main_clients[0].tool_sets)
    assert reviewer_clients and all(
        "sitina_publish_extension" not in tools for tools in reviewer_clients[0].tool_sets
    )
