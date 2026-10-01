from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from sitina.extensions.authority import (
    CandidatePreparationError,
    ExtensionAuthorityError,
)
from sitina.extensions.manager import ExtensionInstallError, ExtensionManager
from sitina.extensions.spec import ExtensionSpecError
from sitina.extensions.spec import load_skill
from sitina.loop import LoopBackend
from sitina.loop import InputKind, OperationMode
from sitina.security.macos_keychain import MemoryKeychainBackend


def _skill(root: Path, *, name: str = "x", description: str = "Count fixture rows.") -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {description}\n"
        "license: MIT\n"
        "metadata:\n"
        "  author: batch4a\n"
        "allowed-tools: Read\n"
        "---\n"
        "Read references/facts.md before answering.\n",
        encoding="utf-8",
    )
    (directory / "references").mkdir()
    (directory / "references/facts.md").write_text("fixture=31\n", encoding="utf-8")
    return directory


def _plugin(root: Path) -> Path:
    plugin = root / "plugin"
    (plugin / ".sitina-plugin").mkdir(parents=True)
    (plugin / "skills" / "x").mkdir(parents=True)
    (plugin / "skills" / "x" / "SKILL.md").write_text(
        "---\nname: x\ndescription: plugin fixture\n---\nUse the fixture tool.\n", encoding="utf-8"
    )
    (plugin / ".sitina-plugin" / "plugin.json").write_text(
        json.dumps({
            "schema": "SITINA_PLUGIN_V1",
            "name": "fixture-plugin",
            "version": "1.0.0",
            "description": "batch 4a fixture",
            "permissions": ["read", "shell"],
            "components": {"skills": "skills", "tools": ".sitina-plugin/tools.json"},
        }),
        encoding="utf-8",
    )
    (plugin / ".sitina-plugin" / "tools.json").write_text(
        json.dumps({
            "schema": "SITINA_TOOLS_V1",
            "tools": [{
                "name": "fixture",
                "description": "run fixture",
                "permission": "shell",
                "command": ["/usr/bin/true"],
                "input_schema": {"type": "object", "properties": {}},
            }],
        }),
        encoding="utf-8",
    )
    return plugin


def _manager(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config").mkdir()
    extension_root = tmp_path / "extensions"
    state_root = tmp_path / "state"
    keys = MemoryKeychainBackend()
    backend = LoopBackend.open(state_root, keychain_backend=keys)
    manager = ExtensionManager(home, global_root=extension_root)
    authority = manager.bind_shared_authority(state_root=state_root, backend=backend)
    return home, extension_root, state_root, keys, backend, manager, authority


def _context(backend, manager, source: Path):
    try:
        backend.get_task("extension-task")
    except KeyError:
        backend.create_task(
            task_id="extension-task",
            session_id="session-extension",
            task_kind="extension-preparation",
            goal="prepare a candidate",
            required_outcome_ids=("candidate",),
            artifact_ref="cas:extension-artifact",
            environment_ref="environment-extension",
            capability_snapshot_id="capabilities-extension",
        )
    return manager.create_extension_preparation_context("extension-task", source)


def test_skill_candidate_is_complete_and_does_not_publish_default(tmp_path: Path):
    home, extension_root, state_root, keys, backend, manager, authority = _manager(tmp_path)
    try:
        source = _skill(tmp_path / "source")
        prepared = manager.prepare_skill_candidate(source, execution_context=_context(backend, manager, source))
        assert prepared.capability_id.startswith("capability-")
        assert (prepared.path / "SKILL.md").is_file()
        manifest = authority.candidate(prepared.candidate_id)
        assert manifest["candidate_id"] == prepared.candidate_id
        assert manifest["selection_binding"] is None
        assert manifest["publication_id"] is None
        assert manifest["bindings"]["skills"][0]["description"] == "Count fixture rows."
        projection = authority.load_projection()
        assert projection["default_publication_id"] is None
        assert prepared.candidate_id in projection["candidates"]
        with pytest.raises(ExtensionInstallError, match="legacy registry write path"):
            manager.install_skill(source)
    finally:
        backend.close()


def test_plugin_candidate_binds_concrete_tool_and_unknown_executor_is_rejected(tmp_path: Path):
    home, extension_root, state_root, keys, backend, manager, authority = _manager(tmp_path)
    try:
        plugin = _plugin(tmp_path)
        prepared = manager.prepare_plugin_candidate(
            plugin, grants=("shell",), execution_context=_context(backend, manager, plugin)
        )
        manifest = authority.candidate(prepared.candidate_id)
        assert manifest["bindings"]["tools"][0]["executor_type"] == "subprocess-command"
        assert manifest["bindings"]["tools"][0]["command"] == ["/usr/bin/true"]
        assert manifest["permissions"]["granted"] == ["read", "shell"]
        assert not (extension_root / "plugins").exists()
        broken = tmp_path / "broken"
        broken.mkdir()
        (broken / "SKILL.md").write_text("---\nname: x\ndescription: ok\n---\nok\n", encoding="utf-8")
        with pytest.raises((CandidatePreparationError, ExtensionSpecError)):
            manager.prepare_plugin_candidate(
                broken, execution_context=_context(backend, manager, broken)
            )
    finally:
        backend.close()


def test_shared_root_binding_rejects_second_state_root_and_rebuilds_stale_projection(tmp_path: Path):
    home, extension_root, state_root, keys, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        manager.prepare_skill_candidate(source, execution_context=_context(backend, manager, source))
        registry = extension_root / "registry.json"
        registry.write_text("{\"schema\": \"corrupt\"}\n", encoding="utf-8")
        rebuilt = authority.load_projection()
        assert rebuilt["schema"] == "SITINA_EXTENSION_PROJECTION_V1"
        assert rebuilt["applied_frontier"]["stream_version"] > 0
        second_state = tmp_path / "second-state"
        second = LoopBackend.open(second_state, keychain_backend=MemoryKeychainBackend())
        try:
            other = ExtensionManager(home, global_root=extension_root)
            with pytest.raises(ExtensionAuthorityError, match="another state root"):
                other.bind_shared_authority(state_root=second_state, backend=second)
        finally:
            second.close()
    finally:
        backend.close()


def test_backend_persistence_fence_blocks_candidate_copy_and_event(tmp_path: Path):
    home, extension_root, state_root, keys, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        before = len(backend.extension_events(authority.stream_id))
        context = _context(backend, manager, source)
        backend._fail_persistence(RuntimeError("fixture fence"))
        with pytest.raises(Exception, match="required persistent record"):
            manager.prepare_skill_candidate(source, execution_context=context)
        assert not (extension_root / "candidates" / "x").exists()
        assert len(tuple(event for event in backend.store.journal.iter_events(0) if event.stream_id == authority.stream_id)) == before
    finally:
        backend.close()


def test_legacy_inventory_is_a_source_fact_not_a_default_publication(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    extension_root = tmp_path / "extensions"
    extension_root.mkdir()
    (extension_root / "registry.json").write_text(json.dumps({
        "schema": "SITINA_EXTENSION_REGISTRY_V1",
        "generation": 4,
        "plugins": {"old": {"active": "old-1", "versions": [{"path": "/old"}]}},
        "skills": {}, "marketplaces": {},
    }), encoding="utf-8")
    (extension_root / "audit.jsonl").write_text("legacy\n", encoding="utf-8")
    state_root = tmp_path / "state"
    backend = LoopBackend.open(state_root, keychain_backend=MemoryKeychainBackend())
    try:
        manager = ExtensionManager(home, global_root=extension_root)
        authority = manager.bind_shared_authority(state_root=state_root, backend=backend)
        projection = authority.load_projection()
        assert projection["default_publication_id"] is None
        assert projection["legacy_inventory"][0]["entries"][0]["name"] == "old"
        assert json.loads((extension_root / "registry.json").read_text(encoding="utf-8"))["schema"] == "SITINA_EXTENSION_PROJECTION_V1"
    finally:
        backend.close()


def test_common_yaml_comments_and_flow_metadata_are_preserved_safely(tmp_path: Path):
    path = tmp_path / "flow" / "SKILL.md"
    path.parent.mkdir()
    path.write_text(
        "---\n"
        "name: x # one-character names are valid\n"
        "description: Count rows # inline comments are ignored\n"
        "metadata: {author: fixture, version: '1.0'} # flow mapping\n"
        "allowed-tools: [Read, Write]\n"
        "---\nInstructions.\n",
        encoding="utf-8",
    )
    value = load_skill(path)
    assert value.name == "x"
    assert value.description == "Count rows"
    assert value.optional_metadata["metadata"]["author"] == "fixture"
    assert value.allowed_tools == ("Read", "Write")


def test_yaml_unclosed_quote_and_non_string_required_types_fail_closed(tmp_path: Path):
    for body in (
        "name: 'x\ndescription: bad\n",
        "name: 7\ndescription: bad\n",
        "name: x\ndescription: 7\n",
    ):
        path = tmp_path / ("case-" + str(abs(hash(body)))) / "SKILL.md"
        path.parent.mkdir()
        path.write_text("---\n" + body + "---\nok\n", encoding="utf-8")
        with pytest.raises(ExtensionSpecError):
            load_skill(path)


def test_controlled_preparation_records_operation_and_requires_context(tmp_path: Path):
    _, extension_root, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        with pytest.raises(CandidatePreparationError, match="execution context"):
            manager.prepare_skill_candidate(source)
        before = len(backend.extension_events(authority.stream_id))
        prepared = manager.prepare_skill_candidate(
            source,
            execution_context=_context(backend, manager, source),
        )
        task = backend.get_task("extension-task")
        operation = next(item for item in task.operations.values() if item.operation_id.startswith("extension-prepare-"))
        assert operation.effect_status.value == "SUCCEEDED"
        assert operation.result_ref
        assert len(backend.extension_events(authority.stream_id)) == before + 1
        assert prepared.path.is_dir()
        assert str(extension_root) in operation.resources
    finally:
        backend.close()


def test_cancelled_context_and_old_backend_identity_are_rejected_without_effect(tmp_path: Path):
    _, extension_root, state_root, keys, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    context = _context(backend, manager, source)
    before = len(backend.extension_events(authority.stream_id))
    try:
        backend.accept_input("extension-task", input_id="cancel-1", kind=__import__("sitina.loop", fromlist=["InputKind"]).InputKind.CANCEL, body="stop")
        with pytest.raises(Exception):
            manager.prepare_skill_candidate(source, execution_context=context)
        assert len(backend.extension_events(authority.stream_id)) == before
        assert not (extension_root / "candidates" / "x").exists()
    finally:
        backend.close()
    reopened = LoopBackend.open(state_root, keychain_backend=keys)
    try:
        other = ExtensionManager(tmp_path / "home", global_root=extension_root)
        rebound = other.bind_shared_authority(state_root=state_root, backend=reopened)
        with pytest.raises(CandidatePreparationError, match="not issued"):
            other.prepare_skill_candidate(source, execution_context=context)
    finally:
        reopened.close()


def test_source_change_and_failure_settlement_leave_no_unsettled_write(tmp_path: Path):
    _, extension_root, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        context = _context(backend, manager, source)
        (source / "references" / "facts.md").write_text("changed\n", encoding="utf-8")
        with pytest.raises(CandidatePreparationError, match="source changed"):
            manager.prepare_skill_candidate(source, execution_context=context)
        assert len(backend.extension_events(authority.stream_id)) == 0

        (source / "references" / "facts.md").write_text("fixture=31\n", encoding="utf-8")
        (source / "candidate.json").write_text("{\"fixture_value\": 31}\n", encoding="utf-8")
        failed_context = _context(backend, manager, source)
        with pytest.raises(CandidatePreparationError, match="reserved"):
            manager.prepare_skill_candidate(source, execution_context=failed_context)
        task = backend.get_task("extension-task")
        operation = max(task.operations.values(), key=lambda item: item.operation_id)
        assert operation.effect_status.value == "FAILED"
        assert operation.result_ref
        assert not (extension_root / "candidates" / "x").exists()
    finally:
        backend.close()


def test_identical_content_reuses_capability_id_without_path_collision(tmp_path: Path):
    _, _, _, _, backend, manager, authority = _manager(tmp_path)
    first = _skill(tmp_path / "source-a")
    second = _skill(tmp_path / "source-b")
    try:
        first_candidate = manager.prepare_skill_candidate(
            first, execution_context=_context(backend, manager, first)
        )
        second_candidate = manager.prepare_skill_candidate(
            second, execution_context=_context(backend, manager, second)
        )
        assert second_candidate.candidate_id == first_candidate.candidate_id
        assert second_candidate.path == first_candidate.path
        assert len(authority.load_projection()["candidates"]) == 1
    finally:
        backend.close()


def test_same_source_retry_reuses_manifest_and_prepared_fact(tmp_path: Path):
    _, _, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        first = manager.prepare_skill_candidate(source, execution_context=_context(backend, manager, source))
        first_events = [e for e in backend.extension_events(authority.stream_id) if e.event_type == "extension.candidate-prepared"]
        second = manager.prepare_skill_candidate(source, execution_context=_context(backend, manager, source))
        second_events = [e for e in backend.extension_events(authority.stream_id) if e.event_type == "extension.candidate-prepared"]
        assert second.candidate_id == first.candidate_id
        assert second.manifest_ref == first.manifest_ref
        assert [e.event_id for e in second_events] == [e.event_id for e in first_events]
    finally:
        backend.close()


def test_source_change_at_materialization_entry_cannot_mix_old_bindings(tmp_path: Path, monkeypatch):
    _, extension_root, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        context = _context(backend, manager, source)
        original_materialize = authority._materialize_controlled

        def mutate_before_materialize(**kwargs):
            (source / "SKILL.md").write_text(
                "---\nname: x\ndescription: Changed at materialization entry.\n---\nChanged.\n",
                encoding="utf-8",
            )
            return original_materialize(**kwargs)

        monkeypatch.setattr(authority, "_materialize_controlled", mutate_before_materialize)
        with pytest.raises(CandidatePreparationError, match="source changed"):
            manager.prepare_skill_candidate(source, execution_context=context)
        assert not list((extension_root / "candidates").rglob("SKILL.md"))
        assert not [e for e in backend.extension_events(authority.stream_id) if e.event_type == "extension.candidate-prepared"]
    finally:
        backend.close()


def test_control_barrier_after_copy_prevents_fact_commit(tmp_path: Path, monkeypatch):
    _, extension_root, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        context = _context(backend, manager, source)
        from sitina.extensions import authority as authority_module

        original_copy = authority_module._copy_tree_no_links

        def copy_then_cancel(*args, **kwargs):
            original_copy(*args, **kwargs)
            backend.accept_input("extension-task", input_id="cancel-after-copy", kind=InputKind.CANCEL, body="stop")

        monkeypatch.setattr(authority_module, "_copy_tree_no_links", copy_then_cancel)
        with pytest.raises(CandidatePreparationError):
            manager.prepare_skill_candidate(source, execution_context=context)
        assert not list((extension_root / "candidates").rglob("SKILL.md"))
        assert not [e for e in backend.extension_events(authority.stream_id) if e.event_type == "extension.candidate-prepared"]
    finally:
        backend.close()


def test_materialization_failure_holds_unknown_effect(tmp_path: Path, monkeypatch):
    _, extension_root, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        context = _context(backend, manager, source)
        original_publish = backend.publish_extension_json

        def fail_manifest(value, *, purpose):
            if purpose == "sitina-extension-candidate-manifest":
                raise RuntimeError("manifest write failed after rename")
            return original_publish(value, purpose=purpose)

        monkeypatch.setattr(backend, "publish_extension_json", fail_manifest)
        with pytest.raises(CandidatePreparationError):
            manager.prepare_skill_candidate(source, execution_context=context)
        operation = backend.get_task(context.task_id).operations[context.operation_id]
        assert operation.effect_status.value == "UNKNOWN"
        assert backend.operations.unknown_effect_owner == (context.task_id, context.operation_id)
        assert list((extension_root / "candidates").rglob("SKILL.md"))
        assert not [e for e in backend.extension_events(authority.stream_id) if e.event_type == "extension.candidate-prepared"]
    finally:
        backend.close()


def test_tampered_context_cannot_downgrade_write_operation(tmp_path: Path):
    _, extension_root, _, _, backend, manager, authority = _manager(tmp_path)
    source = _skill(tmp_path / "source")
    try:
        context = _context(backend, manager, source)
        malformed = replace(context, intent=replace(context.intent, mode=OperationMode.READ, resources=()))
        with pytest.raises(Exception):
            manager.prepare_skill_candidate(source, execution_context=malformed)
        assert not list((extension_root / "candidates").rglob("SKILL.md"))
        assert not [e for e in backend.extension_events(authority.stream_id) if e.event_type == "extension.candidate-prepared"]
    finally:
        backend.close()
