from __future__ import annotations

import json
from pathlib import Path

import pytest

from sitina.loop import LoopBackend
from sitina.loop.context_window import ContextCoreError, LoopContextIndex, LoopHistoryQuery
from sitina.loop.model import InputKind
from sitina.security.macos_keychain import MemoryKeychainBackend


def test_memory_view_revalidation_is_indexed_with_cas_identity_and_unknown_events_fail_closed(
    tmp_path: Path,
) -> None:
    with LoopBackend.open(tmp_path / "state", keychain_backend=MemoryKeychainBackend()) as backend:
        task = backend.create_task(
            task_id="task-b6-interim-11",
            session_id="session-b6-interim-11",
            task_kind="readonly",
            goal="use a bounded reviewed memory view",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:artifact-b6-interim-11",
            environment_ref="environment-b6-interim-11",
            capability_snapshot_id="capabilities-b6-interim-11",
            memory_view={
                "selected_memory_ids": ["memory-b6-interim-11"],
                "selected_memory_versions": {"memory-b6-interim-11": 1},
                "selection_reasons": ["focused reader fixture"],
                "source_frontier": 1,
                "entries": [{"memory_id": "memory-b6-interim-11", "content_hash": "a" * 64}],
            },
        )
        backend.accept_input(
            task.task_id,
            input_id="correction-b6-interim-11",
            kind=InputKind.CORRECTION,
            body="the selected memory is no longer authoritative",
        )
        handled = backend.handle_next_input(task.task_id, derive_effects_from_record=True)
        current = backend.get_task(task.task_id)
        document = {
            "schema": "SITINA_LOOP_MEMORY_VIEW_REVALIDATION_V1",
            "task_id": task.task_id,
            "original_memory_view_ref": current.memory_view_ref,
            "original_memory_view_hash": current.memory_view_hash,
            "bound_task_revision": current.task_revision,
            "run_instance_id": current.run_instance_id,
            "run_instance_id_epoch": current.execution_epoch,
            "execution_epoch": current.execution_epoch,
            "goal_version": current.goal_version,
            "acceptance_version": current.acceptance_version,
            "handled_input_seq": current.handled_input_seq,
            "correction_input_seq": handled.handled_input_seq,
            "active_entries": [],
            "excluded_entries": [{
                "memory_id": "memory-b6-interim-11",
                "expected_version": 1,
                "observed_source_position": None,
                "observed_status": "revoked",
                "observed_quarantine_status": "active",
                "reason": "focused reader fixture",
            }],
            "excluded_memory_ids": ["memory-b6-interim-11"],
        }
        stored = backend.context_memory.persist(document, purpose="loop-memory-view-revalidation")
        backend._append(
            task_id=task.task_id,
            expected_stream_version=current.task_revision,
            request_id="memory-view-revalidate:b6-interim-11",
            command_type="loop.task.memory-view-revalidate",
            event_type="loop.task-memory-view-revalidated",
            payload={
                "schema": "SITINA_LOOP_MEMORY_VIEW_REVALIDATED_V1",
                "task_id": task.task_id,
                "revalidation_ref": stored.reference_id,
                "revalidation_hash": stored.content_hash,
                "original_memory_view_ref": current.memory_view_ref,
                "original_memory_view_hash": current.memory_view_hash,
                "correction_input_seq": handled.handled_input_seq,
                "excluded_memory_ids": ["memory-b6-interim-11"],
            },
            proofs=(stored.proof,),
        )

        index = LoopContextIndex(backend.store, task.task_id)
        query = LoopHistoryQuery(index, max_page_bytes=4096)
        listed = query.list(kind="memory_view_revalidation")
        assert listed["status"] == "OK"
        assert listed["returned_count"] == 1
        source_ref = listed["entries"][0]["source_ref"]
        read = query.read(source_ref=source_ref, max_bytes=4096)
        assert read["status"] == "OK"
        readable = json.loads(read["readable_text"])
        assert readable["schema"] == "SITINA_LOOP_MEMORY_VIEW_REVALIDATION_V1"
        assert readable["excluded_memory_ids"] == ["memory-b6-interim-11"]

        current = backend.get_task(task.task_id)
        backend._append(
            task_id=task.task_id,
            expected_stream_version=current.task_revision,
            request_id="unknown-event:b6-interim-11",
            command_type="loop.task.unknown-test",
            event_type="loop.task-unknown-test",
            payload={"schema": "SITINA_LOOP_UNKNOWN_TEST_V1", "task_id": task.task_id},
        )
        with pytest.raises(ContextCoreError, match="unknown event type"):
            index.refresh()
