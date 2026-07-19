from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.orchestrator.blackboard_native import (
    BlackboardPatchV1,
    NativeBlackboardConflict,
    NativeBlackboardDocument,
    NativeBlackboardError,
    NativeBlackboardRepository,
)
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class NativeBlackboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.cas = LocalCAS.open(self.home, self.keys)
        self.auth = JournalAuthProvider(self.keys)
        self.journal = LocalJournal.open(self.home, self.auth)
        command = CommandEnvelope(
            "command-blackboard-run",
            "run-tenant",
            "run/run-blackboard",
            "run.create",
            "runner",
            "2026-07-18T00:00:00Z",
            {"run_id": "run-blackboard"},
        )
        event = EventEnvelope(
            "event-blackboard-run",
            "run.created",
            "run-tenant",
            "run/run-blackboard",
            0,
            0,
            "2026-07-18T00:00:00Z",
            {"run_id": "run-blackboard"},
        )
        self.journal.append(command, 0, [event])
        leases = CompatibilityLeaseRegistry(self.home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="blackboard-native-test",
                binary_version="2.0.0",
                reader_capabilities=("journal-event-v2",),
                writer_capabilities=("journal-event-v2",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T02:00:00Z",
                fencing_token=1,
            )
        )
        self.activations = FeatureActivationRegistry()
        self.activations.prepare(
            "journal_event_v2_write",
            required_reader_capabilities=("journal-event-v2",),
            leases=leases,
            now="2026-07-18T00:01:00Z",
            journal_position=1,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "event_type": "runtime.feature-prepared",
                "feature": "journal_event_v2_write",
            },
        )
        self.activations.activate(
            "journal_event_v2_write",
            rollback_floor_version=2,
            journal_position=2,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "event_type": "runtime.feature-activated",
                "feature": "journal_event_v2_write",
            },
        )

    def tearDown(self) -> None:
        self.journal.close()

    @staticmethod
    def _document(version: int, summary: str = "A compact claim") -> NativeBlackboardDocument:
        return NativeBlackboardDocument(
            document_id="document-1",
            task_id="task-1",
            author_agent_id="agent-1",
            document_type="claim",
            content_summary=summary,
            artifact_refs=(),
            related_document_ids=(),
            version=version,
        )

    def test_delta_ratio_compacts_to_new_base_and_restart_recovers(self) -> None:
        repository = NativeBlackboardRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        )
        initialized = repository.initialize(run_id="run-blackboard", occurred_at="2026-07-18T00:01:00Z")
        patched = repository.apply_patch(
            BlackboardPatchV1(
                patch_id="patch-add-1",
                run_id="run-blackboard",
                from_version=0,
                to_version=1,
                operation="add",
                document_id="document-1",
                expected_document_version=None,
                document=self._document(1, "A sufficiently descriptive first claim"),
                source_frontier=self.journal.head_position,
            ),
            occurred_at="2026-07-18T00:02:00Z",
        )
        self.assertNotEqual(patched.base_ref, initialized.base_ref)
        self.assertEqual(patched.version, 1)
        self.assertEqual(patched.patch_count, 0)
        compacted = [event for event in self.journal.iter_events(0) if event.event_type == "blackboard.base-published"][-1]
        self.assertEqual(compacted.payload["compaction_reason"], "delta-ratio")
        self.assertFalse(compacted.payload["independent_recovery_point"])
        self.assertFalse((self.home / "state/blackboard.json").exists())
        self.assertFalse((self.home / "data/sitina.db").exists())

        self.journal.close()
        self.journal = LocalJournal.open(self.home, self.auth)
        reopened = NativeBlackboardRepository(
            self.journal,
            LocalCAS.open(self.home, self.keys),
            self.keys,
            feature_activations=self.activations,
        ).recover("run-blackboard")
        self.assertEqual(reopened.documents, patched.documents)
        self.assertEqual(reopened.base_ref, patched.base_ref)

    def test_patch_count_threshold_and_terminal_independent_recovery_point(self) -> None:
        repository = NativeBlackboardRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
            patch_limit=50,
            delta_to_base_ratio=1_000_000.0,
        )
        repository.initialize(run_id="run-blackboard", occurred_at="2026-07-18T00:01:00Z")
        snapshot = repository.apply_patch(
            BlackboardPatchV1(
                patch_id="patch-1",
                run_id="run-blackboard",
                from_version=0,
                to_version=1,
                operation="add",
                document_id="document-1",
                expected_document_version=None,
                document=self._document(1),
                source_frontier=self.journal.head_position,
            ),
            occurred_at="2026-07-18T00:01:01Z",
        )
        for version in range(2, 51):
            snapshot = repository.apply_patch(
                BlackboardPatchV1(
                    patch_id=f"patch-{version}",
                    run_id="run-blackboard",
                    from_version=version - 1,
                    to_version=version,
                    operation="update",
                    document_id="document-1",
                    expected_document_version=version - 1,
                    document=self._document(version, f"claim revision {version}"),
                    source_frontier=self.journal.head_position,
                ),
                occurred_at=f"2026-07-18T00:01:{version:02d}Z",
            )
        self.assertEqual(snapshot.version, 50)
        self.assertEqual(snapshot.patch_count, 0)
        bases = [event for event in self.journal.iter_events(0) if event.event_type == "blackboard.base-published"]
        self.assertEqual(bases[-1].payload["compaction_reason"], "patch-count")
        self.assertEqual(bases[-1].payload["compacted_patch_count"], 50)

        stream_id = "run/run-blackboard"
        terminal_command = CommandEnvelope(
            "command-blackboard-terminal",
            "run-tenant",
            stream_id,
            "run.terminalize",
            "runner",
            "2026-07-18T00:02:00Z",
            {"run_id": "run-blackboard"},
        )
        terminal_event = EventEnvelope(
            "event-blackboard-terminal",
            "run.terminal",
            "run-tenant",
            stream_id,
            0,
            0,
            "2026-07-18T00:02:00Z",
            {"run_id": "run-blackboard"},
        )
        self.journal.append(
            terminal_command,
            self.journal._stream_heads[stream_id],
            [terminal_event],
        )
        terminal = repository.compact(
            run_id="run-blackboard",
            reason="terminal",
            occurred_at="2026-07-18T00:02:01Z",
        )
        self.assertEqual(terminal.version, 50)
        event = [event for event in self.journal.iter_events(0) if event.event_type == "blackboard.base-published"][-1]
        self.assertTrue(event.payload["independent_recovery_point"])
        base_raw = self.cas.open_verified(self.cas.resolve_reference(event.payload["object_ref"]))
        self.assertIn(b'"previous_base_ref":null', base_raw)

    def test_stale_patch_strict_schema_and_feature_gate_fail_closed(self) -> None:
        repository = NativeBlackboardRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
            delta_to_base_ratio=100.0,
        )
        repository.initialize(run_id="run-blackboard", occurred_at="2026-07-18T00:01:00Z")
        patch = BlackboardPatchV1(
            patch_id="patch-stale",
            run_id="run-blackboard",
            from_version=1,
            to_version=2,
            operation="add",
            document_id="document-1",
            expected_document_version=None,
            document=self._document(1),
            source_frontier=self.journal.head_position,
        )
        with self.assertRaises(NativeBlackboardConflict):
            repository.apply_patch(patch, occurred_at="2026-07-18T00:02:00Z")
        with self.assertRaises(ValidationError):
            NativeBlackboardDocument.model_validate({**self._document(1).model_dump(), "permissions": ["write"]})

        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        with self.assertRaises(NativeBlackboardError):
            NativeBlackboardRepository(self.journal, self.cas, self.keys).compact(
                run_id="run-blackboard",
                reason="pre-deletion",
                occurred_at="2026-07-18T00:03:00Z",
            )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)


if __name__ == "__main__":
    unittest.main()
