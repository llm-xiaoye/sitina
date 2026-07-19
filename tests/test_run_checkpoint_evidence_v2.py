from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.evidence.reference_v2 import ReferencedEvidenceError, ReferencedEvidenceRepository, RunEvidenceV2
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.orchestrator.run_checkpoint_v2 import RunCheckpointV2Error, RunCheckpointV2Repository
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class RunCheckpointAndEvidenceV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.cas = LocalCAS.open(self.home, self.keys)
        self.journal = LocalJournal.open(self.home, JournalAuthProvider(self.keys))
        leases = CompatibilityLeaseRegistry(self.home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="checkpoint-evidence-v2-test",
                binary_version="2.0.0",
                reader_capabilities=("checkpoint-v2", "evidence-v2"),
                writer_capabilities=("checkpoint-v2", "evidence-v2"),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T02:00:00Z",
                fencing_token=1,
            )
        )
        self.activations = FeatureActivationRegistry()
        for index, (feature, capability) in enumerate(
            (("checkpoint_v2_write", "checkpoint-v2"), ("evidence_v2_write", "evidence-v2")),
            1,
        ):
            self.activations.prepare(
                feature,
                required_reader_capabilities=(capability,),
                leases=leases,
                now="2026-07-18T00:01:00Z",
                journal_position=index * 2 - 1,
                journal_control_event={
                    "schema": "RUNTIME_FEATURE_PREPARED_V1",
                    "event_type": "runtime.feature-prepared",
                    "feature": feature,
                },
            )
            self.activations.activate(
                feature,
                rollback_floor_version=2,
                journal_position=index * 2,
                journal_control_event={
                    "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                    "event_type": "runtime.feature-activated",
                    "feature": feature,
                },
            )

    def tearDown(self) -> None:
        self.journal.close()

    def _append_run_event(self, run_id: str, ordinal: int, event_type: str, body: bytes | None = None):
        stream_id = f"run/{run_id}"
        proofs = ()
        refs = ()
        published = None
        if body is not None:
            published = self.cas.publish_verified(
                encrypt_object(body, self.keys, tenant_id="run-tenant", purpose="run-object")
            )
            proofs = (published,)
            refs = (published.object_ref.reference_id,)
        command = CommandEnvelope(
            f"command-{run_id}-{ordinal}",
            "run-tenant",
            stream_id,
            "run.fixture",
            "fixture-runner",
            f"2026-07-18T00:{ordinal:02d}:00Z",
            {"run_id": run_id, "ordinal": ordinal},
        )
        event = EventEnvelope(
            f"event-{run_id}-{ordinal}",
            event_type,
            "run-tenant",
            stream_id,
            0,
            0,
            f"2026-07-18T00:{ordinal:02d}:00Z",
            {"run_id": run_id, "ordinal": ordinal},
            refs,
        )
        receipt = self.journal.append(
            command,
            self.journal._stream_heads.get(stream_id, 0),
            [event],
            object_reference_proofs=proofs,
        )
        return published, receipt.last_position

    def test_incremental_checkpoints_are_run_scoped_bounded_and_terminal_is_independent(self) -> None:
        goal, _ = self._append_run_event("run-main", 1, "run.created", b"main run goal")
        foreign, _ = self._append_run_event("run-other", 2, "run.created", b"foreign run body")
        _control, first_through = self._append_run_event("run-main", 3, "task.completed")
        repository = RunCheckpointV2Repository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        )
        first = repository.create(
            run_id="run-main",
            through_position=first_through,
            occurred_at="2026-07-18T00:10:00Z",
        )
        self.assertLessEqual(first.raw_size, 512 * 1024)
        self.assertIn(goal.object_ref.reference_id, first.document.new_cas_refs)
        self.assertNotIn(foreign.object_ref.reference_id, first.document.new_cas_refs)

        output, second_through = self._append_run_event("run-main", 4, "agent.output-published", b"main output")
        self._append_run_event("run-other", 5, "agent.output-published", b"foreign output")
        second = repository.create(
            run_id="run-main",
            through_position=second_through,
            occurred_at="2026-07-18T00:11:00Z",
        )
        self.assertEqual(second.document.base_checkpoint_ref, first.object_ref.reference_id)
        self.assertEqual(second.document.new_cas_refs, (output.object_ref.reference_id,))
        chain = repository.restore_chain("run-main")
        self.assertEqual([item.object_ref.reference_id for item in chain], [first.object_ref.reference_id, second.object_ref.reference_id])

        _none, terminal_position = self._append_run_event("run-main", 6, "run.terminal")
        terminal = repository.compact_terminal(
            run_id="run-main",
            through_position=terminal_position,
            occurred_at="2026-07-18T00:12:00Z",
        )
        self.assertEqual(terminal.document.checkpoint_kind, "terminal_compact")
        self.assertIsNone(terminal.document.base_checkpoint_ref)
        self.assertEqual(
            terminal.document.new_cas_refs,
            tuple(sorted((goal.object_ref.reference_id, output.object_ref.reference_id))),
        )
        self.assertEqual(repository.restore_chain("run-main"), (repository.latest("run-main"),))
        compacted = next(event for event in self.journal.iter_events(0) if event.event_type == "run.checkpoint-chain-compacted")
        self.assertFalse(compacted.payload["history_objects_deleted"])
        self.assertEqual(
            compacted.payload["released_checkpoint_root_refs"],
            [first.object_ref.reference_id, second.object_ref.reference_id],
        )

    def test_checkpoint_and_evidence_writers_fail_before_cas_when_feature_is_not_activated(self) -> None:
        self._append_run_event("run-gated", 1, "run.created")
        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        with self.assertRaises(RunCheckpointV2Error):
            RunCheckpointV2Repository(self.journal, self.cas, self.keys).create(
                run_id="run-gated",
                through_position=self.journal.head_position,
                occurred_at="2026-07-18T00:10:00Z",
            )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)
        with self.assertRaises(ReferencedEvidenceError):
            ReferencedEvidenceRepository(self.journal, self.cas, self.keys).create(
                run_id="run-gated",
                checkpoint=None,  # type: ignore[arg-type]
                input_refs=(),
                output_refs=(),
                tool_record_refs=(),
                provider_call_ids=(),
                evidence_policy_hash="a" * 64,
                occurred_at="2026-07-18T00:11:00Z",
            )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)

    def test_evidence_v2_contains_only_references_and_replays_consistently(self) -> None:
        goal, _ = self._append_run_event("run-evidence", 1, "run.created", b"goal body")
        output, _ = self._append_run_event("run-evidence", 2, "agent.output-published", b"output body")
        _none, terminal_position = self._append_run_event("run-evidence", 3, "run.terminal")
        checkpoints = RunCheckpointV2Repository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        )
        checkpoint = checkpoints.create(
            run_id="run-evidence",
            through_position=terminal_position,
            terminal_compact=True,
            occurred_at="2026-07-18T00:10:00Z",
        )
        repository = ReferencedEvidenceRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        )
        evidence = repository.create(
            run_id="run-evidence",
            checkpoint=checkpoint,
            input_refs=(goal.object_ref.reference_id,),
            output_refs=(output.object_ref.reference_id,),
            tool_record_refs=(),
            provider_call_ids=("provider-call-1",),
            evidence_policy_hash="a" * 64,
            occurred_at="2026-07-18T00:11:00Z",
        )
        durable = evidence.document.model_dump(mode="json", by_alias=True)
        self.assertFalse(ReferencedEvidenceRepository.FORBIDDEN_BODY_FIELDS & set(durable))
        publication = next(event for event in self.journal.iter_events(0) if event.event_type == "run.evidence-published")
        self.assertNotIn("goal body", str(publication.payload))
        self.assertNotIn("output body", str(publication.payload))
        reopened = repository.open(publication)
        self.assertEqual(reopened.document, evidence.document)
        report = repository.verify_replay(reopened)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["classified_ref_count"], 2)
        self.assertEqual(report["body_copy_count"], 0)

        with self.assertRaises(ValidationError):
            RunEvidenceV2.model_validate({**durable, "response": "duplicated body"})
        with self.assertRaises(ReferencedEvidenceError):
            repository.create(
                run_id="run-evidence",
                checkpoint=checkpoint,
                input_refs=("cas:" + "f" * 64,),
                output_refs=(),
                tool_record_refs=(),
                provider_call_ids=(),
                evidence_policy_hash="a" * 64,
                occurred_at="2026-07-18T00:12:00Z",
            )


if __name__ == "__main__":
    unittest.main()
