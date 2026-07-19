from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from pydantic import ValidationError

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.commands.model import CommandEnvelope
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.orchestrator.agent_context_v2 import (
    AgentContextManifestRepository,
    AgentContextManifestV2,
    AgentContextV2Error,
)
from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream, ProviderExecutor
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class AgentContextManifestV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.cas = LocalCAS.open(self.home, self.keys)
        self.journal = LocalJournal.open(self.home, JournalAuthProvider(self.keys))
        command = CommandEnvelope(
            "command-context-run",
            "run-tenant",
            "run/run-context",
            "run.create",
            "runner",
            "2026-07-18T00:00:00Z",
            {"run_id": "run-context"},
        )
        event = EventEnvelope(
            "event-context-run",
            "run.created",
            "run-tenant",
            "run/run-context",
            0,
            0,
            "2026-07-18T00:00:00Z",
            {"run_id": "run-context"},
        )
        self.journal.append(command, 0, [event])
        leases = CompatibilityLeaseRegistry(self.home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="agent-context-v2-test",
                binary_version="2.0.0",
                reader_capabilities=("agent-context-v2",),
                writer_capabilities=("agent-context-v2",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T01:00:00Z",
                fencing_token=1,
            )
        )
        self.activations = FeatureActivationRegistry()
        self.activations.prepare(
            "agent_context_v2_write",
            required_reader_capabilities=("agent-context-v2",),
            leases=leases,
            now="2026-07-18T00:01:00Z",
            journal_position=1,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "event_type": "runtime.feature-prepared",
                "feature": "agent_context_v2_write",
            },
        )
        self.activations.activate(
            "agent_context_v2_write",
            rollback_floor_version=2,
            journal_position=2,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "event_type": "runtime.feature-activated",
                "feature": "agent_context_v2_write",
            },
        )

    def tearDown(self) -> None:
        self.journal.close()

    def _object(self, text: str, purpose: str):
        return self.cas.publish_verified(
            encrypt_object(text.encode(), self.keys, tenant_id="context-tenant", purpose=purpose)
        ).object_ref

    def test_manifest_reconstructs_identical_hash_without_storing_rendered_prompt(self) -> None:
        prompt = self._object("System template", "prompt-template")
        project = self._object("Project context", "project-context")
        conversation = self._object("Goal and constraints", "conversation-state")
        summary = self._object("Confirmed summary", "rolling-summary")
        memory = self._object("Relevant accepted memory", "retrieved-memory")
        blackboard = self._object("Blackboard base", "blackboard-base")
        delta = self._object("Latest blackboard patch", "blackboard-delta")
        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        repository = AgentContextManifestRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        )
        published = repository.create(
            run_id="run-context",
            call_id="call-context-1",
            agent_id="agent-context-1",
            prompt_template_ref=prompt,
            base_project_context_ref=project,
            conversation_state_ref=conversation,
            rolling_summary_ref=summary,
            retrieved_memory_refs=(memory,),
            blackboard_base_ref=blackboard,
            delta_refs=(delta,),
            occurred_at="2026-07-18T00:02:00Z",
        )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before + 1)
        self.assertIn(b"System template", published.rendered)
        self.assertIn(b"Latest blackboard patch", published.rendered)
        publication = next(event for event in self.journal.iter_events(0) if event.event_type == "agent.context-manifest-published")
        self.assertNotIn("System template", str(publication.payload))
        self.assertNotIn("Latest blackboard patch", str(publication.payload))
        self.assertEqual(len(publication.object_refs), len(set(published.manifest.component_refs)) + 1)
        reopened = repository.open(publication)
        self.assertEqual(reopened.manifest, published.manifest)
        self.assertEqual(reopened.rendered, published.rendered)
        self.assertEqual(reopened.manifest.rendered_input_hash, published.manifest.rendered_input_hash)

    def test_context_publication_does_not_stale_the_canonical_run_stream(self) -> None:
        run_stream = CanonicalStream(self.journal, "run-context", "run/run-context", "f" * 64)
        prompt = self._object("System template", "prompt-template")
        delta = self._object("Current request", "delta")
        published = AgentContextManifestRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        ).create(
            run_id="run-context",
            call_id="call-context-stream-isolation",
            agent_id="agent-context-1",
            prompt_template_ref=prompt,
            base_project_context_ref=None,
            conversation_state_ref=None,
            rolling_summary_ref=None,
            retrieved_memory_refs=(),
            blackboard_base_ref=None,
            delta_refs=(delta,),
            occurred_at="2026-07-18T00:03:00Z",
        )
        receipt, _refs = run_stream.append(
            "provider-result-admitted",
            ({"schema": "PROVIDER_RESULT_ADMITTED_V1", "manifest_ref": published.manifest_ref.reference_id},),
            actor="run-command-handler",
        )
        publication = next(
            event for event in self.journal.iter_events(0) if event.payload.get("call_id") == "call-context-stream-isolation"
        )
        self.assertEqual(publication.stream_id, "run-context/run-context")
        self.assertEqual(receipt.stream_id, "run/run-context")

    def test_feature_gate_and_expected_hash_fail_before_manifest_publication(self) -> None:
        prompt = self._object("template", "prompt-template")
        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        with self.assertRaises(AgentContextV2Error):
            AgentContextManifestRepository(self.journal, self.cas, self.keys).create(
                run_id="run-context",
                call_id="call-disabled",
                agent_id="agent-disabled",
                prompt_template_ref=prompt,
                base_project_context_ref=None,
                conversation_state_ref=None,
                rolling_summary_ref=None,
                retrieved_memory_refs=(),
                blackboard_base_ref=None,
                delta_refs=(),
                occurred_at="2026-07-18T00:02:00Z",
            )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)
        with self.assertRaises(AgentContextV2Error):
            AgentContextManifestRepository(
                self.journal,
                self.cas,
                self.keys,
                feature_activations=self.activations,
            ).create(
                run_id="run-context",
                call_id="call-wrong-hash",
                agent_id="agent-context-1",
                prompt_template_ref=prompt,
                base_project_context_ref=None,
                conversation_state_ref=None,
                rolling_summary_ref=None,
                retrieved_memory_refs=(),
                blackboard_base_ref=None,
                delta_refs=(),
                occurred_at="2026-07-18T00:02:00Z",
                expected_rendered_input_hash="0" * 64,
            )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)

    def test_manifest_schema_rejects_extra_fields_and_duplicate_refs(self) -> None:
        reference = "cas:" + "a" * 64
        value = {
            "schema": "SITINA_AGENT_CONTEXT_MANIFEST_V2",
            "run_id": "run-context",
            "call_id": "call-context",
            "agent_id": "agent-context",
            "prompt_template_ref": reference,
            "base_project_context_ref": None,
            "conversation_state_ref": None,
            "rolling_summary_ref": None,
            "retrieved_memory_refs": [],
            "blackboard_base_ref": None,
            "delta_refs": [],
            "renderer_version": "context-renderer-v2",
            "rendered_input_hash": "b" * 64,
        }
        with self.assertRaises(ValidationError):
            AgentContextManifestV2.model_validate({**value, "rendered_prompt": "forbidden copy"})
        with self.assertRaises(ValidationError):
            AgentContextManifestV2.model_validate({**value, "delta_refs": [reference, reference]})

    def test_activated_provider_input_path_publishes_components_once_and_manifest_per_call(self) -> None:
        executor = object.__new__(ProviderExecutor)
        executor.journal = self.journal
        executor.cas = self.cas
        executor.context = SimpleNamespace(provider=self.keys)
        executor.feature_activations = self.activations
        executor.run_id = "run-context"
        before = len(list((self.home / "cas/objects").rglob("*.obj")))

        first, first_hash, rendered_hash = executor._publish_input_binding_v2(
            call_id="call-provider-1",
            agent_id="agent-provider",
            system_prompt="Stable system prompt",
            user_prompt="One delta prompt",
            input_context={"goal": "stable context", "turn": 1},
        )
        after_first = len(list((self.home / "cas/objects").rglob("*.obj")))
        second, second_hash, second_rendered_hash = executor._publish_input_binding_v2(
            call_id="call-provider-2",
            agent_id="agent-provider",
            system_prompt="Stable system prompt",
            user_prompt="One delta prompt",
            input_context={"goal": "stable context", "turn": 1},
        )
        after_second = len(list((self.home / "cas/objects").rglob("*.obj")))

        self.assertEqual(after_first - before, 4)  # three bodies plus one manifest
        self.assertEqual(after_second - after_first, 1)  # component bodies deduplicate
        self.assertNotEqual(first.object_ref.reference_id, second.object_ref.reference_id)
        self.assertNotEqual(first_hash, second_hash)
        self.assertEqual(rendered_hash, second_rendered_hash)
        publications = [
            event for event in self.journal.iter_events(0)
            if event.event_type == "agent.context-manifest-published"
        ]
        self.assertEqual(len(publications), 2)
        self.assertNotIn("Stable system prompt", str(publications))
        self.assertNotIn("One delta prompt", str(publications))


if __name__ == "__main__":
    unittest.main()
