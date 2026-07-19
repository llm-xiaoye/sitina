from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sitina.compatibility.capabilities import (
    CapabilityError,
    FormatCapabilityRegistry,
    UnknownRequiredSchema,
)
from sitina.compatibility.feature_flags import FeatureActivationRegistry, FeatureGateError
from sitina.compatibility.leases import (
    CompatibilityLeaseRegistry,
    RuntimeCompatibilityLease,
    StaleFencingToken,
)
from sitina.compatibility.upcasters import UpcasterRegistry
from sitina.evidence.reference_v2 import RunEvidenceV2
from sitina.orchestrator.agent_context_v2 import AgentContextManifestV2
from sitina.orchestrator.run_checkpoint_v2 import RunCheckpointV2


class StorageCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (root / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.home = root
        self.repo = Path(__file__).resolve().parents[1]

    def test_registry_covers_every_new_format_and_has_stable_hash(self) -> None:
        registry = FormatCapabilityRegistry.load(self.repo / "config/format_capabilities.json")
        self.assertEqual(
            set(registry.names),
            {
                "SITINA_JOURNAL_EVENT",
                "SITINA_RUN_CHECKPOINT",
                "SITINA_AUTHORITY_CHECKPOINT",
                "SITINA_RUN_EVIDENCE",
                "SITINA_AGENT_CONTEXT_MANIFEST",
                "SITINA_MEMORY",
                "SITINA_CAS_COMPRESSION",
                "SITINA_ENVELOPE_ALIAS_PACK",
                "SITINA_TRASH_BUNDLE",
                "SITINA_PROJECTION_SCHEMA",
            },
        )
        again = FormatCapabilityRegistry.load(self.repo / "config/format_capabilities.json")
        self.assertEqual(registry.registry_hash, again.registry_hash)
        self.assertEqual(len(registry.registry_hash), 64)

    def test_unknown_required_major_fails_closed_but_optional_is_directory_only(self) -> None:
        registry = FormatCapabilityRegistry.load(self.repo / "config/format_capabilities.json")
        with self.assertRaises(UnknownRequiredSchema):
            registry.classify_event("SITINA_UNKNOWN_REQUIRED_V9", required=True)
        decision = registry.classify_event("SITINA_UNKNOWN_OPTIONAL_V9", required=False)
        self.assertFalse(decision.semantic_support)
        self.assertTrue(decision.event_directory_only)

    def test_upcaster_is_deterministic_pure_and_audited(self) -> None:
        stored = {
            "schema": "SITINA_RUN_CHECKPOINT_V1",
            "checkpoint_id": "checkpoint-1",
            "run_id": "run-1",
            "journal_from_position": 12,
            "journal_to_position": 19,
            "cas_refs": ["cas:" + "a" * 64, "cas:" + "b" * 64],
            "frontier_commitment": "c" * 64,
        }
        registry = UpcasterRegistry.default()
        first = registry.upcast(stored)
        second = registry.upcast(json.loads(json.dumps(stored)))
        self.assertEqual(first.canonical_document, second.canonical_document)
        self.assertEqual(first.audit_record, second.audit_record)
        self.assertEqual(first.canonical_document["schema"], "SITINA_RUN_CHECKPOINT_V2")
        self.assertEqual(first.canonical_document["run_id"], "run-1")
        RunCheckpointV2.model_validate(first.canonical_document)
        self.assertNotIn("upcasted_at", first.audit_record)
        self.assertEqual(len(first.audit_record["upcaster_hash"]), 64)

    def test_every_advertised_upcaster_exists_and_produces_a_strict_canonical_document(self) -> None:
        registry = UpcasterRegistry.default()
        self.assertEqual(
            {item["name"] for item in registry.manifest},
            {
                "journal-event-v1-to-v2",
                "checkpoint-v1-to-v2",
                "evidence-v1-to-v2",
                "agent-context-v1-to-v2",
            },
        )
        ref = lambda character: "cas:" + character * 64
        evidence = registry.upcast(
            {
                "schema": "SITINA_RUN_EVIDENCE_V1",
                "evidence_id": "evidence-1",
                "run_id": "run-1",
                "journal_from_position": 1,
                "journal_to_position": 8,
                "terminal_event_id": "event-terminal",
                "terminal_event_hash": "a" * 64,
                "checkpoint_ref": ref("b"),
                "input_refs": [ref("c")],
                "output_refs": [ref("d")],
                "tool_record_refs": [ref("e")],
                "provider_call_ids": ["call-1"],
                "evidence_policy_hash": "f" * 64,
            }
        )
        RunEvidenceV2.model_validate(evidence.canonical_document)
        context = registry.upcast(
            {
                "schema": "SITINA_AGENT_CONTEXT_MANIFEST_V1",
                "run_id": "run-1",
                "call_id": "call-1",
                "agent_id": "agent-1",
                "prompt_template_ref": ref("1"),
                "base_project_context_ref": None,
                "conversation_state_ref": ref("2"),
                "retrieved_memory_refs": [ref("3")],
                "blackboard_base_ref": None,
                "delta_refs": [ref("4")],
                "rendered_input_hash": "5" * 64,
            }
        )
        AgentContextManifestV2.model_validate(context.canonical_document)
        event = registry.upcast(
            {
                "schema": "SITINA_JOURNAL_EVENT_V1",
                "event_id": "event-1",
                "event_type": "future.optional",
                "tenant_id": "tenant-1",
                "stream_id": "stream-1",
                "stream_version": 1,
                "position": 1,
                "occurred_at": "2026-07-18T00:00:00Z",
                "payload": {"schema": "FUTURE_OPTIONAL_V1"},
                "object_refs": [],
            }
        )
        self.assertEqual(event.canonical_document["projection_requirement"], "OPTIONAL")

    def test_feature_activation_requires_all_live_readers_and_journal_control_event(self) -> None:
        leases = CompatibilityLeaseRegistry(self.home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="new-reader",
                binary_version="2.0.0",
                reader_capabilities=("checkpoint-v2", "cas-zstd"),
                writer_capabilities=("checkpoint-v1",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T00:10:00Z",
                fencing_token=1,
            )
        )
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="old-reader",
                binary_version="1.0.0",
                reader_capabilities=("checkpoint-v1",),
                writer_capabilities=("checkpoint-v1",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T00:10:00Z",
                fencing_token=1,
            )
        )
        activations = FeatureActivationRegistry()
        with self.assertRaises(FeatureGateError):
            activations.prepare(
                "checkpoint_v2_write",
                required_reader_capabilities=("checkpoint-v2",),
                leases=leases,
                now="2026-07-18T00:05:00Z",
                journal_position=50,
                journal_control_event=None,
            )
        leases.release("old-reader", fencing_token=1)
        prepared = activations.prepare(
            "checkpoint_v2_write",
            required_reader_capabilities=("checkpoint-v2",),
            leases=leases,
            now="2026-07-18T00:05:00Z",
            journal_position=51,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "event_type": "runtime.feature-prepared",
                "feature": "checkpoint_v2_write",
            },
        )
        self.assertEqual(prepared.state, "PREPARED")
        activated = activations.activate(
            "checkpoint_v2_write",
            rollback_floor_version=2,
            journal_position=52,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "event_type": "runtime.feature-activated",
                "feature": "checkpoint_v2_write",
            },
        )
        self.assertFalse(activated.rollback_safe_after_first_write)
        with self.assertRaises(FeatureGateError):
            activations.assert_writer_compatible(binary_version=1, capabilities=("checkpoint-v1",))

    def test_expired_lease_and_stale_fence_cannot_write_or_replace(self) -> None:
        leases = CompatibilityLeaseRegistry(self.home)
        first = RuntimeCompatibilityLease.build(
            process_id="writer",
            binary_version="2.0.0",
            reader_capabilities=("checkpoint-v2",),
            writer_capabilities=("checkpoint-v2",),
            started_at="2026-07-18T00:00:00Z",
            lease_expires_at="2026-07-18T00:01:00Z",
            fencing_token=7,
        )
        leases.register(first)
        with self.assertRaises(FeatureGateError):
            leases.assert_writer("writer", fencing_token=7, now="2026-07-18T00:02:00Z")
        with self.assertRaises(StaleFencingToken):
            leases.register(
                RuntimeCompatibilityLease.build(
                    process_id="writer",
                    binary_version="2.0.0",
                    reader_capabilities=("checkpoint-v2",),
                    writer_capabilities=("checkpoint-v2",),
                    started_at="2026-07-18T00:02:00Z",
                    lease_expires_at="2026-07-18T00:03:00Z",
                    fencing_token=7,
                )
            )

    def test_feature_activation_replays_from_journal_order_and_detects_ungated_first_write(self) -> None:
        from types import SimpleNamespace

        prepared = SimpleNamespace(
            position=10,
            event_type="runtime.feature-prepared",
            payload={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "feature": "checkpoint_v2_write",
                "required_reader_capabilities": ["checkpoint-v2"],
            },
        )
        activated = SimpleNamespace(
            position=11,
            event_type="runtime.feature-activated",
            payload={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "feature": "checkpoint_v2_write",
                "rollback_floor_version": 2,
            },
        )
        first_write = SimpleNamespace(
            position=12,
            event_type="run.checkpoint-published",
            payload={"schema": "SITINA_RUN_CHECKPOINT_PUBLISHED_V2"},
        )
        replayed = FeatureActivationRegistry.from_journal_events((prepared, activated, first_write))
        state = replayed.state("checkpoint_v2_write")
        self.assertIsNotNone(state)
        self.assertEqual(state.first_write_position, 12)
        with self.assertRaises(FeatureGateError):
            FeatureActivationRegistry.from_journal_events((first_write,))

    def test_capability_file_rejects_duplicate_formats(self) -> None:
        path = self.home / "duplicates.json"
        value = json.loads((self.repo / "config/format_capabilities.json").read_text(encoding="utf-8"))
        value["formats"].append(dict(value["formats"][0]))
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(CapabilityError):
            FormatCapabilityRegistry.load(path)


if __name__ == "__main__":
    unittest.main()
