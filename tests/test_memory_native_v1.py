from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from sitina.cas.crypto import encrypt_object
from sitina.cas.local import LocalCAS
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.memory.native import (
    EpisodeRepository,
    MemoryACL,
    MemoryAccessDenied,
    MemoryDocument,
    MemoryRepository,
    MemoryStateError,
)
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class JournalNativeMemoryV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")
        self.keys = InMemoryKeyProvider()
        self.auth = JournalAuthProvider(self.keys)
        self.cas = LocalCAS.open(self.home, self.keys)
        self.journal = LocalJournal.open(self.home, self.auth)
        leases = CompatibilityLeaseRegistry(self.home)
        leases.register(
            RuntimeCompatibilityLease.build(
                process_id="memory-v1-test-writer",
                binary_version="2.0.0",
                reader_capabilities=("memory-v1",),
                writer_capabilities=("memory-v1",),
                started_at="2026-07-18T00:00:00Z",
                lease_expires_at="2026-07-18T01:00:00Z",
                fencing_token=1,
            )
        )
        self.activations = FeatureActivationRegistry()
        self.activations.prepare(
            "memory_v1_write",
            required_reader_capabilities=("memory-v1",),
            leases=leases,
            now="2026-07-18T00:00:01Z",
            journal_position=1,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_PREPARED_V1",
                "event_type": "runtime.feature-prepared",
                "feature": "memory_v1_write",
            },
        )
        self.activations.activate(
            "memory_v1_write",
            rollback_floor_version=2,
            journal_position=2,
            journal_control_event={
                "schema": "RUNTIME_FEATURE_ACTIVATED_V1",
                "event_type": "runtime.feature-activated",
                "feature": "memory_v1_write",
            },
        )
        self.memory = MemoryRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        )

    def tearDown(self) -> None:
        self.journal.close()

    @staticmethod
    def _acl(*, owner: str = "memory-agent", reader: str = "controller-agent", reviewer: str = "user-1") -> MemoryACL:
        return MemoryACL(
            readers=tuple(sorted({owner, reader, reviewer})),
            writers=(owner,),
            reviewers=(reviewer,),
        )

    def _candidate(
        self,
        memory_id: str,
        *,
        scope: str = "project_shared",
        owner_id: str = "project/example",
        namespace: str = "project/example/auth",
        supersedes: tuple[str, ...] = (),
        acl: MemoryACL | None = None,
    ) -> MemoryDocument:
        return self.memory.create_candidate(
            memory_id=memory_id,
            scope=scope,
            owner_id=owner_id,
            namespace=namespace,
            content=f"durable lesson for {memory_id}",
            source_event_ids=("event-source-1",),
            source_run_ids=("run-source-1",),
            evidence_refs=(),
            confidence=0.86,
            sensitivity="low",
            valid_from="2026-07-18T00:00:00Z",
            expires_at=None,
            retention_policy="until-superseded",
            supersedes=supersedes,
            acl=acl or self._acl(),
            actor="memory-agent",
        )

    def test_schema_is_strict_candidate_is_not_accepted_and_body_is_one_cas_object(self) -> None:
        with self.assertRaises(ValidationError):
            MemoryDocument.model_validate(
                {
                    "schema": "SITINA_MEMORY_V1",
                    "memory_id": "memory-extra",
                    "scope": "project_shared",
                    "owner_id": "project/example",
                    "namespace": "project/example/auth",
                    "content_ref": "cas:" + "a" * 64,
                    "content_hash": "b" * 64,
                    "confidence": 1.0,
                    "sensitivity": "low",
                    "valid_from": "2026-07-18T00:00:00Z",
                    "retention_policy": "until-superseded",
                    "acl": {"readers": ["reader"], "writers": ["writer"], "reviewers": ["reviewer"]},
                    "unexpected": True,
                }
            )

        candidate = self._candidate("memory-one")
        self.assertEqual(candidate.status, "candidate")
        self.assertEqual(self.memory.retrieve(actor="controller-agent"), ())
        events = tuple(self.journal.iter_events(0))
        created = next(event for event in events if event.event_type == "memory.candidate-created")
        self.assertNotIn("content", created.payload)
        self.assertNotIn("durable lesson", str(created.payload))
        self.assertEqual(created.object_refs, (candidate.content_ref,))
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), 1)
        duplicate = self._candidate("memory-one")
        self.assertEqual(duplicate.content_ref, candidate.content_ref)
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), 1)

    def test_memory_v1_writer_fails_before_cas_without_journal_feature_activation(self) -> None:
        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        disabled = MemoryRepository(self.journal, self.cas, self.keys)
        with self.assertRaises(MemoryStateError):
            disabled.create_candidate(
                memory_id="memory-gate-denied",
                scope="project_shared",
                owner_id="project/example",
                namespace="project/example/auth",
                content="must not be published",
                source_event_ids=(),
                source_run_ids=(),
                evidence_refs=(),
                confidence=0.5,
                sensitivity="low",
                valid_from="2026-07-18T00:00:00Z",
                expires_at=None,
                retention_policy="until-superseded",
                supersedes=(),
                acl=self._acl(),
                actor="memory-agent",
            )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before)

    def test_full_state_machine_and_default_retrieval_excludes_noncurrent_memory(self) -> None:
        first = self._candidate("memory-old")
        accepted = self.memory.transition(
            first.memory_id,
            "accepted",
            actor="user-1",
            occurred_at="2026-07-18T00:01:00Z",
            reason_code="review-approved",
        )
        self.assertEqual(accepted.status, "accepted")
        self.assertEqual([item.memory_id for item in self.memory.retrieve(actor="controller-agent")], ["memory-old"])
        self.assertEqual([item["root_id"] for item in self.memory.active_roots()], ["memory-old"])

        replacement = self._candidate("memory-new", supersedes=("memory-old",))
        self.memory.transition(
            replacement.memory_id,
            "accepted",
            actor="user-1",
            occurred_at="2026-07-18T00:02:00Z",
            reason_code="review-approved",
        )
        old = self.memory.transition(
            first.memory_id,
            "superseded",
            actor="user-1",
            occurred_at="2026-07-18T00:03:00Z",
            reason_code="replacement-accepted",
            superseded_by="memory-new",
        )
        self.assertEqual(old.status, "superseded")
        self.assertEqual(old.superseded_by, "memory-new")
        self.assertEqual([item.memory_id for item in self.memory.retrieve(actor="controller-agent")], ["memory-new"])
        self.assertEqual([item["root_id"] for item in self.memory.active_roots()], ["memory-new"])
        self.memory.transition(
            first.memory_id,
            "revoked",
            actor="user-1",
            occurred_at="2026-07-18T00:04:00Z",
            reason_code="source-revoked",
        )
        rejected = self._candidate("memory-rejected")
        self.assertEqual(
            self.memory.transition(
                rejected.memory_id,
                "rejected",
                actor="user-1",
                occurred_at="2026-07-18T00:05:00Z",
                reason_code="not-reusable",
            ).status,
            "rejected",
        )
        expiring = self._candidate("memory-expiring")
        self.memory.transition(
            expiring.memory_id,
            "accepted",
            actor="user-1",
            occurred_at="2026-07-18T00:06:00Z",
            reason_code="review-approved",
        )
        self.assertEqual(
            self.memory.transition(
                expiring.memory_id,
                "expired",
                actor="user-1",
                occurred_at="2026-07-18T00:07:00Z",
                reason_code="retention-ended",
            ).status,
            "expired",
        )
        with self.assertRaises(MemoryStateError):
            self.memory.transition(
                rejected.memory_id,
                "accepted",
                actor="user-1",
                occurred_at="2026-07-18T00:08:00Z",
                reason_code="invalid-reversal",
            )

    def test_read_write_review_acl_is_enforced_for_all_four_scopes(self) -> None:
        cases = (
            ("agent_private", "agent/coder", "agent/coder/security"),
            ("run_shared", "run/run-22", "run/run-22/lessons"),
            ("project_shared", "project/example", "project/example/auth"),
            ("user", "user/alice", "user/alice/preferences"),
        )
        for index, (scope, owner, namespace) in enumerate(cases):
            memory_id = f"memory-scope-{index}"
            acl = self._acl()
            document = self._candidate(memory_id, scope=scope, owner_id=owner, namespace=namespace, acl=acl)
            with self.assertRaises(MemoryAccessDenied):
                self.memory.get(document.memory_id, actor="intruder")
            with self.assertRaises(MemoryAccessDenied):
                self.memory.transition(
                    document.memory_id,
                    "accepted",
                    actor="memory-agent",
                    occurred_at="2026-07-18T00:01:00Z",
                    reason_code="writer-is-not-reviewer",
                )
            self.memory.transition(
                document.memory_id,
                "accepted",
                actor="user-1",
                occurred_at="2026-07-18T00:02:00Z",
                reason_code="review-approved",
            )
            recovered, content = self.memory.get(document.memory_id, actor="controller-agent")
            self.assertEqual(recovered.scope, scope)
            self.assertIn(memory_id, content or "")

        with self.assertRaises(MemoryAccessDenied):
            self.memory.create_candidate(
                memory_id="memory-unauthorized-write",
                scope="project_shared",
                owner_id="project/example",
                namespace="project/example/auth",
                content="denied",
                source_event_ids=(),
                source_run_ids=(),
                evidence_refs=(),
                confidence=0.5,
                sensitivity="low",
                valid_from="2026-07-18T00:00:00Z",
                expires_at=None,
                retention_policy="until-superseded",
                supersedes=(),
                acl=self._acl(),
                actor="intruder",
            )

    def test_episode_references_existing_run_objects_and_only_adds_lesson(self) -> None:
        goal = self.cas.publish_verified(encrypt_object(b"run goal", self.keys, tenant_id="run-tenant", purpose="run-goal"))
        evidence = self.cas.publish_verified(encrypt_object(b"terminal evidence", self.keys, tenant_id="run-tenant", purpose="run-evidence"))
        command = CommandEnvelope(
            "cmd-run-source",
            "run-tenant",
            "run/run-episode",
            "run.complete",
            "runner",
            "2026-07-18T00:00:00Z",
            {"run_id": "run-episode"},
        )
        event = EventEnvelope(
            "event-run-source",
            "run.completed",
            "run-tenant",
            "run/run-episode",
            0,
            0,
            "2026-07-18T00:00:00Z",
            {
                "run_id": "run-episode",
                "goal_ref": goal.object_ref.reference_id,
                "terminal_evidence_ref": evidence.object_ref.reference_id,
            },
            tuple(sorted((goal.object_ref.reference_id, evidence.object_ref.reference_id))),
        )
        self.journal.append(command, 0, [event], object_reference_proofs=(goal, evidence))
        before = len(list((self.home / "cas/objects").rglob("*.obj")))
        episode = EpisodeRepository(
            self.journal,
            self.cas,
            self.keys,
            feature_activations=self.activations,
        ).create(
            episode_id="episode-run-1",
            source_run_id="run-episode",
            goal_ref=goal.object_ref,
            action_event_range=(1, 1),
            terminal_evidence_ref=evidence.object_ref,
            outcome="succeeded",
            failure_reason_code=None,
            lesson="Reuse the verified rollback check.",
            occurred_at="2026-07-18T00:01:00Z",
        )
        self.assertEqual(len(list((self.home / "cas/objects").rglob("*.obj"))), before + 1)
        episode_event = next(event for event in self.journal.iter_events(1) if event.event_type == "memory.episode-created")
        self.assertEqual(episode_event.payload["action_event_range"], [1, 1])
        self.assertNotIn("run_body", episode_event.payload)
        self.assertNotIn("lesson", episode_event.payload)
        self.assertEqual(episode.goal_ref, goal.object_ref.reference_id)


if __name__ == "__main__":
    unittest.main()
