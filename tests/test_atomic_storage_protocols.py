from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sitina.cas.packs import MetadataPackReader, MetadataPackWriter, PackWriteDisabled
from sitina.effects.durable import DurableProviderEffect, EffectIdentity, EffectRecoveryError
from sitina.projections.generations import ProjectionGenerationPublisher, ProjectionGenerationReader
from sitina.storage.leases import DurableLeaseRegistry, LeaseFenceError
from sitina.storage.transactions import CASJournalTransaction, DurableOperationStore, SimulatedOperationCrash
from sitina.trash.transactions import TrashDeletionCoordinator


class _FakeTrashAdapter:
    def __init__(self) -> None:
        self.moves: dict[str, str] = {}
        self.calls = 0

    def move_to_trash(self, bundle: Path, *, idempotency_key: str) -> str:
        self.calls += 1
        return self.moves.setdefault(idempotency_key, f"fake-trash://{bundle.name}")


class AtomicStorageProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("1\n", encoding="utf-8")

    def test_cas_is_durable_before_journal_and_resume_is_idempotent(self) -> None:
        calls: list[str] = []
        crashed = False

        def fault(boundary: str) -> None:
            nonlocal crashed
            if boundary == "after_cas_publish" and not crashed:
                crashed = True
                raise SimulatedOperationCrash(boundary)

        store = DurableOperationStore(self.home)
        transaction = CASJournalTransaction(store, fault_injector=fault)
        with self.assertRaises(SimulatedOperationCrash):
            transaction.commit(
                operation_id="message-1",
                command_hash="a" * 64,
                publish_cas=lambda: calls.append("publish") or {"body_ref": "cas:" + "b" * 64},
                verify_cas=lambda receipt: calls.append("verify") or receipt,
                append_journal=lambda proof: calls.append("journal") or {"position": 7, "body_ref": proof["body_ref"]},
                release_staging=lambda: calls.append("release"),
                update_projection=lambda receipt: calls.append("projection"),
            )
        self.assertEqual(calls, ["publish"])
        self.assertEqual(store.load("message-1").state, "CAS_PUBLISHED")

        completed = CASJournalTransaction(store).commit(
            operation_id="message-1",
            command_hash="a" * 64,
            publish_cas=lambda: calls.append("publish-again") or {},
            verify_cas=lambda receipt: calls.append("verify") or receipt,
            append_journal=lambda proof: calls.append("journal") or {"position": 7, "body_ref": proof["body_ref"]},
            release_staging=lambda: calls.append("release"),
            update_projection=lambda receipt: calls.append("projection"),
        )
        self.assertEqual(completed.state, "COMPLETED")
        self.assertEqual(calls, ["publish", "verify", "journal", "release", "projection"])

    def test_provider_unknown_outcome_never_blindly_resends(self) -> None:
        identity = EffectIdentity.build(
            session_id="session-1",
            turn_index=3,
            message_id="message-3",
            logical_call_id="call-1",
            provider_profile="gpt",
            request_hash="c" * 64,
        )
        effect = DurableProviderEffect(self.home)
        requested = effect.request(identity)
        self.assertEqual(requested.state, "NOT_SENT")
        effect.begin_send(identity.effect_id, fencing_token=1)
        unknown = effect.mark_outcome_unknown(identity.effect_id, fencing_token=1)
        self.assertEqual(unknown.state, "SENT_OUTCOME_UNKNOWN")
        self.assertFalse(effect.may_physically_send(identity.effect_id))
        with self.assertRaises(EffectRecoveryError):
            effect.begin_send(identity.effect_id, fencing_token=1)
        published = effect.record_result_cas_published(
            identity.effect_id,
            fencing_token=1,
            result_ref="cas:" + "d" * 64,
        )
        self.assertEqual(published.state, "RESULT_CAS_PUBLISHED")
        committed = effect.record_result_journal_committed(identity.effect_id, fencing_token=1, position=11)
        self.assertEqual(committed.state, "RESULT_JOURNAL_COMMITTED")

    def test_projection_pointer_is_v2_atomic_and_falls_back_to_previous(self) -> None:
        root = self.home / "projections"
        publisher = ProjectionGenerationPublisher(root)

        def build(name: str, value: str) -> Path:
            path = root / "building" / f"{name}.sqlite"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE values_table(id INTEGER PRIMARY KEY,value TEXT NOT NULL)")
            connection.execute("INSERT INTO values_table VALUES(1,?)", (value,))
            connection.commit()
            connection.close()
            return path

        first = publisher.publish(
            generation_id="generation-1",
            building_database=build("generation-1", "old"),
            authority_checkpoint_commitment="1" * 64,
            journal_frontier=10,
            schema_coverage_hash="2" * 64,
            created_at="2026-07-18T00:00:00Z",
        )
        second = publisher.publish(
            generation_id="generation-2",
            building_database=build("generation-2", "new"),
            authority_checkpoint_commitment="3" * 64,
            journal_frontier=12,
            schema_coverage_hash="4" * 64,
            created_at="2026-07-18T00:01:00Z",
        )
        self.assertEqual(second["schema"], "PROJECTION_GENERATION_POINTER_V2")
        self.assertEqual(second["authority_checkpoint_commitment"], "3" * 64)
        self.assertEqual(len(list((root / "current").glob("*.sqlite"))), 1)
        self.assertEqual(len(list((root / "previous").glob("*.sqlite"))), 1)
        reader = ProjectionGenerationReader(root)
        selected = reader.select(authority_checkpoint_commitments={"1" * 64, "3" * 64})
        self.assertEqual(selected.pointer["generation_id"], "generation-2")
        Path(selected.database_path).write_bytes(b"damaged")
        fallback = reader.select(authority_checkpoint_commitments={"1" * 64, "3" * 64})
        self.assertTrue(fallback.used_previous)
        self.assertEqual(fallback.pointer["generation_id"], "generation-1")
        self.assertNotEqual(first["semantic_checksum"], "")

    def test_pack_tail_is_invisible_until_durable_index_switch(self) -> None:
        writer = MetadataPackWriter(self.home, kind="alias", write_enabled=False)
        with self.assertRaises(PackWriteDisabled):
            writer.append("alias-1", {"object_id": "a" * 64, "envelope_id": "b" * 64})

        def crash(boundary: str) -> None:
            if boundary == "after_pack_fsync":
                raise SimulatedOperationCrash(boundary)

        writer = MetadataPackWriter(self.home, kind="alias", write_enabled=True, fault_injector=crash)
        with self.assertRaises(SimulatedOperationCrash):
            writer.append("alias-1", {"object_id": "a" * 64, "envelope_id": "b" * 64})
        reader = MetadataPackReader(self.home, kind="alias")
        self.assertIsNone(reader.get("alias-1"))
        self.assertEqual(writer.reconcile_candidates(), ("alias-1",))
        MetadataPackWriter(self.home, kind="alias", write_enabled=True).reconcile()
        self.assertEqual(reader.get("alias-1")["envelope_id"], "b" * 64)

    def test_trash_move_crash_reconciles_before_session_deleted(self) -> None:
        adapter = _FakeTrashAdapter()
        events: list[str] = []
        crashed = False

        def fault(boundary: str) -> None:
            nonlocal crashed
            if boundary == "after_trash_move" and not crashed:
                crashed = True
                raise SimulatedOperationCrash(boundary)

        coordinator = TrashDeletionCoordinator(self.home, adapter=adapter, fault_injector=fault)
        refs = ("cas:" + "e" * 64,)
        with self.assertRaises(SimulatedOperationCrash):
            coordinator.delete(
                session_id="session-exact",
                title="Same title",
                journal_frontier=20,
                object_refs=refs,
                append_event=lambda event: events.append(event["event_type"]) or len(events),
                confirmed=True,
            )
        self.assertEqual(events, ["session.deletion-prepared"])
        receipt = TrashDeletionCoordinator(self.home, adapter=adapter).delete(
            session_id="session-exact",
            title="Same title",
            journal_frontier=20,
            object_refs=refs,
            append_event=lambda event: events.append(event["event_type"]) or len(events),
            confirmed=True,
        )
        self.assertEqual(receipt["state"], "DELETION_COMMITTED")
        self.assertEqual(events, ["session.deletion-prepared", "session.deleted"])
        self.assertEqual(adapter.calls, 2)
        manifest = json.loads((self.home / receipt["bundle_manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["session_id"], "session-exact")
        self.assertEqual(manifest["object_refs"], list(refs))
        self.assertNotIn("body", manifest)

    def test_durable_resource_lease_rejects_stale_fencing_token(self) -> None:
        leases = DurableLeaseRegistry(self.home)
        first = leases.acquire(
            resource_type="journal-writer",
            resource_id="journal-1",
            holder_id="process-1",
            issued_at="2026-07-18T00:00:00Z",
            expires_at="2026-07-18T00:05:00Z",
        )
        self.assertEqual(first.fencing_token, 1)
        leases.release(first.lease_id, fencing_token=1)
        second = leases.acquire(
            resource_type="journal-writer",
            resource_id="journal-1",
            holder_id="process-2",
            issued_at="2026-07-18T00:06:00Z",
            expires_at="2026-07-18T00:10:00Z",
        )
        self.assertEqual(second.fencing_token, 2)
        with self.assertRaises(LeaseFenceError):
            leases.assert_holder(first.lease_id, fencing_token=1, now="2026-07-18T00:07:00Z")


if __name__ == "__main__":
    unittest.main()
