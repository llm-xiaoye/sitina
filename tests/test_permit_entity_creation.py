from __future__ import annotations

import datetime as dt
import unittest

from sitina.protocols.entity_creation import (
    CreationDisposition, EntityCreationError, EntityKind, begin_entity_creation, reconcile_source, target_create,
)
from sitina.protocols.permits import PermitPurpose
from sitina.protocols.run import RunAggregate, RunProtocolError, RunState


def setup():
    run, _ = RunAggregate.open("run-1")
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    return run.grant_permit(expected_stream_version=1, purpose=PermitPurpose.ENTITY_CREATE, scope="task", count=2, max_depth=2, expires_at=expiry)[:2]


def begin(run, permit):
    return begin_entity_creation(run, permit, process_id="process-1", entity_id="task-1", entity_kind=EntityKind.TASK, create_command_id="create-command-1", request_hash="11" * 32, idempotency_binding="binding-1")


class PermitEntityCreationTests(unittest.TestCase):
    def test_binding_is_frozen_in_run_permit_transaction_and_blocks_closing(self) -> None:
        run, permit = setup(); updated, _, process, events = begin(run, permit)
        self.assertIn(process.process_id, updated.pending_creation_processes)
        self.assertEqual(events[1]["binding_hash"], process.binding_hash)
        closing, _ = updated.begin_closing(expected_stream_version=updated.stream_version)
        with self.assertRaises(RunProtocolError): closing.terminal(RunState.SUCCEEDED, expected_stream_version=closing.stream_version)

    def test_created_first_forces_forward_confirmation(self) -> None:
        run, permit = setup(); run, _, process, _ = begin(run, permit)
        created, _ = target_create(process, canonical_stream_state="NO_STREAM", canonical_request_hash=None)
        self.assertEqual(created.disposition, CreationDisposition.CREATED)
        with self.assertRaises(EntityCreationError): reconcile_source(run, created, canonical_target_state="TOMBSTONED", canonical_request_hash=created.request_hash)
        run, confirmed, _ = reconcile_source(run, created, canonical_target_state="CREATED", canonical_request_hash=created.request_hash)
        self.assertEqual(confirmed.disposition, CreationDisposition.CONFIRMED); self.assertEqual(run.pending_creation_processes, ())

    def test_tombstone_first_releases_only_after_canonical_query(self) -> None:
        run, permit = setup(); run, _, process, _ = begin(run, permit)
        tombstone, _ = target_create(process, canonical_stream_state="NO_STREAM", canonical_request_hash=None, deterministic_rejection="invalid-spec")
        with self.assertRaises(EntityCreationError): reconcile_source(run, tombstone, canonical_target_state="NO_STREAM", canonical_request_hash=tombstone.request_hash)
        run, released, _ = reconcile_source(run, tombstone, canonical_target_state="TOMBSTONED", canonical_request_hash=tombstone.request_hash)
        self.assertEqual(released.disposition, CreationDisposition.RELEASED); self.assertEqual(run.pending_creation_processes, ())

    def test_ack_loss_projection_lag_and_duplicate_replay_use_same_command(self) -> None:
        run, permit = setup(); _, _, process, _ = begin(run, permit)
        created, first = target_create(process, canonical_stream_state="NO_STREAM", canonical_request_hash=None)
        replayed, second = target_create(process, canonical_stream_state="CREATED", canonical_request_hash=process.request_hash)
        self.assertEqual(first["create_command_id"], second["create_command_id"])
        self.assertEqual(created.create_command_id, replayed.create_command_id)

    def test_same_entity_id_different_hash_is_integrity_incident(self) -> None:
        run, permit = setup(); _, _, process, _ = begin(run, permit)
        incident, event = target_create(process, canonical_stream_state="CREATED", canonical_request_hash="22" * 32)
        self.assertEqual(incident.disposition, CreationDisposition.INTEGRITY_INCIDENT)
        self.assertIn("INTEGRITY_INCIDENT", event["schema"])

    def test_task_graph_node_cannot_be_independent_entity(self) -> None:
        run, permit = setup()
        with self.assertRaises(EntityCreationError):
            begin_entity_creation(run, permit, process_id="p", entity_id="task-graph-node/n1", entity_kind=EntityKind.TASK_GRAPH_NODE, create_command_id="c", request_hash="11" * 32, idempotency_binding="b")


if __name__ == "__main__": unittest.main()
