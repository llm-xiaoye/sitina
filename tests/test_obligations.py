from __future__ import annotations

import unittest

from sitina.projections.schema import open_projection
from sitina.protocols.obligations import (
    ObligationAggregate,
    ObligationState,
    ProtocolRegistryProjection,
)
from sitina.protocols.permits import PermitPurpose
from sitina.protocols.run import RunAggregate


class ObligationTests(unittest.TestCase):
    def test_protocol_terminal_is_separate_from_obligation_satisfaction(self) -> None:
        obligation, _ = ObligationAggregate.create(
            "obligation-1", "run-1", "protocol-1", required_for_run_terminal=True
        )
        obligation, _ = obligation.record_protocol_terminal("11" * 32)
        self.assertEqual(obligation.state, ObligationState.OPEN)
        obligation, _ = obligation.satisfy("22" * 32)
        self.assertEqual(obligation.state, ObligationState.SATISFIED)

    def test_successor_plan_is_stable_and_uses_two_generic_creation_sagas(self) -> None:
        obligation, _ = ObligationAggregate.create(
            "obligation-1", "run-1", "protocol-1", required_for_run_terminal=True
        )
        obligation, plan, _ = obligation.require_successor("NO_CONSENSUS")
        duplicate, duplicate_plan, duplicate_event = obligation.require_successor("NO_CONSENSUS")
        self.assertEqual(duplicate, obligation)
        self.assertEqual(duplicate_plan, plan)
        self.assertEqual(duplicate_event["schema"], "OBLIGATION_SUCCESSOR_DUPLICATE_V1")
        run, _ = RunAggregate.open("run-1")
        run, obligation_permit, _ = run.grant_permit(
            expected_stream_version=run.stream_version,
            purpose=PermitPurpose.ENTITY_CREATE,
            scope="obligation",
            count=1,
            max_depth=1,
            expires_at="2099-01-01T00:00:00Z",
            permit_id="permit-obligation-1",
        )
        run, protocol_permit, _ = run.grant_permit(
            expected_stream_version=run.stream_version,
            purpose=PermitPurpose.ENTITY_CREATE,
            scope="protocol",
            count=1,
            max_depth=1,
            expires_at="2099-01-01T00:00:00Z",
            permit_id="permit-protocol-1",
        )
        updated, processes, facts = plan.begin_creation_sagas(
            run, obligation_permit, protocol_permit
        )
        self.assertEqual(len(processes), 2)
        self.assertEqual(len(updated.pending_creation_processes), 2)
        self.assertEqual({fact["schema"] for fact in facts}, {"PERMIT_CONSUMED_V1", "ENTITY_CREATION_FROZEN_V1"})

    def test_protocol_registry_builds_only_from_created_and_terminal_events(self) -> None:
        projection = ProtocolRegistryProjection()
        projection = projection.apply(
            {"schema": "PROTOCOL_CREATED_V1", "protocol_id": "protocol-1", "run_id": "run-1"},
            source_position=1,
        )
        projection = projection.apply(
            {"schema": "OBLIGATION_CREATED_V1", "obligation_id": "obligation-1", "run_id": "run-1", "required_for_run_terminal": True},
            source_position=2,
        )
        self.assertEqual(projection.required_open_count("run-1"), 1)
        with self.assertRaises(Exception):
            projection.apply({"schema": "PROJECTION_GUESS_V1"}, source_position=3)
        projection = projection.apply(
            {"schema": "OBLIGATION_TERMINAL_V1", "obligation_id": "obligation-1", "state": "SATISFIED"},
            source_position=3,
        )
        self.assertEqual(projection.required_open_count("run-1"), 0)

    def test_projection_schema_has_protocol_and_obligation_registry(self) -> None:
        connection = open_projection(":memory:")
        try:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("protocol_registry", tables)
            self.assertIn("obligation_registry", tables)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
