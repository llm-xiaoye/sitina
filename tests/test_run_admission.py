from __future__ import annotations

import datetime as dt
import unittest

from sitina.protocols.permits import PermitError, PermitPurpose
from sitina.protocols.run import RunAggregate, RunProtocolError, RunState


def future(): return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z")


class RunAdmissionTests(unittest.TestCase):
    def test_grant_and_begin_closing_serialize_on_run_stream_cas(self) -> None:
        run, _ = RunAggregate.open("run-1")
        granted, permit, _ = run.grant_permit(expected_stream_version=1, purpose=PermitPurpose.ENTITY_CREATE, scope="task", count=1, max_depth=2, expires_at=future())
        with self.assertRaises(RunProtocolError): run.begin_closing(expected_stream_version=granted.stream_version)
        closing, _ = granted.begin_closing(expected_stream_version=granted.stream_version)
        self.assertEqual(closing.state, RunState.CLOSING)
        with self.assertRaises(PermitError):
            permit.consume(current_admission_generation=closing.admission_generation, purpose=PermitPurpose.ENTITY_CREATE, scope="task", depth=0, idempotency_binding="binding-1")

    def test_closing_uses_blocking_facts_not_a_business_state(self) -> None:
        run, _ = RunAggregate.open("run-1"); closing, _ = run.begin_closing(expected_stream_version=1)
        blocked = closing.add_blocker("fact-1")
        self.assertEqual(blocked.state, RunState.CLOSING)
        self.assertNotIn("CLOSING_BLOCKED", {state.value for state in RunState})
        with self.assertRaises(RunProtocolError): blocked.terminal(RunState.SUCCEEDED, expected_stream_version=2)
        terminal, _ = blocked.remove_blocker("fact-1").terminal(RunState.SUCCEEDED, expected_stream_version=2)
        self.assertEqual(terminal.state, RunState.SUCCEEDED)

    def test_closing_permit_purpose_scope_count_and_depth_are_enforced(self) -> None:
        run, _ = RunAggregate.open("run-1"); closing, _ = run.begin_closing(expected_stream_version=1)
        closing, permit, _ = closing.grant_permit(expected_stream_version=2, purpose=PermitPurpose.CLOSING_ENTITY_CREATE, scope="obligation", count=1, max_depth=1, expires_at=future())
        with self.assertRaises(PermitError): permit.consume(current_admission_generation=closing.admission_generation, purpose=PermitPurpose.CLOSING_ENTITY_CREATE, scope="task", depth=0, idempotency_binding="x")
        with self.assertRaises(PermitError): permit.consume(current_admission_generation=closing.admission_generation, purpose=PermitPurpose.CLOSING_ENTITY_CREATE, scope="obligation", depth=2, idempotency_binding="x")
        consumed, _ = permit.consume(current_admission_generation=closing.admission_generation, purpose=PermitPurpose.CLOSING_ENTITY_CREATE, scope="obligation", depth=1, idempotency_binding="x")
        with self.assertRaises(PermitError): consumed.consume(current_admission_generation=closing.admission_generation, purpose=PermitPurpose.CLOSING_ENTITY_CREATE, scope="obligation", depth=1, idempotency_binding="y")

    def test_abort_closing_rotates_generation(self) -> None:
        run, _ = RunAggregate.open("run-1"); closing, _ = run.begin_closing(expected_stream_version=1); active, _ = closing.abort_closing(expected_stream_version=2)
        self.assertEqual(active.state, RunState.ACTIVE); self.assertEqual(active.admission_generation, 3)


if __name__ == "__main__": unittest.main()
