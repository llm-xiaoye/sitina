from __future__ import annotations

import unittest

from sitina.effects.audit import SideEffectAudit


def complete_events() -> list[dict]:
    return [
        {"schema": "EFFECT_REQUESTED_V1", "effect_id": "effect-1", "request_hash": "a" * 64, "permit_id": "permit-1"},
        {"schema": "EFFECT_ATTEMPT_CLAIMED_V1", "effect_id": "effect-1", "effect_attempt_id": "attempt-1", "task_fence": "task-fence", "dispatch_fence": "dispatch-fence"},
        {"schema": "EFFECT_INVOCATION_STARTED_V1", "effect_id": "effect-1", "effect_attempt_id": "attempt-1", "approval_id": "approval-1", "budget_bundle_id": "budget-1"},
        {"schema": "OBSERVATION_ADMITTED_V1", "effect_id": "effect-1", "effect_attempt_id": "attempt-1", "observation_id": "observation-1"},
        {"schema": "EFFECT_OUTCOME_ADVANCED_V1", "effect_id": "effect-1", "outcome": "SUCCEEDED", "settlement": "SETTLED", "basis": "AUTHORITATIVE_REMOTE_OBSERVATION"},
    ]


class SideEffectAuditTests(unittest.TestCase):
    def test_complete_effect_chain_has_no_audit_gap(self) -> None:
        report = SideEffectAudit.build(complete_events())
        self.assertTrue(report.passed)
        self.assertEqual(report.unexplained_in_flight, 0)
        self.assertEqual(report.unresolved_exposure, 0)

    def test_policy_unknown_is_reported_separately_from_confirmed_outcome(self) -> None:
        events = complete_events()
        events[-1] = {"schema": "EFFECT_OUTCOME_ADVANCED_V1", "effect_id": "effect-1", "outcome": "OUTCOME_UNKNOWN", "settlement": "SETTLED", "basis": "POLICY_DISPOSITION"}
        report = SideEffectAudit.build(events)
        self.assertEqual(report.confirmed_success_count, 0)
        self.assertEqual(report.policy_settled_unknown_count, 1)
        self.assertTrue(report.passed)

    def test_in_flight_secret_or_destruction_gap_fails_predicate(self) -> None:
        events = complete_events()[:3]
        events.append({"schema": "QUARANTINE_SECRET_POSITIVE_V1", "effect_id": "effect-1", "quarantine_id": "q-1"})
        report = SideEffectAudit.build(events)
        self.assertFalse(report.passed)
        self.assertGreater(report.unexplained_in_flight, 0)
        self.assertEqual(report.destruction_gap_count, 1)


if __name__ == "__main__":
    unittest.main()
