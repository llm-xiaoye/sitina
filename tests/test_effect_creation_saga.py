from __future__ import annotations

import unittest

from sitina.effects.creation import (
    CreationDisposition,
    EffectCreationIncident,
    EffectCreationSaga,
    EffectPermit,
)


class EffectCreationSagaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.saga = EffectCreationSaga()
        self.permit = EffectPermit("permit-1", "run-1", "effect-1", "a" * 64)

    def test_effect_requested_wins_no_stream_and_forces_source_confirmation(self) -> None:
        process, events = self.saga.begin(self.permit, process_id="process-1", command_id="create-1")
        self.assertEqual(events[0]["schema"], "PERMIT_CONSUMED_PENDING_EFFECT_V1")
        process, event = self.saga.apply_target(process, canonical_state="NO_STREAM")
        self.assertEqual(event["schema"], "EFFECT_REQUESTED_V1")
        self.assertEqual(process.disposition, CreationDisposition.EFFECT_REQUESTED)
        process, event = self.saga.reconcile(process, canonical_state="EFFECT_REQUESTED", canonical_request_hash="a" * 64)
        self.assertEqual(process.disposition, CreationDisposition.CONFIRMED)
        self.assertEqual(event["schema"], "EFFECT_CREATION_CONFIRMED_V1")

    def test_tombstone_must_win_before_permit_is_released(self) -> None:
        process, _ = self.saga.begin(self.permit, process_id="process-2", command_id="create-2")
        process, event = self.saga.apply_target(process, canonical_state="NO_STREAM", rejection="POLICY_DENIED")
        self.assertEqual(event["schema"], "EFFECT_CREATION_ABORTED_V1")
        self.assertEqual(process.disposition, CreationDisposition.TOMBSTONED)
        process, release = self.saga.reconcile(process, canonical_state="TOMBSTONED", canonical_request_hash="a" * 64)
        self.assertEqual(process.disposition, CreationDisposition.RELEASED)
        self.assertTrue(release["permit_released"])

    def test_lost_ack_reuses_stable_process_and_command(self) -> None:
        first, _ = self.saga.begin(self.permit, process_id="process-3", command_id="create-3")
        duplicate, events = self.saga.begin(self.permit, process_id="process-3", command_id="create-3")
        self.assertEqual(first, duplicate)
        self.assertEqual(events, ())

    def test_same_identity_different_request_hash_is_security_incident(self) -> None:
        self.saga.begin(self.permit, process_id="process-4", command_id="create-4")
        conflicting = EffectPermit("permit-1", "run-1", "effect-1", "b" * 64)
        with self.assertRaises(EffectCreationIncident) as raised:
            self.saga.begin(conflicting, process_id="process-4", command_id="create-4")
        self.assertEqual(raised.exception.fact["classification"], "SAME_ID_DIFFERENT_HASH")


if __name__ == "__main__":
    unittest.main()
