from __future__ import annotations

import unittest

from sitina.effects.read_sessions import ReadEffectSession, ReadEffectSessionError


class ReadEffectSessionTests(unittest.TestCase):
    def test_each_query_has_distinct_effect_attempt_receipt_and_observation(self) -> None:
        session = ReadEffectSession.create("session-1", "mock.read", "principal-1", query_limit=2, expires_at=100)
        session, q1 = session.reserve("query-effect-1", "a" * 64, run_permit_id="permit-1", now=1)
        session, q2 = session.reserve("query-effect-2", "b" * 64, run_permit_id="permit-2", now=1)
        self.assertEqual(len({q1.effect_id, q2.effect_id, q1.attempt_id, q2.attempt_id, q1.receipt_id, q2.receipt_id, q1.observation_id, q2.observation_id}), 8)

    def test_session_slot_and_run_permit_bind_same_effect_and_hash(self) -> None:
        session = ReadEffectSession.create("session-2", "mock.read", "principal-1", query_limit=1, expires_at=100)
        session, slot = session.reserve("query-effect-1", "a" * 64, run_permit_id="permit-1", now=1)
        with self.assertRaises(ReadEffectSessionError):
            session.consume(slot.slot_id, effect_id="query-effect-1", request_hash="b" * 64)
        session, event = session.consume(slot.slot_id, effect_id="query-effect-1", request_hash="a" * 64)
        self.assertEqual(event["schema"], "READ_EFFECT_SESSION_SLOT_CONSUMED_V1")

    def test_tombstone_releases_but_successful_creation_consumes_slot(self) -> None:
        session = ReadEffectSession.create("session-3", "mock.read", "principal-1", query_limit=1, expires_at=100)
        session, slot = session.reserve("query-effect-1", "a" * 64, run_permit_id="permit-1", now=1)
        session, released = session.tombstone(slot.slot_id, effect_id="query-effect-1", request_hash="a" * 64)
        self.assertTrue(released["slot_released"])
        session, replacement = session.reserve("query-effect-2", "b" * 64, run_permit_id="permit-2", now=2)
        session, _ = session.consume(replacement.slot_id, effect_id="query-effect-2", request_hash="b" * 64)
        with self.assertRaises(ReadEffectSessionError):
            session.reserve("query-effect-3", "c" * 64, run_permit_id="permit-3", now=3)


if __name__ == "__main__":
    unittest.main()
