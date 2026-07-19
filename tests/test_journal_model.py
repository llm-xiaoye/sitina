from __future__ import annotations

import unittest

from sitina.commands.model import CommandEnvelope
from sitina.journal.model import CanonicalizationError, EventEnvelope, JournalModelError, parse_canonical_json


def command(**changes):
    values = {
        "command_id": "cmd-1",
        "tenant_id": "tenant-1",
        "stream_id": "stream-1",
        "command_type": "fixture.set",
        "actor_id": "actor-1",
        "issued_at": "2026-07-13T00:00:00Z",
        "received_at": "2026-07-13T00:00:01Z",
        "payload": {"x": 1},
    }
    values.update(changes)
    return CommandEnvelope(**values)


class _Auth:
    def authenticate(self, journal_id, epoch, event_hash):
        return "journal-auth:test:v1", "ab" * 32

    def verify(self, journal_id, epoch, key_id, event_hash, tag):
        return key_id == "journal-auth:test:v1" and tag == "ab" * 32


class JournalModelTests(unittest.TestCase):
    def test_command_hash_ignores_transport_received_at(self) -> None:
        left = command(received_at="2026-07-13T00:00:01Z")
        right = command(received_at="2026-07-13T00:00:02Z")
        self.assertEqual(left.command_request_hash, right.command_request_hash)

    def test_command_hash_changes_with_payload(self) -> None:
        self.assertNotEqual(command(payload={"x": 1}).command_request_hash, command(payload={"x": 2}).command_request_hash)

    def test_command_round_trip_rejects_unknown_fields_and_major(self) -> None:
        value = command()
        self.assertEqual(CommandEnvelope.from_stored_bytes(value.stored_bytes()), value)
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b'{"major":1,"unknown":true}', allowed_fields={"major"})
        with self.assertRaises(ValueError):
            command(major=2)

    def test_event_hash_excludes_auth_but_stored_bytes_bind_it(self) -> None:
        event = EventEnvelope(
            event_id="event-1", event_type="fixture.changed", tenant_id="tenant-1", stream_id="stream-1",
            stream_version=1, position=1, occurred_at="2026-07-13T00:00:00Z", payload={"x": 1},
        )
        sealed = event.seal(journal_id="journal-1", epoch=1, authenticator=_Auth())
        self.assertEqual(sealed.event_hash, event.computed_event_hash)
        self.assertTrue(sealed.verify(journal_id="journal-1", epoch=1, authenticator=_Auth()))
        self.assertEqual(EventEnvelope.from_stored_bytes(sealed.canonical_stored_bytes()), sealed)
        self.assertIn(b"journal_auth_tag", sealed.canonical_stored_bytes())

    def test_event_refs_must_be_sorted_unique_and_coordinates_nonnegative(self) -> None:
        with self.assertRaises(JournalModelError):
            EventEnvelope("e", "t", "tenant", "stream", 0, 0, "2026-07-13T00:00:00Z", {}, ("b", "a"))
        with self.assertRaises(JournalModelError):
            EventEnvelope("e", "t", "tenant", "stream", -1, 0, "2026-07-13T00:00:00Z", {})


if __name__ == "__main__":
    unittest.main()
