from __future__ import annotations

import datetime as dt
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.commands.authorization import AuthorizationDecision, AuthorizationEngine
from sitina.journal.dead_letters import record_dead_letter
from sitina.journal.local import LocalJournal
from sitina.journal.operational import (
    OperationalAuthority, OperationalAuthorityError, OperationalFactType, TerminalEligibility, assert_journal_authoritative,
)
from sitina.journal.schema_registry import SchemaRegistry, SchemaRegistryError
from sitina.journal.security_intake import SecurityIntake
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


NOW = "2026-07-13T00:00:00Z"


class OperationalAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        self.journal = LocalJournal.open(self.home, JournalAuthProvider(InMemoryKeyProvider()))
        self.authority = OperationalAuthority(self.journal)

    def tearDown(self) -> None:
        self.journal.close(); shutil.rmtree(self.home)

    def test_sqlite_or_log_only_row_is_never_authoritative(self) -> None:
        with self.assertRaises(OperationalAuthorityError): assert_journal_authoritative(None)
        reference = self.authority.record(OperationalFactType.AUDIT, {"action": "fixture"}, occurred_at=NOW)
        self.assertEqual(assert_journal_authoritative(reference), reference)
        self.assertEqual(self.journal.head_position, 1)

    def test_security_intake_never_stores_raw_payload_or_secret(self) -> None:
        raw = b"password=top-secret-business-payload"
        result = SecurityIntake(self.authority, max_bytes=8).ingest(raw, content_type="text/plain", occurred_at=NOW)
        self.assertFalse(result.metadata["raw_payload_stored"])
        self.assertNotIn("top-secret", str(result.metadata))
        self.assertEqual(result.disposition, "QUARANTINE_ATTESTATION")

    def test_blocking_dead_letter_and_projection_failure_block_terminal_eligibility(self) -> None:
        terminal = TerminalEligibility()
        dead = record_dead_letter(self.authority, source_event_hash="11" * 32, handler_id="handler-1", failure_class="EIO", attempt_count=3, blocking=True, raw_payload=b"secret", occurred_at=NOW)
        terminal.observe(dead)
        failure = self.authority.record(OperationalFactType.PROJECTION_FAILURE, {"projection": "required"}, occurred_at=NOW, blocking=True)
        terminal.observe(failure)
        self.assertFalse(terminal.eligible)
        self.assertEqual((terminal.blocking_dead_letters, terminal.required_projection_failures), (1, 1))

    def test_schema_registry_is_immutable_and_unknown_major_fails_closed(self) -> None:
        records = []; registry = SchemaRegistry(records.append)
        first = registry.register("fixture.changed", 1, "11" * 32, ("22" * 32,))
        self.assertEqual(registry.register("fixture.changed", 1, "11" * 32, ("22" * 32,)), first)
        self.assertEqual(len(records), 1)
        with self.assertRaises(SchemaRegistryError): registry.register("fixture.changed", 1, "33" * 32, ())
        with self.assertRaises(SchemaRegistryError): registry.resolve("fixture.changed", 2)

    def test_authorization_decision_binds_all_inputs_and_is_recorded(self) -> None:
        records = []; engine = AuthorizationEngine(records.append)
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        decision = AuthorizationDecision("actor-1", "capability-1", "11" * 32, "target-1", "22" * 32, future, "audit-1", False, "policy-deny")
        engine.decide(decision)
        self.assertEqual(records[0]["decision_hash"], decision.decision_hash)
        changed = AuthorizationDecision("actor-1", "capability-1", "11" * 32, "target-2", "22" * 32, future, "audit-1", False, "policy-deny")
        self.assertNotEqual(changed.decision_hash, decision.decision_hash)


if __name__ == "__main__": unittest.main()
