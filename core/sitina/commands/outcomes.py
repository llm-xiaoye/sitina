from __future__ import annotations

import sqlite3

from sitina.journal.local import LocalJournal

from .model import CommandResult, CommandStatus


class CanonicalCoverageUnavailable(RuntimeError):
    pass


class CommandOutcomeResolver:
    """Canonical Journal first; SQLite is a disposable acceleration cache only."""

    def __init__(self, journal: LocalJournal, cache: sqlite3.Connection | None = None):
        self.journal = journal
        self.cache = cache
        self.canonical_coverage_available = True

    def query(self, command_id: str, request_hash: str) -> CommandResult:
        if not self.canonical_coverage_available:
            return CommandResult(CommandStatus.UNKNOWN, command_id, request_hash, reason="canonical cold coverage unavailable")
        canonical = self.journal.query_command(command_id, request_hash)
        if canonical.status is not CommandStatus.COMMITTED:
            return canonical
        receipt = canonical.receipt
        events = tuple(
            event for event in self.journal.iter_events(receipt.first_position - 1)
            if receipt.first_position <= event.position <= receipt.last_position
        )
        rejected = next((event for event in events if event.event_type == "command.rejected"), None)
        if rejected:
            return CommandResult(
                CommandStatus.REJECTED, command_id, request_hash, receipt=receipt,
                reason=str(rejected.payload["reason_code"]), canonical_outcome_ref=receipt.transaction_hash,
            )
        return canonical

    def cache_lookup(self, command_id: str) -> tuple | None:
        if self.cache is None:
            return None
        return self.cache.execute(
            "SELECT request_hash,status,transaction_hash,first_position,last_position FROM command_outcomes WHERE command_id=?",
            (command_id,),
        ).fetchone()

