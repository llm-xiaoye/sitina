from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Sequence

from sitina.cas.model import ExistingDurableObjectRootProof, PublishedObjectReceipt
from sitina.journal.local import CommandConflict, ExpectedStreamVersionConflict, LocalJournal
from sitina.journal.model import EventEnvelope

from .model import CommandEnvelope, CommandResult, CommandStatus
from .outcomes import CommandOutcomeResolver


class RetryableNotAccepted(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandPlan:
    events: tuple[EventEnvelope, ...] = ()
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        if bool(self.events) == bool(self.rejection_reason):
            raise ValueError("plan must contain either events or one deterministic rejection")


class CommandGateway:
    def __init__(self, journal: LocalJournal, *, resolver: CommandOutcomeResolver | None = None):
        self.journal = journal
        self.resolver = resolver or CommandOutcomeResolver(journal)

    def submit(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof] = (),
    ) -> CommandResult:
        existing = self.resolver.query(command.command_id, command.command_request_hash)
        if existing.status is not CommandStatus.UNKNOWN:
            return existing
        try:
            plan = planner(command)
        except RetryableNotAccepted as error:
            return CommandResult(CommandStatus.RETRYABLE_NOT_ACCEPTED, command.command_id, command.command_request_hash, reason=str(error))
        if plan.rejection_reason is not None:
            event = EventEnvelope(
                f"event-{uuid.uuid4().hex}", "command.rejected", command.tenant_id, command.stream_id, 0, 0,
                command.issued_at, {"reason_code": plan.rejection_reason, "request_hash": command.command_request_hash},
            )
            try:
                receipt = self.journal.append(command, expected_stream_version, [event])
            except (CommandConflict, ExpectedStreamVersionConflict) as error:
                return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))
            return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, receipt=receipt, reason=plan.rejection_reason, canonical_outcome_ref=receipt.transaction_hash)
        try:
            receipt = self.journal.append(command, expected_stream_version, plan.events, object_reference_proofs)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))
        return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt, canonical_outcome_ref=receipt.transaction_hash)

    def query(self, command_id: str, request_hash: str) -> CommandResult:
        return self.resolver.query(command_id, request_hash)

