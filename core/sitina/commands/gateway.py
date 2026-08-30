from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from sitina.cas.model import ExistingDurableObjectRootProof, PublishedObjectReceipt
from sitina.journal.local import CommandConflict, ExpectedStreamVersionConflict, LocalJournal
from sitina.journal.model import EventEnvelope, canonical_json_bytes

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
        """Submit an ordinary command.

        Authority/finalization material is intentionally absent from this
        public signature.  Code Mode uses the separate, typed method below;
        ordinary writers therefore cannot opt into a seal by passing a flag.
        """
        return self._submit(
            command, expected_stream_version, planner, object_reference_proofs,
            authority_envelope=None,
        )

    def submit_authority(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        authority_envelope: Mapping[str, Any],
    ) -> CommandResult:
        """Submit one Journal-verified authority operation."""
        if not isinstance(authority_envelope, Mapping):
            raise TypeError("signed authority envelope is required")
        return self._submit(
            command, expected_stream_version, planner, object_reference_proofs,
            authority_envelope=authority_envelope,
        )

    def submit_code_mode_acceptance(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        authority_envelope: Mapping[str, Any],
    ) -> CommandResult:
        """Submit the host-built Code Mode acceptance pair only."""
        if not isinstance(authority_envelope, Mapping):
            raise TypeError("signed acceptance envelope is required")
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_acceptance_operation(
                command, expected_stream_version, plan.events, object_reference_proofs,
                envelope=authority_envelope,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_attempt_advance(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> CommandResult:
        """Submit the reserved authenticated attempt mapping."""
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_attempt_advance(
                command, expected_stream_version, plan.events, object_reference_proofs,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_tty_nonce_consumption(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> CommandResult:
        """Submit the dedicated, non-authority TTY nonce fact."""
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_tty_nonce_consumption(
                command, expected_stream_version, plan.events, object_reference_proofs,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_execution_authorization(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> CommandResult:
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_execution_authorization(
                command, expected_stream_version, plan.events, object_reference_proofs,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_execution_parent(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> CommandResult:
        """Submit the dedicated authenticated execution-parent mapping."""
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_execution_parent(
                command, expected_stream_version, plan.events, object_reference_proofs,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_forge_child_authorization(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> CommandResult:
        """Submit the dedicated attempt-execution child mapping."""
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_forge_child_authorization(
                command, expected_stream_version, plan.events, object_reference_proofs,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_completion_plan(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
    ) -> CommandResult:
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_completion_plan(
                command, expected_stream_version, plan.events, object_reference_proofs,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_fact(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *, terminal_bundle: bool = False,
    ) -> CommandResult:
        """Submit a reserved producer fact through its dedicated Journal gate."""
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_fact(
                command, expected_stream_version, plan.events, object_reference_proofs,
                terminal_bundle=terminal_bundle,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_producer_fact(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *, producer_role: str,
    ) -> CommandResult:
        """Submit a role-specific Code Mode producer fact.

        This entry is deliberately distinct from ordinary ``submit`` and
        from the terminal bundle exception.  LocalJournal validates the
        role's exact schema, event type, purpose and evidence subtype before
        it considers a replay or allocates a Journal position.
        """
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_producer_fact(
                command, expected_stream_version, plan.events, object_reference_proofs,
                producer_role=producer_role,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_code_mode_root_producer_fact(
        self, command: CommandEnvelope, expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *, producer_role: str,
    ) -> CommandResult:
        """Submit a root-FSM dispatch/settlement/selection fact.

        Keeping this API distinct makes the ordinary proposal writer unable
        to manufacture a root transition merely by copying a payload.
        """
        if producer_role not in {
            "root_scheduling", "root_dispatch_acceptance", "root_dispatch",
            "root_settled", "root_result_accepted", "root_selection",
        }:
            raise ValueError("unknown root producer role")
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_code_mode_root_producer_fact(
                command, expected_stream_version, plan.events, object_reference_proofs,
                producer_role=producer_role,
            )
            return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt)
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))

    def submit_planned_authority(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        completion_plan: Mapping[str, Any],
        logical_operation_id: str,
        completion_plan_reference: str | None = None,
    ) -> CommandResult:
        """Submit an operation whose event projection is plan-committed."""
        # Do not short-circuit a planned replay through the lightweight
        # outcome index.  LocalJournal must compare the complete event/CAS
        # projection under its writer lock so same-command/different-payload
        # submissions are rejected rather than treated as idempotent.
        try:
            plan = planner(command)
            if plan.rejection_reason is not None:
                return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, reason=plan.rejection_reason)
            receipt = self.journal.append_planned_authority_operation(
                command, expected_stream_version, plan.events, object_reference_proofs,
                completion_plan=completion_plan,
                logical_operation_id=logical_operation_id,
                completion_plan_reference=completion_plan_reference,
            )
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))
        return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt, canonical_outcome_ref=receipt.transaction_hash)

    def _submit(
        self,
        command: CommandEnvelope,
        expected_stream_version: int,
        planner: Callable[[CommandEnvelope], CommandPlan],
        object_reference_proofs: Sequence[PublishedObjectReceipt | ExistingDurableObjectRootProof],
        *,
        authority_envelope: Mapping[str, Any] | None,
    ) -> CommandResult:
        # The resolver is a read-only index and is deliberately not an
        # admission path.  In particular, it must not turn a command id into
        # a promise of replay before this invocation has rebuilt the event
        # and proof projection.  LocalJournal owns the writer lock and is the
        # only component allowed to decide whether a replay is exact.
        try:
            plan = planner(command)
        except RetryableNotAccepted as error:
            return CommandResult(CommandStatus.RETRYABLE_NOT_ACCEPTED, command.command_id, command.command_request_hash, reason=str(error))
        if plan.rejection_reason is not None:
            rejection_identity = hashlib.sha256(
                canonical_json_bytes({
                    "command_id": command.command_id,
                    "request_hash": command.command_request_hash,
                    "reason_code": plan.rejection_reason,
                })
            ).hexdigest()
            event = EventEnvelope(
                f"event-rejected-{rejection_identity}", "command.rejected", command.tenant_id, command.stream_id, 0, 0,
                command.issued_at, {"reason_code": plan.rejection_reason, "request_hash": command.command_request_hash},
            )
            try:
                receipt = self.journal.append(command, expected_stream_version, [event])
            except (CommandConflict, ExpectedStreamVersionConflict) as error:
                return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))
            return CommandResult(CommandStatus.REJECTED, command.command_id, command.command_request_hash, receipt=receipt, reason=plan.rejection_reason, canonical_outcome_ref=receipt.transaction_hash)
        try:
            if authority_envelope is None:
                receipt = self.journal.append(
                    command, expected_stream_version, plan.events, object_reference_proofs
                )
            else:
                receipt = self.journal.append_authority_operation(
                    command, expected_stream_version, plan.events, object_reference_proofs,
                    envelope=authority_envelope,
                )
        except (CommandConflict, ExpectedStreamVersionConflict) as error:
            return CommandResult(CommandStatus.CONFLICT, command.command_id, command.command_request_hash, reason=str(error))
        return CommandResult(CommandStatus.COMMITTED, command.command_id, command.command_request_hash, receipt=receipt, canonical_outcome_ref=receipt.transaction_hash)

    def query(self, command_id: str, request_hash: str) -> CommandResult:
        return self.resolver.query(command_id, request_hash)
