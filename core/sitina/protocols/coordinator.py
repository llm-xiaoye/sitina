from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from sitina.commands.model import CommandResult, CommandStatus
from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier
from sitina.scheduling.processes import ProcessManager, ProcessStallDetected


class CoordinationError(RuntimeError):
    def __init__(self, message: str, *, fact: dict[str, Any]):
        super().__init__(message)
        self.fact = fact


@dataclass(frozen=True)
class SuccessorCommand:
    command_id: str
    request_hash: str
    target_stream_id: str
    command_type: str
    payload: Mapping[str, Any]
    source_event_hash: str


@dataclass(frozen=True)
class ProtocolCoordinator:
    coordinator_id: str
    definition_hash: str
    manager: ProcessManager
    journal_facts: tuple[dict[str, Any], ...] = ()

    def __init__(self, coordinator_id: str, definition_hash: str, *, max_steps: int = 100):
        validate_identifier(coordinator_id, field="protocol_coordinator_id")
        if len(definition_hash) != 64:
            raise CoordinationError(
                "invalid Protocol Coordinator definition",
                fact={"schema": "PROTOCOL_COORDINATION_CONFIG_REJECTED_V1"},
            )
        manager = ProcessManager(
            f"process-{coordinator_id}", definition_hash, max_steps=max_steps
        )
        object.__setattr__(self, "coordinator_id", coordinator_id)
        object.__setattr__(self, "definition_hash", definition_hash)
        object.__setattr__(self, "manager", manager)
        object.__setattr__(self, "journal_facts", ())

    @classmethod
    def _from_manager(
        cls,
        coordinator_id: str,
        definition_hash: str,
        manager: ProcessManager,
        journal_facts: tuple[dict[str, Any], ...],
    ) -> "ProtocolCoordinator":
        instance = object.__new__(cls)
        object.__setattr__(instance, "coordinator_id", coordinator_id)
        object.__setattr__(instance, "definition_hash", definition_hash)
        object.__setattr__(instance, "manager", manager)
        object.__setattr__(instance, "journal_facts", journal_facts)
        return instance

    @staticmethod
    def _route(event: Mapping[str, Any]) -> tuple[str, str, dict[str, Any]]:
        schema = event.get("schema")
        if schema == "DEBATE_SYNTHESIS_FINALIZED_V1" and event.get("outcome") == "NO_CONSENSUS":
            source = str(event["debate_id"])
            kind = "create-debate-successor-obligation"
            target_prefix = "obligation/debate-successor"
        elif schema == "MERGE_FAILED_V1":
            source = str(event["merge_id"])
            kind = "create-arbitration-obligation"
            target_prefix = "obligation/arbitration"
        elif schema == "PROPOSAL_ROUND_NO_SELECTION_V1" and event.get("next_action") == "ARBITRATION":
            source = str(event["round_id"])
            kind = "create-proposal-arbitration"
            target_prefix = "obligation/proposal-arbitration"
        elif schema == "ARBITRATION_FAILED_V1":
            source = str(event["arbitration_id"])
            kind = "create-arbitration-failure-successor"
            target_prefix = "obligation/arbitration-successor"
        elif schema == "REWORK_RETRY_EXHAUSTED_V1":
            source = str(event["rework_id"])
            kind = "create-rework-successor"
            target_prefix = "obligation/rework-successor"
        else:
            raise CoordinationError(
                "terminal Protocol Event has no frozen successor route",
                fact={"schema": "PROTOCOL_COORDINATION_ROUTE_REJECTED_V1", "source_schema": schema},
            )
        target_identity = domain_hash(
            "PROTOCOL_COORDINATION_TARGET",
            canonical_json_bytes({"schema": schema, "source": source, "kind": kind}),
        )
        target = f"{target_prefix}/{target_identity}"
        payload = {
            "source_schema": schema,
            "source_protocol_id": source,
            "target_stream_id": target,
            "coordination_kind": kind,
        }
        return kind, target, payload

    def observe(
        self, source_event_hash: str, event: Mapping[str, Any]
    ) -> tuple["ProtocolCoordinator", SuccessorCommand, tuple[dict[str, Any], ...]]:
        if len(source_event_hash) != 64:
            raise CoordinationError(
                "invalid terminal Protocol Event hash",
                fact={"schema": "PROTOCOL_COORDINATION_SOURCE_REJECTED_V1"},
            )
        action, target, payload = self._route(event)
        try:
            manager, step, manager_facts = self.manager.plan_step(
                source_event_hash=source_event_hash,
                action=action,
                payload=payload,
            )
        except ProcessStallDetected as error:
            fact = {
                "schema": "PROTOCOL_COORDINATION_STALL_DETECTED_V1",
                "coordinator_id": self.coordinator_id,
                "source_event_hash": source_event_hash,
                "source_schema": event.get("schema"),
                "process_fact": error.fact,
                "frozen_next_actions": ["SPLIT", "REASSIGN", "REWORK", "ARBITRATION", "ASK_USER", "CANCEL", "FAIL"],
            }
            raise CoordinationError("Protocol coordination stalled", fact=fact) from error
        command = SuccessorCommand(
            step.command_id,
            step.request_hash,
            target,
            action,
            payload,
            source_event_hash,
        )
        if not manager_facts:
            return self, command, ()
        coordination_fact = {
            "schema": "PROTOCOL_COORDINATION_COMMAND_PLANNED_V1",
            "coordinator_id": self.coordinator_id,
            "source_event_hash": source_event_hash,
            "source_schema": event.get("schema"),
            "command_id": command.command_id,
            "request_hash": command.request_hash,
            "target_stream_id": target,
            "command_type": action,
            "cross_stream_direct_mutation": False,
        }
        facts = manager_facts + (coordination_fact,)
        updated = self._from_manager(
            self.coordinator_id,
            self.definition_hash,
            manager,
            self.journal_facts + facts,
        )
        return updated, command, facts

    def record_outcome(
        self,
        command: SuccessorCommand,
        canonical_outcome_ref: str,
        *,
        target_event_hash: str,
    ) -> tuple["ProtocolCoordinator", dict[str, Any]]:
        if len(canonical_outcome_ref) != 64 or len(target_event_hash) != 64:
            raise CoordinationError(
                "coordination outcome requires canonical references",
                fact={"schema": "PROTOCOL_COORDINATION_OUTCOME_REJECTED_V1"},
            )
        pending = self.manager.pending_step
        if (
            pending is None
            or pending.command_id != command.command_id
            or pending.request_hash != command.request_hash
        ):
            raise CoordinationError(
                "coordination outcome does not match pending Command",
                fact={"schema": "PROTOCOL_COORDINATION_OUTCOME_CONFLICT_V1"},
            )
        manager, outcome_facts = self.manager.reconcile_outcome(
            lambda command_id, request_hash: CommandResult(
                CommandStatus.COMMITTED,
                command_id,
                request_hash,
                canonical_outcome_ref=canonical_outcome_ref,
            )
        )
        target_fact = {
            "schema": "PROTOCOL_COORDINATION_TARGET_OBSERVED_V1",
            "coordinator_id": self.coordinator_id,
            "command_id": command.command_id,
            "request_hash": command.request_hash,
            "target_stream_id": command.target_stream_id,
            "canonical_outcome_ref": canonical_outcome_ref,
            "target_event_hash": target_event_hash,
        }
        updated = self._from_manager(
            self.coordinator_id,
            self.definition_hash,
            manager,
            self.journal_facts + outcome_facts + (target_fact,),
        )
        return updated, target_fact

    @classmethod
    def rebuild(
        cls,
        coordinator_id: str,
        definition_hash: str,
        journal_facts: tuple[dict[str, Any], ...],
        *,
        max_steps: int = 100,
    ) -> "ProtocolCoordinator":
        manager = ProcessManager.rebuild(
            f"process-{coordinator_id}",
            definition_hash,
            journal_facts,
            max_steps=max_steps,
        )
        return cls._from_manager(coordinator_id, definition_hash, manager, journal_facts)
