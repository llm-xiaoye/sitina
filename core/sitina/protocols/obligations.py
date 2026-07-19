from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .entity_creation import EntityCreationProcess, EntityKind, begin_entity_creation
from .permits import AdmissionPermit
from .run import RunAggregate


class ObligationError(RuntimeError):
    pass


class ObligationState(str, Enum):
    OPEN = "OPEN"
    SUCCESSOR_REQUIRED = "SUCCESSOR_REQUIRED"
    SATISFIED = "SATISFIED"
    SUPERSEDED = "SUPERSEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL_OBLIGATION_STATES = frozenset(
    {
        ObligationState.SATISFIED,
        ObligationState.SUPERSEDED,
        ObligationState.FAILED,
        ObligationState.CANCELLED,
    }
)


@dataclass(frozen=True)
class SuccessorPlan:
    source_obligation_id: str
    generation: int
    reason: str
    successor_obligation_id: str
    successor_protocol_id: str
    obligation_create_command_id: str
    protocol_create_command_id: str
    obligation_request_hash: str
    protocol_request_hash: str

    @classmethod
    def derive(cls, source_obligation_id: str, generation: int, reason: str) -> "SuccessorPlan":
        seed = canonical_json_bytes(
            {"source_obligation_id": source_obligation_id, "generation": generation, "reason": reason}
        )
        identity = domain_hash("SUCCESSOR_OBLIGATION_IDENTITY", seed)
        obligation_id = f"obligation-successor-{identity}"
        protocol_id = f"protocol-successor-{identity}"
        obligation_request = domain_hash(
            "CREATE_SUCCESSOR_OBLIGATION",
            canonical_json_bytes(
                {"source": source_obligation_id, "successor": obligation_id, "reason": reason}
            ),
        )
        protocol_request = domain_hash(
            "CREATE_SUCCESSOR_PROTOCOL",
            canonical_json_bytes(
                {"source": source_obligation_id, "successor": protocol_id, "obligation": obligation_id}
            ),
        )
        return cls(
            source_obligation_id,
            generation,
            reason,
            obligation_id,
            protocol_id,
            f"create-{obligation_id}",
            f"create-{protocol_id}",
            obligation_request,
            protocol_request,
        )

    def begin_creation_sagas(
        self,
        run: RunAggregate,
        obligation_permit: AdmissionPermit,
        protocol_permit: AdmissionPermit,
    ) -> tuple[RunAggregate, tuple[EntityCreationProcess, ...], tuple[dict[str, Any], ...]]:
        updated, _, obligation_process, obligation_facts = begin_entity_creation(
            run,
            obligation_permit,
            process_id=f"process-create-{self.successor_obligation_id}",
            entity_id=self.successor_obligation_id,
            entity_kind=EntityKind.OBLIGATION,
            create_command_id=self.obligation_create_command_id,
            request_hash=self.obligation_request_hash,
            idempotency_binding=f"binding-{self.successor_obligation_id}",
            depth=1,
        )
        current_protocol_permit = next(
            item for item in updated.permits if item.permit_id == protocol_permit.permit_id
        )
        updated, _, protocol_process, protocol_facts = begin_entity_creation(
            updated,
            current_protocol_permit,
            process_id=f"process-create-{self.successor_protocol_id}",
            entity_id=self.successor_protocol_id,
            entity_kind=EntityKind.PROTOCOL,
            create_command_id=self.protocol_create_command_id,
            request_hash=self.protocol_request_hash,
            idempotency_binding=f"binding-{self.successor_protocol_id}",
            depth=1,
        )
        return updated, (obligation_process, protocol_process), obligation_facts + protocol_facts


@dataclass(frozen=True)
class ObligationAggregate:
    obligation_id: str
    run_id: str
    protocol_id: str
    required_for_run_terminal: bool
    state: ObligationState = ObligationState.OPEN
    stream_version: int = 1
    protocol_terminal_ref: str | None = None
    terminal_fact_ref: str | None = None
    successor_plan: SuccessorPlan | None = None

    @classmethod
    def create(
        cls,
        obligation_id: str,
        run_id: str,
        protocol_id: str,
        *,
        required_for_run_terminal: bool,
    ) -> tuple["ObligationAggregate", dict[str, Any]]:
        for value, field in (
            (obligation_id, "obligation_id"),
            (run_id, "run_id"),
            (protocol_id, "protocol_id"),
        ):
            validate_identifier(value, field=field)
        aggregate = cls(obligation_id, run_id, protocol_id, required_for_run_terminal)
        return aggregate, {
            "schema": "OBLIGATION_CREATED_V1",
            "obligation_id": obligation_id,
            "run_id": run_id,
            "protocol_id": protocol_id,
            "required_for_run_terminal": required_for_run_terminal,
        }

    def _open(self) -> None:
        if self.state is not ObligationState.OPEN:
            raise ObligationError(f"Obligation is {self.state.value}")

    @staticmethod
    def _fact(reference: str, field: str) -> None:
        if len(reference) != 64:
            raise ObligationError(f"invalid {field} reference")

    def record_protocol_terminal(self, terminal_ref: str) -> tuple["ObligationAggregate", dict[str, Any]]:
        self._open()
        self._fact(terminal_ref, "protocol terminal")
        if self.protocol_terminal_ref:
            if self.protocol_terminal_ref != terminal_ref:
                raise ObligationError("Protocol terminal reference conflict")
            return self, {
                "schema": "OBLIGATION_PROTOCOL_TERMINAL_DUPLICATE_V1",
                "obligation_id": self.obligation_id,
                "protocol_terminal_ref": terminal_ref,
            }
        updated = replace(
            self,
            stream_version=self.stream_version + 1,
            protocol_terminal_ref=terminal_ref,
        )
        return updated, {
            "schema": "OBLIGATION_PROTOCOL_TERMINAL_OBSERVED_V1",
            "obligation_id": self.obligation_id,
            "protocol_terminal_ref": terminal_ref,
            "obligation_state": updated.state.value,
        }

    def satisfy(self, satisfaction_ref: str) -> tuple["ObligationAggregate", dict[str, Any]]:
        self._open()
        self._fact(satisfaction_ref, "satisfaction")
        updated = replace(
            self,
            state=ObligationState.SATISFIED,
            terminal_fact_ref=satisfaction_ref,
            stream_version=self.stream_version + 1,
        )
        return updated, {
            "schema": "OBLIGATION_TERMINAL_V1",
            "obligation_id": self.obligation_id,
            "state": updated.state.value,
            "terminal_fact_ref": satisfaction_ref,
        }

    def require_successor(
        self, reason: str
    ) -> tuple["ObligationAggregate", SuccessorPlan, dict[str, Any]]:
        if self.state is ObligationState.SUCCESSOR_REQUIRED and self.successor_plan:
            if self.successor_plan.reason != reason:
                raise ObligationError("Successor disposition is already bound to another reason")
            return self, self.successor_plan, {
                "schema": "OBLIGATION_SUCCESSOR_DUPLICATE_V1",
                "obligation_id": self.obligation_id,
                "successor_obligation_id": self.successor_plan.successor_obligation_id,
            }
        self._open()
        plan = SuccessorPlan.derive(self.obligation_id, self.stream_version + 1, reason)
        updated = replace(
            self,
            state=ObligationState.SUCCESSOR_REQUIRED,
            stream_version=self.stream_version + 1,
            successor_plan=plan,
        )
        return updated, plan, {
            "schema": "OBLIGATION_SUCCESSOR_REQUIRED_V1",
            "obligation_id": self.obligation_id,
            "successor_obligation_id": plan.successor_obligation_id,
            "successor_protocol_id": plan.successor_protocol_id,
            "reason": reason,
        }

    def terminal(
        self, state: ObligationState, fact_ref: str
    ) -> tuple["ObligationAggregate", dict[str, Any]]:
        self._open()
        if state not in TERMINAL_OBLIGATION_STATES:
            raise ObligationError("invalid terminal Obligation state")
        self._fact(fact_ref, "terminal")
        updated = replace(
            self,
            state=state,
            terminal_fact_ref=fact_ref,
            stream_version=self.stream_version + 1,
        )
        return updated, {
            "schema": "OBLIGATION_TERMINAL_V1",
            "obligation_id": self.obligation_id,
            "state": state.value,
            "terminal_fact_ref": fact_ref,
        }


@dataclass(frozen=True)
class ProtocolRegistryProjection:
    protocols: Mapping[str, Mapping[str, Any]] = None  # type: ignore[assignment]
    obligations: Mapping[str, Mapping[str, Any]] = None  # type: ignore[assignment]
    source_position: int = 0

    def __post_init__(self) -> None:
        if self.protocols is None:
            object.__setattr__(self, "protocols", {})
        if self.obligations is None:
            object.__setattr__(self, "obligations", {})

    def apply(self, fact: Mapping[str, Any], *, source_position: int) -> "ProtocolRegistryProjection":
        if source_position != self.source_position + 1:
            raise ObligationError("Protocol Registry requires a gap-free source prefix")
        schema = fact.get("schema")
        protocols = {key: dict(value) for key, value in self.protocols.items()}
        obligations = {key: dict(value) for key, value in self.obligations.items()}
        if schema == "PROTOCOL_CREATED_V1":
            protocol_id = str(fact["protocol_id"])
            protocols[protocol_id] = {
                "protocol_id": protocol_id,
                "run_id": str(fact["run_id"]),
                "state": "CREATED",
                "created_position": source_position,
                "terminal_position": None,
            }
        elif schema == "PROTOCOL_TERMINAL_V1":
            protocol_id = str(fact["protocol_id"])
            if protocol_id not in protocols:
                raise ObligationError("Protocol terminal without Created fact")
            protocols[protocol_id]["state"] = str(fact["state"])
            protocols[protocol_id]["terminal_position"] = source_position
        elif schema == "OBLIGATION_CREATED_V1":
            obligation_id = str(fact["obligation_id"])
            obligations[obligation_id] = {
                "obligation_id": obligation_id,
                "run_id": str(fact["run_id"]),
                "required_for_run_terminal": bool(fact["required_for_run_terminal"]),
                "state": "OPEN",
                "created_position": source_position,
                "terminal_position": None,
            }
        elif schema == "OBLIGATION_TERMINAL_V1":
            obligation_id = str(fact["obligation_id"])
            if obligation_id not in obligations:
                raise ObligationError("Obligation terminal without Created fact")
            obligations[obligation_id]["state"] = str(fact["state"])
            obligations[obligation_id]["terminal_position"] = source_position
        else:
            raise ObligationError("Registry accepts only authoritative Created/Terminal facts")
        return ProtocolRegistryProjection(protocols, obligations, source_position)

    def required_open_count(self, run_id: str) -> int:
        return sum(
            1
            for item in self.obligations.values()
            if item["run_id"] == run_id
            and item["required_for_run_terminal"]
            and item["state"] not in {state.value for state in TERMINAL_OBLIGATION_STATES}
        )
