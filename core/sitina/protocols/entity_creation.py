from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .permits import AdmissionPermit, PermitPurpose
from .run import RunAggregate


class EntityCreationError(RuntimeError):
    pass


class EntityKind(str, Enum):
    TASK = "TASK"
    PROTOCOL = "PROTOCOL"
    OBLIGATION = "OBLIGATION"
    CLAIM = "CLAIM"
    RESOURCE_LEASE = "RESOURCE_LEASE"
    TASK_GRAPH_NODE = "TASK_GRAPH_NODE"


class CreationDisposition(str, Enum):
    PENDING = "PENDING"
    CREATED = "CREATED"
    TOMBSTONED = "TOMBSTONED"
    CONFIRMED = "CONFIRMED"
    RELEASED = "RELEASED"
    INTEGRITY_INCIDENT = "INTEGRITY_INCIDENT"


@dataclass(frozen=True)
class EntityCreationProcess:
    process_id: str
    run_id: str
    permit_id: str
    entity_id: str
    entity_kind: EntityKind
    create_command_id: str
    request_hash: str
    idempotency_binding: str
    disposition: CreationDisposition = CreationDisposition.PENDING
    target_fact_hash: str | None = None

    @property
    def binding_hash(self) -> str:
        return domain_hash(
            "ENTITY_CREATION_BINDING",
            canonical_json_bytes(
                {
                    "process_id": self.process_id, "run_id": self.run_id, "permit_id": self.permit_id,
                    "entity_id": self.entity_id, "entity_kind": self.entity_kind.value,
                    "create_command_id": self.create_command_id, "request_hash": self.request_hash,
                    "idempotency_binding": self.idempotency_binding,
                }
            ),
        )


def begin_entity_creation(
    run: RunAggregate,
    permit: AdmissionPermit,
    *,
    process_id: str,
    entity_id: str,
    entity_kind: EntityKind,
    create_command_id: str,
    request_hash: str,
    idempotency_binding: str,
    depth: int = 0,
) -> tuple[RunAggregate, AdmissionPermit, EntityCreationProcess, tuple[dict, ...]]:
    if entity_kind is EntityKind.TASK_GRAPH_NODE or entity_id.startswith("task-graph-node/"):
        raise EntityCreationError("TaskGraph Node is owned by the TaskGraph aggregate and cannot have an independent stream")
    for value, field in ((process_id, "process_id"), (entity_id, "entity_id"), (create_command_id, "create_command_id"), (idempotency_binding, "idempotency_binding")):
        validate_identifier(value, field=field)
    if len(request_hash) != 64:
        raise EntityCreationError("invalid create request hash")
    purpose = PermitPurpose.CLOSING_ENTITY_CREATE if run.state.value == "CLOSING" else PermitPurpose.ENTITY_CREATE
    updated_permit, consume_event = permit.consume(
        current_admission_generation=run.admission_generation, purpose=purpose, scope=entity_kind.value.lower(),
        depth=depth, idempotency_binding=idempotency_binding,
    )
    process = EntityCreationProcess(process_id, run.run_id, permit.permit_id, entity_id, entity_kind, create_command_id, request_hash, idempotency_binding)
    permits = tuple(updated_permit if item.permit_id == permit.permit_id else item for item in run.permits)
    updated_run = replace(
        run, stream_version=run.stream_version + 1, permits=permits,
        pending_creation_processes=run.pending_creation_processes + (process_id,),
    )
    frozen = {"schema": "ENTITY_CREATION_FROZEN_V1", "binding_hash": process.binding_hash, **{key: value.value if isinstance(value, Enum) else value for key, value in process.__dict__.items()}}
    return updated_run, updated_permit, process, (consume_event, frozen)


def target_create(
    process: EntityCreationProcess,
    *,
    canonical_stream_state: str,
    canonical_request_hash: str | None,
    deterministic_rejection: str | None = None,
) -> tuple[EntityCreationProcess, dict]:
    if process.disposition not in {CreationDisposition.PENDING, CreationDisposition.CREATED, CreationDisposition.TOMBSTONED}:
        raise EntityCreationError("creation process is already terminal")
    if canonical_stream_state == "CREATED":
        if canonical_request_hash != process.request_hash:
            incident = replace(process, disposition=CreationDisposition.INTEGRITY_INCIDENT)
            return incident, {"schema": "ENTITY_CREATION_INTEGRITY_INCIDENT_V1", "entity_id": process.entity_id, "expected_hash": process.request_hash, "actual_hash": canonical_request_hash}
        created = replace(process, disposition=CreationDisposition.CREATED, target_fact_hash=canonical_request_hash)
        return created, {"schema": "ENTITY_CREATED_OBSERVED_V1", "entity_id": process.entity_id, "create_command_id": process.create_command_id, "request_hash": process.request_hash}
    if canonical_stream_state == "TOMBSTONED":
        if canonical_request_hash != process.request_hash:
            raise EntityCreationError("Tombstone binding hash mismatch")
        tombstoned = replace(process, disposition=CreationDisposition.TOMBSTONED, target_fact_hash=canonical_request_hash)
        return tombstoned, {"schema": "ENTITY_TOMBSTONE_OBSERVED_V1", "entity_id": process.entity_id, "request_hash": process.request_hash}
    if canonical_stream_state != "NO_STREAM":
        raise EntityCreationError("unknown canonical target stream state")
    if deterministic_rejection:
        tombstoned = replace(process, disposition=CreationDisposition.TOMBSTONED, target_fact_hash=process.request_hash)
        return tombstoned, {"schema": "ENTITY_CREATION_ABORTED_TOMBSTONE_V1", "entity_id": process.entity_id, "create_command_id": process.create_command_id, "request_hash": process.request_hash, "reason": deterministic_rejection}
    created = replace(process, disposition=CreationDisposition.CREATED, target_fact_hash=process.request_hash)
    return created, {"schema": "ENTITY_CREATED_V1", "entity_id": process.entity_id, "entity_kind": process.entity_kind.value, "create_command_id": process.create_command_id, "request_hash": process.request_hash}


def reconcile_source(run: RunAggregate, process: EntityCreationProcess, *, canonical_target_state: str, canonical_request_hash: str) -> tuple[RunAggregate, EntityCreationProcess, dict]:
    if canonical_request_hash != process.request_hash:
        raise EntityCreationError("canonical query returned a different request hash")
    if process.disposition is CreationDisposition.CREATED and canonical_target_state == "CREATED":
        terminal = replace(process, disposition=CreationDisposition.CONFIRMED)
        event = {"schema": "ENTITY_CREATION_CONFIRMED_V1", "entity_id": process.entity_id, "binding_hash": process.binding_hash}
    elif process.disposition is CreationDisposition.TOMBSTONED and canonical_target_state == "TOMBSTONED":
        terminal = replace(process, disposition=CreationDisposition.RELEASED)
        event = {"schema": "ENTITY_CREATION_PERMIT_RELEASED_V1", "entity_id": process.entity_id, "binding_hash": process.binding_hash}
    else:
        raise EntityCreationError("source reconciliation requires matching canonical Created or Tombstone outcome")
    updated = replace(
        run, stream_version=run.stream_version + 1,
        pending_creation_processes=tuple(item for item in run.pending_creation_processes if item != process.process_id),
    )
    return updated, terminal, event

