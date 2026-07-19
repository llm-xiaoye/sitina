from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class CreationDisposition(str, Enum):
    PENDING = "PENDING"
    EFFECT_REQUESTED = "EFFECT_REQUESTED"
    TOMBSTONED = "TOMBSTONED"
    CONFIRMED = "CONFIRMED"
    RELEASED = "RELEASED"
    INTEGRITY_INCIDENT = "INTEGRITY_INCIDENT"


class EffectCreationError(RuntimeError):
    pass


class EffectCreationIncident(EffectCreationError):
    def __init__(self, fact: dict[str, Any]):
        super().__init__(fact["classification"])
        self.fact = fact


@dataclass(frozen=True)
class EffectPermit:
    permit_id: str
    run_id: str
    effect_id: str
    request_hash: str

    def __post_init__(self) -> None:
        for value, field in ((self.permit_id, "permit_id"), (self.run_id, "run_id"), (self.effect_id, "effect_id")):
            validate_identifier(value, field=field)
        if len(self.request_hash) != 64:
            raise ValueError("invalid request hash")


@dataclass(frozen=True)
class EffectCreationProcess:
    process_id: str
    command_id: str
    permit_id: str
    run_id: str
    effect_id: str
    request_hash: str
    disposition: CreationDisposition = CreationDisposition.PENDING

    @property
    def binding_hash(self) -> str:
        return domain_hash(
            "EFFECT_CREATION_PROCESS",
            canonical_json_bytes(
                {
                    "process_id": self.process_id,
                    "command_id": self.command_id,
                    "permit_id": self.permit_id,
                    "run_id": self.run_id,
                    "effect_id": self.effect_id,
                    "request_hash": self.request_hash,
                }
            ),
        )


class EffectCreationSaga:
    """Persistent-state equivalent used by the Process Manager replay path."""

    def __init__(self) -> None:
        self._processes: dict[str, EffectCreationProcess] = {}

    def begin(self, permit: EffectPermit, *, process_id: str, command_id: str) -> tuple[EffectCreationProcess, tuple[dict[str, Any], ...]]:
        validate_identifier(process_id, field="process_id")
        validate_identifier(command_id, field="command_id")
        candidate = EffectCreationProcess(process_id, command_id, permit.permit_id, permit.run_id, permit.effect_id, permit.request_hash)
        previous = self._processes.get(process_id)
        if previous is not None:
            if previous.binding_hash != candidate.binding_hash:
                fact = {
                    "schema": "EFFECT_CREATION_SECURITY_INCIDENT_V1",
                    "classification": "SAME_ID_DIFFERENT_HASH",
                    "process_id": process_id,
                    "expected_binding_hash": previous.binding_hash,
                    "actual_binding_hash": candidate.binding_hash,
                }
                raise EffectCreationIncident(fact)
            return previous, ()
        self._processes[process_id] = candidate
        return candidate, (
            {
                "schema": "PERMIT_CONSUMED_PENDING_EFFECT_V1",
                "permit_id": permit.permit_id,
                "run_id": permit.run_id,
                "effect_id": permit.effect_id,
                "request_hash": permit.request_hash,
                "process_id": process_id,
                "command_id": command_id,
            },
        )

    def apply_target(self, process: EffectCreationProcess, *, canonical_state: str, canonical_request_hash: str | None = None, rejection: str | None = None) -> tuple[EffectCreationProcess, dict[str, Any]]:
        current = self._processes.get(process.process_id)
        if current != process:
            raise EffectCreationError("stale creation process")
        if canonical_state in {"EFFECT_REQUESTED", "TOMBSTONED"}:
            if canonical_request_hash != process.request_hash:
                raise EffectCreationIncident(
                    {
                        "schema": "EFFECT_CREATION_SECURITY_INCIDENT_V1",
                        "classification": "SAME_ID_DIFFERENT_HASH",
                        "effect_id": process.effect_id,
                        "expected_hash": process.request_hash,
                        "actual_hash": canonical_request_hash,
                    }
                )
            disposition = CreationDisposition.EFFECT_REQUESTED if canonical_state == "EFFECT_REQUESTED" else CreationDisposition.TOMBSTONED
            updated = replace(process, disposition=disposition)
            schema = "EFFECT_REQUESTED_OBSERVED_V1" if disposition is CreationDisposition.EFFECT_REQUESTED else "EFFECT_TOMBSTONE_OBSERVED_V1"
        elif canonical_state == "NO_STREAM" and rejection is None:
            updated = replace(process, disposition=CreationDisposition.EFFECT_REQUESTED)
            schema = "EFFECT_REQUESTED_V1"
        elif canonical_state == "NO_STREAM" and rejection is not None:
            updated = replace(process, disposition=CreationDisposition.TOMBSTONED)
            schema = "EFFECT_CREATION_ABORTED_V1"
        else:
            raise EffectCreationError("unknown target state")
        self._processes[process.process_id] = updated
        return updated, {
            "schema": schema,
            "effect_id": process.effect_id,
            "request_hash": process.request_hash,
            "command_id": process.command_id,
            "permit_id": process.permit_id,
            **({"reason": rejection} if rejection else {}),
        }

    def reconcile(self, process: EffectCreationProcess, *, canonical_state: str, canonical_request_hash: str) -> tuple[EffectCreationProcess, dict[str, Any]]:
        if canonical_request_hash != process.request_hash:
            raise EffectCreationIncident(
                {
                    "schema": "EFFECT_CREATION_SECURITY_INCIDENT_V1",
                    "classification": "SAME_ID_DIFFERENT_HASH",
                    "effect_id": process.effect_id,
                    "expected_hash": process.request_hash,
                    "actual_hash": canonical_request_hash,
                }
            )
        if process.disposition is CreationDisposition.EFFECT_REQUESTED and canonical_state == "EFFECT_REQUESTED":
            updated = replace(process, disposition=CreationDisposition.CONFIRMED)
            event = {"schema": "EFFECT_CREATION_CONFIRMED_V1", "permit_released": False}
        elif process.disposition is CreationDisposition.TOMBSTONED and canonical_state == "TOMBSTONED":
            updated = replace(process, disposition=CreationDisposition.RELEASED)
            event = {"schema": "EFFECT_CREATION_PERMIT_RELEASED_V1", "permit_released": True}
        else:
            raise EffectCreationError("canonical target does not match process outcome")
        self._processes[process.process_id] = updated
        return updated, {**event, "effect_id": process.effect_id, "binding_hash": process.binding_hash}
