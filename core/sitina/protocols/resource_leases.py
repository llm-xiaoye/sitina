from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from enum import Enum

from sitina.journal.model import validate_identifier, validate_timestamp


class ResourceLeaseError(RuntimeError):
    pass


class ReservationState(str, Enum):
    RESERVED = "RESERVED"
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class ResourceRequirement:
    resource_id: str
    units: int

    def __post_init__(self) -> None:
        validate_identifier(self.resource_id, field="resource_id")
        if self.units < 1: raise ResourceLeaseError("resource units must be positive")


@dataclass(frozen=True)
class ProgressEvidenceRef:
    evidence_hash: str
    policy_hash: str
    accepted: bool

    def __post_init__(self) -> None:
        if len(self.evidence_hash) != 64 or len(self.policy_hash) != 64: raise ResourceLeaseError("invalid progress evidence hash")


@dataclass(frozen=True)
class Reservation:
    resource_id: str
    units: int
    state: ReservationState
    expires_at: str
    renew_count: int = 0
    total_renewal_seconds: int = 0
    progress_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResourceLeaseAggregate:
    lease_id: str
    task_id: str
    requirements: tuple[ResourceRequirement, ...]
    max_renewals: int
    max_total_renewal_seconds: int
    reservations: tuple[Reservation, ...] = ()
    stream_version: int = 0

    def __post_init__(self) -> None:
        validate_identifier(self.lease_id, field="lease_id"); validate_identifier(self.task_id, field="task_id")
        if len({item.resource_id for item in self.requirements}) != len(self.requirements): raise ResourceLeaseError("duplicate resource requirement")

    def reserve(self, *, resource_id: str, units: int, expires_at: str) -> tuple["ResourceLeaseAggregate", dict]:
        validate_timestamp(expires_at)
        requirement = next((item for item in self.requirements if item.resource_id == resource_id), None)
        if requirement is None or units != requirement.units: raise ResourceLeaseError("reservation does not exactly satisfy declared requirement")
        if any(item.resource_id == resource_id and item.state not in {ReservationState.RELEASED, ReservationState.REVOKED} for item in self.reservations): raise ResourceLeaseError("resource already reserved")
        reservation = Reservation(resource_id, units, ReservationState.RESERVED, expires_at)
        return replace(self, reservations=self.reservations + (reservation,), stream_version=self.stream_version + 1), {"schema": "RESOURCE_RESERVED_V1", **reservation.__dict__, "state": reservation.state.value}

    @property
    def fully_reserved(self) -> bool:
        active_ids = {item.resource_id for item in self.reservations if item.state in {ReservationState.RESERVED, ReservationState.ACTIVE}}
        return active_ids == {item.resource_id for item in self.requirements}

    def activate(self) -> tuple["ResourceLeaseAggregate", tuple[dict, ...]]:
        if not self.fully_reserved: raise ResourceLeaseError("partial multi-resource reservation cannot activate Task")
        updated_reservations = tuple(replace(item, state=ReservationState.ACTIVE) if item.state is ReservationState.RESERVED else item for item in self.reservations)
        events = tuple({"schema": "RESOURCE_LEASE_ACTIVATED_V1", "resource_id": item.resource_id, "units": item.units} for item in updated_reservations if item.state is ReservationState.ACTIVE)
        return replace(self, reservations=updated_reservations, stream_version=self.stream_version + 1), events

    def renew(self, *, resource_id: str, extension_seconds: int, progress: ProgressEvidenceRef) -> tuple["ResourceLeaseAggregate", dict]:
        if not progress.accepted: raise ResourceLeaseError("renewal requires accepted progress evidence")
        reservation = next((item for item in self.reservations if item.resource_id == resource_id and item.state is ReservationState.ACTIVE), None)
        if reservation is None: raise ResourceLeaseError("resource lease is not active")
        if extension_seconds < 1 or reservation.renew_count + 1 > self.max_renewals or reservation.total_renewal_seconds + extension_seconds > self.max_total_renewal_seconds:
            raise ResourceLeaseError("resource renewal bound exceeded")
        expiry = dt.datetime.fromisoformat(reservation.expires_at.replace("Z", "+00:00")) + dt.timedelta(seconds=extension_seconds)
        renewed = replace(reservation, expires_at=expiry.isoformat().replace("+00:00", "Z"), renew_count=reservation.renew_count + 1, total_renewal_seconds=reservation.total_renewal_seconds + extension_seconds, progress_evidence=reservation.progress_evidence + (progress.evidence_hash,))
        reservations = tuple(renewed if item is reservation else item for item in self.reservations)
        return replace(self, reservations=reservations, stream_version=self.stream_version + 1), {"schema": "RESOURCE_LEASE_RENEWED_V1", "resource_id": resource_id, "extension_seconds": extension_seconds, "progress_evidence_hash": progress.evidence_hash}

    def release(self, *, resource_id: str, reason: str) -> tuple["ResourceLeaseAggregate", dict]:
        reservation = next((item for item in self.reservations if item.resource_id == resource_id and item.state in {ReservationState.RESERVED, ReservationState.ACTIVE}), None)
        if reservation is None: raise ResourceLeaseError("no releasable reservation")
        released = replace(reservation, state=ReservationState.RELEASED)
        return replace(self, reservations=tuple(released if item is reservation else item for item in self.reservations), stream_version=self.stream_version + 1), {"schema": "RESOURCE_LEASE_RELEASED_V1", "resource_id": resource_id, "reason": reason}

    def revoke(self, *, resource_id: str, reason: str) -> tuple["ResourceLeaseAggregate", dict]:
        reservation = next((item for item in self.reservations if item.resource_id == resource_id and item.state in {ReservationState.RESERVED, ReservationState.ACTIVE}), None)
        if reservation is None: raise ResourceLeaseError("no revocable reservation")
        revoked = replace(reservation, state=ReservationState.REVOKED)
        return replace(self, reservations=tuple(revoked if item is reservation else item for item in self.reservations), stream_version=self.stream_version + 1), {"schema": "RESOURCE_LEASE_REVOKED_V1", "resource_id": resource_id, "reason": reason}

    @property
    def compensation_release_inputs(self) -> tuple[dict, ...]:
        return tuple({"lease_id": self.lease_id, "resource_id": item.resource_id, "expected_state": item.state.value, "command_binding": f"compensate-{self.lease_id}-{item.resource_id}"} for item in self.reservations if item.state in {ReservationState.RESERVED, ReservationState.ACTIVE})

