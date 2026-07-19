from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class CapacityError(RuntimeError):
    pass


class AdmissionClass(str, Enum):
    ORDINARY = "ORDINARY"
    OPERATIONAL_CONTROL = "OPERATIONAL_CONTROL"
    RECOVERY = "RECOVERY"


@dataclass(frozen=True)
class ParserLimits:
    max_command_bytes: int
    max_event_bytes: int
    max_frame_bytes: int
    max_events_per_frame: int
    max_object_references: int

    def check_command(self, size: int) -> None:
        if size < 0 or size > self.max_command_bytes:
            raise CapacityError("command exceeds parser limit before allocation")

    def check_event(self, size: int) -> None:
        if size < 0 or size > self.max_event_bytes:
            raise CapacityError("event exceeds parser limit before allocation")

    def check_frame_header(self, declared_size: int, event_count: int, object_reference_count: int) -> None:
        if declared_size < 0 or declared_size > self.max_frame_bytes:
            raise CapacityError("frame exceeds parser limit before allocation")
        if event_count < 0 or event_count > self.max_events_per_frame:
            raise CapacityError("event count exceeds parser limit")
        if object_reference_count < 0 or object_reference_count > self.max_object_references:
            raise CapacityError("object reference count exceeds parser limit")


@dataclass(frozen=True)
class CapacityProfile:
    profile_id: str
    qualification_status: str
    parser_limits: ParserLimits
    min_free_percent: float
    emergency_reserve_bytes: int
    recovery_reserve_bytes: int
    emergency_reserve_inodes: int
    rollover_headroom_bytes: int
    staging_headroom_bytes: int
    measured_slos: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapacityProfile":
        if value.get("schema") != "SITINA_CAPACITY_PROFILE_V1":
            raise CapacityError("wrong capacity profile schema")
        limits = ParserLimits(**value["parser_limits"])
        profile = cls(
            value["profile_id"], value["qualification_status"], limits, value["disk_gate"]["min_free_percent"],
            value["disk_gate"]["emergency_reserve_bytes"], value["disk_gate"]["recovery_reserve_bytes"],
            value["disk_gate"]["emergency_reserve_inodes"], value["disk_gate"]["rollover_headroom_bytes"],
            value["disk_gate"]["staging_headroom_bytes"], dict(value["measured_slos"]),
        )
        if profile.qualification_status != "NOT_YET_QUALIFIED" or profile.measured_slos:
            raise CapacityError("Phase 1 capacity profile must remain unqualified with empty measured SLOs")
        return profile

    @property
    def supported_capacity(self) -> None:
        return None


@dataclass(frozen=True)
class DiskObservation:
    free_bytes: int
    total_bytes: int
    free_inodes: int
    requested_bytes: int
    requested_inodes: int = 1


@dataclass(frozen=True)
class CapacityDecision:
    admitted: bool
    admission_class: AdmissionClass
    blockers: tuple[str, ...]
    remaining_bytes: int
    remaining_inodes: int


class DiskGate:
    def __init__(self, profile: CapacityProfile):
        self.profile = profile

    def decide(self, observation: DiskObservation, admission_class: AdmissionClass) -> CapacityDecision:
        remaining = observation.free_bytes - observation.requested_bytes
        remaining_inodes = observation.free_inodes - observation.requested_inodes
        blockers: list[str] = []
        if observation.total_bytes <= 0 or remaining / observation.total_bytes * 100 < self.profile.min_free_percent:
            blockers.append("MIN_FREE_PERCENT")
        reserve = self.profile.recovery_reserve_bytes
        if admission_class is AdmissionClass.ORDINARY:
            reserve += self.profile.emergency_reserve_bytes
        required_headroom = self.profile.rollover_headroom_bytes + self.profile.staging_headroom_bytes
        if remaining < reserve + required_headroom:
            blockers.append("BYTES_RESERVE_OR_HEADROOM")
        inode_reserve = self.profile.emergency_reserve_inodes if admission_class is AdmissionClass.ORDINARY else 1
        if remaining_inodes < inode_reserve:
            blockers.append("INODE_RESERVE")
        return CapacityDecision(not blockers, admission_class, tuple(blockers), remaining, remaining_inodes)

