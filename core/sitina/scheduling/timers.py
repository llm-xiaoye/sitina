from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier, validate_timestamp


class TimerError(RuntimeError):
    pass


class TimerState(str, Enum):
    SCHEDULED = "SCHEDULED"
    FIRED = "FIRED"
    CANCELLED = "CANCELLED"
    HELD_UNCERTAIN = "HELD_UNCERTAIN"


@dataclass(frozen=True)
class ClockSample:
    wall_utc: str
    monotonic_seconds: float
    uncertainty_seconds: float

    @property
    def wall_datetime(self) -> dt.datetime:
        validate_timestamp(self.wall_utc)
        return dt.datetime.fromisoformat(self.wall_utc.replace("Z", "+00:00"))


@dataclass(frozen=True)
class DurableTimer:
    timer_id: str
    target_id: str
    purpose: str
    deadline_utc: str
    target_command_id: str
    created_wall_utc: str
    created_monotonic_ns: int | None
    state: TimerState = TimerState.SCHEDULED
    fired_command_ref: str | None = None


class TimerService:
    def __init__(self, *, max_clock_uncertainty_seconds: float = 5.0):
        self.max_clock_uncertainty_seconds = max_clock_uncertainty_seconds
        self.timers: dict[str, DurableTimer] = {}
        self.journal_facts: list[dict[str, Any]] = []
        self.incidents: list[dict[str, Any]] = []
        self.takeover_held = False

    def schedule(self, *, timer_id: str, target_id: str, purpose: str, deadline_utc: str, sample: ClockSample) -> tuple[DurableTimer, dict]:
        for value, field in ((timer_id, "timer_id"), (target_id, "target_id"), (purpose, "timer_purpose")): validate_identifier(value, field=field)
        validate_timestamp(deadline_utc)
        command_hash = domain_hash("TIMER_TARGET_COMMAND", canonical_json_bytes({"timer_id": timer_id, "target_id": target_id, "purpose": purpose, "deadline_utc": deadline_utc}))
        command_id = f"timer-command-{command_hash}"
        existing = self.timers.get(timer_id)
        if existing:
            if existing.target_command_id != command_id: raise TimerError("Timer ID binding conflict")
            return existing, {"schema": "TIMER_SCHEDULE_DUPLICATE_V1", "timer_id": timer_id, "target_command_id": command_id}
        timer = DurableTimer(
            timer_id,
            target_id,
            purpose,
            deadline_utc,
            command_id,
            sample.wall_utc,
            round(sample.monotonic_seconds * 1_000_000_000),
        )
        event = {"schema": "DURABLE_TIMER_SCHEDULED_V1", **timer.__dict__, "state": timer.state.value}
        self.timers[timer_id] = timer; self.journal_facts.append(event)
        return timer, event

    def is_due(self, timer_id: str, sample: ClockSample, *, same_process_lifetime: bool) -> bool:
        timer = self.timers[timer_id]
        if timer.state is not TimerState.SCHEDULED: return False
        if sample.uncertainty_seconds > self.max_clock_uncertainty_seconds:
            incident = {
                "schema": "CLOCK_UNCERTAINTY_INCIDENT_V1",
                "timer_id": timer_id,
                "uncertainty_ns": round(sample.uncertainty_seconds * 1_000_000_000),
                "threshold_ns": round(self.max_clock_uncertainty_seconds * 1_000_000_000),
                "takeover_held": True,
            }
            self.incidents.append(incident); self.takeover_held = True
            self.timers[timer_id] = replace(timer, state=TimerState.HELD_UNCERTAIN)
            return False
        deadline = dt.datetime.fromisoformat(timer.deadline_utc.replace("Z", "+00:00"))
        conservative_wall = sample.wall_datetime - dt.timedelta(seconds=sample.uncertainty_seconds)
        if conservative_wall < deadline: return False
        if same_process_lifetime and timer.created_monotonic_ns is not None:
            created_wall = dt.datetime.fromisoformat(timer.created_wall_utc.replace("Z", "+00:00"))
            delta = deadline - created_wall
            required_elapsed_ns = max(
                0,
                (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000,
            )
            observed_elapsed_ns = round(sample.monotonic_seconds * 1_000_000_000) - timer.created_monotonic_ns
            if observed_elapsed_ns < required_elapsed_ns: return False
        return True

    def fire(self, timer_id: str, sample: ClockSample, *, same_process_lifetime: bool, command_ref: str) -> tuple[DurableTimer, dict]:
        timer = self.timers[timer_id]
        if timer.state is TimerState.FIRED:
            return timer, {"schema": "TIMER_FIRE_DUPLICATE_V1", "timer_id": timer_id, "target_command_id": timer.target_command_id}
        if not self.is_due(timer_id, sample, same_process_lifetime=same_process_lifetime): raise TimerError("Timer is not safely due")
        if len(command_ref) != 64: raise TimerError("Timer target Command requires canonical outcome reference")
        fired = replace(timer, state=TimerState.FIRED, fired_command_ref=command_ref)
        event = {"schema": "DURABLE_TIMER_FIRED_V1", "timer_id": timer_id, "target_command_id": timer.target_command_id, "command_ref": command_ref, "deadline_utc": timer.deadline_utc}
        self.timers[timer_id] = fired; self.journal_facts.append(event)
        return fired, event

    @classmethod
    def rebuild(cls, journal_facts: Iterable[dict[str, Any]], *, max_clock_uncertainty_seconds: float = 5.0) -> "TimerService":
        service = cls(max_clock_uncertainty_seconds=max_clock_uncertainty_seconds)
        for fact in journal_facts:
            if fact["schema"] == "DURABLE_TIMER_SCHEDULED_V1":
                values = {key: fact[key] for key in DurableTimer.__dataclass_fields__}
                values["state"] = TimerState(values["state"])
                service.timers[values["timer_id"]] = DurableTimer(**values)
            elif fact["schema"] == "DURABLE_TIMER_FIRED_V1":
                timer = service.timers[fact["timer_id"]]
                service.timers[timer.timer_id] = replace(timer, state=TimerState.FIRED, fired_command_ref=fact["command_ref"])
            service.journal_facts.append(dict(fact))
        return service
