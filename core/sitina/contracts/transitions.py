from __future__ import annotations


class InvalidContractTransition(ValueError):
    pass


_TRANSITIONS = {
    "task": {
        "PENDING": {"READY", "BLOCKED", "CANCELLED"},
        "READY": {"RUNNING", "BLOCKED", "CANCELLED"},
        "RUNNING": {"COMPLETED", "FAILED", "BLOCKED", "CANCELLED"},
        "BLOCKED": {"READY", "CANCELLED"},
        "COMPLETED": set(),
        "FAILED": set(),
        "CANCELLED": set(),
        "SKIPPED": set(),
    },
    "failure": {
        "OPEN": {"ACKNOWLEDGED", "RESOLVED"},
        "ACKNOWLEDGED": {"RESOLVED"},
        "RESOLVED": set(),
    },
    "span": {
        "PENDING": {"RUNNING", "CANCELLED"},
        "RUNNING": {"OK", "ERROR", "CANCELLED"},
        "OK": set(),
        "ERROR": set(),
        "CANCELLED": set(),
    },
    "handoff": {
        "OFFERED": {"ACCEPTED", "REJECTED", "CANCELLED", "EXPIRED"},
        "ACCEPTED": set(),
        "REJECTED": set(),
        "CANCELLED": set(),
        "EXPIRED": set(),
    },
    "evaluation": {
        "DRAFT": {"FINAL", "INVALIDATED"},
        "FINAL": {"INVALIDATED"},
        "INVALIDATED": set(),
    },
}


def validate_contract_transition(family: str, current: str, target: str) -> None:
    states = _TRANSITIONS.get(family)
    if states is None or current not in states or target not in states[current]:
        raise InvalidContractTransition(f"invalid {family} transition: {current} -> {target}")
