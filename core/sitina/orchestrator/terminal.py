"""Terminal taxonomy and read-only legacy normalization."""

from __future__ import annotations

from typing import Any


TERMINAL_EVENT_TYPES = {
    "run_completed",
    "run_blocked",
    "run_failed",
    "run_timeout",
    "run_cancelled",
    "run_interrupted",
    "run_paused",
}


def terminal_summary(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    terminals = [event for event in timeline if event.get("event_type") in TERMINAL_EVENT_TYPES]
    first = terminals[0] if terminals else {}
    raw_type = first.get("event_type")
    legacy_blocked = raw_type == "run_failed" and first.get("status") == "blocked"
    return {
        "exists": bool(terminals),
        "count": len(terminals),
        "type": raw_type,
        "status": first.get("status"),
        "reason": first.get("reason"),
        "legacy_blocked_terminal": legacy_blocked,
        "normalized_terminal": "run_blocked" if legacy_blocked else raw_type,
    }


def normalized_terminal_type(event: dict[str, Any]) -> str | None:
    event_type = event.get("event_type")
    if event_type == "run_failed" and event.get("status") == "blocked":
        return "run_blocked"
    return str(event_type) if event_type in TERMINAL_EVENT_TYPES else None
