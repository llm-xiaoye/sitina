"""Provider accounting with explicit logical-call and HTTP-attempt semantics."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine, ReplayResult
from sitina.storage import SitinaStore


class ProviderAccounting:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def for_run(
        self,
        run_id: str,
        *,
        timeline: list[dict[str, Any]] | None = None,
        replay: ReplayResult | None = None,
    ) -> dict[str, Any]:
        timeline = timeline if timeline is not None else RunLedger(self.home, self.store).timeline(run_id)
        replay = replay if replay is not None else ReplayEngine(self.home, self.store).replay(run_id, record=False)
        unified_started = [
            event
            for event in timeline
            if event.get("event_type") == "agent_call_started" and (event.get("payload_json") or {}).get("provider_mode") == "live"
        ]
        unified_terminals = [
            event
            for event in timeline
            if event.get("event_type") == "agent_call_terminal" and (event.get("payload_json") or {}).get("provider_mode") == "live"
        ]
        if unified_started or unified_terminals:
            started = unified_started
            successful = [event for event in unified_terminals if (event.get("payload_json") or {}).get("terminal_status") == "completed"]
            failed = [event for event in unified_terminals if (event.get("payload_json") or {}).get("terminal_status") != "completed"]
            logical_call_source = "unified_agent_call_audit"
        else:
            started = [
                event
                for event in timeline
                if event.get("event_type") == "agent_started" and (event.get("payload_json") or {}).get("provider_mode") == "live"
            ]
            successful = [
                event
                for event in timeline
                if event.get("event_type") == "agent_completed" and (event.get("payload_json") or {}).get("provider_mode") == "live"
            ]
            failed = [
                event
                for event in timeline
                if event.get("event_type") == "agent_blocked" and (event.get("payload_json") or {}).get("provider_mode") == "live"
            ]
            logical_call_source = "legacy_agent_lifecycle"
        attempt_groups = self._attempt_groups(timeline, replay)
        first_attempts = [self._first_attempt(items) for items in attempt_groups.values() if items]
        first_attempts = [item for item in first_attempts if item is not None]
        all_attempts = [item for items in attempt_groups.values() for item in items]
        run_started = next((event for event in timeline if event.get("event_type") == "run_started"), {})
        start_payload = run_started.get("payload_json") or {}
        controlled_fixture = bool(start_payload.get("controlled_fixture"))
        real_provider_called = bool(all_attempts) and not controlled_fixture
        wall_clock = self._wall_clock_duration(timeline)
        first_tokens = self._token_totals(first_attempts)
        all_tokens = self._token_totals(all_attempts)
        sum_first_duration = sum(self._non_negative_int(item.get("duration_ms")) for item in first_attempts)
        sum_all_duration = sum(self._non_negative_int(item.get("duration_ms")) for item in all_attempts)
        return {
            "logical_agent_calls": len(started),
            "successful_agent_calls": len(successful),
            "failed_agent_calls": len(failed),
            "http_attempts": len(all_attempts),
            "retry_attempts": sum(1 for item in all_attempts if self._non_negative_int(item.get("attempt"), default=1) > 1),
            "first_attempt_prompt_tokens": first_tokens["prompt"],
            "first_attempt_completion_tokens": first_tokens["completion"],
            "first_attempt_total_tokens": first_tokens["total"],
            "all_attempt_prompt_tokens": all_tokens["prompt"],
            "all_attempt_completion_tokens": all_tokens["completion"],
            "all_attempt_total_tokens": all_tokens["total"],
            "cache_read_tokens": all_tokens["cache_read"],
            "cache_write_tokens": all_tokens["cache_write"],
            "sum_first_attempt_duration_ms": sum_first_duration,
            "sum_all_attempt_duration_ms": sum_all_duration,
            "run_wall_clock_duration_ms": wall_clock,
            "provider_parallelism_detected": self._parallelism_detected(all_attempts, wall_clock, sum_all_duration),
            "attempts_missing_token_usage": sum(1 for item in all_attempts if not isinstance(item.get("token_usage"), dict)),
            "controlled_fixture": controlled_fixture,
            "controlled_fixture_type": start_payload.get("controlled_fixture_type"),
            "real_provider_called": real_provider_called,
            "excluded_from_live_usage_totals": controlled_fixture,
            "logical_call_source": logical_call_source,
            "counting_methodology": {
                "logical_agent_call": "one persisted live agent_call_started event from the unified AgentRunner entry; legacy runs use agent_started",
                "http_attempt": "one explicit provider_http_attempt result; legacy runs use each persisted provider_calls entry",
                "first_attempt_tokens": "token usage from the lowest numbered HTTP attempt for each logical agent call",
                "all_attempt_tokens": "token usage from every persisted HTTP attempt, including retries when usage is available",
                "duration_sum": "sum of per-attempt duration_ms; it is not elapsed wall-clock time",
                "wall_clock": "elapsed time from run_started to the first terminal event",
                "parallelism": "true when provider intervals overlap or summed attempt duration exceeds wall-clock duration",
                "controlled_fixture_exclusion": "controlled failure fixtures are reported but excluded from real live usage totals",
            },
        }

    def empty(self) -> dict[str, Any]:
        return {
            "logical_agent_calls": 0,
            "successful_agent_calls": 0,
            "failed_agent_calls": 0,
            "http_attempts": 0,
            "retry_attempts": 0,
            "first_attempt_prompt_tokens": 0,
            "first_attempt_completion_tokens": 0,
            "first_attempt_total_tokens": 0,
            "all_attempt_prompt_tokens": 0,
            "all_attempt_completion_tokens": 0,
            "all_attempt_total_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "sum_first_attempt_duration_ms": 0,
            "sum_all_attempt_duration_ms": 0,
            "run_wall_clock_duration_ms": 0,
            "provider_parallelism_detected": False,
            "attempts_missing_token_usage": 0,
            "controlled_fixture": False,
            "controlled_fixture_type": None,
            "real_provider_called": False,
            "excluded_from_live_usage_totals": False,
            "logical_call_source": "none",
            "counting_methodology": self.methodology(),
        }

    @staticmethod
    def controlled_fixture_metadata(goal: str, provider_mode: str) -> dict[str, Any]:
        lowered = str(goal or "").lower()
        controlled = provider_mode == "live" and "controlled" in lowered and "fixture" in lowered
        fixture_type = None
        if controlled:
            fixture_type = "provider_failure"
            for marker, name in (
                ("parse", "parse_failure"),
                ("deadline", "timeout"),
                ("timeout", "timeout"),
                ("401", "http_401"),
                ("auth", "http_401"),
                ("403", "http_403"),
                ("permission", "http_403"),
                ("429", "http_429"),
                ("rate", "http_429"),
                ("cancel", "cancel"),
                ("interrupt", "interrupt"),
            ):
                if marker in lowered:
                    fixture_type = name
                    break
        return {
            "controlled_fixture": controlled,
            "controlled_fixture_type": fixture_type,
            "real_provider_called": False if controlled else None,
            "excluded_from_live_usage_totals": controlled,
        }

    @staticmethod
    def methodology() -> dict[str, str]:
        return {
            "logical_agent_call": "one persisted live agent_call_started event from the unified AgentRunner entry; legacy runs use agent_started",
            "http_attempt": "one explicit provider_http_attempt result; legacy runs use each persisted provider_calls entry",
            "first_attempt_tokens": "token usage from the lowest numbered HTTP attempt for each logical agent call",
            "all_attempt_tokens": "token usage from every persisted HTTP attempt, including retries when usage is available",
            "duration_sum": "sum of per-attempt duration_ms; it is not elapsed wall-clock time",
            "wall_clock": "elapsed time from run_started to the first terminal event",
            "parallelism": "true when provider intervals overlap or summed attempt duration exceeds wall-clock duration",
            "controlled_fixture_exclusion": "controlled failure fixtures are reported but excluded from real live usage totals",
        }

    def _attempt_groups(self, timeline: list[dict[str, Any]], replay: ReplayResult) -> dict[str, list[dict[str, Any]]]:
        explicit: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in timeline:
            if event.get("event_type") not in {"provider_http_attempt_completed", "provider_http_attempt_failed"}:
                continue
            payload = dict(event.get("payload_json") or {})
            logical_id = str(payload.get("logical_call_id") or f"{event.get('task_id')}:{event.get('agent_id')}")
            explicit[logical_id].append(payload)
        if explicit:
            for items in explicit.values():
                items.sort(key=lambda item: self._non_negative_int(item.get("attempt"), default=1))
            return dict(explicit)

        legacy: dict[str, list[dict[str, Any]]] = {}
        for index, snapshot in enumerate(replay.agent_snapshots):
            if snapshot.get("provider_mode") != "live" and not snapshot.get("provider_calls"):
                continue
            logical_id = str(snapshot.get("call_id") or f"legacy:{index}:{snapshot.get('task_id')}:{snapshot.get('agent_id')}")
            calls = [dict(call) for call in (snapshot.get("provider_calls") or []) if isinstance(call, dict)]
            calls.sort(key=lambda item: self._non_negative_int(item.get("attempt"), default=1))
            legacy[logical_id] = calls
        return legacy

    @staticmethod
    def _first_attempt(items: list[dict[str, Any]]) -> dict[str, Any] | None:
        return min(items, key=lambda item: ProviderAccounting._non_negative_int(item.get("attempt"), default=1)) if items else None

    @staticmethod
    def _token_totals(attempts: list[dict[str, Any]]) -> dict[str, int]:
        totals = {"prompt": 0, "completion": 0, "total": 0, "cache_read": 0, "cache_write": 0}
        for attempt in attempts:
            usage = attempt.get("token_usage")
            if not isinstance(usage, dict):
                continue
            prompt = ProviderAccounting._non_negative_int(usage.get("input_tokens", usage.get("prompt_tokens")))
            completion = ProviderAccounting._non_negative_int(usage.get("output_tokens", usage.get("completion_tokens")))
            total = ProviderAccounting._non_negative_int(usage.get("total_tokens"), default=prompt + completion)
            totals["prompt"] += prompt
            totals["completion"] += completion
            totals["total"] += total
            totals["cache_read"] += ProviderAccounting._non_negative_int(usage.get("cache_read_tokens"))
            totals["cache_write"] += ProviderAccounting._non_negative_int(usage.get("cache_write_tokens"))
        return totals

    @staticmethod
    def _wall_clock_duration(timeline: list[dict[str, Any]]) -> int:
        start = next((event.get("timestamp") for event in timeline if event.get("event_type") == "run_started"), None)
        terminal_types = {"run_completed", "run_blocked", "run_failed", "run_timeout", "run_cancelled", "run_interrupted", "run_paused"}
        end = next((event.get("timestamp") for event in timeline if event.get("event_type") in terminal_types), None)
        start_dt = ProviderAccounting._parse_time(start)
        end_dt = ProviderAccounting._parse_time(end)
        return max(0, int((end_dt - start_dt).total_seconds() * 1000)) if start_dt and end_dt else 0

    @staticmethod
    def _parallelism_detected(attempts: list[dict[str, Any]], wall_clock: int, duration_sum: int) -> bool:
        intervals: list[tuple[dt.datetime, dt.datetime]] = []
        for attempt in attempts:
            start = ProviderAccounting._parse_time(attempt.get("provider_call_started_at"))
            end = ProviderAccounting._parse_time(attempt.get("provider_call_completed_at"))
            if start and end:
                intervals.append((start, end))
        intervals.sort(key=lambda item: item[0])
        if any(intervals[index][0] < intervals[index - 1][1] for index in range(1, len(intervals))):
            return True
        return bool(wall_clock and duration_sum > wall_clock + 10)

    @staticmethod
    def _parse_time(value: Any) -> dt.datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _non_negative_int(value: Any, *, default: int = 0) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return default
