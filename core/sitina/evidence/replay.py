from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from .assessment import EvidenceAssessment
from .isolation_provider import ReplayIsolationProvider


class ReplayMode(str, Enum):
    REPLAY_ORIGINAL = "REPLAY_ORIGINAL"
    REPLAY_CURRENT_AUDIT = "REPLAY_CURRENT_AUDIT"


@dataclass(frozen=True)
class ReplayResult:
    mode: ReplayMode
    replayed_positions: tuple[int, ...]
    presented_assessment_hash: str
    generated_assessment: bool
    current_audit: str
    external_effect_count: int
    live_journal_position_allocated: bool
    live_permit_or_lease_allocated: bool
    disposable_projection: bool
    isolation_capability: str


class OfflineReplayEngine:
    def __init__(
        self,
        events: tuple[Mapping[str, object], ...],
        *,
        terminal_position: int,
        original_assessment: EvidenceAssessment,
        isolation: ReplayIsolationProvider,
    ):
        self.events = tuple(events)
        self.terminal_position = terminal_position
        self.original_assessment = original_assessment
        self.isolation = isolation

    def run(self, mode: ReplayMode, *, supplements: tuple[Mapping[str, object], ...] = ()) -> ReplayResult:
        replayed = tuple(
            int(event["position"])
            for event in self.events
            if isinstance(event.get("position"), int) and int(event["position"]) <= self.terminal_position
        )
        current = self.original_assessment.status.value
        if mode is ReplayMode.REPLAY_CURRENT_AUDIT:
            for supplement in supplements:
                if supplement.get("accepted") is True and isinstance(supplement.get("audit"), str):
                    current = str(supplement["audit"])
        return ReplayResult(
            mode=mode,
            replayed_positions=replayed,
            presented_assessment_hash=self.original_assessment.assessment_hash,
            generated_assessment=False,
            current_audit=current,
            external_effect_count=0,
            live_journal_position_allocated=False,
            live_permit_or_lease_allocated=False,
            disposable_projection=True,
            isolation_capability=self.isolation.capability.value,
        )

