from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sitina.authority.model import AuthorityResolution

from sitina.commands.model import CommandEnvelope
from sitina.journal.local import LocalJournal
from sitina.journal.model import EventEnvelope
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from sitina.utils import load_json_yaml


class BPlusShadowError(RuntimeError):
    pass


@dataclass(frozen=True)
class RoutedWriteResult:
    writer: str
    resolution_id: str
    journal_first: bool
    effect_capability_ceiling: str


class AuthorityRoutedWriter:
    """Fixture router. Flags are observational and never select a writer."""

    effect_capability_ceiling = "MOCK_ONLY"

    def __init__(self, legacy_sink: Any, journal_sink: Any, projector: Any):
        self.legacy_sink = legacy_sink
        self.journal_sink = journal_sink
        self.projector = projector

    def dispatch(
        self,
        payload: Mapping[str, Any],
        resolution: AuthorityResolution,
        *,
        now: int,
        phase_flag: str | None = None,
        feature_flag: bool | None = None,
    ) -> RoutedWriteResult:
        del phase_flag, feature_flag
        try:
            resolution.assert_fresh(now=now)
        except Exception as error:
            raise BPlusShadowError("stale authority resolution denies business dispatch") from error
        if resolution.writer_count != 1:
            raise BPlusShadowError("authority resolution authorizes no unique writer")
        value = dict(payload)
        if resolution.authorizes_legacy:
            self.legacy_sink(value)
            return RoutedWriteResult("legacy", resolution.resolution_id, False, self.effect_capability_ceiling)
        if resolution.authorizes_journal:
            self.journal_sink(value)
            self.projector(value)
            return RoutedWriteResult("journal", resolution.resolution_id, True, self.effect_capability_ceiling)
        raise BPlusShadowError("authority resolution denies business dispatch")


@dataclass(frozen=True)
class ShadowObservation:
    enabled: bool
    goal_hash: str
    receipt_transaction_hash: str | None
    external_calls: int
    authority: bool = False


class BPlusShadowAdapter:
    """Non-authoritative mirror. It has no Provider, Tool, MCP, or effect adapter."""

    def __init__(self, home: Path, *, enabled: bool):
        self.home = home.resolve(strict=True)
        self.enabled = enabled
        self.root = self.home / "shadow/bplus-phase2"
        self._provider = InMemoryKeyProvider(environment="test", namespace="bplus-phase2-shadow")

    @classmethod
    def from_home(cls, home: Path) -> "BPlusShadowAdapter":
        config_path = home / "config/sitina.yaml"
        if not config_path.is_file():
            return cls(home, enabled=False)
        config = load_json_yaml(config_path)
        runtime = config.get("runtime") if isinstance(config.get("runtime"), dict) else {}
        return cls(home, enabled=runtime.get("bplus_shadow_enabled") is True)

    def observe_run_request(self, goal: str, *, provider_mode: str) -> ShadowObservation:
        goal_hash = hashlib.sha256(goal.encode("utf-8")).hexdigest()
        if not self.enabled:
            return ShadowObservation(False, goal_hash, None, 0)
        if self.home == Path("/Users/moss/SitinaHub"):
            raise BPlusShadowError("Phase 2 shadow adapter cannot write under Production Home")
        if not (self.home / ".sitina-bplus-disposable-v1").is_file() and not (self.home / ".sitina-bplus-shadow-v1").is_file():
            raise BPlusShadowError("Phase 2 shadow adapter requires an isolated Home marker")
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / ".sitina-bplus-shadow-v1").write_text("phase2-shadow\n", encoding="utf-8")
        command_id = f"shadow-observe-{goal_hash}"
        stream_id = f"shadow-run/{goal_hash[:24]}"
        command = CommandEnvelope(
            command_id, "shadow-tenant", stream_id, "shadow.observe-run", "shadow-observer",
            "2026-07-13T00:00:00Z",
            {"goal_hash": goal_hash, "goal_length": len(goal), "provider_mode_class": "live-request" if provider_mode == "live" else "non-live"},
        )
        event = EventEnvelope(
            f"shadow-event-{goal_hash}", "shadow.run-request-observed", "shadow-tenant", stream_id, 0, 0,
            "2026-07-13T00:00:00Z",
            {"goal_hash": goal_hash, "goal_length": len(goal), "real_provider_or_tool_dispatch_allowed": False},
        )
        journal = LocalJournal.open(self.root, JournalAuthProvider(self._provider), journal_id="journal-shadow-phase2", namespace_kind="shadow")
        try:
            expected = sum(1 for item in journal.iter_events(0) if item.stream_id == stream_id)
            receipt = journal.append(command, expected, [event])
        finally:
            journal.close()
        return ShadowObservation(True, goal_hash, receipt.transaction_hash, 0)

    @staticmethod
    def classify_legacy_compatibility(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
        differences = []
        for key in sorted(set(before) | set(after)):
            if before.get(key) != after.get(key):
                differences.append(
                    {
                        "field": key, "classification": "EXPECTED_NONAUTHORITY_SHADOW_REPRESENTATION"
                        if key == "shadow_observation" else "REGRESSION",
                        "before": before.get(key), "after": after.get(key),
                    }
                )
        return {
            "schema": "BPLUS_PHASE2_LEGACY_COMPATIBILITY_V1", "differences": differences,
            "blocking_count": sum(item["classification"] == "REGRESSION" for item in differences),
        }

    def compare_protocol_views(
        self,
        proposals: list[Any],
        handoffs: list[Any],
        blackboard_documents: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Build read-only Phase 3 compatibility views without Legacy writes."""
        from sitina.legacy.protocol_views import LegacyProtocolViews

        views = LegacyProtocolViews()
        return {
            "schema": "BPLUS_PHASE3_PROTOCOL_VIEWS_V1",
            "proposal": views.proposal_view(proposals, []),
            "handoff": views.handoff_view(handoffs),
            "blackboard": views.blackboard_view(blackboard_documents),
            "authority": False,
            "legacy_mutable_writes": 0,
        }
