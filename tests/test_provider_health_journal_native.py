from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.runners.provider import ProviderHealthRegistry
from sitina.storage import SitinaStore


class _SmokeClient:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def smoke(self, profile: str, *, max_tokens: int):
        if self.fail:
            raise RuntimeError("original provider failure")
        return {"ok": True, "profile": profile, "model": "fixture-model"}


class ProviderHealthJournalNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        (self.home / ".sitina-clean-acceptance-v1").write_text("1\n", encoding="utf-8")
        (self.home / "config").mkdir()
        (self.home / "config/sitina.yaml").write_text(
            json.dumps(
                {
                    "state_source_of_truth": "canonical_journal",
                    "storage_authority": {
                        "canonical_source": "journal",
                        "content_source": "cas",
                        "projection_role": "disposable_rebuildable_view",
                        "legacy_enabled": False,
                        "legacy_read_enabled": False,
                        "legacy_fallback_enabled": False,
                        "legacy_write_enabled": False,
                        "active_business_jsonl_enabled": False,
                        "missing_legacy_is_valid": True,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.events: list[dict] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def registry(self, *, append=None) -> ProviderHealthRegistry:
        return ProviderHealthRegistry(
            self.home,
            journal_events=lambda: tuple(self.events),
            journal_append=append or self.events.append,
        )

    def test_status_and_writes_use_journal_events_without_legacy_database(self) -> None:
        with patch.object(SitinaStore, "init_db", side_effect=AssertionError("Legacy init called")), patch.object(
            SitinaStore, "get_provider_health", side_effect=AssertionError("Legacy read called")
        ), patch.object(SitinaStore, "upsert_provider_health", side_effect=AssertionError("Legacy write called")):
            registry = self.registry()
            self.assertEqual(registry.status("gpt")["status"], "unknown")
            observed = registry.mark_healthy("gpt", model="gpt-fixture", latency_ms=42)
            self.assertEqual(observed["status"], "healthy")
            self.assertEqual(registry.status("gpt")["latency_ms"], 42)
        self.assertFalse((self.home / "data/sitina.db").exists())
        event = self.events[-1]
        self.assertEqual(event["schema"], "PROVIDER_HEALTH_OBSERVED_V1")
        self.assertEqual(event["event_type"], "provider.health-observed")
        self.assertEqual(event["profile"], "gpt")

    def test_health_persistence_failure_never_relabels_provider_result(self) -> None:
        def broken_append(_event):
            raise OSError("health Journal unavailable")

        registry = self.registry(append=broken_append)
        healthy = registry.check_profiles(_SmokeClient(), ["gpt"], max_tokens=8)
        self.assertEqual(healthy[0]["check"], "ok")
        self.assertEqual(healthy[0]["status"], "healthy")
        self.assertEqual(healthy[0]["health_persistence_error_type"], "OSError")
        failed = registry.check_profiles(_SmokeClient(fail=True), ["gpt"], max_tokens=8)
        self.assertEqual(failed[0]["check"], "failed")
        self.assertIn("original provider failure", failed[0]["provider_error"])
        self.assertEqual(failed[0]["health_persistence_error_type"], "OSError")


if __name__ == "__main__":
    unittest.main()
