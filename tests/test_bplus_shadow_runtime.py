from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.journal.local import LocalJournal
from sitina.journal.locks import WriterLock
from sitina.journal.model import EventEnvelope
from sitina.commands.model import CommandEnvelope
from sitina.orchestrator.bplus_adapter import BPlusShadowAdapter, BPlusShadowError
from sitina.orchestrator.engine import SitinaEngine
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider


class BPlusShadowRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(os.environ["SITINA_HOME"])

    def test_default_remains_legacy_and_creates_no_shadow_journal(self) -> None:
        adapter = BPlusShadowAdapter.from_home(self.home)
        self.assertFalse(adapter.enabled)
        observation = adapter.observe_run_request("fixture", provider_mode="mock")
        self.assertFalse(observation.enabled); self.assertFalse((self.home / "shadow/bplus-phase2").exists())
        engine = SitinaEngine(self.home)
        self.assertFalse(engine.bplus_shadow.enabled)

    def test_minimal_legacy_home_without_optional_config_defaults_off(self) -> None:
        home = Path(tempfile.mkdtemp(dir=self.home))
        try:
            adapter = BPlusShadowAdapter.from_home(home)
            self.assertFalse(adapter.enabled)
            engine = SitinaEngine(home)
            self.assertFalse(engine.bplus_shadow.enabled)
        finally:
            shutil.rmtree(home)

    def test_enabled_shadow_mirrors_hash_only_and_cannot_dispatch_real_provider_or_tool(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.home) as temporary:
            home = Path(temporary)
            (home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
            config_path = home / "config/sitina.yaml"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                json.dumps({"runtime": {"bplus_shadow_enabled": True}}, sort_keys=True),
                encoding="utf-8",
            )
            adapter = BPlusShadowAdapter.from_home(home)
            observation = adapter.observe_run_request("top secret fixture goal", provider_mode="live")
            self.assertTrue(observation.enabled)
            self.assertFalse(observation.authority)
            self.assertEqual(observation.external_calls, 0)
            raw = (adapter.root / "journal/active.seg").read_bytes()
            self.assertNotIn(b"top secret fixture goal", raw)
            self.assertEqual(observation.receipt_transaction_hash and len(observation.receipt_transaction_hash), 64)

    def test_disabling_shadow_leaves_legacy_output_shape_unchanged_and_classifies_differences(self) -> None:
        before = {"status": "completed", "external_call_count": 0}
        after = dict(before)
        report = BPlusShadowAdapter.classify_legacy_compatibility(before, after)
        self.assertEqual(report["blocking_count"], 0); self.assertEqual(report["differences"], [])
        changed = BPlusShadowAdapter.classify_legacy_compatibility(before, {**after, "shadow_observation": {"authority": False}})
        self.assertEqual(changed["blocking_count"], 0)

    def test_production_home_is_rejected_even_if_flag_were_enabled(self) -> None:
        adapter = BPlusShadowAdapter(Path("/Users/moss/SitinaHub"), enabled=True)
        with self.assertRaises(BPlusShadowError): adapter.observe_run_request("fixture", provider_mode="mock")

    def test_failed_journal_recovery_releases_writer_lock_for_diagnostics(self) -> None:
        home = Path(tempfile.mkdtemp(dir=self.home)); (home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        provider = InMemoryKeyProvider(); auth = JournalAuthProvider(provider)
        journal = LocalJournal.open(home, auth)
        command = CommandEnvelope("cmd-1", "tenant-1", "stream-1", "fixture", "actor-1", "2026-07-13T00:00:00Z", {})
        event = EventEnvelope("event-1", "fixture", "tenant-1", "stream-1", 0, 0, "2026-07-13T00:00:00Z", {})
        journal.append(command, 0, [event]); journal.close()
        active = home / "journal/active.seg"; raw = bytearray(active.read_bytes()); raw[30] ^= 1; active.write_bytes(raw)
        with self.assertRaises(Exception): LocalJournal.open(home, auth)
        diagnostic = WriterLock.acquire(home / "journal/writer.lock", "journal-shadow-1", 1); diagnostic.close()
        shutil.rmtree(home)


if __name__ == "__main__": unittest.main()
