from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sitina.legacy.retirement import DisabledLegacyStore, LegacyAccessDisabled, LegacyRuntimePolicy
from sitina.orchestrator.bplus_production import BPlusProductionRuntimeError, ProductionRuntimeContext
from sitina.orchestrator.context import ContextBuilder
from sitina.storage import SitinaStore
from sitina.evals import run_safety_eval


class LegacyRetirementDisabledTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name)
        (self.home / ".sitina-clean-acceptance-v1").write_text("clean-acceptance\n", encoding="utf-8")
        (self.home / "config").mkdir()
        (self.home / "config/sitina.yaml").write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
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
        (self.home / "config/context_policy.json").write_text(
            json.dumps({
                "schema": "SITINA_CONTEXT_POLICY_V1",
                "token_budget": 4096,
                "history_token_budget": 1024,
                "max_recent_turns": 6,
                "renderer_version": "context-renderer-v2",
                "long_context_token_threshold": 2048,
            }),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_missing_legacy_is_valid_and_no_empty_database_is_created(self) -> None:
        policy = LegacyRuntimePolicy.load(self.home)
        self.assertTrue(policy.protected_environment)
        self.assertTrue(policy.fully_disabled)
        self.assertTrue(policy.missing_legacy_is_valid)
        with self.assertRaises(LegacyAccessDisabled):
            SitinaStore(self.home).init_db()
        self.assertFalse((self.home / "data/sitina.db").exists())

    def test_disabled_policy_detects_exact_retired_sqlite_artifacts_without_opening_them(self) -> None:
        policy = LegacyRuntimePolicy.load(self.home)
        (self.home / "data").mkdir()
        database = self.home / "data/sitina.db"
        database.write_bytes(b"")
        self.assertEqual(policy.unexpected_sqlite_artifacts(self.home), (database.resolve(),))
        self.assertEqual(database.read_bytes(), b"")

    def test_production_runtime_fails_closed_before_using_unexpected_legacy_sqlite(self) -> None:
        (self.home / ".sitina-bplus-disposable-v1").write_text("controlled\n", encoding="utf-8")
        (self.home / "data").mkdir()
        database = self.home / "data/sitina.db"
        database.write_bytes(b"")
        genesis = SimpleNamespace(
            environment_kind="CONTROLLED_PRODUCTION_SIMULATION",
            journal_id="journal-no-legacy-sqlite",
            intended_snapshot_hash="a" * 64,
            key_namespace="no-legacy-sqlite",
        )
        fence = {
            "state": "FROZEN_NO_WRITER",
            "production_genesis_journal_id": genesis.journal_id,
            "intended_snapshot_hash": genesis.intended_snapshot_hash,
        }
        with patch(
            "sitina.orchestrator.bplus_production.ProductionGenesisBuilder.load_persisted",
            return_value=genesis,
        ), patch(
            "sitina.orchestrator.bplus_production.LegacyWriteGate.read_verified_record",
            return_value=fence,
        ), self.assertRaisesRegex(BPlusProductionRuntimeError, "retired live SQLite artifacts"):
            ProductionRuntimeContext.load(self.home, allow_simulation=True)
        self.assertEqual(database.read_bytes(), b"")

    def test_disabled_store_rejects_direct_access(self) -> None:
        store = DisabledLegacyStore(LegacyRuntimePolicy.load(self.home))
        for operation in (
            store.connect,
            lambda: store.list_runs(limit=None),
            lambda: store.get_run("old-run"),
            lambda: store.timeline("old-run"),
        ):
            with self.assertRaises(LegacyAccessDisabled):
                operation()

    def test_journal_read_paths_do_not_touch_disabled_store(self) -> None:
        policy = LegacyRuntimePolicy.load(self.home)
        fake = object.__new__(ProductionRuntimeContext)
        fake.authority = SimpleNamespace(events=(), fast_start_report=None)
        fake.legacy = DisabledLegacyStore(policy)
        fake.legacy_policy = policy
        self.assertEqual(ProductionRuntimeContext.list_runs(fake), [])
        self.assertIsNone(ProductionRuntimeContext.show_run(fake, "old-run"))
        trace = ProductionRuntimeContext.trace_run(fake, "old-run")
        self.assertEqual(trace["status"], "not_found")
        self.assertFalse(trace["fallback_used"])
        protocol = ProductionRuntimeContext.protocol_view(fake, "old-run", "proposals")
        self.assertEqual(protocol["status"], "not_found")
        self.assertFalse(protocol["legacy_read_enabled"])
        self.assertFalse(protocol["fallback_used"])
        entity = ProductionRuntimeContext.find_protocol_entity(
            fake, "handoff", "old-handoff", id_fields=("handoff_id",)
        )
        self.assertEqual(entity["status"], "not_found")
        self.assertFalse(entity["legacy_read_enabled"])
        self.assertFalse(entity["fallback_used"])

    def test_unmarked_nonproduction_home_remains_explicit_legacy_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture_home = Path(directory)
            (fixture_home / "config").mkdir()
            (fixture_home / "config/sitina.yaml").write_text(
                json.dumps(
                    {
                        "storage_authority": {
                            "legacy_enabled": False,
                            "legacy_read_enabled": False,
                            "legacy_fallback_enabled": False,
                            "legacy_write_enabled": False,
                            "active_business_jsonl_enabled": False,
                            "missing_legacy_is_valid": True,
                        }
                    }
                ),
                encoding="utf-8",
            )
            policy = LegacyRuntimePolicy.load(fixture_home)
            self.assertFalse(policy.protected_environment)
            self.assertTrue(policy.legacy_enabled)
            self.assertTrue(policy.read_enabled)
            self.assertTrue(policy.write_enabled)

    def test_protected_eval_never_initializes_legacy_storage(self) -> None:
        with patch.object(SitinaStore, "init_db", side_effect=AssertionError("Legacy init invoked")):
            results = run_safety_eval(self.home)
        names = {item["case"] for item in results}
        self.assertIn("Legacy and JSONL routes fail closed", names)
        self.assertNotIn("approved write and rollback gate", names)
        self.assertFalse((self.home / "data/sitina.db").exists())

    def test_protected_context_never_reads_markdown_memory_as_authority(self) -> None:
        (self.home / "memory").mkdir()
        (self.home / "memory/global_memory.md").write_text(
            "legacy memory must not enter production context\n",
            encoding="utf-8",
        )
        context = ContextBuilder(self.home).build_default_context({"run_id": "run-protected"})
        self.assertEqual(context["memory"], "")
        self.assertEqual(context["memory_authority"], "canonical-journal-cas-memory-v1")


if __name__ == "__main__":
    unittest.main()
