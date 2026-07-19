from __future__ import annotations

import os, shutil, tempfile, unittest
from pathlib import Path

from sitina.legacy.importer import ImportError, MigrationWorkspace
from sitina.legacy.migration_control import MigrationControl, MigrationControlError


class LegacyImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root=Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.root/".sitina-bplus-migration-workspace-v1").write_text("fixture\n")
    def tearDown(self) -> None: shutil.rmtree(self.root,ignore_errors=True)

    def test_import_is_deterministic_deduplicates_representation_and_preserves_conflicts(self) -> None:
        records=({"source_id":"legacy-1","source_hash":"a"*64,"classification":"COORDINATION_FACT","payload":{"x":1}}, {"source_id":"legacy-1","source_hash":"a"*64,"classification":"AUDIT_REPRESENTATION","payload":{"x":1}}, {"source_id":"legacy-1","source_hash":"b"*64,"classification":"LEGACY_INCOMPLETE","payload":{"x":2}})
        one=MigrationWorkspace(self.root).import_records(records,snapshot_hash="c"*64,conversion_rule_hash="d"*64)
        two=MigrationWorkspace(self.root).import_records(records,snapshot_hash="c"*64,conversion_rule_hash="d"*64)
        self.assertEqual(one.candidate_hash,two.candidate_hash); self.assertEqual(one.deduplicated_count,1); self.assertEqual(one.conflict_count,1)
        self.assertFalse(one.authority)

    def test_projection_derived_fact_fabrication_is_rejected(self) -> None:
        with self.assertRaises(ImportError): MigrationWorkspace(self.root).import_records(({"source_id":"x","source_hash":"a"*64,"classification":"PROJECTION_DERIVED_NATIVE_FACT","payload":{}},),snapshot_hash="c"*64,conversion_rule_hash="d"*64)

    def test_migration_control_accepts_verified_candidate_but_is_not_business_authority(self) -> None:
        candidate=MigrationWorkspace(self.root).import_records(({"source_id":"x","source_hash":"a"*64,"classification":"COORDINATION_FACT","payload":{}},),snapshot_hash="c"*64,conversion_rule_hash="d"*64)
        with self.assertRaises(MigrationControlError): MigrationControl().accept(candidate,verifier_id=None)
        fact=MigrationControl().accept(candidate,verifier_id="verifier-1")
        self.assertFalse(fact.business_authority); self.assertFalse(fact.cutover_authority); self.assertEqual(fact.candidate_hash,candidate.candidate_hash)


if __name__ == "__main__": unittest.main()
