from __future__ import annotations

import os, shutil, tempfile, unittest
from pathlib import Path

from sitina.legacy.production_genesis import GenesisError, GenesisRegistry, ProductionGenesisBuilder


class ProductionJournalGenesisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home=Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home/".sitina-bplus-disposable-v1").write_text("fixture\n")
        self.builder=ProductionGenesisBuilder(self.home)
    def tearDown(self) -> None: shutil.rmtree(self.home,ignore_errors=True)

    def test_phase6a_builds_only_non_authoritative_fixture_identity(self) -> None:
        genesis=self.builder.build_fixture(installation_id="fixture-install",journal_id="journal-production-fixture",epoch_root="a"*64,key_namespace="phase6a-fixture",intended_snapshot_hash="b"*64,format_profile_hash="c"*64,operator_id="operator-1")
        self.assertEqual(genesis.environment_kind,"FIXTURE"); self.assertFalse(genesis.authority)
        self.assertTrue(genesis.genesis_id.startswith("fixture-genesis:"))

    def test_shadow_identity_or_feature_flag_cannot_be_reinterpreted(self) -> None:
        with self.assertRaises(GenesisError): self.builder.build_fixture(installation_id="fixture-install",journal_id="journal-shadow-phase2",epoch_root="a"*64,key_namespace="phase6a-fixture",intended_snapshot_hash="b"*64,format_profile_hash="c"*64,operator_id="operator-1",feature_flags={"production":True})

    def test_same_identity_different_bytes_is_incident_and_independent_verifier_required(self) -> None:
        first=self.builder.build_fixture(installation_id="fixture-install",journal_id="journal-production-fixture",epoch_root="a"*64,key_namespace="phase6a-fixture",intended_snapshot_hash="b"*64,format_profile_hash="c"*64,operator_id="operator-1")
        registry=GenesisRegistry(); registry.accept(first)
        with self.assertRaises(GenesisError): registry.accept(first.with_updates(format_profile_hash="d"*64))
        with self.assertRaises(GenesisError): self.builder.verify_independent(first,verifier_id="operator-1")
        verified=self.builder.verify_independent(first,verifier_id="verifier-2"); self.assertTrue(verified.independently_verified)


if __name__ == "__main__": unittest.main()

