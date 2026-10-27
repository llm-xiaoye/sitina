from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import unittest

from sitina.legacy.cutover_contracts import CutoverCommandIdentity, READINESS_PREDICATE_IDS
from sitina.legacy.maintenance_manifest import CutoverDryRun, MaintenanceManifestBuilder, MaintenanceManifestError


def inputs() -> dict[str,bool]: return {item:True for item in READINESS_PREDICATE_IDS}


class CutoverDryRunTests(unittest.TestCase):
    def test_candidate_binds_window_quorum_paths_prestate_and_stable_command(self) -> None:
        command=CutoverCommandIdentity.freeze("cutover-command-1",{"snapshot_hash":"a"*64,"genesis_hash":"b"*64})
        candidate=MaintenanceManifestBuilder().build_candidate(predicates=inputs(),command=command,intended_snapshot_hash="a"*64,genesis_hash="b"*64,operators=("operator-1","operator-2"),allowed_paths=("/fixture/legacy","/fixture/journal"),window=(100,200),expires_at=200,expected_pre_state="LEGACY_WRITER_AUTHORIZED",stop_conditions=("SENTINEL_DRIFT","ACK_UNKNOWN"))
        self.assertFalse(candidate.authority); self.assertFalse(candidate.execute_capability_present); self.assertEqual(len(candidate.manifest_hash),64)
        report=CutoverDryRun().evaluate(candidate)
        self.assertTrue(report["eligible_for_phase6b_review"]); self.assertFalse(report["executed"])

    def test_missing_predicate_quorum_or_fixture_path_blocks_candidate(self) -> None:
        command=CutoverCommandIdentity.freeze("cutover-command-1",{"snapshot_hash":"a"*64,"genesis_hash":"b"*64})
        base=dict(predicates=inputs(),command=command,intended_snapshot_hash="a"*64,genesis_hash="b"*64,operators=("o1","o2"),allowed_paths=("/fixture/legacy","/fixture/journal"),window=(100,200),expires_at=200,expected_pre_state="LEGACY_WRITER_AUTHORIZED",stop_conditions=("STOP",))
        bad=inputs(); bad[READINESS_PREDICATE_IDS[0]]=False
        with self.assertRaises(MaintenanceManifestError): MaintenanceManifestBuilder().build_candidate(**{**base,"predicates":bad})
        with self.assertRaises(MaintenanceManifestError): MaintenanceManifestBuilder().build_candidate(**{**base,"operators":("o1",)})
        with self.assertRaises(MaintenanceManifestError): MaintenanceManifestBuilder().build_candidate(**{**base,"allowed_paths":((_SITINA_ACCOUNT_HOME + '/SitinaHub/data'),)})

if __name__ == "__main__": unittest.main()
