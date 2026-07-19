from __future__ import annotations

import subprocess, unittest
from pathlib import Path

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
        with self.assertRaises(MaintenanceManifestError): MaintenanceManifestBuilder().build_candidate(**{**base,"allowed_paths":("/Users/moss/SitinaHub/data",)})

    def test_phase6a_script_has_no_execute_option(self) -> None:
        script=Path(__file__).parents[1]/"scripts/cutover-dry-run.py"
        source=script.read_text(encoding="utf-8")
        self.assertNotIn('add_argument("--execute"',source); self.assertNotIn("execute_cutover",source)
        completed=subprocess.run(["/Users/moss/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3",str(script),"--help"],capture_output=True,text=True)
        self.assertEqual(completed.returncode,0); self.assertNotIn("--execute",completed.stdout)


if __name__ == "__main__": unittest.main()

