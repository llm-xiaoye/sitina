from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.archive.backup import BackupError, BackupHoldRegistry, CanonicalBackupBuilder
from sitina.cas.gc import GCController, GCFenceError, GCMarkFrontier, REQUIRED_CATALOGS
from sitina.journal.model import FrontierRef


class CanonicalBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        self.source = self.home / "canonical"; (self.source / "journal").mkdir(parents=True); (self.source / "cas").mkdir()
        (self.source / "journal" / "segment-1").write_bytes(b"segment"); (self.source / "cas" / "object-1").write_bytes(b"object")
        self.frontier = FrontierRef("journal-1", 1, "local", 1, "a" * 64)

    def tearDown(self) -> None: shutil.rmtree(self.home)

    def test_backup_freezes_prefix_holds_closure_and_verifies_before_release(self) -> None:
        holds = BackupHoldRegistry(); builder = CanonicalBackupBuilder(holds)
        manifest = builder.build("backup-1", source_root=self.source, destination=self.home / "backup", frontier=self.frontier, reachable_paths=("journal/segment-1", "cas/object-1"), active_prefix_disposition="FORCED_ROLLOVER")
        self.assertTrue(holds.is_held("backup-1", "cas/object-1"))
        result = builder.verify_restore(manifest, restore_root=self.home / "restore")
        self.assertTrue(result["verified"])
        builder.release_hold(manifest, restore_verified=True)
        self.assertFalse(holds.is_held("backup-1", "cas/object-1"))

    def test_gc_cannot_quarantine_backup_held_object(self) -> None:
        records=[]; gc=GCController(lambda e,p: records.append((e,p)))
        frontier=GCMarkFrontier(self.frontier,1,{name:"v1" for name in REQUIRED_CATALOGS},"b"*64,"c"*64)
        gc.mark(frontier,("object-1",)); gc.add_backup("object-1")
        with self.assertRaises(GCFenceError): gc.quarantine("object-1")

    def test_missing_reachable_object_fails_and_retains_hold(self) -> None:
        holds=BackupHoldRegistry(); builder=CanonicalBackupBuilder(holds)
        with self.assertRaises(BackupError): builder.build("backup-2",source_root=self.source,destination=self.home/"backup2",frontier=self.frontier,reachable_paths=("cas/missing",),active_prefix_disposition="FROZEN_EXACT_PREFIX")
        self.assertTrue(holds.has_backup("backup-2"))

    def test_hold_cannot_release_before_isolated_verify(self) -> None:
        holds=BackupHoldRegistry(); builder=CanonicalBackupBuilder(holds)
        manifest=builder.build("backup-3",source_root=self.source,destination=self.home/"backup3",frontier=self.frontier,reachable_paths=("cas/object-1",),active_prefix_disposition="FROZEN_EXACT_PREFIX")
        with self.assertRaises(BackupError): builder.release_hold(manifest,restore_verified=False)


if __name__ == "__main__": unittest.main()
