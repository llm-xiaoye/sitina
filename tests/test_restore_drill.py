from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.archive.backup import BackupHoldRegistry, CanonicalBackupBuilder
from sitina.archive.restore import RestoreDrill, RestoreError, RestoreIdentityIncident
from sitina.journal.model import FrontierRef


class RestoreDrillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home=Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home/".sitina-bplus-disposable-v1").write_text("fixture\n")
        source=self.home/"source"; (source/"journal").mkdir(parents=True); (source/"cas").mkdir(); (source/"journal"/"segment").write_bytes(b"journal"); (source/"cas"/"object").write_bytes(b"cas")
        self.manifest=CanonicalBackupBuilder(BackupHoldRegistry()).build("backup-1",source_root=source,destination=self.home/"final-cold",frontier=FrontierRef("journal-1",1,"local",1,"a"*64),reachable_paths=("journal/segment","cas/object"),active_prefix_disposition="FORCED_ROLLOVER")

    def tearDown(self) -> None: shutil.rmtree(self.home)

    def test_restore_validates_identity_chain_and_object_closure_without_writer(self) -> None:
        result=RestoreDrill().restore(self.manifest,source_copy=self.home/"final-cold",target=self.home/"restored",source_kind="FINAL_COLD_COPY")
        self.assertTrue(result.verified); self.assertFalse(result.writer_activated); self.assertEqual(result.journal_id,"journal-1")

    def test_same_identity_different_hash_is_integrity_incident(self) -> None:
        target=self.home/"restored2"; target.mkdir(); (target/"restore-identity.json").write_text('{"backup_id":"backup-1","manifest_hash":"different"}')
        with self.assertRaises(RestoreIdentityIncident): RestoreDrill().restore(self.manifest,source_copy=self.home/"final-cold",target=target,source_kind="FINAL_COLD_COPY")

    def test_changed_recovered_bytes_require_new_epoch(self) -> None:
        (self.home/"final-cold"/"cas"/"object").write_bytes(b"changed")
        with self.assertRaises(RestoreError): RestoreDrill().restore(self.manifest,source_copy=self.home/"final-cold",target=self.home/"restore3",source_kind="FINAL_COLD_COPY")
        result=RestoreDrill().restore(self.manifest,source_copy=self.home/"final-cold",target=self.home/"restore4",source_kind="FINAL_COLD_COPY",allow_new_recovery_epoch=2)
        self.assertEqual(result.recovery_epoch,2); self.assertFalse(result.original_epoch_adopted)

    def test_staging_copy_is_never_accepted_as_cold_restore_source(self) -> None:
        with self.assertRaises(RestoreError): RestoreDrill().restore(self.manifest,source_copy=self.home/"final-cold",target=self.home/"restore5",source_kind="STAGING")


if __name__ == "__main__": unittest.main()
