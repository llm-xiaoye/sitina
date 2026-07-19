from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.archive.copies import ArchiveCopyAssessment, ArchiveCopyState
from sitina.archive.jobs import ArchiveJob, ArchiveJobError, ArchiveJobState


class ArchiveCopyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        self.artifact = self.home / "artifact"; self.artifact.mkdir(); (self.artifact / "bundle.json").write_text('{"ok":true}\n')

    def tearDown(self) -> None: shutil.rmtree(self.home)

    def test_staging_then_final_location_each_receive_fresh_verification(self) -> None:
        job = ArchiveJob.create("job-1", "package-1", "artifact-1", self.artifact)
        job, staged = job.materialize_staging(self.home / "archive-staging")
        job, _ = job.verify_staging(staged)
        job, copy = job.transfer_final(staged, self.home / "cold" / "copy-1", copy_id="copy-1", residency={"region":"local","fault_domain":"cold-1"})
        job, final = job.verify_final(copy)
        job, _ = job.complete()
        self.assertEqual(job.state, ArchiveJobState.COMPLETED)
        self.assertEqual(final.assessment, ArchiveCopyAssessment.VERIFIED)
        self.assertNotEqual(job.staging_verification_id, final.final_verification_id)

    def test_job_completion_does_not_imply_replica_policy_compliance(self) -> None:
        job = ArchiveJob.create("job-2", "package-1", "artifact-1", self.artifact)
        self.assertFalse(job.replica_policy_compliant)

    def test_copy_can_be_stored_and_contradicted(self) -> None:
        job = ArchiveJob.create("job-3", "package-1", "artifact-1", self.artifact)
        job, staged = job.materialize_staging(self.home / "stage3"); job, _ = job.verify_staging(staged)
        job, copy = job.transfer_final(staged, self.home / "cold3", copy_id="copy-3", residency={"region":"local"})
        contradicted = copy.assess(ArchiveCopyAssessment.CONTRADICTED, verifier_id="verifier-2")
        self.assertEqual(contradicted.state, ArchiveCopyState.STORED)
        self.assertEqual(contradicted.assessment, ArchiveCopyAssessment.CONTRADICTED)

    def test_streams_own_lifecycle_and_projection_cannot_transition(self) -> None:
        job = ArchiveJob.create("job-4", "package-1", "artifact-1", self.artifact)
        self.assertEqual(job.stream_id, "archive-job/job-4")
        with self.assertRaises(AttributeError): getattr(job.projection(), "complete")()


if __name__ == "__main__": unittest.main()
