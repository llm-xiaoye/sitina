from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.evidence.bundle import BundleBuilder, ContainerUnavailable
from sitina.evidence.seal import EvidenceSealer
from sitina.security.key_provider import InMemoryKeyProvider
from tests.test_evidence_package import core
from tests.test_evidence_seal import passed_assessment


class BundleArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")
        provider = InMemoryKeyProvider(); handle = provider.issue_evidence_sealer_capability("evidence-sealer")
        self.core = core(); self.assessment = passed_assessment(); self.seal = EvidenceSealer(provider, handle, evidence_policy_hash="a" * 64).seal(self.core, self.assessment, trusted_time=None)
        self.builder = BundleBuilder(self.home)

    def tearDown(self) -> None: shutil.rmtree(self.home)

    def test_layout_compression_owner_and_mtime_do_not_change_semantic_hash(self) -> None:
        first = self.builder.build_logical("artifact-1", self.core, self.assessment, self.seal, capability_manifest={"verify":"SELF_CONTAINED"}, layout_metadata={"mtime":0,"uid":0})
        second = self.builder.build_logical("artifact-2", self.core, self.assessment, self.seal, capability_manifest={"verify":"SELF_CONTAINED"}, layout_metadata={"mtime":99,"uid":501})
        self.assertEqual(first.semantic_hash, second.semantic_hash)
        self.assertNotEqual(first.container_hash, second.container_hash)

    def test_container_byte_change_changes_container_hash(self) -> None:
        artifact = self.builder.build_logical("artifact-3", self.core, self.assessment, self.seal, capability_manifest={"verify":"SELF_CONTAINED"})
        before = artifact.container_hash
        (artifact.path / "layout.json").write_text("{}\n", encoding="utf-8")
        self.assertNotEqual(self.builder.compute_container_hash(artifact.path), before)

    def test_same_generation_artifacts_enclose_identical_hash_layers(self) -> None:
        one = self.builder.build_logical("artifact-4", self.core, self.assessment, self.seal, capability_manifest={"verify":"SELF_CONTAINED"})
        two = self.builder.build_logical("artifact-5", self.core, self.assessment, self.seal, capability_manifest={"verify":"SELF_CONTAINED"})
        self.assertEqual((one.core_hash, one.assessment_hash, one.seal_hash), (two.core_hash, two.assessment_hash, two.seal_hash))

    def test_unavailable_zstandard_never_claims_deterministic_tar_zst(self) -> None:
        with self.assertRaises(ContainerUnavailable): self.builder.build_deterministic_tar_zst("artifact-zst", self.core, self.assessment, self.seal, capability_manifest={})


if __name__ == "__main__": unittest.main()
