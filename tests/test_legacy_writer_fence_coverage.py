from __future__ import annotations

import os, shutil, tempfile, unittest
from pathlib import Path

from sitina.authority.model import AuthorityState
from sitina.authority.resolver import AuthorityResolver
from sitina.legacy.fence import (
    AUTHORITY_GUARDED_WRITER_ENTRYPOINTS, LegacyWriteDenied, LegacyWriteGate,
    build_authority_fence_coverage,
)
from tests.test_authority_resolver import facts


class LegacyWriterFenceCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home=Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home/".sitina-bplus-disposable-v1").write_text("fixture\n")
        self.resolver=AuthorityResolver("binary","profile",ttl=10)
    def tearDown(self) -> None: shutil.rmtree(self.home,ignore_errors=True)

    def test_registry_covers_every_current_top_level_writer_entry(self) -> None:
        report=build_authority_fence_coverage(AUTHORITY_GUARDED_WRITER_ENTRYPOINTS)
        self.assertEqual(report["blocker_count"],0); self.assertGreaterEqual(report["entrypoint_count"],8)

    def test_legacy_gate_requires_fresh_legacy_resolution(self) -> None:
        gate=LegacyWriteGate(self.home); authorized=self.resolver.resolve(facts(),now=100)
        gate.assert_writes_authorized(authorized,now=100)
        prepared=self.resolver.resolve(facts(prepared=True,command_id="c",request_hash="d"*64,genesis_hash="e"*64,snapshot_hash="f"*64,cutover_absence_proven=False),now=100)
        with self.assertRaises(LegacyWriteDenied): gate.assert_writes_authorized(prepared,now=100)
        with self.assertRaises(LegacyWriteDenied): gate.assert_writes_authorized(authorized,now=111)

    def test_simulated_frozen_fixture_blocks_direct_mutation_gate(self) -> None:
        gate=LegacyWriteGate(self.home); gate.freeze("snapshot-1",fixture_authorization=True)
        with self.assertRaises(LegacyWriteDenied): gate.assert_writes_authorized(self.resolver.resolve(facts(),now=100),now=100)


if __name__ == "__main__": unittest.main()

