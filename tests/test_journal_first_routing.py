from __future__ import annotations

import unittest

from sitina.authority.resolver import AuthorityResolver
from sitina.orchestrator.bplus_adapter import AuthorityRoutedWriter, BPlusShadowError
from tests.test_authority_resolver import facts


class JournalFirstRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver=AuthorityResolver("binary","profile",ttl=10); self.events=[]
        self.router=AuthorityRoutedWriter(lambda p:self.events.append(("legacy",p)),lambda p:self.events.append(("journal",p)),lambda p:self.events.append(("projection",p)))

    def test_legacy_resolution_uses_only_legacy_sink(self) -> None:
        result=self.router.dispatch({"command":"x"},self.resolver.resolve(facts(),now=100),now=100,phase_flag="JOURNAL",feature_flag=True)
        self.assertEqual(result.writer,"legacy"); self.assertEqual([item[0] for item in self.events],["legacy"])

    def test_journal_resolution_appends_journal_before_projection(self) -> None:
        f=facts(prepared=True,command_id="c",request_hash="d"*64,genesis_hash="e"*64,snapshot_hash="f"*64,outcome_status="COMMITTED",outcome_verified=True,outcome_command_id="c",outcome_request_hash="d"*64,outcome_genesis_hash="e"*64,outcome_snapshot_hash="f"*64,cutover_absence_proven=False)
        result=self.router.dispatch({"command":"x"},self.resolver.resolve(f,now=100),now=100)
        self.assertEqual(result.writer,"journal"); self.assertEqual([item[0] for item in self.events],["journal","projection"])

    def test_every_no_writer_resolution_rejects_business_dispatch(self) -> None:
        resolution=self.resolver.resolve(facts(prepared=True,command_id="c",request_hash="d"*64,genesis_hash="e"*64,snapshot_hash="f"*64,cutover_absence_proven=False),now=100)
        with self.assertRaises(BPlusShadowError): self.router.dispatch({"command":"x"},resolution,now=100)
        self.assertEqual(self.events,[])

    def test_effect_capability_ceiling_remains_mock_only(self) -> None:
        self.assertEqual(self.router.effect_capability_ceiling,"MOCK_ONLY")


if __name__ == "__main__": unittest.main()

