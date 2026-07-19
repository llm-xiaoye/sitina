from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.effects.ingress import AdmissionClass, DurableJournalIntake, IngressGateway, ReceiptKind
from sitina.effects.ingress_spool import DurableIngressSpool, IngressCapacity


class EffectIngressDurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n", encoding="utf-8")
        self.spool = DurableIngressSpool(self.home, IngressCapacity(ordinary=1, observation=1, receipt=1, closing=1))
        self.journal = DurableJournalIntake(self.home)

    def tearDown(self) -> None:
        shutil.rmtree(self.home)

    def test_spool_barrier_returns_custody_only_and_never_accepted_alias(self) -> None:
        gateway = IngressGateway(journal=None, spool=self.spool)
        receipt = gateway.receive(source_identity="remote-1", raw=b"payload", classification="OBSERVATION", nonce="nonce-1", target_hint="effect-1", admission_class=AdmissionClass.OBSERVATION, received_at=1)
        self.assertEqual(receipt.kind, ReceiptKind.DURABLY_RECEIVED)
        self.assertFalse(receipt.business_admitted)
        self.assertFalse(receipt.satisfies("EFFECT_OUTCOME"))
        self.assertNotIn("ACCEPTED", {item.name for item in ReceiptKind})
        candidate = next((self.spool.candidates).glob("*.json")).read_text(encoding="utf-8")
        self.assertNotIn(b"payload".hex(), candidate)
        self.assertIn("AES256_GCM_DURABLE_INGRESS_SPOOL_V1", candidate)

    def test_journal_frame_is_the_only_source_of_journal_admitted(self) -> None:
        gateway = IngressGateway(journal=self.journal, spool=self.spool)
        receipt = gateway.receive(source_identity="remote-1", raw=b"payload", classification="OBSERVATION", nonce="nonce-1", target_hint="effect-1", admission_class=AdmissionClass.OBSERVATION, received_at=1)
        self.assertEqual(receipt.kind, ReceiptKind.JOURNAL_ADMITTED)
        self.assertTrue(receipt.business_admitted)
        self.assertTrue(receipt.journal_frame_hash)

    def test_restart_drains_same_stable_command_and_maps_custody_to_admission(self) -> None:
        receipt = IngressGateway(journal=None, spool=self.spool).receive(source_identity="remote-1", raw=b"payload", classification="OBSERVATION", nonce="nonce-1", target_hint="effect-1", admission_class=AdmissionClass.OBSERVATION, received_at=1)
        restarted = DurableIngressSpool(self.home, IngressCapacity(ordinary=1, observation=1, receipt=1, closing=1))
        mappings = restarted.drain(self.journal)
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].custody_receipt_id, receipt.receipt_id)
        self.assertEqual(mappings[0].journal_receipt.kind, ReceiptKind.JOURNAL_ADMITTED)
        self.assertEqual(mappings, restarted.drain(self.journal))

    def test_invalid_input_gets_terminal_journal_rejection_not_business_truth(self) -> None:
        receipt = IngressGateway(journal=self.journal, spool=self.spool).receive(source_identity="remote-1", raw=b"invalid", classification="INVALID", nonce="nonce-1", target_hint="effect-1", admission_class=AdmissionClass.OBSERVATION, received_at=1)
        self.assertEqual(receipt.kind, ReceiptKind.JOURNAL_ADMITTED)
        self.assertEqual(receipt.terminal_disposition, "REJECTED_QUARANTINED")
        self.assertFalse(receipt.business_admitted)

    def test_emergency_reserves_and_total_outage_stop_dispatch(self) -> None:
        ordinary = IngressGateway(journal=None, spool=self.spool)
        ordinary.receive(source_identity="a", raw=b"1", classification="ORDINARY", nonce="n1", target_hint="x", admission_class=AdmissionClass.ORDINARY, received_at=1)
        failure = ordinary.receive(source_identity="b", raw=b"2", classification="ORDINARY", nonce="n2", target_hint="x", admission_class=AdmissionClass.ORDINARY, received_at=2)
        self.assertEqual(failure.kind, ReceiptKind.UNRECEIVED_RETRYABLE)
        protected = ordinary.receive(source_identity="c", raw=b"3", classification="OBSERVATION", nonce="n3", target_hint="x", admission_class=AdmissionClass.OBSERVATION, received_at=3)
        self.assertEqual(protected.kind, ReceiptKind.DURABLY_RECEIVED)
        outage = IngressGateway(journal=None, spool=None)
        failed = outage.receive(source_identity="d", raw=b"4", classification="OBSERVATION", nonce="n4", target_hint="x", admission_class=AdmissionClass.OBSERVATION, received_at=4)
        self.assertEqual(failed.kind, ReceiptKind.UNRECEIVED_RETRYABLE)
        self.assertTrue(outage.outbound_dispatch_stopped)


if __name__ == "__main__":
    unittest.main()
