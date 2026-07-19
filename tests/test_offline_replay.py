from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sitina.evidence.isolation_provider import IsolationCapability, ReplayIsolationProvider, probe_replay_isolation
from sitina.evidence.replay import OfflineReplayEngine, ReplayMode
from sitina.evidence.sandbox import ApplicationReplaySandbox
from tests.test_evidence_seal import passed_assessment


class OfflineReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"])); (self.home / ".sitina-bplus-disposable-v1").write_text("fixture\n")

    def tearDown(self) -> None: shutil.rmtree(self.home)

    def test_application_guards_deny_adversarial_effects_but_do_not_claim_os_sandbox(self) -> None:
        sandbox = ApplicationReplaySandbox(read_roots=(self.home,), output_root=self.home / "output")
        results = sandbox.run_adversarial_probe()
        self.assertTrue(all(item["denied"] for item in results.values()))
        self.assertEqual(sandbox.capability, IsolationCapability.APPLICATION_GUARDED_ZERO_EFFECT)
        self.assertIn("socket", results); self.assertIn("subprocess", results); self.assertIn("ctypes", results); self.assertIn("symlink_escape", results); self.assertIn("device", results); self.assertIn("inherited_fd", results)

    def test_unqualified_provider_cannot_label_enforced_sandbox(self) -> None:
        with self.assertRaises(ValueError): ReplayIsolationProvider.qualified("fake", kernel_enforced=False, guarantees={name: True for name in ReplayIsolationProvider.REQUIRED_GUARANTEES}, adversarial_results={name: True for name in ReplayIsolationProvider.REQUIRED_ADVERSARIAL_TESTS})
        actual = probe_replay_isolation()
        self.assertEqual(actual.capability, IsolationCapability.APPLICATION_GUARDED_ZERO_EFFECT)

    def test_replay_original_stops_at_t_and_does_not_generate_assessment(self) -> None:
        events = tuple({"position": i, "kind": "effect" if i == 2 else "fact"} for i in range(1, 6))
        assessment = passed_assessment()
        result = OfflineReplayEngine(events, terminal_position=3, original_assessment=assessment, isolation=probe_replay_isolation()).run(ReplayMode.REPLAY_ORIGINAL)
        self.assertEqual(result.replayed_positions, (1, 2, 3))
        self.assertEqual(result.presented_assessment_hash, assessment.assessment_hash)
        self.assertFalse(result.generated_assessment)
        self.assertEqual(result.external_effect_count, 0)

    def test_current_audit_applies_only_accepted_supplements_and_has_no_live_authority(self) -> None:
        result = OfflineReplayEngine(({"position":1,"kind":"fact"},), terminal_position=1, original_assessment=passed_assessment(), isolation=probe_replay_isolation()).run(ReplayMode.REPLAY_CURRENT_AUDIT, supplements=({"accepted":True,"audit":"CONTRADICTED"},{"accepted":False,"audit":"PASSED"}))
        self.assertEqual(result.current_audit, "CONTRADICTED")
        self.assertFalse(result.live_journal_position_allocated)
        self.assertFalse(result.live_permit_or_lease_allocated)
        self.assertTrue(result.disposable_projection)


if __name__ == "__main__": unittest.main()
