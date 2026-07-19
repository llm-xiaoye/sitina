from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from sitina.legacy.protocol_views import LegacyProtocolViews
from sitina.orchestrator.bplus_adapter import BPlusShadowAdapter
from sitina.protocols.blackboard import BlackboardNamespace


class ProtocolLegacyComparisonTests(unittest.TestCase):
    def test_fixed_views_match_legacy_report_shapes(self) -> None:
        views = LegacyProtocolViews()
        self.assertEqual(set(views.proposal_view([], []).keys()), {"submitted", "evaluations", "selections"})
        self.assertEqual(set(views.handoff_view([]).keys()), {"count", "items"})
        self.assertEqual(set(views.blackboard_view({}).keys()), {"count", "documents"})

    def test_phase_minus1_baseline_semantics_are_explicitly_classified(self) -> None:
        baseline = json.loads(Path("/Users/moss/Desktop/sitina/output/sitina-bplus-legacy-behavior-baseline-phase-minus1-final.json").read_text())
        report = LegacyProtocolViews.compare_baseline(
            baseline,
            proposal={"submitted_count": 4, "evaluation_count": 27, "selection_count": 0},
            handoff={"count": 15},
            blackboard={"present": True, "keys": ["count", "documents"]},
        )
        self.assertEqual(report["blocking_count"], 0)
        self.assertTrue(all(item["classification"] != "UNCLASSIFIED" for item in report["differences"]))

    def test_shadow_protocol_views_never_write_legacy_mutable_files(self) -> None:
        home = Path(os.environ["SITINA_HOME"])
        before = {path: (home / path).read_bytes() if (home / path).is_file() else None for path in ("state/handoffs.json", "state/blackboard.json", "state/proposals.json")}
        report = BPlusShadowAdapter.from_home(home).compare_protocol_views([], [], {})
        after = {path: (home / path).read_bytes() if (home / path).is_file() else None for path in before}
        self.assertEqual(before, after)
        self.assertFalse(report["authority"])


if __name__ == "__main__":
    unittest.main()
