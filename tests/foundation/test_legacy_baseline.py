from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sitina.legacy.baseline import LegacyBehaviorBaselineBuilder

from home_factory import DisposableHomeFactory


PROFILE_HASH = "432bc042d5b258d56b852c5c74ea499920dce55849cd0375d011037b0c71c90e"


class LegacyBaselineTests(unittest.TestCase):
    def test_fixture_baseline_is_reproducible_and_covers_required_semantics(self) -> None:
        source = Path(__file__).resolve().parents[2]
        production = Path("/Users/moss/SitinaHub")
        current_test_home = Path(__import__("os").environ["SITINA_HOME"])
        factory = DisposableHomeFactory(source, production, current_test_home / "nested-baselines")
        left_home = factory.create(prefix="baseline-left-")
        right_home = factory.create(prefix="baseline-right-")
        try:
            left = LegacyBehaviorBaselineBuilder(left_home.path, python_profile_hash=PROFILE_HASH).capture()
            right = LegacyBehaviorBaselineBuilder(right_home.path, python_profile_hash=PROFILE_HASH).capture()
            self.assertEqual(
                left.semantic_hash,
                right.semantic_hash,
                json.dumps(
                    {
                        key: {"left": left.document.get(key), "right": right.document.get(key)}
                        for key in left.document
                        if left.document.get(key) != right.document.get(key)
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
            )
            semantic = left.document["semantic"]
            for key in (
                "run",
                "task_graph",
                "proposal",
                "review",
                "handoff",
                "arbitration",
                "blackboard",
                "lease",
                "side_effect",
                "replay",
                "evidence_export",
                "cli",
            ):
                self.assertIn(key, semantic)
            self.assertEqual(semantic["external_call_count"], 0)
        finally:
            left_home.cleanup()
            right_home.cleanup()


if __name__ == "__main__":
    unittest.main()
