from __future__ import annotations

import json
import unittest
from pathlib import Path


class CapabilityConfigTests(unittest.TestCase):
    def test_default_configuration_is_fail_closed_and_canary_is_not_global(self) -> None:
        root = Path(__file__).resolve().parents[1]
        sitina = json.loads((root / "config" / "sitina.yaml").read_text(encoding="utf-8"))
        policy = json.loads((root / "config" / "true_multi_agent_policy.json").read_text(encoding="utf-8"))
        self.assertEqual(sitina["effects"]["activation_level"], "MOCK_ONLY")
        self.assertFalse(sitina["effects"]["live_capability_authorized"])
        self.assertTrue(sitina["providers"]["live_requires_explicit_flag"])
        self.assertTrue(policy["live_opt_in_required"])
        self.assertFalse(policy["external_mutation_allowed"])
        self.assertFalse(policy["execution_handoff_bypass_enabled"])
        self.assertEqual(policy["transport_retries"], 3)
        self.assertTrue(policy["deepseek_token_test_no_fallback"])
        self.assertEqual(policy["provider_fallback_profiles"], [])


if __name__ == "__main__":
    unittest.main()
