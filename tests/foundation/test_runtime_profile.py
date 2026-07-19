from __future__ import annotations

import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / "scripts/bootstrap-bplus-dev.py"))
ProfileError = MODULE["ProfileError"]
assert_interpreter = MODULE["assert_interpreter"]
assert_target_isolated = MODULE["assert_target_isolated"]


class RuntimeProfileTests(unittest.TestCase):
    def test_current_runner_is_exact_pinned_python(self) -> None:
        self.assertEqual(sys.version_info[:3], (3, 12, 13))
        assert_interpreter()

    def test_system_python_39_is_rejected(self) -> None:
        with patch.object(sys, "version_info", (3, 9, 6)):
            with self.assertRaises(ProfileError):
                assert_interpreter()

    def test_profile_target_cannot_overlap_production(self) -> None:
        production = Path("/Users/moss/SitinaHub")
        for target in (production, production / ".venv", production.parent):
            with self.subTest(target=target):
                with self.assertRaises(ProfileError):
                    assert_target_isolated(target, production)

    def test_bin_sitina_prefers_the_approved_bundled_profile(self) -> None:
        launcher = (ROOT / "bin/sitina").read_text(encoding="utf-8")
        expected = ".cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
        self.assertIn(expected, launcher)
        self.assertNotIn("/usr/bin/python3", launcher)


if __name__ == "__main__":
    unittest.main()
