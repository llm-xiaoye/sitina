from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RuntimeProfileTests(unittest.TestCase):
    def test_current_runner_is_exact_pinned_python(self) -> None:
        self.assertEqual(sys.version_info[:3], (3, 12, 13))

    def test_bin_sitina_prefers_the_approved_bundled_profile(self) -> None:
        launcher = (ROOT / "bin/sitina").read_text(encoding="utf-8")
        expected = ".cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
        self.assertIn(expected, launcher)
        self.assertNotIn("/usr/bin/python3", launcher)


if __name__ == "__main__":
    unittest.main()
