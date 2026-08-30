"""Permanent fence contract: verify subprocess is denied in frozen homes.

This test documents and enforces the fence's correct behavior: subprocess.Popen
must be denied while frozen. It should ALWAYS PASS (even after verifier fixes) —
it's a contract test for the fence itself, not the verifier.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import unittest

from tests.fixtures.frozen_home import make_frozen_home, FrozenBootstrapUnavailable


class FrozenFenceContractTests(unittest.TestCase):
    """Permanent contract: fence denies subprocess.Popen while frozen."""

    def test_subprocess_denied_in_frozen_home(self):
        """Bare subprocess.run must be denied in a frozen home.

        This is a FENCE CONTRACT test, not a verifier test. It should always
        pass — if it fails, the fence itself is broken. The verifier must work
        AROUND this constraint (via authorized execution channel or in-process).
        """
        try:
            frozen_home = make_frozen_home()
        except FrozenBootstrapUnavailable as exc:
            self.skipTest(str(exc))
        try:
            # Attempt subprocess in a frozen-home subprocess
            result = subprocess.run(
                [
                    sys.executable, "-c",
                    f"import os; os.environ['SITINA_HOME']='{frozen_home}'; "
                    f"import sitina; from sitina.legacy.fence import install_legacy_mutation_guard; "
                    f"install_legacy_mutation_guard('{frozen_home}'); import subprocess; "
                    f"subprocess.run(['{sys.executable}', '--version'], capture_output=True)"
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Must fail with LegacyWriteDenied
            self.assertNotEqual(result.returncode, 0,
                               "Fence must deny subprocess.Popen while frozen")
            self.assertIn("LegacyWriteDenied", result.stderr)
            self.assertIn("subprocess.Popen", result.stderr)
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
