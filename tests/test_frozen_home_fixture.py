"""Verify that make_frozen_home() actually activates the fence."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.fixtures import frozen_home as frozen_home_fixture
from tests.fixtures.frozen_home import make_frozen_home, FrozenBootstrapUnavailable


class FrozenHomeFixtureTests(unittest.TestCase):
    """Verify the frozen-home fixture correctly activates fence restrictions."""

    def test_frozen_home_denies_subprocess(self):
        """Subprocess.run in a frozen home must raise LegacyWriteDenied.

        This test runs in a subprocess with SITINA_HOME pre-set to a frozen temp
        home, then attempts subprocess.run. The fence should deny it.
        """
        try:
            frozen_home = make_frozen_home()
        except FrozenBootstrapUnavailable as exc:
            self.skipTest(str(exc))
        try:
            # Run Python in subprocess with frozen home active
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
            # Should have failed with LegacyWriteDenied
            self.assertNotEqual(result.returncode, 0, "subprocess should be denied in frozen home")
            self.assertIn("LegacyWriteDenied", result.stderr,
                          "Expected LegacyWriteDenied in stderr")
            self.assertIn("subprocess.Popen", result.stderr,
                          "Expected fence to deny subprocess.Popen")
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)

    def test_frozen_home_has_valid_freeze_record(self):
        """Frozen home must have the disposable marker AND a VALID freeze record
        (state FROZEN_NO_WRITER with a record_hash) — verified via the gate's
        status(), not merely file existence."""
        try:
            frozen_home = make_frozen_home()
        except FrozenBootstrapUnavailable as exc:
            self.skipTest(str(exc))
        try:
            self.assertTrue((frozen_home / ".sitina-bplus-disposable-v1").exists(),
                           "Should have disposable marker")
            from sitina.legacy.fence import LegacyWriteGate
            status = LegacyWriteGate(frozen_home).status()
            self.assertEqual(status.state, "FROZEN_NO_WRITER",
                            f"must be a valid frozen record, got {status.state}")
            self.assertIsNotNone(status.record_hash, "freeze record_hash must be present")
        finally:
            shutil.rmtree(frozen_home, ignore_errors=True)

    def test_unrelated_same_named_exception_is_not_converted_to_skip(self):
        """Exception names are not identities: an unrelated class must fail."""
        class LegacyWriteDenied(RuntimeError):
            pass

        created: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args, **kwargs):
            path = Path(real_mkdtemp(*args, **kwargs))
            created.append(path)
            return str(path)

        with (
            patch.object(frozen_home_fixture.tempfile, "mkdtemp", side_effect=tracked_mkdtemp),
            patch.object(frozen_home_fixture.subprocess, "run", side_effect=LegacyWriteDenied("unrelated")),
        ):
            with self.assertRaises(LegacyWriteDenied):
                make_frozen_home()
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created), created)

    def test_real_legacy_write_denied_is_the_only_skip_and_cleans_home(self):
        from sitina.legacy.fence import LegacyWriteDenied

        created: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args, **kwargs):
            path = Path(real_mkdtemp(*args, **kwargs))
            created.append(path)
            return str(path)

        with (
            patch.object(frozen_home_fixture.tempfile, "mkdtemp", side_effect=tracked_mkdtemp),
            patch.object(frozen_home_fixture.subprocess, "run", side_effect=LegacyWriteDenied("frozen")),
        ):
            with self.assertRaises(FrozenBootstrapUnavailable):
                make_frozen_home()
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created), created)

    def test_core_lookup_failure_does_not_create_temp_home(self):
        with (
            patch.object(frozen_home_fixture, "get_core_path", side_effect=RuntimeError("missing core")),
            patch.object(frozen_home_fixture.tempfile, "mkdtemp") as mkdtemp,
        ):
            with self.assertRaisesRegex(RuntimeError, "missing core"):
                make_frozen_home()
        mkdtemp.assert_not_called()

    def test_marker_creation_failure_cleans_temp_home(self):
        created: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args, **kwargs):
            path = Path(real_mkdtemp(*args, **kwargs))
            created.append(path)
            return str(path)

        with (
            patch.object(frozen_home_fixture.tempfile, "mkdtemp", side_effect=tracked_mkdtemp),
            patch.object(Path, "touch", side_effect=OSError("marker denied")),
        ):
            with self.assertRaisesRegex(OSError, "marker denied"):
                make_frozen_home()
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created), created)

    def test_non_object_freeze_json_fails_and_cleans_temp_home(self):
        created: list[Path] = []
        real_mkdtemp = tempfile.mkdtemp

        def tracked_mkdtemp(*args, **kwargs):
            path = Path(real_mkdtemp(*args, **kwargs))
            created.append(path)
            return str(path)

        fake_result = subprocess.CompletedProcess(
            args=[sys.executable], returncode=0, stdout="FREEZE_JSON:[]\n", stderr=""
        )
        with (
            patch.object(frozen_home_fixture.tempfile, "mkdtemp", side_effect=tracked_mkdtemp),
            patch.object(frozen_home_fixture.subprocess, "run", return_value=fake_result),
        ):
            with self.assertRaisesRegex(RuntimeError, "must be an object"):
                make_frozen_home()
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created), created)


if __name__ == "__main__":
    unittest.main()
