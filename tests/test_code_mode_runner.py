from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import code_mode_runner


class CodeModeRunnerTests(unittest.TestCase):
    def test_dry_run_is_zero_provider_and_not_code_mode_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            (root / "config" / "code_mode_profile.json").write_text(
                json.dumps({"schema": "CODE_MODE_PROFILE_V1", "identity_paths": ["config/code_mode_profile.json"]}),
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = code_mode_runner.main(["--dry-run", "--workspace", str(root)])
            document = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(document["dry_run_status"], "DRY_RUN_PASSED")
            self.assertEqual(document["provider_requests"], 0)
            self.assertEqual(document["physical_requests"], 0)
            self.assertEqual(document["status"], "CODE_MODE_BLOCKED")
            self.assertEqual(document["legacy_bplus_status"], "LEGACY_BPLUS_BLOCKED")
            self.assertFalse(document["execution_performed"])

    def test_candidate_is_valid_in_an_ordinary_environment_without_sitina_bypass_vars(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment.pop("SITINA_HOME", None)
        environment.pop("SITINA_CONTROL_PLANE_READONLY", None)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, str(repo / "scripts" / "code_mode_runner.py"),
             "--dry-run", "--workspace", str(repo)],
            cwd=repo,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertTrue(document["candidate_valid"], document)
        self.assertEqual(document["physical_requests"], 0)
        self.assertEqual(document["status"], "CODE_MODE_BLOCKED")


if __name__ == "__main__":
    unittest.main()
