from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"


class InstallIdentityTests(unittest.TestCase):
    def _run_in_home(self, source: str, home: Path) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["HOME"] = str(home)
        environment.pop("SITINA_HOME", None)
        environment["PYTHONPATH"] = str(CORE)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-c", source],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_canonical_home_is_protected_and_noncanonical_home_is_disposable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sitina-install-identity-") as temporary:
            result = self._run_in_home(
                """
from pathlib import Path
from sitina.legacy.retirement import LegacyRuntimePolicy

expected = (Path.home() / "SitinaHub").resolve(strict=False)
canonical = expected
canonical.mkdir(parents=True)
protected = LegacyRuntimePolicy.load(canonical)
fixture = Path.home() / "other-fixture"
fixture.mkdir()
disposable = LegacyRuntimePolicy.load(fixture)
assert canonical == expected
assert protected.protected_environment is True
assert protected.fully_disabled is True
assert protected.missing_legacy_is_valid is True
assert disposable.protected_environment is False
assert disposable.legacy_enabled is True
assert disposable.fully_disabled is False
from sitina.install_identity import LEGACY_PRODUCTION_HOME, canonical_journal_native_home
assert canonical_journal_native_home() == expected
legacy = LegacyRuntimePolicy.load(LEGACY_PRODUCTION_HOME)
assert legacy.protected_environment is True
assert legacy.fully_disabled is True
assert legacy.missing_legacy_is_valid is True
print("identity policy ok")
""",
                Path(temporary),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_constants_default_follows_home_in_a_new_process(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sitina-install-identity-") as temporary:
            result = self._run_in_home(
                """
from pathlib import Path
from sitina.constants import SITINA_HOME

expected = (Path.home() / "SitinaHub").resolve(strict=False)
assert SITINA_HOME.resolve(strict=False) == expected, (SITINA_HOME, expected)
print(SITINA_HOME)
""",
                Path(temporary),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_canonical_home_rejects_clean_acceptance_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sitina-install-identity-") as temporary:
            result = self._run_in_home(
                """
from pathlib import Path
from unittest.mock import patch
from sitina.install_identity import LEGACY_PRODUCTION_HOME
from sitina.orchestrator.clean_acceptance import CleanAcceptanceContext, CleanAcceptanceError

root = Path.home() / "SitinaHub"
root.mkdir(parents=True)
(root / CleanAcceptanceContext.MARKER).touch()
with patch(
    "sitina.orchestrator.clean_acceptance.MacOSKeychainProvider",
    side_effect=AssertionError("canonical clean-acceptance guard was bypassed"),
):
    try:
        CleanAcceptanceContext.initialize(root)
    except CleanAcceptanceError as error:
        assert str(error) == "clean acceptance cannot use the active Sitina installation", error
        print("clean acceptance rejected")
    else:
        raise AssertionError("canonical home accepted a Clean Acceptance marker")
try:
    CleanAcceptanceContext.initialize(LEGACY_PRODUCTION_HOME)
except CleanAcceptanceError as error:
    assert str(error) == "clean acceptance cannot use the fixed Legacy Production root", error
else:
    raise AssertionError("fixed Legacy Production root accepted by Clean Acceptance")
""",
                Path(temporary),
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_code_mode_rejects_canonical_home_as_mutation_workspace_and_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sitina-install-identity-") as temporary:
            result = self._run_in_home(
                """
from pathlib import Path
from sitina.orchestrator.code_mode_gate import CodeModeRuntimePolicy, build_candidate_manifest

root = Path.home() / "SitinaHub"
root.mkdir(parents=True)
policy = CodeModeRuntimePolicy()
authorization = policy.authorize(
    mode="MULTI",
    message="create a file in the workspace",
    session_id="session-1",
    workspace=root,
)
assert authorization["allowed"] is False, authorization
assert authorization["intent_authorized"] is False, authorization
assert authorization["reasons"] == ["Code Mode cannot mutate the active Sitina installation"], authorization
try:
    build_candidate_manifest(root, identity_paths=())
except ValueError as error:
    assert str(error) == "Code Mode candidate cannot be the active Sitina installation", error
    print("code mode rejected")
else:
    raise AssertionError("canonical home was accepted as a Code Mode candidate")
""",
                Path(temporary),
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
