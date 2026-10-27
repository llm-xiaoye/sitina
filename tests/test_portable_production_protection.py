"""Protection regressions; all mutations are inside a disposable test root."""
import os
import pwd
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from sitina import install_identity as identity
from sitina.legacy import fence, importer, production_genesis
from sitina.operations import phase6b
from sitina.orchestrator import bplus_production

class PortableProtectionTests(unittest.TestCase):
    def test_real_account_matches_existing_formal_location(self):
        expected = (Path(pwd.getpwuid(os.getuid()).pw_dir) / "SitinaHub").resolve()
        self.assertEqual(identity.LEGACY_PRODUCTION_HOME, expected)

    def test_other_account_has_no_developer_username(self):
        with patch.object(identity.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir="/home/another-account")):
            self.assertEqual(identity.account_production_home(), Path("/home/another-account/SitinaHub").resolve())

    def test_home_override_does_not_change_protected_account(self):
        expected = identity.account_production_home()
        with patch.dict(os.environ, {"HOME":"/isolated-test-home"}):
            self.assertEqual(identity.account_production_home(), expected)
            self.assertEqual(identity.canonical_journal_native_home(), Path("/isolated-test-home/SitinaHub"))

    def test_fresh_process_ignores_home_override_for_every_guard(self):
        code = """from sitina.install_identity import LEGACY_PRODUCTION_HOME
from sitina.legacy import fence, importer, production_genesis
from sitina.operations import phase6b
from sitina.orchestrator import bplus_production
assert all(m.LEGACY_PRODUCTION_HOME == LEGACY_PRODUCTION_HOME for m in (fence,importer,production_genesis,phase6b,bplus_production))
print(LEGACY_PRODUCTION_HOME)
"""
        env = dict(os.environ, HOME="/isolated-test-home", PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(identity.account_production_home()))

    def test_missing_account_fails_closed(self):
        with patch.object(identity.pwd, "getpwuid", side_effect=KeyError("missing account")):
            with self.assertRaises(KeyError):
                identity.account_production_home()

    def test_invalid_account_directory_fails_closed(self):
        for value in ("", "relative-home", "/"):
            with self.subTest(value=value), patch.object(identity.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=value)):
                with self.assertRaises(RuntimeError):
                    identity.account_production_home()

    def test_account_symlink_resolves_to_protected_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "actual").mkdir()
            (root / "alias").symlink_to(root / "actual", target_is_directory=True)
            with patch.object(identity.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(root/"alias"))):
                self.assertEqual(identity.account_production_home(), (root/"actual/SitinaHub").resolve())

    def test_markers_cannot_authorize_protected_root_or_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            production = base / "production"
            production.mkdir()
            for marker in (".sitina-bplus-disposable-v1", ".sitina-bplus-migration-workspace-v1"):
                (production / marker).touch()
            alias = base / "alias"
            alias.symlink_to(production, target_is_directory=True)
            before = sorted(p.name for p in production.iterdir())
            for target in (production, alias):
                with self.subTest(target=target), patch.object(fence, "LEGACY_PRODUCTION_HOME", production.resolve()), patch.object(importer, "LEGACY_PRODUCTION_HOME", production.resolve()), patch.object(production_genesis, "LEGACY_PRODUCTION_HOME", production.resolve()):
                    gate = fence.LegacyWriteGate(target)
                    with self.assertRaises(fence.LegacyWriteDenied):
                        gate.freeze("portable-test-001", fixture_authorization=True)
                    with self.assertRaises(fence.LegacyWriteDenied):
                        gate.unfreeze_fixture()
                    with self.assertRaises(importer.ImportError):
                        importer.MigrationWorkspace(target)
                    with self.assertRaises(production_genesis.GenesisError):
                        production_genesis.ProductionGenesisBuilder(target).build_fixture(
                            installation_id="test-installation", journal_id="test-journal",
                            epoch_root="test-epoch", key_namespace="test-namespace",
                            intended_snapshot_hash="sha256:"+"1"*64,
                            format_profile_hash="sha256:"+"2"*64, operator_id="test-operator")
            self.assertEqual(sorted(p.name for p in production.iterdir()), before)

    def test_isolated_marked_migration_remains_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/".sitina-bplus-migration-workspace-v1").touch()
            self.assertEqual(importer.MigrationWorkspace(root).root, root.resolve())

    def test_all_changed_consumers_share_account_identity(self):
        for module in (fence, importer, production_genesis, phase6b, bplus_production):
            self.assertEqual(module.LEGACY_PRODUCTION_HOME, identity.account_production_home())

