from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sitina.runtime.execution_contract import ManifestValidationError, ProductionHomeGuard

from home_factory import DisposableHomeFactory, MARKER


class DisposableHomeTests(unittest.TestCase):
    def test_factory_creates_nonsecret_seeded_home_and_safe_cleanup(self) -> None:
        source = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "production"
            production.mkdir()
            factory = DisposableHomeFactory(source, production, root / "test-homes")
            disposable = factory.create()
            home = disposable.path
            self.assertTrue((home / MARKER).is_file())
            self.assertTrue((home / "fixtures/legacy/sitina.db").is_file())
            self.assertTrue((home / "README.md").is_file())
            self.assertTrue((home / "temp").is_dir())
            self.assertTrue((home / "outputs/generated").is_dir())
            self.assertTrue((home / "outputs/reports/Sitina_v1_final_acceptance_report.md").is_file())
            self.assertFalse(any(path.name == "gpt.env" and "profiles" not in path.parts for path in home.rglob("*")))
            self.assertNotIn("/Users/moss", (home / "config/mcp/servers.yaml").read_text(encoding="utf-8"))
            disposable.cleanup()
            self.assertFalse(home.exists())

    def test_cleanup_refuses_missing_marker(self) -> None:
        source = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "production"
            production.mkdir()
            disposable = DisposableHomeFactory(source, production, root / "test-homes").create()
            (disposable.path / MARKER).unlink()
            with self.assertRaises(RuntimeError):
                disposable.cleanup()

    def test_import_environment_must_be_set_before_constants_load(self) -> None:
        current = os.environ.get("SITINA_HOME")
        self.assertIsNotNone(current)
        self.assertNotEqual(Path(current).resolve(), Path("/Users/moss/SitinaHub").resolve())

    def test_production_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            production.mkdir()
            alias = Path(temporary) / "alias"
            alias.symlink_to(production, target_is_directory=True)
            with self.assertRaises(ManifestValidationError):
                ProductionHomeGuard(production).assert_test_home_isolated(alias)


if __name__ == "__main__":
    unittest.main()
