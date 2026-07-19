from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import sitina.cli as cli


class ReadOnlyDiagnosticsCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_home = cli.SITINA_HOME
        self.home = Path(tempfile.mkdtemp(dir=os.environ["SITINA_HOME"]))
        cli.SITINA_HOME = self.home
        (self.home / "config").mkdir()
        repo = Path(__file__).resolve().parents[1]
        shutil.copyfile(repo / "config" / "format_capabilities.json", self.home / "config" / "format_capabilities.json")
        shutil.copyfile(repo / "config" / "feature_flags.json", self.home / "config" / "feature_flags.json")
        self.legacy = self.home / "legacy-fixture"
        self.legacy.mkdir()
        (self.legacy / "old.jsonl").write_text('{"old":true}\n', encoding="utf-8")

    def tearDown(self) -> None:
        cli.SITINA_HOME = self.original_home

    def _main(self, arguments: list[str]) -> tuple[int, object]:
        with redirect_stdout(StringIO()):
            code = cli.main(arguments)
        return code, cli._LAST_PRINTED_JSON

    def test_parser_exposes_every_required_read_only_diagnostic(self) -> None:
        parser = cli.build_parser()
        commands = (
            ["storage", "inspect"],
            ["journal", "startup-report"],
            ["journal", "verify", "--full"],
            ["journal", "scrub", "--background"],
            ["projection", "report"],
            ["projection", "coverage"],
            ["memory", "report"],
            ["storage", "gc", "--dry-run"],
            ["storage", "migration-plan"],
            ["storage", "archive-plan", "--source", str(self.legacy)],
            ["runtime", "compatibility"],
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(callable(parser.parse_args(command).func))

    def test_non_authority_diagnostics_are_read_only_and_do_not_initialize_legacy(self) -> None:
        before = {
            str(path.relative_to(self.home)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.home.rglob("*")
            if path.is_file()
        }
        code, migration = self._main(["storage", "migration-plan"])
        self.assertEqual(code, 0)
        self.assertTrue(migration["dry_run"])
        self.assertFalse(migration["migration_executed"])
        code, inspect = self._main(["storage", "inspect"])
        self.assertEqual(code, 0)
        self.assertTrue(inspect["read_only"])
        code, compatibility = self._main(["runtime", "compatibility"])
        self.assertEqual(code, 0)
        self.assertTrue(compatibility["read_only"])
        code, archive = self._main(
            ["storage", "archive-plan", "--source", str(self.legacy), "--target", str(self.home / "cold-target")]
        )
        self.assertEqual(code, 0)
        self.assertTrue(archive["dry_run"])
        self.assertFalse(archive["source_deleted"])
        self.assertFalse((self.home / "cold-target").exists())
        self.assertFalse((self.home / "data" / "sitina.db").exists())
        after = {
            str(path.relative_to(self.home)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.home.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
