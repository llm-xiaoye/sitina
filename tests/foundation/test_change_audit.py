from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/change-audit-dry-run.py"
MODULE = runpy.run_path(str(SCRIPT))
AuditError = MODULE["AuditError"]
build_manifest = MODULE["build_manifest"]


class ContentManifestTests(unittest.TestCase):
    def test_runtime_and_secret_files_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "core").mkdir()
            (root / "core/app.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "config").mkdir()
            (root / "config/public.yaml").write_text("enabled: true\n", encoding="utf-8")
            (root / "config/private.env").write_text("TOKEN=do-not-read\n", encoding="utf-8")
            (root / "data").mkdir()
            (root / "data/sitina.db").write_bytes(b"runtime")
            manifest = build_manifest(root)
            paths = {entry["path"] for entry in manifest["entries"]}
            self.assertEqual(paths, {"config/public.yaml", "core/app.py"})

    def test_symlink_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "core").mkdir()
            (root / "data").mkdir()
            (root / "data/secret.py").write_text("SECRET = 1\n", encoding="utf-8")
            (root / "core/alias.py").symlink_to(root / "data/secret.py")
            with self.assertRaises(AuditError):
                build_manifest(root)

    def test_manifest_is_reproducible_and_links_previous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs/design.md").write_text("design\n", encoding="utf-8")
            first = build_manifest(root, "sha256:previous")
            second = build_manifest(root, "sha256:previous")
            self.assertEqual(first, second)
            self.assertEqual(first["previous_manifest_hash"], "sha256:previous")


if __name__ == "__main__":
    unittest.main()
