from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_manifest_module():
    path = ROOT / "scripts/storage-source-manifest.py"
    spec = importlib.util.spec_from_file_location("storage_source_manifest", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load source-manifest module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourceManifestCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_manifest_module()
        cls.manifest = cls.module.build(ROOT, previous_manifest_hash=None)
        cls.paths = {item["path"] for item in cls.manifest["entries"]}

    def test_runtime_source_roots_are_manifested(self) -> None:
        required = {
            "agents/sitina-controller.md",
            "benchmarks/journal_benchmark.py",
            "mcp_servers/common_stdio.py",
            "prompts/agents/controller.md",
        }
        self.assertTrue(required.issubset(self.paths))

    def test_declared_safe_config_env_is_included(self) -> None:
        self.assertTrue(set(self.module.SAFE_ENV_FILES).issubset(self.paths))

    def test_secret_profile_env_and_generated_bytes_are_excluded(self) -> None:
        self.assertFalse(any(path.startswith("profiles/") for path in self.paths))
        self.assertFalse(any("__pycache__" in path or path.endswith(".pyc") for path in self.paths))

    def test_manifest_is_path_safe_and_unique(self) -> None:
        paths = [item["path"] for item in self.manifest["entries"]]
        self.assertEqual(len(paths), len(set(paths)))
        for value in paths:
            path = Path(value)
            self.assertFalse(path.is_absolute())
            self.assertNotIn("..", path.parts)


if __name__ == "__main__":
    unittest.main()
