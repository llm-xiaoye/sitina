from __future__ import annotations

import argparse
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/storage-closure-sentinel.py"
SPEC = importlib.util.spec_from_file_location("storage_closure_sentinel", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
sentinel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sentinel)


class StorageClosureSentinelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.extensions = self.root / "extensions"
        self.extensions.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _capture(self, name: str) -> Path:
        output = self.root / name
        arguments = argparse.Namespace(
            home=str(self.home),
            goal_thread_id="fixture-goal",
            output=str(output),
            workers=2,
            additional_root=[],
        )
        with mock.patch.dict(os.environ, {"SITINA_EXTENSIONS_HOME": str(self.extensions)}):
            self.assertEqual(sentinel.capture(arguments), 0)
        return output

    def test_capture_covers_authority_runtime_and_external_roots(self) -> None:
        fixture = {
            "journal/active.seg": b"journal",
            "cas/objects/aa01": b"cas-body",
            "projections/current.sqlite": b"projection",
            "output/evidence.json": b"evidence",
            "state/checkpoint.json": b"checkpoint",
            "runtime/compatibility-leases/process.lease.json": b"lease",
        }
        for relative, body in fixture.items():
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        (self.extensions / "registry.json").write_text("{}\n", encoding="utf-8")
        output = self._capture("sentinel.json")
        value = json.loads(output.read_text(encoding="utf-8"))
        roots = {item["label"]: item for item in value["roots"]}
        for label in ("journal", "cas", "projections", "output", "state", "runtime", "external_extensions"):
            self.assertTrue(roots[label]["exists"], label)
            self.assertGreater(roots[label]["entry_count"], 0, label)
        self.assertEqual(sentinel._load(str(output))["report_sha256"], value["report_sha256"])

    def test_capture_rejects_symlinked_production_root(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.home / "journal").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(sentinel.SentinelError, "must not be a symlink"):
            self._capture("sentinel.json")

    def test_diff_localizes_changed_cas_bucket(self) -> None:
        object_path = self.home / "cas/objects/aa01"
        object_path.parent.mkdir(parents=True)
        object_path.write_bytes(b"before")
        before = self._capture("before.json")
        object_path.write_bytes(b"after")
        after = self._capture("after.json")
        output = self.root / "diff.json"
        arguments = argparse.Namespace(before=str(before), after=str(after), output=str(output))
        self.assertEqual(sentinel.compare(arguments), 0)
        diff = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(diff["unchanged"])
        cas = next(item for item in diff["root_changes"] if item["label"] == "cas")
        self.assertEqual([item["name"] for item in cas["bucket_changes"]], ["objects/aa"])

    def test_tampered_report_is_rejected(self) -> None:
        output = self._capture("sentinel.json")
        value = json.loads(output.read_text(encoding="utf-8"))
        value["captured_at"] = "tampered"
        output.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(sentinel.SentinelError, "report hash mismatch"):
            sentinel._load(str(output))

    def test_root_mutation_during_capture_is_rejected(self) -> None:
        root = self.home / "journal"
        root.mkdir()
        active = root / "active.seg"
        active.write_bytes(b"stable")
        original_paths = sentinel._paths
        calls = 0

        def mutate_on_second_inventory(candidate: Path) -> list[Path]:
            nonlocal calls
            calls += 1
            if calls == 2:
                active.write_bytes(b"changed-after-hash")
            return original_paths(candidate)

        with mock.patch.object(sentinel, "_paths", side_effect=mutate_on_second_inventory):
            with self.assertRaisesRegex(sentinel.SentinelError, "changed during Sentinel capture"):
                sentinel._capture_root("journal", root, workers=1)


if __name__ == "__main__":
    unittest.main()
