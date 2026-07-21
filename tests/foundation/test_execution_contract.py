from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sitina.runtime.execution_contract import (
    BootstrapManifestV0,
    ExecutionManifestV1,
    ManifestValidationError,
    ProductionHomeGuard,
)


SHA = "0" * 64


class ProductionHomeGuardTests(unittest.TestCase):
    def test_production_home_parent_descendant_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            production = base / "production"
            production.mkdir()
            alias = base / "alias"
            alias.symlink_to(production, target_is_directory=True)
            guard = ProductionHomeGuard(production)
            for unsafe in (production, production / "tests", base, alias):
                with self.subTest(path=unsafe):
                    with self.assertRaises(ManifestValidationError):
                        guard.assert_test_home_isolated(unsafe)

    def test_production_mutable_root_cannot_be_authorized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            (production / "data").mkdir(parents=True)
            guard = ProductionHomeGuard(production)
            with self.assertRaises(ManifestValidationError):
                guard.assert_mutation_roots_safe([production / "data" / "candidate"])


class BootstrapManifestTests(unittest.TestCase):
    def manifest(self, root: Path) -> dict:
        production = root / "production"
        production.mkdir()
        return {
            "schema": "PHASE_MINUS_1_BOOTSTRAP_V0",
            "bootstrap_id": "bootstrap-1",
            "authorization": {
                "authorized_phase": "-1",
                "authorized_task_range": "1..3",
                "approval_reference": "owner:standing-v1",
                "required_stop_point": "BOOTSTRAP_PROMOTION_REVIEW",
            },
            "roots": {
                "production_home": str(production),
                "bootstrap_workspace": str(root / "workspace"),
            },
            "initial_hashes": {"complete_plan_sha256": SHA},
            "exact_authorized_files": [str(root / "workspace" / "new.py")],
            "prohibited_operations": [
                "IMPORT_OR_RUN_SITINA_RUNTIME",
                "RUN_ANY_TEST",
                "WRITE_PRODUCTION_MUTABLE_DATA",
                "DELETE_OVERWRITE_OR_MODIFY_LEGACY_MATERIAL",
            ],
        }

    def test_missing_authorization_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = self.manifest(Path(temporary))
            del value["authorization"]["approval_reference"]
            with self.assertRaises(ManifestValidationError):
                BootstrapManifestV0.from_mapping(value)

    def test_phase_or_task_expansion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = self.manifest(Path(temporary))
            value["authorization"]["authorized_task_range"] = "1..4"
            with self.assertRaises(ManifestValidationError):
                BootstrapManifestV0.from_mapping(value)

    def test_self_generated_hash_forward_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = self.manifest(Path(temporary))
            value["dependency_lock_hash"] = SHA
            with self.assertRaises(ManifestValidationError):
                BootstrapManifestV0.from_mapping(value)


class ExecutionManifestTests(unittest.TestCase):
    def test_optional_production_sentinel_bindings_are_validated_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "production"
            test_home = root / "tests"
            source = root / "source"
            production.mkdir()
            test_home.mkdir()
            source.mkdir()
            value = {
                "schema": "EXECUTION_MANIFEST_V1",
                "execution_id": "exec-sentinel",
                "authorization": {
                    "authorized_phase": "6",
                    "authorized_task_range": "step6-gate",
                    "approval_reference": "owner:step6",
                    "required_stop_point": "STEP6_ACCEPTANCE",
                    "stable_command_id": "command-step6",
                    "stable_request_hash": SHA,
                },
                "roots": {
                    "production_home": str(production),
                    "test_home_root": str(test_home),
                    "authorized_mutation_roots": [str(source)],
                },
                "hashes": {
                    "baseline_manifest_hash": SHA,
                    "bootstrap_foundation_record_hash": SHA,
                    "python_profile_hash": SHA,
                    "dependency_lock_hash": SHA,
                    "plan_suite_hash": SHA,
                    "production_sentinel_hash": "sha256:" + SHA,
                    "production_mutable_sentinel_hash": "sha256:" + "1" * 64,
                },
                "exact_authorized_files": [],
            }
            manifest = ExecutionManifestV1.from_mapping(value)
            self.assertEqual(manifest.production_sentinel_hash, "sha256:" + SHA)
            self.assertEqual(manifest.production_mutable_sentinel_hash, "sha256:" + "1" * 64)
            value["hashes"]["production_mutable_sentinel_hash"] = "not-a-hash"
            with self.assertRaises(ManifestValidationError):
                ExecutionManifestV1.from_mapping(value)

    def test_production_test_home_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            production.mkdir()
            value = {
                "schema": "EXECUTION_MANIFEST_V1",
                "execution_id": "exec-1",
                "authorization": {
                    "authorized_phase": "-1",
                    "authorized_task_range": "1..9",
                    "approval_reference": "owner:standing-v1:phase-minus1",
                    "required_stop_point": "PHASE_MINUS1_ACCEPTANCE",
                    "stable_command_id": "command-1",
                    "stable_request_hash": SHA,
                },
                "roots": {
                    "production_home": str(production),
                    "test_home_root": str(production),
                    "authorized_mutation_roots": [str(Path(temporary) / "source")],
                },
                "hashes": {
                    "baseline_manifest_hash": SHA,
                    "bootstrap_foundation_record_hash": SHA,
                    "python_profile_hash": SHA,
                    "dependency_lock_hash": SHA,
                    "plan_suite_hash": SHA,
                },
                "exact_authorized_files": [],
            }
            with self.assertRaises(ManifestValidationError):
                ExecutionManifestV1.from_mapping(value)


if __name__ == "__main__":
    unittest.main()
