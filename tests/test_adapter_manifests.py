from __future__ import annotations

import json
import unittest
from pathlib import Path

from sitina.effects.adapters import (
    AdapterManifest,
    AdapterManifestError,
    AdapterRegistry,
    RecoveryLevel,
    sign_manifest,
)


def payload(level: str = "A") -> dict:
    return {
        "adapter_id": "mock-a",
        "version": 1,
        "binary_hash": "a" * 64,
        "operation": "mock.mutate",
        "externality": "MUTATION",
        "reversibility": "REVERSIBLE",
        "recovery_level": level,
        "request_schema_hash": "b" * 64,
        "result_schema_hash": "c" * 64,
        "remote_idempotency": level == "A",
        "status_query": level in {"A", "B"},
        "not_found_proves_absence": False,
        "external_request_id_required": True,
        "idempotency_retention_seconds": 60,
        "max_physical_sends_per_attempt": 1,
        "sdk_retries_enabled": False,
        "redirect_replay_enabled": False,
        "publisher": "sitina-test",
    }


class AdapterManifestTests(unittest.TestCase):
    def test_signed_versioned_manifest_is_verified_in_non_test_profile(self) -> None:
        manifest = sign_manifest(payload(), b"manifest-key")
        registry = AdapterRegistry(b"manifest-key", profile="shadow")
        registry.register(manifest)
        self.assertEqual(registry.get("mock-a", 1).recovery_level, RecoveryLevel.A)

    def test_unsigned_or_tampered_manifest_is_rejected(self) -> None:
        unsigned = AdapterManifest.from_mapping(payload())
        with self.assertRaises(AdapterManifestError):
            AdapterRegistry(b"manifest-key", profile="shadow").register(unsigned)
        signed = sign_manifest(payload(), b"manifest-key")
        tampered = signed.with_updates(operation="mock.other")
        with self.assertRaises(AdapterManifestError):
            AdapterRegistry(b"manifest-key", profile="shadow").register(tampered)

    def test_transport_can_never_hide_a_second_physical_send(self) -> None:
        bad = payload()
        bad["max_physical_sends_per_attempt"] = 2
        with self.assertRaises(AdapterManifestError):
            AdapterManifest.from_mapping(bad)
        bad = payload()
        bad["sdk_retries_enabled"] = True
        with self.assertRaises(AdapterManifestError):
            AdapterManifest.from_mapping(bad)

    def test_idempotency_retention_expiry_downgrades_level_a_retry_policy(self) -> None:
        manifest = sign_manifest(payload(), b"manifest-key")
        self.assertEqual(manifest.recovery_policy(elapsed_seconds=59), "IDEMPOTENT_QUERY_OR_RETRY")
        self.assertEqual(manifest.recovery_policy(elapsed_seconds=61), "QUERY_ONLY_RETENTION_EXPIRED")

    def test_checked_in_mock_manifest_set_is_signed_and_live_disabled(self) -> None:
        value = json.loads((Path(__file__).parents[1] / "config" / "effect_adapters.mock.json").read_text(encoding="utf-8"))
        self.assertEqual(value["profile"], "MOCK_ONLY")
        self.assertFalse(value["live_capability_authorized"])
        registry = AdapterRegistry(bytes.fromhex(value["verification_key_hex"]), profile="shadow")
        for raw in value["manifests"]:
            expected_hash = raw["manifest_hash"]
            manifest = AdapterManifest.from_mapping({key: item for key, item in raw.items() if key != "manifest_hash"})
            self.assertEqual(manifest.manifest_hash, expected_hash)
            registry.register(manifest)


if __name__ == "__main__":
    unittest.main()
