from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from sitina.journal.model import CanonicalizationError, canonical_json_bytes, domain_hash, parse_canonical_json


ROOT = Path(__file__).resolve().parents[1]


class BPlusProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = json.loads((ROOT / "tests/vectors/bplus_v1_vectors.json").read_text(encoding="utf-8"))

    def test_all_normative_profile_documents_and_ids_exist(self) -> None:
        expected = {
            "canonical-json-v1.md": "SITINA_CANONICAL_JSON_V1",
            "local-frame-v1.md": "SITINA_LOCAL_FRAME_V1",
            "identifier-hash-v1.md": "SITINA_IDENTIFIER_HASH_V1",
            "crypto-v1.md": "SITINA_CRYPTO_V1",
            "journal-auth-v1.md": "SITINA_JOURNAL_AUTH_V1",
            "macos-durability-v1.md": "MACOS_APFS_FSYNC_PROCESS_OS_CRASH_V1",
        }
        for name, profile_id in expected.items():
            with self.subTest(name=name):
                text = (ROOT / "docs/bplus-profiles" / name).read_text(encoding="utf-8")
                self.assertIn(profile_id, text)
                self.assertIn(profile_id, self.vectors["profile_ids"])

    def test_canonical_golden_vector_normalizes_nfc_and_sorts_keys(self) -> None:
        encoded = canonical_json_bytes(self.vectors["canonical"]["input"])
        self.assertEqual(encoded.hex(), self.vectors["canonical"]["expected_utf8_hex"])
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), self.vectors["canonical"]["expected_sha256"])

    def test_command_domain_hash_golden_vector(self) -> None:
        raw = self.vectors["command_request"]["canonical_utf8"].encode()
        self.assertEqual(domain_hash("COMMAND_REQUEST", raw), self.vectors["command_request"]["domain_hash"])

    def test_invalid_numbers_and_duplicate_keys_fail_closed(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"x": 1.5})
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"x": 2**63})
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b'{"x":1,"x":2}')

    def test_persisted_bytes_must_round_trip_exactly(self) -> None:
        with self.assertRaises(CanonicalizationError):
            parse_canonical_json(b'{ "x": 1 }')
        self.assertEqual(parse_canonical_json(b'{"x":1}'), {"x": 1})


if __name__ == "__main__":
    unittest.main()
