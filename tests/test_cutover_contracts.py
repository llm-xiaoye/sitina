from __future__ import annotations

import unittest
from pathlib import Path

from sitina.legacy.cutover_contracts import (
    ContractError,
    CutoverCommandIdentity,
    CutoverContracts,
    READINESS_PREDICATE_IDS,
)


class CutoverContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = CutoverContracts.from_file(Path(__file__).parents[1] / "config/cutover_contracts.bplus_v1.json")

    def test_profile_and_every_contract_hash_are_frozen(self) -> None:
        self.assertEqual(self.contracts.profile_id, "SITINA_CUTOVER_CONTRACTS_BPLUS_V1")
        self.assertEqual(len(self.contracts.contract_hash), 64)
        self.assertEqual(set(self.contracts.predicate_ids), set(READINESS_PREDICATE_IDS))
        self.assertTrue(self.contracts.policy_input_signed)

    def test_command_identity_is_stable_and_same_id_different_request_fails(self) -> None:
        identity = CutoverCommandIdentity.freeze("cutover-command-1", {"snapshot_hash": "a" * 64, "genesis_hash": "b" * 64})
        self.assertEqual(identity, CutoverCommandIdentity.freeze("cutover-command-1", {"genesis_hash": "b" * 64, "snapshot_hash": "a" * 64}))
        with self.assertRaises(ContractError): identity.assert_same("cutover-command-1", "c" * 64)

    def test_predicate_registry_is_exhaustive_and_rejects_unknown_or_missing(self) -> None:
        values = {item: True for item in READINESS_PREDICATE_IDS}
        self.contracts.validate_predicates(values)
        with self.assertRaises(ContractError): self.contracts.validate_predicates({**values, "UNKNOWN": True})
        values.pop(READINESS_PREDICATE_IDS[0])
        with self.assertRaises(ContractError): self.contracts.validate_predicates(values)


if __name__ == "__main__": unittest.main()

