from __future__ import annotations

import json
import unittest
from pathlib import Path

from sitina.runtime.capacity import AdmissionClass, CapacityError, CapacityProfile, DiskGate, DiskObservation


ROOT = Path(__file__).resolve().parents[1]


class CapacityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = CapacityProfile.from_mapping(json.loads((ROOT / "config/capacity_profile.shadow.json").read_text()))

    def test_hard_limits_reject_before_allocation(self) -> None:
        limits = self.profile.parser_limits
        with self.assertRaises(CapacityError): limits.check_command(limits.max_command_bytes + 1)
        with self.assertRaises(CapacityError): limits.check_event(limits.max_event_bytes + 1)
        with self.assertRaises(CapacityError): limits.check_frame_header(limits.max_frame_bytes + 1, 1, 1)
        with self.assertRaises(CapacityError): limits.check_frame_header(100, limits.max_events_per_frame + 1, 1)

    def test_ordinary_traffic_cannot_consume_emergency_reserve(self) -> None:
        gate = DiskGate(self.profile)
        free = self.profile.recovery_reserve_bytes + self.profile.emergency_reserve_bytes + self.profile.rollover_headroom_bytes + self.profile.staging_headroom_bytes
        observation = DiskObservation(free + 100, 10 * free, 20000, 200)
        self.assertFalse(gate.decide(observation, AdmissionClass.ORDINARY).admitted)
        self.assertTrue(gate.decide(observation, AdmissionClass.OPERATIONAL_CONTROL).admitted)

    def test_most_restrictive_percent_bytes_inode_and_headroom_condition_wins(self) -> None:
        gate = DiskGate(self.profile)
        cases = (
            DiskObservation(10, 1000, 20000, 1),
            DiskObservation(10_000_000_000, 20_000_000_000, 2, 1),
            DiskObservation(2_000_000_000, 100_000_000_000, 20000, 1),
        )
        for observation in cases:
            with self.subTest(observation=observation): self.assertFalse(gate.decide(observation, AdmissionClass.ORDINARY).admitted)

    def test_profile_is_explicitly_unqualified_and_exposes_no_supported_capacity(self) -> None:
        self.assertEqual(self.profile.qualification_status, "NOT_YET_QUALIFIED")
        self.assertEqual(self.profile.measured_slos, {})
        self.assertIsNone(self.profile.supported_capacity)


if __name__ == "__main__": unittest.main()
