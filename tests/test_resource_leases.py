from __future__ import annotations

import unittest

from sitina.protocols.resource_leases import (
    ProgressEvidenceRef, ResourceLeaseAggregate, ResourceLeaseError, ResourceRequirement, ReservationState,
)


def lease(): return ResourceLeaseAggregate("lease-1", "task-1", (ResourceRequirement("gpu", 1), ResourceRequirement("memory", 4)), 2, 60)


class ResourceLeaseTests(unittest.TestCase):
    def test_partial_multi_resource_reservation_cannot_activate(self) -> None:
        current, _ = lease().reserve(resource_id="gpu", units=1, expires_at="2026-07-13T01:00:00Z")
        with self.assertRaises(ResourceLeaseError): current.activate()
        current, _ = current.reserve(resource_id="memory", units=4, expires_at="2026-07-13T01:00:00Z")
        current, _ = current.activate(); self.assertTrue(all(item.state is ReservationState.ACTIVE for item in current.reservations))

    def test_renew_requires_accepted_progress_and_respects_bounds(self) -> None:
        current = lease()
        for resource, units in (("gpu", 1), ("memory", 4)): current, _ = current.reserve(resource_id=resource, units=units, expires_at="2026-07-13T01:00:00Z")
        current, _ = current.activate()
        with self.assertRaises(ResourceLeaseError): current.renew(resource_id="gpu", extension_seconds=10, progress=ProgressEvidenceRef("11" * 32, "22" * 32, False))
        progress = ProgressEvidenceRef("11" * 32, "22" * 32, True)
        current, _ = current.renew(resource_id="gpu", extension_seconds=30, progress=progress)
        current, _ = current.renew(resource_id="gpu", extension_seconds=30, progress=progress)
        with self.assertRaises(ResourceLeaseError): current.renew(resource_id="gpu", extension_seconds=1, progress=progress)

    def test_release_revoke_and_compensation_inputs_are_stable(self) -> None:
        current, _ = lease().reserve(resource_id="gpu", units=1, expires_at="2026-07-13T01:00:00Z")
        self.assertEqual(current.compensation_release_inputs[0]["command_binding"], "compensate-lease-1-gpu")
        current, _ = current.release(resource_id="gpu", reason="partial-failure")
        self.assertEqual(current.compensation_release_inputs, ())

    def test_exact_requirement_units_are_required(self) -> None:
        with self.assertRaises(ResourceLeaseError): lease().reserve(resource_id="memory", units=3, expires_at="2026-07-13T01:00:00Z")


if __name__ == "__main__": unittest.main()
