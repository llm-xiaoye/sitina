from __future__ import annotations

import threading
import time
import unittest

from sitina.projections.consistency import (
    ConsistencyError, ConsistencyLevel, ProjectionTracker, ProjectorState, ReadOptions, wait_for_frontier,
)


class ProjectionConsistencyTests(unittest.TestCase):
    def test_strong_wait_uses_fixed_caller_target_not_moving_head(self) -> None:
        tracker = ProjectionTracker(applied={"j1": 1}, head={"j1": 3})
        def advance():
            time.sleep(0.02); tracker.update_head({"j1": 100}); tracker.update_applied({"j1": 3})
        thread = threading.Thread(target=advance); thread.start()
        metadata = wait_for_frontier(tracker, ReadOptions(ConsistencyLevel.STRONG, {"j1": 3}, 1.0))
        thread.join()
        self.assertEqual(metadata.target_frontier, {"j1": 3})
        self.assertEqual(metadata.applied_frontier["j1"], 3)

    def test_failed_blocked_and_incompatible_projector_fail_closed(self) -> None:
        for state in (ProjectorState.FAILED, ProjectorState.BLOCKED, ProjectorState.INCOMPATIBLE):
            tracker = ProjectionTracker(applied={"j1": 0}, head={"j1": 1}); tracker.set_state(state)
            with self.subTest(state=state), self.assertRaises(ConsistencyError):
                wait_for_frontier(tracker, ReadOptions(ConsistencyLevel.STRONG, {"j1": 1}, 0.1))

    def test_eventual_and_stale_return_vector_metadata_and_lag(self) -> None:
        tracker = ProjectionTracker(applied={"j1": 3, "j2": 2}, head={"j1": 5, "j2": 4})
        eventual = wait_for_frontier(tracker, ReadOptions(ConsistencyLevel.EVENTUAL, {"j1": 5, "j2": 4}))
        stale = wait_for_frontier(tracker, ReadOptions(ConsistencyLevel.STALE, {"j1": 5, "j2": 4}))
        self.assertEqual(eventual.lag_events, 4)
        self.assertTrue(eventual.stale and stale.stale)


if __name__ == "__main__": unittest.main()
