from __future__ import annotations

import unittest

from sitina.scheduling.timers import ClockSample, TimerError, TimerService, TimerState


class DurableTimerTests(unittest.TestCase):
    def test_restart_rebuilds_timer_from_utc_deadline_and_stable_command(self) -> None:
        service = TimerService(); timer, _ = service.schedule(timer_id="timer-1", target_id="task-1", purpose="claim-expiry", deadline_utc="2026-07-13T00:01:00Z", sample=ClockSample("2026-07-13T00:00:00Z", 100.0, 0.1))
        rebuilt = TimerService.rebuild(service.journal_facts)
        self.assertEqual(rebuilt.timers["timer-1"].target_command_id, timer.target_command_id)
        fired, _ = rebuilt.fire("timer-1", ClockSample("2026-07-13T00:01:01Z", 1.0, 0.1), same_process_lifetime=False, command_ref="11" * 32)
        self.assertEqual(fired.state, TimerState.FIRED)

    def test_wall_clock_rollback_or_monotonic_shortfall_does_not_fire_early(self) -> None:
        service = TimerService(); service.schedule(timer_id="timer-1", target_id="task-1", purpose="expiry", deadline_utc="2026-07-13T00:01:00Z", sample=ClockSample("2026-07-13T00:00:00Z", 100.0, 0.1))
        self.assertFalse(service.is_due("timer-1", ClockSample("2026-07-12T23:59:00Z", 170.0, 0.1), same_process_lifetime=True))
        self.assertFalse(service.is_due("timer-1", ClockSample("2026-07-13T00:02:00Z", 120.0, 0.1), same_process_lifetime=True))
        self.assertTrue(service.is_due("timer-1", ClockSample("2026-07-13T00:01:01Z", 161.0, 0.1), same_process_lifetime=True))

    def test_large_clock_uncertainty_records_incident_and_holds_takeover(self) -> None:
        service = TimerService(max_clock_uncertainty_seconds=2.0); service.schedule(timer_id="timer-1", target_id="task-1", purpose="takeover", deadline_utc="2026-07-13T00:01:00Z", sample=ClockSample("2026-07-13T00:00:00Z", 1.0, 0.1))
        self.assertFalse(service.is_due("timer-1", ClockSample("2026-07-13T00:02:00Z", 200.0, 10.0), same_process_lifetime=True))
        self.assertTrue(service.takeover_held); self.assertEqual(service.timers["timer-1"].state, TimerState.HELD_UNCERTAIN)
        self.assertEqual(service.incidents[0]["schema"], "CLOCK_UNCERTAINTY_INCIDENT_V1")

    def test_duplicate_schedule_and_fire_reuse_stable_target_command(self) -> None:
        service = TimerService(); sample = ClockSample("2026-07-13T00:00:00Z", 1.0, 0.0)
        first, _ = service.schedule(timer_id="timer-1", target_id="task-1", purpose="expiry", deadline_utc="2026-07-13T00:00:00Z", sample=sample)
        second, _ = service.schedule(timer_id="timer-1", target_id="task-1", purpose="expiry", deadline_utc="2026-07-13T00:00:00Z", sample=sample)
        self.assertEqual(first.target_command_id, second.target_command_id)
        service.fire("timer-1", sample, same_process_lifetime=True, command_ref="11" * 32)
        duplicate, event = service.fire("timer-1", sample, same_process_lifetime=True, command_ref="11" * 32)
        self.assertEqual(event["target_command_id"], first.target_command_id); self.assertEqual(duplicate.state, TimerState.FIRED)


if __name__ == "__main__": unittest.main()
