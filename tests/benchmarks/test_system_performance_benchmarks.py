from __future__ import annotations

import unittest

from sitina.orchestrator.performance_management import RepeatableBenchmark


def _clock(durations: tuple[int, ...]):
    values: list[int] = []
    cursor = 0
    for duration in durations:
        values.extend((cursor, cursor + duration))
        cursor += duration + 1000
    iterator = iter(values)
    return lambda: next(iterator)


class SystemPerformanceBenchmarkTests(unittest.TestCase):
    def test_e05_routing_fast_multi_handoff_blackboard_replay_have_separate_repeatable_latency_throughput_resource_gates(self) -> None:
        benchmark = RepeatableBenchmark()
        workloads = {
            "routing": ((40, 42, 38, 41, 39), 0, 1, 45),
            "FAST": ((80, 82, 78, 81, 79), 1, 2, 85),
            "MULTI": ((180, 185, 175, 182, 178), 4, 6, 190),
            "handoff": ((55, 58, 52, 56, 54), 0, 2, 60),
            "blackboard": ((30, 32, 28, 31, 29), 0, 1, 35),
            "replay": ((65, 68, 62, 66, 64), 0, 2, 70),
        }
        reports = {}
        for name, (durations, physical_calls, resources, p95_limit) in workloads.items():
            report = benchmark.measure(
                name,
                lambda workload=name, calls=physical_calls, units=resources: ({"workload": workload, "result": "equivalent"}, calls, units),
                warmup_iterations=2,
                measurement_iterations=5,
                clock_ns=_clock(durations),
                environment={"fixture": "deterministic", "provider": "none", "suite": "performance-regression-v1"},
            )
            reports[name] = report
            self.assertEqual((report.warmup_iterations, report.measurement_iterations, report.sample_count, report.error_count), (2, 5, 5, 0))
            self.assertLessEqual(report.p95_duration_ns, p95_limit)
            self.assertGreater(report.throughput_per_second_milli, 0)
            self.assertLessEqual(report.peak_resource_units, resources)
            self.assertEqual(len(report.output_hashes), 1)
        self.assertEqual(set(reports), {"routing", "FAST", "MULTI", "handoff", "blackboard", "replay"})
        self.assertEqual(sum(item.physical_call_count for item in reports.values()), 25)


if __name__ == "__main__":
    unittest.main()
