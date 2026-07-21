"""Strict unittest runner for the execution activation gate.

Unlike ordinary development regression suites, this runner treats every
non-pass outcome as activation-blocking and verifies that every explicitly
selected test was both collected and started exactly once.
"""
from __future__ import annotations

import argparse
import json
import sys
import unittest
from collections import Counter
from dataclasses import dataclass
from typing import Sequence, TextIO


SUMMARY_MARKER = "SITINA_ACTIVATION_GATE_JSON:"
POLICY = "ZERO_NONPASS_AND_COMPLETE_V1"


def _unittest_selector(value: str) -> str:
    if value.endswith(".py"):
        return value[:-3].replace("/", ".")
    return value


def _flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    tests: list[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            tests.extend(_flatten(item))
        else:
            tests.append(item)
    return tests


class RecordingResult(unittest.TextTestResult):
    """Text result that records the exact test identities actually started."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_test_ids: list[str] = []

    def startTest(self, test):  # noqa: N802 - unittest API
        self.started_test_ids.append(test.id())
        super().startTest(test)


@dataclass(frozen=True)
class LoadedGateSuite:
    suite: unittest.TestSuite
    selector_counts: dict[str, int]
    collected_test_ids: tuple[str, ...]
    collection_errors: tuple[str, ...]


def load_gate_suite(selectors: Sequence[str]) -> LoadedGateSuite:
    loader = unittest.TestLoader()
    combined = unittest.TestSuite()
    selector_counts: dict[str, int] = {}
    collected_ids: list[str] = []
    collection_errors: list[str] = []

    for raw_selector in selectors:
        selector = _unittest_selector(raw_selector)
        prior_error_count = len(loader.errors)
        loaded = loader.loadTestsFromName(selector)
        tests = _flatten(loaded)
        ids = [test.id() for test in tests]
        selector_counts[raw_selector] = len(ids)
        if not ids:
            collection_errors.append(f"selector collected zero tests: {raw_selector}")
        collection_errors.extend(loader.errors[prior_error_count:])
        collected_ids.extend(ids)
        combined.addTests(loaded)

    duplicate_ids = sorted(test_id for test_id, count in Counter(collected_ids).items() if count != 1)
    if duplicate_ids:
        collection_errors.append(f"duplicate collected test ids: {duplicate_ids}")

    return LoadedGateSuite(
        suite=combined,
        selector_counts=selector_counts,
        collected_test_ids=tuple(collected_ids),
        collection_errors=tuple(collection_errors),
    )


def _detail(items) -> list[dict[str, str]]:
    return [{"test_id": test.id(), "detail": detail} for test, detail in items]


def run_loaded_gate(
    loaded: LoadedGateSuite,
    *,
    stream: TextIO | None = None,
    verbosity: int = 2,
) -> dict[str, object]:
    runner = unittest.TextTestRunner(
        stream=stream or sys.stderr,
        verbosity=verbosity,
        resultclass=RecordingResult,
    )
    result = runner.run(loaded.suite)
    assert isinstance(result, RecordingResult)

    collected = list(loaded.collected_test_ids)
    started = list(result.started_test_ids)
    collection_complete = (
        not loaded.collection_errors
        and bool(loaded.selector_counts)
        and all(count > 0 for count in loaded.selector_counts.values())
    )
    execution_complete = Counter(started) == Counter(collected)
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    expected_failures = len(result.expectedFailures)
    unexpected_successes = len(result.unexpectedSuccesses)
    nonpass_ids = {
        *(test.id() for test, _detail_text in result.failures),
        *(test.id() for test, _detail_text in result.errors),
        *(test.id() for test, _reason in result.skipped),
        *(test.id() for test, _detail_text in result.expectedFailures),
        *(test.id() for test in result.unexpectedSuccesses),
    }
    passed = sum(1 for test_id in started if test_id not in nonpass_ids)
    accepted = (
        collection_complete
        and execution_complete
        and failures == 0
        and errors == 0
        and skipped == 0
        and expected_failures == 0
        and unexpected_successes == 0
    )

    return {
        "schema": "SITINA_EXECUTION_ACTIVATION_GATE_RESULT_V1",
        "policy": POLICY,
        "accepted": accepted,
        "selector_counts": loaded.selector_counts,
        "collection_errors": list(loaded.collection_errors),
        "collection_complete": collection_complete,
        "execution_complete": execution_complete,
        "collected_test_count": len(collected),
        "executed_test_count": result.testsRun,
        "passed": passed,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
        "expected_failures": expected_failures,
        "unexpected_successes": unexpected_successes,
        "missing_test_ids": sorted((Counter(collected) - Counter(started)).elements()),
        "unexpected_test_ids": sorted((Counter(started) - Counter(collected)).elements()),
        "failure_details": _detail(result.failures),
        "error_details": _detail(result.errors),
        "skip_details": _detail(result.skipped),
        "expected_failure_details": _detail(result.expectedFailures),
        "unexpected_success_details": [test.id() for test in result.unexpectedSuccesses],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("selectors", nargs="+")
    arguments = parser.parse_args(argv)
    summary = run_loaded_gate(load_gate_suite(arguments.selectors))
    print(SUMMARY_MARKER + json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
