#!/usr/bin/env python3
"""Complete registered-suite runner with an exact historical skip allowlist."""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, TextIO

from tests.foundation.activation_gate_runner import (
    RecordingResult,
    _flatten,
    _test_ids_sha256,
    _unittest_selector,
)


SUMMARY_MARKER = "SITINA_REGISTRATION_GATE_JSON:"
POLICY = "EXACT_HISTORICAL_SKIP_ALLOWLIST_V1"
EXCLUDED_SUITES = frozenset({"all_registered_unique"})


@dataclass(frozen=True)
class LoadedRegistrationSuite:
    suite: unittest.TestSuite
    selectors: tuple[str, ...]
    selector_counts: dict[str, int]
    collected_test_ids: tuple[str, ...]
    collection_errors: tuple[str, ...]
    expected_skips: tuple[dict[str, str], ...]


def _load_registry(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("test registry must be a JSON object")
    return value


def unique_registered_selectors(registry: dict[str, object]) -> tuple[str, ...]:
    suites = registry.get("suites")
    if not isinstance(suites, dict):
        raise ValueError("test registry has no suites object")
    seen: set[str] = set()
    selectors: list[str] = []
    for suite_name, raw_definition in suites.items():
        if suite_name in EXCLUDED_SUITES:
            continue
        if not isinstance(raw_definition, dict) or not isinstance(
            raw_definition.get("selectors"), list
        ):
            raise ValueError(f"suite has no selectors list: {suite_name}")
        for selector in raw_definition["selectors"]:
            if not isinstance(selector, str):
                raise ValueError(f"suite selector is not a string: {suite_name}")
            if selector not in seen:
                seen.add(selector)
                selectors.append(selector)
    if not selectors:
        raise ValueError("test registry has no registered selectors")
    return tuple(selectors)


def _expected_skips(registry: dict[str, object]) -> tuple[dict[str, str], ...]:
    raw_allowlist = registry.get("historical_skip_allowlist")
    if not isinstance(raw_allowlist, list):
        raise ValueError("test registry has no historical_skip_allowlist")
    entries: list[dict[str, str]] = []
    for raw_entry in raw_allowlist:
        if (
            not isinstance(raw_entry, dict)
            or set(raw_entry) != {"test_id", "reason"}
            or not isinstance(raw_entry["test_id"], str)
            or not isinstance(raw_entry["reason"], str)
        ):
            raise ValueError("historical skip allowlist entry is malformed")
        entries.append({"test_id": raw_entry["test_id"], "reason": raw_entry["reason"]})
    ids = [entry["test_id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("historical skip allowlist contains duplicate test ids")
    return tuple(sorted(entries, key=lambda entry: entry["test_id"]))


def load_registration_suite(registry_path: Path) -> LoadedRegistrationSuite:
    registry = _load_registry(registry_path)
    selectors = unique_registered_selectors(registry)
    loader = unittest.TestLoader()
    combined = unittest.TestSuite()
    selector_counts: dict[str, int] = {}
    collected_ids: list[str] = []
    collection_errors: list[str] = []
    for raw_selector in selectors:
        prior_error_count = len(loader.errors)
        loaded = loader.loadTestsFromName(_unittest_selector(raw_selector))
        tests = _flatten(loaded)
        ids = [test.id() for test in tests]
        selector_counts[raw_selector] = len(ids)
        if not ids:
            collection_errors.append(f"selector collected zero tests: {raw_selector}")
        collection_errors.extend(loader.errors[prior_error_count:])
        collected_ids.extend(ids)
        combined.addTests(loaded)
    duplicate_ids = sorted(
        test_id for test_id, count in Counter(collected_ids).items() if count != 1
    )
    if duplicate_ids:
        collection_errors.append(f"duplicate collected test ids: {duplicate_ids}")
    return LoadedRegistrationSuite(
        suite=combined,
        selectors=selectors,
        selector_counts=selector_counts,
        collected_test_ids=tuple(collected_ids),
        collection_errors=tuple(collection_errors),
        expected_skips=_expected_skips(registry),
    )


def _details(items) -> list[dict[str, str]]:
    return [{"test_id": test.id(), "detail": detail} for test, detail in items]


def run_loaded_registration_suite(
    loaded: LoadedRegistrationSuite,
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
    observed_skips = sorted(
        (
            {"test_id": test.id(), "reason": reason}
            for test, reason in result.skipped
        ),
        key=lambda entry: entry["test_id"],
    )
    expected_skips = list(loaded.expected_skips)
    collection_complete = (
        not loaded.collection_errors
        and bool(loaded.selector_counts)
        and all(count > 0 for count in loaded.selector_counts.values())
    )
    execution_complete = Counter(started) == Counter(collected)
    failures = len(result.failures)
    errors = len(result.errors)
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
    skip_allowlist_match = observed_skips == expected_skips
    accepted = (
        collection_complete
        and execution_complete
        and failures == 0
        and errors == 0
        and expected_failures == 0
        and unexpected_successes == 0
        and skip_allowlist_match
    )
    return {
        "schema": "SITINA_REGISTERED_TEST_GATE_RESULT_V1",
        "policy": POLICY,
        "accepted": accepted,
        "selector_count": len(loaded.selectors),
        "selector_counts": loaded.selector_counts,
        "collected_test_ids": collected,
        "collected_test_ids_sha256": _test_ids_sha256(collected),
        "started_test_ids": started,
        "started_test_ids_sha256": _test_ids_sha256(started),
        "collection_errors": list(loaded.collection_errors),
        "collection_complete": collection_complete,
        "execution_complete": execution_complete,
        "collected_test_count": len(collected),
        "executed_test_count": result.testsRun,
        "passed": passed,
        "failures": failures,
        "errors": errors,
        "skipped": len(observed_skips),
        "expected_failures": expected_failures,
        "unexpected_successes": unexpected_successes,
        "skip_allowlist_match": skip_allowlist_match,
        "skip_details": observed_skips,
        "expected_skip_details": expected_skips,
        "missing_test_ids": sorted((Counter(collected) - Counter(started)).elements()),
        "unexpected_test_ids": sorted((Counter(started) - Counter(collected)).elements()),
        "failure_details": _details(result.failures),
        "error_details": _details(result.errors),
        "expected_failure_details": _details(result.expectedFailures),
        "unexpected_success_details": [test.id() for test in result.unexpectedSuccesses],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    arguments = parser.parse_args(argv)
    summary = run_loaded_registration_suite(load_registration_suite(arguments.registry))
    print(SUMMARY_MARKER + json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
