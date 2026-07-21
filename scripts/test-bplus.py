#!/usr/bin/env python3
"""Manifest-bound layered test runner for Sitina B+."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tests/test_suites.json"
PHASE_MINUS1_MANIFEST = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-execution-manifest-v1-phase-minus1.json")
FOUNDATION = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-bootstrap-foundation-record.json")
INITIAL_SENTINEL = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-production-sentinel-initial.json")
MUTABLE_SENTINEL = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-production-mutable-sentinel-phase-minus1-baseline.json")
CONTROL_ROOT = Path("/Users/moss/Desktop/sitina/output")
GOAL_THREAD_ID = "019f5c6b-3083-7860-b45b-c8b487c4e3ab"


NETWORK_GUARD = r'''
import ipaddress
import json
import os
import socket
import sys
import traceback

_attempt_log = os.environ.get("SITINA_EXTERNAL_ATTEMPT_LOG")
_production_attempt_log = os.environ.get("SITINA_PRODUCTION_ATTEMPT_LOG")
_production_home = os.path.realpath(os.environ["SITINA_PRODUCTION_HOME"])
_production_mutable_roots = tuple(
    os.path.join(_production_home, name)
    for name in ("data", "logs", "state", "artifacts", "outputs", "memory", "backups", "temp")
)
_original_connect = socket.socket.connect
_original_create_connection = socket.create_connection

def _resolved_path(value):
    if isinstance(value, int) or value is None:
        return None
    try:
        raw = os.fsdecode(value)
    except (TypeError, ValueError):
        return None
    if not os.path.isabs(raw):
        raw = os.path.join(os.getcwd(), raw)
    return os.path.realpath(raw)

def _inside_production_mutable(value):
    resolved = _resolved_path(value)
    if resolved is None:
        return False
    return any(resolved == root or resolved.startswith(root + os.sep) for root in _production_mutable_roots)

def _record_production_attempt(event, arguments):
    if _production_attempt_log:
        with open(_production_attempt_log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "event": event,
                "arguments": [repr(item) for item in arguments],
                "stack": traceback.format_stack(limit=12),
            }, sort_keys=True) + "\n")

def _production_audit_guard(event, arguments):
    path_indexes = {
        "open": (0,),
        "os.listdir": (0,),
        "os.scandir": (0,),
        "os.remove": (0,),
        "os.rmdir": (0,),
        "os.mkdir": (0,),
        "os.chmod": (0,),
        "os.chown": (0,),
        "os.truncate": (0,),
        "os.utime": (0,),
        "os.symlink": (0, 1),
        "os.link": (0, 1),
        "os.rename": (0, 1),
        "sqlite3.connect": (0,),
    }.get(event, ())
    selected = tuple(arguments[index] for index in path_indexes if index < len(arguments))
    if any(_inside_production_mutable(value) for value in selected):
        _record_production_attempt(event, selected)
        raise PermissionError("B+ isolated test guard denied Production mutable-path access")

sys.addaudithook(_production_audit_guard)

def _allowed(host):
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

def _deny(target):
    if _attempt_log:
        with open(_attempt_log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"target": repr(target)}, sort_keys=True) + "\n")
    raise RuntimeError("B+ isolated test guard denied external network")

def guarded_connect(self, address):
    host = address[0] if isinstance(address, tuple) and address else str(address)
    if not _allowed(host):
        return _deny(address)
    return _original_connect(self, address)

def guarded_create_connection(address, *args, **kwargs):
    host = address[0] if isinstance(address, tuple) and address else str(address)
    if not _allowed(host):
        return _deny(address)
    return _original_create_connection(address, *args, **kwargs)

socket.socket.connect = guarded_connect
socket.create_connection = guarded_create_connection
'''


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"expected object: {path}")
    return value


def validate_control_plane(manifest_path: Path, config: dict[str, Any]) -> Any:
    previous_control_plane = os.environ.get("SITINA_CONTROL_PLANE_READONLY")
    os.environ["SITINA_CONTROL_PLANE_READONLY"] = "1"
    sys.path.insert(0, str(ROOT / "core"))
    try:
        from sitina.runtime.execution_contract import (
            BootstrapFoundationRecord,
            ExecutionManifestV1,
            load_json_read_only,
        )
    finally:
        if previous_control_plane is None:
            os.environ.pop("SITINA_CONTROL_PLANE_READONLY", None)
        else:
            os.environ["SITINA_CONTROL_PLANE_READONLY"] = previous_control_plane

    foundation = BootstrapFoundationRecord.from_mapping(load_json_read_only(FOUNDATION))
    resolved_manifest = manifest_path.resolve(strict=True)
    if (
        resolved_manifest.parent != CONTROL_ROOT.resolve(strict=True)
        or (
            not resolved_manifest.name.endswith("execution-manifest-v1.json")
            and resolved_manifest != PHASE_MINUS1_MANIFEST
        )
    ):
        raise SystemExit(f"execution manifest is outside the control root or has an invalid name: {resolved_manifest}")
    raw_manifest = _load_json(resolved_manifest)
    goal = raw_manifest.get("goal") if isinstance(raw_manifest.get("goal"), dict) else {}
    if goal.get("thread_id") != GOAL_THREAD_ID or goal.get("standing_owner_authorization_hash") != "sha256:05621d9bd89ee19fb80ec44f84b770a88808345639068d261a3aec126d916601":
        raise SystemExit("execution manifest is not bound to this Goal and Standing Owner Authorization")
    manifest = ExecutionManifestV1.from_mapping(raw_manifest)
    manifest.assert_promotion_from(foundation)
    approved = Path(config["approved_python"]).resolve(strict=True)
    if Path(sys.executable).resolve(strict=True) != approved:
        raise SystemExit(f"runner must use approved python: {approved}")
    return manifest


def _write_json_new_or_replace(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _parse_json_lines(value: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in value.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            item = {"unparsed": line[:1000]}
        records.append(item if isinstance(item, dict) else {"value": item})
    return records


def _unittest_selector(value: str) -> str:
    if value.endswith(".py"):
        return value[:-3].replace("/", ".")
    return value


def _activation_gate_summary(output: str) -> dict[str, Any] | None:
    marker = "SITINA_ACTIVATION_GATE_JSON:"
    lines = [line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
    if len(lines) != 1:
        return None
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", nargs="?")
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--live-approval")
    parser.add_argument("--execution-manifest", type=Path)
    arguments = parser.parse_args(argv)
    config = _load_json(CONFIG)
    suites = config["suites"]
    if arguments.list:
        for name, definition in suites.items():
            print(f"{name}: {len(definition['selectors'])} selectors; {definition['external_io_policy']}")
        return 0
    if arguments.suite not in suites:
        parser.error(f"suite must be one of: {', '.join(sorted(suites))}")
    if arguments.suite == "live_provider_opt_in":
        raise SystemExit("The selected pre-cutover manifest does not authorize live-provider tests")
    definition = suites[arguments.suite]
    manifest_path = arguments.execution_manifest or Path(definition.get("execution_manifest", PHASE_MINUS1_MANIFEST))
    manifest = validate_control_plane(manifest_path, config)
    phase_token = "phase-minus1" if manifest.authorized_phase == "-1" else f"phase{manifest.authorized_phase.lower()}"
    result_path = CONTROL_ROOT / f"sitina-bplus-{phase_token}-test-results.json"
    suite_result_root = CONTROL_ROOT / f"sitina-bplus-{phase_token}-test-results"
    selectors = arguments.test or list(definition["selectors"])

    sys.path.insert(0, str(ROOT / "tests/foundation"))
    from home_factory import DisposableHomeFactory, capture_production_mutable_sentinel, capture_production_sentinel

    production = Path(config["production_home"])
    initial = _load_json(INITIAL_SENTINEL)
    before = capture_production_sentinel(production, GOAL_THREAD_ID)
    if before["report_sha256"] != initial["report_sha256"]:
        raise SystemExit("production sentinel differs before test execution")
    if not MUTABLE_SENTINEL.is_file():
        raise SystemExit("extended Production mutable-root sentinel baseline is missing")
    mutable_initial = _load_json(MUTABLE_SENTINEL)
    mutable_before = capture_production_mutable_sentinel(production, GOAL_THREAD_ID)
    if mutable_before["report_sha256"] != mutable_initial["report_sha256"]:
        raise SystemExit("extended Production mutable-root sentinel differs before test execution")

    factory = DisposableHomeFactory(ROOT, production, Path(config["test_home_root"]))
    disposable = factory.create(prefix=f"{arguments.suite}-")
    home = disposable.path
    guard_directory = home / ".guard"
    guard_directory.mkdir()
    (guard_directory / "sitecustomize.py").write_text(NETWORK_GUARD, encoding="utf-8")
    attempt_log = home / "external-attempts.jsonl"
    production_attempt_log = home / "production-attempts.jsonl"
    environment = dict(os.environ)
    environment.update(
        {
            "SITINA_HOME": str(home),
            "SITINA_PYTHON": config["approved_python"],
            "SITINA_LIVE_TEST": "0",
            "SITINA_BPLUS_TEST_LAYER": arguments.suite,
            "SITINA_EXECUTION_MANIFEST": str(manifest_path.resolve(strict=True)),
            "SITINA_PRODUCTION_SENTINEL_VERIFIED": "1",
            "SITINA_EXTERNAL_ATTEMPT_LOG": str(attempt_log),
            "SITINA_PRODUCTION_ATTEMPT_LOG": str(production_attempt_log),
            "SITINA_PRODUCTION_HOME": str(production),
            "SITINA_PRODUCTION_GUARD_PROFILE": "APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1",
            "HOME": str(home),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                (str(guard_directory), str(ROOT), str(ROOT / "tests/foundation"), str(ROOT / "core"))
            ),
            "PATH": os.pathsep.join((str(Path(config["approved_python"]).parent), os.environ.get("PATH", ""))),
        }
    )
    for name in list(environment):
        if any(fragment in name.upper() for fragment in ("API_KEY", "AUTH_TOKEN", "PASSWORD", "PRIVATE_KEY")):
            environment.pop(name, None)
    strict_activation_gate = definition.get("result_policy") == "ZERO_NONPASS_AND_COMPLETE_V1"
    if strict_activation_gate:
        command = [
            config["approved_python"], "-m", "tests.foundation.activation_gate_runner", *selectors,
        ]
    else:
        command = [config["approved_python"], "-m", "unittest", *[_unittest_selector(item) for item in selectors]]
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=home,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=int(definition["timeout_seconds"]))
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            output, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
    duration = time.monotonic() - started
    sys.stdout.write(output)
    test_count_match = re.search(r"Ran\s+(\d+)\s+tests?\s+in\s+", output)
    skipped_match = re.search(r"skipped=(\d+)", output)
    warning_lines = [
        line[:1000]
        for line in output.splitlines()
        if re.search(r"(?:^|\b)(?:[A-Za-z]+Warning|WARNING)(?:\b|:)", line)
    ]
    external_attempts = attempt_log.read_text(encoding="utf-8") if attempt_log.exists() else ""
    production_attempts = production_attempt_log.read_text(encoding="utf-8") if production_attempt_log.exists() else ""
    production_attempt_records = _parse_json_lines(production_attempts)
    activation_gate = _activation_gate_summary(output) if strict_activation_gate else None
    return_code = process.returncode if not timed_out else 124
    if strict_activation_gate and (
        activation_gate is None or activation_gate.get("accepted") is not True
    ):
        return_code = return_code or 128
    if external_attempts:
        return_code = return_code or 125
    if production_attempts:
        return_code = return_code or 127

    disposable.cleanup()
    after = capture_production_sentinel(production, GOAL_THREAD_ID)
    mutable_after = capture_production_mutable_sentinel(production, GOAL_THREAD_ID)
    sentinel_unchanged = (
        before["report_sha256"] == after["report_sha256"]
        and mutable_before["report_sha256"] == mutable_after["report_sha256"]
        and mutable_initial["report_sha256"] == mutable_after["report_sha256"]
    )
    if not sentinel_unchanged:
        return_code = return_code or 126
    result = {
        "schema": "BPLUS_TEST_RESULT_V1",
        "suite": arguments.suite,
        "selectors": selectors,
        "mode": "tests",
        "command": command,
        "child_cwd": str(home),
        "duration_seconds": round(duration, 6),
        "test_count": int(test_count_match.group(1)) if test_count_match else None,
        "skipped_count": int(skipped_match.group(1)) if skipped_match else 0,
        "activation_gate": activation_gate,
        "warning_count": len(warning_lines),
        "warning_lines": warning_lines[:200],
        "stdout_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "timed_out": timed_out,
        "return_code": return_code,
        "external_attempt_count": len(external_attempts.splitlines()),
        "production_attempt_count": len(production_attempts.splitlines()),
        "production_attempt_records": production_attempt_records[:500],
        "production_attempt_log_sha256": hashlib.sha256(production_attempts.encode("utf-8")).hexdigest(),
        "production_guard_profile": "APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1",
        "production_sentinel_before": before["report_sha256"],
        "production_sentinel_after": after["report_sha256"],
        "production_mutable_sentinel_before": mutable_before["report_sha256"],
        "production_mutable_sentinel_after": mutable_after["report_sha256"],
        "production_sentinel_unchanged": sentinel_unchanged,
        "execution_manifest_hash": manifest.manifest_hash,
    }
    _write_json_new_or_replace(result_path, result)
    suite_result_root.mkdir(parents=True, exist_ok=True)
    _write_json_new_or_replace(suite_result_root / f"{arguments.suite}.json", result)
    if timed_out:
        print(f"suite timeout after {definition['timeout_seconds']}s", file=sys.stderr)
    if external_attempts:
        print("external network attempt denied", file=sys.stderr)
    if production_attempts:
        print("Production mutable-path attempt denied", file=sys.stderr)
    if not sentinel_unchanged:
        print("production sentinel changed during tests", file=sys.stderr)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
