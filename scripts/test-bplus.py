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
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.bplus_dependency_gate import (  # noqa: E402 - ROOT must be importable first
    SUMMARY_MARKER as DEPENDENCY_GATE_MARKER,
    audit_dependency_lock,
)


CONFIG = ROOT / "tests/test_suites.json"
PHASE_MINUS1_MANIFEST = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-execution-manifest-v1-phase-minus1.json")
FOUNDATION = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-bootstrap-foundation-record.json")
INITIAL_SENTINEL = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-production-sentinel-initial.json")
MUTABLE_SENTINEL = Path("/Users/moss/Desktop/sitina/output/sitina-bplus-production-mutable-sentinel-phase-minus1-baseline.json")
CONTROL_ROOT = Path("/Users/moss/Desktop/sitina/output")
GOAL_THREAD_ID = "019f5c6b-3083-7860-b45b-c8b487c4e3ab"
CAPTURE_MARKER = "SITINA_BPLUS_CAPTURE_JSON:"


NETWORK_GUARD = r'''
import ipaddress
import json
import os
import socket
import sys
import traceback

_attempt_log = os.environ.get("SITINA_EXTERNAL_ATTEMPT_LOG")
_production_attempt_log = os.environ.get("SITINA_PRODUCTION_ATTEMPT_LOG")
_readonly_attempt_log = os.environ.get("SITINA_READONLY_ATTEMPT_LOG")
_production_home = os.path.realpath(os.environ["SITINA_PRODUCTION_HOME"])
_readonly_roots = tuple(
    os.path.realpath(value)
    for value in json.loads(os.environ.get("SITINA_READONLY_ROOTS_JSON", "[]"))
)
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

def _inside_readonly_root(value):
    resolved = _resolved_path(value)
    if resolved is None:
        return False
    return any(
        resolved == root or resolved.startswith(root + os.sep)
        for root in _readonly_roots
    )

def _is_write_event(event, arguments):
    if event == "open":
        mode = arguments[1] if len(arguments) > 1 else None
        flags = arguments[2] if len(arguments) > 2 else 0
        if isinstance(mode, str) and any(value in mode for value in "wax+"):
            return True
        if isinstance(flags, int):
            write_flags = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT
                | os.O_TRUNC | os.O_APPEND
            )
            return bool(flags & write_flags)
        return False
    return event not in {"os.listdir", "os.scandir"}

def _record_production_attempt(event, arguments):
    if _production_attempt_log:
        with open(_production_attempt_log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "event": event,
                "arguments": [repr(item) for item in arguments],
                "stack": traceback.format_stack(limit=12),
            }, sort_keys=True) + "\n")

def _record_readonly_attempt(event, arguments):
    if _readonly_attempt_log:
        with open(_readonly_attempt_log, "a", encoding="utf-8") as handle:
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
    if (
        _is_write_event(event, arguments)
        and any(_inside_readonly_root(value) for value in selected)
    ):
        _record_readonly_attempt(event, selected)
        raise PermissionError("B+ isolated test guard denied read-only-root mutation")

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


def _validate_sentinel_baseline(
    path: Path,
    *,
    expected_schema: str,
    production_home: Path,
    goal_thread_id: str,
    expected_report_hash: str | None,
) -> tuple[Path, dict[str, Any]]:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise SystemExit(f"sentinel baseline must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if resolved.parent != CONTROL_ROOT.resolve(strict=True):
        raise SystemExit(f"sentinel baseline is outside the control root: {resolved}")
    value = _load_json(resolved)
    if value.get("schema") != expected_schema:
        raise SystemExit(f"sentinel baseline has wrong schema: {resolved}")
    if value.get("production_home") != str(production_home.resolve(strict=True)):
        raise SystemExit(f"sentinel baseline targets a different production home: {resolved}")
    if value.get("goal_thread_id") != goal_thread_id:
        raise SystemExit(f"sentinel baseline targets a different Goal: {resolved}")
    if (
        value.get("observation_mode") != "CONTENT_ADDRESSED_RELPATH_SIZE_MODE_SHA256_V2"
        or value.get("hash_algorithm") != "sha256"
    ):
        raise SystemExit(f"sentinel baseline has an invalid observation contract: {resolved}")
    report_hash = value.get("report_sha256")
    if not isinstance(report_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", report_hash):
        raise SystemExit(f"sentinel baseline has an invalid report hash: {resolved}")
    core = dict(value)
    core.pop("report_sha256", None)
    actual = hashlib.sha256(
        json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if actual != report_hash:
        raise SystemExit(f"sentinel baseline report hash mismatch: {resolved}")
    if expected_report_hash is not None and expected_report_hash.removeprefix("sha256:") != report_hash:
        raise SystemExit(f"sentinel baseline is not bound by the execution manifest: {resolved}")
    return resolved, value


def _validate_dependency_environment(
    manifest: Any, config: Mapping[str, Any]
) -> dict[str, object]:
    expected_lock_sha256 = config.get("dependency_lock_sha256")
    if not isinstance(expected_lock_sha256, str):
        raise SystemExit("test configuration does not bind the dependency lock")
    dependency_gate = audit_dependency_lock(
        ROOT / "requirements-bplus.lock",
        expected_lock_sha256=expected_lock_sha256,
    )
    manifest_lock_sha256 = manifest.dependency_lock_hash.removeprefix("sha256:")
    dependency_gate["historical_manifest_dependency_lock_sha256"] = manifest_lock_sha256
    dependency_gate["historical_manifest_binding_match"] = (
        dependency_gate["lock_sha256"] == manifest_lock_sha256
    )
    print(
        DEPENDENCY_GATE_MARKER
        + json.dumps(dependency_gate, ensure_ascii=False, sort_keys=True)
    )
    if dependency_gate["accepted"] is not True:
        raise SystemExit("dependency lock/runtime consistency gate rejected execution")
    return dependency_gate


def validate_control_plane(manifest_path: Path, config: dict[str, Any]) -> tuple[Any, dict[str, object]]:
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
    dependency_gate = _validate_dependency_environment(manifest, config)
    return manifest, dependency_gate


def _write_json_new_or_replace(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _publish_result(
    *,
    result_path: Path,
    suite_result_root: Path,
    suite: str,
    result: dict[str, Any],
    capture_only: bool,
) -> None:
    """Publish ordinary evidence, or leave all global result paths untouched."""

    if capture_only:
        return
    _write_json_new_or_replace(result_path, result)
    suite_result_root.mkdir(parents=True, exist_ok=True)
    _write_json_new_or_replace(
        suite_result_root / f"{suite}.json",
        result,
    )


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


def _registration_gate_summary(output: str) -> dict[str, Any] | None:
    marker = "SITINA_REGISTRATION_GATE_JSON:"
    lines = [line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
    if len(lines) != 1:
        return None
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _execute_disposable_child(
    *,
    arguments: argparse.Namespace,
    config: Mapping[str, Any],
    definition: Mapping[str, Any],
    selectors: list[str],
    manifest_path: Path,
    capture_readonly_roots: list[str],
    home: Path,
) -> dict[str, Any]:
    guard_directory = home / ".guard"
    guard_directory.mkdir()
    (guard_directory / "sitecustomize.py").write_text(
        NETWORK_GUARD,
        encoding="utf-8",
    )
    attempt_log = home / "external-attempts.jsonl"
    production_attempt_log = home / "production-attempts.jsonl"
    readonly_attempt_log = home / "readonly-attempts.jsonl"
    environment = dict(os.environ)
    environment.update(
        {
            "SITINA_HOME": str(home),
            "SITINA_PYTHON": config["approved_python"],
            "SITINA_LIVE_TEST": "0",
            "SITINA_BPLUS_TEST_LAYER": arguments.suite,
            "SITINA_EXECUTION_MANIFEST": str(
                manifest_path.resolve(strict=True)
            ),
            "SITINA_PRODUCTION_SENTINEL_VERIFIED": "1",
            "SITINA_EXTERNAL_ATTEMPT_LOG": str(attempt_log),
            "SITINA_PRODUCTION_ATTEMPT_LOG": str(
                production_attempt_log
            ),
            "SITINA_READONLY_ATTEMPT_LOG": str(readonly_attempt_log),
            "SITINA_READONLY_ROOTS_JSON": json.dumps(
                capture_readonly_roots,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "SITINA_PRODUCTION_HOME": config["production_home"],
            "SITINA_PRODUCTION_GUARD_PROFILE": (
                "APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1"
            ),
            "HOME": str(home),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(home / ".pycache"),
            "PYTHONPATH": os.pathsep.join(
                (
                    str(guard_directory),
                    str(ROOT),
                    str(ROOT / "tests/foundation"),
                    str(ROOT / "core"),
                )
            ),
            "PATH": os.pathsep.join(
                (
                    str(Path(config["approved_python"]).parent),
                    os.environ.get("PATH", ""),
                )
            ),
        }
    )
    for name in list(environment):
        if any(
            fragment in name.upper()
            for fragment in (
                "API_KEY",
                "AUTH_TOKEN",
                "PASSWORD",
                "PRIVATE_KEY",
            )
        ):
            environment.pop(name, None)
    strict_activation_gate = (
        definition.get("result_policy")
        == "ZERO_NONPASS_AND_COMPLETE_V1"
    )
    registration_policy = (
        definition.get("result_policy")
        == "EXACT_HISTORICAL_SKIP_ALLOWLIST_V1"
    )
    if strict_activation_gate:
        command = [
            config["approved_python"],
            "-m",
            "tests.foundation.activation_gate_runner",
            *selectors,
        ]
    elif registration_policy:
        command = [
            config["approved_python"],
            "-m",
            "tests.foundation.registration_gate_runner",
            "--registry",
            str(CONFIG),
        ]
    else:
        command = [
            config["approved_python"],
            "-m",
            "unittest",
            *[_unittest_selector(item) for item in selectors],
        ]
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
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def terminate_child_group(
        _signum: int,
        _frame: Any,
    ) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=10)
        except ProcessLookupError:
            pass
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, terminate_child_group)
    timed_out = False
    try:
        try:
            output, _ = process.communicate(
                timeout=int(definition["timeout_seconds"])
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                output, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
    duration = time.monotonic() - started
    sys.stdout.write(output)
    test_count_match = re.search(
        r"Ran\s+(\d+)\s+tests?\s+in\s+",
        output,
    )
    skipped_match = re.search(r"skipped=(\d+)", output)
    warning_lines = [
        line[:1000]
        for line in output.splitlines()
        if re.search(
            r"(?:^|\b)(?:[A-Za-z]+Warning|WARNING)(?:\b|:)",
            line,
        )
    ]
    external_attempts = (
        attempt_log.read_text(encoding="utf-8")
        if attempt_log.exists()
        else ""
    )
    production_attempts = (
        production_attempt_log.read_text(encoding="utf-8")
        if production_attempt_log.exists()
        else ""
    )
    readonly_attempts = (
        readonly_attempt_log.read_text(encoding="utf-8")
        if readonly_attempt_log.exists()
        else ""
    )
    activation_gate = (
        _activation_gate_summary(output)
        if strict_activation_gate
        else None
    )
    registration_gate = (
        _registration_gate_summary(output)
        if registration_policy
        else None
    )
    return_code = process.returncode if not timed_out else 124
    if strict_activation_gate and (
        activation_gate is None
        or activation_gate.get("accepted") is not True
    ):
        return_code = return_code or 128
    if registration_policy and (
        registration_gate is None
        or registration_gate.get("accepted") is not True
    ):
        return_code = return_code or 129
    if external_attempts:
        return_code = return_code or 125
    if production_attempts:
        return_code = return_code or 127
    if readonly_attempts:
        return_code = return_code or 130
    return {
        "command": command,
        "duration": duration,
        "output": output,
        "test_count_match": test_count_match,
        "skipped_match": skipped_match,
        "warning_lines": warning_lines,
        "external_attempts": external_attempts,
        "production_attempts": production_attempts,
        "production_attempt_records": _parse_json_lines(
            production_attempts
        ),
        "readonly_attempts": readonly_attempts,
        "readonly_attempt_records": _parse_json_lines(
            readonly_attempts
        ),
        "activation_gate": activation_gate,
        "registration_gate": registration_gate,
        "return_code": return_code,
        "timed_out": timed_out,
    }


def _execute_with_disposable_cleanup(
    disposable: Any,
    operation: Callable[[], dict[str, Any]],
) -> tuple[dict[str, Any], bool, str | None]:
    cleanup_error: str | None = None
    try:
        result = operation()
    finally:
        try:
            disposable.cleanup()
        except Exception as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"
            print(
                f"disposable home cleanup failed: {cleanup_error}",
                file=sys.stderr,
            )
    cleanup_succeeded = (
        cleanup_error is None and not disposable.path.exists()
    )
    return result, cleanup_succeeded, cleanup_error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", nargs="?")
    parser.add_argument("--test", action="append", default=[])
    parser.add_argument("--evidence-stage")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--live-approval")
    parser.add_argument("--execution-manifest", type=Path)
    parser.add_argument("--production-sentinel", type=Path)
    parser.add_argument("--production-mutable-sentinel", type=Path)
    parser.add_argument("--capture-only", action="store_true")
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
    if arguments.capture_only and (
        os.environ.get("SITINA_STEP7_OFFICIAL_GATE_CAPTURE") != "1"
        or arguments.suite
        not in {"execution_activation_gate", "all_registered_unique"}
    ):
        raise SystemExit(
            "capture-only is reserved for the Step 7 official deployed gates"
        )
    capture_readonly_roots: list[str] = []
    if arguments.capture_only:
        try:
            source_root = Path(
                os.environ["SITINA_STEP7_SOURCE_ROOT"]
            )
            if (
                not source_root.is_absolute()
                or source_root.resolve(strict=True) != source_root
            ):
                raise ValueError(
                    "capture-only source root is not canonical"
                )
            raw_capture_roots = json.loads(
                os.environ["SITINA_STEP7_CAPTURE_READONLY_ROOTS_JSON"]
            )
            capture_readonly_roots = [
                str(Path(value).resolve(strict=True))
                for value in raw_capture_roots
            ]
        except (
            KeyError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise SystemExit(
                "capture-only read-only roots are invalid"
            ) from exc
        expected_capture_roots = [
            str(source_root),
            str(ROOT.resolve(strict=True)),
            str(CONTROL_ROOT.resolve(strict=True)),
        ]
        if capture_readonly_roots != expected_capture_roots:
            raise SystemExit(
                "capture-only read-only roots do not match source, "
                "deployment, and control roots"
            )
    definition = suites[arguments.suite]
    evidence_stage = arguments.evidence_stage or arguments.suite
    directed_stage_contracts = {
        "minimal_negative_contract": {
            "suite": "unit_fast",
            "selectors": [
                "tests/foundation/test_dependency_lock_gate.py",
                "tests/foundation/test_registration_gate_runner.py",
            ],
        },
        "identity_sentinel_directed": {
            "suite": "unit_fast",
            "selectors": [
                "tests/foundation/test_sentinel_content_addressed.py",
                "tests/test_execution_bridge.py",
                "tests/test_execution_bridge_integration.py",
                "tests/test_execution_sandbox.py",
            ],
        },
    }
    formal_stage_by_suite = {
        "execution_activation_gate": "execution_activation",
        "step7_readiness_gate": "step7_readiness_gate",
        "unit_fast": "unit_fast",
        "integration_isolated": "integration_isolated",
        "all_registered_unique": "all_registered_unique",
    }
    if arguments.evidence_stage:
        directed = directed_stage_contracts.get(evidence_stage)
        if directed is not None:
            if (
                arguments.suite != directed["suite"]
                or arguments.test != directed["selectors"]
            ):
                raise SystemExit("directed evidence stage does not match its exact suite/selectors")
        elif (
            formal_stage_by_suite.get(arguments.suite) != evidence_stage
            or arguments.test
        ):
            raise SystemExit("formal evidence stage does not match its exact suite/selectors")
    manifest_path = arguments.execution_manifest or Path(definition.get("execution_manifest", PHASE_MINUS1_MANIFEST))
    manifest, dependency_gate = validate_control_plane(manifest_path, config)
    if manifest.production_home != Path(config["production_home"]).resolve(strict=True):
        raise SystemExit("execution manifest and test configuration name different production homes")
    if (arguments.production_sentinel or arguments.production_mutable_sentinel) and arguments.execution_manifest is None:
        raise SystemExit("custom sentinel baselines require an explicit execution manifest")
    phase_token = "phase-minus1" if manifest.authorized_phase == "-1" else f"phase{manifest.authorized_phase.lower()}"
    result_path = CONTROL_ROOT / f"sitina-bplus-{phase_token}-test-results.json"
    suite_result_root = CONTROL_ROOT / f"sitina-bplus-{phase_token}-test-results"
    registration_policy = (
        definition.get("result_policy") == "EXACT_HISTORICAL_SKIP_ALLOWLIST_V1"
    )
    if registration_policy:
        if arguments.test:
            raise SystemExit("all_registered_unique does not accept --test overrides")
        from tests.foundation.registration_gate_runner import unique_registered_selectors

        selectors = list(unique_registered_selectors(config))
    else:
        selectors = arguments.test or list(definition["selectors"])

    sys.path.insert(0, str(ROOT / "tests/foundation"))
    from home_factory import DisposableHomeFactory, capture_production_mutable_sentinel, capture_production_sentinel

    production = Path(config["production_home"])
    sentinel_path = arguments.production_sentinel or INITIAL_SENTINEL
    mutable_sentinel_path = arguments.production_mutable_sentinel or MUTABLE_SENTINEL
    if manifest.production_sentinel_hash is None:
        raise SystemExit("execution manifest does not bind a production sentinel")
    sentinel_path, initial = _validate_sentinel_baseline(
        sentinel_path,
        expected_schema="PRODUCTION_SENTINEL_V2",
        production_home=production,
        goal_thread_id=GOAL_THREAD_ID,
        expected_report_hash=manifest.production_sentinel_hash,
    )
    before = capture_production_sentinel(production, GOAL_THREAD_ID)
    if before["report_sha256"] != initial["report_sha256"]:
        raise SystemExit("production sentinel differs before test execution")
    if not mutable_sentinel_path.is_file():
        raise SystemExit("extended Production mutable-root sentinel baseline is missing")
    resolved_manifest = manifest_path.resolve(strict=True)
    legacy_unbound_mutable = (
        resolved_manifest == PHASE_MINUS1_MANIFEST.resolve(strict=True)
        and mutable_sentinel_path.resolve(strict=True) == MUTABLE_SENTINEL.resolve(strict=True)
    )
    if manifest.production_mutable_sentinel_hash is None and not legacy_unbound_mutable:
        raise SystemExit("execution manifest does not bind the mutable production sentinel")
    mutable_sentinel_path, mutable_initial = _validate_sentinel_baseline(
        mutable_sentinel_path,
        expected_schema="PRODUCTION_MUTABLE_SENTINEL_V3",
        production_home=production,
        goal_thread_id=GOAL_THREAD_ID,
        expected_report_hash=manifest.production_mutable_sentinel_hash,
    )
    if mutable_initial.get("base_v1_report_sha256") != initial["report_sha256"]:
        raise SystemExit("mutable sentinel baseline is not based on the selected base sentinel")
    mutable_before = capture_production_mutable_sentinel(production, GOAL_THREAD_ID)
    if mutable_before["report_sha256"] != mutable_initial["report_sha256"]:
        raise SystemExit("extended Production mutable-root sentinel differs before test execution")

    factory = DisposableHomeFactory(ROOT, production, Path(config["test_home_root"]))
    disposable = factory.create(prefix=f"{arguments.suite}-")
    home = disposable.path
    child, cleanup_succeeded, cleanup_error = (
        _execute_with_disposable_cleanup(
            disposable,
            lambda: _execute_disposable_child(
                arguments=arguments,
                config=config,
                definition=definition,
                selectors=selectors,
                manifest_path=manifest_path,
                capture_readonly_roots=capture_readonly_roots,
                home=home,
            ),
        )
    )
    command = child["command"]
    duration = child["duration"]
    output = child["output"]
    test_count_match = child["test_count_match"]
    skipped_match = child["skipped_match"]
    warning_lines = child["warning_lines"]
    external_attempts = child["external_attempts"]
    production_attempts = child["production_attempts"]
    production_attempt_records = child["production_attempt_records"]
    readonly_attempts = child["readonly_attempts"]
    readonly_attempt_records = child["readonly_attempt_records"]
    activation_gate = child["activation_gate"]
    registration_gate = child["registration_gate"]
    return_code = child["return_code"]
    timed_out = child["timed_out"]
    if not cleanup_succeeded:
        return_code = return_code or 131
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
        "schema": "BPLUS_TEST_RESULT_V2",
        "stage": evidence_stage,
        "suite": arguments.suite,
        "selectors": selectors,
        "mode": "tests",
        "command": command,
        "child_cwd": str(home),
        "child_home_cleanup_succeeded": cleanup_succeeded,
        "child_home_cleanup_error": cleanup_error,
        "duration_seconds": round(duration, 6),
        "test_count": int(test_count_match.group(1)) if test_count_match else None,
        "skipped_count": int(skipped_match.group(1)) if skipped_match else 0,
        "activation_gate": activation_gate,
        "registration_gate": registration_gate,
        "dependency_gate": dependency_gate,
        "warning_count": len(warning_lines),
        "warning_lines": warning_lines[:200],
        "stdout_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "timed_out": timed_out,
        "return_code": return_code,
        "external_attempt_count": len(external_attempts.splitlines()),
        "production_attempt_count": len(production_attempts.splitlines()),
        "production_attempt_records": production_attempt_records[:500],
        "production_attempt_log_sha256": hashlib.sha256(production_attempts.encode("utf-8")).hexdigest(),
        "readonly_attempt_count": len(readonly_attempts.splitlines()),
        "readonly_attempt_records": readonly_attempt_records[:500],
        "readonly_attempt_log_sha256": hashlib.sha256(
            readonly_attempts.encode("utf-8")
        ).hexdigest(),
        "capture_only": arguments.capture_only,
        "production_guard_profile": "APPLICATION_ENFORCED_PYTHON_AUDIT_HOOK_V1",
        "production_sentinel_before": before["report_sha256"],
        "production_sentinel_after": after["report_sha256"],
        "production_mutable_sentinel_before": mutable_before["report_sha256"],
        "production_mutable_sentinel_after": mutable_after["report_sha256"],
        "production_sentinel_unchanged": sentinel_unchanged,
        "production_sentinel_baseline": str(sentinel_path),
        "production_mutable_sentinel_baseline": str(mutable_sentinel_path),
        "execution_manifest_hash": manifest.manifest_hash,
    }
    _publish_result(
        result_path=result_path,
        suite_result_root=suite_result_root,
        suite=arguments.suite,
        result=result,
        capture_only=arguments.capture_only,
    )
    if arguments.capture_only:
        print(
            CAPTURE_MARKER
            + json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    if timed_out:
        print(f"suite timeout after {definition['timeout_seconds']}s", file=sys.stderr)
    if external_attempts:
        print("external network attempt denied", file=sys.stderr)
    if production_attempts:
        print("Production mutable-path attempt denied", file=sys.stderr)
    if readonly_attempts:
        print("read-only-root mutation attempt denied", file=sys.stderr)
    if not cleanup_succeeded:
        print("disposable home cleanup failed", file=sys.stderr)
    if not sentinel_unchanged:
        print("production sentinel changed during tests", file=sys.stderr)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
