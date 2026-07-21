"""Trusted stdlib-only worker executed inside the OS sandbox.

The parent binds this file's hash into a one-use capability.  This module must
not import Sitina or any third-party package before kernel limits are applied.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import doctest
import errno
import hashlib
import importlib.util
import io
import json
import os
import resource
import socket
import subprocess
import sys
import threading
import traceback
import unittest
from pathlib import Path


RESULT_MARKER = "SITINA_SANDBOX_WORKER_RESULT:"
PROOF_MARKER = "SITINA_SANDBOX_WORKER_PROOF:"
CHALLENGE_MARKER = "SITINA_SANDBOX_PARENT_CHALLENGE:"

_TRUSTED_TEST_LOADER = unittest.TestLoader
_TRUSTED_TEXT_RUNNER = unittest.TextTestRunner
_TRUSTED_DOCTEST_FINDER = doctest.DocTestFinder
_TRUSTED_DOCTEST_RUNNER = doctest.DocTestRunner


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


class _DarwinTaskInfo(ctypes.Structure):
    _fields_ = [
        ("virtual_size", ctypes.c_uint64),
        ("resident_size", ctypes.c_uint64),
        ("total_user", ctypes.c_uint64),
        ("total_system", ctypes.c_uint64),
        ("threads_user", ctypes.c_uint64),
        ("threads_system", ctypes.c_uint64),
        ("policy", ctypes.c_int32),
        ("faults", ctypes.c_int32),
        ("pageins", ctypes.c_int32),
        ("cow_faults", ctypes.c_int32),
        ("messages_sent", ctypes.c_int32),
        ("messages_received", ctypes.c_int32),
        ("syscalls_mach", ctypes.c_int32),
        ("syscalls_unix", ctypes.c_int32),
        ("csw", ctypes.c_int32),
        ("threadnum", ctypes.c_int32),
        ("numrunning", ctypes.c_int32),
        ("priority", ctypes.c_int32),
    ]


def _darwin_virtual_size() -> int:
    """Return current VM size so RLIMIT_AS can bound *additional* allocation.

    Darwin maps a roughly 400-GiB shared region before Python starts, so an
    absolute 1-GiB RLIMIT_AS is already below the process's VM size.  Binding
    the hard ceiling to current VM plus the configured allowance preserves a
    real kernel-enforced memory-growth limit.
    """

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    libproc.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    libproc.proc_pidinfo.restype = ctypes.c_int
    info = _DarwinTaskInfo()
    size = libproc.proc_pidinfo(os.getpid(), 4, 0, ctypes.byref(info), ctypes.sizeof(info))
    if size != ctypes.sizeof(info) or info.virtual_size <= 0:
        raise RuntimeError("cannot determine Darwin sandbox VM baseline")
    return int(info.virtual_size)


def _decode_request(value: str) -> dict[str, object]:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        request = json.loads(raw)
    except Exception as error:
        raise RuntimeError("sandbox worker request is invalid") from error
    if not isinstance(request, dict):
        raise RuntimeError("sandbox worker request must be an object")
    return request


def _apply_limits(raw: object) -> None:
    if not isinstance(raw, dict):
        raise RuntimeError("sandbox resource limits are missing")
    bindings = {
        "cpu_seconds": resource.RLIMIT_CPU,
        "memory_bytes": resource.RLIMIT_AS,
        "file_bytes": resource.RLIMIT_FSIZE,
        "process_count": resource.RLIMIT_NPROC,
        "open_files": resource.RLIMIT_NOFILE,
    }
    for name, limit_kind in bindings.items():
        value = raw.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise RuntimeError(f"sandbox resource limit is invalid: {name}")
        if name == "memory_bytes":
            value = _darwin_virtual_size() + value
        _soft, hard = resource.getrlimit(limit_kind)
        if hard != resource.RLIM_INFINITY and value > hard:
            raise RuntimeError(f"sandbox resource limit exceeds host ceiling: {name}")
        # Lower the effective limit without trying to lower the inherited hard
        # ceiling.  Darwin rejects RLIMIT_NPROC hard ceilings below the UID's
        # already-running process count; the soft ceiling is the kernel limit
        # that constrains this worker.
        resource.setrlimit(limit_kind, (value, hard))


def _module(path: Path, ordinal: int):
    name = f"_sitina_sandbox_target_{ordinal}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load sandbox target: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_doctest(path: Path, ordinal: int, expected_count: int) -> dict[str, int]:
    finder = _TRUSTED_DOCTEST_FINDER(exclude_empty=True)
    runner = _TRUSTED_DOCTEST_RUNNER(verbose=False)
    find = finder.find
    run = runner.run
    summarize = runner.summarize
    module = _module(path, ordinal)
    found = find(module)
    collected = sum(len(test.examples) for test in found)
    if collected != expected_count:
        raise RuntimeError("doctest discovery does not match sealed TestPlan")
    for test in found:
        run(test, out=lambda _value: None)
    summary = summarize(verbose=False)
    return {
        "collected": collected,
        "executed": summary.attempted,
        "passed": summary.attempted - summary.failed,
        "failed": summary.failed,
        "skipped": 0,
        "errors": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }


def _flatten_test_ids(suite: object) -> list[str]:
    if isinstance(suite, unittest.TestCase):
        return [suite.id()]
    result: list[str] = []
    try:
        children = list(suite)  # type: ignore[arg-type]
    except TypeError as error:
        raise RuntimeError("unittest discovery returned a non-suite object") from error
    for child in children:
        result.extend(_flatten_test_ids(child))
    return result


def _run_unittest(path: Path, ordinal: int, planned_ids: list[str]) -> dict[str, int]:
    loader = _TRUSTED_TEST_LOADER()
    runner = _TRUSTED_TEXT_RUNNER(stream=io.StringIO(), verbosity=0)
    load = loader.loadTestsFromModule
    run = runner.run
    module = _module(path, ordinal)
    suite = load(module)
    actual_ids = _flatten_test_ids(suite)
    if actual_ids != planned_ids:
        raise RuntimeError("unittest discovery does not match sealed TestPlan")
    collected = len(actual_ids)
    result = run(suite)
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    expected_failures = len(result.expectedFailures)
    unexpected_successes = len(result.unexpectedSuccesses)
    nonpass_ids = {
        *(test.id() for test, _detail in result.failures),
        *(test.id() for test, _detail in result.errors),
        *(test.id() for test, _reason in result.skipped),
        *(test.id() for test, _detail in result.expectedFailures),
        *(test.id() for test in result.unexpectedSuccesses),
    }
    started = result.testsRun
    passed = max(0, started - len(nonpass_ids))
    return {
        "collected": collected,
        "executed": started,
        "passed": passed,
        "failed": failures,
        "skipped": skipped,
        "errors": errors,
        "expected_failures": expected_failures,
        "unexpected_successes": unexpected_successes,
    }


def _run_tests(request: dict[str, object]) -> dict[str, object]:
    raw_targets = request.get("targets")
    read_roots = request.get("read_roots")
    plan = request.get("test_plan")
    plan_hash = request.get("test_plan_hash")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise RuntimeError("sandbox worker has no test targets")
    if not isinstance(read_roots, list) or not read_roots:
        raise RuntimeError("sandbox worker has no read roots")
    if not isinstance(plan, dict) or plan.get("schema") != "SITINA_TRUSTED_TEST_PLAN_V1":
        raise RuntimeError("sandbox worker has no trusted TestPlan")
    if not isinstance(plan_hash, str) or hashlib.sha256(_canonical(plan)).hexdigest() != plan_hash:
        raise RuntimeError("sandbox trusted TestPlan hash mismatch")
    planned_targets = plan.get("targets")
    if not isinstance(planned_targets, list) or len(planned_targets) != len(raw_targets):
        raise RuntimeError("sandbox trusted TestPlan target mismatch")
    expected_total = plan.get("collected_test_count")
    if not isinstance(expected_total, int) or isinstance(expected_total, bool) or expected_total <= 0:
        raise RuntimeError("sandbox trusted TestPlan has no executable tests")
    for root in reversed(read_roots):
        if not isinstance(root, str):
            raise RuntimeError("sandbox read root is invalid")
        sys.path.insert(0, root)

    totals = {
        "collected": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "errors": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    target_results: list[dict[str, object]] = []
    for ordinal, (raw, planned) in enumerate(zip(raw_targets, planned_targets, strict=True)):
        if not isinstance(raw, dict) or raw.get("mode") not in {"doctest", "unittest"}:
            raise RuntimeError("sandbox test target is invalid")
        if not isinstance(planned, dict):
            raise RuntimeError("sandbox trusted TestPlan target is invalid")
        path = Path(str(raw.get("path")))
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise RuntimeError("sandbox test target is not an absolute regular file")
        if (
            planned.get("index") != ordinal
            or planned.get("path") != str(path)
            or planned.get("mode") != raw.get("mode")
            or planned.get("source_hash") != hashlib.sha256(path.read_bytes()).hexdigest()
        ):
            raise RuntimeError("sandbox target does not match sealed TestPlan")
        expected_count = planned.get("expected_count")
        planned_ids = planned.get("planned_test_ids")
        if (
            not isinstance(expected_count, int)
            or isinstance(expected_count, bool)
            or expected_count < 0
            or not isinstance(planned_ids, list)
            or any(not isinstance(item, str) for item in planned_ids)
        ):
            raise RuntimeError("sandbox trusted TestPlan counts are invalid")
        try:
            # Keep target chatter separate from the single authenticated
            # protocol line emitted through sys.__stdout__ by main().
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                counts = (
                    _run_unittest(path, ordinal, planned_ids)
                    if raw["mode"] == "unittest"
                    else _run_doctest(path, ordinal, expected_count)
                )
        except BaseException as error:  # untrusted test failures become evidence, not worker escape
            counts = {
                "collected": 0,
                "executed": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "errors": 1,
                "expected_failures": 0,
                "unexpected_successes": 0,
            }
            target_results.append(
                {
                    "path": str(path),
                    "mode": raw["mode"],
                    "counts": counts,
                    "error_type": type(error).__name__,
                    "error_trace_hash_input": "".join(traceback.format_exception_only(type(error), error))[:1000],
                }
            )
        else:
            target_results.append({"path": str(path), "mode": raw["mode"], "counts": counts})
        for name in totals:
            totals[name] += counts[name]
    if totals["collected"] != expected_total:
        raise RuntimeError("sandbox collected count does not match sealed TestPlan")
    return {
        "schema": "SITINA_SANDBOX_TEST_RESULT_V1",
        "mode": "tests",
        "test_plan_hash": plan_hash,
        "counts": totals,
        "targets": target_results,
    }


def _denied(callable_) -> bool:
    try:
        callable_()
    except PermissionError:
        return True
    except OSError as error:
        return error.errno in {errno.EPERM, errno.EACCES, errno.EAGAIN}
    return False


def _run_probe(request: dict[str, object]) -> dict[str, object]:
    outside_read = str(request["outside_read"])
    outside_write = str(request["outside_write"])
    symlink_escape = str(request["symlink_escape"])

    def socket_probe():
        with socket.socket() as handle:
            handle.connect(("127.0.0.1", 9))

    def dns_probe():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as handle:
            handle.sendto(b"x", ("1.1.1.1", 53))

    def no_inherited_descriptors() -> bool:
        for descriptor in range(3, int(request["resource_limits"]["open_files"])):  # type: ignore[index]
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno == errno.EBADF:
                    continue
                return False
            return False
        return True

    results = {
        "socket": _denied(socket_probe),
        "dns": _denied(dns_probe),
        "subprocess": _denied(lambda: subprocess.run(["/usr/bin/true"], check=True)),
        # FFI remains available for Python internals, but it cannot use libc to
        # escape the no-process boundary. system() returns a non-zero wait
        # status because Seatbelt denies the child creation.
        "ctypes": ctypes.CDLL(None).system(b"/usr/bin/true") != 0,
        "absolute_write": _denied(lambda: Path(outside_write).write_text("denied", encoding="utf-8")),
        "absolute_read": _denied(lambda: Path(outside_read).read_bytes()),
        "symlink_escape": _denied(lambda: Path(symlink_escape).write_text("denied", encoding="utf-8")),
        "device": _denied(lambda: open("/dev/disk0", "rb")),
        "inherited_fd": no_inherited_descriptors(),
    }
    return {"schema": "SITINA_SANDBOX_PROBE_RESULT_V1", "mode": "probe", "results": results}


def main(argv: list[str] | None = None) -> int:
    # Capture the protocol primitives in main-frame locals before any target
    # module is imported.  Target code can mutate module globals, sys streams,
    # or stdlib attributes, but it cannot replace these already-bound objects.
    protocol_input = sys.__stdin__.buffer
    protocol_output = sys.__stdout__
    encode_response = base64.urlsafe_b64encode
    response_digest = hashlib.sha256
    json_dumps = json.dumps
    enumerate_threads = threading.enumerate
    controller_thread_id = threading.get_ident()
    result_marker = RESULT_MARKER
    proof_marker = PROOF_MARKER
    challenge_prefix = CHALLENGE_MARKER.encode("ascii")

    def canonicalize(value: object) -> bytes:
        return json_dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def untrusted_threads() -> list[str]:
        return sorted(
            str(item.name)
            for item in enumerate_threads()
            if item.ident != controller_thread_id
        )

    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    arguments = parser.parse_args(argv)
    request = _decode_request(arguments.request)
    response: dict[str, object]
    try:
        _apply_limits(request.get("resource_limits"))
        mode = request.get("mode")
        if mode == "tests":
            response = _run_tests(request)
        elif mode == "probe":
            response = _run_probe(request)
        else:
            raise RuntimeError("sandbox worker mode is invalid")
        response["worker_ok"] = True
    except BaseException as error:
        response = {
            "worker_ok": False,
            "error_type": type(error).__name__,
            "error": str(error)[:1000],
        }
    lingering_threads = untrusted_threads()
    if lingering_threads:
        response = {
            "worker_ok": False,
            "error_type": "UntrustedThreadPersisted",
            "error": "target left background threads active",
            "thread_name_hashes": [
                response_digest(value.encode("utf-8")).hexdigest()
                for value in lingering_threads
            ],
        }
    canonical_response = canonicalize(response)
    encoded = encode_response(canonical_response).decode("ascii")
    protocol_output.write(result_marker + encoded + "\n")
    protocol_output.flush()
    challenge_line = protocol_input.readline(256)
    if not challenge_line.startswith(challenge_prefix):
        return 3
    challenge = challenge_line[len(challenge_prefix):].strip()
    if len(challenge) != 64 or any(value not in b"0123456789abcdef" for value in challenge):
        return 3
    # A background target thread that races for the challenge invalidates the
    # protocol even if it exits before it can emit a forged proof.
    if untrusted_threads():
        return 4
    proof = response_digest(challenge + b"\0" + canonical_response).hexdigest()
    protocol_output.write(proof_marker + proof + "\n")
    protocol_output.flush()
    return 0 if response.get("worker_ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
