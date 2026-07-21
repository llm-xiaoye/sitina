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
import importlib.util
import io
import json
import os
import resource
import socket
import subprocess
import sys
import traceback
import unittest
from pathlib import Path


RESULT_MARKER = "SITINA_SANDBOX_WORKER_RESULT:"


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


def _run_doctest(path: Path, ordinal: int) -> dict[str, int]:
    module = _module(path, ordinal)
    found = doctest.DocTestFinder(exclude_empty=True).find(module)
    collected = sum(len(test.examples) for test in found)
    runner = doctest.DocTestRunner(verbose=False)
    for test in found:
        runner.run(test, out=lambda _value: None)
    summary = runner.summarize(verbose=False)
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


def _run_unittest(path: Path, ordinal: int) -> dict[str, int]:
    module = _module(path, ordinal)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)
    collected = suite.countTestCases()
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
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
    if not isinstance(raw_targets, list) or not raw_targets:
        raise RuntimeError("sandbox worker has no test targets")
    if not isinstance(read_roots, list) or not read_roots:
        raise RuntimeError("sandbox worker has no read roots")
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
    for ordinal, raw in enumerate(raw_targets):
        if not isinstance(raw, dict) or raw.get("mode") not in {"doctest", "unittest"}:
            raise RuntimeError("sandbox test target is invalid")
        path = Path(str(raw.get("path")))
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise RuntimeError("sandbox test target is not an absolute regular file")
        try:
            # Keep target chatter separate from the single authenticated
            # protocol line emitted through sys.__stdout__ by main().
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                counts = (
                    _run_unittest(path, ordinal)
                    if raw["mode"] == "unittest"
                    else _run_doctest(path, ordinal)
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
    return {"mode": "tests", "counts": totals, "targets": target_results}


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
    return {"mode": "probe", "results": results}


def main(argv: list[str] | None = None) -> int:
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
    token = str(request.get("result_token") or "")
    encoded = base64.urlsafe_b64encode(
        json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    print(RESULT_MARKER + token + ":" + encoded, file=sys.__stdout__, flush=True)
    return 0 if response.get("worker_ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
