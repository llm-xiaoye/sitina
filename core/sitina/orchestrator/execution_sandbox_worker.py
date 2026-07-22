"""Trusted stdlib-only signing supervisor and Seatbelt item worker.

The parent binds this file's hash into a one-use capability.  This module must
not import Sitina or any third-party package.  Target modules run only in
per-item Seatbelt processes and never share the supervisor's result channel.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import doctest
import errno
import hashlib
import hmac
import importlib.util
import io
import json
import os
import resource
import select
import socket
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path


RESULT_MARKER = "SITINA_SANDBOX_WORKER_RESULT:"
PROOF_MARKER = "SITINA_SANDBOX_WORKER_PROOF:"
EXECUTOR_RESULT_MARKER = "SITINA_SANDBOX_EXECUTOR_RESULT:"
KEY_MARKER = "SITINA_SANDBOX_CONTROLLER_KEY:"
CHALLENGE_MARKER = "SITINA_SANDBOX_PARENT_CHALLENGE:"

ITEM_SUCCESS_EXIT = 70
ITEM_EXCEPTION_EXIT = 71
ITEM_FAILURE_EXIT = 72

_TRUSTED_DOCTEST_FINDER = doctest.DocTestFinder


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


def _example_fingerprint(example: doctest.Example) -> str:
    identity = {
        "source": example.source,
        "want": example.want,
        "exc_msg": example.exc_msg,
        "options": [
            [int(flag), bool(enabled)]
            for flag, enabled in sorted(example.options.items())
        ],
    }
    return hashlib.sha256(_canonical(identity)).hexdigest()


def _exception_only(error: BaseException) -> tuple[str, str]:
    error_type = type(error)
    rendered = traceback.format_exception_only(error_type, error)
    if issubclass(error_type, SyntaxError):
        prefixes = (
            f"{error_type.__qualname__}:",
            f"{error_type.__module__}.{error_type.__qualname__}:",
        )
        rendered = rendered[
            next(index for index, line in enumerate(rendered) if line.startswith(prefixes)):
        ]
    return f"{error_type.__module__}.{error_type.__qualname__}", "".join(rendered)


def _validated_test_targets(
    request: dict[str, object],
) -> tuple[list[tuple[dict[str, object], dict[str, object]]], list[str], str]:
    """Validate the sealed plan without importing or executing a target."""

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
    if any(not isinstance(root, str) for root in read_roots):
        raise RuntimeError("sandbox read root is invalid")

    if any(
        not isinstance(planned, dict) or planned.get("mode") != "doctest"
        for planned in planned_targets
    ):
        raise RuntimeError("generic unittest result source is unsupported and fails closed")

    validated: list[tuple[dict[str, object], dict[str, object]]] = []
    validated_total = 0
    for ordinal, (raw, planned) in enumerate(zip(raw_targets, planned_targets, strict=True)):
        if not isinstance(raw, dict) or raw.get("mode") != "doctest":
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
        planned_examples = planned.get("planned_examples")
        if (
            not isinstance(expected_count, int)
            or isinstance(expected_count, bool)
            or expected_count < 0
            or not isinstance(planned_ids, list)
            or any(not isinstance(item, str) for item in planned_ids)
            or planned_ids
            or not isinstance(planned_examples, list)
            or len(planned_examples) != expected_count
        ):
            raise RuntimeError("sandbox trusted TestPlan counts are invalid")
        for index, example in enumerate(planned_examples):
            if (
                not isinstance(example, dict)
                or example.get("index") != index
                or not isinstance(example.get("fingerprint"), str)
                or not isinstance(example.get("want"), str)
                or not (example.get("exc_msg") is None or isinstance(example.get("exc_msg"), str))
                or not isinstance(example.get("options"), list)
            ):
                raise RuntimeError("sandbox trusted TestPlan example is invalid")
        validated.append((raw, planned))
        validated_total += expected_count
    if validated_total != expected_total:
        raise RuntimeError("sandbox collected count does not match sealed TestPlan")
    return validated, list(read_roots), plan_hash


def _option_flags(raw: object) -> int:
    if not isinstance(raw, list):
        raise RuntimeError("sandbox doctest options are invalid")
    flags = 0
    for item in raw:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], int)
            or isinstance(item[0], bool)
            or not isinstance(item[1], bool)
        ):
            raise RuntimeError("sandbox doctest option is invalid")
        flags = flags | item[0] if item[1] else flags & ~item[0]
    return flags


def _execute_prior_example(test: doctest.DocTest, example_number: int) -> None:
    example = test.examples[example_number]
    option_flags = 0
    for flag, enabled in example.options.items():
        option_flags = option_flags | flag if enabled else option_flags & ~flag
    if option_flags & doctest.SKIP:
        return
    output = doctest._SpoofOut()
    filename = f"<doctest {test.name}[{example_number}]>"
    compile_flags = doctest._extract_future_flags(test.globs)
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            exec(
                compile(example.source, filename, "single", compile_flags, True),
                test.globs,
            )
    except BaseException:
        # Doctest continues after both expected and unexpected exceptions.  The
        # supervisor independently observes every prior item in its own run.
        pass


def _item_executor_main(encoded_request: str) -> int:
    """Run one sealed item with no structured result channel to the supervisor.

    The process has only raw stdout/stderr.  The signing supervisor owns the
    mapping from this exact process to the sealed item and constructs the
    observation after the process exits.
    """

    raw_write = os.write
    raw_exit = os._exit
    enumerate_threads = threading.enumerate
    executor_thread_id = threading.get_ident()
    try:
        request = _decode_request(encoded_request)
        if set(request) != {
            "schema",
            "target",
            "example_index",
            "fingerprints",
            "read_roots",
            "resource_limits",
        } or request.get("schema") != "SITINA_SANDBOX_DOCTEST_ITEM_REQUEST_V1":
            raise RuntimeError("sandbox item request is invalid")
        target = request.get("target")
        fingerprints = request.get("fingerprints")
        read_roots = request.get("read_roots")
        example_index = request.get("example_index")
        if (
            not isinstance(target, dict)
            or set(target) != {"index", "path", "source_hash"}
            or not isinstance(target.get("index"), int)
            or isinstance(target.get("index"), bool)
            or not isinstance(fingerprints, list)
            or not fingerprints
            or any(not isinstance(value, str) for value in fingerprints)
            or not isinstance(example_index, int)
            or isinstance(example_index, bool)
            or not 0 <= example_index < len(fingerprints)
            or not isinstance(read_roots, list)
            or not read_roots
            or any(not isinstance(root, str) for root in read_roots)
        ):
            raise RuntimeError("sandbox item binding is invalid")
        _apply_limits(request.get("resource_limits"))
        for root in reversed(read_roots):
            sys.path.insert(0, root)
        path = Path(str(target.get("path")))
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != target.get("source_hash")
        ):
            raise RuntimeError("sandbox item target identity is invalid")
        finder = _TRUSTED_DOCTEST_FINDER(exclude_empty=True)
        module = _module(path, int(target["index"]))
        flattened = [
            (test, number, example)
            for test in finder.find(module)
            for number, example in enumerate(test.examples)
        ]
        actual_fingerprints = [
            _example_fingerprint(example) for _test, _number, example in flattened
        ]
        if actual_fingerprints != fingerprints:
            raise RuntimeError("sandbox item discovery does not match sealed fingerprints")
        test, example_number, example = flattened[example_index]
        for prior_number in range(example_number):
            _execute_prior_example(test, prior_number)
        option_flags = 0
        for flag, enabled in example.options.items():
            option_flags = option_flags | flag if enabled else option_flags & ~flag
        if option_flags & doctest.SKIP:
            raise RuntimeError("sandbox supervisor launched a skipped item")
        output = doctest._SpoofOut()
        filename = f"<doctest {test.name}[{example_number}]>"
        compile_flags = doctest._extract_future_flags(test.globs)
        error_record: dict[str, str] | None = None
        try:
            with contextlib.redirect_stdout(output):
                exec(
                    compile(example.source, filename, "single", compile_flags, True),
                    test.globs,
                )
        except BaseException as error:
            error_type, error_text = _exception_only(error)
            error_record = {"exception_type": error_type, "exception_text": error_text}
        lingering = [
            item for item in enumerate_threads() if item.ident != executor_thread_id
        ]
        if lingering:
            raise RuntimeError("target left background threads active")
        rendered = output.getvalue().encode("utf-8")
        if rendered:
            raw_write(1, rendered)
        if error_record is not None:
            raw_write(2, error_record["exception_text"].encode("utf-8"))
            raw_exit(ITEM_EXCEPTION_EXIT)
        raw_exit(ITEM_SUCCESS_EXIT)
    except BaseException as error:
        detail = f"{type(error).__name__}:{str(error)[:500]}".encode(
            "utf-8", errors="replace"
        )
        try:
            raw_write(2, detail + b"\n")
        finally:
            raw_exit(ITEM_FAILURE_EXIT)
    return ITEM_FAILURE_EXIT


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


def _executor_main(encoded_request: str) -> int:
    """Run the target-free qualification probe inside Seatbelt."""

    protocol_output = sys.__stdout__
    encode_response = base64.urlsafe_b64encode
    json_dumps = json.dumps
    enumerate_threads = threading.enumerate
    executor_thread_id = threading.get_ident()
    response_digest = hashlib.sha256
    request = _decode_request(encoded_request)

    def untrusted_threads() -> list[str]:
        return sorted(
            str(item.name)
            for item in enumerate_threads()
            if item.ident != executor_thread_id
        )

    response: dict[str, object]
    try:
        _apply_limits(request.get("resource_limits"))
        mode = request.get("mode")
        if mode == "probe":
            response = _run_probe(request)
        else:
            raise RuntimeError("structured executor protocol is probe-only")
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
    canonical_response = json_dumps(
        response, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    encoded = encode_response(canonical_response).decode("ascii")
    protocol_output.write(EXECUTOR_RESULT_MARKER + encoded + "\n")
    protocol_output.flush()
    return 0 if response.get("worker_ok") is True else 2


def _executor_binding(
    request: dict[str, object],
    *,
    payload: dict[str, object] | None = None,
    option: str = "--execute-request",
) -> tuple[list[str], int, int]:
    binding = request.get("executor")
    if not isinstance(binding, dict) or set(binding) != {
        "schema",
        "sandbox_executable",
        "python_executable",
        "worker_path",
        "sandbox_policy",
        "sandbox_policy_hash",
    }:
        raise RuntimeError("sandbox executor binding is invalid")
    if binding.get("schema") != "SITINA_SANDBOX_EXECUTOR_BINDING_V1":
        raise RuntimeError("sandbox executor binding schema is invalid")
    # The outer profile authorizes the exact literal path, but intentionally
    # does not grant directory traversal over /usr.  The controller capability
    # already resolved and hash-bound this executable before launch.
    sandbox_executable = Path(str(binding.get("sandbox_executable")))
    python_executable = Path(str(binding.get("python_executable")))
    worker_path = Path(str(binding.get("worker_path")))
    policy = binding.get("sandbox_policy")
    policy_hash = binding.get("sandbox_policy_hash")
    if (
        sandbox_executable != Path("/usr/bin/sandbox-exec")
        or os.path.abspath(str(python_executable)) != os.path.abspath(sys.executable)
        or os.path.abspath(str(worker_path)) != os.path.abspath(__file__)
        or not isinstance(policy, str)
        or not isinstance(policy_hash, str)
        or hashlib.sha256(policy.encode("utf-8")).hexdigest() != policy_hash
    ):
        raise RuntimeError("sandbox executor binding identity is invalid")
    limits = request.get("resource_limits")
    if not isinstance(limits, dict):
        raise RuntimeError("sandbox executor resource limits are invalid")
    wall_seconds = limits.get("wall_seconds")
    file_bytes = limits.get("file_bytes")
    if (
        not isinstance(wall_seconds, int)
        or isinstance(wall_seconds, bool)
        or wall_seconds <= 0
        or not isinstance(file_bytes, int)
        or isinstance(file_bytes, bool)
        or file_bytes <= 0
    ):
        raise RuntimeError("sandbox executor bounds are invalid")
    if option not in {"--execute-request", "--execute-item"}:
        raise RuntimeError("sandbox executor option is invalid")
    encoded_request = base64.urlsafe_b64encode(
        _canonical(request if payload is None else payload)
    ).decode("ascii")
    command = [
        str(sandbox_executable),
        "-p",
        policy,
        str(python_executable),
        "-I",
        "-S",
        "-u",
        str(worker_path),
        option,
        encoded_request,
    ]
    return command, wall_seconds, file_bytes


def _run_bounded_executor(
    command: list[str], wall_seconds: int, file_bytes: int
) -> tuple[int, bytes, bytes, bool]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("sandbox executor pipes are unavailable")
    buffers = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
    streams = {process.stdout.fileno(): process.stdout, process.stderr.fileno(): process.stderr}
    deadline = time.monotonic() + wall_seconds
    invalid = False
    while streams:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            invalid = True
            break
        readable, _writable, _exceptional = select.select(
            list(streams.values()), [], [], min(remaining, 0.1)
        )
        if not readable and process.poll() is not None:
            readable = list(streams.values())
        for stream in readable:
            chunk = os.read(stream.fileno(), 64 * 1024)
            if not chunk:
                streams.pop(stream.fileno(), None)
                continue
            buffers[stream.fileno()].extend(chunk)
            if sum(len(value) for value in buffers.values()) > file_bytes:
                invalid = True
                break
        if invalid:
            break
    if invalid:
        process.terminate()
    try:
        return_code = process.wait(timeout=2 if invalid else max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        process.kill()
        return_code = process.wait()
        invalid = True
    stdout = bytes(buffers[process.stdout.fileno()])
    stderr = bytes(buffers[process.stderr.fileno()])
    process.stdout.close()
    process.stderr.close()
    return return_code, stdout, stderr, invalid


def _run_protocol_executor(request: dict[str, object]) -> dict[str, object]:
    """Run the target-free probe protocol inside Seatbelt."""

    if request.get("mode") != "probe":
        raise RuntimeError("structured executor protocol is probe-only")
    command, wall_seconds, file_bytes = _executor_binding(request)
    return_code, stdout, stderr, invalid = _run_bounded_executor(
        command, wall_seconds, file_bytes
    )
    lines = stdout.splitlines()
    payloads = [line[len(EXECUTOR_RESULT_MARKER):] for line in lines if line.startswith(EXECUTOR_RESULT_MARKER.encode("ascii"))]
    if (
        invalid
        or stderr
        or len(lines) != 1
        or len(payloads) != 1
        or return_code not in {0, 2}
    ):
        stderr_detail = stderr.decode("utf-8", errors="replace")[:500]
        stdout_detail = stdout.decode("utf-8", errors="replace")[:500]
        raise RuntimeError(
            "sandbox executor protocol is invalid: "
            f"return_code={return_code}; invalid={invalid}; "
            f"stdout={stdout_detail!r}; stderr={stderr_detail!r}"
        )
    try:
        response = json.loads(base64.urlsafe_b64decode(payloads[0]))
    except Exception as error:
        raise RuntimeError("sandbox executor response is invalid") from error
    if not isinstance(response, dict):
        raise RuntimeError("sandbox executor response must be an object")
    expected_return_code = 0 if response.get("worker_ok") is True else 2
    if return_code != expected_return_code:
        raise RuntimeError("sandbox executor result and exit status differ")
    return response


def _run_observed_item(
    request: dict[str, object],
    *,
    raw: dict[str, object],
    planned: dict[str, object],
    example: dict[str, object],
    read_roots: list[str],
) -> dict[str, object]:
    planned_examples = planned.get("planned_examples")
    if not isinstance(planned_examples, list):
        raise RuntimeError("sandbox item plan is invalid")
    fingerprints = [
        item.get("fingerprint") if isinstance(item, dict) else None
        for item in planned_examples
    ]
    if any(not isinstance(value, str) for value in fingerprints):
        raise RuntimeError("sandbox item fingerprints are invalid")
    item_request: dict[str, object] = {
        "schema": "SITINA_SANDBOX_DOCTEST_ITEM_REQUEST_V1",
        "target": {
            "index": planned["index"],
            "path": raw["path"],
            "source_hash": planned["source_hash"],
        },
        "example_index": example["index"],
        "fingerprints": fingerprints,
        "read_roots": read_roots,
        "resource_limits": request["resource_limits"],
    }
    command, wall_seconds, file_bytes = _executor_binding(
        request, payload=item_request, option="--execute-item"
    )
    return_code, stdout, stderr, invalid = _run_bounded_executor(
        command, wall_seconds, file_bytes
    )
    if invalid:
        raise RuntimeError("sandbox item observation exceeded its bound")
    try:
        observed_stdout = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("sandbox item stdout is not UTF-8") from error
    observation: dict[str, object] = {
        "index": example["index"],
        "fingerprint": example["fingerprint"],
        "attempted": True,
        "stdout": observed_stdout,
        "exception_type": None,
        "exception_text": None,
    }
    if return_code == ITEM_SUCCESS_EXIT:
        if stderr:
            raise RuntimeError("sandbox successful item wrote stderr")
        return observation
    if return_code == ITEM_EXCEPTION_EXIT:
        try:
            exception_text = stderr.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise RuntimeError("sandbox item exception stderr is not UTF-8") from error
        if not exception_text:
            raise RuntimeError("sandbox item exception stderr is empty")
        # The supervisor constructs the structured observation solely from
        # the OS-visible process mapping, exit status, stdout and stderr.  No
        # target-writable marker or JSON result channel is accepted.
        observation["exception_type"] = "observed.sandbox_item_exception"
        observation["exception_text"] = exception_text
        return observation
    stderr_detail = stderr.decode("utf-8", errors="replace")[:500]
    stdout_detail = stdout.decode("utf-8", errors="replace")[:500]
    raise RuntimeError(
        "sandbox item did not reach the trusted observer boundary: "
        f"return_code={return_code}; stdout={stdout_detail!r}; stderr={stderr_detail!r}"
    )


def _run_observed_tests(request: dict[str, object]) -> dict[str, object]:
    """Construct observations outside every target process.

    Each attempted item is mapped to one exact Seatbelt process.  That process
    owns only raw stdout/stderr and an exit status; it never has the signed
    response pipe, the controller key, or a structured observation channel.
    """

    targets, read_roots, plan_hash = _validated_test_targets(request)
    limits = request.get("resource_limits")
    if (
        not isinstance(limits, dict)
        or not isinstance(limits.get("cpu_seconds"), int)
        or isinstance(limits.get("cpu_seconds"), bool)
        or int(limits["cpu_seconds"]) <= 0
    ):
        raise RuntimeError("sandbox aggregate CPU bound is invalid")
    cpu_budget = float(limits["cpu_seconds"])
    initial_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    initial_cpu = float(initial_usage.ru_utime + initial_usage.ru_stime)

    def assert_cpu_budget() -> None:
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        consumed = float(usage.ru_utime + usage.ru_stime) - initial_cpu
        if consumed > cpu_budget:
            raise RuntimeError("sandbox item processes exceeded aggregate CPU bound")

    target_observations: list[dict[str, object]] = []
    for raw, planned in targets:
        planned_examples = planned["planned_examples"]
        assert isinstance(planned_examples, list)
        examples: list[dict[str, object]] = []
        for example in planned_examples:
            assert isinstance(example, dict)
            if _option_flags(example.get("options")) & doctest.SKIP:
                examples.append(
                    {
                        "index": example["index"],
                        "fingerprint": example["fingerprint"],
                        "attempted": False,
                        "stdout": "",
                        "exception_type": None,
                        "exception_text": None,
                    }
                )
                continue
            observed = _run_observed_item(
                request,
                raw=raw,
                planned=planned,
                example=example,
                read_roots=read_roots,
            )
            assert_cpu_budget()
            examples.append(observed)
        target_observations.append(
            {"path": raw["path"], "mode": raw["mode"], "examples": examples}
        )
    response: dict[str, object] = {
        "schema": "SITINA_SANDBOX_TEST_OBSERVATIONS_V1",
        "mode": "tests",
        "test_plan_hash": plan_hash,
        "observations": target_observations,
        "worker_ok": True,
    }
    if (
        not isinstance(limits.get("file_bytes"), int)
        or len(_canonical(response)) > int(limits["file_bytes"])
    ):
        raise RuntimeError("sandbox observed response exceeds its bound")
    return response


def _run_separate_executor(request: dict[str, object]) -> dict[str, object]:
    if request.get("mode") == "tests":
        return _run_observed_tests(request)
    return _run_protocol_executor(request)


def main(argv: list[str] | None = None) -> int:
    # These protocol primitives and the one-use key live only in this signing
    # supervisor.  Target modules run only in per-item Seatbelt processes that
    # have raw stdout/stderr but never this supervisor's signed result channel.
    protocol_input = sys.__stdin__.buffer
    protocol_output = sys.__stdout__
    encode_response = base64.urlsafe_b64encode
    response_digest = hashlib.sha256
    keyed_digest = hmac.digest
    json_dumps = json.dumps
    result_marker = RESULT_MARKER
    proof_marker = PROOF_MARKER
    key_prefix = KEY_MARKER.encode("ascii")
    challenge_prefix = CHALLENGE_MARKER.encode("ascii")

    def canonicalize(value: object) -> bytes:
        return json_dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--request")
    mode.add_argument("--execute-request")
    mode.add_argument("--execute-item")
    arguments = parser.parse_args(argv)
    if arguments.execute_item is not None:
        return _item_executor_main(arguments.execute_item)
    if arguments.execute_request is not None:
        return _executor_main(arguments.execute_request)
    request = _decode_request(arguments.request)
    key_line = protocol_input.readline(256)
    if not key_line.startswith(key_prefix):
        return 3
    encoded_key = key_line[len(key_prefix):].strip()
    if len(encoded_key) != 64 or any(value not in b"0123456789abcdef" for value in encoded_key):
        return 3
    protocol_key = bytes.fromhex(encoded_key.decode("ascii"))
    response: dict[str, object]
    try:
        response = _run_separate_executor(request)
    except BaseException as error:
        response = {
            "worker_ok": False,
            "error_type": type(error).__name__,
            "error": str(error)[:1000],
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
    proof = keyed_digest(
        protocol_key,
        challenge + b"\0" + canonical_response,
        "sha256",
    ).hex()
    protocol_output.write(proof_marker + proof + "\n")
    protocol_output.flush()
    return 0 if response.get("worker_ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
