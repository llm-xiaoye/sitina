from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from types import SimpleNamespace
import threading
import time
from pathlib import Path

import pytest

from sitina.loop import CompletionProposal, InputKind, LoopHost, TaskStatus
from sitina.loop.control import LoopAuthorityError, LoopAuthorityLease, authority_socket_path, send_control_request
from sitina.loop.model import TaskConflict
from sitina.loop.status_reader import read_task_status
from sitina.security.macos_keychain import MemoryKeychainBackend


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _context() -> dict[str, str]:
    return {
        "provider_identity": "fixture-provider:model-a:capacity-1",
        "environment_ref": "fixture-environment:v1",
        "capability_snapshot_id": "fixture-capabilities:v1",
        "software_identity": "fixture-software:3a",
        "config_identity": "fixture-config:v1",
    }


def _payload(workspace: Path, *, task_id: str = "task-3a", **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "command": "submit",
        "task_id": task_id,
        "submission_id": "submission-1",
        "task_kind": "readonly",
        "goal": "inspect the fixture",
        "workspace": str(workspace),
        "check_command": ["python", "-m", "pytest"],
        "provider_profile": "fixture",
        "approve_writes": False,
    }
    value.update(overrides)
    return value


def test_host_admission_is_stable_and_conflicts_before_new_cas(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "input.txt").write_text("before", encoding="utf-8")
    keys = MemoryKeychainBackend()
    with LoopHost(root, keychain_backend=keys, descriptor_context=_context()) as host:
        first = host._handle_command(_payload(workspace))
        assert first["status"] == "accepted"
        assert first["disposition"] == "created"
        first_task = first["task"]
        assert first_task["request_fingerprint"]
        assert first_task["descriptor_ref"]
        before = _tree_hashes(root)
        (workspace / "input.txt").write_text("after", encoding="utf-8")
        second = host._handle_command(_payload(workspace))
        assert second["disposition"] == "existing"
        assert second["task"]["artifact_ref"] == first_task["artifact_ref"]
        assert second["task"]["descriptor_ref"] == first_task["descriptor_ref"]
        assert _tree_hashes(root) == before
        with pytest.raises(TaskConflict):
            host._handle_command(_payload(workspace, goal="a different goal"))
        with pytest.raises(TaskConflict):
            host._handle_command(_payload(workspace, check_command=["python", "-m", "other_check"]))
        with pytest.raises(TaskConflict):
            host._handle_command(_payload(workspace, approve_writes=True))
        with pytest.raises(TaskConflict):
            host._handle_command(_payload(workspace, task_id="other-task"))

    # The task descriptor is the authority for anonymous exact-endpoint reads.
    # These assertions extend admission/conflict coverage; no model is called.
    from dataclasses import replace
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from unittest.mock import patch
    from sitina.extensions.manager import ExtensionManager
    from sitina.extensions.tools import ToolApprovalDenied, ToolCatalog
    from sitina.loop.task_runtime import LoopOperationAdapter, LoopTaskRunner
    from sitina.loop.model import EffectStatus, OperationMode
    from sitina.runners.provider import ProviderToolCall

    hits: list[str] = []

    class Endpoint(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_GET(self) -> None:
            hits.append(self.path)
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/not-scoped")
                self.end_headers()
                return
            body = b"actual anonymous read"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    url = endpoint + "/allowed"
    redirect = endpoint + "/redirect"
    try:
        with LoopHost(tmp_path / "network-state", keychain_backend=MemoryKeychainBackend(),
                      descriptor_context=_context()) as host:
            payload = _payload(
                workspace, task_id="http-read", submission_id="http-submission",
                authorization="cli", network_read_urls=[url, redirect],
            )
            accepted = host._handle_command(payload)
            task = host.backend.get_task("http-read")
            descriptor = host.backend.context_memory.read(
                str(task.descriptor_ref), expected_hash=str(task.descriptor_hash),
            )
            assert descriptor["authorization"]["network_read_urls"] == sorted([url, redirect])
            assert host._handle_command(payload)["disposition"] == "existing"
            with pytest.raises(TaskConflict):
                host._handle_command({**payload, "network_read_urls": [url]})
            with pytest.raises(ValueError):
                host._handle_command({**payload, "task_id": "invalid-scope-task", "submission_id": "invalid-scope", "network_read_urls": "not-an-array"})
            adapter = LoopOperationAdapter(host.backend, "http-read", workspace,
                                           mutation_allowed=False)
            runner = SimpleNamespace(approve_writes=False)
            approval = lambda request: LoopTaskRunner._approve_tool_request(
                runner, adapter, "main", request,
            )
            tool_home = tmp_path / "http-tools"
            tool_home.mkdir()
            catalog = ToolCatalog(
                ExtensionManager(tool_home, global_root=tmp_path / "http-extensions"),
                workspace=workspace, strict_workspace=True, approval_callback=approval,
                _native_network_authority=(host.backend, "http-read"),
            )
            call = ProviderToolCall("authorized-get", "sitina_http_request", {"url": url})
            result = adapter.tool_call(
                "http-test", call, lambda: catalog.execute(call.name, call.arguments),
                permission="network",
            )
            assert result.status == "ok"
            assert result.value["body"] == "actual anonymous read"
            operation = host.backend.get_task("http-read").operations[adapter.operation_ids[-1]]
            assert operation.mode is OperationMode.READ
            assert operation.effect_status is EffectStatus.SUCCEEDED
            assert hits == ["/allowed"]
            for arguments in (
                {"url": endpoint + "/not-scoped"},
                {"url": url, "method": "POST"},
                {"url": url, "body": ""},
                {"url": url, "headers": {"Authorization": "must-not-send"}},
            ):
                with pytest.raises(ToolApprovalDenied):
                    catalog.execute("sitina_http_request", arguments)
            with patch.object(catalog, "approval_callback", side_effect=lambda request:
                              LoopTaskRunner._approve_tool_request(runner, adapter, "reviewer", request)):
                with pytest.raises(ToolApprovalDenied):
                    catalog.execute("sitina_http_request", {"url": url})
            assert hits == ["/allowed"]
            reviewer = LoopOperationAdapter(host.backend, "http-read", workspace,
                                            reviewer_read_only=True)
            with patch.object(catalog, "execute", wraps=catalog.execute) as dispatch:
                denied = reviewer.tool_call(
                    "review-http-test", ProviderToolCall("reviewer-get", "sitina_http_request", {"url": url}),
                    lambda: catalog.execute("sitina_http_request", {"url": url}),
                    permission="network",
                )
                assert denied.status == "error"
                assert dispatch.call_count == 0
            grant_id = catalog.authorize_for_loop("sitina_http_request", {"url": url})
            catalog._network_execution.grant = catalog._network_grants.pop(grant_id)
            try:
                with pytest.raises(ToolApprovalDenied):
                    with catalog._open_authorized_http(
                        redirect, data=None, headers={}, method="GET", timeout=5,
                    ):
                        pytest.fail("changed endpoint reached transport")
                current = host.backend.get_task("http-read")
                with patch.object(host.backend, "get_task",
                                  return_value=replace(current, goal_version=current.goal_version + 1)):
                    from sitina.legacy.fence import LegacyWriteDenied
                    with pytest.raises(LegacyWriteDenied):
                        with catalog._open_authorized_http(
                            url, data=None, headers={}, method="GET", timeout=5,
                        ):
                            pytest.fail("stale task version reached transport")
            finally:
                catalog._network_execution.grant = None
            redirected = catalog.execute("sitina_http_request", {"url": redirect})
            assert redirected.status == "error"
            assert redirected.value["http_status"] == 302
            assert redirected.value["physical_send_state"] == "RESPONSE_RECEIVED"
            assert hits == ["/allowed", "/redirect"]
            from sitina.extensions.tools import ToolRuntimeError
            with patch("sitina.extensions.tools.urllib.request.OpenerDirector.open",
                       side_effect=TimeoutError("dispatch observation unavailable")):
                with pytest.raises(ToolRuntimeError, match="tool effect is unknown"):
                    adapter.tool_call(
                        "http-test", ProviderToolCall("unknown-get", "sitina_http_request", {"url": url}),
                        lambda: catalog.execute("sitina_http_request", {"url": url}),
                        permission="network",
                    )
            unknown = host.backend.get_task("http-read").operations[adapter.operation_ids[-1]]
            assert unknown.effect_status is EffectStatus.UNKNOWN
            assert unknown.unknown_effect is True
            assert hits == ["/allowed", "/redirect"]
            assert (workspace / "input.txt").read_text(encoding="utf-8") == "after"
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        assert not server_thread.is_alive()


def test_concurrent_resubmit_has_one_admission_and_disconnect_does_not_cancel(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    started = threading.Event()
    release = threading.Event()

    def executor(_task_id: str, _task: object) -> None:
        started.set()
        release.wait(5)

    with LoopHost(
        root,
        keychain_backend=MemoryKeychainBackend(),
        descriptor_context=_context(),
        task_executor=executor,
    ) as host:
        payload = _payload(workspace, reviewer_request_timeout_seconds=0.25)
        responses: list[dict[str, object]] = []
        threads = [
            threading.Thread(target=lambda: responses.append(host._handle_command(payload)), daemon=True)
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert sorted(str(item["disposition"]) for item in responses) == ["created", "existing"]
        assert started.wait(2)
        admitted = host.backend.get_task(str(payload["task_id"]))
        descriptor = host.backend.context_memory.read(admitted.descriptor_ref, expected_hash=admitted.descriptor_hash)
        assert descriptor["reviewer_request_timeout_seconds"] == "0.25"
        with pytest.raises(TaskConflict):
            host._handle_command({**payload, "reviewer_request_timeout_seconds": 0.5})
        for invalid in (True, 0, -1, "nan", "inf", []):
            with pytest.raises(ValueError):
                host._handle_command({**payload, "reviewer_request_timeout_seconds": invalid})

        # A client that disconnects before reading its response cannot revoke
        # the host-owned queued execution.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(authority_socket_path(root)))
        client.sendall((__import__("json").dumps(payload) + "\n").encode())
        client.close()
        time.sleep(0.1)
        assert started.is_set()
        release.set()


def test_busy_host_close_keeps_lease_until_executor_drains(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    started = threading.Event()
    release = threading.Event()

    def executor(_task_id: str, _task: object) -> None:
        started.set()
        release.wait(5)

    host = LoopHost(
        root,
        keychain_backend=MemoryKeychainBackend(),
        descriptor_context=_context(),
        task_executor=executor,
    ).start()
    try:
        host._handle_command(_payload(workspace))
        assert started.wait(2)
        host.close()
        with pytest.raises(LoopAuthorityError):
            LoopAuthorityLease(root).acquire()
        blocked = send_control_request(root, _payload(workspace, task_id="other"))
        assert blocked["status"] == "blocked"
        release.set()
        deadline = time.monotonic() + 3
        while host._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.02)
        host.close()
        with LoopAuthorityLease(root):
            pass
    finally:
        release.set()
        host.close()


def test_attach_and_status_are_zero_write_observations(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with LoopHost(root, keychain_backend=MemoryKeychainBackend(), descriptor_context=_context()) as host:
        host._handle_command(_payload(workspace))
        before = _tree_hashes(root)
        attached = host._handle_command({"command": "attach", "task_id": "task-3a"})
        status = send_control_request(root, {"command": "status", "task_id": "task-3a"})
        assert attached["mode"] == "read_only"
        assert status["status"] == "ok"
        assert _tree_hashes(root) == before


def test_offline_status_replays_admission_descriptor_without_writes(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    keys = MemoryKeychainBackend()
    with LoopHost(root, keychain_backend=keys, descriptor_context=_context()) as host:
        host._handle_command(_payload(workspace))
    before = _tree_hashes(root)
    result = read_task_status(root, "task-3a", keychain_backend=keys)
    assert result["task"]["descriptor_ref"]
    assert result["task"]["request_fingerprint"]
    assert _tree_hashes(root) == before


def test_isolated_host_helper_survives_client_disconnect(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source_root = Path(__file__).resolve().parents[1]
    helper = r'''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[3] + "/core")
from sitina.loop.host import LoopHost
from sitina.security.macos_keychain import MemoryKeychainBackend

root = Path(sys.argv[1])
workspace = Path(sys.argv[2])
def executor(_backend, task_id, _task):
    (workspace / "continued.txt").write_text(task_id, encoding="utf-8")
host = LoopHost(root, keychain_backend=MemoryKeychainBackend(),
    descriptor_context={
        "provider_identity": "subprocess-provider",
        "environment_ref": "subprocess-environment",
        "capability_snapshot_id": "subprocess-capabilities",
        "software_identity": "subprocess-software",
        "config_identity": "subprocess-config",
    }, runner_executor=executor).start()
print("READY", flush=True)
try:
    sys.stdin.buffer.read()
finally:
    host.close()
'''
    env = dict(os.environ)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "SITINA_HOME": str(source_root),
        "SITINA_R4_DEV_ROOT": str(source_root),
    })
    process = subprocess.Popen(
        [str(source_root / ".venv-r4/bin/python"), "-B", "-I", "-c", helper, str(root), str(workspace), str(source_root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "READY"
        payload = _payload(workspace, task_id="subprocess-task", submission_id="subprocess-submission")
        payload.update(_context())
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(authority_socket_path(root)))
        client.sendall((json.dumps(payload) + "\n").encode())
        client.close()
        deadline = time.monotonic() + 5
        while not (workspace / "continued.txt").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert (workspace / "continued.txt").read_text(encoding="utf-8") == "subprocess-task"
    finally:
        if process.stdin is not None:
            process.stdin.close()
        process.wait(timeout=5)
        if process.returncode != 0:
            raise AssertionError(process.stderr.read() if process.stderr is not None else "host helper failed")


def test_runner_executor_routes_each_task_to_its_persisted_workspace(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace_a = tmp_path / "workspace-a"
    workspace_b = tmp_path / "workspace-b"
    workspace_a.mkdir()
    workspace_b.mkdir()

    def executor(backend, task_id: str, _task: object) -> None:
        projection = backend.get_task(task_id)
        descriptor = backend.context_memory.read(
            str(projection.descriptor_ref), expected_hash=str(projection.descriptor_hash)
        )
        workspace = Path(str(descriptor["workspace"]["path"]))
        (workspace / "host-routed.txt").write_text(task_id, encoding="utf-8")

    with LoopHost(
        root,
        keychain_backend=MemoryKeychainBackend(),
        descriptor_context=_context(),
        runner_executor=executor,
    ) as host:
        host._handle_command(_payload(workspace_a, task_id="task-a", submission_id="submission-a"))
        host._handle_command(_payload(workspace_b, task_id="task-b", submission_id="submission-b"))
        deadline = time.monotonic() + 3
        while not ((workspace_a / "host-routed.txt").exists() and (workspace_b / "host-routed.txt").exists()):
            if time.monotonic() >= deadline:
                raise AssertionError("host did not execute both descriptor-bound tasks")
            time.sleep(0.02)
        assert (workspace_a / "host-routed.txt").read_text(encoding="utf-8") == "task-a"
        assert (workspace_b / "host-routed.txt").read_text(encoding="utf-8") == "task-b"


def test_executor_error_is_persisted_and_does_not_stop_later_tasks(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    completed: list[str] = []

    def executor(task_id: str, _task: object) -> None:
        if task_id == "task-error":
            raise RuntimeError("fixture executor failed")
        completed.append(task_id)

    with LoopHost(
        root,
        keychain_backend=MemoryKeychainBackend(),
        descriptor_context=_context(),
        task_executor=executor,
    ) as host:
        host._handle_command(_payload(workspace, task_id="task-error", submission_id="error-submission"))
        host._handle_command(_payload(workspace, task_id="task-after", submission_id="after-submission"))
        host._queue.join()
        failed = host.backend.get_task("task-error")
        assert failed.status.value == "STALLED"
        assert failed.waiting_reason and "fixture executor failed" in str(failed.waiting_reason)
        assert completed == ["task-after"]


def test_cli_host_wiring_rebuilds_runner_from_descriptor(monkeypatch, tmp_path: Path) -> None:
    import argparse
    import sitina.cli as cli
    import sitina.loop.development as development
    import sitina.loop.host as host_module
    import sitina.loop.task_runtime as runtime_module

    source_root = tmp_path / "source"
    config_root = source_root / "config"
    sitina_root = source_root / "core" / "sitina"
    config_root.mkdir(parents=True)
    source_config = Path(__file__).resolve().parents[1] / "config"
    for policy_name in ("orchestration_policy.json", "observability_policy.json"):
        (config_root / policy_name).write_bytes((source_config / policy_name).read_bytes())
    sitina_root.mkdir(parents=True)
    (config_root / "loop_context_capacity.json").write_text(
        '{"entries":[{"profile":"fixture","endpoint":"fixture://endpoint","model":"fixture-model",'
        '"wire_protocol":"fixture-wire","context_capacity_tokens":1000}]}',
        encoding="utf-8",
    )
    (sitina_root / "task_runtime.py").write_text("fixture", encoding="utf-8")
    state_root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    boundary = development.DevelopmentBoundary(
        source_root=source_root,
        interpreter=source_root / ".venv-r4" / "bin" / "python",
        config_root=config_root,
        state_root=state_root,
        business_workspace=workspace,
        runtime_root=source_root,
        credential_references=(),
        forbidden_write_roots=(),
    )
    captured: dict[str, object] = {}

    def validate(**kwargs):
        captured.setdefault("validations", []).append(kwargs)
        return development.DevelopmentBoundary(
            source_root=source_root,
            interpreter=source_root / ".venv-r4" / "bin" / "python",
            config_root=config_root,
            state_root=state_root,
            business_workspace=Path(kwargs["business_workspace"]),
            runtime_root=source_root,
            credential_references=(),
            forbidden_write_roots=(),
        )

    class FakeRunner:
        def __init__(self, runner_boundary, *, provider_profile, approve_writes, reviewer_request_timeout_seconds=None):
            captured["runner_boundary"] = runner_boundary
            captured["provider_profile"] = provider_profile
            captured["approve_writes"] = approve_writes
            captured["reviewer_request_timeout_seconds"] = reviewer_request_timeout_seconds

        def run_existing(self, backend, **kwargs):
            captured["run_existing"] = kwargs

    class FakeBackend:
        class Memory:
            def read(self, _ref, *, expected_hash):
                return {
                    "workspace": {"path": str(workspace / "task-specific")},
                    "provider_profile": "fixture",
                    "reviewer_request_timeout_seconds": "0.25",
                    "authorization": {"approve_writes": True},
                    "acceptance": {"check_command": ["fixture-check"]},
                }

        context_memory = Memory()

        def get_task(self, _task_id):
            return SimpleNamespace(descriptor_ref="descriptor", descriptor_hash="hash", task_kind="readonly")

    class FakeHost:
        def __init__(self, _state_root, **kwargs):
            captured["host_kwargs"] = kwargs
            self.runner_executor = kwargs["runner_executor"]

        def start(self):
            self.runner_executor(FakeBackend(), "task-cli", {})
            return self

        def serve_forever(self):
            raise KeyboardInterrupt

        def begin_drain(self):
            captured["drained"] = True

        def wait_for_quiescence(self):
            captured["waited"] = True

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(development.DevelopmentBoundary, "validate", staticmethod(validate))
    monkeypatch.setattr(development, "validate_runtime_boundary", validate)
    monkeypatch.setattr(host_module, "LoopHost", FakeHost)
    monkeypatch.setattr(runtime_module, "LoopTaskRunner", FakeRunner)
    args = argparse.Namespace(
        loop_host_cmd="serve",
        state_root=str(state_root),
        workspace=str(workspace),
        provider_profile="fixture",
        approve_writes=False,
    )
    assert cli.cmd_loop_host(args) == 130
    assert captured["run_existing"]["check_command"] == ("fixture-check",)
    assert captured["approve_writes"] is True
    assert captured["runner_boundary"].business_workspace == workspace / "task-specific"
    assert captured["drained"] and captured["waited"] and captured["closed"]
    assert captured["reviewer_request_timeout_seconds"] == "0.25"


def test_terminal_duplicate_attach_and_offline_status_replay_original_result(tmp_path: Path) -> None:
    root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    keys = MemoryKeychainBackend()
    request = _payload(workspace, task_id="terminal-task", submission_id="terminal-submission")
    with LoopHost(root, keychain_backend=keys, descriptor_context=_context()) as host:
        first = host._handle_command(request)
        task = host.backend.get_task("terminal-task")
        host.backend.accept_input("terminal-task", input_id="cancel-terminal", kind=InputKind.CANCEL, body="cancel")
        task = host.backend.handle_next_input("terminal-task")
        proposal = CompletionProposal(
            proposal_id="terminal-proposal",
            terminal_status=TaskStatus.CANCELLED,
            expected_task_revision=task.task_revision,
            expected_run_instance_id=task.run_instance_id,
            expected_execution_epoch=task.execution_epoch,
            expected_goal_version=task.goal_version,
            expected_acceptance_version=task.acceptance_version,
            expected_received_input_seq=task.received_input_seq,
            expected_handled_input_seq=task.handled_input_seq,
            artifact_ref=task.artifact_ref,
            final_result={"answer": "original"},
        )
        host.backend.propose_terminal("terminal-task", proposal)
        before = _tree_hashes(root)
        duplicate = host._handle_command(request)
        attached = host._handle_command({"command": "attach", "task_id": "terminal-task"})
        assert duplicate["disposition"] == "existing"
        assert duplicate["task"]["status"] == TaskStatus.CANCELLED.value
        assert attached["task"]["terminal_result"]["final_result"]["answer"] == "original"
        assert _tree_hashes(root) == before
    offline = read_task_status(root, "terminal-task", keychain_backend=keys)
    assert offline["task"]["status"] == TaskStatus.CANCELLED.value
    assert offline["task"]["terminal_result"]["final_result"]["answer"] == "original"
    assert offline["task"]["terminal_result_ref"]
