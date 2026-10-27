"""Provider descriptions and authorization for the task execution contract."""
from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from sitina.execution import EXECUTION_TOOLS, TASK_EXECUTION_CONTRACT, ExecutionDenied

_FILE_TOOLS = frozenset({"sitina_read_file", "sitina_read_lines", "sitina_list_directory", "sitina_glob",
    "sitina_grep", "sitina_write_file", "sitina_edit_file", "sitina_apply_patch",
    "sitina_task_diff", "sitina_delete_file", "sitina_rename_file"})
_WORKSPACE_TOOLS = frozenset({"sitina_git_status", "sitina_git_diff", "sitina_worktree_create",
    "sitina_worktree_integrate", "sitina_worktree_verify", "sitina_worktree_cleanup"})


def bind_task_execution_catalog(catalog: Any, policy_provider: Callable[[], Any]) -> None:
    from sitina.extensions.tools import ToolDefinition
    catalog._task_execution_policy_provider = policy_provider
    common = {
        "cwd": {"type": "string"}, "environment": {"type": "object", "additionalProperties": {"type": "string"}},
        "timeout_seconds": {"type": "number"},
        "yield_time_ms": {"type": "number", "minimum": 0, "maximum": 10000,
                          "description": "Milliseconds to wait before returning the original execution; 0..10000."},
        "pty": {"type": "boolean"}, "rows": {"type": "integer"}, "columns": {"type": "integer"},
        "network_urls": {"type": "array", "items": {"type": "string"}, "description":
            "Exact anonymous read destinations. With full public-read permission, official registry roots "
            "https://pypi.org/simple/ and https://registry.npmjs.org/ also cover package metadata. "
            "Archives and metadata sidecars require URLs advertised by verified registry metadata."},
        "git_urls": {"type": "array", "items": {"type": "string"}, "description":
            "Anonymous HTTPS Git repository roots for clone, fetch and ls-remote. Declare the repository "
            "here to authorize its read-only smart-HTTP endpoints. network_urls covers exact HTTP reads "
            "and registry metadata; it does not nominate a Git repository. Credentials, push and other "
            "remote writes remain denied."},
        "write_paths": {"type": "array", "items": {"type": "string"}, "description":
            "Authorized business paths this execution may write, absolute or task-workspace-relative. "
            "Select the actual task-specific output directories, not a shared parent such as /tmp "
            "or the user's home: existing files under selected directories are snapshotted for recovery. "
            "Omitting this field inherits and reserves the current authorized write roots for the "
            "execution lifetime. Use [] when no business-file writes are needed, including read-only "
            "clients or services that only read their inputs; this permits concurrent read-only work "
            "without reserving the whole workspace. It does not change cwd, read roots or network authority."},
        "verification_inputs": {"type": "array", "items": {"type": "string"}, "description":
            "For an execution used to verify a requirement, list the relevant project input files "
            "(source, tests and configuration). Their real versions are bound before and after execution. "
            "Do not list generated logs or outputs as inputs. Completion claims need a successful "
            "native receipt with unchanged declared inputs; this list is scope, not a claim of passing."},
        "listen_ports": {"type": "array", "items": {"type": "integer"}},
    }
    def unavailable(_arguments):
        raise ExecutionDenied("this capability requires the native task operation runtime")
    def add(name, description, properties, required=(), permission="shell"):
        current = catalog._tools.get(name)
        handler = current.handler if current else unavailable
        catalog._tools[name] = ToolDefinition(name, description, catalog._object_schema(properties, required),
                                             permission, "sitina", handler)
    add("sitina_shell",
        "Execute finite Shell commands; task completion waits for their original process to exit. "
        "For a service that must remain available after delivery, use sitina_process_start with keep=true. "
        "Execute original Shell text with a non-login system Shell in the task scope. Pipes, redirects, &&, "
        "scripts, installers, tests and builds are supported. The command can modify authorized task files. "
        "Supply exact public network_urls, supported official dependency registry roots, or git_urls when fetching; "
        "all descendants share file/network restrictions. "
        "Declare writable paths to coordinate parallel work; omit for the current task write scope. Results may "
        "remain RUNNING: observe/control the returned process_id and never launch a duplicate. Shell exit status "
        "has the actual Shell meaning; a successful pipeline exit does not prove every stage succeeded.",
        {**common, "command": {"type": "string"}, "shell": {"type": "string", "enum": ["/bin/zsh", "/bin/bash", "/bin/sh"]}}, ("command",))
    add("sitina_exec",
        "Execute a finite program; task completion waits for its original process to exit. "
        "For a service that must remain available after delivery, use sitina_process_start with keep=true. "
        "Supply independent executable and argv arguments, without a Shell or whitespace splitting. "
        "Use the project interpreter/toolchain; normal programs, pytest/Jest/builds and dependency tools are allowed. "
        "Returns the original process_id, ordered persisted output and real state. RUNNING/UNKNOWN must not be resent. "
        "Nominate exact public read URLs, supported official dependency registry roots or public Git repositories. "
        "Authentication and remote writes are denied.",
        {**common, "executable": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}}}, ("executable",))
    add("sitina_process_start",
        "Start a task-owned persistent process or terminal. Use keep=true for a service that must remain "
        "available after delivery; it retains ownership and stop controls without waiting for the service to exit. "
        "Supply command as exact argv, a Shell string, or "
        "terminal=true for a persistent non-login PTY Shell. cd/export/activation affect that terminal only. "
        "Reserve explicit listen_ports and then register the owned service before testing it. "
        "Observe the returned original process_id; task pause stops new actions and leaves launched commands running.",
        {**common, "command": {"type": ["array", "string"], "items": {"type": "string"}},
         "executable": {"type": "string"}, "argv": {"type": "array", "items": {"type": "string"}},
         "terminal": {"type": "boolean"}, "keep": {"type": "boolean"}})
    identity = {"process_id": {"type": "string"}}
    add("sitina_process_status", "Observe the original task-owned execution. UNKNOWN is unresolved, never stopped.", identity, ("process_id",), "read")
    add("sitina_process_log", "Read the next bounded original output page using per-stream byte offsets. "
        "Pipe streams are distinct; PTY is one combined stream. Preserve each next_offset on reconnection. "
        "The complete output is retained even when this page is bounded.",
        {**identity, "offsets": {"type": "object", "additionalProperties": {"type": "integer"}},
         "tail_lines": {"type": "integer"}}, ("process_id",), "read")
    add("sitina_process_input", "Send UTF-8 input to the original task process. The user has exclusive input during "
        "takeover; a denied input must wait for the user to return the terminal. Input is not a new program execution.",
        {**identity, "data": {"type": "string"}}, ("process_id", "data"))
    add("sitina_process_interrupt", "Request SIGINT on this original command and its process group; inspect the actual resulting state.", identity, ("process_id",))
    add("sitina_process_stop", "Request stop and cleanup of the owned command. Report acknowledged actual state; UNKNOWN retains responsibility.", identity, ("process_id",))
    add("sitina_process_resize", "Resize the original PTY, without creating a new session.",
        {**identity, "rows": {"type": "integer"}, "columns": {"type": "integer"}}, ("process_id", "rows", "columns"))
    add("sitina_register_service", "Register a running owned service at a port reserved in that process start. "
        "Only registered task services receive local test writes; localhost alone grants no access.",
        {**identity, "port": {"type": "integer"}}, ("process_id", "port"))
    add("sitina_task_skills", "List this task's pinned Skill summaries and versions; load a relevant Skill's "
        "instructions on demand. Use normal task execution tools for its scripts and resources. Global changes "
        "do not replace this task's versions. Only the parent may replace this task's exclusion list.",
        {"action": {"type": "string", "enum": ["list", "load", "exclude"]},
         "name": {"type": "string"}, "exclusions": {"type": "array", "items": {"type": "string"}}}, (), "read")
    add("sitina_manage_skills", "Import public Skills explicitly requested by the user. First inspect the "
        "original user-provided HTTPS source, then install an exact selected_source from the returned choices. "
        "Use status with the original management_request_id when the outcome is unknown; never repeat an "
        "unknown installation. Repeating install replays the original result, not a new download. Only when "
        "recovery.can_retry is true, use retry with request_id equal to that exact management_request_id "
        "and the same source/selected_source/enable. At most three attempts are allowed; repeating the same "
        "retry remains idempotent. Otherwise report the blocker and retain successful results. "
        "This uses the same global store as the Skills page. Existing task versions "
        "stay pinned; new tasks use enabled installed versions. Only the writable main task may manage Skills.",
        {"action": {"type": "string", "enum": ["inspect", "install", "retry", "status"]},
         "source": {"type": "string"}, "selected_source": {"type": "string"},
         "request_id": {"type": "string"}, "enable": {"type": "boolean"}}, ("action",), "write")
    add("sitina_task_environment", "Inspect or explicitly change task-shared environment/scope for future commands. "
        "A terminal export/cd does not change this layer. Do not copy Provider credentials. "
        "In current-user local-access mode the main agent does not need grant_paths just to access "
        "a local path; read/write roots track snapshots and coordinated resources. grant_paths registers "
        "additional task-relevant roots for that tracking and requires a concrete purpose. "
        "Children follow their delegated resources and request changes from their parent.",
        {"action": {"type": "string", "enum": ["inspect", "set", "unset", "grant_paths"]},
         "values": {"type": "object", "additionalProperties": {"type": "string"}},
         "keys": {"type": "array", "items": {"type": "string"}},
         "read_roots": {"type": "array", "items": {"type": "string"}},
         "write_roots": {"type": "array", "items": {"type": "string"}}, "purpose": {"type": "string"}}, (), "write")


def authorize_task_tool(catalog: Any, definition: Any, arguments: Mapping[str, Any]) -> str | None:
    """Task authority replaces filename/command-name risk guesses on this surface."""
    from sitina.extensions.tools import ApprovalRequest, ToolApprovalDenied
    provider = getattr(catalog, "_task_execution_policy_provider", None)
    if provider is None or definition.name not in (_FILE_TOOLS | EXECUTION_TOOLS | _WORKSPACE_TOOLS):
        return None
    catalog._last_authorization_scan = None
    policy = provider()
    name = definition.name
    try:
        if name in _FILE_TOOLS and name != "sitina_glob":
            raw = str(arguments.get("path") or catalog.workspace)
            path = Path(raw).expanduser()
            if not path.is_absolute():
                path = catalog.workspace / path
            canonical = policy.check_path(path, write=definition.permission != "read")
            write_targets = [canonical] if definition.permission != "read" else []
            if name == "sitina_rename_file":
                destination = Path(str(arguments.get("destination") or "")).expanduser()
                if not destination.is_absolute():
                    destination = catalog.workspace / destination
                write_targets.append(policy.check_path(destination, write=True))
            guard = getattr(catalog, "_task_execution_resource_guard", None)
            if write_targets and guard is not None:
                guard(tuple(write_targets))
        elif name == "sitina_glob":
            pattern = str(arguments.get("pattern") or "")
            if not pattern:
                raise ExecutionDenied("glob pattern is empty")
            prefix = pattern
            for mark in ("*", "?", "["):
                prefix = prefix.split(mark, 1)[0]
            path = Path(prefix).expanduser()
            if not path.is_absolute():
                path = catalog.workspace / path
            policy.check_path(path if path.is_dir() else path.parent)
        elif name in _WORKSPACE_TOOLS:
            authorizer = getattr(catalog, "_task_workspace_authorizer", None)
            if authorizer is None:
                raise ExecutionDenied("native workspace authority is not bound")
            authorizer(name, arguments)
        elif name in {"sitina_shell", "sitina_exec", "sitina_process_start"}:
            cwd = Path(str(arguments.get("cwd") or catalog.workspace)).expanduser()
            policy.check_cwd(cwd if cwd.is_absolute() else catalog.workspace / cwd)
    except (OSError, ValueError) as error:
        raise ToolApprovalDenied(str(error), authorization_ref="task-scope:" + policy.task_id,
                                 denial_kind=getattr(error, "denial_kind", "AUTHORIZATION")) from error
    reference = "task-scope:" + policy.task_id
    if definition.permission != "read":
        request = ApprovalRequest("approval-" + uuid.uuid4().hex, name, definition.permission, "medium",
                                  definition.origin, dict(arguments), "task-authorized execution capability")
        if catalog.approval_callback is None or not catalog.approval_callback(request):
            raise ToolApprovalDenied("task permission is unavailable for " + name, authorization_ref=request.request_id)
        reference = request.request_id
    return reference

class TaskFileExecutor:
    """Versioned native file effects with the task's recovery baseline and scope."""

    def __init__(self, manager, policy_provider, resource_guard):
        self.manager = manager
        self.policy_provider = policy_provider
        self.resource_guard = resource_guard
        self._issued = {}
        self.risk_scanner = None

    @staticmethod
    def _raw_version(value):
        if value is None:
            return None
        if not isinstance(value, str):
            raise ExecutionDenied("expected file version must be a SHA-256 or null")
        raw = value.removeprefix("sha256:")
        if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
            raise ExecutionDenied("expected file version is not a SHA-256")
        return raw

    def _mint_direct_capability(self, *, run_id, authorization_ref, target_repo,
                                allowed_roots, purpose, allowed_targets=None):
        from types import SimpleNamespace
        capability = SimpleNamespace(run_id=run_id, authorization_ref=authorization_ref,
                                     allowed_targets=tuple(allowed_targets or ()))
        self._issued[id(capability)] = capability
        return capability

    def _check(self, capability, run_id, path):
        if self._issued.get(id(capability)) is not capability or capability.run_id != run_id:
            raise ExecutionDenied("native file execution capability is not current")
        canonical = self.policy_provider().check_path(Path(path), write=True)
        if capability.allowed_targets and str(canonical) not in {
                str(Path(p).expanduser().resolve()) for p in capability.allowed_targets}:
            raise ExecutionDenied("file target differs from the prepared operation")
        self.resource_guard((canonical,))
        return canonical

    @staticmethod
    def _receipt(value, *, before=None, after=None):
        return {**value, "status": "ok",
                "before_hash": None if before is None else "sha256:" + before,
                "after_hash": None if after is None else "sha256:" + after,
                "patch_id": hashlib.sha256(repr(value).encode()).hexdigest(),
                "native_write_observed": True, "worker_observed": False}

    def write_direct(self, *, target, content, run_id, capability,
                     expected_before_hash=None, verified_source_paths=()):
        path = self._check(capability, run_id, target)
        before = self._raw_version(expected_before_hash)
        result = self.manager.write_file(path, content, expected_version=before)
        return self._receipt(result, before=result["before_version"], after=result["version"])

    def execute(self, *, operation, run_id, target, capability, destination=None,
                expected_before_hash=None, **_kwargs):
        path = self._check(capability, run_id, target)
        before = self._raw_version(expected_before_hash)
        if operation == "delete":
            result = self.manager.delete_file(path, expected_version=before)
            return self._receipt(result, before=result["before_version"], after=None)
        if operation == "move" and destination is not None:
            target_path = self._check(capability, run_id, destination)
            result = self.manager.move_file(path, target_path, expected_version=before)
            return self._receipt(result, before=before, after=None)
        raise ExecutionDenied("unsupported native file operation")


def bind_task_workspace_catalog(catalog, manager, policy_provider, resource_guard, *, verification_reader=None):
    from sitina.extensions.tools import ToolDefinition
    catalog._task_execution_resource_guard = resource_guard
    catalog._write_executor = TaskFileExecutor(manager, policy_provider, resource_guard)
    def read_lines(value):
        path = policy_provider().check_path(Path(value["path"]))
        expected = value.get("expected_version")
        if expected is not None:
            expected = TaskFileExecutor._raw_version(expected)
        result = manager.read_lines(path, value["start_line"], value["end_line"],
                                    expected_version=expected)
        version = result.get("version")
        if isinstance(version, str):
            result["version"] = "sha256:" + version
            catalog._expected_before_hashes[str(path)] = result["version"]
        return result
    def task_diff(value):
        path = policy_provider().check_path(Path(value["path"]))
        return manager.task_diff(path)
    catalog._tools["sitina_read_lines"] = ToolDefinition(
        "sitina_read_lines", "Read an exact source line range with its full-file version, actual range and continuation. "
        "Preserve version for edits; a stale expected_version is rejected.",
        catalog._object_schema({"path": {"type": "string"}, "start_line": {"type": "integer"},
                                "end_line": {"type": "integer"}, "expected_version": {"type": "string"}},
                               ("path", "start_line", "end_line")), "read", "sitina", read_lines)
    catalog._tools["sitina_task_diff"] = ToolDefinition(
        "sitina_task_diff", "Show one file's changes relative to this task's original recovery baseline.",
        catalog._object_schema({"path": {"type": "string"}}, ("path",)), "read", "sitina", task_diff)
    workspace_tools = TaskWorkspaceTools(catalog, manager, policy_provider, resource_guard, verification_reader)
    workspace_tools.bind()


class TaskGitExecutor:
    """Fixed local Git argv, inside the existing task's real macOS sandbox."""

    _COMMANDS = frozenset({"rev-parse", "ls-files", "ls-tree", "diff", "check-ref-format", "worktree",
                           "read-tree", "update-index", "apply", "merge-file", "cat-file"})

    def __init__(self, manager, policy_provider):
        self.manager, self.policy_provider = manager, policy_provider
        self.history = []

    def __call__(self, *, argv, cwd, environment, input_bytes):
        prefix = ["/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(cwd)]
        if list(argv[:len(prefix)]) != prefix or len(argv) <= len(prefix):
            raise ExecutionDenied("Git argv does not match the fixed native invocation contract")
        command = list(argv[len(prefix):])
        if command[0] not in self._COMMANDS:
            raise ExecutionDenied("native Git supports local status/diff/worktree operations only")
        policy = self.policy_provider()
        policy.check_path(Path(cwd), write=command[0] in {"worktree", "read-tree", "update-index", "apply"})
        merge_reads = []
        if command[0] == "merge-file":
            if command[:3] != ["merge-file", "-p", "--diff3"] or len(command) != 6:
                raise ExecutionDenied("merge input shape is not the native three-way contract")
            artifact_members = self.manager.artifact_root / "workspace-management"
            for filename, expected_name in zip(command[3:], ("current", "base", "result"), strict=True):
                path = Path(filename)
                if path.name != expected_name or not path.parent.resolve().is_relative_to(artifact_members) or not stat.S_ISREG(path.lstat().st_mode):
                    raise ExecutionDenied("merge input is not an exact task-owned baseline member")
                merge_reads.append(path.resolve())
        with tempfile.TemporaryDirectory(prefix="sitina-git-") as temporary:
            scratch = Path(temporary).resolve()
            (scratch / "home").mkdir()
            (scratch / "tmp").mkdir()
            profile = policy.sandbox_profile(runtime_roots=(scratch,), gateway_port=None)
            if merge_reads:
                profile += "(allow file-read* " + " ".join("(literal " + json.dumps(str(path)) + ")" for path in merge_reads) + ")\n"
            passed = dict(environment)
            passed.update({"HOME": str(scratch / "home"), "TMPDIR": str(scratch / "tmp"), "GIT_OPTIONAL_LOCKS": "0"})
            try:
                result = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, *argv], cwd=cwd,
                    env=passed, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as error:
                from sitina.task_workspace import WorkspaceError
                stdout, stderr = getattr(error, "stdout", None) or b"", getattr(error, "stderr", None) or b""
                timed_out = isinstance(error, subprocess.TimeoutExpired)
                evidence = self.manager.artifact_root / "workspace-management" / "git-errors" / uuid.uuid4().hex
                descriptor = {"argv": list(argv), "cwd": str(cwd), "passed_environment": passed,
                    "method_status": "TIMED_OUT" if timed_out else "LAUNCH_FAILED", "exit_code": None,
                    "child_streams_observed": timed_out, "exception_type": type(error).__name__, "exception": str(error)}
                encoded = (json.dumps(descriptor, sort_keys=True, indent=2) + "\n").encode()
                evidence.mkdir(parents=True)
                (evidence / "child-stdout.bin").write_bytes(stdout)
                (evidence / "child-stderr.bin").write_bytes(stderr)
                (evidence / "command.json").write_bytes(encoded)
                self.history.append({"argv": list(argv), "cwd": str(cwd), "exit_code": None,
                    "method_status": descriptor["method_status"], "sandboxed": timed_out,
                    "sandbox_profile_sha256": hashlib.sha256(profile.encode()).hexdigest(), "network": "DENIED",
                    "raw_evidence_ref": str(evidence)})
                raise WorkspaceError("GIT_METHOD_FAILED", str(error), evidence_path=str(evidence),
                    method_status=descriptor["method_status"], exit_code=None) from error
            self.history.append({"argv": list(argv), "cwd": str(cwd), "exit_code": result.returncode,
                "sandbox_profile_sha256": hashlib.sha256(profile.encode()).hexdigest(), "network": "DENIED",
                "child_stdout_bytes": len(result.stdout), "child_stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "child_stderr_bytes": len(result.stderr), "child_stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
            return result


class TaskWorkspaceTools:
    """Native tools on the catalog's existing operation and receipt surface."""

    def __init__(self, catalog, manager, policy_provider, resource_guard, verification_reader):
        self.catalog, self.manager = catalog, manager
        self.policy_provider, self.resource_guard = policy_provider, resource_guard
        self.verification_reader = verification_reader
        self.git = TaskGitExecutor(manager, policy_provider)
        manager.bind_git_runner(self.git)

    def _path(self, raw):
        path = Path(raw).expanduser()
        return path if path.is_absolute() else self.manager.workspace / path

    def _git_context(self, policy, *, write=False):
        root = self.manager.workspace
        while True:
            policy.check_path(root)
            entry = root / ".git"
            if entry.is_dir():
                git_dir = entry.resolve()
                break
            if entry.is_file():
                policy.check_path(entry)
                if entry.stat().st_size > 4096:
                    raise ExecutionDenied("Git directory pointer is oversized")
                raw = entry.read_text(encoding="utf-8").strip()
                if not raw.startswith("gitdir: ") or "\n" in raw:
                    raise ExecutionDenied("Git directory pointer is malformed")
                git_dir = (root / raw.removeprefix("gitdir: ")).resolve()
                break
            if entry.exists() or root.parent == root:
                raise ExecutionDenied("workspace is not a supported local Git repository")
            root = root.parent
        policy.check_path(git_dir, write=write)
        common = git_dir
        pointer = git_dir / "commondir"
        if pointer.exists():
            policy.check_path(pointer)
            if not pointer.is_file() or pointer.stat().st_size > 4096:
                raise ExecutionDenied("Git common-directory pointer is malformed")
            common = (git_dir / pointer.read_text(encoding="utf-8").strip()).resolve()
            policy.check_path(common, write=write)
        return root, git_dir, common

    def authorize(self, name, value):
        from sitina.task_workspace import WorkspaceError
        policy = self.policy_provider()
        try:
            mutates_git = name in {"sitina_worktree_create", "sitina_worktree_cleanup"}
            _, git_dir, common = self._git_context(policy, write=mutates_git)
            targets = []
            if name == "sitina_git_diff":
                policy.check_path(self._path(value["path"]))
            elif name == "sitina_worktree_create":
                targets = [policy.check_path(self.manager.workspace, write=True), policy.check_path(self._path(value["path"]), write=True), git_dir, common]
                for raw in value.get("paths", []):
                    policy.check_path(self._path(raw))
            elif name in {"sitina_worktree_integrate", "sitina_worktree_verify", "sitina_worktree_cleanup"}:
                info = self.manager.describe_worktree(self._path(value["path"]))
                worktree = policy.check_path(Path(info["path"]), write=name != "sitina_worktree_verify")
                if name == "sitina_worktree_integrate":
                    targets = [worktree, policy.check_path(self.manager.workspace, write=True)]
                elif name == "sitina_worktree_cleanup":
                    targets = [worktree, git_dir, common]
                if name == "sitina_worktree_verify" and self.verification_reader is None:
                    raise ExecutionDenied("trusted native check evidence is unavailable")
            if targets:
                self.resource_guard(tuple(targets))
        except WorkspaceError as error:
            raise ExecutionDenied(str(error)) from error

    def _finish(self, value, start):
        history = self.git.history[start:]
        if not history:
            return value
        document = {"schema": "SITINA_NATIVE_GIT_EVIDENCE_V1", "task_id": self.manager.task_id, "invocations": history}
        raw = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
        root = self.manager.artifact_root / "workspace-management" / "git-evidence"
        root.mkdir(exist_ok=True)
        path = root / (uuid.uuid4().hex + ".json")
        with path.open("xb") as stream:
            stream.write(raw)
        return {**value, "git_execution": {"sandboxed": all(item.get("sandboxed", True) for item in history), "network": "DENIED", "invocation_count": len(history),
                "evidence_ref": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}}

    def _verify(self, value):
        path = self._path(value["path"])
        ids = value["check_process_ids"]
        if not ids or len(ids) != len(set(ids)):
            raise ExecutionDenied("verification requires distinct existing native check process IDs")
        evidence = []
        errors = []
        for process_id in ids:
            try:
                observed = self.verification_reader(process_id)
            except (OSError, ValueError, KeyError) as error:
                errors.append({"process_id": process_id, "reason": "CHECK_EVIDENCE_UNAVAILABLE", "error": str(error)})
                continue
            if not isinstance(observed, Mapping):
                errors.append({"process_id": process_id, "reason": "CHECK_EVIDENCE_NOT_OBJECT"})
                continue
            valid = (observed.get("execution_contract") == TASK_EXECUTION_CONTRACT
                and observed.get("process_id") == process_id and observed.get("task_id") == self.manager.task_id
                and observed.get("state") == "STOPPED" and observed.get("effect_settled") is True
                and observed.get("completion_status") == "COMPLETED" and observed.get("trusted_completion") is True
                and observed.get("execution_started") is True and observed.get("program_status") == "PASS"
                and type(observed.get("exit_code")) is int and observed["exit_code"] == 0
                and isinstance(observed.get("manifest_hash"), str) and bool(observed["manifest_hash"])
                and isinstance(observed.get("completion_hash"), str) and bool(observed["completion_hash"]))
            binding = observed.get("workspace_check_binding")
            if not valid or not isinstance(binding, Mapping) or binding.get("schema") != "SITINA_WORKSPACE_CHECK_BINDING_V1" or binding.get("task_id") != self.manager.task_id or not isinstance(binding.get("bindings"), list):
                errors.append({"process_id": process_id, "reason": "CHECK_NOT_COMPLETED_OR_UNBOUND"})
                continue
            if binding.get("cwd") != observed.get("cwd"):
                errors.append({"process_id": process_id, "reason": "CHECK_CWD_BINDING_MISMATCH"})
                continue
            candidates = [item for item in binding["bindings"] if isinstance(item, Mapping) and item.get("worktree_path") == str(path.resolve())]
            if len(candidates) != 1:
                errors.append({"process_id": process_id, "reason": "CHECK_WORKTREE_BINDING_MISSING"})
                continue
            match = self.manager.match_check_binding(path, candidates[0])
            if not match["matched"]:
                errors.append({"process_id": process_id, "reason": match["reason"]})
                continue
            evidence.append({"process_id": process_id, "manifest_hash": observed["manifest_hash"],
                "completion_hash": observed["completion_hash"], "cwd": observed["cwd"],
                "exit_code": observed["exit_code"], "role": match["role"], "members_sha256": match["members_sha256"], "member_count": match["member_count"]})
        result = self.manager.verify_worktree(path, checks={"accepted": not errors and len(evidence) == len(ids),
            "scope": "NATIVE_COMMAND_EXIT_AND_CURRENT_FILE_VERSIONS", "evidence": evidence, "errors": errors})
        return {**result, "status": "ok" if result["status"] == "verified" else "blocked", "worktree_status": result["status"]}

    def invoke(self, name, value):
        from sitina.extensions.tools import ToolApprovalDenied
        from sitina.task_workspace import WorkspaceError
        try:
            self.authorize(name, value)
        except (OSError, ValueError) as error:
            raise ToolApprovalDenied(str(error),
                                     denial_kind=getattr(error, "denial_kind", "AUTHORIZATION")) from error
        start = len(self.git.history)
        try:
            if name == "sitina_git_status":
                result = self.manager.git_status(offset=value.get("offset", 0), limit=value.get("limit", 100))
            elif name == "sitina_git_diff":
                result = self.manager.git_diff(self._path(value["path"]), staged=value.get("staged", False), max_bytes=value.get("max_bytes", 16000))
            elif name == "sitina_worktree_create":
                record = self.manager.create_worktree(self._path(value["path"]), branch=value.get("branch"), paths=[self._path(raw) for raw in value.get("paths", [])])
                result = {"status": "ok", "worktree_status": record["status"], "path": record["path"], "workspace_path": record["workspace_path"],
                    "branch": record["branch"], "source_git": record["source_git"], "source_index_state": record["source_index_state"],
                    "member_count": len(record["origin"]), "dependency_readiness": record["dependency_readiness"]}
            elif name == "sitina_worktree_integrate":
                result = self.manager.integrate_worktree(self._path(value["path"]), paths=[Path(raw) for raw in value.get("paths", [])])
                result = {**result, "worktree_status": result["status"], "status": "ok" if result["status"] == "integrated" else "blocked"}
            elif name == "sitina_worktree_verify":
                result = self._verify(value)
            else:
                result = self.manager.cleanup_worktree(self._path(value["path"]))
                result = {**result, "worktree_status": result["status"], "status": "ok" if result["status"] == "removed" else "blocked"}
            return self._finish(result, start)
        except WorkspaceError as error:
            return self._finish(error.as_dict(), start)

    def bind(self):
        from sitina.extensions.tools import ToolDefinition
        self.catalog._task_workspace_authorizer = self.authorize
        definitions = {
            "sitina_git_status": ("Read bounded local staged/working status without running repository filters. No network, commits or remote writes.", {"offset": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}}, (), "read"),
            "sitina_git_diff": ("Read one local file's bounded index/worktree or HEAD/index diff without repository filters. diff_suppressed means the requested byte bound was exceeded.", {"path": {"type": "string"}, "staged": {"type": "boolean"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 65536}}, ("path",), "read"),
            "sitina_worktree_create": ("Create an isolated local worktree carrying dirty tracked source and only explicit task-related untracked/config paths. Does not commit. Dependencies start not_checked.", {"path": {"type": "string"}, "branch": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}}, ("path",), "write"),
            "sitina_worktree_integrate": ("Three-way integrate this task's worktree against its dirty baseline and current original files. Conflicts write no source files. Explicitly select new untracked task output paths.", {"path": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}}, ("path",), "write"),
            "sitina_worktree_verify": ("Verify integrated bytes using existing completed native check process IDs and their Host-recorded exact file versions. Model assertions and prior checks for different bytes are rejected.", {"path": {"type": "string"}, "check_process_ids": {"type": "array", "minItems": 1, "maxItems": 50, "items": {"type": "string"}}}, ("path", "check_process_ids"), "write"),
            "sitina_worktree_cleanup": ("Remove only an integrated, verified task worktree with no active, retained, unresolved or unsaved resources. Recovery baselines and local branches are preserved.", {"path": {"type": "string"}}, ("path",), "write"),
        }
        for name, (description, properties, required, permission) in definitions.items():
            self.catalog._tools[name] = ToolDefinition(name, description, self.catalog._object_schema(properties, required), permission, "sitina",
                lambda value, tool=name: self.invoke(tool, value))
