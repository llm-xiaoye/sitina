"""Controller-owned Code Mode execution boundary.

The controller is the only Sitina component that owns the Journal/CAS writer,
authorization validation and acceptance decisions.  ``WorkerToolExecutor`` is
an adapter at that boundary: it delegates the actual file/process operation to
one short-lived stdlib worker and verifies the returned observation locally.
The worker is never given a provider, broker, Journal/CAS object or capability
object.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import socket
import shlex
import subprocess
import sys
import sysconfig
import time
import fcntl
from pathlib import Path
from typing import Any, Mapping

from sitina.runners.tool_executor import ToolExecutor, _UNSET
from sitina.security.redaction import redact_boundary_value
from sitina.utils import ensure_dir, redact_text, sha256_text


class CodeModeControllerError(PermissionError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


_UNITTEST_RUN_LINE = re.compile(r"^Ran\s+(?P<count>\d+)\s+tests?\s+in\s+.+$", re.MULTILINE)
_UNITTEST_STATUS_LINE = re.compile(
    r"^(?P<status>OK|FAILED)(?:\s+\((?P<details>[^()]*)\))?\s*$",
    re.MULTILINE,
)
_UNITTEST_DETAIL = re.compile(
    r"^(?P<name>failures?|errors?|skipped|expected failures?|unexpected successes?)\s*=\s*(?P<count>\d+)$",
    re.IGNORECASE,
)


def _parse_unittest_result(
    output: str,
    *,
    argv: list[str],
    return_code: int,
    timed_out: bool,
    output_hash: str,
) -> dict[str, Any] | None:
    """Derive a strict, controller-owned summary from unittest's bounded output.

    The worker's output is untrusted.  This parser accepts only the canonical
    summary emitted by the stdlib runner, binds the result to the exact argv
    and output hash, and rejects ambiguity instead of inferring counts from an
    exit status alone.
    """
    if not isinstance(output, str) or not isinstance(return_code, int) or isinstance(return_code, bool):
        return None
    if not isinstance(timed_out, bool) or not isinstance(output_hash, str) or not output_hash:
        return None
    if timed_out:
        return None
    run_matches = list(_UNITTEST_RUN_LINE.finditer(output))
    status_matches = list(_UNITTEST_STATUS_LINE.finditer(output))
    if len(run_matches) != 1 or len(status_matches) != 1:
        return None
    collected = int(run_matches[0].group("count"))
    status_match = status_matches[0]
    status = status_match.group("status")
    if (return_code == 0 and status != "OK") or (return_code != 0 and status != "FAILED"):
        return None
    details = status_match.group("details")
    counts = {
        "failed_test_count": 0,
        "error_test_count": 0,
        "skipped_test_count": 0,
        "expected_failure_count": 0,
        "unexpected_success_count": 0,
    }
    if details:
        seen: set[str] = set()
        for raw_detail in details.split(","):
            detail = _UNITTEST_DETAIL.fullmatch(raw_detail.strip())
            if detail is None:
                return None
            name = " ".join(detail.group("name").lower().split())
            key = {
                "failure": "failed_test_count",
                "failures": "failed_test_count",
                "error": "error_test_count",
                "errors": "error_test_count",
                "skipped": "skipped_test_count",
                "expected failure": "expected_failure_count",
                "expected failures": "expected_failure_count",
                "unexpected success": "unexpected_success_count",
                "unexpected successes": "unexpected_success_count",
            }.get(name)
            if key is None or key in seen:
                return None
            seen.add(key)
            counts[key] = int(detail.group("count"))
    accounted = sum(counts.values())
    passed = collected - accounted
    if passed < 0:
        return None
    if status == "OK" and any(counts.values()):
        # A skipped/expected/unexpected result is not a clean OK evidence
        # value; retain the exact counts but do not silently call it passed.
        pass
    if status == "FAILED" and not accounted:
        return None
    return {
        "schema": "SITINA_CONTROLLER_UNITTEST_RESULT_V1",
        "argv": list(argv),
        "output_hash": output_hash,
        "collected_test_count": collected,
        "executed_test_count": collected,
        "passed_test_count": passed,
        **counts,
        "timed_out": False,
        "runner_return_code": return_code,
    }


def _seatbelt_literal(path: Path) -> str:
    value = str(path)
    if any(char in value for char in ("\x00", "\n", "\r")):
        raise CodeModeControllerError("sandbox path contains forbidden characters")
    return json.dumps(value)


def _code_mode_sandbox_profile(
    *, python_executable: Path, worker_script: Path,
    read_roots: tuple[Path, ...], write_roots: tuple[Path, ...],
    allow_fork: bool,
) -> str:
    """Build the Code Mode policy without consulting the Legacy fence.

    The worker needs the interpreter and stdlib, the bundled worker, and the
    declared workspace.  It may fork only to run the exact interpreter used
    for a structured tester command; all other exec and all networking stay
    denied.  This is deliberately local to Code Mode so importing Legacy B+
    cannot grant or configure this boundary.
    """
    python = Path(python_executable).expanduser().resolve(strict=True)
    worker = Path(worker_script).expanduser().resolve(strict=True)
    roots = {python.parent, worker.parent}
    for item in sysconfig.get_paths().values():
        candidate = Path(item).expanduser()
        if candidate.exists():
            roots.add(candidate.resolve(strict=True))
    roots.update(Path(item).expanduser().resolve(strict=True) for item in read_roots)
    roots.update(Path(item).expanduser().resolve(strict=True) for item in write_roots)
    reads = tuple(sorted(roots, key=str))
    writes = tuple(sorted({Path(item).expanduser().resolve(strict=True) for item in write_roots}, key=str))
    # macOS resolves /tmp through /private and the interpreter may live below
    # a framework prefix. Permit metadata traversal of ancestors without
    # granting their contents; data access remains limited to `reads`.
    ancestors: set[Path] = set()
    for item in reads:
        ancestors.update(item.parents)
    lines = [
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
        "(deny network*)",
        "(allow process-fork)" if allow_fork else "(deny process-fork)",
        "(allow signal (target children))" if allow_fork else "(deny signal)",
        f"(allow process-exec (literal {_seatbelt_literal(python)}))",
        "(allow file-read-metadata file-test-existence",
        *(f"  (subpath {_seatbelt_literal(item)})" for item in sorted(ancestors, key=str)),
        ")",
        "(allow file-read* file-test-existence",
        *(f"  (subpath {_seatbelt_literal(item)})" for item in reads),
        ")",
        "(allow file-write*",
        *(f"  (subpath {_seatbelt_literal(item)})" for item in writes),
        ")",
    ]
    return "\n".join(lines) + "\n"


class CodeModeControllerSession:
    """One controller-owned execution session.

    This object is intentionally created by the active runtime after it has
    validated the session authorization.  It is not a replacement for the
    external authority host: in live mode the host remains the signer and
    transport owner; this session owns the local worker boundary and evidence
    decisions.  Offline/scripted sessions are explicitly non-authoritative.
    """

    def __init__(
        self,
        *,
        context: Any,
        run_id: str,
        session_id: str,
        authorization: Mapping[str, Any],
        workspace: Path,
        offline: bool,
        session_instance_id: str | None = None,
    ) -> None:
        if not isinstance(authorization, Mapping) or not authorization.get("authorization_ref"):
            raise CodeModeControllerError("controller session requires an issued authorization")
        self.context = context
        self.run_id = str(run_id)
        self.session_id = str(session_id)
        context_instance_id = getattr(context, "session_instance_id", None)
        if not context_instance_id and offline:
            # A bare offline test seam has no authority identity. Give this
            # controller a fresh local namespace so its worker capability is
            # still never reusable across controller instances.
            context_instance_id = "session-instance-" + secrets.token_hex(16)
            try:
                setattr(context, "session_instance_id", context_instance_id)
            except Exception as error:  # pragma: no cover - hostile seam
                raise CodeModeControllerError("offline context cannot hold session instance") from error
        self.session_instance_id = str(
            session_instance_id or context_instance_id or ""
        )
        if not self.session_instance_id.strip() or self.session_instance_id != getattr(context, "session_instance_id", None):
            raise CodeModeControllerError("controller session instance binding is invalid")
        self.authorization = dict(authorization)
        authorization_instance = self.authorization.get("session_instance_id")
        if authorization_instance is None or authorization_instance == "":
            # Direct/fixture contexts are non-authoritative, but their local
            # capability is still scoped to the live controller instance
            # rather than being reusable across controller instances. A live
            # canary admission still checks this field before provider IO.
            self.authorization["session_instance_id"] = self.session_instance_id
        elif authorization_instance != self.session_instance_id:
            raise CodeModeControllerError("controller authorization session instance mismatch")
        self.workspace = Path(workspace).expanduser().resolve(strict=True)
        if self.workspace.is_symlink() or not self.workspace.is_dir():
            raise CodeModeControllerError("controller workspace must be a real directory")
        self.controller_id = "controller-" + secrets.token_hex(16)
        raw_attempt = self.authorization.get("run_attempt")
        if isinstance(raw_attempt, bool) or not isinstance(raw_attempt, int) or raw_attempt < 1:
            raise CodeModeControllerError("controller run attempt binding is invalid")
        self.run_attempt = int(raw_attempt)
        self._offline = bool(offline)
        self._closed = False
        self._live_capability: Any | None = None
        # The issuer token never crosses the controller boundary.  The
        # runtime handle constructor accepts only tokens registered here;
        # callers cannot manufacture an equivalent object by copying fields.
        from sitina.orchestrator.true_multi_agent_runtime import _ControllerCapabilityIssuer
        broker_issuer = getattr(getattr(context, "_broker_client", None), "_controller_capability_issuer", None)
        self._live_capability_issuer = (
            broker_issuer if isinstance(broker_issuer, _ControllerCapabilityIssuer)
            else _ControllerCapabilityIssuer()
        )
        self._attempts: dict[int, "WorkerToolExecutor"] = {}
        self._controller_proof = getattr(context, "_controller_proof", None)
        self._worker_script = Path(__file__).resolve().parents[3] / "scripts" / "code_mode_worker.py"
        if not self._worker_script.is_file() or self._worker_script.is_symlink():
            raise CodeModeControllerError("Code Mode worker executable is unavailable")
        self.worker_code_hash = hashlib.sha256(self._worker_script.read_bytes()).hexdigest()
        # A per-session advisory lock is only a liveness/fencing primitive;
        # it is never an authority credential.  A fresh CLI namespace gets a
        # fresh lock, while a restart can safely fence stale process records
        # before opening any old Journal/CAS namespace.
        runtime_root = Path(getattr(context, "home", self.workspace)).expanduser().resolve(strict=True)
        self._namespace_lock_path = runtime_root / ".code-mode-session.lock"
        self._managed_processes_path = runtime_root / ".code-mode-managed-processes.json"
        self._namespace_lock = self._namespace_lock_path.open("a+")
        try:
            fcntl.flock(self._namespace_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self._namespace_lock.close()
            raise CodeModeControllerError("Code Mode session namespace is already owned") from error
        self._managed_processes_path.write_text("[]", encoding="utf-8")

    def _register_managed_process(self, pid: int, start_identity: str, *, kind: str) -> None:
        records: list[dict[str, Any]] = []
        try:
            value = json.loads(self._managed_processes_path.read_text(encoding="utf-8"))
            if isinstance(value, list):
                records = [dict(item) for item in value if isinstance(item, Mapping)]
        except (OSError, ValueError):
            pass
        records.append({"pid": int(pid), "start_identity": str(start_identity), "kind": str(kind)})
        self._managed_processes_path.write_text(json.dumps(records, sort_keys=True), encoding="utf-8")

    def _unregister_managed_process(self, pid: int) -> None:
        try:
            value = json.loads(self._managed_processes_path.read_text(encoding="utf-8"))
            records = [dict(item) for item in value if isinstance(item, Mapping) and int(item.get("pid") or 0) != int(pid)] if isinstance(value, list) else []
            self._managed_processes_path.write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
        except (OSError, ValueError):
            pass

    @property
    def authoritative(self) -> bool:
        broker = getattr(self.context, "_broker_client", None)
        proof = self._controller_proof
        return bool(
            not self._offline
            # The proof is an opaque object created by the attested CLI host.
            # It must never be accepted merely because a caller can construct
            # a Mapping with plausible-looking fields.
            and proof is not None
            and broker is not None
            and callable(getattr(broker, "is_attested_host_client", None))
            and broker.is_attested_host_client()
            and getattr(self.context, "_controller_proof", None) is proof
            and getattr(self.context, "_controller_proof_issuer_id", None) == dict(getattr(broker, "identity", {})).get("issuer_id")
            and getattr(self.context, "_controller_proof_state_identity", None) == getattr(getattr(self.context, "identity", None), "state_identity", None)
            and getattr(self.context, "_active_controller_session", None) is self
        )

    def assert_canary_access(self, context: Any, authorization: Mapping[str, Any]) -> None:
        """Admission used by the acceptance gate, never by a worker.

        A context-shaped object or a copied issuer string is insufficient.  A
        canary must be evaluated by the same live controller session that owns
        the attested external broker connection and the exact run binding.
        Offline/scripted sessions deliberately fail this check.
        """
        self.assert_live()
        if context is not self.context or getattr(context, "_active_controller_session", None) is not self or not self.authoritative:
            raise CodeModeControllerError("canary requires the active authoritative controller session")
        broker = getattr(context, "_broker_client", None)
        if broker is None or not bool(broker.is_attested_host_client()):
            raise CodeModeControllerError("controller authority is not an attested host client")
        if authorization.get("session_id") != self.session_id:
            raise CodeModeControllerError("canary session binding mismatch")
        if authorization.get("session_instance_id") != self.session_instance_id:
            raise CodeModeControllerError("canary session instance binding mismatch")
        if authorization.get("workspace") != str(self.workspace):
            raise CodeModeControllerError("canary workspace binding mismatch")
        if authorization.get("run_id") != self.run_id:
            raise CodeModeControllerError("canary run binding mismatch")
        if authorization.get("run_attempt") != self.run_attempt:
            raise CodeModeControllerError("canary attempt binding mismatch")

    def assert_live(self) -> None:
        if self._closed:
            raise CodeModeControllerError("controller session is closed")
        if not self.session_id or self.authorization.get("session_id") != self.session_id:
            raise CodeModeControllerError("controller session authorization mismatch")
        attempt = self.authorization.get("run_attempt")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt != self.run_attempt:
            raise CodeModeControllerError("controller attempt binding is invalid")
        if int(self.authorization.get("expires_at") or 0) <= int(time.time()):
            raise CodeModeControllerError("controller session authorization expired")

    def worker_executor(
        self,
        *,
        attempt: int,
        authorization_binding: Mapping[str, Any],
        workspace: Path | None = None,
        before_hashes: Mapping[str, str | None] | None = None,
        store: Any | None = None,
    ) -> "WorkerToolExecutor":
        self.assert_live()
        if int(attempt) < 1:
            raise CodeModeControllerError("worker attempt must be positive")
        if int(attempt) in self._attempts:
            raise CodeModeControllerError("worker executor cannot be replayed for an attempt")
        executor = WorkerToolExecutor(
            self,
            home=Path(getattr(self.context, "home", self.workspace)),
            store=store,
            enforce_write_boundary=True,
            authorization_binding=authorization_binding,
            authorization_authority=self.context,
            attempt=int(attempt),
            worker_workspace=workspace or self.workspace,
            before_hashes=before_hashes,
        )
        self._attempts[int(attempt)] = executor
        return executor

    def advance_attempt(self, authorization: Mapping[str, Any]) -> None:
        """Atomically move this controller to the next attempt.

        Rework is a new run-attempt authorization, not a mutation of the old
        worker capability.  All current Tester/worker/sealer reads go through
        this object, so updating it before the next worker is created prevents
        attempt-one facts from being reported as attempt two.
        """
        self.assert_live()
        if not isinstance(authorization, Mapping):
            raise CodeModeControllerError("next attempt authorization is invalid")
        next_attempt = authorization.get("run_attempt")
        if isinstance(next_attempt, bool) or not isinstance(next_attempt, int):
            raise CodeModeControllerError("next attempt authorization is missing")
        if next_attempt != self.run_attempt + 1:
            raise CodeModeControllerError("controller attempt transition is not exact")
        exact_fields = ("session_instance_id", "session_id", "run_id", "workspace", "generation")
        for field in exact_fields:
            if authorization.get(field) != self.authorization.get(field):
                raise CodeModeControllerError("next attempt binding changed: " + field)
        for executor in tuple(self._attempts.values()):
            executor.close()
        self.authorization = dict(authorization)
        self.run_attempt = next_attempt

    def start_new_run(self, *, run_id: str, authorization: Mapping[str, Any]) -> None:
        """Reuse the live session boundary for a distinct fresh run.

        A conversation can issue multiple runs without making the previous
        run's attempt number leak into the new run.  The old run remains an
        audit record, while this controller's active binding is replaced only
        by the run owner with attempt one.
        """
        self.assert_live()
        if not isinstance(authorization, Mapping) or str(run_id) != str(authorization.get("run_id") or ""):
            raise CodeModeControllerError("new run authorization is incomplete")
        if authorization.get("session_instance_id") != self.session_instance_id:
            raise CodeModeControllerError("new run session instance changed")
        if authorization.get("session_id") != self.session_id:
            raise CodeModeControllerError("new run conversation session changed")
        if authorization.get("workspace") != str(self.workspace):
            raise CodeModeControllerError("new run workspace changed")
        next_attempt = authorization.get("run_attempt")
        if isinstance(next_attempt, bool) or next_attempt != 1:
            raise CodeModeControllerError("new run must start at attempt one")
        for executor in tuple(self._attempts.values()):
            executor.close()
        self._attempts.clear()
        self.run_id = str(run_id)
        self.authorization = dict(authorization)
        self.run_attempt = 1

    def close(self) -> None:
        if getattr(self, "_namespace_lock", None) is None:
            return
        self._closed = True
        for executor in tuple(self._attempts.values()):
            executor.close()
        try:
            self._managed_processes_path.write_text("[]", encoding="utf-8")
            fcntl.flock(self._namespace_lock.fileno(), fcntl.LOCK_UN)
            self._namespace_lock.close()
            self._namespace_lock = None
        except OSError:
            pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def issue_canary_authorization(self, gate: Any, **kwargs: Any) -> dict[str, Any]:
        self.assert_live()
        kwargs["runtime_context"] = self.context
        kwargs["controller_session"] = self
        kwargs.setdefault("live_capability", self.live_capability_for_admission())
        return dict(gate.issue_canary_authorization(**kwargs))

    def mint_live_network_capability(self, *, purpose: str, session_id: str, run_id: str) -> Any:
        """Mint the opaque opt-in only after this controller owns the run."""
        self.assert_live()
        if str(run_id) != self.run_id or str(session_id) != self.session_id:
            raise CodeModeControllerError("live capability is outside the active controller scope")
        issued_at = int(time.time())
        self._live_capability = self._live_capability_issuer.mint(
            purpose=purpose,
            session_id=self.session_id,
            run_id=self.run_id,
            issued_at=issued_at,
            expires_at=issued_at + 900,
            cli_session_instance_id=self.session_instance_id,
        )
        return self._live_capability

    def live_capability_for_admission(self) -> Any:
        """Return the controller-owned one-use handle for the current action."""
        self.assert_live()
        if self._live_capability is None:
            from sitina.journal.model import CODE_MODE_LIVE_CAPABILITY_PURPOSE
            self.mint_live_network_capability(
                purpose=CODE_MODE_LIVE_CAPABILITY_PURPOSE,
                session_id=self.session_id,
                run_id=self.run_id,
            )
        return self._live_capability

    def evaluate_canary(self, gate: Any, **kwargs: Any) -> dict[str, Any]:
        self.assert_live()
        kwargs["runtime_context"] = self.context
        kwargs["controller_session"] = self
        # The issuer pin is read from this active controller's attested host
        # connection. A caller-supplied identity is never an authority input.
        kwargs.pop("expected_issuer_identity", None)
        kwargs["expected_issuer_identity"] = self.context.canary_authority_binding()["issuer_id"]
        return dict(gate.evaluate_canary(**kwargs))

    def run_tester(self, runtime: Any, **kwargs: Any) -> dict[str, Any]:
        """Run the controller-owned offline Tester with this session binding."""
        runner = getattr(runtime, "run_controlled_tester", None)
        if not callable(runner):
            raise CodeModeControllerError("Code Mode runtime has no controlled Tester")
        return dict(runner(controller_session=self, **kwargs))


class WorkerToolExecutor(ToolExecutor):
    """Controller-side ToolExecutor whose mutation primitive is a worker."""

    WORKER_TIMEOUT_SECONDS = 5

    def __init__(self, controller: CodeModeControllerSession, *, attempt: int, worker_workspace: Path, before_hashes: Mapping[str, str | None] | None = None, **kwargs: Any):
        runtime_home = kwargs.get("home")
        super().__init__(**kwargs)
        self.controller = controller
        self.attempt = int(attempt)
        raw_authorization_binding = dict(self.authorization_binding)
        if (
            controller._offline
            and not raw_authorization_binding.get("session_instance_id")
        ):
            raw_authorization_binding["session_instance_id"] = controller.session_instance_id
            self.authorization_binding = raw_authorization_binding
        self.worker_workspace = Path(worker_workspace).expanduser().resolve(strict=True)
        self._runtime_state_root = (
            Path(runtime_home).expanduser().resolve(strict=True)
            if runtime_home is not None and Path(runtime_home).expanduser().is_dir()
            else None
        )
        if self.worker_workspace.is_symlink() or not self.worker_workspace.is_dir():
            raise CodeModeControllerError("worker workspace must be a real directory")
        self._expected_before_hashes = {
            str(Path(key).expanduser().resolve(strict=False)): value
            for key, value in dict(before_hashes or {}).items()
        }
        self._consumed_operations = 0
        self._issued_bindings: dict[str, dict[str, Any]] = {}
        self._revoked = False

    def _binding(self, *, purpose: str, argv_hash: str | None = None) -> dict[str, Any]:
        self.controller.assert_live()
        auth_binding = self.authorization_binding
        if auth_binding.get("session_instance_id") != self.controller.session_instance_id:
            raise CodeModeControllerError("worker authorization session instance mismatch")
        worker_run_id = str(auth_binding.get("run_id") or "")
        if worker_run_id != self.controller.run_id and not worker_run_id.startswith(
            f"forge-exec-{self.controller.run_id}-"
        ):
            raise CodeModeControllerError("worker run binding mismatch")
        root = self.worker_workspace
        stat_result = os.stat(root, follow_symlinks=False)
        parent_root = self.controller.workspace
        parent_stat = os.stat(parent_root, follow_symlinks=False)
        operation_id = f"{self.controller.controller_id}:{self.attempt}:{self._consumed_operations + 1}:{secrets.token_hex(12)}"
        binding = {
            "schema": "CODE_MODE_WORKER_BINDING_V1",
            "controller_id": self.controller.controller_id,
            "controller_pid": os.getpid(),
            "session_instance_id": self.controller.session_instance_id,
            "session_id": self.controller.session_id,
            "run_id": worker_run_id,
            "parent_run_id": self.controller.run_id,
            "child_run_id": worker_run_id,
            "intent_hash": str(auth_binding.get("intent_hash") or ""),
            "workspace": str(root),
            "workspace_dev": int(stat_result.st_dev),
            "workspace_inode": int(stat_result.st_ino),
            "parent_workspace": str(parent_root),
            "parent_workspace_dev": int(parent_stat.st_dev),
            "parent_workspace_inode": int(parent_stat.st_ino),
            "attempt": self.attempt,
            "purpose": purpose,
            "read_roots": [str(root)],
            "write_roots": [str(root)],
            "runner_hash": self.controller.worker_code_hash,
            "expires_at": min(int(auth_binding.get("expires_at") or 0), int(time.time()) + 120),
            "operation_id": operation_id,
            "nonce": secrets.token_hex(32),
        }
        if argv_hash is not None:
            binding["argv_hash"] = str(argv_hash)
        if binding["expires_at"] <= int(time.time()):
            raise CodeModeControllerError("worker authorization is expired")
        self._issued_bindings[hashlib.sha256(_canonical(binding)).hexdigest()] = binding
        return binding

    def _run_worker(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if self._revoked:
            raise CodeModeControllerError("worker capability has been revoked")
        if self._consumed_operations >= 128:
            raise CodeModeControllerError("worker operation budget exhausted")
        if request.get("schema") != "CODE_MODE_WORKER_REQUEST_V1":
            raise CodeModeControllerError("worker request schema is invalid")
        supplied_binding = request.get("binding")
        if not isinstance(supplied_binding, Mapping):
            raise CodeModeControllerError("worker binding is required")
        binding_hash = hashlib.sha256(_canonical(dict(supplied_binding))).hexdigest()
        issued_binding = self._issued_bindings.pop(binding_hash, None)
        if issued_binding is None or dict(issued_binding) != dict(supplied_binding):
            raise CodeModeControllerError("worker binding is not a fresh controller-issued operation")
        if int(issued_binding.get("attempt") or 0) != self.attempt:
            raise CodeModeControllerError("worker binding attempt mismatch")
        if issued_binding.get("session_instance_id") != self.controller.session_instance_id:
            raise CodeModeControllerError("worker binding session instance mismatch")
        try:
            parent_stat = os.stat(self.controller.workspace, follow_symlinks=False)
            worker_stat = os.stat(self.worker_workspace, follow_symlinks=False)
        except OSError as error:
            raise CodeModeControllerError("worker workspace identity is unavailable") from error
        if (
            int(issued_binding.get("parent_workspace_dev") or -1) != int(parent_stat.st_dev)
            or int(issued_binding.get("parent_workspace_inode") or -1) != int(parent_stat.st_ino)
            or int(issued_binding.get("workspace_dev") or -1) != int(worker_stat.st_dev)
            or int(issued_binding.get("workspace_inode") or -1) != int(worker_stat.st_ino)
        ):
            raise CodeModeControllerError("worker workspace binding changed")
        operation = str(request.get("operation") or "")
        expected_purpose = {
            "write": "file-write", "append": "file-write",
            "delete": "file-delete", "rename": "file-rename",
            "shell": "tester-command",
        }.get(operation)
        if expected_purpose != issued_binding.get("purpose"):
            raise CodeModeControllerError("worker operation purpose mismatch")
        argv = request.get("argv")
        if operation == "shell":
            if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
                raise CodeModeControllerError("worker shell argv is invalid")
            argv_hash = _hash_bytes(_canonical(argv))
            if request.get("argv_hash") != argv_hash:
                raise CodeModeControllerError("worker argv hash mismatch")
        self._consumed_operations += 1
        sandbox = Path("/usr/bin/sandbox-exec")
        if platform.system() != "Darwin" or not sandbox.is_file() or sandbox.is_symlink():
            raise CodeModeControllerError("Code Mode worker requires macOS sandbox-exec")
        python_executable = Path(sys.executable).expanduser().resolve(strict=True)
        profile = _code_mode_sandbox_profile(
            python_executable=python_executable,
            worker_script=self.controller._worker_script,
            read_roots=(self.worker_workspace,),
            write_roots=(self.worker_workspace,),
            allow_fork=operation == "shell",
        )
        start_identity = None
        parent, child = socket.socketpair()
        process = None
        try:
            command = [
                str(sandbox), "-p", profile,
                "--", str(python_executable), str(self.controller._worker_script),
                "--control-fd", str(child.fileno()),
            ]
            process = subprocess.Popen(
                command,
                cwd=str(self.worker_workspace),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=(child.fileno(),),
                start_new_session=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "HOME": str(self.worker_workspace),
                    "TMPDIR": str(self.worker_workspace / ".sitina-worker-tmp"),
                    "SITINA_CODE_MODE_WORKER": "1",
                },
            )
            start_identity = self._process_start_identity(process.pid)
            if not start_identity:
                raise CodeModeControllerError("worker process start identity is unavailable")
            self.controller._register_managed_process(int(process.pid), start_identity, kind="code-mode-worker")
            request_with_identity = dict(request)
            wire_binding = dict(supplied_binding)
            wire_binding.update({
                "worker_pid": int(process.pid),
                "worker_start_identity": start_identity,
                "timeout_seconds": self.WORKER_TIMEOUT_SECONDS,
                "control_fd": int(child.fileno()),
            })
            request_with_identity["binding"] = wire_binding
            request_with_identity["control_fd"] = int(wire_binding["control_fd"])
            child.close()
            parent.sendall(_canonical(request_with_identity) + b"\n")
            parent.shutdown(socket.SHUT_WR)
            parent.settimeout(self.WORKER_TIMEOUT_SECONDS + 5)
            line = parent.makefile("rb").readline()
            if not line:
                raise CodeModeControllerError("Code Mode worker exited without an observation")
            response = json.loads(line.decode("utf-8"))
            if not isinstance(response, Mapping) or response.get("schema") != "CODE_MODE_WORKER_RESULT_V1":
                raise CodeModeControllerError("Code Mode worker returned an invalid observation")
            observed = dict(response)
            if observed.get("worker_pid") != int(process.pid):
                raise CodeModeControllerError("worker PID binding mismatch")
            if observed.get("worker_code_hash") != self.controller.worker_code_hash:
                raise CodeModeControllerError("worker code identity mismatch")
            if observed.get("worker_start_identity") != start_identity:
                raise CodeModeControllerError("worker start identity binding mismatch")
            if observed.get("control_fd") != int(wire_binding["control_fd"]):
                raise CodeModeControllerError("worker control FD binding mismatch")
            canonical_binding_hash = hashlib.sha256(_canonical(wire_binding)).hexdigest()
            if observed.get("binding_hash") != canonical_binding_hash:
                raise CodeModeControllerError("worker canonical binding hash mismatch")
            if observed.get("operation_id") != wire_binding.get("operation_id"):
                raise CodeModeControllerError("worker operation binding mismatch")
            if observed.get("nonce_hash") != hashlib.sha256(str(wire_binding.get("nonce")).encode()).hexdigest():
                raise CodeModeControllerError("worker nonce binding mismatch")
            if observed.get("secret_env_absent") is not True:
                raise CodeModeControllerError("worker environment contains a secret")
            if operation == "shell" and observed.get("process_group_reaped") is not True:
                raise CodeModeControllerError("tester process group cleanup was not proved")
            fd_inventory = observed.get("fd_inventory")
            if isinstance(fd_inventory, list):
                inventory = [item for item in fd_inventory if isinstance(item, Mapping)]
                control_fd = int(wire_binding["control_fd"])
                try:
                    inventory_fds = [int(item["fd"]) for item in inventory]
                    inventory_ok = (
                        control_fd not in {0, 1, 2}
                        and len(inventory_fds) == len(set(inventory_fds))
                        and set(inventory_fds) == {0, 1, 2, control_fd}
                        and all(
                            isinstance(item.get("identity_hash"), str)
                            and len(item["identity_hash"]) == 64
                            and all(char in "0123456789abcdef" for char in item["identity_hash"])
                            for item in inventory
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    inventory_ok = False
            else:
                inventory_ok = False
            if not inventory_ok:
                raise CodeModeControllerError(
                    "worker file descriptor inventory is not restricted: "
                    + _hash_bytes(_canonical(fd_inventory if isinstance(fd_inventory, list) else []))
                    + ":fds=" + ",".join(str(item.get("fd")) for item in fd_inventory if isinstance(item, Mapping))
                    + ":control=" + str(wire_binding.get("control_fd"))
                )
            if process.wait(timeout=3) != 0:
                raise CodeModeControllerError("worker exited unsuccessfully")
            observed["worker_binding_hash"] = canonical_binding_hash
            return observed
        finally:
            try:
                parent.close()
            except OSError:
                pass
            if process is not None:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                if start_identity:
                    self.controller._unregister_managed_process(int(process.pid))

    @staticmethod
    def _process_start_identity(pid: int) -> str | None:
        try:
            result = subprocess.run(
                ["/bin/ps", "-p", str(int(pid)), "-o", "lstart="],
                check=True, capture_output=True, text=True, timeout=2,
            )
            value = result.stdout.strip()
            return _hash_bytes(value.encode("utf-8")) if value else None
        except (OSError, subprocess.SubprocessError):
            return None

    def _controller_hash(self, path: Path) -> str | None:
        try:
            if path.is_symlink() or not path.is_file():
                return None
            return _hash_bytes(path.read_bytes())
        except OSError:
            return None

    def _checked_path(self, target: str) -> Path:
        raw_path = Path(target).expanduser()
        if raw_path.is_symlink():
            raise CodeModeControllerError("worker target may not be a symlink")
        path = raw_path.resolve(strict=False)
        resolved = path
        try:
            resolved.relative_to(self.worker_workspace)
        except ValueError:
            raise CodeModeControllerError("worker target escapes controller workspace") from None
        cursor = self.worker_workspace
        for component in resolved.relative_to(self.worker_workspace).parts:
            cursor = cursor / component
            if cursor.is_symlink():
                raise CodeModeControllerError("worker path may not contain symlinks")
        return resolved

    def write_direct(self, *, target: str, content: str, run_id: str, expected_before_hash: object = _UNSET, capability: Any = None) -> dict[str, Any]:
        error = self._validate_direct_capability(capability, target=target, run_id=run_id, operation="write")
        if error:
            return {"status": "blocked", "reason": error}
        if not isinstance(content, str):
            return {"status": "blocked", "reason": "worker content is invalid"}
        redaction = redact_boundary_value(content, boundary="write")
        if redaction.redacted_paths:
            return {"status": "blocked", "reason": "write blocked: sensitive content at persistence boundary", "redacted_paths": list(redaction.redacted_paths)}
        path = self._checked_path(target)
        scan = self.risk_scanner.scan("write", target=str(path), allowed_roots=[str(self.worker_workspace)])
        if scan.action == "block":
            return {"status": "blocked", "reason": "controller risk scanner blocked worker write"}
        before = self._controller_hash(path)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "before_hash": before}
        result = self._run_worker({
            "schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "write", "path": str(path),
            "content": content, "expected_before_hash": before, "binding": self._binding(purpose="file-write"),
        })
        after = self._controller_hash(path)
        if result.get("status") != "ok" or result.get("before_hash") != before or after != result.get("after_hash"):
            return {"status": "blocked", "reason": "worker observation failed controller hash verification", "before_hash": before, "after_hash": after}
        value = {"status": "ok", "patch_id": sha256_text(f"{run_id}\n{path}\n{before}\n{after}"), "before_hash": before, "after_hash": after, "worker_observed": True, "worker_binding_hash": result.get("worker_binding_hash")}
        self._record_direct_audit("tool_worker_write", {"target": str(path), **value}, run_id=run_id, risk_scan_id=scan.risk_scan_id, authorization_ref=str(self.authorization_binding.get("authorization_ref") or ""), exit_status="ok")
        return value

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        operation = str(kwargs.get("operation") or "")
        capability = kwargs.get("capability")
        if operation in {"delete", "move", "shell"}:
            error = self._validate_direct_capability(capability, target=str(kwargs.get("target") or kwargs.get("cwd") or self.controller.workspace), run_id=str(kwargs.get("run_id") or ""), operation=operation, destination=kwargs.get("destination")) if operation != "shell" else None
            if error:
                return {"status": "blocked", "reason": error}
        self._active_worker_capability = capability
        try:
            return super().execute(**kwargs)
        finally:
            self._active_worker_capability = None

    def _write(self, target: str | None, content: str, run_id: str, *, expected_before_hash: object = _UNSET) -> dict[str, Any]:
        return self.write_direct(target=str(target or ""), content=content, run_id=run_id, expected_before_hash=expected_before_hash, capability=getattr(self, "_active_worker_capability", None))

    def _delete(self, target: str | None, run_id: str, *, expected_before_hash: object = _UNSET) -> dict[str, Any]:
        path = self._checked_path(str(target or ""))
        before = self._controller_hash(path)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "before_hash": before}
        result = self._run_worker({"schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "delete", "path": str(path), "expected_before_hash": before, "binding": self._binding(purpose="file-delete")})
        after = self._controller_hash(path)
        if result.get("status") != "ok" or after is not None:
            return {"status": "blocked", "reason": "worker delete observation failed controller verification", "before_hash": before, "after_hash": after}
        return {"status": "ok", "operation": "delete", "path": str(path), "before_hash": before, "after_hash": None, "worker_observed": True, "worker_binding_hash": result.get("worker_binding_hash")}

    def _move(self, target: str | None, destination: str | None, run_id: str, *, expected_before_hash: object = _UNSET) -> dict[str, Any]:
        source, dest = self._checked_path(str(target or "")), self._checked_path(str(destination or ""))
        before = self._controller_hash(source)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "before_hash": before}
        result = self._run_worker({"schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "rename", "path": str(source), "destination": str(dest), "expected_before_hash": before, "binding": self._binding(purpose="file-rename")})
        after = self._controller_hash(dest)
        if result.get("status") != "ok" or self._controller_hash(source) is not None or after != result.get("after_hash"):
            return {"status": "blocked", "reason": "worker rename observation failed controller verification", "before_hash": before, "after_hash": after}
        return {"status": "ok", "operation": "rename", "path": str(source), "destination": str(dest), "before_hash": before, "after_hash": after, "worker_observed": True, "worker_binding_hash": result.get("worker_binding_hash")}

    def _snapshot(self) -> dict[str, tuple[str, str | None, bytes | str | None]]:
        root = self.worker_workspace
        snapshot: dict[str, tuple[str, str | None]] = {}
        for path in root.rglob("*"):
            # The controller's local audit store is runtime state, not a
            # worker mutation.  Production places it outside the execution
            # workspace; the disposable fixture may colocate it under
            # ``data``.  Exclude only this explicit managed state root so all
            # user files, symlinks, and type changes remain observable.
            relative_parts = path.relative_to(root).parts
            runtime_state_path = False
            if self._runtime_state_root is not None and self._runtime_state_root != root:
                try:
                    path.relative_to(self._runtime_state_root)
                    runtime_state_path = True
                except ValueError:
                    pass
            if (
                ".sitina-worker-tmp" in relative_parts
                or runtime_state_path
                or path.is_socket()
            ):
                continue
            rel = str(path.relative_to(root))
            if path.is_symlink():
                target = os.readlink(path)
                snapshot[rel] = ("symlink", _hash_bytes(target.encode()), target)
            elif path.is_file():
                snapshot[rel] = ("file", self._controller_hash(path), path.read_bytes())
            elif path.is_dir():
                snapshot[rel] = ("dir", None, None)
        return snapshot

    @staticmethod
    def _is_logical_python_interpreter(value: str) -> bool:
        """Return whether *value* is a policy-level Python name.

        A bare logical interpreter name is deliberately different from an
        absolute executable supplied by a caller.  Only the former can be
        resolved to the controller's already-selected interpreter; this
        keeps the policy language useful in a worker environment whose PATH
        is intentionally minimal without turning it into a caller path
        grant.
        """
        if "/" in value or "\\" in value:
            return False
        if value in {"python", "python3"}:
            return True
        return False

    @staticmethod
    def _parse_allowed_command(value: str) -> list[str] | None:
        try:
            parsed = shlex.split(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed and all(isinstance(item, str) for item in parsed) else None

    def _resolved_controller_python(self) -> str | None:
        try:
            executable = Path(sys.executable).expanduser().resolve(strict=True)
        except OSError:
            return None
        return str(executable) if executable.is_file() else None

    def _canonical_shell_argv(self, argv: list[str], allowed_commands: list[str]) -> list[str] | None:
        """Return the one executable argv admitted by the tester policy.

        The returned list is the execution identity.  In particular, a
        logical ``python`` policy is resolved to this controller process's
        interpreter before it is hashed, bound, or passed to the worker.
        Caller-supplied Python paths and interpreter aliases never receive
        that rewrite and therefore cannot match a logical policy.
        """
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(item, str) for item in argv)
            or any(item in {"-c", "--command", "-i", "--interactive"} for item in argv)
            or any(item in {";", "&&", "||", "|", ">", ">>", "<", "`"} for item in argv)
        ):
            return None
        resolved_python: str | None = None
        for raw_policy in allowed_commands:
            policy = self._parse_allowed_command(raw_policy)
            if policy is None:
                continue
            expected_interpreter = policy[0]
            logical_policy = self._is_logical_python_interpreter(expected_interpreter)
            if logical_policy:
                # ``python`` and ``python3`` are the only accepted logical
                # spellings.  They are equivalent policy names, but neither
                # can be replaced by an absolute caller-supplied path.
                if not self._is_logical_python_interpreter(argv[0]):
                    continue
                if resolved_python is None:
                    resolved_python = self._resolved_controller_python()
                if resolved_python is None:
                    continue
                execution_interpreter = resolved_python
            else:
                # Absolute/other executable policies remain exact.  They do
                # not allow the caller to replace a logical Python policy.
                if argv[0] != expected_interpreter:
                    continue
                execution_interpreter = expected_interpreter

            if argv == policy:
                return [execution_interpreter, *policy[1:]]

            # Only the explicitly supported test runners may add workspace
            # Python files.  Their module and all policy fields remain exact.
            if len(policy) == 3 and policy[1:3] in (
                ["-m", "unittest"], ["-m", "doctest"],
            ):
                if len(argv) < 3 or argv[1:3] != policy[1:3]:
                    continue
                try:
                    for value in argv[3:]:
                        path = self._checked_shell_test_path(value)
                        if not path.is_file() or path.suffix != ".py":
                            return None
                except (CodeModeControllerError, OSError):
                    return None
                return [execution_interpreter, *argv[1:]]
        return None

    def _canonical_policy_argv(self, allowed_commands: list[str]) -> list[list[str]]:
        """Canonicalize policy entries for the worker's audit envelope."""
        canonical: list[list[str]] = []
        resolved_python: str | None = None
        for raw_policy in allowed_commands:
            policy = self._parse_allowed_command(raw_policy)
            if policy is None:
                continue
            if self._is_logical_python_interpreter(policy[0]):
                if resolved_python is None:
                    resolved_python = self._resolved_controller_python()
                if resolved_python is None:
                    continue
                canonical.append([resolved_python, *policy[1:]])
            else:
                canonical.append(list(policy))
        return canonical

    def _checked_shell_test_path(self, value: str) -> Path:
        """Resolve a tester file relative to the worker's declared cwd."""
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.worker_workspace / path
        return self._checked_path(str(path))

    def _shell_argv_allowed(self, argv: list[str], allowed_commands: list[str]) -> bool:
        """Admit only exact structured tester invocations.

        The historical permissions list is a policy input, not an argv
        prefix grant.  Inline code, shell-like switches and arbitrary module
        execution are rejected even if an old policy happened to contain a
        short prefix.
        """
        return self._canonical_shell_argv(argv, allowed_commands) is not None

    def _shell(self, command: str, allowed_commands: list[str], run_id: str, *, cwd: str | None = None) -> dict[str, Any]:
        import shlex
        try:
            argv = shlex.split(command)
        except ValueError:
            return {"status": "blocked", "reason": "shell command quoting is invalid"}
        canonical_argv = self._canonical_shell_argv(argv, allowed_commands)
        if canonical_argv is None:
            return {"status": "blocked", "reason": "worker argv is not an exact safe tester command"}
        before = self._snapshot()
        allowed_argv = self._canonical_policy_argv(allowed_commands)
        argv_hash = _hash_bytes(_canonical(canonical_argv))
        try:
            result = self._run_worker({"schema": "CODE_MODE_WORKER_REQUEST_V1", "operation": "shell", "argv": canonical_argv, "argv_hash": argv_hash, "cwd": str(self._checked_path(str(cwd or self.worker_workspace))), "allowed_argv": allowed_argv, "binding": self._binding(purpose="tester-command", argv_hash=argv_hash)})
        except Exception as error:
            # Treat an invalid worker observation like an unregistered
            # mutation: inspect and restore before reporting the failure.
            after = self._snapshot()
            changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
            rollback_ok = True
            if changed:
                try:
                    self._restore_snapshot(before, after, changed)
                    rollback_ok = self._snapshot() == before
                except OSError:
                    rollback_ok = False
            return {
                "status": "blocked" if rollback_ok else "dirty",
                "reason": "worker observation failed",
                "error_hash": hashlib.sha256(type(error).__name__.encode("utf-8")).hexdigest(),
                "unregistered_paths": changed[:200],
                "rollback_status": "complete" if rollback_ok else "failed",
            }
        after = self._snapshot()
        changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
        if changed:
            # Shell/test commands are observational in the controller ledger;
            # an unregistered workspace mutation is rejected and restored.
            try:
                self._restore_snapshot(before, after, changed)
                restored = self._snapshot()
                rollback_ok = restored == before
            except OSError:
                rollback_ok = False
            return {"status": "blocked" if rollback_ok else "dirty", "reason": "worker command produced unregistered workspace mutation", "unregistered_paths": changed[:200], "rollback_status": "complete" if rollback_ok else "failed"}
        output = str(result.get("output") or "")
        output_hash = sha256_text(output)
        timed_out = bool(result.get("timed_out"))
        exit_code = result.get("exit_code")
        unittest_result = None
        if len(canonical_argv) >= 3 and canonical_argv[1:3] == ["-m", "unittest"]:
            if isinstance(exit_code, int) and not isinstance(exit_code, bool):
                unittest_result = _parse_unittest_result(
                    output,
                    argv=canonical_argv,
                    return_code=exit_code,
                    timed_out=timed_out,
                    output_hash=output_hash,
                )
        return {
            "status": result.get("status", "blocked"),
            "exit_code": exit_code,
            "output_hash": output_hash,
            "timed_out": timed_out,
            "process_group_reaped": bool(result.get("process_group_reaped")),
            "worker_observed": True,
            "argv": list(canonical_argv),
            "unittest_result": unittest_result,
        }

    def _restore_snapshot(self, before: Mapping[str, tuple[str, str | None, bytes | str | None]], after: Mapping[str, tuple[str, str | None, bytes | str | None]], changed: list[str]) -> None:
        # The rollback image exists only in controller memory.  It is never
        # returned to the worker/model or persisted in Journal/CAS, so a
        # pre-existing secret can be restored without becoming evidence.
        for rel in sorted(changed, key=lambda value: (value.count(os.sep), value), reverse=True):
            path = self.worker_workspace / rel
            if rel not in before:
                if path.is_file() or path.is_symlink():
                    path.unlink()
                elif path.is_dir():
                    try:
                        path.rmdir()
                    except OSError:
                        pass
            else:
                original_kind, _original_hash, original_value = before[rel]
                if original_kind == "file" and isinstance(original_value, bytes):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(original_value)
                elif original_kind == "symlink" and isinstance(original_value, str):
                    if path.exists() or path.is_symlink():
                        path.unlink()
                    path.symlink_to(original_value)
                elif original_kind == "dir" and not path.is_dir():
                    path.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        self._revoked = True
        self._issued_bindings.clear()
        self._consumed_operations = 128
