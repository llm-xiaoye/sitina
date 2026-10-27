from __future__ import annotations

import fcntl
import hashlib
import json
import os
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from .model import InputKind, TaskConflict


class LoopAuthorityError(RuntimeError):
    pass


class LoopControlRequestError(LoopAuthorityError):
    """Describe delivery without treating a missing receipt as rejection."""

    def __init__(
        self, message: str, *, delivery_status: str, phase: str,
        can_start_host: bool = False,
    ) -> None:
        super().__init__(message)
        self.delivery_status = delivery_status
        self.phase = phase
        self.can_start_host = can_start_host and delivery_status == "NOT_SENT"


def control_delivery_failure(error: BaseException) -> dict[str, Any]:
    not_sent = (
        isinstance(error, LoopControlRequestError)
        and error.delivery_status == "NOT_SENT"
    )
    return {
        "status": "not_sent" if not_sent else "receipt_unknown",
        "delivery_status": "NOT_SENT" if not_sent else "OUTCOME_UNKNOWN",
        "reason": (
            "指令尚未发送。"
            if not_sent else
            "指令可能已被接收，但回执尚未确认；请先查询原指令的收件记录，不要重复提交。"
        ),
        "transport_error": {
            "reason": str(error),
            "phase": getattr(error, "phase", "unclassified"),
            "error_type": type(error).__name__,
            "cause_type": type(error.__cause__).__name__ if error.__cause__ else None,
        },
    }


def input_receipt(task: Any, input_id: str) -> dict[str, Any]:
    """Project an existing durable input; this function never accepts input."""
    record = next((item for item in task.inputs if item.input_id == input_id), None)
    if record is None:
        return {"status": "NOT_FOUND", "task_id": task.task_id, "input_id": input_id}
    return {
        "status": "RECEIVED",
        "task_id": task.task_id,
        "input_id": record.input_id,
        "kind": record.kind.value,
        "body_hash": record.body_hash,
        "sequence": record.sequence,
        "handled": record.sequence <= task.handled_input_seq,
    }


def authority_socket_path(state_root: str | os.PathLike[str]) -> Path:
    """Return a pure, short endpoint independent of ``TMPDIR`` or cwd."""

    canonical = str(Path(state_root).expanduser().resolve(strict=False))
    identity = hashlib.sha256(canonical.encode()).hexdigest()[:32]
    user_scope = str(getattr(os, "getuid", lambda: 0)())
    return Path("/tmp") / f"sitina-loop-{user_scope}-{identity}" / "control.sock"


class LoopAuthorityLease:
    """Inter-process ownership acquired before any persistent Loop initialization."""

    def __init__(self, state_root: str | os.PathLike[str]) -> None:
        self.state_root = Path(state_root).expanduser().resolve(strict=False)
        self.lock_path = self.state_root / "loop-authority.lock"
        self._file: Any | None = None

    def acquire(self) -> "LoopAuthorityLease":
        self.state_root.mkdir(parents=True, exist_ok=True)
        candidate = self.lock_path.open("a+")
        try:
            fcntl.flock(candidate.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            candidate.close()
            raise LoopAuthorityError("another live coordinator already owns this Loop state root") from error
        self._file = candidate
        return self

    def close(self) -> None:
        if self._file is not None:
            try:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            finally:
                self._file.close()
                self._file = None

    def __enter__(self) -> "LoopAuthorityLease":
        return self.acquire()

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


class LoopControlAuthority:
    """Unix-socket input surface owned by the one live LoopBackend instance."""

    def __init__(
        self,
        backend: Any,
        state_root: Path,
        *,
        lease: LoopAuthorityLease | None = None,
        command_handler: Any | None = None,
        input_handler: Any | None = None,
        health_handler: Any | None = None,
    ) -> None:
        self.backend = backend
        self.state_root = Path(state_root).resolve(strict=False)
        self.socket_path = authority_socket_path(self.state_root)
        self.lock_path = self.state_root / "loop-authority.lock"
        self._lease = lease
        self._command_handler = command_handler
        self._input_handler = input_handler
        self._health_handler = health_handler
        self._owns_lease = lease is None
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._authority_owned = False
        self._bound_endpoint_identity: tuple[int, int] | None = None

    def _prepare_endpoint_parent(self) -> None:
        parent = self.socket_path.parent
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            parent.mkdir(mode=0o700, parents=False, exist_ok=False)
            parent_stat = parent.lstat()
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            raise LoopAuthorityError("control socket parent must be a private real directory")
        if int(parent_stat.st_uid) != int(getattr(os, "getuid", lambda: parent_stat.st_uid)()):
            raise LoopAuthorityError("control socket parent is not owned by the current user")
        # Tighten a caller-created directory, but never follow a substituted
        # symlink or mutate a directory owned by another user.
        if stat.S_IMODE(parent_stat.st_mode) != 0o700:
            os.chmod(parent, 0o700, follow_symlinks=False)
        verified = parent.lstat()
        if (
            stat.S_ISLNK(verified.st_mode)
            or not stat.S_ISDIR(verified.st_mode)
            or stat.S_IMODE(verified.st_mode) != 0o700
            or int(verified.st_uid) != int(getattr(os, "getuid", lambda: verified.st_uid)())
        ):
            raise LoopAuthorityError("control socket parent failed private-directory verification")

    def _remove_stale_endpoint(self) -> None:
        try:
            endpoint = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(endpoint.st_mode) or not stat.S_ISSOCK(endpoint.st_mode):
            raise LoopAuthorityError("control socket endpoint is occupied by a non-socket object")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.2)
            probe.connect(str(self.socket_path))
        except (ConnectionRefusedError, ConnectionResetError, FileNotFoundError, NotADirectoryError):
            # The exclusive state lease is already held by this authority, so
            # a refused socket is our own stale endpoint and may be reclaimed.
            try:
                current = self.socket_path.lstat()
                if stat.S_ISSOCK(current.st_mode):
                    self.socket_path.unlink()
            except FileNotFoundError:
                return
        else:
            raise LoopAuthorityError("another live control authority is listening at the endpoint")
        finally:
            probe.close()

    def start(self) -> "LoopControlAuthority":
        if self._lease is None:
            self._lease = LoopAuthorityLease(self.state_root).acquire()
        elif (
            self._lease._file is None
            or self._lease.state_root != self.state_root
        ):
            raise LoopAuthorityError(
                "control authority requires an already-acquired lease for this exact state root"
            )
        try:
            self._prepare_endpoint_parent()
            self._remove_stale_endpoint()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o600)
            listener.listen(8)
            listener.settimeout(0.2)
            self._socket = listener
            endpoint_stat = self.socket_path.lstat()
            if not stat.S_ISSOCK(endpoint_stat.st_mode):
                raise LoopAuthorityError("control endpoint did not bind as a socket")
            self._bound_endpoint_identity = (int(endpoint_stat.st_dev), int(endpoint_stat.st_ino))
            self._authority_owned = True
            self._thread = threading.Thread(target=self._serve, name="sitina-loop-control", daemon=True)
            self._thread.start()
            from sitina.legacy.fence import _register_native_network_authority
            _register_native_network_authority(self)
            return self
        except BaseException:
            self.close()
            raise

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                try:
                    connection.settimeout(2.0)
                    payload = self._read_request(connection)
                    response = self._dispatch(payload)
                except BaseException as error:
                    response = {
                        "status": "error",
                        "error_type": type(error).__name__,
                        "reason": str(error),
                    }
                try:
                    # _read_request uses a short polling timeout. A response
                    # may be much larger than its request, so give the write
                    # its own bounded budget instead of inheriting that poll.
                    connection.settimeout(2.0)
                    connection.sendall(
                        json.dumps(response, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
                    )
                except (BrokenPipeError, ConnectionError, TimeoutError, OSError):
                    # A broken client is scoped to this request. The authority
                    # must remain available for later pause/cancel/status input.
                    continue

    @staticmethod
    def _read_request(connection: socket.socket) -> Mapping[str, Any]:
        chunks = bytearray()
        deadline = time.monotonic() + 2.0
        while b"\n" not in chunks:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LoopAuthorityError("control request exceeded its whole-request deadline")
            connection.settimeout(min(0.25, remaining))
            piece = connection.recv(65536)
            if not piece:
                break
            chunks.extend(piece)
            if len(chunks) > 1024 * 1024:
                raise LoopAuthorityError("control request exceeds one MiB")
        value = json.loads(bytes(chunks).split(b"\n", 1)[0])
        if not isinstance(value, dict):
            raise LoopAuthorityError("control request must be an object")
        return value

    def _dispatch(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        command = str(payload.get("command") or "")
        task_id = str(payload.get("task_id") or "")
        if not task_id:
            raise LoopAuthorityError("task_id is required")
        if self._command_handler is not None and command in {"submit", "attach", "resume"}:
            return dict(self._command_handler(payload))
        if command == "status":
            task = self.backend.get_task(task_id)
            response = {"status": "ok", "task": task.as_dict()}
            if "input_id" in payload:
                input_id = payload["input_id"]
                if not isinstance(input_id, str) or not input_id:
                    raise LoopAuthorityError("input_id must be a non-empty string")
                response["input_receipt"] = input_receipt(task, input_id)
            if self._health_handler is not None:
                response["host_health"] = dict(self._health_handler())
            return response
        if command == "team":
            arguments = payload.get("arguments")
            if not isinstance(arguments, Mapping):
                raise LoopAuthorityError("team arguments must be an object")
            return {"status": "ok", "team": self.backend.manage_team(task_id, arguments)}
        if command == "retention":
            allowed = {"command", "task_id", "action", "operation_id", "memory_id", "approval_seconds"}
            if set(payload) - allowed:
                raise LoopAuthorityError("unknown retention control fields")
            operation_id = payload.get("operation_id")
            action = payload.get("action", "status")
            if not isinstance(operation_id, str) or not operation_id:
                raise LoopAuthorityError("retention operation_id is required")
            result = self.backend.memory_retention(
                task_id=task_id, action=action, operation_id=operation_id,
                memory_id=payload.get("memory_id"),
                approval_seconds=payload.get("approval_seconds", 3600),
            )
            return {"status": "ok", "retention": result}
        if command != "input":
            raise LoopAuthorityError("unknown control command")
        kind = InputKind(str(payload.get("kind") or ""))
        body = str(payload.get("body") or "")
        input_id = str(payload.get("input_id") or "")
        if not input_id:
            raise LoopAuthorityError("input_id is required")
        before = self.backend.get_task(task_id)
        accepted = self.backend.accept_input(task_id, input_id=input_id, kind=kind, body=body)
        # A duplicate receipt is an idempotent observation, not a second
        # attempt to handle whatever input happens to be next in the queue.
        if accepted.received_input_seq == before.received_input_seq:
            return {"status": "accepted", "task": accepted.as_dict(), "duplicate": True}
        # During same-version restart reconciliation the live host may durably
        # accept control/input records, but it must not advance business
        # versions until recovery claims the task's new epoch.
        if (
            getattr(accepted, "run_instance_id", None) != self.backend.run_instance_id
            or getattr(accepted, "recovery_state", None) not in {"READY_NEW_TASK", "READY_RECOVERED"}
        ):
            if self._input_handler is not None:
                self._input_handler(task_id, accepted)
            return {"status": "accepted", "disposition": "pending_recovery", "task": accepted.as_dict()}
        # The accept and handle calls acquire the Backend state lock
        # independently.  A Runner may handle the record observed in
        # ``before`` between those calls, so never carry a kind decision from
        # that stale projection.  The Backend selects and classifies the
        # actual next durable record under its own lock; a concurrent handle
        # is an idempotent race and is retried from the fresh projection.
        while True:
            current = self.backend.get_task(task_id)
            if current.received_input_seq == current.handled_input_seq:
                task = current
                break
            next_record = next(
                (item for item in current.inputs if item.sequence == current.handled_input_seq + 1),
                None,
            )
            if next_record is None:
                raise LoopAuthorityError("accepted input has no next durable record")
            try:
                task = self.backend.handle_next_input(
                    task_id,
                    expected_input_seq=next_record.sequence,
                    expected_input_id=next_record.input_id,
                    derive_effects_from_record=True,
                )
            except TaskConflict:
                raced = self.backend.get_task(task_id)
                if raced.handled_input_seq >= next_record.sequence:
                    continue
                raise
        if self._input_handler is not None:
            self._input_handler(task_id, task)
        return {"status": "accepted", "task": task.as_dict()}

    def close(self) -> None:
        from sitina.legacy.fence import _unregister_native_network_authority
        _unregister_native_network_authority(self)
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self._authority_owned and self._bound_endpoint_identity is not None:
            try:
                endpoint = self.socket_path.lstat()
                identity = (int(endpoint.st_dev), int(endpoint.st_ino))
                if stat.S_ISSOCK(endpoint.st_mode) and identity == self._bound_endpoint_identity:
                    self.socket_path.unlink()
            except FileNotFoundError:
                pass
            finally:
                self._authority_owned = False
                self._bound_endpoint_identity = None
        if self._owns_lease and self._lease is not None:
            self._lease.close()
            self._lease = None

    def __enter__(self) -> "LoopControlAuthority":
        return self.start()

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def send_control_request(state_root: str | os.PathLike[str], payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        request_bytes = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise LoopControlRequestError(
            "control request could not be encoded", delivery_status="NOT_SENT", phase="encode",
        ) from error
    socket_path = authority_socket_path(state_root)
    if not socket_path.exists():
        raise LoopControlRequestError(
            "no live Loop authority is listening for this state root",
            delivery_status="NOT_SENT", phase="connect", can_start_host=True,
        )
    client = None
    phase = "connect"
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect(str(socket_path))
        # sendall may send a prefix before raising. Mark uncertainty first.
        phase = "send"
        client.sendall(request_bytes)
        phase = "receive"
        chunks = bytearray()
        while b"\n" not in chunks:
            piece = client.recv(65536)
            if not piece:
                break
            chunks.extend(piece)
    except (ConnectionError, TimeoutError, OSError) as error:
        raise LoopControlRequestError(
            f"live Loop authority control request failed during {phase}",
            delivery_status="NOT_SENT" if phase == "connect" else "OUTCOME_UNKNOWN",
            phase=phase,
            can_start_host=phase == "connect" and isinstance(error, (FileNotFoundError, ConnectionRefusedError)),
        ) from error
    finally:
        if client is not None:
            client.close()
    if b"\n" not in chunks:
        raise LoopControlRequestError(
            "Loop authority returned no complete response",
            delivery_status="OUTCOME_UNKNOWN", phase="response",
        )
    try:
        response = json.loads(bytes(chunks).split(b"\n", 1)[0])
    except (json.JSONDecodeError, UnicodeError) as error:
        raise LoopControlRequestError(
            "Loop authority returned an invalid response",
            delivery_status="OUTCOME_UNKNOWN", phase="response",
        ) from error
    if not isinstance(response, dict) or not isinstance(response.get("status"), str) or not response["status"]:
        raise LoopControlRequestError(
            "Loop authority returned an invalid response",
            delivery_status="OUTCOME_UNKNOWN", phase="response",
        )
    return response


def send_control_input(state_root: str | os.PathLike[str], payload: Mapping[str, Any]) -> dict[str, Any]:
    """Send once, then reconcile an uncertain receipt through a read-only query."""
    from sitina.journal.model import canonical_json_bytes

    request = dict(payload)
    if (
        request.get("command") != "input"
        or any(not isinstance(request.get(key), str) or not request[key] for key in ("task_id", "input_id", "kind"))
        or not isinstance(request.get("body"), str)
    ):
        raise ValueError("input requires task_id, input_id, kind and a string body")
    kind = InputKind(request["kind"])
    body_hash = hashlib.sha256(canonical_json_bytes({
        "schema": "SITINA_LOOP_INPUT_BODY_V1",
        "task_id": request["task_id"],
        "input_id": request["input_id"],
        "kind": kind.value,
        "body": request["body"],
    })).hexdigest()
    identity = {"task_id": request["task_id"], "input_id": request["input_id"]}
    try:
        response = send_control_request(state_root, request)
    except (LoopAuthorityError, OSError) as error:
        failure = {**control_delivery_failure(error), **identity}
        if failure["delivery_status"] == "NOT_SENT":
            return failure
    else:
        if response.get("status") == "accepted":
            return {
                **response, **identity, "delivery_status": "ACCEPTED",
                "receipt_source": "authority_response",
            }
        failure = {
            **control_delivery_failure(LoopControlRequestError(
                "authority did not return an accepted input receipt",
                delivery_status="OUTCOME_UNKNOWN", phase="response",
            )),
            **identity, "authority_response": response,
        }
    try:
        observed = send_control_request(state_root, {"command": "status", **identity})
    except (LoopAuthorityError, OSError) as error:
        failure["reconciliation"] = {"status": "UNAVAILABLE", "reason": str(error)}
        return failure
    receipt = observed.get("input_receipt")
    task = observed.get("task")
    if (
        observed.get("status") == "ok"
        and isinstance(task, Mapping) and task.get("task_id") == request["task_id"]
        and isinstance(receipt, Mapping) and receipt.get("status") == "RECEIVED"
        and receipt.get("task_id") == request["task_id"]
        and receipt.get("input_id") == request["input_id"]
        and receipt.get("kind") == kind.value and receipt.get("body_hash") == body_hash
        and type(receipt.get("sequence")) is int and receipt["sequence"] > 0
        and type(receipt.get("handled")) is bool
    ):
        return {
            "status": "accepted", **identity, "delivery_status": "ACCEPTED",
            "receipt_source": "read_only_reconciliation",
            "input_receipt": dict(receipt), "task": task,
            "original_delivery": failure,
        }
    failure["reconciliation"] = {
        "status": "NOT_CONFIRMED",
        "input_receipt": dict(receipt) if isinstance(receipt, Mapping) else None,
    }
    return failure
