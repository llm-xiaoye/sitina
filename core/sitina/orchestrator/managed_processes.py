"""Managed background processes owned by one Sitina execution run."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from sitina.security.redaction import isolated_env, redact_text


class ManagedProcessError(RuntimeError):
    pass


class ManagedProcessManager:
    """Owns process handles, PID metadata and redacted log files for a run."""

    _LIVE_HANDLES: dict[int, subprocess.Popen[str]] = {}

    def __init__(
        self,
        home: Path,
        *,
        workspace: Path,
        run_id: str,
        audit: Callable[[str, Mapping[str, Any]], None] | None = None,
        allow_keep: bool = False,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        self.workspace = Path(workspace).expanduser().resolve(strict=True)
        if not self.workspace.is_dir() or self.workspace.is_symlink():
            raise ManagedProcessError("managed process workspace must be a real directory")
        self.run_id = str(run_id)
        self.audit = audit
        self.allow_keep = bool(allow_keep)
        self.root = self.home / "artifacts" / "managed-processes" / self.run_id
        self.root.mkdir(parents=True, exist_ok=True)
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def _emit(self, event: str, payload: Mapping[str, Any]) -> None:
        safe = {key: redact_text(str(value)) if isinstance(value, str) else value for key, value in payload.items()}
        if self.audit is not None:
            self.audit(event, safe)
        else:
            path = self.root / "audit.jsonl"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"event": event, **safe}, ensure_ascii=False, sort_keys=True) + "\n")

    def _resolve_cwd(self, cwd: str | None) -> Path:
        candidate = (self.workspace / (cwd or ".")).resolve(strict=True) if not Path(cwd or ".").is_absolute() else Path(cwd).expanduser().resolve(strict=True)
        try:
            candidate.relative_to(self.workspace)
        except ValueError:
            raise ManagedProcessError("managed process cwd escapes execution workspace") from None
        return candidate

    def start(self, command: Sequence[str] | str, *, cwd: str | None = None, keep: bool = False) -> dict[str, Any]:
        if isinstance(command, str):
            raise ManagedProcessError("managed process start requires argv array, not a shell string")
        argv = [str(item) for item in command]
        if not argv or any(not item.strip() for item in argv):
            raise ManagedProcessError("managed process command is empty")
        if keep and not self.allow_keep:
            raise ManagedProcessError("keeping a managed process requires explicit keep authorization")
        workdir = self._resolve_cwd(cwd)
        process_id = "process-" + uuid.uuid4().hex
        log_path = self.root / f"{process_id}.log"
        metadata_path = self.root / f"{process_id}.json"
        try:
            # The caller has already passed ToolCatalog's scoped shell risk
            # gate. This narrow fence context is the only route by which a
            # bound managed process may cross the frozen Legacy subprocess
            # guard; it does not authorize an arbitrary shell or host cwd.
            from sitina.legacy.fence import authorized_extension_effect
            with authorized_extension_effect(
                permission="shell", approval_granted=True,
                purpose="sitina-managed-process-start",
            ):
                process = subprocess.Popen(
                    argv,
                    cwd=str(workdir),
                    env=isolated_env(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                )
        except Exception:
            raise

        def drain_log() -> None:
            assert process.stdout is not None
            with log_path.open("a", encoding="utf-8") as handle:
                for line in process.stdout:
                    handle.write(redact_text(line))
                    handle.flush()
            process.stdout.close()

        threading.Thread(target=drain_log, name=f"sitina-managed-log-{process.pid}", daemon=True).start()
        metadata = {
            "schema": "SITINA_MANAGED_PROCESS_V1",
            "process_id": process_id,
            "run_id": self.run_id,
            "pid": int(process.pid),
            "command": [redact_text(item) for item in argv],
            "cwd": str(workdir),
            "log_path": str(log_path),
            "metadata_path": str(metadata_path),
            "keep": bool(keep),
            "started_at": time.time(),
        }
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        self._processes[process_id] = process
        self._LIVE_HANDLES[int(process.pid)] = process
        self._metadata[process_id] = metadata
        self._emit("managed_process_started", {key: value for key, value in metadata.items() if key != "metadata_path"})
        return self.status(process_id)

    def _load(self, process_id: str) -> dict[str, Any]:
        if process_id in self._metadata:
            return self._metadata[process_id]
        path = self.root / f"{process_id}.json"
        if not path.is_file():
            raise ManagedProcessError("managed process was not found")
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("run_id") != self.run_id:
            raise ManagedProcessError("managed process belongs to another run")
        self._metadata[process_id] = value
        return value

    def status(self, process_id: str) -> dict[str, Any]:
        metadata = self._load(process_id)
        handle = self._processes.get(process_id)
        if handle is None:
            handle = self._LIVE_HANDLES.get(int(metadata["pid"]))
            if handle is not None:
                self._processes[process_id] = handle
        returncode = handle.poll() if handle is not None else None
        if returncode is None and handle is None:
            try:
                os.kill(int(metadata["pid"]), 0)
                state = "running"
            except OSError:
                state = "stopped"
        else:
            state = "running" if returncode is None else "stopped"
        result = {**metadata, "state": state, "returncode": returncode}
        self._emit("managed_process_status", {"process_id": process_id, "state": state, "returncode": returncode})
        return result

    def log(self, process_id: str, *, tail_lines: int = 200) -> dict[str, Any]:
        metadata = self._load(process_id)
        limit = max(1, min(int(tail_lines), 2000))
        path = Path(str(metadata["log_path"])).resolve(strict=True)
        try:
            path.relative_to(self.root)
        except ValueError:
            raise ManagedProcessError("managed process log escapes its run root") from None
        text = path.read_text(encoding="utf-8", errors="replace")
        result = {"process_id": process_id, "log_path": str(path), "text": redact_text("".join(text.splitlines(True)[-limit:]))}
        self._emit("managed_process_log_read", {"process_id": process_id, "line_limit": limit})
        return result

    def stop(self, process_id: str, *, timeout_seconds: float = 5.0) -> dict[str, Any]:
        metadata = self._load(process_id)
        handle = self._processes.get(process_id)
        pid = int(metadata["pid"])
        if handle is None:
            handle = self._LIVE_HANDLES.get(pid)
            if handle is not None:
                self._processes[process_id] = handle
        deadline = time.monotonic() + max(0.1, float(timeout_seconds))

        def alive() -> bool:
            try:
                os.kill(pid, 0)
            except OSError:
                return False
            return True

        if handle is not None and handle.poll() is not None:
            self._LIVE_HANDLES.pop(pid, None)
            state = self.status(process_id)
            if state.get("state") == "stopped":
                self._emit("managed_process_stopped", {"process_id": process_id, "pid": pid, "already_stopped": True})
                return state
        try:
            os.killpg(pid, signal.SIGTERM)
        except OSError:
            # A stale PID is safe only after an explicit liveness check below.
            pass
        while alive() and time.monotonic() < deadline:
            if handle is not None:
                try:
                    handle.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
            else:
                time.sleep(0.1)
        if alive():
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            kill_deadline = time.monotonic() + 2.0
            while alive() and time.monotonic() < kill_deadline:
                time.sleep(0.05)
        if alive():
            raise ManagedProcessError(f"managed process {process_id} did not stop")
        self._LIVE_HANDLES.pop(pid, None)
        self._emit("managed_process_stopped", {"process_id": process_id, "pid": metadata.get("pid")})
        result = self.status(process_id)
        if result.get("state") != "stopped":
            raise ManagedProcessError(f"managed process {process_id} stop could not be verified")
        return result

    def cleanup(self) -> dict[str, Any]:
        stopped: list[str] = []
        kept: list[str] = []
        failures: list[dict[str, Any]] = []
        known = set(self._metadata) | set(self._processes)
        for metadata_path in self.root.glob("process-*.json"):
            known.add(metadata_path.stem)
        for process_id in sorted(known):
            metadata = self._load(process_id)
            if bool(metadata.get("keep")):
                kept.append(process_id)
                continue
            try:
                result = self.stop(process_id)
                if result.get("state") != "stopped":
                    raise ManagedProcessError("stop did not verify a stopped state")
            except ManagedProcessError as error:
                failures.append({"process_id": process_id, "error_type": type(error).__name__})
            else:
                stopped.append(process_id)
        self._emit("managed_process_cleanup", {"stopped": stopped, "kept": kept, "failures": failures})
        if failures:
            raise ManagedProcessError("managed process cleanup failed for " + ",".join(item["process_id"] for item in failures))
        return {"run_id": self.run_id, "stopped": stopped, "kept": kept, "failures": failures}


__all__ = ["ManagedProcessError", "ManagedProcessManager"]
