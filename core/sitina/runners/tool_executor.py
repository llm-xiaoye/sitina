from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.guards.approvals import ApprovalManager, scope_hash
from sitina.guards.diff import DiffVerifier
from sitina.guards.path_lease import PathLease
from sitina.guards.risk import RiskScanner
from sitina.schemas.models import RiskScanResult
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, isolated_env, normalize_command, sha256_text


_UNSET = object()


class ToolExecutor:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.risk_scanner = RiskScanner(home)
        self.approvals = ApprovalManager(home, self.store)
        self.diff = DiffVerifier()
        from sitina.effects.legacy_adapters import ShadowEffectBridge
        self.effect_shadow = ShadowEffectBridge.from_environment()

    def effect_shadow_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        from sitina.effects.legacy_adapters import LegacyAdapterKind
        return self.effect_shadow.identity(LegacyAdapterKind.TOOL, payload)

    def execute(
        self,
        *,
        operation: str,
        run_id: str,
        agent: str,
        target: str | None = None,
        content: str | None = None,
        destination: str | None = None,
        command: str | None = None,
        allowed_commands: list[str] | None = None,
        approval_id: str | None = None,
        approved_files: list[str] | None = None,
        allowed_roots: list[str] | None = None,
        precomputed_risk_scan: dict[str, Any] | RiskScanResult | None = None,
        expected_before_hash: str | None = _UNSET,
    ) -> dict[str, Any]:
        if self.effect_shadow.enabled:
            return {"status": "shadowed", **self.effect_shadow_identity({"operation": operation, "run_id": run_id, "agent": agent, "target": target, "destination": destination, "command": command}), "physical_send_count": 0}
        started = time.time()
        if precomputed_risk_scan:
            scan = precomputed_risk_scan if isinstance(precomputed_risk_scan, RiskScanResult) else RiskScanResult.model_validate(precomputed_risk_scan)
        else:
            scan = self.risk_scanner.scan(operation, target=target, command=command, allowed_roots=allowed_roots or [str(self.home)])
        self.store.insert_risk_scan(scan.model_dump(), run_id=run_id)

        if scan.action == "block":
            self.store.record_audit("tool_blocked", scan.model_dump(), run_id=run_id, agent=agent, risk_scan_id=scan.risk_scan_id, exit_status="blocked")
            return {"status": "blocked", "reason": "risk scanner blocked operation", "risk_scan": scan.model_dump()}

        if scan.approval_required:
            required_scope = scope_hash(approved_files or ([target] if target else []), allowed_commands or [])
            ok, reason = self.approvals.validate(
                approval_id=approval_id,
                run_id=run_id,
                risk_scan=scan,
                required_scope_hash=required_scope,
                risk_action=scan.action,
            )
            if not ok:
                self.store.record_audit("tool_approval_rejected", {"reason": reason, "scan": scan.model_dump()}, run_id=run_id, agent=agent, risk_scan_id=scan.risk_scan_id, approval_id=approval_id, exit_status="blocked")
                return {"status": "blocked", "reason": reason, "risk_scan": scan.model_dump()}

        try:
            if operation == "read":
                result = self._read(target)
            elif operation in {"write", "overwrite"}:
                result = self._write(target, content or "", run_id, expected_before_hash=expected_before_hash)
            elif operation == "delete":
                result = self._delete(target, run_id)
            elif operation == "move":
                result = self._move(target, destination, run_id)
            elif operation == "shell":
                result = self._shell(command or "", allowed_commands or [], run_id)
            else:
                result = {"status": "blocked", "reason": f"operation not implemented for direct execution: {operation}"}
        except Exception as exc:  # noqa: BLE001
            result = {"status": "dirty" if operation in {"write", "overwrite", "delete", "move"} else "error", "reason": str(exc)}

        duration_ms = int((time.time() - started) * 1000)
        self.store.record_audit(
            "tool_call",
            {"operation": operation, "target": target, "command": command, "result": result},
            run_id=run_id,
            agent=agent,
            risk_scan_id=scan.risk_scan_id,
            approval_id=approval_id,
            exit_status=result.get("status"),
            duration_ms=duration_ms,
        )
        return {"risk_scan": scan.model_dump(), **result}

    def _read(self, target: str | None) -> dict[str, Any]:
        if not target:
            return {"status": "blocked", "reason": "read target required"}
        path = Path(target).expanduser()
        return {"status": "ok", "content": path.read_text(encoding="utf-8")}

    def _write(self, target: str | None, content: str, run_id: str, *, expected_before_hash: object = _UNSET) -> dict[str, Any]:
        if not target:
            return {"status": "blocked", "reason": "write target required"}
        path = Path(target).expanduser()
        ensure_dir(path.parent)
        before = self.diff.before_hash(path)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "expected_before_hash": expected_before_hash, "actual_before_hash": before}
        before_content = path.read_text(encoding="utf-8") if path.exists() and path.is_file() else None
        patch_id = sha256_text(f"{run_id}\n{path}\n{before}\n{content}")
        patch_path = self.home / "artifacts" / "patches" / f"{patch_id.split(':', 1)[1]}.json"
        with PathLease(path, run_id, self.home):
            if before != self.diff.before_hash(path):
                return {"status": "blocked", "reason": "before_hash changed before write"}
            tmp = path.with_suffix(path.suffix + ".sitina-tmp")
            try:
                tmp.write_text(content, encoding="utf-8")
                tmp.replace(path)
            except Exception:
                if tmp.exists():
                    tmp.unlink()
                raise
        patch_path.write_text(
            (
                "{\n"
                f'  "patch_id": "{patch_id}",\n'
                f'  "run_id": "{run_id}",\n'
                f'  "path": "{str(path)}",\n'
                f'  "before_hash": {("null" if before is None else json_quote(before))},\n'
                f'  "after_hash": "{self.diff.before_hash(path)}",\n'
                f'  "before_content": {("null" if before_content is None else json_quote(before_content))},\n'
                f'  "after_content": {json_quote(content)}\n'
                "}\n"
            ),
            encoding="utf-8",
        )
        return {"status": "ok", "patch_id": patch_id, "before_hash": before, "after_hash": self.diff.before_hash(path)}

    def _delete(self, target: str | None, run_id: str) -> dict[str, Any]:
        if not target:
            return {"status": "blocked", "reason": "delete target required"}
        path = Path(target).expanduser()
        before = self.diff.before_hash(path)
        with PathLease(path, run_id, self.home):
            if not path.exists():
                return {"status": "ok", "note": "already absent", "before_hash": before}
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        return {"status": "ok", "before_hash": before, "after_hash": None}

    def _move(self, target: str | None, destination: str | None, run_id: str) -> dict[str, Any]:
        if not target or not destination:
            return {"status": "blocked", "reason": "move target and destination required"}
        src = Path(target).expanduser()
        dst = Path(destination).expanduser()
        ensure_dir(dst.parent)
        with PathLease(src, run_id, self.home), PathLease(dst, run_id, self.home):
            shutil.move(str(src), str(dst))
        return {"status": "ok", "from": str(src), "to": str(dst)}

    def _shell(self, command: str, allowed_commands: list[str], run_id: str) -> dict[str, Any]:
        normalized = normalize_command(command)
        if not any(normalized == normalize_command(item) or normalized.startswith(normalize_command(item) + " ") for item in allowed_commands):
            return {"status": "blocked", "reason": "command not in allowed_commands"}
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, env=isolated_env(), cwd=str(self.home), timeout=60)
        output_dir = self.home / "artifacts" / "command_outputs" / run_id
        ensure_dir(output_dir)
        out_path = output_dir / (sha256_text(command).split(":", 1)[1] + ".txt")
        out_path.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        return {"status": "ok" if proc.returncode == 0 else "failed", "exit_code": proc.returncode, "artifact_path": str(out_path)}


def json_quote(value: str) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)
