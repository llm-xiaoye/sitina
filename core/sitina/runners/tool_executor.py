from __future__ import annotations

import hashlib
import os
import shutil
import shlex
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sitina.constants import SITINA_HOME
from sitina.guards.approvals import ApprovalManager, scope_hash
from sitina.guards.diff import DiffVerifier
from sitina.guards.path_lease import PathLease
from sitina.guards.risk import RiskScanner
from sitina.schemas.models import RiskScanResult
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, isolated_env, normalize_command, sha256_text


_UNSET = object()


@dataclass(frozen=True)
class DirectMutationCapability:
    """Opaque capability minted by this ToolExecutor for one bound mutation."""

    token: str
    run_id: str
    authorization_ref: str
    target_repo: str
    allowed_roots: tuple[str, ...]
    purpose: str
    issued_at: int
    expires_at: int
    allowed_targets: tuple[str, ...] = ()


class ToolExecutor:
    def __init__(
        self,
        home: Path = SITINA_HOME,
        store: SitinaStore | None = None,
        *,
        enforce_write_boundary: bool = False,
        authorization_binding: Mapping[str, Any] | None = None,
        authorization_authority: Any | None = None,
    ):
        self.home = home
        self.store = store or SitinaStore(home)
        self.risk_scanner = RiskScanner(home)
        self.approvals = ApprovalManager(home, self.store)
        self.diff = DiffVerifier()
        # SL1: when true, every write is fail-closed sensitive-content checked
        # BEFORE it touches disk (redact_boundary_value on the content). Opt-in
        # so the execution bridge enforces it without changing other write paths.
        self.enforce_write_boundary = enforce_write_boundary
        self.authorization_binding = dict(authorization_binding or {})
        self.authorization_authority = authorization_authority
        self._direct_capabilities: dict[str, DirectMutationCapability] = {}
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
        cwd: str | None = None,
        allowed_commands: list[str] | None = None,
        approval_id: str | None = None,
        approved_files: list[str] | None = None,
        allowed_roots: list[str] | None = None,
        precomputed_risk_scan: dict[str, Any] | RiskScanResult | None = None,
        expected_before_hash: str | None = _UNSET,
        verified_source_paths: tuple[str, ...] = (),
        capability: DirectMutationCapability | None = None,
    ) -> dict[str, Any]:
        if self.effect_shadow.enabled:
            return {"status": "shadowed", **self.effect_shadow_identity({"operation": operation, "run_id": run_id, "agent": agent, "target": target, "destination": destination, "command": command}), "physical_send_count": 0}
        if operation in {"write", "overwrite", "delete", "move"}:
            capability_error = self._validate_direct_capability(
                capability, target=target or "", run_id=run_id, operation=operation,
                destination=destination,
            )
            if capability_error is not None:
                return {"status": "blocked", "reason": capability_error}
        started = time.time()
        if precomputed_risk_scan:
            scan = precomputed_risk_scan if isinstance(precomputed_risk_scan, RiskScanResult) else RiskScanResult.model_validate(precomputed_risk_scan)
        else:
            scan = self.risk_scanner.scan(
                operation, target=target, command=command,
                allowed_roots=allowed_roots or (
                    list(capability.allowed_roots) if capability is not None else [str(self.home)]
                ),
            )
        try:
            self.store.insert_risk_scan(scan.model_dump(), run_id=run_id)
        except Exception:
            # Disposable extension fixtures may not have the retired SQLite
            # tables.  The risk result is still enforced; a hash-only fallback
            # audit keeps the direct primitive observable without persisting
            # content or allowing the write to fail for an absent legacy table.
            self._write_direct_audit_fallback(run_id, "risk_scan", {
                "risk_scan_id": scan.risk_scan_id,
                "action": scan.action,
            })

        if scan.action == "block":
            self.store.record_audit("tool_blocked", scan.model_dump(), run_id=run_id, agent=agent, risk_scan_id=scan.risk_scan_id, exit_status="blocked")
            return {"status": "blocked", "reason": "risk scanner blocked operation", "risk_scan": scan.model_dump()}

        if scan.approval_required:
            capability_approved = (
                capability is not None
                and approval_id == capability.authorization_ref
                and capability.run_id == run_id
            )
            if not capability_approved:
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
                result = self._write(
                    target, content or "", run_id,
                    expected_before_hash=expected_before_hash,
                    verified_source_paths=verified_source_paths,
                )
            elif operation == "delete":
                result = self._delete(target, run_id, expected_before_hash=expected_before_hash)
            elif operation == "move":
                result = self._move(target, destination, run_id, expected_before_hash=expected_before_hash)
            elif operation == "shell":
                result = self._shell(command or "", allowed_commands or [], run_id, cwd=cwd)
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

    def write_direct(
        self,
        *,
        target: str,
        content: str | bytes,
        run_id: str,
        expected_before_hash: object = _UNSET,
        capability: DirectMutationCapability | None = None,
        verified_source_paths: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Strong write primitive for an already-authorized execution scope.

        The final risk scan and audit remain here as a second boundary.  Only
        hashes and sizes are persisted as patch evidence; file contents never
        enter artifacts, Journal, or CAS through this path.
        """
        capability_error = self._validate_direct_capability(
            capability, target=target, run_id=run_id, operation="write"
        )
        if capability_error is not None:
            return {"status": "blocked", "reason": capability_error}
        assert capability is not None
        scan = self.risk_scanner.scan(
            "write",
            target=target,
            allowed_roots=list(capability.allowed_roots),
        )
        try:
            self.store.insert_risk_scan(scan.model_dump(), run_id=run_id)
        except Exception:
            self._write_direct_audit_fallback(run_id, "risk_scan", {
                "risk_scan_id": scan.risk_scan_id,
                "action": scan.action,
            })
        if scan.action == "block":
            result = {
                "status": "blocked",
                "reason": "risk scanner blocked direct write",
                "risk_scan": scan.model_dump(),
            }
            self._record_direct_audit(
                "tool_direct_write_blocked", result, run_id=run_id,
                risk_scan_id=scan.risk_scan_id, authorization_ref=capability.authorization_ref,
                exit_status="blocked",
            )
            return result
        result = self._write(
            target, content, run_id, expected_before_hash=expected_before_hash,
            verified_source_paths=verified_source_paths,
        )
        result = {"risk_scan": scan.model_dump(), **result}
        self._record_direct_audit(
            "tool_direct_write", {
                "target": str(Path(target).expanduser().resolve(strict=False)),
                "before_hash": result.get("before_hash"),
                "after_hash": result.get("after_hash"),
                "status": result.get("status"),
            }, run_id=run_id, risk_scan_id=scan.risk_scan_id,
            authorization_ref=capability.authorization_ref,
            exit_status=result.get("status"),
        )
        return result

    def _record_direct_audit(
        self, event: str, payload: dict[str, Any], *, run_id: str,
        risk_scan_id: str, authorization_ref: str, exit_status: str | None,
    ) -> None:
        try:
            self.store.record_audit(
                event, payload, run_id=run_id, agent="forge-execution-role",
                risk_scan_id=risk_scan_id, approval_id=authorization_ref,
                exit_status=exit_status,
            )
        except Exception:
            self._write_direct_audit_fallback(run_id, event, {
                **payload, "risk_scan_id": risk_scan_id,
                "authorization_ref": authorization_ref,
                "exit_status": exit_status,
            })

    def _write_direct_audit_fallback(self, run_id: str, event: str, payload: dict[str, Any]) -> None:
        import json
        path = self.home / "artifacts" / "direct-mutation-audit" / f"{run_id}.jsonl"
        ensure_dir(path.parent)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"event": event, **payload}, sort_keys=True) + "\n")

    def _mint_direct_capability(
        self,
        *,
        run_id: str,
        authorization_ref: str,
        target_repo: str,
        allowed_roots: list[str],
        purpose: str,
        allowed_targets: list[str] | None = None,
    ) -> DirectMutationCapability:
        """Mint an opaque capability after the caller's authorization gate."""
        if not all(str(value).strip() for value in (run_id, authorization_ref, target_repo, purpose)):
            raise ValueError("direct mutation capability binding is incomplete")
        if not (
            authorization_ref.startswith("approval-")
            or authorization_ref.startswith("appr_")
            or authorization_ref.startswith("execution-authorization:")
            or authorization_ref.startswith("execution-authorization-child:")
        ):
            raise ValueError("direct mutation capability authorization reference is invalid")
        is_execution_ref = authorization_ref.startswith(
            ("execution-authorization:", "execution-authorization-child:")
        )
        if is_execution_ref and not self.authorization_binding:
            raise ValueError("execution authorization must be bound to the current task")
        repo = Path(target_repo).expanduser().resolve(strict=True)
        roots = tuple(sorted({str(Path(value).expanduser().resolve(strict=True)) for value in allowed_roots}))
        if not roots or any(not (Path(value).is_dir() and not Path(value).is_symlink()) for value in roots):
            raise ValueError("direct mutation capability roots are invalid")
        if not any(repo == Path(value) or Path(value) in repo.parents for value in roots):
            raise ValueError("direct mutation capability repository is outside its roots")
        binding = self.authorization_binding
        if allowed_targets and binding:
            raise ValueError("exact-target grants cannot widen a separately bound execution authorization")
        if binding:
            if is_execution_ref and str(binding.get("schema") or "") != "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1":
                raise ValueError("direct mutation execution authorization is not a Code Mode child")
            if is_execution_ref:
                validator = getattr(self.authorization_authority, "validate_execution_child_authorization", None)
                child_ref = str(binding.get("authorization_ref") or "")
                if not callable(validator) or not validator(
                    binding, run_id=str(run_id), authorization_ref=child_ref
                ):
                    raise ValueError("direct mutation capability child authorization is not issuer-validated")
            outer_ref = str(binding.get("authorization_ref") or "")
            if str(binding.get("run_id") or "") != str(run_id):
                raise ValueError("direct mutation capability run binding mismatch")
            if str(authorization_ref) != outer_ref:
                if not str(authorization_ref).startswith("appr_"):
                    raise ValueError("direct mutation capability authorization binding mismatch")
                approval = self.store.get_approval(str(authorization_ref))
                if not isinstance(approval, Mapping) or str(approval.get("run_id") or "") != str(run_id):
                    raise ValueError("direct mutation capability approval record is unavailable")
            bound_values = binding.get("scope") if isinstance(binding.get("scope"), list) else [binding.get("execution_root") or binding.get("target_repo") or binding.get("workspace")]
            bound_repos = {str(Path(str(value)).expanduser().resolve(strict=True)) for value in bound_values if value}
            if str(repo) not in bound_repos:
                raise ValueError("direct mutation capability target repository mismatch")
            expiry = int(binding.get("expires_at") or 0)
            if expiry <= int(time.time()):
                raise ValueError("direct mutation authorization is expired")
        elif authorization_ref.startswith("appr_"):
            try:
                approval = self.store.get_approval(authorization_ref)
            except Exception:
                approval = None
            if not isinstance(approval, Mapping) or str(approval.get("run_id") or "") != str(run_id):
                raise ValueError("direct mutation capability approval record is unavailable")
        issued_at = int(time.time())
        binding_expiry = int(binding.get("expires_at") or 0) if binding else 0
        if binding_expiry and binding_expiry <= issued_at:
            raise ValueError("direct mutation authorization is expired")
        capability = DirectMutationCapability(
            token=uuid.uuid4().hex,
            run_id=str(run_id),
            authorization_ref=str(authorization_ref),
            target_repo=str(repo),
            allowed_roots=roots,
            purpose=str(purpose),
            issued_at=issued_at,
            expires_at=min(issued_at + 900, binding_expiry) if binding_expiry else issued_at + 900,
            allowed_targets=tuple(sorted({str(Path(item).expanduser().resolve(strict=False)) for item in (allowed_targets or ())})),
        )
        self._direct_capabilities[capability.token] = capability
        return capability

    def _validate_direct_capability(
        self,
        capability: DirectMutationCapability | None,
        *,
        target: str,
        run_id: str,
        operation: str,
        destination: str | None = None,
    ) -> str | None:
        if not isinstance(capability, DirectMutationCapability):
            return "direct mutation capability required"
        if self._direct_capabilities.get(capability.token) is not capability:
            return "direct mutation capability is not owned by this executor"
        if capability.run_id != str(run_id) or not capability.authorization_ref:
            return "direct mutation capability run binding mismatch"
        now = int(time.time())
        if capability.issued_at > now or capability.expires_at <= now:
            return "direct mutation capability is expired"
        binding = self.authorization_binding
        if binding:
            is_execution_ref = capability.authorization_ref.startswith(
                ("execution-authorization:", "execution-authorization-child:")
            )
            if is_execution_ref and str(binding.get("schema") or "") != "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1":
                return "direct mutation execution authorization is not a Code Mode child"
            if is_execution_ref:
                validator = getattr(self.authorization_authority, "validate_execution_child_authorization", None)
                child_ref = str(binding.get("authorization_ref") or "")
                if not callable(validator) or not validator(
                    binding, run_id=capability.run_id, authorization_ref=child_ref
                ):
                    return "direct mutation child authorization is not issuer-validated"
            if str(binding.get("run_id") or "") != capability.run_id:
                return "direct mutation capability authorization run mismatch"
            outer_ref = str(binding.get("authorization_ref") or "")
            if capability.authorization_ref != outer_ref:
                if not capability.authorization_ref.startswith("appr_"):
                    return "direct mutation capability authorization object mismatch"
                try:
                    approval = self.store.get_approval(capability.authorization_ref)
                except Exception:
                    approval = None
                if not isinstance(approval, Mapping) or str(approval.get("run_id") or "") != capability.run_id:
                    return "direct mutation capability approval record is unavailable"
            if int(binding.get("expires_at") or 0) <= now:
                return "direct mutation authorization object is expired"
            bound_values = binding.get("scope") if isinstance(binding.get("scope"), list) else [binding.get("execution_root") or binding.get("target_repo") or binding.get("workspace")]
            bound_repos = {str(Path(str(value)).expanduser().resolve(strict=False)) for value in bound_values if value}
            if capability.target_repo not in bound_repos:
                return "direct mutation capability target repository mismatch"
        elif capability.authorization_ref.startswith("appr_"):
            try:
                approval = self.store.get_approval(capability.authorization_ref)
            except Exception:
                approval = None
            if not isinstance(approval, Mapping) or str(approval.get("run_id") or "") != capability.run_id:
                return "direct mutation capability approval record is unavailable"
        path = Path(target).expanduser().resolve(strict=False)
        repo = Path(capability.target_repo)
        if capability.allowed_targets and str(path) not in capability.allowed_targets:
            return "direct mutation target is not an authorized exact target"
        if not capability.allowed_targets and not (path == repo or repo in path.parents):
            return "direct mutation target does not match target_repo binding"
        if not any(path == Path(root) or Path(root) in path.parents for root in capability.allowed_roots):
            return f"direct {operation} target escapes capability scope"
        if destination is not None:
            destination_path = Path(destination).expanduser().resolve(strict=False)
            if capability.allowed_targets and str(destination_path) not in capability.allowed_targets:
                return "direct mutation destination is not an authorized exact target"
            if not capability.allowed_targets and not (destination_path == repo or repo in destination_path.parents):
                return "direct mutation destination does not match target_repo binding"
            if not any(destination_path == Path(root) or Path(root) in destination_path.parents for root in capability.allowed_roots):
                return f"direct {operation} destination escapes capability scope"
        return None

    def _read(self, target: str | None) -> dict[str, Any]:
        if not target:
            return {"status": "blocked", "reason": "read target required"}
        path = Path(target).expanduser()
        return {"status": "ok", "content": path.read_text(encoding="utf-8")}

    def _write(
        self, target: str | None, content: str | bytes, run_id: str, *,
        expected_before_hash: object = _UNSET, verified_source_paths: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        if not target:
            return {"status": "blocked", "reason": "write target required", "effect_dispatched": False}
        if not isinstance(content, (str, bytes)):
            return {"status": "blocked", "reason": "write content is invalid", "effect_dispatched": False}
        binary = isinstance(content, bytes)
        content_bytes = content if binary else content.encode("utf-8")
        # SL1 pre-write hard gate: reject sensitive content BEFORE it reaches
        # disk. Fail-closed, no mutation of content, no write-then-scan.
        if self.enforce_write_boundary:
            from sitina.security.redaction import redact_boundary_value
            boundary = redact_boundary_value(
                content.decode("utf-8", errors="surrogateescape") if binary else content,
                boundary="write", verified_source_paths=verified_source_paths,
            )
            if boundary.redacted_paths:
                return {
                    "status": "blocked",
                    "reason": "write blocked: sensitive content at persistence boundary",
                    "effect_dispatched": False,
                    "redacted_paths": list(boundary.redacted_paths),
                }
        path = Path(target).expanduser()
        ensure_dir(path.parent)
        before = self.diff.before_hash(path)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "effect_dispatched": False, "expected_before_hash": expected_before_hash, "actual_before_hash": before}
        patch_id = sha256_text(f"{run_id}\n{path}\n{before}\n{content}")
        patch_path = self.home / "artifacts" / "patches" / f"{patch_id.split(':', 1)[1]}.json"
        ensure_dir(patch_path.parent)
        with PathLease(path, run_id, self.home):
            if before != self.diff.before_hash(path):
                return {"status": "blocked", "reason": "before_hash changed before write", "effect_dispatched": False}
            fd, temporary = tempfile.mkstemp(prefix=".sitina-write-", dir=path.parent)
            tmp = Path(temporary)
            try:
                with os.fdopen(fd, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as handle:
                    handle.write(content)
                    if path.exists():
                        os.fchmod(handle.fileno(), stat.S_IMODE(path.stat().st_mode))
                    handle.flush()
                    os.fsync(handle.fileno())
                if before != self.diff.before_hash(path):
                    tmp.unlink()
                    return {"status": "blocked", "reason": "before_hash changed before replacement", "effect_dispatched": False}
                tmp.replace(path)
            except Exception:
                if tmp.exists():
                    tmp.unlink()
                raise
        after = self.diff.before_hash(path)
        patch_path.write_text(
            __import__("json").dumps(
                {
                    "schema": "SITINA_SAFE_PATCH_EVIDENCE_V2",
                    "patch_id": patch_id,
                    "run_id": run_id,
                    "path": str(path),
                    "before_hash": before,
                    "after_hash": after,
                    "content_sha256": "sha256:" + hashlib.sha256(content_bytes).hexdigest(),
                    "content_bytes": len(content_bytes),
                },
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        return {"status": "ok", "patch_id": patch_id, "before_hash": before, "after_hash": after}

    def _delete(
        self, target: str | None, run_id: str,
        *, expected_before_hash: object = _UNSET,
    ) -> dict[str, Any]:
        if not target:
            return {"status": "blocked", "reason": "delete target required"}
        path = Path(target).expanduser()
        before = self.diff.before_hash(path)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "before_hash": before}
        if path.is_symlink() or (path.exists() and not path.is_file()):
            return {"status": "blocked", "reason": "delete target is not a regular file"}
        with PathLease(path, run_id, self.home):
            if before != self.diff.before_hash(path):
                return {"status": "blocked", "reason": "before_hash changed before delete"}
            if not path.exists():
                return {"status": "ok", "note": "already absent", "before_hash": before}
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        return {"status": "ok", "before_hash": before, "after_hash": None}

    def _move(
        self, target: str | None, destination: str | None, run_id: str,
        *, expected_before_hash: object = _UNSET,
    ) -> dict[str, Any]:
        if not target or not destination:
            return {"status": "blocked", "reason": "move target and destination required"}
        src = Path(target).expanduser()
        dst = Path(destination).expanduser()
        before = self.diff.before_hash(src)
        if expected_before_hash is not _UNSET and before != expected_before_hash:
            return {"status": "blocked", "reason": "before_hash mismatch", "before_hash": before}
        if src.is_symlink() or not src.is_file() or dst.is_symlink() or dst.exists():
            return {"status": "blocked", "reason": "move requires regular source and absent destination"}
        ensure_dir(dst.parent)
        with PathLease(src, run_id, self.home), PathLease(dst, run_id, self.home):
            if before != self.diff.before_hash(src):
                return {"status": "blocked", "reason": "before_hash changed before move"}
            shutil.move(str(src), str(dst))
        return {
            "status": "ok", "from": str(src), "to": str(dst), "path": str(src),
            "destination": str(dst), "before_hash": before,
            "after_hash": self.diff.before_hash(dst),
        }

    def _shell(self, command: str, allowed_commands: list[str], run_id: str, *, cwd: str | None = None) -> dict[str, Any]:
        normalized = normalize_command(command)
        if not any(normalized == normalize_command(item) or normalized.startswith(normalize_command(item) + " ") for item in allowed_commands):
            return {"status": "blocked", "reason": "command not in allowed_commands"}
        if "\x00" in command or "\n" in command or "\r" in command:
            return {"status": "blocked", "reason": "shell command contains forbidden control bytes"}
        try:
            argv = shlex.split(command)
        except ValueError:
            return {"status": "blocked", "reason": "shell command quoting is invalid"}
        if not argv:
            return {"status": "blocked", "reason": "shell command is empty"}
        workdir = Path(cwd or self.home).expanduser().resolve(strict=True)
        proc = subprocess.run(argv, shell=False, capture_output=True, text=True, env=isolated_env(), cwd=str(workdir), timeout=60)
        output_dir = self.home / "artifacts" / "command_outputs" / run_id
        ensure_dir(output_dir)
        out_path = output_dir / (sha256_text(command).split(":", 1)[1] + ".txt")
        from sitina.security.redaction import redact_text
        out_path.write_text(redact_text(proc.stdout + proc.stderr), encoding="utf-8")
        return {"status": "ok" if proc.returncode == 0 else "failed", "exit_code": proc.returncode, "artifact_path": str(out_path)}


def json_quote(value: str) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)
