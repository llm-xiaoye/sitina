from __future__ import annotations

import json
import shutil
import tarfile
import datetime as dt
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.guards.approvals import ApprovalManager
from sitina.guards.risk import RiskScanner
from sitina.storage import SitinaStore
from sitina.orchestrator.baseline import BaselineManager
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.evidence_bundle import EvidenceBundleManager
from sitina.utils import ensure_dir, file_sha256, iso_now, new_id, read_json, sha256_text, stable_json, write_json


class MaintenanceOps:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.risk = RiskScanner(home)
        self.approvals = ApprovalManager(home, self.store)

    def approve_builtin(self, *, operation: str, target: str, run_id: str = "maintenance") -> dict[str, Any]:
        scan = self.risk.scan(operation, target=target, allowed_roots=[str(self.home)])
        self.store.insert_risk_scan(scan.model_dump(), run_id=run_id)
        approval = self.approvals.create(
            run_id=run_id,
            action="approve",
            risk_scan=scan,
            plan_hash=sha256_text(stable_json({"operation": operation, "target": target})),
            approved_touched_files=[target],
            approved_commands=[],
        )
        return {"approval": approval.model_dump(), "risk_scan": scan.model_dump()}

    def rollback_run(self, run_id: str, *, approve_now: bool = False) -> dict[str, Any]:
        patch_files = sorted((self.home / "artifacts" / "patches").glob("*.json"), reverse=True)
        patches: list[dict[str, Any]] = []
        for path in patch_files:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if payload.get("run_id") == run_id:
                patches.append(payload)
        if not approve_now:
            scan = self.risk.scan("rollback", target=str(self.home / "artifacts" / "patches" / run_id), allowed_roots=[str(self.home)])
            self.store.insert_risk_scan(scan.model_dump(), run_id=run_id)
            return {"status": "blocked", "reason": "rollback requires approval", "risk_scan": scan.model_dump()}
        approval_ctx = self.approve_builtin(operation="rollback", target=str(self.home / "artifacts" / "patches" / run_id), run_id=run_id)
        restored: list[dict[str, Any]] = []
        for patch in patches:
            target = Path(patch["path"])
            before_content = patch.get("before_content")
            before_hash = patch.get("before_hash")
            ensure_dir(target.parent)
            if before_content is None:
                if target.exists():
                    target.unlink()
                after = None
            else:
                target.write_text(before_content, encoding="utf-8")
                after = file_sha256(target)
            restored.append({"path": str(target), "expected_before_hash": before_hash, "after_rollback_hash": after})
        self.store.record_audit("rollback", {"run_id": run_id, "restored": restored}, run_id=run_id, approval_id=approval_ctx["approval"]["approval_id"], risk_scan_id=approval_ctx["risk_scan"]["risk_scan_id"], exit_status="ok")
        return {"status": "ok", "run_id": run_id, "approval_id": approval_ctx["approval"]["approval_id"], "restored": restored}

    def prune(
        self,
        *,
        older_than_days: int = 30,
        dry_run: bool = True,
        archive: bool = False,
        approve_now: bool = False,
    ) -> dict[str, Any]:
        if older_than_days < 0:
            raise ValueError("older_than_days must be non-negative")
        if archive:
            dry_run = False
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=older_than_days)
        baseline_runs = self._baseline_run_ids()
        acceptance_runs = self._acceptance_run_ids()
        registry = self._archive_registry()
        archived_runs = registry.get("archived_runs", {}) if isinstance(registry.get("archived_runs"), dict) else {}
        candidates: list[dict[str, Any]] = []
        for run in self.store.list_runs(limit=None):
            updated_at = self._parse_time(run.get("updated_at"))
            if updated_at is None or updated_at >= cutoff:
                continue
            run_id = str(run["run_id"])
            protections: list[str] = []
            if run_id in baseline_runs:
                protections.append("baseline_run")
            if run_id in acceptance_runs:
                protections.append("acceptance_report_reference")
            if run_id in archived_runs:
                protections.append("already_archived")
            bundle = self._verified_evidence_bundle(run_id)
            if bundle is None:
                protections.append("verified_evidence_bundle_required")
            candidates.append(
                {
                    "run_id": run_id,
                    "updated_at": run.get("updated_at"),
                    "verified_evidence_bundle": bundle,
                    "protections": protections,
                    "archive_eligible": not protections,
                }
            )
        archived_now: list[dict[str, Any]] = []
        if archive:
            for candidate in candidates:
                if not candidate["archive_eligible"]:
                    continue
                entry = {
                    "run_id": candidate["run_id"],
                    "archived_at": iso_now(),
                    "evidence_bundle": candidate["verified_evidence_bundle"],
                    "older_than_days": older_than_days,
                    "archive_type": "metadata_only",
                }
                archived_runs[candidate["run_id"]] = entry
                archived_now.append(entry)
            registry.update({"schema_version": "1.0", "archived_runs": archived_runs, "updated_at": iso_now()})
            write_json(self.archive_registry_path, registry)
            self.store.record_audit(
                "prune_archive",
                {"older_than_days": older_than_days, "archived_runs": [item["run_id"] for item in archived_now], "permanent_delete": False, "vacuum_performed": False},
                exit_status="ok",
            )
        return {
            "status": "ok",
            "mode": "archive" if archive else "dry_run",
            "dry_run": bool(dry_run),
            "archive_requested": bool(archive),
            "older_than_days": older_than_days,
            "candidate_count": len(candidates),
            "eligible_candidate_count": sum(1 for item in candidates if item["archive_eligible"]),
            "candidates": candidates,
            "archived_count": len(archived_now),
            "archived_runs": archived_now,
            "checkpoint_orphans": self._checkpoint_orphans(),
            "permanent_delete": False,
            "deleted_run_count": 0,
            "deleted_files": [],
            "vacuum_performed": False,
            "vacuum_requires_explicit_future_confirmation": True,
            "approval_flag_ignored_for_non_destructive_archive": bool(approve_now),
        }

    @property
    def archive_registry_path(self) -> Path:
        return self.home / "state" / "run_archive_registry.json"

    def _archive_registry(self) -> dict[str, Any]:
        value = read_json(self.archive_registry_path, default=None)
        return value if isinstance(value, dict) else {"schema_version": "1.0", "archived_runs": {}}

    def _baseline_run_ids(self) -> set[str]:
        return {
            str(run_id)
            for manifest in BaselineManager(self.home).manifests()
            if BaselineManager.verify(manifest)
            for run_id in (manifest.get("run_ids") or {}).values()
            if run_id
        }

    def _acceptance_run_ids(self) -> set[str]:
        run_ids: set[str] = set()
        directory = self.home / "outputs" / "reports" / "acceptance"
        if not directory.exists():
            return run_ids
        for path in directory.glob("*.json"):
            report = read_json(path, default=None)
            if not isinstance(report, dict):
                continue
            if report.get("run_id"):
                run_ids.add(str(report["run_id"]))
            values = report.get("run_ids")
            if isinstance(values, list):
                run_ids.update(str(value) for value in values if value)
            elif isinstance(values, dict):
                run_ids.update(str(value) for value in values.values() if value)
        return run_ids

    def _verified_evidence_bundle(self, run_id: str) -> str | None:
        root = self.home / "outputs" / "evidence" / "bundles" / run_id
        if not root.exists():
            return None
        manager = EvidenceBundleManager(self.home, self.store)
        for directory in sorted((path for path in root.iterdir() if path.is_dir()), reverse=True):
            result = manager.verify(directory)
            if result.get("status") == "passed" and result.get("run_id") == run_id:
                return str(directory.relative_to(self.home))
        return None

    def _checkpoint_orphans(self) -> dict[str, Any]:
        manager = CheckpointManager(self.home)
        index = read_json(manager.index_path, default={}) or {}
        indexed = {
            str(item.get("checkpoint_id"))
            for item in index.get("checkpoints", [])
            if isinstance(item, dict) and item.get("checkpoint_id")
        }
        files = {path.stem for path in manager.directory.glob("checkpoint_*.json")} if manager.directory.exists() else set()
        return {
            "indexed_missing_files": sorted(indexed - files),
            "unindexed_files": sorted(files - indexed),
            "checked_only": True,
        }

    @staticmethod
    def _parse_time(value: Any) -> dt.datetime | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)

    def restore(self, archive: str, *, approve_now: bool = False, apply: bool = False) -> dict[str, Any]:
        archive_path = Path(archive).expanduser()
        if not approve_now:
            scan = self.risk.scan("restore", target=str(archive_path), allowed_roots=[str(self.home)])
            self.store.insert_risk_scan(scan.model_dump())
            return {"status": "blocked", "reason": "restore requires approval", "risk_scan": scan.model_dump()}
        approval_ctx = self.approve_builtin(operation="restore", target=str(archive_path))
        restore_id = "restore_" + new_id()
        extract_dir = self.home / "artifacts" / "restores" / restore_id
        ensure_dir(extract_dir)
        with tarfile.open(archive_path, "r:gz") as tar:
            self._safe_extract(tar, extract_dir)
        applied: list[str] = []
        if apply:
            for rel in ("config", "schemas", "prompts"):
                src = extract_dir / rel
                dst = self.home / rel
                if src.exists():
                    if dst.exists():
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                    applied.append(rel)
        self.store.record_audit("restore", {"archive": str(archive_path), "extract_dir": str(extract_dir), "applied": applied}, approval_id=approval_ctx["approval"]["approval_id"], risk_scan_id=approval_ctx["risk_scan"]["risk_scan_id"], exit_status="ok")
        return {"status": "ok", "approval_id": approval_ctx["approval"]["approval_id"], "extract_dir": str(extract_dir), "applied": applied, "apply": apply}

    def _safe_extract(self, tar: tarfile.TarFile, destination: Path) -> None:
        dest = destination.resolve()
        for member in tar.getmembers():
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest) + "/") and target != dest:
                raise ValueError(f"tar path escape blocked: {member.name}")
            lower = member.name.lower()
            if lower.endswith(".env") or "token" in lower or "secret" in lower:
                continue
            tar.extract(member, dest)
