"""Portable, hash-verified evidence bundles with redacted relative paths."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.guards.secrets import scan_json_for_secrets, scan_paths_for_secrets
from sitina.orchestrator.acceptance_report import AcceptanceReportGenerator
from sitina.orchestrator.audit_verify import AuditVerifier
from sitina.orchestrator.checkpoint import CheckpointManager
from sitina.orchestrator.cli_evidence import CliEvidenceRecorder
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.replay import ReplayEngine
from sitina.orchestrator.replay_snapshot import ReplaySnapshotManager
from sitina.orchestrator.run_manifest import RunManifestManager
from sitina.storage import SitinaStore
from sitina.utils import canonicalize_agent_input, file_sha256, iso_now, new_id, read_json, redact_text, sha256_text, stable_json, write_json


class EvidenceBundleManager:
    SCHEMA_VERSION = "1.0"

    @staticmethod
    def legacy_compatibility_claims() -> dict[str, Any]:
        return {
            "classification": "artifact_integrity_verified_compatibility_export",
            "completeness_level": "LEGACY_TERMINAL_MANIFEST",
            "bplus_opt_compliant": False,
            "bplus_sealed": False,
            "portable_relative_paths": True,
            "artifact_hashes_verified": True,
        }

    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.root = home / "outputs" / "evidence" / "bundles"

    def export(self, run_id: str) -> dict[str, Any]:
        timeline = RunLedger(self.home, self.store).timeline(run_id)
        if not timeline:
            return {"status": "incomplete", "run_id": run_id, "reason": "run not found"}
        replay_engine = ReplayEngine(self.home, self.store)
        replay = replay_engine.replay(run_id, record=False)
        simulation = replay_engine.simulate(run_id, record=False).model_dump()
        reports = AcceptanceReportGenerator(self.home)
        live_report = reports.generate_live_report(run_id)
        audit_verify = AuditVerifier(self.home, self.store).verify_evidence(run_id)
        acceptance = reports.generate_acceptance_report(
            run_id,
            live_report=live_report,
            enforce_cli_protocol=False,
            audit_result=audit_verify,
        )
        manifest = RunManifestManager(self.home, self.store).ensure(run_id)
        snapshot_directory = ReplaySnapshotManager(self.home).run_directory(run_id)
        replay_snapshots = [read_json(path, default={}) for path in sorted(snapshot_directory.glob("*.json"))] if snapshot_directory.exists() else []
        checkpoints = [CheckpointManager(self.home).show(str(item["checkpoint_id"])) for item in CheckpointManager(self.home).list(run_id)]
        payloads = {
            "run_manifest.json": manifest,
            "trace.json": RunLedger(self.home, self.store).trace_summary(run_id),
            "ledger.json": timeline,
            "audit.json": AuditVerifier(self.home, self.store)._audit_rows(run_id),
            "audit_verify.json": audit_verify,
            "replay.json": replay.model_dump(),
            "replay_snapshots.json": replay_snapshots,
            "simulate.json": simulation,
            "diff.json": live_report["diff"],
            "proposals.json": replay.proposals,
            "handoff.json": replay.handoff_chain,
            "arbitration.json": replay.arbitrations,
            "lease.json": replay.leases,
            "blackboard.json": replay.blackboard_summary,
            "checkpoints.json": [item for item in checkpoints if item],
            "report_live.json": live_report,
            "report_acceptance.json": acceptance,
            "secret_scan.json": live_report["secret_scan"],
            "code_revision.json": live_report["code_revision"],
            "cli_checks.json": CliEvidenceRecorder(self.home).summary(run_id),
        }
        safe_payloads = {name: self._sanitize(value) for name, value in payloads.items()}
        findings = [finding for value in safe_payloads.values() for finding in scan_json_for_secrets(value, scope="evidence_bundle")]
        if findings:
            return {"status": "failed", "run_id": run_id, "reason": "secret scan blocked evidence export", "secret_findings": len(findings)}
        bundle_id = "evidence_" + new_id()
        directory = self.root / run_id / bundle_id
        for relative, value in safe_payloads.items():
            write_json(directory / relative, value)
        files = [
            {"path": relative, "hash": file_sha256(directory / relative)}
            for relative in sorted(safe_payloads)
        ]
        body = {
            "bundle_id": bundle_id,
            "bundle_schema_version": self.SCHEMA_VERSION,
            "run_id": run_id,
            "created_at": iso_now(),
            "code_revision": live_report["code_revision"],
            "files": files,
            "compatibility_claims": self.legacy_compatibility_claims(),
        }
        bundle_manifest = body | {"evidence_hash": sha256_text(stable_json(body))}
        write_json(directory / "manifest.json", bundle_manifest)
        return {"status": "passed", "run_id": run_id, "bundle_id": bundle_id, "bundle_path": str(directory), "evidence_hash": bundle_manifest["evidence_hash"]}

    def verify(self, bundle: Path | str) -> dict[str, Any]:
        directory = Path(bundle).expanduser().resolve(strict=False)
        manifest = read_json(directory / "manifest.json", default=None)
        if not isinstance(manifest, dict):
            return {"status": "failed", "errors": ["bundle manifest missing"]}
        errors: list[str] = []
        claimed = manifest.get("evidence_hash")
        body = {key: value for key, value in manifest.items() if key != "evidence_hash"}
        if claimed != sha256_text(stable_json(body)):
            errors.append("bundle manifest evidence_hash mismatch")
        for item in manifest.get("files", []):
            relative = item.get("path") if isinstance(item, dict) else None
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                errors.append("bundle contains unsafe relative path")
                continue
            path = directory / relative
            if not path.is_file():
                errors.append(f"bundle file missing: {relative}")
            elif file_sha256(path) != item.get("hash"):
                errors.append(f"bundle file hash mismatch: {relative}")
        listed = {
            str(item.get("path"))
            for item in manifest.get("files", [])
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        actual = {
            path.relative_to(directory).as_posix()
            for path in directory.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        }
        for relative in sorted(actual - listed):
            errors.append(f"bundle contains unlisted file: {relative}")
        if any(path.is_symlink() for path in directory.rglob("*")):
            errors.append("bundle contains symbolic link")
        text_files = [path for path in directory.rglob("*") if path.is_file()]
        for path in text_files:
            text = path.read_text(encoding="utf-8", errors="replace")
            if str(self.home) in text or re.search(r"/Users/[^/\s]+/", text):
                errors.append(f"bundle contains absolute local path: {path.relative_to(directory)}")
        secret_scan = scan_paths_for_secrets([directory], scope="evidence_bundle")
        if secret_scan["count"]:
            errors.append("bundle secret scan failed")
        return {
            "status": "passed" if not errors else "failed",
            "bundle_id": manifest.get("bundle_id"),
            "run_id": manifest.get("run_id"),
            "errors": errors,
            "secret_findings": secret_scan["count"],
        }

    def _sanitize(self, value: Any) -> Any:
        safe = canonicalize_agent_input(value) if isinstance(value, dict) else value
        return self._sanitize_value(safe)

    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): self._sanitize_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        if isinstance(value, str):
            redacted = redact_text(value).replace(str(self.home), "$SITINA_HOME")
            return re.sub(r"/Users/[^/\s]+/", "$USER_HOME/", redacted)
        return value
