from __future__ import annotations

import datetime as dt
from pathlib import Path

from sitina.constants import SITINA_HOME
from sitina.schemas.models import ApprovalRecord, RiskScanResult
from sitina.storage import SitinaStore
from sitina.utils import iso_now, new_id, sha256_text, stable_json, utc_now


def scope_hash(files: list[str], commands: list[str] | None = None) -> str:
    return sha256_text(stable_json({"files": sorted(files), "commands": sorted(commands or [])}))


class ApprovalManager:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def create(
        self,
        *,
        run_id: str,
        action: str,
        risk_scan: RiskScanResult,
        plan_hash: str,
        approved_touched_files: list[str],
        approved_commands: list[str] | None = None,
        ttl_hours: int = 24,
    ) -> ApprovalRecord:
        expires = utc_now() + dt.timedelta(hours=ttl_hours)
        record = ApprovalRecord(
            approval_id="appr_" + new_id(),
            run_id=run_id,
            action=action,  # type: ignore[arg-type]
            scope_hash=scope_hash(approved_touched_files, approved_commands),
            risk_scan_id=risk_scan.risk_scan_id,
            risk_scan_hash=risk_scan.risk_scan_hash,
            plan_hash=plan_hash,
            approved_touched_files=approved_touched_files,
            approved_commands=approved_commands or [],
            expires_at=expires.isoformat().replace("+00:00", "Z"),
            created_at=iso_now(),
        )
        self.store.insert_approval(record.model_dump())
        self.store.record_audit(
            "approval_record",
            record.model_dump(),
            run_id=run_id,
            approval_id=record.approval_id,
            risk_scan_id=risk_scan.risk_scan_id,
        )
        return record

    def validate(
        self,
        *,
        approval_id: str | None,
        run_id: str,
        risk_scan: RiskScanResult,
        required_scope_hash: str,
        risk_action: str,
    ) -> tuple[bool, str]:
        if risk_action == "block":
            return False, "risk action block cannot be overridden by approval"
        if not approval_id:
            return False, "approval_id is required"
        raw = self.store.get_approval(approval_id)
        if not raw:
            return False, "approval_id not found"
        record = ApprovalRecord.model_validate(raw)
        if record.run_id != run_id:
            return False, "approval_id is bound to another run"
        if record.action != "approve":
            return False, f"approval action is {record.action}"
        if record.risk_scan_id != risk_scan.risk_scan_id or record.risk_scan_hash != risk_scan.risk_scan_hash:
            return False, "approval_id is bound to a different risk scan"
        if record.scope_hash != required_scope_hash:
            return False, "approval_id scope hash mismatch"
        expiry = dt.datetime.fromisoformat(record.expires_at.replace("Z", "+00:00"))
        if utc_now() >= expiry:
            return False, "approval_id expired"
        return True, "approval accepted"
