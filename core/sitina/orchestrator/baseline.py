"""Revision-bound, immutable mock-baseline manifests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.utils import iso_now, new_id, read_json, sha256_text, stable_json, write_json


class BaselineManager:
    SCHEMA_VERSION = "1.0"

    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.directory = home / "outputs" / "evidence" / "baselines"

    def save(
        self,
        *,
        revision: dict[str, Any],
        records: dict[str, dict[str, Any]],
        secret_scan: dict[str, Any],
    ) -> dict[str, Any]:
        statuses = {name: str(record.get("status")) for name, record in records.items()}
        overall = "passed" if statuses and all(status == "passed" for status in statuses.values()) and int(secret_scan.get("total_findings", 0)) == 0 else "failed"
        body = {
            "baseline_id": "baseline_" + new_id(),
            "baseline_schema_version": self.SCHEMA_VERSION,
            "code_revision": revision.get("code_revision"),
            "code_revision_type": revision.get("code_revision_type"),
            "config_hash": revision.get("config_hash"),
            "run_ids": {name: record.get("run_id") for name, record in records.items()},
            "records": records,
            "created_at": iso_now(),
            "test_summary": {"category_count": len(records), "statuses": statuses},
            "secret_scan": secret_scan,
            "overall_status": overall,
        }
        manifest = body | {"evidence_hash": sha256_text(stable_json(body))}
        write_json(self.directory / f"{body['baseline_id']}.json", manifest)
        return manifest

    def current(self, revision: dict[str, Any]) -> dict[str, Any] | None:
        for manifest in self.manifests():
            if (
                manifest.get("code_revision") == revision.get("code_revision")
                and manifest.get("config_hash") == revision.get("config_hash")
                and self.verify(manifest)
            ):
                return manifest
        return None

    def latest(self) -> dict[str, Any] | None:
        manifests = self.manifests()
        return manifests[0] if manifests else None

    def manifests(self) -> list[dict[str, Any]]:
        if not self.directory.exists():
            return []
        values: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("baseline_*.json"), reverse=True):
            value = read_json(path, default=None)
            if isinstance(value, dict):
                values.append(value)
        values.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return values

    @staticmethod
    def verify(manifest: dict[str, Any]) -> bool:
        claimed = manifest.get("evidence_hash")
        body = {key: value for key, value in manifest.items() if key != "evidence_hash"}
        return claimed == sha256_text(stable_json(body))

    @staticmethod
    def legacy_id(records: dict[str, dict[str, Any]]) -> str:
        run_ids = {name: record.get("run_id") for name, record in records.items()}
        return "baseline_legacy_" + sha256_text(stable_json(run_ids)).split(":", 1)[1][:16]
