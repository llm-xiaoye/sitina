from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from sitina.journal.model import canonical_json_bytes, domain_hash

from .backup import CanonicalBackupManifest, _relative_path, _require_disposable


class RestoreError(RuntimeError):
    pass


class RestoreIdentityIncident(RestoreError):
    pass


@dataclass(frozen=True)
class RestoreResult:
    verified: bool
    writer_activated: bool
    journal_id: str
    source_epoch: int
    recovery_epoch: int
    original_epoch_adopted: bool
    manifest_hash: str


class RestoreDrill:
    def restore(
        self,
        manifest: CanonicalBackupManifest,
        *,
        source_copy: Path,
        target: Path,
        source_kind: str,
        allow_new_recovery_epoch: int | None = None,
    ) -> RestoreResult:
        if source_kind != "FINAL_COLD_COPY":
            raise RestoreError("restore source must be a final cold copy")
        source = Path(source_copy).resolve()
        destination = Path(target).resolve(strict=False)
        _require_disposable(source)
        _require_disposable(destination)
        identity_path = destination / "restore-identity.json"
        if identity_path.is_file():
            try:
                existing = json.loads(identity_path.read_text(encoding="utf-8"))
            except Exception as error:
                raise RestoreIdentityIncident("restore identity is unreadable") from error
            if existing.get("backup_id") == manifest.backup_id and existing.get("manifest_hash") != manifest.manifest_hash:
                raise RestoreIdentityIncident("same backup identity is bound to different manifest bytes")
        mismatches: list[str] = []
        for item in manifest.files:
            path = source / _relative_path(item.path)
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item.sha256:
                mismatches.append(item.path)
        if mismatches and allow_new_recovery_epoch is None:
            raise RestoreError("recovered bytes differ from the frozen backup manifest")
        source_epoch = manifest.frontier.epoch
        recovery_epoch = source_epoch
        original_adopted = True
        result_manifest_hash = manifest.manifest_hash
        if mismatches:
            if allow_new_recovery_epoch is None or allow_new_recovery_epoch <= source_epoch:
                raise RestoreError("changed recovered bytes require a strictly newer recovery epoch")
            recovery_epoch = allow_new_recovery_epoch
            original_adopted = False
            observed = {
                item.path: hashlib.sha256((source / _relative_path(item.path)).read_bytes()).hexdigest()
                for item in manifest.files if (source / _relative_path(item.path)).is_file()
            }
            result_manifest_hash = domain_hash(
                "RECOVERY_EPOCH_MANIFEST",
                canonical_json_bytes({"predecessor": manifest.manifest_hash, "epoch": recovery_epoch, "observed": observed}),
            )
        destination.mkdir(parents=True, exist_ok=True)
        for item in manifest.files:
            source_file = source / _relative_path(item.path)
            if not source_file.is_file():
                raise RestoreError("recovery source is missing an object")
            target_file = destination / _relative_path(item.path)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_file, target_file)
        identity = {
            "schema": "RESTORE_IDENTITY_V1",
            "backup_id": manifest.backup_id,
            "manifest_hash": result_manifest_hash,
            "journal_id": manifest.frontier.journal_id,
            "source_epoch": source_epoch,
            "recovery_epoch": recovery_epoch,
            "writer_activated": False,
        }
        identity_path.write_bytes(canonical_json_bytes(identity) + b"\n")
        return RestoreResult(True, False, manifest.frontier.journal_id, source_epoch, recovery_epoch, original_adopted, result_manifest_hash)

