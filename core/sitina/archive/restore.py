from __future__ import annotations

import json
import os
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from sitina.journal.model import canonical_json_bytes, domain_hash

from .backup import (
    BackupError, BackupFile, CanonicalBackupManifest, _read_member,
    _require_disposable, _root_fd, _root_path, _validate_paths, _write_member,
)


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
        source = _root_path(source_copy)
        destination = _root_path(target)
        try:
            _require_disposable(source)
            _require_disposable(destination)
            _validate_paths(tuple(item.path for item in manifest.files), reserved=frozenset({"restore-identity.json"}))
            with ExitStack() as stack:
                source_fd = stack.enter_context(_root_fd(source))
                destination_fd = stack.enter_context(_root_fd(destination)) if os.path.lexists(destination) else None
                # Inspect the existing identity before replacing any member.
                if destination_fd is not None:
                    try:
                        os.stat("restore-identity.json", dir_fd=destination_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        try:
                            kind, raw = _read_member(destination_fd, "restore-identity.json")
                            if kind != "REGULAR":
                                raise ValueError("restore identity must be a regular file")
                            existing = json.loads(raw)
                            if not isinstance(existing, dict):
                                raise ValueError("restore identity must be an object")
                        except (BackupError, ValueError, UnicodeError) as error:
                            raise RestoreIdentityIncident("restore identity is unreadable") from error
                        if existing.get("backup_id") == manifest.backup_id and existing.get("manifest_hash") != manifest.manifest_hash:
                            raise RestoreIdentityIncident("same backup identity is bound to different manifest bytes")
                observed: dict[str, BackupFile] = {}
                mismatches: list[str] = []
                for item in manifest.files:
                    kind, raw = _read_member(source_fd, item.path)
                    if kind != item.kind:
                        raise RestoreError("recovered object type differs from the frozen backup manifest")
                    if not item.matches(kind, raw):
                        if kind == "SYMLINK":
                            raise RestoreError("recovered symbolic-link target differs from the frozen backup manifest")
                        mismatches.append(item.path)
                    observed[item.path] = BackupFile.from_raw(item.path, kind, raw)
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
                    result_manifest_hash = domain_hash(
                        "RECOVERY_EPOCH_MANIFEST",
                        canonical_json_bytes({
                            "predecessor": manifest.manifest_hash,
                            "epoch": recovery_epoch,
                            "observed": {path: item.sha256 for path, item in observed.items()},
                        }),
                    )
                replacing = destination_fd is not None
                if destination_fd is None:
                    destination_fd = stack.enter_context(_root_fd(destination, create=True, exclusive=True))
                for item in manifest.files:
                    kind, raw = _read_member(source_fd, item.path)
                    if not observed[item.path].matches(kind, raw):
                        raise RestoreError("recovery source changed before copy")
                    _write_member(destination_fd, item.path, kind, raw, replace_existing=replacing)
                for item in manifest.files:
                    if not observed[item.path].matches(*_read_member(destination_fd, item.path)):
                        raise RestoreError("restored member differs from the verified recovery source")
                identity = {
                    "schema": "RESTORE_IDENTITY_V1",
                    "backup_id": manifest.backup_id,
                    "manifest_hash": result_manifest_hash,
                    "journal_id": manifest.frontier.journal_id,
                    "source_epoch": source_epoch,
                    "recovery_epoch": recovery_epoch,
                    "writer_activated": False,
                }
                _write_member(
                    destination_fd, "restore-identity.json", "REGULAR",
                    canonical_json_bytes(identity) + b"\n", replace_existing=replacing,
                )
        except BackupError as error:
            raise RestoreError(str(error)) from error
        return RestoreResult(True, False, manifest.frontier.journal_id, source_epoch, recovery_epoch, original_adopted, result_manifest_hash)
