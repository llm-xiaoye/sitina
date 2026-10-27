#!/usr/bin/env python3
from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from sitina.archive.production_backup import (
    ProductionBackupBuilder,
    ProductionBackupManifest,
    ProductionRestoreDrill,
    ProductionSnapshotMetadata,
    derive_verified_frontier,
    validate_restored_authorities,
)
from sitina.journal.model import canonical_json_bytes, domain_hash
from sitina.orchestrator.bplus_production import ProductionRuntimeContext


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _progress(value: dict[str, object]) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


def _resolution_hash(resolution: object) -> str:
    body = {
        "state": getattr(getattr(resolution, "state"), "value"),
        "writer_count": int(getattr(resolution, "writer_count")),
        "resolution_id": str(getattr(resolution, "resolution_id")),
        "input_frontier_hash": str(getattr(resolution, "input_frontier_hash")),
        "issued_at": int(getattr(resolution, "issued_at")),
        "expires_at": int(getattr(resolution, "expires_at")),
        "authorizes_journal": bool(getattr(resolution, "authorizes_journal")),
        "authorizes_legacy": bool(getattr(resolution, "authorizes_legacy")),
    }
    return domain_hash("AUTHORITY_FENCING_STATE", canonical_json_bytes(body))


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and independently restore-verify a frozen Sitina Production authority backup."
    )
    parser.add_argument("--home", type=Path, default=Path((_SITINA_ACCOUNT_HOME + '/SitinaHub')))
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--goal-thread-id", required=True)
    parser.add_argument("--before-sentinel", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--staging-parent", type=Path, required=True)
    parser.add_argument("--restore-parent", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    before_sentinel = args.before_sentinel.expanduser().resolve(strict=True)
    source_manifest = args.source_manifest.expanduser().resolve(strict=True)
    stage_parent = args.staging_parent.expanduser().resolve(strict=False)
    restore_parent = args.restore_parent.expanduser().resolve(strict=False)
    evidence_output = args.evidence_output.expanduser().resolve(strict=False)
    stage_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    restore_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = restore_parent / ".sitina-bplus-disposable-v1"
    if not marker.exists():
        marker.write_text("storage-production-closure-restore-parent\n", encoding="utf-8")
    if marker.is_symlink() or not marker.is_file():
        raise RuntimeError("restore parent marker is invalid")
    destination = home / "backups" / args.backup_id
    contexts: list[ProductionRuntimeContext] = []

    def metadata_provider() -> ProductionSnapshotMetadata:
        context = ProductionRuntimeContext.load(home)
        contexts.append(context)
        frontier = derive_verified_frontier(context)
        inventory = context.provider.public_inventory()
        return ProductionSnapshotMetadata(
            args.goal_thread_id,
            frontier,
            frontier.position,
            context.genesis.genesis_hash,
            _resolution_hash(context.authority.resolution),
            _sha256(before_sentinel),
            _sha256(source_manifest),
            inventory,
        )

    builder = ProductionBackupBuilder(progress=_progress)
    manifest = builder.build(
        args.backup_id,
        source_home=home,
        destination=destination,
        staging_parent=stage_parent,
        metadata_provider=metadata_provider,
    )
    manifest = ProductionBackupManifest.load(manifest.backup_root)
    if len(contexts) != 1:
        raise RuntimeError("backup metadata provider did not resolve exactly one frozen Production context")
    restore_target = restore_parent / args.backup_id
    drill = ProductionRestoreDrill(progress=_progress)
    report = drill.restore(
        manifest,
        target=restore_target,
        semantic_validator=lambda root, value: validate_restored_authorities(
            root,
            value,
            provider=contexts[0].provider,
        ),
    )
    evidence = {
        "schema": "SITINA_STORAGE_PRODUCTION_BACKUP_EVIDENCE_V1",
        "backup_id": manifest.backup_id,
        "backup_root": str(manifest.backup_root),
        "manifest_hash": manifest.manifest_hash,
        "manifest_file_sha256": _sha256(manifest.backup_root / "backup-manifest.json"),
        "file_count": len(manifest.files),
        "logical_bytes": manifest.logical_bytes,
        "unique_inode_bytes": manifest.unique_inode_bytes,
        "frontier": manifest.metadata.frontier.__dict__,
        "restore_root": str(restore_target),
        "restore_verification_sha256": _sha256(restore_target / "restore-verification.json"),
        "restore": report,
        "credentials_copied": False,
        "writer_activated_during_restore": False,
    }
    evidence_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = evidence_output.with_name(f".{evidence_output.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with temporary.open("rb") as handle:
        os.fsync(handle.fileno())
    os.replace(temporary, evidence_output)
    print(json.dumps({"status": "VERIFIED", **evidence}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "FAILED_CLOSED",
                    "error_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise
