#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from sitina.archive.production_backup import (
    ProductionBackupManifest,
    ProductionRestoreDrill,
    validate_restored_authorities,
)
from sitina.security.macos_keychain import MacOSKeychainProvider


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _progress(value: dict[str, object]) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Restore and semantically verify an existing Sitina Production authority backup."
    )
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--restore-parent", type=Path, required=True)
    parser.add_argument("--restore-id", required=True)
    parser.add_argument("--verifier-source-manifest", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    backup_root = args.backup_root.expanduser().resolve(strict=True)
    restore_parent = args.restore_parent.expanduser().resolve(strict=True)
    verifier_manifest = args.verifier_source_manifest.expanduser().resolve(strict=True)
    evidence_output = args.evidence_output.expanduser().resolve(strict=False)
    marker = restore_parent / ".sitina-bplus-disposable-v1"
    if marker.is_symlink() or not marker.is_file():
        raise RuntimeError("restore parent is not a marked disposable root")
    manifest = ProductionBackupManifest.load(backup_root)
    genesis_path = backup_root / "payload/state/bplus-production-genesis/genesis.json"
    genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
    environment = {
        "PRODUCTION": "production",
        "CONTROLLED_PRODUCTION_SIMULATION": "production-simulation",
    }.get(str(genesis.get("environment_kind")))
    if environment is None:
        raise RuntimeError("backup Genesis has an unsupported Keychain environment")
    provider = MacOSKeychainProvider(
        environment=environment,
        namespace=str(genesis["key_namespace"]),
    )
    restore_target = restore_parent / args.restore_id
    report = ProductionRestoreDrill(progress=_progress).restore(
        manifest,
        target=restore_target,
        semantic_validator=lambda root, value: validate_restored_authorities(
            root,
            value,
            provider=provider,
        ),
    )
    evidence = {
        "schema": "SITINA_STORAGE_PRODUCTION_RESTORE_RETRY_EVIDENCE_V1",
        "backup_id": manifest.backup_id,
        "backup_root": str(backup_root),
        "manifest_hash": manifest.manifest_hash,
        "backup_manifest_file_sha256": _sha256(backup_root / "backup-manifest.json"),
        "verifier_source_manifest": str(verifier_manifest),
        "verifier_source_manifest_file_sha256": _sha256(verifier_manifest),
        "restore_id": args.restore_id,
        "restore_root": str(restore_target),
        "restore_verification_sha256": _sha256(restore_target / "restore-verification.json"),
        "restore": report,
        "credentials_copied": False,
        "writer_activated": False,
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
