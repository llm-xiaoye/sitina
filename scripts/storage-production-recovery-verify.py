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
    load_restored_genesis,
    validate_restored_authorities,
)
from sitina.security.macos_keychain import MacOSKeychainProvider


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with temporary.open("rb") as handle:
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reverify native recovery domains in an existing isolated restore.")
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--restore-root", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    args = parser.parse_args()
    backup_root = args.backup_root.expanduser().resolve(strict=True)
    restore_root = args.restore_root.expanduser().resolve(strict=True)
    source_manifest = args.source_manifest.expanduser().resolve(strict=True)
    evidence_output = args.evidence_output.expanduser().resolve(strict=False)
    manifest = ProductionBackupManifest.load(backup_root)
    genesis = load_restored_genesis(restore_root, manifest)
    provider = MacOSKeychainProvider(environment="production", namespace=genesis.key_namespace)
    semantic = validate_restored_authorities(restore_root, manifest, provider=provider)
    evidence: dict[str, object] = {
        "schema": "SITINA_STORAGE_PRODUCTION_NATIVE_RECOVERY_VERIFIED_V1",
        "status": "VERIFIED",
        "backup_id": manifest.backup_id,
        "backup_manifest_hash": manifest.manifest_hash,
        "backup_manifest_file_sha256": _sha256(backup_root / "backup-manifest.json"),
        "restore_root": str(restore_root),
        "prior_restore_receipt_sha256": _sha256(restore_root / "restore-verification.json"),
        "source_manifest": str(source_manifest),
        "source_manifest_file_sha256": _sha256(source_manifest),
        "semantic": semantic,
        "writer_activated": False,
        "credentials_copied": False,
    }
    _atomic_json(evidence_output, evidence)
    print(json.dumps(evidence, sort_keys=True), flush=True)
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
                    "error_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise
