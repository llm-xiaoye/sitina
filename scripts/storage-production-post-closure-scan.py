#!/usr/bin/env python3
from __future__ import annotations

import os as _sitina_os
import pwd as _sitina_pwd
import sys as _sitina_sys
_SITINA_ACCOUNT_HOME = _sitina_pwd.getpwuid(_sitina_os.getuid()).pw_dir

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

from sitina.guards.secrets import scan_paths_for_secrets
from sitina.runners.profiles import ProfileLoader
from sitina.security.profile_exception import evaluate_deepseek_direct_storage_exception


PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
DEFAULT_EVIDENCE_ROOT = Path((_SITINA_ACCOUNT_HOME + '/Desktop/sitina/output/storage-production-closure'))


def _audit_module() -> Any:
    path = Path(__file__).with_name("storage-production-security-audit.py")
    spec = importlib.util.spec_from_file_location("storage_production_security_audit_postscan", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("security audit module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rescan closure-time source, report, Sentinel, and artifact changes."
    )
    parser.add_argument("--home", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--accept-deepseek-direct-storage-risk", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    evidence_root = args.evidence_root.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve(strict=False)
    if output == home or home in output.parents:
        raise RuntimeError("post-closure scan evidence must remain outside Production")
    module = _audit_module()
    literals = module._configured_literals(home)
    exception = evaluate_deepseek_direct_storage_exception(
        ProfileLoader(home).audit_profiles(),
        user_accepted=bool(args.accept_deepseek_direct_storage_risk),
    )
    source_paths = [home / item for item in module.SOURCE_SCOPE]
    artifact_paths = [
        home / "artifacts",
        home / "output",
        home / "outputs",
        home / "logs",
        evidence_root,
    ]
    source_patterns_raw = scan_paths_for_secrets(source_paths, scope="post_closure_source")
    artifact_patterns_raw = scan_paths_for_secrets(artifact_paths, scope="post_closure_artifacts")
    source_review = module._review_source_patterns(home, source_patterns_raw)
    artifact_review = module._review_artifact_patterns(artifact_patterns_raw)
    source_exact = module._scan_file_literals(source_paths, literals)
    artifact_exact = module._scan_file_literals(artifact_paths, literals)
    exact_hits = (
        int(source_exact["exact_provider_literal_hit_count"])
        + int(artifact_exact["exact_provider_literal_hit_count"])
    )
    status = (
        "ok"
        if exception.get("status") == "accepted"
        and exact_hits == 0
        and source_exact["unsafe_path_count"] == 0
        and artifact_exact["unsafe_path_count"] == 0
        and source_review["status"] == "reviewed"
        and artifact_review["status"] == "reviewed"
        else "failed"
    )
    value: dict[str, object] = {
        "schema": "SITINA_STORAGE_PRODUCTION_POST_CLOSURE_SCAN_V1",
        "status": status,
        "profile_storage_exception_status": exception.get("status"),
        "source": {
            "exact_provider_literal_hit_count": source_exact["exact_provider_literal_hit_count"],
            "scanned_files": source_exact["scanned_files"],
            "unsafe_path_count": source_exact["unsafe_path_count"],
            "pattern_review_status": source_review["status"],
            "pattern_review_unresolved_count": source_review["unresolved_count"],
        },
        "artifacts": {
            "exact_provider_literal_hit_count": artifact_exact["exact_provider_literal_hit_count"],
            "scanned_files": artifact_exact["scanned_files"],
            "unsafe_path_count": artifact_exact["unsafe_path_count"],
            "pattern_review_status": artifact_review["status"],
            "pattern_review_unresolved_count": artifact_review["unresolved_count"],
        },
        "exact_provider_literal_persistence_hit_count": exact_hits,
        "credential_value_included": False,
        "message_or_response_bodies_included": False,
        "secret_values_included": False,
    }
    _write(output, value)
    own_hits, _size, _digest = module._scan_regular_file_literals(output, literals)
    if own_hits:
        raise RuntimeError("post-closure scan evidence exact-value containment failed")
    print(
        json.dumps(
            {
                "status": status,
                "evidence_output": str(output),
                "evidence_sha256": _sha256(output),
                "exact_provider_literal_persistence_hit_count": exact_hits,
                "source_unresolved_count": source_review["unresolved_count"],
                "artifact_unresolved_count": artifact_review["unresolved_count"],
                "secret_values_included": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0 if status == "ok" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed_closed",
                    "error_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
                    "secret_values_included": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)
