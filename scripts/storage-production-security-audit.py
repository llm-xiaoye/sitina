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
import stat
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

from sitina.archive.production_backup import ProductionBackupManifest
from sitina.cas.local import LocalCAS
from sitina.compatibility.feature_flags import FeatureActivationRegistry
from sitina.guards.secrets import SecretFinding, scan_json_for_secrets, scan_paths_for_secrets, scan_text_for_secrets
from sitina.journal.model import canonical_json_bytes
from sitina.orchestrator.bplus_production import ProductionRuntimeContext
from sitina.runners.profiles import ProfileLoader
from sitina.security.profile_exception import evaluate_deepseek_direct_storage_exception


PRODUCTION_HOME = Path((_SITINA_ACCOUNT_HOME + '/SitinaHub'))
DEFAULT_EVIDENCE_ROOT = Path((_SITINA_ACCOUNT_HOME + '/Desktop/sitina/output/storage-production-closure'))
SOURCE_SCOPE = (
    "README.md",
    "pyproject.toml",
    "requirements-bplus.lock",
    "bin",
    "config",
    "core",
    "docs",
    "examples",
    "schemas",
    "scripts",
    "tests",
)
REVIEWED_SECURITY_IMPLEMENTATION_PATHS = frozenset(
    {
        "core/sitina/security/macos_keychain.py",
        "core/sitina/runners/provider.py",
        "core/sitina/protocols/blackboard.py",
        "core/sitina/orchestrator/engine.py",
        "core/sitina/security/profile_exception.py",
        "scripts/storage-production-approved-exception-canary.py",
        "scripts/storage-production-post-closure-scan.py",
        "scripts/storage-production-security-audit.py",
    }
)
REVIEWED_SELF_AUDIT_FILES = frozenset(
    {
        "storage-production-security-audit-pre-permission.json",
        "storage-production-security-audit-final.json",
    }
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _configured_literals(home: Path) -> tuple[bytes, ...]:
    """Read provider literals for exact matching without persisting any derivative."""

    values: set[bytes] = set()
    for path in sorted((home / "profiles").glob("*.env")):
        if path.name.endswith(".template"):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            if key.removeprefix("export ").strip() != ProfileLoader.TOKEN_KEY:
                continue
            literal = value.strip().strip("'\"").encode("utf-8")
            if literal:
                values.add(literal)
    return tuple(values)


def _exact_hits(raw: bytes, literals: tuple[bytes, ...]) -> int:
    return sum(raw.count(literal) for literal in literals)


def _finding_groups(findings: Iterable[SecretFinding]) -> list[dict[str, object]]:
    counts: Counter[tuple[str, str]] = Counter()
    paths: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        key = (finding.pattern_type, finding.field_path)
        counts[key] += 1
        paths[key].add(_path_token(finding.path))
    return [
        {
            "pattern_type": pattern,
            "field_path": field,
            "count": counts[(pattern, field)],
            "distinct_path_count": len(paths[(pattern, field)]),
            "sample_path_tokens": sorted(paths[(pattern, field)])[:5],
            "secret_values_included": False,
        }
        for pattern, field in sorted(counts)
    ]


def _summary_from_safe_result(value: dict[str, Any]) -> dict[str, object]:
    findings = [
        SecretFinding(
            scope=str(item["scope"]),
            path=str(item["path"]),
            table=str(item["table"]) if item.get("table") is not None else None,
            row_id=str(item["row_id"]) if item.get("row_id") is not None else None,
            field_path=str(item["field_path"]),
            pattern_type=str(item["pattern_type"]),
        )
        for item in value.get("findings", [])
    ]
    return {
        "status": value.get("status"),
        "finding_count": len(findings),
        "scanned_files": int(value.get("scanned_files", 0)),
        "skipped_files": int(value.get("skipped_files", 0)),
        "finding_groups": _finding_groups(findings),
        "secret_values_included": False,
    }


def _review_source_patterns(home: Path, value: dict[str, Any]) -> dict[str, object]:
    disposition: Counter[str] = Counter()
    unresolved_path_tokens: set[str] = set()
    for item in value.get("findings", []):
        path = Path(str(item["path"])).resolve(strict=False)
        try:
            relative = path.relative_to(home).as_posix()
        except ValueError:
            disposition["unresolved"] += 1
            unresolved_path_tokens.add(_path_token(str(path)))
            continue
        if relative.startswith("tests/"):
            disposition["controlled_security_test_fixture"] += 1
        elif relative in REVIEWED_SECURITY_IMPLEMENTATION_PATHS:
            disposition["security_or_redaction_implementation"] += 1
        else:
            disposition["unresolved"] += 1
            unresolved_path_tokens.add(_path_token(relative))
    return {
        "status": "reviewed" if disposition["unresolved"] == 0 else "unresolved",
        "finding_count": sum(disposition.values()),
        "disposition_counts": dict(sorted(disposition.items())),
        "unresolved_count": disposition["unresolved"],
        "unresolved_path_tokens": sorted(unresolved_path_tokens),
        "secret_values_included": False,
    }


def _review_artifact_patterns(value: dict[str, Any]) -> dict[str, object]:
    """Classify only the safe source-enum fields in this audit's own evidence."""

    disposition: Counter[str] = Counter()
    unresolved_path_tokens: set[str] = set()
    expected_root = DEFAULT_EVIDENCE_ROOT.resolve(strict=True)
    field_prefix = "$.provider_profiles.profiles["
    field_suffix = "].secret_source"
    validated_files: dict[Path, bool] = {}
    for item in value.get("findings", []):
        path = Path(str(item["path"])).resolve(strict=False)
        field = str(item["field_path"])
        index_text = field[len(field_prefix) : -len(field_suffix)] if field.startswith(field_prefix) and field.endswith(field_suffix) else ""
        if path not in validated_files:
            valid = False
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                valid = (
                    path.parent == expected_root
                    and path.name in REVIEWED_SELF_AUDIT_FILES
                    and not path.is_symlink()
                    and payload.get("schema") == "SITINA_STORAGE_PRODUCTION_SECURITY_AUDIT_V1"
                    and payload.get("secret_values_included") is False
                )
            except (OSError, json.JSONDecodeError, AttributeError):
                valid = False
            validated_files[path] = valid
        if (
            validated_files[path]
            and str(item["pattern_type"]) == "sensitive_field"
            and index_text.isdigit()
        ):
            disposition["self_audit_safe_source_enum"] += 1
        else:
            disposition["unresolved"] += 1
            unresolved_path_tokens.add(_path_token(str(path)))
    return {
        "status": "reviewed" if disposition["unresolved"] == 0 else "unresolved",
        "finding_count": sum(disposition.values()),
        "disposition_counts": dict(sorted(disposition.items())),
        "unresolved_count": disposition["unresolved"],
        "unresolved_path_tokens": sorted(unresolved_path_tokens),
        "secret_values_included": False,
    }


def _scan_regular_file_literals(
    path: Path,
    literals: tuple[bytes, ...],
    *,
    chunk_size: int = 8 * 1024 * 1024,
) -> tuple[int, int, str]:
    """Scan one stable regular file without following links or loading it whole."""

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError("exact-value scan requires a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    hits = 0
    scanned = 0
    maximum = max((len(item) for item in literals), default=1)
    tail = b""
    try:
        opened = os.fstat(descriptor)
        expected = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        observed = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if observed != expected or not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("file changed before exact-value scan")
        while True:
            chunk = os.read(descriptor, chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            combined = tail + chunk
            combined_base = scanned - len(tail)
            boundary = scanned
            for literal in literals:
                start = 0
                while True:
                    index = combined.find(literal, start)
                    if index < 0:
                        break
                    if combined_base + index + len(literal) > boundary:
                        hits += 1
                    start = index + 1
            scanned += len(chunk)
            tail = combined[-(maximum - 1) :] if maximum > 1 else b""
    finally:
        os.close(descriptor)
    after = path.lstat()
    final = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if final != expected or scanned != before.st_size:
        raise RuntimeError("file changed during exact-value scan")
    return hits, scanned, digest.hexdigest()


def _regular_candidates(paths: Iterable[Path]) -> tuple[list[Path], list[str]]:
    candidates: list[Path] = []
    unsafe: list[str] = []
    for item in paths:
        if not item.exists() and not item.is_symlink():
            continue
        if item.is_symlink():
            unsafe.append(_path_token(str(item)))
            continue
        if item.is_file():
            candidates.append(item)
            continue
        for directory, directory_names, file_names in os.walk(item, followlinks=False):
            current = Path(directory)
            retained: list[str] = []
            for name in sorted(directory_names):
                child = current / name
                if child.is_symlink():
                    unsafe.append(_path_token(str(child)))
                else:
                    retained.append(name)
            directory_names[:] = retained
            for name in sorted(file_names):
                child = current / name
                if child.is_symlink():
                    unsafe.append(_path_token(str(child)))
                elif child.is_file():
                    candidates.append(child)
                else:
                    unsafe.append(_path_token(str(child)))
    return sorted(set(candidates)), sorted(set(unsafe))


def _scan_file_literals(
    paths: Iterable[Path],
    literals: tuple[bytes, ...],
    *,
    deduplicate_inodes: bool = False,
) -> dict[str, object]:
    candidates, unsafe = _regular_candidates(paths)
    files = 0
    bytes_scanned = 0
    hits = 0
    hardlink_aliases = 0
    hit_paths: set[str] = set()
    seen: set[tuple[int, int]] = set()
    for path in candidates:
        metadata = path.lstat()
        identity = (metadata.st_dev, metadata.st_ino)
        if deduplicate_inodes and identity in seen:
            hardlink_aliases += 1
            continue
        seen.add(identity)
        count, size, _digest = _scan_regular_file_literals(path, literals)
        files += 1
        bytes_scanned += size
        if count:
            hits += count
            hit_paths.add(_path_token(str(path)))
    return {
        "candidate_file_count": len(candidates),
        "scanned_files": files,
        "scanned_bytes": bytes_scanned,
        "hardlink_alias_count": hardlink_aliases,
        "unsafe_path_count": len(unsafe),
        "unsafe_path_tokens": unsafe,
        "exact_provider_literal_hit_count": hits,
        "hit_path_tokens": sorted(hit_paths),
        "secret_values_included": False,
    }


def _backup_mode_disposition(*, actual: int, recorded: int) -> str:
    """Accept only an exact mode or the authorized 0644 -> 0600 tightening."""

    if actual == recorded:
        return "exact"
    if recorded == 0o644 and actual == 0o600:
        return "owner_only_tightening"
    return "invalid"


def _scan_backups(
    home: Path,
    literals: tuple[bytes, ...],
    *,
    progress: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    """Verify every backup manifest/payload while scanning for exact literals."""

    backup_roots = sorted(path for path in (home / "backups").glob("storage-closure-*") if path.is_dir())
    current_objects = {path.stem for path in (home / "cas/objects").glob("*/*.obj")}
    backup_reports: list[dict[str, object]] = []
    total_hits = 0
    total_files = 0
    unique_files = 0
    scanned_bytes = 0
    hardlink_aliases = 0
    mode_tightenings = 0
    profile_file_count = 0
    missing_current_cas: set[str] = set()
    hit_paths: set[str] = set()
    for root in backup_roots:
        manifest = ProductionBackupManifest.load(root)
        prior_paths: dict[str, Path] = {}
        prior_hashes: dict[str, str] = {}
        backup_hits = 0
        backup_scanned_bytes = 0
        backup_unique_files = 0
        backup_cas_objects = 0
        backup_mode_tightenings = 0
        for item in manifest.files:
            relative = Path(item.path)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("backup manifest contains an unsafe path")
            path = root / "payload" / relative
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise RuntimeError("backup payload contains a non-regular file")
            mode_disposition = _backup_mode_disposition(
                actual=metadata.st_mode & 0o7777,
                recorded=int(item.mode, 8),
            )
            if mode_disposition == "invalid" or metadata.st_size != item.size:
                raise RuntimeError("backup payload metadata differs from its manifest")
            if mode_disposition == "owner_only_tightening":
                mode_tightenings += 1
                backup_mode_tightenings += 1
            total_files += 1
            if relative.parts and relative.parts[0] == "profiles":
                profile_file_count += 1
            if item.path.startswith("cas/objects/") and item.path.endswith(".obj"):
                backup_cas_objects += 1
                object_id = relative.stem
                if item.sha256 != object_id or object_id not in current_objects:
                    missing_current_cas.add(_path_token(f"{manifest.backup_id}:{object_id}"))
            if item.hardlink_to is not None:
                predecessor = prior_paths.get(item.hardlink_to)
                if predecessor is None or not os.path.samefile(path, predecessor):
                    raise RuntimeError("backup hardlink topology differs from its manifest")
                if prior_hashes[item.hardlink_to] != item.sha256:
                    raise RuntimeError("backup hardlink hash differs from its predecessor")
                hardlink_aliases += 1
            else:
                count, size, digest = _scan_regular_file_literals(path, literals)
                if digest != item.sha256 or size != item.size:
                    raise RuntimeError("backup payload bytes differ from its manifest")
                unique_files += 1
                backup_unique_files += 1
                scanned_bytes += size
                backup_scanned_bytes += size
                backup_hits += count
                total_hits += count
                if count:
                    hit_paths.add(_path_token(f"{manifest.backup_id}:{item.path}"))
            prior_paths[item.path] = path
            prior_hashes[item.path] = item.sha256
        backup_reports.append(
            {
                "backup_id": manifest.backup_id,
                "manifest_hash": manifest.manifest_hash,
                "manifest_verified": True,
                "credentials_copied": manifest.body_mapping()["credentials_copied"],
                "logical_file_count": len(manifest.files),
                "unique_file_count": backup_unique_files,
                "bytes_scanned": backup_scanned_bytes,
                "cas_object_count": backup_cas_objects,
                "owner_only_mode_tightening_count": backup_mode_tightenings,
                "exact_provider_literal_hit_count": backup_hits,
                "secret_values_included": False,
            }
        )
        if progress is not None:
            progress(
                {
                    "phase": "backup",
                    "backup_index": len(backup_reports),
                    "backup_count": len(backup_roots),
                    "logical_file_count": len(manifest.files),
                    "unique_file_count": backup_unique_files,
                    "bytes_scanned": backup_scanned_bytes,
                    "exact_hit_count": backup_hits,
                    "secret_values_included": False,
                }
            )
    status = (
        "ok"
        if backup_roots
        and total_hits == 0
        and profile_file_count == 0
        and not missing_current_cas
        and all(item["credentials_copied"] is False for item in backup_reports)
        else "failed"
    )
    return {
        "status": status,
        "backup_count": len(backup_reports),
        "backups": backup_reports,
        "logical_file_count": total_files,
        "unique_file_count": unique_files,
        "hardlink_alias_count": hardlink_aliases,
        "owner_only_mode_tightening_count": mode_tightenings,
        "bytes_scanned": scanned_bytes,
        "profile_file_count": profile_file_count,
        "cas_object_missing_from_verified_production_count": len(missing_current_cas),
        "cas_object_missing_path_tokens": sorted(missing_current_cas),
        "exact_provider_literal_hit_count": total_hits,
        "hit_path_tokens": sorted(hit_paths),
        "secret_values_included": False,
    }


def _permissions(home: Path) -> dict[str, object]:
    roots = ("journal", "cas", "projections", "state", "data", "backups", "profiles")
    unsafe_files: list[str] = []
    unsafe_directories: list[str] = []
    file_count = 0
    directory_count = 0
    for name in roots:
        root = home / name
        if not root.exists():
            continue
        for path in (root, *root.rglob("*")):
            observed = path.lstat()
            relative = path.relative_to(home).as_posix()
            if stat.S_ISLNK(observed.st_mode):
                unsafe_files.append(_path_token(relative + ":symlink"))
            elif stat.S_ISDIR(observed.st_mode):
                directory_count += 1
                if observed.st_mode & 0o077:
                    unsafe_directories.append(_path_token(relative))
            elif stat.S_ISREG(observed.st_mode):
                file_count += 1
                if observed.st_mode & 0o077:
                    unsafe_files.append(_path_token(relative))
            else:
                unsafe_files.append(_path_token(relative + ":special"))
    return {
        "status": "ok" if not unsafe_files and not unsafe_directories else "unsafe",
        "file_count": file_count,
        "directory_count": directory_count,
        "unsafe_file_count": len(unsafe_files),
        "unsafe_directory_count": len(unsafe_directories),
        "unsafe_file_path_tokens": sorted(unsafe_files),
        "unsafe_directory_path_tokens": sorted(unsafe_directories),
        "required_file_mode": "0600",
        "required_directory_mode": "0700",
    }


def _write_evidence(path: Path, value: dict[str, object]) -> None:
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
    parser = argparse.ArgumentParser(description="Verify Production persistence contains no configured provider secret.")
    parser.add_argument("--home", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--evidence-output", type=Path, default=DEFAULT_EVIDENCE_ROOT / "storage-production-security-audit.json")
    parser.add_argument(
        "--accept-deepseek-direct-storage-risk",
        action="store_true",
        help="Accept only the exact user-approved DeepSeek owner-only direct-storage exception.",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    output = args.evidence_output.expanduser().resolve(strict=False)
    literals = _configured_literals(home)
    profile_audit = ProfileLoader(home).audit_profiles()
    profile_exception = evaluate_deepseek_direct_storage_exception(
        profile_audit,
        user_accepted=bool(args.accept_deepseek_direct_storage_risk),
    )
    print(json.dumps({"phase": "profiles", "profile_count": len(profile_audit["profiles"]), "secret_values_included": False}), flush=True)

    source_paths = [home / item for item in SOURCE_SCOPE]
    source_exact_paths = [home / item for item in SOURCE_SCOPE if item != "docs"]
    docs_and_sentinel_paths = [home / "docs"]
    artifact_paths = [home / "logs", home / "artifacts", home / "output", home / "outputs", DEFAULT_EVIDENCE_ROOT]
    source_pattern_result = scan_paths_for_secrets(source_paths, scope="source_and_tests")
    artifact_pattern_result = scan_paths_for_secrets(artifact_paths, scope="logs_artifacts_reports")
    source_patterns = _summary_from_safe_result(source_pattern_result)
    source_pattern_review = _review_source_patterns(home, source_pattern_result)
    artifact_patterns = _summary_from_safe_result(artifact_pattern_result)
    artifact_pattern_review = _review_artifact_patterns(artifact_pattern_result)
    source_exact = _scan_file_literals(source_exact_paths, literals)
    docs_and_sentinel_exact = _scan_file_literals(docs_and_sentinel_paths, literals)
    artifact_exact = _scan_file_literals(artifact_paths, literals)
    journal_raw_exact = _scan_file_literals(
        [
            home / "journal/active.seg",
            home / "journal/sealed",
            home / "journal/indexes",
            home / "journal/certificates",
            home / "journal/writer.lock",
            home / "journal/writer.lock.generation.json",
        ],
        literals,
    )
    checkpoint_exact = _scan_file_literals([home / "journal/checkpoints"], literals)
    projection_exact = _scan_file_literals([home / "projections"], literals)
    state_and_data_exact = _scan_file_literals([home / "state", home / "data"], literals)
    print(
        json.dumps(
            {
                "phase": "files",
                "source_files": source_exact["scanned_files"] + docs_and_sentinel_exact["scanned_files"],
                "artifact_files": artifact_exact["scanned_files"],
                "persistent_raw_files": (
                    journal_raw_exact["scanned_files"]
                    + checkpoint_exact["scanned_files"]
                    + projection_exact["scanned_files"]
                    + state_and_data_exact["scanned_files"]
                ),
                "exact_hit_count": (
                    source_exact["exact_provider_literal_hit_count"]
                    + docs_and_sentinel_exact["exact_provider_literal_hit_count"]
                    + artifact_exact["exact_provider_literal_hit_count"]
                    + journal_raw_exact["exact_provider_literal_hit_count"]
                    + checkpoint_exact["exact_provider_literal_hit_count"]
                    + projection_exact["exact_provider_literal_hit_count"]
                    + state_and_data_exact["exact_provider_literal_hit_count"]
                ),
            }
        ),
        flush=True,
    )

    backups = _scan_backups(
        home,
        literals,
        progress=lambda item: print(json.dumps(item, sort_keys=True), flush=True),
    )
    print(
        json.dumps(
            {
                "phase": "backups",
                "backup_count": backups["backup_count"],
                "logical_file_count": backups["logical_file_count"],
                "unique_file_count": backups["unique_file_count"],
                "bytes_scanned": backups["bytes_scanned"],
                "exact_hit_count": backups["exact_provider_literal_hit_count"],
                "secret_values_included": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )

    context = ProductionRuntimeContext.load(home)
    events = context._verified_history_events()
    journal_findings: list[SecretFinding] = []
    journal_exact_hits = 0
    error_record_count = 0
    journal_hit_positions: list[int] = []
    refs: set[str] = set()
    for event in events:
        value = event.core_mapping()
        raw = canonical_json_bytes(value)
        count = _exact_hits(raw, literals)
        if count:
            journal_exact_hits += count
            journal_hit_positions.append(event.position)
        journal_findings.extend(
            scan_json_for_secrets(value, path=f"journal-position:{event.position}", scope="journal")
        )
        if "error" in event.event_type.lower() or any("error" in str(key).lower() for key in event.payload):
            error_record_count += 1
        refs.update(event.object_refs)
    print(json.dumps({"phase": "journal", "event_count": len(events), "object_reference_count": len(refs), "exact_hit_count": journal_exact_hits}), flush=True)

    cas = LocalCAS(
        home,
        context.provider,
        "production",
        authority_resolution=context.authority.resolution,
        genesis_hash=context.genesis.genesis_hash,
        feature_activations=FeatureActivationRegistry.from_journal_events(context.events),
        read_only=True,
    )
    object_paths = sorted((home / "cas" / "objects").rglob("*.obj"))
    cas_findings: list[SecretFinding] = []
    cas_exact_hits = 0
    cas_plaintext_bytes = 0
    cas_hit_objects: list[str] = []
    for index, path in enumerate(object_paths, start=1):
        reference_id = "cas:" + path.stem
        reference = cas.resolve_reference(reference_id)
        plaintext = cas.open_verified(reference)
        cas_plaintext_bytes += len(plaintext)
        count = _exact_hits(plaintext, literals)
        if count:
            cas_exact_hits += count
            cas_hit_objects.append(_path_token(reference_id))
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text:
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                cas_findings.extend(scan_text_for_secrets(text, path=reference_id, scope="cas"))
            else:
                cas_findings.extend(scan_json_for_secrets(value, path=reference_id, scope="cas"))
        if index == 1 or index % 10_000 == 0 or index == len(object_paths):
            print(
                json.dumps(
                    {
                        "phase": "cas",
                        "objects_verified": index,
                        "object_count": len(object_paths),
                        "plaintext_bytes_verified": cas_plaintext_bytes,
                        "exact_hit_count": cas_exact_hits,
                    }
                ),
                flush=True,
            )

    exact_persistence_hits = (
        int(source_exact["exact_provider_literal_hit_count"])
        + int(docs_and_sentinel_exact["exact_provider_literal_hit_count"])
        + int(artifact_exact["exact_provider_literal_hit_count"])
        + int(journal_raw_exact["exact_provider_literal_hit_count"])
        + int(checkpoint_exact["exact_provider_literal_hit_count"])
        + int(projection_exact["exact_provider_literal_hit_count"])
        + int(state_and_data_exact["exact_provider_literal_hit_count"])
        + int(backups["exact_provider_literal_hit_count"])
        + journal_exact_hits
        + cas_exact_hits
    )
    permissions = _permissions(home)
    raw_surface_scans = {
        "journal_files": journal_raw_exact,
        "checkpoints": checkpoint_exact,
        "projections": projection_exact,
        "state_and_data": state_and_data_exact,
        "docs_reports_and_sentinel": docs_and_sentinel_exact,
    }
    raw_surfaces_safe = all(
        int(item["exact_provider_literal_hit_count"]) == 0
        and int(item["unsafe_path_count"]) == 0
        for item in raw_surface_scans.values()
    )
    internal_security_ok = (
        exact_persistence_hits == 0
        and source_pattern_review["status"] == "reviewed"
        and artifact_pattern_review["status"] == "reviewed"
        and int(source_exact["unsafe_path_count"]) == 0
        and int(artifact_exact["unsafe_path_count"]) == 0
        and raw_surfaces_safe
        and backups["status"] == "ok"
        and not journal_findings
        and not cas_findings
        and permissions["status"] == "ok"
    )
    profile_storage_accepted = profile_audit["status"] == "ok" or profile_exception["status"] == "accepted"
    value: dict[str, object] = {
        "schema": "SITINA_STORAGE_PRODUCTION_SECURITY_AUDIT_V1",
        "status": "ok" if internal_security_ok and profile_storage_accepted else "failed",
        "internal_security_status": "ok" if internal_security_ok else "failed",
        "home": str(home),
        "frontier": {
            "position": events[-1].position,
            "commitment": context.authority.fast_start_report.authority_state.last_transaction_hash,
        },
        "provider_profiles": profile_audit,
        "profile_storage_exception": profile_exception,
        "effective_profile_storage_status": "ok" if profile_storage_accepted else "failed",
        "configured_provider_literal_count": len(literals),
        "source_and_tests": {
            "patterns": source_patterns,
            "pattern_review": source_pattern_review,
            "exact": source_exact,
        },
        "raw_persistence_surfaces": raw_surface_scans,
        "backups": backups,
        "logs_artifacts_reports": {
            "patterns": artifact_patterns,
            "pattern_review": artifact_pattern_review,
            "exact": artifact_exact,
        },
        "journal": {
            "authenticated_event_count": len(events),
            "error_record_count": error_record_count,
            "pattern_finding_count": len(journal_findings),
            "finding_groups": _finding_groups(journal_findings),
            "exact_provider_literal_hit_count": journal_exact_hits,
            "hit_position_count": len(journal_hit_positions),
            "hit_position_tokens": [_path_token(str(value)) for value in journal_hit_positions],
            "secret_values_included": False,
        },
        "cas": {
            "verified_object_count": len(object_paths),
            "journal_reference_count": len(refs),
            "plaintext_bytes_verified": cas_plaintext_bytes,
            "pattern_finding_count": len(cas_findings),
            "finding_groups": _finding_groups(cas_findings),
            "exact_provider_literal_hit_count": cas_exact_hits,
            "hit_object_count": len(cas_hit_objects),
            "hit_object_tokens": cas_hit_objects,
            "secret_values_included": False,
        },
        "permissions": permissions,
        "exact_provider_literal_persistence_hit_count": exact_persistence_hits,
        "secret_values_included": False,
    }
    _write_evidence(output, value)
    print(
        json.dumps(
            {
                "status": value["status"],
                "evidence_output": str(output),
                "evidence_sha256": _sha256(output),
                "exact_provider_literal_persistence_hit_count": exact_persistence_hits,
                "profile_plaintext_secret_count": profile_audit["plaintext_secret_count"],
                "secret_values_included": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0 if value["status"] == "ok" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "failed_closed",
                    "error_type": type(error).__name__,
                    "error_sha256": hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
                    "secret_values_included": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)
