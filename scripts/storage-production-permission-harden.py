#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sitina.archive.production_backup import FrozenProductionPrefix
from sitina.journal.model import canonical_json_bytes
from sitina.legacy.fence import authorized_production_permission_hardening
from sitina.orchestrator.bplus_production import ProductionRuntimeContext


PRODUCTION_HOME = Path("/Users/moss/SitinaHub")
EXTERNAL_ROOTS = (
    Path("/Users/moss/Desktop/sitina/output/storage-production-closure"),
    Path("/Users/moss/Desktop/sitina/.storage-restore-drills"),
    Path("/Users/moss/Desktop/sitina/.storage-activation-simulations"),
    Path("/Users/moss/Desktop/sitina/.storage-backup-staging"),
)
HOME_ROOTS = (
    "journal",
    "cas",
    "projections",
    "state",
    "data",
    "backups",
    "profiles",
    "artifacts",
    "output",
    "outputs",
    "logs",
    "memory",
)


class PermissionHardeningError(RuntimeError):
    pass


@dataclass(frozen=True)
class Entry:
    path: Path
    kind: str
    mode: int

    @property
    def target_mode(self) -> int:
        return 0o700 if self.kind == "directory" else 0o600


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return digest.hexdigest()


def _inside(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def _roots(home: Path, requested: tuple[Path, ...] = ()) -> tuple[Path, ...]:
    values = [home / name for name in HOME_ROOTS if (home / name).exists()]
    values.extend(path.resolve(strict=True) for path in EXTERNAL_ROOTS if path.exists())
    allowed = tuple(path.resolve(strict=True) for path in values)
    if requested:
        selected: list[Path] = []
        external = tuple(path.resolve(strict=True) for path in EXTERNAL_ROOTS if path.exists())
        home_allowed = tuple(home / name for name in HOME_ROOTS if (home / name).exists())
        for raw in requested:
            path = raw.expanduser().resolve(strict=True)
            if path not in home_allowed and not any(_inside(path, (root,)) for root in external):
                raise PermissionHardeningError("requested permission scope is outside the approved root allowlist")
            selected.append(path)
        resolved = tuple(selected)
    else:
        resolved = allowed
    if any(path.is_symlink() or not path.is_dir() for path in resolved):
        raise PermissionHardeningError("permission scope contains an invalid root")
    for index, path in enumerate(resolved):
        if any(path != other and _inside(path, (other,)) for other in resolved[:index]):
            raise PermissionHardeningError("permission roots overlap")
    return resolved


def _discover(roots: tuple[Path, ...]) -> tuple[Entry, ...]:
    entries: list[Entry] = []
    for root in roots:
        observed_root = os.lstat(root)
        if not stat.S_ISDIR(observed_root.st_mode):
            raise PermissionHardeningError("permission root changed type")
        entries.append(Entry(root, "directory", observed_root.st_mode & 0o7777))
        for current, names, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            for name in names:
                path = current_path / name
                observed = os.lstat(path)
                if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                    raise PermissionHardeningError(f"permission scope rejects directory entry: {path}")
                entries.append(Entry(path, "directory", observed.st_mode & 0o7777))
            for name in files:
                path = current_path / name
                observed = os.lstat(path)
                if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
                    raise PermissionHardeningError(f"permission scope rejects file entry: {path}")
                entries.append(Entry(path, "file", observed.st_mode & 0o7777))
    return tuple(entries)


def _frontier(home: Path) -> dict[str, object]:
    context = ProductionRuntimeContext.load(home)
    report = context.authority.fast_start_report
    if report is None:
        raise PermissionHardeningError("Production Fast Start authority is unavailable")
    state = report.authority_state
    return {
        "journal_id": state.journal_id,
        "epoch": state.epoch,
        "position": state.head_position,
        "commitment": state.last_transaction_hash,
    }


def _mode(value: int) -> str:
    return f"0o{value:04o}"


def _manifest(entries: tuple[Entry, ...]) -> dict[str, object]:
    changed: list[dict[str, object]] = []
    for entry in entries:
        if entry.mode == entry.target_mode:
            continue
        item: dict[str, object] = {
            "path": str(entry.path),
            "kind": entry.kind,
            "before_mode": _mode(entry.mode),
            "after_mode": _mode(entry.target_mode),
        }
        if entry.kind == "file":
            item["content_sha256"] = _sha256(entry.path)
            item["size"] = entry.path.stat().st_size
        changed.append(item)
    body: dict[str, object] = {
        "schema": "SITINA_STORAGE_PERMISSION_CHANGE_MANIFEST_V1",
        "policy": "DIRECTORIES_0700_FILES_0600_NO_SYMLINKS_NO_SPECIAL_FILES",
        "entries": changed,
    }
    return {**body, "manifest_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest()}


def _verify_manifest(value: dict[str, Any]) -> None:
    claimed = value.get("manifest_sha256")
    body = {key: item for key, item in value.items() if key != "manifest_sha256"}
    if value.get("schema") != "SITINA_STORAGE_PERMISSION_CHANGE_MANIFEST_V1" or claimed != hashlib.sha256(canonical_json_bytes(body)).hexdigest():
        raise PermissionHardeningError("permission change manifest is invalid")


def _apply_manifest(value: dict[str, Any], roots: tuple[Path, ...], *, rollback: bool) -> None:
    _verify_manifest(value)
    for item in value["entries"]:
        path = Path(str(item["path"])).resolve(strict=True)
        if not _inside(path, roots):
            raise PermissionHardeningError("permission manifest path is outside the approved scope")
        observed = os.lstat(path)
        kind = str(item["kind"])
        if stat.S_ISLNK(observed.st_mode) or (kind == "file" and not stat.S_ISREG(observed.st_mode)) or (kind == "directory" and not stat.S_ISDIR(observed.st_mode)):
            raise PermissionHardeningError("permission manifest target changed type")
        current = observed.st_mode & 0o7777
        expected = int(str(item["after_mode" if rollback else "before_mode"]), 8)
        target = int(str(item["before_mode" if rollback else "after_mode"]), 8)
        if current != expected:
            raise PermissionHardeningError(f"permission manifest target mode drifted: {path}")
        if kind == "file" and (_sha256(path) != item["content_sha256"] or path.stat().st_size != int(item["size"])):
            raise PermissionHardeningError(f"permission manifest target content drifted: {path}")
        os.chmod(path, target, follow_symlinks=False)


def _verify_after(
    entries: tuple[Entry, ...],
    manifest: dict[str, Any],
    *,
    rollback: bool = False,
) -> dict[str, object]:
    changed = {str(item["path"]): item for item in manifest["entries"]}
    unsafe_files = 0
    unsafe_directories = 0
    for entry in entries:
        observed = os.lstat(entry.path)
        item = changed.get(str(entry.path))
        target = (
            int(str(item["before_mode"]), 8)
            if rollback and item is not None
            else (0o700 if entry.kind == "directory" else 0o600)
        )
        if observed.st_mode & 0o7777 != target:
            if entry.kind == "directory":
                unsafe_directories += 1
            else:
                unsafe_files += 1
        if item is not None and entry.kind == "file":
            if _sha256(entry.path) != item["content_sha256"] or entry.path.stat().st_size != int(item["size"]):
                raise PermissionHardeningError("file content changed during permission hardening")
    return {
        "status": "ok" if unsafe_files == 0 and unsafe_directories == 0 else "unsafe",
        "file_count": sum(entry.kind == "file" for entry in entries),
        "directory_count": sum(entry.kind == "directory" for entry in entries),
        "unsafe_file_count": unsafe_files,
        "unsafe_directory_count": unsafe_directories,
    }


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manifest, harden, verify, or roll back Sitina storage filesystem modes.")
    parser.add_argument("--home", type=Path, default=PRODUCTION_HOME)
    parser.add_argument("--operation", choices=("apply", "verify", "rollback"), required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--rollback-evidence", type=Path)
    parser.add_argument("--goal-thread-id", required=True)
    parser.add_argument("--scope-root", action="append", type=Path, default=[])
    return parser.parse_args()


def _permission_authorization(
    frozen_prefix: object,
    *,
    home_roots: tuple[Path, ...],
    manifest_sha256: str,
    goal_thread_id: str,
):
    if not home_roots:
        return nullcontext()
    return authorized_production_permission_hardening(
        frozen_prefix,
        roots=home_roots,
        manifest_sha256=manifest_sha256,
        goal_thread_id=goal_thread_id,
    )


def main() -> int:
    args = _arguments()
    home = args.home.expanduser().resolve(strict=True)
    output = args.evidence_output.expanduser().resolve(strict=False)
    roots = _roots(home, tuple(args.scope_root))
    frontier_before = _frontier(home)
    fence = FrozenProductionPrefix.acquire(home) if args.operation in {"apply", "rollback"} else nullcontext()
    with fence as frozen_prefix:
        entries_before = _discover(roots)
        if args.operation == "apply":
            manifest = _manifest(entries_before)
            home_roots = tuple(path for path in roots if _inside(path, (home,)))
            with _permission_authorization(
                frozen_prefix,
                home_roots=home_roots,
                manifest_sha256=str(manifest["manifest_sha256"]),
                goal_thread_id=args.goal_thread_id,
            ):
                _apply_manifest(manifest, roots, rollback=False)
        elif args.operation == "rollback":
            if args.rollback_evidence is None:
                raise PermissionHardeningError("rollback requires --rollback-evidence")
            evidence = json.loads(args.rollback_evidence.expanduser().resolve(strict=True).read_text(encoding="utf-8"))
            manifest = dict(evidence["change_manifest"])
            home_roots = tuple(path for path in roots if _inside(path, (home,)))
            with _permission_authorization(
                frozen_prefix,
                home_roots=home_roots,
                manifest_sha256=str(manifest["manifest_sha256"]),
                goal_thread_id=args.goal_thread_id,
            ):
                _apply_manifest(manifest, roots, rollback=True)
        else:
            manifest = _manifest(entries_before)
        entries_after = _discover(roots)
        if len(entries_after) != len(entries_before) or {str(item.path) for item in entries_after} != {str(item.path) for item in entries_before}:
            raise PermissionHardeningError("permission scope inventory changed during operation")
        verification = _verify_after(entries_after, manifest, rollback=args.operation == "rollback")
    frontier_after = _frontier(home)
    if frontier_after != frontier_before:
        raise PermissionHardeningError("Production Journal changed during permission operation")
    expected_ok = args.operation in {"apply", "verify"}
    status = "ok" if verification["status"] == "ok" and (expected_ok or args.operation == "rollback") else "failed"
    value: dict[str, object] = {
        "schema": "SITINA_STORAGE_PRODUCTION_PERMISSION_EVIDENCE_V1",
        "operation": args.operation,
        "status": status,
        "home": str(home),
        "roots": [str(path) for path in roots],
        "frontier_before": frontier_before,
        "frontier_after": frontier_after,
        "journal_mutation_count": 0,
        "cas_mutation_count": 0,
        "content_mutation_count": 0,
        "change_count": len(manifest["entries"]),
        "change_manifest": manifest,
        "verification": verification,
        "rollback_supported": True,
        "secret_values_included": False,
    }
    _write(output, value)
    print(
        json.dumps(
            {
                "status": status,
                "operation": args.operation,
                "change_count": len(manifest["entries"]),
                "verification": verification,
                "evidence_output": str(output),
                "evidence_sha256": _sha256(output),
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
        raise
