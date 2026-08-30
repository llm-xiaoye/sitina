"""Content-addressed V2 patch manifests for accepted execution mutations.

V2 represents delete as an explicit tombstone and rename as one source to one
destination entry. No operation is inferred from a missing file.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence


class ExecutionPatchError(RuntimeError):
    pass


ACCEPTED_MUTATION_OPERATIONS = frozenset({"create", "modify", "append", "rename", "delete"})
UNSUPPORTED_DESTRUCTIVE_OPERATIONS = frozenset()
REPLAY_ENTRY_OPERATIONS = ACCEPTED_MUTATION_OPERATIONS


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_join(root: Path, relative: str) -> Path:
    """Join a manifest-relative path without traversing a symlink."""
    candidate = (root / relative).resolve(strict=False)
    if not _inside(candidate, root):
        raise ExecutionPatchError("patch path escapes its repository")
    current = root
    for part in Path(relative).parts:
        if part in {"", "."}:
            continue
        current = current / part
        if current.is_symlink():
            raise ExecutionPatchError("patch path traverses a symlink")
    return candidate


def _hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExecutionPatchError("patch mutation hash is invalid")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ExecutionPatchError("patch mutation hash is invalid")
    return digest


def build_patch_manifest(
    *,
    run_id: str,
    execution_attempt_id: str,
    workspace: Path,
    diff_paths: Sequence[str],
    mutation_events: Sequence[Mapping[str, object]],
    content_refs: Mapping[str, str],
    target_repo: str | None = None,
) -> tuple[dict[str, object], str]:
    root = Path(workspace).expanduser().resolve(strict=True)
    candidates = tuple(Path(value).expanduser().resolve(strict=False) for value in diff_paths)
    if not candidates or len(set(candidates)) != len(candidates):
        raise ExecutionPatchError("patch manifest requires unique changed paths")
    events = [dict(item) for item in mutation_events if item.get("denied") is False]
    if not events:
        raise ExecutionPatchError("patch manifest has no successful mutation events")
    if any(
        item.get("operation") not in ACCEPTED_MUTATION_OPERATIONS
        or not isinstance(item.get("path"), str)
        or not item.get("path")
        or not isinstance(item.get("authorization_ref"), str)
        or not item.get("authorization_ref")
        for item in events
    ):
        raise ExecutionPatchError("patch manifest contains an unsupported or unaudited mutation")
    candidate_paths = {str(path) for path in candidates}
    event_paths = {str(item["path"]) for item in events}
    if event_paths != candidate_paths:
        raise ExecutionPatchError("successful mutation paths do not exactly match the collected diff")
    content_paths = {str(item["path"]) for item in events if item.get("operation") != "delete"}
    if set(content_refs) != content_paths:
        raise ExecutionPatchError("immutable content references do not exactly match live mutation content")
    sequences = [int(item.get("sequence", 0)) for item in events]
    if any(value <= 0 for value in sequences) or len(set(sequences)) != len(sequences):
        raise ExecutionPatchError("patch mutation ledger sequence is invalid")

    entries: list[dict[str, object]] = []
    for source in sorted(candidates, key=str):
        if not _inside(source, root) or source.is_symlink():
            raise ExecutionPatchError("patch manifest source escapes the execution workspace")
        absolute = str(source)
        path_events = sorted(
            (item for item in events if item.get("path") == absolute),
            key=lambda item: int(item.get("sequence", 0)),
        )
        if not path_events:
            raise ExecutionPatchError("changed path has no successful mutation event")
        operation = str(path_events[-1]["operation"])
        before_hash = _hash(path_events[0].get("before_hash"))
        previous = before_hash
        for index, event in enumerate(path_events):
            event_before = _hash(event.get("before_hash"))
            event_after = _hash(event.get("after_hash"))
            if index > 0 and event_before != previous:
                raise ExecutionPatchError("patch mutation hash chain is discontinuous")
            if event_after is None and str(event.get("operation")) != "delete":
                raise ExecutionPatchError("successful non-delete mutation has no after hash")
            previous = event_after
        relative = source.relative_to(root).as_posix()
        common: dict[str, object] = {
            "path": relative,
            "source_path": relative,
            "operation": operation,
            "before_hash": before_hash,
            "mutation_sequences": [int(item["sequence"]) for item in path_events],
            "mutation_operations": [str(item["operation"]) for item in path_events],
            "authorization_refs": [item.get("authorization_ref") for item in path_events],
        }
        if operation == "delete":
            if source.exists() or previous is not None:
                raise ExecutionPatchError("delete source is not an explicit verified tombstone")
            entries.append({**common, "after_hash": None, "tombstone": True, "size": 0, "mode": 0})
            continue
        content_path = source
        if operation == "rename":
            destination = path_events[-1].get("destination")
            if not isinstance(destination, str) or not destination:
                raise ExecutionPatchError("rename mutation lacks destination identity")
            content_path = Path(destination).expanduser().resolve(strict=False)
            if not _inside(content_path, root) or content_path.is_symlink() or not content_path.is_file():
                raise ExecutionPatchError("rename destination is outside or not a regular file")
        if not content_path.is_file() or content_path.is_symlink():
            raise ExecutionPatchError("patch content path is not a regular file")
        raw = content_path.read_bytes()
        digest = _sha256(raw)
        if previous != digest:
            raise ExecutionPatchError("final mutation hash does not match patch content")
        reference = content_refs.get(absolute)
        if not isinstance(reference, str) or not reference:
            raise ExecutionPatchError("patch content has no immutable object reference")
        entry = {
            **common,
            "after_hash": digest,
            "content_ref": reference,
            "size": len(raw),
            "mode": stat.S_IMODE(content_path.stat().st_mode),
        }
        if operation == "rename":
            entry["destination"] = content_path.relative_to(root).as_posix()
        entries.append(entry)

    tree_hash = _sha256(_canonical([[item["path"], item["after_hash"], item["mode"]] for item in entries]))
    manifest: dict[str, object] = {
        "schema": "SITINA_EXECUTION_PATCH_MANIFEST_V2",
        "run_id": run_id,
        "execution_attempt_id": execution_attempt_id,
        "entries": entries,
        "mutation_event_count": len(mutation_events),
        "successful_mutation_event_count": sum(item.get("denied") is False for item in mutation_events),
        "denied_mutation_event_count": sum(item.get("denied") is True for item in mutation_events),
        "unique_path_count": len(entries),
        "after_tree_hash": tree_hash,
    }
    if target_repo is not None:
        manifest["target_repo"] = str(Path(target_repo).expanduser().resolve(strict=True))
    return manifest, _sha256(_canonical(manifest))


def replay_patch_manifest(
    manifest: Mapping[str, object], *, destination: Path, load_content: Callable[[str], bytes]
) -> str:
    if manifest.get("schema") not in {"SITINA_EXECUTION_PATCH_MANIFEST_V1", "SITINA_EXECUTION_PATCH_MANIFEST_V2"}:
        raise ExecutionPatchError("patch manifest schema is invalid")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ExecutionPatchError("patch manifest has no entries")
    root = Path(destination).expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=False)
    replayed: list[list[object]] = []
    seen: set[str] = set()
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise ExecutionPatchError("patch manifest entry is invalid")
        operation = raw.get("operation")
        mutations = raw.get("mutation_operations")
        if operation not in REPLAY_ENTRY_OPERATIONS or not isinstance(mutations, list) or not mutations or any(value not in ACCEPTED_MUTATION_OPERATIONS for value in mutations):
            raise ExecutionPatchError("patch replay operation contract is invalid")
        relative = raw.get("path")
        if not isinstance(relative, str) or not relative or relative in seen:
            raise ExecutionPatchError("patch manifest path is invalid or duplicated")
        seen.add(relative)
        source = _safe_join(root, relative)
        before_hash = _hash(raw.get("before_hash"))
        if operation == "delete":
            if raw.get("after_hash") is not None or raw.get("tombstone") is not True:
                raise ExecutionPatchError("delete patch entry is not an explicit tombstone")
            if source.exists() or source.is_symlink():
                if source.is_symlink() or not source.is_file() or _sha256(source.read_bytes()) != before_hash:
                    raise ExecutionPatchError("delete patch source identity mismatch")
                source.unlink()
            replayed.append([relative, None, 0])
            continue
        reference = raw.get("content_ref")
        if not isinstance(reference, str):
            raise ExecutionPatchError("patch replay content reference is invalid")
        content = load_content(reference)
        digest = _sha256(content)
        if digest != raw.get("after_hash") or len(content) != raw.get("size"):
            raise ExecutionPatchError("patch replay content identity mismatch")
        mode = raw.get("mode")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777:
            raise ExecutionPatchError("patch replay file mode is invalid")
        target = source
        if operation == "rename":
            destination_relative = raw.get("destination")
            if not isinstance(destination_relative, str) or not destination_relative or destination_relative in seen:
                raise ExecutionPatchError("rename patch destination is invalid or duplicated")
            seen.add(destination_relative)
            target = _safe_join(root, destination_relative)
            if source.exists() or source.is_symlink():
                if source.is_symlink() or not source.is_file() or _sha256(source.read_bytes()) != before_hash:
                    raise ExecutionPatchError("rename patch source identity mismatch")
        if target.exists() or target.is_symlink():
            raise ExecutionPatchError("patch replay target already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        if operation == "rename" and source.exists():
            source.rename(target)
            os.chmod(target, mode)
        else:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        replayed.append([relative, digest, mode])
    tree_hash = _sha256(_canonical(replayed))
    if tree_hash != manifest.get("after_tree_hash"):
        raise ExecutionPatchError("patch replay tree hash mismatch")
    return tree_hash


def verify_patch_replay(manifest: Mapping[str, object], *, load_content: Callable[[str], bytes]) -> str:
    with tempfile.TemporaryDirectory(prefix="sitina-patch-replay-") as parent:
        return replay_patch_manifest(manifest, destination=Path(parent) / "replayed", load_content=load_content)
