"""Deterministic, content-addressed delivery manifest for accepted executions."""
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


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def build_patch_manifest(
    *,
    run_id: str,
    execution_attempt_id: str,
    workspace: Path,
    diff_paths: Sequence[str],
    mutation_events: Sequence[Mapping[str, object]],
    content_refs: Mapping[str, str],
) -> tuple[dict[str, object], str]:
    root = Path(workspace).expanduser().resolve(strict=True)
    candidates = tuple(Path(value).expanduser().resolve(strict=True) for value in diff_paths)
    if not candidates or len(set(candidates)) != len(candidates):
        raise ExecutionPatchError("patch manifest requires unique changed files")
    normalized_events = [dict(item) for item in mutation_events]
    successful_events = [
        item for item in normalized_events if item.get("denied") is False
    ]
    allowed_operations = {"create", "modify", "append"}
    if not successful_events:
        raise ExecutionPatchError("patch manifest has no successful mutation events")
    if any(
        item.get("operation") not in allowed_operations
        or not isinstance(item.get("path"), str)
        or not item.get("path")
        or not isinstance(item.get("authorization_ref"), str)
        or not item.get("authorization_ref")
        for item in successful_events
    ):
        raise ExecutionPatchError("patch manifest contains an unsupported or unaudited mutation")
    candidate_paths = {str(path) for path in candidates}
    successful_paths = {str(item["path"]) for item in successful_events}
    if successful_paths != candidate_paths:
        raise ExecutionPatchError(
            "successful mutation paths do not exactly match the collected diff"
        )
    if set(content_refs) != candidate_paths:
        raise ExecutionPatchError(
            "immutable content references do not exactly match the collected diff"
        )
    global_sequences = [int(item.get("sequence", 0)) for item in successful_events]
    if (
        any(value <= 0 for value in global_sequences)
        or len(set(global_sequences)) != len(global_sequences)
    ):
        raise ExecutionPatchError("patch mutation ledger sequence is invalid")

    def normalized_hash(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ExecutionPatchError("patch mutation hash is invalid")
        digest = value.removeprefix("sha256:")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ExecutionPatchError("patch mutation hash is invalid")
        return digest

    entries: list[dict[str, object]] = []
    for path in sorted(candidates, key=lambda item: str(item.relative_to(root))):
        if not _inside(path, root) or path.is_symlink() or not path.is_file():
            raise ExecutionPatchError("patch manifest path is outside the execution workspace")
        raw = path.read_bytes()
        absolute = str(path)
        path_events = [
            item
            for item in normalized_events
            if item.get("path") == absolute and item.get("denied") is False
        ]
        if not path_events:
            raise ExecutionPatchError("changed file has no successful mutation event")
        path_events.sort(key=lambda item: int(item.get("sequence", 0)))
        sequences = [int(item.get("sequence", 0)) for item in path_events]
        if any(value <= 0 for value in sequences) or len(set(sequences)) != len(sequences):
            raise ExecutionPatchError("patch mutation sequence is invalid")
        before_hash = normalized_hash(path_events[0].get("before_hash"))
        prior_after = before_hash
        for index, event in enumerate(path_events):
            event_before = normalized_hash(event.get("before_hash"))
            event_after = normalized_hash(event.get("after_hash"))
            if event_after is None:
                raise ExecutionPatchError("successful mutation has no after hash")
            if index > 0 and event_before != prior_after:
                raise ExecutionPatchError("patch mutation hash chain is discontinuous")
            prior_after = event_after
        final_event_hash = prior_after
        digest = _sha256(raw)
        if final_event_hash != digest:
            raise ExecutionPatchError("final mutation hash does not match patch content")
        reference = content_refs.get(absolute)
        if not isinstance(reference, str) or not reference:
            raise ExecutionPatchError("patch content has no immutable object reference")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "operation": "create" if before_hash is None else "modify",
                "before_hash": before_hash,
                "after_hash": digest,
                "content_ref": reference,
                "size": len(raw),
                "mode": stat.S_IMODE(path.stat().st_mode),
                "mutation_sequences": sequences,
                "mutation_operations": [str(item["operation"]) for item in path_events],
                "authorization_refs": [item.get("authorization_ref") for item in path_events],
            }
        )
    tree_hash = _sha256(
        _canonical(
            [
                [item["path"], item["after_hash"], item["mode"]]
                for item in entries
            ]
        )
    )
    manifest: dict[str, object] = {
        "schema": "SITINA_EXECUTION_PATCH_MANIFEST_V1",
        "run_id": run_id,
        "execution_attempt_id": execution_attempt_id,
        "entries": entries,
        "mutation_event_count": len(normalized_events),
        "successful_mutation_event_count": sum(
            item.get("denied") is False for item in normalized_events
        ),
        "denied_mutation_event_count": sum(
            item.get("denied") is True for item in normalized_events
        ),
        "unique_path_count": len(entries),
        "after_tree_hash": tree_hash,
    }
    return manifest, _sha256(_canonical(manifest))


def replay_patch_manifest(
    manifest: Mapping[str, object],
    *,
    destination: Path,
    load_content: Callable[[str], bytes],
) -> str:
    if manifest.get("schema") != "SITINA_EXECUTION_PATCH_MANIFEST_V1":
        raise ExecutionPatchError("patch manifest schema is invalid")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ExecutionPatchError("patch manifest has no entries")
    root = Path(destination).expanduser().resolve(strict=False)
    root.mkdir(parents=True, exist_ok=False)
    replayed: list[list[object]] = []
    seen: set[str] = set()
    for raw_entry in entries:
        if not isinstance(raw_entry, Mapping):
            raise ExecutionPatchError("patch manifest entry is invalid")
        relative = raw_entry.get("path")
        if not isinstance(relative, str) or not relative or relative in seen:
            raise ExecutionPatchError("patch manifest path is invalid or duplicated")
        seen.add(relative)
        target = (root / relative).resolve(strict=False)
        if not _inside(target, root):
            raise ExecutionPatchError("patch replay path escapes destination")
        reference = raw_entry.get("content_ref")
        if not isinstance(reference, str):
            raise ExecutionPatchError("patch replay content reference is invalid")
        content = load_content(reference)
        digest = _sha256(content)
        if digest != raw_entry.get("after_hash") or len(content) != raw_entry.get("size"):
            raise ExecutionPatchError("patch replay content identity mismatch")
        mode = raw_entry.get("mode")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777:
            raise ExecutionPatchError("patch replay file mode is invalid")
        target.parent.mkdir(parents=True, exist_ok=True)
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


def verify_patch_replay(
    manifest: Mapping[str, object], *, load_content: Callable[[str], bytes]
) -> str:
    with tempfile.TemporaryDirectory(prefix="sitina-patch-replay-") as parent:
        return replay_patch_manifest(
            manifest,
            destination=Path(parent) / "replayed",
            load_content=load_content,
        )
