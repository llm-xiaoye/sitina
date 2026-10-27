from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from .model import EffectStatus


# Bound collection cost independently of model context; file bytes never enter a prompt.
MAX_GENERATED_BYTES = 64 * 1024 * 1024
MAX_GENERATED_ENTRIES = 256
GENERATED_FILE_SCHEMA = "SITINA_GENERATED_FILE_V1"


def capture_generated_files(memory: Any, *, task_id: str, operation_id: str,
                            output_root: Path) -> dict[str, Any]:
    """Snapshot settled command output into the existing authenticated CAS.

    The caller must have verified successful completion and unchanged inputs.
    Publication alone does not deliver a file or establish business success.
    """
    files: list[dict[str, Any]] = []
    total = 0
    entries = 0
    root_fd = None
    def walk_error(error: OSError) -> None:
        raise error

    try:
        root_fd = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for directory, dirs, names, directory_fd in os.fwalk(".", dir_fd=root_fd, follow_symlinks=False, onerror=walk_error):
            dirs.sort()
            names.sort()
            entries += len(dirs) + len(names)
            if entries > MAX_GENERATED_ENTRIES:
                raise ValueError("generated output exceeds the bounded entry count")
            for name in dirs:
                if not stat.S_ISDIR(os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode):
                    raise ValueError("generated output contains a linked directory")
            for name in names:
                relative = (Path(directory) / name).as_posix()
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        raise ValueError("generated output must contain only regular unlinked files")
                    remaining = MAX_GENERATED_BYTES - total
                    if before.st_size > remaining:
                        raise ValueError("generated output exceeds the byte budget")
                    raw = stream.read(remaining + 1)
                    after = os.fstat(stream.fileno())
                    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
                    if (len(raw) > remaining or len(raw) != before.st_size
                            or identity(before) != identity(after)):
                        raise ValueError("generated output changed while being captured")
                total += len(raw)
                digest = hashlib.sha256(raw).hexdigest()
                stored = memory.persist({
                    "schema": GENERATED_FILE_SCHEMA, "task_id": task_id, "operation_id": operation_id,
                    "path": relative, "size_bytes": len(raw), "sha256": digest,
                    "content_base64": base64.b64encode(raw).decode("ascii"),
                }, purpose="loop-generated-file")
                files.append({
                    "file_ref": "generated-file:" + operation_id + ":" + stored.reference_id,
                    "path": relative, "size_bytes": len(raw), "sha256": digest,
                    "content_hash": stored.content_hash,
                })
    except (OSError, ValueError) as error:
        # Never offer a partially captured tree as a complete delivery source.
        return {"generated_files": [], "generated_files_status": "UNAVAILABLE",
                "generated_files_error": str(error)}
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return {"generated_files": files, "generated_files_status": "AVAILABLE" if files else "EMPTY"}


def resolve_generated_file(backend: Any, task_id: str, file_ref: str) -> bytes:
    """Resolve only a committed successful operation of this task, after reopen too."""
    parts = file_ref.split(":", 2)
    if len(parts) != 3 or parts[0] != "generated-file" or not parts[1] or not parts[2].startswith("cas:"):
        raise ValueError("invalid generated file reference")
    task = backend.get_task(task_id)
    operation = task.operations.get(parts[1])
    if (operation is None or operation.effect_status is not EffectStatus.SUCCEEDED
            or operation.unknown_effect or not operation.result_ref
            or operation.bound_goal_version != task.goal_version
            or operation.bound_acceptance_version != task.acceptance_version
            or operation.bound_input_seq != task.handled_input_seq):
        raise ValueError("generated file requires a successful current-task operation")
    receipt = backend.context_memory.read(operation.result_ref)
    result = receipt.get("result")
    if (not isinstance(result, Mapping) or result.get("effect_kind") != "command"
            or result.get("effect_settled") is not True or result.get("program_status") != "PASS"
            or result.get("generated_files_status") != "AVAILABLE"):
        raise ValueError("generated file has no successful settled command receipt")
    offered = result.get("generated_files")
    matches = [item for item in offered if isinstance(item, Mapping) and item.get("file_ref") == file_ref] if isinstance(offered, list) else []
    if len(matches) != 1:
        raise ValueError("generated file reference is not in its operation receipt")
    item = matches[0]
    document = backend.context_memory.read(parts[2], expected_hash=item["content_hash"])
    if (document.get("schema") != GENERATED_FILE_SCHEMA or document.get("task_id") != task_id
            or document.get("operation_id") != operation.operation_id
            or any(document.get(key) != item.get(key) for key in ("path", "size_bytes", "sha256"))):
        raise ValueError("generated file binding differs from its receipt")
    raw = base64.b64decode(document["content_base64"], validate=True)
    if len(raw) != item["size_bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
        raise ValueError("generated file bytes differ from their receipt")
    return raw
