from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Iterable

from sitina.journal.model import canonical_json_bytes, domain_hash


class LegacyArchivePlanError(RuntimeError):
    pass


class LegacyArchivePlanner:
    """Read-only inventory and recovery plan. It has no archive or deletion method."""

    @staticmethod
    def _digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _roots(values: Iterable[str | Path]) -> tuple[Path, ...]:
        roots = tuple(sorted({Path(value).expanduser().resolve(strict=True) for value in values}, key=str))
        if any(root.is_symlink() or not root.is_dir() for root in roots):
            raise LegacyArchivePlanError("Legacy archive source must be a real directory")
        for index, root in enumerate(roots):
            if any(root == other or root in other.parents or other in root.parents for other in roots[index + 1 :]):
                raise LegacyArchivePlanError("Legacy archive source roots must not overlap")
        return roots

    def plan(
        self,
        source_roots: Iterable[str | Path],
        *,
        cold_archive_target: str | Path,
    ) -> dict[str, Any]:
        roots = self._roots(source_roots)
        target = Path(cold_archive_target).expanduser().resolve(strict=False)
        if any(target == root or target in root.parents or root in target.parents for root in roots):
            raise LegacyArchivePlanError("cold archive target must be outside every Legacy source")
        files: list[dict[str, Any]] = []
        allocated_seen: set[tuple[int, int]] = set()
        reclaimable_allocated = 0
        for root_index, root in enumerate(roots):
            root_id = f"legacy-root-{root_index + 1}"
            for path in sorted(root.rglob("*")):
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    raise LegacyArchivePlanError(f"Legacy inventory rejects symlink: {root_id}/{relative}")
                if path.is_dir():
                    continue
                if not path.is_file():
                    raise LegacyArchivePlanError(f"Legacy inventory rejects special file: {root_id}/{relative}")
                metadata = path.stat()
                identity = (metadata.st_dev, metadata.st_ino)
                allocated = int(getattr(metadata, "st_blocks", 0)) * 512
                if identity not in allocated_seen:
                    reclaimable_allocated += allocated
                    allocated_seen.add(identity)
                files.append(
                    {
                        "source_root_id": root_id,
                        "relative_path": relative,
                        "logical_bytes": metadata.st_size,
                        "allocated_bytes": allocated,
                        "sha256": self._digest(path),
                    }
                )
        leaves = [
            domain_hash("LEGACY_ARCHIVE_FILE", canonical_json_bytes(item))
            for item in files
        ]
        merkle = self._merkle_root(leaves)
        provisional: dict[str, Any] = {
            "schema": "SITINA_LEGACY_ARCHIVE_PLAN_V1",
            "dry_run": True,
            "source_roots": [
                {"source_root_id": f"legacy-root-{index + 1}", "path": str(root)}
                for index, root in enumerate(roots)
            ],
            "files": files,
            "file_count": len(files),
            "logical_bytes": sum(int(item["logical_bytes"]) for item in files),
            "estimated_reclaimable_allocated_bytes": reclaimable_allocated,
            "tree_merkle_root": merkle,
            "cold_archive_target": str(target),
            "restore_test": {
                "executed": False,
                "required_source": "FINAL_VERIFIED_COLD_COPY",
                "isolated_destination_required": True,
                "verify_every_file_hash": True,
                "verify_tree_merkle_root": True,
            },
            "signed_catalog": {
                "created": False,
                "signature_required_before_source_release": True,
                "catalog_commitment": merkle,
            },
            "risks": [
                "NO_ARCHIVE_COPY_HAS_BEEN_CREATED",
                "NO_OFFSITE_RESTORE_TEST_HAS_RUN",
                "SOURCE_MAY_HAVE_CHANGED_AFTER_INVENTORY",
                "HARD_LINK_AND_FILESYSTEM_COMPRESSION_MAKE_RECLAIM_ESTIMATES_APPROXIMATE",
            ],
            "rollback": {
                "current_action": "NONE_REQUIRED_DRY_RUN",
                "future_release_method": "MOVE_VERIFIED_LOCAL_COPY_TO_NATIVE_TRASH_AFTER_SECOND_CONFIRMATION",
                "delete_command_available": False,
            },
            "execution_sequence_if_separately_authorized": [
                "CREATE_ARCHIVE",
                "VERIFY_ARCHIVE",
                "OFFSITE_ISOLATED_RESTORE_TEST",
                "SECOND_USER_CONFIRMATION",
                "MOVE_LOCAL_COPY_TO_NATIVE_TRASH",
            ],
            "archive_created": False,
            "source_moved": False,
            "source_deleted": False,
            "native_trash_operated": False,
        }
        return {
            **provisional,
            "plan_commitment": domain_hash("LEGACY_ARCHIVE_PLAN", canonical_json_bytes(provisional)),
        }

    @staticmethod
    def _merkle_root(leaves: list[str]) -> str:
        if not leaves:
            return domain_hash("LEGACY_ARCHIVE_EMPTY_TREE", b"")
        level = list(leaves)
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [
                domain_hash("LEGACY_ARCHIVE_MERKLE_NODE", bytes.fromhex(level[index]) + bytes.fromhex(level[index + 1]))
                for index in range(0, len(level), 2)
            ]
        return level[0]


__all__ = ["LegacyArchivePlanError", "LegacyArchivePlanner"]
