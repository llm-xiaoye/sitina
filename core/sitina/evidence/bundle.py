from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash

from .assessment import EvidenceAssessment
from .package import EvidencePackageCore
from .seal import EvidenceSeal


class ContainerUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class BundleArtifact:
    artifact_id: str
    path: Path
    semantic_hash: str
    container_hash: str
    core_hash: str
    assessment_hash: str
    seal_hash: str
    container_profile: str = "LOGICAL_DIRECTORY_V1"


class BundleBuilder:
    def __init__(self, home: Path):
        self.home = Path(home).resolve()
        if not (self.home / ".sitina-bplus-disposable-v1").is_file():
            raise PermissionError("bundle builder requires a marked disposable home")
        self.root = self.home / "evidence-bundles"

    @staticmethod
    def _write(path: Path, value: Mapping[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(dict(value)) + b"\n")

    def build_logical(
        self,
        artifact_id: str,
        core: EvidencePackageCore,
        assessment: EvidenceAssessment,
        seal: EvidenceSeal,
        *,
        capability_manifest: Mapping[str, object],
        layout_metadata: Mapping[str, object] | None = None,
    ) -> BundleArtifact:
        if assessment.core_hash != core.core_hash or seal.core_hash != core.core_hash or seal.assessment_hash != assessment.assessment_hash:
            raise ValueError("bundle hash layers are inconsistent")
        path = self.root / artifact_id
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)
        semantic = {
            "schema": "EVIDENCE_BUNDLE_SEMANTIC_V1",
            "core_hash": core.core_hash,
            "assessment_hash": assessment.assessment_hash,
            "seal_hash": seal.seal_hash,
            "capability_manifest": dict(capability_manifest),
        }
        semantic_hash = domain_hash("EVIDENCE_BUNDLE_SEMANTIC", canonical_json_bytes(semantic))
        self._write(path / "core.json", core.core_mapping())
        self._write(path / "assessment.json", assessment.mapping())
        self._write(path / "seal.json", seal.mapping())
        self._write(path / "capabilities.json", dict(capability_manifest))
        self._write(path / "semantic.json", {**semantic, "semantic_hash": semantic_hash})
        self._write(
            path / "layout.json",
            {
                "schema": "LOGICAL_DIRECTORY_LAYOUT_V1",
                "artifact_id": artifact_id,
                "profile": "LOGICAL_DIRECTORY_V1",
                "metadata": dict(layout_metadata or {}),
            },
        )
        return BundleArtifact(
            artifact_id,
            path,
            semantic_hash,
            self.compute_container_hash(path),
            core.core_hash,
            assessment.assessment_hash,
            seal.seal_hash,
        )

    def compute_container_hash(self, path: Path) -> str:
        root = Path(path).resolve()
        entries: list[dict[str, object]] = []
        for item in sorted(root.rglob("*")):
            relative = item.relative_to(root).as_posix()
            if item.is_symlink():
                raise ValueError("bundle containers cannot contain symlinks")
            if item.is_file():
                entries.append(
                    {
                        "path": relative,
                        "mode": item.stat().st_mode & 0o777,
                        "size": item.stat().st_size,
                        "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
                    }
                )
        return domain_hash("EVIDENCE_BUNDLE_CONTAINER", canonical_json_bytes(entries))

    def build_deterministic_tar_zst(self, *_args: object, **_kwargs: object) -> BundleArtifact:
        raise ContainerUnavailable("zstandard is unavailable; deterministic tar.zst is not claimed")

