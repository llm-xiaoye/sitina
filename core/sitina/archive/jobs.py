from __future__ import annotations

import hashlib
import shutil
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier

from .copies import ArchiveCopy, ArchiveCopyAssessment


class ArchiveJobError(RuntimeError):
    pass


class ArchiveJobState(str, Enum):
    CREATED = "CREATED"
    STAGING_MATERIALIZED = "STAGING_MATERIALIZED"
    STAGING_VERIFIED = "STAGING_VERIFIED"
    FINAL_TRANSFERRED = "FINAL_TRANSFERRED"
    FINAL_VERIFIED = "FINAL_VERIFIED"
    COMPLETED = "COMPLETED"


def _tree_hash(root: Path) -> str:
    if not root.is_dir() or any(path.is_symlink() for path in root.rglob("*")):
        raise ArchiveJobError("archive tree is missing or contains a symlink")
    entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in sorted(root.rglob("*")) if path.is_file()
    ]
    return domain_hash("ARCHIVE_COPY_TREE", canonical_json_bytes(entries))


@dataclass(frozen=True)
class ArchiveJobProjection:
    job_id: str
    state: ArchiveJobState
    package_id: str
    artifact_id: str


@dataclass(frozen=True)
class ArchiveJob:
    job_id: str
    package_id: str
    artifact_id: str
    source_path: Path
    source_hash: str
    state: ArchiveJobState = ArchiveJobState.CREATED
    staging_path: Path | None = None
    staging_verification_id: str | None = None
    final_copy: ArchiveCopy | None = None
    replica_policy_compliant: bool = False

    @classmethod
    def create(cls, job_id: str, package_id: str, artifact_id: str, source_path: Path) -> "ArchiveJob":
        for value, field in ((job_id, "job_id"), (package_id, "package_id"), (artifact_id, "artifact_id")):
            validate_identifier(value, field=field)
        source = Path(source_path).resolve()
        return cls(job_id, package_id, artifact_id, source, _tree_hash(source))

    @property
    def stream_id(self) -> str:
        return f"archive-job/{self.job_id}"

    def projection(self) -> ArchiveJobProjection:
        return ArchiveJobProjection(self.job_id, self.state, self.package_id, self.artifact_id)

    def materialize_staging(self, destination: Path) -> tuple["ArchiveJob", Path]:
        if self.state is not ArchiveJobState.CREATED:
            raise ArchiveJobError("staging materialization is out of order")
        target = Path(destination).resolve()
        if target.exists():
            raise ArchiveJobError("staging destination already exists")
        shutil.copytree(self.source_path, target, symlinks=False)
        return replace(self, state=ArchiveJobState.STAGING_MATERIALIZED, staging_path=target), target

    def verify_staging(self, staged: Path) -> tuple["ArchiveJob", dict[str, object]]:
        if self.state is not ArchiveJobState.STAGING_MATERIALIZED or Path(staged).resolve() != self.staging_path:
            raise ArchiveJobError("staging verification is out of order")
        actual = _tree_hash(self.staging_path)
        if actual != self.source_hash:
            raise ArchiveJobError("staging copy differs from source artifact")
        verification_id = "staging-verification-" + uuid.uuid4().hex
        event = {"schema": "ARCHIVE_STAGING_VERIFIED_V1", "verification_id": verification_id, "content_hash": actual}
        return replace(self, state=ArchiveJobState.STAGING_VERIFIED, staging_verification_id=verification_id), event

    def transfer_final(
        self,
        staged: Path,
        destination: Path,
        *,
        copy_id: str,
        residency: dict[str, str],
    ) -> tuple["ArchiveJob", ArchiveCopy]:
        if self.state is not ArchiveJobState.STAGING_VERIFIED or Path(staged).resolve() != self.staging_path:
            raise ArchiveJobError("final transfer is out of order")
        target = Path(destination).resolve()
        if target.exists():
            raise ArchiveJobError("final archive destination already exists")
        shutil.copytree(self.staging_path, target, symlinks=False)
        copy = ArchiveCopy(copy_id, self.package_id, self.artifact_id, target, dict(residency), _tree_hash(target))
        return replace(self, state=ArchiveJobState.FINAL_TRANSFERRED, final_copy=copy), copy

    def verify_final(self, copy: ArchiveCopy) -> tuple["ArchiveJob", ArchiveCopy]:
        if self.state is not ArchiveJobState.FINAL_TRANSFERRED or self.final_copy is None or copy.copy_id != self.final_copy.copy_id:
            raise ArchiveJobError("final verification is out of order")
        actual = _tree_hash(copy.path)
        if actual != self.source_hash or actual != copy.content_hash:
            raise ArchiveJobError("final archive copy differs from verified staging")
        verification_id = "final-verification-" + uuid.uuid4().hex
        verified = replace(copy, assessment=ArchiveCopyAssessment.VERIFIED, verifier_id="archive-verifier", final_verification_id=verification_id)
        return replace(self, state=ArchiveJobState.FINAL_VERIFIED, final_copy=verified), verified

    def complete(self) -> tuple["ArchiveJob", dict[str, object]]:
        if self.state is not ArchiveJobState.FINAL_VERIFIED:
            raise ArchiveJobError("archive job is not final-verified")
        event = {"schema": "ARCHIVE_JOB_COMPLETED_V1", "job_id": self.job_id, "replica_policy_compliant": False}
        return replace(self, state=ArchiveJobState.COMPLETED), event

