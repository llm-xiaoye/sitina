from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Mapping


class ArchiveCopyState(str, Enum):
    STORED = "STORED"


class ArchiveCopyAssessment(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    CONTRADICTED = "CONTRADICTED"


@dataclass(frozen=True)
class ArchiveCopy:
    copy_id: str
    package_id: str
    artifact_id: str
    path: Path
    residency: Mapping[str, str]
    content_hash: str
    state: ArchiveCopyState = ArchiveCopyState.STORED
    assessment: ArchiveCopyAssessment = ArchiveCopyAssessment.UNVERIFIED
    verifier_id: str | None = None
    final_verification_id: str | None = None

    @property
    def stream_id(self) -> str:
        return f"archive-copy/{self.copy_id}"

    def assess(self, assessment: ArchiveCopyAssessment, *, verifier_id: str) -> "ArchiveCopy":
        return replace(self, assessment=assessment, verifier_id=verifier_id)

