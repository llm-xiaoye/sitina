from __future__ import annotations

from pathlib import Path

from sitina.constants import SITINA_HOME
from sitina.schemas.models import ArtifactRecord
from sitina.storage import SitinaStore
from sitina.utils import command_fingerprint, env_fingerprint, file_sha256, isolated_env, iso_now


class ArtifactRegistry:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def register_command_output(
        self,
        *,
        run_id: str,
        turn_id: str,
        producing_agent: str,
        command: str,
        cwd: str,
        artifact_path: str,
    ) -> ArtifactRecord:
        artifact_hash = file_sha256(Path(artifact_path))
        if not artifact_hash:
            raise FileNotFoundError(artifact_path)
        fingerprint = command_fingerprint(command, cwd, env_fingerprint(isolated_env()))
        record = ArtifactRecord(
            artifact_hash=artifact_hash,
            run_id=run_id,
            turn_id=turn_id,
            producing_agent=producing_agent,  # type: ignore[arg-type]
            producing_command_fingerprint=fingerprint,
            artifact_path=artifact_path,
            created_at=iso_now(),
        )
        self.store.insert_artifact(record.model_dump())
        return record


class EvidenceVerifier:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def verify_artifact(
        self,
        *,
        artifact_hash: str,
        run_id: str,
        command: str,
        cwd: str,
    ) -> tuple[bool, str]:
        artifact = self.store.get_artifact(artifact_hash)
        if not artifact:
            return False, "artifact_hash not registered"
        if artifact["run_id"] != run_id:
            return False, "artifact belongs to another run"
        expected = command_fingerprint(command, cwd, env_fingerprint(isolated_env()))
        if artifact["producing_command_fingerprint"] != expected:
            return False, "command fingerprint mismatch"
        if not Path(artifact["artifact_path"]).exists():
            return False, "artifact path no longer exists"
        return True, "artifact verified"
