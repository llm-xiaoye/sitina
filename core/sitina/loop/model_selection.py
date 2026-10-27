"""Small, durable DeepSeek model selection shared by native Loop roles.

The credential and endpoint remain properties of the authorized profile.  A
selection changes only the model sent on the next Provider request.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from dataclasses import replace
from pathlib import Path

from sitina.runners.provider import ProviderProfile


MODEL_IDS = {"flash": "deepseek-flash", "pro": "deepseek-v4-pro"}


class ModelSelectionError(ValueError):
    pass


class ModelSelectionStore:
    def __init__(self, state_root: str | Path):
        self.root = Path(state_root).expanduser().resolve(strict=False)
        self.path = self.root / "model-selection.json"
        self.lock_path = self.root / "model-selection.lock"

    def read(self) -> dict[str, object]:
        if not self.path.exists() and not self.path.is_symlink():
            return {"schema": "SITINA_MODEL_SELECTION_V1", "choice": "flash", "model": MODEL_IDS["flash"], "revision": 0}
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ModelSelectionError("model selection must be an owned, non-writable-by-others regular file")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ModelSelectionError("model selection is unreadable") from error
        if (not isinstance(value, dict) or set(value) != {"schema", "choice", "model", "revision", "changed_at"}
                or value.get("schema") != "SITINA_MODEL_SELECTION_V1"
                or value.get("choice") not in MODEL_IDS
                or value.get("model") != MODEL_IDS[value["choice"]]
                or type(value.get("revision")) is not int or value["revision"] < 1
                or type(value.get("changed_at")) is not int or value["changed_at"] < 0):
            raise ModelSelectionError("model selection has an invalid schema or value")
        return value

    def set(self, choice: str) -> dict[str, object]:
        if choice not in MODEL_IDS:
            raise ModelSelectionError("choose flash or pro")
        self.root.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            current = self.read()
            if current["choice"] == choice and current["revision"] > 0:
                return current
            value = {"schema": "SITINA_MODEL_SELECTION_V1", "choice": choice,
                     "model": MODEL_IDS[choice], "revision": int(current["revision"]) + 1,
                     "changed_at": int(time.time())}
            temp = self.root / f".model-selection-{os.getpid()}-{time.time_ns()}.tmp"
            temp_descriptor = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(temp_descriptor, "wb") as stream:
                    stream.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, self.path)
                directory = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                if temp.exists():
                    temp.unlink()
            return value
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def apply(self, profile: ProviderProfile) -> ProviderProfile:
        if profile.name != "deepseek":
            raise ModelSelectionError("model selection is limited to the authorized DeepSeek profile")
        return replace(profile, model=str(self.read()["model"]))
