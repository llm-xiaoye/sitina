from __future__ import annotations

import os
from pathlib import Path

from sitina.constants import SITINA_HOME
from sitina.utils import ensure_dir, sha256_text


class PathLease:
    def __init__(self, path: Path, run_id: str, home: Path = SITINA_HOME):
        self.path = path.expanduser().resolve(strict=False)
        self.run_id = run_id
        self.home = home
        digest = sha256_text(str(self.path)).split(":", 1)[1]
        self.lock_path = home / "state" / "locks" / f"{digest}.lock"
        self.acquired = False

    def acquire(self) -> None:
        ensure_dir(self.lock_path.parent)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            fd = os.open(self.lock_path, flags)
        except FileExistsError as exc:
            raise RuntimeError(f"path lease already held for {self.path}") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"{self.run_id}\n{self.path}\n")
        self.acquired = True

    def release(self) -> None:
        if self.acquired and self.lock_path.exists():
            self.lock_path.unlink()
        self.acquired = False

    def __enter__(self) -> "PathLease":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
