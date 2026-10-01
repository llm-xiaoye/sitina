from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def launcher_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("SITINA_HOME", None)
    environment.pop("SITINA_SOURCE_ROOT", None)
    environment.pop("SITINA_PYTHON", None)
    environment.pop("SITINA_R4_DEV_ROOT", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def test_development_launcher_help_exposes_current_auto_loop() -> None:
    completed = subprocess.run(
        [str(ROOT / "bin/sitina"), "--help"],
        cwd=ROOT,
        env=launcher_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "open the current Loop with automatic routing" in completed.stdout
    assert "loop-state" in completed.stdout
    assert "FAST/MULTI" not in completed.stdout


def test_legacy_development_launcher_rejects_wrong_home_before_cli_import(tmp_path: Path) -> None:
    import shutil
    from tests.test_loop_batch_1b_runtime import boundary_fixture

    boundary = boundary_fixture(tmp_path)
    launcher_root = boundary.source_root
    (launcher_root / "bin").mkdir()
    for name in ("sitina", "sitina-r4-dev"):
        shutil.copy2(ROOT / "bin" / name, launcher_root / "bin" / name)
    environment = launcher_environment()
    environment["SITINA_HOME"] = str(tmp_path / "wrong")
    completed = subprocess.run(
        [str(launcher_root / "bin/sitina"), "--help"],
        cwd=launcher_root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 64
    assert "SITINA_HOME points at a different" in completed.stderr
    assert not (tmp_path / "wrong").exists()
