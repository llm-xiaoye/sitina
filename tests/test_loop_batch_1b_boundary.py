from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sitina.loop.development import (
    DevelopmentBoundary,
    DevelopmentBoundaryError,
    InstallationBoundary,
    boundary_interpreter_entry,
    runtime_subprocess_environment,
    validate_runtime_boundary,
)


def fixture_root(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    root = tmp_path / "dev"
    python = root / ".venv-r4/bin/python"
    config = root / "config"
    credential = tmp_path / "credential.env"
    python.parent.mkdir(parents=True)
    python.write_text("fixture interpreter", encoding="utf-8")
    config.mkdir(parents=True)
    credential.write_text("API_KEY=fixture-only", encoding="utf-8")
    (root / "profiles").mkdir()
    (root / "profiles/deepseek.env").symlink_to(credential)
    (root / ".sitina-r4-development-root-v1.json").write_text(
        json.dumps(
            {
                "schema": "SITINA_R4_DEVELOPMENT_ROOT_V1",
                "development_root": str(root),
                "runtime_relative_root": "runtime/r4-loop-dev",
                "state_authority_relative_root": "runtime/r4-loop-dev/state/task-1",
                "credential_references": [
                    {"path": "profiles/deepseek.env", "access": "read_only_reference"}
                ],
                "forbidden_write_roots": [str(tmp_path / "source"), str(tmp_path / "desktop")],
            }
        ),
        encoding="utf-8",
    )
    state = root / "runtime/r4-loop-dev/state/task-1"
    workspace = root / "runtime/r4-loop-dev/workspaces/task-1"
    return root, python, state, workspace


def test_development_boundary_rejects_unset_environment(tmp_path: Path) -> None:
    root, python, state, workspace = fixture_root(tmp_path)
    with pytest.raises(DevelopmentBoundaryError, match="SITINA_R4_DEV_ROOT"):
        DevelopmentBoundary.validate(
            source_root=None,
            interpreter=python,
            state_root=state,
            business_workspace=workspace,
            environment={},
        )


def test_development_boundary_records_correct_isolated_fixture(tmp_path: Path) -> None:
    root, python, state, workspace = fixture_root(tmp_path)
    boundary = DevelopmentBoundary.validate(
        source_root=root,
        interpreter=python,
        state_root=state,
        business_workspace=workspace,
        environment={"SITINA_HOME": str(root), "SITINA_R4_DEV_ROOT": str(root)},
    )
    report = boundary.as_dict()
    assert report["source_root"] == str(root)
    assert report["interpreter"] == str(python)
    assert report["config_root"] == str(root / "config")
    assert report["state_root"] == str(state)
    assert report["business_workspace"] == str(workspace)
    assert report["credential_references"][0]["access"] == "read_only_reference"
    assert report["credential_references"][0]["resolved_path"] == str(tmp_path / "credential.env")
    child_environment = runtime_subprocess_environment(boundary, {})
    assert child_environment["SITINA_R4_DEV_ROOT"] == str(root)
    assert child_environment["SITINA_PYTHON"] == str(root / ".venv-r4/bin/python")
    assert boundary_interpreter_entry(boundary) == root / ".venv-r4/bin/python"


def test_development_boundary_rejects_wrong_and_symlinked_roots(tmp_path: Path) -> None:
    root, python, state, workspace = fixture_root(tmp_path)
    wrong = tmp_path / "wrong"
    wrong.mkdir()
    with pytest.raises(DevelopmentBoundaryError, match="SITINA_HOME"):
        DevelopmentBoundary.validate(
            source_root=root,
            interpreter=python,
            state_root=state,
            business_workspace=workspace,
            environment={"SITINA_HOME": str(wrong), "SITINA_R4_DEV_ROOT": str(root)},
        )
    alias = tmp_path / "dev-alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(DevelopmentBoundaryError, match="symlink"):
        DevelopmentBoundary.validate(
            source_root=alias,
            interpreter=python,
            state_root=state,
            business_workspace=workspace,
            environment={"SITINA_HOME": str(alias), "SITINA_R4_DEV_ROOT": str(alias)},
        )


def test_development_boundary_rejects_state_or_workspace_symlink_escape(tmp_path: Path) -> None:
    root, python, state, workspace = fixture_root(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    state.parent.mkdir(parents=True)
    state.symlink_to(outside, target_is_directory=True)
    with pytest.raises(DevelopmentBoundaryError, match="symlink"):
        DevelopmentBoundary.validate(
            source_root=root,
            interpreter=python,
            state_root=state,
            business_workspace=workspace,
            environment={"SITINA_HOME": str(root), "SITINA_R4_DEV_ROOT": str(root)},
        )


def test_development_boundary_rejects_alternate_state_authority_before_creation(tmp_path: Path) -> None:
    root, python, _state, workspace = fixture_root(tmp_path)
    alternate = root / "runtime/r4-loop-dev/state/alternate"
    with pytest.raises(DevelopmentBoundaryError, match="unique state authority"):
        DevelopmentBoundary.validate(
            source_root=root,
            interpreter=python,
            state_root=alternate,
            business_workspace=workspace,
            environment={"SITINA_HOME": str(root), "SITINA_R4_DEV_ROOT": str(root)},
        )
    assert not alternate.exists()


def test_installed_boundary_binds_source_interpreter_state_and_workspace(tmp_path: Path) -> None:
    root = tmp_path / "installed"
    physical_python = root / "python/bin/python3.12"
    physical_python.parent.mkdir(parents=True)
    physical_python.write_text("fixture interpreter", encoding="utf-8")
    python = physical_python.with_name("python3")
    python.symlink_to(physical_python.name)
    (root / "config").mkdir()
    state = root / "runtime/loop/state"
    workspace = root / "runtime/loop/workspaces/default"
    environment = {
        "SITINA_HOME": str(root),
        "SITINA_SOURCE_ROOT": str(root),
        "SITINA_PYTHON": str(python),
    }

    boundary = validate_runtime_boundary(
        source_root=root,
        interpreter=python,
        state_root=state,
        business_workspace=workspace,
        environment=environment,
    )

    assert isinstance(boundary, InstallationBoundary)
    report = boundary.as_dict()
    assert report["schema"] == "SITINA_LOOP_INSTALLATION_BOUNDARY_V1"
    assert report["interpreter"] == str(physical_python)
    assert boundary.source_root == root
    assert boundary.interpreter == physical_python
    assert boundary.interpreter_entry == python
    assert boundary_interpreter_entry(boundary) == python
    assert boundary.state_root == state
    assert boundary.business_workspace == workspace
    assert not state.exists()
    assert not workspace.exists()
    child_environment = runtime_subprocess_environment(boundary, {})
    assert "SITINA_R4_DEV_ROOT" not in child_environment
    assert child_environment["SITINA_PYTHON"] == str(python)

    replacement = physical_python.with_name("python3.13")
    replacement.write_text("replacement interpreter", encoding="utf-8")
    python.unlink()
    python.symlink_to(replacement.name)
    with pytest.raises(DevelopmentBoundaryError, match="no longer matches"):
        boundary_interpreter_entry(boundary)


def test_installed_boundary_rejects_alternate_state_authority(tmp_path: Path) -> None:
    root = tmp_path / "installed"
    python = root / "python/bin/python3"
    python.parent.mkdir(parents=True)
    python.write_text("fixture interpreter", encoding="utf-8")
    (root / "config").mkdir()
    environment = {
        "SITINA_HOME": str(root),
        "SITINA_SOURCE_ROOT": str(root),
        "SITINA_PYTHON": str(python),
    }

    with pytest.raises(DevelopmentBoundaryError, match="unique state authority"):
        InstallationBoundary.validate(
            source_root=root,
            interpreter=python,
            state_root=root / "runtime/loop/state/alternate",
            business_workspace=root / "runtime/loop/workspaces/default",
            environment=environment,
        )
