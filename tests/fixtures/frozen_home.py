"""Frozen-home test fixture for verifying fence behavior under production conditions.

The legacy fence is process-global and binds to SITINA_HOME at first import. To test
frozen-home behavior, tests must run in a subprocess with SITINA_HOME pre-set to a
temporary frozen home created by this fixture.

This module deliberately does NOT import sitina, to avoid binding the fence in the
caller's process as a side effect.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class FrozenBootstrapUnavailable(RuntimeError):
    """Raised ONLY when a frozen home cannot be bootstrapped because the current
    process is itself frozen (its fence denies subprocess.Popen). Tests skip on
    this. Every OTHER failure must fail the test, not skip."""


def get_core_path() -> str:
    """Locate the sitina core path from this test file (no import side effect)."""
    root = Path(__file__).resolve().parents[2]
    core = root / "core"
    if not (core / "sitina" / "__init__.py").is_file():
        raise RuntimeError(f"Sitina core path not found at {core}")
    return str(core)


def make_frozen_home() -> Path:
    """Create a temporary frozen home with a VALIDATED production freeze record.

    Spawns an isolated bootstrap subprocess (SITINA_HOME pre-set) that calls
    LegacyWriteGate.freeze(...) and emits JSON {state, record_hash}. The parent
    precisely asserts state == FROZEN_NO_WRITER and record_hash startswith
    "sha256:". Only a LegacyWriteDenied from the parent's own subprocess.Popen
    (outer process is itself frozen) is turned into a skip; every other failure
    (non-zero rc, import/freeze error, corrupt JSON, wrong state, bad hash,
    missing core) raises and fails the test. The temp home is cleaned up on any
    failure/skip.
    """
    core = get_core_path()
    home = Path(tempfile.mkdtemp(prefix="sitina-frozen-test-"))
    completed = False
    try:
        (home / ".sitina-bplus-disposable-v1").touch()

        bootstrap = (
            "import os, sys, json; "
            f"os.environ['SITINA_HOME']={str(home)!r}; "
            f"sys.path.insert(0, {core!r}); "
            "from sitina.legacy.fence import LegacyWriteGate, install_legacy_mutation_guard; "
            "install_legacy_mutation_guard(LegacyWriteGate(os.environ['SITINA_HOME']).home); "
            "st = LegacyWriteGate(os.environ['SITINA_HOME']).freeze('test-snapshot', fixture_authorization=True); "
            "print('FREEZE_JSON:' + json.dumps({'state': str(st.state), 'record_hash': st.record_hash}))"
        )
        try:
            result = subprocess.run(
                [sys.executable, "-c", bootstrap],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as exc:  # cleanup is handled by the outer finally
            # Importing sitina here would bind the process-global fence. The
            # real exception can only have been raised after fence.py was
            # loaded, so compare against that already-loaded class object.
            fence_module = sys.modules.get("sitina.legacy.fence")
            expected = getattr(fence_module, "LegacyWriteDenied", None)
            if expected is not None and type(exc) is expected:
                raise FrozenBootstrapUnavailable(
                    "outer process is frozen; cannot spawn bootstrap (LegacyWriteDenied)"
                ) from exc
            raise

        def _fail(msg: str) -> None:
            raise RuntimeError(
                f"{msg}\nrc={result.returncode}\nstdout={result.stdout}"
                f"\nstderr={result.stderr[:500]}"
            )

        if result.returncode != 0:
            _fail("frozen bootstrap subprocess failed")
        marker = "FREEZE_JSON:"
        line = next((ln for ln in result.stdout.splitlines() if ln.startswith(marker)), None)
        if line is None:
            _fail("bootstrap did not emit FREEZE_JSON")
        try:
            record = json.loads(line[len(marker):])
        except json.JSONDecodeError:
            _fail("bootstrap FREEZE_JSON is corrupt")
        if not isinstance(record, dict):
            _fail("bootstrap FREEZE_JSON must be an object")
        if record.get("state") != "FROZEN_NO_WRITER":
            _fail(f"freeze produced invalid state: {record.get('state')!r}")
        if not str(record.get("record_hash") or "").startswith("sha256:"):
            _fail(f"freeze record_hash missing/invalid: {record.get('record_hash')!r}")
        completed = True
        return home
    finally:
        if not completed:
            shutil.rmtree(home, ignore_errors=True)
