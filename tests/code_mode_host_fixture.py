"""Test-only bootstrap for the external Code Mode authority host.

Tests exercise the same executable/FD boundary as CLI. They never import or
instantiate an issuer implementation from the Sitina package.
"""
from __future__ import annotations

import os
import hashlib
import secrets
import socket
import subprocess
import sys
from pathlib import Path
from typing import Mapping
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBroker, _connect_attested_host
from sitina.journal.model import canonical_json_bytes


def _source_manifest_hash(source_root: Path) -> str:
    config = source_root / "config"
    paths = list(config.iterdir()) if config.is_dir() else []
    core = source_root / "core" / "sitina"
    if core.is_dir():
        paths.extend(core.rglob("*.py"))
    records = []
    for path in sorted(set(paths), key=lambda item: str(item)):
        relative = str(path.relative_to(source_root))
        if path.is_file() and not path.is_symlink():
            records.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        else:
            records.append({"path": relative, "absent": True})
    return hashlib.sha256(canonical_json_bytes(records)).hexdigest()


def launch_code_mode_host(
    *, state_root: Path, workspace: Path, runtime_state_identity: str,
    runtime_journal_id: str, source_root: Path, provider: object | None = None,
    reviewer_verification: Mapping[str, str] | None = None,
    session_instance_id: str | None = None,
) -> CodeModeAuthorityBroker:
    source_root = Path(__file__).resolve().parents[1]
    entrypoint = source_root / "scripts" / "code_mode_authority_host.py"
    parent, child = socket.socketpair()
    bootstrap_read, bootstrap_write = os.pipe()
    process = subprocess.Popen(
        [sys.executable, str(entrypoint), "--control-fd", str(child.fileno()), "--bootstrap-fd", str(bootstrap_read)],
        pass_fds=(child.fileno(), bootstrap_read), close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child.close()
    os.close(bootstrap_read)
    challenge = secrets.token_bytes(32)
    authority_private_key = secrets.token_bytes(32)
    controller_capability_private_key = Ed25519PrivateKey.generate()
    controller_capability_public_key = controller_capability_private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    state_stat = state_root.stat()
    workspace_stat = workspace.stat()
    source_stat = source_root.stat()
    try:
        import json
        bootstrap = {
            "challenge_secret": challenge.hex(),
            "authority_private_key_hex": authority_private_key.hex(),
            "controller_capability_public_key": controller_capability_public_key.hex(),
            "state_root": str(state_root),
            "state_root_identity": f"{state_stat.st_dev}:{state_stat.st_ino}",
            "runtime_state_identity": runtime_state_identity,
            "runtime_journal_id": runtime_journal_id,
            "session_instance_id": session_instance_id or ("session-instance-" + secrets.token_hex(16)),
            "workspace": str(workspace),
            "workspace_identity": f"{workspace_stat.st_dev}:{workspace_stat.st_ino}",
            "source_root": str(source_root),
            "source_root_identity": f"{source_stat.st_dev}:{source_stat.st_ino}",
            "source_manifest_hash": _source_manifest_hash(source_root),
            "verification_material": (
                provider.export_read_only_verification_material()
                if provider is not None and hasattr(provider, "export_read_only_verification_material")
                else None
            ),
            # The offline fixture exposes only the provider's declared
            # non-secret profile metadata to the host.  Keep the authenticated
            # profile name identical to the runtime fact; hard-coding a
            # DeepSeek key here would make the host reject a neutral/scripted
            # profile even though the production launcher passes the selected
            # profile path and resolves credentials inside the host.
            "profiles": ({
                str(getattr(getattr(provider, "profile", None), "name", "") or "scripted-code-mode"): {
                    "name": str(getattr(getattr(provider, "profile", None), "name", "") or "scripted-code-mode"),
                    "base_url": getattr(getattr(provider, "profile", None), "base_url", "https://api.deepseek.com"),
                    "model": getattr(getattr(provider, "profile", None), "model", "deepseek-v4-pro"),
                    "wire_protocol": str(getattr(getattr(provider, "profile", None), "wire_protocol", "") or "openai_chat_completions"),
                    "adapter_capabilities": list(getattr(getattr(provider, "profile", None), "adapter_capabilities", ()) or ()),
                    "allowed_endpoint_hosts": list(getattr(getattr(provider, "profile", None), "allowed_endpoint_hosts", ()) or ()),
                    "auth_token": "",
                },
            } if provider is not None else {}),
            "reviewer_verification": dict(reviewer_verification or {}),
        }
        if os.environ.get("SITINA_CODE_MODE_TEST_HOOKS") == "1":
            ready_path = os.environ.get("SITINA_CODE_MODE_ACCEPTANCE_BARRIER_READY")
            release_path = os.environ.get("SITINA_CODE_MODE_ACCEPTANCE_BARRIER_RELEASE")
            if ready_path and release_path:
                bootstrap["test_acceptance_snapshot_barrier"] = {
                    "ready": ready_path,
                    "release": release_path,
                }
        os.write(bootstrap_write, json.dumps(bootstrap, separators=(",", ":")).encode())
    finally:
        os.close(bootstrap_write)
        del authority_private_key
    return _connect_attested_host(
        parent, process, expected_entrypoint=entrypoint, challenge=challenge,
        controller_capability_private_key=controller_capability_private_key,
    )
