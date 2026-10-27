from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from sitina.security.redaction import isolated_env, is_secret_name, redact_text


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def new_id(prefix: str = "") -> str:
    body = f"{utc_now():%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
    return f"{prefix}{body}" if prefix else body


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonicalize_agent_input(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(redact_text(json.dumps(payload, ensure_ascii=False, sort_keys=True)))


def compute_agent_input_hash(payload: dict[str, Any]) -> str:
    return sha256_text(stable_json(canonicalize_agent_input(payload)))


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return sha256_bytes(path.read_bytes())


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    ensure_dir(path.parent)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_json_yaml(path: Path) -> Any:
    """Load JSON-compatible YAML.

    Sitina config files intentionally use JSON syntax with .yaml names. JSON is
    valid YAML and keeps the first-stage harness free of a PyYAML dependency.
    """

    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} must be JSON-compatible YAML: {exc}") from exc


def normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def command_fingerprint(command: str, cwd: str, env_fingerprint: str) -> str:
    return sha256_text(normalize_command(command) + "\n" + str(Path(cwd).resolve()) + "\n" + env_fingerprint)


def env_fingerprint(env: dict[str, str]) -> str:
    return sha256_text(stable_json(dict(sorted(env.items()))))


def chmod_octal(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))[2:].zfill(3)


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
