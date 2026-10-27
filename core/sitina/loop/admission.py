from __future__ import annotations

"""Immutable admission inputs for the background Loop host.

The submission intent is deliberately smaller than the executable descriptor.
It contains only caller-selected values that identify what was requested.  The
descriptor is the first-run observation (workspace/artifact/config identities)
and is never recomputed when a duplicate submission is received.
"""

import hashlib
import json
import os
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _norm_path(value: str | os.PathLike[str]) -> str:
    return str(Path(value).expanduser().resolve(strict=False))


@dataclass(frozen=True)
class SubmissionIntent:
    task_id: str
    submission_id: str
    task_kind: str
    goal: str
    workspace_path: str
    check_command: tuple[str, ...]
    provider_profile: str
    approve_writes: bool
    authorization: str
    environment_selection: str
    capability_selection: str
    network_read_urls: tuple[str, ...] = ()
    public_web_read: bool = False
    reviewer_request_timeout_seconds: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result = {
            "schema": "SITINA_LOOP_SUBMISSION_INTENT_V1",
            "task_id": self.task_id,
            "submission_id": self.submission_id,
            "task_kind": self.task_kind,
            "goal": self.goal,
            "workspace_path": self.workspace_path,
            "check_command": list(self.check_command),
            "provider_profile": self.provider_profile,
            "approve_writes": self.approve_writes,
            "authorization": self.authorization,
            "environment_selection": self.environment_selection,
            "capability_selection": self.capability_selection,
        }
        if self.network_read_urls:
            result["network_read_urls"] = list(self.network_read_urls)
        if self.public_web_read:
            result["public_web_read"] = True
        if self.reviewer_request_timeout_seconds is not None:
            result["reviewer_request_timeout_seconds"] = self.reviewer_request_timeout_seconds
        return result


def normalize_reviewer_request_timeout(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("reviewer request timeout must be a finite positive number")
    try:
        seconds = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("reviewer request timeout must be a finite positive number") from error
    if not 0 < seconds < float("inf"):
        raise ValueError("reviewer request timeout must be a finite positive number")
    return str(seconds)


def is_public_web_read_url(value: Any) -> bool:
    """Limit task-wide browsing to ordinary anonymous public HTTPS names."""
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.port not in {None, 443}
                or parsed.netloc.casefold() not in {host, host + ":443"}):
            return False
        if host.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".example")) or host in {"localhost", "metadata.google.internal"}:
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return False
        labels = host.split(".")
        return len(labels) >= 2 and all(label and len(label) <= 63 and label[0].isalnum() and label[-1].isalnum() and all(c.isascii() and (c.isalnum() or c == "-") for c in label) for label in labels)
    except (ValueError, TypeError):
        return False


def build_submission_intent(
    *,
    task_id: str,
    submission_id: str | None,
    task_kind: str,
    goal: str,
    workspace_path: str | os.PathLike[str],
    check_command: Sequence[str] = (),
    provider_profile: str = "",
    reviewer_request_timeout_seconds: float | str | None = None,
    approve_writes: bool = False,
    network_read_urls: Sequence[str] = (),
    public_web_read: bool = False,
    authorization: str = "",
    environment_selection: str = "",
    capability_selection: str = "",
) -> SubmissionIntent:
    if not isinstance(network_read_urls, (tuple, list)):
        raise ValueError("network read URLs must be an explicit sequence")
    if type(public_web_read) is not bool:
        raise ValueError("public web read scope must be boolean")
    allowed_urls = []
    for value in network_read_urls:
        if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) <= 32 or ord(c) == 127 for c in value):
            raise ValueError("network read URL must be a non-empty exact URL")
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise ValueError("network read URL requires an anonymous HTTP(S) endpoint without a fragment")
        parsed.port
        allowed_urls.append(value)
    network_scope = tuple(sorted(set(allowed_urls)))
    normalized = tuple(str(item) for item in check_command)
    if any(not item for item in normalized):
        raise ValueError("check command entries must be non-empty")
    values = {
        "task_id": str(task_id).strip(),
        "submission_id": str(submission_id or task_id).strip(),
        "task_kind": str(task_kind).strip(),
        "goal": str(goal),
        "workspace_path": _norm_path(workspace_path),
        "provider_profile": str(provider_profile).strip(),
        "authorization": str(authorization).strip(),
        "environment_selection": str(environment_selection).strip(),
        "capability_selection": str(capability_selection).strip(),
    }
    if any(not values[key] for key in ("task_id", "submission_id", "task_kind", "goal", "workspace_path")):
        raise ValueError("submission identity, task kind, goal, and workspace are required")
    return SubmissionIntent(check_command=normalized, approve_writes=bool(approve_writes), network_read_urls=network_scope, public_web_read=public_web_read, reviewer_request_timeout_seconds=normalize_reviewer_request_timeout(reviewer_request_timeout_seconds), **values)


def submission_fingerprint(intent: SubmissionIntent) -> str:
    """Hash only stable user intent; no workspace snapshot/default is included."""

    return hashlib.sha256(_canonical(intent.as_dict())).hexdigest()


def validate_capability_binding(
    binding: Mapping[str, Any], capability_selection: str
) -> dict[str, Any]:
    """Validate the host-resolved capability binding persisted with a descriptor.

    The submission fingerprint intentionally contains only the logical slot.
    This separate binding is a host observation captured exactly once at
    admission and is therefore never accepted from an ordinary caller.
    """

    if not isinstance(binding, Mapping):
        raise ValueError("capability binding must be an object")
    required = (
        "schema", "slot_id", "publication_id", "candidate_id", "snapshot_id",
        "snapshot_hash", "location_binding", "read_position", "resolution_stream_id", "resolution_ref",
        "resolution_hash", "resolution_cas_proof",
    )
    if any(not str(binding.get(key) or "").strip() for key in required if key not in {"read_position", "resolution_cas_proof"}):
        raise ValueError("capability binding identity is incomplete")
    if binding.get("schema") != "SITINA_LOOP_CAPABILITY_BINDING_V1":
        raise ValueError("capability binding schema is invalid")
    if str(binding.get("slot_id") or "").strip().casefold() != str(capability_selection or "").strip().casefold():
        raise ValueError("capability binding slot differs from the submission selection")
    if not isinstance(binding.get("read_position"), Mapping):
        raise ValueError("capability binding lacks its fixed Journal read position")
    if not isinstance(binding.get("resolution_cas_proof"), Mapping):
        raise ValueError("capability binding lacks its CAS proof")
    read_position = binding["read_position"]
    if not str(read_position.get("stream_id") or "").strip():
        raise ValueError("capability binding read position lacks stream identity")
    if not str(read_position.get("event_id") or "").strip() or not str(read_position.get("event_hash") or "").strip():
        raise ValueError("capability binding read position lacks event identity")
    return dict(binding)


def workspace_identity(path: str | os.PathLike[str]) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve(strict=False)
    try:
        stat = resolved.stat()
    except OSError:
        return {"path": str(resolved), "exists": False}
    snapshot: dict[str, str] = {}
    if resolved.is_dir():
        ignored = {".git", ".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache"}
        try:
            candidates = sorted(resolved.rglob("*"), key=lambda item: item.as_posix())
        except OSError:
            raise OSError(f"workspace snapshot could not be enumerated: {resolved}")
        for child in candidates:
            if not child.is_file() or child.is_symlink() or any(part in ignored for part in child.relative_to(resolved).parts):
                continue
            try:
                snapshot[child.relative_to(resolved).as_posix()] = hashlib.sha256(child.read_bytes()).hexdigest()
            except OSError:
                raise OSError(f"workspace snapshot could not read: {child}")
    return {
        "path": str(resolved),
        "exists": True,
        "device": int(stat.st_dev),
        "inode": int(stat.st_ino),
        "mode": int(stat.st_mode),
        "content_snapshot": snapshot,
    }


def build_run_descriptor(
    intent: SubmissionIntent,
    *,
    required_outcome_ids: Sequence[str],
    goal_ref: str,
    goal_hash: str,
    initial_artifact_ref: str,
    initial_artifact_hash: str,
    environment_ref: str,
    capability_snapshot_id: str,
    workspace_observation: Mapping[str, Any],
    provider_identity: str,
    software_identity: str,
    config_identity: str,
    protocol_versions: Mapping[str, str] | None = None,
    capability_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if any(not str(value).strip() for value in (provider_identity, software_identity, config_identity)):
        raise ValueError("executable descriptor identities must be resolved by the host")
    descriptor = {
        "schema": "SITINA_LOOP_RUN_DESCRIPTOR_V1",
        "spec_version": "sitina-loop-v1-r4",
        "descriptor_version": 1,
        "task_id": intent.task_id,
        "submission_id": intent.submission_id,
        "task_kind": intent.task_kind,
        "required_outcome_ids": list(required_outcome_ids),
        "goal_ref": goal_ref,
        "goal_hash": goal_hash,
        "provider_profile": intent.provider_profile,
        "workspace": dict(workspace_observation),
        "initial_artifact": {"reference": initial_artifact_ref, "hash": initial_artifact_hash},
        "goal": intent.goal,
        "acceptance": {"check_command": list(intent.check_command)},
        "allowed_roots": [intent.workspace_path],
        "provider_identity": provider_identity,
        "capability_snapshot_id": capability_snapshot_id,
        "environment_ref": environment_ref,
        "authorization": {"mode": intent.authorization, "approve_writes": intent.approve_writes,
                          "execution_contract": "SITINA_TASK_EXECUTION_V1"},
        "software_identity": software_identity,
        "config_identity": config_identity,
        "protocol_versions": dict(protocol_versions or {"loop": "sitina-loop-v1-r4", "descriptor": "1"}),
        "termination_contract_version": "sitina-termination-v1",
        "continuity_contract_version": "sitina-continuity-v1",
    }
    if intent.network_read_urls:
        descriptor["authorization"]["network_read_urls"] = list(intent.network_read_urls)
    if intent.public_web_read:
        descriptor["authorization"]["public_web_read"] = True
    if capability_binding is not None:
        descriptor["capability_binding"] = dict(capability_binding)
    if intent.reviewer_request_timeout_seconds is not None:
        descriptor["reviewer_request_timeout_seconds"] = intent.reviewer_request_timeout_seconds
    return descriptor
